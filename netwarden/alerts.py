#!/usr/bin/env python3
"""
netwarden - alerts.py: the proactive "what changed on your network?" engine.

Most of netwarden answers the questions you ASK. This answers the one you'd forget
to ask: "did anything change while I wasn't looking?" It learns your network's normal
shape from a BASELINE window, then flags what is new in a RECENT window:

  - 新裝置 (new_devices)      : a device whose first_seen falls inside the recent window
  - 行為變化 (behavior_changes): a KNOWN device started using a service it never used
                                 in the baseline (brand-new devices are reported as
                                 new_devices instead, not as a "change")
  - 安全提醒 (threats)         : recent traffic to a flagged malicious / high-risk domain
  - DNS 可見度 (visibility)    : a device that may bypass the DNS filter (DoH lookups) or
                                 went quiet in DNS while still online (visibility.py)
  - 開放埠 (exposure)          : a risky / newly opened port from the user's last
                                 opt-in exposure check (exposure.py)
  - 不尋常時段 (unusual_hours) : a device that is normally idle at night was busy at
                                 night in the last 24 h (activity.py; always-on types skipped)
  - 流量暴增 (bandwidth_spikes): OPTIONAL (ntopng): a device moved several times its usual
                                 day's bytes in the recent window (conservative; see below)
  - 路由器埠 (upnp)            : a device asked the router (UPnP) to forward a port from the
                                 internet: a new mapping, or one on a risky port (upnp.py)
  - 就寢時間 (bedtime)         : the user's own bedtime rule saw a device in use after bedtime
                                 (bedtime.py; notify only). Where a rule covers the device and
                                 the night, the generic unusual_hours alert is left out.
  plus a short privacy summary (privacy.py) and the family context (estimated screen time
  per person + this week vs last week; screentime.py / weekly.py) for the digest -
  context, not alerts.

All local, deterministic, read-only. No LLM is required: these facts stand on their
own. The weekly push can OPTIONALLY ask the brain to word them nicely, but the digest
renderer here already speaks plain language.

    python3 -m netwarden.alerts --db data/demo.db            # human-readable digest
    python3 -m netwarden.alerts --db data/demo.db --json     # machine form
    python3 -m netwarden.alerts --db data/demo.db --lang en  # any supported language
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

from netwarden import (activity, bedtime, cache, exposure, i18n, naming, nethealth, privacy,
                       routine, screentime, services, settings, store, threatintel, tuning,
                       upnp, visibility, weekly)

# A ts-string upper bound. DNS timestamps are ISO-8601 strings sorted lexically, so
# "9999-..." compares greater than any real timestamp -> "everything up to now".
FUTURE = "9999-12-31T23:59:59.999999Z"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _short(iso: str, tz=None) -> str:
    """'2026-10-21T06:05:...Z' -> '10-21 14:05' in local time (NETWARDEN_TZ / the system
    zone, like the dashboard) for human-friendly digests."""
    from netwarden import activity   # lazy: activity is only needed for this
    try:
        dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        return dt.astimezone(tz or activity.local_tz()).strftime("%m-%d %H:%M")
    except (TypeError, ValueError):
        return (iso or "")[5:16].replace("T", " ")


def _device_names(db) -> dict:
    """mac -> best human label (user's label > hostname > vendor > mac)."""
    return store.device_names(db)


def new_devices(db, since: str) -> list:
    """Devices first seen at/after `since` (ISO string), newest first."""
    names = _device_names(db)
    out = []
    for r in db.execute(
        "SELECT mac, ip, vendor, hostname, is_self, randomized, first_seen FROM devices "
        "WHERE first_seen >= ? ORDER BY first_seen DESC",
        (since,),
    ):
        out.append({
            "mac": r["mac"],
            "ip": r["ip"],
            "name": names.get(r["mac"], r["mac"]),
            "vendor": r["vendor"],
            "is_self": bool(r["is_self"]),
            "randomized": bool(r["randomized"]),
            "first_seen": r["first_seen"],
        })
    return out


def _services_in_window(db, start: str, end: str) -> dict:
    """mac -> {service_id: set(domains)} for distinct domains seen in [start, end)."""
    m: dict = {}
    for r in db.execute(
        "SELECT device_mac, domain FROM dns_events "
        "WHERE device_mac IS NOT NULL AND ts >= ? AND ts < ? "
        "GROUP BY device_mac, domain",
        (start, end),
    ):
        sid, _cat = services.lookup(r["domain"])
        if not sid or routine.is_routine(r["domain"]):
            continue   # background traffic (clock, updates, ...) is no behavior change
        m.setdefault(r["device_mac"], {}).setdefault(sid, set()).add(r["domain"])
    return m


def behavior_changes(db, recent_since: str, baseline_since: str) -> list:
    """Services a KNOWN device uses in [recent_since, now) but did NOT use in its
    baseline [baseline_since, recent_since). Devices with no baseline are skipped
    here on purpose - they surface under new_devices instead."""
    recent = _services_in_window(db, recent_since, FUTURE)
    baseline = _services_in_window(db, baseline_since, recent_since)
    names = _device_names(db)
    out = []
    for mac, svcs in recent.items():
        prior = baseline.get(mac)
        if not prior:
            continue  # no baseline -> brand-new device, not a behavior "change"
        fresh = sorted((s for s in svcs if s not in prior), key=services.service_name)
        if not fresh:
            continue
        out.append({
            "mac": mac,
            "name": names.get(mac, mac),
            "new_service_ids": fresh,          # stable ids; localize() names them
            "new_services": [services.service_name(s) for s in fresh],
            "domains": sorted({d for s in fresh for d in svcs[s]}),
        })
    out.sort(key=lambda c: c["name"])
    return out


def recent_threats(db, recent_since: str) -> list:
    """threatintel hits on EVERY distinct domain seen in the recent window (not just
    each device's top-N, so a rare low-volume beacon still gets caught)."""
    names = _device_names(db)
    table = threatintel.indicators()   # once, not per domain (it may read the feed file)
    found: dict = {}
    for r in db.execute(
        "SELECT device_mac, domain, COUNT(*) AS n FROM dns_events "
        "WHERE device_mac IS NOT NULL AND ts >= ? "
        "GROUP BY device_mac, domain",
        (recent_since,),
    ):
        hit = threatintel.match(r["domain"], table)
        if not hit:
            continue
        sev, ind = hit
        label, why = threatintel.describe(ind)
        found[(r["device_mac"], r["domain"])] = {
            "mac": r["device_mac"],
            "device": names.get(r["device_mac"], r["device_mac"]),
            "domain": r["domain"],
            "severity": sev,
            "indicator": ind,
            "label": label,
            "why": why,
            "count": r["n"],
        }
    order = {threatintel.SEV_MALICIOUS: 0, threatintel.SEV_HIGH_RISK: 1}
    return sorted(found.values(), key=lambda f: (order.get(f["severity"], 9), f["domain"]))


def visibility_alerts(db, recent_hours: float) -> list:
    """Devices that may bypass the DNS filter (an ACTIVE DoH/canary bypass) or went
    quiet in DNS while still online. Mute key: "visibility:bypass" / "visibility:quiet"."""
    res = visibility.analyze(db, hours=recent_hours)
    out = [{**b, "kind": "bypass", "ack": "visibility:bypass"} for b in res["bypass"] if b["active"]]
    out += [{**q, "kind": "quiet", "ack": "visibility:quiet"} for q in res["quiet"]]
    return out


# A bandwidth spike is deliberately hard to trigger: only a device that already moved
# SPIKE_MIN_BYTES in the recent window, has at least SPIKE_MIN_DAYS earlier days of byte
# counters, and moved >= SPIKE_RATIO x its median day AND >= SPIKE_MIN_BYTES more than it.
SPIKE_MIN_BYTES = 2_000_000_000
SPIKE_RATIO = 4.0
SPIKE_MIN_DAYS = 4
SPIKE_BASELINE_DAYS = 7


def bandwidth_spikes(db, recent_hours: float, now: datetime | None = None) -> list:
    """Devices whose bytes in the last `recent_hours` dwarf their usual day (only with a
    traffic sensor; no samples -> []). Mute key: "bandwidth:spike". Biggest first.
    Shared through netwarden.cache (the snapshot and alerts.compute both ask)."""
    if now is not None:
        return _bandwidth_spikes(db, recent_hours, now)
    now = datetime.now(timezone.utc)
    return cache.memo(db, "alerts.bandwidth_spikes", (recent_hours, _iso(now)[:16]),
                      lambda: _bandwidth_spikes(db, recent_hours, now))


def _bandwidth_spikes(db, recent_hours: float, now: datetime) -> list:
    recent = store.bandwidth_window(db, _iso(now - timedelta(hours=recent_hours)))
    names = _device_names(db)
    out = []
    for mac, bw in recent.items():
        total = (bw["rx_bytes"] or 0) + (bw["tx_bytes"] or 0)
        if mac.startswith("ip:") or total < SPIKE_MIN_BYTES:
            continue
        # A busy device that moves this much EVERY day is ruled out by the cheap lower
        # bounds (a median of lower bounds is a lower bound of the median); only the
        # rest pays for reading every sample of its week.
        floor = store.bandwidth_days_floor(db, mac, now, SPIKE_BASELINE_DAYS + 1)[1:]
        if not _is_spike(total, _median(sorted(floor))):
            continue
        days = store.bandwidth_days(db, mac, now, SPIKE_BASELINE_DAYS + 1)[1:]
        usual = sorted(d for d in days if d is not None)
        if len(usual) < SPIKE_MIN_DAYS:
            continue   # too little history to call anything unusual
        typical = _median(usual)
        if not _is_spike(total, typical):
            continue
        out.append({"mac": mac, "name": names.get(mac, mac), "ack": "bandwidth:spike",
                    "rx_bytes": bw["rx_bytes"], "tx_bytes": bw["tx_bytes"], "total": total,
                    "typical": int(typical), "ratio": round(total / max(typical, 1), 1),
                    "hours": recent_hours})
    return sorted(out, key=lambda x: -x["total"])


def _median(values: list):
    """The median of an ascending list (0 for an empty one)."""
    n = len(values)
    if not n:
        return 0
    return values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2


def _is_spike(total, typical) -> bool:
    return total >= SPIKE_RATIO * typical and total - typical >= SPIKE_MIN_BYTES


def spike_text(a: dict, lang: str) -> str:
    """One localized sentence for a bandwidth spike (dashboard, digest, offline AI)."""
    from netwarden.brain import human_bytes   # brain imports alerts
    # a whole number (>= SPIKE_RATIO by construction): no decimal separator to localize
    return i18n.t("alert.bw_spike", lang, name=a["name"], total=human_bytes(a["total"]),
                  rx=human_bytes(a["rx_bytes"]), tx=human_bytes(a["tx_bytes"]),
                  h=int(a["hours"]), typical=human_bytes(a["typical"]), ratio=round(a["ratio"]))


def compute(db, recent_hours: float = 24.0, baseline_days: float = 7.0) -> dict:
    """Assemble every alert kind over the recent-vs-baseline windows, with the user's
    acknowledged/trusted items filtered out (a trusted device goes quiet; a muted
    (device, domain) threat - or (device, "port:23") / (device, "visibility:quiet") -
    stops showing). "privacy" rides along as context for the digest; it is a summary,
    not an alert. Shared through netwarden.cache while the data is unchanged."""
    return cache.memo(db, "alerts.compute", (recent_hours, baseline_days),
                      lambda: _compute(db, recent_hours, baseline_days))


# Stage X ack keys (the inbox, inbox.py). Besides each alert's own key ("port:23", a
# threat's domain, "bedtime:3:2026-10-21", ...) and "" (trust the whole device):
NEW_KEY = "new"                 # "Got it" on a new device without trusting it
MUTE_PREFIX = "mute:"           # (mac, "mute:<kind>"): no more alerts of that kind for it
MUTE_KINDS = tuning.DEVICE_KINDS   # (tuning.py: the same rows, plus "less:" and whole types)


def change_key(c: dict) -> str:
    """The ack key of one behavior change: a later change with other services shows again."""
    return "change:" + ",".join(c.get("new_service_ids") or [])


def _setting(db, key: str) -> bool:
    """A dashboard on/off switch for an alert kind (settings.py; default on)."""
    return bool(settings.get(db, {}, key))


def unusual_hours(db, tz=None) -> list:
    """The "unusual hours" alerts before acks: off with its setting, and without the
    nights a bedtime rule already watches (one alert, not two). The device flag in the
    snapshot (brain) uses the same list, so a device is never tagged without an alert."""
    if not _setting(db, "alerts.unusual_hours"):
        return []
    night = activity.night_alerts(db, tz=tz)
    if _setting(db, "family.bedtime_alerts"):   # a rule only replaces it while bedtime alerts are on
        night = bedtime.suppress_night(db, night, tz)
    return night


def _compute(db, recent_hours: float, baseline_days: float) -> dict:
    now = datetime.now(timezone.utc)
    recent_since = _iso(now - timedelta(hours=recent_hours))
    baseline_since = _iso(now - timedelta(hours=recent_hours) - timedelta(days=baseline_days))
    acks = store.list_acks(db)
    trusted = {mac for (mac, dom) in acks if dom == ""}
    priv = privacy.analyze(db, recent_since)

    def tuned(kind: str, items: list, key=lambda a: a["ack"], device=True) -> list:
        """The items the user's acks and tuning (tuning.py: off / less sensitive, per
        device and per type) let through, each a copy with its "level" (the rule's
        sensitivity, for "Why this alert?"). Results of cached computations are never
        changed in place."""
        out = []
        for a in items:
            mac = a.get("mac") if device else None
            if mac and store.is_muted(acks, mac, key(a)):
                continue
            if not tuning.keeps(acks, kind, mac, a):
                continue
            out.append({**a, "level": tuning.level(acks, kind, mac)})
        return out

    bed_on = _setting(db, "family.bedtime_alerts")
    night = unusual_hours(db)
    bed = bedtime.alerts(db) if bed_on else []
    return {
        "generated": _iso(now),
        "window": {"recent_hours": recent_hours, "baseline_days": baseline_days},
        "new_devices": tuned("new", [d for d in new_devices(db, recent_since)
                                     if d["mac"] not in trusted and (d["mac"], NEW_KEY) not in acks],
                             device=False),
        "behavior_changes": tuned("change", [c for c in behavior_changes(db, recent_since,
                                                                         baseline_since)
                                             if c["mac"] not in trusted], key=change_key),
        "threats": tuned("threat", recent_threats(db, recent_since),
                         key=lambda t: t.get("domain", "")),
        "visibility": tuned("visibility", visibility_alerts(db, recent_hours)),
        "exposure": tuned("exposure", exposure.findings(db)),
        # a bedtime rule watching the same device + night replaces the generic alert
        "unusual_hours": tuned("night", night),
        "bedtime": tuned("bedtime", bed),
        "bandwidth_spikes": tuned("spike", bandwidth_spikes(db, recent_hours, now)),
        # a mapping to an address no device holds has no device to mute it on
        "upnp": tuned("upnp", upnp.alerts(db, recent_since)),
        # whole-network outages: acked on the pseudo device "network" ("outage:<id>")
        "outage": tuned("outage", nethealth.alerts(db, recent_since)),
        "privacy": {"home": priv["home"], "worst": privacy.worst(priv["devices"], 1)},
        "family": family_summary(db),
    }


def family_summary(db) -> dict:
    """The digest's family context: estimated screen time per person (7 days) and the
    canonical week-over-week comparison (home totals + the devices that changed most)."""
    c = weekly.compare(db)
    from netwarden import presence   # Stage P: arrivals per person - only who opted in
    pres = []
    for x in presence.snapshot(db):
        arr = [e for e in x["events_7d"] if e["kind"] == "arrive"]
        pres.append({"person": x["person"], "arrivals": len(arr),
                     "late": sum(1 for e in arr if e.get("late"))})
    return {"members": screentime.member_totals(db),
            "week": {"has_history": c["has_history"], "home": c["home"],
                     "devices": c["devices"][:5]},
            "presence": pres}


def has_alerts(result: dict) -> bool:
    return bool(result["new_devices"] or result["behavior_changes"] or result["threats"]
                or result.get("visibility") or result.get("exposure")
                or result.get("unusual_hours") or result.get("bandwidth_spikes")
                or result.get("upnp") or result.get("bedtime") or result.get("outage"))


def localize(result: dict, lang: str, names: dict | None = None) -> dict:
    """A copy of compute()'s result with service names, threat label/why, visibility
    explanations, port notes and privacy reasons in `lang`. names = naming.display_names
    (db, lang): a device named by its bare MAC gets the dashboard's name for it."""
    if names:
        result = naming.relabel(result, names)
    out = {
        **result,
        "behavior_changes": [
            {**c, "new_services": [services.service_name(s, lang)
                                   for s in c.get("new_service_ids", c["new_services"])]}
            for c in result["behavior_changes"]],
        "threats": [threatintel.localize(t, lang) for t in result["threats"]],
        "visibility": [{**v, "text": visibility.explain(v["kind"], v, lang)}
                       for v in result.get("visibility", [])],
        "exposure": [{**e, **exposure.port_info(e["port"], lang)}
                     for e in result.get("exposure", [])],
        "unusual_hours": [{**a, "text": activity.explain(a, lang)}
                          for a in result.get("unusual_hours", [])],
        "bandwidth_spikes": [{**a, "text": spike_text(a, lang)}
                             for a in result.get("bandwidth_spikes", [])],
        "upnp": [upnp.localize(m, lang) for m in result.get("upnp", [])],
        "bedtime": [bedtime.localize_hit(b, {}, lang) for b in result.get("bedtime", [])],
        "outage": [nethealth.localize_outage(o, lang) for o in result.get("outage", [])],
    }
    # Stage Q: "Why this alert?" - the rule, the data points and the threshold, per alert
    # ("explain": a threat's "why" is already the threat list's own reason text)
    from netwarden import explain
    for section, kind in explain.SECTIONS.items():
        out[section] = [{**a, "explain": explain.explain(kind, a, lang, result.get("window"))}
                        for a in out.get(section) or []]
    if "privacy" in result:
        p = result["privacy"]
        out["privacy"] = {"home": {**p["home"], "line": privacy.home_line(p["home"], lang)},
                          "worst": [{**w, "reason": privacy.reason(w, lang)} for w in p["worst"]]}
    if result.get("family"):
        out["family"] = localize_family(result["family"], lang)
    return out


def localize_family(fam: dict, lang: str) -> dict:
    """family_summary() with plain-language highlights and one line per person."""
    if "highlights" in fam:            # already localized
        return fam
    sep = i18n.t("list_sep", lang)
    members = [{**m, "top_services": [services.service_name(s, lang) for s in m["top"]],
                "text": i18n.t("digest.family_member", lang, owner=m["owner"],
                               dur=screentime.duration(m["minutes"], lang),
                               services=sep.join(services.service_name(s, lang) for s in m["top"])
                               or "—")}
               for m in fam["members"]]
    pres = [{**x, "text": i18n.t("digest.presence_line", lang, person=x["person"],
                                 n=x["arrivals"], late=x["late"])}
            for x in fam.get("presence") or []]
    return {**fam, "members": members, "presence": pres,
            "highlights": weekly.highlights(fam["week"], lang, 3)}


def render_digest(result: dict, lang: str = i18n.DEFAULT, names: dict | None = None) -> str:
    """A plain-language weekly digest (default 繁體中文). Deterministic; no LLM involved.
    names: naming.display_names(db, lang), so nameless devices are not named by MAC."""
    lang = i18n.normalize(lang)
    tr = lambda key, **kw: i18n.t("digest." + key, lang, **kw)  # noqa: E731
    result = localize(result, lang, names)
    nd, bc, th = result["new_devices"], result["behavior_changes"], result["threats"]
    vis, exp = result.get("visibility", []), result.get("exposure", [])
    w = result["window"]
    lines = [tr("title"),
             tr("window", h=int(w["recent_hours"]), d=int(w["baseline_days"])),
             ""]
    if not has_alerts(result):
        lines.append(tr("all_clear"))
        priv = _privacy_lines(result, tr)
        if priv:
            lines += [""] + priv
        fam = _family_lines(result, tr)
        if fam:
            lines += [""] + fam
        return "\n".join(lines)

    if exp:
        lines.append(tr("exposure"))
        for e in exp:
            lines.append("  • " + tr("exposure_line", name=e["name"], ip=e["ip"], port=e["port"],
                                     service=e["service"], risk=e["risk_name"],
                                     new=tr("new_flag") if e["new"] else ""))
            lines.append(f"      {e['note']}")
        lines.append("")

    outs = result.get("outage", [])
    if outs:
        lines.append(tr("outages"))
        lines += ["  • " + o["text"] for o in outs]
        lines.append("")

    ports = result.get("upnp", [])
    if ports:
        lines.append(tr("upnp"))
        lines += ["  • " + m["text"] for m in ports]
        lines.append("      " + i18n.t("upnp.howto", lang))
        lines.append("")

    if th:
        lines.append(tr("threats"))
        for t in th:
            tag = threatintel.severity_tag(t["severity"], lang)
            lines.append("  " + tr("threat_line", tag=tag, device=t["device"],
                                   domain=t["domain"], label=t["label"], count=t["count"]))
            lines.append(f"      {t['why']}")
        lines.append("")

    if nd:
        lines.append(tr("new_devices"))
        for d in nd:
            info = [d["vendor"]] if d["vendor"] else []
            info += [f"IP {d['ip']}", tr("first_seen", when=_short(d["first_seen"]))]
            lines.append("  • " + tr("device_line", name=d["name"],
                                     info=tr("sep").join(info)))
        lines.append("")

    if bc:
        lines.append(tr("changes"))
        for c in bc:
            lines.append("  • " + tr("change_line", name=c["name"],
                                     services=i18n.t("list_sep", lang).join(c["new_services"])))
        lines.append("")

    night = result.get("unusual_hours", [])
    if night:
        lines.append(tr("unusual_hours"))
        lines += ["  • " + a["text"] for a in night]
        lines.append("")

    bed = result.get("bedtime", [])
    if bed:
        lines.append(tr("bedtime"))
        lines += ["  • " + b["text"] for b in bed]
        lines.append("")

    spikes = result.get("bandwidth_spikes", [])
    if spikes:
        lines.append(tr("bandwidth_spikes"))
        lines += ["  • " + a["text"] for a in spikes]
        lines.append("")

    if vis:
        lines.append(tr("visibility"))
        lines += ["  • " + v["text"] for v in vis]
        lines.append("")

    priv = _privacy_lines(result, tr)
    if priv:
        lines += priv + [""]

    fam = _family_lines(result, tr)
    if fam:
        lines += fam + [""]

    lines.append(tr("footer"))
    return "\n".join(lines).rstrip()


def _family_lines(result: dict, tr) -> list:
    """The digest's short family section: this week vs last week + estimated screen time
    per person. `result` must already be localized. Nothing without any screen time."""
    f = result.get("family")
    if not f or not (f.get("members") or f["week"]["home"]["minutes"]["this"]):
        return []
    lines = [tr("family")]
    lines += ["  " + h for h in f.get("highlights", [])]
    lines += ["  • " + m["text"] for m in f.get("members", [])]
    lines += ["  • " + x["text"] for x in f.get("presence") or [] if "text" in x]
    lines.append("  " + tr("family_note"))
    return lines


def _privacy_lines(result: dict, tr) -> list:
    """The digest's short privacy section: home summary + the most-tracked device.
    `result` must already be localized. Nothing when no tracker was looked up."""
    p = result.get("privacy")
    if not p or not p["home"]["tracker_queries"]:
        return []
    lines = [tr("privacy"), "  " + p["home"]["line"]]
    for wd in p["worst"]:
        lines.append("  " + tr("privacy_worst", name=wd["name"], grade=wd["grade"],
                               reason=wd["reason"]))
    return lines


def digest_language(db) -> str:
    """The weekly digest's language without --lang: the ui.language setting (env
    NETWARDEN_LANG > the dashboard setting > zh-Hant), like the dashboard's."""
    from netwarden import brain, settings   # lazy: brain imports alerts
    return settings.get(db, brain.load_env(), "ui.language")


def main(argv=None, prog=None) -> int:
    ap = argparse.ArgumentParser(prog=prog, description="netwarden proactive alerts / weekly digest.")
    ap.add_argument("--db", default=str(store.DEFAULT_DB))
    ap.add_argument("--hours", type=float, default=24.0, help="recent window, hours")
    ap.add_argument("--baseline-days", type=float, default=7.0, help="baseline window, days")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--lang", default=None,
                    help=f"digest language code (default: the language setting, else "
                         f"{i18n.DEFAULT}); one of " + ", ".join(i18n.CODES))
    args = ap.parse_args(argv)

    try:
        db = store.connect(args.db)
    except store.DBError as e:   # Stage K: the cron mail says what is wrong, not a traceback
        from netwarden import web   # lazy: web imports alerts
        print(web.db_problem_text(e, i18n.normalize(args.lang)), file=sys.stderr)
        return 2
    lang = i18n.normalize(args.lang or digest_language(db))
    result = compute(db, recent_hours=args.hours, baseline_days=args.baseline_days)
    names = naming.display_names(db, lang)
    if args.json:
        print(json.dumps(localize(result, lang, names), ensure_ascii=False, indent=2))
    else:
        print(render_digest(result, lang, names))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
