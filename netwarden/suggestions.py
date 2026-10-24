#!/usr/bin/env python3
"""
netwarden - suggestions.py: the suggestion center - "what could I do next?"

Every module already knows what is wrong in its corner (an open Telnet port, a router
forwarding a camera to the internet, a phone using its own DNS-over-HTTPS resolver,
trackers that got through, unnamed devices, repeated outages, ...). This module turns
those findings into ONE list of actionable suggestions, each with

  id         stable across runs ("port:<mac>:23", "upnp:TCP:554", "trackers", ...)
  severity   high | medium | low          pillar  security | privacy | health | tidiness | family
  why        plain language                steps   per platform (AdGuard Home / Pi-hole /
                                                  router / the device / netwarden / the ISP)
  rules      copyable filter rules (AdGuard + Pi-hole) where blocking helps
  status     open | done | dismissed | snoozed (the user's own notes, suggestion_state)

and notices when one TOOK EFFECT, from the data alone: the domain is now blocked in the
recent DNS events, the port is closed in the latest check, the UPnP mapping is gone, the
device got a name, a bedtime rule now covers the device, redaction is on.

Nothing here changes anything: no rule is ever applied, no router touched. "Done" only
records that the user did it by hand; whether it worked is read from the data.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from netwarden import (activity, bedtime, brain, cache, exposure, i18n, naming, nethealth,
                       privacy, store, upnp, visibility)

SEVERITIES = ("high", "medium", "low")
PILLARS = ("security", "privacy", "health", "tidiness")
STATUSES = ("open", "done", "dismissed", "snoozed")
ID_RE = re.compile(r"^[a-z_]+(?::[A-Za-z0-9._:-]{1,190})?$")
MAX_ID = 200
SNOOZE_DAYS = (1, 90)
EFFECT_DAYS = 30           # "took effect" items stay on the Done list this long
OUTAGE_REPEAT = 2          # outages of one cause in 7 days before "repeated outages"
PERSONAL_TYPES = ("phone", "tablet", "computer", "console")   # bedtime candidates
TIDY_TYPES = ("phone", "tablet", "computer", "console", "tv", "streaming", "wearable")

# kind -> (platforms with steps, pillar). Steps live in the locales as
# sug.<kind>.steps.<platform> (one step per line).
KINDS = {
    "port": (("device", "router"), "security"),
    "upnp": (("router", "device"), "security"),
    "threat": (("adguard", "pihole", "device"), "security"),
    "doh": (("adguard", "pihole", "device"), "security"),
    "trackers": (("adguard", "pihole"), "privacy"),
    "blocklist": (("adguard", "pihole"), "privacy"),
    "ai_redact": (("netwarden",), "privacy"),
    "outages_isp": (("isp", "router"), "health"),
    "outages_router": (("router",), "health"),
    "names": (("netwarden",), "tidiness"),
    "owners": (("netwarden",), "tidiness"),
    "bedtime": (("netwarden", "device"), "family"),
    # Stage Q: router and network hygiene (hygiene.py) - only what no kind above covers
    "upnp_stale": (("router",), "security"),
    "firmware": (("router",), "security"),
    "iot_net": (("router", "device"), "privacy"),
}


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def kind_of(sid: str) -> str:
    return sid.split(":", 1)[0]


def valid_id(sid) -> bool:
    return isinstance(sid, str) and len(sid) <= MAX_ID and bool(ID_RE.match(sid)) \
        and kind_of(sid) in KINDS


def _item(sid: str, severity: str, params: dict | None = None, devices=(), rules=None,
          copy: str | None = None, evidence: dict | None = None) -> dict:
    kind = kind_of(sid)
    return {"id": sid, "kind": kind, "pillar": KINDS[kind][1], "severity": severity,
            "params": params or {}, "devices": list(devices), "rules": rules,
            "copy": copy, "evidence": evidence or {}}


def _blocked_after(db, mac: str | None, domains: list, since: str) -> tuple[bool, str | None]:
    """Lookups of `domains` (and their subdomains) by `mac` since `since`: (still open?,
    when blocking took effect). Open = for SOME looked-up domain, its newest lookup got
    through. Took effect = per domain, the first blocked lookup after its last one that
    got through; the latest of those (the moment the last one was blocked)."""
    who = "device_mac = ? AND " if mac else ""
    pre = [mac] if mac else []
    effects = []
    for d in domains:   # each domain on its own: one blocked name must not hide another
        args = [d, "%." + d]
        rows = db.execute(f"""SELECT MAX(CASE WHEN blocked = 0 THEN ts END) AS last_open,
                                     MAX(ts) AS last
                              FROM dns_events WHERE {who}ts >= ? AND (domain = ? OR domain LIKE ?)""",
                          pre + [since] + args).fetchone()
        if not rows["last"]:
            continue                            # not looked up: says nothing either way
        if rows["last_open"] and rows["last_open"] >= rows["last"]:
            return True, None                   # this one still gets through
        effects.append(db.execute(f"""SELECT MIN(ts) FROM dns_events WHERE {who}ts > ?
                                      AND blocked = 1 AND (domain = ? OR domain LIKE ?)""",
                                  pre + [rows["last_open"] or since] + args).fetchone()[0])
    if not effects:
        return True, None                       # no lookups at all: nothing to tell yet
    return False, max(e for e in effects if e) if any(effects) else None


# --- detectors: each returns (active items, resolved items) --------------------------
# A resolved item = {id, effect_ts, devices, params}: the problem it was about is gone,
# and the data says when.

def _ports(db, ctx) -> tuple:
    active, resolved = [], []
    names = ctx["names"]
    for f in exposure.findings(db):
        if f["risk"] not in exposure.RISKY:
            continue
        sid = f"port:{f['mac']}:{f['port']}"
        active.append(_item(sid, "high" if f["risk"] == "high" else "medium",
                            {"name": f["name"], "port": f["port"], "service": f["service"],
                             "ip": f["ip"]},
                            devices=[{"mac": f["mac"], "name": f["name"]}],
                            evidence={"checked_ts": f["checked_ts"]}))
    for mac in store.checked_macs(db):
        hist = store.port_check_history(db, mac, limit=6)
        if len(hist) < 2 or hist[0]["ts"] < ctx["effect_since"]:
            continue
        for port, is_open in hist[0]["ports"].items():
            if is_open or exposure.PORTS.get(port, ("", "low"))[1] not in exposure.RISKY:
                continue
            # closed now; when was it last open, and which check first found it closed?
            closed_at = hist[0]["ts"]
            for h in hist[1:]:
                if h["ports"].get(port):
                    resolved.append({"id": f"port:{mac}:{port}", "effect_ts": closed_at,
                                     "params": {"name": names.get(mac, mac), "port": port,
                                                "service": exposure.PORTS[port][0], "ip": h["ip"]},
                                     "devices": [{"mac": mac, "name": names.get(mac, mac)}]})
                    break
                closed_at = h["ts"]
    return active, resolved


def _upnp(db, ctx) -> tuple:
    active = []
    for m in upnp.mappings(db):
        if not m["risky"]:
            continue
        sid = f"upnp:{m['protocol']}:{m['external_port']}"
        active.append(_item(sid, "high", {"name": m["name"], "proto": m["protocol"],
                                          "ext": m["external_port"], "port": m["internal_port"],
                                          "service": m["service"], "ip": m["internal_client"]},
                            devices=[{"mac": m["mac"], "name": m["name"]}] if m["mac"] else []))
    resolved = []
    cur = {a["id"] for a in active}
    for r in db.execute("""SELECT protocol, external_port, internal_client, internal_port, mac,
                                  MAX(last_seen) AS last_seen FROM upnp_mappings
                           WHERE last_seen >= ? GROUP BY protocol, external_port""",
                        (ctx["effect_since"],)):
        sid = f"upnp:{r['protocol']}:{r['external_port']}"
        if sid in cur or upnp.risky_port(dict(r)) is None:
            continue
        gone = db.execute("SELECT MIN(ts) FROM upnp_snapshots WHERE available = 1 AND ts > ?",
                          (r["last_seen"],)).fetchone()[0]
        if gone:
            name = ctx["names"].get(r["mac"], r["internal_client"]) if r["mac"] else r["internal_client"]
            resolved.append({"id": sid, "effect_ts": gone,
                             "params": {"name": name, "proto": r["protocol"],
                                        "ext": r["external_port"], "port": r["internal_port"],
                                        "service": upnp.RISKY_PORTS.get(upnp.risky_port(dict(r)), ""),
                                        "ip": r["internal_client"]},
                             "devices": [{"mac": r["mac"], "name": name}] if r["mac"] else []})
    return active, resolved


def _rules_for(domains: list) -> dict:
    doms = sorted({d for d in domains if privacy.rule_safe(d)})
    return {"adguard": "\n".join(f"||{d}^" for d in doms), "pihole": "\n".join(doms)}


def _threats(db, ctx) -> tuple:
    from netwarden import alerts   # alerts imports this module's neighbours; keep it lazy
    week = ctx["week_since"]
    per: dict = {}
    for t in alerts.recent_threats(db, week):
        per.setdefault(t["mac"], []).append(t)
    active, resolved = [], []
    for mac, hits in per.items():
        doms = sorted({t["domain"] for t in hits})
        still, effect = _blocked_after(db, mac, doms, week)
        name = ctx["names"].get(mac, mac)
        sev = "high" if any(t["severity"] == "malicious" for t in hits) else "medium"
        params = {"name": name, "domains": i18n.t("list_sep", ctx["lang"]).join(doms[:3]),
                  "n": len(doms)}
        if still:
            active.append(_item(f"threat:{mac}", sev, params,
                                devices=[{"mac": mac, "name": name}], rules=_rules_for(doms)))
        elif effect:
            resolved.append({"id": f"threat:{mac}", "effect_ts": effect, "params": params,
                             "devices": [{"mac": mac, "name": name}]})
    return active, resolved


def _doh(db, ctx) -> tuple:
    res = visibility.analyze(db, hours=24)
    active, resolved = [], []
    for b in res["bypass"]:
        doms = sorted({x["domain"] for x in b["resolvers"]})
        name = b["name"]
        params = {"name": name, "resolvers": i18n.t("list_sep", ctx["lang"]).join(doms[:3])
                  or visibility.CANARY}
        if b["active"]:
            rules = visibility.rules({"bypass": [b]})
            active.append(_item(f"doh:{b['mac']}", "medium", params,
                                devices=[{"mac": b["mac"], "name": name}], rules=rules))
        else:
            still, effect = _blocked_after(db, b["mac"], doms, ctx["day_since"])
            if not still and effect:
                resolved.append({"id": f"doh:{b['mac']}", "effect_ts": effect, "params": params,
                                 "devices": [{"mac": b["mac"], "name": name}]})
    return active, resolved


def _privacy(db, ctx) -> tuple:
    priv = privacy.analyze(db, ctx["day_since"])
    home = priv["home"]
    active = []
    if home["tracker_queries"]:
        rules = privacy.block_rules(priv["_entries"])
        if rules["count"] and home["grade"] != "A":
            sev = "medium" if home["grade"] in "DF" else "low"
            active.append(_item("trackers", sev, {"n": rules["count"], "grade": home["grade"],
                                                  "pct": round(100 * home["blocked_share"])},
                                rules={"adguard": rules["adguard"], "pihole": rules["pihole"]},
                                evidence={"entries": [e["entry"] for e in priv["_entries"]
                                                      if e["count"] > e["blocked"]][:40]}))
        if home["grade"] in "DF" and home["blocked_share"] < 0.2:
            active.append(_item("blocklist", "medium", {"grade": home["grade"],
                                                        "pct": round(100 * home["blocked_share"])}))
    ctx["privacy_home"] = home
    return active, []


def _ai(db, ctx) -> tuple:
    ai = ctx["ai"]
    if ai["mode"] != "offline" and ai["destination"] == "cloud" and not ai["redact"]:
        return [_item("ai_redact", "medium", {"provider": ai["provider"]})], []
    r = db.execute("SELECT updated_at FROM settings WHERE key = 'ai.redact'").fetchone()
    if ai["redact"] and ai["destination"] == "cloud" and r and r[0] >= ctx["effect_since"]:
        return [], [{"id": "ai_redact", "effect_ts": r[0], "params": {"provider": ai["provider"]},
                     "devices": []}]
    return [], []


def _outages(db, ctx) -> tuple:
    h = nethealth.compute(db)
    ctx["health"] = h
    active = []
    for cause, sid in (("isp", "outages_isp"), ("router", "outages_router")):
        outs = [o for o in h["outages_7d"] if o["cause"] == cause]
        if len(outs) >= OUTAGE_REPEAT:
            log = "\n".join(nethealth.outage_text(o, ctx["lang"]) for o in outs[:10])
            active.append(_item(sid, "medium" if len(outs) >= 3 else "low",
                                {"n": len(outs), "minutes": sum(o["minutes"] for o in outs)},
                                copy=log))
    return active, []


def _recent_devices(db, ctx) -> list:
    return [dict(r) for r in db.execute(
        "SELECT mac, hostname, vendor, is_self FROM devices WHERE last_seen >= ? ORDER BY mac",
        (ctx["week_since"],))]


def _tidiness(db, ctx) -> tuple:
    from netwarden import devicetype
    devs = _recent_devices(db, ctx)
    labels, profiles = store.get_labels(db), store.get_profiles(db)
    announced = store.identity_names(db)
    types = {m: r["type"] for m, r in devicetype.classify_all(db).items()}
    ctx["device_count"] = len(devs)
    unnamed = [d for d in devs if not d["is_self"] and d["mac"] not in labels
               and not d["hostname"] and not announced.get(d["mac"])]
    ctx["unnamed"] = len(unnamed)
    personal = [d for d in devs if not d["is_self"] and types.get(d["mac"]) in TIDY_TYPES]
    nobody = [d for d in personal
              if not (profiles.get(d["mac"]) or {}).get("owner")
              and not (profiles.get(d["mac"]) or {}).get("room")]
    ctx["personal"], ctx["nobody"] = len(personal), len(nobody)
    names = ctx["names"]
    active, resolved = [], []
    if unnamed:
        active.append(_item("names", "low", {"n": len(unnamed)},
                            devices=[{"mac": d["mac"], "name": names.get(d["mac"], d["mac"])}
                                     for d in unnamed[:20]]))
    else:
        r = db.execute("SELECT MAX(updated_at) FROM device_labels").fetchone()[0]
        if r and r >= ctx["effect_since"]:
            resolved.append({"id": "names", "effect_ts": r, "params": {"n": 0}, "devices": []})
    if nobody:
        active.append(_item("owners", "low", {"n": len(nobody)},
                            devices=[{"mac": d["mac"], "name": names.get(d["mac"], d["mac"])}
                                     for d in nobody[:20]]))
    elif personal:
        r = db.execute("SELECT MAX(updated_at) FROM device_profiles").fetchone()[0]
        if r and r >= ctx["effect_since"]:
            resolved.append({"id": "owners", "effect_ts": r, "params": {"n": 0}, "devices": []})
    return active, resolved


def _bedtime(db, ctx) -> tuple:
    profiles = store.get_profiles(db)
    raw = activity.night_alerts(db)
    left = {a["mac"] for a in bedtime.suppress_night(db, raw)}
    rules = store.bedtime_rules(db)
    active, resolved = [], []
    for a in raw:
        owner = (profiles.get(a["mac"]) or {}).get("owner")
        if not owner or a["type"] not in PERSONAL_TYPES:
            continue
        params = {"name": a["name"], "owner": owner, "window": a["window"]}
        dev = [{"mac": a["mac"], "name": a["name"]}]
        if a["mac"] in left:
            active.append(_item(f"bedtime:{a['mac']}", "medium", params, devices=dev))
        else:
            ts = max((r["created_at"] for r in rules if r["enabled"]
                      and (r["mac"] == a["mac"] or (r["owner"] and r["owner"] == owner))),
                     default=None)
            if ts:
                resolved.append({"id": f"bedtime:{a['mac']}", "effect_ts": ts, "params": params,
                                 "devices": dev})
    return active, resolved


def _hygiene(db, ctx) -> tuple:
    """Stage Q: the hygiene card's findings that no other detector covers. Risky UPnP
    ports, open ports and DoH stay with _upnp / _ports / _doh (counted once)."""
    from netwarden import hygiene
    f = hygiene.facts(db)
    sep = i18n.t("list_sep", ctx["lang"])
    active = []
    if f["upnp_stale"]:
        s = f["upnp_stale"]
        active.append(_item("upnp_stale", "medium",
                            {"n": len(s), "ports": sep.join(f"{x['proto']} {x['ext']} → {x['ip']}"
                                                            for x in s[:4])},
                            devices=[{"mac": x["mac"], "name": x["name"]} for x in s if x["mac"]]))
    if f["router"]["model"]:
        active.append(_item("firmware", "low", {"model": f["router"]["model"]}))
    if f["iot"]:
        active.append(_item("iot_net", "low",
                            {"n": len(f["iot"]), "names": sep.join(x["name"] for x in f["iot"][:4])},
                            devices=[{"mac": x["mac"], "name": x["name"]} for x in f["iot"][:20]]))
    return active, []


DETECTORS = (_ports, _upnp, _threats, _doh, _privacy, _ai, _outages, _tidiness, _bedtime,
             _hygiene)


# --- putting it together ----------------------------------------------------------------

def detect(db, env: dict | None = None) -> dict:
    """Canonical (unlocalized) suggestions, shared through netwarden.cache:
    {active: [...], resolved: [...], context: {...}} - no user status applied yet."""
    ai = brain.ai_config(env or {}, db)
    key = (ai["mode"], ai["destination"], bool(ai["redact"]))
    return cache.memo(db, "suggestions.detect", key, lambda: _detect(db, ai))


def _detect(db, ai: dict) -> dict:
    now = datetime.now(timezone.utc)
    ctx = {"names": store.device_names(db), "ai": {k: ai[k] for k in
                                                   ("mode", "destination", "redact", "provider")},
           "lang": "en", "day_since": _iso(now - timedelta(hours=24)),
           "week_since": _iso(now - timedelta(days=7)),
           "effect_since": _iso(now - timedelta(days=EFFECT_DAYS))}
    active, resolved = [], []
    for fn in DETECTORS:
        a, r = fn(db, ctx)
        active += a
        resolved += r
    seen = {a["id"] for a in active}
    resolved = [r for r in resolved if r["id"] not in seen]
    sev = {s: i for i, s in enumerate(SEVERITIES)}
    active.sort(key=lambda a: (sev[a["severity"]], PILLARS.index(a["pillar"])
                               if a["pillar"] in PILLARS else 9, a["id"]))
    context = {k: ctx.get(k) for k in ("device_count", "unnamed", "personal", "nobody")}
    context["privacy_home"] = {k: ctx["privacy_home"][k] for k in
                               ("grade", "queries", "tracker_queries", "blocked_share")} \
        if ctx.get("privacy_home") else None
    return {"generated": _iso(now), "active": active, "resolved": resolved,
            "context": context}


def _snoozed(st: dict, now_iso: str) -> bool:
    return st["status"] == "snoozed" and (st.get("until") or "") > now_iso


# Resolved items whose evidence ("some label / owner changed lately") does not prove the
# suggestion was ever shown: listed as done only once the user has acted on them.
NEEDS_HISTORY = ("names", "owners")


def with_status(det: dict, states: dict, now: datetime | None = None) -> dict:
    """Apply the user's notes: {open, done, dismissed, snoozed} lists (canonical)."""
    now_iso = _iso(now or datetime.now(timezone.utc))
    out = {"open": [], "done": [], "dismissed": [], "snoozed": []}
    resolved = {r["id"]: r for r in det["resolved"]}
    for a in det["active"]:
        st = states.get(a["id"])
        if not st or (st["status"] == "snoozed" and not _snoozed(st, now_iso)):
            out["open"].append({**a, "status": "open"})
        elif st["status"] == "done":   # the user did it; the data does not show it yet
            out["done"].append({**a, "status": "done", "waiting": True,
                                "marked_ts": st["updated_at"], "effect_ts": None})
        else:
            out[st["status"]].append({**a, "status": st["status"], "until": st.get("until"),
                                      "marked_ts": st["updated_at"]})
    active_ids = {a["id"] for a in det["active"]}
    for sid, r in resolved.items():
        st = states.get(sid) or {}
        if sid in NEEDS_HISTORY and not st:
            continue   # nothing shows it was ever suggested: no "took effect" for it
        out["done"].append({**_item(sid, "low", r["params"], r["devices"]), "status": "done",
                            "waiting": False, "effect_ts": r["effect_ts"],
                            "marked_ts": st.get("updated_at") if st.get("status") == "done" else None,
                            "auto": st.get("status") != "done"})
    # marked done, no longer found, and no evidence of when: resolved, date unknown
    for sid, st in states.items():
        if st["status"] == "done" and sid not in active_ids and sid not in resolved \
                and valid_id(sid):
            data = st.get("data") or {}
            out["done"].append({**_item(sid, data.get("severity") or "low", data.get("params") or {},
                                        data.get("devices") or []),
                                "status": "done", "waiting": False, "effect_ts": None,
                                "marked_ts": st["updated_at"], "auto": False})
    out["done"].sort(key=lambda d: (d["waiting"] is False, d.get("effect_ts") or d.get("marked_ts")
                                    or ""), reverse=True)
    return out


def tracker_effect(db, st: dict) -> str | None:
    """For a "trackers" suggestion marked done: when the first of the trackers it listed
    showed up blocked after the user marked it."""
    entries = [e for e in ((st.get("data") or {}).get("entries") or []) if privacy.rule_safe(e)]
    if not entries:
        return None
    entries = entries[:20]
    cond = " OR ".join(["domain = ? OR domain LIKE ?"] * len(entries))
    args = [x for e in entries for x in (e, "%." + e)]
    return db.execute(f"SELECT MIN(ts) FROM dns_events WHERE blocked = 1 AND ts >= ? AND ({cond})",
                      [st["updated_at"]] + args).fetchone()[0]


# --- localized text -------------------------------------------------------------------

def _params_text(params: dict, lang: str) -> dict:
    out = dict(params)
    if "service" in out and not out["service"]:
        out["service"] = "?"
    return out


def localize(item: dict, lang: str, names: dict | None = None) -> dict:
    """One suggestion in `lang`. names (naming.display_names): a device the canonical
    text names by its bare MAC gets its display name instead."""
    kind = item["kind"]
    p = _params_text(item["params"], lang)
    if names:
        item = naming.relabel(item, names)
        if p.get("name") in names:
            p["name"] = names[p["name"]]
    steps = {}
    for plat in KINDS[kind][0]:
        text = i18n.t(f"sug.{kind}.steps.{plat}", lang, **p)
        steps[plat] = [s.strip() for s in text.split("\n") if s.strip()]
    def text(part):
        # a count: the language's own singular rule ("1 device", ru "21 устройство")
        key = f"sug.{kind}.{part}"
        if "n" not in p:
            return i18n.t(key, lang, **p)
        return i18n.tn(key, p["n"], lang, **{k: v for k, v in p.items() if k != "n"})
    return {**item, "title": text("title"),
            "why": text("why"),
            "done_title": i18n.t(f"sug.{kind}.done", lang, **p),
            "platforms": [{"key": plat, "name": i18n.t("sug.platform." + plat, lang),
                           "steps": steps[plat]} for plat in KINDS[kind][0]],
            "severity_name": i18n.t("sug.sev." + item["severity"], lang),
            "pillar_name": i18n.t("sug.pillar." + item["pillar"], lang)}


def localize_many(items: list, lang: str, names: dict | None = None) -> list:
    return [localize(i, lang, names) for i in items]


def report(db, lang: str = i18n.DEFAULT, env: dict | None = None) -> dict:
    """GET /api/suggestions."""
    from netwarden import score
    lang = i18n.normalize(lang)
    det = detect(db, env)
    states = store.suggestion_states(db)
    lists = with_status(det, states)
    for d in lists["done"]:             # trackers: the effect is read from the stored list
        if d["id"] == "trackers" and d.get("waiting"):
            ts = tracker_effect(db, states.get("trackers") or {})
            if ts:
                d.update(waiting=False, effect_ts=ts)
    gains = score.gains(db, env, det)
    names = naming.display_names(db, lang)
    out = {}
    for name, items in lists.items():
        out[name] = [{**localize(i, lang, names), "points": gains.get(i["id"], 0)} for i in items]
    # the list and "Next best steps" share one order: worst first, then the biggest gain
    out["open"].sort(key=lambda i: (SEVERITIES.index(i["severity"]), -i["points"]))
    top = out["open"][:3]
    return {**out, "top": top, "counts": {k: len(v) for k, v in out.items()},
            "generated": det["generated"], "demo": store.is_demo(db),
            "note": i18n.t("sug.note", lang)}


def check_status(db, sid: str, status: str, days: int | None = None,
                 env: dict | None = None) -> tuple:
    """Validate a decision WITHOUT writing it: (sid, status, until, data) for
    write_status(), or ValueError (bad input) / LookupError (no such suggestion). Only
    ids that exist right now (or that the user marked before) can be marked."""
    if not valid_id(sid):
        raise ValueError("bad_id")
    if not isinstance(status, str) or status not in STATUSES:
        raise ValueError("bad_status")
    states = store.suggestion_states(db)
    det = detect(db, env)
    item = next((a for a in det["active"] if a["id"] == sid), None) or \
        next((r for r in det["resolved"] if r["id"] == sid), None)
    if item is None and sid not in states:
        raise LookupError(sid)
    until = None
    if status == "snoozed":
        try:
            days = int(days if days is not None else 7)
        except (TypeError, ValueError):
            raise ValueError("bad_days") from None
        if not SNOOZE_DAYS[0] <= days <= SNOOZE_DAYS[1]:
            raise ValueError("bad_days")
        until = _iso(datetime.now(timezone.utc) + timedelta(days=days))
    data = None
    if item is not None and status != "open":   # remember what it was about (for "Done")
        data = {"severity": item.get("severity"), "params": item.get("params"),
                "devices": item.get("devices")}
        if sid == "trackers":
            data["entries"] = (item.get("evidence") or {}).get("entries") or []
    return sid, status, until, data


def write_status(db, checked: tuple) -> None:
    """Store a decision check_status() accepted."""
    store.set_suggestion_state(db, *checked)


def set_status(db, sid: str, status: str, days: int | None = None, env: dict | None = None) -> None:
    """POST /api/suggestions/<id>: record the user's decision (see check_status)."""
    write_status(db, check_status(db, sid, status, days, env))


def open_count(db, env: dict | None = None) -> int:
    det = detect(db, env)
    return len(with_status(det, store.suggestion_states(db))["open"])
