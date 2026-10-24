#!/usr/bin/env python3
"""
netwarden - timeline.py: one device's story, newest first.

Built from what the store already holds (no LLM, read-only):

  first_seen       when discovery / DNS first saw the device
  new_service      the first lookup of a service the device had not used in its first
                   day (its "normal" start), and likewise new_domain for unknown domains
  threat           the first contact with a malicious / high-risk domain
  unusual_hours    night activity although the device is normally idle (activity.py)
  bandwidth_spike  an hour (or a run of hours) with far more bytes than usual - only
                   when the optional traffic sensor (ntopng) is configured
  open_port        a risky / newly opened port from the user's last opt-in check
  upnp_mapping     the device asked the router (UPnP) to forward a port from the internet
  identified       it first announced its model / name on the LAN (mDNS / SSDP)
  (routine background lookups - clock, updates, CDNs - never count as "new")
  user_*           the user's own actions that carry a timestamp: trust, mute, rename,
                   type/owner/room edits

Each item: {ts (UTC ISO), when (local "YYYY-MM-DD HH:MM"), kind, text (localized), ...}.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo

from netwarden import (activity, bedtime, exposure, i18n, routine, services, store, threatintel,
                       tuning, upnp)

NEW_AFTER_HOURS = 24      # services first used this long after the device's first lookup
MAX_NEW_DOMAINS = 10
MAX_ITEMS = 60
SPIKE_DAYS = 7
SPIKE_FACTOR = 3          # an hour above 3 x the device's 90th-percentile hour ...
SPIKE_MIN_BYTES = 1e9     # ... and above 1 GB is a spike


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _domains(db, mac: str) -> list:
    """Every domain the device ever looked up: rows (domain, first, n)."""
    return db.execute("""SELECT domain, MIN(ts) AS first, COUNT(*) AS n FROM dns_events
                         WHERE device_mac = ? GROUP BY domain""", (mac,)).fetchall()


def _new_lookups(db, mac: str, rows: list | None = None) -> tuple[list, list]:
    """(new services, new unknown domains) for the device: [(first_ts, id/domain, n)]."""
    rows = _domains(db, mac) if rows is None else rows
    if not rows:
        return [], []
    start = min(r["first"] for r in rows)
    cutoff = _iso(datetime.strptime(start, "%Y-%m-%dT%H:%M:%S.%fZ")
                  + timedelta(hours=NEW_AFTER_HOURS))
    svc: dict = {}
    unknown = []
    for r in rows:
        if routine.is_routine(r["domain"]):
            continue    # the clock, updates, CDNs ...: background traffic, never "new"
        sid, _cat = services.lookup(r["domain"])
        if sid:
            first, n = svc.get(sid, (r["first"], 0))
            svc[sid] = (min(first, r["first"]), n + r["n"])
        elif r["first"] >= cutoff:
            unknown.append((r["first"], r["domain"], r["n"]))
    new_svc = [(first, sid, n) for sid, (first, n) in svc.items() if first >= cutoff]
    unknown.sort(reverse=True)
    return new_svc, unknown[:MAX_NEW_DOMAINS]


def _threats(db, mac: str, rows: list | None = None) -> list:
    indicators = threatintel.indicators()
    out = []
    for r in (_domains(db, mac) if rows is None else rows):
        hit = threatintel.match(r["domain"], indicators)
        if hit:
            out.append((r["first"], r["domain"], r["n"], hit))
    return out


def bandwidth_spikes(db, mac: str, now: datetime | None = None) -> list:
    """Runs of hours whose bytes (rx+tx) far exceed the device's usual hour:
    [{ts, hours, bytes, typical}] (typical = its median busy hour)."""
    now = now or datetime.now(timezone.utc)
    rows = db.execute("""SELECT mac AS key, ip, ts, rx_bytes, tx_bytes FROM traffic_samples
                         WHERE mac = ? AND ts >= ? ORDER BY ip, ts, rowid""",
                      (mac, _iso(now - timedelta(days=SPIKE_DAYS)))).fetchall()
    per_hour: dict = {}
    first_ts: dict = {}
    for prev, cur in store._series_pairs(rows):   # each IP's counter diffed on its own
        hour = cur["ts"][:13]
        per_hour[hour] = per_hour.get(hour, 0) + (store._delta(prev["rx_bytes"], cur["rx_bytes"])
                                                  + store._delta(prev["tx_bytes"], cur["tx_bytes"]))
        first_ts[hour] = min(first_ts.get(hour, cur["ts"]), cur["ts"])
    vals = sorted(v for v in per_hour.values() if v > 0)
    if len(vals) < 24:   # less than a day of data: no idea what "usual" is
        return []
    p90 = vals[int(0.9 * (len(vals) - 1))]
    typical = vals[len(vals) // 2]
    limit = max(SPIKE_FACTOR * p90, SPIKE_MIN_BYTES)
    spikes: list = []
    for hour in sorted(per_hour):
        if per_hour[hour] <= limit:
            continue
        prev_hour = _iso(datetime.strptime(hour, "%Y-%m-%dT%H") - timedelta(hours=1))[:13]
        if spikes and spikes[-1]["_last"] == prev_hour:   # a run of spike hours = one item
            spikes[-1]["hours"] += 1
            spikes[-1]["bytes"] += per_hour[hour]
            spikes[-1]["_last"] = hour
        else:
            spikes.append({"ts": first_ts[hour], "hours": 1, "bytes": per_hour[hour],
                           "typical": typical, "_last": hour})
    for s in spikes:
        s.pop("_last")
    return spikes


def _what(domain: str, lang: str) -> str:
    """The muted thing of an ack key, in words."""
    if domain.startswith("port:"):
        return i18n.t("tl.what.port", lang, port=domain[5:])
    if domain.startswith("visibility:"):
        return i18n.t("tl.what.visibility", lang)
    if domain == activity.ACK:
        return i18n.t("tl.what.night", lang)
    if domain.startswith(upnp.ACK_PREFIX):
        proto, _sep, port = domain[len(upnp.ACK_PREFIX):].partition(":")
        return i18n.t("tl.what.upnp", lang, proto=proto, port=port)
    if domain.startswith(bedtime.ACK_PREFIX):            # bedtime:<rule id>:<night>
        return i18n.t("tl.what.bedtime", lang, night=domain.rsplit(":", 1)[-1])
    kind = tuning.key_kind(domain)
    if ":" in domain and kind in tuning.KINDS:          # any other internal key: its kind
        return i18n.t("app.tune.kind." + kind, lang)
    return domain                                       # a threat contact: the domain itself


def _ack_text(domain: str, lang: str) -> str:
    """One of the user's acks for this device, in words (never the raw key)."""
    if domain.startswith((tuning.MUTE, tuning.LESS)):   # Stage Q: "Tune" on a whole kind
        kind = domain.split(":", 1)[1]
        what = i18n.t("app.tune.kind." + kind, lang) if kind in tuning.KINDS else kind
        return i18n.t("tl.user_less" if domain.startswith(tuning.LESS) else "tl.user_mute_kind",
                      lang, what=what)
    return i18n.t("tl.user_mute", lang, what=_what(domain, lang))


def timeline(db, mac: str, lang: str = i18n.DEFAULT, tz: tzinfo | None = None,
             now: datetime | None = None) -> list | None:
    """GET /api/timeline: the device's events, newest first. None if the MAC is unknown."""
    from netwarden.brain import human_bytes   # brain imports this module's neighbours
    lang = i18n.normalize(lang)
    tz = tz or activity.local_tz()
    explicit_now, now = now, now or datetime.now(timezone.utc)
    dev = db.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone() if mac else None
    if not dev:
        return None
    tr = lambda key, **kw: i18n.t("tl." + key, lang, **kw)  # noqa: E731
    items = []

    def add(ts, kind, text, **extra):
        if ts:
            items.append({"ts": ts, "kind": kind, "text": text, **extra})

    add(dev["first_seen"], "first_seen",
        tr("first_seen", vendor=dev["vendor"]) if dev["vendor"] else tr("first_seen_plain"))
    domains = _domains(db, mac)
    new_svc, new_dom = _new_lookups(db, mac, domains)
    for first, sid, n in new_svc:
        add(first, "new_service", tr("new_service", service=services.service_name(sid, lang), n=n),
            service=sid)
    for first, dom, n in new_dom:
        add(first, "new_domain", tr("new_domain", domain=dom, n=n), domain=dom)
    for first, dom, n, (sev, ind) in _threats(db, mac, domains):
        label, _why = threatintel.describe(ind, lang)
        add(first, "threat", tr("threat", tag=threatintel.severity_tag(sev, lang), domain=dom,
                                label=label, n=n), domain=dom, severity=sev)
    for a in activity.night_alerts(db, tz=tz, now=explicit_now):
        if a["mac"] == mac:
            add(a["first_ts"], "unusual_hours", activity.explain(a, lang))
    for s in bandwidth_spikes(db, mac, now):
        add(s["ts"], "bandwidth_spike", tr("bandwidth_spike", bytes=human_bytes(s["bytes"]),
                                           h=s["hours"], typical=human_bytes(s["typical"])))
    ports = exposure.latest(db, mac, lang)
    for p in (ports or {}).get("open", []):
        if p["risk"] in exposure.RISKY or p["new"]:
            add(ports["ts"], "open_port",
                tr("open_port", port=p["port"], service=p["service"], risk=p["risk_name"],
                   new=i18n.t("digest.new_flag", lang) if p["new"] else ""), port=p["port"])
    for m in upnp.mappings(db):
        if m["mac"] == mac:
            add(m["first_seen"], "upnp_mapping", tr("upnp_mapping", proto=m["protocol"],
                                                    ext=m["external_port"], port=m["internal_port"]),
                port=m["external_port"], risky=m["risky"])
    for r in store.identities(db, mac).get(mac, []):
        if r["source"] in ("mdns", "ssdp") and (r.get("model") or r.get("name")):
            add(r["first_seen"], "identified",
                tr("identified", what=r.get("model") or r.get("name"),
                   via=i18n.t("ident.src." + r["source"], lang)))
    for a in store.acks_for(db, mac):
        if a["domain"] == "":
            add(a["created_at"], "user_trust", tr("user_trust"))
        else:
            add(a["created_at"], "user_mute", _ack_text(a["domain"], lang))
    lab = store.label_history(db, mac)
    if lab:
        add(lab["updated_at"], "user_rename", tr("user_rename", label=lab["label"]))
    prof = store.get_profiles(db).get(mac)
    if prof:
        from netwarden import devicetype
        parts = []
        if prof["type"]:
            parts.append(tr("f.type", v=devicetype.type_name(prof["type"], lang)))
        if prof["owner"]:
            parts.append(tr("f.owner", v=prof["owner"]))
        if prof["room"]:
            parts.append(tr("f.room", v=prof["room"]))
        add(prof["updated_at"], "user_profile",
            tr("user_profile", details=i18n.t("list_sep", lang).join(parts)))
    items.sort(key=lambda i: i["ts"], reverse=True)
    for i in items[:MAX_ITEMS]:
        i["when"] = activity.to_local(i["ts"], tz).strftime("%Y-%m-%d %H:%M")
    return items[:MAX_ITEMS]
