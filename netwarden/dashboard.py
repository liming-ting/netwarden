#!/usr/bin/env python3
"""
netwarden - dashboard.py: data shaping for the web dashboard (no HTTP here)

The dashboard's device list needs EVERY known device - not only the ones with DNS in
the window that brain.snapshot() lists - plus a few facts the snapshot leaves out
(first / last seen, online, new, how many things need attention). inventory() merges
the localized snapshot with the devices table into that one list, so the page can
filter, sort and group without a request per device.

Read-only: it only reads netwarden's own SQLite.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netwarden import devicetype, identify, privacy, store, upnp

ONLINE_MINUTES = 30   # seen by a LAN sweep (every 15 min) or in DNS this recently = online
RISKY_PORTS = ("high", "medium")


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _last_dns(db, since: str) -> dict:
    """mac -> newest DNS event ts in the window."""
    return {r[0]: r[1] for r in db.execute(
        "SELECT device_mac, MAX(ts) FROM dns_events "
        "WHERE device_mac IS NOT NULL AND ts >= ? GROUP BY device_mac", (since,))}


def _bare_device(row, label: str | None, prof: dict, t: dict | None, trusted: bool,
                 lang: str) -> dict:
    """A known device with no DNS in the window, in the snapshot-device shape."""
    return {"name": label or row["hostname"] or None, "label": label,
            **{f: prof[f] for f in ("owner", "room") if prof.get(f)},
            "type": (t or {}).get("type", "unknown"), "type_info": devicetype.localize(t, lang),
            "hostname": row["hostname"] or None, "vendor": row["vendor"],
            "is_self": bool(row["is_self"]), "ips": [row["ip"]] if row["ip"] else [],
            "mac": row["mac"], "trusted": trusted, "queries": 0, "blocked": 0,
            "distinct_domains": 0, "services": [], "top_domains": []}


def inventory(db, snap: dict, lang: str, hours: float = 24, now: datetime | None = None) -> dict:
    """The localized snapshot (web.localize_snapshot) with `devices` widened to the whole
    inventory. Each device also gets first_seen / last_seen / last_active (UTC ISO),
    online, new (first seen inside the window), randomized, threat_count and
    risky_ports (open high/medium ports the user has not muted)."""
    now = now or datetime.now(timezone.utc)
    since = _iso(now - timedelta(hours=hours))
    online_since = _iso(now - timedelta(minutes=ONLINE_MINUTES))
    rows = {r["mac"]: r for r in db.execute("SELECT * FROM devices")}
    by_mac = {d["mac"]: d for d in snap["devices"] if d.get("mac")}
    labels, profiles = store.get_labels(db), store.get_profiles(db)
    acks = store.list_acks(db)
    types = None   # classify_all() only if some device is missing from the snapshot
    last_dns = _last_dns(db, since)
    # The table's privacy column must agree with the drawer / /api/privacy: every device
    # with DNS in the window gets its grade (the snapshot only carries it when there are
    # tracker lookups - that is what the LLM needs, not what a table needs).
    priv = {p["mac"]: p for p in privacy.analyze(db, since)["devices"] if p["mac"] and p["queries"]}
    threats: dict = {}
    for t in snap.get("threats", []):
        threats[t.get("mac")] = threats.get(t.get("mac"), 0) + 1
    idents = identify.summary_all(db)   # Stage N: what devices announced on the LAN
    upnp_risky: dict = {}
    for m in upnp.mappings(db):
        if m["mac"] and m["risky"] and (m["mac"], m["ack"]) not in acks \
                and (m["mac"], "") not in acks:
            upnp_risky[m["mac"]] = upnp_risky.get(m["mac"], 0) + 1

    out = []
    for mac, row in rows.items():
        d = by_mac.get(mac)
        if d is None:
            if types is None:
                types = devicetype.classify_all(db)
            d = _bare_device(row, (labels.get(mac) or {}).get("label"), profiles.get(mac) or {},
                             types.get(mac), (mac, "") in acks, lang)
        d = dict(d)
        if "privacy" not in d and mac in priv:
            d["privacy"] = {k: priv[mac][k] for k in ("grade", "tracker_share", "blocked_share",
                                                     "main_category", "main_company")}
        active =max(filter(None, (row["last_seen"], last_dns.get(mac))))
        risky = [p for p in d.get("open_ports", []) if p.get("risk") in RISKY_PORTS]
        d.update(first_seen=row["first_seen"], last_seen=row["last_seen"], last_active=active,
                 online=active >= online_since, new=row["first_seen"] >= since,
                 randomized=bool(row["randomized"]), threat_count=threats.get(mac, 0),
                 risky_ports=len(risky), upnp_risky=upnp_risky.get(mac, 0))
        if (profiles.get(mac) or {}).get("shared"):
            d["shared"] = True      # Stage P: the household's device (TV, speaker)
        ident = idents.get(mac)
        if ident:
            d["ident"] = {k: ident[k] for k in ("name", "manufacturer", "model", "sources")}
            if not d.get("vendor") and ident["manufacturer"]:
                d["vendor"] = ident["manufacturer"]
        out.append(d)
    # DNS clients we could not tie to an inventory row (no MAC) still show up.
    out += [dict(d, online=False, new=False, threat_count=0, risky_ports=0)
            for d in snap["devices"] if not d.get("mac")]
    out.sort(key=lambda d: (-d.get("queries", 0), (d.get("name") or d.get("vendor") or "").lower()))
    return {**snap, "devices": out, "online_minutes": ONLINE_MINUTES}
