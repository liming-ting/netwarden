"""
netwarden - hygiene.py: the router and network hygiene card (Stage Q, Security view).

Read-only and built ONLY from data netwarden already has - no new probing, never a login
anywhere. Each check says pass / warn / fail / unknown, why in plain language, and the
steps the user applies by hand:

    upnp        is UPnP on? (the router answered the discovery cycle's read-only UPnP look)
    upnp_risky  forwarded ports on risky services (remote admin, RDP, SMB, Telnet, SSH,
                databases, camera streams - upnp.RISKY_PORTS)
    upnp_stale  forwarded ports pointing at addresses no current device holds
    router      the router's model as it announced itself (SSDP / UPnP); a reminder to
                check the vendor's support page for firmware (plain text, no outbound check)
    dns_bypass  devices that bypass the DNS filter with their own encrypted DNS
    exposure    risky open services found by the user's last opt-in port check
    iot         smart-home devices with heavy tracker contact -> a guest / IoT network

The findings also feed the suggestion center (suggestions._hygiene: kinds upnp_stale,
firmware, iot_net) - checks that an existing suggestion already covers (risky UPnP ports,
open ports, DoH) only LINK to those suggestions, so the score never counts a problem twice.

    facts(db)          -> canonical findings (cached)
    report(db, lang)   -> GET /api/hygiene {checks: [...], counts, demo}
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netwarden import cache, exposure, i18n, naming, store, upnp, visibility

STATUSES = ("pass", "warn", "fail", "unknown")
CHECKS = ("upnp", "upnp_risky", "upnp_stale", "router", "dns_bypass", "exposure", "iot")
STALE_DAYS = 7                   # a device not seen this long no longer "holds" its address
IOT_TYPES = ("camera", "tv", "streaming", "speaker", "appliance", "vacuum", "iot")
IOT_MIN_TRACKERS = 50            # tracker lookups in 24 h ...
IOT_MIN_SHARE = 0.25             # ... and at least this share of its lookups
MAX_LIST = 4                     # names / ports listed in one sentence


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def facts(db) -> dict:
    """Canonical (unlocalized) findings, shared through netwarden.cache."""
    return cache.memo(db, "hygiene.facts", (), lambda: _facts(db))


def _router(db, snap: dict | None) -> dict:
    """{ip, model} of the router as it announced itself, or model None."""
    ip = (snap or {}).get("gateway_ip")
    model = None
    if ip:
        row = db.execute("SELECT mac FROM devices WHERE ip = ?", (ip,)).fetchone()
        if row:
            for r in db.execute("""SELECT manufacturer, model FROM device_identity WHERE mac = ?
                                   AND source IN ('ssdp', 'mdns') ORDER BY source = 'ssdp' DESC""",
                                (row["mac"],)):
                parts = [p for p in (r["manufacturer"], r["model"]) if p]
                if parts:
                    # "TP-Link" + "Archer C6"; a model that already names its maker stays as is
                    model = parts[-1] if len(parts) == 2 and parts[0].lower() in parts[1].lower() \
                        else " ".join(parts)
                    break
    if not model and (snap or {}).get("gateway_name"):
        model = snap["gateway_name"]
    return {"ip": ip, "model": model}


def _facts(db) -> dict:
    from netwarden import devicetype, privacy
    now = datetime.now(timezone.utc)
    day = _iso(now - timedelta(hours=24))
    stale_since = _iso(now - timedelta(days=STALE_DAYS))
    names = store.device_names(db)
    snap = store.upnp_latest(db)
    last_ok = db.execute("SELECT * FROM upnp_snapshots WHERE available = 1 ORDER BY ts DESC "
                         "LIMIT 1").fetchone()
    maps = upnp.mappings(db) if snap and snap["available"] else []
    seen = {r["mac"]: r["last_seen"] for r in db.execute("SELECT mac, last_seen FROM devices")}
    # forwards to a device that is gone - a RISKY one is already the upnp finding (and its
    # score deduction): one problem, counted and shown once
    stale = [m for m in maps if not m["risky"]
             and (not m["mac"] or (seen.get(m["mac"]) or "") < stale_since)]
    has_dns = bool(db.execute("SELECT EXISTS(SELECT 1 FROM dns_events)").fetchone()[0])
    vis = visibility.analyze(db, hours=24)
    bypass = [b for b in vis["bypass"] if b["active"]]
    checked = bool(store.checked_macs(db))
    open_risky = [f for f in exposure.findings(db) if f["risk"] in exposure.RISKY]
    iot = []
    if has_dns:
        types = {m: r["type"] for m, r in devicetype.classify_all(db).items()}
        for d in privacy.analyze(db, day)["devices"]:
            if d["mac"] and types.get(d["mac"]) in IOT_TYPES \
                    and d["tracker_queries"] >= IOT_MIN_TRACKERS \
                    and d["tracker_share"] >= IOT_MIN_SHARE:
                iot.append({"mac": d["mac"], "name": d["name"] or names.get(d["mac"], d["mac"]),
                            "trackers": d["tracker_queries"], "share": d["tracker_share"]})
    return {
        "upnp": {"checked": snap is not None, "available": bool(snap and snap["available"]),
                 "ever_available": last_ok is not None, "mappings": len(maps)},
        "upnp_risky": [{"id": f"upnp:{m['protocol']}:{m['external_port']}", "mac": m["mac"],
                        "name": m["name"], "proto": m["protocol"], "ext": m["external_port"],
                        "service": m["service"]} for m in maps if m["risky"]],
        "upnp_stale": [{"proto": m["protocol"], "ext": m["external_port"],
                        "ip": m["internal_client"], "mac": m["mac"],
                        "name": m["name"] if m["mac"] else m["internal_client"],
                        "gone": m["mac"] is None} for m in stale],
        "router": _router(db, dict(last_ok) if last_ok else (dict(snap) if snap else None)),
        "has_dns": has_dns,
        "dns_bypass": [{"id": f"doh:{b['mac']}", "mac": b["mac"], "name": b["name"]} for b in bypass],
        "port_checked": checked,
        "exposure": [{"id": f"port:{f['mac']}:{f['port']}", "mac": f["mac"], "name": f["name"],
                      "port": f["port"], "service": f["service"], "risk": f["risk"]}
                     for f in open_risky],
        "iot": sorted(iot, key=lambda x: -x["trackers"]),
    }


def _list(items: list, lang: str, fmt) -> str:
    sep = i18n.t("list_sep", lang)
    shown = [fmt(x) for x in items[:MAX_LIST]]
    if len(items) > MAX_LIST:
        shown.append(i18n.t("hyg.more", lang, n=len(items) - MAX_LIST))
    return sep.join(shown)


def checks(f: dict, lang: str, names: dict | None = None) -> list:
    """The localized checks for facts() `f`."""
    names = names or {}
    t = lambda key, **kw: i18n.t("hyg." + key, lang, **kw)  # noqa: E731
    nm = lambda x: names.get(x.get("mac"), x.get("name")) if x.get("mac") else x.get("name")  # noqa: E731
    out = []

    def add(key, status, text, sids=(), facts_=()):
        steps = [s.strip() for s in t(key + ".steps", **_step_params(f)).split("\n") if s.strip()]
        out.append({"key": key, "status": status, "status_name": t("status." + status),
                    "title": t(key + ".title"), "text": text,
                    "steps": steps if status in ("warn", "fail") or key == "router" else [],
                    "suggestions": list(sids), "facts": list(facts_)})

    u = f["upnp"]
    if not u["checked"]:
        add("upnp", "unknown", t("upnp.unknown"))
        add("upnp_risky", "unknown", t("upnp.unknown"))
        add("upnp_stale", "unknown", t("upnp.unknown"))
    elif not u["available"]:
        add("upnp", "pass", t("upnp.pass"))
        add("upnp_risky", "pass", t("upnp_risky.pass"))
        add("upnp_stale", "pass", t("upnp_stale.pass"))
    else:
        add("upnp", "warn", t("upnp.warn", n=u["mappings"]))
        r = f["upnp_risky"]
        add("upnp_risky", "fail" if r else "pass",
            t("upnp_risky.fail", n=len(r), ports=_list(r, lang, lambda x: f"{x['proto']} {x['ext']} "
                                                                        f"({x['service']}, {nm(x)})"))
            if r else t("upnp_risky.pass"), [x["id"] for x in r])
        s = f["upnp_stale"]
        add("upnp_stale", "warn" if s else "pass",
            t("upnp_stale.warn", n=len(s), ports=_list(s, lang, lambda x: f"{x['proto']} {x['ext']} → "
                                                                        f"{x['ip']}"))
            if s else t("upnp_stale.pass"), ["upnp_stale"] if s else [])
    ro = f["router"]
    if ro["model"]:
        add("router", "pass", t("router.pass", model=ro["model"]), ["firmware"])
    else:
        add("router", "unknown", t("router.unknown"))
    if not f["has_dns"]:
        add("dns_bypass", "unknown", t("no_dns"))
    else:
        b = f["dns_bypass"]
        add("dns_bypass", "warn" if b else "pass",
            t("dns_bypass.warn", n=len(b), names=_list(b, lang, nm)) if b else t("dns_bypass.pass"),
            [x["id"] for x in b])
    if not f["port_checked"]:
        add("exposure", "unknown", t("exposure.unknown"))
    else:
        e = f["exposure"]
        status = "fail" if any(x["risk"] == "high" for x in e) else ("warn" if e else "pass")
        add("exposure", status,
            t("exposure.warn", n=len(e), ports=_list(e, lang, lambda x: f"{nm(x)} {x['port']} "
                                                                     f"{x['service']}"))
            if e else t("exposure.pass"), [x["id"] for x in e])
    if not f["has_dns"]:
        add("iot", "unknown", t("no_dns"))
    else:
        i = f["iot"]
        add("iot", "warn" if i else "pass",
            t("iot.warn", n=len(i), names=_list(i, lang, nm)) if i else t("iot.pass"),
            ["iot_net"] if i else [])
    return out


def _step_params(f: dict) -> dict:
    return {"model": f["router"]["model"] or "?"}


def report(db, lang: str = i18n.DEFAULT) -> dict:
    """GET /api/hygiene."""
    lang = i18n.normalize(lang)
    cs = checks(facts(db), lang, naming.display_names(db, lang))
    counts = {s: sum(1 for c in cs if c["status"] == s) for s in STATUSES}
    worst = next((s for s in ("fail", "warn") if counts[s]), "pass" if counts["pass"] else "unknown")
    return {"checks": cs, "counts": counts, "status": worst,
            "summary": i18n.t("hyg.summary." + worst, lang, n=counts["fail"] + counts["warn"]),
            "note": i18n.t("hyg.note", lang), "demo": store.is_demo(db)}
