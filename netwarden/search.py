#!/usr/bin/env python3
"""
netwarden - search.py: find anything (no LLM) and look things up in reverse.

  search(q)          devices (name, label, owner, room, vendor, IP, MAC, type), services
                     and domains seen recently that match `q`, with counts
  service_detail()   which devices use a service, how much, first/last seen
  domain_detail()    the same for one domain (and its subdomains), plus whether it is a
                     known threat or tracker

Plain substring matching, case-insensitive. Counts cover the last `days` days (default
7); first/last seen cover the whole retained history. Read-only.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from netwarden import devicetype, i18n, naming, privacy, routine, services, store, threatintel

SEARCH_DAYS = 7
MAX_QUERY = 100
LIMIT = 20


def _since(days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _clean_domain(d: str) -> str:
    return (d or "").strip().lower().strip(".")


def _domain_rows(db, since: str):
    """Per domain over the window: queries, blocked, distinct devices."""
    return db.execute("""SELECT domain, COUNT(*) AS n, SUM(blocked) AS b,
                                COUNT(DISTINCT COALESCE(device_mac, 'ip:' || client_ip)) AS devs
                         FROM dns_events WHERE ts >= ? GROUP BY domain""", (since,)).fetchall()


def device_index(db, lang: str) -> list:
    """Every inventory device with the fields search matches on (and shows)."""
    names = naming.display_names(db, lang)   # never a bare MAC as the name
    labels = store.get_labels(db)
    profiles = store.get_profiles(db)
    types = devicetype.classify_all(db)
    out = []
    for r in db.execute("SELECT mac, ip, vendor, hostname FROM devices ORDER BY mac"):
        mac = r["mac"]
        p = profiles.get(mac) or {}
        t = types.get(mac) or devicetype.decide([])
        out.append({"mac": mac, "name": names.get(mac, mac),
                    "label": (labels.get(mac) or {}).get("label") or "",
                    "hostname": r["hostname"] or "", "vendor": r["vendor"] or "",
                    "ip": r["ip"] or "", "owner": p.get("owner") or "",
                    "room": p.get("room") or "", "type": t["type"],
                    "type_name": devicetype.type_name(t["type"], lang)})
    return out


def search(db, q: str, lang: str = i18n.DEFAULT, days: float = SEARCH_DAYS) -> dict:
    """GET /api/search: {q, devices[], services[], domains[]} (each list <= LIMIT)."""
    lang = i18n.normalize(lang)
    q = " ".join((q or "").split())[:MAX_QUERY]
    needle = q.lower()
    res = {"q": q, "days": days, "devices": [], "services": [], "domains": []}
    if not needle:
        return res
    for d in device_index(db, lang):
        fields = ("name", "label", "hostname", "vendor", "ip", "mac", "owner", "room",
                  "type_name", "type")
        hits = [f for f in fields if needle in str(d[f]).lower()]
        if hits:
            res["devices"].append({**d, "matched": hits[0]})
    svc: dict = {}
    since = _since(days)
    for r in _domain_rows(db, since):
        dom = r["domain"]
        sid, cat = services.lookup(dom)
        name = services.service_name(sid, lang) if sid else None
        en_name = services.service_name(sid, "en") if sid else None
        if sid and any(needle in (x or "").lower() for x in (name, en_name, sid)):
            s = svc.setdefault(sid, {"id": sid, "name": name, "category": cat,
                                     "category_name": services.category_name(cat, lang),
                                     "queries": 0, "domains": 0})
            s["queries"] += r["n"]
            s["domains"] += 1
        if needle in dom.lower():
            res["domains"].append({"domain": dom, "queries": r["n"], "blocked": r["b"] or 0,
                                   "devices": r["devs"], "service": name,
                                   "routine": routine.lookup(dom)})
    for sid, s in svc.items():   # distinct devices over all of the service's domains
        s["devices"] = _service_device_count(db, sid, since)
    res["services"] = sorted(svc.values(), key=lambda s: (-s["queries"], s["name"]))[:LIMIT]
    res["domains"] = sorted(res["domains"], key=lambda d: (-d["queries"], d["domain"]))[:LIMIT]
    res["devices"] = res["devices"][:LIMIT]
    return res


def _service_domains(db, sid: str) -> list:
    """Every domain in the retained history that belongs to service `sid`."""
    return [r["domain"] for r in db.execute("SELECT DISTINCT domain FROM dns_events")
            if services.lookup(r["domain"])[0] == sid]


def _service_device_count(db, sid: str, since: str) -> int:
    doms = _service_domains(db, sid)
    if not doms:
        return 0
    return db.execute("""SELECT COUNT(DISTINCT COALESCE(device_mac, 'ip:' || client_ip))
                         FROM dns_events WHERE ts >= ? AND domain IN (SELECT value FROM json_each(?))""",
                      (since, json.dumps(doms))).fetchone()[0]


DAY_HOURS = 24   # round 10e: the device drawer's own domain table counts the last 24 h


def _per_device(db, domains: list, since: str) -> list:
    """Which devices looked up any of `domains`: counts in the window (and in the last
    24 h, the device drawer's period: the two drawers can be compared), first/last seen
    over all history. Unattributed clients appear as 'ip:<addr>'."""
    if not domains:
        return []
    names = store.device_names(db)
    day = (datetime.now(timezone.utc) - timedelta(hours=DAY_HOURS)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    # one JSON parameter, not one "?" per domain: a service seen under thousands of
    # names would pass SQLite's limit on bound variables (Stage K)
    rows = db.execute(
        """SELECT COALESCE(device_mac, 'ip:' || client_ip) AS key, device_mac,
                  SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS n,
                  SUM(CASE WHEN ts >= ? THEN blocked ELSE 0 END) AS b,
                  SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS day,
                  COUNT(*) AS total, MIN(ts) AS first_seen, MAX(ts) AS last_seen
           FROM dns_events WHERE domain IN (SELECT value FROM json_each(?)) GROUP BY key""",
        (since, since, day, json.dumps(domains))).fetchall()
    out = [{"mac": r["device_mac"], "name": names.get(r["device_mac"], r["key"][3:])
            if r["device_mac"] else r["key"][3:],
            "queries": r["n"], "blocked": r["b"] or 0, "queries_total": r["total"],
            "queries_24h": r["day"],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"]} for r in rows]
    out.sort(key=lambda d: (-d["queries"], -d["queries_total"], d["name"] or ""))
    return out


def _flags(domains: list, lang: str) -> dict:
    """Threat + tracker flags over a set of domains (the most severe threat wins)."""
    threat, tracker = None, None
    order = {threatintel.SEV_MALICIOUS: 0, threatintel.SEV_HIGH_RISK: 1}
    tbl, indicators = privacy.table(), threatintel.indicators()
    for d in domains:
        hit = threatintel.match(d, indicators)
        if hit and (threat is None or order.get(hit[0], 9) < order.get(threat["severity"], 9)):
            label, why = threatintel.describe(hit[1], lang)
            threat = {"severity": hit[0], "indicator": hit[1], "label": label, "why": why,
                      "domain": d}
        tr = privacy.lookup(d, tbl)
        if tr and tracker is None:
            entry, cat, company = tr
            tracker = {"entry": entry, "category": cat, "company": company,
                       "category_name": privacy.category_name(cat, lang)}
    return {"threat": threat, "tracker": tracker}


def resolve_service(name: str, lang: str) -> str | None:
    """A service id, or a display name in `lang` / English -> the service id."""
    name = " ".join((name or "").split())
    if not name:
        return None
    ids = {sid for sid, _cat in services.SERVICES.values()}
    if name in ids:
        return name
    low = name.lower()
    for sid in sorted(ids):
        if low in ((services.service_name(sid, lang) or "").lower(),
                   (services.service_name(sid, "en") or "").lower()):
            return sid
    return None


def service_detail(db, name: str, lang: str = i18n.DEFAULT,
                   days: float = SEARCH_DAYS) -> dict | None:
    """GET /api/service: who uses it. None if `name` is not a known service."""
    lang = i18n.normalize(lang)
    sid = resolve_service(name, lang)
    if not sid:
        return None
    cat = next(c for s, c in services.SERVICES.values() if s == sid)
    domains = _service_domains(db, sid)
    since = _since(days)
    devices = _per_device(db, domains, since)
    return {"id": sid, "name": services.service_name(sid, lang), "category": cat,
            "category_name": services.category_name(cat, lang), "days": days,
            "domains": sorted(domains), "devices": devices,
            "queries": sum(d["queries"] for d in devices),
            "first_seen": min((d["first_seen"] for d in devices), default=None),
            "last_seen": max((d["last_seen"] for d in devices), default=None),
            **_flags(domains, lang)}


def domain_detail(db, domain: str, lang: str = i18n.DEFAULT,
                  days: float = SEARCH_DAYS) -> dict | None:
    """GET /api/domain: who looked up `domain` (or a subdomain of it). None if empty."""
    lang = i18n.normalize(lang)
    dom = _clean_domain(domain)[:253]
    if not dom:
        return None
    pattern = "%." + dom.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    domains = [r["domain"] for r in db.execute(
        "SELECT DISTINCT domain FROM dns_events WHERE domain = ? OR domain LIKE ? ESCAPE '\\'",
        (dom, pattern))]
    sid, cat = services.lookup(dom)
    devices = _per_device(db, domains, _since(days))
    return {"domain": dom, "days": days, "domains": sorted(domains),
            "service": services.service_name(sid, lang), "category": cat,
            "category_name": services.category_name(cat, lang), "devices": devices,
            "queries": sum(d["queries"] for d in devices),
            "blocked": sum(d["blocked"] for d in devices),
            "first_seen": min((d["first_seen"] for d in devices), default=None),
            "last_seen": max((d["last_seen"] for d in devices), default=None),
            # calm context for normal background traffic (clock, updates, CDNs, ...)
            "routine": routine.info(dom, lang),
            **_flags(domains or [dom], lang)}
