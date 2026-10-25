#!/usr/bin/env python3
"""
netwarden - weekly.py: "this week vs last week", for the whole home and per device.

This week = the last 7 days up to now (from local midnight six days ago); last week =
the same span exactly 7 days earlier, so a Wednesday morning compares with last
Wednesday morning, never with a full week. Compared:

    queries        DNS lookups
    minutes        estimated screen time (screentime.py; foreground apps only)
    trackers       lookups of known trackers (privacy.py)
    blocked_share  share of lookups the DNS filter blocked
    new_services   apps / services seen this week but not last week (routine background
                   traffic excluded, like the behavior-change alert)
    new_devices    devices that joined in the window

highlights() turns that into a few plain-language sentences (the Family card, the
printable report, the weekly digest). Canonical numbers here; text at the edge.
No history for last week -> "has_history": False and a gentle "not enough history yet".
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo

from netwarden import activity, cache, i18n, privacy, routine, screentime, services, store

WEEK = timedelta(days=7)
MIN_CHANGE_PCT = 10            # smaller moves read as "about the same"
MIN_MINUTES_FOR_PCT = 30       # below this, a percentage of screen time is noise
TOP_DEVICES = 12


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def windows(tz: tzinfo, now: datetime) -> dict:
    start = screentime.local_midnight(now.astimezone(tz).date() - timedelta(days=6), tz)
    return {"this": (start, now), "last": (start - WEEK, now - WEEK)}


def pct(this: float, last: float):
    """Whole-number % change, or None when there is nothing to compare with."""
    if not last:
        return None
    return int(round(100 * (this - last) / last))


def _metric(this: float, last: float) -> dict:
    return {"this": this, "last": last, "pct": pct(this, last)}


def _dns(db, since: str, until: str, tbl: dict) -> dict:
    """mac -> {queries, blocked, trackers, services: set}; '' = the whole home."""
    out: dict = {}
    hit_cache: dict = {}
    for r in db.execute("""SELECT COALESCE(device_mac, '') AS mac, domain, COUNT(*) AS n,
                                  SUM(blocked) AS b
                           FROM dns_events WHERE ts >= ? AND ts < ? GROUP BY 1, 2""",
                        (since, until)):
        dom = r["domain"]
        if dom not in hit_cache:
            sid, _cat = services.lookup(dom)
            hit_cache[dom] = (privacy.lookup(dom, tbl) is not None,
                              sid if sid and not routine.is_routine(dom) else None)
        tracker, sid = hit_cache[dom]
        for key in {r["mac"], ""}:
            a = out.setdefault(key, {"queries": 0, "blocked": 0, "trackers": 0, "services": set()})
            a["queries"] += r["n"]
            a["blocked"] += r["b"] or 0
            a["trackers"] += r["n"] if tracker else 0
            if sid:
                a["services"].add(sid)
    return out


def compare(db, tz: tzinfo | None = None, now: datetime | None = None) -> dict:
    """The canonical comparison (numbers + ids, no text). Without an explicit `now` it is
    shared through netwarden.cache."""
    tz = tz or activity.local_tz()
    if now is None:
        return cache.memo(db, "weekly.compare", (activity.tz_label(tz),),
                          lambda: _compare(db, tz, None))
    return _compare(db, tz, now)


def _compare(db, tz: tzinfo, now: datetime | None) -> dict:
    explicit, now = now, now or datetime.now(timezone.utc)
    win = windows(tz, now)
    tbl = privacy.table()
    dns = {k: _dns(db, _iso(a), _iso(b), tbl) for k, (a, b) in win.items()}
    st = screentime.compute(db, tz, explicit)
    oldest = db.execute("SELECT MIN(ts) FROM dns_events").fetchone()[0]
    has_history = bool(oldest and oldest < _iso(win["last"][0] + timedelta(days=1)))

    def minutes(mac: str, key: str) -> int:
        dev = st["devices"].get(mac)
        a, b = win[key]
        return int(round(screentime.overlap(dev["union"], a.timestamp(), b.timestamp()) / 60)) \
            if dev else 0

    def block(this: dict, last: dict) -> dict:
        share = lambda a: round(a["blocked"] / a["queries"], 3) if a["queries"] else 0.0  # noqa: E731
        return {"queries": _metric(this["queries"], last["queries"]),
                "trackers": _metric(this["trackers"], last["trackers"]),
                "blocked_share": {"this": share(this), "last": share(last),
                                  "pts": round(100 * (share(this) - share(last)))}}

    blank = {"queries": 0, "blocked": 0, "trackers": 0, "services": set()}
    names = store.device_names(db)
    owners = {m: p["owner"] for m, p in store.get_profiles(db).items() if p.get("owner")}
    first_seen = {r["mac"]: r["first_seen"] for r in db.execute("SELECT mac, first_seen FROM devices")}
    new_devices = {k: sorted(m for m, fs in first_seen.items() if _iso(a) <= fs < _iso(b))
                   for k, (a, b) in win.items()}

    macs = (set(dns["this"]) | set(dns["last"]) | set(st["devices"])) - {""}
    devices = []
    home_min = {"this": 0, "last": 0}
    for mac in macs:
        if mac not in first_seen:
            continue
        this, last = dns["this"].get(mac, blank), dns["last"].get(mac, blank)
        mins = {k: minutes(mac, k) for k in ("this", "last")}
        for k in mins:
            home_min[k] += mins[k]
        fresh = sorted(this["services"] - last["services"]) if mac not in new_devices["this"] \
            and last["queries"] else []
        devices.append({"mac": mac, "name": names.get(mac, mac), "owner": owners.get(mac),
                        "minutes": _metric(mins["this"], mins["last"]),
                        "new_service_ids": fresh, "new": mac in new_devices["this"],
                        **block(this, last)})
    devices.sort(key=lambda d: (-abs(d["minutes"]["this"] - d["minutes"]["last"]),
                                -abs(d["queries"]["this"] - d["queries"]["last"]), d["name"]))
    home_this, home_last = dns["this"].get("", blank), dns["last"].get("", blank)
    return {
        "tz": activity.tz_label(tz), "has_history": has_history,
        "this": {"start": _iso(win["this"][0]), "end": _iso(win["this"][1])},
        "last": {"start": _iso(win["last"][0]), "end": _iso(win["last"][1])},
        "home": {"minutes": _metric(home_min["this"], home_min["last"]),
                 **block(home_this, home_last),
                 "new_service_ids": sorted(home_this["services"] - home_last["services"])
                 if home_last["queries"] else [],
                 "new_devices": [{"mac": m, "name": names.get(m, m)} for m in new_devices["this"]],
                 "new_devices_last": len(new_devices["last"])},
        "devices": devices[:TOP_DEVICES],
    }


# --- plain language ------------------------------------------------------------------

def _signed(p: int) -> str:
    return f"+{p}" if p > 0 else str(p)


def _trend(m: dict, key: str, lang: str, **kw) -> str:
    """'<key>.up' / '.down' / '.same' with pct and both values; a count `n` is written the
    language's way ("1,444" / "1.444" / "1 444", as the cards above show it) and picks the
    plural form."""
    p = m["pct"]
    if p is None:
        return ""
    way = "same" if abs(p) < MIN_CHANGE_PCT else ("up" if p > 0 else "down")
    if isinstance(kw.get("n"), int):
        n = kw.pop("n")
        return i18n.tn(f"{key}.{way}", n, lang, n=i18n.num(n, lang), pct=i18n.pct(abs(p), lang), **kw)
    return i18n.t(f"{key}.{way}", lang, pct=i18n.pct(abs(p), lang), **kw)


def highlights(c: dict, lang: str, limit: int = 5) -> list:
    """A few short sentences, most interesting first."""
    lang = i18n.normalize(lang)
    if not c["has_history"]:
        return [i18n.t("wow.no_history", lang)]
    h = c["home"]
    out = []
    m = h["minutes"]
    if m["last"] >= MIN_MINUTES_FOR_PCT or m["this"] >= MIN_MINUTES_FOR_PCT:
        line = _trend(m, "wow.hl.minutes", lang, this=screentime.duration(m["this"], lang),
                      last=screentime.duration(m["last"], lang))
        if line:
            out.append(line)
    top = next((d for d in c["devices"]
                if abs(d["minutes"]["this"] - d["minutes"]["last"]) >= MIN_MINUTES_FOR_PCT), None)
    if top:
        diff = top["minutes"]["this"] - top["minutes"]["last"]
        out.append(i18n.t("wow.hl.device_more" if diff > 0 else "wow.hl.device_less", lang,
                          name=top["name"], dur=screentime.duration(abs(diff), lang)))
    q = _trend(h["queries"], "wow.hl.queries", lang, n=h["queries"]["this"])
    if q:
        out.append(q)
    t = _trend(h["trackers"], "wow.hl.trackers", lang, n=h["trackers"]["this"])
    if t and h["trackers"]["this"]:
        out.append(t)
    sep = i18n.t("list_sep", lang)
    fresh = [(d["name"], s) for d in c["devices"] for s in d["new_service_ids"]]
    if fresh:
        shown = [i18n.t("wow.on_device", lang, service=services.service_name(s, lang), name=n)
                 for n, s in fresh[:3]]
        more = len(fresh) - len(shown)
        out.append(i18n.t("wow.hl.new_services", lang, list=sep.join(shown))
                   + (" " + i18n.t("wow.more", lang, n=more) if more > 0 else ""))
    nd = h["new_devices"]
    if nd:
        out.append(i18n.t("wow.hl.new_devices", lang, n=len(nd),
                          list=sep.join(d["name"] for d in nd[:3])))
    if not out:
        out.append(i18n.t("wow.hl.quiet", lang))
    return out[:limit]


def report(db, lang: str, tz: tzinfo | None = None, now: datetime | None = None) -> dict:
    """GET /api/weekly: compare() + localized highlights, service names and percentages."""
    from netwarden import naming
    lang = i18n.normalize(lang)
    # the dashboard's names (a nameless device is not called by its MAC), highlights included
    c = naming.relabel(compare(db, tz, now), naming.display_names(db, lang))
    loc = lambda ids: [services.service_name(s, lang) for s in ids]  # noqa: E731
    return {**c,
            "home": {**c["home"], "new_services": loc(c["home"]["new_service_ids"])},
            "devices": [{**d, "new_services": loc(d["new_service_ids"])} for d in c["devices"]],
            "highlights": highlights(c, lang)}
