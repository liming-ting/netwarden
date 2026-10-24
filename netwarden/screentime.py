#!/usr/bin/env python3
"""
netwarden - screentime.py: ESTIMATED screen time per device, app and day, from the DNS
lookups we already store (no new collection, nothing blocked, nothing sent anywhere).

This is a conversation starter for a family ("the tablet was on YouTube about 2 h on
Tuesday night"), not a stopwatch and not surveillance. The UI says so next to it.

How it is estimated
  1. Lookups are mapped to an app with services.py. Only FOREGROUND categories count:
     video, social, games, shopping (+ food delivery), education and a few "other"
     sites people actually look at (news, banking, government, tools). Routine
     background traffic (routine.py: clock, updates, connectivity / certificate checks,
     CDNs, cloud hosting), system / push / cloud sync, smart-home phone-home, ads and
     trackers, blocked lookups and unknown domains never count - so an idle device that
     only phones home does not pile up "screen time".
  2. Per device x app, lookup MINUTES are chained into sessions: the next lookup must
     follow within the category's gap tolerance (video / games keep a stream open and
     look up rarely: 15 min; social / shopping: 8 min; ...). A session needs lookups in
     at least MIN_LOOKUP_MINUTES different minutes - a single lookup is usually a
     background refresh, not a person looking at a screen. A session lasts from its
     first lookup to its last, plus a short tail for the time after the last lookup.
  3. Sessions are cut at LOCAL hour boundaries (time.timezone / NETWARDEN_TZ). One device
     never gets more than 60 min in an hour: when two apps overlap (a video in one tab,
     a chat in another) their minutes are scaled to the device's real active time.

Known limits (also in docs/family.md): DNS caching and long-lived connections hide some
use (under-count) while apps refreshing in the background add some (over-count); a
shared device (the living-room TV) is not a person; DoH / VPN / mobile data are
invisible; private-address phones that change their MAC split into several devices.

Everything is computed from one memoized pass over the last WINDOW_DAYS days
(netwarden.cache), shared by the Family view, the device drawer, bedtime rules
(bedtime.py) and the weekly comparison (weekly.py).
"""
from __future__ import annotations

from datetime import date, datetime, time as dtime, timedelta, timezone, tzinfo
from functools import lru_cache

from netwarden import activity, cache, i18n, routine, services, store

# screen-time categories, in display order
CATS = ("video", "social", "games", "shopping", "education", "other")
# services.py category -> screen-time category; anything not listed is background
SCREEN_CATEGORY = {
    "video": "video", "social": "social", "gaming": "games", "shopping": "shopping",
    "food": "shopping", "education": "education",
    "news": "other", "dev": "other", "finance": "other", "gov": "other",
}
# tools that programs talk to, not people (an API call is not screen time)
MACHINE_SERVICES = {"Anthropic API", "OpenAI API", "PyPI", "npm", "Docker"}
# category -> (gap tolerance s, tail s): how long a pause may be inside one session, and
# how much time a session gets after its last lookup
GAPS = {
    "video": (15 * 60, 5 * 60), "games": (15 * 60, 5 * 60),
    "social": (8 * 60, 2 * 60), "shopping": (8 * 60, 2 * 60),
    "education": (10 * 60, 3 * 60), "other": (5 * 60, 60),
}
MIN_LOOKUP_MINUTES = 2      # a session needs lookups in this many different minutes
WINDOW_DAYS = 15            # one pass covers today + the 14 days before (weekly.py)
MAX_DAYS = 14               # what /api/screentime accepts
DEFAULT_DAYS = 7
TOP_SERVICES = 5
CATEGORY_KEY = {"video": "cat.video", "social": "cat.social", "games": "cat.gaming",
                "shopping": "cat.shopping", "education": "cat.education",
                "other": "fam.cat.other"}


@lru_cache(maxsize=65536)
def classify(domain: str):
    """(service id, screen category) for a lookup that counts as screen time, else None."""
    if routine.is_routine(domain):
        return None
    sid, cat = services.lookup(domain)
    scat = SCREEN_CATEGORY.get(cat)
    return (sid, scat) if sid and scat and sid not in MACHINE_SERVICES else None


# --- time helpers ------------------------------------------------------------------

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def local_midnight(day: date, tz: tzinfo) -> datetime:
    return datetime.combine(day, dtime(0, 0), tzinfo=tz)


def local_dates(today: date, days: int) -> list:
    """The last `days` local dates, oldest first, ending with `today` (ISO strings)."""
    return [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]


def _pieces(start: float, end: float, tz: tzinfo):
    """Split [start, end) (epoch seconds) at local hour boundaries:
    yields ((iso date, hour), seconds)."""
    t = start
    while t < end:
        lt = datetime.fromtimestamp(t, tz)
        nxt = (lt.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)).timestamp()
        if nxt <= t:                       # a DST fold: never loop forever
            nxt = t + 3600 - (t % 3600)
        stop = min(end, nxt)
        yield (lt.date().isoformat(), lt.hour), stop - t
        t = stop


def merge(intervals) -> list:
    """Union of [start, end] intervals, sorted, as a list of [start, end]."""
    out: list = []
    for s, e in sorted(intervals):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def overlap(intervals, start: float, end: float) -> float:
    """Seconds of `intervals` (merged) that fall inside [start, end)."""
    return sum(max(0.0, min(e, end) - max(s, start)) for s, e in intervals)


# --- sessions ----------------------------------------------------------------------

def sessions(minutes, gap: float, tail: float) -> list:
    """Sorted, distinct lookup minutes (epoch s) -> [[start, end], ...] sessions."""
    out = []
    start = prev = None
    n = 0
    for t in minutes:
        if prev is not None and t - prev <= gap:
            prev, n = t, n + 1
            continue
        if prev is not None and n >= MIN_LOOKUP_MINUTES:
            out.append([start, prev + tail])
        start = prev = t
        n = 1
    if prev is not None and n >= MIN_LOOKUP_MINUTES:
        out.append([start, prev + tail])
    return out


def _minute_epochs(db, since: str, until: str) -> dict:
    """mac -> {service id: sorted lookup-minute epochs} for counting lookups, plus the
    category of each service id (key None)."""
    epoch: dict = {}
    out: dict = {}
    cats: dict = {}
    for r in db.execute("""SELECT device_mac AS mac, domain, substr(ts, 1, 16) AS m
                           FROM dns_events
                           WHERE ts >= ? AND ts < ? AND device_mac IS NOT NULL AND blocked = 0
                           GROUP BY 1, 2, 3""", (since, until)):
        hit = classify(r["domain"])
        if not hit:
            continue
        sid, cat = hit
        t = epoch.get(r["m"])
        if t is None:
            t = epoch[r["m"]] = datetime.strptime(r["m"], "%Y-%m-%dT%H:%M").replace(
                tzinfo=timezone.utc).timestamp()
        out.setdefault(r["mac"], {}).setdefault(sid, set()).add(t)
        cats[sid] = cat
    return {"minutes": {mac: {sid: sorted(ts) for sid, ts in svc.items()}
                        for mac, svc in out.items()}, "cats": cats}


def compute(db, tz: tzinfo | None = None, now: datetime | None = None) -> dict:
    """The memoized core: every device's sessions over the last WINDOW_DAYS local days.
    {"tz", "today", "dates", "cats": {sid: category},
     "devices": {mac: {"union": [[s, e]...], "sessions": {sid: [[s, e]...]},
                       "days": {date: {"total": s, "svc": {sid: s}}}}}}
    (seconds). Without an explicit `now` it is shared through netwarden.cache."""
    tz = tz or activity.local_tz()
    if now is None:
        today = datetime.now(tz).date().isoformat()
        return cache.memo(db, "screentime.compute", (activity.tz_label(tz), today),
                          lambda: _compute(db, tz, None))
    return _compute(db, tz, now)


def _compute(db, tz: tzinfo, now: datetime | None) -> dict:
    now = now or datetime.now(timezone.utc)
    today = now.astimezone(tz).date()
    dates = local_dates(today, WINDOW_DAYS)
    since = _iso(local_midnight(date.fromisoformat(dates[0]), tz))
    raw = _minute_epochs(db, since, _iso(now + timedelta(minutes=1)))
    cats = raw["cats"]
    devices = {}
    for mac, svc in raw["minutes"].items():
        per_svc = {sid: sessions(mins, *GAPS[cats[sid]]) for sid, mins in svc.items()}
        per_svc = {sid: s for sid, s in per_svc.items() if s}
        if not per_svc:
            continue
        union = merge([iv for s in per_svc.values() for iv in s])
        # seconds per local hour: each app's own, and the device's real (union) time
        hours: dict = {}
        for sid, ivs in per_svc.items():
            for s, e in ivs:
                for key, secs in _pieces(s, e, tz):
                    h = hours.setdefault(key, {})
                    h[sid] = h.get(sid, 0.0) + secs
        real: dict = {}
        for s, e in union:
            for key, secs in _pieces(s, e, tz):
                real[key] = real.get(key, 0.0) + secs
        days: dict = {}
        for key, per in hours.items():
            total = sum(per.values())
            cap = min(real.get(key, 0.0), 3600.0)       # at most 60 min in any hour
            factor = cap / total if total > cap else 1.0
            day = days.setdefault(key[0], {"total": 0.0, "svc": {}})
            for sid, secs in per.items():
                day["svc"][sid] = day["svc"].get(sid, 0.0) + secs * factor
            day["total"] += total * factor
        devices[mac] = {"union": union, "sessions": per_svc, "days": days}
    return {"tz": activity.tz_label(tz), "today": today.isoformat(), "dates": dates,
            "cats": cats, "devices": devices}


# --- localized text ----------------------------------------------------------------

def duration(minutes: float, lang: str) -> str:
    """75 -> '1 h 15 min' in `lang` (whole minutes; under a minute -> '< 1 min')."""
    m = int(round(minutes or 0))
    if m < 1:
        return i18n.t("fam.dur_lt1", lang)
    h, m = divmod(m, 60)
    if h and m:
        return i18n.t("fam.dur_hm", lang, h=h, m=m)
    return i18n.t("fam.dur_h", lang, h=h) if h else i18n.t("fam.dur_m", lang, m=m)


def category_name(cat: str, lang: str) -> str:
    return i18n.t(CATEGORY_KEY.get(cat, "fam.cat.other"), lang)


# --- reports -----------------------------------------------------------------------

def _mins(secs: float) -> int:
    return int(round(secs / 60))


def _svc_list(totals: dict, cats: dict, lang: str, n: int | None = None) -> list:
    items = sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))
    items = [(sid, secs) for sid, secs in items if _mins(secs) >= 1]
    return [{"id": sid, "name": services.service_name(sid, lang), "category": cats.get(sid, "other"),
             "category_name": category_name(cats.get(sid, "other"), lang), "minutes": _mins(secs)}
            for sid, secs in (items[:n] if n else items)]


def device_days(data: dict, mac: str, dates: list) -> tuple:
    """(total s, {sid: s}, [(date, s)]) of one device over `dates`."""
    dev = data["devices"].get(mac) or {"days": {}}
    total, svc, per_day = 0.0, {}, []
    for d in dates:
        day = dev["days"].get(d) or {"total": 0.0, "svc": {}}
        total += day["total"]
        per_day.append((d, day["total"]))
        for sid, secs in day["svc"].items():
            svc[sid] = svc.get(sid, 0.0) + secs
    return total, svc, per_day


def today_text(svc_today: dict, total_today: float, lang: str) -> str:
    """'About 1 h 20 min on YouTube today' (+ the total when other apps add up)."""
    if _mins(total_today) < 1:
        return i18n.t("fam.today_none", lang)
    sid, secs = max(svc_today.items(), key=lambda kv: (kv[1], kv[0]))
    top = i18n.t("fam.today_top", lang, dur=duration(secs / 60, lang),
                 service=services.service_name(sid, lang))
    if _mins(total_today) - _mins(secs) >= 5:
        top += " " + i18n.t("fam.today_total", lang, dur=duration(total_today / 60, lang))
    return top


def report(db, lang: str, days: int = DEFAULT_DAYS, mac: str | None = None,
           owner: str | None = None, tz: tzinfo | None = None,
           now: datetime | None = None, person_id: int | None = None) -> dict:
    """GET /api/screentime: totals per member (owner), category, app and device over the
    last `days` local days (today included), a per-day trend, and today's line for each
    device. `mac` / `owner` narrow it down. All numbers are whole minutes."""
    lang = i18n.normalize(lang)
    tz = tz or activity.local_tz()
    days = max(1, min(MAX_DAYS, int(days)))
    data = compute(db, tz, now)
    dates = data["dates"][-days:]
    today = data["today"]
    from netwarden import naming
    names = naming.display_names(db, lang)   # the dashboard's names, never a bare MAC
    owners = {m: p["owner"] for m, p in store.get_profiles(db).items() if p.get("owner")}
    macs = sorted(data["devices"])
    if mac:
        macs = [m for m in macs if m == mac]
    if owner:
        macs = [m for m in macs if owners.get(m) == owner]
    if person_id is not None:
        p = store.person(db, person_id)
        macs = [m for m in macs if p and owners.get(m) == p["name"]]
    cats = data["cats"]

    home_days = {d: 0.0 for d in dates}
    home_svc: dict = {}
    devs, members = [], {}
    for m in macs:
        total, svc, per_day = device_days(data, m, dates)
        if _mins(total) < 1:
            continue
        t_total, t_svc, _ = device_days(data, m, [today])
        for d, secs in per_day:
            home_days[d] += secs
        for sid, secs in svc.items():
            home_svc[sid] = home_svc.get(sid, 0.0) + secs
        who = owners.get(m, "")
        devs.append({"mac": m, "name": names.get(m, m), "owner": who or None,
                     "minutes": _mins(total), "today_minutes": _mins(t_total),
                     "today_text": today_text(t_svc, t_total, lang),
                     "by_day": [{"date": d, "minutes": _mins(s)} for d, s in per_day],
                     "top_services": _svc_list(svc, cats, lang, TOP_SERVICES)})
        g = members.setdefault(who, {"days": {d: 0.0 for d in dates}, "svc": {}, "macs": [],
                                     "today": 0.0})
        g["macs"].append(m)
        g["today"] += t_total
        for d, secs in per_day:
            g["days"][d] += secs
        for sid, secs in svc.items():
            g["svc"][sid] = g["svc"].get(sid, 0.0) + secs
    devs.sort(key=lambda x: (-x["minutes"], x["name"]))

    by_cat: dict = {}
    for sid, secs in home_svc.items():
        by_cat[cats.get(sid, "other")] = by_cat.get(cats.get(sid, "other"), 0.0) + secs
    total = sum(home_days.values())
    member_list = []
    ids = {p["name"]: p["id"] for p in store.people(db)}   # Stage P: the person behind it
    for who, g in members.items():
        tot = sum(g["days"].values())
        member_list.append({
            "owner": who or None, "person_id": ids.get(who),
            "minutes": _mins(tot), "today_minutes": _mins(g["today"]),
            "avg_minutes": _mins(tot / len(dates)),
            "by_day": [{"date": d, "minutes": _mins(g["days"][d])} for d in dates],
            "top_services": _svc_list(g["svc"], cats, lang, TOP_SERVICES),
            "devices": [{"mac": m, "name": names.get(m, m)} for m in g["macs"]]})
    # people first (most time first), the shared / unassigned devices last
    member_list.sort(key=lambda g: (g["owner"] is None, -g["minutes"], g["owner"] or ""))
    return {
        "tz": data["tz"], "days": days, "dates": dates, "today": today,
        "minutes": _mins(total), "today_minutes": _mins(home_days.get(today, 0.0)),
        "by_day": [{"date": d, "minutes": _mins(home_days[d])} for d in dates],
        "categories": [{"key": c, "name": category_name(c, lang), "minutes": _mins(by_cat[c])}
                       for c in CATS if _mins(by_cat.get(c, 0.0)) >= 1],
        "services": _svc_list(home_svc, cats, lang, 12),
        "members": member_list, "devices": devs,
        "note": i18n.t("fam.note", lang), "method": i18n.t("fam.method", lang),
    }


def member_totals(db, days: int = 7, tz: tzinfo | None = None,
                  now: datetime | None = None) -> list:
    """Compact canonical per-owner totals for the digest and the AI snapshot:
    [{owner, minutes, today_minutes, top: [service id, ...]}], most time first. Devices
    without an owner are left out (a shared TV is not a person)."""
    tz = tz or activity.local_tz()
    data = compute(db, tz, now)
    dates = data["dates"][-days:]
    owners = {m: p["owner"] for m, p in store.get_profiles(db).items() if p.get("owner")}
    acc: dict = {}
    for m, who in owners.items():
        total, svc, _ = device_days(data, m, dates)
        t_total, _, _ = device_days(data, m, [data["today"]])
        if _mins(total) < 1:
            continue
        g = acc.setdefault(who, {"owner": who, "secs": 0.0, "today": 0.0, "svc": {}})
        g["secs"] += total
        g["today"] += t_total
        for sid, secs in svc.items():
            g["svc"][sid] = g["svc"].get(sid, 0.0) + secs
    out = [{"owner": g["owner"], "minutes": _mins(g["secs"]), "today_minutes": _mins(g["today"]),
            "top": [sid for sid, _s in sorted(g["svc"].items(), key=lambda kv: (-kv[1], kv[0]))[:3]]}
           for g in acc.values()]
    return sorted(out, key=lambda g: (-g["minutes"], g["owner"]))
