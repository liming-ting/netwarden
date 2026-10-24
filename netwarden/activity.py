#!/usr/bin/env python3
"""
netwarden - activity.py: WHEN is each device busy?

From the DNS events we already store (no new collection):

  grid       a 7 x 24 heatmap (weekday x hour, LOCAL time) of DNS lookups over the
             last 7 days - per device or for the whole home
  typical    the hours a device is usually active, e.g. "07:00-12:00, 18:00-23:00"
  night      "unusual hours": a device that is normally idle at night (00:00-05:00)
             was busy at night in the last 24 h - e.g. a kid's tablet at 01:30

Local time = the system's local time zone, or NETWARDEN_TZ (an IANA name such as
Asia/Taipei, resolved with zoneinfo). Without zoneinfo data for that name we fall back
to the system's current UTC offset (DST changes inside the week are then ignored) - a
missing time-zone database never breaks anything.

Conservative on purpose (no noise): the night alert skips always-on device types
(cameras, routers, speakers, TVs, ...), devices with fewer than MIN_HISTORY_DAYS days of
history, devices that were active at night on more than an occasional baseline night,
and small counts. Acks: (mac, "activity:night") mutes it; a trusted device is skipped.

Times are aggregated in 10-minute UTC buckets before converting, so zones with a
half-hour offset (India: +05:30) still land in the right local hour.
"""
from __future__ import annotations

import logging
import math
import os
from datetime import datetime, timedelta, timezone, tzinfo

from netwarden import cache, i18n, store

GRID_DAYS = 7
NIGHT_HOURS = range(0, 5)     # local 00:00-05:00
NIGHT_MIN_QUERIES = 10        # significant = at least this many lookups at night ...
NIGHT_ACTIVE_MIN = 3          # ... a baseline night "counts" from this many lookups
MIN_HISTORY_DAYS = 3          # need this many active days in the baseline week
BASELINE_DAYS = 7
MAX_GAP_HOURS = 1             # typical hours: merge stretches split by one quiet hour
ACK = "activity:night"
FUTURE = "9999-12-31T23:59:59.999999Z"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- time zone -------------------------------------------------------------------

SETTING_TZ: str | None = None   # the dashboard's time.timezone (settings.apply sets it)


def _configured_tz_name() -> str | None:
    name = os.environ.get("NETWARDEN_TZ")
    if name:
        return name
    from netwarden import brain   # brain imports us; .env is read lazily
    return brain.load_env().get("NETWARDEN_TZ") or SETTING_TZ


def _zone(name: str) -> tzinfo | None:
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:   # no zoneinfo / no tzdata / bad name
        return None


def _system_zone_name() -> str | None:
    """The system zone's IANA name, if any: the TZ environment variable when it names a
    zone ("Europe/Berlin", ":Asia/Kolkata" or a zoneinfo file path - what `docker run -e
    TZ=...` and the C library use), else /etc/localtime (Linux/WSL/macOS). A TZ we cannot
    name (a POSIX rule like "CST-8") -> None: the caller falls back to the current UTC
    offset, which the C library computed from that same TZ."""
    env = (os.environ.get("TZ") or "").strip()
    if env:
        env = env[1:] if env.startswith(":") else env
        if env.startswith("/"):
            return _zone_name_of_file(env)
        return env if _zone(env) is not None else None
    return _zone_name_of_file("/etc/localtime")


def _zone_name_of_file(path: str) -> str | None:
    """"Asia/Taipei" for /usr/share/zoneinfo/Asia/Taipei (or a link to it), else None."""
    try:
        real = os.path.realpath(path)
    except OSError:
        return None
    marker = "zoneinfo" + os.sep
    return real.split(marker, 1)[1] if marker in real else None


_warned_tz: set = set()


def _warn_bad_tz(name: str) -> None:
    """Say ONCE per name that NETWARDEN_TZ is not a zone we know (the fallback to the
    system zone would otherwise be silent). The name is not a secret; it is truncated."""
    if name not in _warned_tz:
        _warned_tz.add(name)
        logging.getLogger("netwarden.activity").warning(
            "NETWARDEN_TZ=%r is not a known time zone (e.g. Asia/Taipei); using the system zone",
            name[:64])


def local_tz(name: str | None = None) -> tzinfo:
    """The local time zone: `name` (or NETWARDEN_TZ) via zoneinfo, else the system's
    zone (by name when TZ or /etc/localtime tells us, else its current UTC offset)."""
    name = (name if name is not None else _configured_tz_name() or "").strip()
    if name and _zone(name) is None:
        _warn_bad_tz(name)
    for candidate in (name, _system_zone_name()):
        tz = _zone(candidate) if candidate else None
        if tz is not None:
            return tz
    return datetime.now().astimezone().tzinfo or timezone.utc


def tz_label(tz: tzinfo) -> str:
    """'Asia/Taipei' for a zoneinfo zone, else the UTC offset, e.g. 'UTC+08:00'."""
    key = getattr(tz, "key", None)
    if key:
        return key
    off = datetime.now(tz).utcoffset() or timedelta(0)
    if not off:
        return "UTC"
    sign, mins = ("+" if off >= timedelta(0) else "-"), abs(int(off.total_seconds())) // 60
    return f"UTC{sign}{mins // 60:02d}:{mins % 60:02d}"


def to_local(ts: str, tz: tzinfo) -> datetime:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(tz)


# --- aggregation -------------------------------------------------------------------

def _buckets(db, since: str, until: str = FUTURE, mac: str | None = None,
             per_device: bool = True):
    """(mac, 10-minute UTC bucket, count) rows. per_device=False: the whole home
    (unattributed events included), mac = ''."""
    key = "COALESCE(device_mac, '')" if per_device else "''"
    where = "ts >= ? AND ts < ?"
    args: list = [since, until]
    if mac:
        where += " AND device_mac = ?"
        args.append(mac)
    elif per_device:
        where += " AND device_mac IS NOT NULL"
    return db.execute(f"""SELECT {key} AS mac, substr(ts, 1, 15) AS b, COUNT(*) AS n
                          FROM dns_events WHERE {where} GROUP BY 1, 2""", args).fetchall()


class _Local:
    """Bucket -> local datetime, cached (the same buckets repeat across devices)."""
    def __init__(self, tz: tzinfo):
        self.tz, self.cache = tz, {}

    def __call__(self, bucket: str) -> datetime:
        dt = self.cache.get(bucket)
        if dt is None:   # the middle of the 10-minute bucket ("10:2" -> 10:25)
            dt = datetime.strptime(bucket + "5", "%Y-%m-%dT%H:%M").replace(
                tzinfo=timezone.utc).astimezone(self.tz)
            self.cache[bucket] = dt
        return dt


def _blank() -> dict:
    return {"grid": [[0] * 24 for _ in range(7)], "hourly": [0] * 24, "total": 0,
            "night": 0, "date_hours": set(), "nights": {}, "first": None, "last": None}


def _stats(rows, tz: tzinfo) -> dict:
    """mac -> counts per weekday x hour, per hour, per local date/night."""
    local = _Local(tz)
    out: dict = {}
    for r in rows:
        dt = local(r["b"])
        s = out.setdefault(r["mac"], _blank())
        s["grid"][dt.weekday()][dt.hour] += r["n"]
        s["hourly"][dt.hour] += r["n"]
        s["total"] += r["n"]
        s["date_hours"].add((dt.date(), dt.hour))
        if dt.hour in NIGHT_HOURS:
            s["night"] += r["n"]
            s["nights"][dt.date()] = s["nights"].get(dt.date(), 0) + r["n"]
            s["first"] = min(s["first"] or dt, dt)
            s["last"] = max(s["last"] or dt, dt)
    return out


def typical_hours(s: dict) -> list:
    """Hours the device is usually active, as [start, end) ranges (end may wrap past
    midnight: [22, 2]). An hour is typical when it saw activity on at least 30% of the
    active days (and on 2+ days once there are 2+)."""
    days = {d for d, _h in s["date_hours"]}
    if not days:
        return []
    need = max(1 if len(days) < 2 else 2, math.ceil(0.3 * len(days)))
    per_hour = [0] * 24
    for _d, h in s["date_hours"]:
        per_hour[h] += 1
    on = [per_hour[h] >= need for h in range(24)]
    if all(on):
        return [[0, 24]]
    ranges, start = [], None
    for h in range(24):
        if on[h] and start is None:
            start = h
        if not on[h] and start is not None:
            ranges.append([start, h])
            start = None
    if start is not None:
        ranges.append([start, 24])
    merged: list = []
    for r in ranges:   # a single quiet hour does not split a stretch of activity
        if merged and r[0] - merged[-1][1] <= MAX_GAP_HOURS:
            merged[-1][1] = r[1]
        else:
            merged.append(r)
    ranges = merged
    if len(ranges) > 1 and ranges[0][0] == 0 and ranges[-1][1] == 24:   # wraps midnight
        first = ranges.pop(0)
        ranges[-1][1] = first[1]
    return ranges


def hours_text(ranges: list, sep: str = ", ") -> str:
    """[[7, 12], [22, 2]] -> '07:00–12:00, 22:00–02:00' (language-neutral)."""
    return sep.join(f"{a:02d}:00–{b % 24 if b != 24 else 24:02d}:00" for a, b in ranges)


def _summary(s: dict) -> dict:
    """The compact, canonical per-device facts (brain snapshot + API)."""
    ranges = typical_hours(s)
    peak = max(((wd, h) for wd in range(7) for h in range(24)),
               key=lambda x: s["grid"][x[0]][x[1]])
    return {"total": s["total"], "night_queries": s["night"],
            "night_share": round(s["night"] / s["total"], 3) if s["total"] else 0.0,
            "typical_hours": ranges, "typical_text": hours_text(ranges),
            "active_days": len({d for d, _h in s["date_hours"]}),
            "peak": {"weekday": peak[0], "hour": peak[1],
                     "count": s["grid"][peak[0]][peak[1]]} if s["total"] else None}


def profiles(db, tz: tzinfo | None = None, now: datetime | None = None,
             days: int = GRID_DAYS) -> dict:
    """mac -> _summary() for every device with DNS in the last `days` days."""
    tz = tz or local_tz()
    now = now or datetime.now(timezone.utc)
    stats = _stats(_buckets(db, _iso(now - timedelta(days=days))), tz)
    return {mac: _summary(s) for mac, s in stats.items() if mac}


def grid(db, mac: str | None = None, tz: tzinfo | None = None, now: datetime | None = None,
         days: int = GRID_DAYS) -> dict:
    """The 7 x 24 heatmap (rows Monday..Sunday, columns local hours 0..23) + summary.
    Without an explicit `now` the result is shared through netwarden.cache: the home
    grid is on every page refresh, and the week-long GROUP BY is the slowest part of it."""
    tz = tz or local_tz()
    if now is None:
        return cache.memo(db, "activity.grid", (mac or "", tz_label(tz), days),
                          lambda: _grid(db, mac, tz, datetime.now(timezone.utc), days))
    return _grid(db, mac, tz, now, days)


def _grid(db, mac: str | None, tz: tzinfo, now: datetime, days: int) -> dict:
    rows = _buckets(db, _iso(now - timedelta(days=days)), mac=mac, per_device=bool(mac))
    s = _stats(rows, tz).get(mac or "", _blank())
    return {"mac": mac, "tz": tz_label(tz), "days": days, "grid": s["grid"],
            "hourly": s["hourly"], **_summary(s)}


# --- unusual hours ---------------------------------------------------------------

def _window(first: datetime, last: datetime) -> str:
    return f"{first:%H:%M}–{last:%H:%M}"


def night_alerts(db, types: dict | None = None, tz: tzinfo | None = None,
                 now: datetime | None = None) -> list:
    """Devices normally idle at night that were busy at night in the last 24 h.
    types: mac -> type key (devicetype.classify_all; computed if omitted). Without an
    explicit `now` / `types` the result is shared through netwarden.cache."""
    tz = tz or local_tz()
    if now is None and types is None:
        return cache.memo(db, "activity.night_alerts", (tz_label(tz),),
                          lambda: _night_alerts(db, None, tz, None))
    return _night_alerts(db, types, tz, now)


def _night_alerts(db, types: dict | None, tz: tzinfo, now: datetime | None) -> list:
    from netwarden import devicetype
    explicit_now, now = now, now or datetime.now(timezone.utc)
    recent_since = _iso(now - timedelta(hours=24))
    base_since = _iso(now - timedelta(hours=24) - timedelta(days=BASELINE_DAYS))
    recent = _stats(_buckets(db, recent_since), tz)
    candidates = {m: s for m, s in recent.items() if m and s["night"] >= NIGHT_MIN_QUERIES}
    if not candidates:
        return []
    if types is None:
        types = {m: r["type"] for m, r in devicetype.classify_all(db, explicit_now).items()}
    names = store.device_names(db)
    out = []
    for mac, s in sorted(candidates.items()):
        typ = types.get(mac, "unknown")
        if typ in devicetype.ALWAYS_ON:
            continue
        base = _stats(_buckets(db, base_since, recent_since, mac=mac), tz).get(mac)
        if not base:
            continue
        days = len({d for d, _h in base["date_hours"]})
        if days < MIN_HISTORY_DAYS:
            continue
        busy_nights = sum(1 for n in base["nights"].values() if n >= NIGHT_ACTIVE_MIN)
        if busy_nights > (days - 1) // 4:   # night activity is part of its normal
            continue
        # exact first/last night lookup (the buckets above are only 10-minute precise)
        at_night = [t for t in (to_local(r[0], tz) for r in db.execute(
                        "SELECT ts FROM dns_events WHERE device_mac = ? AND ts >= ? ORDER BY ts",
                        (mac, recent_since))) if t.hour in NIGHT_HOURS]
        first, last = (at_night[0], at_night[-1]) if at_night else (s["first"], s["last"])
        out.append({"mac": mac, "name": names.get(mac, mac), "type": typ,
                    "night_queries": s["night"], "window": _window(first, last),
                    "first_ts": _iso(first.astimezone(timezone.utc)),
                    "last_ts": _iso(last.astimezone(timezone.utc)),
                    "baseline_days": days, "baseline_nights": busy_nights,
                    "typical_text": hours_text(typical_hours(base)), "ack": ACK})
    out.sort(key=lambda a: (-a["night_queries"], a["name"]))
    return out


# --- localized text ----------------------------------------------------------------

def weekday_names(lang: str) -> list:
    return [i18n.t(f"act.wd.{i}", lang) for i in range(7)]


def explain(item: dict, lang: str) -> str:
    """One localized sentence for an unusual-hours finding."""
    return i18n.tn("activity.night_line", item["night_queries"], lang, name=item["name"],
                   window=item["window"])


def summary_text(g: dict, lang: str) -> str:
    if not g["total"]:
        return i18n.t("activity.no_data", lang)
    if not g["typical_hours"]:
        return i18n.t("activity.irregular", lang, tz=g["tz"])
    return i18n.t("activity.typical", lang, hours=hours_text(g["typical_hours"],
                                                              i18n.t("list_sep", lang)),
                  tz=g["tz"])


def report(db, mac: str | None, lang: str, tz: tzinfo | None = None,
           now: datetime | None = None) -> dict:
    """GET /api/activity: the grid + localized labels, summary and any night alert."""
    lang = i18n.normalize(lang)
    tz = tz or local_tz()
    g = grid(db, mac, tz=tz, now=now)
    g["weekdays"] = weekday_names(lang)
    g["summary"] = summary_text(g, lang)
    g["night_share_text"] = (i18n.t("activity.night_share", lang,
                                    pct=round(g["night_share"] * 100))
                             if g["total"] else "")
    if mac:
        hit = next((a for a in night_alerts(db, tz=tz, now=now) if a["mac"] == mac), None)
        g["unusual"] = {**hit, "text": explain(hit, lang)} if hit else None
    return g
