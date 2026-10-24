"""
netwarden - quiet.py: quiet hours (Stage Q) - "don't ping me while we sleep".

A daily window in the configured time zone (activity.local_tz), e.g. 22:30-07:00 (an
end at or before the start crosses midnight), with optional per-weekday overrides. A
window belongs to the day it STARTS on (like bedtime.py): Friday's override "23:30-09:00"
is Friday night into Saturday morning; "off" means no quiet hours that night.

During a window every alert is still recorded and shown on the dashboard and in the
inbox; only NOTIFICATIONS wait. notify.route() asks active() and holds the event; at the
end of the window notify.release() turns everything held into ONE "while you were
asleep" summary (exactly once). Critical security alerts go through anyway while the
setting quiet.critical is on (the default).

Settings (settings.py registry, group "quiet"):
    quiet.enabled   bool   False      quiet.start  "22:30"     quiet.end  "07:00"
    quiet.days      str    ""         e.g. "4=23:30-09:00,5=off" (0 = Monday)
    quiet.critical  bool   True       critical security alerts still notify

    config(db, env)                -> {enabled, start, end, days, critical}
    window_on(cfg, day, tz)        -> (start, end) aware datetimes of `day`'s window, or None
    active(cfg, now, tz)           -> {"win", "start", "end"} of the window `now` is in, or None
    describe(db, env, lang, ...)   -> what GET /api/notify shows ("quiet")
"""
from __future__ import annotations

import re
from datetime import date, datetime, time as dtime, timedelta, timezone

from netwarden import activity, i18n

TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
DAY_RE = re.compile(r"^([0-6])=(off|([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d)$")
DEFAULT_START, DEFAULT_END = "22:30", "07:00"


class BadQuiet(ValueError):
    """A quiet-hours value the settings registry refuses (err.setting_invalid)."""


def clean_time(value: str) -> str:
    """"7:00" / "07:00" -> "07:00"; anything else -> BadQuiet."""
    v = (value or "").strip()
    if re.fullmatch(r"\d:[0-5]\d", v):
        v = "0" + v
    if not TIME_RE.match(v):
        raise BadQuiet(value)
    return v


def parse_days(text: str) -> dict:
    """"4=23:30-09:00,5=off" -> {4: ("23:30", "09:00"), 5: None}. BadQuiet on anything
    malformed, a repeated weekday or a window that starts and ends at the same minute."""
    out: dict = {}
    for part in [p.strip() for p in (text or "").split(",") if p.strip()]:
        m = DAY_RE.match(part)
        if not m:
            raise BadQuiet(part)
        day = int(m.group(1))
        if day in out:
            raise BadQuiet(part)
        if m.group(2) == "off":
            out[day] = None
        else:
            s, e = m.group(2).split("-")
            if s == e:
                raise BadQuiet(part)
            out[day] = (s, e)
    return out


def clean_days(value: str) -> str:
    """The canonical text of an override list (sorted by weekday)."""
    days = parse_days(value)
    return ",".join(f"{d}={'off' if days[d] is None else days[d][0] + '-' + days[d][1]}"
                    for d in sorted(days))


def config(db, env: dict | None = None) -> dict:
    from netwarden import settings
    v = settings.values(db, env or {})
    try:
        days = parse_days(v["quiet.days"])
    except BadQuiet:
        days = {}
    start, end = v["quiet.start"], v["quiet.end"]
    if start == end:            # (the validator refuses it; an old value must not mean 24 h)
        return {"enabled": False, "start": start, "end": end, "days": days,
                "critical": v["quiet.critical"]}
    return {"enabled": bool(v["quiet.enabled"]), "start": start, "end": end, "days": days,
            "critical": bool(v["quiet.critical"])}


def _hm(text: str) -> dtime:
    h, m = text.split(":")
    return dtime(int(h), int(m))


def window_on(cfg: dict, day: date, tz) -> tuple | None:
    """(start, end) of the window that starts on local `day`, or None (off that night)."""
    if not cfg["enabled"]:
        return None
    wd = day.weekday()
    span = cfg["days"][wd] if wd in cfg["days"] else (cfg["start"], cfg["end"])
    if span is None:
        return None
    s, e = _hm(span[0]), _hm(span[1])
    start = datetime.combine(day, s, tzinfo=tz)
    end = datetime.combine(day + timedelta(days=1) if e <= s else day, e, tzinfo=tz)
    # a fixed-offset tz is exact; a zoneinfo one may shift by a DST hour - fine for "quiet"
    return start, end


def active(cfg: dict, now: datetime | None = None, tz=None) -> dict | None:
    """The window `now` falls in: {"win": its local start date, "start", "end" (UTC
    datetimes)}, or None. Yesterday's window may still run past midnight."""
    if not cfg["enabled"]:
        return None
    tz = tz or activity.local_tz()
    now = now or datetime.now(timezone.utc)
    local = now.astimezone(tz)
    for day in (local.date() - timedelta(days=1), local.date()):
        w = window_on(cfg, day, tz)
        if w and w[0] <= local < w[1]:
            return {"win": day.isoformat(), "start": w[0].astimezone(timezone.utc),
                    "end": w[1].astimezone(timezone.utc)}
    return None


def next_start(cfg: dict, now: datetime | None = None, tz=None) -> datetime | None:
    """When the next window begins (UTC), within a week; None if quiet hours are off."""
    if not cfg["enabled"]:
        return None
    tz = tz or activity.local_tz()
    now = now or datetime.now(timezone.utc)
    local = now.astimezone(tz)
    for i in range(8):
        w = window_on(cfg, local.date() + timedelta(days=i), tz)
        if w and w[0] > local:
            return w[0].astimezone(timezone.utc)
    return None


def _iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt else None


def days_text(cfg: dict, lang: str) -> str:
    """The overrides in plain words: "Fri 23:30–09:00 · Sat off"."""
    names = activity.weekday_names(lang)
    parts = []
    for d in sorted(cfg["days"]):
        span = cfg["days"][d]
        parts.append(f"{names[d]} " + (i18n.t("quiet.off_night", lang) if span is None
                                       else f"{span[0]}–{span[1]}"))
    return " · ".join(parts)


def describe(db, env: dict | None, lang: str, now: datetime | None = None, tz=None) -> dict:
    """{enabled, active, start, end, days, critical, until, next_start, text, tz}: the
    quiet-hours state the dashboard shows (times are local "HH:MM"; until/next_start UTC)."""
    tz = tz or activity.local_tz()
    cfg = config(db, env)
    act = active(cfg, now, tz)
    nxt = None if act else next_start(cfg, now, tz)
    if not cfg["enabled"]:
        text = i18n.t("quiet.state_off", lang)
    elif act:
        text = i18n.t("quiet.state_on", lang,
                      end=act["end"].astimezone(tz).strftime("%H:%M"))
    else:   # the NEXT window's own hours (a weekday override may differ from the usual)
        start, end = cfg["start"], cfg["end"]
        if nxt is not None:
            w = window_on(cfg, nxt.astimezone(tz).date(), tz)
            if w:
                start, end = (x.astimezone(tz).strftime("%H:%M") for x in w)
        text = i18n.t("quiet.state_next", lang, start=start, end=end)
    return {"enabled": cfg["enabled"], "active": bool(act), "start": cfg["start"],
            "end": cfg["end"], "critical": cfg["critical"],
            "days": {str(d): (None if s is None else list(s)) for d, s in cfg["days"].items()},
            "days_text": days_text(cfg, lang), "win": act["win"] if act else None,
            "until": _iso(act["end"]) if act else None, "next_start": _iso(nxt),
            "text": text, "tz": activity.tz_label(tz)}
