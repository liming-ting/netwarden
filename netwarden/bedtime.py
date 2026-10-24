#!/usr/bin/env python3
"""
netwarden - bedtime.py: bedtime / quiet-hours rules. NOTIFY ONLY - netwarden never
blocks, pauses or changes anything on the network; a rule just says "tell me when this
person's devices are in use after bedtime".

A rule (store.bedtime_rules) targets one person (every device whose owner is that name)
or one device, on a set of weekdays, with a LOCAL time window that may cross midnight
(22:00-07:00 started on Sunday is Sunday night -> Monday morning). It alerts when the
estimated screen time inside one window (screentime.py: foreground apps only, so a
phone charging on the nightstand stays quiet) reaches min_minutes.

    alerts(db)            the last 24 h, for alerts.compute() (kind "bedtime")
    preview(db, rule)     what a rule WOULD have flagged in the last 7 days (the editor)
    covers(...)           does a rule cover a device + time span? (alerts.py then drops
                          the generic "unusual hours" alert for it - one alert, not two)

Ack key: "bedtime:<rule id>:<night date>" mutes ONE night ("got it"), so the rule keeps
working tomorrow; trusting the device mutes it entirely, like every other alert.
"""
from __future__ import annotations

import re
from datetime import date, datetime, time as dtime, timedelta, timezone, tzinfo

from netwarden import activity, i18n, screentime, services, store

MAX_RULES = 50
MAX_NAME = 40
MIN_MINUTES = (1, 240)
DEFAULT_MIN_MINUTES = 10
PREVIEW_DAYS = 7
TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
ACK_PREFIX = "bedtime:"
SCHOOL_NIGHTS = [6, 0, 1, 2, 3]       # Sunday..Thursday night


class BadRule(ValueError):
    """A rule field failed validation: .code -> err.<code> text, .field for the form."""
    def __init__(self, code: str, field: str):
        super().__init__(code)
        self.code, self.field = code, field


def validate(db, raw: dict) -> dict:
    """A POSTed rule -> a clean rule dict (store.save_bedtime_rule shape), or BadRule.
    Exactly one target (owner text or a known device MAC), 1-7 distinct weekdays, two
    different HH:MM times, a sane minute threshold, a short one-line name."""
    if not isinstance(raw, dict):
        raise BadRule("bad_rule", "rule")
    rid = raw.get("id")
    if rid is not None and (isinstance(rid, bool) or not isinstance(rid, int)
                            or not 1 <= rid <= store.MAX_ROWID):
        raise BadRule("bad_rule", "id")
    name = raw.get("name") or ""
    if not isinstance(name, str) or len(name) > 200:
        raise BadRule("bad_rule_name", "name")
    owner, mac = raw.get("owner") or "", raw.get("mac") or ""
    pid = raw.get("person_id")
    if pid is not None:   # Stage P: a person by id (the same as their name as owner)
        p = store.person(db, pid) if isinstance(pid, int) and not isinstance(pid, bool) \
            and 1 <= pid <= store.MAX_ROWID else None
        if p is None or owner:
            raise BadRule("bad_rule_target", "target")
        owner = p["name"]
    if not isinstance(owner, str) or not isinstance(mac, str):
        raise BadRule("bad_rule_target", "target")
    owner = store.clean_text(owner)
    mac = mac.strip()
    if bool(owner) == bool(mac):
        raise BadRule("bad_rule_target", "target")
    if mac:
        row = db.execute("SELECT mac FROM devices WHERE mac IN (?, ?)",
                         (mac, mac.lower())).fetchone() if len(mac) <= 64 else None
        if not row:
            raise BadRule("bad_rule_target", "target")
        mac = row["mac"]
    days = raw.get("days")
    if not isinstance(days, list) or not days or len(days) > 7 or \
            any(isinstance(d, bool) or not isinstance(d, int) or not 0 <= d <= 6 for d in days) \
            or len(set(days)) != len(days):
        raise BadRule("bad_rule_days", "days")
    start, end = raw.get("start"), raw.get("end")
    for field, v in (("start", start), ("end", end)):
        if not isinstance(v, str) or not TIME_RE.match(v):
            raise BadRule("bad_rule_time", field)
    if start == end:
        raise BadRule("bad_rule_time", "end")
    mins = raw.get("min_minutes", DEFAULT_MIN_MINUTES)
    if isinstance(mins, bool) or not isinstance(mins, int) or \
            not MIN_MINUTES[0] <= mins <= MIN_MINUTES[1]:
        raise BadRule("bad_rule_minutes", "min_minutes")
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise BadRule("bad_rule", "enabled")
    return {"id": rid, "name": store.clean_text(name, MAX_NAME), "owner": owner or None,
            "mac": mac or None, "days": sorted(days), "start": start, "end": end,
            "min_minutes": mins, "enabled": enabled}


# --- windows -------------------------------------------------------------------------

def _hm(text: str) -> dtime:
    h, m = text.split(":")
    return dtime(int(h), int(m))


NIGHT_CUTOFF = dtime(12, 0)   # a "night" runs noon -> noon


def window(rule: dict, night: date, tz: tzinfo) -> tuple:
    """(start, end) aware datetimes of the rule's window on `night`. A start before noon
    is after midnight, i.e. the NEXT calendar day: "Sunday night 00:00-06:00" is Monday
    00:00-06:00, so the school-nights preset never covers Saturday night."""
    s, e = _hm(rule["start"]), _hm(rule["end"])
    day = night + timedelta(days=1) if s < NIGHT_CUTOFF else night
    start = datetime.combine(day, s, tzinfo=tz)
    end = datetime.combine(day + timedelta(days=1) if e <= s else day, e, tzinfo=tz)
    return start, end


def occurrences(rule: dict, since: datetime, until: datetime, tz: tzinfo) -> list:
    """[(night date, start, end)] of the rule's windows that overlap [since, until)."""
    out = []
    d = since.astimezone(tz).date() - timedelta(days=2)   # a window may end 2 days later
    last = until.astimezone(tz).date()
    while d <= last:
        if d.weekday() in rule["days"]:
            ws, we = window(rule, d, tz)
            if ws < until and we > since:
                out.append((d, ws, we))
        d += timedelta(days=1)
    return out


def targets(rule: dict, owners: dict) -> list:
    """The devices a rule covers right now (owner -> every device with that owner)."""
    if rule.get("mac"):
        return [rule["mac"]]
    return sorted(m for m, o in owners.items() if o == rule.get("owner"))


def _owners(db) -> dict:
    return {m: p["owner"] for m, p in store.get_profiles(db).items() if p.get("owner")}


def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def hits(db, rule: dict, since: datetime, until: datetime, tz: tzinfo,
         data: dict | None = None, owners: dict | None = None) -> list:
    """Every (device, night) where the rule's window held >= min_minutes of estimated
    screen time, counting only up to `until`. Newest night first."""
    data = data or screentime.compute(db, tz, until)
    owners = _owners(db) if owners is None else owners
    out = []
    for mac in targets(rule, owners):
        dev = data["devices"].get(mac)
        if not dev:
            continue
        for night, ws, we in occurrences(rule, since, until, tz):
            a, b = ws.timestamp(), min(we, until).timestamp()
            secs = screentime.overlap(dev["union"], a, b)
            if secs / 60 < rule["min_minutes"]:
                continue
            inside = [(max(s, a), min(e, b)) for s, e in dev["union"] if e > a and s < b]
            per = {sid: screentime.overlap(ivs, a, b) for sid, ivs in dev["sessions"].items()}
            top = max(per.items(), key=lambda kv: (kv[1], kv[0]))[0] if per else None
            out.append({"rule_id": rule.get("id"), "mac": mac, "night": night.isoformat(),
                        "weekday": night.weekday(), "window": f"{rule['start']}–{rule['end']}",
                        "minutes": int(round(secs / 60)), "service_id": top,
                        "first_ts": _utc(datetime.fromtimestamp(inside[0][0], timezone.utc)),
                        "last_ts": _utc(datetime.fromtimestamp(inside[-1][1], timezone.utc)),
                        "ack": f"{ACK_PREFIX}{rule.get('id')}:{night.isoformat()}"})
    out.sort(key=lambda h: (h["night"], h["mac"]), reverse=True)
    return out


def alerts(db, tz: tzinfo | None = None, now: datetime | None = None) -> list:
    """Bedtime alerts of the last 24 h (every enabled rule), unfiltered by acks
    (alerts.compute filters). Each carries owner / rule name for the text."""
    tz = tz or activity.local_tz()
    explicit, now = now, now or datetime.now(timezone.utc)
    rules = [r for r in store.bedtime_rules(db) if r["enabled"]]
    if not rules:
        return []
    data = screentime.compute(db, tz, explicit)
    owners, names = _owners(db), store.device_names(db)
    out = []
    for r in rules:
        for h in hits(db, r, now - timedelta(hours=24), now, tz, data, owners):
            out.append({**h, "name": names.get(h["mac"], h["mac"]), "owner": owners.get(h["mac"]),
                        "rule_name": r["name"], "start": r["start"], "end": r["end"],
                        "min_minutes": r["min_minutes"]})
    return out


def covers(rules: list, owners: dict, mac: str, first: datetime, last: datetime,
           tz: tzinfo) -> bool:
    """Does an enabled rule cover `mac` for the whole span first..last (one window)?"""
    for r in rules:
        if not r["enabled"] or mac not in targets(r, owners):
            continue
        for _night, ws, we in occurrences(r, first, last + timedelta(seconds=1), tz):
            if ws <= first and last <= we:
                return True
    return False


def suppress_night(db, night: list, tz: tzinfo | None = None) -> list:
    """activity.night_alerts() minus the ones a bedtime rule already watches."""
    rules = store.bedtime_rules(db)
    if not night or not rules:
        return night
    tz = tz or activity.local_tz()
    owners = _owners(db)
    parse = lambda ts: datetime.fromisoformat(ts.replace("Z", "+00:00"))  # noqa: E731
    return [a for a in night
            if not covers(rules, owners, a["mac"], parse(a["first_ts"]), parse(a["last_ts"]), tz)]


# --- text + API shapes ---------------------------------------------------------------

def night_label(night: str, lang: str) -> str:
    """'2026-10-20' -> 'Tue 10-20' (weekday localized)."""
    d = date.fromisoformat(night)
    return f"{activity.weekday_names(lang)[d.weekday()]} {d:%m-%d}"


def days_text(days: list, lang: str) -> str:
    """[6, 0, 1, 2, 3] -> the localized preset name, or 'Mon, Tue, ...'."""
    s = sorted(days)
    if s == list(range(7)):
        return i18n.t("bed.days.every", lang)
    if s == sorted(SCHOOL_NIGHTS):
        return i18n.t("bed.days.school", lang)
    if s == [4, 5]:
        return i18n.t("bed.days.weekend", lang)
    names = activity.weekday_names(lang)
    order = [6, 0, 1, 2, 3, 4, 5] if 6 in s and 0 in s else range(7)
    return i18n.t("list_sep", lang).join(names[d] for d in order if d in s)


def explain(item: dict, lang: str) -> str:
    """One localized sentence for a bedtime alert / preview hit."""
    svc = services.service_name(item.get("service_id"), lang) if item.get("service_id") else ""
    key = "bed.alert_line_svc" if svc else "bed.alert_line"
    return i18n.t(key, lang, name=item["name"], dur=screentime.duration(item["minutes"], lang),
                  window=item["window"], night=night_label(item["night"], lang), service=svc)


def localize_hit(h: dict, names: dict, lang: str) -> dict:
    item = {**h, "name": h.get("name") or names.get(h["mac"], h["mac"])}
    return {**item, "night_label": night_label(h["night"], lang),
            "service": services.service_name(h["service_id"], lang) if h.get("service_id") else None,
            "text": explain(item, lang)}


def rule_view(db, rule: dict, lang: str, tz: tzinfo, now: datetime, data: dict,
              owners: dict, names: dict) -> dict:
    """A rule as the dashboard shows it: target name, days text and its last-7-days hits."""
    since = now - timedelta(days=PREVIEW_DAYS)
    hs = hits(db, rule, since, now, tz, data, owners)
    return {**rule, "target_name": rule["owner"] or names.get(rule["mac"], rule["mac"]),
            "devices": [{"mac": m, "name": names.get(m, m)} for m in targets(rule, owners)],
            "days_text": days_text(rule["days"], lang),
            "hits": [localize_hit(h, names, lang) for h in hs],
            "summary": summary_text(hs, lang)}


def summary_text(hs: list, lang: str) -> str:
    """'In the last 7 days this would have alerted on 3 nights: Mon 10-19, ...'."""
    if not hs:
        return i18n.t("bed.preview_none", lang, days=PREVIEW_DAYS)
    nights = sorted({h["night"] for h in hs})
    return i18n.t("bed.preview_some", lang, days=PREVIEW_DAYS, n=len(nights),
                  nights=i18n.t("list_sep", lang).join(night_label(n, lang) for n in nights))


def report(db, lang: str, tz: tzinfo | None = None, now: datetime | None = None) -> dict:
    """GET /api/bedtime: every rule with its last-7-days hits, plus the people and the
    devices a new rule can target."""
    lang = i18n.normalize(lang)
    tz = tz or activity.local_tz()
    explicit, now = now, now or datetime.now(timezone.utc)
    data = screentime.compute(db, tz, explicit)
    owners, names = _owners(db), store.device_names(db)
    people = sorted(set(owners.values()))
    ids = {p["name"]: p["id"] for p in store.people(db)}
    return {"tz": activity.tz_label(tz),
            "rules": [{**rule_view(db, r, lang, tz, now, data, owners, names),
                       "person_id": ids.get(r["owner"])}
                      for r in store.bedtime_rules(db)],
            "people": people, "max_rules": MAX_RULES,
            # Stage P: every person (also those without devices yet) a rule can target
            "persons": [{"id": p["id"], "name": p["name"]} for p in store.people(db)],
            "note": i18n.t("bed.note", lang, tz=activity.tz_label(tz))}


def preview(db, rule: dict, lang: str, tz: tzinfo | None = None,
            now: datetime | None = None) -> dict:
    """POST /api/bedtime/preview: an UNSAVED (validated) rule's last-7-days hits."""
    lang = i18n.normalize(lang)
    tz = tz or activity.local_tz()
    explicit, now = now, now or datetime.now(timezone.utc)
    data = screentime.compute(db, tz, explicit)
    owners, names = _owners(db), store.device_names(db)
    view = rule_view(db, rule, lang, tz, now, data, owners, names)
    return {"hits": view["hits"], "summary": view["summary"], "devices": view["devices"],
            "days_text": view["days_text"]}
