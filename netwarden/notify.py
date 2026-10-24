"""
netwarden - notify.py: THE one place that decides whether an event becomes a
notification (Stage P; quiet hours + the "while you were asleep" summary: Stage Q).

Every notifiable event goes through route(): the presence arrivals and departures
(presence.events) and every alert (inbox.alert_items, as "alert.<kind>" events). route()
answers "deliver this now?" - it never sends anything itself: the dashboard shows what
GET /api/notify returns as browser notifications and toasts (app.js checkNotify,
deduplicated by `key`), so nothing ever leaves this machine.

A decision is made ONCE per event and kept in notify_log:
    sent      shown when it happened (route() returns it)
    held      it happened during quiet hours (quiet.py) and is not critical (or critical
              alerts do not bypass): it waits; the dashboard still lists the alert itself
    released  the window ended and it went into that window's ONE summary
release() turns a finished window's held events into one quiet_summaries row - exactly
once (UNIQUE window, one transaction), also after a restart. The very first routing on a
database only primes the log (nothing old is held or summarized).

    event = {"kind": "presence.arrive" | "presence.leave", "person_id": 3, "ts": ...}
          | {"kind": "alert.<inbox kind>", "key": <stable instance key>, "mac", "name",
             "critical": bool, "detail": ...}
    route(db, event, now, people, quiet_now) -> the event + {"key", "critical"}, or None
    feed(db, env, lang, ...)                 -> GET /api/notify
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from netwarden import i18n, quiet, store, tuning

KINDS = ("presence.arrive", "presence.leave")
ALERT = "alert."
# A notification is about NOW: older presence events are history (the timeline shows them).
# The age counts from when the event became knowable ("due": a departure is only known a
# grace period after the last sighting, presence.events), not from its own timestamp.
MAX_AGE = timedelta(minutes=30)
# An event routed late whose own time ("at") fell inside a quiet window that has ended
# since joins that window's summary (_window), if it is at most this old.
LATE_ROUTE = timedelta(hours=24)
PRIMED = "notify.primed"         # meta: the log has been primed on this database
MAX_DELIVER = 50
SUMMARY_LINES = 8


def _when(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def _iso(dt: datetime) -> str:
    # in UTC whatever zone an aware `dt` carries: stored times compare as strings
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def critical(event: dict) -> bool:
    """Critical security alerts (they may bypass quiet hours): a threat-list domain
    contacted, a NEW router port mapping on a risky port, a NEWLY opened high-risk port,
    and a DNS-filter bypass by a device that is itself new on the network."""
    kind = (event.get("kind") or "")[len(ALERT):] if (event.get("kind") or "").startswith(ALERT) else ""
    return kind in ("threat", "exposure", "upnp", "visibility") and bool(event.get("critical"))


def quiet_now(db, env: dict | None = None, now: datetime | None = None, tz=None) -> dict:
    """{"cfg", "active"} for route(): computed once per batch."""
    cfg = quiet.config(db, env)
    return {"cfg": cfg, "active": quiet.active(cfg, now, tz), "tz": tz}


def route(db, event: dict, now: datetime | None = None, people: dict | None = None,
          quiet_state: dict | None = None) -> dict | None:
    """Should `event` be shown as a notification now? -> the event with a stable dedupe
    `key` (+ critical), or None (not notifiable, switched off, or held for the summary).
    `people` (id -> store.person) saves a lookup per event; `quiet_state` (quiet_now())
    one settings read per event."""
    kind = event.get("kind") or ""
    now = now or datetime.now(timezone.utc)
    if kind in KINDS:
        when = _when(event.get("due") or event.get("ts") or "")
        if when is None or now - when > MAX_AGE or when - now > MAX_AGE:
            return None
        pid = event.get("person_id")
        p = (people or {}).get(pid) if people is not None else store.person(db, pid)
        if not p or not p.get("presence"):
            return None
        if not p.get("notify_arrive" if kind == "presence.arrive" else "notify_leave"):
            return None
        ev = {**event, "key": f"{kind}:{pid}:{event['ts']}", "critical": False,
              "at": event["ts"]}
        data = {"person_id": pid, "name": p.get("name"), "ts": event["ts"]}
    elif kind.startswith(ALERT) and kind[len(ALERT):] in tuning.KINDS:
        if not isinstance(event.get("key"), str) or not event["key"]:
            return None
        ev = {**event, "critical": critical(event), "at": event.get("when")}
        data = {k: event.get(k) for k in ("mac", "name", "detail")}
    else:
        return None
    return _decide(db, ev, data, now, quiet_state)


def _window(qs: dict, ev: dict, now: datetime, tz=None) -> dict | None:
    """The quiet window the event belongs to: the one running now, or - for an event
    first routed only after its window ended (the machine was off overnight, a source
    caught up late) - the window its own time `at` fell in, within LATE_ROUTE. Such an
    event goes into that night's summary instead of popping up the next morning."""
    if qs["active"] is not None:
        return qs["active"]
    at = _when(ev.get("at") or "")
    if at is None or at > now or now - at > LATE_ROUTE:
        return None
    return quiet.active(qs["cfg"], at, tz or qs.get("tz"))


def _decide(db, ev: dict, data: dict, now: datetime, qs: dict | None) -> dict | None:
    row = db.execute("SELECT state FROM notify_log WHERE key = ?", (ev["key"],)).fetchone()
    if row is None:
        qs = qs if qs is not None else quiet_now(db, now=now)
        act = _window(qs, ev, now)
        hold = act is not None and store.get_meta(db, PRIMED) == "1" \
            and not (ev["critical"] and qs["cfg"]["critical"])
        if hold:
            data = {**data, "win_start": _iso(act["start"])}
        with db:
            db.execute("""INSERT OR IGNORE INTO notify_log (key, kind, ts, state, critical, win,
                                                            until, data)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                       (ev["key"], ev["kind"], _iso(now), "held" if hold else "sent",
                        int(ev["critical"]), act["win"] if hold else None,
                        _iso(act["end"]) if hold else None,
                        json.dumps(data, ensure_ascii=False)))
        row = db.execute("SELECT state FROM notify_log WHERE key = ?", (ev["key"],)).fetchone()
    return ev if row["state"] == "sent" else None


def prime(db) -> None:
    """After the first batch on a database: from now on quiet hours may hold events."""
    if store.get_meta(db, PRIMED) != "1":
        store.set_meta(db, PRIMED, "1")


# --- the summary ------------------------------------------------------------------

def release(db, now: datetime | None = None) -> list:
    """Every quiet window that has ended and still holds events -> ONE summary each.
    Exactly once: the held rows are claimed and the summary written in one IMMEDIATE
    transaction, and a window has at most one summary (UNIQUE). Returns the new ids."""
    now_iso = _iso(now or datetime.now(timezone.utc))
    wins = [r["win"] for r in db.execute(
        "SELECT DISTINCT win FROM notify_log WHERE state = 'held' AND until <= ?", (now_iso,))]
    made = []
    for win in wins:
        db.execute("BEGIN IMMEDIATE")
        try:
            rows = db.execute("""SELECT key, kind, ts, critical, until, data FROM notify_log
                                 WHERE state = 'held' AND win = ? AND until <= ? ORDER BY ts""",
                              (win, now_iso)).fetchall()
            if rows:
                items = []
                for r in rows:
                    d = json.loads(r["data"] or "{}")
                    items.append({"key": r["key"], "kind": r["kind"], "ts": r["ts"],
                                  **{k: v for k, v in d.items() if k != "win_start"}})
                start = min((json.loads(r["data"] or "{}").get("win_start") or r["ts"]) for r in rows)
                cur = db.execute("""INSERT OR IGNORE INTO quiet_summaries
                                    (win, start_ts, end_ts, items, created_at) VALUES (?, ?, ?, ?, ?)""",
                                 (win, start, max(r["until"] for r in rows),
                                  json.dumps(items, ensure_ascii=False), now_iso))
                if cur.rowcount:
                    made.append(cur.lastrowid)
                else:   # (a summary for this window exists: add what was held after it)
                    old = db.execute("SELECT id, items FROM quiet_summaries WHERE win = ?",
                                     (win,)).fetchone()
                    # ... and show it again: a summary the user already closed would
                    # otherwise hide these late events for good
                    db.execute("UPDATE quiet_summaries SET items = ?, seen_at = NULL WHERE id = ?",
                               (json.dumps(json.loads(old["items"]) + items, ensure_ascii=False),
                                old["id"]))
                db.execute("UPDATE notify_log SET state = 'released' WHERE state = 'held' "
                           "AND win = ? AND until <= ?", (win, now_iso))
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return made


def held_count(db, win: str | None) -> int:
    if not win:
        return 0
    return db.execute("SELECT COUNT(*) FROM notify_log WHERE state = 'held' AND win = ?",
                      (win,)).fetchone()[0]


def _line(it: dict, lang: str, names: dict, people: dict) -> str:
    kind = it["kind"]
    if kind in KINDS:
        p = people.get(it.get("person_id")) or {}
        from netwarden import activity
        when = _when(it.get("ts") or "")
        time = when.astimezone(activity.local_tz()).strftime("%H:%M") if when else ""
        return i18n.t("quiet.item." + kind, lang, name=p.get("name") or it.get("name") or "?",
                      time=time)
    k = kind[len(ALERT):]
    name = names.get(it.get("mac")) or it.get("name") or it.get("mac") or "?"
    detail = it.get("detail")
    if k == "change" and isinstance(detail, list):
        from netwarden import services
        detail = i18n.t("list_sep", lang).join(services.service_name(s, lang) for s in detail)
    elif k == "outage" and isinstance(detail, str):
        detail = i18n.t("health.cause." + detail, lang)
    return i18n.t("quiet.item." + k, lang, name=name, detail=detail or "")


def _href(it: dict) -> str:
    kind = it["kind"]
    if kind in KINDS:
        return f"#/people/{it.get('person_id')}"
    k = kind[len(ALERT):]
    if k == "outage":
        return "#/health"
    mac = it.get("mac")
    return f"#/device/{mac}" if mac else "#/security"


def localize_summary(db, s: dict, lang: str, tz=None) -> dict:
    """A quiet_summaries row for the dashboard: title, one line per held event."""
    from netwarden import activity, naming
    tz = tz or activity.local_tz()
    items = json.loads(s["items"]) if isinstance(s["items"], str) else s["items"]
    names = naming.display_names(db, lang)
    people = {p["id"]: p for p in store.people(db)}
    span = "–".join(_when(t).astimezone(tz).strftime("%H:%M") for t in (s["start_ts"], s["end_ts"]))
    lines = [{"kind": it["kind"], "text": _line(it, lang, names, people), "href": _href(it)}
             for it in items]
    return {"id": s["id"], "win": s["win"], "key": f"quiet:{s['win']}", "start_ts": s["start_ts"],
            "end_ts": s["end_ts"], "created_at": s["created_at"], "seen": bool(s["seen_at"]),
            "count": len(lines), "title": i18n.t("quiet.summary_title", lang, span=span),
            "text": i18n.t("quiet.summary_text", lang, n=len(lines)),
            "items": lines[:SUMMARY_LINES], "more": max(0, len(lines) - SUMMARY_LINES)}


def summaries(db, lang: str, unseen_only: bool = True, limit: int = 3) -> list:
    rows = db.execute(f"""SELECT * FROM quiet_summaries {'WHERE seen_at IS NULL' if unseen_only else ''}
                          ORDER BY end_ts DESC LIMIT ?""", (limit,)).fetchall()
    return [localize_summary(db, dict(r), lang) for r in rows]


def mark_seen(db, sid, seen: bool = True) -> bool:
    """The user closed (or, Undo, reopened) a summary card. False if there is no such id."""
    if isinstance(sid, bool) or not isinstance(sid, int) or not 0 < sid < 2 ** 63:
        return False
    with db:
        cur = db.execute("UPDATE quiet_summaries SET seen_at = ? WHERE id = ?",
                         (store.now() if seen else None, sid))
    return cur.rowcount == 1


# --- the feed the dashboard polls ------------------------------------------------

def alert_events(db, lang: str, hours: float = 24) -> list:
    """Every current alert as an "alert.<kind>" event (inbox.alert_items)."""
    from netwarden import inbox
    out = []
    for it in inbox.alert_items(db, lang, hours):
        out.append({"kind": ALERT + it["kind"], "key": it["nkey"], "mac": it["mac"],
                    "name": it["name"], "critical": it["critical"], "detail": it.get("detail"),
                    "title": it["title"], "text": it["text"], "href": it["href"],
                    "sev": it["sev"], "when": it.get("when")})
    return out


def run(db, env: dict | None = None, lang: str = "en", hours: float = 24,
        now: datetime | None = None, tz=None) -> list:
    """One pass: release finished windows, route every current alert and presence event.
    -> the events to deliver now. The run loop calls it every minute, so holds are
    recorded even while no dashboard is open."""
    from netwarden import presence
    now = now or datetime.now(timezone.utc)
    release(db, now)
    qs = quiet_now(db, env, now, tz)
    people = {p["id"]: p for p in store.people(db)}
    out = []
    for e in alert_events(db, lang, hours) + presence.events(db, tz, None, env):
        r = route(db, e, now, people, qs)
        if r:
            out.append(r)
    prime(db)
    release(db, now)        # late events held into a window that has already ended
    return out


def feed(db, env: dict | None, lang: str, hours: float = 24, now: datetime | None = None,
         tz=None) -> dict:
    """GET /api/notify: {quiet, deliver, held, summaries}. `deliver` = what may pop up now
    (the page dedupes by key and primes on its first load); held events wait for the
    summary; `summaries` = unseen "while you were asleep" summaries, newest first."""
    from netwarden import activity
    tz = tz or activity.local_tz()
    lang = i18n.normalize(lang)
    out = run(db, env, lang, hours, now, tz)
    people = {p["id"]: p for p in store.people(db)}
    deliver = []
    for e in out[:MAX_DELIVER]:
        if e["kind"] in KINDS:
            p = people.get(e.get("person_id")) or {}
            when = _when(e["ts"])
            deliver.append({"key": e["key"], "kind": e["kind"], "critical": False,
                            "tag": i18n.t("app.pres.title", lang),
                            "text": i18n.t("app.pres.n_" + e["kind"].split(".")[1], lang,
                                           name=p.get("name") or "",
                                           time=when.astimezone(tz).strftime("%H:%M")),
                            "href": f"#/people/{e.get('person_id')}", "mac": None})
        else:
            deliver.append({"key": e["key"], "kind": e["kind"], "critical": e["critical"],
                            "tag": i18n.t(TAGS.get(e["kind"][len(ALERT):], "ui.tag_new"), lang)
                            if e["kind"] != ALERT + "threat" else
                            i18n.t("sev.malicious" if e["sev"] == 0 else "sev.high_risk", lang),
                            "text": f"{e['title']}: {e['text']}", "href": e["href"],
                            "mac": e["mac"]})
    q = quiet.describe(db, env, lang, now, tz)
    return {"quiet": q, "deliver": deliver, "held": held_count(db, q["win"]),
            "summaries": summaries(db, lang)}


TAGS = {"exposure": "ui.tag_exposure", "upnp": "app.tag_upnp", "outage": "app.tag_outage",
        "visibility": "ui.tag_visibility", "night": "ui.tag_night", "bedtime": "app.tag_bedtime",
        "spike": "ui.tag_spike", "new": "ui.tag_new", "change": "ui.tag_changed"}
