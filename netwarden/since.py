"""
netwarden - since.py: "Since your last visit" (Stage T, the Overview banner).

The page remembers when this browser last had the dashboard open (localStorage) and asks
GET /api/since?t=<UTC ISO> what happened after that, in five plain counts the household
can act on - each with the few items a click leads to:

    devices     devices that joined the network (devices.first_seen > t)
    alerts      alerts that appeared (their first routing in notify_log, Stage Q, is after
                t - or they were never routed yet) and are still current
    outages     outages that started (the outage log)
    arrivals    people who came home (presence ON only; presence.events)
    effects     suggestions that took effect (the data shows the change after t)

Read-only; localized names via naming.display_names. Nothing on the very first visit:
the page sends no `t` then.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netwarden import i18n, inbox, naming, nethealth, presence, store, suggestions

MAX_ITEMS = 5               # items listed per kind (the counts are complete)
MAX_SPAN = timedelta(days=30)    # an older last visit counts from 30 days ago


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_since(raw: str | None, now: datetime | None = None) -> str | None:
    """The `t` parameter as a canonical UTC ISO string (clamped to MAX_SPAN), or None
    when missing / malformed / in the future."""
    if not raw or not isinstance(raw, str) or len(raw) > 40:
        return None
    try:
        dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    try:
        dt = dt.astimezone(timezone.utc)
    except OverflowError:   # "0001-01-01T00:00:00+05:00" is before year 1 in UTC
        return None
    if dt > now + timedelta(minutes=5):
        return None
    return _iso(max(dt, now - MAX_SPAN))


def report(db, since: str, lang: str, env: dict | None = None, hours: float = 24,
           tz=None) -> dict:
    """{since, total, devices, alerts, outages, arrivals, effects}: each {n, items}."""
    lang = i18n.normalize(lang)
    names = naming.display_names(db, lang)
    rows = db.execute("SELECT mac, first_seen, is_self FROM devices WHERE first_seen > ? "
                      "ORDER BY first_seen DESC", (since,)).fetchall()
    devices = [{"mac": r["mac"], "name": names.get(r["mac"], r["mac"]), "ts": r["first_seen"]}
               for r in rows if not r["is_self"]]

    routed = {r["key"]: r["ts"] for r in db.execute("SELECT key, ts FROM notify_log")}
    alerts = [{"id": it["id"], "kind": it["kind"], "mac": it["mac"], "title": it["title"],
               "href": it["href"]}
              for it in inbox.alert_items(db, lang, hours)
              if routed.get(it["nkey"], "9999") > since and it["kind"] != "new"]

    outages = [{"id": o["id"], "ts": o["start_ts"], "cause": o["cause"],
                "text": nethealth.localize_outage(o, lang, tz)["text"]}
               for o in nethealth.outage_list(db, days=31) if o["start_ts"] > since]

    people = {p["id"]: p for p in store.people(db)}
    arrivals = [{"person": e["person_id"], "name": (people.get(e["person_id"]) or {}).get("name"),
                 "ts": e["ts"]}
                for e in presence.events(db, tz, None, env)
                if e["kind"] == "presence.arrive" and e["ts"] > since
                and (people.get(e["person_id"]) or {}).get("presence")]

    det = suggestions.detect(db, env)
    done = suggestions.with_status(det, store.suggestion_states(db))["done"]
    effects = [{"id": d["id"], "ts": d["effect_ts"],
                "title": suggestions.localize(d, lang, names)["title"]}
               for d in done if not d.get("waiting") and (d.get("effect_ts") or "") > since]

    out = {"since": since}
    total = 0
    for key, items in (("devices", devices), ("alerts", alerts), ("outages", outages),
                       ("arrivals", arrivals), ("effects", effects)):
        out[key] = {"n": len(items), "items": items[:MAX_ITEMS]}
        total += len(items)
    out["total"] = total
    return out
