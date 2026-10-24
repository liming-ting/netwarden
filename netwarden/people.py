"""
netwarden - people.py: the household's people (Stage P) - validation and the views.

A person (store.people) has a display name, an avatar (an emoji or up to 3 letters; empty
= their initials), a color (COLORS), an optional child flag and a short note. Each device
belongs to at most one person (device_profiles.owner = the person's name) or to "Shared"
(device_profiles.shared = 1, the household's TV / speaker) or to nobody.

Everything here is the USER's own notes in netwarden's SQLite - nothing about the network
changes. Names, notes and avatars are hostile text for every renderer (escape always).

    validate(db, raw)         -> a clean person dict, or BadPerson(code, field)
    cards(db, lang, tz)       -> GET /api/people: every person as a card + Shared + legacy items
    detail(db, pid, lang, tz) -> GET /api/person?id=: one person in full
    assign_items(db, raw)     -> POST /api/people/assign: validated [(mac, owner|None, shared)]
"""
from __future__ import annotations

import unicodedata

from netwarden import (activity, bedtime, devicetype, i18n, inbox, naming, presence, screentime,
                       store)

MAX_NAME = 40
MAX_NOTE = 200
MAX_AVATAR = 8          # characters (an emoji with modifiers / ZWJ can take several)
MAX_PEOPLE = 50
MAX_ASSIGN = 200        # devices per bulk assignment
COLORS = ("blue", "green", "amber", "rose", "violet", "teal", "orange", "slate")
FIELDS = ("id", "name", "avatar", "color", "child", "note")


class BadPerson(ValueError):
    def __init__(self, code: str, field: str = ""):
        super().__init__(code)
        self.code, self.field = code, field


def _avatar(value) -> str:
    """'' (initials), an emoji, or up to 3 letters / digits. Never markup or controls."""
    if not isinstance(value, str):
        raise BadPerson("bad_person", "avatar")
    v = value.strip()
    if not v:
        return ""
    if len(v) > MAX_AVATAR or any(unicodedata.category(c)[0] in "CZ" and c != "‍"
                                  and unicodedata.category(c) != "Cf" for c in v) \
            or any(c in "<>&\"'`‪‫‬‭‮⁦⁧⁨⁩"
                   for c in v):
        raise BadPerson("bad_person", "avatar")
    if all(c.isalnum() for c in v) and len(v) > 3:
        raise BadPerson("bad_person", "avatar")
    return v


def validate(db, raw) -> dict:
    """A POSTed person -> {id?, name, avatar, color, child, note}. The name is required,
    one line, at most MAX_NAME characters and unique (case-insensitive) among people."""
    if not isinstance(raw, dict) or set(raw) - set(FIELDS):
        raise BadPerson("bad_person", "person")
    pid = raw.get("id")
    if pid is not None:
        if isinstance(pid, bool) or not isinstance(pid, int) or store.person(db, pid) is None:
            raise BadPerson("no_person", "id")
    name = raw.get("name")
    if not isinstance(name, str) or len(name) > 200:
        raise BadPerson("bad_person_name", "name")
    name = store.clean_text(name, MAX_NAME)
    if not name:
        raise BadPerson("bad_person_name", "name")
    for p in store.people(db):
        if p["id"] != pid and p["name"].casefold() == name.casefold():
            raise BadPerson("person_exists", "name")
    if pid is None and len(store.people(db)) >= MAX_PEOPLE:
        raise BadPerson("too_many_people", "name")
    color = raw.get("color", "")
    if color not in ("",) + COLORS:
        raise BadPerson("bad_person", "color")
    child = raw.get("child", False)
    if not isinstance(child, bool):
        raise BadPerson("bad_person", "child")
    note = raw.get("note", "")
    if not isinstance(note, str) or len(note) > 2000:
        raise BadPerson("bad_person", "note")
    return {"id": pid, "name": name, "avatar": _avatar(raw.get("avatar", "")), "color": color,
            "child": child, "note": store.clean_text(note, MAX_NOTE)}


def owner_name(db, text: str) -> str:
    """The legacy owner field (POST /api/profile) -> a person's exact name. An existing
    person matches case-insensitively; a new name goes through validate() (length, the
    MAX_PEOPLE cap) and becomes that person when set_profile() stores it."""
    name = store.clean_text(text, 200)
    for p in store.people(db):
        if p["name"].casefold() == name.casefold():
            return p["name"]
    return validate(db, {"name": name})["name"]


def save(db, clean: dict) -> int:
    """Store a validate()d person (an update keeps the presence settings)."""
    old = store.person(db, clean["id"]) if clean.get("id") else None
    return store.save_person(db, {**(old or {}), **clean})


def initials(name: str) -> str:
    """'Mom' -> 'M', 'Anna Lee' -> 'AL', '媽媽' -> '媽' (one CJK character is enough),
    'Person 03' -> 'P3' (a number is kept whole, without leading zeros: not 'P0').
    static/app.js initialsOf() is the same rule."""
    words = name.split()
    if not words:
        return "?"
    if len(words) == 1:
        return words[0][0].upper()
    second = words[1]
    if second.isascii() and second.isdigit():
        second = str(int(second))[:2]
    else:
        second = second[0]
    return (words[0][0] + second).upper()


# --- assigning devices ------------------------------------------------------------------

def assign_items(db, raw) -> list:
    """POST /api/people/assign {"items": [{"mac", "person": id | null, "shared": bool}]}
    -> [(mac, owner name | None, shared)]. Every MAC must be in the inventory; person
    null + shared false = unassigned."""
    if not isinstance(raw, list) or not raw or len(raw) > MAX_ASSIGN:
        raise BadPerson("bad_assign", "items")
    known = {r["mac"] for r in db.execute("SELECT mac FROM devices")}
    ids = {p["id"]: p["name"] for p in store.people(db)}
    out, seen = [], set()
    for it in raw:
        if not isinstance(it, dict) or set(it) - {"mac", "person", "shared"}:
            raise BadPerson("bad_assign", "items")
        mac, pid, shared = it.get("mac"), it.get("person"), it.get("shared", False)
        if not isinstance(mac, str) or mac.lower() not in known or mac.lower() in seen:
            raise BadPerson("bad_assign", "mac")
        if pid is not None and (isinstance(pid, bool) or not isinstance(pid, int) or pid not in ids):
            raise BadPerson("no_person", "person")
        if not isinstance(shared, bool) or (shared and pid is not None):
            raise BadPerson("bad_assign", "shared")
        seen.add(mac.lower())
        out.append((mac.lower(), ids.get(pid), shared))
    return out


def assign(db, items: list) -> list:
    """Apply assign_items(); returns the before-state as POSTable items (for Undo)."""
    profiles = store.get_profiles(db)
    ids = {p["name"]: p["id"] for p in store.people(db)}
    before = []
    for mac, owner, shared in items:
        p = profiles.get(mac) or {}
        before.append({"mac": mac, "person": ids.get(p.get("owner")),
                       "shared": bool(p.get("shared")) and not p.get("owner")})
        store.assign(db, mac, owner, shared)
    return before


# --- views ------------------------------------------------------------------------------

def _base(p: dict) -> dict:
    return {"id": p["id"], "name": p["name"], "avatar": p["avatar"], "initials": initials(p["name"]),
            "color": p["color"], "child": p["child"], "note": p["note"], "presence": p["presence"],
            "notify_arrive": p["notify_arrive"], "notify_leave": p["notify_leave"],
            "default_devices": p["presence_macs"] is None, "presence_macs": p["presence_macs"]}


def _context(db, lang: str, tz, env):
    """What cards() and detail() share: names, types, screen time, bedtime, alerts, presence."""
    names = naming.display_names(db, lang)
    types = devicetype.classify_all(db)
    rand = {r["mac"]: (bool(r["randomized"]), r["last_seen"]) for r in
            db.execute("SELECT mac, randomized, last_seen FROM devices")}
    st = screentime.report(db, lang, 7, tz=tz)
    bed = bedtime.report(db, lang, tz=tz)
    items = inbox.collect(db, lang, env)
    pres = {r["id"]: r for r in presence.report(db, lang, tz, env=env, names=names)["people"]}
    return names, types, rand, st, bed, items, pres


def _devices(macs, names, types, rand, lang) -> list:
    return [{"mac": m, "name": names.get(m, m), "type": (types.get(m) or {}).get("type"),
             "type_name": devicetype.type_name((types.get(m) or {}).get("type"), lang),
             "randomized": rand.get(m, (False, None))[0], "last_seen": rand.get(m, (False, None))[1]}
            for m in macs]


def _card(p, macs, ctx, lang) -> dict:
    names, types, rand, st, bed, items, pres = ctx
    member = next((m for m in st["members"] if m["owner"] == p["name"]), None)
    rules = [r for r in bed["rules"] if r["owner"] == p["name"]
             or (r["mac"] and r["mac"] in macs)]
    hits = sum(len(r["hits"]) for r in rules if r["enabled"])
    alerts = [{"id": i["id"], "kind": i["kind"], "title": i["title"], "text": i["text"],
               "href": i["href"], "sev": i["sev"]} for i in items if i.get("mac") in macs]
    pr = pres.get(p["id"]) or {}
    return {**_base(p), "devices": _devices(macs, names, types, rand, lang),
            "today_minutes": member["today_minutes"] if member else 0,
            "week_minutes": member["minutes"] if member else 0,
            "top_services": [s["name"] for s in (member["top_services"] if member else [])[:3]],
            "bedtime": {"rules": len(rules), "enabled": sum(1 for r in rules if r["enabled"]),
                        "hits": hits,
                        "text": (i18n.t("people.bed_none", lang) if not rules else
                                 i18n.t("people.bed_hits", lang, n=hits) if hits else
                                 i18n.t("people.bed_ok", lang))},
            "alerts": alerts[:5], "alert_count": len(alerts),
            "state": pr.get("state", "off"), "state_name": pr.get("state_name"),
            "state_reason": pr.get("reason")}


def cards(db, lang: str, tz=None, env: dict | None = None) -> dict:
    """GET /api/people. `items` keeps the old shape ({name, devices, macs, names} per owner
    with devices) for older pages and scripts."""
    lang = i18n.normalize(lang)
    tz = tz or activity.local_tz()
    ctx = _context(db, lang, tz, env)
    names, types, rand = ctx[0], ctx[1], ctx[2]
    mine = presence.owned(db)
    profiles = store.get_profiles(db)
    inventory = set(rand)
    shared = sorted(m for m, p in profiles.items() if p.get("shared") and m in inventory)
    assigned = {m for ms in mine.values() for m in ms} | set(shared)
    legacy = [{**g, "names": [names.get(m, m) for m in g["macs"]]}
              for g in store.profile_values(db, "owner")]
    return {"people": [_card(p, mine.get(p["name"], []), ctx, lang) for p in store.people(db)],
            "shared": {"devices": _devices(shared, names, types, rand, lang)},
            "unassigned": len(inventory - assigned),
            "colors": list(COLORS), "items": legacy}


def detail(db, pid: int, lang: str, tz=None, env: dict | None = None) -> dict | None:
    """GET /api/person?id=: the card plus 7-day screen time per day and per service, the
    bedtime rules that cover them, their open alerts and (if on) their presence."""
    p = store.person(db, pid)
    if p is None:
        return None
    lang = i18n.normalize(lang)
    tz = tz or activity.local_tz()
    ctx = _context(db, lang, tz, env)
    macs = presence.owned(db).get(p["name"], [])
    card = _card(p, macs, ctx, lang)
    st, bed, pres = ctx[3], ctx[4], ctx[6]
    member = next((m for m in st["members"] if m["owner"] == p["name"]), None)
    card["alerts"] = [{"id": i["id"], "kind": i["kind"], "title": i["title"], "text": i["text"],
                       "href": i["href"], "sev": i["sev"]} for i in ctx[5] if i.get("mac") in macs]
    return {**card,
            "screen": {"by_day": member["by_day"] if member else
                       [{"date": d, "minutes": 0} for d in st["dates"]],
                       "top_services": member["top_services"] if member else [],
                       "avg_minutes": member["avg_minutes"] if member else 0,
                       "note": st["note"]},
            "rules": [r for r in bed["rules"] if r["owner"] == p["name"]
                      or (r["mac"] and r["mac"] in macs)],
            "presence_info": pres.get(pid)}
