"""
netwarden - backup.py: save and restore the user's OWN notes as one JSON file.

What a backup holds - only what the user typed or decided, never collected data,
never a secret:

    labels         device names + notes            (device_labels)
    people         the household's people (Stage P) (people)
    profiles       type / owner / room / shared     (device_profiles)
    acks           trusted devices, "Got it" / muted / snoozed alerts   (acks)
    suggestions    done / dismissed / snoozed       (suggestion_state)
    bedtime_rules  the family's bedtime rules       (bedtime_rules)
    settings       what was changed in the dashboard (settings; never ai.key and
                   friends, which live in .env only)

Paired phones are NOT included: a restored backup must never sign a browser in.

    export(db)                      -> the backup document (dict)
    validate(doc)                   -> a clean copy, or BadBackup(code) - strict
    preview(db, doc, mode, env)     -> what restoring would change, per section
    restore(db, doc, mode, env)     -> apply it in ONE transaction; returns preview()

mode "merge" adds and updates (nothing of the user's is removed); "replace" makes each
section exactly what the backup says (settings set in the environment are left alone).
Used by GET /api/backup, POST /api/backup/preview, POST /api/restore (this computer
only) and `python3 -m netwarden backup` / `restore`.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import netwarden
from netwarden import bedtime, devicetype, settings, store, suggestions
from netwarden import people as _people

FORMAT = "netwarden-backup"
VERSION = 1
MAX_BYTES = 1 << 20              # the whole file
MAX_ITEMS = 5000                 # per section
MODES = ("merge", "replace")
SECTIONS = ("labels", "people", "profiles", "acks", "suggestions", "bedtime_rules", "settings")
PERSON_KEYS = ("avatar", "color", "child", "note", "presence", "presence_macs", "notify_arrive",
               "notify_leave")
SAMPLES = 5                      # example lines per section in a preview
MAX_SUGGESTION_DATA = 4096       # what a decided suggestion was about (shown under "Done")

DEVICE_KEY_RE = re.compile(r"^[0-9A-Za-z:._-]{1,64}$")   # a MAC (or the pseudo device "network")
TS_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z$")


class BadBackup(ValueError):
    """Not a netwarden backup we can read -> err.<code> (and the section, if any)."""
    def __init__(self, code: str, section: str = ""):
        super().__init__(f"{code} {section}".strip())
        self.code, self.section = code, section


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- export ----------------------------------------------------------------------

def stored_settings(db) -> dict:
    """The non-secret settings the user changed in the dashboard (DB rows only)."""
    out = {}
    for key, raw in store.get_settings(db).items():
        s = settings.REGISTRY.get(key)
        if s is None or s.secret:
            continue
        try:
            out[key] = s.clean(json.loads(raw))
        except (ValueError, TypeError):
            continue          # an invalid stored value is not worth carrying along
    return out


def export(db) -> dict:
    labels = [{"mac": m, "label": v["label"], "note": v["note"] or ""}
              for m, v in sorted(store.get_labels(db).items())]
    profiles = [{"mac": m, "type": p["type"], "owner": p["owner"], "room": p["room"],
                 "shared": p["shared"]}
                for m, p in sorted(store.get_profiles(db).items())]
    people = [{"name": p["name"], **{k: p[k] for k in PERSON_KEYS}} for p in store.people(db)]
    acks = [{"mac": a["mac"], "key": a["domain"], "until": a["until"]} for a in store.all_acks(db)]
    sugs = [{"id": sid, "status": st["status"], "until": st["until"], "data": st["data"]}
            for sid, st in sorted(store.suggestion_states(db).items())]
    rules = [{k: r[k] for k in ("id", "name", "owner", "mac", "days", "start", "end",
                                "min_minutes", "enabled")} for r in store.bedtime_rules(db)]
    return {"format": FORMAT, "version": VERSION, "created": _now(),
            "app_version": netwarden.__version__, "demo": store.is_demo(db),
            "data": {"labels": labels, "people": people, "profiles": profiles, "acks": acks,
                     "suggestions": sugs, "bedtime_rules": rules,
                     "settings": stored_settings(db)}}


def dumps(doc: dict) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=1) + "\n").encode("utf-8")


def filename() -> str:
    return f"netwarden-backup-{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"


# --- validation ------------------------------------------------------------------

# Every key a backup may contain, per level (export() writes exactly these): anything
# else - "sessions", a typo, a field from a future version - is refused, not ignored.
DOC_KEYS = {"format", "version", "created", "app_version", "demo", "data"}
ITEM_KEYS = {
    "labels": {"mac", "label", "note"},
    "people": {"name", *PERSON_KEYS},
    "profiles": {"mac", "type", "owner", "room", "shared"},
    "acks": {"mac", "key", "until"},
    "suggestions": {"id", "status", "until", "data"},
    "bedtime_rules": {"id", "name", "owner", "mac", "days", "start", "end", "min_minutes",
                      "enabled"},
}


def _list(data: dict, section: str) -> list:
    v = data.get(section, [])
    if not isinstance(v, list) or len(v) > MAX_ITEMS:
        raise BadBackup("backup_invalid", section)
    if any(not isinstance(x, dict) or set(x) - ITEM_KEYS[section] for x in v):
        raise BadBackup("backup_invalid", section)
    return v


def _text(v, limit: int, section: str, required: bool = False) -> str:
    if v is None:
        v = ""
    if not isinstance(v, str) or len(v) > limit * 4:
        raise BadBackup("backup_invalid", section)
    v = store.clean_text(v, limit)
    if required and not v:
        raise BadBackup("backup_invalid", section)
    return v


def _device(v, section: str) -> str:
    if not isinstance(v, str) or not DEVICE_KEY_RE.match(v.strip()):
        raise BadBackup("backup_invalid", section)
    return v.strip()


def _ts(v, section: str) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str) or not TS_RE.match(v):
        raise BadBackup("backup_invalid", section)
    return v


def validate(doc) -> dict:
    """A parsed backup -> a clean, canonical copy. Strict: unknown format / newer
    version / wrong types / too many items -> BadBackup. Duplicates: the last one wins."""
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise BadBackup("backup_format")
    ver = doc.get("version")
    if isinstance(ver, bool) or not isinstance(ver, int) or ver < 1:
        raise BadBackup("backup_format")
    if ver > VERSION:
        raise BadBackup("backup_version")
    data = doc.get("data")
    if not isinstance(data, dict) or set(doc) - DOC_KEYS:
        raise BadBackup("backup_format")
    if any(k not in SECTIONS for k in data):
        raise BadBackup("backup_invalid")
    out: dict = {s: {} for s in SECTIONS}
    for x in _list(data, "labels"):
        mac = _device(x.get("mac"), "labels")
        out["labels"][mac] = {"label": _text(x.get("label"), 100, "labels", required=True),
                              "note": _text(x.get("note"), 500, "labels")}
    for x in _list(data, "profiles"):
        mac = _device(x.get("mac"), "profiles")
        typ = x.get("type")
        if typ is not None and typ not in devicetype.TYPES:
            raise BadBackup("backup_invalid", "profiles")
        shared = x.get("shared", False)
        if not isinstance(shared, bool):
            raise BadBackup("backup_invalid", "profiles")
        prof = {"type": typ or None,
                "owner": _text(x.get("owner"), store.MAX_PROFILE_TEXT, "profiles") or None,
                "room": _text(x.get("room"), store.MAX_PROFILE_TEXT, "profiles") or None}
        prof["shared"] = shared and not prof["owner"]
        if any(prof.values()):
            out["profiles"][mac] = prof
    people = _list(data, "people")
    if len(people) > _people.MAX_PEOPLE:
        raise BadBackup("backup_invalid", "people")
    for x in people:
        out["people"].update(_person(x))
    for x in _list(data, "acks"):
        mac = _device(x.get("mac"), "acks")
        key = x.get("key", "")
        if not isinstance(key, str) or len(key) > 300 or any(ord(c) < 32 for c in key):
            raise BadBackup("backup_invalid", "acks")
        out["acks"][(mac, key)] = _ts(x.get("until"), "acks")
    for x in _list(data, "suggestions"):
        sid, status = x.get("id"), x.get("status")
        if not suggestions.valid_id(sid) or status not in store.SUGGESTION_STATUSES:
            raise BadBackup("backup_invalid", "suggestions")
        info = x.get("data")
        if info is not None and (not isinstance(info, dict) or
                                 len(json.dumps(info, ensure_ascii=False)) > MAX_SUGGESTION_DATA):
            raise BadBackup("backup_invalid", "suggestions")
        out["suggestions"][sid] = {"status": status, "until": _ts(x.get("until"), "suggestions"),
                                   "data": info}
    rules = []
    for x in _list(data, "bedtime_rules"):
        try:   # bedtime.validate needs the device to exist; check the shape without it
            clean = bedtime.validate(_NoDB(x.get("mac")), x)
        except bedtime.BadRule:
            raise BadBackup("backup_invalid", "bedtime_rules") from None
        rules.append(clean)
    if len(rules) > bedtime.MAX_RULES:
        raise BadBackup("backup_invalid", "bedtime_rules")
    out["bedtime_rules"] = rules
    sets = data.get("settings", {})
    if not isinstance(sets, dict) or len(sets) > len(settings.REGISTRY):
        raise BadBackup("backup_invalid", "settings")
    for key, value in sets.items():
        s = settings.REGISTRY.get(key)
        if s is None or s.secret:
            raise BadBackup("backup_invalid", "settings")
        try:
            out["settings"][key] = s.clean(value)
        except settings.SettingError:
            raise BadBackup("backup_invalid", "settings") from None
    return out


def _person(x: dict) -> dict:
    """One backed-up person -> {name: clean fields} (people.validate's rules)."""
    try:
        clean = _people.validate(_NoPeople(), {k: x[k] for k in ("name", "avatar", "color",
                                                                  "child", "note") if k in x})
    except _people.BadPerson:
        raise BadBackup("backup_invalid", "people") from None
    flags = {k: x.get(k, False) for k in ("presence", "notify_arrive", "notify_leave")}
    macs = x.get("presence_macs")
    if any(not isinstance(v, bool) for v in flags.values()) or (macs is not None and (
            not isinstance(macs, list) or len(macs) > 50
            or any(not isinstance(m, str) or not DEVICE_KEY_RE.match(m) for m in macs))):
        raise BadBackup("backup_invalid", "people")
    return {clean["name"]: {"avatar": clean["avatar"], "color": clean["color"],
                            "child": clean["child"], "note": clean["note"],
                            "presence_macs": sorted(set(macs)) if macs is not None else None,
                            **flags}}


class _NoPeople:
    """people.validate without a DB: no one to clash with (duplicates: the last wins)."""
    def execute(self, _sql, _args=()):
        rows = []
        return type("Cur", (), {"fetchone": staticmethod(lambda: None),
                                "__iter__": lambda self: iter(rows)})()


class _NoDB:
    """Stands in for the DB in bedtime.validate: "the target device exists" for exactly
    the MAC the rule names (a backup may come from before a device was discovered)."""
    def __init__(self, mac):
        self.mac = mac.strip() if isinstance(mac, str) and DEVICE_KEY_RE.match(mac.strip()) else None

    def execute(self, _sql, _args=()):
        row = {"mac": self.mac} if self.mac else None
        return type("Cur", (), {"fetchone": staticmethod(lambda: row)})()


def parse(raw: bytes | str) -> dict:
    """Bytes / text of a backup file -> validate()d data (BadBackup on anything else)."""
    if len(raw) > MAX_BYTES:
        raise BadBackup("backup_too_large")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise BadBackup("backup_format") from None
    return validate(doc)


# --- preview / restore -------------------------------------------------------------

def _rule_sig(r: dict) -> tuple:
    return (r.get("owner"), r.get("mac"), tuple(sorted(r["days"])), r["start"], r["end"],
            r["min_minutes"])


def _current(db) -> dict:
    return {
        "labels": {m: {"label": v["label"], "note": v["note"] or ""}
                   for m, v in store.get_labels(db).items()},
        "people": {p["name"]: {k: p[k] for k in PERSON_KEYS} for p in store.people(db)},
        "profiles": {m: {k: p[k] for k in ("type", "owner", "room", "shared")}
                     for m, p in store.get_profiles(db).items()},
        "acks": {(a["mac"], a["domain"]): a["until"] for a in store.all_acks(db)},
        "suggestions": {sid: {"status": st["status"], "until": st["until"], "data": st["data"]}
                        for sid, st in store.suggestion_states(db).items()},
        "bedtime_rules": store.bedtime_rules(db),
        "settings": stored_settings(db),
    }


def _env_locked(env: dict | None) -> set:
    env = env or {}
    return {k for k, s in settings.REGISTRY.items() if s.env and (env.get(s.env) or "").strip()}


def _sample(op: str, what, before=None, after=None) -> dict:
    return {"op": op, "what": what, "before": before, "after": after}


def _plan(db, data: dict, mode: str, env: dict | None) -> dict:
    """{section: {add, change, remove, same, skipped, samples, apply: {...}}}."""
    if mode not in MODES:
        raise BadBackup("backup_mode")
    cur = _current(db)
    known = {r["mac"] for r in db.execute("SELECT mac FROM devices")}
    names = store.device_names(db)
    plan = {}
    for sec in ("labels", "people", "profiles", "acks", "suggestions"):
        new, old = data[sec], cur[sec]
        p = {"add": 0, "change": 0, "remove": 0, "same": 0, "skipped": 0, "samples": []}
        for k, v in new.items():
            if k not in old:
                p["add"] += 1
                if len(p["samples"]) < SAMPLES:
                    p["samples"].append(_sample("add", _what(sec, k, names), None, _show(sec, v)))
            elif _cmp(sec, old[k]) != _cmp(sec, v):
                p["change"] += 1
                if len(p["samples"]) < SAMPLES:
                    p["samples"].append(_sample("change", _what(sec, k, names), _show(sec, old[k]),
                                                _show(sec, v)))
            else:
                p["same"] += 1
        if mode == "replace":
            for k in old:
                if k not in new:
                    p["remove"] += 1
                    if len(p["samples"]) < SAMPLES:
                        p["samples"].append(_sample("remove", _what(sec, k, names),
                                                    _show(sec, old[k])))
        plan[sec] = p
    # bedtime rules: a rule for a device this DB has never seen is skipped
    rules = [r for r in data["bedtime_rules"] if not r["mac"] or r["mac"] in known]
    old_sigs = {_rule_sig(r) for r in cur["bedtime_rules"]}
    p = {"add": 0, "change": 0, "remove": 0, "same": 0,
         "skipped": len(data["bedtime_rules"]) - len(rules), "samples": []}
    for r in rules:
        if _rule_sig(r) in old_sigs:
            p["same"] += 1
            continue
        p["add"] += 1
        if len(p["samples"]) < SAMPLES:
            p["samples"].append(_sample("add", r["name"] or r["owner"] or r["mac"], None,
                                        f"{r['start']}–{r['end']}"))
    if mode == "replace":
        new_sigs = {_rule_sig(r) for r in rules}
        p["remove"] = sum(1 for r in cur["bedtime_rules"] if _rule_sig(r) not in new_sigs)
    total = len(rules) if mode == "replace" else \
        len(cur["bedtime_rules"]) + p["add"]
    if total > bedtime.MAX_RULES:
        raise BadBackup("too_many_rules", "bedtime_rules")
    p["rules"] = rules
    plan["bedtime_rules"] = p
    # settings: environment-set keys stay as they are
    locked = _env_locked(env)
    new = {k: v for k, v in data["settings"].items() if k not in locked}
    old = cur["settings"]
    p = {"add": 0, "change": 0, "remove": 0, "same": 0,
         "skipped": len(data["settings"]) - len(new), "samples": []}
    for k, v in new.items():
        op = "add" if k not in old else ("same" if old[k] == v else "change")
        p[op] += 1
        if op != "same" and len(p["samples"]) < SAMPLES:
            p["samples"].append(_sample(op, k, _show("settings", old.get(k)), _show("settings", v)))
    if mode == "replace":
        gone = [k for k in old if k not in new and k not in locked]
        p["remove"] = len(gone)
        p["samples"] += [_sample("remove", k, _show("settings", old[k])) for k in gone][:SAMPLES]
    p["values"] = new
    plan["settings"] = p
    return plan


def _cmp(sec: str, v):
    """The part of a value that counts as "changed" (a suggestion's remembered context
    does not; nor does a person's presence switch - a restore never changes it)."""
    if sec == "people":
        return {k: x for k, x in v.items() if k != "presence"}
    return (v["status"], v["until"]) if sec == "suggestions" else v


def _what(sec: str, k, names: dict) -> str:
    """What a preview line is about: a device by its name (MAC when this DB has none)."""
    if sec == "acks":
        return f"{names.get(k[0]) or k[0]} {k[1]}".strip()
    if sec in ("labels", "profiles"):
        return names.get(k) or str(k)
    return str(k)


def _show(sec: str, v):
    """A short, plain description of one value for the preview (escaped by the page)."""
    if v is None:
        return None
    if sec == "labels":
        return v["label"]
    if sec == "profiles":
        return " · ".join(x for x in (v.get("type"), v.get("owner"), v.get("room")) if x)
    if sec == "people":
        return " ".join(x for x in (v.get("avatar"), v.get("note")) if x) or "·"
    if sec == "acks":
        return v
    if sec == "suggestions":
        return v["status"]
    return v if isinstance(v, (str, int, float, bool)) else json.dumps(v, ensure_ascii=False)


def preview(db, data: dict, mode: str, env: dict | None = None) -> dict:
    """What restore() would do: {mode, sections: [{key, add, change, remove, same,
    skipped, samples}], changes: total}."""
    plan = _plan(db, data, mode, env)
    secs = [{"key": s, **{k: v for k, v in plan[s].items() if k not in ("rules", "values")}}
            for s in SECTIONS]
    return {"mode": mode, "sections": secs,
            "changes": sum(s["add"] + s["change"] + s["remove"] for s in secs)}


def restore(db, data: dict, mode: str, env: dict | None = None) -> dict:
    """Apply a validated backup in one transaction (all or nothing). Returns preview()
    as it was just before."""
    before = preview(db, data, mode, env)
    plan = _plan(db, data, mode, env)
    ts = store.now()
    with db:
        if mode == "replace":
            for table in ("device_labels", "device_profiles", "acks", "suggestion_state",
                          "people"):
                db.execute(f"DELETE FROM {table}")
        for name, p in data["people"].items():
            # A restore never switches presence ON: that needs the person's own informed
            # "yes" (the privacy confirmation on the People page). A new person starts with
            # it off, an existing one keeps what they chose; the chosen devices and the
            # notification switches are restored and apply once presence is turned on.
            db.execute("""INSERT INTO people (name, avatar, color, child, note, presence,
                              presence_macs, notify_arrive, notify_leave, presence_since,
                              created_at, updated_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(name) DO UPDATE SET avatar = excluded.avatar,
                              color = excluded.color, child = excluded.child,
                              note = excluded.note,
                              presence_macs = excluded.presence_macs,
                              notify_arrive = excluded.notify_arrive,
                              notify_leave = excluded.notify_leave,
                              updated_at = excluded.updated_at""",
                       (name, p["avatar"], p["color"], int(p["child"]), p["note"], 0,
                        None if p["presence_macs"] is None else json.dumps(p["presence_macs"]),
                        int(p["notify_arrive"]), int(p["notify_leave"]), ts, ts, ts))
        for mac, v in data["labels"].items():
            db.execute("""INSERT INTO device_labels (mac, label, note, updated_at) VALUES (?, ?, ?, ?)
                          ON CONFLICT(mac) DO UPDATE SET label = excluded.label,
                              note = excluded.note, updated_at = excluded.updated_at""",
                       (mac, v["label"], v["note"], ts))
        for mac, p in data["profiles"].items():
            db.execute("""INSERT INTO device_profiles (mac, type, owner, room, shared, updated_at)
                          VALUES (?, ?, ?, ?, ?, ?)
                          ON CONFLICT(mac) DO UPDATE SET type = excluded.type,
                              owner = excluded.owner, room = excluded.room,
                              shared = excluded.shared, updated_at = excluded.updated_at""",
                       (mac, p["type"], p["owner"], p["room"], int(bool(p.get("shared"))), ts))
        for (mac, key), until in data["acks"].items():
            db.execute("""INSERT INTO acks (mac, domain, created_at, until) VALUES (?, ?, ?, ?)
                          ON CONFLICT(mac, domain) DO UPDATE SET until = excluded.until""",
                       (mac, key, ts, until))
        for sid, st in data["suggestions"].items():
            db.execute("""INSERT INTO suggestion_state (id, status, until, data, updated_at)
                          VALUES (?, ?, ?, ?, ?)
                          ON CONFLICT(id) DO UPDATE SET status = excluded.status,
                              until = excluded.until,
                              data = COALESCE(excluded.data, suggestion_state.data),
                              updated_at = excluded.updated_at""",
                       (sid, st["status"], st["until"] if st["status"] == "snoozed" else None,
                        json.dumps(st["data"], ensure_ascii=False) if st.get("data") else None, ts))
        rules = plan["bedtime_rules"]["rules"]
        if mode == "replace":
            db.execute("DELETE FROM bedtime_rules")
        existing = {_rule_sig(r) for r in store.bedtime_rules(db)}
        taken = {r["id"] for r in store.bedtime_rules(db)}
        for r in rules:
            if _rule_sig(r) in existing:
                continue
            rid = r["id"] if r["id"] and r["id"] not in taken else None
            cur = db.execute("""INSERT INTO bedtime_rules (id, name, owner, mac, days, win_start,
                                    win_end, min_minutes, enabled, created_at, updated_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                             (rid, r["name"], r["owner"], r["mac"],
                              ",".join(str(d) for d in sorted(r["days"])), r["start"], r["end"],
                              r["min_minutes"], int(r["enabled"]), ts, ts))
            taken.add(cur.lastrowid)
            existing.add(_rule_sig(r))
        values = plan["settings"]["values"]
        if mode == "replace":
            locked = _env_locked(env)
            for key in stored_settings(db):
                if key not in values and key not in locked:
                    db.execute("DELETE FROM settings WHERE key = ?", (key,))
        for key, value in values.items():
            db.execute("""INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
                          ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                              updated_at = excluded.updated_at""",
                       (key, json.dumps(value, ensure_ascii=False), ts))
    store.sync_people(db)   # an owner the backup names without a person row becomes one
    return before
