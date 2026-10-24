"""
netwarden - tuning.py: how loud each alert is - per alert type and per device (Stage Q).

ONE mechanism, the acks table the inbox already uses (store.add_ack / remove_ack): the
user's own notes, nothing on the network changes.

    level "normal"   no row
    level "less"     ack (target, "less:<kind>")   fewer, stronger alerts (KEEPS below)
    level "off"      ack (target, "mute:<kind>")   until NULL = "until I change it";
                                                   until set  = snoozed for 1 h / 1 day / 1 week
    target           a device MAC, or ALL ("all") = every device

The inbox's "Mute" (mute:<kind> for one device) and "Snooze" (an item's own ack key with
an until) are the same rows, so the Tuning panel (state()) lists all of them with their
expiry, and restore() undoes any one. The two older switches alerts.unusual_hours and
family.bedtime_alerts (settings) still turn their kind off for everyone; state() lists
them too, so nothing is ever silently quiet.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from netwarden import store

ALL = "all"                      # the acks table's "device" for a whole alert type
MUTE, LESS = "mute:", "less:"
LEVELS = ("normal", "less", "off")
# Every alert kind (inbox.py's names). Per device: all but "new" (a device is new once)
# and "outage" (about the whole network).
KINDS = ("threat", "exposure", "upnp", "visibility", "night", "bedtime", "spike", "change",
         "new", "outage")
DEVICE_KINDS = KINDS[:8]
# How long "off" lasts: None = until I change it.
SNOOZES = {"1h": timedelta(hours=1), "1d": timedelta(days=1), "1w": timedelta(days=7),
           "forever": None}
# Security alert types: switching one OFF for the whole home (any snooze) is this
# computer's call only and needs an explicit confirmation (web._tuning_post). Per device,
# and "less sensitive" (still keeps the worst of them, KEEPS), stay open to every session.
CRITICAL_KINDS = ("threat", "exposure", "upnp")
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z")
# The old on/off switches that still silence a whole kind (settings.py).
SWITCHES = {"night": "alerts.unusual_hours", "bedtime": "family.bedtime_alerts"}

# What "less sensitive" keeps: a stricter version of each rule (explain.py states it).
LESS_NIGHT_QUERIES = 30          # activity.NIGHT_MIN_QUERIES (10) x 3
LESS_SPIKE_RATIO = 8.0           # alerts.SPIKE_RATIO (4) x 2 ...
LESS_SPIKE_BYTES = 5_000_000_000  # ... and at least 5 GB in the window
LESS_OUTAGE_MIN = 10
LESS_CHANGE_SERVICES = 2
KEEPS = {
    "threat": lambda a: a.get("severity") == "malicious",
    "exposure": lambda a: a.get("risk") == "high",
    "upnp": lambda a: bool(a.get("risky")),
    "visibility": lambda a: a.get("kind") == "bypass",
    "night": lambda a: (a.get("night_queries") or 0) >= LESS_NIGHT_QUERIES,
    "bedtime": lambda a: (a.get("minutes") or 0) >= 2 * (a.get("min_minutes") or 0),
    "spike": lambda a: (a.get("ratio") or 0) >= LESS_SPIKE_RATIO
                       and (a.get("total") or 0) >= LESS_SPIKE_BYTES,
    "change": lambda a: len(a.get("new_service_ids") or []) >= LESS_CHANGE_SERVICES,
    "new": lambda a: not a.get("randomized"),
    "outage": lambda a: (a.get("minutes") or 0) >= LESS_OUTAGE_MIN,
}


class BadTuning(ValueError):
    """A tuning request the API refuses -> 400 err.<code>."""
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- reading (alerts.compute asks these with ONE store.list_acks set) -----------------

def is_off(acks: set, kind: str, mac: str | None) -> bool:
    """Is `kind` switched off (or snoozed) for this device or for everyone?"""
    return (ALL, MUTE + kind) in acks or bool(mac and (mac, MUTE + kind) in acks)


def is_less(acks: set, kind: str, mac: str | None) -> bool:
    return (ALL, LESS + kind) in acks or bool(mac and (mac, LESS + kind) in acks)


def keeps(acks: set, kind: str, mac: str | None, item: dict) -> bool:
    """Does the tuning let this alert through (not off; strong enough when "less")?"""
    if is_off(acks, kind, mac):
        return False
    return not is_less(acks, kind, mac) or KEEPS[kind](item)


def level(acks: set, kind: str, mac: str | None) -> str:
    """The level in force for (kind, device): the stricter of the device's and the
    whole type's."""
    if is_off(acks, kind, mac):
        return "off"
    return "less" if is_less(acks, kind, mac) else "normal"


# --- writing ---------------------------------------------------------------------

def _check(db, kind, target) -> str:
    if not isinstance(kind, str) or kind not in KINDS:
        raise BadTuning("bad_tuning")
    if target is None or target == ALL:
        return ALL
    if not isinstance(target, str) or kind not in DEVICE_KINDS:
        raise BadTuning("bad_tuning")
    row = db.execute("SELECT mac FROM devices WHERE mac IN (?, ?)",
                     (target.strip(), target.strip().lower())).fetchone()
    if not row:
        raise BadTuning("bad_mac")
    return row["mac"]


def set_level(db, kind: str, target: str | None, lvl: str, snooze: str | None = None,
              now: datetime | None = None) -> dict:
    """Set (kind, target) to `lvl`; "off" takes `snooze` (1h | 1d | 1w | forever / None).
    Returns {kind, mac, level, until, before: [rows it replaced]} - `before` is what
    restore_rows() needs for Undo."""
    mac = _check(db, kind, target)
    if lvl not in LEVELS:
        raise BadTuning("bad_tuning")
    if snooze is not None and (lvl != "off" or snooze not in SNOOZES):
        raise BadTuning("bad_tuning")
    now = now or datetime.now(timezone.utc)
    span = SNOOZES.get(snooze or "forever")
    until = _iso(now + span) if span else None
    before = rows_for(db, mac, kind)
    with db:
        db.execute("DELETE FROM acks WHERE mac = ? AND domain IN (?, ?)",
                   (mac, MUTE + kind, LESS + kind))
        if lvl != "normal":
            db.execute("INSERT INTO acks (mac, domain, created_at, until) VALUES (?, ?, ?, ?)",
                       (mac, (MUTE if lvl == "off" else LESS) + kind, _iso(now), until))
    return {"kind": kind, "mac": mac, "level": lvl, "until": until, "before": before}


def silences_critical(mac: str, domain: str) -> bool:
    """Would an acks row (mac, domain) switch a security alert type off for everyone?"""
    return mac == ALL and domain in tuple(MUTE + k for k in CRITICAL_KINDS)


def clean_row(r) -> dict:
    """A tuning row coming back from the page (Undo): the right shape, and real UTC
    timestamps - a malformed `until` would compare wrongly and might never expire."""
    if not isinstance(r, dict) or not isinstance(r.get("domain"), str) \
            or not isinstance(r.get("created_at"), str) or not TS_RE.fullmatch(r["created_at"]) \
            or not (r.get("until") is None or (isinstance(r["until"], str)
                                                and TS_RE.fullmatch(r["until"]))):
        raise BadTuning("bad_tuning")
    return r


def rows_for(db, mac: str, kind: str) -> list:
    return [dict(r) for r in db.execute(
        "SELECT mac, domain, created_at, until FROM acks WHERE mac = ? AND domain IN (?, ?)",
        (mac, MUTE + kind, LESS + kind))]


def restore_rows(db, mac: str, kind: str, rows: list) -> None:
    """Undo a set_level(): put (mac, kind)'s tuning rows back exactly as they were."""
    with db:
        db.execute("DELETE FROM acks WHERE mac = ? AND domain IN (?, ?)",
                   (mac, MUTE + kind, LESS + kind))
        for r in rows:
            if r.get("domain") in (MUTE + kind, LESS + kind):
                db.execute("INSERT OR REPLACE INTO acks (mac, domain, created_at, until) "
                           "VALUES (?, ?, ?, ?)", (mac, r["domain"], r["created_at"], r["until"]))


# --- the Tuning panel ----------------------------------------------------------------

def key_kind(key: str) -> str | None:
    """The alert kind an item's own ack key belongs to (for snoozed items)."""
    if key.startswith((MUTE, LESS)):
        return key.split(":", 1)[1]
    for prefix, kind in (("port:", "exposure"), ("visibility:", "visibility"),
                         ("activity:", "night"), ("bandwidth:", "spike"), ("upnp:", "upnp"),
                         ("bedtime:", "bedtime"), ("change:", "change"), ("outage:", "outage")):
        if key.startswith(prefix):
            return kind
    if key == "new":
        return "new"
    return "threat" if key else None


def state(db, env: dict | None = None, now: datetime | None = None) -> list:
    """Every tuning in force: [{id, kind, mac, level ("less" | "off" | "snoozed"), key,
    until, created_at, source ("tuning" | "snooze" | "setting")}], soonest expiry first.
    A snoozed single item ("Snooze" in the inbox) is listed with its own key."""
    from netwarden import settings
    now_iso = _iso(now or datetime.now(timezone.utc))
    out = []
    for r in db.execute("SELECT mac, domain, created_at, until FROM acks "
                        "WHERE until IS NULL OR until > ? ORDER BY created_at", (now_iso,)):
        key = r["domain"]
        if key.startswith((MUTE, LESS)):
            kind = key.split(":", 1)[1]
            lvl = "less" if key.startswith(LESS) else "off"
            src = "tuning"
        elif r["until"] and key:         # a snoozed single alert ("" = trust: not tuning)
            kind, lvl, src = key_kind(key), "snoozed", "snooze"
        else:
            continue
        if kind not in KINDS:
            continue
        out.append({"id": f"ack|{r['mac']}|{key}", "kind": kind, "mac": r["mac"], "key": key,
                    "level": lvl, "until": r["until"], "created_at": r["created_at"],
                    "source": src})
    vals = settings.values(db, env or {})
    for kind, skey in SWITCHES.items():
        if not vals[skey]:
            out.append({"id": f"setting|{skey}", "kind": kind, "mac": ALL, "key": skey,
                        "level": "off", "until": None, "created_at": None, "source": "setting",
                        "env": settings.REGISTRY[skey].env and
                        bool((env or {}).get(settings.REGISTRY[skey].env))})
    out.sort(key=lambda e: (e["until"] is None, e["until"] or "", e["kind"]))
    return out


def restore(db, entry_id: str, env: dict | None = None) -> dict:
    """Undo one Tuning-panel entry ("Restore"): the ack row is deleted (returned, so the
    page's Undo can put it back with restore_undo()), a legacy switch is turned on."""
    from netwarden import settings
    if not isinstance(entry_id, str) or len(entry_id) > 400:
        raise BadTuning("bad_tuning")
    src, _, rest = entry_id.partition("|")
    if src == "setting":
        if rest not in SWITCHES.values():
            raise BadTuning("bad_tuning")
        try:
            settings.update(db, env, {rest: True})
        except settings.SettingError as e:
            raise BadTuning(e.code) from None
        return {"setting": rest}
    if src != "ack":
        raise BadTuning("bad_tuning")
    mac, _, key = rest.partition("|")
    row = db.execute("SELECT mac, domain, created_at, until FROM acks WHERE mac = ? AND domain = ?",
                     (mac, key)).fetchone()
    if not row or not key:
        raise BadTuning("no_tuning")
    store.remove_ack(db, mac, key)
    return {"row": dict(row)}


def restore_undo(db, undo: dict, env: dict | None = None) -> None:
    """Put back what restore() removed (the page's Undo)."""
    from netwarden import settings
    if not isinstance(undo, dict):
        raise BadTuning("bad_tuning")
    if "setting" in undo:
        if undo["setting"] not in SWITCHES.values():
            raise BadTuning("bad_tuning")
        try:
            settings.update(db, env, {undo["setting"]: False})
        except settings.SettingError as e:
            raise BadTuning(e.code) from None
        return
    r = undo.get("row")
    if set(undo) != {"row"} or not isinstance(r, dict) or not isinstance(r.get("mac"), str):
        raise BadTuning("bad_tuning")
    clean_row(r)
    if len(r["domain"]) > 300 or key_kind(r["domain"]) not in KINDS:
        raise BadTuning("bad_tuning")
    if r["mac"] != ALL and not db.execute("SELECT 1 FROM devices WHERE mac = ?", (r["mac"],)).fetchone() \
            and r["mac"] != "network":
        raise BadTuning("bad_mac")
    with db:
        db.execute("INSERT OR REPLACE INTO acks (mac, domain, created_at, until) VALUES (?, ?, ?, ?)",
                   (r["mac"], r["domain"], r["created_at"], r["until"]))


def device_levels(db, mac: str) -> dict:
    """{kind: {level, until, scope ("device" | "all")}} for one device's drawer."""
    acks = store.list_acks(db)
    rows = {(r["mac"], r["domain"]): r["until"] for r in db.execute(
        "SELECT mac, domain, until FROM acks WHERE mac IN (?, ?)", (mac, ALL))}
    out = {}
    for kind in DEVICE_KINDS:
        lvl = level(acks, kind, mac)
        scope = "device"
        if lvl != "normal" and not ((mac, MUTE + kind) in acks or (mac, LESS + kind) in acks):
            scope = "all"
        key = (MUTE if lvl == "off" else LESS) + kind
        until = rows.get((mac if scope == "device" else ALL, key)) if lvl != "normal" else None
        out[kind] = {"level": lvl, "until": until, "scope": scope}
    return out
