"""
netwarden - push.py: opt-in push notifications (round 10, Stage N; docs/notifications.md).

Off by default. A user (an admin: this computer, or an admin session) adds CHANNELS -
ntfy, Gotify, Home Assistant, a webhook, Discord, Slack, Telegram, LINE, Matrix
(channels.py) - and decides per channel WHAT goes there and HOW MUCH it says:

    categories   security | devices | family | health | score | digest (weekly)
    min_sev      alerts at least this severe (0 critical ... 3 low)
    level        minimal  "1 new alert: Security - open the dashboard" (no names)
                 standard plain-language sentence with device display names; no MAC or
                          IP addresses, no raw domains (the default)
                 detailed + addresses and domains (a channel off the private network
                          needs an explicit confirmation)
    lang         "" = the dashboard's language, or its own
    quiet_bypass high-severity security alerts still go out during quiet hours
    rate         messages per hour at most; the excess is bundled into ONE summary
    daily        an optional daily digest at push.digest_time

The text is never written by the LLM: it is the dashboard's own sentences (the quiet-hours
summary lines, notify._line), built deterministically. The user sees the exact request
(credentials masked) in the Settings preview before anything is sent.

The pipeline, in two loops that never block a request:

    collect(db, env)   the notify loop, every minute: current alerts (inbox.alert_items via
                       notify.alert_events: mute, snooze, ack and sensitivity already
                       applied), a home-score drop, the weekly / daily digest -> one
                       push_outbox row per (channel, event key): dedupe, also across
                       restarts. A new or re-enabled channel is PRIMED first (what is
                       already there is not news). Quiet hours hold rows; at the window's
                       end they become ONE summary. An acked / muted alert's row is dropped.
    deliver(db, env)   the push loop, every 15 s: due rows -> channels.send(), at most 3
                       retries with backoff + jitter (Retry-After honoured), the rate limit,
                       a delivery log per channel (time, category, ok or an error CLASS).

Secrets (tokens, passwords, webhook URLs that embed one, the HMAC secret) live in the
push_channels.secrets column: never returned by an API, never logged (scheme + host only),
never in an export, report, backup or the static demo. Environment variables can define
channels too (NETWARDEN_NOTIFY_<n>_*, env_specs): those are read-only on the page and
their secrets are never written to the database.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import random
import re
from datetime import datetime, timedelta, timezone

from netwarden import channels, i18n, settings, store

log = logging.getLogger("netwarden.push")

CATEGORIES = ("security", "devices", "family", "health", "score", "digest")
CATEGORY_OF = {"threat": "security", "exposure": "security", "upnp": "security",
               "visibility": "security", "new": "devices", "change": "devices",
               "night": "family", "bedtime": "family", "outage": "health", "spike": "health"}
DEFAULT_CATEGORIES = ("security", "devices", "health")
LEVELS = ("minimal", "standard", "detailed")
MAX_CHANNELS = 20
MAX_NAME = 40
RATE_DEFAULT, RATE_MIN, RATE_MAX = 10, 1, 60
MAX_ATTEMPTS = 4                  # the first try + at most 3 retries
BACKOFF = (30, 120, 600)          # seconds before retry 1, 2, 3 (x 0.8-1.2 jitter)
SCORE_DROP = 10                   # points from one day to the next that count as a drop
SUMMARY_LINES = 10
LOG_KEEP = 100                    # delivery log rows kept per channel
SENDS_PER_RUN = 20                # deliver() sends at most this many messages per pass
ENV_SLOTS = range(1, 10)          # NETWARDEN_NOTIFY_1_* ... NETWARDEN_NOTIFY_9_*
ENV_PREFIX = "NETWARDEN_NOTIFY_"
OPTION_KEYS = ("level", "lang", "categories", "min_sev", "quiet_bypass", "rate", "daily")
TIMEOUT = channels.TIMEOUT        # tests shorten it


class BadPush(ValueError):
    """A request about channels we refuse -> 400 {error: err.<code>, field}."""
    def __init__(self, code: str, field: str = ""):
        super().__init__(f"{field}: {code}")
        self.code, self.field = code, field


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


# --- channels: storage, environment, validation -------------------------------------

def _options(raw: dict) -> dict:
    """The per-channel options in canonical form (stored ones may be old / partial)."""
    cats = raw.get("categories")
    return {"level": raw.get("level") if raw.get("level") in LEVELS else "standard",
            "lang": raw.get("lang") if raw.get("lang") in i18n.CODES else "",
            "categories": [c for c in CATEGORIES if c in cats] if isinstance(cats, list)
            else list(DEFAULT_CATEGORIES),
            "min_sev": raw.get("min_sev") if raw.get("min_sev") in (0, 1, 2, 3) else 3,
            "quiet_bypass": raw.get("quiet_bypass") is not False,
            "rate": raw.get("rate") if isinstance(raw.get("rate"), int)
            and not isinstance(raw.get("rate"), bool) and RATE_MIN <= raw["rate"] <= RATE_MAX
            else RATE_DEFAULT,
            "daily": raw.get("daily") is True}


def _channel(row, env: dict | None = None) -> dict:
    cfg = json.loads(row["config"] or "{}")
    secrets = json.loads(row["secrets"] or "{}")
    if row["source"] == "env":     # an environment channel: its secrets stay in the environment
        spec = env_specs(env or {}).get(cfg.get("slot"))
        secrets = dict(spec["secrets"]) if spec else {}
    return {"id": row["id"], "name": row["name"], "type": row["type"],
            "enabled": bool(row["enabled"]), "source": row["source"],
            "fields": cfg.get("fields") or {}, "secrets": secrets,
            "confirmed": bool(cfg.get("confirmed")), "slot": cfg.get("slot"),
            **_options(cfg), "primed": bool(row["primed"]),
            "last_ok_ts": row["last_ok_ts"], "last_error": row["last_error"],
            "last_error_ts": row["last_error_ts"], "created_at": row["created_at"]}


def env_specs(env: dict) -> dict:
    """Channels configured in the environment (headless / Docker; docs/notifications.md):
    NETWARDEN_NOTIFY_<n>_TYPE=ntfy plus _<FIELD> for every field of that type (_URL,
    _TOPIC, _TOKEN, _USER, _PASSWORD, _SECRET, _SERVICE, _CHAT_ID, _TO, _ROOM, _PIN) and
    the options _NAME, _LEVEL, _LANG, _CATEGORIES (comma list), _MIN_SEVERITY
    (critical|high|medium|low), _RATE, _DAILY, _QUIET_BYPASS. An invalid one is skipped
    (and logged once, without values). -> {slot: {name, type, fields, secrets, options}}."""
    out = {}
    for n in ENV_SLOTS:
        p = f"{ENV_PREFIX}{n}_"
        ctype = (env.get(p + "TYPE") or "").strip().lower()
        if not ctype:
            continue
        try:
            if ctype not in channels.TYPES:
                raise channels.BadChannel("type", "push_type")
            flds, secs = {}, {}
            for f in channels.fields(ctype):
                v = channels.clean_field(ctype, f, env.get(p + f.name.upper()) or "")
                if v:
                    (secs if f.kind.startswith("secret") else flds)[f.name] = v
            sev = (env.get(p + "MIN_SEVERITY") or "low").strip().lower()
            cats = [c.strip().lower() for c in (env.get(p + "CATEGORIES") or "").split(",") if c.strip()]
            opts = _options({"level": (env.get(p + "LEVEL") or "standard").strip().lower(),
                             "lang": i18n.match(env.get(p + "LANG") or "") or "",
                             "categories": cats or list(DEFAULT_CATEGORIES),
                             "min_sev": channels.SEVERITIES.index(sev)
                             if sev in channels.SEVERITIES else 3,
                             "rate": int(env.get(p + "RATE") or RATE_DEFAULT)
                             if (env.get(p + "RATE") or "").strip().isdigit() else RATE_DEFAULT,
                             "daily": (env.get(p + "DAILY") or "").strip().lower() in ("1", "true", "yes", "on"),
                             "quiet_bypass": (env.get(p + "QUIET_BYPASS") or "1").strip().lower()
                             not in ("0", "false", "no", "off")})
            name = store.clean_text(env.get(p + "NAME") or f"env-{n}", MAX_NAME) or f"env-{n}"
            out[n] = {"name": name, "type": ctype, "fields": flds, "secrets": secs, "options": opts}
        except channels.BadChannel as e:
            if (n, e.field) not in _env_warned:
                _env_warned.add((n, e.field))
                log.warning("ignoring %s%d_*: invalid %s", ENV_PREFIX, n, e.field)
    return out


_env_warned: set = set()


def sync_env(db, env: dict | None) -> None:
    """Mirror the environment channels into push_channels (no secrets), so they have a
    dedupe ledger and a delivery log like any other. A slot this process's environment
    lacks is only marked STALE (hidden, never delivered), never deleted: another process on
    the same database (`notify list` from a plain shell next to a Docker / systemd install)
    may simply not have the variables. Back in the environment, the row is live again and
    re-primed (what happened in between is not news)."""
    specs = env_specs(env or {})
    rows = {}
    for r in db.execute("SELECT id, name, config FROM push_channels WHERE source = 'env'"):
        cfg = json.loads(r["config"] or "{}")
        rows[cfg.get("slot")] = (r, cfg)
    if not specs and all(cfg.get("stale") for _r, cfg in rows.values()):
        return
    with db:
        for slot, (r, cfg) in rows.items():
            if slot not in specs and not cfg.get("stale"):
                db.execute("UPDATE push_channels SET config = ? WHERE id = ?",
                           (json.dumps({**cfg, "stale": True}, ensure_ascii=False), r["id"]))
        for slot, s in specs.items():
            row, old_cfg = rows.get(slot, (None, {}))
            cfg = json.dumps({"slot": slot, "fields": s["fields"], **s["options"]}, ensure_ascii=False)
            name = s["name"]
            clash = db.execute("SELECT id FROM push_channels WHERE name = ? AND NOT "
                               "(source = 'env' AND id = ?)",
                               (name, row["id"] if row else -1)).fetchone()
            if clash:
                name = f"{name} (env {slot})"
            if row:
                db.execute("UPDATE push_channels SET name = ?, type = ?, config = ?, enabled = 1, "
                           "primed = CASE WHEN ? THEN 0 ELSE primed END WHERE id = ?",
                           (name, s["type"], cfg, bool(old_cfg.get("stale")), row["id"]))
            else:
                db.execute("""INSERT INTO push_channels (name, type, enabled, config, secrets, source,
                                  created_at, updated_at) VALUES (?, ?, 1, ?, '{}', 'env', ?, ?)""",
                           (name, s["type"], cfg, store.now(), store.now()))


def all_channels(db, env: dict | None = None, enabled_only: bool = False) -> list:
    sync_env(db, env)
    q = "SELECT * FROM push_channels" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY id"
    return [_channel(r, env) for r in db.execute(q) if _live(r)]


def _live(row) -> bool:
    """Not an environment channel this process's environment lacks (sync_env: stale)."""
    return row["source"] != "env" or not json.loads(row["config"] or "{}").get("stale")


def get(db, env: dict | None, cid) -> dict:
    if isinstance(cid, bool) or not isinstance(cid, int) or not 0 < cid < 2 ** 63:
        raise BadPush("push_unknown", "id")
    sync_env(db, env)
    row = db.execute("SELECT * FROM push_channels WHERE id = ?", (cid,)).fetchone()
    if row is None or not _live(row):
        raise BadPush("push_unknown", "id")
    return _channel(row, env)


def by_name(db, env: dict | None, name: str) -> dict | None:
    sync_env(db, env)
    row = db.execute("SELECT * FROM push_channels WHERE name = ?", (name,)).fetchone()
    return _channel(row, env) if row and _live(row) else None


SIGNING_ONLY = {("webhook", "secret")}   # signs the request, never sent itself


def no_secret_to_new_host(ctype: str, old: dict, flds: dict, secs: dict, typed: dict) -> None:
    """Write-only secrets stay write-only: a stored token is only ever sent to the server
    it was entered for. When the endpoint's scheme/host/port changes, every kept (not
    re-typed) secret that travels with the request must be entered again."""
    before = channels.shown_endpoint(ctype, old.get("fields") or {}, old.get("secrets") or {})
    if before == channels.shown_endpoint(ctype, flds, secs):
        return
    for name in channels.secret_names(ctype):
        if name not in typed and secs.get(name) and (ctype, name) not in SIGNING_ONLY:
            raise BadPush("push_reenter", name)


def validate(db, payload: dict, old: dict | None = None) -> dict:
    """A channel as the Settings page sends it -> {name, type, fields, secrets, options,
    confirmed}. `secrets`: {name: "new value" | null (clear)}; a name left out keeps the
    stored value (write-only fields). BadPush / channels.BadChannel on anything wrong."""
    if not isinstance(payload, dict):
        raise BadPush("bad_json")
    allowed = {"id", "name", "type", "fields", "secrets", "lang", "confirm", *OPTION_KEYS,
               "enabled", "language"}
    if set(payload) - allowed:
        raise BadPush("bad_json")
    ctype = old["type"] if old else payload.get("type")
    if not isinstance(ctype, str) or ctype not in channels.TYPES:
        raise BadPush("push_type", "type")
    if old and payload.get("type") not in (None, ctype):
        raise BadPush("push_type", "type")
    name = payload.get("name")
    if not isinstance(name, str) or not store.clean_text(name, MAX_NAME):
        raise BadPush("push_name", "name")
    name = store.clean_text(name, MAX_NAME)
    raw_f, raw_s = payload.get("fields") or {}, payload.get("secrets") or {}
    if not isinstance(raw_f, dict) or not isinstance(raw_s, dict) or len(raw_f) > 20 or len(raw_s) > 20:
        raise BadPush("bad_json")
    names = {f.name for f in channels.fields(ctype)}
    if set(raw_f) - names or set(raw_s) - set(channels.secret_names(ctype)):
        raise BadPush("bad_json")
    flds, secs = {}, {}
    for f in channels.fields(ctype):
        if f.kind.startswith("secret"):
            if f.name in raw_s:
                v = raw_s[f.name]
                v = "" if v is None else v
            else:
                v = (old or {}).get("secrets", {}).get(f.name, "")
            v = channels.clean_field(ctype, f, v)
            if v:
                secs[f.name] = v
        else:
            v = channels.clean_field(ctype, f, raw_f.get(f.name, (old or {}).get("fields", {}).get(f.name, "")))
            if v:
                flds[f.name] = v
    if old:
        no_secret_to_new_host(ctype, old, flds, secs, raw_s)
    if flds.get("pin") and not channels.endpoint(ctype, flds, secs).startswith("https://"):
        raise BadPush("push_pin_http", "pin")
    if ctype == "ntfy" and flds.get("user") and not secs.get("password"):
        raise BadPush("push_required", "password")
    opts = {}
    level = payload.get("level", (old or {}).get("level", "standard"))
    if level not in LEVELS:
        raise BadPush("push_invalid", "level")
    opts["level"] = level
    lang = payload.get("language", (old or {}).get("lang", ""))
    if lang not in ("", *i18n.CODES):
        raise BadPush("push_invalid", "language")
    opts["lang"] = lang
    cats = payload.get("categories", (old or {}).get("categories", list(DEFAULT_CATEGORIES)))
    if not isinstance(cats, list) or len(cats) > len(CATEGORIES) or any(c not in CATEGORIES for c in cats):
        raise BadPush("push_invalid", "categories")
    opts["categories"] = [c for c in CATEGORIES if c in cats]
    sev = payload.get("min_sev", (old or {}).get("min_sev", 3))
    if isinstance(sev, bool) or sev not in (0, 1, 2, 3):
        raise BadPush("push_invalid", "min_sev")
    opts["min_sev"] = sev
    rate = payload.get("rate", (old or {}).get("rate", RATE_DEFAULT))
    if isinstance(rate, bool) or not isinstance(rate, int) or not RATE_MIN <= rate <= RATE_MAX:
        raise BadPush("push_invalid", "rate")
    opts["rate"] = rate
    for k, dflt in (("quiet_bypass", True), ("daily", False)):
        v = payload.get(k, (old or {}).get(k, dflt))
        if not isinstance(v, bool):
            raise BadPush("push_invalid", k)
        opts[k] = v
    dest = channels.destination(ctype, flds, secs)
    confirmed = payload.get("confirm") is True or bool(old and old.get("confirmed")
                                                       and old.get("level") == "detailed")
    if level == "detailed" and dest == "cloud" and not confirmed:
        raise BadPush("push_confirm_detailed", "level")
    return {"name": name, "type": ctype, "fields": flds, "secrets": secs, "options": opts,
            "confirmed": level == "detailed" and confirmed}


def save(db, env: dict | None, payload: dict) -> int:
    """Create (no id) or update a channel. A new channel starts PAUSED: nothing is sent
    until the user resumes it (normally after a test message). Returns the id."""
    old = None
    if payload.get("id") is not None:
        old = get(db, env, payload.get("id"))
        if old["source"] == "env":
            raise BadPush("push_env", "id")
    v = validate(db, payload, old)
    cfg = json.dumps({"fields": v["fields"], **v["options"], "confirmed": v["confirmed"]},
                     ensure_ascii=False)
    secrets = json.dumps(v["secrets"], ensure_ascii=False)
    try:
        with db:
            if old:
                db.execute("""UPDATE push_channels SET name = ?, config = ?, secrets = ?, updated_at = ?,
                              primed = CASE WHEN enabled = 1 THEN primed ELSE 0 END WHERE id = ?""",
                           (v["name"], cfg, secrets, store.now(), old["id"]))
                return old["id"]
            if db.execute("SELECT COUNT(*) FROM push_channels").fetchone()[0] >= MAX_CHANNELS:
                raise BadPush("push_too_many")
            cur = db.execute("""INSERT INTO push_channels (name, type, enabled, config, secrets, source,
                                    created_at, updated_at) VALUES (?, ?, 0, ?, ?, 'db', ?, ?)""",
                             (v["name"], v["type"], cfg, secrets, store.now(), store.now()))
            return cur.lastrowid
    except store.sqlite3.IntegrityError:
        raise BadPush("push_name_taken", "name") from None


def set_enabled(db, env: dict | None, cid, on) -> None:
    """Pause / resume. Resuming re-primes: what happened while paused is not sent."""
    ch = get(db, env, cid)
    if not isinstance(on, bool):
        raise BadPush("bad_json")
    if ch["source"] == "env":
        raise BadPush("push_env", "id")
    with db:
        db.execute("UPDATE push_channels SET enabled = ?, primed = 0, updated_at = ? WHERE id = ?",
                   (int(on), store.now(), ch["id"]))
        if not on:   # nothing waits for a paused channel
            db.execute("UPDATE push_outbox SET state = 'dropped' WHERE channel_id = ? "
                       "AND state IN ('queued', 'held')", (ch["id"],))


def _delete_rows(db, cid: int) -> None:
    db.execute("DELETE FROM push_outbox WHERE channel_id = ?", (cid,))
    db.execute("DELETE FROM push_log WHERE channel_id = ?", (cid,))
    db.execute("DELETE FROM push_channels WHERE id = ?", (cid,))


def delete(db, env: dict | None, cid) -> None:
    ch = get(db, env, cid)
    if ch["source"] == "env":
        raise BadPush("push_env", "id")
    with db:
        _delete_rows(db, ch["id"])


# --- what the API shows (never a secret) ----------------------------------------------

def public(db, ch: dict, lang: str) -> dict:
    lang = i18n.normalize(lang)
    err = ch["last_error"]
    q = db.execute("SELECT COUNT(*) FROM push_outbox WHERE channel_id = ? AND state IN "
                   "('queued', 'held')", (ch["id"],)).fetchone()[0]
    return {"id": ch["id"], "name": ch["name"], "type": ch["type"], "enabled": ch["enabled"],
            "source": ch["source"], "editable": ch["source"] != "env",
            "env_slot": ch["slot"] if ch["source"] == "env" else None,
            "fields": {k: v for k, v in ch["fields"].items()},
            "secrets": {n: bool(ch["secrets"].get(n)) for n in channels.secret_names(ch["type"])},
            "endpoint": channels.shown_endpoint(ch["type"], ch["fields"], ch["secrets"]),
            "destination": channels.destination(ch["type"], ch["fields"], ch["secrets"]),
            "hosted": ch["type"] in channels.HOSTED,
            **{k: ch[k] for k in OPTION_KEYS}, "confirmed": ch["confirmed"],
            "last_ok_ts": ch["last_ok_ts"], "last_error": err, "last_error_ts": ch["last_error_ts"],
            "error_text": i18n.t("push.err." + err, lang) if err in channels.ERROR_CLASSES else None,
            "waiting": q}


def types_info(lang: str) -> list:
    return [{"type": t, "hosted": hosted, "docs": docs, "name": i18n.t("push.type." + t, lang),
             "help": i18n.t("push.help." + t, lang),
             "fields": [{"name": f.name, "kind": f.kind, "required": f.required,
                         "placeholder": f.placeholder, "max": f.max_len,
                         "label": i18n.t("push.field." + f.name, lang)} for f in flds]}
            for t, (flds, hosted, docs) in channels.TYPES.items()]


def describe(db, env: dict | None, lang: str) -> dict:
    """GET /api/channels (admins only)."""
    lang = i18n.normalize(lang)
    return {"channels": [public(db, c, lang) for c in all_channels(db, env)],
            "types": types_info(lang), "levels": list(LEVELS), "categories": list(CATEGORIES),
            "max": MAX_CHANNELS, "rate": [RATE_MIN, RATE_MAX, RATE_DEFAULT],
            "advertised": bool(advertised(db, env)), "demo": store.is_demo(db),
            "env_prefix": ENV_PREFIX}


def history(db, env: dict | None, cid, lang: str, limit: int = 30) -> list:
    """The delivery log of one channel, newest first."""
    ch = get(db, env, cid)
    lang = i18n.normalize(lang)
    return [{"ts": r["ts"], "kind": r["kind"], "category": r["category"], "ok": bool(r["ok"]),
             "error": r["error"], "status": r["status"], "n": r["n"],
             "text": i18n.t("push.err." + r["error"], lang) if r["error"] in channels.ERROR_CLASSES else ""}
            for r in db.execute("SELECT * FROM push_log WHERE channel_id = ? ORDER BY id DESC LIMIT ?",
                                (ch["id"], max(1, min(100, limit))))]


# --- events ---------------------------------------------------------------------------

def advertised(db, env: dict | None) -> str:
    return settings.get(db, env or {}, "lan.advertised_url") or ""


def _alert_events(db) -> list:
    from netwarden import notify
    ips = {r["mac"]: r["ip"] for r in db.execute("SELECT mac, ip FROM devices")}
    out = []
    for e in notify.alert_events(db, "en"):
        akind = e["kind"][len(notify.ALERT):]
        if akind not in CATEGORY_OF:
            continue
        out.append({"kind": "alert", "akind": akind, "key": "alert:" + e["key"],
                    "category": CATEGORY_OF[akind], "sev": int(e["sev"]),
                    "critical": bool(e["critical"]), "mac": e["mac"], "name": e["name"],
                    "detail": e["detail"], "ip": ips.get(e["mac"]) or None})
    return out


def _local(now: datetime, tz):
    return now.astimezone(tz)


def _digest_time(db, env) -> tuple:
    h, m = (settings.get(db, env or {}, "push.digest_time") or "08:00").split(":")
    return int(h), int(m)


def _timed_events(db, env, now: datetime, tz) -> list:
    """The home-score drop of today, and the digests whose time has come."""
    out = []
    local = _local(now, tz)
    hist = store.score_history(db, (local.date() - timedelta(days=7)).isoformat())
    if len(hist) >= 2 and hist[-1]["day"] == local.date().isoformat() \
            and hist[-2]["score"] - hist[-1]["score"] >= SCORE_DROP:
        out.append({"kind": "score", "key": f"score:{hist[-1]['day']}", "category": "score",
                    "sev": 2, "from": hist[-2]["score"], "to": hist[-1]["score"]})
    hh, mm = _digest_time(db, env)
    if (local.hour, local.minute) >= (hh, mm):
        out.append({"kind": "daily", "key": f"daily:{local.date().isoformat()}", "category": "digest",
                    "sev": 3})
        if local.weekday() == int(settings.get(db, env or {}, "push.weekly_day")):
            y, w, _d = local.isocalendar()
            out.append({"kind": "weekly", "key": f"weekly:{y}-W{w:02d}", "category": "digest", "sev": 3})
    return out


def events(db, env: dict | None, now: datetime | None = None, tz=None) -> list:
    from netwarden import activity
    now = _now(now)
    return _alert_events(db) + _timed_events(db, env, now, tz or activity.local_tz())


def wants(ch: dict, ev: dict) -> bool:
    """Does this channel take this event at all?"""
    if ev["kind"] == "daily":
        return ch["daily"]
    if ev["category"] not in ch["categories"]:
        return False
    return ev["kind"] != "alert" or ev["sev"] <= ch["min_sev"]


def bypasses_quiet(ch: dict, ev: dict) -> bool:
    return ch["quiet_bypass"] and ev.get("category") == "security" and ev.get("sev", 3) <= 1


def collect(db, env: dict | None = None, now: datetime | None = None, tz=None) -> int:
    """Turn current events into outbox rows for every enabled channel. Returns how many
    rows were queued or held. Cheap when no channel is enabled (one SELECT)."""
    from netwarden import activity, notify
    now = _now(now)
    chans = all_channels(db, env, enabled_only=True)
    if not chans or store.is_demo(db):   # the demo home's channels are never used
        return 0
    tz = tz or activity.local_tz()
    evs = events(db, env, now, tz)
    qs = notify.quiet_now(db, env, now, tz)
    act = qs["active"]
    stamp = _iso(now)
    current = {e["key"] for e in evs if e["kind"] == "alert"}
    made = 0
    with db:
        for ch in chans:
            if not ch["primed"]:   # what is already there when a channel starts is not news
                db.executemany("""INSERT OR IGNORE INTO push_outbox (channel_id, key, kind, category, sev,
                                      state, created_at, data) VALUES (?, ?, ?, ?, ?, 'skipped', ?, '{}')""",
                               [(ch["id"], e["key"], e["kind"], e["category"], e["sev"], stamp) for e in evs])
                db.execute("UPDATE push_channels SET primed = 1 WHERE id = ?", (ch["id"],))
                continue
            for e in evs:
                if not wants(ch, e):
                    continue
                hold = act is not None and not bypasses_quiet(ch, e)
                cur = db.execute("""INSERT OR IGNORE INTO push_outbox (channel_id, key, kind, category, sev,
                                        critical, state, created_at, next_at, until, win, data)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                 (ch["id"], e["key"], e["kind"], e["category"], e["sev"],
                                  int(bool(e.get("critical"))), "held" if hold else "queued", stamp, stamp,
                                  _iso(act["end"]) if hold else None, act["win"] if hold else None,
                                  json.dumps(e, ensure_ascii=False)))
                made += cur.rowcount
            # acked / muted / snoozed meanwhile (or no longer current): not sent after all
            rows = db.execute("SELECT id, key FROM push_outbox WHERE channel_id = ? AND kind = 'alert' "
                              "AND state IN ('queued', 'held') AND attempts = 0", (ch["id"],)).fetchall()
            gone = [(r["id"],) for r in rows if r["key"] not in current]
            if gone:
                db.executemany("UPDATE push_outbox SET state = 'dropped' WHERE id = ?", gone)
        _release(db, now)
    return made


def _release(db, now: datetime) -> None:
    """Held rows whose quiet window has ended -> ONE summary row per channel and window
    (one held row alone just goes out as itself)."""
    stamp = _iso(now)
    groups = db.execute("SELECT channel_id, win FROM push_outbox WHERE state = 'held' AND until <= ? "
                        "GROUP BY channel_id, win", (stamp,)).fetchall()
    for g in groups:
        rows = db.execute("SELECT * FROM push_outbox WHERE channel_id = ? AND win IS ? AND state = 'held' "
                          "AND until <= ? ORDER BY sev, id", (g["channel_id"], g["win"], stamp)).fetchall()
        if len(rows) == 1:
            db.execute("UPDATE push_outbox SET state = 'queued', next_at = ? WHERE id = ?",
                       (stamp, rows[0]["id"]))
            continue
        items = [json.loads(r["data"]) for r in rows]
        db.execute("""INSERT OR IGNORE INTO push_outbox (channel_id, key, kind, category, sev, state,
                          created_at, next_at, data) VALUES (?, ?, 'summary', ?, ?, 'queued', ?, ?, ?)""",
                   (g["channel_id"], f"quiet:{g['win']}:{rows[0]['id']}", rows[0]["category"],
                    min(r["sev"] for r in rows), stamp, stamp,
                    json.dumps({"kind": "summary", "items": items}, ensure_ascii=False)))
        db.executemany("UPDATE push_outbox SET state = 'bundled' WHERE id = ?", [(r["id"],) for r in rows])


# --- rendering: the same sentences as the dashboard -----------------------------------

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# aa:bb:cc:dd:ee:ff / aa-bb-.. , aabb.ccdd.eeff (Cisco), aabbccddeeff (no separators)
_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}|[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}"
                  r"|[0-9a-fA-F]{12})\b")
# anything that might be an IPv6 address (a colon among hex digits, maybe an embedded IPv4
# and a zone): ipaddress decides, so "08:00" or "Note::" stay as they are
_IPV6_CANDIDATE = re.compile(r"(?<![\w:.%])[0-9a-fA-F:.]*:[0-9a-fA-F:.]*(?:%[\w.-]+)?(?![\w:%])")


def _ipv6(m) -> str:
    token = m.group()
    body = token.rstrip(".")   # the end of a sentence is not part of the address
    try:
        ipaddress.IPv6Address(body)
    except ValueError:
        return token
    return channels.MASK + token[len(body):]


def scrub(text: str) -> str:
    """minimal / standard: no address ever, even inside a (hostile) device name."""
    text = _IPV6_CANDIDATE.sub(_ipv6, text)
    return _IPV4.sub(channels.MASK, _MAC.sub(channels.MASK, text))


def _cat(category: str, lang: str) -> str:
    return i18n.t("push.cat." + category, lang)


def alert_line(db, ev: dict, lang: str, level: str, names: dict) -> str:
    """One alert as the quiet-hours summary sentence (notify._line); a threat's domain
    and the device's addresses only at `detailed`."""
    from netwarden import notify
    detail = ev.get("detail")
    if ev.get("akind") == "threat" and level != "detailed":
        detail = i18n.t("sev.malicious" if ev.get("sev") == 0 else "sev.high_risk", lang)
    line = notify._line({"kind": notify.ALERT + ev["akind"], "mac": ev.get("mac"),
                         "name": ev.get("name"), "detail": detail}, lang, names, {})
    if level == "detailed":
        addr = [x for x in (ev.get("ip"), ev.get("mac")) if x and x != "network"]
        if addr:
            line += "\n" + i18n.t("push.addr", lang, addr=" · ".join(addr))
        return line
    return scrub(line)


def _link(db, env, level: str, ev: dict | None = None) -> str:
    base = advertised(db, env)
    if not base:
        return ""
    if level == "detailed" and ev and ev.get("kind") == "alert" and ev.get("mac") \
            and ev["mac"] != "network":
        return f"{base}/#/device/{ev['mac']}"
    return f"{base}/#/inbox"


def _lines(db, items: list, lang: str, level: str, names: dict) -> list:
    out = []
    for it in items[:SUMMARY_LINES]:
        if it.get("kind") == "alert":
            out.append("• " + alert_line(db, it, lang, level, names).replace("\n", " · "))
        elif it.get("kind") == "score":
            out.append("• " + i18n.t("push.score.drop", lang, old=it["from"], new=it["to"]))
        else:
            out.append("• " + i18n.t("push.kind." + it.get("kind", "alert"), lang))
    if len(items) > SUMMARY_LINES:
        out.append(i18n.t("push.more", lang, n=len(items) - SUMMARY_LINES))
    return out


def _digest_lines(db, env, kind: str, lang: str, tz) -> list:
    from netwarden import inbox, score, weekly
    if kind == "weekly":
        return weekly.report(db, lang, tz)["highlights"]
    lines = []
    sc = score.report(db, lang, env, tz)
    if sc.get("score") is not None:
        lines.append(i18n.t("push.daily.score", lang, score=sc["score"]))
    c = inbox.report(db, lang, env)["counts"]
    lines.append(i18n.tn("push.daily.open", c["total"], lang, urgent=c["urgent"]))
    return lines


def render(db, env: dict | None, ch: dict, data: dict, tz=None, now: datetime | None = None) -> dict:
    """The message for `data` (an outbox row's event) on channel `ch`: {title, body, url,
    sev, category, kind, lang, level, count, id, ts}. Deterministic: never the LLM."""
    from netwarden import activity, naming
    tz = tz or activity.local_tz()
    lang = ch["lang"] or settings.get(db, env or {}, "ui.language")
    level = ch["level"]
    kind = data.get("kind", "alert")
    names = naming.display_names(db, lang)
    items = data.get("items") or []
    count = len(items) if kind in ("summary", "bundle") else 1
    sev = min([i.get("sev", 3) for i in items] or [3]) if items else data.get("sev", 3)
    category = data.get("category") or (items[0].get("category") if items else "")
    key = data.get("key") or ""
    if level != "detailed" and key:   # an event key may hold a MAC: a stable hash instead
        key = "nw-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]
    msg = {"kind": kind, "category": category, "sev": sev if sev in (0, 1, 2, 3) else 3,
           "lang": lang, "level": level, "count": count, "id": key,
           "ts": _iso(_now(now)), "url": _link(db, env, level, data)}
    if kind == "test":
        msg.update(title=i18n.t("push.test.title", lang), body=i18n.t("push.test.body", lang),
                   category="test")
        return msg
    if level == "minimal":
        if kind in ("weekly", "daily"):
            body = i18n.t("push.min.digest", lang)
        elif count > 1:
            body = i18n.tn("push.min.many", count, lang)
        else:
            body = i18n.t("push.min.one", lang, category=_cat(category, lang))
        msg.update(title="netwarden", body=body)
        return msg
    if kind == "alert":
        msg.update(title=i18n.t("push.title", lang, category=_cat(category, lang)),
                   body=alert_line(db, data, lang, level, names))
    elif kind == "score":
        msg.update(title=i18n.t("push.title", lang, category=_cat("score", lang)),
                   body=i18n.t("push.score.drop", lang, old=data["from"], new=data["to"]))
    elif kind in ("weekly", "daily"):
        lines = _digest_lines(db, env, kind, lang, tz)
        msg.update(title=i18n.t("push.title_" + kind, lang), body="\n".join(lines))
        if level != "detailed":
            msg["body"] = scrub(msg["body"])
    else:   # summary (quiet hours) | bundle (rate limit)
        msg.update(title=i18n.t("push.title_" + kind, lang, n=count),
                   body="\n".join(_lines(db, items, lang, level, names)))
    return msg


# --- delivery -------------------------------------------------------------------------

def _record(db, ch: dict, kind: str, category: str, res, n: int = 1,
            now: datetime | None = None) -> None:
    """One delivery-log row (+ the channel's last result). Never a token: an error CLASS."""
    stamp = _iso(_now(now))
    db.execute("INSERT INTO push_log (channel_id, ts, kind, category, ok, error, status, n) "
               "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
               (ch["id"], stamp, kind, category or "", int(res.ok), res.error or None, res.status, n))
    if res.ok:
        db.execute("UPDATE push_channels SET last_ok_ts = ?, last_error = NULL WHERE id = ?",
                   (stamp, ch["id"]))
    else:
        db.execute("UPDATE push_channels SET last_error = ?, last_error_ts = ? WHERE id = ?",
                   (res.error, stamp, ch["id"]))
    db.execute("""DELETE FROM push_log WHERE channel_id = ? AND id NOT IN
                  (SELECT id FROM push_log WHERE channel_id = ? ORDER BY id DESC LIMIT ?)""",
               (ch["id"], ch["id"], LOG_KEEP))


def _send(ch: dict, msg: dict, sender=None):
    try:
        req = channels.build(ch["type"], ch["fields"], ch["secrets"], msg)
    except (KeyError, channels.BadChannel):
        return channels.Result(False, "config")
    if not req.url:
        return channels.Result(False, "config")
    res = (sender or channels.send)(req, TIMEOUT)
    log.info("push %s (%s) %s -> %s", ch["name"][:40], ch["type"],
             channels.shown_endpoint(ch["type"], ch["fields"], ch["secrets"]),
             "ok" if res.ok else res.error)   # scheme + host only, never a token
    return res


def _sent_last_hour(db, cid: int, now: datetime) -> int:
    return db.execute("SELECT COUNT(*) FROM push_log WHERE channel_id = ? AND ok = 1 AND kind != 'test' "
                      "AND ts >= ?", (cid, _iso(now - timedelta(hours=1)))).fetchone()[0]


def _bundle(db, ch: dict, rows: list, now: datetime) -> None:
    """Over the rate limit: these rows go out as ONE message."""
    items = []
    for r in rows:
        d = json.loads(r["data"] or "{}")
        items += d.get("items") or [d] if d.get("kind") in ("summary", "bundle") else [d]
    stamp = _iso(now)
    with db:
        db.execute("""INSERT OR IGNORE INTO push_outbox (channel_id, key, kind, category, sev, state,
                          created_at, next_at, data) VALUES (?, ?, 'bundle', ?, ?, 'queued', ?, ?, ?)""",
                   (ch["id"], f"bundle:{rows[0]['id']}", rows[0]["category"], min(r["sev"] for r in rows),
                    stamp, stamp, json.dumps({"kind": "bundle", "items": items}, ensure_ascii=False)))
        db.executemany("UPDATE push_outbox SET state = 'bundled' WHERE id = ?", [(r["id"],) for r in rows])


def deliver(db, env: dict | None = None, now: datetime | None = None, sender=None, tz=None) -> int:
    """Send what is due, per channel within its rate limit. Returns messages sent."""
    now = _now(now)
    chans = all_channels(db, env, enabled_only=True)
    if chans and store.is_demo(db):
        return 0
    sent = budget = 0
    for ch in chans:
        due = db.execute("SELECT * FROM push_outbox WHERE channel_id = ? AND state = 'queued' "
                         "AND (next_at IS NULL OR next_at <= ?) ORDER BY sev, id",
                         (ch["id"], _iso(now))).fetchall()
        if not due:
            continue
        room = ch["rate"] - _sent_last_hour(db, ch["id"], now)
        if room <= 0:
            continue
        if len(due) > room:      # room - 1 one by one, the rest as ONE summary
            _bundle(db, ch, due[room - 1:], now)
            due = db.execute("SELECT * FROM push_outbox WHERE channel_id = ? AND state = 'queued' "
                             "AND (next_at IS NULL OR next_at <= ?) ORDER BY kind = 'bundle', sev, id",
                             (ch["id"], _iso(now))).fetchall()[:room]
        for r in due:
            if budget >= SENDS_PER_RUN:
                return sent
            budget += 1
            data = json.loads(r["data"] or "{}")
            try:
                msg = render(db, env, ch, data, tz, now)
                msg["txn"] = f"outbox-{r['id']}"   # the same on every retry (Matrix dedupe)
            except Exception as e:   # noqa: BLE001 - a broken row must not stop the queue
                log.warning("push: could not render a %s message: %s", r["kind"], type(e).__name__)
                with db:
                    db.execute("UPDATE push_outbox SET state = 'failed' WHERE id = ?", (r["id"],))
                continue
            res = _send(ch, msg, sender)
            attempts = r["attempts"] + 1
            with db:
                if res.ok:
                    db.execute("UPDATE push_outbox SET state = 'sent', attempts = ?, sent_at = ? WHERE id = ?",
                               (attempts, _iso(now), r["id"]))
                    sent += 1
                elif res.retryable and attempts < MAX_ATTEMPTS:
                    wait = max(res.retry_after or 0,
                               BACKOFF[attempts - 1] * random.uniform(0.8, 1.2))   # noqa: S311
                    db.execute("UPDATE push_outbox SET attempts = ?, next_at = ? WHERE id = ?",
                               (attempts, _iso(now + timedelta(seconds=wait)), r["id"]))
                else:
                    db.execute("UPDATE push_outbox SET state = 'failed', attempts = ? WHERE id = ?",
                               (attempts, r["id"]))
                _record(db, ch, r["kind"], msg.get("category"), res, msg.get("count") or 1, now)
            if not res.ok and res.error in ("http_401", "http_403", "http_404", "config", "tls",
                                            "tls_pin", "redirect"):
                break            # the channel itself is wrong: the rest waits for the next pass
    return sent


def test(db, env: dict | None, cid, sender=None) -> channels.Result:
    """ONE test message on an explicit click (Settings / `notify test`). Logged."""
    ch = get(db, env, cid)
    if store.is_demo(db):
        raise BadPush("push_demo", "id")
    msg = render(db, env, ch, {"kind": "test", "key": "test"})
    msg["txn"] = "test-" + os.urandom(8).hex()   # every click is a new message
    res = _send(ch, msg, sender)
    with db:
        _record(db, ch, "test", "test", res)
    return res


def enqueue_digest(db, env: dict | None, kind: str = "weekly", now: datetime | None = None) -> int:
    """`notify send-digest`: a digest now, for every enabled channel that takes digests
    (weekly: category "digest"; daily: the daily option). Returns rows queued."""
    now = _now(now)
    stamp = _iso(now)
    ev = {"kind": kind, "key": f"{kind}-manual:{stamp}", "category": "digest", "sev": 3}
    n = 0
    with db:
        for ch in all_channels(db, env, enabled_only=True):
            if (kind == "weekly" and "digest" in ch["categories"]) or (kind == "daily" and ch["daily"]):
                n += db.execute("""INSERT OR IGNORE INTO push_outbox (channel_id, key, kind, category, sev,
                                       state, created_at, next_at, data) VALUES (?, ?, ?, 'digest', 3,
                                       'queued', ?, ?, ?)""",
                                (ch["id"], ev["key"], kind, stamp, stamp, json.dumps(ev))).rowcount
    return n


# --- the preview (no network) ---------------------------------------------------------

SAMPLE = {"kind": "alert", "akind": "new", "key": "alert:sample", "category": "devices", "sev": 3,
          "critical": False, "mac": "aa:bb:cc:00:00:01", "name": None, "detail": None,
          "ip": "192.168.1.23"}


def sample_event(db, sample: str) -> dict:
    """What the preview shows: the newest real alert of this home (the exact text it would
    send), or a made-up "new device" when there is none; a test message; a digest."""
    if sample in ("test", "weekly", "daily"):
        return {"kind": sample, "key": sample, "category": "digest", "sev": 3}
    evs = _alert_events(db)
    if evs:
        return sorted(evs, key=lambda e: e["sev"])[0]
    return dict(SAMPLE)


def preview(db, env: dict | None, payload: dict, sample: str = "alert") -> dict:
    """POST /api/channels/preview: a draft (or saved) channel -> the exact request it
    would send for a sample event, credentials masked. Never contacts anything."""
    old = None
    if payload.get("id") is not None:
        old = get(db, env, payload.get("id"))
    if old and old["source"] == "env":
        v = {"type": old["type"], "fields": old["fields"], "secrets": old["secrets"],
             "options": {k: old[k] for k in OPTION_KEYS}}
    else:
        draft = {k: payload[k] for k in payload if k not in ("sample",)}
        draft.setdefault("name", (old or {}).get("name") or "preview")
        draft["confirm"] = True       # a preview is not a save: show detailed as it would be
        try:
            v = validate(db, draft, old)
        except (channels.BadChannel, BadPush) as e:
            if isinstance(e, BadPush) and e.code != "push_reenter":
                raise
            # an incomplete draft still previews: placeholders where a field is missing
            # (a preview sends nothing, so a secret to re-enter only blocks the save)
            v = _lenient(payload, old)
    ch = {"id": 0, "name": "preview", "type": v["type"], "fields": v["fields"],
          "secrets": v["secrets"], **v["options"]}
    if sample not in ("alert", "test", "weekly", "daily"):
        raise BadPush("bad_json", "sample")
    ev = sample_event(db, sample)
    if ev.get("key") == SAMPLE["key"]:
        ev["name"] = i18n.t("push.sample_name", ch["lang"] or settings.get(db, env or {}, "ui.language"))
    msg = render(db, env, ch, ev)
    filled = {f.name: (v["fields"].get(f.name) or v["secrets"].get(f.name)
                       or (_placeholder(v["type"], f) if f.required else ""))
              for f in channels.fields(v["type"])}
    flds = {k: x for k, x in filled.items() if k not in channels.secret_names(v["type"])}
    secs = {k: x for k, x in filled.items() if k in channels.secret_names(v["type"])}
    flds["pin"] = v["fields"].get("pin", "")
    req = channels.build(v["type"], flds, secs, msg)
    lang = ch["lang"] or settings.get(db, env or {}, "ui.language")
    return {"request": channels.preview(req), "title": msg["title"], "body": msg["body"],
            "url": msg["url"], "lang": lang, "level": ch["level"],
            "destination": channels.destination(v["type"], v["fields"], v["secrets"]),
            "hosted": v["type"] in channels.HOSTED}


def _placeholder(ctype: str, f) -> str:
    if f.kind == "secret_url":
        return f.placeholder.replace("…", "SECRET")
    if f.kind == "secret":
        return "123456789:SECRET-SECRET-SECRET-SECRET" if ctype == "telegram" else "SECRET"
    return f.placeholder.replace("…", "") or "x"


def _lenient(payload: dict, old: dict | None) -> dict:
    ctype = (old or {}).get("type") or payload.get("type")
    if ctype not in channels.TYPES:
        raise BadPush("push_type", "type")
    flds, secs = {}, {}
    for f in channels.fields(ctype):
        src = payload.get("secrets" if f.kind.startswith("secret") else "fields") or {}
        val = src.get(f.name) if isinstance(src, dict) else None
        if val is None:
            val = (old or {}).get("secrets" if f.kind.startswith("secret") else "fields", {}).get(f.name, "")
        try:
            val = channels.clean_field(ctype, f, val if isinstance(val, str) else "")
        except channels.BadChannel:
            val = ""
        if val:
            (secs if f.kind.startswith("secret") else flds)[f.name] = val
    raw = {k: payload[k] for k in OPTION_KEYS if k in payload}
    if "language" in payload:
        raw["lang"] = payload["language"]
    return {"type": ctype, "fields": flds, "secrets": secs, "options": _options({**(old or {}), **raw})}
