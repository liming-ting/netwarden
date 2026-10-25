"""
netwarden - live.py: what changed, pushed to open dashboards (Stage T).

The dashboard keeps a server-sent events stream open (GET /api/stream, web.py). This
module is the ONE thing that decides what to push: a single in-process change detector
per database that compares compact snapshots of the home - never a query per browser.

    poke(db_path)   "new data may have landed": the run loops call it after every
                    successful run, the keep-warm pass after each pass, the web server
                    after every data-changing POST. Cheap: it only sets an Event.
    Detector        one thread (only while at least one stream is open) that wakes on a
                    poke - or every FALLBACK_S, because "online" moves with the clock -
                    debounces, takes ONE snapshot on its own connection, diffs it with the
                    previous one and appends small typed events to a ring buffer.
    subscribe()     a stream's cursor into that buffer (caps: MAX_STREAMS in total,
                    MAX_PER_CLIENT per client address), wait() blocks until there is news.

Event types (all small; the page refetches what an event names):
    device_new {mac}  device_online {mac}  device_offline {mac}
    alert_new {id, kind, mac, sev}         inbox_changed {count}
    presence_changed {person, state}       health_changed {level}
    suggestion_changed {open}              settings_changed {}
    notes_changed {}   (labels, owners, people, acks: the user's own notes, any tab)

Ids are "<epoch>-<seq>". The epoch is new whenever the detector starts from a fresh
baseline (process start, or after it idled with no stream open), so a Last-Event-ID
from before that can never be resumed by mistake: such a client gets `resync` and
reloads everything once. Read-only: this module only reads netwarden's SQLite and never
calls the LLM or the network.
"""
from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from netwarden import store

log = logging.getLogger("netwarden.live")

RING = 256            # events kept for Last-Event-ID resume
MAX_STREAMS = 8       # open streams in total ...
MAX_PER_CLIENT = 3    # ... and per client address (a phone cannot take them all)
FALLBACK_S = 60.0     # re-check this often while streams are open ("online" ages out)
DEBOUNCE_S = 0.4      # a burst of pokes (several loops finishing together) = one check
IDLE_S = 120.0        # no stream for this long: stop the thread, forget the baseline
MAX_DEVICE_EVENTS = 50   # more device changes than this in one check: one inbox-style batch

EVENT_TYPES = ("device_new", "device_online", "device_offline", "alert_new", "inbox_changed",
               "presence_changed", "health_changed", "suggestion_changed", "settings_changed",
               "notes_changed")


class Full(Exception):
    """No room for another stream (in total, or for this client address)."""


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def snapshot(db, env: dict | None = None, hours: float = 24) -> dict:
    """The compact state of the home the detector compares: plain, small values only.
    Reuses the cached computations the dashboard reads (netwarden.cache), so a check on
    a warm cache costs a few milliseconds."""
    from netwarden import dashboard, inbox, nethealth, presence, suggestions
    now = datetime.now(timezone.utc)
    online_since = _iso(now - timedelta(minutes=dashboard.ONLINE_MINUTES))
    # online exactly as the device list says it (dashboard.last_active: the newest evidence)
    last = dashboard.last_active(db, online_since)
    here = dashboard.online_macs(db, last, online_since)
    devices = {mac: mac in here for mac in last}
    items = inbox.report(db, "en", env=env, hours=hours)["items"]
    alerts = {it["id"]: {"kind": it["kind"], "mac": it["mac"], "sev": it["sev"]}
              for it in items if it["kind"] != "suggestion"}
    det = suggestions.detect(db, env)
    lists = suggestions.with_status(det, store.suggestion_states(db))
    sug = {k: sorted(i["id"] for i in v) for k, v in lists.items()}
    pres = {str(p["id"]): p.get("state", "off") for p in presence.core(db, env=env)["people"]}
    level = nethealth.verdict(nethealth.compute(db, hours))["level"]
    row = db.execute("""SELECT
        (SELECT COUNT(*) || '|' || IFNULL(MAX(updated_at), '') FROM settings),
        (SELECT COUNT(*) || '|' || IFNULL(MAX(updated_at), '') FROM device_labels) || '/' ||
        (SELECT COUNT(*) || '|' || IFNULL(MAX(updated_at), '') FROM device_profiles) || '/' ||
        (SELECT COUNT(*) || '|' || IFNULL(MAX(updated_at), '') || '|' || IFNULL(MAX(id), '')
           FROM people) || '/' ||
        (SELECT COUNT(*) || '|' || IFNULL(MAX(created_at), '') || '|'
           || TOTAL(julianday(created_at)) FROM acks) || '/' ||
        (SELECT COUNT(*) || '|' || IFNULL(MAX(updated_at), '') FROM bedtime_rules)""").fetchone()
    return {"devices": devices, "alerts": alerts, "inbox": len(items), "sug": sug,
            "pres": pres, "health": level, "settings": row[0], "notes": row[1]}


def diff(old: dict | None, new: dict) -> list:
    """The events that take `old` to `new` (an empty list for the first snapshot)."""
    if old is None:
        return []
    out = []
    dev_events = []
    for mac, online in new["devices"].items():
        was = old["devices"].get(mac)
        if was is None:
            dev_events.append({"type": "device_new", "mac": mac})
        elif was != online:
            dev_events.append({"type": "device_online" if online else "device_offline", "mac": mac})
    if len(dev_events) > MAX_DEVICE_EVENTS:     # a first sweep of a big home: one summary
        dev_events = dev_events[:MAX_DEVICE_EVENTS]
    out += dev_events
    for aid, a in new["alerts"].items():
        if aid not in old["alerts"]:
            out.append({"type": "alert_new", "id": aid, **a})
    if new["inbox"] != old["inbox"] or set(new["alerts"]) != set(old["alerts"]):
        out.append({"type": "inbox_changed", "count": new["inbox"]})
    if new["sug"] != old["sug"]:
        out.append({"type": "suggestion_changed", "open": len(new["sug"].get("open", []))})
    for pid, state in new["pres"].items():
        if old["pres"].get(pid) != state:
            out.append({"type": "presence_changed", "person": int(pid), "state": state})
    if set(old["pres"]) - set(new["pres"]):
        out.append({"type": "presence_changed", "person": None, "state": None})
    if new["health"] != old["health"]:
        out.append({"type": "health_changed", "level": new["health"]})
    if new["settings"] != old["settings"]:
        out.append({"type": "settings_changed"})
    if new["notes"] != old["notes"]:
        out.append({"type": "notes_changed"})
    return out


class Subscription:
    """One open stream's place in the detector's event buffer."""

    def __init__(self, detector: "Detector", client: str, cursor: int):
        self.detector, self.client, self.cursor = detector, client, cursor
        self.closed = False

    def wait(self, timeout: float) -> list | None:
        """New events since the last call (possibly []), after at most `timeout` seconds;
        None when the detector stopped (the stream should end)."""
        return self.detector._wait(self, timeout)

    def close(self) -> None:
        self.detector._unsubscribe(self)


class Detector:
    """The one change detector of one database. `compute(db)` -> a snapshot (tests pass
    their own); `computations` counts how often it ran (it must never scale with the
    number of open streams)."""

    def __init__(self, db_path, env: dict | None = None, hours: float = 24, compute=None):
        self.db_path, self.env, self.hours = str(db_path), env or {}, hours
        self.compute = compute or (lambda db: snapshot(db, self.env, self.hours))
        self.cond = threading.Condition()
        self.wake = threading.Event()
        self.subs: list = []
        self.events: deque = deque(maxlen=RING)    # (seq, event dict)
        self.seq = 0
        self.epoch = secrets.token_hex(4)
        self.base = None            # the last snapshot
        self.thread = None
        self.stopped = False
        self.computations = 0
        self.idle_since = time.monotonic()
        self.fallback_s, self.debounce_s, self.idle_s = FALLBACK_S, DEBOUNCE_S, IDLE_S

    # --- streams --------------------------------------------------------------------

    def subscribe(self, client: str) -> Subscription:
        with self.cond:
            if self.stopped:
                raise Full("stopped")
            if len(self.subs) >= MAX_STREAMS or \
                    sum(1 for s in self.subs if s.client == client) >= MAX_PER_CLIENT:
                raise Full(client)
            sub = Subscription(self, client, self.seq)
            self.subs.append(sub)
            if self.thread is None or not self.thread.is_alive():
                self.thread = threading.Thread(target=self._run, name="netwarden-live",
                                               daemon=True)
                self.thread.start()
        self.wake.set()             # a first stream: take the baseline now
        return sub

    def _unsubscribe(self, sub: Subscription) -> None:
        with self.cond:
            sub.closed = True
            if sub in self.subs:
                self.subs.remove(sub)
            if not self.subs:
                self.idle_since = time.monotonic()

    def last_id(self) -> str:
        with self.cond:
            return f"{self.epoch}-{self.seq}"

    def resume(self, sub: Subscription, last_id: str | None) -> list | None:
        """Events after `last_id` for a reconnecting stream (and move its cursor there):
        [] = nothing missed, None = cannot resume (another epoch, or too old)."""
        if not last_id:
            return []
        epoch, _, raw = str(last_id).partition("-")
        with self.cond:
            # (isascii: "²".isdigit() is True, int("²") raises)
            if epoch != self.epoch or not (raw.isascii() and raw.isdigit()) or len(raw) > 12:
                return None
            seq = int(raw)
            oldest = self.events[0][0] if self.events else self.seq + 1
            if seq > self.seq or seq < oldest - 1:
                return None
            sub.cursor = self.seq
            return [self._framed(s, e) for s, e in self.events if s > seq]

    def _framed(self, seq: int, event: dict) -> dict:
        return {**event, "id": f"{self.epoch}-{seq}"}

    def _wait(self, sub: Subscription, timeout: float) -> list | None:
        deadline = time.monotonic() + timeout
        with self.cond:
            while not self.stopped and not sub.closed and self.seq <= sub.cursor:
                left = deadline - time.monotonic()
                if left <= 0:
                    return []
                self.cond.wait(left)
            if self.stopped or sub.closed:
                return None
            out = [self._framed(s, e) for s, e in self.events if s > sub.cursor]
            sub.cursor = self.seq
            return out

    def streams(self) -> int:
        with self.cond:
            return len(self.subs)

    # --- the detector thread ----------------------------------------------------------

    def poke(self) -> None:
        self.wake.set()

    def stop(self) -> None:
        with self.cond:
            self.stopped = True
            self.cond.notify_all()
        self.wake.set()

    def publish(self, events: list) -> None:
        if not events:
            return
        with self.cond:
            for e in events:
                self.seq += 1
                self.events.append((self.seq, e))
            self.cond.notify_all()

    def check(self, db) -> list:
        """One comparison (the thread's body; tests call it directly)."""
        snap = self.compute(db)
        self.computations += 1
        events = diff(self.base, snap)
        self.base = snap
        self.publish(events)
        return events

    def _run(self) -> None:
        db = None
        try:
            while not self.stopped:
                self.wake.wait(self.fallback_s)
                if self.stopped:
                    break
                with self.cond:
                    idle = not self.subs and time.monotonic() - self.idle_since > self.idle_s
                    if idle:      # nobody listens: forget the baseline, a new epoch later
                        self.base, self.events = None, deque(maxlen=RING)
                        self.epoch, self.thread = secrets.token_hex(4), None
                        return
                    listening = bool(self.subs)
                if not listening:
                    self.wake.clear()
                    continue
                time.sleep(self.debounce_s)
                self.wake.clear()
                try:
                    db = db or store.connect(self.db_path)
                    self.check(db)
                except Exception as e:   # noqa: BLE001 - the next poke retries
                    from netwarden import health
                    log.debug("live check failed: %s", health.sanitize_error(e))
        finally:
            if db is not None:
                db.close()


# --- one detector per database file ------------------------------------------------------

_lock = threading.Lock()
_detectors: dict = {}


def _key(db_path) -> str:
    return os.path.abspath(str(db_path))


def detector(db_path, env: dict | None = None, hours: float = 24) -> Detector:
    """The detector of this database (created on first use)."""
    key = _key(db_path)
    with _lock:
        d = _detectors.get(key)
        if d is None or d.stopped:
            d = _detectors[key] = Detector(key, env, hours)
        return d


def poke(db_path) -> None:
    """New data may have landed in this database: let its detector (if any) look."""
    d = _detectors.get(_key(db_path))
    if d is not None:
        d.poke()


def stop_all() -> None:
    with _lock:
        for d in _detectors.values():
            d.stop()
        _detectors.clear()
