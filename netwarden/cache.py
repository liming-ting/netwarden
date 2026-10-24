"""
netwarden - cache.py: a small, safe memo for the expensive read-side computations.

The dashboard asks for the same derived data many times: one page refresh fires six
requests at once, and brain.snapshot(), devicetype.classify_all() and alerts.compute()
each recompute (often each other's) work over days of DNS events and traffic samples.
memo() keeps one result per (database file, computation, arguments) while the data has
not changed, and lets concurrent requests wait for ONE computation instead of racing.

When is a result stale?
  - the database's fingerprint changed: every table those computations read is summed
    up by cheap, indexed aggregates (row counts, newest / oldest timestamps, last
    rowids); any ingest, sweep, port check or user note (label, profile, ack) moves it;
  - or it is older than TTL seconds (time windows such as "the last 24 h" move on even
    when no new data arrives).

Never waiting behind a recompute (Stage V3): while ANOTHER thread is recomputing a key
(the startup warm-up, a loop's after-hook), a request gets the previous result instead,
as long as it is younger than STALE_MAX and the user's own notes are unchanged (a
label, ack or setting must show at once). batch() takes the fingerprint once per page
request instead of once per memo call.

In-memory databases are never cached (each ":memory:" connection is its own DB), so
unit tests on them see every change at once. Results are handed out as private copies
(marshal round trip: plain dicts / lists / sets / str / numbers), so a caller that
modifies what it got can never corrupt the cache. Read-only: it only reads SQLite.
"""
from __future__ import annotations

import marshal
import threading
import time
from contextlib import contextmanager

TTL = 30.0          # seconds; one dashboard refresh interval
MAX_ENTRIES = 64

_lock = threading.Lock()
_entries: dict = {}     # key -> (fingerprint, created monotonic, marshalled value)
_key_locks: dict = {}   # key -> Lock (single flight)
stats = {"hits": 0, "misses": 0, "stale": 0}

# (aggregate, is it the USER's doing?) - user notes, settings and checks the user asked
# for must show at once; the rest is data the loops keep adding (see STALE_MAX below)
PARTS = (
    ("(SELECT COUNT(*) FROM dns_events)", False), ("(SELECT MAX(ts) FROM dns_events)", False),
    ("(SELECT MIN(ts) FROM dns_events)", False), ("(SELECT MAX(rowid) FROM dns_events)", False),
    ("(SELECT MAX(rowid) FROM traffic_samples)", False),
    ("(SELECT MAX(ts) FROM traffic_samples)", False),
    ("(SELECT MIN(ts) FROM traffic_samples)", False),
    ("(SELECT COUNT(device_mac) FROM dns_events)", False),
    ("""(SELECT COUNT(*) || '|' || MAX(last_seen) || '|' || MAX(first_seen) || '|' ||
            TOTAL(LENGTH(hostname)) || '|' || TOTAL(LENGTH(ip)) || '|' || TOTAL(randomized)
            || '|' || TOTAL(LENGTH(vendor)) || '|' || TOTAL(is_self) FROM devices)""", False),
    ("(SELECT COUNT(*) || '|' || MAX(updated_at) FROM device_labels)", True),
    ("(SELECT COUNT(*) || '|' || MAX(updated_at) FROM device_profiles)", True),
    # (sums, not just MAX: any one snooze / tuning row changing its times must show)
    ("(SELECT COUNT(*) || '|' || MAX(created_at) || '|' || TOTAL(julianday(created_at)) || '|' "
     "|| COUNT(until) || '|' || TOTAL(julianday(until)) FROM acks)", True),
    ("(SELECT COUNT(*) || '|' || MAX(ts) FROM port_checks)", True),
    ("""(SELECT COUNT(*) || '|' || MAX(last_seen) || '|' || TOTAL(LENGTH(name))
            || '|' || TOTAL(LENGTH(model)) FROM device_identity)""", False),
    ("(SELECT COUNT(*) || '|' || MAX(ts) FROM upnp_snapshots)", False),
    ("(SELECT COUNT(*) || '|' || MAX(last_seen) FROM upnp_mappings)", False),
    ("(SELECT COUNT(*) || '|' || MAX(updated_at) || '|' || MAX(id) FROM bedtime_rules)", True),
    ("(SELECT group_concat(key || '=' || value) FROM meta)", True),
    ("(SELECT COUNT(*) || '|' || MAX(updated_at) FROM settings)", True),
    ("(SELECT COUNT(*) || '|' || MAX(ts) FROM health_samples)", False),
    ("(SELECT COUNT(*) || '|' || MAX(updated_at) || '|' || MAX(id) FROM outages)", False),
    ("(SELECT COUNT(*) || '|' || MAX(updated_at) FROM suggestion_state)", True),
    # Stage P: people (the user's) and the presence check's sightings (data)
    ("(SELECT COUNT(*) || '|' || MAX(updated_at) || '|' || MAX(id) FROM people)", True),
    ("(SELECT COUNT(*) || '|' || MAX(ts) FROM presence_samples)", False),
)
FINGERPRINT_SQL = "SELECT " + ",\n    ".join(expr for expr, _user in PARTS)
# positions of the user's part in fingerprint(); the two list files (custom trackers,
# threat feed) at the end count as the user's too
_USER = tuple(i for i, (_e, user) in enumerate(PARTS) if user) + (len(PARTS), len(PARTS) + 1)

# A request never queues behind ANOTHER thread's recomputation (the warm-up, a loop's
# after-run pass, a parallel request) of a result that only new DATA made stale: while
# that runs, it gets the previous result if it is at most STALE_MAX seconds old and the
# user's own notes are unchanged. Without a previous result it waits (single flight).
STALE_MAX = 90.0


def db_file(db) -> str | None:
    """The main database file of a connection, or None for an in-memory DB."""
    row = db.execute("PRAGMA database_list").fetchone()
    return (row[2] or None) if row else None


STAMP_TTL = 2.0     # seconds; a stat() costs ~5 ms on WSL's /mnt/c
_stamps: dict = {}


def _file_stamps() -> tuple:
    """(mtime, size) of the user-editable lists the computations read: the custom
    tracker file and the downloaded threat feed. Editing one invalidates the cache
    (within STAMP_TTL seconds)."""
    from netwarden import privacy, threatintel   # lazy: both import cache
    paths = (privacy.CUSTOM_FILE, threatintel.CACHE)
    hit = _stamps.get(paths)
    if hit and time.monotonic() - hit[0] < STAMP_TTL:
        return hit[1]
    out = []
    for path in paths:
        try:
            st = path.stat()
            out.append((st.st_mtime_ns, st.st_size))
        except OSError:
            out.append(None)
    _stamps[paths] = (time.monotonic(), tuple(out))
    return tuple(out)


_local = threading.local()


def fingerprint(db) -> tuple:
    """Cheap aggregates over every table the cached computations read (COUNT(device_mac)
    also moves when store.link_unattributed() attributes old events in place), plus the
    tracker / threat list files. Inside batch() it is computed once per connection
    (again only after that connection wrote something)."""
    b = getattr(_local, "batch", None)
    hit = b.get(id(db)) if b is not None else None
    if hit and hit[0] is db and hit[1] == db.total_changes:
        return hit[2]
    fp = tuple(db.execute(FINGERPRINT_SQL).fetchone()) + _file_stamps()
    if b is not None:
        b[id(db)] = (db, db.total_changes, fp)
    return fp


def _user_part(fp: tuple) -> tuple:
    return tuple(fp[i] for i in _USER)


@contextmanager
def batch():
    """One unit of work (a page request, a warm-up pass) in this thread: the fingerprint
    (~20 ms on a big DB; a snapshot asks a dozen memos) is taken once per connection
    and reused until that connection writes. Data another connection writes meanwhile
    is picked up by the next unit of work."""
    prev = getattr(_local, "batch", None)
    _local.batch = {} if prev is None else prev
    try:
        yield
    finally:
        _local.batch = prev


@contextmanager
def fresher(max_age: float):
    """Inside this block (this thread only), cached results older than max_age seconds
    count as stale. The web server's keep-warm pass (runner.Warmer) uses it to refresh
    results BEFORE a page request would find them expired and have to wait."""
    prev = getattr(_local, "max_age", None)
    _local.max_age = max_age
    try:
        yield
    finally:
        _local.max_age = prev


def memo(db, name: str, args: tuple, compute, ttl: float | None = None,
         loose: bool = False):
    """compute() once per (db file, name, args) while the data is unchanged and the
    result younger than TTL; otherwise recompute. Always returns a fresh copy.
    ttl / loose: for slow, coarse results (the 7-day export window) - a longer lifetime,
    and loose=True keeps the result while new data arrives (it only ages out)."""
    path = db_file(db)
    if not path:
        return compute()
    key = (path, name, args)
    max_age = getattr(_local, "max_age", None)
    ttl = ttl or TTL
    ttl = ttl if max_age is None else min(ttl, max_age)
    with _lock:
        klock = _key_locks.setdefault(key, threading.Lock())
        hit = _entries.get(key)
        if len(_key_locks) > MAX_LOCKS:
            _trim_locks(keep=key)
    if hit and max_age is None and klock.locked():
        fp = fingerprint(db)
        if time.monotonic() - hit[1] < STALE_MAX and _user_part(hit[0]) == _user_part(fp):
            stats["stale"] += 1
            return marshal.loads(hit[2])
    with klock:   # a second request for the same thing waits for the first one
        fp = fingerprint(db)
        hit = _entries.get(key)
        if hit and (loose or hit[0] == fp) and time.monotonic() - hit[1] < ttl:
            stats["hits"] += 1
            return marshal.loads(hit[2])
        stats["misses"] += 1
        value = compute()
        try:
            blob = marshal.dumps(value)
        except ValueError:      # not plain data: don't cache it
            return value
        with _lock:
            _entries[key] = (fp, time.monotonic(), blob)
            while len(_entries) > MAX_ENTRIES:   # oldest first
                oldest = min(_entries, key=lambda k: _entries[k][1])
                _entries.pop(oldest)
                _key_locks.pop(oldest, None)
        return marshal.loads(blob)


MAX_LOCKS = 4 * MAX_ENTRIES   # single-flight locks kept (one per key ever asked for)


def _trim_locks(keep) -> None:
    """Stage K: drop the idle locks of keys that hold no result (a computation that
    raised or was not cacheable; arguments come from requests - every device / search
    asked for - so they must not pile up for the life of the process). Caller holds _lock."""
    for k in [k for k, lk in _key_locks.items()
              if k not in _entries and k != keep and not lk.locked()]:
        del _key_locks[k]


def sizes() -> dict:
    """{entries, locks, bytes}: what the cache holds right now (the soak test watches it)."""
    with _lock:
        return {"entries": len(_entries), "locks": len(_key_locks),
                "bytes": sum(len(e[2]) for e in _entries.values())}


def clear() -> None:
    with _lock:
        _entries.clear()
        _key_locks.clear()
        _stamps.clear()
