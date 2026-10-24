"""
netwarden - SQLite store (devices + per-client DNS events)

Pure standard library. One file DB, default data/netwarden.db (gitignored).

Identity model:
  - A device is keyed by its MAC address: IPs come and go with DHCP, the MAC stays
    (except randomized/privacy MACs, which we flag and live with for now).
  - Each DNS event keeps the raw client IP *and* the device MAC that held that IP when
    we ingested it. Ingest runs often, so that is ~the device at query time, and a later
    IP reassignment can't silently re-attribute old history to a different device.
  - Optional traffic_samples (from traffic_ingest / ntopng) follow the same rule, and
    store CUMULATIVE counters; totals and rates come from differencing them.
"""
from __future__ import annotations

import bisect
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _data_paths(environ=None) -> tuple[Path, Path]:
    """(data directory, default DB) - read once at import, from the REAL environment:

      NETWARDEN_DB        the database file (the image sets /data/netwarden.db); its
                          folder is then the data directory too
      NETWARDEN_DATA_DIR  the data directory (DB = <dir>/netwarden.db)
      a source checkout   <checkout>/data (as always: pyproject.toml beside the package)
      installed (pip)     $XDG_DATA_HOME/netwarden, else ~/.local/share/netwarden -
                          never inside site-packages
    """
    environ = os.environ if environ is None else environ
    db = (environ.get("NETWARDEN_DB") or "").strip()
    if db:
        p = Path(db).expanduser()
        return p.parent, p
    folder = (environ.get("NETWARDEN_DATA_DIR") or "").strip()
    if folder:
        d = Path(folder).expanduser()
    else:
        root = Path(__file__).resolve().parent.parent
        if (root / "pyproject.toml").is_file():
            d = root / "data"
        else:
            base = (environ.get("XDG_DATA_HOME") or "").strip()
            d = (Path(base).expanduser() if base else Path.home() / ".local" / "share") / "netwarden"
    return d, d / "netwarden.db"


DATA_DIR, DEFAULT_DB = _data_paths()

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,               -- last IP we saw it on (NULL once another device takes it)
    vendor      TEXT,
    hostname    TEXT,
    randomized  INTEGER NOT NULL DEFAULT 0,
    is_self     INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS devices_ip ON devices(ip);

CREATE TABLE IF NOT EXISTS dns_events (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,      -- 'adguard' | 'pihole'
    ts          TEXT NOT NULL,      -- UTC, ISO 8601, microseconds: 2026-10-21T00:05:01.123456Z
    client_ip   TEXT NOT NULL,
    client_name TEXT,               -- hostname as the DNS server knew it, if any
    device_mac  TEXT REFERENCES devices(mac),   -- NULL until we can tie the IP to a device
    domain      TEXT NOT NULL,
    qtype       TEXT,
    status      TEXT,               -- DNS rcode, e.g. NOERROR / NXDOMAIN
    reason      TEXT,               -- server's raw verdict: NotFilteredNotFound (AdGuard), GRAVITY (Pi-hole)
    blocked     INTEGER NOT NULL DEFAULT 0,
    cached      INTEGER NOT NULL DEFAULT 0,
    upstream    TEXT,
    elapsed_ms  REAL,
    block_reason TEXT,              -- short WHY for blocked rows (see BLOCK_REASONS); NULL otherwise
    UNIQUE (source, ts, client_ip, domain, qtype)
);
CREATE INDEX IF NOT EXISTS dns_events_device_ts ON dns_events(device_mac, ts);
CREATE INDEX IF NOT EXISTS dns_events_client_ts ON dns_events(client_ip, ts);
CREATE INDEX IF NOT EXISTS dns_events_domain ON dns_events(domain);

CREATE TABLE IF NOT EXISTS ingest_state (
    source      TEXT PRIMARY KEY,
    last_ts     TEXT NOT NULL       -- newest event ts ingested from this source
);

-- The user's own notes about THEIR devices. netwarden stays read-only to the
-- NETWORK; these tables record only local preferences, never a router/firewall change.
CREATE TABLE IF NOT EXISTS device_labels (
    mac         TEXT PRIMARY KEY,
    label       TEXT NOT NULL,      -- friendly name, e.g. "客廳攝影機"
    note        TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL
);

-- More of the user's own notes: a device-type override and who / where the device is.
-- Free text, local only; NULL = not set (the type then comes from devicetype.py).
CREATE TABLE IF NOT EXISTS device_profiles (
    mac         TEXT PRIMARY KEY,
    type        TEXT,               -- a devicetype.TYPES key the user picked
    owner       TEXT,               -- the person it belongs to: people.name, e.g. "媽媽"
    room        TEXT,               -- e.g. "客廳"
    updated_at  TEXT NOT NULL,
    shared      INTEGER NOT NULL DEFAULT 0   -- Stage P: the household's (TV, speaker); owner NULL
);

-- Stage P: the people of the household (people.py). device_profiles.owner and
-- bedtime_rules.owner name a person by people.name (unique; a rename updates both in the
-- same transaction), so every older reader of "owner" keeps working. Presence is opt-in
-- per person (presence.py); presence_macs NULL = "their phones".
CREATE TABLE IF NOT EXISTS people (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,   -- never reused: notification keys name it
    name        TEXT NOT NULL UNIQUE,
    avatar      TEXT NOT NULL DEFAULT '',  -- an emoji or up to 3 letters; '' = the initials
    color       TEXT NOT NULL DEFAULT '',  -- a people.COLORS key
    child       INTEGER NOT NULL DEFAULT 0,
    note        TEXT NOT NULL DEFAULT '',
    presence    INTEGER NOT NULL DEFAULT 0,
    presence_macs  TEXT,               -- JSON list of MACs; NULL = their phones
    notify_arrive  INTEGER NOT NULL DEFAULT 0,
    notify_leave   INTEGER NOT NULL DEFAULT 0,
    presence_since TEXT,               -- "forget": presence history before this is ignored
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
-- Stage P: "this device was seen on the LAN at ts" for presence devices only, from the
-- discovery sweep and the light presence check (DNS activity is read from dns_events).
CREATE TABLE IF NOT EXISTS presence_samples (
    mac         TEXT NOT NULL,
    ts          TEXT NOT NULL,      -- UTC ISO 8601, same format as dns_events.ts
    source      TEXT NOT NULL       -- 'sweep' | 'check'
);
CREATE INDEX IF NOT EXISTS presence_samples_mac_ts ON presence_samples(mac, ts);

-- Acknowledged / muted alerts. domain = '' means "trust this whole device". Stage X:
-- until = a snoozed ack that stops counting after this UTC time (NULL = for good).
CREATE TABLE IF NOT EXISTS acks (
    mac         TEXT NOT NULL,
    domain      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    until       TEXT,
    PRIMARY KEY (mac, domain)
);

-- OPTIONAL per-device bandwidth, from a traffic sensor (ntopng). Each row is a
-- CUMULATIVE byte counter as the sensor reported it; window totals and rates come
-- from differencing consecutive samples. rx = received BY the device (download).
CREATE TABLE IF NOT EXISTS traffic_samples (
    mac         TEXT,               -- NULL if we couldn't tie the IP to a device yet
    ip          TEXT NOT NULL,
    ts          TEXT NOT NULL,      -- UTC ISO 8601, same format as dns_events.ts
    rx_bytes    INTEGER NOT NULL,
    tx_bytes    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS traffic_samples_mac_ts ON traffic_samples(mac, ts);
CREATE INDEX IF NOT EXISTS traffic_samples_ts ON traffic_samples(ts);
CREATE INDEX IF NOT EXISTS dns_events_ts ON dns_events(ts);

-- Health: one row per data source ('adguard', 'ntopng', 'discovery', ...), written by
-- every ingest / traffic / discovery run (CLI or background loop).
CREATE TABLE IF NOT EXISTS source_status (
    source        TEXT PRIMARY KEY,
    last_ok_ts    TEXT,             -- UTC ISO, last successful run
    last_error_ts TEXT,             -- UTC ISO, last failed run
    last_error    TEXT,             -- sanitized message of that failure
    last_count    INTEGER           -- what the last good run brought in (events / hosts / devices)
);

-- Opt-in exposure checks (exposure.py): one row per (device, port) per user-triggered
-- check. A plain TCP connect from this computer; all ports of one device check share ts.
CREATE TABLE IF NOT EXISTS port_checks (
    mac         TEXT NOT NULL,
    ip          TEXT NOT NULL,      -- the address we connected to
    port        INTEGER NOT NULL,
    open        INTEGER NOT NULL,   -- 1 = the TCP connect succeeded
    ts          TEXT NOT NULL       -- UTC ISO 8601, same format as dns_events.ts
);
CREATE INDEX IF NOT EXISTS port_checks_mac_ts ON port_checks(mac, ts);

-- Small key/value facts about the DB itself, e.g. demo = '1' for the seeded demo home.
CREATE TABLE IF NOT EXISTS meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

-- Stage N: what devices say about themselves on the LAN (identify.py) - one row per
-- (device, evidence source). source: 'mdns' | 'ssdp' | 'netbios' (announced by the
-- device itself; netbios = a Windows / Samba computer name, detail = its workgroup),
-- 'dhcp' (the name the router hands out, via reverse DNS), 'dns' (the client name the
-- DNS server - AdGuard / Pi-hole - knows). All text is hostile input from the network.
CREATE TABLE IF NOT EXISTS device_identity (
    mac          TEXT NOT NULL,
    source       TEXT NOT NULL,
    name         TEXT,              -- friendly name, e.g. "客廳電視" (mDNS fn / SSDP friendlyName)
    manufacturer TEXT,
    model        TEXT,
    kind         TEXT,              -- a devicetype.TYPES hint, or NULL
    detail       TEXT,              -- what announced it: mDNS service types / SSDP device type
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    PRIMARY KEY (mac, source)
);

-- Stage N: read-only UPnP look at the router (upnp.py). One row per check ...
CREATE TABLE IF NOT EXISTS upnp_snapshots (
    ts           TEXT PRIMARY KEY,
    available    INTEGER NOT NULL,  -- 1 = an Internet gateway answered UPnP
    gateway_ip   TEXT,
    gateway_name TEXT,
    external_ip  TEXT,              -- the home's public address (shown masked by default)
    status       TEXT,              -- GetStatusInfo: Connected / Disconnected / ...
    mappings     INTEGER NOT NULL DEFAULT 0,
    error        TEXT               -- sanitized, when the gateway answered badly
);
-- ... and every port mapping ever seen, with when it was first / last seen. "Current"
-- = seen by the newest available snapshot.
CREATE TABLE IF NOT EXISTS upnp_mappings (
    protocol        TEXT NOT NULL,      -- TCP | UDP
    external_port   INTEGER NOT NULL,
    remote_host     TEXT NOT NULL DEFAULT '',
    internal_client TEXT NOT NULL,      -- the LAN address the router forwards to
    internal_port   INTEGER NOT NULL,
    description     TEXT,               -- what the device called it (hostile text)
    enabled         INTEGER NOT NULL DEFAULT 1,
    lease           INTEGER,            -- seconds left; 0 = permanent
    mac             TEXT,               -- the device behind internal_client, if known
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    PRIMARY KEY (protocol, external_port, remote_host, internal_client, internal_port)
);

-- Stage F: the user's bedtime / quiet-hours rules (bedtime.py). NOTIFY ONLY: netwarden
-- never blocks anything. A rule targets one person (every device with that owner) OR one
-- device; days = the weekdays the window STARTS on (0 = Monday), so a 22:00-07:00
-- window on "6,0,1,2,3" is Sunday..Thursday night ("school nights"). Local user data.
CREATE TABLE IF NOT EXISTS bedtime_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,   -- never reused: acks name the id
    name        TEXT NOT NULL DEFAULT '',
    owner       TEXT,               -- device_profiles.owner, e.g. "小孩" ...
    mac         TEXT,               -- ... or one device
    days        TEXT NOT NULL,      -- "6,0,1,2,3"
    win_start   TEXT NOT NULL,      -- local "22:00"
    win_end     TEXT NOT NULL,      -- local "07:00" (<= start: the window crosses midnight)
    min_minutes INTEGER NOT NULL DEFAULT 10,   -- estimated screen time before it alerts
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- Settings the user changed in the dashboard (netwarden/settings.py registry). value is
-- JSON; an environment variable for the same key always wins; secrets are never stored.
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- Round 7 C: what each AI answer cost (usage.py) - local only, never sent anywhere. One
-- row per answer: tokens as the provider reported them (or a local estimate: estimated=1)
-- and the estimated cost in US$ from the price table / settings (NULL = no price, e.g. a
-- model on this computer). Kept USAGE_KEEP_DAYS whatever the retention (monthly totals).
CREATE TABLE IF NOT EXISTS ai_usage (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,      -- UTC, when the answer finished
    provider    TEXT NOT NULL,      -- "Anthropic" / "Ollama" / "host:port"
    model       TEXT NOT NULL,
    destination TEXT NOT NULL,      -- cloud | lan | local
    mode        TEXT NOT NULL,      -- chat | insight | demo (demo.build_ai_usage, synthetic)
    requests    INTEGER NOT NULL DEFAULT 1,
    input_tokens       INTEGER NOT NULL DEFAULT 0,   -- uncached input
    output_tokens      INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens  INTEGER NOT NULL DEFAULT 0,
    estimated   INTEGER NOT NULL DEFAULT 0,
    cost_usd    REAL
);
CREATE INDEX IF NOT EXISTS ai_usage_ts ON ai_usage(ts);

-- Stage H: network health (nethealth.py). The run loop's probe of the local default
-- gateway (and, opt-in, of one user-chosen internet host:port) - one row per probe.
CREATE TABLE IF NOT EXISTS health_samples (
    ts          TEXT NOT NULL,      -- UTC ISO 8601, same format as dns_events.ts
    target      TEXT NOT NULL,      -- 'gateway' | 'internet'
    ok          INTEGER NOT NULL,   -- 1 = it answered
    latency_ms  REAL,               -- average round trip (ICMP) or connect time (TCP)
    loss        REAL,               -- share of ICMP echoes lost, 0..1 (TCP: 0 or 1)
    method      TEXT                -- 'icmp' | 'tcp'
);
CREATE INDEX IF NOT EXISTS health_samples_target_ts ON health_samples(target, ts);
-- The outage log: derived from the samples + DNS upstream failures, kept as rows so the
-- history survives the samples' own pruning and every alert has a stable id.
CREATE TABLE IF NOT EXISTS outages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,   -- never reused: acks name the id
    start_ts    TEXT NOT NULL,      -- first bad minute (UTC)
    end_ts      TEXT NOT NULL,      -- end of the last bad minute (UTC)
    cause       TEXT NOT NULL,      -- 'router' | 'isp' | 'upstream' (nethealth.CAUSES)
    ongoing     INTEGER NOT NULL DEFAULT 0,
    gateway_min INTEGER NOT NULL DEFAULT 0,   -- minutes the gateway did not answer
    dns_min     INTEGER NOT NULL DEFAULT 0,   -- minutes DNS upstream lookups failed
    probe_min   INTEGER NOT NULL DEFAULT 0,   -- minutes the internet probe failed
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS outages_end ON outages(end_ts);

-- Stage H: what the user decided about a suggestion (suggestions.py) - local user data,
-- never pruned. status: done | dismissed | snoozed (no row = open); data = the
-- suggestion as it was when the user decided (JSON), so a resolved one can still be shown.
CREATE TABLE IF NOT EXISTS suggestion_state (
    id          TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    until       TEXT,               -- snoozed until (UTC ISO)
    data        TEXT,
    updated_at  TEXT NOT NULL
);

-- Stage H: one home network score per local day (score.py), for the weekly trend.
CREATE TABLE IF NOT EXISTS score_history (
    day         TEXT PRIMARY KEY,   -- local date "2026-10-22"
    score       INTEGER NOT NULL,
    parts       TEXT NOT NULL,      -- JSON {pillar: points}
    ts          TEXT NOT NULL
);

-- Stage Q: the notification ledger (notify.py). One row per notifiable event (an alert
-- instance or a presence arrival / departure) the first time netwarden routed it, so a
-- decision is made exactly once: 'sent' (shown when it happened), 'held' (it happened in
-- quiet hours; `until` = the end of that window) or 'released' (it went into the
-- window's "while you were asleep" summary). data = canonical JSON for that summary.
CREATE TABLE IF NOT EXISTS notify_log (
    key         TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    ts          TEXT NOT NULL,      -- first routed (UTC)
    state       TEXT NOT NULL,      -- 'sent' | 'held' | 'released'
    critical    INTEGER NOT NULL DEFAULT 0,
    win         TEXT,               -- the quiet window it was held in (its local start date)
    until       TEXT,               -- that window's end (UTC): release time
    data        TEXT
);
CREATE INDEX IF NOT EXISTS notify_log_state ON notify_log(state, until);
-- ... and one "while you were asleep" summary per quiet window, created exactly once
-- (UNIQUE win) when the window ends. seen_at = the user closed it on the dashboard.
CREATE TABLE IF NOT EXISTS quiet_summaries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    win         TEXT NOT NULL UNIQUE,
    start_ts    TEXT NOT NULL,
    end_ts      TEXT NOT NULL,
    items       TEXT NOT NULL,      -- JSON list of the held events (canonical)
    created_at  TEXT NOT NULL,
    seen_at     TEXT
);

-- Round 10 N: push notification channels (push.py, channels.py). config = non-secret
-- fields + options (JSON); secrets = tokens / passwords / webhook URLs / HMAC secret
-- (JSON): NEVER returned by an API, logged, exported, backed up or put in a report.
-- source 'env' = defined by NETWARDEN_NOTIFY_<n>_* (its secrets stay in the environment).
-- primed = 0: the next collect marks what is already there as not news.
CREATE TABLE IF NOT EXISTS push_channels (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    type          TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 0,
    config        TEXT NOT NULL DEFAULT '{}',
    secrets       TEXT NOT NULL DEFAULT '{}',
    source        TEXT NOT NULL DEFAULT 'db',
    primed        INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    last_ok_ts    TEXT,
    last_error    TEXT,             -- an error CLASS (channels.ERROR_CLASSES), never a body
    last_error_ts TEXT
);
-- One row per (channel, event key): the dedupe ledger and the delivery queue in one.
-- state: queued | held (quiet hours, until = the window's end) | sent | failed |
-- skipped (primed) | dropped (acked / muted / paused) | bundled (went into a summary).
CREATE TABLE IF NOT EXISTS push_outbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id  INTEGER NOT NULL,
    key         TEXT NOT NULL,
    kind        TEXT NOT NULL,      -- alert | score | weekly | daily | summary | bundle
    category    TEXT NOT NULL,
    sev         INTEGER NOT NULL DEFAULT 3,
    critical    INTEGER NOT NULL DEFAULT 0,
    state       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    next_at     TEXT,
    until       TEXT,
    win         TEXT,
    attempts    INTEGER NOT NULL DEFAULT 0,
    sent_at     TEXT,
    data        TEXT NOT NULL DEFAULT '{}',
    UNIQUE (channel_id, key)
);
CREATE INDEX IF NOT EXISTS push_outbox_due ON push_outbox(channel_id, state, next_at);
-- The delivery log a channel shows in Settings: time, what, ok or an error class.
CREATE TABLE IF NOT EXISTS push_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id  INTEGER NOT NULL,
    ts          TEXT NOT NULL,
    kind        TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT '',
    ok          INTEGER NOT NULL,
    error       TEXT,
    status      INTEGER,
    n           INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS push_log_channel ON push_log(channel_id, id);

-- Stage M: phone pairing (pairing.py). Secrets are stored ONLY as SHA-256 hashes.
-- A one-time code: 10 minutes, single use (used_at set atomically).
CREATE TABLE IF NOT EXISTS pair_codes (
    id          INTEGER PRIMARY KEY,
    code_hash   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    admin       INTEGER NOT NULL DEFAULT 0   -- round 6: `pair --admin` (15 minutes)
);
-- A paired browser's session (cookie nw_session); 30-day sliding expiry. label = its
-- user agent (hostile text: escaped on output). User data: revoked only by the user.
-- admin = 1: redeemed from an admin code - may do what this computer's own browser may.
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    label       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    admin       INTEGER NOT NULL DEFAULT 0
);
"""

BUSY_TIMEOUT_MS = 10_000      # loops + web server share one file: wait, don't fail
# Stage K: with readers always overlapping (loops + dashboard), SQLite's automatic
# checkpoint never gets to reset the WAL file, so it only grows; checkpoint() empties it
# now and then, and journal_size_limit truncates it whenever it is reset
WAL_LIMIT_BYTES = 8 * 1024 * 1024
MIN_RETENTION_DAYS = 8        # the 7-day views (+ 1 day of baseline) must stay intact
DEFAULT_RETENTION_DAYS = 90

EVENT_FIELDS = ("source", "ts", "client_ip", "client_name", "domain", "qtype", "status",
                "reason", "blocked", "cached", "upstream", "elapsed_ms", "block_reason")

# Raw verdicts that mean "the client did not get a real answer" -> a short, source-
# independent block_reason (stable English keys; the privacy statistics group by them).
# AdGuard Home's FilteringReason and Pi-hole v6's query status names never overlap.
# Not blocking: AdGuard NotFiltered* / Rewrite* / FilteredSafeSearch (a rewrite);
# Pi-hole FORWARDED / CACHE / CACHE_STALE / RETRIED* / IN_PROGRESS / UNKNOWN.
BLOCK_REASONS = {
    # AdGuard Home (openapi.yaml: FilteringReason)
    "FilteredBlackList": "blocklist",
    "FilteredSafeBrowsing": "safebrowsing",
    "FilteredParental": "parental",
    "FilteredBlockedService": "service",
    "FilteredInvalid": "invalid",
    # Pi-hole v6 (FTL datastructure.c: is_blocked())
    "GRAVITY": "blocklist",
    "GRAVITY_CNAME": "blocklist",       # blocked during deep CNAME inspection
    "REGEX": "regex",
    "REGEX_CNAME": "regex",
    "DENYLIST": "denylist",
    "DENYLIST_CNAME": "denylist",
    "EXTERNAL_BLOCKED_IP": "upstream",  # the upstream resolver blocked it
    "EXTERNAL_BLOCKED_NULL": "upstream",
    "EXTERNAL_BLOCKED_NXRA": "upstream",
    "EXTERNAL_BLOCKED_EDE15": "upstream",
    "SPECIAL_DOMAIN": "special",        # e.g. use-application-dns.net, iCloud Private Relay
    "DBBUSY": "busy",                   # Pi-hole's gravity DB was busy: refused for safety
}


def block_reason(raw: str | None) -> str | None:
    """Short block reason for a server's raw verdict, or None if it was not blocked."""
    return BLOCK_REASONS.get(raw or "")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class DBError(sqlite3.OperationalError):
    """The database file itself is the problem (Stage K): kind = 'corrupt' (damaged / not
    a database), 'locked' (another program holds it longer than the busy timeout) or
    'unreadable' (missing permissions, read-only, a directory, ...). str() keeps
    SQLite's own message for the log; users see a localized text (err.db_<kind>,
    cli.db.<kind>) instead of a traceback."""
    def __init__(self, kind: str, detail: str, path=None):
        super().__init__(detail)
        self.kind, self.path = kind, str(path) if path is not None else None


_PROBLEMS = (("corrupt", ("not a database", "malformed", "disk image", "encrypted",
                          "file is not")),
             ("locked", ("locked", "busy")),
             ("unreadable", ("unable to open", "readonly", "read-only", "permission",
                             "disk i/o", "access", "is a directory", "out of memory")))


def problem(e: BaseException) -> str | None:
    """'corrupt' | 'locked' | 'unreadable' when `e` says the database FILE is the trouble,
    else None (a bug, a constraint, ...)."""
    if isinstance(e, DBError):
        return e.kind
    if isinstance(e, sqlite3.DatabaseError) and not isinstance(e, sqlite3.IntegrityError):
        text = str(e).lower()
        for kind, words in _PROBLEMS:
            if any(w in text for w in words):
                return kind
    return None


def connect(path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    """Open (and create/migrate) the store. File DBs use WAL + a busy timeout, so the
    background loops and the web server can read and write the same file at once
    without "database is locked". A damaged, locked or unreadable file raises DBError."""
    # a "file:" URI is not a path here (sqlite3 is opened without uri=True): taken as one
    # it would silently create a "file:/..." folder tree under the working directory
    if str(path).lower().startswith("file:"):
        raise DBError("unreadable", "a file: URI is not a database path", Path(str(path)))
    path = Path(path)
    memory = str(path) == ":memory:"
    db = None
    try:
        if not memory:
            path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000)
        db.row_factory = sqlite3.Row
        db.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        if not memory:
            try:  # persistent; a filesystem without shared-memory support keeps the default
                db.execute("PRAGMA journal_mode = WAL")
                db.execute(f"PRAGMA journal_size_limit = {WAL_LIMIT_BYTES}")
            except sqlite3.OperationalError as e:
                if problem(e) == "corrupt":
                    raise
        db.execute("PRAGMA foreign_keys = ON")
        db.executescript(SCHEMA)
        _migrate(db)
        return db
    except (sqlite3.DatabaseError, OSError) as e:
        if db is not None:
            db.close()
        kind = problem(e) or ("unreadable" if isinstance(e, OSError) else None)
        if kind is None:
            raise
        raise DBError(kind, str(e) or type(e).__name__, path) from e


def _migrate(db: sqlite3.Connection) -> None:
    """Bring a DB created by an older netwarden up to SCHEMA (additive, idempotent)."""
    if "until" not in {r["name"] for r in db.execute("PRAGMA table_info(acks)")}:
        with db:   # Stage X: snoozed acks
            db.execute("ALTER TABLE acks ADD COLUMN until TEXT")
    if "shared" not in {r["name"] for r in db.execute("PRAGMA table_info(device_profiles)")}:
        with db:   # Stage P: "Shared" devices
            db.execute("ALTER TABLE device_profiles ADD COLUMN shared INTEGER NOT NULL DEFAULT 0")
    for table in ("pair_codes", "sessions"):   # round 6: admin pairing (headless installs)
        if "admin" not in {r["name"] for r in db.execute(f"PRAGMA table_info({table})")}:
            with db:
                db.execute(f"ALTER TABLE {table} ADD COLUMN admin INTEGER NOT NULL DEFAULT 0")
    sync_people(db)   # Stage P: every owner named anywhere is a person
    cols = {r["name"] for r in db.execute("PRAGMA table_info(dns_events)")}
    if "block_reason" not in cols:
        with db:
            db.execute("ALTER TABLE dns_events ADD COLUMN block_reason TEXT")
            # Backfill from the raw verdict we always kept; a blocked row whose verdict
            # we can't map still gets a reason, so "blocked" and "why" never disagree.
            for raw, short in BLOCK_REASONS.items():
                db.execute("""UPDATE dns_events SET block_reason = ?
                              WHERE blocked = 1 AND block_reason IS NULL AND reason = ?""",
                           (short, raw))
            db.execute("""UPDATE dns_events SET block_reason = 'other'
                          WHERE blocked = 1 AND block_reason IS NULL""")
    # Older discovery / demo builds stored fixed-language placeholders as the vendor,
    # which then showed up as the device name in every UI language. "Unknown" is ""
    # now; devices.randomized / is_self say the rest and the UI localizes them.
    if db.execute(f"SELECT 1 FROM devices WHERE vendor IN ({','.join('?' * len(LEGACY_VENDORS))}) "
                  "LIMIT 1", LEGACY_VENDORS).fetchone():
        with db:
            db.execute(f"UPDATE devices SET vendor = '' WHERE vendor IN "
                       f"({','.join('?' * len(LEGACY_VENDORS))})", LEGACY_VENDORS)
    for table, ack_ids in ACKED_ID_TABLES.items():
        _autoincrement(db, table, ack_ids)


# Tables whose ids appear in ack keys ("outage:<id>", "bedtime:<id>:<night>"): an id must
# never be handed out twice, or an old "Got it" would silently mute a NEW outage / rule.
# table -> SQL giving the ids the acks mention (so the counter starts above them).
ACKED_ID_TABLES = {
    "outages": "SELECT substr(domain, 8) AS id FROM acks WHERE domain LIKE 'outage:%'",
    "bedtime_rules": """SELECT substr(domain, 9, instr(substr(domain, 9), ':') - 1) AS id
                        FROM acks WHERE domain LIKE 'bedtime:%:%'""",
}
MAX_ROWID = 2 ** 63 - 1


def _autoincrement(db: sqlite3.Connection, table: str, ack_ids: str) -> None:
    """Rebuild a pre-AUTOINCREMENT `table` (older builds reused the highest deleted id)
    and start its counter above every id an ack still mentions. Runs once per DB."""
    sql = db.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                     (table,)).fetchone()["sql"]
    if "AUTOINCREMENT" in sql.upper():
        return
    new_sql = re.sub(r"^CREATE TABLE\s+(IF NOT EXISTS\s+)?\"?" + table + r"\"?",
                     f"CREATE TABLE {table}__new", sql, count=1, flags=re.I)
    new_sql = re.sub(r"\bid\s+INTEGER PRIMARY KEY\b", "id INTEGER PRIMARY KEY AUTOINCREMENT",
                     new_sql, count=1, flags=re.I)
    acked = [int(r["id"]) for r in db.execute(ack_ids) if str(r["id"]).isdigit()]
    db.execute("BEGIN")
    try:
        db.execute(new_sql)
        db.execute(f"INSERT INTO {table}__new SELECT * FROM {table}")
        db.execute(f"DROP TABLE {table}")
        db.execute(f"ALTER TABLE {table}__new RENAME TO {table}")
        top = max([db.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()[0]]
                  + [i for i in acked if i <= MAX_ROWID])
        db.execute("DELETE FROM sqlite_sequence WHERE name = ?", (table,))
        db.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", (table, top))
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise
    db.executescript(SCHEMA)   # the indexes dropped with the old table


LEGACY_VENDORS = ("随机MAC (手机/隐私模式)", "— (未知厂商)", "(this machine · netwarden)",
                  "randomized MAC (phone/privacy)", "randomized MAC (private address)")


# --- devices ---------------------------------------------------------------

def upsert_device(db: sqlite3.Connection, d: dict, seen: str | None = None) -> None:
    """Insert/refresh a device record (shape: discovery.device_record). Needs a MAC."""
    if not d.get("mac"):
        return
    seen = seen or now()
    with db:
        # An IP belongs to one device at a time: whoever had it before lost it.
        db.execute("UPDATE devices SET ip = NULL WHERE ip = ? AND mac != ?", (d["ip"], d["mac"]))
        db.execute(
            """INSERT INTO devices (mac, ip, vendor, hostname, randomized, is_self, first_seen, last_seen)
               VALUES (:mac, :ip, :vendor, :hostname, :randomized, :is_self, :seen, :seen)
               ON CONFLICT(mac) DO UPDATE SET
                   ip = excluded.ip,
                   vendor = COALESCE(NULLIF(excluded.vendor, ''), devices.vendor),
                   hostname = COALESCE(NULLIF(excluded.hostname, ''), devices.hostname),
                   randomized = excluded.randomized,
                   is_self = excluded.is_self,
                   last_seen = excluded.last_seen""",
            {**d, "randomized": int(bool(d.get("randomized"))),
             "is_self": int(bool(d.get("is_self"))), "seen": seen},
        )


def ip_to_mac(db: sqlite3.Connection) -> dict[str, str]:
    """Current IP -> MAC map of known devices."""
    return {r["ip"]: r["mac"] for r in db.execute("SELECT ip, mac FROM devices WHERE ip IS NOT NULL")}


def device_names(db: sqlite3.Connection) -> dict:
    """mac -> best human name (the user's label > hostname > the name the device
    announced on the LAN (mDNS / SSDP) > vendor > mac)."""
    announced = identity_names(db)
    names = {r["mac"]: r["hostname"] or announced.get(r["mac"]) or r["vendor"] or r["mac"]
             for r in db.execute("SELECT mac, vendor, hostname FROM devices")}
    for mac, lab in get_labels(db).items():
        names[mac] = lab["label"]
    return names


# --- device identity evidence (Stage N, identify.py) ---------------------------

IDENTITY_SOURCES = ("mdns", "ssdp", "netbios", "dns", "dhcp")   # best evidence first
ANNOUNCED_SOURCES = ("mdns", "ssdp", "netbios")   # names a device gave itself
MAX_IDENTITY_TEXT = 96


def upsert_identity(db: sqlite3.Connection, mac: str, source: str, name: str = "",
                    manufacturer: str = "", model: str = "", kind: str | None = None,
                    detail: str = "", seen: str | None = None) -> None:
    """Record what `source` says about a device. Text is cleaned (one line, capped);
    an empty value keeps what we knew before."""
    if not mac or source not in IDENTITY_SOURCES:
        return
    seen = seen or now()
    vals = {k: clean_text(v, MAX_IDENTITY_TEXT) or None
            for k, v in (("name", name), ("manufacturer", manufacturer), ("model", model),
                         ("detail", detail))}
    with db:
        db.execute(
            """INSERT INTO device_identity (mac, source, name, manufacturer, model, kind,
                                            detail, first_seen, last_seen)
               VALUES (:mac, :source, :name, :manufacturer, :model, :kind, :detail, :seen, :seen)
               ON CONFLICT(mac, source) DO UPDATE SET
                   name = COALESCE(excluded.name, device_identity.name),
                   manufacturer = COALESCE(excluded.manufacturer, device_identity.manufacturer),
                   model = COALESCE(excluded.model, device_identity.model),
                   kind = COALESCE(excluded.kind, device_identity.kind),
                   detail = COALESCE(excluded.detail, device_identity.detail),
                   last_seen = MAX(device_identity.last_seen, excluded.last_seen)""",
            {"mac": mac, "source": source, "kind": kind or None, "seen": seen, **vals})


def identities(db: sqlite3.Connection, mac: str | None = None) -> dict:
    """mac -> [{source, name, manufacturer, model, kind, detail, first_seen, last_seen}],
    best evidence first (IDENTITY_SOURCES order)."""
    order = " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(IDENTITY_SOURCES))
    sql = f"SELECT * FROM device_identity {'WHERE mac = ?' if mac else ''} " \
          f"ORDER BY mac, CASE source {order} ELSE 9 END"
    out: dict = {}
    for r in db.execute(sql, (mac,) if mac else ()):
        out.setdefault(r["mac"], []).append({k: r[k] for k in r.keys() if k != "mac"})
    return out


def identity_names(db: sqlite3.Connection) -> dict:
    """mac -> the friendly name a device announced itself (mDNS, then SSDP, then its
    NetBIOS computer name)."""
    out: dict = {}
    for r in db.execute("""SELECT mac, name FROM device_identity
                           WHERE source IN ('mdns', 'ssdp', 'netbios') AND name IS NOT NULL
                             AND name != ''
                           ORDER BY CASE source WHEN 'mdns' THEN 0 WHEN 'ssdp' THEN 1
                                    ELSE 2 END"""):
        out.setdefault(r["mac"], r["name"])
    return out


# --- UPnP snapshots (Stage N, upnp.py) ------------------------------------------

def record_upnp(db: sqlite3.Connection, snap: dict, mappings: list, ts: str | None = None) -> str:
    """Store one UPnP check: the gateway facts in upnp_snapshots and each mapping's
    first / last sighting in upnp_mappings. Returns the snapshot ts."""
    ts = ts or now()
    with db:
        db.execute("""INSERT OR REPLACE INTO upnp_snapshots (ts, available, gateway_ip,
                          gateway_name, external_ip, status, mappings, error)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                   (ts, int(bool(snap.get("available"))), snap.get("gateway_ip"),
                    snap.get("gateway_name"), snap.get("external_ip"), snap.get("status"),
                    len(mappings), snap.get("error")))
        for m in mappings:
            db.execute(
                """INSERT INTO upnp_mappings (protocol, external_port, remote_host,
                       internal_client, internal_port, description, enabled, lease, mac,
                       first_seen, last_seen)
                   VALUES (:protocol, :external_port, :remote_host, :internal_client,
                           :internal_port, :description, :enabled, :lease, :mac, :ts, :ts)
                   ON CONFLICT(protocol, external_port, remote_host, internal_client,
                               internal_port) DO UPDATE SET
                       description = excluded.description, enabled = excluded.enabled,
                       lease = excluded.lease, mac = COALESCE(excluded.mac, upnp_mappings.mac),
                       last_seen = MAX(upnp_mappings.last_seen, excluded.last_seen)""",
                {"remote_host": "", "description": None, "enabled": 1, "lease": None,
                 "mac": None, **m, "ts": ts})
    return ts


def upnp_latest(db: sqlite3.Connection) -> dict | None:
    """The newest UPnP snapshot row, or None if UPnP was never checked."""
    r = db.execute("SELECT * FROM upnp_snapshots ORDER BY ts DESC LIMIT 1").fetchone()
    return dict(r) if r else None


def upnp_first_ts(db: sqlite3.Connection) -> str | None:
    """When netwarden first found the gateway answering UPnP (the "before" of "new")."""
    return db.execute("SELECT MIN(ts) FROM upnp_snapshots WHERE available = 1").fetchone()[0]


def upnp_current(db: sqlite3.Connection) -> list[dict]:
    """The mappings the newest snapshot saw. Empty when that check found no UPnP gateway:
    a user who followed the advice and turned UPnP off must not keep seeing old ports."""
    r = db.execute("SELECT ts, available FROM upnp_snapshots ORDER BY ts DESC LIMIT 1").fetchone()
    if not r or not r["available"]:
        return []
    return [dict(m) for m in db.execute(
        "SELECT * FROM upnp_mappings WHERE last_seen >= ? ORDER BY external_port, protocol",
        (r["ts"],))]


def self_mac(db: sqlite3.Connection) -> str | None:
    row = db.execute("SELECT mac FROM devices WHERE is_self = 1 ORDER BY last_seen DESC").fetchone()
    return row["mac"] if row else None


# --- DNS events ------------------------------------------------------------

def insert_events(db: sqlite3.Connection, events: list[dict]) -> int:
    """Insert normalized events (dicts with EVENT_FIELDS + device_mac). Returns # new rows."""
    cols = EVENT_FIELDS + ("device_mac",)
    sql = (f"INSERT OR IGNORE INTO dns_events ({', '.join(cols)}) "
           f"VALUES ({', '.join(':' + c for c in cols)})")
    with db:
        before = db.total_changes
        db.executemany(sql, [{c: e.get(c) for c in cols} for e in events])
        return db.total_changes - before


def link_unattributed(db: sqlite3.Connection, ip_mac: dict[str, str], since: str) -> int:
    """Attach device_mac to events that arrived before we knew the device.

    Only touches events newer than `since` (a recent window), so we don't pin
    ancient history on whoever happens to hold the IP today."""
    n = 0
    with db:
        for ip, mac in ip_mac.items():
            cur = db.execute(
                """UPDATE dns_events SET device_mac = ?
                   WHERE device_mac IS NULL AND client_ip = ? AND ts >= ?""",
                (mac, ip, since),
            )
            n += cur.rowcount
    return n


def get_watermark(db: sqlite3.Connection, source: str) -> str | None:
    row = db.execute("SELECT last_ts FROM ingest_state WHERE source = ?", (source,)).fetchone()
    return row["last_ts"] if row else None


def set_watermark(db: sqlite3.Connection, source: str, ts: str) -> None:
    with db:
        db.execute(
            """INSERT INTO ingest_state (source, last_ts) VALUES (?, ?)
               ON CONFLICT(source) DO UPDATE SET last_ts = MAX(last_ts, excluded.last_ts)""",
            (source, ts),
        )


# --- read side (for reports now, brain.py later) ---------------------------

def device_activity(db: sqlite3.Connection, since: str | None = None, top: int = 5) -> list[dict]:
    """Per client: device info, query/blocked counts, and its top domains."""
    since = since or "0000"
    clients = db.execute(
        """SELECT COALESCE(e.device_mac, 'ip:' || e.client_ip) AS key,
                  e.device_mac, d.vendor, d.hostname, d.is_self,
                  GROUP_CONCAT(DISTINCT e.client_ip) AS ips,
                  MAX(e.client_name) AS client_name,
                  COUNT(*) AS queries, SUM(e.blocked) AS blocked,
                  COUNT(DISTINCT e.domain) AS domains,
                  MIN(e.ts) AS first_ts, MAX(e.ts) AS last_ts
           FROM dns_events e LEFT JOIN devices d ON d.mac = e.device_mac
           WHERE e.ts >= ?
           GROUP BY key ORDER BY queries DESC""",
        (since,),
    ).fetchall()
    # Every client's top domains in ONE query (not one per client): rank per key.
    tops: dict = {}
    for t in db.execute(
        """SELECT key, domain, n, blocked FROM (
               SELECT COALESCE(device_mac, 'ip:' || client_ip) AS key, domain,
                      COUNT(*) AS n, SUM(blocked) AS blocked,
                      ROW_NUMBER() OVER (PARTITION BY COALESCE(device_mac, 'ip:' || client_ip)
                                         ORDER BY COUNT(*) DESC, domain) AS rank
               FROM dns_events WHERE ts >= ? GROUP BY key, domain)
           WHERE rank <= ? ORDER BY key, rank""",
        (since, top),
    ):
        tops.setdefault(t["key"], []).append({"domain": t["domain"], "n": t["n"],
                                              "blocked": t["blocked"]})
    return [{**dict(c), "top_domains": tops.get(c["key"], [])} for c in clients]


def daily_trend(db: sqlite3.Connection, mac: str, days: int = 7) -> list[dict]:
    """Per-day query/blocked counts for one device over the last `days` days,
    oldest first, with empty days filled in as zero (so a sparkline has no gaps)."""
    since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    rows = db.execute(
        """SELECT substr(ts, 1, 10) AS day, COUNT(*) AS queries, SUM(blocked) AS blocked
           FROM dns_events WHERE device_mac = ? AND ts >= ?   -- same as day >= since; indexed
           GROUP BY day""",
        (mac, since),
    ).fetchall()
    by_day = {r["day"]: (r["queries"], r["blocked"] or 0) for r in rows}
    today = datetime.now(timezone.utc).date()
    out = []
    for i in range(days - 1, -1, -1):
        day = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        q, b = by_day.get(day, (0, 0))
        out.append({"day": day, "queries": q, "blocked": b})
    return out


# --- traffic samples (optional bandwidth source) ---------------------------

def insert_traffic_samples(db: sqlite3.Connection, samples: list[dict]) -> int:
    """Store cumulative per-host counters ({mac, ip, ts, rx_bytes, tx_bytes}). Returns # rows."""
    rows = [{"mac": s.get("mac"), "ip": s["ip"], "ts": s["ts"],
             "rx_bytes": int(s.get("rx_bytes") or 0), "tx_bytes": int(s.get("tx_bytes") or 0)}
            for s in samples if s.get("ip")]
    with db:
        db.executemany(
            """INSERT INTO traffic_samples (mac, ip, ts, rx_bytes, tx_bytes)
               VALUES (:mac, :ip, :ts, :rx_bytes, :tx_bytes)""", rows)
    return len(rows)


def _delta(prev: int, cur: int) -> int:
    """Growth of a cumulative counter. A decrease means the counter reset (sensor or
    device restart): the new value is what accrued since the reset - never negative."""
    return cur - prev if cur >= prev else cur


def _secs(a: str, b: str) -> float:
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    return (datetime.strptime(b, fmt) - datetime.strptime(a, fmt)).total_seconds()


def _series_pairs(rows):
    """Consecutive (prev, cur) samples within each (key, ip) counter series. One MAC can
    hold several IPs at once (IPv4 + IPv6, old + new lease), each with its OWN cumulative
    counter - diffing across them would look like a reset every switch. `rows` must be
    ordered by key, ip, ts."""
    prev = None
    for r in rows:
        if prev is not None and prev["key"] == r["key"] and prev["ip"] == r["ip"]:
            yield prev, r
        prev = r


STALE_SERIES_SECONDS = 600  # an IP series this much older than the device's newest
                            # sample no longer counts toward the "current" rate
CURRENT_RATE_MAX_AGE = 900  # ... nor does any series silent for this long before "now"


def bandwidth_summary(db: sqlite3.Connection, since: str | None = None,
                      as_of: str | None = None) -> dict:
    """Per device (keyed by MAC, or 'ip:<addr>' if unattributed), over samples at/after `since`:
        rx_bytes / tx_bytes : bytes downloaded / uploaded in the window (summed deltas)
        rx_bps / tx_bps     : current rate in bits/s: each live IP series' last pair, summed
                              (series whose newest sample is > STALE_SERIES_SECONDS older
                              than the device's newest sample, or > CURRENT_RATE_MAX_AGE
                              older than `as_of` (default: now), are skipped)
        peak_bps            : highest combined (rx+tx) bits/s at any sample time
    Each (device, IP) series is diffed on its own. Its last sample in the day before
    `since` serves as baseline, so the first delta inside the window is not lost.
    A device needs at least two samples (counting the baseline) to appear."""
    scan = _bandwidth_scan(db, since or "0000", rates=True)
    out = {key: {"rx_bytes": rx, "tx_bytes": tx, "rx_bps": 0, "tx_bps": 0,
                 "peak_bps": scan["peak"].get(key, 0)} for key, (rx, tx) in scan["totals"].items()}
    # "Now" for the current rate: the clock, or for the demo DB (frozen synthetic data,
    # no loops) its newest sample, so the seeded story still has a current rate.
    if as_of is None:
        as_of = now()
        if is_demo(db):
            as_of = db.execute("SELECT MAX(ts) FROM traffic_samples").fetchone()[0] or as_of
    end, device_end = scan["end"], {}
    for (key, _ip), ts in end.items():
        if ts > device_end.get(key, ""):
            device_end[key] = ts
    for (key, ip), (drx, dtx, dt_us) in scan["last_pair"].items():
        # A series that stopped reporting well before the device's newest reading (an
        # old DHCP lease, an IPv6 address that went away) is history, not a current
        # rate - and so is a device that has not reported at all for a while (it went
        # offline hours ago: its last pair must not read as "now").
        end_ts = end[(key, ip)]
        if _secs(end_ts, device_end[key]) > STALE_SERIES_SECONDS \
                or _secs(end_ts, as_of) > CURRENT_RATE_MAX_AGE:
            continue
        out[key]["rx_bps"] += drx * 8e6 / dt_us
        out[key]["tx_bps"] += dtx * 8e6 / dt_us
    for s in out.values():
        for k in ("rx_bps", "tx_bps", "peak_bps"):
            s[k] = round(s[k])
    return out


def _epoch_us(ts: str, _memo: dict = {}) -> int:   # noqa: B006 - a deliberate cache
    """Microseconds since the epoch of a netwarden timestamp (2026-10-21T00:05:01.123456Z).
    One traffic poll writes the same timestamp for every host, so the parse is memoized
    (bounded: cleared when it grows large)."""
    v = _memo.get(ts)
    if v is None:
        dt = datetime(int(ts[0:4]), int(ts[5:7]), int(ts[8:10]), int(ts[11:13]),
                      int(ts[14:16]), int(ts[17:19]), tzinfo=timezone.utc)
        v = int(dt.timestamp()) * 1_000_000 + int(ts[20:26] or 0)
        if len(_memo) > 200_000:
            _memo.clear()
        _memo[ts] = v
    return v


def _bandwidth_scan(db: sqlite3.Connection, since: str, rates: bool) -> dict:
    """The series differencing behind bandwidth_summary() / bandwidth_totals(): ONE pass
    over the window's samples in time order (the ts index), each (key, ip) series diffed
    against its own previous sample; a series' last sample in the day before `since` is
    its baseline, so the first delta inside the window is not lost. (A streaming pass
    in Python is ~3x faster here than the same differencing as SQL window functions,
    which have to sort every sample by series first.) -> {
        totals:    {key: (rx, tx)}               keys with >= 1 counted delta
        peak:      {key: bits/s}                 highest combined rate of all its series
                                                 ending at one sample time (rates only)
        last_pair: {(key, ip): (drx, dtx, dt_us)} each series' last TIMED pair (a
                                                 duplicate timestamp adds bytes, no rate)
        end:       {(key, ip): ts}               when each series last reported}"""
    try:
        base_from = (datetime.fromisoformat(since) - timedelta(days=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        base_from = since  # no parseable window start -> no baseline
    cur = db.cursor()
    cur.row_factory = None
    prev: dict = {}      # (key, ip) -> (us, rx, tx) of its previous sample
    end: dict = {}
    # baseline: the latest sample per series before the window (SQLite takes the bare
    # columns from the MAX(ts) row)
    for key, ip, ts, rx, tx in cur.execute(
            """SELECT COALESCE(mac, 'ip:' || ip) AS key, ip, MAX(ts), rx_bytes, tx_bytes
               FROM traffic_samples WHERE ts >= ? AND ts < ? GROUP BY key, ip""",
            (base_from, since)):
        prev[(key, ip)] = (_epoch_us(ts) if rates else 0, rx, tx)
        end[(key, ip)] = ts
    totals: dict = {}
    per_ts: dict = {}    # (key, ts) -> summed bits/s of the series' timed pairs at ts
    last_pair: dict = {}
    for key, ip, ts, rx, tx in cur.execute(
            """SELECT COALESCE(mac, 'ip:' || ip), ip, ts, rx_bytes, tx_bytes
               FROM traffic_samples WHERE ts >= ? ORDER BY ts, rowid""", (since,)):
        series = (key, ip)
        us = _epoch_us(ts) if rates else 0
        p = prev.get(series)
        prev[series] = (us, rx, tx)
        end[series] = ts
        if p is None:
            continue
        drx = _delta(p[1], rx)
        dtx = _delta(p[2], tx)
        t = totals.get(key)
        totals[key] = (drx, dtx) if t is None else (t[0] + drx, t[1] + dtx)
        if rates and us > p[0]:
            per_ts[(key, ts)] = per_ts.get((key, ts), 0) + (drx + dtx) * 8e6 / (us - p[0])
            last_pair[series] = (drx, dtx, us - p[0])
    peak: dict = {}
    for (key, _ts), bps in per_ts.items():
        if bps > peak.get(key, 0):
            peak[key] = bps
    return {"totals": totals, "peak": peak, "last_pair": last_pair, "end": end}


def bandwidth_totals(db: sqlite3.Connection, since: str) -> dict:
    """Just the window totals of bandwidth_summary() - {key: {rx_bytes, tx_bytes}}, same
    series diffing, same baseline, same "two samples" rule - without the current and
    peak rates, whose per-sample timing math dominates the cost on long windows (the
    7-day CSV export). Shared through netwarden.cache like bandwidth_window()."""
    from netwarden import cache
    return cache.memo(db, "store.bandwidth_totals", (since[:16],),
                      lambda: _bandwidth_totals(db, since))


def _bandwidth_totals(db: sqlite3.Connection, since: str) -> dict:
    return {key: {"rx_bytes": rx, "tx_bytes": tx}
            for key, (rx, tx) in _bandwidth_scan(db, since, rates=False)["totals"].items()}


def bandwidth_days(db: sqlite3.Connection, mac: str, now: datetime, days: int = 8) -> list:
    """One device's bytes (rx + tx) per rolling 24-hour bucket ending at `now`: index 0 =
    the last 24 h, 1 = the 24 h before, ... None for a bucket without any counted delta
    (no data then). Each IP series is diffed on its own (resets as in _delta); a delta
    counts toward the bucket of its later sample. Indexed per MAC: cheap for one device."""
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    start = now - timedelta(days=days + 1)   # one extra day: a baseline for the first delta
    # bucket edges as timestamps, oldest first: a sample at or before edge k (now - k
    # days) is at least k days old - string order is time order for our timestamps
    edges = [(now - timedelta(days=k)).strftime(fmt) for k in range(days, 0, -1)]
    now_s = now.strftime(fmt)
    cur = db.cursor()
    cur.row_factory = None
    out: list = [None] * days
    prev: dict = {}       # ip -> (rx, tx) of its previous sample
    for ip, ts, rx, tx in cur.execute(
            """SELECT ip, ts, rx_bytes, tx_bytes FROM traffic_samples
               WHERE mac = ? AND ts >= ? ORDER BY ts, rowid""", (mac, start.strftime(fmt))):
        p = prev.get(ip)
        prev[ip] = (rx, tx)
        if p is None or ts > now_s:
            continue
        b = days - bisect.bisect_left(edges, ts)
        if b < days:
            out[b] = (out[b] or 0) + _delta(p[0], rx) + _delta(p[1], tx)
    return out


def bandwidth_days_floor(db: sqlite3.Connection, mac: str, now: datetime,
                         days: int = 8) -> list:
    """A cheap LOWER BOUND of bandwidth_days() per bucket (0 where nothing is known):
    for the device's current IP series, the counter growth between the bucket edges,
    read with ~10 indexed one-row lookups instead of every sample. It never exceeds the
    exact value - each delta is >= cur - prev, so their sum is >= last - first, and a
    series it does not look at only makes it smaller - so a check that fails on these
    numbers fails on the exact ones too (alerts.bandwidth_spikes uses it as a filter)."""
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    start = (now - timedelta(days=days + 1)).strftime(fmt)   # bandwidth_days' window
    edges = [(now - timedelta(days=k)).strftime(fmt) for k in range(days + 1)]
    row = db.execute("""SELECT ip FROM traffic_samples WHERE mac = ? AND ts >= ? AND ts <= ?
                        ORDER BY ts DESC, rowid DESC LIMIT 1""", (mac, start, edges[0])).fetchone()
    if row is None:
        return [0] * days
    at = []   # the series' last (rx, tx) at or before each edge (inside the window)
    for e in edges:
        r = db.execute("""SELECT rx_bytes, tx_bytes FROM traffic_samples
                          WHERE mac = ? AND ip = ? AND ts >= ? AND ts <= ?
                          ORDER BY ts DESC, rowid DESC LIMIT 1""", (mac, row[0], start, e)).fetchone()
        at.append((r[0], r[1]) if r else None)
    return [max(0, at[k][0] - at[k + 1][0]) + max(0, at[k][1] - at[k + 1][1])
            if at[k] and at[k + 1] else 0 for k in range(days)]


def bandwidth_window(db: sqlite3.Connection, since: str) -> dict:
    """bandwidth_summary() for a rolling window ("the last 24 h"), shared through
    netwarden.cache: callers whose window starts within the same minute (the snapshot,
    the type guesser, ...) reuse one computation while no new samples arrive."""
    from netwarden import cache
    return cache.memo(db, "store.bandwidth_window", (since[:16],),
                      lambda: bandwidth_summary(db, since))


def bandwidth_trend(db: sqlite3.Connection, mac: str, days: int = 7) -> list[dict]:
    """Per-day rx/tx bytes for one device over the last `days` days, oldest first,
    zero-filled like daily_trend. Each delta counts toward the day of its later sample."""
    today = datetime.now(timezone.utc).date()
    first_day = (today - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    # one extra day back, so the first counted delta has a sample to diff against
    fetch_from = (today - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = db.execute(
        """SELECT mac AS key, ip, ts, rx_bytes, tx_bytes FROM traffic_samples
           WHERE mac = ? AND ts >= ? ORDER BY ip, ts, rowid""",
        (mac, fetch_from),
    ).fetchall()
    by_day: dict = {}
    for prev, cur in _series_pairs(rows):  # each IP's counter diffed on its own
        day = cur["ts"][:10]
        if day < first_day:
            continue
        rx, tx = by_day.get(day, (0, 0))
        by_day[day] = (rx + _delta(prev["rx_bytes"], cur["rx_bytes"]),
                       tx + _delta(prev["tx_bytes"], cur["tx_bytes"]))
    out = []
    for i in range(days - 1, -1, -1):
        day = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        rx, tx = by_day.get(day, (0, 0))
        out.append({"day": day, "rx_bytes": rx, "tx_bytes": tx})
    return out


# --- user data: device labels + acknowledged/muted alerts ------------------
# These record only the user's LOCAL preferences. netwarden never changes the
# network itself; muting an alert just stops netwarden from nagging about it.

def set_label(db: sqlite3.Connection, mac: str, label: str, note: str = "") -> None:
    """Give a device a friendly name. Empty label clears it."""
    if not mac:
        return
    if not (label or "").strip():
        clear_label(db, mac)
        return
    with db:
        db.execute(
            """INSERT INTO device_labels (mac, label, note, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(mac) DO UPDATE SET
                   label = excluded.label, note = excluded.note,
                   updated_at = excluded.updated_at""",
            (mac, label.strip(), (note or "").strip(), now()),
        )


def clear_label(db: sqlite3.Connection, mac: str) -> None:
    with db:
        db.execute("DELETE FROM device_labels WHERE mac = ?", (mac,))


def get_labels(db: sqlite3.Connection) -> dict:
    """mac -> {'label':..., 'note':...} for every labeled device."""
    return {r["mac"]: {"label": r["label"], "note": r["note"]}
            for r in db.execute("SELECT mac, label, note FROM device_labels")}


PROFILE_FIELDS = ("type", "owner", "room")
MAX_PROFILE_TEXT = 64


def clean_text(value, limit: int = MAX_PROFILE_TEXT) -> str:
    """User free text -> one trimmed line without control characters, at most `limit`
    characters. (It stays hostile input: every renderer still escapes it.)"""
    text = "".join(ch if ch.isprintable() else " " for ch in str(value or ""))
    return " ".join(text.split())[:limit]


def set_profile(db: sqlite3.Connection, mac: str, **fields) -> None:
    """Set some of a device's type / owner / room. Only the given fields change; an
    empty value (or None) clears that field. A profile with nothing left is deleted.
    The type is NOT validated here (devicetype.TYPES is; see web /api/profile)."""
    if not mac:
        return
    unknown = set(fields) - set(PROFILE_FIELDS) - {"shared"}
    if unknown:
        raise ValueError(f"unknown profile field(s): {sorted(unknown)}")
    cur = get_profiles(db).get(mac, {**{f: None for f in PROFILE_FIELDS}, "shared": False})
    for f, v in fields.items():
        cur[f] = bool(v) if f == "shared" else (clean_text(v) or None)
    if fields.get("owner"):
        cur["shared"] = False       # a person's device is not the household's
    elif cur.get("shared"):
        cur["owner"] = None
    with db:
        if cur["owner"]:
            _ensure_person(db, cur["owner"])
        if not any(cur[f] for f in PROFILE_FIELDS) and not cur["shared"]:
            db.execute("DELETE FROM device_profiles WHERE mac = ?", (mac,))
            return
        db.execute(
            """INSERT INTO device_profiles (mac, type, owner, room, shared, updated_at)
               VALUES (:mac, :type, :owner, :room, :shared, :ts)
               ON CONFLICT(mac) DO UPDATE SET
                   type = excluded.type, owner = excluded.owner, room = excluded.room,
                   shared = excluded.shared, updated_at = excluded.updated_at""",
            {**cur, "shared": int(bool(cur["shared"])), "mac": mac, "ts": now()})


def get_profiles(db: sqlite3.Connection) -> dict:
    """mac -> {'type', 'owner', 'room', 'shared', 'updated_at'} for every device with a
    profile (owner = the person's name, people.name)."""
    return {r["mac"]: {"type": r["type"], "owner": r["owner"], "room": r["room"],
                       "shared": bool(r["shared"]), "updated_at": r["updated_at"]}
            for r in db.execute("SELECT * FROM device_profiles")}


# --- people (Stage P, people.py validates) ---------------------------------------------
# A person is a row in `people`; their devices are the device_profiles rows whose owner
# is their name. sync_people() turns any owner text without a row (older databases, a
# restored backup, the old /api/profile field) into a person, so there is one list.

PERSON_FIELDS = ("name", "avatar", "color", "child", "note", "presence", "presence_macs",
                 "notify_arrive", "notify_leave", "presence_since")


def _ensure_person(db: sqlite3.Connection, name: str) -> None:
    """Make sure `name` is a person (inside the caller's transaction)."""
    ts = now()
    db.execute("INSERT OR IGNORE INTO people (name, created_at, updated_at) VALUES (?, ?, ?)",
               (name, ts, ts))


def sync_people(db: sqlite3.Connection) -> int:
    """Create a person for every owner named by a device or a bedtime rule that has none
    yet (idempotent: existing people and their edits are never touched). Returns # new."""
    missing = [r[0] for r in db.execute(
        """SELECT DISTINCT o FROM (SELECT owner AS o FROM device_profiles
                                   UNION SELECT owner FROM bedtime_rules)
           WHERE o IS NOT NULL AND o != '' AND o NOT IN (SELECT name FROM people)
           ORDER BY o""")]
    if missing:
        with db:
            for name in missing:
                _ensure_person(db, name)
    return len(missing)


def _person(r) -> dict:
    import json
    try:
        macs = json.loads(r["presence_macs"]) if r["presence_macs"] else None
    except ValueError:
        macs = None
    return {"id": r["id"], "name": r["name"], "avatar": r["avatar"], "color": r["color"],
            "child": bool(r["child"]), "note": r["note"], "presence": bool(r["presence"]),
            "presence_macs": macs if isinstance(macs, list) else None,
            "notify_arrive": bool(r["notify_arrive"]), "notify_leave": bool(r["notify_leave"]),
            "presence_since": r["presence_since"], "created_at": r["created_at"],
            "updated_at": r["updated_at"]}


def people(db: sqlite3.Connection) -> list[dict]:
    """Every person, oldest first (ids are stable, so this order is too)."""
    return [_person(r) for r in db.execute("SELECT * FROM people ORDER BY id")]


def person(db: sqlite3.Connection, pid: int) -> dict | None:
    r = db.execute("SELECT * FROM people WHERE id = ?", (pid,)).fetchone()
    return _person(r) if r else None


def person_by_name(db: sqlite3.Connection, name: str) -> dict | None:
    r = db.execute("SELECT * FROM people WHERE name = ?", (name,)).fetchone()
    return _person(r) if r else None


def save_person(db: sqlite3.Connection, p: dict) -> int:
    """Insert (no / unknown id) or update a VALIDATED person; a rename carries the
    person's devices and bedtime rules along in the same transaction. Returns the id."""
    import json
    ts = now()
    vals = {f: p.get(f) for f in PERSON_FIELDS}
    vals.update(child=int(bool(p.get("child"))), presence=int(bool(p.get("presence"))),
                notify_arrive=int(bool(p.get("notify_arrive"))),
                notify_leave=int(bool(p.get("notify_leave"))),
                presence_macs=None if p.get("presence_macs") is None
                else json.dumps(list(p["presence_macs"])),
                avatar=p.get("avatar") or "", color=p.get("color") or "", note=p.get("note") or "",
                id=p.get("id"), ts=ts)
    with db:
        old = db.execute("SELECT name FROM people WHERE id = ?", (vals["id"],)).fetchone() \
            if vals["id"] is not None else None
        if old:
            db.execute("""UPDATE people SET name = :name, avatar = :avatar, color = :color,
                              child = :child, note = :note, presence = :presence,
                              presence_macs = :presence_macs, notify_arrive = :notify_arrive,
                              notify_leave = :notify_leave, presence_since = :presence_since,
                              updated_at = :ts WHERE id = :id""", vals)
            if old["name"] != vals["name"]:
                for table in ("device_profiles", "bedtime_rules"):
                    db.execute(f"UPDATE {table} SET owner = ? WHERE owner = ?",
                               (vals["name"], old["name"]))
            return vals["id"]
        cur = db.execute("""INSERT INTO people (id, name, avatar, color, child, note, presence,
                                presence_macs, notify_arrive, notify_leave, presence_since,
                                created_at, updated_at)
                            VALUES (:id, :name, :avatar, :color, :child, :note, :presence,
                                    :presence_macs, :notify_arrive, :notify_leave,
                                    :presence_since, :ts, :ts)""", vals)
        return cur.lastrowid


def delete_person(db: sqlite3.Connection, pid: int) -> dict | None:
    """Remove a person: their devices become unassigned and their bedtime rules go too
    (a rule for nobody would only confuse). Returns everything removed - the person, the
    MACs and the rules - so the page can offer Undo (restore_person), or None."""
    p = person(db, pid)
    if p is None:
        return None
    macs = [r["mac"] for r in db.execute(
        "SELECT mac FROM device_profiles WHERE owner = ? ORDER BY mac", (p["name"],))]
    rules = [r for r in bedtime_rules(db) if r["owner"] == p["name"]]
    with db:
        db.execute("UPDATE device_profiles SET owner = NULL, updated_at = ? WHERE owner = ?",
                   (now(), p["name"]))
        db.execute("""DELETE FROM device_profiles WHERE owner IS NULL AND type IS NULL
                      AND room IS NULL AND shared = 0""")
        db.execute("DELETE FROM bedtime_rules WHERE owner = ?", (p["name"],))
        db.execute("DELETE FROM people WHERE id = ?", (pid,))
    return {"person": p, "macs": macs, "rules": rules}


def restore_person(db: sqlite3.Connection, gone: dict) -> int:
    """Undo delete_person(): the same id, devices and rules (a device that has another
    owner by now keeps that one)."""
    p = dict(gone["person"])
    if person(db, p["id"]) is not None or person_by_name(db, p["name"]) is not None:
        raise ValueError("person_exists")
    pid = save_person(db, p)
    for mac in gone.get("macs") or []:
        cur = get_profiles(db).get(mac) or {}
        if not cur.get("owner"):
            set_profile(db, mac, owner=p["name"])
    for r in gone.get("rules") or []:
        save_bedtime_rule(db, r)
    return pid


def assign(db: sqlite3.Connection, mac: str, owner: str | None, shared: bool = False) -> None:
    """Give a device to a person (by name), to the household (shared) or to nobody."""
    set_profile(db, mac, owner=owner or "", shared=bool(shared and not owner))


def insert_presence_samples(db: sqlite3.Connection, rows: list) -> int:
    """[(mac, ts, source)] -> stored. Returns # rows."""
    if rows:
        with db:
            db.executemany("INSERT INTO presence_samples (mac, ts, source) VALUES (?, ?, ?)", rows)
    return len(rows)


def profile_values(db: sqlite3.Connection, field: str) -> list[dict]:
    """Distinct owners or rooms with their devices: [{name, devices, macs}], most
    devices first. Only for devices still in the inventory."""
    if field not in ("owner", "room"):
        raise ValueError(field)
    groups: dict = {}
    for r in db.execute(f"""SELECT p.mac, p.{field} AS v FROM device_profiles p
                            JOIN devices d ON d.mac = p.mac
                            WHERE p.{field} IS NOT NULL AND p.{field} != ''
                            ORDER BY p.mac"""):
        groups.setdefault(r["v"], []).append(r["mac"])
    return sorted(({"name": k, "devices": len(v), "macs": v} for k, v in groups.items()),
                  key=lambda g: (-g["devices"], g["name"]))


def label_history(db: sqlite3.Connection, mac: str) -> dict | None:
    """The device's label row with its timestamp (for the timeline), or None."""
    r = db.execute("SELECT label, updated_at FROM device_labels WHERE mac = ?", (mac,)).fetchone()
    return dict(r) if r else None


def acks_for(db: sqlite3.Connection, mac: str) -> list[dict]:
    """The device's acknowledgements with timestamps, oldest first: [{domain, created_at}]."""
    return [dict(r) for r in db.execute(
        "SELECT domain, created_at FROM acks WHERE mac = ? ORDER BY created_at", (mac,))]


def add_ack(db: sqlite3.Connection, mac: str, domain: str = "", until: str | None = None) -> None:
    """Acknowledge/mute an alert. domain='' trusts the whole device. `until` (UTC ISO)
    snoozes it instead: the ack stops counting after that time. Acking again for good
    turns a snooze into a permanent ack; a snooze never shortens a permanent one."""
    if not mac:
        return
    with db:
        db.execute(
            """INSERT INTO acks (mac, domain, created_at, until) VALUES (?, ?, ?, ?)
               ON CONFLICT(mac, domain) DO UPDATE SET
                   until = CASE WHEN acks.until IS NULL AND excluded.until IS NOT NULL
                                THEN NULL ELSE excluded.until END,
                   created_at = CASE WHEN acks.until IS NULL THEN acks.created_at
                                     ELSE excluded.created_at END""",
            (mac, domain or "", now(), until),
        )


def remove_ack(db: sqlite3.Connection, mac: str, domain: str = "") -> None:
    with db:
        db.execute("DELETE FROM acks WHERE mac = ? AND domain = ?", (mac, domain or ""))


def list_acks(db: sqlite3.Connection) -> set:
    """Set of (mac, domain) acknowledgements in force now; domain='' = whole device
    trusted. A snooze that ran out no longer counts."""
    return {(r["mac"], r["domain"])
            for r in db.execute("SELECT mac, domain FROM acks WHERE until IS NULL OR until > ?",
                                (now(),))}


def all_acks(db: sqlite3.Connection) -> list[dict]:
    """Every ack row, expired snoozes included: [{mac, domain, created_at, until}]."""
    return [dict(r) for r in db.execute(
        "SELECT mac, domain, created_at, until FROM acks ORDER BY mac, domain")]


def is_muted(acks: set, mac: str, domain: str = "") -> bool:
    """True if this device is trusted wholesale, or this exact (mac, domain) is muted."""
    return (mac, "") in acks or (mac, domain or "") in acks


# --- bedtime rules (Stage F, bedtime.py validates; notify only) --------------

RULE_FIELDS = ("name", "owner", "mac", "days", "start", "end", "min_minutes", "enabled")


def _rule(r) -> dict:
    return {"id": r["id"], "name": r["name"], "owner": r["owner"], "mac": r["mac"],
            "days": [int(x) for x in r["days"].split(",") if x != ""],
            "start": r["win_start"], "end": r["win_end"], "min_minutes": r["min_minutes"],
            "enabled": bool(r["enabled"]), "created_at": r["created_at"],
            "updated_at": r["updated_at"]}


def bedtime_rules(db: sqlite3.Connection) -> list[dict]:
    """Every rule, oldest first: [{id, name, owner, mac, days: [int], start, end,
    min_minutes, enabled, created_at, updated_at}]."""
    return [_rule(r) for r in db.execute("SELECT * FROM bedtime_rules ORDER BY id")]


def save_bedtime_rule(db: sqlite3.Connection, rule: dict) -> int:
    """Insert (no / unknown id) or update (existing id) a VALIDATED rule; returns its id."""
    ts = now()
    vals = {f: rule.get(f) for f in RULE_FIELDS}
    vals.update(days=",".join(str(d) for d in sorted(set(rule["days"]))),
                enabled=int(bool(rule.get("enabled", True))), name=rule.get("name") or "",
                ts=ts, id=rule.get("id"))
    with db:
        if vals["id"] is not None and db.execute("SELECT 1 FROM bedtime_rules WHERE id = ?",
                                                 (vals["id"],)).fetchone():
            db.execute("""UPDATE bedtime_rules SET name = :name, owner = :owner, mac = :mac,
                              days = :days, win_start = :start, win_end = :end,
                              min_minutes = :min_minutes, enabled = :enabled, updated_at = :ts
                          WHERE id = :id""", vals)
            return vals["id"]
        cur = db.execute("""INSERT INTO bedtime_rules (id, name, owner, mac, days, win_start, win_end,
                                min_minutes, enabled, created_at, updated_at)
                            VALUES (:id, :name, :owner, :mac, :days, :start, :end,
                                    :min_minutes, :enabled, :ts, :ts)""", vals)
        return cur.lastrowid


def delete_bedtime_rule(db: sqlite3.Connection, rule_id: int) -> dict | None:
    """Remove a rule; returns what it was (so the page can offer Undo), or None."""
    row = db.execute("SELECT * FROM bedtime_rules WHERE id = ?", (rule_id,)).fetchone()
    if not row:
        return None
    with db:
        db.execute("DELETE FROM bedtime_rules WHERE id = ?", (rule_id,))
    return _rule(row)


# --- exposure checks (opt-in, user-triggered; see exposure.py) --------------

def insert_port_checks(db: sqlite3.Connection, rows: list[dict]) -> int:
    """Store one check's results: dicts {mac, ip, port, open, ts}. Returns # rows."""
    with db:
        db.executemany(
            "INSERT INTO port_checks (mac, ip, port, open, ts) VALUES (:mac, :ip, :port, :open, :ts)",
            [{**r, "open": int(bool(r["open"]))} for r in rows])
    return len(rows)


def port_check_history(db: sqlite3.Connection, mac: str, limit: int = 2) -> list[dict]:
    """The newest `limit` checks of one device, newest first:
    [{ts, ip, ports: {port: open_bool}}]."""
    stamps = [r["ts"] for r in db.execute(
        "SELECT DISTINCT ts FROM port_checks WHERE mac = ? ORDER BY ts DESC LIMIT ?",
        (mac, limit))]
    out = []
    for ts in stamps:
        rows = db.execute("SELECT ip, port, open FROM port_checks WHERE mac = ? AND ts = ? "
                          "ORDER BY port", (mac, ts)).fetchall()
        out.append({"ts": ts, "ip": rows[0]["ip"] if rows else "",
                    "ports": {r["port"]: bool(r["open"]) for r in rows}})
    return out


def checked_macs(db: sqlite3.Connection) -> list[str]:
    """Every device that has at least one exposure check."""
    return [r["mac"] for r in db.execute("SELECT DISTINCT mac FROM port_checks ORDER BY mac")]


# --- health: per-source run status -----------------------------------------

def record_source_ok(db: sqlite3.Connection, source: str, count: int, ts: str | None = None) -> None:
    """A source run succeeded and brought in `count` items. Keeps the last error for
    reference (its ts tells whether it is older than this success)."""
    with db:
        db.execute(
            """INSERT INTO source_status (source, last_ok_ts, last_count) VALUES (?, ?, ?)
               ON CONFLICT(source) DO UPDATE SET
                   last_ok_ts = excluded.last_ok_ts, last_count = excluded.last_count""",
            (source, ts or now(), int(count)))


def record_source_error(db: sqlite3.Connection, source: str, error: str, ts: str | None = None) -> None:
    """A source run failed. `error` must already be sanitized (see health.sanitize_error)."""
    with db:
        db.execute(
            """INSERT INTO source_status (source, last_error_ts, last_error) VALUES (?, ?, ?)
               ON CONFLICT(source) DO UPDATE SET
                   last_error_ts = excluded.last_error_ts, last_error = excluded.last_error""",
            (source, ts or now(), error))


def source_status(db: sqlite3.Connection) -> dict:
    """source -> {last_ok_ts, last_error_ts, last_error, last_count}."""
    return {r["source"]: {k: r[k] for k in ("last_ok_ts", "last_error_ts", "last_error",
                                             "last_count")}
            for r in db.execute("SELECT * FROM source_status")}


# --- meta: facts about this DB ----------------------------------------------

def set_meta(db: sqlite3.Connection, key: str, value: str) -> None:
    with db:
        db.execute("""INSERT INTO meta (key, value) VALUES (?, ?)
                      ON CONFLICT(key) DO UPDATE SET value = excluded.value""", (key, str(value)))


def get_meta(db: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def is_demo(db: sqlite3.Connection) -> bool:
    """True for the synthetic demo home (scripts/demo_seed.py / `netwarden demo`). Its
    IPs may belong to REAL devices on the user's LAN, so live actions must stay off."""
    return get_meta(db, "demo") == "1"


# --- settings the user changed in the dashboard (netwarden/settings.py) -------

USAGE_KEEP_DAYS = 400   # ai_usage rows: a year of monthly totals, whatever the retention
USAGE_FIELDS = ("requests", "input_tokens", "output_tokens", "cache_write_tokens",
                "cache_read_tokens")


def add_ai_usage(db: sqlite3.Connection, row: dict) -> None:
    """One finished AI answer (usage.record builds the row)."""
    with db:
        db.execute("""INSERT INTO ai_usage (ts, provider, model, destination, mode, requests,
                      input_tokens, output_tokens, cache_write_tokens, cache_read_tokens,
                      estimated, cost_usd) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (row.get("ts") or now(), row["provider"], row["model"], row["destination"],
                    row["mode"], *(int(row.get(k) or 0) for k in USAGE_FIELDS),
                    1 if row.get("estimated") else 0, row.get("cost_usd")))


def ai_usage_since(db: sqlite3.Connection, since: str) -> list:
    """Totals per (provider, model, destination) of the answers since `since` (UTC ISO):
    rows {provider, model, destination, answers, estimated, priced, cost_usd, <fields>}."""
    sums = ", ".join(f"SUM({k}) AS {k}" for k in USAGE_FIELDS)
    return [dict(r) for r in db.execute(
        f"""SELECT provider, model, destination, COUNT(*) AS answers, {sums},
                   SUM(estimated) AS estimated, COUNT(cost_usd) AS priced,
                   COALESCE(SUM(cost_usd), 0) AS cost_usd
            FROM ai_usage WHERE ts >= ? GROUP BY provider, model, destination
            ORDER BY cost_usd DESC, answers DESC""", (since,))]


def get_settings(db: sqlite3.Connection) -> dict:
    """key -> raw JSON text of every stored setting (settings.py decodes + validates)."""
    return {r["key"]: r["value"] for r in db.execute("SELECT key, value FROM settings")}


def put_settings(db: sqlite3.Connection, changes: dict) -> None:
    """Store {key: json_text}; a None value removes the key (back to its default).
    All changes land in one transaction."""
    ts = now()
    with db:
        for key, value in changes.items():
            if value is None:
                db.execute("DELETE FROM settings WHERE key = ?", (key,))
            else:
                db.execute("""INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
                              ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                                             updated_at = excluded.updated_at""",
                           (key, value, ts))


# --- network health (Stage H, nethealth.py) ------------------------------------------

def insert_health_sample(db: sqlite3.Connection, target: str, ok: bool,
                         latency_ms: float | None = None, loss: float | None = None,
                         method: str | None = None, ts: str | None = None) -> None:
    with db:
        db.execute("""INSERT INTO health_samples (ts, target, ok, latency_ms, loss, method)
                      VALUES (?, ?, ?, ?, ?, ?)""",
                   (ts or now(), target, int(bool(ok)),
                    None if latency_ms is None else round(float(latency_ms), 2),
                    None if loss is None else round(float(loss), 3), method))


def health_samples(db: sqlite3.Connection, target: str, since: str,
                   until: str = "9999") -> list[dict]:
    """One target's probes in [since, until), oldest first: [{ts, ok, latency_ms, loss}]."""
    return [dict(r) for r in db.execute(
        """SELECT ts, ok, latency_ms, loss, method FROM health_samples
           WHERE target = ? AND ts >= ? AND ts < ? ORDER BY ts""", (target, since, until))]


def outages(db: sqlite3.Connection, since: str = "0000") -> list[dict]:
    """Outages that ended at/after `since` (or are still going on), newest first."""
    return [dict(r) for r in db.execute(
        "SELECT * FROM outages WHERE end_ts >= ? OR ongoing = 1 ORDER BY start_ts DESC",
        (since,))]


# --- suggestion status + score history (Stage H; user data / derived) ----------------

SUGGESTION_STATUSES = ("done", "dismissed", "snoozed")


def suggestion_states(db: sqlite3.Connection) -> dict:
    """id -> {status, until, data (decoded JSON or None), updated_at}."""
    import json
    out = {}
    for r in db.execute("SELECT * FROM suggestion_state"):
        try:
            data = json.loads(r["data"]) if r["data"] else None
        except ValueError:
            data = None
        out[r["id"]] = {"status": r["status"], "until": r["until"], "data": data,
                        "updated_at": r["updated_at"]}
    return out


def set_suggestion_state(db: sqlite3.Connection, sid: str, status: str | None,
                         until: str | None = None, data: dict | None = None) -> None:
    """Record the user's decision; status None / "open" forgets it (back to open)."""
    import json
    with db:
        if not status or status == "open":
            db.execute("DELETE FROM suggestion_state WHERE id = ?", (sid,))
            return
        if status not in SUGGESTION_STATUSES:
            raise ValueError(status)
        db.execute("""INSERT INTO suggestion_state (id, status, until, data, updated_at)
                      VALUES (?, ?, ?, ?, ?)
                      ON CONFLICT(id) DO UPDATE SET status = excluded.status,
                          until = excluded.until,
                          data = COALESCE(excluded.data, suggestion_state.data),
                          updated_at = excluded.updated_at""",
                   (sid, status, until if status == "snoozed" else None,
                    json.dumps(data, ensure_ascii=False) if data is not None else None, now()))


def put_score(db: sqlite3.Connection, day: str, score: int, parts: dict,
              ts: str | None = None) -> None:
    import json
    with db:
        db.execute("""INSERT INTO score_history (day, score, parts, ts) VALUES (?, ?, ?, ?)
                      ON CONFLICT(day) DO UPDATE SET score = excluded.score,
                          parts = excluded.parts, ts = excluded.ts""",
                   (day, int(score), json.dumps(parts, sort_keys=True), ts or now()))


def score_history(db: sqlite3.Connection, since_day: str = "0000") -> list[dict]:
    """[{day, score, parts, ts}] oldest first."""
    import json
    return [{"day": r["day"], "score": r["score"], "parts": json.loads(r["parts"]), "ts": r["ts"]}
            for r in db.execute("SELECT * FROM score_history WHERE day >= ? ORDER BY day",
                                (since_day,))]


# --- retention + DB stats ----------------------------------------------------

def retention_days(value=None) -> int:
    """NETWARDEN_RETENTION_DAYS (or a --days value) -> days to keep, never below
    MIN_RETENTION_DAYS. Empty / invalid -> DEFAULT_RETENTION_DAYS."""
    try:
        days = int(str(value).strip()) if value not in (None, "") else DEFAULT_RETENTION_DAYS
    except ValueError:
        days = DEFAULT_RETENTION_DAYS
    return max(MIN_RETENTION_DAYS, days)


def checkpoint(db: sqlite3.Connection) -> bool:
    """Copy the WAL into the database and truncate it (Stage K). Waits up to the busy
    timeout for readers; True = done, False = busy now (try again later). Best effort."""
    try:
        return db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
    except sqlite3.OperationalError:
        return False


def prune(db: sqlite3.Connection, days: int, vacuum: bool = False) -> dict:
    """Delete DNS events, traffic samples, identity evidence and UPnP history older than
    `days` (clamped to the minimum). Devices, labels and acks are the user's
    inventory/notes and are kept, and so is the newest UPnP snapshot (the current state
    of the router). Returns {days, cutoff, dns_events, traffic_samples, identity, upnp,
    vacuumed}."""
    days = retention_days(days)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    with db:
        dns = db.execute("DELETE FROM dns_events WHERE ts < ?", (cutoff,)).rowcount
        traffic = db.execute("DELETE FROM traffic_samples WHERE ts < ?", (cutoff,)).rowcount
        ident = db.execute("DELETE FROM device_identity WHERE last_seen < ?", (cutoff,)).rowcount
        upnp = db.execute("""DELETE FROM upnp_snapshots WHERE ts < ?
                             AND ts != (SELECT MAX(ts) FROM upnp_snapshots)""",
                          (cutoff,)).rowcount
        upnp += db.execute("""DELETE FROM upnp_mappings WHERE last_seen < ? AND last_seen <
                              COALESCE((SELECT MAX(ts) FROM upnp_snapshots WHERE available = 1),
                                       '')""", (cutoff,)).rowcount
        health = db.execute("DELETE FROM health_samples WHERE ts < ?", (cutoff,)).rowcount
        health += db.execute("DELETE FROM outages WHERE end_ts < ? AND ongoing = 0",
                             (cutoff,)).rowcount
        health += db.execute("DELETE FROM score_history WHERE ts < ?", (cutoff,)).rowcount
        # Stage P: presence history follows the same retention as everything collected
        presence = db.execute("DELETE FROM presence_samples WHERE ts < ?", (cutoff,)).rowcount
        # Stage Q: the notification ledger (a pending hold is kept until it is released)
        db.execute("DELETE FROM notify_log WHERE ts < ? AND state != 'held'", (cutoff,))
        db.execute("DELETE FROM quiet_summaries WHERE end_ts < ?", (cutoff,))
        # Round 10 N: the push ledger (finished rows; the delivery log keeps its own cap)
        db.execute("DELETE FROM push_outbox WHERE created_at < ? AND state NOT IN ('queued', 'held')",
                   (cutoff,))
        db.execute("DELETE FROM push_log WHERE ts < ?", (cutoff,))
        # Round 7 C: AI usage keeps its own, longer window (this month's totals + budget)
        keep = (datetime.now(timezone.utc) - timedelta(days=USAGE_KEEP_DAYS)) \
            .strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        db.execute("DELETE FROM ai_usage WHERE ts < ?", (min(cutoff, keep),))
        # Stage M: expired phone sessions and spent / expired pairing codes
        stamp = now()
        db.execute("DELETE FROM sessions WHERE expires_at <= ?", (stamp,))
        db.execute("DELETE FROM pair_codes WHERE expires_at <= ? OR used_at IS NOT NULL", (stamp,))
    if vacuum:
        db.execute("VACUUM")
    return {"days": days, "cutoff": cutoff, "dns_events": dns, "traffic_samples": traffic,
            "identity": ident, "upnp": upnp, "health": health, "presence": presence,
            "vacuumed": bool(vacuum)}


def db_stats(db: sqlite3.Connection, path: str | Path | None = None) -> dict:
    """Size + row counts + the time span the history covers."""
    size = 0
    if path and str(path) != ":memory:":
        for suffix in ("", "-wal"):
            p = Path(str(path) + suffix)
            if p.exists():
                size += p.stat().st_size
    one = lambda sql: db.execute(sql).fetchone()[0]  # noqa: E731
    lo = [v for v in (one("SELECT MIN(ts) FROM dns_events"),
                      one("SELECT MIN(ts) FROM traffic_samples")) if v]
    hi = [v for v in (one("SELECT MAX(ts) FROM dns_events"),
                      one("SELECT MAX(ts) FROM traffic_samples")) if v]
    return {
        "size_bytes": size,
        "devices": one("SELECT COUNT(*) FROM devices"),
        "dns_events": one("SELECT COUNT(*) FROM dns_events"),
        "traffic_samples": one("SELECT COUNT(*) FROM traffic_samples"),
        "oldest_ts": min(lo) if lo else None,
        "newest_ts": max(hi) if hi else None,
    }
