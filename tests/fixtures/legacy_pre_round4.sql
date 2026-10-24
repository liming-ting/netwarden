BEGIN TRANSACTION;
CREATE TABLE acks (
    mac         TEXT NOT NULL,
    domain      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    until       TEXT,
    PRIMARY KEY (mac, domain)
);
INSERT INTO "acks" VALUES('aa:bb:cc:00:00:01','','2026-10-20T12:00:00.000000Z',NULL);
INSERT INTO "acks" VALUES('aa:bb:cc:00:00:02','doubleclick.net','2026-10-20T12:00:00.000000Z',NULL);
INSERT INTO "acks" VALUES('network','outage:7','2026-10-20T12:00:00.000000Z',NULL);
INSERT INTO "acks" VALUES('aa:bb:cc:00:00:02','bedtime:5:2026-10-19','2026-10-20T12:00:00.000000Z',NULL);
CREATE TABLE bedtime_rules (
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
INSERT INTO "bedtime_rules" VALUES(1,'School nights','小孩',NULL,'6,0,1,2,3','22:00','07:00',10,1,'2026-10-20T12:00:00.000000Z','2026-10-20T12:00:00.000000Z');
CREATE TABLE device_identity (
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
CREATE TABLE device_labels (
    mac         TEXT PRIMARY KEY,
    label       TEXT NOT NULL,      -- friendly name, e.g. "客廳攝影機"
    note        TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL
);
INSERT INTO "device_labels" VALUES('aa:bb:cc:00:00:01','客廳電視','<b>note</b>','2026-10-20T12:00:00.000000Z');
CREATE TABLE device_profiles (
    mac         TEXT PRIMARY KEY,
    type        TEXT,               -- a devicetype.TYPES key the user picked
    owner       TEXT,               -- e.g. "媽媽"
    room        TEXT,               -- e.g. "客廳"
    updated_at  TEXT NOT NULL
);
INSERT INTO "device_profiles" VALUES('aa:bb:cc:00:00:01','tv','媽媽','客廳','2026-10-20T12:00:00.000000Z');
INSERT INTO "device_profiles" VALUES('aa:bb:cc:00:00:02','phone','小孩',NULL,'2026-10-20T12:00:00.000000Z');
CREATE TABLE devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,               -- last IP we saw it on (NULL once another device takes it)
    vendor      TEXT,
    hostname    TEXT,
    randomized  INTEGER NOT NULL DEFAULT 0,
    is_self     INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
INSERT INTO "devices" VALUES('aa:bb:cc:00:00:01','192.168.1.20','Samsung','tv',0,0,'2026-10-20T10:00:00.000000Z','2026-10-20T12:00:00.000000Z');
INSERT INTO "devices" VALUES('aa:bb:cc:00:00:02','192.168.1.21','randomized MAC (phone/privacy)',NULL,1,0,'2026-10-20T10:00:00.000000Z','2026-10-20T12:00:00.000000Z');
INSERT INTO "devices" VALUES('aa:bb:cc:00:00:03','192.168.1.13','','me',0,1,'2026-10-20T10:00:00.000000Z','2026-10-20T12:00:00.000000Z');
CREATE TABLE dns_events (
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
INSERT INTO "dns_events" VALUES(1,'adguard','2026-10-20T11:00:00.000000Z','192.168.1.20','tv','aa:bb:cc:00:00:01','youtube.com','A','NOERROR','NotFilteredNotFound',0,0,'1.1.1.1:53',1.5,NULL);
INSERT INTO "dns_events" VALUES(2,'adguard','2026-10-20T11:00:00.000000Z','192.168.1.20','tv','aa:bb:cc:00:00:01','doubleclick.net','A','NOERROR','FilteredBlackList',1,0,'1.1.1.1:53',1.5,'blocklist');
INSERT INTO "dns_events" VALUES(3,'adguard','2026-10-20T12:00:00.000000Z','192.168.1.20','tv','aa:bb:cc:00:00:01','weird.example','A','NOERROR','SomethingNew',1,0,'1.1.1.1:53',1.5,'other');
INSERT INTO "dns_events" VALUES(4,'adguard','2026-10-20T12:00:00.000000Z','192.168.1.20','tv','aa:bb:cc:00:00:01','netflix.com','A','NOERROR','NotFilteredNotFound',0,0,'1.1.1.1:53',1.5,NULL);
CREATE TABLE health_samples (
    ts          TEXT NOT NULL,      -- UTC ISO 8601, same format as dns_events.ts
    target      TEXT NOT NULL,      -- 'gateway' | 'internet'
    ok          INTEGER NOT NULL,   -- 1 = it answered
    latency_ms  REAL,               -- average round trip (ICMP) or connect time (TCP)
    loss        REAL,               -- share of ICMP echoes lost, 0..1 (TCP: 0 or 1)
    method      TEXT                -- 'icmp' | 'tcp'
);
CREATE TABLE ingest_state (
    source      TEXT PRIMARY KEY,
    last_ts     TEXT NOT NULL       -- newest event ts ingested from this source
);
INSERT INTO "ingest_state" VALUES('adguard','2026-10-20T12:00:00.000000Z');
CREATE TABLE meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);
INSERT INTO "meta" VALUES('legacy_fixture','1');
CREATE TABLE outages (
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
INSERT INTO "outages" VALUES(3,'2026-10-20T10:00:00.000000Z','2026-10-20T11:00:00.000000Z','router',0,60,0,0,'2026-10-20T11:00:00.000000Z');
CREATE TABLE pair_codes (
    id          INTEGER PRIMARY KEY,
    code_hash   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT
);
CREATE TABLE port_checks (
    mac         TEXT NOT NULL,
    ip          TEXT NOT NULL,      -- the address we connected to
    port        INTEGER NOT NULL,
    open        INTEGER NOT NULL,   -- 1 = the TCP connect succeeded
    ts          TEXT NOT NULL       -- UTC ISO 8601, same format as dns_events.ts
);
CREATE TABLE score_history (
    day         TEXT PRIMARY KEY,   -- local date "2026-10-22"
    score       INTEGER NOT NULL,
    parts       TEXT NOT NULL,      -- JSON {pillar: points}
    ts          TEXT NOT NULL
);
CREATE TABLE sessions (
    id          INTEGER PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    label       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);
CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
INSERT INTO "settings" VALUES('alerts.snooze_days','5','2026-10-20T12:00:00.000000Z');
CREATE TABLE source_status (
    source        TEXT PRIMARY KEY,
    last_ok_ts    TEXT,             -- UTC ISO, last successful run
    last_error_ts TEXT,             -- UTC ISO, last failed run
    last_error    TEXT,             -- sanitized message of that failure
    last_count    INTEGER           -- what the last good run brought in (events / hosts / devices)
);
INSERT INTO "source_status" VALUES('adguard','2026-10-20T12:00:00.000000Z',NULL,NULL,4);
CREATE TABLE suggestion_state (
    id          TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    until       TEXT,               -- snoozed until (UTC ISO)
    data        TEXT,
    updated_at  TEXT NOT NULL
);
INSERT INTO "suggestion_state" VALUES('trackers:all','dismissed',NULL,'{}','2026-10-20T12:00:00.000000Z');
CREATE TABLE traffic_samples (
    mac         TEXT,               -- NULL if we couldn't tie the IP to a device yet
    ip          TEXT NOT NULL,
    ts          TEXT NOT NULL,      -- UTC ISO 8601, same format as dns_events.ts
    rx_bytes    INTEGER NOT NULL,
    tx_bytes    INTEGER NOT NULL
);
INSERT INTO "traffic_samples" VALUES('aa:bb:cc:00:00:01','192.168.1.20','2026-10-20T10:00:00.000000Z',10000,1000);
INSERT INTO "traffic_samples" VALUES('aa:bb:cc:00:00:01','192.168.1.20','2026-10-20T11:00:00.000000Z',11000,1100);
INSERT INTO "traffic_samples" VALUES('aa:bb:cc:00:00:01','192.168.1.20','2026-10-20T12:00:00.000000Z',12000,1200);
CREATE TABLE upnp_mappings (
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
CREATE TABLE upnp_snapshots (
    ts           TEXT PRIMARY KEY,
    available    INTEGER NOT NULL,  -- 1 = an Internet gateway answered UPnP
    gateway_ip   TEXT,
    gateway_name TEXT,
    external_ip  TEXT,              -- the home's public address (shown masked by default)
    status       TEXT,              -- GetStatusInfo: Connected / Disconnected / ...
    mappings     INTEGER NOT NULL DEFAULT 0,
    error        TEXT               -- sanitized, when the gateway answered badly
);
CREATE INDEX devices_ip ON devices(ip);
CREATE INDEX dns_events_device_ts ON dns_events(device_mac, ts);
CREATE INDEX dns_events_client_ts ON dns_events(client_ip, ts);
CREATE INDEX dns_events_domain ON dns_events(domain);
CREATE INDEX traffic_samples_mac_ts ON traffic_samples(mac, ts);
CREATE INDEX traffic_samples_ts ON traffic_samples(ts);
CREATE INDEX dns_events_ts ON dns_events(ts);
CREATE INDEX port_checks_mac_ts ON port_checks(mac, ts);
CREATE INDEX health_samples_target_ts ON health_samples(target, ts);
CREATE INDEX outages_end ON outages(end_ts);
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('bedtime_rules',1);
INSERT INTO "sqlite_sequence" VALUES('outages',3);
COMMIT;
