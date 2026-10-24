BEGIN TRANSACTION;
CREATE TABLE acks (
    mac         TEXT NOT NULL,
    domain      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    PRIMARY KEY (mac, domain)
);
INSERT INTO "acks" VALUES('aa:bb:cc:00:00:01','','2026-10-20T12:00:00.000000Z');
INSERT INTO "acks" VALUES('aa:bb:cc:00:00:02','doubleclick.net','2026-10-20T12:00:00.000000Z');
INSERT INTO "acks" VALUES('network','outage:7','2026-10-20T12:00:00.000000Z');
INSERT INTO "acks" VALUES('aa:bb:cc:00:00:02','bedtime:5:2026-10-19','2026-10-20T12:00:00.000000Z');
CREATE TABLE device_labels (
    mac         TEXT PRIMARY KEY,
    label       TEXT NOT NULL,      -- friendly name, e.g. "客廳攝影機"
    note        TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL
);
INSERT INTO "device_labels" VALUES('aa:bb:cc:00:00:01','客廳電視','<b>note</b>','2026-10-20T12:00:00.000000Z');
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
    reason      TEXT,               -- server's filtering verdict, e.g. NotFilteredNotFound
    blocked     INTEGER NOT NULL DEFAULT 0,
    cached      INTEGER NOT NULL DEFAULT 0,
    upstream    TEXT,
    elapsed_ms  REAL,
    UNIQUE (source, ts, client_ip, domain, qtype)
);
INSERT INTO "dns_events" VALUES(1,'adguard','2026-10-20T11:00:00.000000Z','192.168.1.20','tv','aa:bb:cc:00:00:01','youtube.com','A','NOERROR','NotFilteredNotFound',0,0,'1.1.1.1:53',1.5);
INSERT INTO "dns_events" VALUES(2,'adguard','2026-10-20T11:00:00.000000Z','192.168.1.20','tv','aa:bb:cc:00:00:01','doubleclick.net','A','NOERROR','FilteredBlackList',1,0,'1.1.1.1:53',1.5);
INSERT INTO "dns_events" VALUES(3,'adguard','2026-10-20T12:00:00.000000Z','192.168.1.20','tv','aa:bb:cc:00:00:01','weird.example','A','NOERROR','SomethingNew',1,0,'1.1.1.1:53',1.5);
INSERT INTO "dns_events" VALUES(4,'adguard','2026-10-20T12:00:00.000000Z','192.168.1.20','tv','aa:bb:cc:00:00:01','netflix.com','A','NOERROR','NotFilteredNotFound',0,0,'1.1.1.1:53',1.5);
CREATE TABLE ingest_state (
    source      TEXT PRIMARY KEY,
    last_ts     TEXT NOT NULL       -- newest event ts ingested from this source
);
INSERT INTO "ingest_state" VALUES('adguard','2026-10-20T12:00:00.000000Z');
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
CREATE INDEX devices_ip ON devices(ip);
CREATE INDEX dns_events_device_ts ON dns_events(device_mac, ts);
CREATE INDEX dns_events_client_ts ON dns_events(client_ip, ts);
CREATE INDEX dns_events_domain ON dns_events(domain);
CREATE INDEX traffic_samples_mac_ts ON traffic_samples(mac, ts);
COMMIT;
