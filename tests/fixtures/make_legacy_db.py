#!/usr/bin/env python3
"""
Stage K: build a small "user database" with an OLDER netwarden and dump it as SQL - the
fixtures tests/fixtures/legacy_<era>.sql that test_stage_k_db.py migrates with today's
code. Run it with the old tree first on the path (extract a backup under /tmp, never
over the repo):

    mkdir -p /tmp/nwk/pre-round3 && tar -xzf ~/netwarden_backup_..._pre-round3.tgz -C /tmp/nwk/pre-round3
    PYTHONPATH=/tmp/nwk/pre-round3/netwarden python3 tests/fixtures/make_legacy_db.py \\
        /tmp/legacy.db tests/fixtures/legacy_pre_round3.sql

The old store.connect() creates its schema; rows are then written with plain SQL into
whatever tables / columns that version has (version-agnostic), covering every
migration today's store._migrate() performs: legacy vendor placeholders, blocked events
without block_reason, owners without a people table, acks without `until`, bedtime
rules / outages without AUTOINCREMENT whose ids acks still mention.
"""
import sqlite3
import sys
from pathlib import Path

from netwarden import store   # the OLD one (PYTHONPATH)

TS = "2026-10-20T{}:00:00.000000Z"
ROWS = {
    "devices": [
        dict(mac="aa:bb:cc:00:00:01", ip="192.168.1.20", vendor="Samsung", hostname="tv",
             randomized=0, is_self=0, first_seen=TS.format(10), last_seen=TS.format(12)),
        dict(mac="aa:bb:cc:00:00:02", ip="192.168.1.21", vendor="randomized MAC (phone/privacy)",
             hostname=None, randomized=1, is_self=0, first_seen=TS.format(10), last_seen=TS.format(12)),
        dict(mac="aa:bb:cc:00:00:03", ip="192.168.1.13", vendor="", hostname="me",
             randomized=0, is_self=1, first_seen=TS.format(10), last_seen=TS.format(12)),
    ],
    "dns_events": [
        dict(source="adguard", ts=TS.format(h), client_ip="192.168.1.20", client_name="tv",
             device_mac="aa:bb:cc:00:00:01", domain=d, qtype="A", status="NOERROR",
             reason=r, blocked=b, cached=0, upstream="1.1.1.1:53", elapsed_ms=1.5,
             block_reason=why)   # what that era's ingest stored (dropped where no column yet)
        for h, d, r, b, why in ((11, "youtube.com", "NotFilteredNotFound", 0, None),
                                (11, "doubleclick.net", "FilteredBlackList", 1, "blocklist"),
                                (12, "weird.example", "SomethingNew", 1, "other"),
                                (12, "netflix.com", "NotFilteredNotFound", 0, None))
    ],
    "ingest_state": [dict(source="adguard", last_ts=TS.format(12))],
    "device_labels": [dict(mac="aa:bb:cc:00:00:01", label="客廳電視", note="<b>note</b>",
                           updated_at=TS.format(12))],
    "device_profiles": [dict(mac="aa:bb:cc:00:00:01", type="tv", owner="媽媽", room="客廳",
                             updated_at=TS.format(12)),
                        dict(mac="aa:bb:cc:00:00:02", type="phone", owner="小孩", room=None,
                             updated_at=TS.format(12))],
    "acks": [dict(mac="aa:bb:cc:00:00:01", domain="", created_at=TS.format(12)),
             dict(mac="aa:bb:cc:00:00:02", domain="doubleclick.net", created_at=TS.format(12)),
             dict(mac="network", domain="outage:7", created_at=TS.format(12)),
             dict(mac="aa:bb:cc:00:00:02", domain="bedtime:5:2026-10-19", created_at=TS.format(12))],
    "traffic_samples": [dict(mac="aa:bb:cc:00:00:01", ip="192.168.1.20", ts=TS.format(h),
                             rx_bytes=1000 * h, tx_bytes=100 * h) for h in (10, 11, 12)],
    "source_status": [dict(source="adguard", last_ok_ts=TS.format(12), last_error_ts=None,
                           last_error=None, last_count=4)],
    "meta": [dict(key="legacy_fixture", value="1")],
    "bedtime_rules": [dict(id=1, name="School nights", owner="小孩", mac=None, days="6,0,1,2,3",
                           win_start="22:00", win_end="07:00", min_minutes=10, enabled=1,
                           created_at=TS.format(12), updated_at=TS.format(12))],
    "settings": [dict(key="alerts.snooze_days", value="5", updated_at=TS.format(12))],
    "outages": [dict(id=3, start_ts=TS.format(10), end_ts=TS.format(11), cause="router",
                     ongoing=0, gateway_min=60, dns_min=0, probe_min=0, updated_at=TS.format(11))],
    "suggestion_state": [dict(id="trackers:all", status="dismissed", until=None, data="{}",
                              updated_at=TS.format(12))],
}


def main(db_path: str, sql_out: str) -> None:
    p = Path(db_path)
    for suffix in ("", "-wal", "-shm"):
        Path(str(p) + suffix).unlink(missing_ok=True)
    db = store.connect(p)
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    with db:
        for table, rows in ROWS.items():
            if table not in tables:
                continue
            cols = [r[1] for r in db.execute(f"PRAGMA table_info({table})")]
            for row in rows:
                keep = {k: v for k, v in row.items() if k in cols}
                db.execute(f"INSERT INTO {table} ({', '.join(keep)}) VALUES "
                           f"({', '.join('?' * len(keep))})", tuple(keep.values()))
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    lines = list(db.iterdump())
    db.close()
    Path(sql_out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{sql_out}: {len(tables)} tables, {len(lines)} statements")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
