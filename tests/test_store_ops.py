"""
Tests for the store's operational side (Stage C): WAL + busy timeout so loops and the
web server can share one file, source_status (health), the meta/demo flag, retention
pruning and DB stats. Temporary on-disk DBs only; no network.
"""
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netwarden import store

MAC = "aa:bb:cc:00:00:01"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ago(**kw):
    return iso(datetime.now(timezone.utc) - timedelta(**kw))


def event(ts, i=0, domain="example.com"):
    return {"source": "test", "ts": ts, "client_ip": "192.168.1.5", "client_name": None,
            "domain": domain, "qtype": "A", "status": "NOERROR", "reason": "", "blocked": 0,
            "cached": 0, "upstream": "", "elapsed_ms": 1.0, "device_mac": None}


class FileDBTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "t.db"

    def tearDown(self):
        self.tmp.cleanup()

    def test_wal_and_busy_timeout(self):
        db = store.connect(self.path)
        self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(db.execute("PRAGMA busy_timeout").fetchone()[0], store.BUSY_TIMEOUT_MS)
        db.close()

    def test_concurrent_writers_never_hit_locked(self):
        store.connect(self.path).close()
        errors = []

        def writer(n):
            try:
                db = store.connect(self.path)
                for i in range(40):
                    store.insert_events(db, [event(ago(seconds=i, microseconds=n), i,
                                                   f"w{n}-{i}.example")])
                    store.record_source_ok(db, f"src{n}", i)
                db.close()
            except sqlite3.OperationalError as e:
                errors.append(e)

        def reader():
            try:
                db = store.connect(self.path)
                for _ in range(40):
                    store.device_activity(db)
                db.close()
            except sqlite3.OperationalError as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
        threads += [threading.Thread(target=reader) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        db = store.connect(self.path)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0], 160)

    def test_db_stats(self):
        db = store.connect(self.path)
        store.upsert_device(db, {"ip": "192.168.1.5", "mac": MAC, "vendor": "x", "hostname": "",
                                 "randomized": False, "is_self": False})
        store.insert_events(db, [event(ago(days=3)), event(ago(hours=1), domain="b.example")])
        store.insert_traffic_samples(db, [{"mac": MAC, "ip": "192.168.1.5", "ts": ago(days=5),
                                           "rx_bytes": 1, "tx_bytes": 1}])
        st = store.db_stats(db, self.path)
        self.assertGreater(st["size_bytes"], 0)
        self.assertEqual((st["devices"], st["dns_events"], st["traffic_samples"]), (1, 2, 1))
        self.assertLess(st["oldest_ts"], ago(days=4))       # the traffic sample
        self.assertGreater(st["newest_ts"], ago(hours=2))   # the newest DNS event


class SourceStatusTests(unittest.TestCase):
    def test_ok_then_error_keeps_both(self):
        db = store.connect(":memory:")
        store.record_source_ok(db, "adguard", 12, ts="2026-01-01T00:00:00.000000Z")
        store.record_source_error(db, "adguard", "boom", ts="2026-01-01T00:01:00.000000Z")
        row = store.source_status(db)["adguard"]
        self.assertEqual(row, {"last_ok_ts": "2026-01-01T00:00:00.000000Z",
                               "last_error_ts": "2026-01-01T00:01:00.000000Z",
                               "last_error": "boom", "last_count": 12})
        store.record_source_ok(db, "adguard", 3)
        row = store.source_status(db)["adguard"]
        self.assertEqual(row["last_count"], 3)
        self.assertEqual(row["last_error"], "boom")   # history kept; ts order tells it's old
        self.assertGreater(row["last_ok_ts"], row["last_error_ts"])

    def test_meta_and_demo_flag(self):
        db = store.connect(":memory:")
        self.assertFalse(store.is_demo(db))
        self.assertIsNone(store.get_meta(db, "demo"))
        store.set_meta(db, "demo", "1")
        self.assertTrue(store.is_demo(db))
        store.set_meta(db, "demo", "0")
        self.assertFalse(store.is_demo(db))


class RetentionTests(unittest.TestCase):
    def test_retention_days_default_min_and_invalid(self):
        self.assertEqual(store.retention_days(None), 90)
        self.assertEqual(store.retention_days(""), 90)
        self.assertEqual(store.retention_days("30"), 30)
        self.assertEqual(store.retention_days(3), store.MIN_RETENTION_DAYS)
        self.assertEqual(store.retention_days("-5"), store.MIN_RETENTION_DAYS)
        self.assertEqual(store.retention_days("lots"), 90)

    def test_prune_deletes_only_old_history(self):
        db = store.connect(":memory:")
        store.upsert_device(db, {"ip": "192.168.1.5", "mac": MAC, "vendor": "x", "hostname": "",
                                 "randomized": False, "is_self": False}, seen=ago(days=200))
        store.set_label(db, MAC, "客廳攝影機")
        store.add_ack(db, MAC, "xmeye.net")
        store.insert_events(db, [event(ago(days=40), domain="old.example"),
                                 event(ago(days=7, hours=23), domain="week.example"),
                                 event(ago(hours=1), domain="new.example")])
        store.insert_traffic_samples(db, [
            {"mac": MAC, "ip": "192.168.1.5", "ts": ago(days=40), "rx_bytes": 1, "tx_bytes": 1},
            {"mac": MAC, "ip": "192.168.1.5", "ts": ago(hours=1), "rx_bytes": 2, "tx_bytes": 2}])
        res = store.prune(db, 30)
        self.assertEqual((res["dns_events"], res["traffic_samples"], res["days"]), (1, 1, 30))
        domains = {r[0] for r in db.execute("SELECT domain FROM dns_events")}
        self.assertEqual(domains, {"week.example", "new.example"})
        # the user's inventory and notes survive any retention setting
        self.assertEqual(store.get_labels(db)[MAC]["label"], "客廳攝影機")
        self.assertIn((MAC, "xmeye.net"), store.list_acks(db))
        self.assertEqual(db.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 1)

    def test_prune_never_goes_below_the_minimum(self):
        db = store.connect(":memory:")
        store.insert_events(db, [event(ago(days=7, hours=12), domain="keep.example")])
        res = store.prune(db, 1)
        self.assertEqual(res["days"], store.MIN_RETENTION_DAYS)
        self.assertEqual(res["dns_events"], 0)   # the 7-day views stay intact

    def test_prune_vacuum(self):
        with tempfile.TemporaryDirectory() as d:
            db = store.connect(Path(d) / "v.db")
            store.insert_events(db, [event(ago(days=100, seconds=i), domain=f"d{i}.example")
                                     for i in range(300)])
            res = store.prune(db, 90, vacuum=True)
            self.assertTrue(res["vacuumed"])
            self.assertEqual(res["dns_events"], 300)
            db.close()


if __name__ == "__main__":
    unittest.main()
