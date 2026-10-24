"""
Tests for netwarden.runner (the `run` background loops) and the *_recorded helpers
that write source_status. Fake jobs and a fake DNS source; no LAN sweep, no network.
"""
import logging
import tempfile
import threading
import time
import unittest
from pathlib import Path

from netwarden import discovery, dns_ingest, runner, store, traffic_ingest


class FakeDNS:
    source = "adguard"

    def __init__(self, fail=False):
        self.fail = fail

    def events(self, since):
        if self.fail:
            raise OSError("connection refused by http://admin:s3cret@127.0.0.1:3000")
        yield {"source": "adguard", "ts": "2026-01-01T00:00:00.000000Z",
               "client_ip": "203.0.113.9", "client_name": None, "domain": "example.com",
               "qtype": "A", "status": "NOERROR", "reason": "", "blocked": 0, "cached": 0,
               "upstream": "", "elapsed_ms": 1.0}


class FakeNtopng:
    source = "ntopng"

    def sample(self):
        raise OSError("ntopng did not return JSON")


class BackoffTests(unittest.TestCase):
    def test_backoff_grows_and_caps(self):
        self.assertEqual(runner.backoff(60, 0), 60)
        self.assertEqual(runner.backoff(60, 1), 60)
        self.assertEqual(runner.backoff(60, 2), 120)
        self.assertEqual(runner.backoff(60, 3), 240)
        self.assertEqual(runner.backoff(60, 50), 60 * runner.MAX_BACKOFF_FACTOR)


class LoopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "t.db"
        logging.getLogger("netwarden").addHandler(logging.NullHandler())

    def tearDown(self):
        self.tmp.cleanup()

    def test_failing_job_is_retried_and_never_kills_the_loop(self):
        calls = []

        def job(db):
            calls.append(threading.current_thread().name)
            if len(calls) < 3:
                raise RuntimeError("transient")
            store.record_source_ok(db, "fake", len(calls))

        r = runner.Runner(self.db_path, {}, jobs={"fake": (0.01, job)}).start()
        deadline = time.monotonic() + 5
        while len(calls) < 4 and time.monotonic() < deadline:
            time.sleep(0.01)
        status = r.status()["fake"]
        r.stop()
        self.assertGreaterEqual(len(calls), 4)
        self.assertTrue(all(n == "netwarden-fake" for n in calls))  # its own thread
        self.assertEqual(status["interval_s"], 0.01)
        self.assertTrue(status["running"])
        db = store.connect(self.db_path)
        self.assertIn("fake", store.source_status(db))

    def test_stop_is_fast_even_with_long_intervals(self):
        ran = threading.Event()
        r = runner.Runner(self.db_path, {}, jobs={
            "slow": (3600, lambda db: ran.set()),
            "off": (None, "not_configured")}).start()
        self.assertTrue(ran.wait(2))
        self.assertEqual(r.skipped, {"off": "not_configured"})
        t0 = time.monotonic()
        r.stop(timeout=2)
        self.assertLess(time.monotonic() - t0, 2.5)
        self.assertFalse(r.status()["slow"]["running"])

    def test_disabled_runner_starts_nothing(self):
        r = runner.Runner(self.db_path, {"ADGUARD_URL": "http://127.0.0.1:9"}, enabled=False)
        r.start()
        self.assertEqual(r.status(), {})
        r.stop()


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.orig = discovery.availability

    def tearDown(self):
        discovery.availability = self.orig

    def test_plan_follows_configuration(self):
        discovery.availability = lambda: (False, "no_lan")
        p = runner.plan({})
        self.assertEqual(p["dns"], (None, "not_configured"))
        self.assertEqual(p["traffic"], (None, "not_configured"))
        self.assertEqual(p["discovery"], (None, "no_lan"))
        self.assertEqual(p["prune"][0], runner.PRUNE_INTERVAL)   # retention always runs

        discovery.availability = lambda: (True, None)
        p = runner.plan({"ADGUARD_URL": "http://127.0.0.1:9", "NTOPNG_URL": "http://127.0.0.1:9"})
        self.assertEqual(p["dns"][0], runner.DNS_INTERVAL)
        self.assertEqual(p["traffic"][0], runner.TRAFFIC_INTERVAL)
        self.assertEqual(p["discovery"][0], runner.DISCOVERY_INTERVAL)

    def test_prune_job_uses_retention_setting(self):
        discovery.availability = lambda: (False, "no_lan")
        db = store.connect(":memory:")
        store.insert_events(db, [{"source": "t", "ts": "2000-01-01T00:00:00.000000Z",
                                  "client_ip": "192.168.1.5", "domain": "old.example",
                                  "blocked": 0, "cached": 0, "device_mac": None}])
        runner.plan({"NETWARDEN_RETENTION_DAYS": "30"})["prune"][1](db)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0], 0)


class RecordedTests(unittest.TestCase):
    def test_dns_ok_and_error_are_recorded_and_sanitized(self):
        db = store.connect(":memory:")
        st = dns_ingest.ingest_recorded(db, FakeDNS())
        self.assertEqual(st["fetched"], 1)
        row = store.source_status(db)["adguard"]
        self.assertEqual(row["last_count"], 1)
        self.assertIsNone(row["last_error"])
        with self.assertRaises(OSError):
            dns_ingest.ingest_recorded(db, FakeDNS(fail=True))
        row = store.source_status(db)["adguard"]
        self.assertIn("connection refused", row["last_error"])
        self.assertNotIn("s3cret", row["last_error"])
        self.assertEqual(row["last_count"], 1)   # the last good run is kept

    def test_traffic_error_is_recorded(self):
        db = store.connect(":memory:")
        with self.assertRaises(OSError):
            traffic_ingest.ingest_recorded(db, FakeNtopng())
        self.assertIn("JSON", store.source_status(db)["ntopng"]["last_error"])

    def test_discovery_failure_is_recorded(self):
        db = store.connect(":memory:")
        orig = discovery.default_iface_net_ip
        discovery.default_iface_net_ip = lambda: (None, None, None)
        try:
            with self.assertRaises(OSError):
                discovery.scan_recorded(db, table={})
        finally:
            discovery.default_iface_net_ip = orig
        self.assertIn("local network", store.source_status(db)["discovery"]["last_error"])

    def test_availability_reasons(self):
        orig_which, orig_net = discovery.shutil.which, discovery.default_iface_net_ip
        try:
            discovery.shutil.which = lambda name: None
            self.assertEqual(discovery.availability(), (False, "no_ip_command"))
            discovery.shutil.which = lambda name: "/usr/sbin/ip"
            discovery.default_iface_net_ip = lambda: ("eth0", None, None)
            self.assertEqual(discovery.availability(), (False, "no_lan"))
            discovery.default_iface_net_ip = lambda: ("eth0", "10.0.0.0/24", "10.0.0.2")
            self.assertEqual(discovery.availability(), (True, None))
        finally:
            discovery.shutil.which, discovery.default_iface_net_ip = orig_which, orig_net


if __name__ == "__main__":
    unittest.main()
