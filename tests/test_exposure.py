"""
Tests for netwarden.exposure - the opt-in, user-triggered port check.

Real connects happen ONLY to listeners these tests open on 127.0.0.1 (loopback is
allowed through the test-only allow_loopback flag); every other test fakes the scan.
"""
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from netwarden import exposure, i18n, store

DEV = "aa:00:00:00:00:51"


def _device(db, ip, mac=DEV, host="ipcam"):
    store.upsert_device(db, {"ip": ip, "mac": mac, "vendor": "cam", "hostname": host,
                             "randomized": False, "is_self": False})


class AllowedTargetTests(unittest.TestCase):
    def test_private_and_link_local_only(self):
        for ip in ("192.168.1.51", "172.16.0.1", "172.31.255.254", "192.168.0.10",
                   "169.254.3.4", "fd12:3456::1", "fe80::1", "fe80::1%eth0"):
            self.assertTrue(exposure.allowed(ip), ip)
        for ip in ("8.8.8.8", "172.32.0.1", "100.64.0.1", "1.1.1.1", "2001:4860::8888",
                   "0.0.0.0", "255.255.255.255", "224.0.0.1", "", "not-an-ip", "10.1.1"):
            self.assertFalse(exposure.allowed(ip), ip)

    def test_loopback_only_with_the_test_flag(self):
        self.assertFalse(exposure.allowed("127.0.0.1"))
        self.assertFalse(exposure.allowed("::1"))
        self.assertTrue(exposure.allowed("127.0.0.1", allow_loopback=True))

    def test_targets_come_from_the_inventory(self):
        db = store.connect(":memory:")
        _device(db, "192.168.1.51")
        _device(db, "8.8.8.8", mac="aa:00:00:00:00:99", host="public")
        self.assertEqual(exposure.targets(db, mac=DEV),
                         [{"mac": DEV, "ip": "192.168.1.51", "name": "ipcam"}])
        # --all silently skips what we may not check; one MAC asked for explicitly refuses
        self.assertEqual([t["mac"] for t in exposure.targets(db, all_devices=True)], [DEV])
        with self.assertRaises(exposure.RefusedTarget):
            exposure.targets(db, mac="aa:00:00:00:00:99")
        with self.assertRaises(exposure.RefusedTarget):
            exposure.targets(db, mac="unknown")
        self.assertEqual(exposure.targets(db), [])
        with self.assertRaises(exposure.RefusedTarget):   # scan() re-checks, too
            exposure.scan([{"mac": "x", "ip": "8.8.8.8"}], ports=[80])

    def test_fixed_port_list_and_limits(self):
        self.assertEqual(sorted(exposure.PORTS), [21, 22, 23, 80, 443, 445, 554, 1883, 3389,
                                                  5555, 7547, 8080, 8443, 9100])
        self.assertEqual(exposure.MAX_WORKERS, 16)
        self.assertLessEqual(exposure.CONNECT_TIMEOUT, 1.0)
        for port in exposure.PORTS:
            for code in i18n.CODES:
                self.assertTrue(exposure.port_info(port, code)["note"].strip())

    def test_demo_db_refuses_live_checks(self):
        db = store.connect(":memory:")
        _device(db, "192.168.1.51")
        store.set_meta(db, "demo", "1")
        with self.assertRaises(exposure.DemoRefused):
            exposure.check(db, mac=DEV)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM port_checks").fetchone()[0], 0)


class LoopbackScanTests(unittest.TestCase):
    """One real listener on 127.0.0.1; checks that we connect, send nothing, and close."""

    def setUp(self):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.open_port = self.srv.getsockname()[1]
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        self.closed_port = probe.getsockname()[1]
        probe.close()                    # nothing listens there any more
        self.received = []

        def accept():
            self.srv.settimeout(5)
            try:
                conn, _ = self.srv.accept()
                conn.settimeout(3)
                self.received.append(conn.recv(1024))   # b"" = peer closed, sent nothing
                conn.close()
            except OSError:
                pass
        self.t = threading.Thread(target=accept, daemon=True)
        self.t.start()

    def tearDown(self):
        self.srv.close()

    def test_check_stores_history_and_sends_nothing(self):
        db = store.connect(":memory:")
        _device(db, "127.0.0.1")
        ports = [self.open_port, self.closed_port]
        with self.assertRaises(exposure.RefusedTarget):   # loopback needs the test flag
            exposure.check(db, mac=DEV, ports=ports)
        seen = []
        rows = exposure.check(db, mac=DEV, ports=ports, allow_loopback=True,
                              progress=lambda d, t: seen.append((d, t)))
        self.assertEqual({r["port"]: r["open"] for r in rows},
                         {self.open_port: True, self.closed_port: False})
        self.assertEqual(seen[-1], (2, 2))
        self.t.join(5)
        self.assertEqual(self.received, [b""])
        latest = exposure.latest(db, DEV, "en")
        self.assertEqual(latest["checked"], 2)
        self.assertEqual([p["port"] for p in latest["open"]], [self.open_port])
        self.assertFalse(latest["open"][0]["new"])     # no earlier check to compare with


class FindingsTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")
        _device(self.db, "192.168.1.51")
        _device(self.db, "192.168.1.1", mac="aa:00:00:00:00:01", host="router")

    def _check(self, mac, ip, ts, open_ports):
        store.insert_port_checks(self.db, [{"mac": mac, "ip": ip, "port": p, "open": p in open_ports,
                                            "ts": ts} for p in exposure.PORTS])

    def test_risky_and_newly_opened(self):
        self._check(DEV, "192.168.1.51", "2026-01-01T00:00:00.000000Z", (80,))
        self._check(DEV, "192.168.1.51", "2026-01-02T00:00:00.000000Z", (23, 80, 554))
        self._check("aa:00:00:00:00:01", "192.168.1.1", "2026-01-02T00:00:00.000000Z", (80, 443))
        f = exposure.findings(self.db, "en")
        self.assertEqual([(x["name"], x["port"], x["risk"], x["new"]) for x in f],
                         [("ipcam", 23, "high", True), ("ipcam", 554, "medium", True)])
        self.assertEqual(f[0]["ack"], "port:23")
        self.assertIn("Mirai", f[0]["note"])
        # a low-risk port that is NEW still gets reported once
        self._check("aa:00:00:00:00:01", "192.168.1.1", "2026-01-03T00:00:00.000000Z", (80, 443, 8080))
        f = exposure.findings(self.db, "en")
        self.assertIn(("router", 8080, True), [(x["name"], x["port"], x["new"]) for x in f])
        self.assertEqual(len(store.port_check_history(self.db, DEV, limit=10)), 2)


class JobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "t.db")
        db = store.connect(self.path)
        _device(db, "192.168.1.51")
        db.close()
        self._scan = exposure.scan
        # never touch the real LAN: a fake scan that reports Telnet open
        exposure.scan = lambda devs, progress=None, **kw: [
            {"mac": d["mac"], "ip": d["ip"], "port": p, "open": p == 23,
             "ts": "2026-01-01T00:00:00.000000Z"} for d in devs for p in exposure.PORTS]

    def tearDown(self):
        exposure.scan = self._scan
        self.tmp.cleanup()

    def test_job_runs_in_background_and_stores_results(self):
        job = exposure.start_job(self.path, mac=DEV)
        self.assertEqual(job["state"], "running")
        for _ in range(100):
            st = exposure.job_status(job["id"])
            if st["state"] != "running":
                break
            time.sleep(0.02)
        self.assertEqual(st["state"], "done")
        db = store.connect(self.path)
        self.assertEqual([p["port"] for p in exposure.latest(db, DEV)["open"]], [23])
        self.assertIsNone(exposure.job_status("nope"))

    def test_job_refusals(self):
        with self.assertRaises(exposure.RefusedTarget):
            exposure.start_job(self.path, mac="unknown")
        db = store.connect(self.path)
        store.set_meta(db, "demo", "1")
        db.close()
        with self.assertRaises(exposure.DemoRefused):
            exposure.start_job(self.path, mac=DEV)


if __name__ == "__main__":
    unittest.main()
