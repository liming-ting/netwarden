"""
Tests for the OPTIONAL bandwidth path: netwarden.traffic_ingest (ntopng adapter),
store.bandwidth_summary / bandwidth_trend, and how brain + web surface it.

A fake ntopng answers /lua/rest/v2/get/host/active.lua on an ephemeral 127.0.0.1 port
(paged, basic auth, the documented {"rc", "rsp": {"data": [...]}} shape). No real
network, no LLM.
"""
import base64
import http.client
import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from netwarden import brain, store, traffic_ingest, web

CAM = "aa:bb:cc:00:00:01"
TV = "aa:bb:cc:00:00:02"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ago(**kw):
    return iso(datetime.now(timezone.utc) - timedelta(**kw))


# --- fake ntopng --------------------------------------------------------------

HOSTS = [  # as active.lua returns them (partial objects, like the docs' examples)
    {"ip": "192.168.1.51", "vlan": 0, "is_localhost": True,
     "bytes": {"total": 9100, "recvd": 100, "sent": 9000}, "thpt": {"bps": 0, "pps": 0}},
    {"ip": "192.168.1.31", "vlan": 0, "is_localhost": True,
     "bytes": {"total": 5500, "recvd": 5000, "sent": 500}},
    {"ip": "192.168.1.99", "vlan": 0, "is_localhost": True, "mac": "DE:AD:BE:EF:00:01",
     "bytes": {"total": 30, "recvd": 10, "sent": 20}},
    {"ip": "8.8.8.8", "vlan": 0, "is_localhost": False,   # remote: must be skipped
     "bytes": {"total": 1, "recvd": 1, "sent": 0}},
    {"ip": "192.168.1.77@2", "vlan": 2, "is_localhost": True,  # unknown device, tagged VLAN
     "bytes": {"total": 3, "recvd": 2, "sent": 1}},
]
AUTH = "Basic " + base64.b64encode(b"admin:secret").decode()


class FakeNtopng(BaseHTTPRequestHandler):
    calls = []

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        type(self).calls.append((u.path, q))
        if self.headers.get("Authorization") != AUTH:
            self.send_response(401)
            self.end_headers()
            return
        if u.path != "/lua/rest/v2/get/host/active.lua":
            self.send_response(404)
            self.end_headers()
            return
        page, per = int(q.get("currentPage", 1)), int(q.get("perPage", 10))
        rsp = {"data": HOSTS[(page - 1) * per: page * per], "currentPage": page, "perPage": per}
        body = json.dumps({"rc": 0, "rc_str": "OK", "rsp": rsp}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class NtopngSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeNtopng)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        FakeNtopng.calls = []

    def test_parses_local_hosts_across_pages(self):
        src = traffic_ingest.NtopngSource(self.url, "admin", "secret", ifid=3, page_size=2)
        samples = src.sample()
        by_ip = {s["ip"]: s for s in samples}
        self.assertEqual(set(by_ip), {"192.168.1.51", "192.168.1.31", "192.168.1.99", "192.168.1.77"})
        self.assertEqual(by_ip["192.168.1.51"]["rx_bytes"], 100)   # recvd = download
        self.assertEqual(by_ip["192.168.1.51"]["tx_bytes"], 9000)  # sent = upload
        self.assertEqual(by_ip["192.168.1.99"]["mac"], "de:ad:be:ef:00:01")
        self.assertIsNone(by_ip["192.168.1.31"]["mac"])
        self.assertEqual(len({s["ts"] for s in samples}), 1)    # one reading, one ts
        # 5 hosts / 2 per page -> pages 1..3, each asking for local hosts on ifid 3
        self.assertEqual([q["currentPage"] for _, q in FakeNtopng.calls], ["1", "2", "3"])
        self.assertTrue(all(q["mode"] == "local" and q["ifid"] == "3" for _, q in FakeNtopng.calls))

    def test_bad_credentials_raise_oserror(self):
        src = traffic_ingest.NtopngSource(self.url, "admin", "wrong")
        with self.assertRaises(OSError):
            src.sample()

    def test_ingest_maps_ip_to_mac(self):
        db = store.connect(":memory:")
        store.upsert_device(db, {"ip": "192.168.1.51", "mac": CAM, "vendor": "cam",
                                 "hostname": "ipcam", "randomized": False, "is_self": False})
        src = traffic_ingest.NtopngSource(self.url, "admin", "secret")
        st = traffic_ingest.ingest(db, src)
        self.assertEqual(st["hosts"], 4)
        self.assertEqual(st["unattributed"], 2)  # .31 and .77 are unknown devices
        rows = {r["ip"]: r["mac"] for r in db.execute("SELECT ip, mac FROM traffic_samples")}
        self.assertEqual(rows["192.168.1.51"], CAM)                  # from the device table
        self.assertEqual(rows["192.168.1.99"], "de:ad:be:ef:00:01")  # ntopng's own MAC wins
        self.assertIsNone(rows["192.168.1.31"])

    def test_unconfigured_is_off(self):
        self.assertIsNone(traffic_ingest.source_from_env({}))


# --- store: differencing ------------------------------------------------------

def sample(mac, ts, rx, tx, ip="192.168.1.51"):
    return {"mac": mac, "ip": ip, "ts": ts, "rx_bytes": rx, "tx_bytes": tx}


class BandwidthStoreTests(unittest.TestCase):
    def test_summary_totals_rates_and_counter_reset(self):
        db = store.connect(":memory:")
        store.insert_traffic_samples(db, [
            sample(CAM, ago(seconds=300), 1000, 10_000),
            sample(CAM, ago(seconds=200), 2000, 20_000),   # +1000 / +10000
            sample(CAM, ago(seconds=100), 500, 25_000),    # rx reset -> +500 (not -1500)
            sample(CAM, ago(seconds=0), 1500, 30_000),     # +1000 / +5000
        ])
        s = store.bandwidth_summary(db, ago(hours=1))[CAM]
        self.assertEqual(s["rx_bytes"], 2500)
        self.assertEqual(s["tx_bytes"], 20_000)
        self.assertAlmostEqual(s["rx_bps"], 1000 * 8 / 100, delta=2)  # last two samples
        self.assertAlmostEqual(s["tx_bps"], 5000 * 8 / 100, delta=5)
        self.assertGreaterEqual(s["peak_bps"], s["rx_bps"] + s["tx_bps"])
        self.assertTrue(all(v >= 0 for v in s.values()))

    def test_summary_needs_two_samples_and_respects_window(self):
        db = store.connect(":memory:")
        store.insert_traffic_samples(db, [sample(CAM, ago(days=3), 1, 1),
                                          sample(CAM, ago(seconds=10), 9, 9)])
        self.assertEqual(store.bandwidth_summary(db, ago(hours=24)), {})

    def test_two_ips_on_one_mac_are_separate_series(self):
        # IPv4 + IPv6 of one device, sampled at different times: interleaving their
        # cumulative counters used to look like a reset every switch (~1e9 overcount).
        db = store.connect(":memory:")
        v6 = "fe80::1"
        store.insert_traffic_samples(db, [
            sample(CAM, ago(seconds=300), 1000, 0),
            sample(CAM, ago(seconds=250), 1_000_000_000, 0, ip=v6),
            sample(CAM, ago(seconds=200), 1500, 0),                    # v4 +500
            sample(CAM, ago(seconds=150), 1_000_000_510, 0, ip=v6),    # v6 +510
        ])
        s = store.bandwidth_summary(db, ago(hours=1))[CAM]
        self.assertEqual(s["rx_bytes"], 1010)
        self.assertAlmostEqual(s["rx_bps"], 500 * 8 / 100 + 510 * 8 / 100, delta=2)
        self.assertLess(s["peak_bps"], 100)   # no reset-inflated spike
        trend = store.bandwidth_trend(db, CAM, days=7)
        self.assertEqual(sum(d["rx_bytes"] for d in trend), 1010)

    def test_same_timestamp_samples_are_deterministic(self):
        # one ntopng reading = one ts for every IP; plus a duplicated row (dt = 0)
        t0, t1 = ago(seconds=200), ago(seconds=100)
        rows = [sample(CAM, t0, 1000, 0), sample(CAM, t0, 5_000_000, 0, ip="fe80::1"),
                sample(CAM, t1, 2000, 0), sample(CAM, t1, 5_000_100, 0, ip="fe80::1"),
                sample(CAM, t1, 2000, 0)]
        results = []
        for order in (rows, rows[::-1]):
            db = store.connect(":memory:")
            store.insert_traffic_samples(db, order)
            results.append(store.bandwidth_summary(db, ago(hours=1))[CAM])
        self.assertEqual(results[0], results[1])
        s = results[0]
        self.assertEqual(s["rx_bytes"], 1100)
        self.assertAlmostEqual(s["rx_bps"], 1100 * 8 / 100, delta=2)
        self.assertAlmostEqual(s["peak_bps"], 1100 * 8 / 100, delta=2)

    def test_current_rate_ignores_stale_ip_series(self):
        # The device moved to a new lease an hour ago: the old IP's last pair is history
        # and must not be added to "now" forever (its bytes still count in the totals).
        db = store.connect(":memory:")
        old, new = "192.168.1.51", "192.168.1.52"
        store.insert_traffic_samples(db, [
            sample(CAM, ago(minutes=70), 0, 0, ip=old),
            sample(CAM, ago(minutes=65), 3_000_000, 0, ip=old),   # 80 kbps, then silence
            sample(CAM, ago(seconds=100), 5000, 0, ip=new),
            sample(CAM, ago(seconds=0), 6000, 0, ip=new),         # +1000 in 100 s
        ])
        s = store.bandwidth_summary(db, ago(hours=2))[CAM]
        self.assertAlmostEqual(s["rx_bps"], 1000 * 8 / 100, delta=2)
        self.assertEqual(s["rx_bytes"], 3_001_000)
        self.assertGreater(s["peak_bps"], 70_000)          # the old burst is still the peak

    def test_series_within_tolerance_still_count_as_current(self):
        # IPv4 + IPv6 read a few seconds apart are both "now".
        db = store.connect(":memory:")
        store.insert_traffic_samples(db, [
            sample(CAM, ago(seconds=130), 0, 0),
            sample(CAM, ago(seconds=30), 1000, 0),
            sample(CAM, ago(seconds=100), 0, 0, ip="fe80::1"),
            sample(CAM, ago(seconds=0), 1000, 0, ip="fe80::1"),
        ])
        s = store.bandwidth_summary(db, ago(hours=1))[CAM]
        self.assertAlmostEqual(s["rx_bps"], 2 * 1000 * 8 / 100, delta=2)

    def test_summary_uses_sample_before_window_as_baseline(self):
        db = store.connect(":memory:")
        store.insert_traffic_samples(db, [
            sample(CAM, ago(hours=2), 1000, 0),       # baseline (before the window)
            sample(CAM, ago(minutes=30), 1500, 0),    # first in-window delta: +500
            sample(CAM, ago(seconds=0), 2500, 0),     # +1000
        ])
        self.assertEqual(store.bandwidth_summary(db, ago(hours=1))[CAM]["rx_bytes"], 1500)

    def test_trend_is_daily_zero_filled(self):
        db = store.connect(":memory:")
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        store.insert_traffic_samples(db, [
            sample(TV, iso(today - timedelta(days=2, hours=-1)), 0, 0),
            sample(TV, iso(today - timedelta(days=2, hours=-2)), 4000, 100),
            sample(TV, iso(today + timedelta(minutes=1)), 3000, 50),  # reset: +3000 / +50
        ])
        trend = store.bandwidth_trend(db, TV, days=7)
        self.assertEqual(len(trend), 7)
        self.assertEqual(trend[-1]["day"], today.strftime("%Y-%m-%d"))
        self.assertEqual(trend[-3]["rx_bytes"], 4000)
        self.assertEqual(trend[-1]["rx_bytes"], 3000)
        self.assertEqual(trend[-1]["tx_bytes"], 50)
        self.assertEqual(sum(d["rx_bytes"] for d in trend), 7000)


# --- brain + web ----------------------------------------------------------------

def seed(path, with_traffic):
    db = store.connect(path)
    for ip, mac, name in (("192.168.1.51", CAM, "ipcam"), ("192.168.1.31", TV, "tv")):
        store.upsert_device(db, {"ip": ip, "mac": mac, "vendor": name, "hostname": name,
                                 "randomized": False, "is_self": False})
        store.insert_events(db, [{
            "source": "demo", "ts": ago(minutes=i + 1), "client_ip": ip, "client_name": name,
            "domain": "xmeye.net" if mac == CAM else "netflix.com", "qtype": "A",
            "status": "NOERROR", "reason": "", "blocked": 0, "cached": 0, "upstream": "",
            "elapsed_ms": 1.0, "device_mac": mac} for i in range(3)])
    if with_traffic:  # only the camera is seen by the sensor
        store.insert_traffic_samples(db, [sample(CAM, ago(hours=2), 0, 0),
                                          sample(CAM, ago(hours=1), 1_000_000, 2_500_000_000)])
    db.close()


class FakeProvider:
    def __init__(self):
        self.calls = []

    def complete(self, system, user, max_tokens=1200):
        self.calls.append((system, user))
        return "FAKE"


class BrainBandwidthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _db(self, with_traffic):
        p = str(Path(self.tmp.name) / f"{with_traffic}.db")
        seed(p, with_traffic)
        return store.connect(p)

    def test_no_traffic_means_no_bandwidth_keys(self):
        snap = brain.snapshot(self._db(False))
        self.assertFalse(snap["has_bandwidth"])
        self.assertTrue(all("bandwidth" not in d for d in snap["devices"]))

    def test_traffic_adds_bandwidth_and_render_line(self):
        db = self._db(True)
        snap = brain.snapshot(db)
        self.assertTrue(snap["has_bandwidth"])
        cam = next(d for d in snap["devices"] if d["mac"] == CAM)
        tv = next(d for d in snap["devices"] if d["mac"] == TV)
        self.assertEqual(cam["bandwidth"]["tx_bytes"], 2_500_000_000)
        self.assertNotIn("bandwidth", tv)
        p = FakeProvider()
        brain.insights(db, p)
        system, user = p.calls[0]
        self.assertIn("uploaded 2.5 GB", user)
        self.assertIn('"has_bandwidth" is true', system)


class WebBandwidthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.with_bw = str(Path(cls.tmp.name) / "bw.db")
        cls.without = str(Path(cls.tmp.name) / "nobw.db")
        seed(cls.with_bw, True)
        seed(cls.without, False)
        web.Handler.env = {}
        web.Handler.hours = 24
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def _get(self, db, path):
        web.Handler.db_path = db
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read()

    def test_page_has_bandwidth_strings(self):
        # The page renders bandwidth text from locale keys; the strings come from
        # /api/locale (default language 繁體中文).
        _, body = self._get(self.without, "/static/app.js")
        self.assertIn("bw.col", body.decode("utf-8"))
        _, body = self._get(self.without, "/api/locale?lang=zh-Hant")
        strings = json.loads(body)["strings"]
        self.assertEqual(strings["bw.col"], "流量")
        self.assertIn("docs/bandwidth.md", strings["bw.no_sensor"])

    def test_devices_and_drilldown_with_traffic(self):
        _, body = self._get(self.with_bw, "/api/devices")
        snap = json.loads(body)
        self.assertTrue(snap["has_bandwidth"])
        cam = next(d for d in snap["devices"] if d["mac"] == CAM)
        self.assertEqual(cam["bandwidth"]["rx_bytes"], 1_000_000)
        status, body = self._get(self.with_bw, "/api/device?mac=" + CAM)
        self.assertEqual(status, 200)
        dev = json.loads(body)
        self.assertTrue(dev["has_bandwidth"])
        self.assertEqual(len(dev["bandwidth_trend"]), 7)
        self.assertEqual(sum(d["tx_bytes"] for d in dev["bandwidth_trend"]), 2_500_000_000)

    def test_devices_and_drilldown_without_traffic(self):
        _, body = self._get(self.without, "/api/devices")
        snap = json.loads(body)
        self.assertFalse(snap["has_bandwidth"])
        self.assertTrue(all("bandwidth" not in d for d in snap["devices"]))
        _, body = self._get(self.without, "/api/device?mac=" + CAM)
        dev = json.loads(body)
        self.assertFalse(dev["has_bandwidth"])
        self.assertTrue(all(d["rx_bytes"] == 0 and d["tx_bytes"] == 0
                            for d in dev["bandwidth_trend"]))


if __name__ == "__main__":
    unittest.main()
