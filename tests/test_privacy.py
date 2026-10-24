"""
Tests for netwarden.privacy - tracker classification, per-device grades, the home
summary and the copyable (never applied) block rules. Pure, in-memory, no network.
"""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netwarden import i18n, privacy, store

TV, PHONE, CAM = "aa:00:00:00:00:01", "aa:00:00:00:00:02", "aa:00:00:00:00:03"


def _ts(hours=0.0, uniq=0):
    t = datetime.now(timezone.utc) - timedelta(hours=hours)
    return t.replace(microsecond=uniq % 1_000_000).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ev(mac, ip, domain, ts, blocked=0):
    return {"source": "test", "ts": ts, "client_ip": ip, "client_name": None, "domain": domain,
            "qtype": "A", "status": "NOERROR", "reason": "", "blocked": blocked, "cached": 0,
            "upstream": "", "elapsed_ms": 1.0, "device_mac": mac}


def seed(db):
    for ip, mac, host in (("10.0.0.31", TV, "tv"), ("10.0.0.21", PHONE, "phone"),
                          ("10.0.0.51", CAM, "cam")):
        store.upsert_device(db, {"ip": ip, "mac": mac, "vendor": "x", "hostname": host,
                                 "randomized": False, "is_self": False})
    evs, u = [], 0

    def add(mac, ip, dom, n, blocked=0, hours=1):
        nonlocal u
        for _ in range(n):
            u += 1
            evs.append(_ev(mac, ip, dom, _ts(hours, u), blocked))
    # TV: 10 netflix, 6 ACR telemetry (two hosts), 4 ads (blocked) -> 6/20 = 30% leak -> D
    add(TV, "10.0.0.31", "netflix.com", 10)
    add(TV, "10.0.0.31", "samsungacr.com", 4)
    add(TV, "10.0.0.31", "log-config.samsungacr.com", 2)
    add(TV, "10.0.0.31", "samsungads.com", 4, blocked=1)
    # phone: every tracker blocked -> A
    add(PHONE, "10.0.0.21", "instagram.com", 10)
    add(PHONE, "10.0.0.21", "app-measurement.com", 5, blocked=1)
    # camera: no trackers at all
    add(CAM, "10.0.0.51", "xmeye.net", 8)
    # old history outside the window must not count
    add(TV, "10.0.0.31", "samsungacr.com", 50, hours=72)
    store.insert_events(db, evs)


class LookupTests(unittest.TestCase):
    def test_suffix_match_longest_entry_wins(self):
        self.assertEqual(privacy.lookup("googleads.g.doubleclick.net")[:2], ("doubleclick.net", "ads"))
        self.assertEqual(privacy.lookup("SSL.Google-Analytics.com.")[1], "analytics")
        self.assertEqual(privacy.lookup("log-config.samsungacr.com"),
                         ("samsungacr.com", "telemetry", "Samsung"))
        # imasdk.googleapis.com is ads, but googleapis.com itself is not a tracker
        self.assertEqual(privacy.lookup("imasdk.googleapis.com")[1], "ads")
        self.assertIsNone(privacy.lookup("android.googleapis.com"))
        self.assertIsNone(privacy.lookup("notdoubleclick.net"))   # not a real suffix
        self.assertIsNone(privacy.lookup("netflix.com"))
        self.assertIsNone(privacy.lookup(""))

    def test_bundled_list_is_curated_and_well_formed(self):
        self.assertTrue(150 <= len(privacy.TRACKERS) <= 250)
        for dom, (cat, company) in privacy.TRACKERS.items():
            self.assertIn(cat, privacy.CATEGORIES, dom)
            self.assertEqual(dom, dom.lower().strip("."), dom)
            self.assertIn(".", dom)
            self.assertTrue(company)
        self.assertEqual(set(privacy.CATEGORIES),
                         {c for c, _ in privacy.TRACKERS.values()})

    def test_custom_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "trackers_custom.txt"
            p.write_text("# my list\nmetrics.example-tv.com telemetry ExampleTV  # inline\n"
                         "tracker.example.net\nweird.example.org Some Company\n"
                         "*.bad.example\nnodot\n\n", encoding="utf-8")
            custom = privacy.load_custom(p)
            self.assertEqual(custom["metrics.example-tv.com"], ("telemetry", "ExampleTV"))
            self.assertEqual(custom["tracker.example.net"], ("other", None))
            self.assertEqual(custom["weird.example.org"], ("other", "Some Company"))
            self.assertNotIn("nodot", custom)
            self.assertEqual(len(custom), 3)
            tbl = privacy.table(p)
            self.assertEqual(privacy.lookup("a.metrics.example-tv.com", tbl)[1], "telemetry")
            self.assertIn("doubleclick.net", tbl)   # the bundled list is still there
        self.assertEqual(privacy.load_custom(Path("/nonexistent/x.txt")), {})


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")
        seed(self.db)
        self.res = privacy.analyze(self.db, privacy.since_hours(24), privacy.TRACKERS)
        self.dev = {d["mac"]: d for d in self.res["devices"]}

    def test_per_device_numbers(self):
        tv = self.dev[TV]
        self.assertEqual((tv["queries"], tv["tracker_queries"], tv["blocked"], tv["unblocked"]),
                         (20, 10, 4, 6))
        self.assertEqual(tv["tracker_share"], 0.5)
        self.assertEqual(tv["blocked_share"], 0.4)
        self.assertEqual(tv["by_category"], {"telemetry": 6, "ads": 4})
        self.assertEqual(tv["main_category"], "telemetry")
        self.assertEqual(tv["main_company"], "Samsung")
        self.assertEqual(tv["top_trackers"][0], {"entry": "samsungacr.com", "category": "telemetry",
                                                 "company": "Samsung", "count": 6, "blocked": 0})
        self.assertEqual(tv["grade"], "D")
        self.assertEqual(self.dev[PHONE]["grade"], "A")
        self.assertEqual(self.dev[CAM]["tracker_queries"], 0)
        self.assertEqual(self.dev[CAM]["grade"], "A")
        self.assertEqual(self.res["devices"][0]["mac"], TV)   # worst first

    def test_home_summary(self):
        home = self.res["home"]
        self.assertEqual((home["queries"], home["tracker_queries"], home["blocked"]), (43, 15, 9))
        line = privacy.home_line(home, "en")
        self.assertIn("15 of 43 lookups (35%)", line)
        self.assertIn("blocked 9 of them (60%)", line)

    def test_grades(self):
        self.assertEqual(privacy.grade(0, 0), "A")
        self.assertEqual(privacy.grade(100, 2), "A")
        self.assertEqual(privacy.grade(100, 5), "B")
        self.assertEqual(privacy.grade(100, 15), "C")
        self.assertEqual(privacy.grade(100, 39), "D")
        self.assertEqual(privacy.grade(100, 40), "F")

    def test_worst_offenders(self):
        worst = privacy.worst(self.res["devices"])
        self.assertEqual([w["mac"] for w in worst], [TV])

    def test_block_rules_only_for_unblocked_trackers(self):
        rules = privacy.block_rules(self.res["_entries"])
        self.assertEqual(rules["adguard"], "||samsungacr.com^")   # ads/analytics were blocked
        self.assertEqual(rules["pihole"].split("\n"),
                         ["log-config.samsungacr.com", "samsungacr.com"])  # exact hosts
        self.assertEqual(rules["count"], 1)
        self.assertEqual(privacy.block_rules([])["adguard"], "")

    def test_reasons_are_localized(self):
        tv = self.dev[TV]
        self.assertEqual(privacy.reason(tv, "en"),
                         "30% of its lookups reach trackers unblocked, mostly Telemetry (Samsung).")
        self.assertIn("遙測", privacy.reason(tv, "zh-Hant"))
        self.assertIn("全部", privacy.reason(self.dev[PHONE], "zh-Hant"))
        self.assertIn("8", privacy.reason(self.dev[CAM], "en"))
        for code in i18n.CODES:
            self.assertNotIn("{", privacy.reason(tv, code))


class ReportTests(unittest.TestCase):
    def test_report_and_device_report(self):
        db = store.connect(":memory:")
        seed(db)
        rep = privacy.report(db, 24, "ja")
        self.assertEqual(rep["home"]["grade"], privacy.grade(43, 6))
        self.assertIn("line", rep["home"])
        self.assertEqual(rep["worst"][0]["mac"], TV)
        self.assertEqual(rep["devices"][0]["main_category_name"], "テレメトリー")
        dev = privacy.device_report(db, TV, 24, "en")
        self.assertEqual(dev["grade"], "D")
        self.assertEqual(dev["rules"]["adguard"], "||samsungacr.com^")
        self.assertIsNone(privacy.device_report(db, "zz", 24, "en"))
        # the phone's trackers were all blocked -> nothing to suggest for it
        self.assertEqual(privacy.device_report(db, PHONE, 24, "en")["rules"]["adguard"], "")

    def test_empty_db(self):
        rep = privacy.report(store.connect(":memory:"), 24, "en")
        self.assertEqual(rep["devices"], [])
        self.assertEqual(rep["home"]["tracker_queries"], 0)
        self.assertEqual(rep["home"]["grade"], "A")


if __name__ == "__main__":
    unittest.main()
