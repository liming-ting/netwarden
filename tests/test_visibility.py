"""
Tests for netwarden.visibility - DoH/canary bypass, "went quiet" and "never in DNS",
with localized explanations and suggestion-only rules. In-memory, no network.
"""
import unittest
from datetime import datetime, timedelta, timezone

from netwarden import i18n, store, visibility

PHONE, ECHO, CAST, LAPTOP, PC = ("aa:00:00:00:00:0%d" % i for i in range(1, 6))


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ev(mac, ip, domain, ts, blocked=0, status="NOERROR"):
    return {"source": "test", "ts": ts, "client_ip": ip, "client_name": None, "domain": domain,
            "qtype": "A", "status": status, "reason": "", "blocked": blocked, "cached": 0,
            "upstream": "", "elapsed_ms": 1.0, "device_mac": mac}


class VisibilityTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        db = self.db = store.connect(":memory:")
        old = _iso(self.now - timedelta(days=3))
        recent = _iso(self.now - timedelta(minutes=5))
        for ip, mac, host, seen in (("10.0.0.21", PHONE, "phone", old),
                                    ("10.0.0.41", ECHO, "echo", recent),
                                    ("10.0.0.35", CAST, "chromecast", recent),
                                    ("10.0.0.60", LAPTOP, "laptop", old),
                                    ("10.0.0.70", PC, "pc", recent)):
            store.upsert_device(db, {"ip": ip, "mac": mac, "vendor": "x", "hostname": host,
                                     "randomized": False, "is_self": False}, seen=seen)
        evs, u = [], 0

        def at(hours):
            nonlocal u
            u += 1
            return _iso((self.now - timedelta(hours=hours)).replace(microsecond=u))
        # phone: DoH bootstrap via Google (answered) + Cloudflare (blocked by the filter)
        evs += [_ev(PHONE, "10.0.0.21", "dns.google", at(1)) for _ in range(3)]
        evs += [_ev(PHONE, "10.0.0.21", "mozilla.cloudflare-dns.com", at(2), blocked=1)]
        # laptop: Firefox canary answered NXDOMAIN by the filter -> fine, not a bypass
        evs += [_ev(LAPTOP, "10.0.0.60", "use-application-dns.net", at(1), status="NXDOMAIN")]
        # pc: canary got a normal answer -> Firefox may turn DoH on
        evs += [_ev(PC, "10.0.0.70", "use-application-dns.net", at(0.5))]
        # echo: hourly until 8 h ago, then silence while discovery still sees it
        evs += [_ev(ECHO, "10.0.0.41", "device-metrics-us.amazon.com", at(h)) for h in range(8, 30)]
        store.insert_events(db, evs)

    def test_resolver_matching(self):
        self.assertEqual(visibility.resolver_for("dns.google"), "Google")
        self.assertEqual(visibility.resolver_for("chrome.cloudflare-dns.com."), "Cloudflare")
        self.assertEqual(visibility.resolver_for("dns11.quad9.net"), "Quad9")
        self.assertEqual(visibility.resolver_for("abc123.dns.nextdns.io"), "NextDNS")
        self.assertIsNone(visibility.resolver_for("google.com"))
        self.assertIsNone(visibility.resolver_for("cloudflare.com"))

    def test_bypass(self):
        res = visibility.analyze(self.db, hours=24, now=self.now)
        by = {b["mac"]: b for b in res["bypass"]}
        phone = by[PHONE]
        self.assertTrue(phone["active"])
        self.assertEqual([r["domain"] for r in phone["resolvers"]],
                         ["dns.google", "mozilla.cloudflare-dns.com"])
        self.assertEqual(phone["resolvers"][1]["blocked"], 1)
        self.assertFalse(by[LAPTOP]["active"])        # NXDOMAIN canary = the filter said no
        self.assertTrue(by[PC]["active"])
        self.assertTrue(by[PC]["canary"]["answered"])
        self.assertEqual(visibility.issue_for(res, PHONE), "bypass")
        self.assertIsNone(visibility.issue_for(res, LAPTOP))

    def test_quiet_and_never(self):
        res = visibility.analyze(self.db, hours=24, now=self.now)
        self.assertEqual([q["mac"] for q in res["quiet"]], [ECHO])
        self.assertEqual(res["quiet"][0]["quiet_hours"], 8)
        self.assertGreaterEqual(res["quiet"][0]["active_hours"], visibility.HOURLY_MIN)
        self.assertEqual([n["mac"] for n in res["never"]], [CAST])
        self.assertEqual(visibility.issue_for(res, CAST), "never")

    def test_quiet_needs_a_regular_habit_and_recent_discovery(self):
        db = store.connect(":memory:")
        mac = "bb:00:00:00:00:01"
        store.upsert_device(db, {"ip": "10.0.0.9", "mac": mac, "vendor": "x", "hostname": "h",
                                 "randomized": False, "is_self": False},
                            seen=_iso(self.now - timedelta(minutes=1)))
        # only 3 lookups, 10 h ago: silent, but it never was an hourly talker
        store.insert_events(db, [_ev(mac, "10.0.0.9", "example.com",
                                     _iso(self.now - timedelta(hours=10, minutes=i)))
                                 for i in range(3)])
        self.assertEqual(visibility.quiet(db, self.now), [])
        # a device discovery hasn't seen recently is offline, not quiet
        self.assertEqual(visibility.quiet(self.db, self.now + timedelta(hours=2)), [])

    def test_never_needs_dns_logs(self):
        db = store.connect(":memory:")
        store.upsert_device(db, {"ip": "10.0.0.9", "mac": "cc:01", "vendor": "x", "hostname": "h",
                                 "randomized": False, "is_self": False})
        self.assertEqual(visibility.never(db), [])   # no DNS source at all -> no noise
        rep = visibility.report(db, 24, "en")
        self.assertEqual(rep["summary"], i18n.t("visibility.no_dns", "en"))

    def test_report_text_suggestions_and_rules(self):
        rep = visibility.report(self.db, 24, "en")
        texts = {i["mac"]: i["text"] for i in rep["items"] if i["kind"] != "bypass" or i["active"]}
        self.assertIn("dns.google (Google)", texts[PHONE])
        self.assertNotIn("mozilla.cloudflare-dns.com", texts[PHONE])   # that one was blocked
        self.assertIn("Firefox", texts[PC])
        self.assertIn("8 h", texts[ECHO])
        self.assertIn("10.0.0.35", texts[CAST])
        self.assertEqual(rep["summary"], "")
        self.assertEqual(len(rep["suggestions"]), 4)        # block DoH, canary, DHCP, hard-coded
        self.assertEqual(rep["rules"]["adguard"].split("\n"),
                         ["||dns.google^", "||use-application-dns.net^$dnsrewrite=NXDOMAIN"])
        self.assertEqual(rep["rules"]["pihole"], "dns.google")
        laptop = next(i for i in rep["items"] if i["mac"] == LAPTOP)
        self.assertIn("blocked", laptop["text"])
        for code in i18n.CODES:
            for item in visibility.report(self.db, 24, code)["items"]:
                self.assertNotIn("{", item["text"])

    def test_all_clear(self):
        db = store.connect(":memory:")
        store.upsert_device(db, {"ip": "10.0.0.9", "mac": "cc:01", "vendor": "x", "hostname": "h",
                                 "randomized": False, "is_self": False})
        store.insert_events(db, [_ev("cc:01", "10.0.0.9", "example.com",
                                     _iso(self.now - timedelta(minutes=3)))])
        rep = visibility.report(db, 24, "zh-Hant")
        self.assertEqual(rep["items"], [])
        self.assertEqual(rep["summary"], i18n.t("visibility.all_clear", "zh-Hant"))
        self.assertEqual(rep["suggestions"], [])


if __name__ == "__main__":
    unittest.main()
