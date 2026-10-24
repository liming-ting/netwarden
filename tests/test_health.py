"""
Tests for netwarden.health - source status, stale detection, sanitized errors, hints
and the localized `netwarden status` table. In-memory DBs, no network; discovery
availability is pinned so results don't depend on the machine running the tests.
"""
import unittest
from datetime import datetime, timedelta, timezone

from netwarden import discovery, health, i18n, store

NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class _PinDiscovery:
    def __init__(self, result):
        self.result = result

    def __enter__(self):
        self.orig = discovery.availability
        discovery.availability = lambda: self.result

    def __exit__(self, *exc):
        discovery.availability = self.orig


class SanitizeTests(unittest.TestCase):
    def test_masks_credentials_and_keys(self):
        msg = ("HTTP 401 for http://admin:hunter2@192.168.1.2:3000/lua/x "
               "Authorization: Basic YWRtaW46aHVudGVyMg== key sk-ant-api03-abcdefghij")
        out = health.sanitize_error(msg, secrets=["hunter2"])
        for secret in ("hunter2", "YWRtaW46aHVudGVyMg==", "sk-ant-api03-abcdefghij", "admin:"):
            self.assertNotIn(secret, out)
        self.assertIn("http://***@192.168.1.2:3000", out)

    def test_one_line_bounded_and_names_the_exception(self):
        out = health.sanitize_error(ConnectionRefusedError("refused\nsecond line " + "x" * 500))
        self.assertNotIn("\n", out)
        self.assertLessEqual(len(out), 300)
        self.assertTrue(out.startswith("ConnectionRefusedError: refused second line"))
        self.assertEqual(health.sanitize_error(TimeoutError()), "TimeoutError")


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")

    def status(self, env, can=(True, None), loops=None):
        with _PinDiscovery(can):
            return health.status(self.db, None, env, loops=loops, now=NOW)

    def test_unconfigured_everything(self):
        st = self.status({}, can=(False, "no_ip_command"))
        self.assertFalse(st["demo"])
        self.assertEqual(set(st["sources"]), {"adguard", "pihole", "ntopng", "discovery",
                                              "mdns", "ssdp", "upnp", "netbios", "gateway"})
        for name, s in st["sources"].items():
            self.assertFalse(s["configured"], name)
            self.assertFalse(s["stale"], name)
        self.assertEqual(st["sources"]["discovery"]["reason"], "no_ip_command")
        self.assertEqual(st["ai"], {"mode": "offline", "model": "offline", "reason": "no_key",
                                    "provider": "offline", "destination": "none",
                                    "redact": False})
        self.assertEqual(st["db"]["retention_days"], 90)
        self.assertIn("version", st)
        self.assertEqual(st["loops"], {})

    def test_fresh_stale_and_error(self):
        store.record_source_ok(self.db, "adguard", 42, ts=iso(NOW - timedelta(minutes=2)))
        store.record_source_ok(self.db, "ntopng", 7, ts=iso(NOW - timedelta(hours=3)))
        store.record_source_error(self.db, "discovery",
                                  "OSError: http://u:p4ss@host/ failed", ts=iso(NOW))
        env = {"ADGUARD_URL": "http://127.0.0.1:3000", "NTOPNG_URL": "http://x:3000",
               "ANTHROPIC_API_KEY": "sk-test", "NETWARDEN_RETENTION_DAYS": "3"}
        st = self.status(env)
        a, n, d = (st["sources"][k] for k in ("adguard", "ntopng", "discovery"))
        self.assertTrue(a["configured"] and not a["stale"])
        self.assertEqual(a["last_count"], 42)
        self.assertTrue(n["stale"])
        self.assertTrue(d["stale"])          # configured (sweep possible) but never OK
        self.assertNotIn("p4ss", d["last_error"])
        self.assertEqual([health.state(k, s) for k, s in st["sources"].items()],
                         ["ok", "off", "stale", "error", "never", "never", "never", "never", "never"])
        # mDNS / SSDP / UPnP / gateway ride along with discovery: "never" alone is no hint
        self.assertFalse([h for h in health.hints(st, "en")
                          if "mDNS" in h or "UPnP" in h or "router ping" in h.lower()])
        self.assertEqual(st["ai"]["mode"], "anthropic")
        self.assertEqual(st["db"]["retention_days"], store.MIN_RETENTION_DAYS)
        self.assertNotIn("sk-test", str(st))
        self.assertNotIn("127.0.0.1:3000", str(st))   # config presence only, no values

    def test_demo_db_is_never_stale(self):
        store.set_meta(self.db, "demo", "1")
        store.record_source_ok(self.db, "adguard", 5, ts=iso(NOW - timedelta(days=30)))
        st = self.status({}, can=(False, "no_lan"))
        self.assertTrue(st["demo"])
        self.assertTrue(st["sources"]["adguard"]["configured"])
        self.assertFalse(st["sources"]["adguard"]["stale"])
        self.assertFalse(st["sources"]["ntopng"]["configured"])
        self.assertNotIn("reason", st["sources"]["discovery"])

    def test_hints_are_actionable_and_localized(self):
        store.record_source_ok(self.db, "adguard", 1, ts=iso(NOW - timedelta(hours=3)))
        st = self.status({"ADGUARD_URL": "http://127.0.0.1:3000"}, can=(False, "no_lan"))
        en = health.hints(st, "en", now=NOW)
        self.assertTrue(any("3 h ago" in h and "AdGuard" in h for h in en), en)
        self.assertTrue(any("NTOPNG_URL" in h for h in en))
        self.assertTrue(any("ANTHROPIC_API_KEY" in h for h in en))
        self.assertTrue(any(i18n.t("status.reason.no_lan", "en") in h for h in en))
        zh = health.hints(st, "zh-Hant", now=NOW)
        self.assertTrue(any("3 小時" in h for h in zh), zh)

    def test_never_ran_hint(self):
        st = self.status({"ADGUARD_URL": "http://127.0.0.1:3000"})
        self.assertEqual(health.state("adguard", st["sources"]["adguard"]), "never")
        self.assertIn(i18n.t("status.hint.adguard_never", "en"), health.hints(st, "en", NOW))

    def test_render_table(self):
        store.record_source_ok(self.db, "adguard", 42, ts=iso(NOW - timedelta(minutes=2)))
        loops = {"dns": {"running": True, "interval_s": 60}}
        st = self.status({"ADGUARD_URL": "x"}, loops=loops)
        out = health.render(st, "en", dashboard="http://127.0.0.1:8787", now=NOW)
        self.assertIn("DNS (AdGuard Home)", out)
        self.assertIn("42", out)
        self.assertIn("2 min", out)
        self.assertIn("DNS ingest: every 1 min (running)", out)
        self.assertIn("Dashboard: http://127.0.0.1:8787", out)
        zh = health.render(st, "zh-Hant", dashboard="", now=NOW)
        self.assertIn("儀表板:未執行", zh)
        self.assertIn("正常", zh)

    def test_ago_and_duration(self):
        self.assertEqual(health.ago(None, "en"), "never")
        self.assertEqual(health.ago(iso(NOW - timedelta(seconds=30)), "en", NOW), "30 s")
        self.assertEqual(health.ago(iso(NOW - timedelta(days=2, hours=5)), "en", NOW), "2 d")
        self.assertEqual(health.duration(60, "en"), "1 min")
        self.assertEqual(health.duration(86400, "zh-Hant"), "1 天")
        self.assertEqual(health.duration(90, "en"), "90 s")


if __name__ == "__main__":
    unittest.main()
