"""
Tests for the offline AI mode (netwarden.offline_ai + brain's offline branch): a
localized, rule-based summary that NEVER touches the network. urllib is booby-trapped
for the whole module, so any outbound attempt fails the test.
"""
import unittest
import urllib.request
from datetime import datetime, timedelta, timezone

from netwarden import brain, i18n, offline_ai, store

CAM, PS5, VAC = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"


def _ts(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ev(mac, ip, domain, ts, blocked=0):
    return {"source": "test", "ts": ts, "client_ip": ip, "client_name": None, "domain": domain,
            "qtype": "A", "status": "NOERROR", "reason": "", "blocked": blocked, "cached": 0,
            "upstream": "", "elapsed_ms": 1.0, "device_mac": mac}


def seed(db, with_traffic=True):
    """A camera on a high-risk cloud, a PS5 that just started Twitch, a brand-new vacuum."""
    dev = lambda ip, mac, vendor, host: store.upsert_device(db, {  # noqa: E731
        "ip": ip, "mac": mac, "vendor": vendor, "hostname": host, "randomized": False,
        "is_self": False}, seen=_ts(days=8))
    dev("192.168.1.51", CAM, "Generic IP camera", "ipcam")
    dev("192.168.1.71", PS5, "Sony Interactive (PS5)", "PS5")
    store.upsert_device(db, {"ip": "192.168.1.55", "mac": VAC, "vendor": "Roborock",
                             "hostname": "roborock-vacuum", "randomized": False,
                             "is_self": False}, seen=_ts(hours=3))
    evs = []
    for i in range(6):
        evs.append(_ev(CAM, "192.168.1.51", "xmeye.net", _ts(hours=1, seconds=i)))
        evs.append(_ev(PS5, "192.168.1.71", "playstation.net", _ts(days=3, seconds=i)))
        evs.append(_ev(PS5, "192.168.1.71", "playstation.net", _ts(hours=2, seconds=i)))
        evs.append(_ev(PS5, "192.168.1.71", "twitch.tv", _ts(hours=2, seconds=30 + i)))
        evs.append(_ev(PS5, "192.168.1.71", "doubleclick.net", _ts(hours=2, seconds=60 + i), 1))
        evs.append(_ev(VAC, "192.168.1.55", "roborock.com", _ts(hours=1, seconds=i)))
    store.insert_events(db, evs)
    if with_traffic:
        store.insert_traffic_samples(db, [
            {"mac": CAM, "ip": "192.168.1.51", "ts": _ts(hours=2), "rx_bytes": 0, "tx_bytes": 0},
            {"mac": CAM, "ip": "192.168.1.51", "ts": _ts(seconds=0), "rx_bytes": 10**7,
             "tx_bytes": 9 * 10**8},
        ])


class _NoNetwork(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig = urllib.request.urlopen

        def boom(*a, **kw):
            raise AssertionError("offline mode must never open a network connection")
        urllib.request.urlopen = boom

    @classmethod
    def tearDownClass(cls):
        urllib.request.urlopen = cls._orig


class OfflineSummaryTests(_NoNetwork):
    def setUp(self):
        self.db = store.connect(":memory:")
        seed(self.db)
        self.p = brain.provider_from_env({})   # no key -> offline

    def test_insight_covers_the_important_signals(self):
        out = brain.insights(self.db, self.p, hours=24, lang="en")
        self.assertIn(i18n.t("offline.title", "en"), out)
        self.assertIn("xmeye.net", out)                       # threat first
        self.assertLess(out.index("xmeye.net"), out.index("roborock-vacuum"))
        self.assertIn("roborock-vacuum", out)                 # new device
        self.assertIn("Twitch", out)                          # behavior change
        self.assertIn("ipcam: ↓", out)                        # bandwidth
        self.assertIn("sends far more", out)                  # upload-heavy camera
        self.assertIn("PS5: 6 of", out)                       # most blocked
        self.assertIn("ANTHROPIC_API_KEY", out)               # how to get real AI
        self.assertNotIn(i18n.t("offline.all_quiet", "en"), out)

    def test_localized(self):
        out = brain.insights(self.db, self.p, hours=24, lang="zh-Hant")
        self.assertIn("離線模式", out)
        self.assertIn("新裝置", out)
        out = brain.insights(self.db, self.p, hours=24, lang="ja")
        self.assertIn("オフラインモード", out)

    def test_ask_and_converse_say_they_cannot_chat(self):
        note = i18n.t("offline.question_note", "en")
        self.assertIn(note, brain.ask(self.db, self.p, "why?", hours=24, lang="en"))
        msgs = [{"role": "assistant", "content": "hi"}, {"role": "user", "content": "why?"}]
        out = brain.converse(self.db, self.p, msgs, hours=24, lang="en")
        self.assertIn(note, out)
        self.assertIn("xmeye.net", out)

    def test_muted_threat_and_trusted_device_go_quiet(self):
        store.add_ack(self.db, CAM, "xmeye.net")
        store.add_ack(self.db, VAC)
        store.add_ack(self.db, PS5)
        out = brain.insights(self.db, self.p, hours=24, lang="en")
        self.assertNotIn("xmeye.net", out)
        self.assertNotIn(i18n.t("offline.new_devices", "en"), out)
        self.assertIn(i18n.t("offline.all_quiet", "en"), out)

    def test_no_data(self):
        out = brain.insights(store.connect(":memory:"), self.p, lang="en")
        self.assertIn(i18n.t("brain.no_data", "en"), out)
        self.assertIn(i18n.t("offline.enable_hint", "en"), out)

    def test_without_traffic_no_bandwidth_section(self):
        db = store.connect(":memory:")
        seed(db, with_traffic=False)
        out = brain.insights(db, self.p, hours=24, lang="en")
        self.assertNotIn("📶", out)

    def test_long_lists_are_capped(self):
        lines = [str(i) for i in range(offline_ai.MAX_LINES + 3)]
        out = offline_ai._capped({"tr": lambda k, **kw: i18n.t("offline." + k, "en", **kw)}, lines)
        self.assertEqual(len(out), offline_ai.MAX_LINES + 1)
        self.assertEqual(out[-1], "…and 3 more")

    def test_complete_fallback_is_labeled(self):
        self.assertIn("Offline mode", offline_ai.OfflineProvider("en").complete("s", "u"))


if __name__ == "__main__":
    unittest.main()
