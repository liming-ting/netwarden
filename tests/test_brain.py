"""
Tests for netwarden.brain - the Explain step.

These use a fake LLM provider, so they make NO network calls and spend NO API
budget. They lock down the parts we control: the snapshot we build from the store,
the empty-data short-circuit, prompt wiring, and provider config errors.
"""
import unittest
from datetime import datetime, timedelta, timezone

from netwarden import brain, store


def _ts(hours_ago: float, uniq: int) -> str:
    t = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return t.replace(microsecond=uniq % 1_000_000).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class FakeProvider:
    """Records what it was asked and returns a canned answer."""

    def __init__(self, reply="FAKE-ANSWER"):
        self.reply = reply
        self.calls = 0
        self.last_system = None
        self.last_user = None

    def complete(self, system, user, max_tokens=1200):
        self.calls += 1
        self.last_system = system
        self.last_user = user
        return self.reply


def seed(db):
    """A tiny two-device home: a chatty camera and this machine."""
    store.upsert_device(db, {"ip": "192.168.1.51", "mac": "aa:bb:cc:00:00:01",
                             "vendor": "Generic IP camera", "hostname": "ipcam",
                             "randomized": False, "is_self": False})
    store.upsert_device(db, {"ip": "192.168.1.13", "mac": "aa:bb:cc:00:00:02",
                             "vendor": "Dell Inc.", "hostname": "pc",
                             "randomized": False, "is_self": True})
    events = []
    uniq = 0
    for domain, n, blocked, mac, ip, name in [
        ("xmeye.net", 12, 0, "aa:bb:cc:00:00:01", "192.168.1.51", "ipcam"),
        ("pool.ntp.org", 2, 0, "aa:bb:cc:00:00:01", "192.168.1.51", "ipcam"),
        ("github.com", 5, 0, "aa:bb:cc:00:00:02", "192.168.1.13", "pc"),
        ("doubleclick.net", 4, 1, "aa:bb:cc:00:00:02", "192.168.1.13", "pc"),
    ]:
        for _ in range(n):
            uniq += 1
            events.append({
                "source": "demo", "ts": _ts(1, uniq), "client_ip": ip,
                "client_name": name, "domain": domain, "qtype": "A",
                "status": "NOERROR", "reason": "", "blocked": blocked,
                "cached": 0, "upstream": "", "elapsed_ms": 1.0, "device_mac": mac,
            })
    store.insert_events(db, events)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")

    def test_snapshot_summarizes_devices(self):
        seed(self.db)
        snap = brain.snapshot(self.db, hours=100000)
        self.assertEqual(snap["known_devices"], 2)
        self.assertEqual(snap["clients_with_dns"], 2)
        self.assertEqual(snap["total_queries"], 23)  # 12+2+5+4
        cam = next(d for d in snap["devices"] if d["mac"] == "aa:bb:cc:00:00:01")
        self.assertEqual(cam["vendor"], "Generic IP camera")
        self.assertFalse(cam["is_self"])
        # top_domains sorted by count desc -> the camera's cloud leads
        self.assertEqual(cam["top_domains"][0]["domain"], "xmeye.net")
        self.assertEqual(cam["top_domains"][0]["count"], 12)
        # service recognition rides along on the snapshot
        self.assertIn("XMEye", cam["top_domains"][0]["service"])
        self.assertEqual(cam["top_domains"][0]["category"], "iot")   # stable key
        self.assertTrue(any("XMEye" in s for s in cam["services"]))
        pc = next(d for d in snap["devices"] if d["mac"] == "aa:bb:cc:00:00:02")
        self.assertTrue(pc["is_self"])
        self.assertEqual(pc["blocked"], 4)  # the four doubleclick blocks
        dbl = next(t for t in pc["top_domains"] if t["domain"] == "doubleclick.net")
        self.assertEqual(dbl["category"], "ads")
        # threat intel rides along: the camera's cloud is flagged high-risk
        self.assertTrue(snap["threats"])
        cam_hit = next(t for t in snap["threats"] if t["domain"] == "xmeye.net")
        self.assertEqual(cam_hit["severity"], "high-risk")

    def test_empty_snapshot_has_no_data(self):
        snap = brain.snapshot(self.db, hours=100000)
        self.assertEqual(snap["total_queries"], 0)
        self.assertFalse(brain._has_data(snap))


class BrainBehaviourTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")

    def test_insights_feeds_data_to_provider(self):
        seed(self.db)
        fake = FakeProvider("INSIGHT-OK")
        out = brain.insights(self.db, fake, hours=100000, lang="English")
        self.assertEqual(out, "INSIGHT-OK")
        self.assertEqual(fake.calls, 1)
        self.assertIn("xmeye.net", fake.last_user)      # the data got in
        self.assertIn("English", fake.last_system)      # the language got in

    def test_insights_empty_does_not_call_provider(self):
        fake = FakeProvider()
        out = brain.insights(self.db, fake, hours=100000)
        self.assertEqual(fake.calls, 0)                 # no data -> no spend
        self.assertIn("DNS", out)                        # a helpful hint instead

    def test_ask_includes_question_and_data(self):
        seed(self.db)
        fake = FakeProvider("ANSWER-OK")
        out = brain.ask(self.db, fake, "which device is most unusual?",
                        hours=100000, lang="English")
        self.assertEqual(out, "ANSWER-OK")
        self.assertIn("which device is most unusual?", fake.last_user)
        self.assertIn("xmeye.net", fake.last_user)


class ProviderConfigTests(unittest.TestCase):
    def test_missing_key_raises(self):
        with self.assertRaises(brain.LLMError):
            brain.AnthropicProvider("")

    def test_provider_from_env_without_key_is_offline(self):
        # Stage C: no key = the rule-based offline provider, not an error.
        p = brain.provider_from_env({})
        self.assertTrue(p.offline)
        self.assertEqual(brain.ai_mode({}), "offline")

    def test_offline_flag_wins_over_a_key(self):
        env = {"ANTHROPIC_API_KEY": "sk-test", brain.OFFLINE_ENV: "1"}
        self.assertEqual(brain.ai_mode(env), "offline")
        self.assertTrue(brain.provider_from_env(env).offline)
        self.assertEqual(brain.ai_mode({"ANTHROPIC_API_KEY": "sk-test"}), "anthropic")
        self.assertIsInstance(brain.provider_from_env({"ANTHROPIC_API_KEY": "sk-test"}),
                              brain.AnthropicProvider)

    def test_describe_provider_reports_model(self):
        key = {"ANTHROPIC_API_KEY": "sk-test"}
        self.assertEqual(brain.describe_provider(key)["model"], brain.DEFAULT_MODEL)
        self.assertEqual(brain.describe_provider(key)["provider"], "Anthropic")
        self.assertEqual(brain.describe_provider(key)["ai_mode"], "anthropic")
        self.assertEqual(
            brain.describe_provider({**key, "ANTHROPIC_MODEL": "m-9"})["model"], "m-9")
        self.assertEqual(brain.describe_provider({})["ai_mode"], "offline")
        self.assertNotIn("sk-test", str(brain.describe_provider(key)))  # key never shown

    def test_env_file_parsing(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".env"
            p.write_text('ANTHROPIC_API_KEY="sk-demo"\n# a comment\nANTHROPIC_MODEL=m-1\n')
            env = brain.load_env(p)
            self.assertEqual(env["ANTHROPIC_API_KEY"], "sk-demo")  # quotes stripped
            self.assertEqual(env["ANTHROPIC_MODEL"], "m-1")


if __name__ == "__main__":
    unittest.main()
