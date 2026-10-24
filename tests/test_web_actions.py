"""
Tests for netwarden.web's user-data + chat endpoints (tasks 10-13):

    POST /api/ack  /api/unack      - mute a threat / trust a whole device
    POST /api/label                - rename a device (empty label clears it)
    POST /api/chat                 - multi-turn conversation (merged insight+Q&A)
    GET  /api/device?mac=...       - drill-down detail (services, trend, threats)

Same recipe as test_web: a real stdlib server on an ephemeral 127.0.0.1 port with a
fake LLM provider, so NO outbound calls and NO API budget. A fresh on-disk DB is used
so the mutating ack/label tests can't disturb anything else.
"""
import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from netwarden import brain, store, web

MAC = "aa:bb:cc:00:00:01"


class FakeProvider:
    def complete(self, system, user, max_tokens=1200):
        # Echo a marker plus the flattened transcript so we can prove the follow-up
        # question actually reached the provider.
        return "FAKE:" + user


def seed_file(path):
    db = store.connect(path)
    store.upsert_device(db, {"ip": "192.168.1.51", "mac": MAC,
                             "vendor": "Generic IP camera", "hostname": "ipcam",
                             "randomized": False, "is_self": False})
    events = [{
        "source": "demo", "ts": f"2026-01-01T00:00:{i:02d}.000000Z",
        "client_ip": "192.168.1.51", "client_name": "ipcam", "domain": "xmeye.net",
        "qtype": "A", "status": "NOERROR", "reason": "", "blocked": 0,
        "cached": 0, "upstream": "", "elapsed_ms": 1.0, "device_mac": MAC,
    } for i in range(6)]
    store.insert_events(db, events)
    db.close()


class WebActionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dbp = str(Path(cls.tmp.name) / "t.db")
        seed_file(cls.dbp)

        cls._orig_provider = brain.provider_from_env
        brain.provider_from_env = lambda env, db=None: FakeProvider()

        web.Handler.db_path = cls.dbp
        web.Handler.env = {}
        web.Handler.lang = "English"
        web.Handler.hours = 100000  # wide enough to include the 2026-01-01 seed

        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        brain.provider_from_env = cls._orig_provider
        cls.tmp.cleanup()

    def _get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read()

    def _post(self, path, obj):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("POST", path, json.dumps(obj), {"content-type": "application/json"})
        r = c.getresponse()
        return r.status, r.read()

    def _threats(self):
        _, body = self._get("/api/devices")
        return json.loads(body)["threats"]

    def test_ack_mutes_domain_then_unack_restores(self):
        # Baseline: the camera's xmeye.net threat is visible.
        self.assertTrue(any(t["domain"] == "xmeye.net" for t in self._threats()))
        # Mute this exact (device, domain) -> it disappears.
        status, _ = self._post("/api/ack", {"mac": MAC, "domain": "xmeye.net"})
        self.assertEqual(status, 200)
        self.assertFalse(any(t["domain"] == "xmeye.net" for t in self._threats()))
        # Un-mute -> it comes back (leaves the DB clean for later tests).
        status, _ = self._post("/api/unack", {"mac": MAC, "domain": "xmeye.net"})
        self.assertEqual(status, 200)
        self.assertTrue(any(t["domain"] == "xmeye.net" for t in self._threats()))

    def test_trust_whole_device_silences_all_its_threats(self):
        status, _ = self._post("/api/ack", {"mac": MAC})  # no domain = trust device
        self.assertEqual(status, 200)
        self.assertEqual(self._threats(), [])
        _, body = self._get("/api/devices")
        self.assertTrue(json.loads(body)["devices"][0]["trusted"])
        # restore
        self._post("/api/unack", {"mac": MAC})
        self.assertTrue(any(t["domain"] == "xmeye.net" for t in self._threats()))

    def test_ack_requires_mac(self):
        status, _ = self._post("/api/ack", {"domain": "xmeye.net"})
        self.assertEqual(status, 400)

    def test_label_sets_then_clears_display_name(self):
        status, _ = self._post("/api/label", {"mac": MAC, "label": "客廳攝影機"})
        self.assertEqual(status, 200)
        _, body = self._get("/api/devices")
        dev = json.loads(body)["devices"][0]
        self.assertEqual(dev["name"], "客廳攝影機")
        self.assertEqual(dev["label"], "客廳攝影機")
        # Empty label clears it; name falls back to the hostname.
        status, _ = self._post("/api/label", {"mac": MAC, "label": ""})
        self.assertEqual(status, 200)
        _, body = self._get("/api/devices")
        dev = json.loads(body)["devices"][0]
        self.assertEqual(dev["name"], "ipcam")
        self.assertIsNone(dev["label"])

    def test_chat_passes_transcript_to_provider(self):
        msgs = [
            {"role": "assistant", "content": "你的攝影機在連 xmeye.net。"},
            {"role": "user", "content": "為什麼這很危險?"},
        ]
        status, body = self._post("/api/chat", {"messages": msgs})
        self.assertEqual(status, 200)
        text = json.loads(body)["text"]
        self.assertTrue(text.startswith("FAKE:"))
        self.assertIn("為什麼這很危險?", text)   # the follow-up reached the model
        self.assertIn("xmeye.net", text)          # a fresh snapshot rode along too

    def test_chat_rejects_empty_or_non_user_last(self):
        s1, _ = self._post("/api/chat", {"messages": []})
        self.assertEqual(s1, 400)
        s2, _ = self._post("/api/chat", {"messages": [{"role": "assistant", "content": "hi"}]})
        self.assertEqual(s2, 400)
        s3, _ = self._post("/api/chat", {"messages": [{"role": "user", "content": "  "}]})
        self.assertEqual(s3, 400)

    def test_device_detail_has_services_trend_threats(self):
        status, body = self._get("/api/device?mac=" + MAC)
        self.assertEqual(status, 200)
        dev = json.loads(body)
        self.assertEqual(dev["mac"], MAC)
        self.assertTrue(dev["services"])                       # recognized a service
        self.assertEqual(len(dev["trend"]), 7)                 # 7-day sparkline, zero-filled
        self.assertTrue(all("queries" in d for d in dev["trend"]))
        self.assertTrue(any(t["domain"] == "xmeye.net" for t in dev["threats"]))

    def test_device_detail_unknown_mac_404(self):
        status, _ = self._get("/api/device?mac=zz:zz:zz:zz:zz:zz")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
