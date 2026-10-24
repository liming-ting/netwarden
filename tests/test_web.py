"""
Tests for netwarden.web - the local dashboard + Q&A API.

Starts the real stdlib server on an ephemeral 127.0.0.1 port in a background
thread, but swaps in a fake LLM provider, so these make NO outbound network
calls and spend NO API budget. They lock down the HTTP routing: the page is
served, /api/devices returns the snapshot, and the two POST endpoints reach
the provider (or reject an empty question) without touching Anthropic.
"""
import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from netwarden import brain, store, web


class FakeProvider:
    def complete(self, system, user, max_tokens=1200):
        return "FAKE-TEXT"


def seed_file(path):
    """One chatty camera, in a real on-disk DB the server can open per request."""
    db = store.connect(path)
    store.upsert_device(db, {"ip": "192.168.1.51", "mac": "aa:bb:cc:00:00:01",
                             "vendor": "Generic IP camera", "hostname": "ipcam",
                             "randomized": False, "is_self": False})
    events = [{
        "source": "demo", "ts": f"2026-01-01T00:00:{i:02d}.000000Z",
        "client_ip": "192.168.1.51", "client_name": "ipcam", "domain": "xmeye.net",
        "qtype": "A", "status": "NOERROR", "reason": "", "blocked": 0,
        "cached": 0, "upstream": "", "elapsed_ms": 1.0,
        "device_mac": "aa:bb:cc:00:00:01",
    } for i in range(6)]
    store.insert_events(db, events)
    db.close()


class WebTests(unittest.TestCase):
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
        web.Handler.hours = 100000  # window wide enough to include the 2026-01-01 seed

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
        c.request("POST", path, json.dumps(obj),
                  {"content-type": "application/json"})
        r = c.getresponse()
        return r.status, r.read()

    def test_root_serves_html(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"netwarden", body)

    def test_devices_returns_snapshot(self):
        status, body = self._get("/api/devices")
        self.assertEqual(status, 200)
        snap = json.loads(body)
        self.assertEqual(snap["clients_with_dns"], 1)
        self.assertEqual(snap["total_queries"], 6)
        self.assertEqual(snap["devices"][0]["top_domains"][0]["domain"], "xmeye.net")
        self.assertIn("service", snap["devices"][0]["top_domains"][0])
        self.assertTrue(snap["devices"][0]["services"])  # recognized at least one
        self.assertIn("threats", snap)                   # threat scan rides along
        self.assertTrue(any(t["domain"] == "xmeye.net" for t in snap["threats"]))

    def test_ask_reaches_provider(self):
        status, body = self._post("/api/ask", {"question": "what is unusual?"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["text"], "FAKE-TEXT")

    def test_insight_reaches_provider(self):
        status, body = self._post("/api/insight", {})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["text"], "FAKE-TEXT")

    def test_empty_question_is_rejected(self):
        status, body = self._post("/api/ask", {"question": "   "})
        self.assertEqual(status, 400)

    def test_meta_reports_model(self):
        web.Handler.env = {"ANTHROPIC_API_KEY": "sk-test"}
        try:
            status, body = self._get("/api/meta")
        finally:
            web.Handler.env = {}
        self.assertEqual(status, 200)
        meta = json.loads(body)
        self.assertEqual(meta["provider"], "Anthropic")
        self.assertEqual(meta["model"], brain.DEFAULT_MODEL)
        self.assertEqual(meta["ai_mode"], "anthropic")
        self.assertNotIn(b"sk-test", body)
        self.assertFalse(meta["demo"])

    def test_meta_without_key_is_offline(self):
        meta = json.loads(self._get("/api/meta")[1])
        self.assertEqual(meta["ai_mode"], "offline")

    def test_unknown_path_404(self):
        status, _ = self._get("/nope")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
