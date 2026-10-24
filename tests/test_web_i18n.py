"""
Tests for the web dashboard's language handling:

    GET  /api/meta                       - default language + the supported list
    GET  /api/locale?lang=..             - UI strings for one language
    GET  /api/devices|device|alerts?lang - service names / threat text localized here
    POST /api/chat|insight|ask {"lang"}  - the LLM is told which language to answer in

Same recipe as test_web: a real stdlib server on an ephemeral 127.0.0.1 port and a
fake provider that CAPTURES the system/user prompts - no outbound calls, no API spend.
"""
import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from netwarden import brain, i18n, store, web

MAC = "aa:bb:cc:00:00:01"


class CapturingProvider:
    calls = []

    def complete(self, system, user, max_tokens=1200):
        CapturingProvider.calls.append((system, user))
        return "FAKE"


def seed_file(path):
    db = store.connect(path)
    store.upsert_device(db, {"ip": "192.168.1.51", "mac": MAC,
                             "vendor": "Generic IP camera", "hostname": "ipcam",
                             "randomized": False, "is_self": False})
    events = []
    for i, domain in enumerate(["xmeye.net"] * 6 + ["pool.ntp.org"] * 2):
        events.append({
            "source": "demo", "ts": f"2026-01-01T00:00:{i:02d}.000000Z",
            "client_ip": "192.168.1.51", "client_name": "ipcam", "domain": domain,
            "qtype": "A", "status": "NOERROR", "reason": "", "blocked": 0,
            "cached": 0, "upstream": "", "elapsed_ms": 1.0, "device_mac": MAC,
        })
    store.insert_events(db, events)
    db.close()


class WebI18nTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dbp = str(Path(cls.tmp.name) / "t.db")
        seed_file(cls.dbp)

        cls._orig_provider = brain.provider_from_env
        brain.provider_from_env = lambda env, db=None: CapturingProvider()

        web.Handler.db_path = cls.dbp
        web.Handler.env = {}
        web.Handler.lang = "繁體中文"   # legacy NETWARDEN_LANG value -> zh-Hant
        web.Handler.hours = 100000      # wide enough to include the 2026-01-01 seed

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

    def setUp(self):
        CapturingProvider.calls = []

    def _get(self, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        return r.status, json.loads(r.read())

    def _post(self, path, obj):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("POST", path, json.dumps(obj), {"content-type": "application/json"})
        r = c.getresponse()
        return r.status, json.loads(r.read())

    # --- meta + locale -------------------------------------------------------

    def test_meta_lists_languages_and_default(self):
        _, meta = self._get("/api/meta")
        self.assertEqual(meta["default_lang"], "zh-Hant")
        self.assertEqual([l["code"] for l in meta["languages"]], i18n.CODES)
        self.assertEqual(len(meta["languages"]), 12)
        self.assertIn({"code": "ko", "name": "한국어"}, meta["languages"])

    def test_meta_suggests_browser_language(self):
        _, meta = self._get("/api/meta", {"accept-language": "fr-CA,fr;q=0.9,en;q=0.5"})
        self.assertEqual(meta["browser_lang"], "fr")
        _, meta = self._get("/api/meta?accept=pt-BR,en")   # navigator.languages wins
        self.assertEqual(meta["browser_lang"], "pt-BR")
        _, meta = self._get("/api/meta", {"accept-language": "tlh"})
        self.assertIsNone(meta["browser_lang"])

    def test_locale_endpoint(self):
        _, loc = self._get("/api/locale?lang=de")
        self.assertEqual(loc["lang"], "de")
        self.assertEqual(loc["strings"]["ui.devices_title"], "Deine Geräte")
        _, loc = self._get("/api/locale?lang=nope")       # unsupported -> server default
        self.assertEqual(loc["lang"], "zh-Hant")
        self.assertEqual(loc["strings"]["ui.devices_title"], "你的裝置")

    def test_page_is_driven_by_locale_keys(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", "/")
        page = c.getresponse().read().decode("utf-8")
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", "/static/app.js")
        page += c.getresponse().read().decode("utf-8")
        self.assertIn('id="langsel"', page)
        self.assertIn("localStorage", page)
        self.assertIn('data-i18n="app.search_open"', page)
        self.assertIn("T('app.nav.' + s)", page)
        self.assertNotIn("你的裝置", page)    # no hard-coded UI text left in the page
        self.assertNotIn("裝置", page)

    # --- data endpoints localize at the edge ---------------------------------

    def test_devices_in_english(self):
        _, snap = self._get("/api/devices?lang=en")
        dev = snap["devices"][0]
        self.assertIn("Camera cloud/P2P (XMEye)", dev["services"])
        self.assertIn("NTP time sync", dev["services"])
        top = next(t for t in dev["top_domains"] if t["domain"] == "xmeye.net")
        self.assertEqual(top["category"], "iot")
        self.assertEqual(top["category_name"], "IoT phone-home")
        threat = next(t for t in snap["threats"] if t["domain"] == "xmeye.net")
        self.assertEqual(threat["label"], "XMEye camera cloud/P2P")
        self.assertIn("Mirai", threat["why"])
        self.assertEqual(threat["severity"], "high-risk")

    def test_devices_default_language_is_traditional(self):
        _, snap = self._get("/api/devices")
        dev = snap["devices"][0]
        self.assertIn("NTP 校時", dev["services"])
        self.assertIn("攝影機雲端/P2P (XMEye)", dev["services"])
        self.assertEqual(snap["threats"][0]["label"], "XMEye 攝影機雲端/P2P")

    def test_device_detail_in_english(self):
        status, dev = self._get(f"/api/device?mac={MAC}&lang=en")
        self.assertEqual(status, 200)
        self.assertIn("NTP time sync", dev["services"])
        self.assertEqual(dev["threats"][0]["label"], "XMEye camera cloud/P2P")

    def test_device_not_found_error_is_localized(self):
        status, body = self._get("/api/device?mac=zz&lang=en")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "Device not found")
        _, body = self._get("/api/device?mac=zz&lang=ja")
        self.assertEqual(body["error"], "デバイスが見つかりません")

    def test_alerts_in_english(self):
        _, a = self._get("/api/alerts?lang=en")
        t = next(t for t in a["threats"] if t["domain"] == "xmeye.net")
        self.assertEqual(t["label"], "XMEye camera cloud/P2P")
        self.assertIn("Mirai", t["why"])
        _, a = self._get("/api/alerts?lang=zh-Hans")
        t = next(t for t in a["threats"] if t["domain"] == "xmeye.net")
        self.assertEqual(t["label"], "XMEye 摄像头云/P2P")

    # --- the AI answers in the requested language ----------------------------

    def test_chat_with_ja_puts_japanese_into_prompt(self):
        msgs = [{"role": "user", "content": "what is unusual?"}]
        status, body = self._post("/api/chat", {"messages": msgs, "lang": "ja"})
        self.assertEqual(status, 200)
        self.assertEqual(body["text"], "FAKE")
        system, _user = CapturingProvider.calls[-1]
        self.assertIn("Japanese (日本語)", system)
        self.assertNotIn("Traditional Chinese", system)

    def test_insight_and_ask_follow_lang(self):
        self._post("/api/insight", {"lang": "de"})
        self.assertIn("German", CapturingProvider.calls[-1][0])
        self._post("/api/ask", {"question": "hi", "lang": "pt-br"})
        self.assertIn("Brazilian Portuguese", CapturingProvider.calls[-1][0])

    def test_no_lang_uses_server_default(self):
        self._post("/api/ask", {"question": "hi"})
        self.assertIn("Traditional Chinese (繁體中文)", CapturingProvider.calls[-1][0])

    def test_empty_question_error_is_localized(self):
        status, body = self._post("/api/ask", {"question": " ", "lang": "en"})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "The question is empty")


if __name__ == "__main__":
    unittest.main()
