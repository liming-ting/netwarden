"""
Stage E1: the dashboard page (netwarden/static) and the data it reads.

- static serving: content types, CSP, ETag/304, cache-busting, no path traversal
- the page itself: offline-only, every string from the locales, escaping helpers, the AI
  only behind explicit actions
- GET /api/inventory (dashboard.inventory): the whole inventory with online / new /
  first & last seen, user notes, and localized like the rest of the API

No LLM (offline env), servers on ephemeral 127.0.0.1 ports, a throw-away demo DB.
"""
import http.client
import json
import re
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

from netwarden import brain, dashboard, demo, i18n, store, web


def _mac(hostname):
    return next(d["mac"] for d in demo.DEVICES if d["hostname"] == hostname)


CHROMECAST, CAM, VACUUM = (_mac(h) for h in ("Chromecast-Living", "ipcam", "roborock-vacuum"))


class _Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        web.Handler.db_path = str(cls.path)
        web.Handler.env = {brain.OFFLINE_ENV: "1"}
        web.Handler.lang = "zh-Hant"
        web.Handler.hours = 24
        web.Handler.loops = None
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def raw(self, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()

    def json(self, path):
        st, _h, body = self.raw(path)
        return st, json.loads(body)

    def post(self, path, obj):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request("POST", path, json.dumps(obj), {"content-type": "application/json"})
        r = c.getresponse()
        return r.status, json.loads(r.read())


class StaticServingTests(_Server):
    def test_index_is_html_with_csp_and_versioned_assets(self):
        st, h, body = self.raw("/")
        self.assertEqual(st, 200)
        self.assertEqual(h["content-type"], "text/html; charset=utf-8")
        self.assertIn("script-src 'self'", h["content-security-policy"])
        self.assertIn("frame-ancestors 'none'", h["content-security-policy"])
        self.assertEqual(h["x-content-type-options"], "nosniff")
        self.assertEqual(h["cache-control"], "no-cache")
        page = body.decode()
        self.assertNotIn("__V__", page)
        v = web.asset_version()
        self.assertIn(f"/static/app.js?v={v}", page)
        self.assertIn(f"/static/app.css?v={v}", page)
        self.assertEqual(self.raw("/index.html")[0], 200)

    def test_assets_have_types_etags_and_cache_rules(self):
        for name, ctype in (("app.js", "text/javascript"), ("app.css", "text/css"),
                            ("icon.svg", "image/svg+xml")):
            st, h, body = self.raw("/static/" + name)
            self.assertEqual(st, 200, name)
            self.assertTrue(h["content-type"].startswith(ctype), name)
            self.assertEqual(h["cache-control"], "no-cache")     # no ?v= -> revalidate
            st, h2, body2 = self.raw("/static/" + name, {"If-None-Match": h["etag"]})
            self.assertEqual((st, body2), (304, b""))
        _st, h, _b = self.raw("/static/app.js?v=" + web.asset_version())
        self.assertIn("immutable", h["cache-control"])
        _st, h, _b = self.raw("/static/app.js?v=stale")
        self.assertEqual(h["cache-control"], "no-cache")

    def test_no_path_traversal_or_hidden_files(self):
        for path in ("/static/../web.py", "/static/..%2fweb.py", "/static/%2e%2e/web.py",
                     "/static/../../.env", "/static/locales/en.json", "/static/.hidden",
                     "/static/", "/static/web.py", "/static/app.js/x", "/static/..\\web.py",
                     "/static/index.html%00.js"):
            st, _h, body = self.raw(path)
            self.assertEqual(st, 404, path)
            self.assertNotIn(b"import", body)
        for bad in ("../web.py", "..", ".env", "sub/app.js", "a\\b.js", "x.py", "", "app.js\0"):
            self.assertIsNone(web.static_file(bad), bad)

    def test_api_responses_are_not_cached_or_sniffed(self):
        _st, h, _b = self.raw("/api/meta")
        self.assertEqual(h["cache-control"], "no-store")
        self.assertEqual(h["x-content-type-options"], "nosniff")


class PageSourceTests(unittest.TestCase):
    """Static checks on the page files themselves (no server needed)."""

    @classmethod
    def setUpClass(cls):
        cls.js = web.static_file("app.js")[0].decode()
        cls.css = web.static_file("app.css")[0].decode()
        cls.html = web.static_file("index.html")[0].decode()

    def test_fully_offline_no_external_urls(self):
        for name, text in (("app.js", self.js), ("app.css", self.css), ("index.html", self.html)):
            self.assertIsNone(re.search(r"https?://", text), name)
            self.assertNotIn("@import", text)
            self.assertNotIn("//cdn", text)
        self.assertNotIn("<script>", self.html)          # CSP: no inline scripts
        self.assertNotIn(" onclick=", self.html + self.js)

    def test_every_used_key_exists_in_every_language(self):
        keys = set(re.findall(r"T\(\s*'([\w.]+)'", self.js))
        keys |= set(re.findall(r'data-i18n(?:-placeholder|-aria)?="([\w.]+)"', self.html))
        keys |= {"app.nav." + s for s in ("overview", "devices", "security", "privacy",
                                          "activity", "ai", "system")}
        keys = {k for k in keys if not k.endswith((".", "_"))}   # dynamic prefixes
        self.assertGreater(len(keys), 150)
        for k in sorted(keys):
            self.assertTrue(i18n.has(k), k)
        en = i18n.strings("en")
        for code in i18n.CODES:
            s = i18n.strings(code)
            with self.subTest(lang=code):
                self.assertEqual([k for k in keys if k not in s], [])
                if code != "en":   # really translated, not English copies
                    for k in ("app.nav.devices", "app.ov.all_good", "app.toast.undo",
                              "app.ob.title", "app.dev.empty"):
                        self.assertNotEqual(s[k], en[k], (code, k))

    def test_escaping_discipline(self):
        # One escaping template tag; raw innerHTML only inside morph()'s <template> and
        # for the language list (escaped by hand).
        self.assertIn("function html(strs, ...vals)", self.js)
        self.assertIn("replace(/[&<>\"']/g", self.js)
        assignments = re.findall(r"\.innerHTML\s*=", self.js)
        self.assertEqual(len(assignments), 2, assignments)
        self.assertIn("tpl.innerHTML = part(content)", self.js)
        self.assertIn("`<option value=\"${esc(l.code)}\">${esc(l.name)}</option>`", self.js)
        self.assertNotIn("insertAdjacentHTML", self.js)
        self.assertNotIn("outerHTML", self.js)
        self.assertNotIn("eval(", self.js)
        self.assertNotIn("window.alert", self.js)
        self.assertNotIn("prompt(", self.js)

    def test_ai_only_behind_explicit_actions(self):
        # The one LLM endpoint the page uses appears once, inside chat(); nothing on load
        # or refresh. (The older /api/insight and /api/chat stay on the server for scripts.)
        self.assertEqual(self.js.count("'/api/chat/stream'"), 1)
        for old in ("'/api/insight'", "'/api/chat'", "'/api/ask'"):
            self.assertNotIn(old, self.js)
        chat = self.js[self.js.index("async function chat(kind)"):]
        chat = chat[:chat.index("\n}\n")]
        self.assertIn("'/api/chat/stream'", chat)
        self.assertIn("new AbortController()", chat)     # the Stop button
        refresh = self.js[self.js.index("const DATASETS"):self.js.index("function schedule()")]
        self.assertNotIn("insight", refresh)
        self.assertNotIn("/api/chat", refresh)
        self.assertNotIn("chat(", refresh)
        ask = self.js[self.js.index("case 'ask':"):]
        ask = ask[:ask.index("break;")]
        self.assertIn("openChat(", ask)                   # "Ask AI" only pre-fills the chat
        self.assertNotIn("chat('send')", ask)

    def test_chat_ux(self):
        for needle in ("sessionStorage.setItem(CHAT_KEY", "data-act=\"copy-msg\"",
                       "data-act=\"chat-stop\"", "data-act=\"chat-retry\"",
                       "e.key === 'Enter' && !e.shiftKey && !e.isComposing",
                       "lang: S.lang", "function suggestions()", "navigator.clipboard"):
            self.assertIn(needle, self.js)
        self.assertIn('id="chatpanel"', self.html)
        self.assertIn('role="dialog"', self.html)
        self.assertIn('id="btnChat"', self.html)
        # md(): escapes first, then adds a few tags of its own
        md = self.js[self.js.index("function md("):]
        md = md[:md.index("\n}\n")]
        self.assertLess(md.index("esc("), md.index("<strong>"))

    def test_notifications_are_opt_in(self):
        # Permission is only requested from the toggle's click handler, never on load.
        self.assertEqual(self.js.count("Notification.requestPermission"), 1)
        toggle = self.js[self.js.index("async function toggleNotify()"):]
        toggle = toggle[:toggle.index("\n}\n")]
        self.assertIn("Notification.requestPermission", toggle)
        self.assertIn("case 'notify':", self.js)
        self.assertIn('role="switch"', self.js)
        self.assertIn("NOTIFIED_KEY", self.js)            # never the same alert twice
        boot = self.js[self.js.rindex("loadChat()"):]
        self.assertNotIn("requestPermission", boot)

    def test_keyboard_sheet_and_go_keys(self):
        self.assertIn("e.key === '?'", self.js)
        self.assertIn("const GO_KEYS = {", self.js)
        for letter, section in (("o", "overview"), ("d", "devices"), ("s", "security"),
                                ("p", "privacy"), ("a", "activity"), ("i", "ai"), ("y", "system")):
            self.assertIn(f"{letter}: '{section}'", self.js)
        self.assertIn('id="keysheet"', self.html)
        self.assertIn('aria-modal="true"', self.html)
        self.assertIn("function trapFocus(", self.js)

    def test_routes_shortcuts_theme_and_motion(self):
        for s in ("overview", "devices", "security", "privacy", "activity", "ai", "system"):
            self.assertIn(f"'{s}'", self.js)
        for needle in ("'#/device/'", "'#/service/'", "'#/domain/'", "hashchange",
                       "visibilitychange", "REFRESH_MS = 30000", "Intl.RelativeTimeFormat",
                       "Intl.NumberFormat", "e.key === '/'", "e.ctrlKey || e.metaKey",
                       "netwarden.theme", "aria-sort", "aria-activedescendant"):
            self.assertIn(needle, self.js)
        self.assertIn("prefers-reduced-motion", self.css)
        self.assertIn("prefers-color-scheme: dark", self.css)
        self.assertIn(':root[data-theme="dark"]', self.css)
        self.assertIn(":focus-visible", self.css)
        self.assertIn("max-width: 760px", self.css)       # mobile layout


class InventoryApiTests(_Server):
    def test_inventory_lists_every_known_device(self):
        st, inv = self.json("/api/inventory?lang=en")
        self.assertEqual(st, 200)
        macs = {d["mac"] for d in inv["devices"]}
        self.assertEqual(macs, {d["mac"] for d in demo.DEVICES})
        _st, snap = self.json("/api/devices?lang=en")
        self.assertNotIn(CHROMECAST, {d["mac"] for d in snap["devices"]})   # no DNS ...
        cc = next(d for d in inv["devices"] if d["mac"] == CHROMECAST)       # ... still listed
        self.assertEqual((cc["queries"], cc["type"]), (0, "streaming"))
        self.assertEqual(cc["type_info"]["type_name"], "Streaming device")
        self.assertEqual(inv["known_devices"], len(demo.DEVICES))
        self.assertEqual(inv["total_queries"], snap["total_queries"])
        for d in inv["devices"]:
            for key in ("first_seen", "last_seen", "last_active", "online", "new",
                        "randomized", "threat_count", "risky_ports", "type_info"):
                self.assertIn(key, d, (d["mac"], key))

    def test_inventory_flags(self):
        _st, inv = self.json("/api/inventory?lang=en")
        by = {d["mac"]: d for d in inv["devices"]}
        self.assertTrue(by[VACUUM]["new"])                 # first seen 6 h ago in the story
        self.assertFalse(by[CAM]["new"])
        self.assertGreater(by[CAM]["threat_count"], 0)
        self.assertGreaterEqual(by[CAM]["risky_ports"], 1)  # telnet 23 + rtsp 554
        self.assertTrue(any(d["online"] for d in inv["devices"]))
        self.assertEqual(by[CAM]["room"], "門口")
        top = by[CAM]["top_domains"][0]
        self.assertEqual(top["service_id"], "svc.xmeye")    # links the page to /api/service
        st, svc = self.json("/api/service?name=svc.xmeye&lang=en")
        self.assertEqual(st, 200)
        self.assertIn(CAM, {d["mac"] for d in svc["devices"]})

    def test_inventory_is_localized_and_follows_user_notes(self):
        _st, inv = self.json("/api/inventory?lang=zh-Hant")
        cc = next(d for d in inv["devices"] if d["mac"] == CHROMECAST)
        self.assertEqual(cc["type_info"]["type_name"], i18n.t("devtype.streaming", "zh-Hant"))
        self.assertEqual(self.post("/api/profile", {"mac": CHROMECAST, "owner": "<b>x</b>"})[0], 200)
        self.assertEqual(self.post("/api/ack", {"mac": CHROMECAST})[0], 200)
        try:
            _st, inv = self.json("/api/inventory?lang=en")
            cc = next(d for d in inv["devices"] if d["mac"] == CHROMECAST)
            self.assertEqual(cc["owner"], "<b>x</b>")     # stored as typed; the page escapes
            self.assertTrue(cc["trusted"])
        finally:
            self.post("/api/profile", {"mac": CHROMECAST, "owner": ""})
            self.post("/api/unack", {"mac": CHROMECAST})

    def test_device_detail_has_first_and_last_seen(self):
        st, d = self.json("/api/device?mac=" + CHROMECAST + "&lang=en")
        self.assertEqual(st, 200)
        self.assertTrue(d["first_seen"] and d["last_seen"])
        self.assertIn("randomized", d)


class InventoryUnitTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")
        self.now = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
        iso = lambda **kw: dashboard._iso(self.now - timedelta(**kw))  # noqa: E731
        store.upsert_device(self.db, {"mac": "aa:aa", "ip": "10.0.0.2", "vendor": "Acme",
                                      "hostname": "old-tv"}, seen=iso(days=5))
        self.db.execute("UPDATE devices SET last_seen = ? WHERE mac = 'aa:aa'", (iso(hours=3),))
        store.upsert_device(self.db, {"mac": "bb:bb", "ip": "10.0.0.3", "vendor": "Beta",
                                      "hostname": None},
                            seen=iso(minutes=5))
        self.db.commit()

    def test_online_new_and_bare_devices(self):
        snap = {"devices": [], "threats": [], "window_hours": 24}
        inv = dashboard.inventory(self.db, snap, "en", hours=24, now=self.now)
        by = {d["mac"]: d for d in inv["devices"]}
        self.assertEqual(set(by), {"aa:aa", "bb:bb"})
        self.assertFalse(by["aa:aa"]["online"])   # last seen 3 h ago
        self.assertFalse(by["aa:aa"]["new"])      # first seen 5 days ago
        self.assertTrue(by["bb:bb"]["online"])
        self.assertTrue(by["bb:bb"]["new"])
        self.assertEqual(by["aa:aa"]["name"], "old-tv")
        self.assertEqual(by["aa:aa"]["queries"], 0)
        self.assertEqual(inv["online_minutes"], dashboard.ONLINE_MINUTES)

    def test_snapshot_devices_win_and_risky_ports_count(self):
        snap = {"devices": [{"mac": "aa:aa", "name": "TV", "queries": 9, "type": "tv",
                             "open_ports": [{"port": 23, "risk": "high"},
                                            {"port": 443, "risk": "low"}]},
                            {"mac": None, "name": "10.0.0.9", "queries": 1}],
                "threats": [{"mac": "aa:aa"}, {"mac": "aa:aa"}], "window_hours": 24}
        inv = dashboard.inventory(self.db, snap, "en", hours=24, now=self.now)
        tv = inv["devices"][0]
        self.assertEqual((tv["mac"], tv["name"], tv["queries"]), ("aa:aa", "TV", 9))
        self.assertEqual((tv["risky_ports"], tv["threat_count"]), (1, 2))
        self.assertTrue(any(d["mac"] is None and not d["online"] for d in inv["devices"]))


if __name__ == "__main__":
    unittest.main()
