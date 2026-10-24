"""Stage G: accessibility + graceful degradation.

- contrast of the theme tokens (both themes) computed from app.css itself
- a GET that raises answers a localized JSON 500 / 503 (busy SQLite), never a dropped
  connection or a traceback; /api/overview leaves a broken dataset out and names it
- /api/meta carries netwarden's time zone; index.html carries the "not running" texts
- an expired phone session lands on /pair?expired=1 with a plain message
- the dashboard's live regions, focus handling and wording (static checks)

Fake data only (a demo copy on an ephemeral 127.0.0.1 port); no LLM, no network.
"""
import html
import http.client
import json
import re
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from netwarden import activity, brain, cache, demo, i18n, pairing, web

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "netwarden" / "static"
LOCALES = ROOT / "netwarden" / "locales"
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"

NEW_KEYS = ("app.toasts_label", "app.load.offline_title", "app.load.offline_text", "app.load.error_title",
            "app.load.auto", "app.load.slow", "app.load.partial", "app.clock.skew", "app.clock.tz",
            "err.busy", "app.pair.session_ended")


# --- contrast (WCAG 2.x relative luminance) ---------------------------------------------
def _lum(hex_):
    h = hex_.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    def ch(v):
        v = int(v, 16) / 255
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(h[i:i + 2]) for i in (0, 2, 4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def tokens(block: str) -> dict:
    return dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{3,6})\b", block))


def themes(css: str) -> dict:
    light = re.search(r"^:root \{(.*?)^\}", css, re.S | re.M).group(1)
    dark = re.search(r'^:root\[data-theme="dark"\] \{(.*?)^\}', css, re.S | re.M).group(1)
    auto = re.search(r"@media \(prefers-color-scheme: dark\) \{(.*?)^\}", css, re.S | re.M).group(1)
    return {"light": tokens(light), "dark": tokens(dark), "auto-dark": tokens(auto)}


class ContrastTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = themes((STATIC / "app.css").read_text(encoding="utf-8"))

    def test_the_automatic_dark_theme_is_the_same_as_the_chosen_one(self):
        self.assertEqual(self.t["dark"], {k: v for k, v in self.t["auto-dark"].items() if k in self.t["dark"]})

    def test_text_is_at_least_4_5_to_1_in_both_themes(self):
        for name in ("light", "dark"):
            v = self.t[name]
            for fg in ("fg", "mut", "faint", "acc", "ok", "warn", "bad"):
                for bg in ("bg", "surface", "surface-2"):
                    with self.subTest(theme=name, fg=fg, bg=bg):
                        self.assertGreaterEqual(contrast(v[fg], v[bg]), 4.5)
            # status text on its own soft tag background, and text on solid fills
            for fg, bg in (("ok", "ok-soft"), ("warn", "warn-soft"), ("bad", "bad-soft"), ("acc", "acc-soft"),
                           ("acc-fg", "acc"), ("on-bad", "bad"), ("on-ok", "ok")):
                with self.subTest(theme=name, fg=fg, bg=bg):
                    self.assertGreaterEqual(contrast(v[fg], v[bg]), 4.5)

    def test_control_borders_are_at_least_3_to_1(self):
        for name in ("light", "dark"):
            v = self.t[name]
            for bg in ("bg", "surface", "surface-2"):
                with self.subTest(theme=name, bg=bg):
                    self.assertGreaterEqual(contrast(v["line-ctl"], v[bg]), 3.0)

    def test_status_fills_never_hard_code_white(self):
        css = (STATIC / "app.css").read_text(encoding="utf-8")
        for sel in (".count", ".btn.danger", ".toast.err"):
            rule = re.search(re.escape(sel) + r"\s*\{([^}]*)\}", css)
            self.assertIsNotNone(rule, sel)
            self.assertNotIn("#fff", rule.group(1).lower(), sel)


# --- the server ---------------------------------------------------------------------------
class DegradationWebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = str(Path(cls.tmp.name) / "g.db")
        demo.build(cls.path)
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        web.close_server(cls.srv)
        cls.tmp.cleanup()
        cache.clear()

    def setUp(self):
        cache.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))
        web.Handler.require_auth = False
        cache.clear()

    def get(self, path, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = {"user-agent": UA}
        if cookie:
            h["cookie"] = cookie
        c.request("GET", path, None, h)
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), body

    def get_json(self, path, cookie=None):
        st, h, body = self.get(path, cookie)
        return st, json.loads(body)

    # a GET that raises ------------------------------------------------------------------
    def test_failure_answer(self):
        self.assertEqual(web.failure_answer(sqlite3.OperationalError("database is locked")), (503, "busy"))
        self.assertEqual(web.failure_answer(sqlite3.OperationalError("database table is locked")), (503, "busy"))
        self.assertEqual(web.failure_answer(sqlite3.OperationalError("no such table: x")), (500, "internal"))
        self.assertEqual(web.failure_answer(KeyError("x")), (500, "internal"))

    def test_a_raising_get_answers_localized_json_not_a_dropped_connection(self):
        def boom(self_):
            raise RuntimeError("secret sk-ant-abc123 /home/user/x.py line 9")
        with mock.patch.object(web.Handler, "_get", boom), self.assertLogs("netwarden.web", "WARNING") as logs:
            st, j = self.get_json("/api/meta?lang=zh-Hant")
        self.assertNotIn("sk-ant-abc123", "\n".join(logs.output))   # logged, without the secret
        self.assertEqual(st, 500)
        self.assertEqual(j["error"], i18n.t("err.internal", "zh-Hant"))
        self.assertNotIn("sk-ant", json.dumps(j))
        self.assertNotIn("Traceback", json.dumps(j))

    def test_a_locked_database_is_503_busy(self):
        def locked(self_):
            raise sqlite3.OperationalError("database is locked")
        with mock.patch.object(web.Handler, "_get", locked), self.assertLogs("netwarden.web", "WARNING"):
            st, j = self.get_json("/api/devices?lang=en")
        self.assertEqual(st, 503)
        self.assertEqual(j["error"], i18n.t("err.busy", "en"))

    def test_overview_leaves_a_broken_dataset_out_and_names_it(self):
        orig = web.Handler._dataset

        def flaky(self_, name, db, lang):
            if name == "privacy":
                raise RuntimeError("privacy module bug")
            return orig(self_, name, db, lang)
        with mock.patch.object(web.Handler, "_dataset", flaky), self.assertLogs("netwarden.web", "WARNING"):
            st, j = self.get_json("/api/overview?lang=en")
        self.assertEqual(st, 200)
        self.assertEqual(j["failed"], ["privacy"])
        self.assertNotIn("privacy", j["parts"])
        self.assertIn("inv", j["parts"])
        self.assertNotIn("module bug", json.dumps(j))

    def test_overview_with_nothing_at_all_is_the_error_state(self):
        def locked(self_, name, db, lang):
            raise sqlite3.OperationalError("database is locked")
        with mock.patch.object(web.Handler, "_dataset", locked), self.assertLogs("netwarden.web", "WARNING"):
            st, j = self.get_json("/api/overview?lang=en")
        self.assertEqual(st, 503)
        self.assertEqual(j["error"], i18n.t("err.busy", "en"))

    def test_a_healthy_overview_has_an_empty_failed_list(self):
        st, j = self.get_json("/api/overview?lang=en")
        self.assertEqual(st, 200)
        self.assertEqual(j["failed"], [])

    # time zone + the boot texts ---------------------------------------------------------
    def test_meta_has_the_time_zone(self):
        st, j = self.get_json("/api/meta")
        self.assertEqual(st, 200)
        self.assertIsInstance(j["tz"], str)
        self.assertTrue(j["tz"])
        self.assertIsInstance(j["tz_offset_min"], int)
        self.assertLessEqual(abs(j["tz_offset_min"]), 14 * 60)

    def test_tz_info(self):
        from datetime import timedelta, timezone
        self.assertEqual(web.tz_info(timezone(timedelta(hours=8))),
                         {"tz": activity.tz_label(timezone(timedelta(hours=8))), "tz_offset_min": 480})
        self.assertEqual(web.tz_info(timezone.utc)["tz_offset_min"], 0)

    def test_index_carries_the_not_running_texts_of_every_language(self):
        st, _h, body = self.get("/")
        self.assertEqual(st, 200)
        page = body.decode("utf-8")
        self.assertNotIn("__OFFLINE__", page)
        m = re.search(r'<script type="application/json" id="off-texts">(.*?)</script>', page, re.S)
        self.assertIsNotNone(m)
        texts = json.loads(m.group(1))
        self.assertEqual(set(texts), {c for c, _n, _l in i18n.LANGS})
        for code, t in texts.items():
            self.assertEqual(set(t), set(web.OFFLINE_KEYS), code)
            self.assertTrue(all(t.values()), code)
        self.assertEqual(texts["zh-Hant"]["title"], i18n.t("app.offline.title", "zh-Hant"))

    def test_offline_texts_json_cannot_close_its_script_element(self):
        with mock.patch.object(web, "offline_texts", lambda: {"en": {"title": "</script><b>"}}):
            out = web.offline_texts_json()
        self.assertNotIn("</script", out)
        self.assertEqual(json.loads(out)["en"]["title"], "</script><b>")

    # an expired phone session -----------------------------------------------------------
    def _remote(self):
        web.Handler.is_local_client = staticmethod(lambda ip: False)
        web.Handler.require_auth = True

    def test_a_stale_cookie_goes_to_pair_expired(self):
        self._remote()
        stale = f"{pairing.COOKIE}={'A' * 43}"
        st, h, _ = self.get("/", cookie=stale)
        self.assertEqual(st, 303)
        self.assertEqual(h["location"], "/pair?expired=1")
        st, j = self.get_json("/api/meta", cookie=stale)
        self.assertEqual(st, 401)
        self.assertTrue(j["pair"])
        self.assertTrue(j["expired"])

    def test_no_cookie_is_a_plain_pair_page(self):
        self._remote()
        st, h, _ = self.get("/")
        self.assertEqual(st, 303)
        self.assertEqual(h["location"], "/pair")
        st, j = self.get_json("/api/meta")
        self.assertEqual(st, 401)
        self.assertFalse(j["expired"])

    def test_pair_expired_says_so_in_the_phones_language(self):
        self._remote()
        for code in ("en", "zh-Hant", "ja"):
            st, _h, body = self.get(f"/pair?expired=1&lang={code}")
            self.assertEqual(st, 200)
            page = body.decode("utf-8")
            self.assertIn('class="pair-expired" role="status"', page)
            self.assertIn(html.escape(i18n.t("app.pair.session_ended", code)), page)
        st, _h, body = self.get("/pair?lang=en")
        self.assertNotIn("pair-expired", body.decode("utf-8"))

    def test_render_page_expired_flag(self):
        self.assertIn("pair-expired", pairing.render_page("en", expired=True))
        self.assertNotIn("pair-expired", pairing.render_page("en"))


# --- the dashboard (static checks) --------------------------------------------------------
class DashboardA11yTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (STATIC / "app.js").read_text(encoding="utf-8")
        cls.css = (STATIC / "app.css").read_text(encoding="utf-8")
        cls.index = (STATIC / "index.html").read_text(encoding="utf-8")

    def test_quiet_live_regions(self):
        # one polite + one assertive region, announced through speak(); toasts themselves
        # are a labelled region with no role/aria-live of their own (no double reading)
        self.assertIn('<div id="say" class="sr" aria-live="polite" aria-atomic="true">', self.index)
        self.assertIn('<div id="shout" class="sr" role="alert" aria-atomic="true">', self.index)
        toasts = re.search(r'<div id="toasts"[^>]*>', self.index).group(0)
        self.assertNotIn("aria-live", toasts)
        self.assertIn('data-i18n-aria="app.toasts_label"', toasts)
        self.assertIn("function speak(", self.js)

    def test_toasts_pause_while_hovered_or_focused(self):
        body = re.search(r"\nfunction toast\(.*?\n\}", self.js, re.S).group(0)
        for ev in ("mouseenter", "focusin", "mouseleave", "focusout"):
            self.assertIn(ev, body)

    def test_dialogs_are_divs_with_a_name(self):
        # ARIA in HTML: role=dialog is not allowed on <aside>
        for el in ("drawer", "chatpanel"):
            tag = re.search(r'<(\w+) id="%s"[^>]*>' % el, self.index)
            self.assertEqual(tag.group(1), "div", el)
            self.assertIn('role="dialog"', tag.group(0))
            self.assertIn("aria-labelledby=", tag.group(0))

    def test_busy_main_and_page_titles(self):
        self.assertIn('<main id="main" tabindex="-1" aria-busy="true">', self.index)
        self.assertIn("$('#main').setAttribute('aria-busy', String(S.skel));", self.js)
        self.assertIn("' - netwarden'", self.js)       # WCAG 2.4.2: the tab names the page

    def test_no_raw_error_text_reaches_the_page(self):
        self.assertIn("function errText(", self.js)
        self.assertIn("T('err.internal')", self.js)
        self.assertNotIn("isNetErr(e) ? T('app.offline') : e.message", self.js)

    def test_focus_waits_for_the_drawer_to_be_focusable(self):
        self.assertIn("function focusSoon(", self.js)
        self.assertIn("focusSoon('#drawer [data-act=\"close\"]')", self.js)
        self.assertIn("const chatIsSheet = ", self.js)
        self.assertIn("chatIsSheet()) { trapFocus(e, [$('#chatpanel')]); return; }", self.js)

    def test_recovery_states(self):
        for needle in ("function loadFailed(", "function bootFailed(", "data-act=\"boot-retry\"",
                       "RETRY_MS", "app.load.partial", "app.clock.skew", "location.replace(url('/pair?expired=1'))"):
            self.assertIn(needle, self.js)
        self.assertIn('id="off-texts">__OFFLINE__</script>', self.index)

    def test_reduced_motion_and_text_spacing(self):
        self.assertIn("prefers-reduced-motion: reduce", self.css)
        # buttons grow with their text (WCAG 1.4.12): a min-height, not a fixed height
        btn = re.search(r"^\.btn \{([^}]*)\}", self.css, re.M).group(1)
        self.assertIn("min-height", btn)
        self.assertNotRegex(btn, r"(?<!-)height:\s*\d")

    def test_phone_primary_actions_are_44px(self):
        self.assertRegex(self.css, r"\.btn \{ min-height: 44px")

    def test_still_two_inner_html_writes(self):
        self.assertEqual(self.js.count(".innerHTML ="), 2)

    def test_status_is_not_colour_alone_in_the_live_indicator(self):
        # reconnecting = a hollow ring, paused = a bar: a shape, not only a colour; the
        # word stays for screen readers on phones (visually hidden, not display:none)
        self.assertRegex(self.css, r"\.live\.st-reconnecting i \{[^}]*background: transparent; border:")
        self.assertRegex(self.css, r"\.live\.st-paused i \{[^}]*width: 4px")
        self.assertNotRegex(self.css, r"\.live \.lbl \{ display: none")


class LocaleTests(unittest.TestCase):
    def test_new_keys_in_every_language(self):
        for code, _n, _l in i18n.LANGS:
            data = json.loads((LOCALES / f"{code}.json").read_text(encoding="utf-8"))
            for key in NEW_KEYS:
                with self.subTest(lang=code, key=key):
                    self.assertTrue(data.get(key))
            self.assertIn("{d}", data["app.clock.skew"], code)
            self.assertIn("{tz}", data["app.clock.tz"], code)


if __name__ == "__main__":
    unittest.main()
