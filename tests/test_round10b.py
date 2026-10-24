"""Round 10b: the static live demo polished - the made-up family's names follow the UI
language (demo.HOUSEHOLDS, one home per script in the static build), a demo label for the
assistant, saved answers for every device's "Ask AI about this device", "not part of the
demo" instead of "Server error (HTTP 404)", a manifest id that belongs to the site's own
path, and a first-visit welcome card (static demo only)."""
import json
import re
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

from netwarden import demo, i18n, store, web
from test_round9_w import APP, B, ROOT

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
CJK = re.compile(r"[㐀-鿿]")


def _user_text(path: Path) -> dict:
    """The family's own words as a demo DB holds them."""
    db = sqlite3.connect(path)
    try:
        return {
            "people": sorted(r[0] for r in db.execute("SELECT name FROM people")),
            "owners": sorted({r[0] for r in db.execute("SELECT owner FROM device_profiles WHERE owner IS NOT NULL")}),
            "rooms": sorted({r[0] for r in db.execute("SELECT room FROM device_profiles WHERE room IS NOT NULL")}),
            "rules": sorted(r[0] for r in db.execute("SELECT name FROM bedtime_rules")),
            "announced": sorted({r[0] for r in db.execute("SELECT name FROM device_identity WHERE name IS NOT NULL")}),
        }
    finally:
        db.close()


class Households(unittest.TestCase):
    """One table of the family's words; a DB keeps the household it was seeded with."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="nw_10b_")
        cls.dir = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_language_to_household(self):
        self.assertEqual(demo.household_for("zh-Hant"), "zh-Hant")
        self.assertEqual(demo.household_for("zh-TW"), "zh-Hant")
        self.assertEqual(demo.household_for("zh-Hans"), "zh-Hans")
        for code, _n, _l in i18n.LANGS:
            if not code.startswith("zh"):
                self.assertEqual(demo.household_for(code), "en", code)
        self.assertEqual(demo.household_for(None), demo.DEFAULT_HOUSEHOLD)

    def test_every_household_has_the_same_words(self):
        keys = set(demo.HOUSEHOLDS[demo.DEFAULT_HOUSEHOLD])
        for name, h in demo.HOUSEHOLDS.items():
            self.assertEqual(set(h), keys, name)
            self.assertEqual(len(set(h.values())), len(h), name)   # no two words the same
        self.assertFalse(any(CJK.search(v) for v in demo.HOUSEHOLDS["en"].values()))
        simp = "".join(demo.HOUSEHOLDS["zh-Hans"].values())
        trad = "".join(demo.HOUSEHOLDS["zh-Hant"].values())
        self.assertFalse(set(simp) & set(i18n.TRADITIONAL_ONLY), simp)
        self.assertFalse(set(trad) & set(i18n.SIMPLIFIED_ONLY), trad)

    def test_built_in_values_unchanged(self):
        # earlier stages (and data/demo.db) know the Taiwanese household by these
        self.assertEqual(demo.PROFILES["b2:55:3a:7c:10:9b"], ("媽媽", None))
        self.assertEqual(demo.DEMO_RULE["name"], "上學日晚上")
        self.assertEqual(set(demo.DEMO_PEOPLE), {"爸爸", "媽媽", "小孩"})
        self.assertIn("爸爸的 iPhone", [i[2] for i in demo.IDENTITY])

    def test_english_home(self):
        path = self.dir / "en.db"
        stats = demo.build(path, now=NOW, household="en")
        self.assertEqual(stats["household"], "en")
        got = _user_text(path)
        self.assertEqual(got["people"], ["Dad", "Kid", "Mom"])
        self.assertEqual(got["rules"], ["School nights"])
        self.assertIn("Kid's room", got["rooms"])
        self.assertIn("Dad's iPhone", got["announced"])
        for words in got.values():
            self.assertFalse([w for w in words if CJK.search(w)], words)
        # the household sticks: a later build asking for another keeps the first
        self.assertEqual(demo.build(path, now=NOW, household="zh-Hant")["household"], "en")
        self.assertEqual(_user_text(path)["announced"], got["announced"])

    def test_simplified_home(self):
        path = self.dir / "hans.db"
        demo.build(path, now=NOW, household="zh-Hans")
        got = _user_text(path)
        self.assertEqual(got["people"], sorted(["爸爸", "妈妈", "小孩"]))
        self.assertIn("客厅", got["rooms"])

    def test_default_and_older_dbs_are_the_taiwanese_home(self):
        path = self.dir / "default.db"
        self.assertEqual(demo.build(path, now=NOW)["household"], "zh-Hant")
        self.assertIn("媽媽", _user_text(path)["people"])
        db = store.connect(path)    # a demo DB from before round 10b: no meta yet
        db.execute("DELETE FROM meta WHERE key = 'demo_household'")
        db.commit()
        db.close()
        self.assertEqual(demo.build(path, now=NOW, household="en")["household"], "zh-Hant")

    def test_unknown_household_refused(self):
        with self.assertRaises(ValueError):
            demo.build(self.dir / "x.db", now=NOW, household="xx")


class StaticBuild(unittest.TestCase):
    """A small build in three languages = three households."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="nw_10b_site_")
        cls.out = Path(cls.tmp.name) / "site"
        cls.stats = B.build(cls.out, now=NOW, langs=["en", "zh-Hant", "zh-Hans"], quick=True,
                            site_url="https://example.invalid/netwarden/", log=lambda *a: None)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def read(self, rel):
        return (self.out / rel).read_text(encoding="utf-8")

    def test_names_follow_the_language(self):
        for lang, want in (("en", "Mom"), ("zh-Hant", "媽媽"), ("zh-Hans", "妈妈")):
            people = [p["name"] for p in json.loads(self.read(B.static_name("/api/people?lang=" + lang)))["people"]]
            self.assertIn(want, people, lang)
        # nothing the English page reads holds a Chinese family word: pages, drawers,
        # reports, exports, saved answers
        words = {v for k in ("zh-Hant", "zh-Hans") for v in demo.HOUSEHOLDS[k].values()}
        for p in (self.out / "demo-data" / "en").rglob("*"):
            if p.is_file():
                text = p.read_text(encoding="utf-8")
                for w in words:
                    self.assertNotIn(w, text, (p.name, w))
        hans = "".join(p.read_text(encoding="utf-8") for p in (self.out / "demo-data" / "zh-Hans").rglob("*.json"))
        self.assertNotIn("媽媽", hans)
        self.assertIn("妈妈", hans)

    def test_device_answers(self):
        for lang in ("en", "zh-Hant", "zh-Hans"):
            idx = json.loads(self.read(B.chat_index(lang)))
            self.assertTrue(idx["devices"], lang)
            for mac in idx["devices"]:
                self.assertTrue((self.out / B.static_name(f"/api/device?mac={mac}&lang={lang}")).exists())
                sse = self.read(B.device_chat_name(mac, lang))
                self.assertIn("event: done", sse)
                self.assertNotIn("--offline-ai", sse)
                self.assertNotIn("ANTHROPIC_API_KEY", sse)
        # review: no saved answer says "cannot answer" to the device question or claims it
        # was computed on the visitor's computer; each says it was saved
        for lang in ("en", "zh-Hant", "zh-Hans"):
            files = list((self.out / "demo-data" / lang / "chat").glob("*"))
            self.assertTrue(files, lang)
            for p in files:
                if p.suffix == ".json":
                    continue
                text = "".join(json.loads(f[6:]).get("t", "") for f in p.read_text(encoding="utf-8").split("\n\n")
                               if f.startswith("data: ") and isinstance(json.loads(f[6:]), dict))
                self.assertNotIn(i18n.t("offline.title", lang), text, p.name)
                self.assertNotIn(i18n.t("intent.title", lang), text, p.name)
                self.assertTrue(text.startswith(i18n.t("app.demo.answer_title", lang)), (p.name, text[:80]))
                # every saved answer is to a question the page offers: none says it cannot answer
                self.assertNotIn(i18n.t("offline.question_note", lang), text, (lang, p.name))
            self.assertTrue(json.loads(self.read(B.chat_index(lang)))["devices"], lang)

    def test_device_name_like_the_page(self):
        self.assertEqual(B.device_name({"name": "Printer", "vendor": "HP"}, "en"), "Printer")
        self.assertEqual(B.device_name({"ident": {"name": "TV"}, "vendor": "Samsung"}, "en"), "TV")
        self.assertEqual(B.device_name({"type": "phone", "type_info": {"type_name": "Phone"}, "owner": "Mom"}, "en"),
                         "Phone · Mom")
        self.assertEqual(B.device_name({"randomized": True}, "en"), i18n.t("app.d.private_device", "en"))

    def test_manifest_belongs_to_the_site_path(self):
        man = json.loads(self.read("static/manifest.webmanifest"))
        self.assertEqual(man["id"], "/netwarden/")
        site = "https://example.invalid/netwarden/"
        man_url = urljoin(site, "static/manifest.webmanifest")
        self.assertEqual(urljoin(man_url, man["start_url"]), site)
        self.assertEqual(urljoin(man_url, man["scope"]), site)
        self.assertEqual(urljoin(site, man["id"]), site)        # id: against the origin
        self.assertEqual(B.demo_manifest(b'{"start_url": "../", "scope": "../"}', "https://x.example"),
                         B.demo_manifest(b'{"start_url": "../", "scope": "../"}', "https://x.example/"))
        with self.assertRaises(B.BuildError):
            B.demo_manifest(b'{"start_url": "/", "scope": "/"}', site)


class RealManifest(unittest.TestCase):
    """The app id defaults to start_url: the root of its own origin, or the ingress base."""

    def test_relative_and_without_id(self):
        man = json.loads(web.static_file("manifest.webmanifest")[0])
        self.assertNotIn("id", man)   # "/" would be the whole origin (the ingress' HA, github.io)
        for base in ("http://192.168.1.20:8787/", "http://ha.local:8123/api/hassio_ingress/abc123/"):
            man_url = urljoin(base, "static/manifest.webmanifest")
            self.assertEqual(urljoin(man_url, man["start_url"]), base)
            self.assertEqual(urljoin(man_url, man["scope"]), base)


class PageCode(unittest.TestCase):
    """app.js: the demo-only parts stay behind DEMO; the real app's wording stays."""

    def fn(self, name, n=1600):
        i = APP.index("function " + name + "(")
        return APP[i:i + n]

    def test_ai_label(self):
        self.assertIn("if (DEMO) return T('app.demo.ai_mode');", self.fn("aiBadge", 200))
        self.assertIn("ui.ai_offline_forced", self.fn("aiBadge", 400))
        self.assertIn("ui.ai_offline_chosen", self.fn("aiBadge", 400))

    def test_not_found(self):
        f = self.fn("httpMsg", 300)
        self.assertIn("status === 404", f)
        self.assertIn("T(DEMO ? 'app.demo.not_found' : 'err.not_found')", f)
        self.assertEqual(APP.count("T('app.err.http'"), 1)     # only through httpMsg
        self.assertIn("return DEMO ?", self.fn("demoBack", 200))
        self.assertEqual(APP.count("${demoBack()}"), 2)          # device + service/domain drawers

    def test_device_answer(self):
        f = self.fn("demoAnswer", 900)
        self.assertIn("window.NWDemo.chatFile('device', ctx.mac, S.lang)", f)
        self.assertIn("T('app.ask_prefill', { name: ctx.name, mac: ctx.mac })", f)

    def test_welcome_is_demo_only(self):
        f = self.fn("demoWelcome")
        self.assertTrue(f.split("\n")[1].strip().startswith("if (!DEMO ||"))
        self.assertIn("aria-labelledby=", f)
        self.assertIn("localStorage.setItem(DEMO_WELCOME_KEY, '1')", self.fn("demoWelcomeHide", 300))
        self.assertIn("${demoWelcome()}", self.fn("viewOverview", 1200))
        self.assertIn("case 'demo-welcome-hide': demoWelcomeHide(); break;", APP)

    def test_strings_in_every_locale(self):
        keys = ("app.demo.ai_mode", "app.demo.not_found", "app.demo.back", "app.demo.w.title", "app.demo.w.text",
                "app.demo.w.try", "app.demo.w.threat", "app.demo.w.bypass", "app.demo.w.night", "app.demo.w.hide",
                "app.demo.w.hidden")
        en = json.loads((ROOT / "netwarden" / "locales" / "en.json").read_text(encoding="utf-8"))
        for p in sorted((ROOT / "netwarden" / "locales").glob("*.json")):
            loc = json.loads(p.read_text(encoding="utf-8"))
            for k in keys:
                self.assertTrue(loc.get(k, "").strip(), (p.name, k))
                if p.stem != "en":
                    self.assertNotEqual(loc[k], en[k], (p.name, k))
            for k in ("app.demo.w.threat", "app.demo.w.bypass", "app.demo.w.night"):
                self.assertIn("{name}", loc[k], (p.name, k))
            self.assertNotIn("--offline-ai", loc["app.demo.ai_mode"])


class ReviewFixes(unittest.TestCase):
    """Review of round 10b: the device question gets no "cannot answer" note, the add-on's
    offline_ai option is named as such, the demo's saved answers say they were saved."""

    def test_device_question_recognised_in_every_language(self):
        from netwarden import offline_ai
        mac = "aa:bb:cc:00:00:01"
        self.assertEqual(len(i18n.CODES), 12)
        for lang in i18n.CODES:
            for name in ("ipcam", "Phone · Mom", "a (b) [c] *d*", "媽媽的 iPhone"):
                q = i18n.t("app.ask_prefill", lang, name=name, mac=mac)
                self.assertTrue(offline_ai.asks_about_focus(q, lang, mac), (lang, name))
                self.assertTrue(offline_ai.asks_about_focus("  " + q.upper() + "\n", lang, mac), lang)
                self.assertFalse(offline_ai.asks_about_focus(q, lang, "aa:bb:cc:00:00:02"), lang)
                self.assertFalse(offline_ai.asks_about_focus(q, lang, None), lang)
                self.assertFalse(offline_ai.asks_about_focus(q + " and block it", lang, mac), lang)
            self.assertFalse(offline_ai.asks_about_focus("why?", lang, mac), lang)
            self.assertFalse(offline_ai.asks_about_focus(None, lang, mac), lang)

    def test_offline_summary_note_only_for_other_questions(self):
        from netwarden import brain, offline_ai
        from test_offline_ai import CAM, seed
        db = store.connect(":memory:")
        seed(db)
        snap = brain.snapshot(db, hours=24)
        for lang in ("en", "de", "ko"):
            note = i18n.t("offline.question_note", lang)
            q = i18n.t("app.ask_prefill", lang, name="ipcam", mac=CAM)
            out = offline_ai.summarize(db, snap, lang, q, CAM)
            self.assertNotIn(note, out, lang)
            self.assertIn(i18n.t("offline.focus_title", lang, name="ipcam").split("ipcam")[0], out)
            self.assertIn(note, offline_ai.summarize(db, snap, lang, "why?", CAM), lang)
            self.assertIn(note, offline_ai.summarize(db, snap, lang, q, None), lang)
            for k in offline_ai.STANDING:     # the chat's own chips are answered by the summary
                self.assertNotIn(note, offline_ai.summarize(db, snap, lang, i18n.t(k, lang), None), (lang, k))
        self.assertIn("app.ai.s1', 'app.ai.s2', 'app.ai.s3'", APP)    # = offline_ai.STANDING
        self.assertEqual(B.SUGGESTED, offline_ai.STANDING)

    def test_addon_offline_reason(self):
        import os
        from unittest import mock
        from netwarden import addon, brain, health
        self.assertEqual(addon.BOOL_OPTIONS["offline_ai"], brain.OFFLINE_ENV)
        # the real path: options -> os.environ (addon.main) -> brain.load_env (ENV_KEYS only)
        opts_env = addon.env_from_options({"offline_ai": True}, environ={})
        self.assertEqual(opts_env[brain.ADDON_ENV], "1")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, opts_env):
            env = brain.load_env(Path(tmp) / "none.env")
        self.assertEqual(brain.offline_reason(env), "addon")
        self.assertEqual(brain.describe_provider(env)["offline_reason"], "addon")
        self.assertEqual(brain.offline_reason({brain.OFFLINE_ENV: "1"}), "forced")
        self.assertEqual(brain.offline_reason({brain.ADDON_ENV: "1"}), "no_key")
        line = health.ai_line(brain.ai_config(env), "en")
        self.assertIn(i18n.t("status.ai.offline_addon", "en"), line)
        self.assertNotIn("--offline-ai", line)
        self.assertIn("addon: 'ui.ai_offline_addon'", APP[APP.index("function aiBadge("):][:400])
        self.assertIn("['forced', 'addon', 'chosen'].includes(st.ai.reason)", APP)

    def test_demo_answer_title(self):
        def sse(*lines):
            return "\n\n".join(["event: start\ndata: {}"] + ["data: " + json.dumps({"t": l + "\n"}, ensure_ascii=False)
                                                             for l in lines] + ["event: done\ndata: {}"]).encode("utf-8")
        for lang in ("en", "zh-Hant", "ja"):
            for title in ("offline.title", "intent.title"):
                out = B.demo_hint(sse(i18n.t(title, lang), "facts", i18n.t("offline.enable_hint", lang)), lang).decode("utf-8")
                texts = [json.loads(f[6:])["t"] for f in out.split("\n\n") if f.startswith("data: ") and '"t"' in f]
                self.assertEqual(texts, [i18n.t("app.demo.answer_title", lang) + "\n", "facts\n",
                                         "💡 " + i18n.t("app.demo.chat_only", lang) + "\n"], (lang, title))

    def test_new_strings_in_every_locale(self):
        en = json.loads((ROOT / "netwarden" / "locales" / "en.json").read_text(encoding="utf-8"))
        for p in sorted((ROOT / "netwarden" / "locales").glob("*.json")):
            loc = json.loads(p.read_text(encoding="utf-8"))
            for k in ("ui.ai_offline_addon", "status.ai.offline_addon", "app.demo.answer_title"):
                self.assertTrue(loc.get(k, "").strip(), (p.name, k))
                self.assertNotIn("--offline-ai", loc[k])
                if p.stem != "en":
                    self.assertNotEqual(loc[k], en[k], (p.name, k))
            self.assertTrue(loc["ui.ai_offline_addon"].startswith("· "), p.name)
            self.assertTrue(loc["app.demo.answer_title"].startswith("🧭 "), p.name)
        self.assertNotIn("（", json.loads((ROOT / "netwarden" / "locales" / "ja.json").read_text(encoding="utf-8"))["app.demo.ai_mode"])


if __name__ == "__main__":
    unittest.main()
