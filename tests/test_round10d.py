"""Round 10d: what a browser check of the live demo found, and the sweeps behind it.

1. Language switches: the palette (and its Settings results) kept the old language. One
   table, LANG_DEPS in app.js, says what a language change refreshes (node:
   tests/js/lang_switch_test.js); every loader of the page is in it, in refresh(), or
   holds no translated text.
2. Plurals: "1 new devices", "1 router forward(s)". Count texts carry CLDR plural forms
   (`key_one`, Russian `_few` / `_many`), chosen by i18n.tn() / t(n=) and TN() in the
   browser; the i18n checker flags a count text without them and any "(s)" hedge.
3. Numbers that disagree: the AI's health answer said "All good" above a list of outages
   and its DNS numbers were not the page's. Both use the page's own verdict (24 h, named).
4. Hard-coded English: "(this machine)" in the demo vendor, language names, list
   separators, decimal marks.
5. Demo coherence: every suggested question has a real answer in every language.

No server, no LLM, no network: the demo home + static checks of app.js and the locales.
"""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from netwarden import ai_intents, ai_tools, alerts, brain, demo, i18n, naming, nethealth, offline_ai, \
    score, store
from test_round10c import CAM, answer_text
from tzkit import pinned_tz

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "netwarden" / "static" / "app.js"
PKG = ROOT / "netwarden"


class PluralCore(unittest.TestCase):
    def test_categories(self):
        cat = i18n.plural_category
        self.assertEqual([cat(n, "en") for n in (0, 1, 2)], ["other", "one", "other"])
        self.assertEqual([cat(n, "fr") for n in (0, 1, 2)], ["one", "one", "other"])
        self.assertEqual([cat(n, "ru") for n in (1, 2, 5, 11, 12, 21, 22, 25, 111)],
                         ["one", "few", "many", "many", "many", "one", "few", "many", "many"])
        self.assertEqual(cat(1, "zh-Hant"), "other")
        self.assertEqual(cat("1,234", "en"), "other")
        self.assertEqual(cat("1", "en"), "one")
        self.assertEqual(cat(1.5, "en"), "other")
        self.assertEqual(cat(None, "en"), "other")

    def test_tn_and_automatic_t(self):
        key = "intent.health_had_outages"
        self.assertTrue(i18n.is_plural(key))
        one, two = (i18n.tn(key, n, "en", when="x") for n in (1, 2))
        self.assertIn("1 outage", one)
        self.assertNotIn("1 outages", one)
        self.assertIn("2 outages", two)
        ru = {n: i18n.tn(key, n, "ru", when="x") for n in (1, 2, 5)}
        self.assertEqual(len(set(ru.values())), 3, ru)
        # zh has one form: the base text for any count
        self.assertEqual(i18n.tn(key, 1, "zh-Hant", when="x"), i18n.tn(key, 2, "zh-Hant", when="x").replace("2", "1"))
        # t() given an integer n picks the form itself
        for lang in ("en", "ru", "fr"):
            for n in (1, 3, 5):
                self.assertEqual(i18n.t(key, lang, n=n, when="x"), i18n.tn(key, n, lang, when="x"))

    def test_every_count_text_has_its_forms_and_the_checker_is_clean(self):
        self.assertEqual(i18n.check(), [])
        en = i18n.strings("en")
        ru = json.loads((PKG / "locales" / "ru.json").read_text(encoding="utf-8"))
        bases = [k[:-4] for k in en if k.endswith("_one") and k[:-4] in en]
        self.assertGreater(len(bases), 100)
        for b in bases:
            self.assertIn(b + "_few", ru, b)
            self.assertIn(b + "_many", ru, b)
        # PLURAL_FIXED says why for each entry, and each entry exists
        for k, why in i18n.PLURAL_FIXED.items():
            self.assertIn(k, en)
            self.assertTrue(why.strip())


class Checker(unittest.TestCase):
    def probs(self, cat):
        return {(c, k, p) for c, k, p, _ in i18n.check(cat, same_allow={})}

    def test_missing_singular_and_hedge(self):
        cat = {"en": {"a": "{n} devices", "b": "Checked {n} file(s)", "c": "Uses http(s) only"},
               "ru": {"a": "{n} устройств", "b": "Проверено {n} файл(ов)", "c": "Только http(s)"}}
        p = self.probs(cat)
        self.assertIn(("en", "a", "plural_missing"), p)
        self.assertIn(("en", "b", "plural_hedge"), p)
        self.assertIn(("ru", "b", "plural_hedge"), p)
        self.assertNotIn(("en", "c", "plural_hedge"), p)
        self.assertNotIn(("ru", "c", "plural_hedge"), p)

    def test_russian_needs_few_and_many(self):
        cat = {"en": {"a": "{n} devices", "a_one": "{n} device"},
               "ru": {"a": "{n} устройств", "a_one": "{n} устройство"}}
        p = self.probs(cat)
        self.assertNotIn(("en", "a", "plural_missing"), p)
        self.assertIn(("ru", "a_few", "plural_forms"), p)
        self.assertIn(("ru", "a_many", "plural_forms"), p)
        cat["ru"].update({"a_few": "{n} устройства", "a_many": "{n} устройств"})
        p = self.probs(cat)
        self.assertFalse({x for x in p if x[2] in ("plural_forms", "extra", "plural_missing")}, p)

    def test_a_form_may_drop_the_count(self):
        cat = {"en": {"a": "{n} times", "a_one": "once"}}
        self.assertFalse({x for x in self.probs(cat) if x[2] == "placeholders"})


class CallSites(unittest.TestCase):
    """Static: a count text is always given its count."""

    @classmethod
    def setUpClass(cls):
        cls.js = APP.read_text(encoding="utf-8")
        cls.en = i18n.strings("en")
        cls.bases = sorted(k[:-4] for k in cls.en if k.endswith("_one") and k[:-4] in cls.en)

    def test_app_js_uses_tn_for_count_texts(self):
        self.assertIn("function TN(", self.js)
        self.assertIn("Intl.PluralRules", self.js)
        bad = [b for b in self.bases if re.search(r"\bT\('" + re.escape(b) + r"'", self.js)]
        self.assertEqual(bad, [])

    def test_python_count_texts_without_n_go_through_tn(self):
        # t("key", n=...) picks the form; a count under another name needs tn()
        need = [b for b in self.bases if "{n}" not in self.en[b]]
        bad = []
        for p in PKG.glob("*.py"):
            src = p.read_text(encoding="utf-8")
            for b in need:
                for m in re.finditer(r"(\w+)\(\s*f?\"" + re.escape(b) + r"\"", src):
                    if m.group(1) not in ("tn", "has", "is_plural"):
                        bad.append((p.name, b, m.group(1)))
        self.assertEqual(bad, [])

    def test_no_hedges_left_in_any_language(self):
        for code in i18n.CODES:
            for k, v in i18n.strings(code).items():
                if not k.startswith(i18n.SAME_OK_KEYS):
                    self.assertIsNone(re.search(i18n._HEDGE_RX, v), (code, k, v))


class LanguageSwitch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = APP.read_text(encoding="utf-8")
        a, b = cls.js.index("const FRESH_PAGES"), cls.js.index("// end LANG_DEPS")
        cls.deps = cls.js[a:b]

    def test_set_lang_ends_with_lang_changed(self):
        body = re.search(r"function setLang\(.*?\n\}", self.js, re.S).group(0)
        self.assertIn("langChanged();", body)

    def test_every_loader_is_refreshed_or_holds_no_text(self):
        loaders = set(re.findall(r"^(?:async )?function (load[A-Z]\w*)\(", self.js, re.M))
        refresh = re.search(r"async function refresh\(\) \{(.*?)\n\}", self.js, re.S).group(1)
        neutral = {"loadFailed",      # a render helper, no fetch
                   "loadChat",        # localStorage: the messages keep their own language
                   "loadNotified",    # localStorage: ids only
                   "loadRecent"}      # localStorage: palette ids only
        missing = [f for f in sorted(loaders - neutral)
                   if f + "(" not in self.deps and f + "(" not in refresh]
        self.assertEqual(missing, [])
        self.assertGreaterEqual(len(loaders), 12)

    def test_palette_and_settings_list_follow_the_language(self):
        self.assertIn("loadAI()", self.deps)
        self.assertIn("renderPalette()", self.deps)
        self.assertIn("relabelToasts()", self.deps)

    def test_language_names_and_list_separators(self):
        self.assertIn("Intl.DisplayNames", self.js)
        self.assertIn("T('list_sep')", self.js)
        self.assertIn("T('app.d.this_computer')", self.js)
        # a tool chip's detail keeps its answer's separator after a switch (stored with it)
        self.assertIn("x.detail.filter(Boolean).join(x.sep || T('list_sep'))", self.js)
        clean = re.search(r"function cleanTool\(x\) \{(.*?)\n\}", self.js, re.S).group(1)
        self.assertIn("sep", clean)
        self.assertNotIn("T(", clean)   # restored chats are cleaned before the strings load
        self.assertIn("cleanTool(Object.assign({}, d, { sep: T('list_sep') }))", self.js)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_node_lang_switch(self):
        r = subprocess.run(["node", str(ROOT / "tests" / "js" / "lang_switch_test.js")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_python_plurals_agree_with_intl(self):
        langs = [c for c in i18n.CODES]
        script = ("const L=%s;const o={};for(const l of L){const r=new Intl.PluralRules(l);"
                  "o[l]=[];for(let n=0;n<=130;n++)o[l].push(r.select(n));}console.log(JSON.stringify(o));"
                  % json.dumps(langs))
        r = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        intl = json.loads(r.stdout)
        for lang in langs:
            ours = [i18n.plural_category(n, lang) for n in range(131)]
            self.assertEqual(ours, intl[lang], lang)


class Numbers(unittest.TestCase):
    def test_num(self):
        self.assertEqual(i18n.num(1234.5, "en", 1), "1,234.5")
        self.assertEqual(i18n.num(1234.5, "de", 1), "1.234,5")
        self.assertEqual(i18n.num(1234.5, "fr", 1), "1 234,5")   # Intl: narrow no-break space
        self.assertEqual(i18n.num(1234, "es"), "1234")        # es / ru group from 5 digits
        self.assertEqual(i18n.num(12345, "es"), "12.345")
        self.assertEqual(i18n.num(1234, "ru"), "1234")
        self.assertEqual(i18n.num(12345, "ru"), "12 345")
        self.assertEqual(i18n.num(1234567, "hi"), "12,34,567")
        self.assertEqual(i18n.num(3.5, "ru", 1), "3,5")
        self.assertEqual(i18n.num(-0.04, "en", 1), "0.0")
        self.assertEqual(i18n.num(-2, "en"), "-2")
        self.assertEqual(i18n.num(8.2, "zh-Hant", 1), "8.2")


class DemoHome(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tz = pinned_tz("Asia/Taipei")
        cls.tz.__enter__()
        cls.tmp = tempfile.TemporaryDirectory(prefix="nw_10d_")
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        cls.db = store.connect(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.tmp.cleanup()
        cls.tz.__exit__(None, None, None)


class DemoAnswers(DemoHome):
    def test_score_items_are_singular_when_one(self):
        for lang in i18n.CODES:
            for d in score.report(self.db, lang)["deductions"]:
                self.assertIsNone(re.search(i18n._HEDGE_RX, d["text"]), (lang, d["text"]))
        for d in score.report(self.db, "en")["deductions"]:
            self.assertIsNone(re.search(r"(?<![\d.,])\b1 (?:new |personal |router )?\w+s\b", d["text"]), d["text"])

    def test_health_page_names_its_period(self):
        self.assertIn("(last 24 h)", nethealth.report(self.db, "en")["verdict"]["text"])
        for lang in i18n.CODES:
            self.assertIn("24", nethealth.report(self.db, lang)["verdict"]["text"], lang)

    def test_ai_health_numbers_are_the_pages(self):
        for lang in ("en", "zh-Hant", "ru"):
            page = nethealth.report(self.db, lang)
            res = ai_tools.run(self.db, "network_health", {"window": "7d"}, lang)
            self.assertEqual(res["detail"], page["verdict"]["text"], lang)
            self.assertEqual(res["summary"], page["verdict"]["title"], lang)

    def test_health_answer_leads_with_the_outages(self):
        for lang in ("en", "zh-Hant", "ru"):
            page = nethealth.report(self.db, lang)
            text, _ = answer_text(self.db, lang, i18n.t("intent.q.health", lang))
            n = page["outages_7d"]
            self.assertGreater(n, 0)   # the demo has outages this week
            head = i18n.tn("intent.health_had_outages", n, lang, when=i18n.t("aitool.win.7d", lang))
            if not any(o.get("ongoing") for o in page["outages"]):
                self.assertIn(head, text, lang)
                # the headline comes before "Right now: all good"
                self.assertLess(text.index(head), text.index(page["verdict"]["title"]), lang)
            self.assertIn(page["verdict"]["text"], text, lang)

    def test_new_this_week_agrees_with_the_summary(self):
        text, _ = answer_text(self.db, "en", i18n.t("intent.q.new_week", "en"))
        day = alerts.localize(alerts.compute(self.db, recent_hours=24), "en", naming.display_names(self.db, "en"))
        week = ai_tools.run(self.db, "list_devices", {"new_since": "7d", "limit": 50}, "en")
        names7 = {d["name"] for d in week.get("devices") or []}
        for d in day["new_devices"]:
            if not d.get("is_self"):
                self.assertIn(d["name"], names7)
        for c in day["behavior_changes"]:
            self.assertIn(c["name"], text)
        if day["behavior_changes"]:
            self.assertIn(i18n.t("aitool.win.24h", "en"), text)

    def test_offline_summary_names_its_periods(self):
        snap = brain.snapshot(self.db)
        for lang in ("en", "zh-Hant"):
            text = offline_ai.summarize(self.db, snap, lang)
            if isinstance(text, list):
                text = "\n".join(text)
            when = i18n.t("aitool.win.24h", lang)
            for key in ("new_devices", "changes"):
                plain = i18n.t("offline." + key, lang)
                if plain in text:
                    self.assertIn(i18n.t("offline.head_when", lang, head=plain, when=when), text, (lang, key))

    def test_zh_hours_use_the_ideographic_comma(self):
        for lang in ("zh-Hant", "zh-Hans", "ja"):
            text, _ = answer_text(self.db, lang, i18n.t("app.ask_prefill", lang, name="ipcam", mac=CAM), CAM)
            self.assertIsNone(re.search(r"\d, \d", text), (lang, text))

    def test_every_suggested_question_has_an_answer(self):
        for lang in i18n.CODES:
            empty = [i18n.t(k, lang).split("{")[0].strip() for k in
                     ("intent.failed", "intent.domains_none", "intent.new_none", "intent.screen_none",
                      "intent.traffic_none", "intent.upnp_unchecked")]
            empty = [e for e in empty if len(e) > 3]
            qs = ai_intents.suggested(self.db, lang)
            self.assertGreaterEqual(len(qs), 4, lang)
            for q in qs:
                a = ai_intents.answer(self.db, lang, q["text"])
                self.assertIsNotNone(a, (lang, q["text"]))
                for e in empty:
                    self.assertNotIn(e, a["text"], (lang, q["text"]))

    def test_the_start_chips_get_answers(self):
        for lang in ("en", "zh-Hant", "ru"):
            for k in ("app.ai.s1", "app.ai.s2", "app.ai.s3"):
                text, _ = answer_text(self.db, lang, i18n.t(k, lang))
                lines = [x for x in text.splitlines() if x.strip()]
                self.assertGreater(len(lines), 3, (lang, k))

    def test_demo_vendor_has_no_english_note(self):
        rows = self.db.execute("SELECT vendor FROM devices").fetchall()
        for (v,) in rows:
            self.assertNotIn("this machine", (v or "").lower())
        for code in i18n.CODES:
            self.assertTrue(i18n.t("app.d.this_computer", code).strip())


# --- round 10d review fixes -----------------------------------------------------------------

class ReviewPlurals(unittest.TestCase):
    """Review 1: a singular form that says "once" is wrong where that form also covers 21
    (Russian) or 0 (French, Portuguese, Hindi)."""

    def probs(self, cat):
        return {(c, k, p) for c, k, p, _ in i18n.check(cat, same_allow={})}

    def test_dropping_the_count_only_where_one_means_1(self):
        cat = {"en": {"a": "{n} times", "a_one": "once"},
               "de": {"a": "{n}-mal", "a_one": "einmal"},
               "ru": {"a": "{n} раз", "a_one": "один раз", "a_few": "{n} раза", "a_many": "{n} раз"},
               "fr": {"a": "{n} fois", "a_one": "une fois"}}
        p = self.probs(cat)
        self.assertIn(("ru", "a_one", "placeholders"), p)
        self.assertIn(("fr", "a_one", "placeholders"), p)
        self.assertNotIn(("en", "a_one", "placeholders"), p)
        self.assertNotIn(("de", "a_one", "placeholders"), p)
        cat["ru"]["a_few"] = "несколько раз"         # _few / _many never drop the count
        self.assertIn(("ru", "a_few", "placeholders"), self.probs(cat))

    def test_real_texts_keep_the_count(self):
        kw = dict(domain="x", label="L", sev="S", h=24)
        for lang, n in (("ru", 21), ("ru", 31), ("fr", 0), ("pt-BR", 0), ("hi", 0)):
            self.assertIn(str(n), i18n.tn("why.data.threat", n, lang, count=n, **kw), (lang, n))
            for key in ("sug.outages_isp.why", "sug.outages_router.title", "sug.outages_router.why"):
                self.assertIn(str(n), i18n.tn(key, n, lang, minutes=5), (lang, key, n))
        self.assertNotIn("1", i18n.tn("sug.outages_router.title", 1, "en"))   # "once" is fine in English

    def test_checker_sees_a_three_word_gap(self):
        cat = {"en": {"a": "{n} new or changed devices"}}
        self.assertIn(("en", "a", "plural_missing"), self.probs(cat))


def chips(db, lang):
    """The chat's data-driven chips exactly as app.js suggestions() builds them: {key: text}."""
    a = alerts.localize(alerts.compute(db), lang, naming.display_names(db, lang))
    out = {}
    ex = (a.get("exposure") or [])[:1]
    if ex:
        out["app.ai.q.exposure"] = i18n.t("app.ai.q.exposure", lang, name=ex[0]["name"], port=ex[0]["port"])
    night = (a.get("unusual_hours") or [])[:1]
    if night:
        out["app.ai.q.night"] = i18n.t("app.ai.q.night", lang,
                                       time=re.split(r"[–-]", str(night[0].get("window") or ""))[0] or "00:00")
    th = (a.get("threats") or [])[:1]
    if th:
        out["app.ai.q.threat"] = i18n.t("app.ai.q.threat", lang, name=th[0]["device"])
    vis = (a.get("visibility") or [])[:1]
    if vis:
        out["app.ai.q.visibility"] = i18n.t("app.ai.q.visibility", lang, name=vis[0]["name"])
    nd = [d for d in a.get("new_devices") or [] if not d.get("is_self")][:1]
    if nd:
        out["app.ai.q.new"] = i18n.t("app.ai.q.new", lang, name=nd[0]["name"])
    ch = (a.get("behavior_changes") or [])[:1]
    if ch:
        out["app.ai.q.change"] = i18n.t("app.ai.q.change", lang, name=ch[0]["name"])
    out["app.ai.q.trackers"] = i18n.t("app.ai.q.trackers", lang)
    out["app.ai.q.bandwidth"] = i18n.t("app.ai.q.bandwidth", lang)
    return out


class ReviewChips(DemoHome):
    """Review 2: the data-driven chips got off-topic answers (port 23 -> the router
    forwards; "誰在" -> who's home), different per language. Each has a fixed intent now."""

    def test_every_app_js_chip_has_a_fixed_answer(self):
        js = APP.read_text(encoding="utf-8")
        used = set(re.findall(r"add\('(app\.ai\.q\.\w+)'", js))
        self.assertGreaterEqual(len(used), 9)
        handled = set(ai_intents.CHIPS) | set(offline_ai.SUMMARY_CHIPS) | set(offline_ai.FOCUS_QUESTIONS)
        self.assertEqual(used - handled, set())

    def test_chips_route_the_same_in_every_language(self):
        want = {k: v["intent"] for k, v in ai_intents.CHIPS.items()}
        for lang in i18n.CODES:
            qs = chips(self.db, lang)
            for k in ("app.ai.q.exposure", "app.ai.q.night", "app.ai.q.threat"):
                self.assertIn(k, qs, lang)      # the demo has each story
            for k, q in qs.items():
                m = ai_intents.match(self.db, lang, q)
                if k in want:
                    self.assertIsNotNone(m, (lang, q))
                    self.assertEqual(m["intent"], want[k], (lang, q))
                else:
                    self.assertIsNone(m, (lang, q))
                    self.assertTrue(offline_ai.answered_here(q, lang, None), (lang, q))

    def test_open_port_chip_explains_that_port(self):
        for lang in ("en", "zh-Hant", "ru"):
            q = chips(self.db, lang)["app.ai.q.exposure"]
            m = ai_intents.match(self.db, lang, q)
            self.assertEqual(m["device"], CAM)
            a = ai_intents.answer(self.db, lang, q)
            body = a["text"].splitlines()
            head = i18n.t("intent.exposure_head", lang, name=naming.display_names(self.db, lang)[CAM],
                          port=m["port"])
            self.assertIn(head, body, lang)
            first = body[body.index(head) + 1]
            self.assertIn(str(m["port"]), first, lang)
            self.assertIn("Telnet", first, lang)
            self.assertEqual(a["intent"], "exposure")        # not the router forwards (UPnP)
            self.assertEqual([c["name"] for c in a["tools"]], ["alerts"])

    def test_night_chip_lists_that_night(self):
        for lang in ("en", "zh-Hant", "ja"):
            q = chips(self.db, lang)["app.ai.q.night"]
            a = ai_intents.answer(self.db, lang, q)
            self.assertEqual(a["intent"], "night", (lang, q))
            at = ai_intents.match(self.db, lang, q)["at"]
            lines = a["text"].splitlines()
            head = lines.index(i18n.t("intent.night_head", lang, when=i18n.t("aitool.win.7d", lang)))
            self.assertIn(at, lines[head + 1], lang)

    def test_device_chip_with_focus_is_the_device_profile(self):
        for lang in ("en", "zh-Hant"):
            q = i18n.t("app.ai.q.device", lang, name="ipcam")
            self.assertTrue(offline_ai.asks_about_focus(q, lang, CAM), lang)
            self.assertIsNone(ai_intents.match(self.db, lang, q, CAM), lang)

    def test_an_unknown_name_is_no_chip(self):
        q = i18n.t("app.ai.q.threat", "en", name="no-such-device-zz")
        self.assertIsNone(ai_intents.chip(self.db, q, "en"))


class ReviewMostUnusual(DemoHome):
    """Review 3: "9 alerts (last 24 h)" under the most unusual device, while the Overview
    said 15. The total leads; the rest is "N more"."""

    def test_total_is_the_overviews(self):
        for lang in ("en", "zh-Hant", "ru"):
            res = ai_tools.run(self.db, "alerts", {"window": "24h", "limit": 20}, lang)
            when = i18n.t("aitool.win.24h", lang)
            text = ai_intents.answer(self.db, lang, i18n.t("app.ai.s1", lang))["text"]
            total = i18n.tn("intent.alerts_head", res["count"], lang, when=when)
            self.assertIn(total, text, lang)
            unusual = i18n.t("intent.unusual_head", lang, name="X").split("X")[0]
            self.assertLess(text.index(total), text.index(unusual), lang)
            top = ai_intents._most_unusual(res["alerts"])
            rest = res["count"] - sum(1 for a in res["alerts"] if a.get("mac") == top)
            if rest:
                self.assertIn(i18n.tn("intent.alerts_more", rest, lang, when=when), text, lang)


class ReviewSmallFixes(unittest.TestCase):
    def test_demo_vendors_are_brand_names(self):
        for d in demo.DEVICES:
            self.assertNotIn("(", d["vendor"], d["vendor"])

    def test_weekly_counts_use_the_languages_digits(self):
        from netwarden import weekly
        de = weekly._trend({"pct": 118}, "wow.hl.queries", "de", n=1444)
        self.assertIn("1.444", de)
        self.assertIn("1,444", weekly._trend({"pct": 118}, "wow.hl.queries", "en", n=1444))
        fr = weekly._trend({"pct": 118}, "wow.hl.queries", "fr", n=1444)
        self.assertIn("1 444", fr)            # Intl's narrow no-break space
        self.assertIn(i18n.num(118, "fr") + " %", fr)

    def test_report_chart_text_is_localized(self):
        from netwarden import report
        b = {"t": "chart", "kind": "bars", "title": "T", "max": 2000,
             "data": [{"label": "a", "value": 1234}, {"label": "b", "value": None}]}
        h = report._chart_html(b, "de")
        self.assertIn('aria-label="T: a 1.234' + i18n.t("list_sep", "de") + 'b —"', h)
        zh = report._chart_html(b, "zh-Hant")
        self.assertIn("a 1,234" + i18n.t("list_sep", "zh-Hant") + "b —", zh)
        md = "\n".join(report._block_md(b, "de"))
        self.assertIn("a 1.234", md)
        self.assertNotIn("None", md)

    def test_tool_heading_stays_in_the_answers_language(self):
        js = APP.read_text(encoding="utf-8")
        self.assertIn("reply.toolsHead = reply.toolsHead || T('app.ai.looked_up')", js)
        self.assertIn("${m.toolsHead || T('app.ai.looked_up')}:", js)
        self.assertIn("toolsHead: m.toolsHead", js)            # saved with the chat
        self.assertIn("toolsHead: typeof m.toolsHead === 'string'", js)   # and restored, checked


if __name__ == "__main__":
    unittest.main()
