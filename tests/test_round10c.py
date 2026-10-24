"""Round 10c: what a browser check of the redeployed live demo found - several of them in
the real app too.

1. A language round-trip kept the other language on screen: the page held ONE copy of the
   data but remembered its ETags per language, so going back to English got a 304 for the
   English bundle and kept the Chinese data. Tags are per dataset now and a language
   change forgets them (and a refresh that was in flight is repeated in the new language).
2. "Ask AI about this device" in zh-Hant / zh-Hans / ja was matched as a domains question
   ("在做什麼") and got only the top domains; the pre-filled question now gets the full
   device profile in every language.
3. The demo's made-up ISP outage could fall inside the health headline's last hour.
4. The chat after a language switch: earlier messages keep their language under a note.
5. Saved answer text: _emphasis_ rendered, singular counts, localized service names.
6. The chat's standing chips get their own answers (the same in every language).
7. The drawer's title is the list's name (/api/device calls the announced name identity).
"""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from netwarden import ai_intents, ai_tools, brain, demo, i18n, nethealth, offline_ai, services, store
from test_round9_w import APP, B, ROOT
from tzkit import pinned_tz

CAM = "a0:43:b0:9f:21:5e"          # the demo's XMEye camera
NOW = datetime(2026, 10, 21, 18, 25, tzinfo=timezone.utc)   # 02:25 in Taipei: just after "last night"


def answer_text(db, lang, question, mac=None, mode="chat"):
    """The offline assistant's reply (text, tool chips) exactly as /api/chat/stream builds it."""
    text, tools = [], []
    msgs = [{"role": "user", "content": question}] if question else []
    for ev in brain.stream_events(db, offline_ai.OfflineProvider(lang), mode, msgs, lang=lang, mac=mac):
        text.append(ev.get("t") or "")
        if "tool" in ev:
            tools.append(ev["tool"])
    return "".join(text), tools


class DemoHome(unittest.TestCase):
    """One demo home in Taipei, built NOW (the assistant reads the last 24 h of the real
    clock; every fact checked here is in the demo at any hour)."""

    @classmethod
    def setUpClass(cls):
        cls.tz = pinned_tz("Asia/Taipei")
        cls.tz.__enter__()
        cls.tmp = tempfile.TemporaryDirectory(prefix="nw_10c_")
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        cls.db = store.connect(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.tmp.cleanup()
        cls.tz.__exit__(None, None, None)


class DeviceQuestion(DemoHome):
    """Item 2: the drawer's pre-filled question = the device's full profile, any language."""

    LANGS = ("en", "zh-Hant", "zh-Hans", "ja", "ko", "de", "ru")

    def facts(self, text):
        return {"domains": set(re.findall(r"\b(?:secu100|star1\.xmeye|xmeye)\.net\b", text)),
                "ports": set(re.findall(r"\b(23|554)/", text)),
                "upnp": "554" in text and "192.168.1.51" in text}

    def test_same_facts_in_every_language(self):
        seen = {}
        for lang in self.LANGS:
            q = i18n.t("app.ask_prefill", lang, name="ipcam", mac=CAM)
            self.assertIsNone(ai_intents.match(self.db, lang, q, CAM), lang)
            text, tools = answer_text(self.db, lang, q, CAM)
            self.assertFalse(tools, lang)                           # not the domains lookup
            self.assertIn(i18n.t("offline.focus_title", lang, name="ipcam"), text, lang)
            self.assertNotIn(i18n.t("offline.question_note", lang), text, lang)
            seen[lang] = self.facts(text)
            self.assertEqual(seen[lang]["domains"], {"secu100.net", "star1.xmeye.net", "xmeye.net"}, lang)
            self.assertEqual(seen[lang]["ports"], {"23", "554"}, lang)
            self.assertTrue(seen[lang]["upnp"], lang)
        self.assertEqual(len({json.dumps(sorted(map(str, f.items()))) for f in seen.values()}), 1, seen)

    def test_a_question_filled_in_another_language(self):
        # the box was filled in English, then the page switched to 繁體中文
        q = i18n.t("app.ask_prefill", "en", name="ipcam", mac=CAM)
        self.assertIsNone(ai_intents.match(self.db, "zh-Hant", q, CAM))
        text, _ = answer_text(self.db, "zh-Hant", q, CAM)
        self.assertIn("secu100.net", text)
        # a real question about the device still gets its intent
        self.assertEqual(ai_intents.match(self.db, "zh-Hant", "它今天連到哪些網站?", CAM)["intent"], "domains")

    def test_service_names_like_the_drawer(self):
        text, _ = answer_text(self.db, "zh-Hant", i18n.t("app.ask_prefill", "zh-Hant", name="ipcam", mac=CAM), CAM)
        xmeye = services.service_name("svc.xmeye", "zh-Hant")
        self.assertIn(xmeye, text)
        self.assertNotIn(services.service_name("svc.xmeye", "en"), text)
        # the domains lookup names services in the asked language too (it used to re-localize
        # an English name, which left it English)
        res = ai_tools.run(self.db, "top_domains", {"window": "24h", "device": CAM, "limit": 8}, "zh-Hant")
        names = {d["domain"]: d.get("service") for d in res["domains"]}
        self.assertEqual(names["xmeye.net"], xmeye)
        self.assertEqual(names["pool.ntp.org"], services.service_name("svc.time|NTP", "zh-Hant"))
        text, _ = answer_text(self.db, "zh-Hant", "ipcam 今天連到哪些網站?", CAM)
        self.assertIn(xmeye, text)


class StandingQuestions(DemoHome):
    """Item 6: the chat's own chips get a real answer each - the same one in every language."""

    WANT = {"app.ai.s1": "alerts", "app.ai.s2": "new_devices", "app.ai.s3": "night"}

    def test_matched_by_text_in_every_language(self):
        self.assertEqual(set(self.WANT), set(offline_ai.STANDING))
        for key, intent in self.WANT.items():
            for lang in i18n.CODES:
                q = i18n.t(key, lang)
                for focus in (None, CAM):
                    m = ai_intents.match(self.db, lang, q, focus)
                    self.assertEqual(m and m["intent"], intent, (key, lang, focus))
                # the chip's words in another UI language still find it
                self.assertEqual(ai_intents.match(self.db, "en", q)["intent"], intent, (key, lang))

    def test_night_answer(self):
        for lang in ("en", "zh-Hant"):
            text, tools = answer_text(self.db, lang, i18n.t("app.ai.s3", lang))
            self.assertIn(i18n.t("intent.night_head", lang, when=i18n.t("aitool.win.7d", lang)), text)
            self.assertIn("Galaxy-Tab-A7", text, lang)                 # the kid's tablet, 01:00-02:00
            self.assertEqual([t["name"] for t in tools], ["alerts", "alerts"])
            self.assertNotIn(i18n.t("offline.state", lang).split("{")[0] or "\0", text)   # not the summary

    def test_nothing_at_night(self):
        db = store.connect(":memory:")
        out = ai_intents.answer(db, "en", i18n.t("app.ai.s3", "en"))
        self.assertEqual(out["intent"], "night")
        self.assertIn(i18n.t("intent.night_none", "en", when=i18n.t("aitool.win.7d", "en")), out["text"])

    def test_changes_and_unusual(self):
        text, _ = answer_text(self.db, "zh-Hant", i18n.t("app.ai.s2", "zh-Hant"))
        self.assertIn("roborock-vacuum", text)                         # the new robot vacuum
        text, _ = answer_text(self.db, "ja", i18n.t("app.ai.s1", "ja"))
        self.assertIn("ipcam", text)


class Plurals(unittest.TestCase):
    """Item 5: "1 more person", "1 new device" - CLDR's one category per language."""

    KEYS = ("offline.focus_queries", "offline.focus_threats", "intent.domains_head", "intent.presence_hidden",
            "intent.new_head", "intent.alerts_head", "intent.upnp_head", "intent.sug_head",
            "intent.devices_head", "intent.devices_head_private")

    def test_rules(self):
        en1 = i18n.tn("intent.presence_hidden", 1, "en")
        self.assertTrue(en1.startswith("1 more person "), en1)
        self.assertTrue(i18n.tn("intent.presence_hidden", 2, "en").startswith("2 more people "))
        self.assertIn("1 new device**", i18n.tn("intent.new_head", 1, "en", when="x"))
        self.assertIn("3 new devices**", i18n.tn("intent.new_head", 3, "en", when="x"))
        self.assertIn("0 nouvel appareil", i18n.tn("intent.new_head", 0, "fr", when="x"))   # French: 0 is one
        self.assertIn("2 nouveaux appareils", i18n.tn("intent.new_head", 2, "fr", when="x"))
        self.assertIn("человек не включил", i18n.tn("intent.presence_hidden", 21, "ru"))
        self.assertIn("11 человек не включили", i18n.tn("intent.presence_hidden", 11, "ru"))   # round 10d: _many
        self.assertEqual(i18n.tn("intent.alerts_head", 1, "zh-Hant", when="x"),
                         i18n.t("intent.alerts_head", "zh-Hant", n=1, when="x"))
        self.assertIn("**2 alerts**", i18n.tn("intent.alerts_head", "2", "en", when="x"))
        self.assertIn("**x alerts**", i18n.tn("intent.alerts_head", "x", "en", when="w"))   # not a number

    def test_no_hedged_plurals_left(self):
        for code in i18n.CODES:
            loc = i18n.strings(code)
            for k in self.KEYS:
                self.assertIn(k + "_one", loc, (code, k))
                for v in (loc[k], loc[k + "_one"]):
                    self.assertNotRegex(v, r"\w\((s|e|en|es)\)", (code, k))   # "device(s)", "Gerät(e)"
        for name in ("ai_intents.py", "offline_ai.py"):
            src = (ROOT / "netwarden" / name).read_text(encoding="utf-8")
            for k in self.KEYS:
                short = k.split(".", 1)[1] if name == "offline_ai.py" else k
                self.assertNotRegex(src, r'(?<!tn\()["\']' + re.escape(k) + r'["\'], *(n|queries)=', k)
                self.assertNotIn(f'tr("{short}"', src)


class DemoOutage(unittest.TestCase):
    """Item 3: the made-up ISP outage always ends well before the headline's last hour."""

    def test_whatever_the_clock(self):
        start = datetime(2026, 3, 7, 0, 0, tzinfo=timezone.utc)      # around US / NZ clock changes
        for zone in ("Asia/Taipei", "UTC", "America/Los_Angeles", "Pacific/Auckland"):
            tz = ZoneInfo(zone)
            for k in range(0, 4 * 24 * 60, 10):
                now = start + timedelta(minutes=k)
                inc = {kind: (s, n) for s, n, kind in demo._incidents(now, tz)}
                s, n = inc["isp"]
                end = s + timedelta(minutes=n)
                self.assertLessEqual(end, now - demo.ISP_CLEAR, (zone, now))   # never "right now"
                self.assertGreater(end, now - timedelta(hours=24), (zone, now))  # but in the last 24 h
                local = s.astimezone(tz)      # 03:13 only when spring-forward skips 02:13
                self.assertIn((local.hour, local.minute), {demo.ISP_OUTAGE[:2], demo.ISP_EARLY, (3, 13)},
                              (zone, now))
                self.assertGreater(inc["router"][0], now - timedelta(hours=demo.HEALTH_HOURS), (zone, now))

    def test_seeded_at_several_times(self):
        with tempfile.TemporaryDirectory(prefix="nw_10c_out_") as tmp, pinned_tz("Asia/Taipei"):
            # 02:25 / 05:10 / 14:00 in Taipei: just after the outage, within 3 h, long after
            for now in (NOW, NOW + timedelta(hours=2, minutes=45), NOW + timedelta(hours=11, minutes=35)):
                path = Path(tmp) / f"d{now:%H%M}.db"
                demo.build(path, now=now)
                db = store.connect(path)
                try:
                    hour_ago = nethealth._iso(now - timedelta(hours=1))
                    q, fails, _ms = nethealth.dns_window(db, hour_ago)
                    self.assertEqual(fails or 0, 0, now)
                    newest = db.execute("SELECT MAX(end_ts) FROM outages").fetchone()[0]
                    self.assertLessEqual(newest, nethealth._iso(now - demo.ISP_CLEAR), now)
                    isp_end = db.execute("SELECT end_ts FROM outages WHERE cause = 'isp'").fetchone()[0]
                    self.assertGreater(isp_end, nethealth._iso(now - timedelta(hours=24)), now)
                    causes = {r[0] for r in db.execute("SELECT cause FROM outages")}
                    self.assertIn("isp", causes, now)
                finally:
                    db.close()


class PageCode(unittest.TestCase):
    """app.js: items 1, 4, 5 and 7 where the browser runs them."""

    def fn(self, name, n=1600):
        i = APP.index("function " + name + "(")
        return APP[i:i + n]

    def test_one_tag_per_dataset(self):
        self.assertNotRegex(APP, r"lastTag\[[^\]]*S\.lang|lastTag\[[^\]]*\+ *lang|lastTag\['\w+' *\+")
        self.assertIn("function forgetTags() { lastTag = {}; }", APP)
        f = self.fn("setLang", 2200)
        self.assertIn("forgetTags();", f)
        # round 10d: the refreshes moved to LANG_DEPS, run by langChanged() after the tags are gone
        self.assertLess(f.index("forgetTags();"), f.index("langChanged();"))
        deps = APP[APP.index("const LANG_DEPS"):APP.index("// end LANG_DEPS")]
        self.assertIn("['datasets', () => true, () => refresh()]", deps)
        self.assertIn("['since', () => !!S.since.r, () => sinceLoad()]", deps)
        # a refresh that was in flight when the language changed fetches again
        self.assertIn("if (lang !== S.lang) { S.refreshing = false; clearTimeout(slow); refresh(); return; }",
                      self.fn("refresh", 1200))

    def test_chat_keeps_its_language(self):
        self.assertIn("lang: S.lang", self.fn("chat", 900))
        self.assertIn("lang: m.lang", self.fn("saveChat", 500))
        log = self.fn("chatLog", 700)
        self.assertIn("T('app.chat.other_lang', { lang: langName(m.lang), now: langName(S.lang) })", log)
        self.assertIn("!otherLang(m)", self.fn("chatMsg", 2600))     # old-language follow-up chips hidden
        self.assertIn("syncChatCtx()", self.fn("refresh", 2600))
        for code in i18n.CODES:
            v = i18n.strings(code)["app.chat.other_lang"]
            self.assertIn("{lang}", v)
            self.assertIn("{now}", v)

    def test_drawer_title_is_the_list_name(self):
        f = self.fn("dname", 900)
        self.assertIn("d.ident && d.ident.name", f)
        self.assertIn("d.identity && d.identity.name", f)
        self.assertEqual(B.device_name({"identity": {"name": "Dad's iPhone"}, "vendor": "Apple"}, "en"),
                         "Dad's iPhone")

    def test_markdown_in_node(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed (run node tests/js/chat_md_test.js)")
        r = subprocess.run([node, str(ROOT / "tests" / "js" / "chat_md_test.js")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class ReviewFixes(DemoHome):
    """The round's review: a health answer names its window, a night line names its device
    once, "most unusual" answers with one device, one singular/plural rule, the in-flight
    refresh after a language change, the "tap one" heading travels with its chips."""

    @staticmethod
    def first(text):
        """The answer's first line after the "Offline mode" banner."""
        return [x for x in text.splitlines()[1:] if x.strip()][0]

    def test_health_answer_names_its_window(self):
        for lang, q in (("en", "Was the internet down recently?"), ("zh-Hant", "最近有斷線嗎?")):
            out = ai_intents.answer(self.db, lang, q)
            self.assertEqual(out["intent"], "health")
            when = i18n.t("aitool.win.7d", lang)
            first = self.first(out["text"])
            # round 10d: the demo's outages in the window lead (test_round10d checks the wording)
            self.assertTrue(first.startswith("**") and f"({when})" in first, first)
        out = ai_intents.answer(self.db, "en", "Was the internet down in the last 24 hours?")
        self.assertIn("(last 24 h)", out["text"])

    def test_night_lines_name_the_device_once(self):
        for lang in ("en", "zh-Hant"):
            text, _ = answer_text(self.db, lang, i18n.t("app.ai.s3", lang))
            self.assertIn("Galaxy-Tab-A7", text)
            self.assertNotRegex(text, r"• (\S+) - \1", lang)

    def test_most_unusual_is_one_device(self):
        for lang in ("en", "ja", "zh-Hant"):
            out = ai_intents.answer(self.db, lang, i18n.t("app.ai.s1", lang))
            # round 10d review: the alert total (the Overview's) leads, then that ONE device
            total, second = [x for x in out["text"].splitlines()[1:] if x.strip()][:2]
            self.assertTrue(total.startswith(i18n.t("intent.alerts_head", lang, n=99).split("99")[0]), total)
            head = i18n.t("intent.unusual_head", lang, name="\0").split("\0")
            self.assertTrue(second.startswith(head[0]) and second.endswith(head[1]), second)
        # the device with the worst alert wins, then the one with more alerts
        rows = [{"mac": "aa:bb:cc:00:00:01", "severity": "medium"}, {"mac": None, "severity": "critical"},
                {"mac": "aa:bb:cc:00:00:02", "severity": "high"}, {"mac": "aa:bb:cc:00:00:03", "severity": "high"},
                {"mac": "aa:bb:cc:00:00:03", "severity": "low"}]
        self.assertEqual(ai_intents._most_unusual(rows), "aa:bb:cc:00:00:03")
        self.assertIsNone(ai_intents._most_unusual([{"mac": None, "severity": "critical"}]))

    def test_suggestions_use_the_one_plural_rule(self):
        from netwarden import suggestions

        def title(n, lang):
            item = {"kind": "owners", "params": {"n": n}, "severity": "low", "pillar": "tidiness"}
            return suggestions.localize(item, lang)["title"]
        self.assertEqual(title(1, "en"), "Say who uses 1 device")
        self.assertEqual(title(2, "en"), "Say who uses 2 devices")
        self.assertIn("21 устройством", title(21, "ru"))          # Russian: 21 is "one"
        self.assertNotIn("1 устройством", title(11, "ru").replace("11", ""))
        src = (ROOT / "netwarden" / "suggestions.py").read_text(encoding="utf-8")
        self.assertNotIn('== 1', src)
        for code in i18n.CODES:     # a singular text never hard-codes the count
            for k in ("sug.names.why_one", "sug.owners.title_one", "sug.owners.why_one"):
                self.assertIn("{n}", i18n.strings(code)[k], (code, k))

    def test_wording(self):
        self.assertIn("這週", i18n.t("app.ai.s2", "zh-Hant"))
        self.assertIn("{now}(으)로", i18n.t("app.chat.other_lang", "ko"))

    def test_page_code(self):
        f = PageCode.fn(self, "refresh", 2800)
        tail = f[f.index("await loadDevice(true)"):]
        self.assertIn("if (lang !== S.lang) { render(); refresh(); return; }", tail)
        self.assertLess(tail.index("S.refreshing = false;"), tail.index("if (lang !== S.lang)"))
        read = PageCode.fn(self, "readAnswer", 3200)
        self.assertIn("reply.sugHead = reply.content.slice(cut + 2)", read)
        msg = PageCode.fn(self, "chatMsg", 2600)
        self.assertIn("!otherLang(m) ? html`${m.sugHead ? html`<div class=\"sug-head\">${md(m.sugHead)}</div>` : ''}", msg)
        self.assertIn("sugHead: m.sugHead", PageCode.fn(self, "saveChat", 600))
        # the server's contract the page relies on: the heading is the answer's last paragraph
        text, _ = answer_text(self.db, "en", "Tell me a poem about routers")
        self.assertTrue(text.endswith("\n\n" + i18n.t("offline.try_these", "en")), text[-200:])


if __name__ == "__main__":
    unittest.main()
