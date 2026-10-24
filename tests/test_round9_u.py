"""Round 9 U: keyboard-first operation - the command palette (people, settings, actions,
"ask the assistant" pre-fill), shortcuts that never fire while typing or composing (IME)
and can be switched off (WCAG 2.1.4, setting ui.shortcuts + a per-browser choice), and
the remembered view (localStorage + the hash query + scroll per history entry).

Static checks of the dashboard source and locales, the setting / /api/meta on a real
stdlib server (ephemeral 127.0.0.1 port), and the node matcher test when node exists.
No LLM, no network.
"""
import http.client
import json
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from netwarden import i18n, settings, store, web

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "netwarden" / "static"
LOCALES = ROOT / "netwarden" / "locales"
JS = (STATIC / "app.js").read_text(encoding="utf-8")
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")

NEW_KEYS = ["app.palette.people", "app.palette.n_devices", "app.palette.room", "app.palette.ask",
            "app.palette.ask_hint", "app.palette.read_all", "app.palette.pause", "app.palette.pause_done",
            "app.palette.pause_none", "app.palette.mute_hour", "app.palette.mute_hour_done",
            "app.palette.scan", "app.palette.single_off", "app.palette.single_on",
            "app.palette.n_results", "app.key.filter", "app.key.single", "app.key.single_hint",
            "app.key.single_on_toast", "app.key.single_off_toast", "app.key.single_note_off",
            "settings.ui.shortcuts", "settings.help.ui.shortcuts"]


def fn_body(name):
    """The source of `function name(...) { ... }` (up to the next top-level function)."""
    m = re.search(r"\n(?:async )?function " + re.escape(name) + r"\(.*?\n\}\n", JS, re.S)
    assert m, name
    return m.group(0)


def keydown_handler():
    i = JS.index("document.addEventListener('keydown', e => {")
    return JS[i:JS.index("\n});\n", i)]


class SettingAndMeta(unittest.TestCase):
    def test_registered_as_a_general_bool_on_by_default(self):
        s = settings.REGISTRY["ui.shortcuts"]
        self.assertEqual((s.type, s.default, s.group, s.admin, s.secret, s.env), ("bool", True, "general", False, False, None))
        db = store.connect(":memory:")
        item = next(i for i in settings.describe(db, {}, "en")["items"] if i["key"] == "ui.shortcuts")
        self.assertEqual((item["section"], item["value"], item["editable"]), ("general", True, True))
        self.assertEqual(item["label"], "Single-key keyboard shortcuts")
        settings.update(db, {}, {"ui.shortcuts": False})
        self.assertIs(settings.get(db, {}, "ui.shortcuts"), False)
        with self.assertRaises(settings.SettingError):
            settings.update(db, {}, {"ui.shortcuts": "sometimes"})

    def test_api_meta_reports_the_home_default(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = str(Path(tmp.name) / "t.db")
        store.connect(path).close()
        old = (web.Handler.db_path, web.Handler.env, web.Handler.lang)
        web.Handler.db_path, web.Handler.env, web.Handler.lang = path, {}, "en"
        srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        def cleanup():
            srv.shutdown()
            web.close_server(srv)
            web.Handler.db_path, web.Handler.env, web.Handler.lang = old
        self.addCleanup(cleanup)

        def meta():
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
            c.request("GET", "/api/meta")
            r = c.getresponse()
            body = json.loads(r.read())
            c.close()
            return body
        self.assertIs(meta()["shortcuts"], True)
        db = store.connect(path)
        settings.update(db, {}, {"ui.shortcuts": False})
        db.close()
        self.assertIs(meta()["shortcuts"], False)


class Shortcuts(unittest.TestCase):
    def test_ime_composition_never_triggers_a_shortcut(self):
        h = keydown_handler()
        guard = "if (e.isComposing || e.keyCode === 229) return;"
        self.assertIn(guard, h)
        self.assertLess(h.index(guard), h.index("e.ctrlKey || e.metaKey"))   # before ANY key is read
        self.assertLess(h.index(guard), h.index("GO_KEYS"))
        pal = JS[JS.index("$('#palq').addEventListener('keydown'"):]
        self.assertIn("if (e.isComposing || e.keyCode === 229) return;", pal[:300])

    def test_single_keys_can_be_switched_off_and_typing_is_left_alone(self):
        h = keydown_handler()
        typing = h.index("if (isTyping(el) || e.altKey || e.ctrlKey || e.metaKey) return;")
        off = h.index("if (!singleKeys())")
        self.assertLess(typing, off)
        for key in ("GO_KEYS[e.key.toLowerCase()]", "openKeys()", "focusFilter()", "toggleChat()", "GROUPS[+e.key - 1]"):
            self.assertLess(off, h.index(key), key)
        body = fn_body("singleKeys")
        self.assertIn("SINGLE_KEY", body)                         # this browser's choice ...
        self.assertIn("S.meta.shortcuts === false", body)         # ... else the home's default
        self.assertIn("const SINGLE_KEY = 'netwarden.single_keys';", JS)
        # Ctrl/Cmd+K works either way (it is read before the gate)
        self.assertLess(h.index("(e.key === 'k' || e.key === 'K') && (e.ctrlKey || e.metaKey)"), off)

    def test_slash_focuses_the_page_filter_else_opens_the_palette(self):
        self.assertIn("else if (e.key === '/') { e.preventDefault(); if (!focusFilter()) openPalette(); }", keydown_handler())
        body = fn_body("focusFilter")
        for sel in ('[data-filter="q"]', '[data-mapf="q"]', "[data-ppl-q]"):
            self.assertIn(sel, body)

    def test_help_sheet_lists_the_keys_and_the_switch(self):
        rows = fn_body("shortcutRows")
        self.assertIn("T('app.key.filter')", rows)
        self.assertIn("k(MOD)}+${k('K')}", rows)
        self.assertIn("singleKeysField('keys-single')", fn_body("keysBody"))
        self.assertIn("singleKeysField('prefs-single')", JS)       # System > Preferences too
        self.assertIn('role="switch"', fn_body("singleKeysField"))


class Palette(unittest.TestCase):
    def test_apg_combobox_with_grouped_listbox(self):
        self.assertIn('role="combobox"', INDEX)
        self.assertIn('aria-haspopup="listbox"', INDEX)
        self.assertIn('id="pallist" class="pal-list" role="listbox"', INDEX)
        self.assertIn('id="palcount" class="sr" aria-live="polite"', INDEX)
        r = fn_body("renderPalette")
        self.assertIn('role="group" aria-labelledby="pg-', r)
        self.assertIn('role="option"', r)
        self.assertIn("aria-activedescendant", r)
        self.assertIn("inp.setAttribute('aria-expanded'", r)

    def test_finds_people_rooms_settings_and_pages(self):
        items = fn_body("paletteItems")
        for f in ("peopleEntries()", "settingEntries()", "deviceActions(", "group('nav'", "group('act'"):
            self.assertIn(f, items)
        self.assertIn("go('#/people/' + p.id)", fn_body("peopleEntries"))
        self.assertIn("'#/devices?room=' + enc(r)", fn_body("peopleEntries"))
        # MAC prefixes with or without separators, owner, room, vendor, IP
        hay = re.search(r"const devHay = d => \[(.*?)\]\.join", JS, re.S).group(1)
        for f in ("d.label", "d.vendor", "d.mac", "replace(/[:-]/g, '')", "d.ips", "d.owner", "d.room"):
            self.assertIn(f, hay)

    def test_viewers_only_see_what_they_may_do(self):
        acts = fn_body("paletteActions")
        self.assertIn("if (local && !S.meta.demo) a('act:scan'", acts)
        self.assertIn("if (local) a('act:check'", acts)
        block = acts[acts.index("  if (local) {\n"):]
        block = block[:block.index("\n  }\n")]
        for aid in ("act:pair", "act:backup", "act:restore", "act:wizard"):
            self.assertIn(aid, block)
        self.assertIn("if (S.meta.remote || !S.ai.s) return [];", fn_body("settingEntries"))
        # settings load on first use only, on this computer
        self.assertIn("if (!S.meta.remote && !S.ai.s && !S.ai.loading)", fn_body("openPalette"))

    def test_assistant_is_prefilled_never_sent(self):
        acts = fn_body("paletteActions")
        self.assertIn("a('ask', T('app.palette.ask', { q: S.pal.q.trim() }), 'i-spark', () => openChat({ draft: S.pal.q.trim() })", acts)
        for name in ("paletteActions", "paletteItems", "runPalette", "renderPalette"):
            self.assertNotIn("chat('send')", fn_body(name), name)

    def test_one_hour_mute_never_shortens_an_existing_tuning(self):
        body = fn_body("snoozeKinds")
        self.assertIn("getJSON('/api/tuning')", body)
        self.assertIn("kinds.filter(k => !tuned.includes(k))", body)
        self.assertIn("for: '1h'", body)
        self.assertIn("/api/tuning/undo", body)                    # ONE undo puts every row back
        crit = re.search(r"const PAUSE_KINDS = \[(.*?)\];", JS).group(1)
        for k in ("threat", "exposure", "upnp"):                   # tuning.CRITICAL_KINDS stay on
            self.assertNotIn(f"'{k}'", crit)

    def test_focus_returns_before_the_entry_runs(self):
        body = fn_body("runPalette")
        self.assertLess(body.index("closePalette(false)"), body.index("it.run()"))

    def test_modal_keeps_keyboard_control(self):
        # (review fix) a click on the hint / a heading must not move focus to the page behind:
        # mousedown inside the panel keeps it in the text box ...
        md = JS[JS.index("$('#palette').addEventListener('mousedown'"):][:300]
        self.assertIn("else if (e.target !== $('#palq') && !(e.target.id === 'pallist'", md)
        self.assertIn("e.preventDefault();", md)
        # ... the page behind is inert while it is open, and given back on close ...
        self.assertIn("['.app', '#drawer', '#chatpanel']", fn_body("openPalette"))
        self.assertIn("el.inert = true", fn_body("openPalette"))
        self.assertIn("el.inert = false", fn_body("closePalette"))
        # ... and wherever the focus is, Esc closes, Tab returns to the box, no shortcut fires
        glob = JS[JS.index("if (S.pal.open) {"):][:500]
        self.assertIn("if (e.key === 'Escape') { e.preventDefault(); closePalette(); }", glob)
        self.assertIn("$('#palq').focus()", glob)
        self.assertIn("return;\n  }\n  if (S.keys.open)", glob)

    def test_unknown_remembered_room_or_owner_stays_visible(self):
        # (review fix) #/devices?room=gone: the menu shows "gone", not "All rooms"
        body = fn_body("viewDevices")
        self.assertIn("keepCur(", body)
        self.assertRegex(body, r"const rooms = keepCur\(.*, f\.room\);")
        self.assertRegex(body, r"const owners = keepCur\(.*, f\.owner\);")


class RememberedView(unittest.TestCase):
    def test_versioned_namespaced_and_validated(self):
        self.assertIn("const viewKey = () => 'netwarden.view.v' + VIEW_V + '.' + dbId();", JS)
        load = fn_body("viewLoad")
        self.assertIn("o.v !== VIEW_V", load)
        self.assertIn("catch (e) { o = null; }", load)
        pages = re.search(r"const VIEW_PAGES = \{(.*?)\n\};", JS, re.S).group(1)
        names = re.findall(r"^  (\w+): \{", pages, re.M)
        self.assertEqual(names, ["devices", "map", "suggestions", "report"])   # report: round 9 X
        for n in names:   # every remembered page is a real page
            self.assertIn(f"'{n}'", re.search(r"const GROUPS = \[(.*?)\n\];", JS, re.S).group(1))

    def test_hash_query_is_relative_and_parsed_off_the_route(self):
        # only "#/..." URLs are ever written (base-aware: works under the HA ingress prefix)
        calls = re.findall(r"history\.(?:replaceState|pushState)\((.*?)\);", JS)
        self.assertEqual(len(calls), 3, calls)
        for call in calls:
            url = re.search(r"''(?:, (.+))?$", call).group(1)
            self.assertIn(url, (None, "w2", "'#/welcome'"), call)
        self.assertIn("w2 = '#/' + S.base", JS)
        ph = fn_body("parseHash")
        self.assertIn("full.indexOf('?')", ph)
        self.assertIn("new URLSearchParams(full.slice(qi + 1, qi + 1 + 600))", ph)   # bounded
        self.assertIn("VIEW_PAGES[r.name].set(viewClean(r.name, r.query", fn_body("onRoute"))

    def test_back_and_reload_restore_scroll_per_entry(self):
        self.assertIn("history.scrollRestoration = 'manual'", JS)
        visit = fn_body("entryVisit")
        self.assertIn("scrollKeep(curEntry)", visit)                   # the entry being left
        self.assertIn("history.replaceState(Object.assign({}, history.state, { nw: id }), '')", visit)
        self.assertIn("S.backY = id && typeof scrollMap[id] === 'number'", JS)
        self.assertIn("restoreScroll(back)", fn_body("onRoute"))
        self.assertIn("const SCROLL_KEY = 'netwarden.scroll', SCROLL_MAX = 60;", JS)

    def test_open_sections_persist(self):
        self.assertIn("document.addEventListener('toggle'", JS)
        self.assertIn('data-persist="score-why"${persistOpen(\'score-why\')}', JS)


class Locales(unittest.TestCase):
    def test_every_language_has_real_translations(self):
        en = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
        for code in i18n.CODES:
            loc = json.loads((LOCALES / f"{code}.json").read_text(encoding="utf-8"))
            for k in NEW_KEYS + ["app.palette_placeholder"]:
                self.assertIn(k, loc, (code, k))
                self.assertEqual(sorted(re.findall(r"\{\w+\}", loc[k])), sorted(re.findall(r"\{\w+\}", en[k])), (code, k))
                if code != "en" and k not in ("app.palette.n_results",):
                    self.assertNotEqual(loc[k], en[k], (code, k))
        hant = json.loads((LOCALES / "zh-Hant.json").read_text(encoding="utf-8"))
        hans = json.loads((LOCALES / "zh-Hans.json").read_text(encoding="utf-8"))
        for k in NEW_KEYS:
            self.assertNotEqual(hant[k], hans[k], k)
            for loc in (hant, hans):
                self.assertFalse(re.search("[，：（）]", loc[k]), k)   # zh punctuation stays ASCII
        self.assertIn("單鍵", hant["app.key.single"])
        self.assertIn("单键", hans["app.key.single"])


class NodeMatcher(unittest.TestCase):
    def test_palette_matcher_in_node(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed (CI's js job runs it)")
        r = subprocess.run([node, str(ROOT / "tests" / "js" / "palette_match_test.js")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_ci_runs_it(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("node tests/js/palette_match_test.js", ci)


if __name__ == "__main__":
    unittest.main()
