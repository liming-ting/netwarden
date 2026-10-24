"""Stage U: the usability pass - seven places with sub-tabs (every old route still a page),
explained inbox actions, "Add a person…" from a device, plain wording in every language.

Static checks of the dashboard source + the locale files; no server, no LLM, no network.
"""
import json
import re
import unittest
from pathlib import Path

from netwarden import i18n

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "netwarden" / "static"
LOCALES = ROOT / "netwarden" / "locales"

# every page route the dashboard had before Stage U (bookmarks / deep links / docs)
OLD_PAGES = ["overview", "inbox", "devices", "map", "people", "security", "health", "suggestions",
             "privacy", "activity", "family", "ai", "system", "settings",
             "report"]   # round 9 X: Overview > Report (the shareable home report)


def groups(js):
    """GROUPS = [['overview', ['overview']], ...] -> [(place, [pages])]"""
    block = re.search(r"const GROUPS = \[(.*?)\n\];", js, re.S).group(1)
    return [(g, re.findall(r"'([a-z]+)'", pages))
            for g, pages in re.findall(r"\['([a-z]+)', \[([^\]]*)\]\]", block)]


def locale(code):
    return json.loads((LOCALES / f"{code}.json").read_text(encoding="utf-8"))


class NavigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (STATIC / "app.js").read_text(encoding="utf-8")
        cls.css = (STATIC / "app.css").read_text(encoding="utf-8")
        cls.groups = groups(cls.js)

    def test_at_most_seven_places_everyday_first_settings_last(self):
        names = [g for g, _ in self.groups]
        self.assertLessEqual(len(names), 7)
        self.assertEqual(names[0], "overview")
        self.assertEqual(names[-1], "settings")
        self.assertEqual(len(set(names)), len(names))

    def test_every_old_route_is_still_a_page_in_exactly_one_place(self):
        pages = [p for _, ps in self.groups for p in ps]
        self.assertEqual(sorted(pages), sorted(OLD_PAGES))
        self.assertIn("const PAGES = GROUPS.flatMap(x => x[1]).concat(['welcome']);", self.js)
        # the drawers and one person keep their own routes
        for needle in ("['device', 'service', 'domain'].includes(name)", "name === 'people' && /^\\d{1,9}$/"):
            self.assertIn(needle, self.js)

    def test_place_link_opens_its_first_page_and_sub_tabs_render_above_the_view(self):
        self.assertIn('href="#/${first}"', self.js)
        self.assertIn("morph($('#view'), html`${subTabs()}${VIEWS[S.base]()}`);", self.js)
        self.assertIn(".subtabs a[aria-current=\"page\"]", self.css)
        # the wizard belongs to Settings
        self.assertIn("[['welcome', 'settings']]", self.js)

    def test_phone_bar_has_four_places_and_more(self):
        m = re.search(r"const NAV_PRIMARY = \[([^\]]*)\]", self.js)
        primary = re.findall(r"'([a-z]+)'", m.group(1))
        self.assertEqual(len(primary), 4)
        self.assertTrue(set(primary) <= {g for g, _ in self.groups})

    def test_digit_keys_follow_the_places_and_go_keys_cover_every_page(self):
        self.assertIn("GROUPS[+e.key - 1][1][0]", self.js)
        self.assertNotIn("SECTIONS", self.js)
        go = dict(re.findall(r"(\w): '([a-z]+)'", re.search(r"const GO_KEYS = \{(.*?)\};", self.js, re.S).group(1)))
        self.assertEqual(sorted(go.values()), sorted(OLD_PAGES))

    def test_one_badge_per_place(self):
        # the inbox already holds every alert + suggestion: no second count on Network
        body = re.search(r"function groupCount\(g\) \{(.*?)\n\}", self.js, re.S).group(1)
        self.assertIn("inboxCount()", body)
        self.assertNotIn("securityCount", body)
        self.assertNotIn("sugCount", body)


class InboxAndPeopleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (STATIC / "app.js").read_text(encoding="utf-8")

    def test_inbox_rows_keep_every_action_reachable(self):
        body = re.search(r"function inboxActs\(it\) \{(.*?)\n\}", self.js, re.S).group(1)
        # main = the first action + trust; the rest (and Tune) in the disclosure, each explained
        self.assertIn("i === 0 || a === 'trust'", body)
        self.assertIn("<details class=\"ib-more\"", body)
        self.assertIn("TN('app.inbox.hint.' + a", body)
        self.assertIn("tuneBtn(tune, it.name)", body)

    def test_add_a_person_from_a_device(self):
        # fix stage: a button next to the list, not a list entry (arrow keys fire `change`
        # on every step in some browsers and must never navigate away - WCAG 3.2.2)
        self.assertIn("personOptions(assignValue(d), false)", self.js)
        self.assertNotIn("value=\"new\"", self.js)
        self.assertIn("case 'add-person-for': addPersonFor(b.dataset.mac)", self.js)
        # the device goes to the NEW person only (a person edited from the form never takes it)
        self.assertIn("const after = f && !body.id && S.ppl.assignAfter;", self.js)
        # not offered to a paired phone (it cannot add people from there either way: same rules)
        self.assertIn("S.meta.remote ? '' : html`<button type=\"button\" class=\"btn sm ghost\" "
                      "data-act=\"add-person-for\"", self.js)
        # cancelling goes back to the device's owner list
        body = re.search(r"function closePersonForm\(\) \{(.*?)\n\}", self.js, re.S).group(1)
        self.assertIn("go(devHref(after.mac))", body)
        self.assertIn("S.drawerFocus", body)

    def test_no_new_inner_html(self):
        self.assertEqual(len(re.findall(r"\.innerHTML\s*=", self.js)), 2)


class WordingTests(unittest.TestCase):
    NEW = ("app.navg.family", "app.navg.network", "app.subnav", "app.inbox.more_actions",
           "app.inbox.hint.ack", "app.inbox.hint.done", "app.inbox.hint.trust", "app.inbox.hint.mute",
           "app.inbox.hint.snooze", "app.inbox.hint.dismiss", "app.inbox.hint.tune",
           "app.ov.open_inbox", "app.ppl.add_new_opt", "app.ppl.assign_after")
    # fix stage: the button no longer carries the count; app.ov.todo_split says it once
    PLACEHOLDERS = {"app.subnav": "{section}", "app.inbox.hint.snooze": "{n}",
                    "app.ov.todo_split": "{alerts}", "app.ppl.assign_after": "{device}"}

    def test_new_keys_in_every_language_with_placeholders(self):
        for code in i18n.CODES:
            data = locale(code)
            for key in self.NEW:
                self.assertTrue(data.get(key, "").strip(), (code, key))
            for key, ph in self.PLACEHOLDERS.items():
                self.assertIn(ph, data[key], (code, key))

    def test_look_alike_names_are_gone(self):
        # "People" vs "Family" and "System" vs "Settings" read as the same thing in a menu
        for code in i18n.CODES:
            data = locale(code)
            labels = [data["app.nav." + p] for p in OLD_PAGES] + [data["app.navg.family"], data["app.navg.network"]]
            self.assertNotEqual(data["app.nav.system"], data["app.nav.settings"], code)
            self.assertNotEqual(data["app.nav.family"], data["app.navg.family"], code)
            self.assertEqual(len(set(labels)), len(labels), code)

    def test_quiet_summary_button_says_what_it_does(self):
        self.assertEqual(i18n.t("app.quiet.dismiss", "en"), "Hide summary")
        self.assertEqual(i18n.t("app.quiet.dismiss", "zh-Hant"), "隱藏摘要")

    def test_zh_hant_is_traditional_and_zh_hans_simplified(self):
        hant, hans = locale("zh-Hant"), locale("zh-Hans")
        for key in self.NEW:
            self.assertFalse(set(hant[key]) & set("这设备显隐网关闭让为"), key)
            self.assertFalse(set(hans[key]) & set("這裝備顯隱網關閉讓為"), key)


if __name__ == "__main__":
    unittest.main()
