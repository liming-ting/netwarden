"""
Tests for netwarden.i18n - the language list, normalize(), and the locale files
themselves (every key in every language, placeholders intact, the two Chinese
scripts kept apart). Pure, deterministic, no network.
"""
import re
import unittest

from netwarden import i18n

EXPECTED = ["en", "zh-Hans", "zh-Hant", "es", "pt-BR", "ja", "de", "fr", "ko", "ru", "id", "hi"]

# Characters that differ between the scripts; one side must never show up in the other.
SIMPLIFIED_ONLY = "设备网务云广载关闭询识语视线连远头机时历险恶报简体发现开统戏购们这为么还没记变对应话问题详动测试浏览拦胁单启传尔见点击运数据"
TRADITIONAL_ONLY = "設備網務雲廣載關閉詢識語視線連遠頭機時歷險惡報簡體發現開統戲購們這為麼還沒記變對應話問題詳動測試瀏覽攔脅單啟傳爾見點擊運數據裝"
_PH = re.compile(r"{(\w+)}")


def _values(code):
    return {k: v for k, v in i18n._catalog()[code].items() if k != "_meta"}


class LanguageListTests(unittest.TestCase):
    def test_twelve_languages_in_ui_order(self):
        self.assertEqual(i18n.CODES, EXPECTED)
        names = dict((c, n) for c, n, _l in i18n.LANGS)
        self.assertEqual(names["zh-Hant"], "繁體中文")
        self.assertEqual(names["pt-BR"], "Português (Brasil)")
        self.assertEqual(names["hi"], "हिन्दी")

    def test_default_is_traditional_chinese(self):
        self.assertEqual(i18n.DEFAULT, "zh-Hant")

    def test_llm_language_names(self):
        self.assertEqual(i18n.llm_language("zh-Hant"), "Traditional Chinese (繁體中文)")
        self.assertEqual(i18n.llm_language("pt-BR"), "Brazilian Portuguese (Português do Brasil)")
        self.assertIn("Japanese", i18n.llm_language("ja"))
        self.assertIn("Traditional Chinese", i18n.llm_language("繁體中文"))  # legacy name


class NormalizeTests(unittest.TestCase):
    def test_codes_pass_through(self):
        for code in EXPECTED:
            self.assertEqual(i18n.normalize(code), code)

    def test_legacy_names(self):
        self.assertEqual(i18n.normalize("繁體中文"), "zh-Hant")
        self.assertEqual(i18n.normalize("简体中文"), "zh-Hans")
        self.assertEqual(i18n.normalize("English"), "en")
        self.assertEqual(i18n.normalize("english"), "en")
        self.assertEqual(i18n.normalize("Español"), "es")
        self.assertEqual(i18n.normalize("日本語"), "ja")
        self.assertEqual(i18n.normalize("Traditional Chinese (繁體中文)"), "zh-Hant")

    def test_regional_tags_case_insensitive(self):
        self.assertEqual(i18n.normalize("zh-tw"), "zh-Hant")
        self.assertEqual(i18n.normalize("ZH_TW"), "zh-Hant")
        self.assertEqual(i18n.normalize("zh-HK"), "zh-Hant")
        self.assertEqual(i18n.normalize("zh-Hant-TW"), "zh-Hant")
        self.assertEqual(i18n.normalize("zh-cn"), "zh-Hans")
        self.assertEqual(i18n.normalize("zh-Hans-CN"), "zh-Hans")
        self.assertEqual(i18n.normalize("zh"), "zh-Hans")
        self.assertEqual(i18n.normalize("pt-br"), "pt-BR")
        self.assertEqual(i18n.normalize("PT_BR"), "pt-BR")
        self.assertEqual(i18n.normalize("pt"), "pt-BR")
        self.assertEqual(i18n.normalize("en-US"), "en")
        self.assertEqual(i18n.normalize("de-AT"), "de")
        self.assertEqual(i18n.normalize("ko-KR"), "ko")

    def test_unknown_and_empty_fall_back_to_default(self):
        for v in ("klingon", "xx-YY", "", None, "   "):
            self.assertEqual(i18n.normalize(v), "zh-Hant")
        self.assertIsNone(i18n.match("klingon"))

    def test_accept_language(self):
        self.assertEqual(i18n.from_accept_language("ja-JP,ja;q=0.9,en;q=0.8"), "ja")
        self.assertEqual(i18n.from_accept_language("xx,en-GB;q=0.5,zh-TW;q=0.7"), "zh-Hant")
        self.assertIsNone(i18n.from_accept_language("xx-YY, tlh"))
        self.assertIsNone(i18n.from_accept_language(""))


class TranslateTests(unittest.TestCase):
    def test_t_with_placeholders_and_fallback(self):
        self.assertEqual(i18n.t("svc.time", "en", brand="NTP"), "NTP time sync")
        self.assertEqual(i18n.t("svc.time", "zh-Hant", brand="NTP"), "NTP 校時")
        self.assertEqual(i18n.t("ui.yes", "Deutsch"), "Ja")           # legacy name ok
        self.assertEqual(i18n.t("no.such.key", "ja"), "no.such.key")  # visible, no crash
        self.assertEqual(i18n.t("svc.time", "en"), "{brand} time sync")  # unfilled stays

    def test_strings_merges_english_for_gaps(self):
        s = i18n.strings("fr")
        self.assertEqual(s["ui.yes"], "Oui")
        self.assertNotIn("_meta", s)


class LocaleFileTests(unittest.TestCase):
    def test_every_key_present_in_every_locale(self):
        ref = set(_values("en"))
        self.assertGreater(len(ref), 100)
        for code in EXPECTED:
            with self.subTest(lang=code):
                keys = set(_values(code))
                self.assertEqual(ref - keys, set(), f"{code} is missing keys")
                self.assertEqual(keys - ref, set(), f"{code} has keys English lacks")
                self.assertTrue(all(isinstance(v, str) and v.strip()
                                    for v in _values(code).values()))
        self.assertEqual(i18n.missing_keys(), {c: [] for c in EXPECTED})

    def test_placeholders_match_english(self):
        en = _values("en")
        for code in EXPECTED:
            for key, text in _values(code).items():
                with self.subTest(lang=code, key=key):
                    self.assertEqual(set(_PH.findall(text)), set(_PH.findall(en[key])))

    def test_real_translations_not_english_copies(self):
        # Chrome strings must actually be translated (brand-only strings may match).
        en = _values("en")
        for code in EXPECTED[1:]:
            for key in ("ui.devices_title", "ui.btn_insight", "ui.rename_prompt",
                        "digest.all_clear", "cat.ads", "threat.xmeye.why"):
                with self.subTest(lang=code, key=key):
                    self.assertNotEqual(_values(code)[key], en[key])

    def test_traditional_has_no_simplified_characters(self):
        for key, text in _values("zh-Hant").items():
            bad = [ch for ch in text if ch in SIMPLIFIED_ONLY]
            self.assertEqual(bad, [], f"zh-Hant {key}: {text}")

    def test_simplified_has_no_traditional_characters(self):
        for key, text in _values("zh-Hans").items():
            bad = [ch for ch in text if ch in TRADITIONAL_ONLY]
            self.assertEqual(bad, [], f"zh-Hans {key}: {text}")


if __name__ == "__main__":
    unittest.main()
