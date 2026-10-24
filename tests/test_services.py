"""
Tests for netwarden.services - the domain -> human service/category map.
Pure, deterministic, no network.
"""
import unittest

from netwarden import services


class ClassifyTests(unittest.TestCase):
    def test_known_domains(self):
        self.assertEqual(services.classify("instagram.com"), ("Instagram", "social"))
        self.assertEqual(services.classify("netflix.com"), ("Netflix", "video"))
        name, cat = services.classify("xmeye.net")
        self.assertIn("XMEye", name)
        self.assertEqual(cat, "iot")

    def test_subdomain_matches_suffix(self):
        self.assertEqual(services.classify("star1.xmeye.net")[0],
                         services.classify("xmeye.net")[0])
        self.assertEqual(services.classify("graph.facebook.com"), ("Facebook", "social"))
        self.assertEqual(services.classify("log-config.samsungacr.com")[1], "iot")

    def test_longest_suffix_wins(self):
        # push.apple.com is more specific than apple.com
        self.assertEqual(services.classify("push.apple.com"),
                         ("Apple push notifications", "system"))
        self.assertEqual(services.classify("store.apple.com"), ("Apple services", "system"))

    def test_unknown_domain(self):
        self.assertEqual(services.classify("totally-unknown-xyz.example"), (None, "unknown"))
        self.assertEqual(services.classify(""), (None, "unknown"))

    def test_ad_category(self):
        self.assertEqual(services.classify("doubleclick.net")[1], "ads")
        self.assertEqual(services.classify("googleads.g.doubleclick.net")[1], "ads")


class LocalizedNameTests(unittest.TestCase):
    def test_brands_are_never_translated(self):
        for lang in ("en", "zh-Hant", "ja", "ru"):
            self.assertEqual(services.classify("instagram.com", lang)[0], "Instagram")

    def test_generic_descriptors_are_translated(self):
        self.assertEqual(services.classify("pool.ntp.org", "en")[0], "NTP time sync")
        self.assertEqual(services.classify("pool.ntp.org", "zh-Hant")[0], "NTP 校時")
        self.assertEqual(services.classify("roborock.com", "zh-Hans")[0], "Roborock 扫地机器人云端")
        self.assertEqual(services.classify("doubleclick.net", "de")[0], "Google-Werbung")
        self.assertIn("XMEye", services.classify("xmeye.net", "ko")[0])  # brand kept

    def test_category_names(self):
        self.assertEqual(services.category_name("ads", "en"), "Ads & tracking")
        self.assertEqual(services.category_name("ads", "zh-Hant"), "廣告/追蹤")
        self.assertEqual(services.category_name("unknown", "fr"), "Inconnu")

    def test_localize_device(self):
        dev = {"mac": "m", "services": ["NTP time sync"],
               "top_domains": [{"domain": "pool.ntp.org", "count": 3,
                                "service": "NTP time sync", "category": "system"}]}
        out = services.localize_device(dev, "zh-Hant")
        self.assertEqual(out["services"], ["NTP 校時"])
        self.assertEqual(out["top_domains"][0]["service"], "NTP 校時")
        self.assertEqual(out["top_domains"][0]["category"], "system")      # stable key
        self.assertEqual(out["top_domains"][0]["category_name"], "系統")
        self.assertEqual(dev["services"], ["NTP time sync"])               # input untouched


class ServicesForTests(unittest.TestCase):
    def test_dedupes_and_skips_unknown(self):
        out = services.services_for([
            "instagram.com", "cdninstagram.com",   # both -> Instagram (dedup)
            "gateway.icloud.com",                   # -> iCloud
            "nobody-knows-this.invalid",            # unknown -> skipped
        ])
        self.assertEqual(out, ["Instagram", "iCloud"])

    def test_preserves_first_appearance_order(self):
        out = services.services_for(["youtube.com", "netflix.com", "youtube.com"])
        self.assertEqual(out, ["YouTube", "Netflix"])


if __name__ == "__main__":
    unittest.main()
