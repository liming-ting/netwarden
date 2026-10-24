"""Round 9 W: the static live demo (scripts/build_static_demo.py, static/demo.js, the Pages
workflow). One small build (2 languages, --quick) in a temp dir; the full one is the
workflow's (and `python3 scripts/build_static_demo.py --out /tmp/x` by hand)."""
import importlib.util
import ipaddress
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from netwarden import web
from test_round6_o import NothingPrivate

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = json.loads((ROOT / "tests" / "fixtures" / "static_demo_names.json").read_text(encoding="utf-8"))
APP = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")


def _builder():
    spec = importlib.util.spec_from_file_location("build_static_demo", ROOT / "scripts" / "build_static_demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _builder()
PLANTED = b"/home/" + b"someone/"   # split: the repo's own scanner (test_round6_o) reads this file


class RequestMap(unittest.TestCase):
    """The builder and demo.js must name the same file for the same request."""

    def test_python_side_matches_the_fixture(self):
        self.assertGreaterEqual(len(FIXTURE["files"]), 20)
        for request, fallback, want in FIXTURE["files"]:
            self.assertEqual(B.static_name(request, fallback), want, request)
        for mode, q, lang, want in FIXTURE["chat"]:
            self.assertEqual(B.chat_name(mode, q, lang), want, q)
        for lang, want in FIXTURE["index"]:
            self.assertEqual(B.chat_index(lang), want)

    def test_fnv_known_values(self):
        self.assertEqual(B.fnv(""), "811c9dc5")
        self.assertEqual(B.fnv("a"), "e40c292c")
        self.assertEqual(B.fnv("foobar"), "bf9cf968")

    def test_names_never_leave_the_data_dir(self):
        for r in ("/api/overview?lang=../../etc", "/api/device?mac=../../x&lang=en", "/api/meta?lang=<b>"):
            name = B.static_name(r)
            self.assertTrue(name.startswith("demo-data/") and ".." not in name, name)

    def test_node_side(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed (CI's js job runs it)")
        r = subprocess.run([node, str(ROOT / "tests" / "js" / "static_demo_test.js")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_ci_runs_it(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("node tests/js/static_demo_test.js", ci)


class QuickBuild(unittest.TestCase):
    NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)   # a Wednesday, pinned

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="nw_w_test_")
        cls.out = Path(cls.tmp.name) / "site"
        cls.stats = B.build(cls.out, now=cls.NOW, langs=["en", "zh-Hant"], quick=True,
                            site_url="https://example.invalid/netwarden", log=lambda *a: None)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def read(self, rel):
        return (self.out / rel).read_text(encoding="utf-8")

    def files(self):
        return [p for p in self.out.rglob("*") if p.is_file()]

    def test_the_page(self):
        page = self.read("index.html")
        self.assertIn('data-static-demo="1"', page)
        self.assertIn('src="static/demo.js', page)
        self.assertIn('http-equiv="Content-Security-Policy"', page)
        self.assertIn('property="og:image" content="https://example.invalid/netwarden/og-image.png"', page)
        self.assertIn('property="og:title"', page)
        self.assertIn('name="description"', page)
        self.assertNotRegex(page, r'(src|href)="/')                 # works under any sub-path
        self.assertNotRegex(page, r'(src|href)="(https?:)?//(?!example\.invalid)')   # nothing external loaded
        self.assertTrue((self.out / ".nojekyll").exists())
        self.assertTrue((self.out / "og-image.png").read_bytes().startswith(b"\x89PNG"))
        for name in B.STATIC_FILES:
            self.assertTrue((self.out / "static" / name).exists(), name)

    def test_meta_is_the_demo_and_offline(self):
        meta = json.loads(self.read("demo-data/api/meta.json"))
        self.assertTrue(meta["demo"])
        self.assertEqual(meta["ai_mode"], "offline")
        self.assertEqual(meta["db_id"], "static-demo")
        sd = meta["static_demo"]
        self.assertEqual(sd["built_at"], "2026-10-21T12:00:00Z")
        for k in ("install_url", "install_url_zh", "source_url"):
            self.assertTrue(sd[k].startswith("https://"), k)

    def test_answers_for_the_pages(self):
        for lang in ("en", "zh-Hant"):
            for req in ("/api/locale", "/api/overview", "/api/settings", "/api/ai/questions"):
                self.assertTrue((self.out / B.static_name(req + "?lang=" + lang)).exists(), (lang, req))
            idx = json.loads(self.read(B.chat_index(lang)))
            self.assertTrue(idx["suggested"])
            for q in idx["answers"]:
                self.assertTrue((self.out / B.chat_name("chat", q, lang)).exists(), q)
            self.assertTrue((self.out / B.chat_name("insight", "", lang)).exists())
        for lang in ("en", "zh-Hant"):   # describes the demo's host, not the build machine
            pair = json.loads(self.read(B.static_name("/api/pair/sessions?lang=" + lang)))
            self.assertEqual(pair["url"], B.DEMO_LAN_URL)
            self.assertIsNone(pair["wsl_firewall"])
        from netwarden import i18n
        for lang in ("en", "zh-Hant"):   # (review fix) no ".env / restart" advice in the demo
            idx = json.loads(self.read(B.chat_index(lang)))
            streams = [self.read(B.chat_name("chat", q, lang)) for q in idx["answers"]]
            streams.append(self.read(B.chat_name("insight", "", lang)))
            note = json.dumps(i18n.t("app.demo.chat_only", lang), ensure_ascii=False)[1:-1]
            for sse in streams:
                self.assertNotIn("ANTHROPIC_API_KEY", sse)
                self.assertNotIn("--offline-ai", sse)
            self.assertTrue(any(note in sse for sse in streams), lang)
        loc = json.loads(self.read("demo-data/zh-Hant/api/locale.json"))
        self.assertIn("app.demo.banner", json.dumps(loc, ensure_ascii=False))
        self.assertGreater(self.stats["requests"], 50)

    def test_every_json_parses_and_html_links_are_relative(self):
        for p in self.files():
            if p.suffix == ".json":
                json.loads(p.read_text(encoding="utf-8"))
            elif p.suffix == ".html":
                self.assertNotRegex(p.read_text(encoding="utf-8"), r'(src|href)="/', p.name)

    def test_size(self):
        total = sum(p.stat().st_size for p in self.files())
        self.assertLess(total, 15_000_000)
        self.assertEqual(total, self.stats["bytes"])

    def test_nothing_private_in_the_output(self):
        nets = set()
        local = ROOT / "CLAUDE.local.md"
        if local.exists():
            nets = NothingPrivate.owner_networks(local.read_text(encoding="utf-8"))
        bad = []
        for p in self.files():
            if p.suffix == ".png":
                continue
            rel = p.relative_to(self.out).as_posix()
            for no, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if NothingPrivate.HOME_PATH.search(line):
                    bad.append((rel, no, "home path"))
                for m in NothingPrivate.EMAIL.finditer(line):
                    if not NothingPrivate.OK_EMAIL_DOMAINS.search(m.group(1)) and "noreply" not in m.group(0):
                        bad.append((rel, no, "e-mail address"))
                if NothingPrivate.KEYISH.search(line):
                    bad.append((rel, no, "key-like string"))
                for m in NothingPrivate.IPV4.finditer(line):
                    try:
                        a = ipaddress.ip_address(m.group(1))
                    except ValueError:
                        continue
                    if any(a in n for n in nets):
                        bad.append((rel, no, "owner LAN address"))
        self.assertEqual(bad, [])   # file, line, category - never the value itself


class Guards(unittest.TestCase):
    def test_privacy_scan_names_file_and_category_only(self):
        site = B.Site()
        site.put("demo-data/en/api/x.json", b'{"a": 1,\n "p": "' + PLANTED + b'secret.db"}')
        with self.assertRaises(B.BuildError) as cm:
            B.privacy_scan(site)
        msg = str(cm.exception)
        self.assertIn("demo-data/en/api/x.json:2", msg)
        self.assertNotIn("someone", msg)
        site = B.Site()
        site.put("a.json", b'{"db": "/tmp/nw_static_demo_x/demo.db"}')
        with self.assertRaises(B.BuildError):
            B.privacy_scan(site, ["/tmp/nw_static_demo_x"])
        site = B.Site()
        site.put("og-image.png", PLANTED)   # binary files are not text-scanned
        B.privacy_scan(site, addresses=[])

    def test_privacy_scan_build_machine_addresses(self):
        site = B.Site()
        site.put("a.json", b'{"url": "http://10.20.30.40:8787/"}')
        with self.assertRaises(B.BuildError) as cm:
            B.privacy_scan(site, addresses=["10.20.30.40"])
        self.assertIn("a.json:1: contains a build machine address", str(cm.exception))
        self.assertNotIn("10.20.30.40", str(cm.exception))
        site = B.Site()
        site.put("a.json", b'{"ip": "10.20.30.4", "x": "110.20.30.40", "v": "10.20.30.400"}')
        B.privacy_scan(site, addresses=["10.20.30.40"])   # whole addresses only
        for a in B.machine_addresses():                   # never loopback / the demo's own LAN
            self.assertFalse(a.startswith(("127.", "192.168.1.")) or a == "::1", "category: address")

    def test_write_guards(self):
        for target in (B.ROOT, B.ROOT / "data"):
            with self.assertRaises(B.BuildError):
                B._write(B.Site(), target)
        with tempfile.TemporaryDirectory() as tmp:
            other = Path(tmp) / "other"
            other.mkdir()
            (other / "keep.txt").write_text("x")
            with self.assertRaises(B.BuildError):         # not empty, not an earlier build
                B._write(B.Site(), other)
            self.assertTrue((other / "keep.txt").exists())
            site = B.Site()
            site.put("index.html", b"<p>1</p>")
            site.put("demo-data/a.json", b"{}")
            out = Path(tmp) / "site"
            B._write(site, out)
            (out / "stale.json").write_text("{}")
            site.files.pop("demo-data/a.json")
            B._write(site, out)                           # an earlier build: replaced as a whole
            self.assertFalse((out / "stale.json").exists())
            self.assertFalse((out / "demo-data").exists())

    def test_unknown_language_refused(self):
        with self.assertRaises(B.BuildError):
            B.build(Path(tempfile.gettempdir()) / "nw_never", langs=["xx-Nope"], log=lambda *a: None)


class RealAppUnchanged(unittest.TestCase):
    """The demo switch exists only in the static build's index.html."""

    def test_real_page_has_no_demo_flag(self):
        page = web.index_html("")
        page = page.decode("utf-8") if isinstance(page, bytes) else page
        self.assertNotIn("data-static-demo", page)
        self.assertNotIn("demo.js", page)
        self.assertIn("demo.js", web.ASSETS)   # served (whitelisted) but never loaded by the app

    def test_demo_switch_needs_both_the_flag_and_the_module(self):
        self.assertIn("const DEMO = document.documentElement.dataset.staticDemo === '1' && "
                      "typeof window.NWDemo === 'object';", APP)

    def test_no_write_request_in_demo_mode(self):
        posts = [m.start() for m in re.finditer(r"method: 'POST'", APP)]
        self.assertEqual(len(posts), 2)                                  # postJSON + the chat stream
        pj = APP.index("async function postJSON")
        self.assertIn("if (DEMO) throw demoRefused();", APP[pj:pj + 200])
        self.assertTrue(pj < posts[0] < pj + 300)
        self.assertIn("const r = DEMO ? await demoAnswer(", APP[posts[1] - 200:posts[1]])
        self.assertNotRegex(APP, r"sendBeacon|XMLHttpRequest|method: \"POST\"|method: 'PUT'|method: 'DELETE'")
        lc = APP.index("function liveConnect")
        self.assertIn("if (DEMO ||", APP[lc:lc + 120])
        rw = APP.index("function registerWorker")
        self.assertIn("if (DEMO ||", APP[rw:rw + 120])
        self.assertEqual(APP.count("innerHTML"), 2)

    def test_banner_strings_in_every_locale(self):
        for p in sorted((ROOT / "netwarden" / "locales").glob("*.json")):
            loc = json.loads(p.read_text(encoding="utf-8"))
            for k in ("app.demo.banner", "app.demo.install", "app.demo.source", "app.demo.hide",
                      "app.demo.readonly", "app.demo.chat_only", "app.demo.full_report",
                      "app.demo.needs_install", "demo.og_title", "demo.og_description", "demo.og_image_alt"):
                self.assertTrue(loc.get(k, "").strip(), (p.name, k))


class PagesWorkflow(unittest.TestCase):
    def setUp(self):
        self.wf = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")

    def test_manual_only_with_current_official_actions(self):
        on = self.wf.split("\non:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(on.strip(), "workflow_dispatch:")
        for a in ("actions/configure-pages@v6", "actions/upload-pages-artifact@v5", "actions/deploy-pages@v5"):
            self.assertIn(a, self.wf)
        self.assertIn("python3 scripts/build_static_demo.py --out _site", self.wf)
        self.assertIn("include-hidden-files: true", self.wf)
        self.assertIn("concurrency:", self.wf)

    def test_write_permissions_on_the_deploy_job_only(self):
        self.assertIn("\npermissions: {}\n", self.wf)
        build, deploy = self.wf.split("\n  deploy:\n", 1)
        self.assertNotIn(": write", build)
        self.assertIn("pages: write", deploy)
        self.assertIn("id-token: write", deploy)
        self.assertEqual(self.wf.count(": write"), 2)

    def test_no_expression_pasted_into_a_script(self):
        # (review fix) step outputs reach `run:` through env:, never as ${{ }} in the script
        for run in re.findall(r"^\s+run: (.*)$", self.wf, re.M):
            self.assertNotIn("${{", run)
        self.assertIn("SITE_URL: ${{ steps.pages.outputs.base_url }}", self.wf)


if __name__ == "__main__":
    unittest.main()
