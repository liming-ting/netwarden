"""Round 9 X: the shareable plain-language home-network report (report.py,
GET /api/report, `netwarden report`, the Report page)."""
from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import re
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from netwarden import (__main__ as cli, brain, demo, family_report, i18n, pairing, redact, report,
                       store, web)

ROOT = Path(__file__).resolve().parent.parent
JS = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")
UTC = ZoneInfo("UTC")
NOW = datetime(2026, 10, 21, 9, 30, tzinfo=timezone.utc)
HOSTILE = '<img src=x onerror=alert(1)>"&\'=HYPERLINK("x")'
_DEMO = {}


def demo_copy(dest: Path) -> Path:
    """A private copy of one demo DB built once for this module (sqlite backup)."""
    if "path" not in _DEMO:
        _DEMO["tmp"] = tempfile.TemporaryDirectory()
        _DEMO["path"] = Path(_DEMO["tmp"].name) / "demo.db"
        demo.build(_DEMO["path"])
    src, dst = sqlite3.connect(_DEMO["path"]), sqlite3.connect(dest)
    src.backup(dst)
    src.close()
    dst.close()
    return dest


def tearDownModule():
    if "tmp" in _DEMO:
        _DEMO["tmp"].cleanup()


class _DemoDB(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = demo_copy(Path(self.tmp.name) / "x.db")
        self.db = store.connect(self.path)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def html(self, lang="en", **opts):
        return report.render_html(report.build(self.db, lang, opts, env={}, tz=UTC, now=NOW))

    def md(self, lang="en", **opts):
        return report.render_md(report.build(self.db, lang, opts, env={}, tz=UTC, now=NOW))

    # what identifies this household
    def secrets(self):
        db = self.db
        return {
            "macs": [r[0] for r in db.execute("SELECT mac FROM devices")],
            "ips": [r[0] for r in db.execute("SELECT ip FROM devices WHERE ip IS NOT NULL AND ip != ''")],
            "people": [p["name"] for p in store.people(db)],
            "labels": [r[0] for r in db.execute("SELECT label FROM device_labels") if len(r[0]) > 3],
            "hostnames": [r[0] for r in db.execute("SELECT hostname FROM devices WHERE hostname IS NOT NULL")
                          if len(r[0]) > 3],
            "domains": [r[0] for r in db.execute("SELECT DISTINCT domain FROM dns_events") if "." in r[0]],
        }


def _body(text: str) -> str:
    """The report minus the header's source link (github.com is a domain, on purpose)."""
    return text.replace(report.netwarden.SOURCE_URL, "")


class OptionTests(unittest.TestCase):
    def test_defaults_and_periods(self):
        self.assertEqual(report.options(), {"period": 7, "privacy": "shareable", "names": "type",
                                            "people": "roles", "format": "html"})
        for raw, want in (("7", 7), ("7d", 7), ("30", 30), ("30D", 30), (30, 30), ("", 7)):
            self.assertEqual(report.options({"period": raw})["period"], want, raw)
        for raw in ("14", "0", "-7", "7x", "1e1", "3000", "७"):
            with self.assertRaises(report.BadOption) as cm:
                report.options({"period": raw})
            self.assertEqual(cm.exception.key, "period")

    def test_unknown_values_name_the_option(self):
        for key, bad in (("privacy", "everything"), ("names", "real"), ("people", "all"),
                         ("format", "pdf"), ("privacy", 3)):
            with self.assertRaises(report.BadOption) as cm:
                report.options({key: bad})
            self.assertEqual(cm.exception.key, key)

    def test_minimal_and_full_fix_the_name_options(self):
        self.assertEqual(report.options({"privacy": "minimal", "names": "keep", "people": "keep"})["names"], "type")
        self.assertEqual(report.options({"privacy": "minimal", "people": "keep"})["people"], "roles")
        self.assertEqual(report.options({"privacy": "full", "names": "type"})["names"], "keep")


class StructureTests(_DemoDB):
    def test_sections_per_level(self):
        full = [s["key"] for s in report.build(self.db, "en", {"privacy": "full"}, env={}, tz=UTC, now=NOW)["sections"]]
        self.assertEqual(full, ["score", "suggestions", "devices", "security", "health", "events"])
        share = [s["key"] for s in report.build(self.db, "en", {}, env={}, tz=UTC, now=NOW)["sections"]]
        self.assertEqual(share, full)
        mini = [s["key"] for s in report.build(self.db, "en", {"privacy": "minimal"}, env={}, tz=UTC,
                                               now=NOW)["sections"]]
        self.assertEqual(mini, ["score", "suggestions"])

    def test_html_is_self_contained_and_printable(self):
        h = self.html()
        self.assertTrue(h.startswith("<!doctype html>"))
        self.assertIn('<html lang="en">', h)
        self.assertIn("default-src 'none'; style-src 'unsafe-inline'; img-src data:", h)
        self.assertEqual(h.count("<style>"), 1)
        for bad in ("<script", "<link", "<img", "<iframe", " src=", "@import", "url(", "<form"):
            self.assertNotIn(bad, h)
        # the only absolute URL is the source link (a link, never fetched); SVGs carry their namespace
        urls = set(re.findall(r'https?://[^\s"<>)]+', h)) - {"http://www.w3.org/2000/svg"}
        urls = {u for u in urls if i18n.t("share.hidden", "en") not in u}   # "http://•••" in a step
        self.assertEqual(urls, {report.netwarden.SOURCE_URL})
        # print: margins for A4 and Letter alike, one section per page
        self.assertIn("@page{margin:15mm 13mm}", h)
        self.assertIn("@media print", h)
        self.assertIn("section{break-before:page", h)
        self.assertIn('<section id="s-score" class=first>', h)
        for key in ("score", "suggestions", "devices", "security", "health", "events"):
            self.assertIn(f'<section id="s-{key}"', h)
            self.assertIn(f'href="#s-{key}"', h)          # the table of contents
        self.assertGreaterEqual(h.count("<svg "), 3)        # pillars, device types, health
        self.assertEqual(h.count("<svg "), h.count('role="img" aria-label='))

    def test_header_date_period_level_version_source(self):
        h = self.html("en")
        self.assertIn("2026-10-21 09:30 UTC", h)
        self.assertIn(i18n.t("share.period_line", "en", days=7, start="2026-10-14", end="2026-10-21"), h)
        self.assertIn(i18n.t("share.level.shareable", "en"), h)
        self.assertIn(f"netwarden {report.netwarden.__version__}", h)
        self.assertIn(f'href="{report.netwarden.SOURCE_URL}"', h)
        self.assertIn(i18n.t("ui.demo_badge", "en"), h)
        m = self.md("en", period="30d", privacy="minimal")
        self.assertTrue(m.startswith("# " + i18n.t("share.title", "en") + "\n"))
        self.assertIn(i18n.t("share.period_line", "en", days=30, start="2026-09-21", end="2026-10-21"), m)
        self.assertIn(f"<{report.netwarden.SOURCE_URL}>", m)

    def test_markdown_sections_in_order(self):
        m = self.md("en", privacy="full")
        heads = re.findall(r"^## (.+)$", m, re.M)
        self.assertEqual(heads, [i18n.t("share.sec." + k, "en", days=7)
                                 for k in ("score", "suggestions", "devices", "security", "health", "events")])
        self.assertNotIn("<", m.replace(f"<{report.netwarden.SOURCE_URL}>", ""))   # no raw HTML in Markdown

    def test_deterministic(self):
        self.assertEqual(self.html(), self.html())
        self.assertEqual(self.md(privacy="full"), self.md(privacy="full"))

    def test_every_language(self):
        for lang in i18n.CODES:
            h = self.html(lang)
            self.assertIn(f'<html lang="{lang}">', h)
            self.assertIn(i18n.t("share.sec.suggestions", lang), h)
            self.assertIsNone(re.search(r"\{\w+\}", h), lang)      # every placeholder filled
            text = re.sub(r"<style>.*?</style>", "", _body(h), flags=re.S)   # (CSS: ".sug.high")
            self.assertIsNone(re.search(r"\b(share|app|sug|score)\.[a-z_.]+\b", text), lang)

    def test_zh_hant_is_the_default_language(self):
        doc = report.build(self.db, "", {}, env={}, tz=UTC, now=NOW)
        self.assertEqual(doc["meta"]["lang"], "zh-Hant")

    def test_score_and_suggestions_come_from_their_modules(self):
        from netwarden import score, suggestions
        doc = report.build(self.db, "en", {"privacy": "full"}, env={}, tz=UTC, now=NOW)
        sec = {s["key"]: s for s in doc["sections"]}
        big = next(b for b in sec["score"]["blocks"] if b["t"] == "score")
        self.assertEqual(big["score"], score.report(self.db, "en", {}, UTC)["score"])
        titles = [b["title"] for b in sec["suggestions"]["blocks"] if b["t"] == "sug"]
        want = [i["title"] for i in suggestions.report(self.db, "en", {})["open"]][:report.MAX_SUGGESTIONS]
        self.assertEqual(titles, want)
        self.assertTrue(any(b.get("rules") for b in sec["suggestions"]["blocks"] if b["t"] == "sug"))


class PrivacyTests(_DemoDB):
    def assert_scrubbed(self, text, what):
        s = self.secrets()
        body = _body(text)
        self.assertIsNone(redact.MAC_RE.search(body), what)
        self.assertIsNone(redact.IPV4_RE.search(body), what)
        for kind in ("macs", "ips", "people", "labels", "hostnames"):
            for v in s[kind]:
                self.assertNotIn(v, body, f"{what}: {kind}")
        for d in s["domains"]:
            self.assertNotIn(d, body, f"{what}: domain")

    def test_shareable_and_minimal_leave_out_addresses_names_and_domains(self):
        for level in ("shareable", "minimal"):
            for lang in ("en", "zh-Hant", "de"):
                self.assert_scrubbed(self.html(lang, privacy=level), f"{level} html {lang}")
                self.assert_scrubbed(self.md(lang, privacy=level, period="30"), f"{level} md {lang}")

    def test_shareable_replaces_people_by_roles_and_devices_by_type(self):
        h = self.html("en")
        self.assertIn(i18n.t("share.role.child", "en", n=1), h)
        self.assertIn(i18n.t("share.role.member", "en", n=1), h)
        self.assertIn(i18n.t("share.dev_n", "en", type=i18n.t("devtype.camera", "en"), n=1), h)
        self.assertNotIn("<pre>", h)                                    # no copyable rules
        self.assertIn(i18n.t("share.rules_hidden", "en"), h)

    def test_full_keeps_everything(self):
        s = self.secrets()
        h = self.html("en", privacy="full")
        for kind in ("macs", "ips", "people"):
            self.assertTrue(all(v in h for v in s[kind]), kind)
        self.assertIn("<pre>", h)                                        # the copyable rules
        self.assertIn("||", h)

    def test_keep_names_keep_people(self):
        store.set_label(self.db, self.secrets()["macs"][0], "媽媽的 iPad")
        names_only = self.html("zh-Hant", names="keep")
        self.assertNotIn("媽媽", names_only)                               # people are still roles
        self.assertIn("的 iPad", names_only)
        both = self.html("zh-Hant", names="keep", people="keep")
        self.assertIn("媽媽的 iPad", both)
        self.assertIn("小孩", both)
        self.assertIsNone(redact.MAC_RE.search(both))                       # still no addresses

    def test_kept_names_still_mask_domains_and_addresses(self):
        # (review fix) a kept name is swapped in after the masking: it must be masked itself
        mac = self.secrets()["macs"][0]
        store.set_label(self.db, mac, "secret-host.example.org via http://10.9.8.7/x aa:bb:cc:00:11:22")
        for fmt in ("html", "md"):
            text = _body(self.html("en", names="keep")) if fmt == "html" else self.md("en", names="keep")
            for leak in ("secret-host.example.org", "example.org", "10.9.8.7", "aa:bb:cc:00:11:22"):
                self.assertNotIn(leak, text, fmt)
            self.assertIn(" via ", text, fmt)                                 # the rest of the name stays
        self.assertIn("secret-host.example.org", self.html("en", privacy="full"))

    def test_hostile_names_are_escaped(self):
        mac = self.secrets()["macs"][0]
        store.set_label(self.db, mac, HOSTILE)
        for level in ("full", "shareable"):
            h = self.html("en", privacy=level, names="keep")
            self.assertNotIn("<img", h)
            self.assertNotIn("onerror=alert(1)>", h.replace("&lt;img src=x onerror=alert(1)&gt;", ""))
        full = self.html("en", privacy="full")
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;&quot;&amp;&#x27;", full)
        m = self.md("en", privacy="full")
        self.assertNotIn("<img", m)
        self.assertIn("&lt;img", m)

    def test_no_secrets_ever(self):
        env = {"ANTHROPIC_API_KEY": "sk-ant-api03-SECRET-xyz", brain.OFFLINE_ENV: "1",
               "NETWARDEN_ADGUARD_URL": "http://admin:hunter2@192.168.1.2:3000",
               "NETWARDEN_ADGUARD_PASSWORD": "hunter2"}
        code = pairing.new_code(self.db)["code"]
        for level in report.PRIVACY:
            for fmt in report.FORMATS:
                body = report.generate(self.db, "en", {"privacy": level, "format": fmt}, env=env, tz=UTC,
                                       now=NOW)[0].decode("utf-8")
                for bad in ("sk-ant", "SECRET", "hunter2", "admin:", code, "192.168.1.2:3000"):
                    self.assertNotIn(bad, body, (level, fmt, bad))


class ScrubberTests(_DemoDB):
    def scrubber(self, **opts):
        from netwarden import devicetype, naming
        return report.Scrubber(self.db, "en", report.options(opts), naming.display_names(self.db, "en"),
                               devicetype.classify_all(self.db))

    def test_addresses_and_domains_are_masked(self):
        s = self.scrubber()
        hid = i18n.t("share.hidden", "en")
        self.assertEqual(s.text("looks up dns.google and 8.8.8.8"), f"looks up {hid} and {hid}")
        self.assertEqual(s.text("server 2001:4860:4860::8888 answered"), f"server {hid} answered")
        self.assertEqual(s.text("edit data/trackers_custom.txt"), "edit data/trackers_custom.txt")
        self.assertEqual(s.text("version 0.1.0 · 3.5 ms"), "version 0.1.0 · 3.5 ms")
        self.assertEqual(s.text("aa:bb:cc:dd:ee:ff"), hid)

    def test_type_words_are_not_device_names(self):
        mac = self.secrets()["macs"][0]
        self.db.execute("UPDATE devices SET hostname = 'printer' WHERE mac = ?", (mac,))
        self.db.commit()
        self.assertEqual(self.scrubber().text("Printer"), "Printer")

    def test_full_is_untouched(self):
        s = self.scrubber(privacy="full")
        self.assertEqual(s.text("aa:bb:cc:dd:ee:ff 192.168.1.5 dns.google"), "aa:bb:cc:dd:ee:ff 192.168.1.5 dns.google")


class SecurityLinesTests(_DemoDB):
    def test_domains_flag(self):
        from netwarden import alerts, naming
        al = alerts.localize(alerts.compute(self.db), "en", naming.display_names(self.db, "en"))
        self.assertTrue(al["threats"])
        with_d = family_report._security_lines(al, "en")
        without = family_report._security_lines(al, "en", domains=False, changes=False, new=False)
        self.assertTrue(any(t["domain"] in "\n".join(with_d) for t in al["threats"]))
        self.assertFalse(any(t["domain"] in "\n".join(without) for t in al["threats"]))


# --- the web API -------------------------------------------------------------------------------

class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = demo_copy(Path(cls.tmp.name) / "w.db")
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def tearDown(self):
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))

    def get(self, path, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        c.request("GET", path, headers={"cookie": cookie} if cookie else {})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r, body

    def test_download_is_an_attachment(self):
        r, body = self.get("/api/report?lang=en")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("content-type"), "text/html; charset=utf-8")
        cd = r.getheader("content-disposition")
        self.assertTrue(cd.startswith('attachment; filename="netwarden-report-'), cd)
        self.assertTrue(cd.endswith('-7d-shareable.html"'), cd)
        self.assertEqual(r.getheader("cache-control"), "no-store")
        self.assertIn(b'<html lang="en">', body)
        r, body = self.get("/api/report?lang=ja&period=30d&privacy=minimal&format=md")
        self.assertEqual(r.getheader("content-type"), "text/markdown; charset=utf-8")
        self.assertIn('-30d-minimal.md"', r.getheader("content-disposition"))
        self.assertTrue(body.decode().startswith("# " + i18n.t("share.title", "ja")))

    def test_inline_preview(self):
        r, body = self.get("/api/report?inline=1&format=md")
        self.assertTrue(r.getheader("content-disposition").startswith("inline;"))
        self.assertEqual(r.getheader("content-type"), "text/plain; charset=utf-8")
        r, _ = self.get("/api/report?inline=1")
        self.assertEqual(r.getheader("content-type"), "text/html; charset=utf-8")

    def test_bad_options_are_localized_400(self):
        for q, key in (("period=14", "period"), ("privacy=all", "privacy"), ("format=pdf", "format"),
                       ("names=" + "x" * 500, "names")):
            r, body = self.get(f"/api/report?lang=de&{q}")
            self.assertEqual(r.status, 400, q)
            self.assertEqual(json.loads(body)["error"], i18n.t("err.bad_report_option", "de", option=key))

    def test_lan_viewer_gets_shareable_and_minimal_but_not_full(self):
        db = store.connect(self.path)
        try:
            token, _sid = pairing.redeem(db, pairing.new_code(db)["code"], "test phone")
        finally:
            db.close()
        web.Handler.is_local_client = staticmethod(lambda ip: False)          # "a phone"
        self.assertEqual(self.get("/api/report")[0].status, 401)              # no session
        cookie = f"{pairing.COOKIE}={token}"
        for q in ("", "?privacy=shareable", "?privacy=minimal&format=md"):
            self.assertEqual(self.get("/api/report" + q, cookie)[0].status, 200, q)
        r, body = self.get("/api/report?privacy=full&lang=fr", cookie)
        self.assertEqual(r.status, 403)
        self.assertEqual(json.loads(body)["error"], i18n.t("err.report_full_admin", "fr"))
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))
        self.assertEqual(self.get("/api/report?privacy=full")[0].status, 200)   # this computer


# --- the CLI -----------------------------------------------------------------------------------

class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = demo_copy(Path(self.tmp.name) / "c.db")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["report", "--db", str(self.path), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_writes_the_file(self):
        f = Path(self.tmp.name) / "r.html"
        code, out, _ = self.run_cli("--period", "30d", "--privacy", "minimal", "--lang", "en", "--out", str(f))
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), i18n.t("cli.report.saved", "en", path=f))
        self.assertIn('<html lang="en">', f.read_text(encoding="utf-8"))

    def test_md_from_the_extension_and_stdout(self):
        f = Path(self.tmp.name) / "r.md"
        self.assertEqual(self.run_cli("--out", str(f))[0], 0)
        self.assertTrue(f.read_text(encoding="utf-8").startswith("# " + i18n.t("share.title", "zh-Hant")))
        code, out, _ = self.run_cli("--out", "-", "--format", "md", "--lang", "ko")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("# " + i18n.t("share.title", "ko")))

    def test_default_file_name_has_the_date(self):
        cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, cwd)
        self.assertEqual(self.run_cli("--lang", "en")[0], 0)
        names = [p.name for p in Path(self.tmp.name).glob("netwarden-report-*.html")]
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r"^netwarden-report-\d{4}-\d{2}-\d{2}-7d-shareable\.html$")

    def test_bad_period(self):
        code, _, err = self.run_cli("--period", "14d", "--lang", "en")
        self.assertEqual(code, 2)
        self.assertIn(i18n.t("err.bad_report_option", "en", option="period"), err)

    def test_listed_in_usage(self):
        self.assertIn("report", cli.COMMANDS)
        self.assertIn("report", cli.LANG_COMMANDS)
        self.assertIn(i18n.t("cli.cmd.report", "en"), cli.usage("en"))


# --- the dashboard -----------------------------------------------------------------------------

class DashboardTests(unittest.TestCase):
    def test_report_page_in_navigation_palette_and_view_state(self):
        self.assertIn("['overview', ['overview', 'report']]", JS)
        self.assertIn("r: 'report' }", JS)
        self.assertIn("report: viewReport }", JS)
        self.assertIn("a('act:share', T('app.palette.report')", JS)
        self.assertIn("return '/api/report?' + q.toString()", JS)
        self.assertIn("api(shareUrl(o))", JS)                     # base-aware (ingress): api() -> url()
        self.assertIn("schema: Object.fromEntries(Object.entries(SHARE_OPTS)", JS)

    def test_full_level_is_offered_to_admins_only(self):
        body = re.search(r"function viewReport\(\) \{(.*?)\n\}", JS, re.S).group(1)
        self.assertIn("admin = !S.meta.remote", body)
        self.assertIn("v === 'full' && !admin", body)
        self.assertIn("if (o.privacy === 'full' && !admin) o.privacy = 'shareable';", body)

    def test_options_match_the_server(self):
        m = re.search(r"const SHARE_OPTS = \{(.*?)\};", JS, re.S).group(1)
        opts = {k: re.findall(r"'([a-z0-9]+)'", v) for k, v in re.findall(r"(\w+): \[([^\]]*)\]", m)}
        self.assertEqual(sorted(opts["privacy"]), sorted(report.PRIVACY))
        self.assertEqual(opts["names"], list(report.NAMES))
        self.assertEqual(opts["people"], list(report.PEOPLE))
        self.assertEqual(opts["format"], list(report.FORMATS))
        self.assertEqual([int(x) for x in opts["period"]], list(report.PERIODS))

    def test_ui_keys_exist(self):
        keys = {k for k in re.findall(r"T\('((?:app\.share|share|app\.palette)\.[a-z_.]+)'", JS)
                if not k.endswith((".", "_"))}                  # prefixes completed at run time
        keys |= {f"share.{p}.{lvl}" for p in ("level", "level_desc") for lvl in report.PRIVACY}
        keys |= {"app.share.days", "app.share.names_type", "app.share.names_keep", "app.share.people_roles",
                 "app.share.people_keep", "app.share.fmt_html", "app.share.fmt_md", "app.nav.report"}
        for lang in i18n.CODES:
            data = json.loads((ROOT / "netwarden" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
            self.assertEqual(sorted(k for k in keys if not data.get(k)), [], lang)


if __name__ == "__main__":
    unittest.main()
