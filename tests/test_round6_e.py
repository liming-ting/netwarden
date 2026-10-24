"""
Round 6 stage E - what the newcomer end-to-end run fixed:

- `scan`, `ingest` and `traffic` print localized text (they were hard-coded English next to
  translated --help lines); `scan` under WSL says why it sees only a few devices.
- Nobody is pointed at scripts/adguard_dev.sh (a dev-only script that needs a hand-downloaded
  binary and serves DNS on port 5354): the wizard, the Overview checklist and the status
  hints ask for the ADGUARD_* / PIHOLE_* settings instead.
- `status --port` follows NETWARDEN_PORT like `run` and `pair`.
- "Name 1 devices" -> singular suggestion texts where a `_one` variant exists.
- The Overview "Data sources" tile is not all-green when no DNS source is configured.
- AI: a reply with no text ends with a note (a thinking model can spend max_tokens on
  thinking; Anthropic requests now add THINKING_HEADROOM); the health verdict's "right
  now" DNS failure rate covers the last 60 minutes, not two clock-hour buckets.

No network: the sweep, the DNS source and the probes are replaced by fakes.
"""
import contextlib
import io
import ipaddress
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from netwarden import (__main__ as cli, brain, discovery, dns_ingest, firstrun, i18n,
                       nethealth, store, suggestions, traffic_ingest)

ROOT = Path(__file__).resolve().parent.parent
LANGS = [c for c, _n, _l in i18n.LANGS]


def capture(fn, *args, **kw):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = fn(*args, **kw)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


DEVICES = [
    {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01", "vendor": "Example Router Co.",
     "hostname": "router.lan", "is_self": False},
    {"ip": "192.168.1.13", "mac": "", "vendor": "", "hostname": "laptop", "is_self": True},
]


class ScanCliTests(unittest.TestCase):
    def scan(self, *argv, wsl=False):
        net = ipaddress.ip_network("192.168.1.0/24")
        with mock.patch.object(discovery, "default_iface_net_ip", return_value=("eth0", net, "192.168.1.13")), \
                mock.patch.object(discovery, "scan", return_value=DEVICES), \
                mock.patch.object(discovery, "load_manuf", return_value={"AABBCC": "Example"}), \
                mock.patch("netwarden.wslnet.is_wsl", return_value=wsl), \
                mock.patch("netwarden.brain.load_env", return_value={}):
            return capture(discovery.main, list(argv))

    def test_english_output(self):
        code, out, _ = self.scan("--lang", "en")
        self.assertEqual(code, 0)
        self.assertIn(i18n.t("cli.scan.network", "en", net="192.168.1.0/24", n="254"), out)
        self.assertIn(i18n.t("cli.scan.found", "en", n=2, s="0.0").split(" in ")[0], out)
        self.assertIn("router.lan", out)
        self.assertNotIn(i18n.t("discovery.wsl_few", "en"), out)

    def test_default_language_is_traditional_chinese_and_columns_line_up(self):
        code, out, _ = self.scan()
        self.assertEqual(code, 0)
        lines = out.splitlines()
        header = next(l for l in lines if i18n.t("cli.scan.col_vendor", "zh-Hant") in l)
        row = next(l for l in lines if "router.lan" in l)
        # the host column starts at the same terminal column (CJK headers are 2 columns wide)
        from netwarden.health import _width
        self.assertEqual(_width(header[:header.index(i18n.t("cli.scan.col_host", "zh-Hant"))]),
                         _width(row[:row.index("router.lan")]))
        self.assertNotIn("Found", out)

    def test_wsl_explains_the_few_devices(self):
        _, out, _ = self.scan("--lang", "en", wsl=True)
        self.assertIn(i18n.t("discovery.wsl_few", "en"), out)

    def test_help_is_localized(self):
        _, out, _ = self.scan("--help")
        self.assertIn(i18n.t("cli.opt.save", "zh-Hant"), out)
        self.assertIn("--lang", out)


class _FakeSource:
    source = "adguard"


class IngestAndTrafficCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "nw.db")
        store.connect(self.db).close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_ingest_line_and_report_are_localized(self):
        st = {"fetched": 7, "inserted": 5, "new_devices": [], "unattributed": 1, "relinked": 2}
        for lang in ("en", "de"):
            with self.subTest(lang=lang), \
                    mock.patch.object(dns_ingest, "load_env", return_value={}), \
                    mock.patch.object(dns_ingest, "source_from_env", return_value=_FakeSource()), \
                    mock.patch.object(dns_ingest, "ingest_recorded", return_value=st), \
                    mock.patch.object(dns_ingest, "close_source"):
                code, out, _ = capture(dns_ingest.main, ["--db", self.db, "--lang", lang])
            self.assertEqual(code, 0)
            self.assertIn(i18n.t("cli.ingest.relinked", lang, n=2), out)
            self.assertIn(i18n.t("cli.ingest.report_title", lang, hours="24", n=0), out)
            line = next(l for l in out.splitlines() if l.startswith("["))
            self.assertRegex(line, r"^\[\d\d:\d\d:\d\d\] adguard")
        self.assertNotIn("fetched", out)   # the German run

    def test_traffic_not_configured_uses_the_status_sentence(self):
        for lang in ("en", "zh-Hant", "ja"):
            with self.subTest(lang=lang), mock.patch("netwarden.brain.load_env", return_value={}):
                code, out, _ = capture(traffic_ingest.main, ["--db", self.db, "--lang", lang])
            self.assertEqual(code, 0)
            self.assertEqual(out.strip(), i18n.t("status.hint.ntopng_off", lang))

    def test_traffic_report_is_localized(self):
        db = store.connect(self.db)
        _, out, _ = capture(traffic_ingest.print_report, db, 24, lang="fr")
        self.assertIn(i18n.t("cli.traffic.report_title", "fr", hours="24", n=0), out)


class StatusPortTests(unittest.TestCase):
    def test_status_probes_the_port_run_listens_on(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "nw.db")
            seen = []
            with mock.patch("netwarden.brain.load_env", return_value={"NETWARDEN_PORT": "8799"}), \
                    mock.patch.object(cli, "_probe", side_effect=lambda p: seen.append(p)):
                capture(cli.main, ["status", "--db", db, "--lang", "en"])
            self.assertEqual(seen, [8799])
            seen.clear()
            with mock.patch("netwarden.brain.load_env", return_value={"NETWARDEN_PORT": "nope"}), \
                    mock.patch.object(cli, "_probe", side_effect=lambda p: seen.append(p)):
                capture(cli.main, ["status", "--db", db, "--lang", "en"])
            self.assertEqual(seen, [8787])   # a bad value: the default, like `pair`


class SingularSuggestionTests(unittest.TestCase):
    def test_one_device_reads_singular(self):
        for kind in ("names", "owners"):
            one = suggestions.localize(suggestions._item(kind, "low", {"n": 1}), "en")
            two = suggestions.localize(suggestions._item(kind, "low", {"n": 2}), "en")
            self.assertNotIn("1 devices", one["title"] + one["why"])
            self.assertEqual(one["title"], i18n.t(f"sug.{kind}.title_one", "en"))
            self.assertIn("2 devices", two["title"] + two["why"])

    def test_every_one_variant_has_a_base_text(self):
        for key in i18n.strings("en"):
            if key.startswith("sug.") and key.endswith("_one"):
                self.assertTrue(i18n.has(key[:-4]), key)


class NewcomerTextTests(unittest.TestCase):
    def test_nobody_is_sent_to_the_dev_adguard_script(self):
        app = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertNotIn("adguard_dev", app)
        for lang in LANGS:
            with self.subTest(lang=lang):
                for key in ("app.wz.dns_none", "app.wz.dns_pihole", "app.ob.dns_body",
                            "status.hint.dns_off", "status.hint.adguard_stale"):
                    self.assertNotIn("adguard_dev", i18n.t(key, lang))
        self.assertIn("ADGUARD_URL=\\nADGUARD_USER=\\nADGUARD_PASS=", app)

    def test_data_sources_tile_warns_without_dns(self):
        app = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertRegex(app, r"T\('app\.stat\.no_dns'\), 'lvl-warn'")

    def test_print_rules(self):
        css = (ROOT / "netwarden" / "static" / "app.css").read_text(encoding="utf-8")
        block = css[css.index("@media print {"):]
        block = block[:block.index("\n}\n")]
        # an open drawer prints alone, unclipped, without its scroll area or buttons
        for rule in ("body:has(.drawer.open) .app", ".drawer.open { position: static",
                     ".drawer.open .drawer-in { overflow: visible", "body.locked { overflow: visible"):
            self.assertIn(rule, block)
        rep = (ROOT / "netwarden" / "static" / "report.css").read_text(encoding="utf-8")
        self.assertIn("@page { size: A4", rep)
        self.assertIn("li { break-inside: avoid; }", rep)

    def test_wizard_reports_wsl(self):
        with tempfile.TemporaryDirectory() as d:
            db = store.connect(str(Path(d) / "nw.db"))
            for wsl in (True, False):
                with mock.patch("netwarden.wslnet.is_wsl", return_value=wsl):
                    self.assertIs(firstrun.status(db, {})["scan"]["wsl"], wsl)
        app = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("s.scan.wsl ?", app)

    def test_cli_sources_keep_no_hard_coded_english(self):
        # the sentences these commands used to print verbatim
        for mod, text in ((discovery, "Found {len(devices)} device(s)"),
                          (discovery, "This host :"),
                          (dns_ingest, "unattributed client(s)"),
                          (traffic_ingest, "Bandwidth is optional and not configured")):
            src = Path(mod.__file__).read_text(encoding="utf-8")
            self.assertNotIn(text, src)
        self.assertFalse(re.search(r'help="[A-Z]?[a-z]', Path(discovery.__file__).read_text(encoding="utf-8")))


class _SilentProvider:
    """A fake model that 'thinks' and then says nothing (blank chunks only)."""
    def __init__(self):
        self.closed = False

    def stream(self, system, user, max_tokens=1200):
        try:
            yield ""
            yield "  "
        finally:
            self.closed = True


class _TalkingProvider(_SilentProvider):
    def stream(self, system, user, max_tokens=1200):
        try:
            yield "Hello"
            yield " there"
        finally:
            self.closed = True


class EmptyAnswerTests(unittest.TestCase):
    """The real-AI check got an empty reply: a thinking model spent max_tokens thinking."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = store.connect(str(Path(self.tmp.name) / "nw.db"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def events(self, p):
        return brain.stream_events(self.db, p, "chat", [{"role": "user", "content": "hi"}],
                                   lang="en", env={})

    def test_no_text_ends_with_a_note(self):
        evs = list(self.events(_SilentProvider()))
        self.assertEqual(evs[-1], {"note": "empty"})
        for lang in LANGS:
            self.assertNotEqual(i18n.t("app.ai.note_empty", lang), "app.ai.note_empty", lang)

    def test_an_answer_gets_no_note(self):
        evs = list(self.events(_TalkingProvider()))
        self.assertNotIn({"note": "empty"}, evs)
        self.assertEqual("".join(e.get("t", "") for e in evs), "Hello there")

    def test_stop_still_closes_upstream(self):
        p = _TalkingProvider()
        gen = self.events(p)
        self.assertEqual(next(e for e in gen if "t" in e), {"t": "Hello"})
        gen.close()                        # the Stop button / a closed browser tab
        self.assertTrue(p.closed)

    def test_anthropic_requests_leave_room_for_thinking(self):
        p = brain.AnthropicProvider("sk-test-not-real")
        seen = []
        with mock.patch.object(p, "_send",   # an empty upstream response, never the network
                               side_effect=lambda body, stream=False: seen.append(body) or io.BytesIO(b"")):
            p._request("S", "U", 500)
            list(p.stream_turn("S", [{"role": "user", "content": "U"}], [], max_tokens=500))
        self.assertTrue(seen)
        for body in seen:
            self.assertEqual(body["max_tokens"], 500 + p.THINKING_HEADROOM)


class DnsRightNowTests(unittest.TestCase):
    """'78% of lookups failing right now' about an outage that ended over an hour ago:
    the last hour is the last 60 minutes, not the last two clock-hour buckets."""
    def test_old_failures_are_not_right_now(self):
        with tempfile.TemporaryDirectory() as d:
            db = store.connect(str(Path(d) / "nw.db"))
            now = datetime.now(timezone.utc)

            def ev(minutes_ago, status):
                return {"source": "adguard", "ts": nethealth._iso(now - timedelta(minutes=minutes_ago)),
                        "client_ip": "192.168.1.9", "client_name": None, "device_mac": None,
                        "domain": "example.com", "qtype": "A", "status": status, "reason": "x",
                        "blocked": 0, "block_reason": None, "cached": 0,
                        "upstream": "192.0.2.53:53", "elapsed_ms": 20.0}
            # 30 failures 70-100 minutes ago (often the previous clock hour), 30 fine lookups since
            store.insert_events(db, [ev(70 + i, "SERVFAIL") for i in range(30)]
                                + [ev(1 + i, "NOERROR") for i in range(30)])
            q, f, ms = nethealth.dns_window(db, nethealth._iso(now - timedelta(hours=1)))
            self.assertEqual((q, f, ms), (30, 0, 20.0))
            h = nethealth._compute(db, 24)
            self.assertEqual(h["dns"]["hour_fail_rate"], 0)
            self.assertEqual(h["dns"]["fails"], 30)       # the day still shows them
            self.assertNotEqual(nethealth.verdict(h)["key"], "dns_failing")
            db.close()


if __name__ == "__main__":
    unittest.main()
