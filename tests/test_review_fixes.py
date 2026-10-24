"""
Regression tests for the read-only review's findings (fix stage): DNS-rebinding guard,
request validation, localized LLM errors, discovery vendor placeholders + opt-in vendor
download, stale bandwidth rates, the canary double count, Pi-hole IN_PROGRESS rows,
secret masking, redirect handling, strict loopback, rule / CSV hardening, CLI --lang,
inventory privacy grades, digest local time and cache invalidation. Pure stdlib, fake
servers on ephemeral 127.0.0.1 ports only; never the real LLM or network.
"""
import contextlib
import http.client
import io
import json
import tempfile
import threading
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from netwarden import (__main__ as cli, alerts, brain, cache, dashboard, demo, discovery,
                       dns_ingest, export, health, i18n, privacy, store, visibility, web)

ISO = "%Y-%m-%dT%H:%M:%S.%fZ"
SECRET = "sk-ant-review-SECRET-123456"


def iso(dt):
    return dt.strftime(ISO)


class WebServerCase(unittest.TestCase):
    """A dashboard on an ephemeral port over a fresh demo DB."""
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        web.Handler.db_path = str(cls.path)
        web.Handler.env = {}
        web.Handler.lang = "zh-Hant"
        web.Handler.hours = 24
        web.Handler.loops = None
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def raw(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        hdrs = {"Host": f"127.0.0.1:{self.port}", **(headers or {})}
        for k, v in hdrs.items():
            if v is not None:
                c.putheader(k, v)
        c.endheaders(body)
        r = c.getresponse()
        data = r.read()
        c.close()
        try:
            return r.status, json.loads(data)
        except ValueError:
            return r.status, data

    def post(self, path, obj, **headers):
        body = json.dumps(obj).encode()
        return self.raw("POST", path, body, {"content-type": "application/json",
                                             "content-length": str(len(body)), **headers})


class HostGuardTests(WebServerCase):
    def test_foreign_host_is_refused(self):
        for host in ("evil.example:%d", "127.0.0.1.evil.example:%d", "localhost:1"):
            st, body = self.raw("GET", "/api/inventory", headers={"Host": host % self.port
                                                                  if "%d" in host else host})
            self.assertEqual(st, 421, host)
            self.assertEqual(body["error"], i18n.t("err.bad_host", "zh-Hant"))
        st, _ = self.raw("GET", "/api/export/devices.csv", headers={"Host": f"evil.example:{self.port}"})
        self.assertEqual(st, 421)
        st, _ = self.raw("GET", "/api/meta", headers={"Host": None})   # no Host at all
        self.assertEqual(st, 421)

    def test_own_names_work(self):
        for host in (f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"LOCALHOST:{self.port}"):
            self.assertEqual(self.raw("GET", "/api/meta", headers={"Host": host})[0], 200, host)

    def test_post_needs_same_origin_when_an_origin_is_sent(self):
        mac = "8c:79:f5:0b:cd:12"
        st, _ = self.post("/api/ack", {"mac": mac, "domain": "x.example"},
                          Origin="http://evil.example")
        self.assertEqual(st, 403)
        st, _ = self.post("/api/ack", {"mac": mac, "domain": "x.example"},
                          Origin=f"http://127.0.0.1:{self.port}")
        self.assertEqual(st, 200)
        st, _ = self.post("/api/unack", {"mac": mac, "domain": "x.example"})   # no Origin: ok
        self.assertEqual(st, 200)
        st, _ = self.post("/api/ack", {"mac": mac}, Host=f"evil.example:{self.port}")
        self.assertEqual(st, 421)

    def test_meta_has_an_opaque_db_id(self):
        st, meta = self.raw("GET", "/api/meta")
        self.assertRegex(meta["db_id"], r"^[0-9a-f]{12}$")
        self.assertNotIn(self.tmp.name, json.dumps(meta))


class RequestValidationTests(WebServerCase):
    def test_bad_lengths(self):
        for length, code in (("-1", 400), ("abc", 400), (str(web.MAX_BODY + 1), 413)):
            st, body = self.raw("POST", "/api/ack", b"", {"content-type": "application/json",
                                                         "content-length": length})
            self.assertEqual(st, code, length)
            self.assertIn("error", body)

    def test_wrong_json_types_are_400_not_a_dropped_connection(self):
        for path, obj in (("/api/ack", {"mac": 5}), ("/api/label", {"mac": "8c:79:f5:0b:cd:12", "label": [1]}),
                          ("/api/ask", {"question": 5}), ("/api/chat", {"messages": "abc"}),
                          ("/api/chat", {"messages": [{"role": "user", "content": 3}]}),
                          ("/api/check", {"mac": ["x"]}), ("/api/profile", {"mac": {"a": 1}})):
            st, body = self.post(path, obj)
            self.assertEqual(st, 400, (path, obj))
            self.assertEqual(body["error"], i18n.t("err.bad_json", "zh-Hant"), (path, obj))

    def test_junk_mac_refused_and_text_capped(self):
        st, body = self.post("/api/ack", {"mac": "zz", "lang": "en"})
        self.assertEqual((st, body["error"]), (400, i18n.t("err.bad_mac", "en")))
        st, _ = self.post("/api/ack", {"mac": "8C:79:F5:0B:CD:12", "domain": "d" * 400})
        self.assertEqual(st, 400)
        mac = "8c:79:f5:0b:cd:12"
        st, _ = self.post("/api/label", {"mac": mac.upper(), "label": "x\n" + "y" * 5000})
        self.assertEqual(st, 200)
        db = store.connect(self.path)
        lab = store.get_labels(db)[mac]["label"]
        self.assertEqual(len(lab), web.MAX_LABEL)
        self.assertNotIn("\n", lab)
        store.clear_label(db, mac)
        st, _ = self.post("/api/profile", {"mac": mac, "owner": "o" * 1000})
        self.assertEqual(st, 200)
        # (review fixes 4: an owner is a person - people.validate's name limit applies)
        from netwarden import people
        self.assertEqual(len(store.get_profiles(db)[mac]["owner"]), people.MAX_NAME)
        store.set_profile(db, mac, owner=None)
        db.close()

    def test_old_chat_endpoint_caps_turns(self):
        seen = {}
        orig = brain.converse
        brain.converse = lambda db, p, msgs, hours, lang, **kw: seen.setdefault("m", msgs) and "ok"
        try:
            msgs = [{"role": "user", "content": "q" * 9000}] * 30    # < MAX_BODY, > the caps
            st, body = self.post("/api/chat", {"messages": msgs})
        finally:
            brain.converse = orig
        self.assertEqual(st, 200)
        self.assertEqual(len(seen["m"]), brain.MAX_TURNS)
        self.assertEqual(len(seen["m"][-1]["content"]), brain.MAX_TURN_CHARS)


class LLMErrorTests(unittest.TestCase):
    def test_kinds_are_localized_with_masked_detail(self):
        e = brain.LLMError(f"Anthropic API 401: invalid key {SECRET}", kind="http")
        text = brain.llm_error_text(e, "de", [SECRET])
        self.assertTrue(text.startswith(i18n.t("err.llm_http", "de")))
        self.assertIn("401", text)
        self.assertNotIn(SECRET, text)
        self.assertEqual(brain.llm_error_text(brain.LLMError("x", kind="no_key"), "ja"),
                         i18n.t("err.llm_no_key", "ja"))
        self.assertEqual(brain.LLMError("x", kind="bogus").kind, "http")

    def test_provider_raises_the_right_kinds(self):
        with self.assertRaises(brain.LLMError) as cm:
            brain.AnthropicProvider("")
        self.assertEqual(cm.exception.kind, "no_key")
        p = brain.AnthropicProvider("k" * 10, timeout=2)
        p.ENDPOINT = "http://127.0.0.1:9/v1/messages"     # nothing listens on port 9
        with self.assertRaises(brain.LLMError) as cm:
            p.complete("s", "u")
        self.assertEqual(cm.exception.kind, "unreachable")

    def test_offline_reason(self):
        self.assertEqual(brain.offline_reason({}), "no_key")
        self.assertEqual(brain.offline_reason({"ANTHROPIC_API_KEY": "k", brain.OFFLINE_ENV: "1"}), "forced")
        self.assertIsNone(brain.offline_reason({"ANTHROPIC_API_KEY": "k"}))
        forced = health.ai_line({"mode": "offline", "model": "offline", "reason": "forced"}, "en")
        self.assertIn(i18n.t("status.ai.offline_forced", "en"), forced)
        self.assertEqual(brain.describe_provider({brain.OFFLINE_ENV: "1"})["offline_reason"], "forced")


class DiscoveryVendorTests(unittest.TestCase):
    def test_unknown_and_randomized_are_empty_not_chinese_text(self):
        self.assertEqual(discovery.label("a6:71:0c:9d:4e:f2", {}), "")
        self.assertEqual(discovery.label("00:11:22:33:44:55", {}), "")
        self.assertEqual(discovery.label("b8:27:eb:00:00:01", discovery.BUILTIN_OUI),
                         "Raspberry Pi Foundation")
        rec = discovery.device_record("192.168.1.13", "d8:3a:dd:1a:2b:3c", {}, is_self=True, hostname="me")
        self.assertEqual(rec["vendor"], "")
        self.assertTrue(rec["is_self"])

    def test_legacy_placeholders_are_cleared_and_known_vendor_kept(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "x.db"
            db = store.connect(path)
            db.execute("INSERT INTO devices (mac, vendor, first_seen, last_seen) "
                       "VALUES ('a6:00:00:00:00:01', '随机MAC (手机/隐私模式)', 'a', 'a'), "
                       "('00:00:00:00:00:02', 'Acme', 'a', 'a')")
            db.commit()
            db.close()
            db = store.connect(path)            # the migration runs on open
            v = dict(db.execute("SELECT mac, vendor FROM devices").fetchall())
            self.assertEqual(v["a6:00:00:00:00:01"], "")
            store.upsert_device(db, {"mac": "00:00:00:00:00:02", "ip": "10.0.0.2", "vendor": "",
                                     "hostname": ""})
            self.assertEqual(db.execute("SELECT vendor FROM devices WHERE mac = '00:00:00:00:00:02'")
                             .fetchone()[0], "Acme")
            db.close()

    def test_load_manuf_never_touches_the_network(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(discovery, "MANUF_CACHE", Path(d) / "manuf.txt"), \
                mock.patch.object(discovery.urllib.request, "urlopen",
                                  side_effect=AssertionError("network!")):
            self.assertEqual(discovery.load_manuf(), discovery.BUILTIN_OUI)

    def test_update_manuf_refuses_an_error_page(self):
        good = "\n".join(f"00:{i // 256:02X}:{i % 256:02X}\tV{i}\tVendor {i}" for i in range(1200))
        pages = {"/bad": b"<html>rate limited</html>", "/good": good.encode()}

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = pages[self.path]
                self.send_response(200)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_port}"
        try:
            with tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(discovery, "CACHE_DIR", Path(d)), \
                    mock.patch.object(discovery, "MANUF_CACHE", Path(d) / "manuf.txt"):
                with mock.patch.object(discovery, "MANUF_URLS", [base + "/bad"]):
                    with self.assertRaises(OSError):
                        discovery.update_manuf(timeout=5)
                    self.assertFalse((Path(d) / "manuf.txt").exists())
                with mock.patch.object(discovery, "MANUF_URLS", [base + "/bad", base + "/good"]):
                    self.assertEqual(discovery.update_manuf(timeout=5), 1200)
                self.assertEqual(discovery.load_manuf()["00:00:05"], "Vendor 5")
        finally:
            srv.shutdown()
            srv.server_close()


class BandwidthStaleTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")

    def add(self, when, rx):
        store.insert_traffic_samples(self.db, [{"ts": iso(when), "ip": "10.0.0.5",
                                                "mac": "aa:bb:cc:dd:ee:01", "rx_bytes": rx,
                                                "tx_bytes": 0}])

    def test_device_silent_for_hours_has_no_current_rate(self):
        t0 = datetime.now(timezone.utc) - timedelta(hours=20)
        self.add(t0, 0)
        self.add(t0 + timedelta(minutes=5), 300_000_000)
        s = store.bandwidth_summary(self.db, iso(t0 - timedelta(hours=1)))["aa:bb:cc:dd:ee:01"]
        self.assertEqual(s["rx_bytes"], 300_000_000)
        self.assertEqual(s["rx_bps"], 0)
        self.assertGreater(s["peak_bps"], 0)

    def test_recent_device_keeps_its_rate(self):
        t0 = datetime.now(timezone.utc) - timedelta(minutes=6)
        self.add(t0, 0)
        self.add(t0 + timedelta(minutes=5), 300_000_000)
        s = store.bandwidth_summary(self.db, iso(t0 - timedelta(hours=1)))["aa:bb:cc:dd:ee:01"]
        self.assertGreater(s["rx_bps"], 7_000_000)


class CanaryTests(unittest.TestCase):
    def test_blocked_nxdomain_row_counts_once(self):
        db = store.connect(":memory:")
        now = datetime.now(timezone.utc)
        mac = "aa:bb:cc:dd:ee:02"
        store.upsert_device(db, {"mac": mac, "ip": "10.0.0.9", "vendor": "", "hostname": "pc"})
        rows = [(iso(now - timedelta(minutes=5)), 1, "NXDOMAIN"), (iso(now - timedelta(minutes=4)), 0, "NOERROR")]
        n = store.insert_events(db, [{"source": "pihole", "ts": ts, "client_ip": "10.0.0.9",
                                      "domain": visibility.CANARY, "qtype": "A", "status": status,
                                      "blocked": b, "cached": 0, "device_mac": mac}
                                     for ts, b, status in rows])
        self.assertEqual(n, 2)
        res = visibility.bypass(db, iso(now - timedelta(hours=1)))
        self.assertTrue(res[0]["canary"]["answered"])
        self.assertTrue(res[0]["active"])


class PiHolePendingTests(unittest.TestCase):
    class Src:
        source = "pihole"

        def __init__(self, events):
            self.batches = events

        def events(self, since):
            return [dict(e) for e in self.batches.pop(0) if not since or e["ts"] >= since]

    def ev(self, sec, domain, status, pending=False):
        ts = iso(datetime(2026, 10, 21, 0, 0, sec, tzinfo=timezone.utc))
        return {"source": "pihole", "ts": ts, "client_ip": "127.0.0.1", "client_name": None,
                "domain": domain, "qtype": "A", "status": status, "reason": None, "blocked": 0,
                "block_reason": None, "cached": 0, "upstream": None, "elapsed_ms": None,
                "pending": pending}

    def test_in_progress_rows_are_fetched_again_finished(self):
        db = store.connect(":memory:")
        first = [self.ev(1, "a.example", "NOERROR"), self.ev(2, "slow.example", None, pending=True),
                 self.ev(3, "c.example", "NOERROR")]
        second = [self.ev(2, "slow.example", "NOERROR"), self.ev(3, "c.example", "NOERROR")]
        src = self.Src([first, second])
        with mock.patch.object(dns_ingest, "local_addresses", lambda: {"127.0.0.1"}), \
                mock.patch.object(discovery, "read_arp", lambda: {}), \
                mock.patch.object(discovery, "default_iface_net_ip", lambda: (None, None, None)):
            st = dns_ingest.ingest(db, src)
            self.assertEqual((st["fetched"], st["held"], st["inserted"]), (3, 1, 2))
            self.assertEqual(store.get_watermark(db, "pihole"), first[1]["ts"])
            st = dns_ingest.ingest(db, src)
            self.assertEqual(st["inserted"], 1)
        row = db.execute("SELECT status FROM dns_events WHERE domain = 'slow.example'").fetchone()
        self.assertEqual(row[0], "NOERROR")

    def test_normalize_marks_in_progress(self):
        p = dns_ingest.PiHole("http://127.0.0.1:9")
        q = {"time": 1761004800.5, "status": "IN_PROGRESS", "domain": "x.example", "type": "A",
             "client": {"ip": "10.0.0.2"}, "reply": {"type": "UNKNOWN"}}
        self.assertTrue(p.normalize(q)["pending"])
        self.assertFalse(p.normalize({**q, "status": "FORWARDED"})["pending"])


class SecretMaskingTests(unittest.TestCase):
    def test_more_secret_shapes_are_masked(self):
        for raw in ("HTTP 401 for X-FTL-SID: abcDEF123456", "GET /api?sid=abcDEF123456&x=1",
                    'body {"token": "abcDEF123456"}', "url ?key=abcDEF123456", "password=abcDEF123456"):
            self.assertNotIn("abcDEF123456", health.sanitize_error(raw), raw)
        pw = "p@ss w/rd+&1"
        out = health.sanitize_error("http://h/api?x=p%40ss%20w%2Frd%2B%261 and p%40ss+w%2Frd%2B%261", [pw])
        self.assertNotIn("p%40ss", out)
        self.assertEqual(health.sanitize_error("bypass detected: monkey business"),
                         "bypass detected: monkey business")

    def test_errors_are_masked_before_they_are_stored(self):
        class Boom:
            source = "pihole"
            password = "hunter2-secret"
            sid = "SIDVALUE12345"

            def events(self, since):
                raise OSError(f"login failed with hunter2-secret (sid SIDVALUE12345)")
        db = store.connect(":memory:")
        with self.assertRaises(OSError):
            dns_ingest.ingest_recorded(db, Boom())
        err = store.source_status(db)["pihole"]["last_error"]
        self.assertNotIn("hunter2-secret", err)
        self.assertNotIn("SIDVALUE12345", err)


class RedirectTests(unittest.TestCase):
    def setUp(self):
        self.servers = []

    def serve(self, target):
        class H(BaseHTTPRequestHandler):
            seen = []

            def do_GET(self):
                H.seen.append(self.headers.get("authorization"))
                if self.path.startswith("/control/querylog") and target:
                    self.send_response(302)
                    self.send_header("location", target() + self.path.replace("querylog", "next"))
                    self.send_header("content-length", "0")
                    self.end_headers()
                    return
                body = b'{"data": [], "oldest": ""}'
                self.send_response(200)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.servers.append(srv)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv, H

    def test_cross_origin_redirect_is_refused_same_origin_followed(self):
        other, other_h = self.serve(None)
        evil = f"http://127.0.0.1:{other.server_port}"
        src_srv, _ = self.serve(lambda: evil)
        ag = dns_ingest.AdGuardHome(f"http://127.0.0.1:{src_srv.server_port}", "u", "pw")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            ag._get("/control/querylog", {})
        cm.exception.close()
        self.assertEqual(other_h.seen, [])           # the credentials never left
        same_srv, same_h = self.serve(lambda: f"http://127.0.0.1:{self.servers[-1].server_port}")
        ag = dns_ingest.AdGuardHome(f"http://127.0.0.1:{same_srv.server_port}", "u", "pw")
        self.assertEqual(ag._get("/control/querylog", {})["data"], [])


class LoopbackTests(unittest.TestCase):
    def test_only_literal_loopback(self):
        for ok in ("127.0.0.1", "127.0.0.2", "localhost"):
            self.assertTrue(web.is_loopback(ok), ok)
        for bad in ("127.evil.com", "0.0.0.0", "192.168.1.13", "::1", "localhost.evil", ""):
            self.assertFalse(web.is_loopback(bad), bad)
        with self.assertRaises(ValueError):
            web.make_server(":memory:", 0, {}, host="127.evil.com")


class OutputHardeningTests(unittest.TestCase):
    def test_rule_names(self):
        self.assertTrue(privacy.rule_safe("ads.example.com"))
        self.assertTrue(privacy.rule_safe("_dmarc.x-y.example"))
        for bad in ("a.example\n||evil^", "a b.example", "x.example$important", "-x.example",
                    "a..b", ".example", "x/y", ""):
            self.assertFalse(privacy.rule_safe(bad), bad)
        rules = privacy.block_rules([
            {"entry": "ok.example", "count": 3, "blocked": 0, "domains": {"t.ok.example": 3}},
            {"entry": "bad.example\n@@||allow^", "count": 9, "blocked": 0, "domains": {"x": 9}},
            {"entry": "ok2.example", "count": 3, "blocked": 0, "domains": {"evil\nline": 3}}])
        self.assertEqual(rules["adguard"], "||ok.example^\n||ok2.example^")
        self.assertEqual(rules["pihole"], "t.ok.example")
        vis = visibility.rules({"bypass": [{"canary": None, "resolvers": [
            {"domain": "dns.google", "count": 2, "blocked": 0},
            {"domain": "x\ndns.google", "count": 2, "blocked": 0}]}]})
        self.assertEqual(vis["pihole"], "dns.google")

    def test_csv_formula_variants(self):
        for v in (" =1+1", "　+1", "＝SUM(A1)", "＋1", "－1", "＠x", "=1"):
            self.assertTrue(export.safe_cell(v).startswith("'"), v)
        for v in ("normal", "a=b", "TV 1"):
            self.assertEqual(export.safe_cell(v), v)


class CliLangTests(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(brain, "load_env", lambda *a, **k: {}):
            try:
                code = cli.main(argv)
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_argv_lang(self):
        self.assertEqual(cli._argv_lang(["--json", "--lang", "de"]), "de")
        self.assertEqual(cli._argv_lang(["--lang=ja"]), "ja")
        self.assertIsNone(cli._argv_lang(["--lang"]))

    def test_help_follows_lang(self):
        code, out, _ = self.run_cli(["status", "--lang", "de", "--help"])
        self.assertEqual(code, 0)
        self.assertIn(i18n.t("cli.cmd.status", "de"), out)
        code, out, err = self.run_cli(["--lang", "ja", "--help"])
        self.assertEqual(code, 0)
        self.assertIn(i18n.t("cli.commands", "ja"), out)
        self.assertNotIn("--lang", err)
        code, out, _ = self.run_cli(["--lang", "en", "prune", "--help"])
        self.assertIn(i18n.t("cli.cmd.prune", "en"), out)


class InventoryPrivacyTests(unittest.TestCase):
    def test_every_dns_device_has_a_grade_matching_privacy(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "demo.db"
            demo.build(path)
            db = store.connect(path)
            snap = web.localize_snapshot(brain.snapshot(db, hours=24), "en")
            inv = dashboard.inventory(db, snap, "en", hours=24)
            rep = privacy.report(db, hours=24, lang="en")
            grades = {x["mac"]: x["grade"] for x in rep["devices"] if x.get("mac")}
            for dev in inv["devices"]:
                if dev.get("queries"):
                    self.assertIn("privacy", dev, dev["mac"])
                    self.assertEqual(dev["privacy"]["grade"], grades[dev["mac"]], dev["mac"])
            db.close()


class SmallFixesTests(unittest.TestCase):
    def test_digest_times_are_local(self):
        from zoneinfo import ZoneInfo
        try:
            tz = ZoneInfo("Asia/Taipei")
        except Exception:   # noqa: BLE001 - no tz database here
            self.skipTest("no zoneinfo data")
        self.assertEqual(alerts._short("2026-10-21T17:30:00.000000Z", tz), "10-22 01:30")
        self.assertEqual(alerts._short("garbage-in"), "ge-in")

    def test_cache_sees_in_place_vendor_updates(self):
        with tempfile.TemporaryDirectory() as d:
            db = store.connect(Path(d) / "c.db")
            store.upsert_device(db, {"mac": "aa:aa:aa:aa:aa:01", "ip": "10.0.0.1", "vendor": "A",
                                     "hostname": "h"})
            before = cache.fingerprint(db)
            with db:
                db.execute("UPDATE devices SET vendor = 'Bigger Vendor'")
            self.assertNotEqual(before, cache.fingerprint(db))
            db.close()

    def test_bad_tz_name_is_logged_once(self):
        from netwarden import activity
        activity._warned_tz.discard("No/Such_Zone_X")
        with self.assertLogs("netwarden.activity", "WARNING") as cm:
            activity.local_tz("No/Such_Zone_X")
            activity.local_tz("No/Such_Zone_X")
        self.assertEqual(len(cm.records), 1)


if __name__ == "__main__":
    unittest.main()
