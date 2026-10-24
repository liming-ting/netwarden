"""
Tests for the unified CLI (python3 -m netwarden ...), the demo seeder and the
status/meta endpoints. `run` is exercised as a real subprocess on an ephemeral port
with --no-loops and --offline-ai (no LAN sweep, no LLM, no outbound calls) and stopped
with SIGINT like Ctrl+C. Everything else runs in-process on temporary DBs.
"""
import contextlib
import http.client
import io
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from netwarden import __main__ as cli
from netwarden import demo, i18n, store, web

ROOT = Path(__file__).resolve().parent.parent


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:  # argparse --help / errors
            code = e.code
    return code, out.getvalue(), err.getvalue()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class UsageTests(unittest.TestCase):
    def test_help_lists_every_command(self):
        code, out, _ = run_cli("--help")
        self.assertEqual(code, 0)
        for cmd in ("run", "web", "scan", "ingest", "traffic", "alerts", "demo", "status", "prune"):
            self.assertIn(f"  {cmd}", out)

    def test_no_args_and_unknown_command(self):
        self.assertEqual(run_cli()[0], 2)
        code, _, err = run_cli("frobnicate")
        self.assertEqual(code, 2)
        self.assertIn("frobnicate", err)

    def test_subcommand_help(self):
        for cmd in ("run", "status", "prune", "demo", "web", "alerts", "ingest", "traffic"):
            code, out, _ = run_cli(cmd, "--help")
            self.assertEqual(code, 0, cmd)
            self.assertIn(f"netwarden {cmd}", out)
        self.assertIn("--offline-ai", run_cli("run", "--help")[1])


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "demo.db"

    def tearDown(self):
        self.tmp.cleanup()

    def test_build_is_deterministic_idempotent_and_keeps_user_notes(self):
        # one pinned clock for both builds: the story is laid out relative to "now", so
        # two wall-clock builds a moment apart may legitimately differ by a lookup that
        # happened in between (this test once raced a minute boundary that way)
        now = datetime.now(timezone.utc)
        a = demo.build(self.path, now=now)
        db = store.connect(self.path)
        first = db.execute("SELECT domain, COUNT(*) FROM dns_events GROUP BY domain").fetchall()
        mac = demo.DEVICES[0]["mac"]
        store.set_label(db, mac, "我的路由器")
        store.add_ack(db, mac, "")
        db.close()
        b = demo.build(self.path, now=now)
        self.assertEqual((a["events"], a["traffic_samples"]), (b["events"], b["traffic_samples"]))
        db = store.connect(self.path)
        again = db.execute("SELECT domain, COUNT(*) FROM dns_events GROUP BY domain").fetchall()
        self.assertEqual([tuple(r) for r in first], [tuple(r) for r in again])
        self.assertEqual(store.get_labels(db)[mac]["label"], "我的路由器")
        self.assertIn((mac, ""), store.list_acks(db))
        self.assertTrue(store.is_demo(db))
        st = store.source_status(db)
        self.assertEqual(set(st), {"adguard", "ntopng", "discovery", "mdns", "ssdp", "upnp",
                                   "netbios", "gateway"})
        self.assertIsNotNone(st["ntopng"]["last_error"])         # the old outage story
        self.assertGreater(st["ntopng"]["last_ok_ts"], st["ntopng"]["last_error_ts"])

    def _rows(self, now):
        demo.build(self.path, now=now)
        db = store.connect(self.path)
        try:
            return {t: sorted(tuple(r) for r in db.execute(q).fetchall()) for t, q in (
                ("dns", "SELECT ts, device_mac, domain, status, blocked FROM dns_events"),
                ("traffic", "SELECT ts, mac, rx_bytes, tx_bytes FROM traffic_samples"),
                ("presence", "SELECT mac, ts FROM presence_samples"),
                ("health", "SELECT ts, ok, latency_ms FROM health_samples"))}
        finally:
            db.close()

    def test_same_clock_same_rows_and_no_second_clock_read(self):
        # pinned 0.3 s before a minute boundary: two wall-clock builds there used to differ
        now = datetime.now(timezone.utc).replace(second=59, microsecond=700_000) \
            - timedelta(minutes=1)
        first = self._rows(now)

        class NoClock(datetime):
            @classmethod
            def now(cls, tz=None):
                raise AssertionError("demo.build read the wall clock despite now=")
        with mock.patch.object(demo, "datetime", NoClock):
            again = self._rows(now)
        self.assertEqual(first, again)
        with self.assertRaises(ValueError):
            demo.build(self.path, now=now.replace(tzinfo=None))

    def test_a_clock_step_across_a_boundary_reshuffles_nothing(self):
        # Regression: build_presence drew its RNG only for steps that were kept and walked
        # a grid relative to now, so a 0.6 s clock step across a minute boundary changed
        # lookups (and the event count) days in the past. These boundaries all did.
        for b in ("2026-10-24T00:00:00", "2026-10-24T01:37:00", "2026-10-24T06:28:00",
                  "2026-10-24T16:10:00", "2026-10-24T19:24:00"):
            at = datetime.fromisoformat(b).replace(tzinfo=timezone.utc)
            before = self._rows(at - timedelta(seconds=0.3))
            after = self._rows(at + timedelta(seconds=0.3))
            for table in ("dns", "traffic"):
                self.assertEqual(len(before[table]), len(after[table]), (b, table))
            routine = (demo.KID_PHONE, demo.MOM_LAPTOP, demo.DAD_NEW_MAC)
            self.assertEqual([r for r in before["dns"] if r[1] in routine],
                             [r for r in after["dns"] if r[1] in routine], b)
            self.assertEqual(len(before["presence"]), len(after["presence"]), b)

    def test_refuses_to_overwrite_real_data(self):
        real = Path(self.tmp.name) / "netwarden.db"
        db = store.connect(real)
        store.upsert_device(db, {"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "x",
                                 "hostname": "", "randomized": False, "is_self": False})
        db.close()
        with self.assertRaises(demo.NotADemoDB):
            demo.build(real)
        code, _, err = run_cli("demo", "--db", str(real), "--lang", "en")
        self.assertEqual(code, 1)
        self.assertIn("Refusing", err)
        db = store.connect(real)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 1)

    def test_demo_command_and_ensure(self):
        code, out, _ = run_cli("demo", "--db", str(self.path), "--lang", "en")
        self.assertEqual(code, 0)
        self.assertIn("Demo home seeded", out)
        self.assertFalse(demo.ensure(self.path))     # already a demo DB
        other = Path(self.tmp.name) / "fresh.db"
        self.assertTrue(demo.ensure(other))


class PruneAndStatusCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "demo.db"
        demo.build(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_prune_clamps_and_vacuums(self):
        code, out, _ = run_cli("prune", "--db", str(self.path), "--days", "2", "--vacuum",
                               "--lang", "en")
        self.assertEqual(code, 0)
        self.assertIn(i18n.t("cli.prune.clamped", "en", min=store.MIN_RETENTION_DAYS), out)
        self.assertIn("older than 8 days", out)
        self.assertIn("VACUUM", out)

    def test_status_json_and_table(self):
        code, out, _ = run_cli("status", "--db", str(self.path), "--json", "--port", "0")
        self.assertEqual(code, 0)
        st = json.loads(out)
        self.assertTrue(st["demo"])
        self.assertEqual(st["db"]["devices"], len(demo.DEVICES))
        self.assertTrue(st["hints"])
        code, out, _ = run_cli("status", "--db", str(self.path), "--port", "0", "--lang", "en")
        self.assertEqual(code, 0)
        self.assertIn("DNS (AdGuard Home)", out)
        self.assertIn("DEMO data", out)

    def test_status_reads_loops_from_a_running_dashboard(self):
        class FakeDash(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({"loops": {"dns": {"running": True, "interval_s": 60}}}).encode()
                self.send_response(200)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeDash)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]
            code, out, _ = run_cli("status", "--db", str(self.path), "--port", str(port),
                                   "--lang", "en")
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIn("DNS ingest: every 1 min (running)", out)
        self.assertIn(f"Dashboard: http://127.0.0.1:{port}", out)


class StatusEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        cls.srv = web.make_server(cls.path, 0, {"ADGUARD_PASS": "pw-secret-1"}, "en",
                                  loops=lambda: {"dns": {"running": True, "interval_s": 60}})
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        web.Handler.loops = None
        cls.tmp.cleanup()

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read()

    def test_status_shape(self):
        status, body = self.get("/api/status?lang=zh-Hant")
        self.assertEqual(status, 200)
        st = json.loads(body)
        for key in ("sources", "ai", "db", "loops", "version", "demo", "hints"):
            self.assertIn(key, st)
        for src in st["sources"].values():
            for key in ("configured", "last_ok_ts", "last_error_ts", "last_error",
                        "last_count", "stale"):
                self.assertIn(key, src)
        self.assertTrue(st["demo"])
        self.assertEqual(st["loops"]["dns"]["interval_s"], 60)
        self.assertEqual(st["ai"]["mode"], "offline")
        self.assertTrue(any("示範" in h for h in st["hints"]))
        self.assertNotIn(b"pw-secret-1", body)

    def test_meta_marks_demo(self):
        meta = json.loads(self.get("/api/meta")[1])
        self.assertTrue(meta["demo"])
        self.assertEqual(meta["ai_mode"], "offline")

    def test_offline_insight_through_the_api(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("POST", "/api/insight", json.dumps({"lang": "en"}),
                  {"content-type": "application/json"})
        r = c.getresponse()
        text = json.loads(r.read())["text"]
        self.assertEqual(r.status, 200)
        self.assertIn("Offline mode", text)
        self.assertIn("roborock", text.lower())

    def test_non_loopback_bind_is_refused(self):
        with self.assertRaises(ValueError):
            web.make_server(self.path, 0, {}, host="0.0.0.0")


class RunProcessTests(unittest.TestCase):
    """The real `python3 -m netwarden run`: starts, answers, stops on Ctrl+C."""

    def start(self, *args):
        port = free_port()
        env = {**os.environ, "PYTHONPATH": str(ROOT), "NETWARDEN_LANG": "en"}
        proc = subprocess.Popen([sys.executable, "-m", "netwarden", "run", "--port", str(port),
                                 "--offline-ai", *args], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                c.request("GET", "/api/meta")
                return proc, port, json.loads(c.getresponse().read())
            except OSError:
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
        proc.kill()
        self.fail("run did not come up: " + proc.communicate()[1])

    def stop(self, proc):
        t0 = time.monotonic()
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=10)
        return proc.returncode, time.monotonic() - t0, out, err

    def test_run_no_loops_offline(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "nw.db"
            proc, port, meta = self.start("--db", str(db), "--no-loops")
            self.assertEqual(meta["ai_mode"], "offline")
            self.assertFalse(meta["demo"])
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            c.request("GET", "/api/status")
            self.assertEqual(json.loads(c.getresponse().read())["loops"], {})
            code, took, out, err = self.stop(proc)
            self.assertEqual(code, 0, err)
            self.assertLess(took, 4)
            self.assertIn("netwarden is running", out)
            self.assertIn("netwarden stopped.", out)
            self.assertTrue((Path(d) / "netwarden.log").exists())

    def test_run_demo_seeds_and_refuses_busy_port(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "demo.db"
            proc, port, meta = self.start("--demo", "--db", str(db))
            try:
                self.assertTrue(meta["demo"])
                busy = subprocess.run([sys.executable, "-m", "netwarden", "run", "--no-loops",
                                       "--port", str(port), "--db", str(db)], cwd=ROOT,
                                      env={**os.environ, "PYTHONPATH": str(ROOT),
                                           "NETWARDEN_LANG": "en"},
                                      capture_output=True, text=True, timeout=20)
                self.assertEqual(busy.returncode, 1)
                self.assertIn(f"Port {port} is already in use", busy.stderr)
            finally:
                code, _took, out, err = self.stop(proc)
            self.assertEqual(code, 0, err)
            self.assertIn("Demo database seeded", out)


if __name__ == "__main__":
    unittest.main()
