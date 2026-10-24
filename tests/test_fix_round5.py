"""
Round 5 fix stage: regression tests for the review findings.

  1  AdGuard / Pi-hole answering a non-JSON page -> one short OSError, a localized status
     hint / page text and a localized CLI line (never JSONDecodeError or a traceback)
  2  a POST whose body is shorter than its content-length -> 400, never a 500
  3  "Add a person..." is a button, not an entry in the owner list (test_stage_u)
  4  the device timeline never shows an internal ack key (less:night, mute:spike, ...)
  5-9 Overview count, "more" link, phone "More" button, reconnect probe, closed drawer
  10 db_problem_text() never prints the English log line to stderr (cron mail)
  11 report.md: hostile names only inside the digest's code fence or escaped in the table
"""
import contextlib
import http.server
import io
import json
import re
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from test_stage_k_fuzz import demo_db
from netwarden import (brain, dns_ingest, export, health, i18n, store, timeline, traffic_ingest,
                       web)

ROOT = Path(__file__).resolve().parent.parent
JS = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")


class _Html(http.server.BaseHTTPRequestHandler):
    """A 'source' that answers every request with a login page (status 200)."""
    def _page(self):
        body = b"<html><body>Please log in</body></html>"
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_DELETE = _page

    def log_message(self, *a):
        pass


class NonJsonSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Html)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_every_source_raises_one_short_oserror(self):
        for src, var in ((dns_ingest.AdGuardHome(self.url, timeout=5), "ADGUARD_URL"),
                         (dns_ingest.PiHole(self.url, "pw", timeout=5), "PIHOLE_URL"),
                         (traffic_ingest.NtopngSource(self.url, timeout=5), "NTOPNG_URL")):
            with self.assertRaises(OSError) as cm:
                if isinstance(src, traffic_ingest.NtopngSource):
                    src.sample()
                else:
                    list(src.events(None))
            self.assertIn("did not return JSON", str(cm.exception))
            self.assertIn(var, str(cm.exception))
            self.assertNotIn("Expecting value", str(cm.exception))

    def test_recorded_error_is_localized_on_page_and_in_hints(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = store.connect(Path(tmp) / "x.db")
            with self.assertRaises(OSError):
                dns_ingest.ingest_recorded(db, dns_ingest.AdGuardHome(self.url, timeout=5))
            env = {"ADGUARD_URL": self.url}
            for lang in ("en", "zh-Hant"):
                st = health.localized(health.status(db, env=env), lang)
                want = i18n.t("err.conn_bad_response", lang)
                self.assertEqual(st["sources"]["adguard"]["error_text"], want)
                hint = [h for h in health.hints(st, lang) if want in h]
                self.assertEqual(len(hint), 1, health.hints(st, lang))
                self.assertNotIn("JSON", hint[0])
            db.close()

    def test_cli_prints_one_localized_line_and_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            err = io.StringIO()
            env = {"ADGUARD_URL": self.url, "NETWARDEN_LANG": "en"}
            with mock.patch.object(dns_ingest, "load_env", return_value=env), \
                    contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = dns_ingest.main(["--db", str(Path(tmp) / "x.db"), "--no-report"])
        self.assertEqual(code, 1)
        out = err.getvalue()
        self.assertNotIn("Traceback", out)
        self.assertNotIn("JSONDecodeError", out)
        self.assertIn(i18n.t("err.conn_bad_response", "en"), out)
        self.assertEqual(len(out.strip().splitlines()), 1)

    def test_error_kinds(self):
        for text, kind in (("URLError: <urlopen error [Errno 111] Connection refused>", "refused"),
                           ("TimeoutError: timed out", "timeout"),
                           ("HTTPError: HTTP Error 401: Unauthorized", "auth"),
                           ("URLError: <urlopen error [Errno -2] Name or service not known>", "unreachable"),
                           ("OSError: Pi-hole did not return JSON - check PIHOLE_URL / credentials", "bad_response"),
                           ("PermissionError: operation not permitted", None)):
            self.assertEqual(health.error_kind(text), kind, text)
        # unknown errors stay as they were stored (already sanitized)
        self.assertEqual(health.error_text("PermissionError: x", "en"), "PermissionError: x")
        self.assertEqual(health.error_text("TimeoutError: timed out", "de"),
                         i18n.t("err.src_timeout", "de"))


class ShortBodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = demo_db(Path(cls.tmp.name) / "short.db")
        cls.patch = mock.patch.object(web.Handler, "timeout", 0.5)
        cls.patch.start()
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        web.close_server(cls.srv)
        cls.patch.stop()
        cls.tmp.cleanup()

    def post(self, length: int, body: bytes, close_write: bool) -> bytes:
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        try:
            s.sendall(b"POST /api/label HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                      b"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                      % (self.port, length) + body)
            if close_write:
                s.shutdown(socket.SHUT_WR)
            buf = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            return buf
        finally:
            s.close()

    def test_stalled_body_is_a_400(self):
        t0 = time.monotonic()
        raw = self.post(100, b"{}", close_write=False)   # promises 100 bytes, sends 2, waits
        self.assertTrue(raw.startswith(b"HTTP/1.0 400") or raw.startswith(b"HTTP/1.1 400"), raw[:80])
        self.assertIn(i18n.t("err.bad_length", "en").encode(), raw)
        self.assertLess(time.monotonic() - t0, 5)

    def test_cut_short_body_is_a_400_not_half_parsed(self):
        raw = self.post(100, b'{"mac": "x"}', close_write=True)
        self.assertIn(b" 400 ", raw.split(b"\r\n", 1)[0])
        self.assertNotIn(b"Traceback", raw)


class TimelineAckTests(unittest.TestCase):
    def test_no_internal_keys_in_the_story(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = demo_db(Path(tmp) / "tl.db")
            db = store.connect(path)
            mac = db.execute("SELECT mac FROM devices ORDER BY mac LIMIT 1").fetchone()["mac"]
            for key in ("less:night", "mute:spike", "bedtime:3:2026-10-20", "bandwidth:spike",
                        "change:svc", "mute:exposure", "xmeye.net"):
                store.add_ack(db, mac, key)
            for lang in ("en", "zh-Hant", "de"):
                texts = [i["text"] for i in timeline.timeline(db, mac, lang)
                         if i["kind"] == "user_mute"]
                self.assertGreaterEqual(len(texts), 7, texts)
                for t in texts:
                    self.assertIsNone(re.search(r"\b(less|mute|bedtime|bandwidth|change):", t), t)
                joined = "\n".join(texts)
                night = i18n.t("app.tune.kind.night", lang)
                self.assertIn(i18n.t("tl.user_less", lang, what=night), joined)
                self.assertIn(i18n.t("tl.user_mute_kind", lang, what=i18n.t("app.tune.kind.spike", lang)), joined)
                self.assertIn("2026-10-20", joined)
                self.assertIn("xmeye.net", joined)     # a threat contact names its domain
            db.close()


class DashboardStaticTests(unittest.TestCase):
    def test_overview_counts_like_the_inbox(self):
        body = re.search(r"function viewOverview\(\) \{(.*?)\n\}", JS, re.S).group(1)
        self.assertIn("const todo = S.data.inbox ? inboxCount() : items.length;", body)
        self.assertIn("T('app.ov.attention_n', { n: fmt.num(todo) })", body)
        self.assertIn("T('app.ov.todo_split'", body)
        self.assertIn("tile('#/inbox', T('app.stat.alerts'), fmt.num(todo - sugs)", body)
        for lang in i18n.CODES:   # the "more" link goes to the inbox and says so
            more = i18n.t("app.ov.more_n", lang)
            self.assertIn("{n}", more)
            self.assertNotIn(i18n.t("app.nav.security", lang), more, lang)
            self.assertNotIn("{n}", i18n.t("app.ov.open_inbox", lang))

    def test_phone_more_button_keeps_its_name(self):
        body = re.search(r"function bottomNav\(\) \{(.*?)\n\}", JS, re.S).group(1)
        self.assertIn("${icon('i-more')}<span class=\"lbl\">${T('app.nav.more')}</span>", body)
        self.assertNotIn("groupLabel(groupHere())", body)

    def test_stream_drop_probes_at_once(self):
        self.assertIn("if (wasLive) refresh();", JS)

    def test_closed_drawer_is_emptied(self):
        self.assertIn("if (!drawerOpen()) morph($('#drawerbody'), '');", JS)


class CliAndExportTests(unittest.TestCase):
    def test_db_problem_text_never_reaches_stderr_without_a_log(self):
        e = store.DBError("corrupt", "file is not a database", "/tmp/x.db")
        err = io.StringIO()
        with mock.patch.object(web.log, "hasHandlers", return_value=False), \
                mock.patch.object(web.log, "warning") as warn, contextlib.redirect_stderr(err):
            text = web.db_problem_text(e, "zh-Hant")
        warn.assert_not_called()
        self.assertEqual(err.getvalue(), "")
        self.assertNotIn("file is not a database", text)

    def test_report_md_keeps_hostile_names_inert(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = demo_db(Path(tmp) / "md.db")
            db = store.connect(path)
            mac = db.execute("SELECT mac FROM devices ORDER BY mac LIMIT 1").fetchone()["mac"]
            store.set_label(db, mac, "<img src=x onerror=alert(1)>```[x](javascript:1)")
            md = export.report_md(db, "en")
            db.close()
        fence = re.search(r"```text\n(.*?)\n```", md, re.S)
        outside = md[:fence.start()] + md[fence.end():]
        self.assertNotIn("<img", outside)
        self.assertIsNone(re.search(r"(?<!\\)\]\(javascript", outside))   # no live link
        self.assertIn("&lt;img", outside)              # the inventory table escapes it
        self.assertNotIn("```[", fence.group(1))        # the name can't close the fence


if __name__ == "__main__":
    unittest.main()
