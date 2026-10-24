"""
Tests for netwarden.threatintel - known-bad / high-risk domain matching.
Pure and deterministic; the feed PARSER is tested with inline text, the --update
download against a fake server on an ephemeral 127.0.0.1 port (no real network).
"""
import io
import json
import os
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from netwarden import threatintel as ti


class CheckTests(unittest.TestCase):
    def test_high_risk_iot_cloud(self):
        m = ti.check("xmeye.net")
        self.assertIsNotNone(m)
        self.assertEqual(m[0], ti.SEV_HIGH_RISK)

    def test_subdomain_matches(self):
        self.assertEqual(ti.check("star1.xmeye.net")[0], ti.SEV_HIGH_RISK)
        self.assertEqual(ti.check("secu100.net")[0], ti.SEV_HIGH_RISK)

    def test_known_malicious_test_domain(self):
        self.assertEqual(ti.check("testsafebrowsing.appspot.com")[0], ti.SEV_MALICIOUS)

    def test_clean_domain_is_none(self):
        self.assertIsNone(ti.check("github.com"))
        self.assertIsNone(ti.check("instagram.com"))
        self.assertIsNone(ti.check(""))


class LocalizationTests(unittest.TestCase):
    def test_check_text_in_requested_language(self):
        sev, label, why = ti.check("xmeye.net")             # canonical English
        self.assertEqual(label, "XMEye camera cloud/P2P")
        self.assertIn("Mirai", why)
        _sev, label_tw, why_tw = ti.check("xmeye.net", lang="zh-Hant")
        self.assertEqual(label_tw, "XMEye 攝影機雲端/P2P")
        self.assertIn("殭屍網路", why_tw)

    def test_feed_entries_get_generic_text(self):
        table = {"evil.example": (ti.SEV_MALICIOUS, ti.FEED)}
        self.assertEqual(ti.check("x.evil.example", table)[1], "Threat-intelligence list")
        self.assertEqual(ti.check("x.evil.example", table, lang="fr")[1],
                         "Liste de renseignement sur les menaces")

    def test_localize_finding(self):
        f = {"domain": "secu100.net", "severity": ti.SEV_HIGH_RISK, "indicator": "secu100",
             "label": "Xiongmai camera cloud", "why": "..."}
        out = ti.localize(f, "es")
        self.assertEqual(out["label"], "Nube de cámaras Xiongmai")
        self.assertEqual(out["severity"], ti.SEV_HIGH_RISK)   # severity key unchanged
        self.assertEqual(f["label"], "Xiongmai camera cloud")  # input untouched


class ScanTests(unittest.TestCase):
    def test_scan_sorts_malicious_first(self):
        snap = {"devices": [
            {"name": "cam", "mac": "a", "ips": ["10.0.0.9"], "top_domains": [
                {"domain": "xmeye.net", "count": 50},
                {"domain": "github.com", "count": 3},
            ]},
            {"name": "pc", "mac": "b", "ips": ["10.0.0.5"], "top_domains": [
                {"domain": "testsafebrowsing.appspot.com", "count": 1},
            ]},
        ]}
        findings = ti.scan_snapshot(snap)
        self.assertEqual(len(findings), 2)                 # github.com not flagged
        self.assertEqual(findings[0]["severity"], ti.SEV_MALICIOUS)  # sorted first
        self.assertEqual(findings[1]["domain"], "xmeye.net")

    def test_clean_snapshot_has_no_findings(self):
        snap = {"devices": [{"name": "pc", "top_domains": [{"domain": "github.com", "count": 9}]}]}
        self.assertEqual(ti.scan_snapshot(snap), [])


class FeedParserTests(unittest.TestCase):
    def test_parses_hosts_format_and_skips_noise(self):
        text = (
            "# a comment\n"
            "0.0.0.0 evil-one.example\n"
            "127.0.0.1 evil-two.example\n"
            "0.0.0.0 localhost\n"      # skipped
            "! adblock comment\n"
            "plain-domain.example\n"
            "0.0.0.0 evil-one.example\n"  # duplicate -> deduped
            "192.168.0.1\n"              # bare IP -> skipped
        )
        out = ti._parse_feed_text(text)
        self.assertIn("evil-one.example", out)
        self.assertIn("evil-two.example", out)
        self.assertIn("plain-domain.example", out)
        self.assertNotIn("localhost", out)
        self.assertNotIn("192.168.0.1", out)
        self.assertEqual(len(out), 3)   # deduped


KEY = "s3cretAuthKey0123456789"   # stands in for a personal URLhaus Auth-Key in the path


class _FeedHandler(BaseHTTPRequestHandler):
    """A fake feed server: /ok/<key>/hostfile, /gone, /denied, /html, /broken."""

    def do_GET(self):
        if self.path == f"/ok/{KEY}/hostfile/":
            body, code = b"# URLhaus-like\n127.0.0.1 bad-one.example\n127.0.0.1 bad-two.example\n", 200
        elif self.path == "/gone":
            body, code = b"gone", 410
        elif self.path == "/denied":
            body, code = b"no", 403
        elif self.path == "/html":
            body, code = b"<html><body>Please log in</body></html>", 200
        else:
            body, code = b"oops", 500
        self.send_response(code)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class FeedUpdateTests(unittest.TestCase):
    """--update: no built-in URL (URLhaus needs a personal Auth-Key since abuse.ch moved to
    authenticated access), the URL is a secret, failures degrade gracefully. Fake server only."""

    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _FeedHandler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(ti, "CACHE", Path(self.tmp.name) / "threatfeed.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        env = mock.patch.dict(os.environ, {"no_proxy": "127.0.0.1", "NO_PROXY": "127.0.0.1"})
        env.start()
        self.addCleanup(env.stop)

    def _cli(self, *argv, lang="en"):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = ti.main(["--lang", lang, *argv])
        return rc, out.getvalue()

    def test_success_caches_domains_but_never_the_url(self):
        n = ti.update_from_feed(f"{self.base}/ok/{KEY}/hostfile/")
        self.assertEqual(n, 2)
        raw = ti.CACHE.read_text(encoding="utf-8")
        self.assertNotIn(KEY, raw)
        self.assertEqual(json.loads(raw)["source"], "127.0.0.1")
        self.assertEqual(ti.indicators()["bad-one.example"], (ti.SEV_MALICIOUS, ti.FEED))

    def test_cli_success_is_localized(self):
        rc, out = self._cli("--update", f"{self.base}/ok/{KEY}/hostfile/", lang="zh-Hant")
        self.assertEqual(rc, 0)
        self.assertIn("2", out)
        self.assertIn("威脅清單", out)
        self.assertNotIn(KEY, out)

    def test_bare_update_explains_auth_key_without_network(self):
        with mock.patch.object(ti.urllib.request, "urlopen", side_effect=AssertionError("network")):
            rc, out = self._cli("--update")
        self.assertEqual(rc, 2)
        self.assertIn("Auth-Key", out)
        self.assertIn(ti.ABUSECH_AUTH_URL, out)
        self.assertFalse(ti.CACHE.exists())

    def test_gone_or_denied_means_auth_key(self):
        for path, code in (("/gone", 410), ("/denied", 403)):
            with self.assertRaises(ti.FeedError) as cm:
                ti.update_from_feed(self.base + path)
            self.assertEqual((cm.exception.kind, cm.exception.code), ("auth", code))
            msg = cm.exception.message("en")
            self.assertIn(str(code), msg)
            self.assertIn("Auth-Key", msg)

    def test_login_page_keeps_the_previous_list(self):
        ti.update_from_feed(f"{self.base}/ok/{KEY}/hostfile/")
        before = ti.CACHE.read_text(encoding="utf-8")
        with self.assertRaises(ti.FeedError) as cm:
            ti.update_from_feed(self.base + "/html")
        self.assertEqual(cm.exception.kind, "empty")
        self.assertEqual(ti.CACHE.read_text(encoding="utf-8"), before)

    def test_server_error_and_unreachable_never_echo_the_key(self):
        rc, out = self._cli("--update", f"{self.base}/other/{KEY}/x")
        self.assertEqual(rc, 1)
        self.assertIn("HTTP 500", out)
        self.assertNotIn(KEY, out)
        with socket.socket() as s:        # a port that is certainly closed
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        rc, out = self._cli("--update", f"http://127.0.0.1:{port}/{KEY}/hostfile/")
        self.assertEqual(rc, 1)
        self.assertNotIn(KEY, out)

    def test_too_big_is_refused(self):
        with mock.patch.object(ti, "MAX_FEED_BYTES", 10):
            with self.assertRaises(ti.FeedError) as cm:
                ti.update_from_feed(f"{self.base}/ok/{KEY}/hostfile/")
        self.assertEqual(cm.exception.kind, "failed")
        self.assertFalse(ti.CACHE.exists())

    def test_only_http_urls(self):
        for url in ("file:///etc/passwd", "ftp://example.org/list", "not a url", ""):
            with self.assertRaises(ti.FeedError) as cm:
                ti.update_from_feed(url)
            self.assertEqual(cm.exception.kind, "bad_url")
        rc, _out = self._cli("--update", "file:///etc/hosts")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
