"""Round 6, stage H: the Home Assistant add-on - add-on mode, options, ingress, files.

No real network and no Supervisor: the ingress proxy is played by tests/ingress_proxy.py,
which connects to the server from 127.0.0.2 (the trusted proxy address is injected for
these tests only); "other devices" are played by injecting Handler.is_local_client.
"""
import contextlib
import http.client
import io
import json
import os
import re
import socket
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock
from urllib.parse import urljoin, urlparse

import netwarden
from netwarden import __main__ as cli
from netwarden import addon, brain, demo, i18n, pairing, store, web

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ingress_proxy import PREFIX, IngressProxy  # noqa: E402

PROXY_IP = "127.0.0.2"
HA_HOST = "homeassistant.local:8123"
_DEMO: dict = {}


def demo_copy(dest: Path) -> str:
    if "path" not in _DEMO:
        _DEMO["tmp"] = tempfile.TemporaryDirectory()
        _DEMO["path"] = Path(_DEMO["tmp"].name) / "demo.db"
        demo.build(_DEMO["path"])
    src, dst = sqlite3.connect(_DEMO["path"]), sqlite3.connect(dest)
    src.backup(dst)
    src.close()
    dst.close()
    return str(dest)


def tearDownModule():
    if "tmp" in _DEMO:
        _DEMO["tmp"].cleanup()


# --- 1. add-on mode and options ---------------------------------------------------------

class AddonMode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.opts = Path(self.tmp.name) / "options.json"

    def write(self, obj):
        self.opts.write_text(json.dumps(obj) if not isinstance(obj, str) else obj, encoding="utf-8")

    def test_active_needs_the_token_and_a_readable_options_file(self):
        self.assertFalse(addon.active({"SUPERVISOR_TOKEN": "t"}, self.opts))     # no file
        self.write({})
        self.assertFalse(addon.active({}, self.opts))                            # no token
        self.assertFalse(addon.active({"SUPERVISOR_TOKEN": ""}, self.opts))
        self.assertTrue(addon.active({"SUPERVISOR_TOKEN": "t"}, self.opts))
        self.assertFalse(addon.active({"SUPERVISOR_TOKEN": "t"}, Path(self.tmp.name)))   # a dir

    def test_read_options_refuses_bad_files_without_echoing_them(self):
        for bad in ("[1, 2]", "not json {", "\"str\"", "{" + " " * addon.MAX_OPTIONS + "}"):
            self.write(bad)
            with self.assertRaises(addon.AddonError) as cm:
                addon.read_options(self.opts)
            self.assertNotIn("str", str(cm.exception).replace("options", ""))
        with self.assertRaises(addon.AddonError):
            addon.read_options(Path(self.tmp.name) / "missing.json")
        self.write({"dns_source": "pihole"})
        self.assertEqual(addon.read_options(self.opts), {"dns_source": "pihole"})

    def test_env_from_options_maps_every_option_and_skips_junk(self):
        opts = {"language": "en", "timezone": "Europe/Berlin", "dns_source": "pihole",
                "adguard_url": "  http://192.168.1.2:3000  ", "adguard_user": "admin",
                "adguard_password": "s3cret-adg", "pihole_url": "http://192.168.1.3",
                "pihole_password": "s3cret-ph", "ntopng_url": "http://192.168.1.4:3001",
                "ntopng_user": "u", "ntopng_password": "s3cret-nt", "anthropic_api_key": "sk-ant-x",
                "ai_api_key": "sk-local", "retention_days": 30, "offline_ai": True,
                "lan_access": False,
                # not ours / wrong types / empty: ignored
                "unknown": "x", "adguard_user ": "y", "ntopng_user_": 1}
        env = addon.env_from_options(opts, environ={})
        self.assertEqual(env["NETWARDEN_LANG"], "en")
        self.assertEqual(env["NETWARDEN_TZ"], "Europe/Berlin")
        self.assertEqual(env["ADGUARD_URL"], "http://192.168.1.2:3000")
        self.assertEqual(env["ADGUARD_PASS"], "s3cret-adg")
        self.assertEqual(env["PIHOLE_PASSWORD"], "s3cret-ph")
        self.assertEqual(env["NTOPNG_PASS"], "s3cret-nt")
        self.assertEqual(env["ANTHROPIC_API_KEY"], "sk-ant-x")
        self.assertEqual(env["NETWARDEN_AI_KEY"], "sk-local")
        self.assertEqual(env["NETWARDEN_RETENTION_DAYS"], "30")
        self.assertEqual((env["NETWARDEN_OFFLINE_AI"], env["NETWARDEN_LAN"]), ("1", "0"))
        # the add-on's fixed listening rules
        self.assertEqual((env["NETWARDEN_HEADLESS"], env["NETWARDEN_REQUIRE_AUTH"],
                          env["NETWARDEN_HOST"], env["NETWARDEN_PORT"]),
                         ("1", "1", "127.0.0.1", str(addon.INGRESS_PORT)))
        self.assertNotIn("x", env.values())
        # empty strings, None, lists, bools in string slots, multi-line values: nothing
        env = addon.env_from_options({"adguard_url": "", "pihole_url": None, "language": ["en"],
                                      "adguard_user": True, "ntopng_url": "a\nb",
                                      "offline_ai": "yes"}, environ={})
        for var in ("ADGUARD_URL", "PIHOLE_URL", "NETWARDEN_LANG", "ADGUARD_USER", "NTOPNG_URL",
                    "NETWARDEN_OFFLINE_AI"):
            self.assertNotIn(var, env)
        # every mapped variable is one netwarden reads from the environment
        for var in list(addon.OPTION_ENV.values()) + list(addon.BOOL_OPTIONS.values()):
            self.assertIn(var, brain.ENV_KEYS)

    def test_home_assistants_time_zone_unless_the_option_is_set(self):
        self.assertEqual(addon.env_from_options({}, {"TZ": "Asia/Taipei"})["NETWARDEN_TZ"], "Asia/Taipei")
        self.assertEqual(addon.env_from_options({"timezone": "UTC"}, {"TZ": "Asia/Taipei"})["NETWARDEN_TZ"], "UTC")
        for odd in ("CST-8", "", "../etc/x", "Europe/Berlin;rm"):
            self.assertNotIn("NETWARDEN_TZ", addon.env_from_options({}, {"TZ": odd}), odd)

    def test_described_lists_names_never_values(self):
        opts = {"adguard_password": "s3cret", "anthropic_api_key": "sk-ant-zzz", "offline_ai": True,
                "lan_access": False, "adguard_url": "", "junk": "x"}
        text = " ".join(addon.described(opts))
        self.assertEqual(addon.described(opts), ["adguard_password", "anthropic_api_key", "offline_ai"])
        for v in ("s3cret", "sk-ant", "junk"):
            self.assertNotIn(v, text)

    def test_ingress_listen_is_the_route_toward_the_proxy(self):
        class FakeSock:
            def __init__(self, ip):
                self.ip = ip

            def connect(self, addr):
                self.addr = addr

            def getsockname(self):
                return (self.ip, 4242)

            def close(self):
                pass
        for got, want in (("172.30.32.1", "172.30.32.1"), ("172.30.33.7", "172.30.33.7"),
                          ("8.8.8.8", "172.30.32.1"), ("0.0.0.0", "172.30.32.1"),
                          ("172.30.32.2", "172.30.32.1"), ("bogus", "172.30.32.1")):
            with mock.patch.object(addon.socket, "socket", lambda *a, ip=got: FakeSock(ip)):
                self.assertEqual(addon.ingress_listen(), want, got)

    def test_prepare_and_drop_chowns_data_but_not_the_options_then_drops(self):
        data = Path(self.tmp.name) / "data"
        (data / "sub").mkdir(parents=True)
        for name in ("options.json", "netwarden.db", "sub/x"):
            (data / name).write_text("{}")
        calls = []
        pw = mock.Mock(pw_uid=10001, pw_gid=10001)
        with mock.patch.object(addon.os, "geteuid", return_value=0, create=True), \
                mock.patch("pwd.getpwnam", return_value=pw), \
                mock.patch.object(addon.os, "chown", lambda p, u, g: calls.append(Path(p).name), create=True), \
                mock.patch.object(addon.os, "setgroups", lambda g: calls.append("setgroups"), create=True), \
                mock.patch.object(addon.os, "setgid", lambda g: calls.append(("setgid", g)), create=True), \
                mock.patch.object(addon.os, "setuid", lambda u: calls.append(("setuid", u)), create=True), \
                mock.patch.dict(os.environ, {}, clear=False), \
                mock.patch.object(addon, "OPTIONS_PATH", data / "options.json"):
            self.assertTrue(addon.prepare_and_drop(data))
            self.assertEqual(os.environ["HOME"], str(data))
        self.assertIn("data", calls)
        self.assertIn("netwarden.db", calls)
        self.assertIn("x", calls)
        self.assertNotIn("options.json", calls)
        self.assertEqual(calls[-3:], ["setgroups", ("setgid", 10001), ("setuid", 10001)])

    def test_prepare_and_drop_keeps_going_when_it_cannot(self):
        with mock.patch.object(addon.os, "geteuid", return_value=1000, create=True):
            self.assertFalse(addon.prepare_and_drop(Path(self.tmp.name)))
        with mock.patch.object(addon.os, "geteuid", return_value=0, create=True), \
                mock.patch("pwd.getpwnam", side_effect=KeyError("netwarden")), \
                self.assertLogs("netwarden.addon", "WARNING"):
            self.assertFalse(addon.prepare_and_drop(Path(self.tmp.name)))
        with mock.patch.object(addon.os, "geteuid", return_value=0, create=True), \
                mock.patch("pwd.getpwnam", return_value=mock.Mock(pw_uid=1, pw_gid=1)), \
                mock.patch.object(addon.os, "chown", side_effect=PermissionError, create=True), \
                mock.patch.object(addon.os, "setuid") as setuid, \
                self.assertLogs("netwarden.addon", "WARNING") as logs:
            self.assertFalse(addon.prepare_and_drop(Path(self.tmp.name)))
            setuid.assert_not_called()

    def test_main_refuses_outside_home_assistant_localized(self):
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"NETWARDEN_LANG": "zh-Hant"}), \
                mock.patch.object(addon, "active", return_value=False), \
                contextlib.redirect_stderr(err):
            self.assertEqual(addon.main([]), 2)
        self.assertIn("Home Assistant Supervisor", err.getvalue())
        self.assertIn("啟動", err.getvalue())
        self.write("[]")
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"NETWARDEN_LANG": "en"}), \
                mock.patch.object(addon, "active", return_value=True), \
                mock.patch.object(addon, "OPTIONS_PATH", self.opts), \
                contextlib.redirect_stderr(err):
            self.assertEqual(addon.main([]), 2)
        self.assertIn("Configuration tab", err.getvalue())

    def test_main_maps_options_drops_and_runs(self):
        self.write({"offline_ai": True, "lan_access": False, "dns_source": "adguard",
                    "anthropic_api_key": "sk-ant-never-logged"})
        seen = {}
        with mock.patch.dict(os.environ, {"SUPERVISOR_TOKEN": "tok-never-logged"}), \
                mock.patch.object(addon, "OPTIONS_PATH", self.opts), \
                mock.patch.object(addon, "prepare_and_drop", lambda: seen.setdefault("dropped", True)), \
                mock.patch.object(cli, "cmd_run", lambda argv: seen.update(
                    argv=argv, env={k: os.environ.get(k) for k in ("NETWARDEN_OFFLINE_AI",
                                                                   "NETWARDEN_REQUIRE_AUTH",
                                                                   "ANTHROPIC_API_KEY")}) or 0), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertLogs("netwarden.addon", "INFO") as logs:
            self.assertEqual(addon.main(["--verbose"]), 0)
        self.assertEqual(seen["argv"], ["--verbose"])
        self.assertTrue(seen["dropped"])
        self.assertEqual(seen["env"], {"NETWARDEN_OFFLINE_AI": "1", "NETWARDEN_REQUIRE_AUTH": "1",
                                       "ANTHROPIC_API_KEY": "sk-ant-never-logged"})
        text = "\n".join(logs.output) + err.getvalue()
        self.assertIn("anthropic_api_key", text)
        self.assertNotIn("never-logged", text)
        self.assertFalse(addon.log.handlers)            # the early stderr handler is gone


class RunWiring(unittest.TestCase):
    """`run` hands the ingress proxy to the server only in add-on mode."""

    def run_cli(self, active: bool) -> dict:
        got = {}

        def fake_make_server(*a, **kw):
            got.update(kw)
            raise OSError("stop here")
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(brain, "load_env", return_value={}), \
                mock.patch.object(addon, "active", return_value=active), \
                mock.patch.object(addon, "ingress_listen", return_value="172.30.32.1"), \
                mock.patch.object(web, "make_server", fake_make_server), \
                mock.patch.object(cli.runner, "setup_logging"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.cmd_run(["--db", str(Path(tmp) / "r.db"), "--no-loops",
                                          "--lang", "en"]), 1)
        return got

    def test_ingress_only_in_addon_mode(self):
        self.assertEqual((self.run_cli(False)["ingress_proxy"], self.run_cli(False)["ingress_host"]),
                         (None, None))
        kw = self.run_cli(True)
        self.assertEqual((kw["ingress_proxy"], kw["ingress_host"]), (addon.INGRESS_PROXY, "172.30.32.1"))
        self.assertEqual(addon.INGRESS_PROXY, "172.30.32.2")   # fixed by the HA docs; not a setting


# --- 2. the base path ------------------------------------------------------------------------

class BasePath(unittest.TestCase):
    def test_ingress_base_accepts_plain_segments_only(self):
        self.assertEqual(web.ingress_base("/api/hassio_ingress/AbC_-12"), "/api/hassio_ingress/AbC_-12")
        self.assertEqual(web.ingress_base("/api/hassio_ingress/tok/"), "/api/hassio_ingress/tok")
        for bad in ("", None, "/", "api/x", "//evil.example", "/a/../b", "/a/./b", "/a b", "/a\"b",
                    "/x\"><script>", "javascript:alert(1)", "/a?b", "/a#b", "/a%2e%2e", "/a\\b",
                    "/" + "a" * 129, "/a" * 9, "/a\n/b"):
            self.assertEqual(web.ingress_base(bad), "", bad)

    def test_pages_put_the_base_in_front_of_every_url(self):
        b = "/api/hassio_ingress/T0k"
        for page in (web.index_html(b).decode(), web.offline_html("en", b).decode(),
                     pairing.render_page("en", "v1", base=b)):
            self.assertIn(f'data-base="{b}"', page)
            for u in re.findall(r'(?:href|src)="([^"]+)"', page):
                if not u.startswith("#"):
                    self.assertTrue(u.startswith(b + "/"), u)
        # at / nothing changes: the same absolute URLs as before
        page = web.index_html().decode()
        self.assertIn('data-base=""', page)
        self.assertIn('href="/static/app.css?v=', page)
        self.assertNotIn("__BASE__", page)

    def test_static_files_never_hard_code_the_root(self):
        st = ROOT / "netwarden" / "static"
        for name in ("app.js", "pair.js", "offline.js"):
            js = (st / name).read_text(encoding="utf-8")
            for pat in (r"fetch\('/", r"EventSource\('/", r"location\.(replace|assign)\('/",
                        r"window\.open\('/", r"href=\"/(api|static|report|pair)"):
                self.assertNotRegex(js, pat, name)
        man = json.loads((st / "manifest.webmanifest").read_text(encoding="utf-8"))
        for u in [man["start_url"], man["scope"]] + [i["src"] for i in man["icons"]]:
            self.assertFalse(u.startswith("/"), u)
        self.assertNotIn('url("/', (st / "app.css").read_text(encoding="utf-8"))
        sw = (st / "sw.js").read_text(encoding="utf-8")
        self.assertIn("self.registration.scope", sw)
        self.assertNotRegex(sw, r"(=|\[|,)\s*'/(offline|static)")   # only ever ROOT + '/...'


# --- 3. through a fake ingress proxy ------------------------------------------------------

class _Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k in ("href", "src") and v and not v.startswith(("#", "data:")):
                self.urls.append(v)


class Ingress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = demo_copy(Path(cls.tmp.name) / "ha.db")
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1",
                                                "NETWARDEN_REQUIRE_AUTH": "1"}, "en",
                                  ingress_proxy=PROXY_IP)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.proxy = IngressProxy(cls.port).start()
        cls.old_hb = web.Handler.STREAM_HEARTBEAT

    @classmethod
    def tearDownClass(cls):
        web.Handler.STREAM_HEARTBEAT = cls.old_hb
        cls.proxy.stop()
        cls.srv.shutdown()
        web.close_server(cls.srv)
        web.Handler.ingress_proxy = None
        web.Handler.require_auth = False
        cls.tmp.cleanup()

    def setUp(self):
        web.Handler.limiter = pairing.Limiter()
        self.addCleanup(self._restore)

    def _restore(self):
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))
        web.Handler.ingress_proxy = PROXY_IP

    # requests: through the proxy (the browser's Host is HA's) or straight to the server
    def via(self, method, path, body=None, origin=f"http://{HA_HOST}", headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.proxy.port, timeout=20)
        h = {"host": HA_HOST, **(headers or {})}
        if method == "POST":
            h["content-type"] = "application/json"
            if origin:
                h["origin"] = origin
        c.request(method, PREFIX + path, json.dumps(body or {}) if method == "POST" else None, h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, r, data

    def direct(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        h = dict(headers or {})
        if method == "POST":
            h["content-type"] = "application/json"
        c.request(method, path, json.dumps(body or {}) if method == "POST" else None, h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, r, data

    def assets(self, html: str, page_url: str) -> list[str]:
        p = _Assets()
        p.feed(html)
        return [urljoin(page_url, u) for u in p.urls]

    def fetch_ok(self, url: str):
        u = urlparse(url)
        self.assertEqual(u.netloc, f"127.0.0.1:{self.proxy.port}", url)
        self.assertTrue(u.path.startswith(PREFIX + "/"), url)
        st, _r, data = self.via("GET", url.split(PREFIX, 1)[1])
        self.assertEqual(st, 200, url)
        return data

    def test_the_spa_and_every_url_it_names_load_under_the_prefix(self):
        page_url = self.proxy.base + "/"
        st, r, data = self.via("GET", "/")
        self.assertEqual(st, 200)
        html = data.decode()
        self.assertIn(f'data-base="{PREFIX}"', html)
        # framed by Home Assistant's own page only
        self.assertEqual(r.getheader("x-frame-options"), "SAMEORIGIN")
        self.assertIn("frame-ancestors 'self'", r.getheader("content-security-policy"))
        self.assertNotIn("frame-ancestors 'none'", r.getheader("content-security-policy"))
        urls = self.assets(html, page_url)
        self.assertGreaterEqual(len(urls), 5)
        for u in urls:
            self.fetch_ok(u)
        # the manifest's relative URLs resolve under the prefix too
        man_url = next(u for u in urls if u.split("?")[0].endswith("manifest.webmanifest"))
        man = json.loads(self.fetch_ok(man_url))
        for u in [man["start_url"], man["scope"]] + [i["src"] for i in man["icons"]]:
            self.fetch_ok(urljoin(man_url, u))
        self.assertEqual(urljoin(man_url, man["start_url"]), page_url)
        # app.css's icon, the service worker and its offline page
        css_url = next(u for u in urls if "/static/app.css" in u)
        self.assertIn('url("icon.svg")', self.fetch_ok(css_url).decode())
        self.fetch_ok(urljoin(css_url, "icon.svg"))
        self.assertIn(b"registration.scope", self.fetch_ok(self.proxy.base + "/sw.js"))
        off = self.fetch_ok(self.proxy.base + "/offline").decode()
        for u in self.assets(off, self.proxy.base + "/offline"):
            self.fetch_ok(u)

    def test_pair_and_weekly_report_pages_under_the_prefix(self):
        for path in ("/pair", "/report/weekly?lang=en"):
            st, _r, data = self.via("GET", path)
            self.assertEqual(st, 200, path)
            html = data.decode()
            urls = self.assets(html, self.proxy.base + path)
            self.assertTrue(urls, path)
            for u in urls:
                self.fetch_ok(u)
        st, _r, data = self.via("GET", "/report/weekly?lang=en")
        self.assertIn(f'href="{PREFIX}/#/family"', data.decode())

    def test_api_meta_says_ingress_admin(self):
        st, _r, data = self.via("GET", "/api/meta?lang=en")
        meta = json.loads(data)
        self.assertEqual(st, 200)
        self.assertEqual((meta["ingress"], meta["addon"], meta["admin"], meta["remote"],
                          meta["signed_in"]), (True, True, True, False, False))
        self.assertFalse(meta["admin_session"])   # no "signed in from another device" warning

    def test_admin_endpoints_and_downloads_work_via_ingress(self):
        for path in ("/api/settings?lang=en", "/api/pair/sessions?lang=en", "/api/setup?lang=en",
                     "/api/export/devices.csv?lang=en", "/api/export/report.md?lang=en"):
            st, _r, data = self.via("GET", path)
            self.assertEqual(st, 200, (path, data[:200]))
        st, r, data = self.via("GET", "/api/backup")
        self.assertEqual(st, 200)
        self.assertIn("attachment", r.getheader("content-disposition"))
        st, _r, data = self.via("POST", "/api/settings", {"values": {"alerts.snooze_days": 9}})
        self.assertEqual(st, 200, data)
        st, _r, data = self.via("POST", "/api/pair/new", {})
        self.assertEqual(st, 200, data)

    def test_post_needs_an_origin_naming_home_assistants_host(self):
        body = {"values": {"alerts.snooze_days": 8}}
        self.assertEqual(self.via("POST", "/api/settings", body, origin=f"https://{HA_HOST}")[0], 200)
        for bad in ("http://evil.example", None, f"http://{HA_HOST}.evil.example", "null",
                    f"http://{HA_HOST}/path", f"ftp://{HA_HOST}"):
            st, _r, data = self.via("POST", "/api/settings", body, origin=bad)
            self.assertEqual(st, 403, (bad, data))

    def test_sse_works_through_the_proxy(self):
        web.Handler.STREAM_HEARTBEAT = 0.2
        sock = socket.create_connection(("127.0.0.1", self.proxy.port), timeout=10)
        try:
            sock.sendall((f"GET {PREFIX}/api/stream HTTP/1.1\r\nHost: {HA_HOST}\r\n"
                          "Accept: text/event-stream\r\nX-Forwarded-For: 192.168.1.50\r\n\r\n").encode())
            buf = b""
            deadline = time.monotonic() + 10
            while b"event: hello" not in buf and time.monotonic() < deadline:
                buf += sock.recv(65536)
            self.assertIn(b"200", buf.split(b"\r\n", 1)[0])
            self.assertIn(b"text/event-stream", buf)
            self.assertIn(b"event: hello", buf)
            time.sleep(0.6)   # the detector's baseline
            db = store.connect(self.path)
            mac = db.execute("SELECT mac FROM devices WHERE is_self = 0 ORDER BY mac LIMIT 1").fetchone()[0]
            db.close()
            st, _r, data = self.via("POST", "/api/label", {"mac": mac, "label": "Via HA", "note": ""})
            self.assertEqual(st, 200, data)
            deadline = time.monotonic() + 10
            while b"event: notes_changed" not in buf and time.monotonic() < deadline:
                buf += sock.recv(65536)
            self.assertIn(b"event: notes_changed", buf)
        finally:
            sock.close()
            self.via("POST", "/api/label", {"mac": mac, "label": "", "note": ""})

    def test_stream_cap_counts_browsers_not_the_proxy(self):
        h = web.Handler.__new__(web.Handler)
        h.ingress, h.client_address = True, (PROXY_IP, 1)
        h.headers = {"x-forwarded-for": "192.168.1.50, 172.30.32.1"}
        self.assertEqual(h._client_key(), "ingress:192.168.1.50")
        h.headers = {"x-forwarded-for": "None, 192.168.1.51, 172.30.32.1"}
        self.assertEqual(h._client_key(), "ingress:192.168.1.51")
        h.ingress = False
        self.assertEqual(h._client_key(), PROXY_IP)

    # --- spoofing: the same headers from anyone else mean nothing --------------------------

    def spoof(self):
        return {"x-ingress-path": PREFIX, "x-hass-source": "core.ingress",
                "x-forwarded-for": "192.168.1.50, 172.30.32.1", "x-forwarded-host": HA_HOST,
                "x-forwarded-proto": "https"}

    def test_headers_from_an_untrusted_lan_peer_are_ignored(self):
        web.Handler.is_local_client = staticmethod(lambda ip: False)   # a phone on the LAN
        st, r, _ = self.direct("GET", "/", headers={**self.spoof(), "host": f"127.0.0.1:{self.port}"})
        self.assertEqual(st, 303)
        self.assertEqual(r.getheader("location"), "/pair")              # no prefix honored
        self.assertEqual(r.getheader("x-frame-options"), "DENY")
        st, _r, data = self.direct("GET", "/api/meta", headers=self.spoof())
        self.assertIn(st, (401, 421))
        for path in web.ADMIN_GETS:
            self.assertIn(self.direct("GET", path, headers=self.spoof())[0], (401, 421), path)
        for path in web.ADMIN_POSTS:
            st, *_ = self.direct("POST", path, {}, headers={**self.spoof(), "origin": f"http://{HA_HOST}",
                                                            "host": HA_HOST})
            self.assertIn(st, (401, 403, 421), path)
        # Home Assistant's Host is not ours either
        self.assertEqual(self.direct("GET", "/api/meta", headers={**self.spoof(), "host": HA_HOST})[0], 421)

    def test_unpaired_lan_clients_stay_locked_out_of_admin_endpoints(self):
        web.Handler.is_local_client = staticmethod(lambda ip: False)
        host = {"host": f"127.0.0.1:{self.port}"}
        for path in web.ADMIN_GETS:
            self.assertEqual(self.direct("GET", path, headers=host)[0], 401, path)
        st, *_ = self.direct("POST", "/api/settings", {"values": {}},
                             headers={**host, "origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(st, 401)

    def test_a_loopback_peer_with_ingress_headers_gets_nothing_extra(self):
        # add-on mode: loopback needs a session too (REQUIRE_AUTH), headers or not
        host = {"host": f"127.0.0.1:{self.port}"}
        st, _r, data = self.direct("GET", "/api/meta", headers={**self.spoof(), **host})
        self.assertEqual(st, 401, data)
        st, r, data = self.direct("GET", "/pair", headers={**self.spoof(), **host})
        self.assertEqual(st, 200)
        self.assertIn('data-base=""', data.decode())
        self.assertNotIn(PREFIX, data.decode())
        self.assertEqual(r.getheader("x-frame-options"), "DENY")

    def test_without_add_on_mode_the_proxy_address_is_just_another_client(self):
        web.Handler.ingress_proxy = None
        st, r, data = self.via("GET", "/api/meta")
        self.assertIn(st, (401, 421))
        self.assertEqual(r.getheader("x-frame-options"), "DENY")


class IngressListener(unittest.TestCase):
    def test_make_server_adds_one_listener_and_resets_between_servers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "l.db")
            srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en",
                                  ingress_proxy=PROXY_IP, ingress_host="127.0.0.3")
            try:
                self.assertEqual(web.Handler.ingress_proxy, PROXY_IP)
                self.assertEqual([s.server_address[0] for s in srv.extra], ["127.0.0.3"])
                self.assertEqual(srv.extra[0].server_address[1], srv.server_address[1])
            finally:
                for s in srv.extra:
                    s.shutdown()
                web.close_server(srv)
            srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en")
            try:
                self.assertIsNone(web.Handler.ingress_proxy)
                self.assertEqual(srv.extra, [])
            finally:
                web.close_server(srv)
            # an address that can't be bound: logged, the server still starts
            with self.assertLogs("netwarden.web", "WARNING"):
                srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en",
                                      ingress_proxy=PROXY_IP, ingress_host="192.0.2.1")
            try:
                self.assertEqual(srv.extra, [])
            finally:
                web.close_server(srv)
                web.Handler.ingress_proxy = None


# --- 4. the add-on's files ---------------------------------------------------------------------

def _yaml_top(text: str) -> dict:
    """Top-level `key: value` lines + the `schema:` / `options:` blocks of a flat YAML."""
    out, block = {}, None
    for ln in text.splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if not ln.startswith(" "):
            k, _, v = ln.partition(":")
            block = k if not v.strip() else None
            out[k] = {} if block else v.strip().strip('"')
        elif block and ln.startswith("  ") and not ln.startswith("   "):
            if ln.strip().startswith("- "):
                out[block] = (out[block] or []) if isinstance(out[block], list) else []
                out[block].append(ln.strip()[2:])
            else:
                k, _, v = ln.strip().partition(":")
                out[block][k] = v.strip()
    return out


class AddonFiles(unittest.TestCase):
    D = ROOT / "ha-addon"

    def setUp(self):
        self.cfg = _yaml_top((self.D / "config.yaml").read_text(encoding="utf-8"))

    def test_config(self):
        c = self.cfg
        self.assertEqual(c["version"], netwarden.__version__)
        self.assertEqual(c["slug"], "netwarden")
        self.assertEqual(c["url"], "https://github.com/liming-ting/netwarden")
        self.assertEqual(c["image"], "ghcr.io/liming-ting/netwarden-addon")
        self.assertEqual(c["arch"], ["amd64", "aarch64", "armv7"])
        self.assertEqual((c["host_network"], c["ingress"], c["ingress_port"], c["panel_admin"]),
                         ("true", "true", str(addon.INGRESS_PORT), "true"))
        self.assertEqual(c["init"], "true")
        self.assertTrue(c["panel_icon"].startswith("mdi:"))
        text = "\n".join(ln for ln in (self.D / "config.yaml").read_text(encoding="utf-8").splitlines()
                         if not ln.lstrip().startswith("#"))
        for never in ("privileged", "full_access", "host_pid", "devices:", "docker_api",
                      "apparmor: false", "auth_api", "ports:"):
            self.assertNotIn(never, text)
        self.assertEqual((c["hassio_api"], c["homeassistant_api"]), ("false", "false"))

    def test_schema_matches_the_option_mapping(self):
        schema, opts = self.cfg["schema"], self.cfg["options"]
        self.assertEqual(set(schema), set(addon.OPTION_ENV) | set(addon.BOOL_OPTIONS))
        for k in addon.SECRET_OPTIONS:
            self.assertEqual(schema[k], "password?", k)
        for k, v in schema.items():
            if k not in addon.SECRET_OPTIONS:
                self.assertNotIn("password", v, k)
        for k in addon.BOOL_OPTIONS:
            self.assertEqual((schema[k], opts[k]), ("bool", "false"))
        self.assertEqual(set(schema["language"][5:-2].split("|")), set(i18n.CODES))
        self.assertEqual(schema["language"].split("(")[1].split("|")[0], i18n.DEFAULT)
        self.assertEqual(schema["dns_source"], "list(adguard|pihole)")
        # only required options have defaults; nothing secret is pre-filled
        self.assertEqual(set(opts), {"dns_source", "offline_ai", "lan_access"})
        tr = (self.D / "translations" / "en.yaml").read_text(encoding="utf-8")
        for k in schema:
            self.assertRegex(tr, rf"(?m)^  {k}:\n    name: \S", k)

    def test_images_and_docs(self):
        def size(name):
            data = (self.D / name).read_bytes()
            self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
            return struct.unpack(">II", data[16:24])
        self.assertEqual(size("icon.png"), (128, 128))
        self.assertEqual(size("logo.png"), (250, 100))
        for name in ("DOCS.md", "README.md", "CHANGELOG.md"):
            text = (self.D / name).read_text(encoding="utf-8")
            self.assertIn("netwarden", text)
        self.assertIn(netwarden.__version__, (self.D / "CHANGELOG.md").read_text(encoding="utf-8"))
        for name in ("config.yaml", "translations/en.yaml", "DOCS.md", "README.md", "CHANGELOG.md"):
            self.assertNotIn(b"\r", (self.D / name).read_bytes(), name)

    def test_repository_layout(self):
        repo = _yaml_top((ROOT / "repository.yaml").read_text(encoding="utf-8"))
        self.assertEqual(repo["url"], "https://github.com/liming-ting/netwarden")
        self.assertTrue(repo["name"] and repo["maintainer"])
        # the Supervisor treats EVERY config.{json,yaml,yml} outside dot-folders as an add-on
        found = [p for p in ROOT.rglob("config.*")
                 if not any(part.startswith(".") for part in p.relative_to(ROOT).parts)
                 and p.suffix in (".json", ".yaml", ".yml")]
        self.assertEqual(found, [self.D / "config.yaml"])

    def test_dockerfile_addon_stage_and_workflow(self):
        text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("FROM runtime AS addon", text)
        addon_stage = text.split("FROM runtime AS addon", 1)[1].split("\nFROM ", 1)[0]
        self.assertIn('CMD ["python3", "-m", "netwarden.addon"]', addon_stage)
        self.assertIn('io.hass.type="addon"', addon_stage)
        self.assertNotIn("USER", addon_stage)       # root only until prepare_and_drop
        # the default image is still the last stage, unprivileged
        last = text.rsplit("\nFROM ", 1)[1]
        self.assertTrue(last.startswith("runtime"))
        self.assertIn("USER netwarden", last)
        wf = (ROOT / ".github" / "workflows" / "docker.yml").read_text(encoding="utf-8")
        self.assertEqual(wf.count("target: addon"), 2)
        self.assertIn("${{ env.IMAGE }}-addon:${{ steps.meta.outputs.version }}", wf)
        self.assertIn("SUPERVISOR_TOKEN=", wf)
        ign = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
        self.assertIn("ha-addon/", ign)


if __name__ == "__main__":
    unittest.main()
