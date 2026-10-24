"""Round 6, stage D: version, headless admin claim, container mode, packaging files.

No real network: servers on ephemeral 127.0.0.1 ports only; "other devices" are played
by injecting Handler.is_local_client (never by binding a LAN address).
"""
import contextlib
import http.client
import io
import json
import logging
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import netwarden
from netwarden import __main__ as cli
from netwarden import brain, headless, pairing, runner, settings, store, web

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- 1. version: one source of truth -------------------------------------------------

class Version(unittest.TestCase):
    def test_pyproject_matches_package_version(self):
        meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(meta["project"]["version"], netwarden.__version__)
        self.assertRegex(netwarden.__version__, r"^\d+\.\d+\.\d+$")
        self.assertEqual(meta["project"]["dependencies"], [])          # zero runtime deps
        self.assertEqual(meta["project"]["scripts"]["netwarden"], "netwarden.__main__:main")
        data = meta["tool"]["setuptools"]["package-data"]["netwarden"]
        for pattern in ("locales/*.json", "static/*", "locale_same_ok.json"):
            self.assertIn(pattern, data)

    def test_cli_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["--version"]), 0)
        # the first line stays exactly this (scripts parse it); round 8 adds license + source
        self.assertEqual(out.getvalue().splitlines()[0], f"netwarden {netwarden.__version__}")


# --- 2. data directory -----------------------------------------------------------------

class DataPaths(unittest.TestCase):
    def test_env_db_wins_then_data_dir_then_checkout(self):
        d, db = store._data_paths({"NETWARDEN_DB": "/data/netwarden.db", "NETWARDEN_DATA_DIR": "/x"})
        self.assertEqual((d, db), (Path("/data"), Path("/data/netwarden.db")))
        d, db = store._data_paths({"NETWARDEN_DATA_DIR": "/var/lib/netwarden"})
        self.assertEqual(db, Path("/var/lib/netwarden/netwarden.db"))
        d, db = store._data_paths({})   # this test runs from a checkout: <checkout>/data
        self.assertEqual(d, ROOT / "data")

    def test_installed_layout_uses_xdg_not_site_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_pkg = Path(tmp) / "site-packages" / "netwarden"
            fake_pkg.mkdir(parents=True)
            with mock.patch.object(store, "__file__", str(fake_pkg / "store.py")):
                d, db = store._data_paths({"XDG_DATA_HOME": tmp + "/xdg"})
                self.assertEqual(db, Path(tmp) / "xdg" / "netwarden" / "netwarden.db")
                d, _ = store._data_paths({"HOME": tmp})
                self.assertNotIn("site-packages", str(d))


# --- 3. admin codes (pairing.py) ----------------------------------------------------------

class AdminCodes(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")
        self.addCleanup(self.db.close)

    def test_admin_code_15_minutes_single_use_admin_session_and_claim(self):
        self.assertFalse(pairing.claimed(self.db))
        c = pairing.new_code(self.db, now=T0, admin=True)
        self.assertEqual((c["ttl_s"], c["admin"]), (15 * 60, True))
        self.assertRegex(c["code"], "^[" + pairing.CODE_ALPHABET + "]{10}$")
        stored = self.db.execute("SELECT code_hash, admin FROM pair_codes").fetchone()
        self.assertNotEqual(stored["code_hash"], c["code"])           # only a hash is kept
        self.assertEqual(stored["admin"], 1)
        token, sid = pairing.redeem(self.db, c["display"], UA, now=T0 + timedelta(minutes=14))
        self.assertTrue(pairing.check(self.db, token, now=T0 + timedelta(minutes=15))["admin"])
        self.assertTrue(pairing.claimed(self.db))
        self.assertIsNone(pairing.redeem(self.db, c["code"], UA, now=T0 + timedelta(minutes=14)))
        row = next(s for s in pairing.sessions(self.db, now=T0) if s["id"] == sid)
        self.assertTrue(row["admin"])

    def test_expired_wrong_and_ordinary_codes(self):
        c = pairing.new_code(self.db, now=T0, admin=True)
        self.assertIsNone(pairing.redeem(self.db, c["code"], UA, now=T0 + timedelta(minutes=15, seconds=1)))
        self.assertIsNone(pairing.redeem(self.db, "ABCDEFGHJK", UA, now=T0))
        self.assertFalse(pairing.claimed(self.db))
        n = pairing.new_code(self.db, now=T0)                           # an ordinary phone code
        self.assertEqual(n["ttl_s"], 10 * 60)
        token, _ = pairing.redeem(self.db, n["code"], UA, now=T0)
        self.assertFalse(pairing.check(self.db, token, now=T0)["admin"])
        self.assertFalse(pairing.claimed(self.db))                    # phones never claim
        self.assertEqual(pairing.revoke_all(self.db), 1)

    def test_old_database_gets_the_admin_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.db"
            raw = sqlite3.connect(path)
            raw.executescript("""
                CREATE TABLE pair_codes (id INTEGER PRIMARY KEY, code_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT);
                CREATE TABLE sessions (id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
                    last_seen TEXT NOT NULL, expires_at TEXT NOT NULL);
                INSERT INTO sessions VALUES (1, 'h', 'ua', '2026-01-01', '2026-01-01', '2999-01-01');""")
            raw.commit()
            raw.close()
            for _ in range(2):   # idempotent
                db = store.connect(path)
                cols = {r["name"] for r in db.execute("PRAGMA table_info(sessions)")}
                self.assertIn("admin", cols)
                self.assertFalse(pairing.sessions(db)[0]["admin"])   # old phones stay non-admin
                db.close()


class DemoAdminSession(unittest.TestCase):
    def test_demo_has_one_admin_session_idempotently_and_keeps_revokes(self):
        from netwarden import demo
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.db"
            demo.build(path)
            demo.build(path)
            db = store.connect(path)
            try:
                admins = [s for s in pairing.sessions(db) if s["admin"]]
                self.assertEqual(len(admins), 1)
                self.assertEqual(admins[0]["device"], "Mac · Firefox")
                pairing.revoke(db, admins[0]["id"])      # the user removed it: stays removed
            finally:
                db.close()
            demo.build(path)
            db = store.connect(path)
            try:
                self.assertFalse([s for s in pairing.sessions(db) if s["admin"]])
            finally:
                db.close()


# --- 4. headless.py -----------------------------------------------------------------

class Headless(unittest.TestCase):
    def test_listen_and_port_from_env(self):
        self.assertEqual(headless.listen({}), {"lan": False, "lan_host": None, "bind_all": False})
        self.assertFalse(headless.listen({"NETWARDEN_HOST": "127.0.0.1"})["lan"])
        self.assertFalse(headless.listen({"NETWARDEN_HOST": "localhost"})["lan"])
        self.assertEqual(headless.listen({"NETWARDEN_HOST": "0.0.0.0"}),
                         {"lan": True, "lan_host": None, "bind_all": True})
        self.assertEqual(headless.listen({"NETWARDEN_HOST": "192.168.1.20"}),
                         {"lan": True, "lan_host": "192.168.1.20", "bind_all": False})
        for bad, code in (("8.8.8.8", "public_host"), ("nas.example", "bad_host"), ("::", "public_host"),
                          ("127.0.0.1:80", "bad_host")):
            with self.assertRaises(headless.ListenError) as e:
                headless.listen({"NETWARDEN_HOST": bad})
            self.assertEqual(e.exception.code, code, bad)
        self.assertEqual(headless.port({}), 8787)
        self.assertEqual(headless.port({"NETWARDEN_PORT": "9000"}), 9000)
        for bad in ("0", "65536", "80a", "-1"):
            with self.assertRaises(headless.ListenError):
                headless.port({"NETWARDEN_PORT": bad})
        self.assertTrue(headless.is_headless({"NETWARDEN_HEADLESS": "1"}))
        self.assertFalse(headless.is_headless({}))

    def test_claim_lines_once_until_claimed(self):
        db = store.connect(":memory:")
        self.addCleanup(db.close)
        lines = headless.claim_lines(db, "en", "http://192.168.1.20:8787", now=T0)
        text = "\n".join(lines)
        m = re.search(r"/pair#([A-Z2-9]{10})", text)
        self.assertTrue(m, text)
        self.assertIn("15", text)
        self.assertIn("2026-10-01 12:15 UTC", text)
        pairing.redeem(db, m.group(1), UA, now=T0)
        self.assertEqual(headless.claim_lines(db, "en", "http://192.168.1.20:8787", now=T0), [])
        for lang in ("zh-Hant", "de", "ja"):   # every language has the texts
            db2 = store.connect(":memory:")
            self.assertNotIn("cli.claim", "\n".join(headless.claim_lines(db2, lang, "http://x:1")))
            db2.close()

    def test_unknown_listen_env_stops_run_with_a_message(self):
        err = io.StringIO()
        old = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, old)
        with mock.patch.object(brain, "load_env", return_value={"NETWARDEN_HOST": "8.8.8.8"}), \
                contextlib.redirect_stderr(err):
            self.assertEqual(cli.cmd_run(["--lang", "en"]), 2)
        self.assertIn("8.8.8.8", err.getvalue())


class FakeServer:
    def serve_forever(self, poll_interval=0.5):
        raise KeyboardInterrupt


class RunClaim(unittest.TestCase):
    """cmd_run in headless LAN mode prints ONE admin code (stdout only) until claimed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "h.db"
        old = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, old)
        lg = logging.getLogger("netwarden")
        saved = (list(lg.handlers), lg.propagate, lg.level)
        self.addCleanup(self._restore_logging, saved)

    @staticmethod
    def _restore_logging(saved):
        lg = logging.getLogger("netwarden")
        for h in list(lg.handlers):
            lg.removeHandler(h)
        for h in saved[0]:
            lg.addHandler(h)
        lg.propagate, lg.level = saved[1], saved[2]

    def _run(self, env):
        def fake_make(*a, **kw):
            web.Handler.lan, web.Handler.lan_url = kw.get("lan", False), "http://192.168.1.20:8787"
            return FakeServer()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(brain, "load_env", return_value=dict(env)), \
                mock.patch.object(web, "make_server", fake_make), \
                mock.patch.object(web, "stop_server", lambda *a, **k: None), \
                mock.patch.object(web, "lan_banner", lambda lang: ["LAN on"]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.cmd_run(["--db", str(self.db_path), "--no-loops", "--lang", "en"])
        web.Handler.lan, web.Handler.lan_url = False, ""
        return rc, out.getvalue(), err.getvalue()

    def test_first_start_prints_one_code_then_never_after_claim(self):
        env = {"NETWARDEN_HEADLESS": "1", "NETWARDEN_HOST": "0.0.0.0", brain.OFFLINE_ENV: "1"}
        rc, out, err = self._run(env)
        self.assertEqual(rc, 0)
        codes = re.findall(r"/pair#([A-Z2-9]{10})", out)
        self.assertEqual(len(codes), 1, out)
        self.assertNotIn(codes[0], err)                                # not in the log lines
        self.assertFalse((self.db_path.parent / "netwarden.log").exists())   # headless: no file
        self.assertIn("standard error", out)
        # not yet claimed: the next start prints a fresh code
        rc, out2, _ = self._run(env)
        self.assertEqual(len(re.findall(r"/pair#[A-Z2-9]{10}", out2)), 1)
        db = store.connect(self.db_path)
        code = re.search(r"/pair#([A-Z2-9]{10})", out2).group(1)
        self.assertIsNotNone(pairing.redeem(db, code, UA))
        db.close()
        rc, out3, err3 = self._run(env)
        self.assertNotIn("/pair#", out3 + err3)

    def test_desktop_and_loopback_headless_never_print_a_code(self):
        for env in ({brain.OFFLINE_ENV: "1"},                                  # desktop
                    {"NETWARDEN_HEADLESS": "1", brain.OFFLINE_ENV: "1"}):     # loopback only
            rc, out, err = self._run(env)
            self.assertEqual(rc, 0)
            self.assertNotIn("/pair#", out + err)
        self.assertTrue((self.db_path.parent / "netwarden.log").exists())   # desktop: as before


# --- 5. the web server: admin sessions, /healthz, advertised URL ------------------------

class WebAdmin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = str(Path(cls.tmp.name) / "w.db")
        store.connect(cls.path).close()
        cls.log = io.StringIO()
        cls.handler = logging.StreamHandler(cls.log)
        lg = logging.getLogger("netwarden")
        cls.saved_level = lg.level
        lg.setLevel(logging.INFO)
        lg.addHandler(cls.handler)
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        cls.port = cls.srv.server_address[1]
        cls.origin = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        web.close_server(cls.srv)
        logging.getLogger("netwarden").removeHandler(cls.handler)
        logging.getLogger("netwarden").setLevel(cls.saved_level)
        cls.tmp.cleanup()

    def setUp(self):
        web.Handler.limiter = pairing.Limiter()
        self.addCleanup(self._restore)

    def _restore(self):
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))
        web.Handler.lan_hosts = web.Handler.proxy_hosts = web.Handler.lan_origins = frozenset()
        web.Handler.lan, web.Handler.lan_url = False, ""
        db = store.connect(self.path)
        pairing.revoke_all(db)
        db.close()

    def phone(self):
        web.Handler.is_local_client = staticmethod(lambda ip: False)

    def req(self, method, path, body=None, cookie=None, host=None, origin="same"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"user-agent": UA}
        if host:
            h["host"] = host
        if cookie:
            h["cookie"] = cookie
        if method == "POST":
            h["content-type"] = "application/json"
            if origin:
                h["origin"] = self.origin if origin == "same" else origin
        c.request(method, path, json.dumps(body or {}) if method == "POST" else None, h)
        r = c.getresponse()
        data = r.read()
        c.close()
        try:
            j = json.loads(data)
        except ValueError:
            j = None
        return r.status, r, j, data

    def code(self, admin=False) -> str:
        db = store.connect(self.path)
        try:
            return pairing.new_code(db, admin=admin)["code"]
        finally:
            db.close()

    def pair(self, admin=False):
        code = self.code(admin)
        st, r, j, _ = self.req("POST", "/api/pair", {"code": code})
        self.assertEqual(st, 200, j)
        return r.getheader("set-cookie").split(";")[0], code

    def test_healthz_public_cheap_and_constant(self):
        self.phone()   # no session, another device, any Host: still answered
        for host in (None, "evil.example"):
            st, r, j, _ = self.req("GET", "/healthz", host=host)
            self.assertEqual((st, j), (200, {"status": "ok", "version": netwarden.__version__}))
            self.assertIsNone(r.getheader("set-cookie"))
            self.assertEqual(r.getheader("cache-control"), "no-store")
        with mock.patch.object(store, "connect", side_effect=AssertionError("no DB")):
            self.assertEqual(self.req("GET", "/healthz")[0], 200)
        held = [web.Handler.DATA_GATE.acquire() for _ in range(2)]   # every data slot busy
        try:
            self.assertEqual(self.req("GET", "/healthz")[0], 200)
        finally:
            for _ in held:
                web.Handler.DATA_GATE.release()

    def test_meta_reports_version_and_admin(self):
        st, _r, meta, _ = self.req("GET", "/api/meta")
        self.assertEqual((meta["version"], meta["admin"], meta["admin_session"], meta["remote"]),
                         (netwarden.__version__, True, False, False))

    def test_lan_clients_without_an_admin_session_get_403_on_every_admin_endpoint(self):
        cookie, _ = self.pair()
        self.phone()
        for path in web.ADMIN_POSTS:
            st, *_ = self.req("POST", path, {}, cookie=cookie)
            self.assertEqual(st, 403, path)
            self.assertEqual(self.req("POST", path, {})[0], 401, path)   # no session at all
        for path in web.ADMIN_GETS:
            self.assertEqual(self.req("GET", path, cookie=cookie)[0], 403, path)
        st, _r, meta, _ = self.req("GET", "/api/meta", cookie=cookie)
        self.assertEqual((meta["remote"], meta["admin"], meta["admin_session"]), (True, False, False))
        st, _r, dev, _ = self.req("GET", "/api/setup", cookie=cookie)
        self.assertFalse(dev["local"])

    def test_an_admin_session_may_do_admin_actions_and_is_listed_as_admin(self):
        self.phone()
        cookie, code = self.pair(admin=True)
        st, _r, meta, _ = self.req("GET", "/api/meta", cookie=cookie)
        self.assertEqual((meta["remote"], meta["admin"], meta["admin_session"]), (False, True, True))
        st, _r, sets, body1 = self.req("GET", "/api/settings", cookie=cookie)
        self.assertEqual(st, 200)
        st, _r, j, body2 = self.req("POST", "/api/settings", {"values": {"alerts.snooze_days": 9}},
                                    cookie=cookie)
        self.assertEqual(st, 200, j)
        st, _r, ses, body3 = self.req("GET", "/api/pair/sessions", cookie=cookie)
        self.assertEqual(st, 200)
        mine = [s for s in ses["sessions"] if s["current"]]
        self.assertTrue(mine and mine[0]["admin"])
        st, _r, newc, body4 = self.req("POST", "/api/pair/new", {}, cookie=cookie)
        self.assertEqual(st, 200)
        # the code this session was made from never shows up in an answer or the log
        for body in (body1, body2, body3, body4):
            self.assertNotIn(code.encode(), body)
        self.assertNotIn(code, self.log.getvalue())
        self.assertIn("ADMIN browser", self.log.getvalue())
        # an ordinary phone paired by the admin is NOT admin
        st, _r, j, _ = self.req("POST", "/api/pair", {"code": newc["code"]})
        self.assertEqual(st, 200)
        db = store.connect(self.path)
        try:
            rows = pairing.sessions(db)
        finally:
            db.close()
        self.assertEqual(sorted(s["admin"] for s in rows), [False, True])
        # revoked: the admin powers end at once
        sid = mine[0]["id"]
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))
        self.assertEqual(self.req("POST", "/api/pair/revoke", {"id": sid})[0], 200)
        self.phone()
        self.assertEqual(self.req("GET", "/api/settings", cookie=cookie)[0], 401)

    def test_wrong_and_used_admin_codes_are_rate_limited(self):
        self.phone()
        code = self.code(admin=True)
        self.assertEqual(self.req("POST", "/api/pair", {"code": code})[0], 200)
        self.assertEqual(self.req("POST", "/api/pair", {"code": code})[0], 400)    # used
        for _ in range(pairing.Limiter().max_fail - 1):   # the used code was miss no. 1
            self.assertEqual(self.req("POST", "/api/pair", {"code": "ABCDEFGHJK"})[0], 400)
        st, _r, j, _ = self.req("POST", "/api/pair", {"code": self.code(admin=True)})
        self.assertEqual(st, 429, j)   # 5 misses: locked out, even with a valid code

    def test_advertised_url_host_origin_and_proxy_rule(self):
        adv = "https://nas.example"
        web.Handler.lan, web.Handler.lan_url = True, adv
        web.Handler.proxy_hosts = web.advertised_hosts(adv)
        web.Handler.lan_hosts = web.Handler.proxy_hosts
        web.Handler.lan_origins = frozenset({adv})
        self.assertEqual(web.Handler.proxy_hosts, frozenset({"nas.example:443", "nas.example"}))
        # a reverse proxy on this machine: loopback client, advertised Host -> NOT local
        st, _r, j, _ = self.req("GET", "/api/meta", host="nas.example")
        self.assertEqual(st, 401, j)
        cookie, _ = self.pair()
        st, _r, meta, _ = self.req("GET", "/api/meta", cookie=cookie, host="nas.example")
        self.assertEqual((st, meta["remote"]), (200, True))
        self.assertEqual(self.req("GET", "/api/settings", cookie=cookie, host="nas.example")[0], 403)
        st, *_ = self.req("POST", "/api/label", {"mac": "x", "label": "y"}, cookie=cookie,
                          host="nas.example", origin="https://nas.example")
        self.assertNotIn(st, (403, 421))          # the https Origin is accepted
        st, *_ = self.req("POST", "/api/label", {}, cookie=cookie, host="nas.example",
                          origin="https://evil.example")
        self.assertEqual(st, 403)
        # a visitor can forge a loopback Host through that proxy: with a proxy in front,
        # loopback is never "this computer" by itself (review fix) - an admin session is
        for host in (None, f"localhost:{self.port}"):
            self.assertEqual(self.req("GET", "/api/settings", host=host)[0], 401, host)
        self.assertEqual(self.req("GET", "/api/settings", cookie=cookie)[0], 403)   # a phone
        admin, _ = self.pair(admin=True)
        st, _r, j, _ = self.req("POST", "/api/pair/new", {}, cookie=admin)
        self.assertEqual(st, 200, j)
        self.assertTrue(j["url"].startswith("https://nas.example/pair#"))


class AdvertisedSetting(unittest.TestCase):
    def test_validator(self):
        ok = {"http://192.168.1.20:8787": "http://192.168.1.20:8787",
              "HTTPS://NAS.Example:443/": "https://nas.example",
              "http://nas.local:80": "http://nas.local",
              "http://localhost:8787": "http://localhost:8787", "": ""}
        for raw, want in ok.items():
            self.assertEqual(settings.clean_advertised_url(raw), want, raw)
        for bad in ("ftp://x", "http://user:pw@x", "http://x/path", "http://x?a=1", "http://x#f",
                    "http://:80", "http://x:99999", "nas.example:8787"):
            with self.assertRaises(settings.SettingError, msg=bad):
                settings.clean_advertised_url(bad)
        s = settings.REGISTRY["lan.advertised_url"]
        self.assertEqual((s.env, s.admin, s.group), ("NETWARDEN_ADVERTISED_URL", True, "lan"))
        self.assertIn("NETWARDEN_ADVERTISED_URL", brain.ENV_KEYS)

    def test_make_server_uses_it_in_lan_mode_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "a.db")
            env = {brain.OFFLINE_ENV: "1", "NETWARDEN_ADVERTISED_URL": "http://192.168.1.20:8787"}
            srv = web.make_server(path, 0, env, "en")             # loopback only: ignored
            try:
                self.assertEqual((web.Handler.lan_url, web.Handler.proxy_hosts), ("", frozenset()))
            finally:
                web.close_server(srv)
            # LAN mode, faked on a loopback "LAN" address (never a real LAN bind)
            with mock.patch.object(web.pairing, "is_lan_ip", lambda ip: True):
                srv = web.make_server(path, 0, env, "en", lan=True, lan_host="127.0.0.2")
            try:
                self.assertEqual(web.Handler.lan_url, "http://192.168.1.20:8787")
                self.assertIn("192.168.1.20:8787", web.Handler.lan_hosts)
            finally:
                web.close_server(srv)
                web.Handler.lan, web.Handler.lan_url = False, ""
                web.Handler.lan_hosts = web.Handler.proxy_hosts = web.Handler.lan_origins = frozenset()


class PairCli(unittest.TestCase):
    def test_pair_admin_prints_an_admin_code_and_list_marks_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "p.db")
            out = io.StringIO()
            with mock.patch.object(brain, "load_env", return_value={}), \
                    mock.patch.object(cli, "_meta", return_value=None), \
                    contextlib.redirect_stdout(out):
                self.assertEqual(cli.cmd_pair(["--db", path, "--local", "--admin", "--lang", "en",
                                               "--port", "8799"]), 0)
            text = out.getvalue()
            self.assertIn("ADMIN code", text)
            self.assertIn("15 minutes", text)
            code = re.search(r"/pair#([A-Z2-9]{10})", text).group(1)
            db = store.connect(path)
            pairing.redeem(db, code, UA)
            db.close()
            out = io.StringIO()
            with mock.patch.object(brain, "load_env", return_value={}), contextlib.redirect_stdout(out):
                cli.cmd_pair(["--db", path, "--list", "--lang", "en"])
            self.assertIn("[Admin]", out.getvalue())

    def test_pair_uses_the_advertised_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "p.db")
            out = io.StringIO()
            env = {"NETWARDEN_ADVERTISED_URL": "http://192.168.1.20:8787"}
            with mock.patch.object(brain, "load_env", return_value=env), \
                    mock.patch.object(cli, "_meta", return_value=None), \
                    contextlib.redirect_stdout(out):
                self.assertEqual(cli.cmd_pair(["--db", path, "--lang", "en"]), 0)
            self.assertIn("http://192.168.1.20:8787/pair#", out.getvalue())


# --- 6. SIGTERM: a real process stops quickly and cleanly ---------------------------------

@unittest.skipUnless(hasattr(signal, "SIGTERM") and os.name == "posix", "POSIX signals")
class Sigterm(unittest.TestCase):
    def test_run_stops_on_sigterm(self):
        with tempfile.TemporaryDirectory() as tmp:
            port = _free_port()
            env = {**os.environ, "NETWARDEN_HEADLESS": "1", "NETWARDEN_PORT": str(port),
                   "NETWARDEN_HOST": "127.0.0.1", "NETWARDEN_DB": str(Path(tmp) / "n.db"),
                   "PYTHONUNBUFFERED": "1", "NETWARDEN_LAN": "0"}
            env.pop("NETWARDEN_REQUIRE_AUTH", None)
            p = subprocess.Popen([sys.executable, "-m", "netwarden", "run", "--no-loops",
                                  "--offline-ai", "--lang", "en"], cwd=str(ROOT), env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 30
                while True:
                    try:
                        c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                        c.request("GET", "/healthz")
                        if c.getresponse().status == 200:
                            break
                    except OSError:
                        pass
                    self.assertIsNone(p.poll(), p.stderr.read() if p.poll() is not None else "")
                    self.assertLess(time.monotonic(), deadline, "never became healthy")
                    time.sleep(0.2)
                t = time.monotonic()
                p.send_signal(signal.SIGTERM)
                out, err = p.communicate(timeout=10)
                self.assertLess(time.monotonic() - t, 5)
                self.assertEqual(p.returncode, 0, err)
                self.assertNotIn(b"Traceback", err)
                self.assertIn(b"standard error", out)
                self.assertIn(b"netwarden stopped", err)    # the log line, on stderr
                self.assertFalse((Path(tmp) / "netwarden.log").exists())
            finally:
                if p.poll() is None:
                    p.kill()
                    p.communicate()


# --- 7. container + CI + installer files (Docker can't run here: check the text) ------------

class ContainerFiles(unittest.TestCase):
    def test_dockerfile(self):
        text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        self.assertTrue(re.match(r"FROM python:3\.\d+-slim", lines[0]), lines[0])
        users = [ln for ln in lines if ln.startswith("USER ")]
        self.assertEqual(users, ["USER netwarden"])
        self.assertLess(text.index("USER netwarden"), text.index("ENTRYPOINT"))
        self.assertIn("HEALTHCHECK", text)
        self.assertIn("/healthz", text)
        self.assertIn("EXPOSE 8787", text)
        self.assertIn('VOLUME ["/data"]', text)
        self.assertIn("NETWARDEN_DB=/data/netwarden.db", text)
        self.assertIn("NETWARDEN_HEADLESS=1", text)
        for pkg in ("iproute2", "iputils-ping", "tzdata"):
            self.assertIn(pkg, text)
        for tool in ("gcc", "build-essential", "curl ", "sudo"):
            self.assertNotIn(tool, text)
        for label in ("title", "source", "version", "licenses"):
            self.assertIn(f"org.opencontainers.image.{label}", text)
        self.assertIn("--no-install-recommends", text)

    def test_dockerignore_keeps_secrets_and_data_out(self):
        pats = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
        for p in (".env", "data/", "*.db", "launch/", "netwarden-backup-*.json", ".git/",
                  "**/__pycache__/"):
            self.assertIn(p, pats)
        self.assertIn("launch/", (ROOT / ".gitignore").read_text(encoding="utf-8").split())

    def test_workflow(self):
        text = (ROOT / ".github" / "workflows" / "docker.yml").read_text(encoding="utf-8")
        code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        self.assertNotIn("pull_request_target", code)
        self.assertIn("pull_request:", text)
        self.assertRegex(text, r"(?m)^permissions:\n  contents: read")
        # pushing happens in exactly one job, and only for v* tags
        jobs = re.split(r"(?m)^  (?=\w[\w-]*:\n)", text.split("\njobs:\n", 1)[1])
        pushing = [j for j in jobs if "push: true" in j]
        self.assertEqual(len(pushing), 1)
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", pushing[0])
        self.assertIn("packages: write", pushing[0])
        self.assertEqual(text.count("packages: write"), 1)
        self.assertIn("linux/arm64", pushing[0])
        self.assertIn("GITHUB_REPOSITORY,,", pushing[0])                # lower-cased, no owner
        self.assertNotIn("OWNER", text)
        smoke = next(j for j in jobs if j.startswith("smoke:"))
        self.assertIn("push: false", smoke)
        self.assertNotIn("secrets.", smoke)
        for step in ("/healthz", "/api/meta", "pair --admin", "id -u", "docker stop", "--offline-ai"):
            self.assertIn(step, smoke)
        for ref in re.findall(r"uses: ([\w./-]+)@(\S+)", text):
            self.assertRegex(ref[1], r"^v\d+$", ref)                     # major-version pins

    def test_compose_examples(self):
        for name in ("compose.yaml", "compose.adguard.yaml", "compose.bridge.yaml"):
            text = (ROOT / "deploy" / name).read_text(encoding="utf-8")
            for key in ("restart: unless-stopped", "init: true", "/data", "healthcheck:", "/healthz"):
                self.assertIn(key, text, name)
            self.assertNotRegex(text, r"(?i)(ADGUARD_PASS|PIHOLE_PASSWORD|API_KEY)\s*:\s*\S", name)
        self.assertIn("adguard/adguardhome", (ROOT / "deploy" / "compose.adguard.yaml").read_text())
        self.assertIn("network_mode: host", (ROOT / "deploy" / "compose.yaml").read_text())

    def test_text_files_use_lf(self):
        for rel in ("Dockerfile", ".dockerignore", "scripts/install_linux.sh",
                    ".github/workflows/docker.yml", "deploy/compose.yaml"):
            self.assertNotIn(b"\r", (ROOT / rel).read_bytes(), rel)


@unittest.skipUnless(shutil.which("sh") and os.name == "posix", "needs a POSIX shell")
class LinuxInstaller(unittest.TestCase):
    SCRIPT = str(ROOT / "scripts" / "install_linux.sh")

    def sh(self, *args, check=True):
        p = subprocess.run(["sh", self.SCRIPT, *args], capture_output=True, text=True, timeout=60)
        if check:
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return p

    def test_dry_run_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            out = self.sh("--dry-run", "--root", str(root)).stdout
            self.assertFalse(root.exists())
            for action in ("mkdir -p", "/opt/netwarden/app", "netwarden.service", "/usr/local/bin/netwarden"):
                self.assertIn(action, out)
            out = self.sh("--dry-run", "--uninstall", "--purge", "--root", str(root)).stdout
            self.assertIn("rm -rf", out)

    def test_install_upgrade_uninstall_purge_in_a_fake_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.sh("--root", tmp)
            app = root / "opt/netwarden/app/netwarden"
            self.assertTrue((app / "__main__.py").is_file())
            self.assertFalse(list(app.rglob("__pycache__")))
            unit = (root / "etc/systemd/system/netwarden.service").read_text()
            for key in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
                        "PrivateTmp=yes", "ReadWritePaths=/var/lib/netwarden",
                        "Restart=on-failure", "User=netwarden", "CapabilityBoundingSet=",
                        "NETWARDEN_HEADLESS=1", "EnvironmentFile=-/etc/netwarden/netwarden.env"):
                self.assertIn(key, unit)
            self.assertNotIn("`", unit)   # no stray command substitution in the heredoc
            self.assertNotIn("$", unit)
            env_file = root / "etc/netwarden/netwarden.env"
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o640)
            env_file.write_text("NETWARDEN_LANG=en\n")
            wrapper = root / "usr/local/bin/netwarden"
            self.assertTrue(os.access(wrapper, os.X_OK))
            data = root / "var/lib/netwarden"
            (data / "netwarden.db").write_text("keep me")
            self.sh("--root", tmp)                                   # upgrade
            self.assertEqual(env_file.read_text(), "NETWARDEN_LANG=en\n")   # settings kept
            self.sh("--uninstall", "--root", tmp)
            self.assertFalse((root / "opt/netwarden").exists())
            self.assertFalse(wrapper.exists())
            self.assertEqual((data / "netwarden.db").read_text(), "keep me")  # data kept
            self.sh("--uninstall", "--purge", "--root", tmp)
            self.assertFalse(data.exists())
            self.assertFalse(env_file.exists())

    def test_bad_options_and_root_check(self):
        self.assertEqual(self.sh("--purge", check=False).returncode, 2)
        self.assertEqual(self.sh("--nope", check=False).returncode, 2)
        self.assertEqual(self.sh("--root", "relative/dir", check=False).returncode, 2)
        if os.geteuid() != 0:   # never actually install on the machine running the tests
            p = self.sh(check=False)
            self.assertEqual(p.returncode, 1)
            self.assertIn("root", p.stderr)


if __name__ == "__main__":
    unittest.main()
