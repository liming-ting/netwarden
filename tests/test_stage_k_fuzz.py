"""
Stage K: input fuzzing of the dashboard API. Every POST endpoint and every GET that
takes parameters gets random and adversarial input (wrong types, missing / extra
fields, huge strings, deep nesting, invalid UTF-8, NaN / Infinity, huge numbers, odd
dates, path tricks), plus raw protocol abuse (bad request lines, unknown methods,
oversized URLs and headers). The contract:

  * never a 5xx and never a traceback in a response;
  * a 4xx always carries a localized JSON {"error": ...};
  * a rejected POST changes nothing in the user's data.

Runs on a private copy of the demo home with the offline AI; a socket guard fails the
test if anything tries to reach a non-loopback address. Deterministic seeds
(tests/fuzzkit.py); NETWARDEN_FUZZ=heavy for a long run.
"""
import hashlib
import http.client
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import quote

import fuzzkit
from netwarden import brain, demo, i18n, store, web

# The user's own data: a rejected request must leave all of it exactly as it was.
USER_TABLES = ("device_labels", "device_profiles", "acks", "people", "bedtime_rules",
               "settings", "suggestion_state", "sessions", "quiet_summaries")

_DEMO = {}


def demo_db(dest: Path) -> Path:
    """A copy of one demo DB built once per run (sqlite backup: WAL-safe)."""
    import sqlite3
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


class _Guard:
    """Refuse (and remember) any connection to a non-loopback address."""
    def __init__(self):
        self.blocked = []
        self._real = socket.socket.connect

    def connect(self, sock, addr):
        host = addr[0] if isinstance(addr, tuple) else str(addr)
        if not (host.startswith("127.") or host in ("localhost", "::1")):
            self.blocked.append(host)
            raise OSError("netwarden test: non-loopback connection refused")
        return self._real(sock, addr)


class _Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = demo_db(Path(cls.tmp.name) / "fuzz.db")
        cls.guard = _Guard()
        cls.patch = mock.patch.object(socket.socket, "connect",
                                      lambda s, a: cls.guard.connect(s, a))
        cls.patch.start()
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]
        db = store.connect(cls.path)
        cls.mac = db.execute("SELECT mac FROM devices ORDER BY mac LIMIT 1").fetchone()["mac"]
        p = db.execute("SELECT id FROM people ORDER BY id LIMIT 1").fetchone()
        cls.person = p["id"] if p else 1
        r = db.execute("SELECT id FROM bedtime_rules ORDER BY id LIMIT 1").fetchone()
        cls.rule = r["id"] if r else 1
        db.close()
        cls.errors = set(i18n.t("err." + k, lang) for lang in ("en", "zh-Hant")
                         for k in ("bad_json",))

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        web.close_server(cls.srv)
        cls.patch.stop()
        cls.tmp.cleanup()

    def tearDown(self):
        self.assertEqual(self.guard.blocked, [], "something tried to reach the network")

    # -- helpers -------------------------------------------------------------------------

    def state(self) -> str:
        db = store.connect(self.path)
        try:
            h = hashlib.sha256()
            for t in USER_TABLES:
                for row in db.execute(f"SELECT * FROM {t} ORDER BY 1"):   # fixed names
                    h.update(repr(tuple(row)).encode("utf-8", "surrogatepass"))
            return h.hexdigest()
        finally:
            db.close()

    def send(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            c.putrequest(method, path, skip_accept_encoding=True)
            hdrs = {"host": f"127.0.0.1:{self.port}", **(headers or {})}
            if body is not None:
                hdrs.setdefault("content-type", "application/json")
                hdrs.setdefault("content-length", str(len(body)))
            for k, v in hdrs.items():
                c.putheader(k, v)
            c.endheaders(body)
            r = c.getresponse()
            return r.status, r.read(), r.getheader("content-type") or ""
        finally:
            c.close()

    def check(self, status, raw, ctype, what):
        self.assertLess(status, 500, f"{what} -> {status}: {raw[:300]!r}")
        self.assertNotIn(b"Traceback", raw, what)
        self.assertNotIn(b'File "/', raw, what)
        if status >= 400:
            self.assertIn("application/json", ctype, what)
            err = json.loads(raw)["error"]
            self.assertIsInstance(err, str, what)
            self.assertTrue(err.strip(), what)


def body_of(payload) -> bytes:
    """JSON with NaN / Infinity and lone surrogates kept (json.dumps escapes them)."""
    return json.dumps(payload, allow_nan=True).encode("ascii")


class PostFuzz(_Server):
    def samples(self) -> dict:
        m, pid, rid = self.mac, self.person, self.rule
        return {
            "/api/ack": {"mac": m, "domain": "tracker.example"},
            "/api/unack": {"mac": m, "domain": "tracker.example"},
            "/api/label": {"mac": m, "label": "Living room TV", "note": "n"},
            "/api/profile": {"mac": m, "type": "tv", "owner": "Mom", "room": "Living", "shared": False},
            "/api/people": {"name": "Grandma", "avatar": "G", "color": "blue", "child": False, "note": ""},
            "/api/people/delete": {"id": pid},
            "/api/people/restore": {"restore": "x"},
            "/api/people/assign": {"person": pid, "mac": m},
            "/api/presence/settings": {"id": pid, "enabled": False, "notify_arrive": True},
            "/api/presence/forget": {"id": pid},
            "/api/presence/link": {"person": pid, "mac": m},
            "/api/presence/unlink": {"person": pid, "mac": m},
            "/api/bedtime": {"rule": {"name": "School nights", "owner": "Kid", "days": [6, 0, 1],
                                      "start": "22:00", "end": "07:00", "min_minutes": 10}},
            "/api/bedtime/delete": {"id": rid},
            "/api/bedtime/preview": {"rule": {"mac": m, "days": [0], "start": "21:00", "end": "06:00"}},
            "/api/suggestions/some-id": {"status": "snoozed", "days": 7},
            "/api/settings": {"values": {"alerts.snooze_days": 5}},
            "/api/chat/preview": {"mode": "chat", "messages": [{"role": "user", "content": "hi"}]},
            "/api/chat/stream": {"messages": [{"role": "user", "content": "what is new?"}], "mac": m},
            "/api/chat": {"messages": [{"role": "user", "content": "hi"}]},
            "/api/ask": {"question": "what is new?"},
            "/api/insight": {},
            "/api/ai/test": {},
            "/api/tuning": {"kind": "new_device", "level": "less", "mac": m},
            "/api/tuning/undo": {"undo": "x"},
            "/api/tuning/restore": {"kind": "night", "confirm": True},
            "/api/tuning/restore_undo": {"undo": "x"},
            "/api/notify/seen": {"id": 1},
            "/api/inbox/act": {"action": "ack", "items": [{"kind": "spike", "mac": m, "key": "x"}]},
            "/api/backup/preview": {"backup": {"format": "netwarden-backup", "version": 1}, "mode": "merge"},
            "/api/restore": {"backup": {"format": "netwarden-backup", "version": 1}, "mode": "merge"},
            "/api/setup": {"step": "welcome", "done": True},
            "/api/setup/scan": {},
            "/api/check": {"mac": m},
            "/api/test/adguard": {},
            "/api/pair": {"code": "123456"},
            "/api/pair/new": {},
            "/api/pair/revoke": {"id": 1},
            "/api/session/logout": {},
            "/api/nonexistent": {"x": 1},
        }

    def test_every_post_endpoint(self):
        for path, sample in self.samples().items():
            r = fuzzkit.rng("post" + path)
            with self.subTest(path=path):
                for i in range(fuzzkit.cases(25)):
                    payload = fuzzkit.payload(r, sample)
                    payload.setdefault("lang", r.choice(("en", "zh-Hant", "xx", 5)))
                    before = self.state()
                    status, raw, ctype = self.send("POST", path, body_of(payload))
                    what = f"POST {path} #{i} {payload!r:.300}"
                    self.check(status, raw, ctype, what)
                    if status >= 400:
                        self.assertEqual(self.state(), before, "rejected but changed: " + what)

    def test_samples_are_accepted(self):
        """The fuzz seeds are real requests: unmutated, the plain ones succeed (so the
        fuzzer explores past the validators instead of bouncing off a typo)."""
        s = self.samples()
        for path in ("/api/label", "/api/ack", "/api/unack", "/api/profile", "/api/chat/preview",
                     "/api/settings", "/api/bedtime/preview", "/api/ask"):
            status, raw, _ct = self.send("POST", path, body_of(s[path]))
            self.assertEqual(status, 200, f"{path}: {raw[:200]!r}")

    def test_bodies_that_are_not_objects(self):
        bad = [b"", b"null", b"[]", b"1", b'"x"', b"NaN", b"{", b"\xff\xfe\x00{}",
               b'{"mac": "\xc3\x28"}', b'{"a": 1, "a": 2}', b"\x00" * 50,
               fuzzkit.deep(100000).encode(), fuzzkit.deep(100000, "dict").encode(),
               b'{"label": "' + b"a" * (900 * 1024) + b'"}']
        for path in ("/api/label", "/api/people", "/api/settings", "/api/inbox/act", "/api/restore"):
            for body in bad:
                before = self.state()
                status, raw, ctype = self.send("POST", path, body)
                self.check(status, raw, ctype, f"{path} {body[:30]!r}")
                self.assertGreaterEqual(status, 400)
                self.assertEqual(self.state(), before)

    def test_framing_and_headers(self):
        p = "/api/label"
        cases = [
            ({"content-type": "text/plain"}, b"{}", 415),
            ({"content-type": "application/json; charset=latin-1"}, b"{}", None),
            ({"content-type": "APPLICATION/JSON"}, b"{}", None),
        ]
        for headers, body, want in cases:
            status, raw, ctype = self.send("POST", p, body, headers)
            self.check(status, raw, ctype, str(headers))
            if want:
                self.assertEqual(status, want)
        for length in ("-1", "abc", "１２", "1e3", " ", "99999999999999999999"):
            status, raw, ctype = self.raw(b"POST /api/label HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                                          b"Content-Type: application/json\r\nContent-Length: "
                                          % self.port + length.encode() + b"\r\n\r\n{}")
            self.check(status, raw, ctype, "length " + length)
            self.assertIn(status, (400, 413))
        status, raw, ctype = self.send("POST", p, b"{}", {"content-length": str(web.MAX_BODY + 1)})
        self.assertEqual(status, 413)

    def raw(self, data: bytes):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=30)
        try:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)
            buf = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        finally:
            s.close()
        if not buf.startswith(b"HTTP/"):   # an HTTP/0.9 answer: the body alone
            return 0, buf, "application/json" if buf.startswith(b"{") else ""
        head, _sep, body = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = int(lines[0].split()[1])
        ctype = next((ln.split(b":", 1)[1].strip().decode() for ln in lines[1:]
                      if ln.lower().startswith(b"content-type:")), "")
        return status, body, ctype


class GetFuzz(_Server):
    def params(self) -> dict:
        m = self.mac
        return {
            "/api/device": {"mac": m},
            "/api/activity": {"mac": m, "days": "7"},
            "/api/timeline": {"mac": m, "hours": "24", "before": "2026-10-22T10:00:00.000000Z"},
            "/api/search": {"q": "tiktok"},
            "/api/service": {"id": "youtube"},
            "/api/domain": {"d": "example.com"},
            "/api/person": {"id": str(self.person)},
            "/api/screentime": {"days": "7", "mac": m, "owner": "Kid"},
            "/api/weekly": {"offset": "0"},
            "/api/bedtime": {"days": "7"},
            "/report/weekly": {"lang": "zh-Hant"},
            "/api/since": {"t": "2026-10-20T10:00:00.000000Z"},
            "/api/ai/questions": {"mac": m},
            "/api/check/status": {"job": "abc"},
            "/api/setup/scan/status": {"job": "abc"},
            "/api/meta": {"accept": "zh-TW,zh;q=0.9"},
            "/api/locale": {"lang": "ja"},
            "/api/health": {"days": "7"},
            "/api/suggestions": {"lang": "de"},
            "/api/inbox": {"lang": "fr"},
            "/api/overview": {"lang": "ko"},
            "/api/export/devices.csv": {"lang": "ru"},
            "/api/export/report.md": {"lang": "hi"},
            "/pair": {"lang": "id", "expired": "1"},
            "/static/app.css": {"v": "x"},
        }

    def query(self, r, sample: dict) -> str:
        q = fuzzkit.mutate(r, sample) if r.random() < 0.8 else {}
        parts = []
        for k, v in q.items():
            v = v if isinstance(v, str) else json.dumps(v, allow_nan=True)
            parts.append(quote(str(k), safe="", errors="surrogatepass") + "="
                         + quote(v, safe="", errors="surrogatepass"))
        if r.random() < 0.2:   # repeated keys, bare keys, stray separators, raw bytes
            parts += ["mac", "lang=", "&&", "%ff%fe", "a=%00", "days=1&days=2"]
        return "&".join(parts)

    def test_every_get_with_parameters(self):
        for path, sample in self.params().items():
            r = fuzzkit.rng("get" + path)
            with self.subTest(path=path):
                for i in range(fuzzkit.cases(20)):
                    q = self.query(r, sample)
                    status, raw, ctype = self.send("GET", f"{path}?{q}")
                    self.check(status, raw, ctype, f"GET {path}?{q[:200]}")

    def test_path_tricks(self):
        for path in ("/static/../netwarden/web.py", "/static/..%2f..%2fweb.py", "/static/%2e%2e/web.py",
                     "/static/.env", "/static/app.css%00.png", "/static//etc/passwd",
                     "/static/C:%5cWindows%5cwin.ini", "/static/" + "a" * 5000, "//api/meta",
                     "/api/meta/../settings", "/api//device?mac=x", "/%ff", "/api/%00",
                     "/static/app.css/", "/static/", "/static", "/report/weekly/..",
                     "http://evil.example/api/meta", "*"):
            status, raw, ctype = self.send("GET", path)
            self.check(status, raw, ctype, path)
            self.assertNotIn(b"import ", raw)          # never a source file
            self.assertNotIn(b"ANTHROPIC", raw)

    def test_protocol_abuse(self):
        p = PostFuzz.raw
        host = b"Host: 127.0.0.1:%d\r\n" % self.port
        cases = {
            "garbage": (b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 40, None),
            "no version": (b"GET /api/meta\r\n\r\n", None),
            "http2": (b"GET /api/meta HTTP/2.0\r\n" + host + b"\r\n", 400),
            "bad version": (b"GET /api/meta HTTP/x.y\r\n" + host + b"\r\n", 400),
            "put": (b"PUT /api/label HTTP/1.1\r\n" + host + b"Content-Length: 0\r\n\r\n", 405),
            "delete": (b"DELETE /api/people HTTP/1.1\r\n" + host + b"\r\n", 405),
            "patch": (b"PATCH /api/settings HTTP/1.1\r\n" + host + b"\r\n", 405),
            "options": (b"OPTIONS * HTTP/1.1\r\n" + host + b"\r\n", 405),
            "trace": (b"TRACE / HTTP/1.1\r\n" + host + b"\r\n", 405),
            "head": (b"HEAD /api/meta HTTP/1.1\r\n" + host + b"\r\n", 405),
            "weird method": (b"F\x00O /api/meta HTTP/1.1\r\n" + host + b"\r\n", None),
            "long url": (b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n" + host + b"\r\n", 414),
            "many headers": (b"GET /api/meta HTTP/1.1\r\n" + host
                             + b"".join(b"X-%d: y\r\n" % i for i in range(150)) + b"\r\n", 431),
            "long header": (b"GET /api/meta HTTP/1.1\r\n" + host + b"X: " + b"y" * 70000
                            + b"\r\n\r\n", 431),
            "bad host": (b"GET /api/meta HTTP/1.1\r\nHost: evil.example\r\n\r\n", 421),
            "no host": (b"GET /api/meta HTTP/1.1\r\n\r\n", 421),
            "utf8 path": ("GET /api/device?mac=名字 HTTP/1.1\r\n".encode() + host + b"\r\n", None),
        }
        for name, (data, want) in cases.items():
            status, raw, ctype = p(self, data)
            with self.subTest(name=name):
                self.assertLess(status, 500, name)
                self.assertNotIn(b"Traceback", raw)
                if status >= 400 and raw:
                    self.assertIn("application/json", ctype, name)
                    self.assertTrue(json.loads(raw)["error"])
                if want:
                    self.assertEqual(status, want, name)

    def test_localized_protocol_errors(self):
        status, raw, _ct = PostFuzz.raw(self, b"PUT /api/label HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                                        % self.port)
        self.assertEqual(status, 405)
        # the server's default language (this server: en); every language has the key
        self.assertEqual(json.loads(raw)["error"], i18n.t("err.bad_method", "en"))
        for lang in i18n.CODES:
            self.assertNotEqual(i18n.t("err.bad_method", lang), "err.bad_method")


if __name__ == "__main__":
    unittest.main()
