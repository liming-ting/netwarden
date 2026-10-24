"""
Round 9 V - integration audit (docs/dev/integrations.md): Pi-hole v6 (and the v5 / v6
mix-ups), AdGuard Home, ntopng and the Home Assistant add-on options, each against a
fake server on an ephemeral 127.0.0.1 port that answers the way the CURRENT upstream
API reference / source says it does:

  Pi-hole    FTL src/api/docs/content/specs (auth.yaml, queries.yaml), src/api/queries.c
  AdGuard    openapi/openapi.yaml + internal/home/authhttp.go + the dev v0.107.79 instance
  ntopng     api_v2.html, examples_v2.html, src/HTTPserver.cpp

    python3 -m unittest tests.test_round9_v -v
"""
from __future__ import annotations

import base64
import json
import ssl
import threading
import unittest
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from netwarden import (addon, conntest, discovery, dns_ingest, health, i18n, store,
                       traffic_ingest)

T0 = datetime(2026, 10, 21, 0, 0, 0, tzinfo=timezone.utc).timestamp()
PHONE = ("192.168.1.12", "aa:bb:cc:00:00:12")
APP_PW = "Ap9PassWordFromPiHoleUI0="
WEB_PW = "web-secret"
V5_TOKEN = "a" * 64


def _ts(secs: float) -> str:
    return datetime.fromtimestamp(T0 + secs, timezone.utc).strftime(dns_ingest.TS_FMT)


class _Server:
    """A ThreadingHTTPServer on 127.0.0.1:0 whose handler calls `self.handle(h, method)`."""

    def __init__(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802
                fake.handle(self, "GET")

            def do_POST(self):  # noqa: N802
                fake.handle(self, "POST")

            def do_DELETE(self):  # noqa: N802
                fake.handle(self, "DELETE")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @staticmethod
    def send(h, code, body=None, ctype="application/json", headers=()):
        raw = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else b"")
        h.send_response(code)
        h.send_header("Content-Type", ctype)
        h.send_header("Content-Length", str(len(raw)))
        for k, v in headers:
            h.send_header(k, v)
        h.end_headers()
        h.wfile.write(raw)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# --- Pi-hole v6 ----------------------------------------------------------------------

def pq(qid, secs, domain="a.example", ip=PHONE[0], name=None, status="FORWARDED"):
    """One /api/queries row exactly as queries.yaml describes it."""
    return {"id": qid, "time": T0 + secs, "type": "A", "domain": domain, "cname": None,
            "status": status, "client": {"ip": ip, "name": name}, "dnssec": "UNKNOWN",
            "reply": {"type": "IP", "time": 0.003}, "list_id": None,
            "upstream": "1.1.1.1#53", "ede": {"code": -1, "text": None}}


class FakeFTL(_Server):
    """Pi-hole v6 FTL's /api per the spec: sessions (seats, 2FA, rate limiting, app
    password), the sessions list, /api/queries (memory + disk, cursor, start, from,
    privacy levels) - or, with v5=True, a Pi-hole v5 (only /admin/api.php)."""

    def __init__(self, v5=False):
        self.v5 = v5
        self.password, self.app_password = WEB_PW, APP_PW
        self.totp = False              # 2FA on: the web password alone is not enough
        self.mode_429 = None           # "rate_limiting" | "api_seats_exceeded"
        self.max_sessions = 16
        self.sessions = {}             # sid -> {id, user_agent, last_active}
        self.foreign = []              # sessions of other clients / old runs (no sid known)
        self.next_id = 0
        self.clock = 10_000            # Pi-hole's own clock (seconds)
        self.queries, self.disk_queries = [], []
        self.earliest = 0.0            # earliest_timestamp of the in-memory log
        self.privacy = 0
        self.calls = []                # (method, path, params, headers)
        super().__init__()

    def _sid(self, h):
        return h.headers.get("X-FTL-SID")

    def handle(self, h, method):
        url = urllib.parse.urlparse(h.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
        self.calls.append((method, url.path, q, dict(h.headers)))
        if self.v5:
            if url.path == "/admin/api.php":
                return self.send(h, 200, {"core_update": False, "core_current": "v5.18.3",
                                          "web_current": "v5.21", "FTL_current": "v5.25.2"})
            return self.send(h, 404, b"<html>404 Not Found</html>", "text/html")
        if url.path == "/api/auth" and method == "POST":
            return self._login(h)
        if url.path == "/api/auth" and method == "DELETE":
            if self.sessions.pop(self._sid(h), None):
                return self.send(h, 204)
            return self.send(h, 401, {"session": {"valid": False, "sid": None}})
        if self._sid(h) not in self.sessions:
            return self.send(h, 401, {"session": {"valid": False, "sid": None},
                                      "error": {"key": "unauthorized", "message": "Unauthorized"}})
        self.sessions[self._sid(h)]["last_active"] = self.clock
        if url.path == "/api/auth/sessions":
            rows = [{"id": s["id"], "current_session": sid == self._sid(h), "valid": True,
                     "user_agent": s["user_agent"], "last_active": s["last_active"], "app": True}
                    for sid, s in self.sessions.items()] + \
                   [{**s, "current_session": False, "valid": True} for s in self.foreign]
            return self.send(h, 200, {"sessions": rows, "took": 0.0})
        if url.path.startswith("/api/auth/session/") and method == "DELETE":
            sid_id = int(url.path.rsplit("/", 1)[1])
            before = len(self.foreign) + len(self.sessions)
            self.foreign = [s for s in self.foreign if s["id"] != sid_id]
            self.sessions = {k: s for k, s in self.sessions.items() if s["id"] != sid_id}
            return self.send(h, 204 if len(self.foreign) + len(self.sessions) < before else 404)
        if url.path == "/api/info/version":
            return self.send(h, 200, {"version": {"core": {"local": {"version": "v6.3"}}}})
        if url.path == "/api/queries":
            return self._queries(h, q)
        self.send(h, 404, {"error": {"key": "not_found", "message": "Not found"}})

    def _login(self, h):
        body = json.loads(h.rfile.read(int(h.headers.get("Content-Length") or 0)) or b"{}")
        if self.mode_429:
            msg = {"rate_limiting": "Rate-limiting login attempts",
                   "api_seats_exceeded": "API seats exceeded"}[self.mode_429]
            return self.send(h, 429, {"error": {"key": self.mode_429, "message": msg, "hint": None}})
        pw = body.get("password")
        if pw == self.password and self.totp:
            return self.send(h, 400, {"error": {"key": "bad_request",
                                                "message": "No 2FA token found in JSON payload"}})
        if pw not in (self.password, self.app_password):
            return self.send(h, 401, {"session": {"valid": False, "totp": self.totp, "sid": None,
                                                  "validity": -1, "message": "password incorrect"}})
        if len(self.sessions) + len(self.foreign) >= self.max_sessions:
            return self.send(h, 429, {"error": {"key": "api_seats_exceeded",
                                                "message": "API seats exceeded"}})
        self.next_id += 1
        sid = f"S{self.next_id}x"
        self.sessions[sid] = {"id": 100 + self.next_id, "user_agent": h.headers.get("User-Agent"),
                              "last_active": self.clock}
        self.send(h, 200, {"session": {"valid": True, "totp": self.totp, "sid": sid, "csrf": "c",
                                       "validity": 1800, "message": "app-password correct"}})

    def _queries(self, h, q):
        if self.privacy >= 3:
            return self.send(h, 200, {"queries": [], "cursor": None, "recordsTotal": 0,
                                      "recordsFiltered": 0, "earliest_timestamp": 0.0,
                                      "earliest_timestamp_disk": 0.0, "took": 0.0})
        src = self.disk_queries if q.get("disk") == "true" else self.queries
        rows = sorted(src, key=lambda r: -r["id"])
        newest = rows[0]["id"] if rows else 0
        cursor = int(q["cursor"]) if "cursor" in q else newest
        rows = [r for r in rows if r["id"] <= cursor]
        if "from" in q:
            rows = [r for r in rows if r["time"] >= float(q["from"])]
        if self.privacy >= 1:
            rows = [{**r, "domain": "hidden"} for r in rows]
        start, length = int(q.get("start", 0)), int(q.get("length", 100))
        self.send(h, 200, {"queries": rows[start:start + length], "cursor": cursor,
                           "recordsTotal": len(src), "recordsFiltered": len(rows),
                           "earliest_timestamp": self.earliest, "earliest_timestamp_disk": 0.0,
                           "draw": 0, "took": 0.0})

    def paths(self, path):
        return [c for c in self.calls if c[1] == path]


class _DBMixin:
    def make_db(self):
        db = store.connect(":memory:")
        store.upsert_device(db, discovery.device_record(*PHONE, {}, hostname=""))
        for p in (mock.patch.object(discovery, "read_arp", lambda: {}),
                  mock.patch.object(discovery, "load_manuf", lambda: {}),
                  mock.patch.object(discovery, "hostname_for", lambda ip: ""),
                  mock.patch.object(discovery, "default_iface_net_ip", lambda: (None, None, None)),
                  mock.patch.object(dns_ingest, "local_addresses", lambda: {"127.0.0.1", "::1"})):
            p.start()
            self.addCleanup(p.stop)
        return db


class PiHoleAuthTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeFTL()
        self.addCleanup(self.fake.close)

    def src(self, pw=APP_PW, url=None, **kw):
        s = dns_ingest.PiHole(url or self.fake.url, pw, timeout=5, **kw)
        self.addCleanup(s.close)
        return s

    def kind_of(self, fn):
        with self.assertRaises(dns_ingest.PiHoleError) as cm:
            fn()
        e = cm.exception
        for secret in (WEB_PW, APP_PW, V5_TOKEN):
            self.assertNotIn(secret, str(e))
        # the stored (sanitized) text maps to the same plain-language kind
        self.assertEqual(health.error_kind(health.sanitize_error(e)), e.kind, str(e))
        self.assertEqual(conntest._kind(e), e.kind)
        return e.kind

    def test_web_interface_address_is_accepted(self):
        for u in ("/admin", "/admin/", "/api", "/"):
            self.assertEqual(dns_ingest.pihole_base_url(self.fake.url + u), self.fake.url)
        self.assertEqual(list(self.src(url=self.fake.url + "/admin/").events(None)), [])

    def test_user_agent_identifies_netwarden(self):
        list(self.src().events(None))
        ua = {c[3].get("User-Agent") for c in self.fake.calls}
        self.assertEqual(ua, {health.USER_AGENT})
        self.assertTrue(health.USER_AGENT.startswith("netwarden/"))

    def test_app_password_works_with_2fa_and_web_password_says_so(self):
        self.fake.totp = True
        self.assertEqual(len(list(self.src(APP_PW).events(None))), 0)
        self.assertEqual(self.kind_of(lambda: self.src(WEB_PW).login()), "totp")

    def test_wrong_password_and_v5_token(self):
        self.assertEqual(self.kind_of(lambda: self.src("nope").login()), "auth")
        self.assertEqual(self.kind_of(lambda: self.src(V5_TOKEN).login()), "token_v5")

    def test_429_rate_limiting_vs_seats(self):
        self.fake.mode_429 = "rate_limiting"
        self.assertEqual(self.kind_of(lambda: self.src().login()), "rate_limited")
        self.fake.mode_429 = "api_seats_exceeded"
        self.assertEqual(self.kind_of(lambda: self.src().login()), "seats")
        # the legacy wording ("no free API session") still maps to seats
        self.assertEqual(health.error_kind("PiHoleError: Pi-hole has no free API session (HTTP 429)"),
                         "seats")

    def test_v5_server_and_no_pihole_at_all(self):
        v5 = FakeFTL(v5=True)
        self.addCleanup(v5.close)
        for pw in (V5_TOKEN, ""):   # with a password (login) and without (straight GET)
            s = self.src(pw, url=v5.url)
            with self.assertRaises(dns_ingest.PiHoleError) as cm:
                list(s.events(None))
            self.assertEqual(cm.exception.kind, "version")
            self.assertIn("Pi-hole v5", str(cm.exception))
        # a web server that is not a Pi-hole at all
        other = _Server()
        other.handle = lambda h, m: other.send(h, 404, b"nope", "text/plain")
        self.addCleanup(other.close)
        e = self.kind_of(lambda: self.src(url=other.url).login())
        self.assertEqual(e, "version")
        for lang in ("en", "zh-Hant"):
            self.assertEqual(health.error_text("PiHoleError: PIHOLE_URL is not a Pi-hole v6 API (HTTP 404)",
                                               lang), i18n.t("err.conn_version", lang))

    def test_conntest_explains_each_case(self):
        env = {"PIHOLE_URL": self.fake.url, "PIHOLE_PASSWORD": APP_PW}
        self.assertTrue(conntest.check("pihole", env)["ok"])
        self.assertEqual(self.fake.sessions, {})            # the test logged out again
        self.fake.mode_429 = "api_seats_exceeded"
        self.assertEqual(conntest.check("pihole", env)["error_kind"], "seats")
        self.fake.mode_429 = None
        self.fake.totp = True
        self.assertEqual(conntest.check("pihole", {**env, "PIHOLE_PASSWORD": WEB_PW})["error_kind"], "totp")
        v5 = FakeFTL(v5=True)
        self.addCleanup(v5.close)
        self.assertEqual(conntest.check("pihole", {"PIHOLE_URL": v5.url})["error_kind"], "version")


class PiHoleSessionTests(_DBMixin, unittest.TestCase):
    """Pi-hole has few API seats: netwarden must never pile sessions up."""

    def setUp(self):
        self.fake = FakeFTL()
        self.addCleanup(self.fake.close)
        self.db = self.make_db()

    def test_stale_sessions_of_ours_are_ended_others_kept(self):
        self.fake.foreign = [
            {"id": 1, "user_agent": health.USER_AGENT, "last_active": self.fake.clock - 3600},  # crashed run
            {"id": 2, "user_agent": "netwarden/0.0.9", "last_active": self.fake.clock - 900},    # older version
            {"id": 3, "user_agent": health.USER_AGENT, "last_active": self.fake.clock - 30},    # a live twin
            {"id": 4, "user_agent": "Mozilla/5.0", "last_active": self.fake.clock - 86400},    # the web UI
            {"id": 5, "user_agent": None, "last_active": self.fake.clock - 86400},             # a script
        ]
        src = dns_ingest.PiHole(self.fake.url, APP_PW, timeout=5)
        src.login()
        self.assertEqual(sorted(s["id"] for s in self.fake.foreign), [3, 4, 5])
        src.close()
        self.assertEqual(self.fake.sessions, {})

    def test_reaping_never_breaks_a_login(self):
        src = dns_ingest.PiHole(self.fake.url, APP_PW, timeout=5)
        with mock.patch.object(src, "_reap_stale", wraps=src._reap_stale):
            self.fake.foreign = [{"id": "junk", "user_agent": health.USER_AGENT, "last_active": "x"}]
            src.login()
        self.assertTrue(src.sid)
        src.close()

    def test_restarts_errors_and_expiry_never_pile_up(self):
        self.fake.queries = [pq(1, 1)]
        for i in range(6):          # six `run` restarts, each one long-lived source
            src = dns_ingest.PiHole(self.fake.url, APP_PW, timeout=5)
            dns_ingest.ingest(self.db, src)
            if i % 2:
                self.fake.sessions.clear()     # Pi-hole forgot us: 401 -> re-login
            self.fake.queries.append(pq(10 + i, 10 + i))
            dns_ingest.ingest(self.db, src)
            self.assertLessEqual(len(self.fake.sessions), 1)
            if i == 3:              # a crash: no close(); the session stays behind ...
                self.fake.clock += 3600
                continue
            src.close()
            self.assertEqual(self.fake.sessions, {})
        # ... and was ended by the next login (same User-Agent, idle an hour)
        self.assertEqual(self.fake.sessions, {})

    def test_relogin_logs_the_old_sid_out_first(self):
        src = dns_ingest.PiHole(self.fake.url, APP_PW, timeout=5)
        src.login()
        old = src.sid
        # a 401 that did NOT end the session (e.g. a proxy in between): the old SID must go
        real = src._call
        state = {"n": 0}

        def flaky(method, path, params=None, body=None):
            if path == "/api/queries" and state["n"] == 0:
                state["n"] += 1
                raise urllib.error.HTTPError(self.fake.url + path, 401, "Unauthorized", {}, None)
            return real(method, path, params, body)
        with mock.patch.object(src, "_call", flaky):
            list(src.events(None))
        self.assertNotIn(old, self.fake.sessions)
        self.assertEqual(len(self.fake.sessions), 1)
        src.close()


class PiHoleQueryTests(_DBMixin, unittest.TestCase):
    def setUp(self):
        self.fake = FakeFTL()
        self.addCleanup(self.fake.close)
        self.db = self.make_db()
        self.src = dns_ingest.PiHole(self.fake.url, APP_PW, page_size=3, timeout=5)
        self.addCleanup(self.src.close)

    def test_empty_log_is_fine(self):
        st = dns_ingest.ingest_recorded(self.db, self.src)
        self.assertEqual((st["fetched"], st["inserted"]), (0, 0))
        self.assertIsNone(store.source_status(self.db)["pihole"]["last_error"])

    def test_paging_boundaries(self):
        for n in (3, 6, 7):      # exactly one page, exactly two pages, two pages + one
            self.fake.queries = [pq(i, i, f"d{i}.example") for i in range(1, n + 1)]
            self.fake.calls.clear()
            evs = list(self.src.events(None))
            self.assertEqual([e["domain"] for e in evs],
                             [f"d{i}.example" for i in range(n, 0, -1)])
            pages = self.fake.paths("/api/queries")
            self.assertEqual(len(pages), n // 3 + 1)
            self.assertTrue(all(p[2]["cursor"] == str(n) for p in pages[1:]))

    def test_time_filter_and_incremental(self):
        self.fake.queries = [pq(1, 1), pq(2, 5)]
        dns_ingest.ingest(self.db, self.src)
        self.fake.queries.append(pq(3, 9, "new.example"))
        self.fake.calls.clear()
        self.assertEqual(dns_ingest.ingest(self.db, self.src)["inserted"], 1)
        self.assertEqual(self.fake.paths("/api/queries")[0][2]["from"], str(int(T0 + 5)))

    def test_watermark_older_than_memory_reads_the_database(self):
        self.fake.queries = [pq(1, 1)]
        dns_ingest.ingest(self.db, self.src)
        # netwarden was down for two days: FTL's memory starts long after our watermark
        self.fake.earliest = T0 + 86400
        self.fake.disk_queries = [pq(1, 1), pq(2, 3600, "gap.example"), pq(3, 90000, "late.example")]
        self.fake.queries = [pq(3, 90000, "late.example")]
        self.fake.calls.clear()
        self.assertEqual(dns_ingest.ingest(self.db, self.src)["inserted"], 2)
        calls = self.fake.paths("/api/queries")
        self.assertNotIn("disk", calls[0][2])
        self.assertTrue(all(c[2].get("disk") == "true" for c in calls[1:]))
        doms = {r[0] for r in self.db.execute("SELECT domain FROM dns_events")}
        self.assertEqual(doms, {"a.example", "gap.example", "late.example"})

    def test_privacy_levels(self):
        self.fake.queries = [pq(1, 1)]
        self.fake.privacy = 3
        with self.assertRaises(dns_ingest.PiHoleError) as cm:
            dns_ingest.ingest_recorded(self.db, self.src)
        self.assertEqual(cm.exception.kind, "log_off")
        row = store.source_status(self.db)["pihole"]
        self.assertEqual(health.error_text(row["last_error"], "zh-Hant"), i18n.t("err.conn_log_off", "zh-Hant"))
        self.fake.privacy = 1
        with self.assertRaises(dns_ingest.PiHoleError) as cm:
            list(self.src.events(None))
        self.assertEqual(cm.exception.kind, "log_off")
        self.fake.privacy = 0
        self.assertEqual(len(list(self.src.events(None))), 1)

    def test_unicode_and_idn_names(self):
        self.fake.queries = [pq(1, 1, "Bücher.Example.", name="客廳電視"),
                             pq(2, 2, "xn--bcher-kva.example"),
                             pq(3, 3, "😀" * 70 + ".example")]         # not a valid IDN: kept
        evs = list(self.src.events(None))
        self.assertEqual(evs[2]["domain"], "xn--bcher-kva.example")
        self.assertEqual(evs[1]["domain"], "xn--bcher-kva.example")
        self.assertEqual(evs[2]["client_name"], "客廳電視")
        self.assertTrue(evs[0]["domain"].endswith(".example"))

    def test_oversized_answer_is_one_plain_error(self):
        self.fake.queries = [pq(i, i, "x" * 200 + ".example") for i in range(1, 4)]
        with mock.patch.object(health.read_json, "__defaults__", (512, 60.0)):
            with self.assertRaises(OSError) as cm:
                list(self.src.events(None))
        self.assertIn("too large", str(cm.exception))
        self.assertEqual(health.error_kind(health.sanitize_error(cm.exception)), "bad_response")

    def test_run_cap_keeps_the_newest(self):
        self.fake.queries = [pq(i, i, f"d{i}.example") for i in range(1, 13)]
        with mock.patch.object(dns_ingest, "MAX_EVENTS_PER_RUN", 5):
            st = dns_ingest.ingest(self.db, self.src)
        self.assertEqual((st["fetched"], st["capped"]), (5, True))
        self.assertEqual(store.get_watermark(self.db, "pihole"), _ts(12))
        # the capped run stopped paging early (3-row pages: 2 requests, not 5)
        self.assertEqual(len(self.fake.paths("/api/queries")), 2)


# --- AdGuard Home ---------------------------------------------------------------------

def aq(secs, domain="a.example", ip=PHONE[0], reason="NotFilteredNotFound", name="",
       unicode_name=None):
    """One QueryLogItem as openapi.yaml and the dev v0.107.79 instance return it."""
    q = {"class": "IN", "name": domain, "type": "A"}
    if unicode_name:
        q["unicode_name"] = unicode_name
    t = datetime.fromtimestamp(T0 + secs, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123+00:00"
    return {"answer": [{"type": "A", "value": "192.0.2.1", "ttl": 60}], "answer_dnssec": False,
            "cached": False, "client": ip, "client_info": {"whois": {}, "name": name,
                                                           "disallowed_rule": "", "disallowed": False},
            "client_proto": "", "elapsedMs": "12.345678", "filterId": 0, "question": q,
            "reason": reason, "rule": "", "rules": [], "status": "NOERROR", "time": t,
            "upstream": "https://dns.example/dns-query"}


class FakeAdGuard(_Server):
    """/control/querylog (limit, strict older_than, oldest), /control/querylog/config
    (or only the pre-v0.107.30 /control/querylog_info), Basic auth -> 401."""

    def __init__(self, user="admin", password="pw"):
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() if user else None
        self.log, self.enabled, self.anonymize = [], True, False
        self.new_config = True
        self.calls = []
        super().__init__()

    def handle(self, h, method):
        url = urllib.parse.urlparse(h.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        self.calls.append((url.path, q))
        if self.auth and h.headers.get("Authorization") != self.auth:
            return self.send(h, 401, b"", "text/plain")
        cfg = {"enabled": self.enabled, "interval": 7776000000, "anonymize_client_ip": self.anonymize,
               "ignored": [], "ignored_enabled": False}
        if url.path == "/control/querylog/config" and self.new_config:
            return self.send(h, 200, cfg)
        if url.path == "/control/querylog_info":
            return self.send(h, 200, {k: cfg[k] for k in ("enabled", "interval", "anonymize_client_ip")})
        if url.path == "/control/status":
            return self.send(h, 200, {"version": "v0.107.79", "running": True, "protection_enabled": True})
        if url.path != "/control/querylog":
            return self.send(h, 404, b"404 page not found", "text/plain")
        rows = sorted(self.log, key=lambda r: dns_ingest.to_utc(r["time"]), reverse=True)
        if "older_than" in q:     # strictly older (RFC 3339 with nanoseconds)
            try:
                cut = dns_ingest.to_utc(q["older_than"])
            except ValueError:
                return self.send(h, 400, b"bad older_than", "text/plain")
            rows = [r for r in rows if dns_ingest.to_utc(r["time"]) < cut]
        limit = int(q.get("limit", 500))
        page = rows[:limit] if limit > 0 else []
        self.send(h, 200, {"data": page, "oldest": page[-1]["time"] if page else ""})


class AdGuardTests(_DBMixin, unittest.TestCase):
    def setUp(self):
        self.fake = FakeAdGuard()
        self.addCleanup(self.fake.close)
        self.db = self.make_db()
        self.src = dns_ingest.AdGuardHome(self.fake.url, "admin", "pw", page_size=2, timeout=5)

    def test_paging_boundaries_and_since(self):
        for n in (2, 4, 5):
            self.fake.log = [aq(i, f"d{i}.example") for i in range(1, n + 1)]
            evs = list(self.src.events(None))
            self.assertEqual([e["domain"] for e in evs], [f"d{i}.example" for i in range(n, 0, -1)])
        self.fake.calls.clear()
        evs = list(self.src.events(_ts(3)))
        self.assertEqual([e["domain"] for e in evs], ["d5.example", "d4.example", "d3.example"])
        self.assertEqual(self.fake.calls[-1][0], "/control/querylog")   # no config check needed

    def test_elapsed_is_a_string_and_unicode_names(self):
        self.fake.log = [aq(1, "xn--bcher-kva.example", unicode_name="bücher.example", name="客廳電視"),
                         aq(2, "Bücher.Example")]   # an AdGuard that sent the Unicode form
        evs = list(self.src.events(None))
        self.assertEqual([e["domain"] for e in evs], ["xn--bcher-kva.example"] * 2)
        self.assertEqual(evs[1]["client_name"], "客廳電視")
        self.assertAlmostEqual(evs[0]["elapsed_ms"], 12.345678)

    def test_query_log_turned_off(self):
        self.fake.enabled = False
        with self.assertRaises(health.SourceError) as cm:
            dns_ingest.ingest_recorded(self.db, self.src)
        self.assertEqual(cm.exception.kind, "log_off")
        row = store.source_status(self.db)["adguard"]
        for lang in ("en", "zh-Hant", "de"):
            self.assertEqual(health.error_text(row["last_error"], lang), i18n.t("err.conn_log_off", lang))
        env = {"ADGUARD_URL": self.fake.url, "ADGUARD_USER": "admin", "ADGUARD_PASS": "pw"}
        self.assertEqual(conntest.check("adguard", env)["error_kind"], "log_off")
        # an older AdGuard Home (querylog_info only) is understood the same way
        self.fake.new_config = False
        with self.assertRaises(health.SourceError):
            list(self.src.events(None))
        self.fake.enabled = True
        self.assertEqual(list(self.src.events(None)), [])        # empty but on: fine
        self.assertTrue(conntest.check("adguard", env)["ok"])

    def test_no_config_endpoint_is_not_an_error(self):
        other = _Server()
        other.handle = lambda h, m: (other.send(h, 200, {"data": [], "oldest": ""})
                                     if h.path.startswith("/control/querylog?") else
                                     other.send(h, 404, b"404 page not found", "text/plain"))
        self.addCleanup(other.close)
        self.assertEqual(list(dns_ingest.AdGuardHome(other.url, timeout=5).events(None)), [])

    def test_wrong_credentials(self):
        bad = dns_ingest.AdGuardHome(self.fake.url, "admin", "wrong", timeout=5)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            list(bad.events(None))
        cm.exception.close()
        self.assertEqual(cm.exception.code, 401)
        env = {"ADGUARD_URL": self.fake.url, "ADGUARD_USER": "admin", "ADGUARD_PASS": "wrong"}
        self.assertEqual(conntest.check("adguard", env)["error_kind"], "auth")

    def test_limit_zero_is_never_sent(self):
        src = dns_ingest.AdGuardHome(self.fake.url, "admin", "pw", page_size=0)
        self.fake.log = [aq(1)]
        self.assertEqual(len(list(src.events(None))), 1)

    def test_cap_and_oversized(self):
        self.fake.log = [aq(i, f"d{i}.example") for i in range(1, 9)]
        with mock.patch.object(dns_ingest, "MAX_EVENTS_PER_RUN", 3):
            st = dns_ingest.ingest(self.db, self.src)
        self.assertEqual((st["fetched"], st["capped"]), (3, True))
        with mock.patch.object(health.read_json, "__defaults__", (256, 60.0)):
            with self.assertRaises(OSError) as cm:
                list(self.src.events(None))
        self.assertIn("too large", str(cm.exception))

    def test_tls_settings(self):
        src = dns_ingest.source_from_env({"ADGUARD_URL": "https://192.168.1.2", "ADGUARD_VERIFY_TLS": "0"})
        ctx = [h for h in src.opener.handlers if hasattr(h, "_context")][0]._context
        self.assertEqual((ctx.verify_mode, ctx.check_hostname), (ssl.CERT_NONE, False))
        src = dns_ingest.source_from_env({"ADGUARD_URL": "https://192.168.1.2"})
        ctx = [h for h in src.opener.handlers if hasattr(h, "_context")][0]._context
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)


# --- TLS ------------------------------------------------------------------------------

class TlsTests(unittest.TestCase):
    def test_https_to_a_plain_http_port_is_explained(self):
        import socketserver

        class PlainHTTP(socketserver.BaseRequestHandler):   # answers any bytes in plain HTTP
            def handle(self):
                self.request.recv(4096)
                self.request.sendall(b"HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n")

        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), PlainHTTP)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        url = f"https://127.0.0.1:{srv.server_address[1]}"
        for name, env in (("pihole", {"PIHOLE_URL": url, "PIHOLE_PASSWORD": APP_PW}),
                          ("adguard", {"ADGUARD_URL": url}),
                          ("ntopng", {"NTOPNG_URL": url})):
            self.assertEqual(conntest.check(name, env)["error_kind"], "tls", name)

    def test_self_signed_certificate_text(self):
        err = urllib.error.URLError(ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"))
        self.assertEqual(conntest._kind(err), "tls")
        text = health.sanitize_error(err)
        self.assertEqual(health.error_kind(text), "tls")
        for lang in i18n.CODES:
            self.assertIn("_VERIFY_TLS=0", health.error_text(text, lang))

    def test_verified_by_default_everywhere(self):
        self.assertEqual(health.tls_context().verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(health.tls_context().check_hostname)
        nt = traffic_ingest.source_from_env({"NTOPNG_URL": "https://192.168.1.2:3001",
                                             "NTOPNG_VERIFY_TLS": "no"})
        ctx = [h for h in nt.opener.handlers if hasattr(h, "_context")][0]._context
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)


# --- ntopng ---------------------------------------------------------------------------

class FakeNtopng(_Server):
    """REST v2 host/active.lua; Basic or "Token <t>" auth (HTTPServer.cpp); without valid
    credentials a 302 to /lua/login.lua (an HTML page), like the real thing."""

    def __init__(self, token="tok123", rc=0):
        self.token, self.rc, self.headers_seen = token, rc, []
        super().__init__()

    def handle(self, h, method):
        url = urllib.parse.urlparse(h.path)
        self.headers_seen.append(h.headers.get("Authorization"))
        if url.path == "/lua/login.lua":
            return self.send(h, 200, b"<html><form>login</form></html>", "text/html")
        if h.headers.get("Authorization") != f"Token {self.token}":
            return self.send(h, 302, b"", "text/html", [("Location", "/lua/login.lua?referer=x")])
        if self.rc:
            return self.send(h, 200, {"rc": self.rc, "rc_str": {-2: "INVALID_INTERFACE",
                                                                -3: "NOT_GRANTED"}[self.rc], "rsp": {}})
        self.send(h, 200, {"rc": 0, "rc_str": "OK", "rc_str_hr": "Success", "rsp": {
            "currentPage": 1, "perPage": 10, "data": [
                {"ip": "192.168.1.12", "is_localhost": True, "vlan": 0, "name": "phone",
                 "bytes": {"total": 300, "recvd": 200, "sent": 100}}]}})


class NtopngTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeNtopng()
        self.addCleanup(self.fake.close)

    def test_token_auth(self):
        src = traffic_ingest.source_from_env({"NTOPNG_URL": self.fake.url, "NTOPNG_TOKEN": "tok123",
                                              "NTOPNG_USER": "ignored"})
        self.assertEqual([s["rx_bytes"] for s in src.sample()], [200])
        self.assertEqual(self.fake.headers_seen[-1], "Token tok123")
        self.assertIn("tok123", health.source_secrets(src))
        self.assertNotIn("tok123", health.sanitize_error(OSError(f"x {src.auth}"),
                                                         health.source_secrets(src)))

    def test_login_redirect_is_an_auth_error(self):
        src = traffic_ingest.NtopngSource(self.fake.url, "admin", "wrong", timeout=5)
        with self.assertRaises(health.SourceError) as cm:
            src.sample()
        self.assertEqual(cm.exception.kind, "auth")
        self.assertEqual(conntest.check("ntopng", {"NTOPNG_URL": self.fake.url})["error_kind"], "auth")
        self.assertEqual(health.error_kind(health.sanitize_error(cm.exception)), "auth")

    def test_return_codes(self):
        for rc, kind, words in ((-3, "auth", "NTOPNG_USER"), (-2, None, "NTOPNG_IFID")):
            self.fake.rc = rc
            src = traffic_ingest.NtopngSource(self.fake.url, token="tok123", timeout=5)
            with self.assertRaises(OSError) as cm:
                src.sample()
            self.assertIn(words, str(cm.exception))
            self.assertEqual(health.error_kind(health.sanitize_error(cm.exception)), kind)

    def test_bad_ifid_does_not_crash(self):
        self.assertEqual(traffic_ingest.source_from_env({"NTOPNG_URL": "http://x", "NTOPNG_IFID": "eth0"}).ifid, 0)


# --- Home Assistant add-on ------------------------------------------------------------

class AddonOptionTests(unittest.TestCase):
    def test_tls_and_token_options(self):
        env = addon.env_from_options({"pihole_verify_tls": False, "adguard_verify_tls": True,
                                      "ntopng_token": " t0k "}, environ={})
        self.assertEqual((env["PIHOLE_VERIFY_TLS"], env["ADGUARD_VERIFY_TLS"], env["NTOPNG_TOKEN"]),
                         ("0", "1", "t0k"))
        self.assertNotIn("NTOPNG_VERIFY_TLS", env)          # unset = verified
        self.assertIn("ntopng_token", addon.SECRET_OPTIONS)
        self.assertEqual(addon.described({"pihole_verify_tls": False, "ntopng_token": "t0k"}),
                         ["ntopng_token", "pihole_verify_tls"])


# --- the error kinds are complete -----------------------------------------------------

class ErrorKindTests(unittest.TestCase):
    def test_every_kind_has_words_in_every_language(self):
        for kind in conntest.ERROR_KINDS:
            for lang in i18n.CODES:
                text = i18n.t("err.conn_" + kind, lang)
                self.assertNotEqual(text, "err.conn_" + kind, (kind, lang))
                if lang != "en" and kind in ("tls", "seats", "totp", "token_v5", "version", "log_off",
                                             "rate_limited"):
                    self.assertNotEqual(text, i18n.t("err.conn_" + kind, "en"), (kind, lang))

    def test_specific_kinds_win_over_generic_ones(self):
        cases = {
            "PiHoleError: Pi-hole wants a 2FA code (HTTP 401) - create an app password": "totp",
            "PiHoleError: Pi-hole rejected the password (HTTP 401): this looks like a v5 API token": "token_v5",
            "PiHoleError: Pi-hole rejected the password (HTTP 401) - check PIHOLE_PASSWORD": "auth",
            "PiHoleError: Pi-hole is rate-limiting login attempts (HTTP 429)": "rate_limited",
            "HTTPError: HTTP Error 429: Too Many Requests": "rate_limited",
            "SourceError: AdGuard Home's query log is turned off": "log_off",
            "OSError: ntopng error -3: NOT_GRANTED: this ntopng user may not read that data": "auth",
            "OSError: Pi-hole did not return JSON - check PIHOLE_URL / credentials": "bad_response",
        }
        for text, kind in cases.items():
            self.assertEqual(health.error_kind(text), kind, text)


if __name__ == "__main__":
    unittest.main()
