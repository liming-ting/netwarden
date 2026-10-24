"""
Tests for the Pi-hole v6 source (dns_ingest.PiHole) against a fake FTL REST API on
an ephemeral 127.0.0.1 port: login, SID header, 401 re-auth, cursor paging, logout,
status -> blocked mapping, client IP -> MAC attribution and incremental ingest.

    python3 -m unittest tests.test_pihole -v
"""
from __future__ import annotations

import json
import ssl
import threading
import unittest
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from netwarden import discovery, dns_ingest, health, runner, store

PHONE = ("192.168.1.12", "3a:1f:7c:62:d5:12")
TV = ("192.168.1.40", "b8:27:eb:00:00:40")      # unknown to the DB, but in ARP
SELF_MAC = "00:1b:21:3c:4d:5e"
T0 = datetime(2026, 10, 21, 0, 0, 0, tzinfo=timezone.utc).timestamp()


def query(qid, secs, ip, domain, status="FORWARDED", reply="IP", name=None, qtype="A"):
    return {"id": qid, "time": T0 + secs, "type": qtype, "domain": domain, "cname": None,
            "status": status, "client": {"ip": ip, "name": name}, "dnssec": "UNKNOWN",
            "reply": {"type": reply, "time": 0.0042}, "list_id": None,
            "upstream": None if status not in ("FORWARDED",) else "1.1.1.1#53",
            "ede": {"code": -1, "text": None}}


class FakePiHole:
    """Just enough of FTL's /api: auth sessions + /api/queries with from/length/start/
    cursor exactly as src/api/queries.c applies them (id DESC, id <= cursor,
    timestamp >= from, `start` rows skipped, cursor echoed or = newest id)."""

    def __init__(self, password="secret"):
        self.password = password
        self.queries = []           # any order; served by id DESC
        self.sessions = set()
        self.logins = self.logouts = 0
        self.query_calls = []       # parsed params of each GET /api/queries
        self.next_sid = 0
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _authed(self):
                return not fake.password or self.headers.get("X-FTL-SID") in fake.sessions

            def do_POST(self):
                if self.path != "/api/auth":
                    return self._send(404, {})
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
                if not fake.password:
                    return self._send(200, {"session": {"valid": True, "totp": False, "sid": None,
                                                        "csrf": None, "validity": -1,
                                                        "message": "no password set"}})
                if body.get("password") != fake.password:
                    return self._send(401, {"session": {"valid": False, "sid": None,
                                                        "message": "password incorrect"}})
                fake.logins += 1
                fake.next_sid += 1
                sid = f"sid{fake.next_sid}"
                fake.sessions.add(sid)
                self._send(200, {"session": {"valid": True, "totp": False, "sid": sid,
                                             "csrf": "c", "validity": 300,
                                             "message": "correct password"}, "took": 0.001})

            def do_DELETE(self):
                sid = self.headers.get("X-FTL-SID")
                if sid in fake.sessions:
                    fake.sessions.discard(sid)
                    fake.logouts += 1
                    return self._send(204)
                self._send(401, {"session": {"valid": False, "message": "no SID provided"}})

            def do_GET(self):
                url = urllib.parse.urlparse(self.path)
                if url.path != "/api/queries":
                    return self._send(404, {})
                if not self._authed():
                    return self._send(401, {"session": {"valid": False}})
                q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
                fake.query_calls.append(q)
                rows = sorted(fake.queries, key=lambda r: -r["id"])
                newest = rows[0]["id"] if rows else 0
                cursor = int(q["cursor"]) if "cursor" in q else newest
                rows = [r for r in rows if r["id"] <= cursor]
                if "from" in q:
                    rows = [r for r in rows if r["time"] >= float(q["from"])]
                start, length = int(q.get("start", 0)), int(q.get("length", 100))
                self._send(200, {"queries": rows[start:start + length], "cursor": cursor,
                                 "recordsTotal": len(fake.queries), "recordsFiltered": len(rows),
                                 "draw": 0, "took": 0.001})

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class PiHoleTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakePiHole()
        self.addCleanup(self.fake.close)
        self.src = dns_ingest.PiHole(self.fake.url, "secret", page_size=2)   # force paging
        self.addCleanup(self.src.close)
        self.db = store.connect(":memory:")
        store.upsert_device(self.db, discovery.device_record(*PHONE, {}, hostname=""))
        store.upsert_device(self.db, discovery.device_record("192.168.1.13", SELF_MAC, {},
                                                             is_self=True, hostname="desk"))
        for p in (mock.patch.object(discovery, "read_arp", lambda: {TV[0]: TV[1]}),
                  mock.patch.object(discovery, "load_manuf", lambda: {}),
                  mock.patch.object(discovery, "hostname_for", lambda ip: ""),
                  mock.patch.object(dns_ingest, "local_addresses",
                                    lambda: {"127.0.0.1", "::1", "192.168.1.13"})):
            p.start()
            self.addCleanup(p.stop)

    def rows(self):
        return [dict(r) for r in self.db.execute(
            """SELECT ts, client_ip, device_mac, domain, status, reason, blocked, block_reason,
                      cached FROM dns_events ORDER BY ts""")]

    def test_ingest_maps_status_attributes_and_pages(self):
        self.fake.queries = [
            query(1, 1, PHONE[0], "Instagram.com."),
            query(2, 2, PHONE[0], "doubleclick.net", status="GRAVITY", reply="IP"),
            query(3, 3, TV[0], "samsungads.com", status="REGEX", reply="NXDOMAIN", name="tv.lan"),
            query(4, 4, "127.0.0.1", "github.com", status="CACHE", reply="CNAME"),
            query(5, 5, "10.9.9.9", "ads.example", status="DENYLIST_CNAME", reply="NODATA"),
            query(6, 6, PHONE[0], "tracker.example", status="EXTERNAL_BLOCKED_NULL"),
        ]
        st = dns_ingest.ingest(self.db, self.src)
        self.assertEqual((st["fetched"], st["inserted"], st["unattributed"]), (6, 6, 1))
        self.assertGreaterEqual(len(self.fake.query_calls), 3)          # 6 rows / pages of 2
        later = self.fake.query_calls[1:]
        self.assertTrue(all(c["cursor"] == "6" for c in later))         # pinned to page 1
        self.assertEqual([c["start"] for c in self.fake.query_calls[:3]], ["0", "2", "4"])
        self.assertEqual(self.fake.logins, 1)                           # one session reused
        self.assertEqual([d["mac"] for d in st["new_devices"]], [TV[1]])

        by = {r["domain"]: r for r in self.rows()}
        self.assertEqual(by["instagram.com"]["device_mac"], PHONE[1])
        self.assertEqual((by["instagram.com"]["blocked"], by["instagram.com"]["block_reason"]),
                         (0, None))
        self.assertEqual(by["instagram.com"]["status"], "NOERROR")
        self.assertEqual((by["doubleclick.net"]["blocked"], by["doubleclick.net"]["block_reason"],
                          by["doubleclick.net"]["reason"]), (1, "blocklist", "GRAVITY"))
        self.assertEqual((by["samsungads.com"]["block_reason"], by["samsungads.com"]["status"],
                          by["samsungads.com"]["device_mac"]), ("regex", "NXDOMAIN", TV[1]))
        self.assertEqual((by["github.com"]["cached"], by["github.com"]["device_mac"]), (1, SELF_MAC))
        self.assertEqual(by["ads.example"]["block_reason"], "denylist")
        self.assertIsNone(by["ads.example"]["device_mac"])
        self.assertEqual(by["tracker.example"]["block_reason"], "upstream")
        self.assertTrue(by["instagram.com"]["ts"].startswith("2026-10-21T00:00:01."))
        tv = self.db.execute("SELECT hostname FROM devices WHERE mac = ?", (TV[1],)).fetchone()
        self.assertEqual(tv["hostname"], "tv.lan")

    def test_incremental_ingest_has_no_duplicates(self):
        self.fake.queries = [query(i, i, PHONE[0], f"d{i}.example") for i in range(1, 4)]
        self.assertEqual(dns_ingest.ingest(self.db, self.src)["inserted"], 3)
        st = dns_ingest.ingest(self.db, self.src)
        self.assertEqual(st["inserted"], 0)
        self.assertLessEqual(st["fetched"], 1)                      # only the watermark row
        self.assertIn("from", self.fake.query_calls[-1])
        self.fake.queries += [query(4, 4, PHONE[0], "d4.example"), query(5, 4.5, PHONE[0], "d5.example")]
        self.assertEqual(dns_ingest.ingest(self.db, self.src)["inserted"], 2)
        self.assertEqual(len(self.rows()), 5)
        self.assertEqual(self.fake.logins, 1)

    def test_expired_session_reauthenticates_once(self):
        self.fake.queries = [query(1, 1, PHONE[0], "a.example")]
        dns_ingest.ingest(self.db, self.src)
        self.fake.sessions.clear()                                  # Pi-hole forgot us
        self.fake.queries.append(query(2, 2, PHONE[0], "b.example"))
        self.assertEqual(dns_ingest.ingest(self.db, self.src)["inserted"], 1)
        self.assertEqual(self.fake.logins, 2)

    def test_close_logs_out_and_is_idempotent(self):
        self.fake.queries = [query(1, 1, PHONE[0], "a.example")]
        dns_ingest.ingest(self.db, self.src)
        self.assertEqual(len(self.fake.sessions), 1)
        self.src.close()
        self.src.close()
        self.assertEqual((self.fake.logouts, len(self.fake.sessions)), (1, 0))
        with dns_ingest.PiHole(self.fake.url, "secret") as src:      # context manager
            list(src.events(None))
        self.assertEqual((self.fake.logouts, len(self.fake.sessions)), (2, 0))

    def test_wrong_password_is_a_clear_recorded_error(self):
        src = dns_ingest.PiHole(self.fake.url, "nope")
        with self.assertRaises(dns_ingest.PiHoleError) as cm:
            dns_ingest.ingest_recorded(self.db, src)
        self.assertIn("PIHOLE_PASSWORD", str(cm.exception))
        self.assertNotIn("nope", str(cm.exception))
        row = store.source_status(self.db)["pihole"]
        self.assertIn("HTTP 401", row["last_error"])

    def test_missing_password_when_one_is_required(self):
        src = dns_ingest.PiHole(self.fake.url, "")
        with self.assertRaises(dns_ingest.PiHoleError) as cm:
            list(src.events(None))
        self.assertIn("PIHOLE_PASSWORD", str(cm.exception))
        self.assertEqual(self.fake.logins, 0)

    def test_pihole_without_password(self):
        self.fake.password = ""
        self.fake.queries = [query(1, 1, PHONE[0], "a.example")]
        for pw in ("", "ignored"):     # no login at all / login answered with sid null
            src = dns_ingest.PiHole(self.fake.url, pw)
            self.assertEqual(len(list(src.events(None))), 1)
            self.assertIsNone(src.sid)
            src.close()
        self.assertEqual(self.fake.logouts, 0)

    def test_tls_verification_default_and_opt_out(self):
        self.assertEqual(dns_ingest.PiHole("https://pi.hole").ctx.verify_mode, ssl.CERT_REQUIRED)
        src = dns_ingest.source_from_env({"PIHOLE_URL": "https://pi.hole", "PIHOLE_PASSWORD": "x",
                                          "PIHOLE_VERIFY_TLS": "0"})
        self.assertEqual(src.ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(src.ctx.check_hostname)


class SelectionTest(unittest.TestCase):
    def test_which_source(self):
        ag, ph = {"ADGUARD_URL": "http://a"}, {"PIHOLE_URL": "http://p"}
        self.assertIsNone(dns_ingest.dns_source_name({}))
        self.assertEqual(dns_ingest.dns_source_name(ag), "adguard")
        self.assertEqual(dns_ingest.dns_source_name(ph), "pihole")
        self.assertEqual(dns_ingest.dns_source_name({**ag, **ph}), "adguard")
        both = {**ag, **ph, "NETWARDEN_DNS_SOURCE": "Pihole"}
        self.assertEqual(dns_ingest.dns_source_name(both), "pihole")
        self.assertIsInstance(dns_ingest.source_from_env(both), dns_ingest.PiHole)
        # asking for a source that isn't configured falls back to the one that is
        self.assertEqual(dns_ingest.dns_source_name({**ag, "NETWARDEN_DNS_SOURCE": "pihole"}),
                         "adguard")
        self.assertTrue(dns_ingest.configured(ph))
        with self.assertRaises(SystemExit) as cm:
            dns_ingest.source_from_env({"NETWARDEN_LANG": "en"})
        self.assertIn("PIHOLE_URL", str(cm.exception.code))

    def test_runner_dns_job_logs_out_when_the_loop_stops(self):
        import tempfile
        from pathlib import Path
        fake = FakePiHole()
        self.addCleanup(fake.close)
        fake.queries = [query(1, 1, "10.9.9.9", "a.example")]
        with mock.patch.object(discovery, "availability", lambda: (False, "no_lan")), \
                mock.patch.object(dns_ingest, "local_addresses", lambda: {"127.0.0.1"}), \
                mock.patch.object(discovery, "read_arp", lambda: {}), \
                mock.patch.object(discovery, "default_iface_net_ip", lambda: (None, None, None)):
            jobs = runner.plan({"PIHOLE_URL": fake.url, "PIHOLE_PASSWORD": "secret"})
            self.assertIsInstance(jobs["dns"][1], runner.DnsJob)
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "t.db"
                r = runner.Runner(path, {}, jobs={"dns": (3600, jobs["dns"][1])}).start()
                deadline = threading.Event()
                for _ in range(200):
                    if fake.logins:
                        break
                    deadline.wait(0.01)
                r.stop(timeout=2)
                db = store.connect(path)
                self.assertEqual(store.source_status(db)["pihole"]["last_count"], 1)
                db.close()
        self.assertEqual((fake.logins, fake.logouts, len(fake.sessions)), (1, 1, 0))


class HealthTest(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")
        p = mock.patch.object(discovery, "availability", lambda: (True, None))
        p.start()
        self.addCleanup(p.stop)

    def test_only_the_selected_dns_source_counts(self):
        env = {"ADGUARD_URL": "http://a", "PIHOLE_URL": "http://p", "PIHOLE_PASSWORD": "pw-12345",
               "NETWARDEN_DNS_SOURCE": "pihole"}
        st = health.status(self.db, None, env)
        self.assertTrue(st["sources"]["pihole"]["configured"])
        self.assertFalse(st["sources"]["adguard"]["configured"])
        hints = health.hints(st, "en")
        self.assertIn(health.i18n.t("status.hint.pihole_never", "en"), hints)
        self.assertFalse(any("ADGUARD_URL" in h for h in hints))   # not a problem: unused
        store.record_source_error(self.db, "pihole", "PiHoleError: pw-12345 rejected")
        st = health.status(self.db, None, env)
        self.assertNotIn("pw-12345", st["sources"]["pihole"]["last_error"])
        self.assertTrue(any("PIHOLE_PASSWORD" in h for h in health.hints(st, "en")))

    def test_one_hint_when_no_dns_source(self):
        st = health.status(self.db, None, {})
        hints = health.hints(st, "zh-Hant")
        self.assertEqual(sum("PIHOLE_URL" in h for h in hints), 1)
        self.assertIn("DNS(Pi-hole)", health.render(st, "zh-Hant"))


if __name__ == "__main__":
    unittest.main()
