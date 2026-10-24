"""
Fix stage after the L/N/F/H/M/X review: one regression test (or more) per finding.
Everything runs on 127.0.0.1 with fake servers; no real LLM, no real host.
"""
import http.client
import http.server
import json
import os
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from netwarden import (__main__ as cli, alerts, backup, bedtime, brain, exposure, i18n, identify,
                       inbox, nethealth, pairing, redact, score, search, settings, store,
                       suggestions, upnp, web)
from test_stage_x import demo_copy

MAC = "aa:bb:cc:dd:ee:01"


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _event(mac, domain, ts, blocked=0):
    return {"source": "t", "ts": ts, "client_ip": "10.0.0.2", "client_name": "", "domain": domain,
            "qtype": "A", "status": "NOERROR", "reason": "", "blocked": blocked, "cached": 0,
            "upstream": "", "elapsed_ms": 1.0, "block_reason": "blocklist" if blocked else None,
            "device_mac": mac}


class _Demo:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = demo_copy(Path(self.tmp.name) / "d.db")
        self.db = store.connect(self.path)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()


# --- 1: NETWARDEN_REQUIRE_AUTH from the real environment ------------------------------

class RequireAuthEnvTests(unittest.TestCase):
    def test_real_env_var_reaches_the_server(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"NETWARDEN_REQUIRE_AUTH": "1"}):
            env = brain.load_env(Path(tmp) / "no.env")     # no .env file at all
            self.assertEqual(env.get("NETWARDEN_REQUIRE_AUTH"), "1")
            srv = web.make_server(Path(tmp) / "a.db", 0, env, "en")
            try:
                self.assertTrue(web.Handler.require_auth)
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
                c.request("GET", "/api/inventory")
                self.assertEqual(c.getresponse().status, 401)
            finally:
                srv.shutdown()
                web.close_server(srv)
                web.Handler.require_auth = False


# --- 2 + 3 + 9: the inbox --------------------------------------------------------------

class InboxFixTests(_Demo, unittest.TestCase):
    def test_batch_with_an_unknown_suggestion_writes_nothing(self):
        th = next(i for i in inbox.report(self.db, "en")["items"] if i["kind"] == "threat")
        before = store.all_acks(self.db)
        with self.assertRaises(inbox.BadRef) as cm:
            inbox.act(self.db, "snooze", [{"kind": "threat", "mac": th["mac"], "key": th["key"]},
                                          {"kind": "suggestion", "sid": "port:aa:bb:cc:dd:ee:ff:22"}])
        self.assertEqual(cm.exception.code, "suggestion_not_found")
        self.assertEqual(store.all_acks(self.db), before)

    def test_wrong_types_are_bad_refs_not_crashes(self):
        for ref in ({"kind": []}, {"kind": {}}, {"kind": "suggestion", "sid": "names", "prev": []}):
            with self.assertRaises(inbox.BadRef):
                inbox.act(self.db, "ack", [ref])

    def test_alert_and_its_fix_are_one_item(self):
        items = inbox.report(self.db, "en")["items"]
        ex = next(i for i in items if i["kind"] == "exposure" and i["fix"])
        self.assertEqual(ex["fix"]["sid"], f"port:{ex['mac']}:{ex['key'].split(':')[1]}")
        self.assertTrue(ex["fix"]["title"])
        sids = {i["sid"] for i in items if i["kind"] == "suggestion"}
        self.assertFalse({i["fix"]["sid"] for i in items if i["fix"]} & sids)


class WebHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = demo_copy(Path(cls.tmp.name) / "w.db")
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        web.close_server(cls.srv)
        cls.tmp.cleanup()

    def raw(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request(method, path, body, {"content-type": "application/json"} if body is not None else {})
        r = c.getresponse()
        return r, r.read()

    def test_hostile_bodies_get_400_not_a_dropped_connection(self):
        for path, body in (("/api/pair", "[" * 200000), ("/api/inbox/act", "[" * 200000),
                           ("/api/inbox/act", json.dumps({"action": "ack", "items": [{"kind": []}]})),
                           ("/api/bedtime/delete", json.dumps({"id": 2 ** 70})),
                           ("/api/bedtime", json.dumps({"rule": {"id": 2 ** 70}}))):
            r, raw = self.raw("POST", path, body)
            self.assertEqual(r.status, 400, (path, raw[:200]))
            self.assertIn("error", json.loads(raw))

    def test_personal_downloads_are_not_stored(self):
        for path in ("/api/export/devices.csv?lang=en", "/api/export/report.md?lang=en",
                     "/api/backup", "/report/weekly?lang=en"):
            r, _ = self.raw("GET", path)
            self.assertEqual(r.status, 200, path)
            self.assertEqual(r.getheader("cache-control"), "no-store", path)
            self.assertIsNone(r.getheader("etag"), path)

    def test_idle_connections_time_out(self):
        with mock.patch.object(web.Handler, "timeout", 0.5):
            s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            t0 = time.monotonic()
            self.assertEqual(s.recv(10), b"")       # the server hung up on the idle client
            self.assertLess(time.monotonic() - t0, 5)
            s.close()

    def test_connection_cap(self):
        with mock.patch.object(web, "MAX_CONNECTIONS", 1):
            hold = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            time.sleep(0.2)
            extra = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            try:
                self.assertEqual(extra.recv(10), b"")   # closed at once: over the cap
            except ConnectionResetError:
                pass
            extra.close()
            hold.close()
        time.sleep(0.3)
        r, _ = self.raw("GET", "/api/meta")
        self.assertEqual(r.status, 200)              # the slot was released


# --- 5: "took effect" ------------------------------------------------------------------

class TookEffectTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")

    def test_unreached_device_keeps_its_last_result(self):
        old = "2020-01-01T00:00:00.000000Z"
        store.upsert_device(self.db, {"mac": "aa:00:00:00:00:01", "ip": "10.0.0.5", "vendor": "",
                                      "hostname": ""}, seen=old)
        store.upsert_device(self.db, {"mac": "aa:00:00:00:00:02", "ip": "10.0.0.6", "vendor": "",
                                      "hostname": ""})
        rows = [{"mac": "aa:00:00:00:00:01", "port": 23, "open": False, "answered": False},
                {"mac": "aa:00:00:00:00:02", "port": 23, "open": False, "answered": False},
                {"mac": "aa:00:00:00:00:03", "port": 23, "open": False, "answered": True}]
        self.assertEqual([r["mac"] for r in exposure.conclusive(self.db, rows)],
                         ["aa:00:00:00:00:02", "aa:00:00:00:00:03"])

    def test_probe_tells_refused_from_silent(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)
        self.assertEqual(exposure._probe("127.0.0.1", port, 1.0), "open")
        srv.close()
        self.assertEqual(exposure._probe("127.0.0.1", port, 1.0), "closed")

    def test_blocked_after_is_per_domain(self):
        now = datetime.now(timezone.utc)
        store.upsert_device(self.db, {"mac": MAC, "ip": "10.0.0.2", "vendor": "", "hostname": ""})
        store.insert_events(self.db, [
            _event(MAC, "xmeye.net", _iso(now - timedelta(hours=2))),             # got through
            _event(MAC, "secu100.net", _iso(now - timedelta(hours=1)), blocked=1)])
        still, _ = suggestions._blocked_after(self.db, MAC, ["secu100.net", "xmeye.net"],
                                              _iso(now - timedelta(days=1)))
        self.assertTrue(still)
        store.insert_events(self.db, [_event(MAC, "xmeye.net", _iso(now - timedelta(minutes=5)), 1)])
        still, effect = suggestions._blocked_after(self.db, MAC, ["secu100.net", "xmeye.net"],
                                                   _iso(now - timedelta(days=1)))
        self.assertFalse(still)
        self.assertEqual(effect, _iso(now - timedelta(minutes=5)))   # when the LAST one was blocked

    def test_tidiness_is_not_done_unless_it_was_ever_suggested(self):
        det = {"active": [], "resolved": [{"id": "owners", "effect_ts": "2026-01-01T00:00:00.000000Z",
                                           "params": {"n": 0}, "devices": []}]}
        self.assertEqual(suggestions.with_status(det, {})["done"], [])
        st = {"owners": {"status": "snoozed", "until": None, "updated_at": "2026-01-01T00:00:00Z"}}
        self.assertEqual([d["id"] for d in suggestions.with_status(det, st)["done"]], ["owners"])


# --- 6: ids in ack keys are never handed out twice -------------------------------------

class IdReuseTests(unittest.TestCase):
    def _outage(self, db):
        return db.execute("""INSERT INTO outages (start_ts, end_ts, cause, updated_at)
                             VALUES ('a', 'b', 'isp', 'c')""").lastrowid

    def test_deleted_or_pruned_outage_ids_are_not_reused(self):
        db = store.connect(":memory:")
        with db:
            first = self._outage(db)
            db.execute("DELETE FROM outages")
            second = self._outage(db)
        self.assertGreater(second, first)

    def test_old_db_is_migrated_above_every_acked_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.db"
            raw = sqlite3.connect(path)
            raw.executescript("""
                CREATE TABLE outages (id INTEGER PRIMARY KEY, start_ts TEXT NOT NULL,
                    end_ts TEXT NOT NULL, cause TEXT NOT NULL, ongoing INTEGER NOT NULL DEFAULT 0,
                    gateway_min INTEGER NOT NULL DEFAULT 0, dns_min INTEGER NOT NULL DEFAULT 0,
                    probe_min INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL);
                INSERT INTO outages VALUES (2, 's', 'e', 'isp', 0, 0, 0, 0, 'u');
                CREATE TABLE bedtime_rules (id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '',
                    owner TEXT, mac TEXT, days TEXT NOT NULL, win_start TEXT NOT NULL,
                    win_end TEXT NOT NULL, min_minutes INTEGER NOT NULL DEFAULT 10,
                    enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL);
                CREATE TABLE acks (mac TEXT NOT NULL, domain TEXT NOT NULL DEFAULT '',
                    ts TEXT NOT NULL, PRIMARY KEY (mac, domain));
                INSERT INTO acks VALUES ('network', 'outage:7', 't');
                INSERT INTO acks VALUES ('k', 'bedtime:9:2026-01-01', 't');""")
            raw.commit()
            raw.close()
            db = store.connect(path)
            self.assertEqual(db.execute("SELECT start_ts FROM outages WHERE id = 2").fetchone()[0], "s")
            with db:
                self.assertEqual(self._outage(db), 8)          # above the acked 7, not 3
                rid = store.save_bedtime_rule(db, {"id": None, "name": "", "owner": "x", "mac": None,
                                                   "days": [0], "start": "22:00", "end": "07:00",
                                                   "min_minutes": 10, "enabled": True})
            self.assertEqual(rid, 10)
            self.assertIn("AUTOINCREMENT", db.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'outages'").fetchone()[0])
            db.close()
            store.connect(path).close()                        # idempotent


# --- 7: bedtime alerts off must not silence the generic night alert ---------------------

class BedtimeSwitchTests(_Demo, unittest.TestCase):
    def test_off_switch_keeps_unusual_hours(self):
        night = [{"mac": MAC, "ack": "activity:night", "name": "x"}]
        with mock.patch("netwarden.activity.night_alerts", return_value=night), \
                mock.patch.object(bedtime, "suppress_night", return_value=[]) as sup:
            settings.update(self.db, {}, {"family.bedtime_alerts": False})
            self.assertEqual([a["mac"] for a in alerts._compute(self.db, 24, 7)["unusual_hours"]], [MAC])
            sup.assert_not_called()
            settings.update(self.db, {}, {"family.bedtime_alerts": True})
            self.assertEqual(alerts._compute(self.db, 24, 7)["unusual_hours"], [])


# --- 8 + 14: redaction ---------------------------------------------------------------------

class RedactionFixTests(unittest.TestCase):
    def test_one_character_names_in_fields(self):
        r = redact.Redactor()
        r.add("[P1]", "媽", "媽")
        r.add("[R1]", "A", "A")
        r.add("[D1]", "P1", "P1")          # a device literally named like a token's body
        snap = {"devices": [{"mac": MAC, "name": "P1", "owner": "媽", "room": "A",
                             "privacy": {"grade": "A"}}],
                "people": [{"owner": "媽", "devices": ["P1"]}]}
        r.redact_fields(snap)
        text = r.redact(json.dumps(snap, ensure_ascii=False))
        self.assertNotIn("媽", text)
        self.assertIn('"owner": "[P1]"', text)
        self.assertIn('"room": "[R1]"', text)
        self.assertIn('"grade": "A"', text)           # only name fields, by whole value
        self.assertNotIn("[[", text)                  # tokens are not redacted again
        self.assertIn("媽", r.unredact(text))

    def test_variants(self):
        r = redact.Redactor()
        r.add("[D1]", "İpek", "İpek")
        r.add("[D2]", "Galaxy-Tab-A7", "Galaxy-Tab-A7")
        r.add("[M1]", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff")
        text = r.redact("İpek; aabbccddeeff; aabb.ccdd.eeff; AA-BB-CC-DD-EE-FF; Galaxy_Tab_A7; "
                        "galaxy tab a7; 13.1.168.192.in-addr.arpa; 100.64.1.2; 8.8.8.8")
        for secret in ("İpek", "aabbcc", "aabb.ccdd", "AA-BB", "Galaxy", "galaxy", "192.168.1.13",
                       "13.1.168.192", "100.64.1.2"):
            self.assertNotIn(secret, text)
        self.assertIn("8.8.8.8", text)
        self.assertIn("İpek", r.unredact(text))


# --- 10: isolated bad minutes ------------------------------------------------------------

class OutageBridgeTests(unittest.TestCase):
    def states(self, pattern):
        t0 = datetime(2026, 10, 20, 2, 0, tzinfo=timezone.utc)
        out = {}
        for i, ch in enumerate(pattern):
            if ch != ".":
                out[(t0 + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M")] = \
                    {"gw": ch == "+", "dns": None, "inet": None}
        return out

    def test_two_lonely_bad_minutes_are_not_an_outage(self):
        now = datetime(2026, 10, 20, 3, 0, tzinfo=timezone.utc)
        self.assertEqual(nethealth.find_outages(self.states("+-++-+"), now), [])

    def test_missing_samples_and_a_lucky_probe_inside_an_outage_are_bridged(self):
        now = datetime(2026, 10, 20, 3, 0, tzinfo=timezone.utc)
        self.assertEqual(len(nethealth.find_outages(self.states("+-.-+"), now)), 1)
        found = nethealth.find_outages(self.states("+---+--+"), now)
        self.assertEqual([o["minutes"] for o in found], [6])


# --- 11 + 12 + 21-UPnP: identify / UPnP hardening ------------------------------------------

class IdentifyHardeningTests(unittest.TestCase):
    def test_trickling_device_hits_one_deadline(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def trickle():
            conn, _ = srv.accept()
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
            try:
                while not stop.is_set():
                    conn.sendall(b"x")
                    time.sleep(0.2)
            except OSError:
                pass
            conn.close()
        threading.Thread(target=trickle, daemon=True).start()
        t0 = time.monotonic()
        with self.assertRaises(TimeoutError):
            identify.http_get(f"http://127.0.0.1:{port}/d.xml", timeout=1.0)
        self.assertLess(time.monotonic() - t0, 3)
        stop.set()
        srv.close()

    def test_utf16_xml_is_refused(self):
        doc = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE r [<!ENTITY a "x">]><r>&a;</r>'
        for data in (doc.encode("utf-16"), doc.encode("utf-16-le"), doc.encode("utf-32")):
            with self.assertRaises(ValueError):
                identify.safe_xml(data)
        self.assertEqual(identify.safe_xml(b"\xef\xbb\xbf<root><a>1</a></root>").tag, "root")
        with self.assertRaises(ValueError):
            identify.safe_xml(b'<?xml version="1.0" encoding="UTF-7"?><r/>')

    def test_only_the_default_gateway_counts(self):
        described = {"10.0.0.9": {"wan": [{"service_type": "x", "control_url": "y"}]}}
        self.assertIsNone(upnp.pick_gateway(described, "10.0.0.1"))
        self.assertEqual(upnp.pick_gateway(described, None)[0], "10.0.0.9")


# --- 13: numeric AI hosts ------------------------------------------------------------------

class DestinationTests(unittest.TestCase):
    def test_numeric_spellings_of_public_addresses_are_cloud(self):
        for url in ("http://134744072:11434", "http://0x08080808/", "http://8.8:80",
                    "http://0x8.0x8.0x8.0x8/"):
            self.assertEqual(settings.destination(url), "cloud", url)
        self.assertEqual(settings.destination("http://167772161:11434"), "lan")     # 10.0.0.1
        self.assertEqual(settings.destination("http://2130706433:11434"), "local")  # 127.0.0.1
        self.assertEqual(settings.destination("http://ollama:11434"), "lan")


# --- 15: Anthropic provider redirects --------------------------------------------------------

class AnthropicRedirectTests(unittest.TestCase):
    def test_cross_host_redirect_is_refused(self):
        hits = []

        class Other(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(self.headers.get("x-api-key"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass
        other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Other)
        threading.Thread(target=other.serve_forever, daemon=True).start()
        target = f"http://127.0.0.1:{other.server_address[1]}/v1/messages"

        class Redir(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("content-length") or 0))
                self.send_response(307)
                self.send_header("location", target)
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        first = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redir)
        threading.Thread(target=first.serve_forever, daemon=True).start()
        try:
            p = brain.AnthropicProvider("sk-test-not-real")
            p.ENDPOINT = f"http://127.0.0.1:{first.server_address[1]}/v1/messages"
            with self.assertRaises(brain.LLMError):
                p.complete("s", "u")
            self.assertEqual(hits, [])
        finally:
            for s in (first, other):
                s.shutdown()
                s.server_close()


# --- 16: score trend -------------------------------------------------------------------------

class ScoreTrendTests(_Demo, unittest.TestCase):
    def test_delta_is_against_the_newest_day_a_week_ago(self):
        day = date.fromisoformat(score.today())
        with self.db:
            self.db.execute("DELETE FROM score_history")
        store.put_score(self.db, (day - timedelta(days=14)).isoformat(), 10, {})
        store.put_score(self.db, (day - timedelta(days=8)).isoformat(), 70, {})
        r = score.report(self.db, "en")
        self.assertEqual(r["delta"], r["score"] - 70)


# --- 17: strict backups ----------------------------------------------------------------------

class StrictBackupTests(unittest.TestCase):
    def doc(self, **data):
        return {"format": backup.FORMAT, "version": 1, "data": data}

    def test_unknown_keys_are_refused(self):
        backup.validate(self.doc(labels=[{"mac": MAC, "label": "TV", "note": ""}]))
        for bad in (self.doc(sessions=[{"token": "x"}]),
                    self.doc(labels=[{"mac": MAC, "label": "TV", "admin": True}]),
                    {**self.doc(), "extra": 1}):
            with self.assertRaises(backup.BadBackup):
                backup.validate(bad)
        with self.assertRaises(backup.BadBackup):
            backup.parse("[" * 200000)


# --- 19: pairing limiter ---------------------------------------------------------------------

class LimiterRaceTests(unittest.TestCase):
    def test_parallel_attempts_are_reserved(self):
        lim = pairing.Limiter(max_fail=5)
        allowed = [lim.attempt("10.0.0.9") == 0 for _ in range(20)]   # a burst, none judged yet
        self.assertEqual(sum(allowed), 5)
        for _ in range(5):
            lim.fail("10.0.0.9")
        self.assertGreater(lim.blocked("10.0.0.9"), 60)               # locked out properly
        self.assertEqual(lim.attempt("10.0.0.8"), 0)                  # others are not
        lim.success("10.0.0.8")
        self.assertEqual(lim._inflight, {})


# --- 20: bedtime windows after midnight -------------------------------------------------------

class BedtimeNightTests(unittest.TestCase):
    def test_a_window_after_midnight_belongs_to_the_next_morning(self):
        rule = {"start": "00:00", "end": "06:00", "days": bedtime.SCHOOL_NIGHTS}
        sunday = date(2026, 10, 18)
        s, e = bedtime.window(rule, sunday, timezone.utc)
        self.assertEqual((s.date(), s.hour, e.date(), e.hour), (date(2026, 10, 19), 0, date(2026, 10, 19), 6))
        # Thursday night is covered, Saturday night (Sunday 00:00-06:00) is not
        since = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)     # Saturday noon
        occ = bedtime.occurrences(rule, since, since + timedelta(days=7), timezone.utc)
        starts = {w[1].date() for w in occ}
        self.assertNotIn(date(2026, 10, 18), starts)                 # Sunday 00:00
        self.assertIn(date(2026, 10, 23), starts)                    # Friday 00:00 = Thursday night
        # an evening window is unchanged
        s, e = bedtime.window({"start": "22:00", "end": "07:00"}, sunday, timezone.utc)
        self.assertEqual((s.date(), e.date()), (sunday, date(2026, 10, 19)))


# --- 21: search names ----------------------------------------------------------------------------

class SearchNameTests(_Demo, unittest.TestCase):
    def test_no_bare_mac_as_a_name(self):
        res = search.search(self.db, "媽媽", "zh-Hant")
        self.assertTrue(res["devices"])
        for d in res["devices"]:
            self.assertNotEqual(d["name"], d["mac"])
        for line in cli.search_lines(res, "zh-Hant"):
            parts = line.strip().split(" · ")
            self.assertEqual(len(parts), len(set(parts)), line)       # nothing said twice


# --- 22: i18n -------------------------------------------------------------------------------------

class I18nFixTests(unittest.TestCase):
    def test_no_double_period_after_an_abbreviated_value(self):
        text = i18n.t("wow.hl.minutes.up", "de", pct=10, this="5 Std.", last="44 Std. 59 Min.")
        self.assertTrue(text.endswith("59 Min."), text)
        self.assertNotIn("..", text)

    def test_zh_punctuation_is_one_style(self):
        for code in ("zh-Hant", "zh-Hans"):
            path = Path(i18n.__file__).parent / "locales" / f"{code}.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            mixed = [k for k, v in data.items() if isinstance(v, str) and any(c in v for c in "，：（）")]
            self.assertEqual(mixed, [], code)

    def test_offline_hint_mentions_the_local_model(self):
        for code in i18n.CODES:
            self.assertIn("Ollama", i18n.t("status.hint.ai_offline", code), code)


# --- 23: the warm-up covers the suggestions -------------------------------------------------------

class WarmSuggestionsTests(_Demo, unittest.TestCase):
    def test_warm_computes_the_suggestions(self):
        from netwarden import runner
        with mock.patch.object(suggestions, "detect", wraps=suggestions.detect) as det:
            runner.warm(self.db, 24, {brain.OFFLINE_ENV: "1"})
        det.assert_called_once()
        self.assertEqual(det.call_args.args[1], {brain.OFFLINE_ENV: "1"})


if __name__ == "__main__":
    unittest.main()
