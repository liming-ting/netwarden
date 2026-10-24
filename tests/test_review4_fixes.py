"""
Round-4 review fixes (stages P, Q, A, T): one regression test per finding where practical.

- the legacy owner field goes through people's rules (case-insensitive, cap, length);
- AI lookups never reveal when a person's devices were online unless that person opted
  in to presence; whole-word person matching; whitespace arguments; result caps;
- the presence check never pings a stale / reused address, and a device that answered
  is "seen" in the inventory too; departures can be notified with a long grace period;
- quiet hours judged at the event's own time; a late addition reopens a closed summary;
  the "next window" text honours weekday overrides;
- tools refusal: only a first-round refusal is remembered, and not forever; narrow match;
  no whitespace-only text blocks; parallel tool calls without an index stay separate;
- /api/since with a date that overflows; ASCII-only digits; restore never turns presence
  on; risky UPnP forwards are not also "stale"; tuning: unknown fields refused, silencing
  a security alert type for everyone is this computer's call and needs a confirmation;
- i18n: 數據 is a mainland term in zh-Hant (數據機 is fine), no full-width semicolons,
  "who's home?" offline in every UI language; initials of "Person 03".
"""
import http.client
import http.server
import ipaddress
import json
import sqlite3
import tempfile
import threading
import time
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netwarden import (ai_intents, ai_tools, backup, brain, cache, demo, hygiene, i18n, live,
                       localai, notify, pairing, people, presence, quiet, redact, settings, since,
                       store, web)

ROOT = Path(__file__).resolve().parent.parent
UTC = timezone.utc
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"
_DEMO = {}


def demo_copy(dest: Path) -> Path:
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


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def device(db, mac, ip, last=None):
    store.upsert_device(db, {"ip": ip, "mac": mac, "vendor": "", "hostname": "",
                             "randomized": False, "is_self": False})
    if last:
        with db:
            db.execute("UPDATE devices SET last_seen = ? WHERE mac = ?", (iso(last), mac))


class _Empty(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = store.connect(Path(self.tmp.name) / "r.db")
        cache.clear()
        self.now = datetime.now(UTC)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()
        cache.clear()


# --- people / owner ---------------------------------------------------------------------

class OwnerTests(_Empty):
    def test_owner_name_matches_case_insensitively_and_checks_the_rules(self):
        people.save(self.db, people.validate(self.db, {"name": "Mom"}))
        self.assertEqual(people.owner_name(self.db, "mom"), "Mom")
        self.assertEqual(len(people.owner_name(self.db, "x" * 120)), people.MAX_NAME)
        with self.assertRaises(people.BadPerson):
            people.owner_name(self.db, "   ")
        for i in range(people.MAX_PEOPLE - 1):
            people.save(self.db, people.validate(self.db, {"name": f"P{i}"}))
        with self.assertRaises(people.BadPerson) as c:
            people.owner_name(self.db, "One too many")
        self.assertEqual(c.exception.code, "too_many_people")
        self.assertEqual(people.owner_name(self.db, "MOM"), "Mom")    # an existing one is fine

    def test_initials_keep_a_number_whole(self):
        self.assertEqual(people.initials("Person 03"), "P3")
        self.assertEqual(people.initials("Anna Lee"), "AL")
        self.assertEqual(people.initials("媽媽"), "媽")
        js = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("parseInt(w[1], 10)", js)


# --- presence ---------------------------------------------------------------------------

class PresenceTests(_Empty):
    def setUp(self):
        super().setUp()
        self.pid = people.save(self.db, people.validate(self.db, {"name": "Ann"}))
        presence.set_presence(self.db, self.pid, enabled=True)
        self.net = ipaddress.ip_network("192.168.1.0/24")

    def phone(self, mac, ip, last):
        device(self.db, mac, ip, last)
        store.set_profile(self.db, mac, owner="Ann", type="phone")

    def test_stale_or_reused_addresses_are_never_pinged(self):
        old, new = "aa:00:00:00:00:01", "aa:00:00:00:00:02"
        self.phone(old, "192.168.1.21", self.now - timedelta(hours=3))
        self.phone(new, "192.168.1.22", self.now - timedelta(days=3))     # gone too long
        with self.db:   # DHCP gave the old phone's address to a device seen since
            self.db.execute("INSERT INTO devices (mac, ip, vendor, hostname, first_seen, last_seen) "
                            "VALUES ('bb:00:00:00:00:09', '192.168.1.21', '', '', ?, ?)",
                            (iso(self.now), iso(self.now)))
        self.assertEqual(presence.check_targets(self.db, self.net, self.now), [])
        with self.db:
            self.db.execute("DELETE FROM devices WHERE mac = 'bb:00:00:00:00:09'")
        self.assertEqual(presence.check_targets(self.db, self.net, self.now),
                         [(old, "192.168.1.21")])

    def test_an_answering_device_is_seen_in_the_inventory_too(self):
        mac = "aa:00:00:00:00:01"
        self.phone(mac, "192.168.1.21", self.now - timedelta(hours=2))
        self.assertEqual(presence.check_recorded(self.db, {}, lambda ip: True, self.net), 1)
        last = self.db.execute("SELECT last_seen FROM devices WHERE mac = ?", (mac,)).fetchone()[0]
        self.assertGreater(last, iso(self.now - timedelta(minutes=1)))

    def test_departures_are_aged_from_when_they_became_known(self):
        mac = "aa:00:00:00:00:01"
        self.phone(mac, "192.168.1.21", self.now - timedelta(minutes=181))
        store.save_person(self.db, {**store.person(self.db, self.pid),
                                    "presence_since": iso(self.now - timedelta(hours=6)),
                                    "notify_leave": True})
        store.insert_presence_samples(self.db, [
            (mac, iso(self.now - timedelta(minutes=m)), "check") for m in range(180, 70, -5)])
        leave = [e for e in presence.events(self.db, UTC, self.now) if e["kind"] == "presence.leave"]
        self.assertEqual(len(leave), 1)
        gap = notify._when(leave[0]["due"]) - notify._when(leave[0]["ts"])
        self.assertEqual(gap, timedelta(minutes=presence.grace_minutes(self.db)))
        # a 60-minute grace period: the departure is 61 min old, but known for 1 min only
        ev = {"kind": "presence.leave", "person_id": self.pid,
              "ts": iso(self.now - timedelta(minutes=61)), "due": iso(self.now - timedelta(minutes=1))}
        self.assertIsNotNone(notify.route(self.db, ev, self.now))
        ev2 = {k: v for k, v in ev.items() if k != "due"} | {"ts": iso(self.now - timedelta(minutes=62))}
        self.assertIsNone(notify.route(self.db, ev2, self.now))


# --- quiet hours -----------------------------------------------------------------------

class QuietTests(_Empty):
    def setUp(self):
        super().setUp()
        settings.update(self.db, {}, {"quiet.enabled": True, "quiet.start": "23:00",
                                      "quiet.end": "07:00"})
        store.set_meta(self.db, notify.PRIMED, "1")
        # 08:00 UTC: the night's window (23:00-07:00 UTC) ended an hour ago
        self.at = datetime(2026, 10, 20, 8, 0, tzinfo=UTC)

    def test_a_late_routed_event_from_inside_the_window_goes_to_its_summary(self):
        qs = notify.quiet_now(self.db, {}, self.at, UTC)
        self.assertIsNone(qs["active"])
        ev = {"kind": "alert.new", "key": "new|aa|x", "mac": "aa", "name": "Cam", "critical": False,
              "when": iso(self.at - timedelta(hours=4))}        # 04:00: inside the night
        self.assertIsNone(notify.route(self.db, ev, self.at, {}, qs))
        self.assertEqual(notify.release(self.db, self.at), [1])
        ev2 = {**ev, "key": "new|bb|x", "when": iso(self.at - timedelta(minutes=30))}   # after it
        self.assertIsNotNone(notify.route(self.db, ev2, self.at, {}, qs))

    def test_a_late_addition_reopens_a_closed_summary(self):
        ev = {"kind": "alert.new", "key": "k1", "mac": "aa", "name": "A", "critical": False,
              "when": iso(self.at - timedelta(hours=4))}
        qs = notify.quiet_now(self.db, {}, self.at, UTC)
        notify.route(self.db, ev, self.at, {}, qs)
        sid = notify.release(self.db, self.at)[0]
        self.assertTrue(notify.mark_seen(self.db, sid))
        notify.route(self.db, {**ev, "key": "k2"}, self.at, {}, qs)
        notify.release(self.db, self.at)
        row = self.db.execute("SELECT seen_at, items FROM quiet_summaries WHERE id = ?", (sid,)).fetchone()
        self.assertIsNone(row["seen_at"])
        self.assertEqual(len(json.loads(row["items"])), 2)

    def test_next_window_text_uses_the_weekday_override(self):
        # 08:00: the next window starts tonight, and tonight has its own hours
        settings.update(self.db, {}, {"quiet.days": f"{self.at.weekday()}=23:30-06:00"})
        d = quiet.describe(self.db, {}, "en", self.at, UTC)
        self.assertIn("23:30", d["text"])
        self.assertIn("06:00", d["text"])


# --- AI lookups ------------------------------------------------------------------------

class AiToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = store.connect(demo_copy(Path(cls.tmp.name) / "a.db"))

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.tmp.cleanup()
        cache.clear()

    def off_person(self):
        return next(p["name"] for p in store.people(self.db) if not p["presence"]
                    and presence.owned(self.db).get(p["name"]))

    def test_no_liveness_for_people_without_presence(self):
        who = self.off_person()
        r = ai_tools.run(self.db, "list_devices", {"person": who})
        self.assertTrue(r["devices"])
        self.assertNotIn("online_now", r)
        self.assertTrue(all("online" not in d and "last_active" not in d for d in r["devices"]))
        self.assertIn("presence", r["note"])
        self.assertEqual(ai_tools.run(self.db, "list_devices", {"person": who, "status": "online"})
                         ["error"], "presence_off")
        r = ai_tools.run(self.db, "top_domains", {"person": who, "window": "7d"})
        self.assertTrue(all("first_local" not in d and "last_local" not in d for d in r["domains"]))
        # the offline answer copes with it
        hit = ai_intents.r_devices(lambda n, a: ai_tools.run(self.db, n, a), lambda k, **kw:
                                   i18n.t(k, "en", **kw), {"person": who}, "en")
        self.assertIn("presence is off", hit[0])
        # ... while a person who opted in gets them
        on = next(p["name"] for p in store.people(self.db) if p["presence"])
        r = ai_tools.run(self.db, "list_devices", {"person": on})
        self.assertIn("online_now", r)

    def test_person_names_match_whole_words_only(self):
        who = store.people(self.db)[0]["name"]
        self.assertEqual(ai_tools.run(self.db, "list_devices", {"person": who + "XYZ"})["error"],
                         "unknown_person")
        self.assertNotIn("error", ai_tools.run(self.db, "list_devices", {"person": who}))
        ctx = ai_tools.Ctx(self.db)
        people.save(self.db, people.validate(self.db, {"name": "Anna Lee"}))
        try:
            self.assertEqual(ai_tools.resolve_person(ctx, "anna"), "Anna Lee")
            self.assertEqual(ai_tools.resolve_person(ctx, "Anna Lee's phone"), "Anna Lee")
            with self.assertRaises(ai_tools.ToolError):
                ai_tools.resolve_person(ctx, "Ann")
        finally:
            with self.db:
                self.db.execute("DELETE FROM people WHERE name = 'Anna Lee'")

    def test_whitespace_arguments_do_not_widen_the_scope(self):
        a = ai_tools.TOOLS["top_domains"].validate({"device": "   ", "window": "24h"})
        self.assertNotIn("device", a)
        with self.assertRaises(ai_tools.ToolError):
            ai_tools.TOOLS["device_detail"].validate({"device": "  "})

    def test_results_stay_inside_the_budget_after_redaction(self):
        r = redact.Redactor.build(self.db)
        s = ai_tools.Session(self.db, r, max_bytes=2000)
        data = 0
        for _ in range(6):
            content, ev = s.call("list_devices", {"limit": 50})
            if not ev.get("error"):         # real results; once spent: a short "limit" note
                data += len(content.encode())
        self.assertLessEqual(data, 2000)
        self.assertTrue(s.limited)
        self.assertNotIn("192.168.1.", content)        # redacted: no raw demo IPs

    def test_error_results_are_capped(self):
        err =ai_tools.ToolError("x", "y", {"candidates": ["n" * 100] * 200})
        tool = ai_tools.TOOLS["list_devices"]
        orig = tool.handler

        def boom(ctx, a):
            raise err
        object.__setattr__(tool, "handler", boom)
        try:
            r = ai_tools.run(self.db, "list_devices", {})
        finally:
            object.__setattr__(tool, "handler", orig)
        self.assertLessEqual(ai_tools._size(r), ai_tools.MAX_RESULT_BYTES)

    def test_one_character_cjk_names_are_redacted_in_free_text(self):
        r = redact.Redactor()
        r._short["媽"] = "[P9]"
        r.real["[P9]"] = "媽"
        self.assertEqual(r.redact("Phone · 媽"), "Phone · [P9]")


# --- brain / providers ----------------------------------------------------------------

class ProviderTests(unittest.TestCase):
    def tearDown(self):
        brain._NO_TOOLS.clear()

    def test_refusal_match_is_narrow(self):
        self.assertTrue(brain.tools_refused(400, "this model does not support tools"))
        self.assertTrue(brain.tools_refused(400, "tool_choice is not supported"))
        self.assertTrue(brain.tools_refused(501, "function calling not available"))
        self.assertFalse(brain.tools_refused(400, "tool_use ids must have a tool_result"))
        self.assertFalse(brain.tools_refused(400, "messages: text content blocks must be non-empty"))

    def test_a_refusal_is_forgotten_after_a_while(self):
        key = ("X", "", "m")
        brain._NO_TOOLS[key] = time.monotonic() - brain.NO_TOOLS_TTL - 1
        tmp = tempfile.TemporaryDirectory()
        db = store.connect(Path(tmp.name) / "b.db")
        try:
            self.assertTrue(brain.tools_plan(db, {}, "chat", True, key)["use"])
            brain._NO_TOOLS[key] = time.monotonic()
            self.assertEqual(brain.tools_plan(db, {}, "chat", True, key)["why"], "unsupported")
        finally:
            db.close()
            tmp.cleanup()

    def test_no_whitespace_only_text_blocks(self):
        conv = [{"role": "user", "content": "q"},
                {"role": "assistant", "text": "\n\n", "calls": [{"id": "t1", "name": "alerts", "args": {}}]}]
        blocks = brain.AnthropicProvider.wire(conv)[1]["content"]
        self.assertEqual([b["type"] for b in blocks], ["tool_use"])
        msgs = localai.OpenAICompatibleProvider.wire("s", conv)
        self.assertEqual(msgs[2]["content"], "")

    def test_parallel_calls_without_index_stay_separate(self):
        chunks = [
            {"choices": [{"delta": {"tool_calls": [{"id": "a", "function": {"name": "alerts", "arguments": ""}}]}}]},
            {"choices": [{"delta": {"tool_calls": [{"function": {"arguments": "{}"}}]}}]},
            {"choices": [{"delta": {"tool_calls": [{"id": "b", "function": {"name": "upnp", "arguments": "{\"x\""}}]}}]},
            {"choices": [{"delta": {"tool_calls": [{"function": {"arguments": ":1}"}}]}}]},
        ]

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["content-length"]))
                body = "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n"
                data = body.encode()
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            p = localai.OpenAICompatibleProvider(f"http://127.0.0.1:{srv.server_address[1]}/v1", "m")
            calls = [x for kind, x in p.stream_turn("s", [{"role": "user", "content": "q"}],
                                                    [{"name": "alerts", "description": "d",
                                                      "parameters": {"type": "object"}}]) if kind == "call"]
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual([(c["id"], c["name"], c["args"], c["ok"]) for c in calls],
                         [("a", "alerts", {}, True), ("b", "upnp", {"x": 1}, True)])


# --- small API edges ------------------------------------------------------------------

class EdgeTests(_Empty):
    def test_since_with_an_overflowing_date(self):
        self.assertIsNone(since.parse_since("0001-01-01T00:00:00+05:00"))

    def test_digits_are_ascii(self):
        self.assertFalse(web._digits("²"))
        self.assertTrue(web._digits("12"))
        det = live.Detector(Path(self.tmp.name) / "r.db", compute=lambda db: {})
        self.assertIsNone(det.resume(types.SimpleNamespace(cursor=0), f"{det.epoch}-²"))

    def test_restore_never_switches_presence_on(self):
        people.save(self.db, people.validate(self.db, {"name": "Ann"}))
        data = backup.validate(json.loads(json.dumps(backup.export(self.db))))
        data["people"]["Ann"]["presence"] = True
        data["people"]["Bob"] = {**data["people"]["Ann"], "presence": True}
        backup.restore(self.db, data, "merge")
        self.assertFalse(any(p["presence"] for p in store.people(self.db)))

    def test_a_risky_forward_is_not_also_stale(self):
        src = (ROOT / "netwarden" / "hygiene.py").read_text(encoding="utf-8")
        self.assertIn('not m["risky"]', src)
        self.assertEqual(hygiene.facts(self.db)["upnp_stale"], [])


class TuningWebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = str(demo_copy(Path(cls.tmp.name) / "t.db"))
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        cls.port = cls.srv.server_address[1]
        cls.origin = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        web.close_server(cls.srv)
        cls.tmp.cleanup()
        cache.clear()

    def setUp(self):
        self.addCleanup(self._restore)

    def _restore(self):
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))
        web.Handler.require_auth = False

    def req(self, method, path, body=None, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = {"user-agent": UA}
        if cookie:
            h["cookie"] = cookie
        if method == "POST":
            h["content-type"] = "application/json"
            h["origin"] = self.origin
        c.request(method, path, json.dumps(body or {}) if method == "POST" else None, h)
        r = c.getresponse()
        data = r.read()
        c.close()
        try:
            return r.status, json.loads(data)
        except ValueError:
            return r.status, None

    def pair(self) -> str:
        web.Handler.is_local_client = staticmethod(lambda ip: False)
        web.Handler.require_auth = True
        db = store.connect(self.path)
        code = pairing.new_code(db)["code"]
        db.close()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("POST", "/api/pair", json.dumps({"code": code}),
                  {"content-type": "application/json", "origin": self.origin, "user-agent": UA})
        r = c.getresponse()
        r.read()
        c.close()
        return (r.getheader("set-cookie") or "").split(";")[0]

    def test_unknown_fields_and_bad_timestamps_are_refused(self):
        st, j = self.req("POST", "/api/tuning", {"kind": "night", "level": "off", "snooze": "1h"})
        self.assertEqual(st, 400, j)
        bad = {"kind": "night", "before": [{"domain": "mute:night", "created_at": "soon", "until": None}]}
        self.assertEqual(self.req("POST", "/api/tuning/undo", bad)[0], 400)
        bad["before"][0].update(created_at=iso(datetime.now(UTC)), until="never")
        self.assertEqual(self.req("POST", "/api/tuning/undo", bad)[0], 400)

    def test_silencing_security_alerts_for_everyone_needs_this_computer_and_a_yes(self):
        st, j = self.req("POST", "/api/tuning", {"kind": "threat", "level": "off"})
        self.assertEqual(st, 400)
        self.assertEqual(j["error"], i18n.t("err.tune_confirm", "en"))
        st, j = self.req("POST", "/api/tuning", {"kind": "threat", "level": "off", "confirm": True})
        self.assertEqual(st, 200, j)
        self.assertEqual(self.req("POST", "/api/tuning/undo",
                                  {"kind": "threat", "before": j["before"]})[0], 200)
        cookie = self.pair()
        st, _ = self.req("POST", "/api/tuning", {"kind": "threat", "level": "off", "confirm": True},
                         cookie=cookie)
        self.assertEqual(st, 403)
        # less sensitive (keeps the malicious ones) and per-device stay open to a phone
        st, j = self.req("POST", "/api/tuning", {"kind": "threat", "level": "less"}, cookie=cookie)
        self.assertEqual(st, 200, j)
        self.req("POST", "/api/tuning/undo", {"kind": "threat", "before": j["before"]}, cookie=cookie)

    def test_profile_owner_reuses_the_person(self):
        db = store.connect(self.path)
        mac = db.execute("SELECT mac FROM devices WHERE is_self = 0 ORDER BY mac LIMIT 1").fetchone()[0]
        name = store.people(db)[0]["name"]
        n = len(store.people(db))
        db.close()
        st, j = self.req("POST", "/api/profile", {"mac": mac, "owner": name.upper() + " "})
        self.assertEqual(st, 200, j)
        self.assertEqual(j["profile"]["owner"], name)
        db = store.connect(self.path)
        self.assertEqual(len(store.people(db)), n)
        db.close()


# --- i18n --------------------------------------------------------------------------------

class I18nTests(unittest.TestCase):
    def test_taiwan_terms_and_punctuation(self):
        hant = json.loads((ROOT / "netwarden/locales/zh-Hant.json").read_text(encoding="utf-8"))
        self.assertNotIn("數據", hant["intent.traffic_none"])
        self.assertIn("數據", i18n.MAINLAND_TERMS)
        self.assertEqual([p for p in i18n.check() if p[2] == "mainland_term"], [])
        flagged = i18n.check({"en": {"a": "modem", "b": "data"},
                              "zh-Hant": {"a": "數據機", "b": "流量數據"}}, {})
        self.assertEqual([(p[1], p[2]) for p in flagged if p[0] == "zh-Hant"], [("b", "mainland_term")])
        for code in ("zh-Hant", "zh-Hans"):
            data = json.loads((ROOT / f"netwarden/locales/{code}.json").read_text(encoding="utf-8"))
            self.assertEqual([k for k, v in data.items() if isinstance(v, str) and "；" in v], [], code)

    def test_who_is_home_in_every_language(self):
        for lang, q in (("ru", "Кто дома?"), ("de", "Wer ist zu Hause?"), ("fr", "Qui est à la maison ?"),
                        ("es", "¿Quién está en casa?"), ("pt-BR", "Quem está em casa?"),
                        ("ko", "누가 집에 있어?"), ("id", "Siapa yang di rumah?"), ("hi", "घर पर कौन है?")):
            self.assertEqual(ai_intents.classify(q, lang), "presence", lang)


if __name__ == "__main__":
    unittest.main()
