"""Stage T: the network map, live updates (/api/stream + live.py), "Since your last
visit" (/api/since), the Overview bundle + ETag/304, undo everywhere.

Servers bind 127.0.0.1 on an ephemeral port only; "another device" is simulated with the
injectable Handler.is_local_client (never by binding a LAN address). No LLM, no network.
"""
import http.client
import json
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netwarden import activity, brain, demo, i18n, live, pairing, since, store, suggestions, web

ROOT = Path(__file__).resolve().parent.parent
_DEMO = {}


def demo_copy(dest: Path) -> str:
    """A private copy of one demo DB built once for this module."""
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


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- the change detector: pure parts ------------------------------------------------------

def _snap(**kw):
    base = {"devices": {"aa": True, "bb": False}, "alerts": {"a1": {"kind": "port", "mac": "aa", "sev": "warn"}},
            "inbox": 3, "sug": {"open": ["s1"], "done": []}, "pres": {"1": "home"}, "health": "ok",
            "settings": "1|x", "notes": "n"}
    base.update(kw)
    return base


class DiffTests(unittest.TestCase):
    def test_first_snapshot_is_the_baseline(self):
        self.assertEqual(live.diff(None, _snap()), [])
        self.assertEqual(live.diff(_snap(), _snap()), [])

    def test_devices(self):
        ev = live.diff(_snap(), _snap(devices={"aa": False, "bb": True, "cc": True}))
        self.assertIn({"type": "device_offline", "mac": "aa"}, ev)
        self.assertIn({"type": "device_online", "mac": "bb"}, ev)
        self.assertIn({"type": "device_new", "mac": "cc"}, ev)

    def test_alerts_inbox_sug_presence_health_settings_notes(self):
        new = _snap(alerts={"a1": {"kind": "port", "mac": "aa", "sev": "warn"},
                            "a2": {"kind": "threat", "mac": "bb", "sev": "bad"}},
                    inbox=4, sug={"open": [], "done": ["s1"]}, pres={"1": "away"}, health="warn",
                    settings="2|y", notes="m")
        types = {e["type"]: e for e in live.diff(_snap(), new)}
        self.assertEqual(types["alert_new"], {"type": "alert_new", "id": "a2", "kind": "threat",
                                              "mac": "bb", "sev": "bad"})
        self.assertEqual(types["inbox_changed"]["count"], 4)
        self.assertEqual(types["suggestion_changed"]["open"], 0)
        self.assertEqual(types["presence_changed"], {"type": "presence_changed", "person": 1, "state": "away"})
        self.assertEqual(types["health_changed"]["level"], "warn")
        self.assertIn("settings_changed", types)
        self.assertIn("notes_changed", types)
        self.assertTrue(set(types) <= set(live.EVENT_TYPES))

    def test_device_burst_is_capped(self):
        many = {f"m{i:03d}": True for i in range(live.MAX_DEVICE_EVENTS * 3)}
        ev = live.diff(_snap(devices={}), _snap(devices=many))
        self.assertEqual(len(ev), live.MAX_DEVICE_EVENTS)


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.state = {"n": 0}
        self.det = live.Detector(":memory:", compute=self._compute)
        self.det.fallback_s, self.det.debounce_s = 30.0, 0.01
        self.addCleanup(self.det.stop)

    def _compute(self, db):
        self.state["n"] += 0
        return _snap(inbox=self.state.get("inbox", 3))

    def test_caps(self):
        subs = [self.det.subscribe("192.168.1.20") for _ in range(live.MAX_PER_CLIENT)]
        with self.assertRaises(live.Full):
            self.det.subscribe("192.168.1.20")                    # per client
        subs += [self.det.subscribe(f"192.168.1.{30 + i}") for i in range(live.MAX_STREAMS - len(subs))]
        with self.assertRaises(live.Full):
            self.det.subscribe("192.168.1.99")                    # in total
        subs[0].close()
        self.det.subscribe("192.168.1.99").close()               # a closed one frees its place
        for s in subs:
            s.close()
        self.assertEqual(self.det.streams(), 0)

    def test_wait_publish_stop(self):
        sub = self.det.subscribe("127.0.0.1")
        self.assertEqual(sub.wait(0.05), [])                   # nothing yet: a heartbeat
        self.det.publish([{"type": "notes_changed"}])
        got = sub.wait(1)
        self.assertEqual([e["type"] for e in got], ["notes_changed"])
        self.assertRegex(got[0]["id"], r"^[0-9a-f]{8}-\d+$")
        self.det.stop()
        self.assertIsNone(sub.wait(1))                         # the stream ends

    def test_resume(self):
        sub = self.det.subscribe("127.0.0.1")
        first = self.det.last_id()
        self.det.publish([{"type": "notes_changed"}, {"type": "settings_changed"}])
        later = self.det.subscribe("127.0.0.2")
        missed = self.det.resume(later, first)
        self.assertEqual([e["type"] for e in missed], ["notes_changed", "settings_changed"])
        self.assertEqual(later.wait(0.01), [])                 # cursor moved past them
        self.assertEqual(self.det.resume(later, self.det.last_id()), [])
        self.assertIsNone(self.det.resume(later, "deadbeef-1"))               # another epoch
        self.assertIsNone(self.det.resume(later, self.det.epoch + "-999"))    # the future
        self.assertIsNone(self.det.resume(later, self.det.epoch + "-x"))
        self.det.publish([{"type": "notes_changed"}] * (live.RING + 5))
        self.assertIsNone(self.det.resume(later, first))      # fell out of the ring
        sub.close()
        later.close()

    def test_one_computation_for_many_streams(self):
        """The detector computes once per change, however many streams are open: never
        per-client polling."""
        subs = [self.det.subscribe(f"127.0.0.{i}") for i in range(1, 7)]
        deadline = time.monotonic() + 5
        while self.det.computations < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.det.computations, 1)            # the baseline, once
        self.state["inbox"] = 9
        self.det.poke()
        got = [s.wait(5) for s in subs]
        self.assertTrue(all([e["type"] for e in g] == ["inbox_changed"] for g in got), got)
        self.assertEqual(self.det.computations, 2)
        for s in subs:
            self.assertEqual(s.wait(0.2), [])                  # 0.2 s of six idle streams ...
        self.assertEqual(self.det.computations, 2)            # ... cost no computation
        for s in subs:
            s.close()

    def test_registry_and_poke(self):
        d = live.detector("/tmp/nw_t_registry.db")
        self.assertIs(live.detector("/tmp/../tmp/nw_t_registry.db"), d)
        d.wake.clear()
        live.poke("/tmp/nw_t_registry.db")
        self.assertTrue(d.wake.is_set())
        live.poke("/tmp/nw_t_nobody.db")                       # no detector: nothing happens
        d.stop()
        self.assertIsNot(live.detector("/tmp/nw_t_registry.db"), d)   # a stopped one is replaced
        live.detector("/tmp/nw_t_registry.db").stop()


class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = demo_copy(Path(cls.tmp.name) / "s.db")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_real_snapshot_and_changes(self):
        det = live.Detector(self.path)
        db = store.connect(self.path)
        try:
            self.assertEqual(det.check(db), [])                # the baseline
            snap = det.base
            self.assertEqual(set(snap), {"devices", "alerts", "inbox", "sug", "pres", "health",
                                         "settings", "notes"})
            self.assertTrue(snap["devices"])
            json.dumps(snap)                                    # compact, plain values
            store.upsert_device(db, {"ip": "192.168.1.250", "mac": "02:11:22:33:44:55", "vendor": "",
                                     "hostname": "newcomer", "randomized": True, "is_self": False})
            mac = next(iter(snap["devices"]))
            store.set_label(db, mac, "Living room TV", "")
            types = [e["type"] for e in det.check(db)]
            self.assertIn("device_new", types)
            self.assertIn("notes_changed", types)
            self.assertEqual(det.check(db), [])                 # nothing new: nothing sent
        finally:
            db.close()


class SinceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = demo_copy(Path(cls.tmp.name) / "since.db")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_demo_story(self):
        """A visit ~12 h ago on the demo comes back to a short, believable list."""
        db = store.connect(self.path)
        try:
            now = datetime.now(timezone.utc)
            r = since.report(db, _iso(now - timedelta(hours=12)), "en")
            self.assertEqual(r["devices"]["n"], 1)               # the robot vacuum, 6 h ago
            # the fix that took effect is the parents' school-night bedtime rule: it covers
            # the tablet's 01:00 lookups only when last night was a school night (Sun-Thu).
            # On Fri/Sat nights the rule does not apply, so the bedtime suggestion is open
            # again - a weekday fact, not a flake (this test failed every weekend before)
            tz = activity.local_tz()
            burst = demo.night_burst_windows(now, tz)[0][0].astimezone(tz)
            school_night = (burst - timedelta(hours=12)).weekday() in demo.SCHOOL_NIGHTS
            tablet = next(d["mac"] for d in demo.DEVICES if d.get("night_burst"))
            bedtime_ids = {e["id"] for e in r["effects"]["items"]}
            if school_night:
                self.assertIn(f"bedtime:{tablet}", bedtime_ids)
            else:
                self.assertNotIn(f"bedtime:{tablet}", bedtime_ids)
                self.assertIn(f"bedtime:{tablet}",
                              {a["id"] for a in suggestions.detect(db, {})["active"]})
            # the long-known findings were seen two days ago (outages / arrivals sit at
            # fixed local times, so their counts depend on when the test runs)
            self.assertFalse({a["kind"] for a in r["alerts"]["items"]} & set(demo.SEEN_KINDS))
            self.assertLessEqual(r["alerts"]["n"], 6)
            self.assertIn("spike", {a["kind"] for a in r["alerts"]["items"]})   # 9-11 h ago
        finally:
            db.close()

    def test_parse(self):
        now = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
        self.assertEqual(since.parse_since("2026-10-01T10:00:00Z", now), "2026-10-01T10:00:00.000000Z")
        self.assertEqual(since.parse_since("2026-10-01T18:00:00+08:00", now), "2026-10-01T10:00:00.000000Z")
        self.assertEqual(since.parse_since("2025-01-01T00:00:00Z", now), _iso(now - since.MAX_SPAN))
        for bad in (None, "", "yesterday", "2026-10-02T00:00:00Z", "x" * 41, "2026-13-01"):
            self.assertIsNone(since.parse_since(bad, now), bad)

    def test_report(self):
        db = store.connect(self.path)
        try:
            t = _iso(datetime.now(timezone.utc) - timedelta(minutes=1))
            store.upsert_device(db, {"ip": "192.168.1.251", "mac": "02:aa:bb:cc:dd:01", "vendor": "",
                                     "hostname": "<b>guest</b>", "randomized": True, "is_self": False})
            r = since.report(db, t, "en")
            self.assertEqual(set(r), {"since", "total", "devices", "alerts", "outages", "arrivals", "effects"})
            self.assertEqual([d["mac"] for d in r["devices"]["items"]], ["02:aa:bb:cc:dd:01"])
            self.assertEqual(r["total"], sum(r[k]["n"] for k in ("devices", "alerts", "outages", "arrivals", "effects")))
            week = since.report(db, _iso(datetime.now(timezone.utc) - timedelta(days=7)), "zh-Hant")
            self.assertGreaterEqual(week["devices"]["n"], 1)
            self.assertGreaterEqual(week["outages"]["n"], 1)   # the demo's outages
            for k in ("devices", "alerts", "outages", "arrivals", "effects"):
                self.assertLessEqual(len(week[k]["items"]), since.MAX_ITEMS)
            for d in week["devices"]["items"]:
                self.assertNotRegex(d["name"], r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")   # never a bare MAC
        finally:
            db.close()


# --- the web server -----------------------------------------------------------------------

class SSE:
    """A raw /api/stream reader (http.client buffers; a socket shows the frames as sent)."""

    def __init__(self, port, path="/api/stream", headers=None, timeout=5):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        h = {"host": f"127.0.0.1:{port}", "accept": "text/event-stream", **(headers or {})}
        req = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
        self.sock.sendall(req.encode())
        self.buf = b""
        head = self._until(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        self.status = int(lines[0].split()[1])
        self.headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:] if ln)}

    def _until(self, mark: bytes) -> bytes:
        while mark not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError(self.buf)
            self.buf += chunk
        out, _, self.buf = self.buf.partition(mark)
        return out

    def frame(self) -> dict:
        """The next frame: {"comment": ...} or {"id", "event", "data", "retry"}."""
        raw = self._until(b"\n\n").decode("utf-8")
        out = {}
        for ln in raw.split("\n"):
            k, _, v = ln.partition(":")
            v = v[1:] if v.startswith(" ") else v
            out["comment" if k == "" else k] = v
        if "data" in out:
            out["data"] = json.loads(out["data"])
        return out

    def until_event(self, name, limit=50) -> dict:
        for _ in range(limit):
            f = self.frame()
            if f.get("event") == name:
                return f
        raise AssertionError(f"no {name} event")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class WebStageT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = demo_copy(Path(cls.tmp.name) / "web.db")
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        cls.port = cls.srv.server_address[1]
        cls.origin = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.old_hb = web.Handler.STREAM_HEARTBEAT

    @classmethod
    def tearDownClass(cls):
        web.Handler.STREAM_HEARTBEAT = cls.old_hb
        cls.srv.shutdown()
        web.close_server(cls.srv)
        cls.tmp.cleanup()

    def setUp(self):
        web.Handler.STREAM_HEARTBEAT = 0.2
        web.Handler.limiter = pairing.Limiter()
        self.streams = []
        self.addCleanup(self._restore)

    def _restore(self):
        for s in self.streams:
            s.close()
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))
        web.Handler.require_auth = False
        deadline = time.monotonic() + 5     # the server notices closed streams at the next heartbeat
        while self.srv.live.streams() and time.monotonic() < deadline:
            time.sleep(0.05)
        db = store.connect(self.path)
        pairing.revoke_all(db)
        db.close()

    def drop(self, s: SSE):
        """Close a stream and wait until the server let go of it (next heartbeat)."""
        n = self.srv.live.streams()
        s.close()
        deadline = time.monotonic() + 5
        while self.srv.live.streams() >= n and time.monotonic() < deadline:
            time.sleep(0.02)

    def stream(self, path="/api/stream", **kw) -> SSE:
        s = SSE(self.port, path, **kw)
        self.streams.append(s)
        return s

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = dict(headers or {})
        if method == "POST":
            h.update({"content-type": "application/json", "origin": self.origin})
        c.request(method, path, json.dumps(body or {}) if method == "POST" else None, h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, r, data

    def get_json(self, path, headers=None):
        st, r, data = self.req("GET", path, headers=headers)
        self.assertEqual(st, 200, data[:200])
        return json.loads(data), r

    # --- SSE -------------------------------------------------------------------------

    def test_framing_heartbeat_and_headers(self):
        s = self.stream()
        self.assertEqual(s.status, 200)
        self.assertTrue(s.headers["content-type"].startswith("text/event-stream"))
        self.assertEqual(s.headers["cache-control"], "no-store")
        self.assertEqual(s.headers["x-content-type-options"], "nosniff")
        self.assertIn("content-security-policy", s.headers)
        self.assertNotIn("content-length", s.headers)
        self.assertEqual(s.frame(), {"retry": str(web.STREAM_RETRY_MS)})
        hello = s.frame()
        self.assertEqual(hello["event"], "hello")
        self.assertEqual(hello["id"], hello["data"]["id"])
        self.assertEqual(s.frame(), {"comment": "hb"})        # ": hb" every STREAM_HEARTBEAT
        self.assertEqual(s.frame(), {"comment": "hb"})

    def test_a_post_pushes_an_event_and_resume(self):
        s = self.stream()
        hello = s.until_event("hello")
        time.sleep(0.6)                                        # the detector's baseline
        db = store.connect(self.path)
        mac = db.execute("SELECT mac FROM devices WHERE is_self = 0 ORDER BY mac LIMIT 1").fetchone()[0]
        db.close()
        st, _r, data = self.req("POST", "/api/label", {"mac": mac, "label": "Hall cam <i>", "note": ""})
        self.assertEqual(st, 200, data)
        ev = s.until_event("notes_changed")
        self.assertRegex(ev["id"], r"^[0-9a-f]{8}-\d+$")
        self.assertEqual(ev["data"]["type"], "notes_changed")
        self.drop(s)
        # a reconnect with Last-Event-ID = hello gets what it missed, then hello
        again = self.stream(headers={"last-event-id": hello["id"]})
        self.assertEqual(again.frame()["retry"], str(web.STREAM_RETRY_MS))
        self.assertEqual(again.frame()["event"], "notes_changed")
        self.assertEqual(again.frame()["event"], "hello")
        # ?last= works the same (EventSource cannot set headers on the first connect)
        q = self.stream(path="/api/stream?last=" + ev["id"])
        q.frame()
        self.assertEqual(q.frame()["event"], "hello")
        self.drop(again)
        self.drop(q)
        # an id from another epoch (a restart): resync, then hello
        old = self.stream(headers={"last-event-id": "0badbeef-12"})
        old.frame()
        self.assertEqual(old.frame()["event"], "resync")
        self.assertEqual(old.frame()["event"], "hello")
        self.req("POST", "/api/label", {"mac": mac, "label": "", "note": ""})

    def test_caps(self):
        for _ in range(live.MAX_PER_CLIENT):
            self.assertEqual(self.stream().status, 200)
        extra = self.stream()
        self.assertEqual(extra.status, 429)
        self.assertEqual(extra.headers["retry-after"], "30")
        self.assertEqual(json.loads(extra._until(b"}") + b"}")["error"],
                         i18n.t("err.too_many_streams", "en"))
        self.streams[0].close()
        deadline = time.monotonic() + 5
        while self.srv.live.streams() >= live.MAX_PER_CLIENT and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.stream().status, 200)            # its place is free again

    def test_host_and_lan_auth(self):
        bad = self.stream(headers={"host": "evil.example:80"})
        self.assertEqual(bad.status, 421)
        web.Handler.is_local_client = staticmethod(lambda ip: False)   # "another device"
        self.assertEqual(self.stream().status, 401)
        db = store.connect(self.path)
        code = pairing.new_code(db)["code"]
        token, _sid = pairing.redeem(db, code, "test-phone")
        db.close()
        ok = self.stream(headers={"cookie": f"{pairing.COOKIE}={token}"})
        self.assertEqual(ok.status, 200)
        ok.until_event("hello")
        db = store.connect(self.path)
        pairing.revoke_all(db)                                 # revoked: the stream ends
        db.close()
        with self.assertRaises((EOFError, ConnectionError, socket.timeout)):
            for _ in range(40):
                ok.frame()
        web.Handler.require_auth = True                        # REQUIRE_AUTH=1: loopback too
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))
        self.assertEqual(self.stream().status, 401)

    def test_streams_never_take_a_data_gate_slot(self):
        """DATA_GATE: open streams (as many as one client may have) never block or slow
        the page's data requests."""
        gate = web.Handler.DATA_GATE
        t0 = time.perf_counter()
        self.get_json("/api/score?lang=en")
        alone = time.perf_counter() - t0
        for _ in range(live.MAX_PER_CLIENT):
            self.stream().until_event("hello")
        self.assertEqual(gate._value, 2)                       # no slot held by a stream
        t0 = time.perf_counter()
        with ThreadPoolExecutor(4) as ex:
            got = list(ex.map(lambda p: self.req("GET", p)[0],
                              ["/api/score?lang=en", "/api/inventory?lang=en", "/api/meta", "/api/notify?lang=en"]))
        took = time.perf_counter() - t0
        self.assertEqual(got, [200, 200, 200, 200])
        self.assertLess(took, max(5.0, 20 * alone))            # not stuck behind the streams

    # --- ETag / 304 + the bundle ------------------------------------------------------

    def test_etag_304_and_never_stale(self):
        body, r = self.get_json("/api/inventory?lang=en")
        tag = r.getheader("etag")
        self.assertRegex(tag, r'^"[0-9a-f]{20}"$')
        self.assertEqual(r.getheader("cache-control"), "no-store")
        st, r2, data = self.req("GET", "/api/inventory?lang=en", headers={"if-none-match": tag})
        self.assertEqual((st, data), (304, b""))
        self.assertEqual(r2.getheader("etag"), tag)
        mac = body["devices"][0]["mac"]
        self.req("POST", "/api/label", {"mac": mac, "label": "Changed name", "note": ""})
        st, r3, data = self.req("GET", "/api/inventory?lang=en", headers={"if-none-match": tag})
        self.assertEqual(st, 200)                              # changed: a fresh body
        self.assertNotEqual(r3.getheader("etag"), tag)
        self.req("POST", "/api/label", {"mac": mac, "label": "", "note": ""})
        st, _r, _d = self.req("GET", "/api/meta", headers={"if-none-match": '"nope"'})
        self.assertEqual(st, 200)

    def test_bundle_equals_the_individual_endpoints(self):
        self.get_json("/api/overview?lang=zh-Hant")            # warm the cache: same moment below
        ov, r = self.get_json("/api/overview?lang=zh-Hant")
        self.assertEqual(set(ov["parts"]), set(web.OVERVIEW))
        for name, path in web.OVERVIEW.items():
            one, r1 = self.get_json(path + ("&" if "?" in path else "?") + "lang=zh-Hant")
            self.assertEqual(ov["etags"][name], r1.getheader("etag"), name)
            strip = lambda d: {k: v for k, v in d.items() if k != "generated"}   # a clock stamp
            self.assertEqual(strip(ov["parts"][name]), strip(one), name)
        st, _r, data = self.req("GET", "/api/overview?lang=zh-Hant", headers={"if-none-match": r.getheader("etag")})
        self.assertIn(st, (200, 304))
        if st == 304:
            self.assertEqual(data, b"")

    def test_since_endpoint(self):
        st, _r, data = self.req("GET", "/api/since?t=garbage&lang=en")
        self.assertEqual(st, 400)
        self.assertEqual(json.loads(data)["error"], i18n.t("err.bad_since", "en"))
        self.assertEqual(self.req("GET", "/api/since")[0], 400)
        t = _iso(datetime.now(timezone.utc) - timedelta(days=3))
        r, _ = self.get_json("/api/since?t=" + t + "&lang=en")
        self.assertEqual(r["since"], t)
        self.assertIn("total", r)

    def test_assets(self):
        self.assertIn("map.js", web.ASSETS)
        st, r, data = self.req("GET", "/static/map.js")
        self.assertEqual(st, 200)
        self.assertIn(b"function layout", data)
        page = self.req("GET", "/")[2].decode()
        self.assertIn("/static/map.js?v=", page)
        self.assertLess(page.index("/static/map.js"), page.index("/static/app.js"))
        sw = (ROOT / "netwarden" / "static" / "sw.js").read_text(encoding="utf-8")
        self.assertIn("path.startsWith('/api/')", sw)   # the stream is never cached (Stage H: below ROOT)


# --- the dashboard's code -----------------------------------------------------------------

class DashboardCodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")

    def test_two_innerhtml_writes(self):
        self.assertEqual(len(re.findall(r"\.innerHTML\s*=", self.js)), 2)

    def test_live_client(self):
        self.assertIn("new EventSource(url('/api/stream')", self.js)   # Stage H: base-aware
        for st in ("live", "reconnecting", "paused"):
            self.assertIn(f"liveState('{st}')", self.js)
        # every event type the server sends is handled
        for t in live.EVENT_TYPES:
            self.assertRegex(self.js, r"\b" + t + r":\s*\[")
        self.assertIn("visibilitychange", self.js)

    def test_undo_everywhere(self):
        self.assertIn("undoPush(opts.undo", self.js)            # every Undo toast is on the stack
        self.assertRegex(self.js, r"e\.key === 'z'|key\.toLowerCase\(\) === 'z'")
        for fn in ("toggleBedRule", "presNotify"):
            self.assertRegex(self.js, fn + r"\([^)]*true\)")    # their undo re-runs with undoing=true

    def test_locale_keys_used_by_stage_t_exist(self):
        en = json.loads((ROOT / "netwarden" / "locales" / "en.json").read_text(encoding="utf-8"))
        keys = set(re.findall(r"T\('((?:app\.(?:map|since|live|key)|app\.bed\.o)[a-z0-9_.]*)'", self.js))
        keys |= {f"app.map.st.{s}" for s in ("alert", "blind", "new", "online", "offline")}
        keys |= {f"app.live.{s}{x}" for s in ("live", "reconnecting", "paused") for x in ("", "_hint")}
        keys |= {f"app.since.{k}" for k in ("devices", "alerts", "outages", "arrivals", "effects")}
        keys = {k for k in keys if not k.endswith(".")}
        missing = sorted(k for k in keys if k not in en)
        self.assertEqual(missing, [])

    @unittest.skipUnless(shutil.which("node"), "node is not installed here")
    def test_map_layout_with_node(self):
        r = subprocess.run(["node", str(ROOT / "tests" / "js" / "map_layout_test.js")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
