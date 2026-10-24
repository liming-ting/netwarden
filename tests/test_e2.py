"""
Stage E2: streaming AI replies, the read-side cache, runner warm-up and the perf DB.

- brain.sse_events (the SSE parser), AnthropicProvider.stream against a FAKE local SSE
  server (ENDPOINT pointed at an ephemeral 127.0.0.1 port: no real network, no budget)
- brain.clean_messages / stream_reply with fake providers and the offline provider
- POST /api/chat/stream: frames, done / error events, validation, secrets masked,
  the client hanging up (Stop) closes the provider's generator
- netwarden.cache: hits, invalidation by any data or user-note change, TTL, copies,
  in-memory DBs never cached
- runner: data loops warm the cache after a successful run (never the LLM)
- scripts/perf_db.py at a tiny size: builds, rebuilds, refuses foreign DBs, benches
"""
import contextlib
import http.client
import importlib.util
import io
import json
import logging
import sqlite3
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from netwarden import (alerts, brain, cache, demo, devicetype, i18n, offline_ai, runner,
                       store, web)

ROOT = Path(__file__).resolve().parent.parent
SECRET = "sk-ant-test-0123456789abcdef"


def _mac(hostname):
    return next(d["mac"] for d in demo.DEVICES if d["hostname"] == hostname)


CAM = _mac("ipcam")


# --- SSE parsing + the Anthropic streaming client ------------------------------------

def _sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


ANTHROPIC_OK = (
    _sse("message_start", {"type": "message_start", "message": {"id": "m1"}})
    + _sse("content_block_start", {"type": "content_block_start", "index": 0,
                                   "content_block": {"type": "text", "text": ""}})
    + ": keep-alive comment\n\n"
    + _sse("ping", {"type": "ping"})
    + _sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                   "delta": {"type": "text_delta", "text": "Hello "}})
    + _sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                   "delta": {"type": "text_delta", "text": "家庭 network."}})
    + _sse("content_block_stop", {"type": "content_block_stop", "index": 0})
    + _sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}})
    + _sse("message_stop", {"type": "message_stop"})
    + _sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                   "delta": {"type": "text_delta", "text": "AFTER-STOP"}}))

ANTHROPIC_ERR = (
    _sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "text_delta", "text": "partial"}})
    + _sse("error", {"type": "error", "error": {"type": "overloaded_error",
                                                "message": "Overloaded"}}))


class FakeAnthropic(BaseHTTPRequestHandler):
    """Plays the Messages API: `mode` picks the canned answer; requests are recorded."""
    mode = "ok"
    seen = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        FakeAnthropic.seen.append({"body": body, "key": self.headers.get("x-api-key"),
                                   "accept": self.headers.get("accept")})
        if self.mode == "http_error":
            payload = json.dumps({"type": "error", "error": {"type": "overloaded_error",
                                                             "message": "Overloaded"}}).encode()
            self.send_response(529)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if not body.get("stream"):
            payload = json.dumps({"content": [{"type": "text", "text": "whole answer"}]}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        text = ANTHROPIC_OK if self.mode == "ok" else ANTHROPIC_ERR
        if self.mode == "cut":
            text = ANTHROPIC_OK.split("event: content_block_stop")[0]
        for line in text.splitlines(keepends=True):
            self.wfile.write(line.replace("\n", "\r\n").encode())
        self.wfile.flush()

    def log_message(self, *a):
        pass


class SseParserTests(unittest.TestCase):
    def test_events_comments_multiline_and_bad_json(self):
        raw = [b": hello\n", b"event: a\n", b'data: {"x":\n', b"data: 1}\n", b"\n",
               b"data: not json\n", b"\n", b"data: [1, 2]\n", b"\n", b"\n",
               b"event: tail\n", b'data: {"y": 2}\n']
        self.assertEqual(list(brain.sse_events(raw)), [
            ("a", {"x": 1}), ("message", {"raw": "not json"}), ("message", {"raw": [1, 2]}),
            ("tail", {"y": 2})])

    def test_crlf_and_utf8(self):
        raw = ['event: e\r\n', 'data: {"t": "台灣"}\r\n', '\r\n']
        self.assertEqual(list(brain.sse_events([s.encode() for s in raw])),
                         [("e", {"t": "台灣"})])


class AnthropicStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeAnthropic)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}/v1/messages"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        FakeAnthropic.mode, FakeAnthropic.seen = "ok", []
        self.p = brain.AnthropicProvider(SECRET, model="test-model", timeout=5)
        self.p.ENDPOINT = self.url

    def test_stream_yields_text_deltas_until_message_stop(self):
        self.assertEqual(list(self.p.stream("SYS", "USER", max_tokens=99)),
                         ["Hello ", "家庭 network."])
        req = FakeAnthropic.seen[0]
        self.assertTrue(req["body"]["stream"])
        # the answer budget + room for the model's thinking (else thinking can eat it all)
        self.assertEqual(req["body"]["max_tokens"], 99 + brain.AnthropicProvider.THINKING_HEADROOM)
        self.assertEqual(req["body"]["system"], "SYS")
        self.assertEqual(req["key"], SECRET)
        self.assertEqual(req["accept"], "text/event-stream")

    def test_error_event_raises_after_partial_text(self):
        FakeAnthropic.mode = "error"
        got = []
        with self.assertRaises(brain.LLMError) as cm:
            for t in self.p.stream("s", "u"):
                got.append(t)
        self.assertEqual(got, ["partial"])
        self.assertIn("Overloaded", str(cm.exception))

    def test_http_error_raises_llm_error(self):
        FakeAnthropic.mode = "http_error"
        with self.assertRaises(brain.LLMError) as cm:
            list(self.p.stream("s", "u"))
        self.assertIn("529", str(cm.exception))
        self.assertIn("Overloaded", str(cm.exception))

    def test_stream_cut_short_just_ends(self):
        # no message_stop: the generator ends with what arrived (the caller decides)
        FakeAnthropic.mode = "cut"
        self.assertEqual("".join(self.p.stream("s", "u")), "Hello 家庭 network.")

    def test_unreachable_is_llm_error(self):
        self.p.ENDPOINT = "http://127.0.0.1:9/v1/messages"
        with self.assertRaises(brain.LLMError):
            list(self.p.stream("s", "u"))

    def test_non_streaming_complete_still_works(self):
        self.assertEqual(self.p.complete("s", "u"), "whole answer")
        self.assertNotIn("stream", FakeAnthropic.seen[0]["body"])


# --- stream_reply ----------------------------------------------------------------------

class StreamingFake:
    def __init__(self):
        self.calls = []

    def stream(self, system, user, max_tokens=1200):
        self.calls.append((system, user, max_tokens))
        yield "one "
        yield "two"


class CompleteOnlyFake:
    def complete(self, system, user, max_tokens=1200):
        return "all at once"


class StreamReplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        cls.db = store.connect(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.tmp.cleanup()

    def test_clean_messages(self):
        self.assertIsNone(brain.clean_messages("hi"))
        self.assertIsNone(brain.clean_messages([{"role": "system", "content": "x"}]))
        self.assertIsNone(brain.clean_messages([{"role": "user", "content": 3}]))
        self.assertIsNone(brain.clean_messages(["x"]))
        self.assertEqual(brain.clean_messages([]), [])
        long = [{"role": "user", "content": "q" * 20000, "extra": 1}] * 40
        out = brain.clean_messages(long)
        self.assertEqual(len(out), brain.MAX_TURNS)
        self.assertEqual(len(out[0]["content"]), brain.MAX_TURN_CHARS)
        self.assertEqual(set(out[0]), {"role", "content"})

    def test_streaming_provider_chat_with_focus(self):
        p = StreamingFake()
        msgs = [{"role": "user", "content": "Is it OK?"}]
        self.assertEqual("".join(brain.stream_reply(self.db, p, "chat", msgs, lang="en",
                                                    mac=CAM)), "one two")
        system, user, max_tokens = p.calls[0]
        self.assertIn(CAM, system)                       # the FOCUS paragraph
        self.assertIn("Is it OK?", user)
        self.assertEqual(max_tokens, 1200)

    def test_unknown_focus_mac_is_ignored(self):
        p = StreamingFake()
        list(brain.stream_reply(self.db, p, "chat", [{"role": "user", "content": "q"}],
                                mac="00:00:00:00:00:00"))
        self.assertNotIn("00:00:00:00:00:00", p.calls[0][0])

    def test_insight_and_complete_only_provider(self):
        p = StreamingFake()
        list(brain.stream_reply(self.db, p, "insight", lang="en"))
        self.assertEqual(p.calls[0][2], 1500)
        self.assertEqual(list(brain.stream_reply(self.db, CompleteOnlyFake(), "insight")),
                         ["all at once"])

    def test_offline_streams_line_by_line(self):
        p = brain.provider_from_env({})
        chunks = list(brain.stream_reply(self.db, p, "insight", lang="en"))
        self.assertGreater(len(chunks), 3)
        snap = brain.snapshot(self.db, hours=24)
        self.assertEqual("".join(chunks), p.answer(self.db, snap, "en"))

    def test_offline_focus_puts_the_device_first(self):
        p = brain.provider_from_env({})
        text = "".join(brain.stream_reply(self.db, p, "chat",
                                          [{"role": "user", "content": "why?"}],
                                          lang="en", mac=CAM))
        name = store.device_names(self.db)[CAM]
        title = i18n.t("offline.focus_title", "en", name=name)
        self.assertIn(title, text)
        self.assertLess(text.index(title), len(text) // 2)
        zh = "".join(brain.stream_reply(self.db, p, "chat",
                                        [{"role": "user", "content": "為什麼?"}],
                                        lang="zh-Hant", mac=CAM))
        self.assertIn(i18n.t("offline.focus_title", "zh-Hant", name=name), zh)

    def test_chunks_roundtrip(self):
        text = "a\nb\r\n\nc"
        self.assertEqual("".join(offline_ai.chunks(text)), text)
        self.assertEqual(list(offline_ai.chunks("")), [])


# --- POST /api/chat/stream -------------------------------------------------------------

class SlowFake:
    """Streams forever (slowly) - for the client-abort test."""
    def __init__(self):
        self.closed = threading.Event()
        self.sent = 0

    def stream(self, system, user, max_tokens=1200):
        try:
            for _ in range(400):
                self.sent += 1
                yield "x" * 64
                time.sleep(0.02)
        finally:
            self.closed.set()


class FailingFake:
    def __init__(self, exc):
        self.exc = exc

    def stream(self, system, user, max_tokens=1200):
        yield "start "
        raise self.exc


class ChatStreamEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        cls._orig = brain.provider_from_env
        cls.provider = None              # None -> the real selection (offline: no key)
        brain.provider_from_env = lambda env, db=None: cls.provider or cls._orig({})
        web.Handler.db_path = str(cls.path)
        web.Handler.env = {"ANTHROPIC_API_KEY": SECRET}
        web.Handler.lang = "zh-Hant"
        web.Handler.hours = 24
        web.Handler.loops = None
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        brain.provider_from_env = cls._orig
        cls.tmp.cleanup()

    def setUp(self):
        type(self).provider = None

    def post(self, obj, ctype="application/json"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request("POST", "/api/chat/stream", json.dumps(obj), {"content-type": ctype})
        return c, c.getresponse()

    def frames(self, obj):
        c, r = self.post(obj)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("content-type"), "text/event-stream; charset=utf-8")
        self.assertEqual(r.getheader("cache-control"), "no-store")
        out = list(brain.sse_events(iter(r.fp.readline, b"")))
        c.close()
        return out

    def test_offline_chat_streams_then_done(self):
        out = self.frames({"mode": "chat", "lang": "en", "mac": CAM,
                           "messages": [{"role": "user", "content": "Why is it risky?"}]})
        self.assertEqual(out[-1], ("done", {}))
        # Stage A: besides text, an offline answer may add `tool` / `suggest` events
        texts = [d["t"] for e, d in out[:-1] if e == "message"]
        self.assertTrue(all(e in ("message", "tool", "suggest", "status", "note")
                            for e, _d in out[:-1]))
        self.assertGreater(len(texts), 3)
        self.assertIn("🔎", "".join(texts))

    def test_insight_needs_no_messages_and_follows_lang(self):
        en = "".join(d.get("t", "") for _e, d in self.frames({"mode": "insight", "lang": "en"}))
        ja = "".join(d.get("t", "") for _e, d in self.frames({"mode": "insight", "lang": "ja"}))
        self.assertTrue(en and ja)
        self.assertNotEqual(en, ja)

    def test_fake_provider_chunks_pass_through(self):
        type(self).provider = StreamingFake()
        out = self.frames({"mode": "chat", "messages": [{"role": "user", "content": "q"}]})
        # round 7 C: the answer's usage comes last (a fake reports nothing: an estimate)
        usage = [d for e, d in out if e == "usage"]
        self.assertEqual(len(usage), 1)
        self.assertTrue(usage[0]["estimated"])
        self.assertEqual([f for f in out if f[0] != "usage"],
                         [("message", {"t": "one "}), ("message", {"t": "two"}), ("done", {})])

    def test_bad_requests(self):
        for body, err in (({"mode": "poem", "messages": []}, "bad_json"),
                          ({"mode": "chat", "messages": "hi"}, "bad_json"),
                          ({"mode": "chat", "messages": [{"role": "x", "content": "q"}]}, "bad_json"),
                          ({"mode": "chat", "mac": 5,
                            "messages": [{"role": "user", "content": "q"}]}, "bad_json"),
                          ({"mode": "chat", "messages": []}, "empty_question"),
                          ({"mode": "chat", "messages": [{"role": "user", "content": "  "}]},
                           "empty_question"),
                          ({"mode": "chat", "messages": [{"role": "assistant", "content": "a"}]},
                           "empty_question")):
            c, r = self.post(body)
            self.assertEqual(r.status, 400, body)
            self.assertEqual(json.loads(r.read())["error"], i18n.t("err." + err, "zh-Hant"), body)
            c.close()
        c, r = self.post({"mode": "insight"}, ctype="text/plain")
        self.assertEqual(r.status, 415)
        c.close()

    def test_llm_error_becomes_a_masked_error_event(self):
        type(self).provider = FailingFake(brain.LLMError(f"Anthropic API 401: bad key {SECRET}"))
        out = self.frames({"mode": "chat", "messages": [{"role": "user", "content": "q"}]})
        self.assertEqual(out[0], ("message", {"t": "start "}))
        event, data = out[-1]
        self.assertEqual(event, "error")
        self.assertIn("401", data["error"])
        self.assertNotIn(SECRET, data["error"])
        self.assertNotIn("done", [e for e, _d in out])

    def test_unexpected_error_is_a_localized_generic_message(self):
        type(self).provider = FailingFake(KeyError("internal detail"))
        with self.assertLogs("netwarden.web", "WARNING"):
            out = self.frames({"mode": "chat", "lang": "de",
                               "messages": [{"role": "user", "content": "q"}]})
        self.assertEqual(out[-1], ("error", {"error": i18n.t("err.stream_failed", "de")}))

    def test_client_hanging_up_stops_the_provider(self):
        slow = type(self).provider = SlowFake()
        c, r = self.post({"mode": "chat", "messages": [{"role": "user", "content": "q"}]})
        self.assertEqual(r.status, 200)
        r.fp.readline()
        r.close()                        # the Stop button: abort the fetch
        c.close()
        self.assertTrue(slow.closed.wait(10), "generator was not closed")
        self.assertLess(slow.sent, 400)

    def test_old_endpoints_mask_secrets_too(self):
        type(self).provider = type("P", (), {"complete": lambda self, s, u, max_tokens=0: (
            _ for _ in ()).throw(brain.LLMError(f"boom {SECRET}"))})()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request("POST", "/api/insight", "{}", {"content-type": "application/json"})
        r = c.getresponse()
        self.assertEqual(r.status, 502)
        self.assertNotIn(SECRET, r.read().decode())
        c.close()


# --- cache -----------------------------------------------------------------------------

class CacheTests(unittest.TestCase):
    def setUp(self):
        cache.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "demo.db"
        demo.build(self.path)
        self.db = store.connect(self.path)
        self.calls = 0

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()
        cache.clear()

    def compute(self):
        self.calls += 1
        return {"n": self.calls, "items": [1, 2, {"x": "y"}]}

    def memo(self, args=()):
        return cache.memo(self.db, "t", args, self.compute)

    def test_hit_until_data_changes(self):
        a = self.memo()
        self.assertEqual(self.memo(), a)
        self.assertEqual(self.calls, 1)
        self.memo(("other",))
        self.assertEqual(self.calls, 2)          # different args, own entry
        changes = [
            lambda: store.add_ack(self.db, CAM, "port:23"),
            lambda: store.remove_ack(self.db, CAM, "port:23"),
            lambda: store.set_label(self.db, CAM, "Garage camera"),
            lambda: store.set_profile(self.db, CAM, room="車庫"),
            lambda: store.insert_events(self.db, [{
                "source": "t", "ts": store.now(), "client_ip": "192.168.1.9", "client_name": "",
                "domain": "new.example", "qtype": "A", "status": "NOERROR", "reason": "",
                "blocked": 0, "cached": 0, "upstream": "", "elapsed_ms": 1.0,
                "device_mac": CAM}]),
            lambda: store.upsert_device(self.db, {"ip": "192.168.1.250", "mac": "02:00:00:00:00:99",
                                                  "vendor": "", "hostname": "new",
                                                  "randomized": True, "is_self": False}),
            lambda: store.set_meta(self.db, "x", "1"),
        ]
        for i, change in enumerate(changes):
            before = self.calls
            change()
            self.memo()
            self.assertEqual(self.calls, before + 1, f"change {i} did not invalidate")
            self.memo()
            self.assertEqual(self.calls, before + 1, f"change {i}: no hit afterwards")

    def test_ttl_expiry(self):
        self.memo()
        orig = cache.TTL
        cache.TTL = 0
        try:
            self.memo()
        finally:
            cache.TTL = orig
        self.assertEqual(self.calls, 2)

    def test_callers_get_private_copies(self):
        a = self.memo()
        a["items"][2]["x"] = "mutated"
        a["n"] = 99
        self.assertEqual(self.memo(), {"n": 1, "items": [1, 2, {"x": "y"}]})

    def test_in_memory_db_is_never_cached(self):
        mem = sqlite3.connect(":memory:")
        self.assertIsNone(cache.db_file(mem))
        for _ in range(3):
            cache.memo(mem, "t", (), self.compute)
        self.assertEqual(self.calls, 3)

    def test_unmarshallable_values_are_returned_not_cached(self):
        obj = object()
        self.assertIs(cache.memo(self.db, "o", (), lambda: obj), obj)
        self.assertIs(cache.memo(self.db, "o", (), lambda: obj), obj)

    def test_concurrent_callers_compute_once(self):
        gate = threading.Event()

        def slow():
            self.calls += 1
            gate.wait(5)
            return {"ok": True}
        out = []

        def worker():
            db = store.connect(self.path)
            out.append(cache.memo(db, "slow", (), slow))
            db.close()
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        time.sleep(0.2)
        gate.set()
        for t in threads:
            t.join(10)
        self.assertEqual(out, [{"ok": True}] * 4)
        self.assertEqual(self.calls, 1)

    def test_cached_views_follow_user_notes(self):
        # the real memoized computations see a fresh note at once
        types = devicetype.classify_all(self.db)
        store.set_profile(self.db, CAM, type="tv")
        self.assertNotEqual(types[CAM]["type"], "tv")
        self.assertEqual(devicetype.classify_all(self.db)[CAM]["type"], "tv")
        n = len(alerts.compute(self.db)["exposure"])
        store.add_ack(self.db, CAM, "")
        self.assertLess(len(alerts.compute(self.db)["exposure"]), n)
        snap = brain.snapshot(self.db)
        store.set_label(self.db, CAM, "Garage cam")
        self.assertNotEqual(snap, brain.snapshot(self.db))


# --- runner warm-up --------------------------------------------------------------------

class RunnerWarmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.quiet = logging.NullHandler()   # the failing-job case logs a warning
        logging.getLogger("netwarden").addHandler(cls.quiet)

    @classmethod
    def tearDownClass(cls):
        logging.getLogger("netwarden").removeHandler(cls.quiet)

    def setUp(self):
        cache.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "demo.db"
        demo.build(self.path)

    def tearDown(self):
        self.tmp.cleanup()
        cache.clear()

    def test_warm_fills_the_cache_without_the_llm(self):
        orig = brain.provider_from_env
        brain.provider_from_env = lambda env, db=None: self.fail("warm must never build a provider")
        try:
            db = store.connect(self.path)
            runner.warm(db, 24)
            hits = cache.stats["hits"]
            brain.snapshot(db, hours=24)
            alerts.compute(db, recent_hours=24)
            self.assertEqual(cache.stats["hits"], hits + 2)
            db.close()
        finally:
            brain.provider_from_env = orig

    def _run(self, name, job, warm_hours):
        calls = []
        orig = runner.warm
        runner.warm = lambda db, h, env=None: calls.append(h)
        try:
            r = runner.Runner(self.path, {}, jobs={name: (3600, job)},
                              warm_hours=warm_hours).start()
            deadline = time.monotonic() + 5
            while r.loops[name].runs < 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            r.stop()
        finally:
            runner.warm = orig
        return calls

    def test_data_loops_warm_after_success_only(self):
        self.assertEqual(self._run("dns", lambda db: None, 24), [24])
        self.assertEqual(self._run("dns", lambda db: None, None), [])
        self.assertEqual(self._run("prune", lambda db: None, 24), [])

        def boom(db):
            raise RuntimeError("down")
        self.assertEqual(self._run("traffic", boom, 24), [])

    def test_failed_warm_up_is_not_a_failed_run(self):
        def bad(db):
            raise RuntimeError("warm broke")
        stop = threading.Event()
        lp = runner.Loop("dns", 3600, lambda db: None, self.path, stop, after=bad).start()
        deadline = time.monotonic() + 5
        while lp.runs < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        stop.set()
        lp.thread.join(5)
        self.assertEqual(lp.failures, 0)
        self.assertIsNotNone(lp.last_ok_ts)


# --- scripts/perf_db.py ----------------------------------------------------------------

def _perf():
    spec = importlib.util.spec_from_file_location("perf_db", ROOT / "scripts" / "perf_db.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class PerfDbTests(unittest.TestCase):
    def setUp(self):
        self.perf = _perf()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "perf.db"

    def tearDown(self):
        self.tmp.cleanup()
        cache.clear()

    def test_build_is_deterministic_and_marked(self):
        st = self.perf.build(self.path, n_devices=16, n_events=400, days=1, sample_minutes=60)
        self.assertEqual((st["devices"], st["events"]), (16, 400))
        self.assertEqual(st["traffic_samples"], 16 * 25)
        db = store.connect(self.path)
        self.assertEqual(store.get_meta(db, "demo"), "1")
        self.assertEqual(store.get_meta(db, "perf"), "1")
        macs = sorted(r[0] for r in db.execute("SELECT mac FROM devices"))
        db.close()
        self.perf.build(self.path, n_devices=16, n_events=400, days=1, sample_minutes=60)
        db = store.connect(self.path)
        self.assertEqual(sorted(r[0] for r in db.execute("SELECT mac FROM devices")), macs)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0], 400)
        db.close()

    def test_refuses_a_database_that_is_not_its_own(self):
        demo.build(self.path)
        with self.assertRaises(self.perf.NotAPerfDB):
            self.perf.build(self.path, n_devices=4, n_events=10, days=1)
        db = store.connect(self.path)
        self.assertIsNone(store.get_meta(db, "perf"))
        self.assertGreater(db.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 4)
        db.close()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(self.perf.main(["build", "--db", str(self.path)]), 1)
        self.assertIn("refusing", err.getvalue())

    def test_bench_hits_every_endpoint(self):
        saved = {k: getattr(web.Handler, k, None) for k in ("db_path", "env", "lang", "hours", "loops")}
        try:
            self.perf.build(self.path, n_devices=12, n_events=300, days=1, sample_minutes=60)
            res = self.perf.bench(self.path, runs=1)
        finally:
            for k, v in saved.items():
                setattr(web.Handler, k, v)
        self.assertEqual(set(res), set(self.perf.ENDPOINTS) | {"(page refresh, 13 requests)", "(page refresh, bundle)"})
        self.assertTrue(all(r["median"] > 0 for r in res.values()))


if __name__ == "__main__":
    unittest.main()
