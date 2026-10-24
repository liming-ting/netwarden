"""
Round 7 C: AI cost efficiency and usage visibility.

- Anthropic prompt caching: the request shape (system blocks with a cache breakpoint,
  the conversation's last block in a tool loop, tools before system, <= 4 breakpoints),
  the stable prefix byte-identical across rounds and questions, volatile parts after it
- usage parsing: message_start / message_delta / JSON usage (input, output, cache write,
  cache read), OpenAI-style usage (stream_options + the fallback for servers refusing it)
- usage.py: the price table (prefix match, overrides, local = no price), cost math, the
  Meter (estimates when nothing is reported, failed requests not counted), monthly
  totals, the budget (near / over / would_exceed) and the "ask first" gate
- trimming: the compact snapshot rendering, history caps, redaction BEFORE clipping, and
  a before/after comparison of the redacted payload for the same input
- web: event usage / budget in /api/chat/stream, budget_ok, GET /api/ai/usage, settings
- offline mode records nothing

Every model server here is a fake on an ephemeral 127.0.0.1 port: no real AI call.
"""
import http.client
import json
import re
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from netwarden import (ai_tools, brain, cache, demo, i18n, localai, redact, settings, store,
                       usage, web)

ROOT = Path(__file__).resolve().parent.parent
KEY = "sk-ant-test-not-real-7c7c7c7c"
MODEL = "claude-sonnet-5-5"
_DEMO = {}


def setUpModule():
    _DEMO["tmp"] = tempfile.TemporaryDirectory()
    _DEMO["path"] = str(Path(_DEMO["tmp"].name) / "demo.db")
    demo.build(_DEMO["path"])


def tearDownModule():
    _DEMO["tmp"].cleanup()


def demo_copy(dest: Path) -> str:
    src, dst = sqlite3.connect(_DEMO["path"]), sqlite3.connect(str(dest))
    src.backup(dst)
    src.close()
    dst.close()
    return str(dest)


# --- fake model servers --------------------------------------------------------------------

def _ev(kind, data):
    return f"event: {kind}\ndata: {json.dumps({'type': kind, **data})}\n\n"


class FakeAnthropic(BaseHTTPRequestHandler):
    """The Messages API with usage: `planner(body, n)` -> {"text": [...], "calls": [(id,
    name, args)], "usage": {...}}. Every request body is recorded."""
    seen: list = []
    planner = None

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        cls = type(self)
        cls.seen.append(body)
        n = len(cls.seen) - 1
        plan = cls.planner(body, n) if cls.planner else {"text": ["Hi."]}
        u = plan.get("usage") or {"input_tokens": 100, "cache_creation_input_tokens": 2000,
                                  "cache_read_input_tokens": 0, "output_tokens": 1}
        if not body.get("stream"):
            b = json.dumps({"content": [{"type": "text", "text": "".join(plan.get("text") or [])}],
                            "usage": {**u, "output_tokens": plan.get("out", 30)}}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        out = [_ev("message_start", {"message": {"id": "m", "role": "assistant", "usage": u}})]
        i = 0
        if plan.get("text"):
            out.append(_ev("content_block_start", {"index": 0, "content_block": {"type": "text", "text": ""}}))
            out += [_ev("content_block_delta", {"index": 0, "delta": {"type": "text_delta", "text": t}})
                    for t in plan["text"]]
            out.append(_ev("content_block_stop", {"index": 0}))
            i = 1
        for j, (cid, name, args) in enumerate(plan.get("calls") or []):
            out.append(_ev("content_block_start", {"index": i + j, "content_block": {
                "type": "tool_use", "id": cid, "name": name, "input": {}}}))
            out.append(_ev("content_block_delta", {"index": i + j, "delta": {
                "type": "input_json_delta", "partial_json": json.dumps(args)}}))
            out.append(_ev("content_block_stop", {"index": i + j}))
        out.append(_ev("message_delta", {"delta": {"stop_reason": "end_turn"},
                                         "usage": {"output_tokens": plan.get("out", 40)}}))
        out.append(_ev("message_stop", {}))
        for f in out:
            self.wfile.write(f.encode())
        self.wfile.flush()


class FakeOpenAI(BaseHTTPRequestHandler):
    """/v1/chat/completions streaming with a final usage chunk; refuse_usage=True answers
    a body WITH stream_options with a 400 that names it (some servers do)."""
    seen: list = []
    refuse_usage = False

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        cls = type(self)
        cls.seen.append(body)
        if cls.refuse_usage and "stream_options" in body:
            b = json.dumps({"error": {"message": "unknown field: stream_options"}}).encode()
            self.send_response(400)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if not body.get("stream"):
            b = json.dumps({"choices": [{"message": {"content": "whole"}}],
                            "usage": {"prompt_tokens": 50, "completion_tokens": 5}}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        frames = ["data: " + json.dumps({"choices": [{"index": 0, "delta": {"content": t}}]}) + "\n\n"
                  for t in ("Local ", "answer.")]
        if "stream_options" in body:
            frames.append("data: " + json.dumps({"choices": [], "usage": {
                "prompt_tokens": 900, "completion_tokens": 12,
                "prompt_tokens_details": {"cached_tokens": 600}}}) + "\n\n")
        frames.append("data: [DONE]\n\n")
        for f in frames:
            self.wfile.write(f.encode())
        self.wfile.flush()


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _breakpoints(body) -> int:
    n = 0
    sysv = body.get("system")
    if isinstance(sysv, list):
        n += sum(1 for b in sysv if "cache_control" in b)
    for t in body.get("tools") or []:
        n += "cache_control" in t
    for m in body.get("messages") or []:
        if isinstance(m["content"], list):
            n += sum(1 for b in m["content"] if "cache_control" in b)
    return n


class _Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = demo_copy(Path(cls.tmp.name) / "demo.db")
        cls.db = store.connect(cls.path)
        cls.srv = _serve(FakeAnthropic)
        cls.osrv = _serve(FakeOpenAI)

    @classmethod
    def tearDownClass(cls):
        for s in (cls.srv, cls.osrv):
            s.shutdown()
            s.server_close()
        cls.db.close()
        cls.tmp.cleanup()
        cache.clear()

    def setUp(self):
        FakeAnthropic.seen, FakeAnthropic.planner = [], None
        FakeOpenAI.seen, FakeOpenAI.refuse_usage = [], False
        localai.OpenAICompatibleProvider._NO_USAGE_OPTION.clear()
        brain._NO_TOOLS.clear()
        self.db.execute("DELETE FROM ai_usage")
        self.db.execute("DELETE FROM settings")
        self.db.commit()

    def anthropic(self, redact_on=False):
        p = brain.AnthropicProvider(KEY, model=MODEL, timeout=5)
        p.ENDPOINT = f"http://127.0.0.1:{self.srv.server_address[1]}/v1/messages"
        p.redact = redact_on
        return p

    def local(self, destination="local"):
        p = localai.OpenAICompatibleProvider(f"http://127.0.0.1:{self.osrv.server_address[1]}/v1",
                                             "llama3.2", timeout=5, destination=destination)
        p.redact = False
        return p

    def ask(self, q, p, env=None, mode="chat", mac=None, budget_ok=False, messages=None):
        msgs = messages if messages is not None else [{"role": "user", "content": q}]
        return list(brain.stream_events(self.db, p, mode, msgs if mode == "chat" else [],
                                        hours=100000, lang="en", mac=mac, env=env or {},
                                        budget_ok=budget_ok))


def _tool_then_answer(body, n):
    if n == 0:
        return {"calls": [("toolu_1", "list_devices", {})],
                "usage": {"input_tokens": 300, "cache_creation_input_tokens": 5000,
                          "cache_read_input_tokens": 0, "output_tokens": 1}, "out": 25}
    return {"text": ["The ", "TV."],
            "usage": {"input_tokens": 400, "cache_creation_input_tokens": 600,
                      "cache_read_input_tokens": 5000, "output_tokens": 1}, "out": 60}


# --- 1. prompt caching: the request shape ----------------------------------------------------

class CacheShapeTests(_Case):
    def test_tool_loop_breakpoints_and_stable_prefix(self):
        FakeAnthropic.planner = staticmethod(_tool_then_answer)
        evs = self.ask("Which device used the most data?", self.anthropic())
        self.assertEqual("".join(e.get("t", "") for e in evs), "The TV.")
        r1, r2 = FakeAnthropic.seen
        for body in (r1, r2):
            # order on the wire: tools, then system (2 blocks: stable + breakpoint), messages
            self.assertTrue(body["tools"])
            self.assertIsInstance(body["system"], list)
            self.assertEqual(body["system"][0]["cache_control"], {"type": "ephemeral"})
            self.assertLessEqual(_breakpoints(body), 4)
            self.assertNotIn("cache_control", json.dumps(body["tools"]))
        # round 1 may be followed by another: the conversation's last block is a breakpoint
        self.assertEqual(r1["messages"][-1]["content"][-1]["cache_control"], {"type": "ephemeral"})
        # round 2 resends round 1 unchanged as its prefix (that is what the cache reads)
        self.assertEqual(r1["system"], r2["system"])
        self.assertEqual(r1["tools"], r2["tools"])
        first = dict(r1["messages"][0]["content"][-1])
        first.pop("cache_control")
        self.assertEqual(r2["messages"][0]["content"], [first] if isinstance(r2["messages"][0]["content"], list)
                         else first["text"])
        self.assertEqual(r2["messages"][-1]["content"][-1]["type"], "tool_result")
        self.assertIn("cache_control", r2["messages"][-1]["content"][-1])

    def test_context_goes_out_once_per_request(self):
        FakeAnthropic.planner = staticmethod(_tool_then_answer)
        self.ask("Which device used the most data?", self.anthropic())
        marker = '"window_hours"'
        for body in FakeAnthropic.seen:
            self.assertEqual(json.dumps(body, ensure_ascii=False).count(marker.replace('"', '\\"')), 1)

    def test_final_round_has_no_conversation_breakpoint(self):
        FakeAnthropic.planner = staticmethod(lambda body, n: {"calls": [(f"t{n}", "list_devices", {})]})
        self.ask("Loop forever", self.anthropic(), env={"NETWARDEN_AI_TOOL_ROUNDS": "1"})
        last = FakeAnthropic.seen[-1]
        self.assertEqual(last.get("tool_choice"), {"type": "none"})
        self.assertNotIn("cache_control", json.dumps(last["messages"]))
        self.assertIn("cache_control", last["system"][0])      # tools + system still cached

    def test_stable_prefix_is_identical_across_questions_and_focus(self):
        FakeAnthropic.planner = staticmethod(lambda body, n: {"text": ["ok"]})
        env = {"NETWARDEN_AI_TOOLS": "off"}
        self.ask("First question?", self.anthropic(), env=env)
        mac = next(iter(store.device_names(self.db)))
        self.ask("A follow-up about this one?", self.anthropic(), env=env, mac=mac,
                 messages=[{"role": "user", "content": "First question?"},
                           {"role": "assistant", "content": "ok"},
                           {"role": "user", "content": "A follow-up about this one?"}])
        a, b = FakeAnthropic.seen
        self.assertEqual(a["system"][0], b["system"][0])
        self.assertEqual(len(a["system"]), 1)               # no focus: one cached block
        self.assertEqual(len(b["system"]), 2)               # the focus line comes AFTER the cut
        self.assertNotIn("cache_control", b["system"][1])
        self.assertIn(mac, b["system"][1]["text"])
        # a chat without tools does not mark the (changing) conversation
        self.assertIsInstance(a["messages"][0]["content"], str)
        # live numbers (the snapshot) never sit in the cached system text
        self.assertNotIn("total_queries", a["system"][0]["text"])

    def test_insight_is_not_cached(self):
        self.ask("", self.anthropic(), mode="insight")
        body = FakeAnthropic.seen[0]
        self.assertIsInstance(body["system"], str)
        self.assertNotIn("cache_control", json.dumps(body))

    def test_system_blocks_edge_cases(self):
        P = brain.AnthropicProvider
        self.assertEqual(P.system_blocks("abc"), "abc")
        self.assertEqual(P.system_blocks("abc", 0), "abc")
        self.assertEqual(P.system_blocks("abc   ", 3), [{"type": "text", "text": "abc",
                                                         "cache_control": {"type": "ephemeral"}}])
        self.assertEqual(P.mark_last([{"role": "user", "content": "  "}]),
                         [{"role": "user", "content": "  "}])
        marked = P.mark_last([{"role": "user", "content": "q"}])
        self.assertEqual(marked[0]["content"], [{"type": "text", "text": "q",
                                                 "cache_control": {"type": "ephemeral"}}])


# --- 2. usage parsing ------------------------------------------------------------------------

class UsageParsingTests(_Case):
    def test_stream_usage_and_cost_from_the_table(self):
        FakeAnthropic.planner = staticmethod(_tool_then_answer)
        evs = self.ask("Which device used the most data?", self.anthropic())
        u = evs[-1]["usage"] if "usage" in evs[-1] else next(e["usage"] for e in evs if "usage" in e)
        self.assertEqual(u["requests"], 2)
        self.assertEqual(u["input_tokens"], 700)
        self.assertEqual(u["cache_write_tokens"], 5600)
        self.assertEqual(u["cache_read_tokens"], 5000)
        self.assertEqual(u["output_tokens"], 85)              # message_delta's final counts
        self.assertFalse(u["estimated"])
        self.assertFalse(u["local"])
        p = usage.table_price(MODEL)
        want = (700 * p["input"] + 5600 * p["cache_write"] + 5000 * p["cache_read"] + 85 * p["output"]) / 1e6
        self.assertAlmostEqual(u["cost_usd"], want, places=6)
        row = self.db.execute("SELECT * FROM ai_usage").fetchone()
        self.assertEqual((row["provider"], row["model"], row["destination"], row["mode"]),
                         ("Anthropic", MODEL, "cloud", "chat"))
        self.assertAlmostEqual(row["cost_usd"], want, places=6)

    def test_complete_reads_json_usage(self):
        p = self.anthropic()
        m = usage.Meter()
        p.meter = m
        m.begin(10)
        self.assertEqual(p.complete("S", "U"), "Hi.")
        t = m.totals()
        self.assertEqual((t["input_tokens"], t["cache_write_tokens"], t["output_tokens"]), (100, 2000, 30))

    def test_json_endpoints_are_counted_too(self):
        brain.insights(self.db, self.anthropic(), hours=100000, lang="en")
        row = self.db.execute("SELECT mode, requests, estimated FROM ai_usage").fetchone()
        self.assertEqual(tuple(row), ("insight", 1, 0))

    def test_openai_usage_with_stream_options(self):
        evs = self.ask("hi", self.local(), env={"NETWARDEN_AI_TOOLS": "off"})
        self.assertEqual(FakeOpenAI.seen[0]["stream_options"], {"include_usage": True})
        u = next(e["usage"] for e in evs if "usage" in e)
        self.assertEqual((u["input_tokens"], u["cache_read_tokens"], u["output_tokens"]), (300, 600, 12))
        self.assertTrue(u["local"])
        self.assertIsNone(u["cost_usd"])                      # own hardware: tokens only

    def test_server_refusing_stream_options_is_retried_once_and_remembered(self):
        FakeOpenAI.refuse_usage = True
        env = {"NETWARDEN_AI_TOOLS": "off"}
        evs = self.ask("hi", self.local(), env=env)
        self.assertEqual("".join(e.get("t", "") for e in evs), "Local answer.")
        self.assertEqual(["stream_options" in b for b in FakeOpenAI.seen], [True, False])
        u = next(e["usage"] for e in evs if "usage" in e)
        self.assertTrue(u["estimated"])                       # nothing reported: a local estimate
        self.assertGreater(u["input_tokens"], 1000)
        self.ask("again", self.local(), env=env)
        self.assertEqual(["stream_options" in b for b in FakeOpenAI.seen], [True, False, False])

    def test_openai_complete_reads_usage(self):
        p = self.local()
        m = usage.Meter()
        p.meter = m
        m.begin(1)
        self.assertEqual(p.complete("S", "U"), "whole")
        self.assertEqual(m.totals()["input_tokens"], 50)


# --- 3. prices, the meter, monthly totals ----------------------------------------------------

class PriceTests(unittest.TestCase):
    def test_table_prefix_match_longest_first(self):
        self.assertEqual(usage.table_price("claude-opus-5-5")["input"], 4.0)
        self.assertEqual(usage.table_price("claude-opus-5")["input"], 5.0)
        self.assertEqual(usage.table_price("claude-opus-5-20260301")["model_key"], "claude-opus-5")
        self.assertEqual(usage.table_price("claude-opus-4-5-20251101")["model_key"], "claude-opus-4-5")
        self.assertEqual(usage.table_price("claude-3-5-haiku-20241022")["model_key"], "claude-3-5-haiku")
        self.assertIsNone(usage.table_price("claude-opus-50"))
        self.assertIsNone(usage.table_price("gpt-4o"))
        self.assertIsNone(usage.table_price(None))
        for key, (i, w, r, o) in usage.ANTHROPIC_PRICES.items():
            self.assertTrue(0 < r < i < w and i < o, key)     # cache read < input < write
        self.assertRegex(usage.PRICES_CHECKED, r"^\d{4}-\d{2}-\d{2}$")

    def test_overrides_and_local(self):
        vals = {"ai.price_input": "1.5", "ai.price_output": "6"}
        p = usage.price(vals, "openai_compat", "some-model", "cloud")
        self.assertEqual((p["input"], p["output"], p["source"]), (1.5, 6.0, "settings"))
        self.assertEqual(usage.price(vals, "anthropic", MODEL, "cloud")["source"], "settings")
        self.assertIsNone(usage.price({"ai.price_input": "1.5", "ai.price_output": ""},
                                      "openai_compat", "m", "cloud"))
        for dest in ("local", "lan"):
            self.assertIsNone(usage.price(vals, "openai_compat", "m", dest))
        self.assertEqual(usage.price({}, "anthropic", MODEL, "cloud")["source"], "table")
        self.assertEqual(usage.cost({"input_tokens": 1_000_000, "output_tokens": 1_000_000},
                                    {"input": 2, "output": 10, "cache_write": 2.5, "cache_read": 0.1}), 12.0)
        self.assertIsNone(usage.cost({"input_tokens": 5}, None))

    def test_meter_estimates_and_skips_failed_requests(self):
        m = usage.Meter()
        self.assertIsNone(m.totals())
        m.begin(500)                       # failed before it answered: not counted
        m.begin(800)
        m.text("x" * 30)                   # answered, reported nothing: estimated
        m.begin(900)
        m.report(input_tokens=10, cache_read=700, output_tokens=1)
        m.report(output_tokens=55)         # the stream's final output count
        t = m.totals()
        self.assertEqual(t["requests"], 2)
        self.assertEqual(t["input_tokens"], 810)
        self.assertEqual(t["cache_read_tokens"], 700)
        self.assertEqual(t["output_tokens"], 10 + 55)
        self.assertTrue(t["estimated"])

    def test_estimate_tokens(self):
        self.assertEqual(usage.estimate_tokens(""), 0)
        self.assertEqual(usage.estimate_tokens("abc"), 1)
        self.assertEqual(usage.estimate_tokens("家庭網路"), 4)
        self.assertGreater(usage.estimate_tokens('{"a":1}' * 300), 600)

    def test_month_totals_follow_the_local_month(self):
        db = store.connect(":memory:")
        now = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
        for ts, cost in (("2026-10-02T00:00:00.000000Z", 0.5), ("2026-10-19T00:00:00.000000Z", None),
                         ("2026-09-15T00:00:00.000000Z", 9.0)):
            store.add_ai_usage(db, {"ts": ts, "provider": "Anthropic", "model": MODEL,
                                    "destination": "cloud", "mode": "chat", "requests": 2,
                                    "input_tokens": 100, "output_tokens": 50, "cost_usd": cost})
        m = usage.month(db, now)
        self.assertEqual((m["answers"], m["priced"], m["unpriced"], m["requests"]), (2, 1, 1, 4))
        self.assertEqual(m["tokens"], 300)
        self.assertAlmostEqual(m["cost_usd"], 0.5)
        self.assertEqual(m["month"], "2026-10")

    def test_prune_keeps_a_year_of_usage(self):
        db = store.connect(":memory:")
        old = (datetime.now(timezone.utc) - timedelta(days=store.USAGE_KEEP_DAYS + 5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
        mid = (datetime.now(timezone.utc) - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        for ts in (old, mid):
            store.add_ai_usage(db, {"ts": ts, "provider": "A", "model": "m", "destination": "cloud",
                                    "mode": "chat"})
        store.prune(db, 30)
        self.assertEqual([r[0] for r in db.execute("SELECT ts FROM ai_usage")], [mid])


# --- 4. the budget -----------------------------------------------------------------------------

class BudgetTests(_Case):
    def spend(self, usd):
        store.add_ai_usage(self.db, {"provider": "Anthropic", "model": MODEL, "destination": "cloud",
                                     "mode": "chat", "input_tokens": 1, "cost_usd": usd})

    def test_states(self):
        self.assertEqual(usage.budget(self.db, {})["state"], "none")
        settings.update(self.db, {}, {"ai.monthly_budget": "1"})
        self.spend(0.5)
        self.assertEqual(usage.budget(self.db, {})["state"], "ok")
        self.spend(0.35)
        b = usage.budget(self.db, {})
        self.assertEqual((b["state"], b["limit"]), ("near", 1.0))
        self.assertAlmostEqual(b["share"], 0.85)
        settings.update(self.db, {}, {"ai.budget_warn": 90})
        self.assertEqual(usage.budget(self.db, {})["state"], "ok")
        self.spend(0.2)
        self.assertEqual(usage.budget(self.db, {})["state"], "over")

    def test_over_budget_asks_first_and_sends_nothing(self):
        settings.update(self.db, {}, {"ai.monthly_budget": "1"})
        self.spend(1.0)
        evs = self.ask("hi", self.anthropic())
        self.assertEqual([list(e) for e in evs], [["budget"]])   # no text, no "empty" note
        self.assertEqual(evs[0]["budget"]["state"], "over")
        self.assertEqual(FakeAnthropic.seen, [])                 # nothing went out
        evs = self.ask("hi", self.anthropic(), budget_ok=True)   # "Send anyway"
        self.assertTrue(FakeAnthropic.seen)
        self.assertTrue(any("usage" in e for e in evs))

    def test_an_answer_that_would_cross_the_budget(self):
        settings.update(self.db, {}, {"ai.monthly_budget": "0.5"})
        self.spend(0.4999)
        gate = usage.check(self.db, {}, self.anthropic(), 20000)
        self.assertEqual(gate["state"], "would_exceed")
        self.assertGreater(gate["estimate_usd"], 0)
        self.assertIsNone(usage.check(self.db, {}, self.anthropic(), 20000, confirmed=True))

    def test_local_models_never_hit_a_money_budget(self):
        settings.update(self.db, {}, {"ai.monthly_budget": "1"})
        self.spend(5.0)
        evs = self.ask("hi", self.local(), env={"NETWARDEN_AI_TOOLS": "off"})
        self.assertNotIn("budget", [k for e in evs for k in e])
        self.assertTrue(FakeOpenAI.seen)

    def test_budget_setting_validation(self):
        clean = settings.REGISTRY["ai.monthly_budget"].clean
        self.assertEqual(clean("5.00"), "5")
        self.assertEqual(clean("12.50"), "12.50")
        self.assertEqual(clean("$3"), "3")
        self.assertEqual(clean("0,5"), "0.5")
        self.assertEqual(clean(""), "")
        for bad in ("0", "-1", "abc", "1e3", "1.23456", "12345678", "nan", "inf"):
            with self.assertRaises(settings.SettingError, msg=bad) as cm:
                clean(bad)
            self.assertIn(cm.exception.code, ("setting_money", "setting_invalid"))
        with self.assertRaises(settings.SettingError):
            settings.update(self.db, {}, {"ai.budget_warn": 40})
        for k in ("ai.monthly_budget", "ai.budget_warn", "ai.price_input", "ai.price_output"):
            s = settings.REGISTRY[k]
            self.assertEqual((s.group, s.admin), ("usage", True))


# --- 5. trimming and redaction -----------------------------------------------------------------

def _old_render(snap: dict) -> str:
    """The pre-round-7 rendering (pretty-printed, every field) - the "before" of the
    redaction comparison and the size numbers."""
    def compact(d):
        d = dict(d)
        d.pop("type_detail", None)
        if "bandwidth" in d:
            d["bandwidth"] = brain.bandwidth_line(d["bandwidth"], snap["window_hours"])
        if "privacy" in d:
            d["privacy"] = brain.privacy_line(d["privacy"])
        if "dns_visibility" in d:
            d["dns_visibility"] = brain.VISIBILITY_TEXT[d["dns_visibility"]]
        if "open_ports" in d:
            d["open_ports"] = brain.ports_line(d["open_ports"])
        return d
    out = {**snap, "devices": [compact(d) for d in snap["devices"]]}
    if "privacy" in snap:
        out["privacy"] = brain.privacy_line({**snap["privacy"], "main_category": None})
    if "not_in_dns_window" in snap:
        out["not_in_dns_window"] = [f"{x['name']}: {brain.VISIBILITY_TEXT[x['issue']]}"
                                    for x in snap["not_in_dns_window"]]
    return json.dumps(out, ensure_ascii=False, indent=2)


TOKEN_RE = re.compile(r"\[(?:D|M|P|R|IP)\d+\]")


class TrimTests(_Case):
    def test_compact_render(self):
        snap = brain.snapshot(self.db, hours=100000)
        new = brain._render(snap)
        self.assertNotIn("\n", new)
        doc = json.loads(new)
        dev = next(d for d in doc["devices"] if d.get("top_domains"))
        self.assertTrue(all(isinstance(t, str) and " x" in t for t in dev["top_domains"]))
        self.assertTrue(all("services" not in d for d in doc["devices"]))
        self.assertTrue(all(d.get(k) not in (None, False, "", []) for d in doc["devices"]
                            for k in brain._DROP_EMPTY if k in d))
        self.assertTrue(all(d.get("mac") for d in doc["devices"]))      # tools need the MAC
        self.assertLess(len(new), 0.6 * len(_old_render(snap)))        # >= 40 % smaller
        self.assertIn("BLOCKED", new)
        whys = [t.get("why") for t in doc.get("threats", [])]
        self.assertEqual(len([w for w in whys if w]), len({t.get("indicator") for t in doc.get("threats", [])}))

    def test_domain_line(self):
        self.assertEqual(brain.domain_line({"domain": "a.com", "count": 3}), "a.com x3")
        self.assertEqual(brain.domain_line({"domain": "t.com", "count": 2, "service": "TikTok",
                                            "category": "social", "blocked": True,
                                            "routine": "routine: cdn"}),
                         "t.com x2 TikTok/social BLOCKED (routine: cdn)")

    def test_history_is_capped_and_the_question_kept_whole(self):
        long = "y" * 7000
        msgs = [{"role": "assistant" if i % 2 else "user", "content": f"{i} " + "z" * 3000}
                for i in range(20)] + [{"role": "user", "content": long}]
        out = brain.trim_history(msgs)
        self.assertEqual(out[-1]["content"], long)
        older = out[:-1]
        self.assertLessEqual(sum(len(m["content"]) for m in older), brain.MAX_HISTORY_CHARS)
        self.assertTrue(all(len(m["content"]) <= brain.MAX_OLD_TURN_CHARS + 6 for m in older))
        self.assertTrue(older[-1]["content"].startswith("19 "))      # newest kept first

    def test_clipping_never_cuts_a_name_in_half(self):
        name = "Galaxy-Tab-A7-LongName"
        text = "a" * (brain.MAX_OLD_TURN_CHARS - 5) + name + " b"
        scrub = lambda s: s.replace(name, "[D9]")                    # noqa: E731
        out = brain.trim_history([{"role": "assistant", "content": text},
                                  {"role": "user", "content": "q"}], scrub)
        self.assertNotIn("Galaxy", out[0]["content"])
        self.assertNotIn("Gal", out[0]["content"][-12:])

    def test_redacted_payload_before_and_after(self):
        """The same snapshot, redacted, rendered the old way and the new way: the new one
        carries no real name / MAC / IP either, and the very same pseudonyms."""
        snap = brain.snapshot(self.db, hours=100000)
        r = redact.Redactor.build(self.db, snap)
        r.redact_fields(snap)
        before, after = r.redact(_old_render(snap)), r.redact(brain._render(snap))
        reals = [x["real"] for x in r.legend() if len(x["real"]) >= 3]
        self.assertGreater(len(reals), 10)
        for real in reals:
            self.assertNotIn(real, before, real)
            self.assertNotIn(real, after, real)
        self.assertEqual(set(TOKEN_RE.findall(before)), set(TOKEN_RE.findall(after)))

    def test_everything_sent_is_redacted_in_a_tool_loop(self):
        FakeAnthropic.planner = staticmethod(_tool_then_answer)
        env = {"NETWARDEN_AI_REDACT": "on"}
        self.ask("Which device used the most data?", self.anthropic(redact_on=True), env=env)
        snap = brain.snapshot(self.db, hours=100000)
        reals = [x["real"] for x in redact.Redactor.build(self.db, snap).legend() if len(x["real"]) >= 3]
        for body in FakeAnthropic.seen:
            raw = json.dumps(body, ensure_ascii=False)
            for real in reals:
                self.assertNotIn(real, raw, real)

    def test_preview_reports_sizes_per_part(self):
        r = brain.preview(self.db, {"ANTHROPIC_API_KEY": KEY}, "chat",
                          [{"role": "user", "content": "Who is home?"}], hours=100000, lang="en")
        t = r["tokens"]
        self.assertEqual(set(t), {"system", "tools", "context", "history", "total"})
        self.assertEqual(t["total"], t["system"] + t["tools"] + t["context"] + t["history"])
        self.assertGreater(t["tools"], 1000)                  # 13 tool definitions
        self.assertGreater(t["context"], t["history"])
        self.assertLess(t["total"], 16000)                    # round 6 measured ~17-18k per request
        self.assertNotIn(KEY, json.dumps(r))


# --- 6. web + offline ----------------------------------------------------------------------------

class WebTests(_Case):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._orig = brain.provider_from_env
        cls.use = None
        brain.provider_from_env = lambda env, db=None: cls.use() if cls.use else cls._orig(env, db)
        web.Handler.db_path = cls.path
        web.Handler.env = {"ANTHROPIC_API_KEY": KEY, "NETWARDEN_AI_TOOLS": "off"}
        web.Handler.lang = "en"
        web.Handler.hours = 100000
        web.Handler.loops = None
        cls.web = _serve(web.Handler)

    @classmethod
    def tearDownClass(cls):
        cls.web.shutdown()
        cls.web.server_close()
        brain.provider_from_env = cls._orig
        super().tearDownClass()

    def req(self, method, path, obj=None):
        c = http.client.HTTPConnection("127.0.0.1", self.web.server_address[1], timeout=30)
        c.request(method, path, json.dumps(obj) if obj is not None else None,
                  {"content-type": "application/json"} if obj is not None else {})
        r = c.getresponse()
        if r.getheader("content-type", "").startswith("text/event-stream"):
            out = list(brain.sse_events(iter(r.fp.readline, b"")))
        else:
            out = json.loads(r.read() or b"null")
        c.close()
        return r.status, out

    def test_usage_event_then_budget_event(self):
        type(self).use = lambda: self.anthropic()
        st, frames = self.req("POST", "/api/chat/stream",
                              {"mode": "chat", "messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual(st, 200)
        kinds = [e for e, _d in frames]
        self.assertEqual(kinds[-2:], ["usage", "done"])
        u = frames[-2][1]
        self.assertEqual(u["provider"], "Anthropic")
        self.assertGreater(u["tokens"], 0)
        settings.update(self.db, {}, {"ai.monthly_budget": "0.01"})
        self.db.execute("UPDATE ai_usage SET cost_usd = 1")
        self.db.commit()
        FakeAnthropic.seen = []
        st, frames = self.req("POST", "/api/chat/stream",
                              {"mode": "chat", "lang": "zh-Hant", "messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual([e for e, _d in frames], ["budget", "done"])
        b = frames[0][1]
        self.assertEqual(b["state"], "over")
        self.assertIn("US$", b["text"])
        self.assertIn("預算", b["text"])
        self.assertEqual(FakeAnthropic.seen, [])
        st, frames = self.req("POST", "/api/chat/stream",
                              {"mode": "chat", "budget_ok": True, "messages": [{"role": "user", "content": "hi"}]})
        self.assertIn("usage", [e for e, _d in frames])
        # only a JSON true counts as "send anyway"
        st, frames = self.req("POST", "/api/chat/stream",
                              {"mode": "chat", "budget_ok": "yes", "messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual(frames[0][0], "budget")

    def test_usage_endpoint(self):
        type(self).use = None
        store.add_ai_usage(self.db, {"provider": "Anthropic", "model": MODEL, "destination": "cloud",
                                     "mode": "chat", "input_tokens": 1000, "output_tokens": 100,
                                     "cost_usd": 0.003})
        st, j = self.req("GET", "/api/ai/usage")
        self.assertEqual(st, 200)
        self.assertEqual(j["month"]["answers"], 1)
        self.assertEqual(j["budget"]["state"], "none")
        self.assertEqual(j["price"]["source"], "table")
        self.assertEqual(j["prices_checked"], usage.PRICES_CHECKED)
        raw = json.dumps(j)
        self.assertNotIn(KEY, raw)
        self.assertNotIn("http", raw)                          # never a URL

    def test_settings_page_has_the_usage_section(self):
        st, j = self.req("GET", "/api/settings")
        self.assertEqual(st, 200)
        self.assertIn("usage", [s["key"] for s in j["sections"]])
        keys = {i["key"]: i for i in j["items"] if i["section"] == "usage"}
        self.assertEqual(set(keys), {"ai.monthly_budget", "ai.budget_warn", "ai.price_input", "ai.price_output"})
        st, j = self.req("POST", "/api/settings", {"values": {"ai.monthly_budget": "-3"}})
        self.assertEqual(st, 400)
        self.assertEqual(j["key"], "ai.monthly_budget")
        self.assertEqual(j["error"], i18n.t("err.setting_money", "en"))


class OfflineTests(_Case):
    def test_offline_records_nothing(self):
        p = brain.provider_from_env({brain.OFFLINE_ENV: "1"}, self.db)
        evs = self.ask("who is home?", p)
        self.assertTrue("".join(e.get("t", "") for e in evs))
        self.assertFalse(any("usage" in e or "budget" in e for e in evs))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM ai_usage").fetchone()[0], 0)
        s = usage.summary(self.db, {brain.OFFLINE_ENV: "1"})
        self.assertEqual((s["ai_mode"], s["price"]), ("offline", None))


class DemoTests(unittest.TestCase):
    def test_demo_month_is_deterministic_idempotent_and_keeps_user_choices(self):
        now = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "demo.db"
            demo.build(path, now=now)
            db = store.connect(path)
            first = [tuple(r) for r in db.execute("SELECT ts, model, cost_usd FROM ai_usage ORDER BY ts")]
            self.assertEqual(len(first), len(demo.DEMO_USAGE) + len(demo.DEMO_USAGE_LOCAL))
            m = usage.month(db, now)
            self.assertGreater(m["answers"], 8)
            self.assertGreaterEqual(m["unpriced"], 1)               # the LAN Ollama evening
            self.assertTrue(all(r[2] is None or r[2] < 0.1 for r in first))
            b = usage.budget(db, {}, now)
            self.assertEqual((b["state"], b["limit"]), ("ok", 1.0))
            # the user's own budget and a real answer survive a reseed
            settings.update(db, {}, {"ai.monthly_budget": "3"})
            store.add_ai_usage(db, {"provider": "Anthropic", "model": MODEL, "destination": "cloud",
                                    "mode": "chat", "input_tokens": 5, "cost_usd": 0.01})
            db.close()
            demo.build(path, now=now)
            db = store.connect(path)
            self.assertEqual(settings.values(db, {})["ai.monthly_budget"], "3")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ai_usage WHERE mode = 'chat'").fetchone()[0], 1)
            again = [tuple(r) for r in db.execute(
                "SELECT ts, model, cost_usd FROM ai_usage WHERE mode = 'demo' ORDER BY ts")]
            self.assertEqual(first, again)
            db.close()


class StaticTests(unittest.TestCase):
    def test_ui_wiring_and_locales(self):
        js = (ROOT / "netwarden/static/app.js").read_text(encoding="utf-8")
        for needle in ("ev.event === 'usage'", "ev.event === 'budget'", "budget_ok: budgetOk",
                       "function usageNote", "function usageStatus", "/api/ai/usage"):
            self.assertIn(needle, js)
        used = {k for k in re.findall(r"'(app\.usage\.[a-z_]+)'", js) if not k.endswith("_")}
        used |= {"app.usage.state_ok", "app.usage.state_near", "app.usage.state_over"}
        en = json.loads((ROOT / "netwarden/locales/en.json").read_text(encoding="utf-8"))
        for code in i18n.CODES:
            cat = json.loads((ROOT / f"netwarden/locales/{code}.json").read_text(encoding="utf-8"))
            for k in used | {"app.usage.budget_over_q", "app.usage.budget_cross_q", "settings.section.usage"}:
                self.assertIn(k, cat, (code, k))
                self.assertIn(k, en)
