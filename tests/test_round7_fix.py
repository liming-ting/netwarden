"""
Round 7 fix stage: the review findings on AI cost (stage C).

1. a tool loop is checked against the monthly budget before EVERY request (usage.Guard):
   the last affordable round answers without lookups (note budget_limit), and nothing is
   sent once even one more request would cross it (note budget_stop)
2. the JSON AI endpoints (/api/insight, /api/ask, /api/chat) ask first too: 409 + the
   localized question, nothing sent; "budget_ok": true sends
3. turns left out by trim_history are named to the model and noted to the user
4./5. the Settings card warns about a half-filled price pair and a budget that cannot be
   checked (a cloud AI without a price)
6. the demo's usage rows always fall inside the current local month
7. money settings get a decimal keyboard on phones

Every model server is a fake on an ephemeral 127.0.0.1 port (test_round7_c): no real AI call.
"""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import test_round7_c as c7
from netwarden import brain, demo, i18n, settings, store, usage, web

KEY, MODEL = c7.KEY, c7.MODEL


def setUpModule():
    c7.setUpModule()


def tearDownModule():
    c7.tearDownModule()


def _always_lookup(usage_in=9000, out=300):
    """A model that wants another lookup in every round (the worst case for cost)."""
    def plan(body, n):
        return {"calls": [(f"toolu_{n}", "list_devices", {})], "out": out,
                "usage": {"input_tokens": usage_in, "cache_creation_input_tokens": 0,
                          "cache_read_input_tokens": 0, "output_tokens": 1}}
    return staticmethod(plan)


class _Case(c7._Case):
    def budget(self, usd, spent=0.0):
        settings.update(self.db, {}, {"ai.monthly_budget": usd})
        if spent:
            store.add_ai_usage(self.db, {"provider": "Anthropic", "model": MODEL,
                                         "destination": "cloud", "mode": "chat",
                                         "input_tokens": 1, "cost_usd": spent})

    def spent(self) -> float:
        return usage.month(self.db)["cost_usd"]


# --- 1. the tool loop and the budget ----------------------------------------------------------

class ToolLoopBudgetTests(_Case):
    def test_without_a_budget_the_loop_runs_all_rounds(self):
        c7.FakeAnthropic.planner = _always_lookup()
        evs = self.ask("Loop", self.anthropic())
        self.assertEqual(len(c7.FakeAnthropic.seen), settings.values(self.db, {})["ai.max_tool_rounds"] + 1)
        self.assertNotIn("budget_limit", [e.get("note") for e in evs])

    def test_the_review_case_stays_within_the_budget(self):
        """US$0.05 budget, nothing spent, 9k input / 300 output per round: before the fix
        5 requests cost US$0.105 with no question asked."""
        self.budget("0.05")
        c7.FakeAnthropic.planner = _always_lookup()
        evs = self.ask("Loop", self.anthropic())
        notes = [e.get("note") for e in evs if "note" in e]
        self.assertIn("budget_limit", notes)
        self.assertNotIn("tool_limit", notes)            # one note, the budget one
        self.assertNotIn("budget", [k for e in evs for k in e])
        self.assertLess(len(c7.FakeAnthropic.seen), 5)
        self.assertEqual(c7.FakeAnthropic.seen[-1].get("tool_choice"), {"type": "none"})
        self.assertLessEqual(self.spent(), 0.05)
        self.assertTrue(any("usage" in e for e in evs))  # what was spent is still shown

    def test_nothing_more_is_sent_once_one_request_would_cross(self):
        # the first round costs far more than estimated (a huge lookup result upstream)
        self.budget("0.1")
        c7.FakeAnthropic.planner = _always_lookup(usage_in=60000)
        evs = self.ask("Loop", self.anthropic())
        self.assertEqual(len(c7.FakeAnthropic.seen), 1)
        notes = [e.get("note") for e in evs if "note" in e]
        self.assertIn("budget_stop", notes)
        self.assertNotIn("empty", notes)                 # the stop note explains the end

    def test_send_anyway_covers_the_whole_answer(self):
        self.budget("0.05", spent=0.05)
        c7.FakeAnthropic.planner = _always_lookup()
        evs = self.ask("Loop", self.anthropic(), budget_ok=True)
        self.assertEqual(len(c7.FakeAnthropic.seen), 5)
        self.assertFalse({"budget_limit", "budget_stop"} & {e.get("note") for e in evs})

    def test_guard_math(self):
        p = usage.table_price(MODEL)
        m = usage.Meter()
        g = usage.Guard(1.0, 0.9, p)
        # one request of 10k input (US$0.02) + 500 output (US$0.005) fits, five do not
        self.assertTrue(g.fits(m, 10000))
        self.assertFalse(g.fits(m, 10000, 5))
        m.begin(10000)
        m.report(input_tokens=40000, output_tokens=500)  # this answer so far: US$0.085
        self.assertFalse(g.fits(m, 10000))
        self.assertIsNone(usage.guard(self.db, {}, self.anthropic()))          # no budget
        self.budget("1")
        self.assertIsInstance(usage.guard(self.db, {}, self.anthropic()), usage.Guard)
        self.assertIsNone(usage.guard(self.db, {}, self.anthropic(), confirmed=True))
        self.assertIsNone(usage.guard(self.db, {}, self.local()))              # no price

    def test_notes_are_localized(self):
        for code in i18n.CODES:
            for k in ("budget_limit", "budget_stop", "history_trimmed"):
                key = "app.ai.note_" + k
                self.assertNotEqual(i18n.t(key, code), key, (code, k))


# --- 2. the JSON endpoints ---------------------------------------------------------------------

class JsonEndpointBudgetTests(_Case):
    def test_brain_functions_ask_first(self):
        self.budget("1", spent=1.0)
        for call in (lambda ok: brain.ask(self.db, self.anthropic(), "hi", hours=100000,
                                          lang="en", env={}, budget_ok=ok),
                     lambda ok: brain.insights(self.db, self.anthropic(), hours=100000,
                                               lang="en", env={}, budget_ok=ok),
                     lambda ok: brain.converse(self.db, self.anthropic(),
                                               [{"role": "user", "content": "hi"}],
                                               hours=100000, lang="en", env={}, budget_ok=ok)):
            c7.FakeAnthropic.seen = []
            with self.assertRaises(brain.BudgetNeeded) as cm:
                call(False)
            self.assertEqual(cm.exception.gate["state"], "over")
            self.assertEqual(c7.FakeAnthropic.seen, [])             # nothing went out
            self.assertIsInstance(call(True), str)
            self.assertEqual(len(c7.FakeAnthropic.seen), 1)


class JsonEndpointWebTests(_Case):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._orig = brain.provider_from_env
        brain.provider_from_env = lambda env, db=None: cls.provider()
        web.Handler.db_path = cls.path
        web.Handler.env = {"ANTHROPIC_API_KEY": KEY, "NETWARDEN_AI_TOOLS": "off"}
        web.Handler.lang = "en"
        web.Handler.hours = 100000
        web.Handler.loops = None
        cls.web = c7._serve(web.Handler)

    @classmethod
    def tearDownClass(cls):
        cls.web.shutdown()
        cls.web.server_close()
        brain.provider_from_env = cls._orig
        super().tearDownClass()

    @classmethod
    def provider(cls):
        p = brain.AnthropicProvider(KEY, model=MODEL, timeout=5)
        p.ENDPOINT = f"http://127.0.0.1:{cls.srv.server_address[1]}/v1/messages"
        p.redact = False
        return p

    req = c7.WebTests.req

    def test_409_then_send_anyway(self):
        self.budget("0.01", spent=0.02)
        bodies = {"/api/ask": {"question": "hi"}, "/api/insight": {},
                  "/api/chat": {"messages": [{"role": "user", "content": "hi"}]}}
        for path, body in bodies.items():
            c7.FakeAnthropic.seen = []
            st, j = self.req("POST", path, {**body, "lang": "zh-Hant"})
            self.assertEqual(st, 409, path)
            self.assertEqual(j["budget"]["state"], "over")
            self.assertIn("預算", j["error"])
            self.assertEqual(j["error"], j["budget"]["text"])
            self.assertEqual(c7.FakeAnthropic.seen, [], path)
            st, j = self.req("POST", path, {**body, "budget_ok": "yes"})   # only JSON true
            self.assertEqual(st, 409, path)
            st, j = self.req("POST", path, {**body, "budget_ok": True})
            self.assertEqual(st, 200, path)
            self.assertIn("text", j)
            self.assertEqual(len(c7.FakeAnthropic.seen), 1, path)


# --- 3. trimmed history --------------------------------------------------------------------------

class HistoryTrimTests(_Case):
    def long_chat(self, n):
        msgs = [{"role": "assistant" if i % 2 else "user", "content": f"turn {i} " + "x" * 1990}
                for i in range(n)]
        return msgs + [{"role": "user", "content": "And now?"}]

    def test_the_model_and_the_user_are_told(self):
        c7.FakeAnthropic.planner = staticmethod(lambda body, n: {"text": ["ok"]})
        msgs = self.long_chat(9)
        parts = brain._chat_parts(brain.snapshot(self.db, hours=100000), msgs, "en")
        kept = brain.trim_history(msgs)
        self.assertEqual(parts["omitted"], len(msgs) - len(kept))
        self.assertGreater(parts["omitted"], 0)
        evs = self.ask("", self.anthropic(), env={"NETWARDEN_AI_TOOLS": "off"}, messages=msgs)
        self.assertIn("history_trimmed", [e.get("note") for e in evs])
        sent = json.dumps(c7.FakeAnthropic.seen[0], ensure_ascii=False)
        self.assertIn(brain.OMITTED.format(n=parts["omitted"]), sent)
        self.assertNotIn("turn 0 ", sent)

    def test_a_short_chat_has_no_note(self):
        c7.FakeAnthropic.planner = staticmethod(lambda body, n: {"text": ["ok"]})
        evs = self.ask("hi", self.anthropic(), env={"NETWARDEN_AI_TOOLS": "off"})
        self.assertNotIn("history_trimmed", [e.get("note") for e in evs])
        self.assertNotIn("earlier message(s)", json.dumps(c7.FakeAnthropic.seen[0]))
        self.assertEqual(brain._chat_parts(brain.snapshot(self.db, hours=1), [], "en")["omitted"], 0)


# --- 4./5. price warnings on the Settings card ----------------------------------------------------

class PriceWarningTests(_Case):
    CLOUD = {"mode": "openai_compat", "destination": "cloud"}

    def test_warnings(self):
        none = {"state": "none", "limit": None}
        some = {"state": "ok", "limit": 5.0}
        w = usage.warnings
        self.assertEqual(w({}, self.CLOUD, None, none), [])
        self.assertEqual(w({"ai.price_input": "0.5"}, self.CLOUD, None, none), ["price_half"])
        self.assertEqual(w({"ai.price_output": "1"}, self.CLOUD, None, none), ["price_half"])
        self.assertEqual(w({"ai.price_input": "0.5", "ai.price_output": "1"}, self.CLOUD,
                           {"input": 0.5}, some), [])
        self.assertEqual(w({}, self.CLOUD, None, some), ["budget_unchecked"])
        # a model on this computer / the LAN, or offline: tokens only, nothing to warn about
        for cfg in ({"mode": "openai_compat", "destination": "lan"},
                    {"mode": "offline", "destination": "none"}):
            self.assertEqual(w({}, cfg, None, some), [])

    def test_summary_carries_them(self):
        env = {"ANTHROPIC_API_KEY": KEY}
        self.assertEqual(usage.summary(self.db, env)["warnings"], [])
        settings.update(self.db, {}, {"ai.price_input": "0.5"})
        s = usage.summary(self.db, env)
        self.assertEqual(s["warnings"], ["price_half"])
        self.assertEqual(s["price"]["source"], "table")      # the table still prices it
        for code in i18n.CODES:
            for k in ("price_half", "budget_unchecked"):
                self.assertNotEqual(i18n.t("app.usage.warn_" + k, code), "app.usage.warn_" + k)


# --- 6. the demo month -----------------------------------------------------------------------------

class DemoMonthTests(unittest.TestCase):
    def test_rows_stay_in_the_current_month(self):
        for now in (datetime(2026, 11, 1, 0, 30, tzinfo=timezone.utc),
                    datetime(2026, 11, 2, 9, tzinfo=timezone.utc),
                    datetime(2026, 10, 31, 23, tzinfo=timezone.utc)):
            with tempfile.TemporaryDirectory() as d:
                path = Path(d) / "demo.db"
                demo.build(path, now=now)
                db = store.connect(path)
                try:
                    ts = [r[0] for r in db.execute("SELECT ts FROM ai_usage WHERE mode = 'demo'")]
                    self.assertEqual(len(ts), len(demo.DEMO_USAGE) + len(demo.DEMO_USAGE_LOCAL))
                    since = usage.month_start(now)
                    stamp = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    self.assertTrue(all(since <= t <= stamp for t in ts), (now, min(ts), max(ts)))
                    self.assertEqual(usage.month(db, now)["answers"], len(ts))
                finally:
                    db.close()


# --- 7. phone keyboards ------------------------------------------------------------------------------

class InputModeTests(unittest.TestCase):
    def test_money_fields_are_decimal(self):
        with tempfile.TemporaryDirectory() as d:
            db = store.connect(Path(d) / "x.db")
            items = {i["key"]: i for i in settings.describe(db, {}, "en")["items"]}
            db.close()
        for k in ("ai.monthly_budget", "ai.price_input", "ai.price_output"):
            self.assertEqual(items[k].get("inputmode"), "decimal", k)
        self.assertNotIn("inputmode", items["health.internet_probe"])
        js = (c7.ROOT / "netwarden/static/app.js").read_text(encoding="utf-8")
        self.assertIn("it.inputmode === 'decimal'", js)
        self.assertIn("USAGE_WARN", js)


if __name__ == "__main__":
    unittest.main()
