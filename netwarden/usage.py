"""
netwarden - usage.py: what the AI costs, counted on this computer (round 7 C).

Nothing here is sent anywhere - no telemetry. Each AI answer is one row in the local
`ai_usage` table: the provider, the model, the tokens the provider reported (or a local
estimate when it reported none) and an ESTIMATED cost from the price table below.

    Meter                       per answer: brain opens one, the provider reports into it
    price(vals, model, dest)    US$ per million tokens for this provider, or None
    record(db, env, ...)        store one answer -> the summary the chat shows under it
    month(db, env)              this local month's totals (the Settings "AI usage" card)
    budget(db, env)             the optional monthly budget: none | ok | near | over
    check(db, env, ...)         before a request: may it go out without asking?

Prices change. ANTHROPIC_PRICES is the one place they live, with the date they were
checked; ai.price_input / ai.price_output (settings) override it - for an OpenAI-compatible
cloud service, or when Anthropic's prices moved. A model on this computer or the LAN
(Ollama, LM Studio, ...) costs nothing per token here: tokens only, never a price.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone

from netwarden import activity, settings, store

# --- the price table ------------------------------------------------------------------

PRICES_CHECKED = "2026-10-24"
PRICES_SOURCE = "https://platform.claude.com/docs/en/about-claude/pricing"

# Anthropic Messages API, US$ per million tokens: (input, 5-minute cache write, cache read,
# output). Model ids match by prefix, longest first ("claude-opus-4-5-20251101" ->
# claude-opus-4-5). Haiku 5.5: its price for prompts up to 100k tokens (ours are far
# smaller). Check PRICES_SOURCE and update PRICES_CHECKED when you touch this.
ANTHROPIC_PRICES = {
    "claude-fable-5-1": (10.0, 12.5, 0.25, 50.0),
    "claude-mythos-5-1": (10.0, 12.5, 0.25, 50.0),
    "claude-fable-5": (10.0, 12.5, 1.0, 50.0),
    "claude-mythos-5": (10.0, 12.5, 1.0, 50.0),
    "claude-opus-5-5": (4.0, 5.0, 0.20, 20.0),
    "claude-opus-5": (5.0, 6.25, 0.50, 25.0),
    "claude-opus-4-8": (5.0, 6.25, 0.50, 25.0),
    "claude-opus-4-7": (5.0, 6.25, 0.50, 25.0),
    "claude-opus-4-6": (5.0, 6.25, 0.50, 25.0),
    "claude-opus-4-5": (5.0, 6.25, 0.50, 25.0),
    "claude-opus-4-1": (15.0, 18.75, 1.50, 75.0),
    "claude-opus-4": (15.0, 18.75, 1.50, 75.0),
    "claude-sonnet-5-5": (2.0, 2.5, 0.10, 10.0),
    "claude-sonnet-5": (2.0, 2.5, 0.20, 10.0),
    "claude-sonnet-4-6": (3.0, 3.75, 0.30, 15.0),
    "claude-sonnet-4-5": (3.0, 3.75, 0.30, 15.0),
    "claude-sonnet-4": (3.0, 3.75, 0.30, 15.0),
    "claude-haiku-5-5": (0.10, 0.125, 0.01, 0.50),
    "claude-haiku-4-5": (1.0, 1.25, 0.10, 5.0),
    "claude-3-5-haiku": (0.80, 1.0, 0.08, 4.0),
}
_BY_LENGTH = sorted(ANTHROPIC_PRICES, key=len, reverse=True)

TYPICAL_OUTPUT = 500     # tokens a reply usually takes, for the "before you send" estimate


def table_price(model: str | None) -> dict | None:
    """The built-in price of an Anthropic model id, or None if we do not know it."""
    m = (model or "").strip().lower()
    for key in _BY_LENGTH:
        if m == key or m.startswith(key + "-"):
            i, w, r, o = ANTHROPIC_PRICES[key]
            return {"input": i, "cache_write": w, "cache_read": r, "output": o,
                    "source": "table", "checked": PRICES_CHECKED, "model_key": key}
    return None


def _money(value) -> float | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if v > 0 and math.isfinite(v) else None


def price(vals: dict, mode: str, model: str | None, destination: str) -> dict | None:
    """US$ per million tokens for this answer's provider, or None (no price: a model on
    this computer / the LAN, or a cloud model we have no price for). The settings
    ai.price_input + ai.price_output win over the table; with only those two numbers a
    cached token costs the input price (an upper bound - providers bill it lower)."""
    if destination in ("local", "lan", "none"):
        return None
    i, o = _money(vals.get("ai.price_input")), _money(vals.get("ai.price_output"))
    if i is not None and o is not None:
        return {"input": i, "cache_write": i, "cache_read": i, "output": o, "source": "settings"}
    return table_price(model) if mode == "anthropic" else None


def cost(tokens: dict, p: dict | None) -> float | None:
    """US$ for {input_tokens, output_tokens, cache_write_tokens, cache_read_tokens}."""
    if p is None:
        return None
    return round((tokens.get("input_tokens", 0) * p["input"] +
                  tokens.get("cache_write_tokens", 0) * p["cache_write"] +
                  tokens.get("cache_read_tokens", 0) * p["cache_read"] +
                  tokens.get("output_tokens", 0) * p["output"]) / 1e6, 6)


# --- counting -------------------------------------------------------------------------

def estimate_tokens(text: str | None) -> int:
    """A rough local token count (no tokenizer here, and none is sent anywhere): about 3
    characters per token for ASCII (our prompts are JSON-heavy, which tokenizes worse
    than prose) and one per other character (CJK). Good to +-30% - a guide, not a bill."""
    if not text:
        return 0
    ascii_n = sum(1 for c in text if ord(c) < 128)
    return math.ceil(ascii_n / 3 + (len(text) - ascii_n))


class Meter:
    """The usage of ONE answer, which may take several requests (a tool loop). brain
    calls begin(estimated input tokens) before each request and text(chunk) for what it
    streams back; the provider calls report(...) with what the API said. A request the
    provider reported nothing for counts with the local estimate (estimated=True); one
    that neither reported nor answered (it failed) is not counted."""

    def __init__(self):
        self.requests: list = []

    def begin(self, est_input: int) -> None:
        self.requests.append({"est_in": int(est_input), "out": [], "got": None})

    def text(self, chunk: str) -> None:
        if self.requests and chunk:
            self.requests[-1]["out"].append(chunk)

    def report(self, input_tokens=0, output_tokens=0, cache_write=0, cache_read=0) -> None:
        """What the API reported for the current request (later reports of the same
        request - a stream's final output count - replace the earlier numbers)."""
        if not self.requests:
            self.begin(0)
        got = self.requests[-1]["got"] or {}
        for k, v in (("input_tokens", input_tokens), ("output_tokens", output_tokens),
                     ("cache_write_tokens", cache_write), ("cache_read_tokens", cache_read)):
            try:
                n = int(v or 0)
            except (TypeError, ValueError):
                n = 0
            if n > 0 or k not in got:
                got[k] = max(0, n)
        self.requests[-1]["got"] = got

    def totals(self) -> dict | None:
        """{requests, input_tokens, output_tokens, cache_write_tokens, cache_read_tokens,
        estimated} of the whole answer, or None if no request counted."""
        out = {k: 0 for k in store.USAGE_FIELDS}
        estimated = False
        for r in self.requests:
            got, said = r["got"], "".join(r["out"])
            if not got and not said:
                continue                     # failed before it answered: nothing billed
            out["requests"] += 1
            if not got or not (got.get("input_tokens") or got.get("cache_read_tokens")
                               or got.get("cache_write_tokens")):
                estimated = True
                got = {"input_tokens": r["est_in"],
                       "output_tokens": (got or {}).get("output_tokens") or estimate_tokens(said)}
            for k in ("input_tokens", "output_tokens", "cache_write_tokens", "cache_read_tokens"):
                out[k] += int(got.get(k) or 0)
        if not out["requests"]:
            return None
        out["estimated"] = estimated
        return out


def _describe(provider) -> tuple:
    """(provider label, destination) of a provider object, never a URL or a key."""
    name = getattr(provider, "name", None) or type(provider).__name__
    return str(name)[:60], getattr(provider, "destination", None) or "cloud"


def _mode_of(provider) -> str:
    return "anthropic" if type(provider).__name__ == "AnthropicProvider" else "openai_compat"


def record(db, env: dict | None, provider, mode: str, totals: dict | None) -> dict | None:
    """Store one finished answer; returns what the chat shows under it: {tokens, requests,
    input_tokens, output_tokens, cache_write_tokens, cache_read_tokens, estimated,
    cost_usd (None = no price), local, provider, model, price_source, budget}."""
    if not totals:
        return None
    label, dest = _describe(provider)
    model = str(getattr(provider, "model", None) or "?")[:120]
    vals = settings.values(db, env or {})
    p = price(vals, _mode_of(provider), model, dest)
    usd = cost(totals, p)
    row = {"provider": label, "model": model, "destination": dest, "mode": mode,
           **{k: totals[k] for k in store.USAGE_FIELDS}, "estimated": totals["estimated"],
           "cost_usd": usd}
    try:
        store.add_ai_usage(db, row)
    except Exception:   # noqa: BLE001 - a read-only / busy DB must not break the answer
        pass
    tokens = sum(totals[k] for k in ("input_tokens", "output_tokens", "cache_write_tokens",
                                     "cache_read_tokens"))
    b = budget(db, env)
    return {**{k: totals[k] for k in store.USAGE_FIELDS}, "tokens": tokens,
            "estimated": totals["estimated"], "cost_usd": usd, "local": dest in ("local", "lan"),
            "provider": label, "model": model, "price_source": p and p["source"],
            "prices_checked": PRICES_CHECKED,
            "budget": {k: b[k] for k in ("state", "share", "spent", "limit")}}


# --- this month and the budget --------------------------------------------------------

def month_start(now: datetime | None = None) -> str:
    """The first moment of the current LOCAL month, as a UTC ISO string."""
    tz = activity.local_tz()
    local = (now or datetime.now(timezone.utc)).astimezone(tz)
    first = local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return first.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def month(db, now: datetime | None = None) -> dict:
    """This local month: {since, month, answers, requests, tokens..., cost_usd, priced,
    unpriced (answers without a price), estimated, by_model: [...]}."""
    since = month_start(now)
    rows = store.ai_usage_since(db, since)
    keys = ("answers",) + store.USAGE_FIELDS
    out = {k: sum(int(r[k] or 0) for r in rows) for k in keys}
    out["cost_usd"] = round(sum(float(r["cost_usd"] or 0) for r in rows), 6)
    out["priced"] = sum(int(r["priced"] or 0) for r in rows)
    out["unpriced"] = out["answers"] - out["priced"]
    out["estimated"] = sum(int(r["estimated"] or 0) for r in rows)
    out["tokens"] = sum(out[k] for k in ("input_tokens", "output_tokens", "cache_write_tokens",
                                         "cache_read_tokens"))
    tz = activity.local_tz()
    out["month"] = (now or datetime.now(timezone.utc)).astimezone(tz).strftime("%Y-%m")
    out["since"] = since
    out["by_model"] = [{"provider": r["provider"], "model": r["model"],
                        "destination": r["destination"], "answers": r["answers"],
                        "tokens": sum(int(r[k] or 0) for k in store.USAGE_FIELDS[1:]),
                        "cost_usd": round(float(r["cost_usd"] or 0), 6) if r["priced"] else None}
                       for r in rows[:12]]
    return out


def budget_limit(vals: dict) -> float | None:
    return _money(vals.get("ai.monthly_budget"))


def budget(db, env: dict | None, now: datetime | None = None, spent: float | None = None) -> dict:
    """{state, limit, spent, share, warn_pct}: state "none" (no budget set), "ok",
    "near" (spent >= ai.budget_warn % of it) or "over" (spent >= the budget)."""
    vals = settings.values(db, env or {})
    limit, warn = budget_limit(vals), vals["ai.budget_warn"]
    if spent is None:
        spent = month(db, now)["cost_usd"]
    out = {"state": "none", "limit": limit, "spent": round(spent, 6), "share": None,
           "warn_pct": warn}
    if limit is None:
        return out
    share = spent / limit
    out["share"] = round(share, 4)
    out["state"] = "over" if share >= 1 else ("near" if share * 100 >= warn else "ok")
    return out


def check(db, env: dict | None, provider, est_input: int, confirmed: bool = False) -> dict | None:
    """Before an answer goes out: None = send it; else {"state": "over" | "would_exceed",
    budget..., "estimate_usd"} = ask the user first (never fail silently, never send
    silently past the budget). `confirmed` = the user already said "send anyway"."""
    if confirmed:
        return None
    vals = settings.values(db, env or {})
    if budget_limit(vals) is None:
        return None
    label, dest = _describe(provider)
    p = price(vals, _mode_of(provider), getattr(provider, "model", None), dest)
    if p is None:          # tokens only: nothing to count against a money budget
        return None
    est = cost({"input_tokens": est_input, "output_tokens": TYPICAL_OUTPUT}, p) or 0.0
    b = budget(db, env)
    if b["state"] == "over":
        return {**b, "estimate_usd": est}
    if b["spent"] + est > b["limit"]:
        return {**b, "state": "would_exceed", "estimate_usd": est}
    return None


class Guard:
    """The budget DURING one answer that takes several requests (a tool loop): check()
    only looked at the first request. Before each further request brain asks fits(meter,
    est_input, n): would this answer so far plus n more requests of about est_input
    tokens (+ TYPICAL_OUTPUT each) stay within the budget? Input is priced at the full
    input price (an upper bound: with prompt caching most of it is a cheap cache read)."""

    def __init__(self, limit: float, spent: float, p: dict):
        self.limit, self.spent, self.p = limit, spent, p

    def fits(self, meter: Meter, est_input: int, n: int = 1) -> bool:
        so_far = cost(meter.totals() or {}, self.p) or 0.0
        each = cost({"input_tokens": est_input, "output_tokens": TYPICAL_OUTPUT}, self.p) or 0.0
        return self.spent + so_far + n * each <= self.limit


def guard(db, env: dict | None, provider, confirmed: bool = False) -> Guard | None:
    """A Guard for this answer, or None: no budget, no price (tokens only), or the user
    already said "send anyway" (then the whole answer may go over - they agreed)."""
    if confirmed:
        return None
    vals = settings.values(db, env or {})
    limit = budget_limit(vals)
    if limit is None:
        return None
    _label, dest = _describe(provider)
    p = price(vals, _mode_of(provider), getattr(provider, "model", None), dest)
    if p is None:
        return None
    return Guard(limit, budget(db, env)["spent"], p)


def summary(db, env: dict | None, now: datetime | None = None) -> dict:
    """GET /api/ai/usage: this month, the budget, and the price in use for the AI that
    is configured now (with the date the table was checked)."""
    from netwarden import brain   # brain imports us
    m = month(db, now)
    cfg = brain.ai_config(env or {}, db)
    vals = settings.values(db, env or {})
    p = None if cfg["mode"] == "offline" else price(vals, cfg["mode"], cfg["model"],
                                                    cfg["destination"])
    b = budget(db, env, now, spent=m["cost_usd"])
    return {"month": m, "budget": b, "price": p, "prices_checked": PRICES_CHECKED,
            "ai_mode": cfg["mode"], "local": cfg["destination"] in ("local", "lan"),
            "model": cfg["model"], "warnings": warnings(vals, cfg, p, b)}


def warnings(vals: dict, cfg: dict, p: dict | None, b: dict) -> list:
    """What the Settings card must say about prices that do not work as the user may
    think (app.usage.warn_<key>):
      price_half        only one of ai.price_input / ai.price_output is set: both are
                        needed, so the built-in table (or no price at all) is in use
      budget_unchecked  a budget is set, but the configured cloud AI has no price - the
                        budget cannot be checked (nothing is counted against it)"""
    out = []
    if (_money(vals.get("ai.price_input")) is None) != (_money(vals.get("ai.price_output")) is None):
        out.append("price_half")
    if b["limit"] is not None and p is None and cfg["mode"] != "offline" \
            and cfg["destination"] not in ("local", "lan", "none"):
        out.append("budget_unchecked")
    return out
