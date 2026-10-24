# Private AI: run the assistant on your own hardware

netwarden's assistant can use one of three "brains". You choose under **System → AI**
in the dashboard, or with environment variables in `.env` (environment wins, and keys
set there are read-only in the dashboard).

| `ai.provider` | What answers | Where your data goes |
|---|---|---|
| `offline` | rule-based summary built into netwarden | nowhere |
| `openai_compat` | a model server you run: Ollama, LM Studio, llama.cpp, vLLM | that server (local / LAN / cloud badge) |
| `anthropic` | Claude (needs `ANTHROPIC_API_KEY`) | Anthropic's cloud |
| `auto` (default) | Anthropic if its key is set, else your server if `ai.base_url` is set, else offline | |

The AI panel always shows a **destination badge**: offline, this computer, your
network, or cloud (amber), plus an eye-off tag when redaction is on. Loopback addresses are "this computer"; private / link-local IPs and
`.local` / `.lan` / `.home.arpa` / single-label names are "your network"; every other
host counts as cloud (names are never resolved to decide).

## Ollama in five minutes

```bash
# on this computer or any machine on your LAN
ollama pull llama3.2          # ~2 GB; qwen2.5:7b answers better if you have the RAM
ollama serve                  # listens on 127.0.0.1:11434
```

Then in **System → AI**: provider *Local model (Ollama, LM Studio, …)*, server
`http://127.0.0.1:11434/v1`, model `llama3.2` → **Save** → **Test connection** (lists the
server's models - click one to use it - and asks for a one-word reply). For a server on
another machine use its LAN address, e.g. `http://192.168.1.20:11434/v1` (start Ollama
with `OLLAMA_HOST=0.0.0.0`). LM Studio: start its server (port 1234) and use
`http://127.0.0.1:1234/v1`.

Same with `.env` (then read-only in the dashboard):

```
NETWARDEN_AI_PROVIDER=openai_compat
NETWARDEN_AI_BASE_URL=http://127.0.0.1:11434/v1
NETWARDEN_AI_MODEL=llama3.2
NETWARDEN_AI_REDACT=auto        # auto | on | off
NETWARDEN_AI_KEY=...            # only if your server wants a bearer token
```

Notes:
- Base URLs must be plain `http(s)://host[:port][/path]`: no `user:pass@`, query or
  fragment. A token goes in `NETWARDEN_AI_KEY` (environment only, never stored or shown).
- Requests to a local / LAN server bypass any HTTP proxy, and redirects are only followed
  on the same origin.
- Connecting gives up after 5 s ("is Ollama running?"); the answer itself may take up to
  2 minutes (a model loading on first use is slow).
- **Test connection** only works for local / LAN servers and only on click. It never
  calls Anthropic or any cloud endpoint.
- Small local models are noticeably weaker than Claude at reasoning over a 300-device
  snapshot; 7B+ models are recommended.

## Redaction (`ai.redact`)

`auto` (default) = on when the destination is cloud, off for local / LAN. `on` / `off`
force it. With redaction on, before anything is sent:

- device names, labels, hostnames → `[D3]`; MACs → `[M3]`; IPs → `[IP3]`
- owners (people) → `[P1]`; rooms → `[R2]`
- any other MAC or private IPv4 in the text (also what you type) → a fresh token

The reply is mapped back to the real names on the netwarden server, also while it streams
(a token split across chunks, `[D` + `3]`, is held back until complete). Tokens are stable
for an unchanged inventory, so follow-up questions keep the same numbers.

**What redaction does NOT hide:** the domains and services devices use (that is what
the AI reasons about), vendors and device types, counts and times, public IPs, and any
name you type that netwarden does not know. Matching is text-based, so a device named
with a common word ("TV", "Office") is also replaced wherever that word appears.

**Preview what will be sent** (button in the chat) shows the exact system and user text
for the current conversation, plus a local-only legend of the tokens. Nothing is sent
when you open it.

## AI usage and a monthly budget

Every AI answer records, **in your own database only** (no telemetry), the provider, the
model, the tokens the provider reported (input, output, cache write, cache read) and an
estimated cost. Under each answer, a small expandable note says "about N tokens, ~US$x";
**Settings → AI usage** shows this month's totals per model.

- **Prices**: a built-in table of Anthropic's list prices (`netwarden/usage.py`, with
  the date they were checked). Prices change: treat the cost as an estimate and check
  Anthropic's pricing page. For another cloud service (OpenAI-compatible), enter your own
  `ai.price_input` / `ai.price_output` (US$ per million tokens); without them, only tokens
  are shown. A model on this computer or your LAN costs nothing here: tokens only.
- **Budget** (`ai.monthly_budget`, US$, empty = none; `ai.budget_warn`, default 80 %):
  the AI usage card and the note under answers warn as you get close. Once a question
  would go over the budget, the chat **asks first** ("Send anyway" / Cancel) and sends
  nothing until you confirm. An answer that looks things up is checked again before each
  lookup round: close to the budget it stops looking up and answers with what it has
  (and says so). The month is your local calendar month. The budget only counts AIs
  with a price: for a cloud service without one, the card says the budget can't be
  checked; set both of your own prices.
- When a provider reports no usage (some local servers), the tokens are a rough local
  estimate (marked "estimated").
- Anthropic **prompt caching** is used automatically: the instructions and tool
  descriptions, and within one answer the conversation so far, are marked cacheable, so
  follow-up requests in a tool loop and questions a few minutes apart are billed at the
  much cheaper cache-read price. Prompts shorter than the model's minimum are simply not
  cached. Details: [docs/dev/ai_cost.md](dev/ai_cost.md).

## API

- `GET /api/ai/usage?lang=` → `{month: {answers, tokens, cost_usd, by_model, ...},
  budget: {state none|ok|near|over, limit, spent, share}, price, prices_checked, local}`.
- `/api/chat/stream` sends `event: usage` after an answer and `event: budget` (nothing
  sent) when a question needs your OK; resend with `"budget_ok": true` to go ahead.
  `POST /api/insight|ask|chat` answer `409 {error, budget}` in that case (nothing sent)
  and take the same `"budget_ok": true`.
- `GET /api/settings?lang=` → `{items: [{key, value, source: env|db|default, editable,
  ...}], ai}`; secrets show only `configured`.
- `POST /api/settings {values: {key: value|null}}` → loopback + same-origin only,
  all-or-nothing, `400 {error, key}` on a bad value, env-set keys refused.
- `POST /api/chat/preview {mode, messages, mac?, lang}` → `{destination, redact, system,
  user, legend, chars, ...}` (never calls the model).
- `POST /api/ai/test {lang}` → `{ok, server, models, model_found, reply, latency_ms,
  error_kind, error_text}`; 409 when the provider is not `openai_compat` or the
  destination is cloud.
- `/api/meta` and `/api/status` carry `ai_mode`, `ai_destination`, `ai_redact`, model,
  provider - never a URL.
