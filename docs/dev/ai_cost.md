# AI cost efficiency and usage visibility (round 7 C)

Code: `netwarden/usage.py` (prices, Meter, budget), `brain.py` (prompt parts, caching,
metering), `localai.py` (OpenAI-style usage), `store.py` (`ai_usage`), `web.py`
(`event: usage|budget`, `GET /api/ai/usage`), `static/app.js` (`usageNote`,
`usageStatus`). Tests: `tests/test_round7_c.py` (fake model servers on 127.0.0.1 only).

## Prompt caching (Anthropic)

Checked against the prompt-caching docs on 2026-10-24: up to 4 breakpoints, prefix order
tools -> system -> messages, default TTL 5 min (a read refreshes it), a minimum cacheable
length per model (512 tokens on the Claude 5.5 / 5.1 family, 1024-4096 on older models;
shorter prompts are just not cached), writes cost 1.25x input, reads 0.1x or less.

What netwarden marks (`AnthropicProvider.system_blocks` / `mark_last`):

| request | breakpoint 1 | breakpoint 2 |
|---|---|---|
| chat with tools, every round but the last | end of the stable system text (covers the tool definitions before it) | the last content block of the conversation (the snapshot + history + tool results so far) |
| final tool round (`tool_choice: none`) | system | - (changing tool_choice invalidates the messages cache anyway) |
| chat without tools | system | - |
| insight / legacy `/api/ask` | none (one-off requests) | - |

- **Stable vs volatile:** `brain._chat_parts` splits the prompt; the system text is the
  same bytes for every question in a language (`cache_cut`), the per-question focus /
  alert line goes AFTER the cut as a second, uncached system block.
- **No breakpoint on the snapshot itself**: it changes every ~60 s (DNS ingest), so a
  cross-question breakpoint there would mostly write and rarely read.
- Within a tool loop round N+1 resends round N byte-for-byte plus the new tool results,
  so it reads everything up to round N's breakpoint. The snapshot is sent once per
  request (in the first user turn), never repeated.
- Tool definitions are never edited per request (that would invalidate everything).

## Trimming (measured on the demo home, chat + 1 earlier exchange)

Local estimate (`usage.estimate_tokens`: ASCII chars / 3 + 1 per non-ASCII char; about
+-30 % vs. a real tokenizer). "Before" = round 6 code on the same input.

| part | before (chars) | after (chars) | after (est. tokens) |
|---|---:|---:|---:|
| system + tools paragraph | 4008 + 1170 | 4095 + 1170 | 1368 (system) |
| tool schemas (13) | 8121 | 7634 (compact JSON) | 2935 (with the paragraph) |
| injected context (snapshot) | 28 916 (indented JSON) | 12 869 (-55 %) | 4362 |
| history (3000-char earlier answer) | 3000+ (uncapped) | 2169 (capped) | 723 |
| **total per request** | ~17-18k tokens (round 6 measurement) | | **~9.4k** |

What was cut: indentation; `services` (duplicated by `top_domains`), `type_detail`,
hostname equal to the name, empty / false / 0 fields; `top_domains` objects -> one line
each (`domain xN service/category BLOCKED (routine...)`); threat `ips` and repeated `why`
texts. History: older turns clipped to 2000 chars, 12 000 chars in total, the last
message always whole (`brain.trim_history`), **scrubbed before clipping** so a cut never
leaves half a real name. Tool results keep their existing caps (50 rows / 8 KB, Session
24 KB).

Redaction is unchanged: `test_redacted_payload_before_and_after` renders the same
redacted snapshot the old way and the new way and checks that neither contains any real
value from the legend and both carry the same pseudonym set; a tool-loop test checks
every request body.

## Usage recording

- `usage.Meter` per answer: each request `begin(estimated input)`, streamed text,
  provider reports (`message_start` / `message_delta` / JSON `usage`; OpenAI
  `stream_options.include_usage`, `prompt_tokens_details.cached_tokens`). A server that
  refuses `stream_options` is retried once without it and remembered per base URL.
  Requests that failed before answering are not counted; nothing reported = estimate.
- `ai_usage` rows (provider, model, destination, mode, requests, 4 token fields,
  estimated, cost_usd or NULL) are kept 400 days (`store.USAGE_KEEP_DAYS`), separately
  from `NETWARDEN_RETENTION_DAYS`. Not part of backups (history, not user notes).
- Offline mode records nothing.

## Prices and the budget

- `usage.ANTHROPIC_PRICES` is the ONE price table (US$ / MTok: input, 5-min cache write,
  cache read, output), `PRICES_CHECKED` the date. Longest-prefix match on the model id
  (dated ids work). Unknown model -> tokens only. Settings `ai.price_input` /
  `ai.price_output` override (cache tokens then billed at the input price); local / LAN
  destinations are never priced.
- The budget gate (`usage.check`) runs before anything is sent, on the streaming chat
  AND the JSON endpoints (`/api/insight|ask|chat` -> `409 {error, budget}`,
  `brain.BudgetNeeded`): state `over` (spent >= limit) or `would_exceed` (spent + this
  question's first request, assuming ~500 output tokens). The UI asks; `budget_ok: true`
  (JSON true only) sends once.
- A tool loop is checked again before EVERY further request (`usage.Guard`, input priced
  at the full input price - an upper bound): when this request and one more would not
  both fit, this round answers without lookups (note `budget_limit`); when not even this
  one fits, nothing more is sent (note `budget_stop`). `budget_ok` skips the guard too
  (the user agreed to go over).
- Earlier turns that do not fit the history cap are dropped oldest first; the model gets
  `brain.OMITTED` ("N earlier messages left out") and the user the note `history_trimmed`.
- The Settings card warns (`usage.warnings`): `price_half` (only one own price set: both
  are needed, so the table / no price is in use) and `budget_unchecked` (a budget, but a
  cloud AI without a price: nothing counts against it).
- Demo rows (`mode` = `demo`, `demo.build_ai_usage`) are scaled into the current local
  month, so the card is never empty early in a month.

## Honest limits

- Costs are estimates from list prices; discounts, taxes, the 1-hour TTL, batch or
  regional pricing are not modelled. Anthropic's console is the bill.
- Cache hits depend on Anthropic (TTL, minimum length, workspace); netwarden only places
  the breakpoints and shows what the API reports.
- Token estimates for providers that report nothing are rough.
