# Contributing to netwarden

Thank you for helping. Bug reports, translation fixes, device-identification rules and small,
focused pull requests are the most useful contributions right now. For anything larger,
please open an issue first so we can agree on the approach.

Security problems: **do not** open a public issue - see [SECURITY.md](SECURITY.md).
Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules (they decide most reviews)

- **Zero runtime dependencies.** Python standard library only: `urllib` for HTTP,
  `http.server` for the dashboard, `sqlite3` for storage. No FastAPI, requests, httpx, SDKs.
  Vendored code only with a compatible license and a note in
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- **Dashboard = vanilla JS/CSS** in `netwarden/static/`: no build step, no npm, no CDN, no web
  fonts, nothing loaded from the internet. Both themes, phone (~375 px) and desktop
  (~1280 px), full keyboard access, WCAG 2.2 AA contrast.
- **Read-only toward the network.** Never change a router, firewall, AdGuard Home or Pi-hole;
  offer steps or copyable rules instead. No ARP spoofing, no MITM, no telemetry.
- **The AI is called only on an explicit user action** - never from background loops or
  page loads.
- **Hostile input everywhere**: device names, mDNS/SSDP/UPnP strings and owner names are
  escaped in HTML, CSV cells go through `export.safe_cell`, secrets never reach responses or logs.
- **Every user-facing string is translated** (see below).

[CLAUDE.md](CLAUDE.md) is the architecture map and the list of conventions; it is written for
human contributors and AI coding assistants alike. Design notes live in [docs/dev/](docs/dev/).

## Development setup

Python 3.11 or newer on Linux, macOS or WSL2. Nothing to install:

```bash
git clone https://github.com/liming-ting/netwarden netwarden && cd netwarden
python3 -m netwarden run --demo --offline-ai     # synthetic demo home on http://127.0.0.1:8787
```

`--offline-ai` guarantees no model is called; `/api/meta` then reports `"ai_mode": "offline"`.
Use a separate port and a copy of the demo database for experiments
(`python3 -m netwarden.web --db /tmp/demo-copy.db --port 8799 --offline-ai`).

## Tests

```bash
python3 -m unittest discover -s tests          # the full suite (1000+ tests)
python3 -m unittest tests.test_web -v          # one module
node tests/js/map_layout_test.js               # the network-map layout (needs Node.js)
python3 -m netwarden.i18n --check              # locale files
python3 -m compileall -q netwarden
```

Tests never touch the real network or a real AI: they use fake servers on ephemeral
`127.0.0.1` ports and fake providers. They must pass on a fresh checkout with `TZ=UTC` and no
`.env`, and create every file they need (databases, fixtures) themselves. Pin clocks
(`demo.build(path, now=...)`) instead of depending on the time of day, and write
expectations in a pinned zone (`tests/tzkit.py`: `with pinned_tz("Asia/Taipei"): ...`) or in
whatever zone the test runs in. Every change comes with tests; CI runs the same commands on
every pull request, under `TZ=UTC` and `TZ=Asia/Taipei`, plus the time-sensitive modules
under America/Los_Angeles and Pacific/Auckland.

Before you push anything that touches times, days or the demo data, run the suite in
several zones (UTC, Taipei, Los Angeles, Kolkata with its half-hour offset, Auckland; it
sets `NETWARDEN_TZ` too, so a local `.env` cannot pin them all to one zone):

```bash
bash scripts/dev/tz_sweep.sh                             # full suite, five zones (~15 min)
bash scripts/dev/tz_sweep.sh Europe/Berlin               # one zone of your choice
TESTS="tests.test_stage_q tests.test_cli" bash scripts/dev/tz_sweep.sh   # a few modules
```

Heavier checks: `NETWARDEN_FUZZ=heavy python3 -m unittest tests.test_stage_k_fuzz`,
`python3 scripts/perf_db.py all` (300-device timing DB under /tmp),
`python3 scripts/soak.py --minutes 20 --port 8799`.

## Translations (12 languages)

Locales live in `netwarden/locales/<code>.json`: en, zh-Hant (the default), zh-Hans, es,
pt-BR, ja, de, fr, ko, ru, id, hi. Rules:

- A new user-facing string (UI, API text, alerts, digest, CLI output) gets a key in **every**
  locale file - a real translation, not English. Keep `{placeholders}` exactly.
- zh-Hant must be genuinely Traditional Chinese with Taiwan usage; zh-Hans genuinely
  Simplified. Chinese punctuation in these files uses ASCII `, : ( )`.
- Strings that are intentionally identical to English (brand names, units) are listed in
  `netwarden/locale_same_ok.json`.
- Run `python3 -m netwarden.i18n --check` and the i18n tests. After editing locales, restart
  the server (they are read at start).
- Adding a language: copy `en.json` to `<code>.json`, translate, set its `_meta` block, run
  the check.

Most non-English translations were machine-assisted. Native speakers: corrections are very
welcome, even a single string.

## Style

- Match the plain, commented style of `netwarden/discovery.py` and `netwarden/dns_ingest.py`:
  small functions, comments that say *why*, no clever abstractions.
- New data sources are adapters like `dns_ingest.Source`; when unconfigured they change nothing.
- New settings go through `netwarden/settings.py` (`register(Setting(...))`) and get a
  `settings.<key>` locale key; they then appear on the Settings page.
- Data-changing POSTs follow the LAN-mode rules in [docs/lan.md](docs/lan.md) (admin actions
  are loopback / admin-session only).
- Demo data: if a feature needs a story, extend `netwarden/demo.py` (deterministic, idempotent,
  never overwriting user edits).

## Pull requests

- One topic per pull request; describe what changed and how you tested it.
- Include screenshots for UI changes (demo data only - never your own network's devices,
  addresses or names).
- No secrets, no real MAC/IP addresses or hostnames in code, tests, docs or screenshots; use
  neutral examples such as `192.168.1.x` and `aa:bb:cc:00:00:01`.

## License of contributions

netwarden is licensed under the GNU AGPL v3 or later ([LICENSE](LICENSE), SPDX
`AGPL-3.0-or-later`). By submitting a contribution you agree that it is licensed under that
same license (inbound = outbound). There is no contributor license agreement (CLA) and no
`Signed-off-by` (DCO) requirement. Only submit work you have the right to contribute; code
from elsewhere needs a compatible license and an entry in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
