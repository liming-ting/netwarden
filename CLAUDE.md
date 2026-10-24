# netwarden — project guide for Claude Code

## What we're building (and why)

An **AI home-network manager** (codename). MVP job: one **"magic moment"** - tell the user something about *their
own* network they didn't know, in plain language. **See** (discover + identify), **Watch** (per-device DNS, optional
bytes), **Explain** (LLM insight + Q&A).

**Principles:**
- **Read-only + suggest.** Never change router/firewall. User actions (mute, trust, rename) only write the user's
  own notes in netwarden's SQLite. Rules are copy-only. **LLM off the hot path:** summarized snapshots, on demand.
- **Zero runtime dependencies (FIRM).** stdlib only: `urllib` (Anthropic API, AdGuard, ntopng), `http.server`
  (dashboard), `sqlite3`. Never add FastAPI / the anthropic SDK / httpx / anything. Dashboard = vanilla JS/CSS, no
  CDN/fonts/build step.
- **Privacy is the product.** No telemetry, no cloud calls except the explicit LLM brain (and the opt-in,
  download-only threat-feed update). Never ARP-spoof / MITM.
- **Open-core:** open-source local agent + paid cloud "brain" later; ship as HA add-on / Docker — no hardware. UI
  default **繁體中文 (zh-Hant)**; homelab users and families.
- **We do NOT rebuild DNS logging or traffic sniffing** (Pi-hole, AdGuard Home, ntopng): we ingest from them and
  spend effort on the AI reasoning / conversation layer.

## Architecture

```
netwarden/
  __main__.py       unified CLI: run web scan ingest traffic alerts demo status prune check
                    search identify health pair backup restore (some delegate to main(argv, prog))
  people.py         Stage P: person (name/avatar/color/child/note); device -> person|shared|none
  presence.py       opt-in who's home: decide(), timeline(), link_suggestions() (private MACs),
                    check_recorded() light ping; notify.route() = THE ONE notification gate
  quiet.py notify.py tuning.py explain.py hygiene.py  Stage Q: quiet hours (held -> ONE summary
                    per window); acks mute:|less:<kind>; "Why this alert?"; router hygiene
  channels.py push.py  round 10 N: push adapters build()/preview()/send() (ONE network fn, no redirects, pin) |
                    channels/outbox/log, collect() (notify loop) -> deliver() (push loop 15 s), render() (no LLM)
  inbox.py          Stage X: alerts + open suggestions in one queue; act() ack|mute|trust|snooze|dismiss|
                    done (+ undo), validated, <= 200 refs; a fixing suggestion rides on it as item.fix (_fixes)
  backup.py         netwarden-backup v1 (user notes only, no secrets/phones); validate/preview/restore merge|
                    replace, 1 tx, 1 MB; conntest.py; firstrun.py (meta setup.*); naming.py display_names
  nethealth.py      Stage H: gateway probe (ping fixed args / TCP 80,443,53), optional internet
                    probe setting; DNS SERVFAIL/REFUSED as a signal; outages (router|isp|dns|unknown)
  suggestions.py    actionable items from every module: stable ids, severity, steps/platform,
                    copy rules; status open|done|dismissed|snoozed; "took effect" from the data
  score.py          0-100 home score: 4 pillars x 25 (unmeasured left out), deductions, trend
  identify.py       mDNS/SSDP (LOCATION: own private IP, 64 KB, safe_xml)/NetBIOS/DHCP/PTR -> device_identity
  upnp.py           IGD: ONLY ALLOWED_ACTIONS (GetExternalIPAddress/StatusInfo/GenericPortMappingEntry, 256)
  routine.py        domain -> connectivity|time|updates|certs|cdn|cloud (calm text, LLM_TEXT)
  screentime.py     Stage F: DNS -> device x service x local day minutes (sessions with a
                    per-category gap/tail; routine/trackers/blocked/unknown excluded; <= 60 min/h)
  bedtime.py        notify-only rules (owner|mac, nights, window may cross midnight, min min);
                    hits/alerts/preview; suppress_night() hides unusual_hours a rule covers
  weekly.py         this week vs 7 d earlier, highlights(); family_report.py /report/weekly (printable)
  report.py         round 9 X (docs/report.md): build() -> {meta, sections} -> render_html|md; privacy full|
                    shareable|minimal, Scrubber.deep() over the FINISHED doc (redact + any IP/domain -> •••);
                    GET /api/report (full = admin), CLI `report`, page #/report; the file: no JS, no external refs
  runner.py         `run` loops (thread + conn, backoff): dns 60 s | traffic 30 s | discovery 15 min | health
                    60 s | prune daily; plan(env); log 1 MB x 3; warm() (never the LLM); Warmer keep-warm 20 s
  cache.py          memo(db, name, args, compute): per DB, fingerprint of tables read (+ notes), TTL 30 s,
                    single-flight, copies; never ":memory:"; batch() = 1 fingerprint/request; stale 90 s
  health.py         status(); sanitize_error() (userinfo, auth, sk-, sid=/token=/key=, given +
                    URL-encoded secrets); opener() = same-origin-redirect urllib for sources
  offline_ai.py     OfflineProvider.answer(db, snap, lang, question, focus): SECTIONS [(fn(ctx) -> lines, notable)] - EXTEND
  privacy.py        TRACKERS (~195 + data/trackers_custom.txt) -> grade A-F (unblocked tracker
                    share <3/10/20/40%), worst(), block_rules() (AdGuard ||d^ + Pi-hole)
  visibility.py     DNS blind spots: DoH/DoT bootstrap + Firefox canary; quiet (>6 h); never (7 d)
  exposure.py       OPT-IN TCP-connect of FIXED PORTS (0.8 s, sends nothing), private inventory IPs; demo -> DemoRefused
  devicetype.py     rule votes (hostname/vendor/services/traffic/self/randomized) -> TYPES key
                    + confidence + reason{key, params}; user override (device_profiles) wins
  settings.py       typed REGISTRY (key/type/default/env/validator/group/secret/admin);
                    effective = env > DB `settings` table > default; describe/update/apply;
                    destination(url) -> local|lan|cloud|none (names never resolved)
  localai.py        OpenAICompatibleProvider (/chat/completions SSE + JSON fallback, /models; 5 s / 120 s; no proxy LAN)
  redact.py         Redactor: names/hostnames/owners/rooms/MACs/IPs <-> [D3]/[P1]/[R2]/[M3]/
                    [IP3] (prefix-trie regex); unredact_stream (split tokens); RedactingProvider
  activity.py       local tz (NETWARDEN_TZ > TZ > /etc/localtime > offset); 7x24 grid, typical
                    hours, night_alerts() (conservative; ALWAYS_ON types skipped; >=3 days)
  search.py         search(q); timeline.py per-device; export.py devices_csv (BOM, safe) + report_md
  demo.py           synthetic home (meta demo=1); NotADemoDB on real data; never over labels/acks; seeds once
  discovery.py      sweep (ping + TCP-knock -> ARP), OUI vendors (OPT-IN `scan --update-vendors`; unknown = ""), PTR
  dns_ingest.py     Source adapters -> normalized DNS events; AdGuardHome (/control/querylog,
                    paged, watermark); PiHole v6; client IP -> MAC (devices, own IPs, ARP)
  traffic_ingest.py OPTIONAL bytes: NtopngSource (REST v2 /lua/rest/v2/get/host/active.lua,
                    local hosts, paged) -> cumulative per-host counters; IP -> MAC via store
  store.py          SQLite (WAL, _migrate()); user data = device_labels + device_profiles (type/owner/room) + acks
  i18n.py           locales/<code>.json (ALL strings + "_meta"; 12), normalize() BCP-47, t() w/ English fallback
  services.py       domain -> (service id, category), longest suffix; generic names "svc.<key>[|brand]" localized
  threatintel.py    "malicious"/"high-risk": curated list + opt-in feed (`--update "URL"`, NO default: URLhaus
                    needs a personal Auth-Key in the URL -> URL = secret, never printed/stored; FeedError kinds)
  brain.py          snapshot() (what the LLM reads); urllib AnthropicProvider (.complete/.stream/
                    .stream_turn = tools); stream_events (+ _tool_loop)/preview; ai_config(env, db);
                    round 7 C: _chat_parts (stable system | volatile focus), cache_control, trim_history
  usage.py          ONE price table (PRICES_CHECKED) + settings override; Meter; ai_usage month; budget check()
  ai_tools.py       Stage A: 13 READ-ONLY lookups (strict schemas, <= 50 rows / 8 KB) + Session
                    (10 calls / 24 KB, redaction); ai_intents.py offline intents + suggested()
  alerts.py         new devices, changes, threats, night, visibility, exposure, spikes, privacy; digest
  web.py            http.server @127.0.0.1:8787 (+ LAN addr with --lan): JSON API + static/. Host
                    (421), POST Origin (403), _auth (sessions/admin), body <= 1 MB, headers
  headless.py       round 6: NETWARDEN_HOST/PORT -> listen; HEADLESS=1 -> stderr logs + ONE admin code until claimed
  addon.py          round 6 H: HA add-on mode (SUPERVISOR_TOKEN + /data/options.json): options -> env, drop root, ingress
  pairing.py        Stage M: one-time codes (+ admin), hashed sessions, Limiter; qr.py (vendor/qrcodegen);
                    wslnet.py: /proc/version -> Hyper-V firewall PowerShell lines (SHOWN, never run)
  dashboard.py      inventory(): snapshot + EVERY devices row, online (30 min), new, randomized
  live.py since.py  Stage T: ONE change detector per DB -> /api/stream (SSE); /api/since banner
  static/           index.html + app.css + app.js (the SPA, no build) + map.js (pure layout) + demo.js (W). E1
scripts/  start.sh; start_windows.cmd (CRLF!) / start_demo_windows.cmd (:8788); adguard_dev.sh;
          dns_traffic.py; demo_seed.py; perf_db.py build|bench [--warm]|all (/tmp/nw_perf.db);
          build_static_demo.py --out DIR [--quick] [--langs en,..] [--site-url] (W: GitHub Pages live demo)
docs/     USER docs (English + .zh-TW where present): install, home_assistant, bandwidth (ntopng), pihole,
          private_ai (Ollama/LM Studio, redaction, settings API), lan (M), identification (N), family (F),
          health (H), people (P), report (X); images/ = README shots (demo data, DPR 1, <300 KB) + social-preview.png (= og-image)
docs/dev/ CONTRIBUTOR notes: stages (D1/D2/E2/F), stagex (X), stage_t (T), stagev3 (V3), stageq (Q), ai_tools (A),
          usability (U), accessibility (G), hardening (K), ha_addon (H), static_demo (W), i18n (plurals), bandwidth_investigation
root      README.md + README.zh-TW.md, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, CHANGELOG, THIRD_PARTY_NOTICES;
          .github/ (ci.yml, docker.yml, pages.yml = manual live demo, issue/PR templates, dependabot); docs in English + zh-Hant ONLY
ha-addon/ config.yaml DOCS/README/CHANGELOG translations/en.yaml icon+logo.png; repository.yaml at the root (one repo)
tests/    unittest (fake providers/servers on ephemeral 127.0.0.1); js/map_layout_test.js (node)
```

**DNS sources** (`dns_source_name`, `make_source`): AdGuard, or Pi-hole v6; both -> AdGuard unless `NETWARDEN_DNS_SOURCE=pihole`.
Sessions, `SourceError(kind)` -> `conntest.ERROR_KINDS`, `*_VERIFY_TLS`: docs/dev/integrations.md (round 9 V). Only the SELECTED source is
"configured". `blocked` 0/1 + nullable `block_reason`. Devices keyed by **MAC**; events/samples keep raw IP *and* MAC
at ingest time. Traffic samples are **cumulative** (decrease = reset). The API key never reaches the browser.
**i18n:** snapshot/alerts data is canonical English + stable keys; localized at the edge (`web.py` `?lang=` / POST
`"lang"`, `/api/locale`, `alerts.render_digest(r, lang)`). **Add a language** = copy `locales/en.json` to `<code>.json`,
translate (keep `{placeholders}`), set `_meta`; `python3 -m netwarden.i18n [--check]` (+ `locale_same_ok.json`) + tests.
**Operations (Stage C):**
- Every ingest/traffic/discovery run goes through `*_recorded()` -> `source_status` (errors via
  `health.sanitize_error`). New source = `health.SOURCES` + `status.src.<name>` / `status.hint.<name>_*` + `runner.plan()` loop.
- `GET /api/status?lang=`; `/api/meta` `ai_mode`, `demo`. **`demo: true` IPs may match REAL LAN devices -> live actions refused.**
- `--offline-ai` on run/web = the SAFE way to exercise the AI UI (confirm `/api/meta` ai_mode == "offline" first).
- Exports `/api/export/devices.csv` + `/report.md`. Retention `NETWARDEN_RETENTION_DAYS` (90, >= 8); devices/labels/acks/
  port_checks never pruned. Logs `data/netwarden.log`. Loops never call the LLM.
**Stages D1 / D2 / E2** - docs/dev/stages.md. **All POSTs require `content-type: application/json`**
(415). Ack keys `port:<n>`, `visibility:bypass|quiet`, `activity:night`, `bandwidth:spike`,
`upnp:<P>:<n>`, Q `mute:|less:<kind>`; `(mac, '')` = trust device. Owner/room/announced names = hostile text: esc() always.
**Dashboard (Stage E1):** `/static/<name>` whitelisted, ETag, `__V__` asset hash (static/ is
re-checked every 2 s; restart after editing locales/), CSP `script-src 'self'`.
- **Navigation (Stage U, docs/dev/usability.md):** `GROUPS` = 7 places with sub-tabs (`subTabs()`); every page keeps its
  own route - a NEW page = add it to a place in GROUPS + `GO_KEYS`. Keys 1-7; phone bar = NAV_PRIMARY + More.
- **Keyboard first (round 9 U, usability.md):** palette = `paletteItems()` (fold()/fuzzy(): case, accents, width, Trad/Simp
  `TS_PAIRS`; node tests/js/palette_match_test.js); local-only actions behind `!S.meta.remote`; "ask" pre-fills only.
  Keys ignore IME (`isComposing`/229) + typing; single keys off = `ui.shortcuts` (/api/meta) or `netwarden.single_keys`.
  View state: `VIEW_PAGES` (validated) -> `netwarden.view.v1.<db>` + hash query (relative `#/` only); scroll per history entry.
- app.js: `html` tag escapes every value; keyed `morph()`; drawers `#/device/<mac>|service/<id>|domain/<d>`; Undo + Ctrl/Cmd+Z.
- LLM ONLY via `chat()`; "Ask AI about device" pre-fills, never sends. Two `innerHTML` writes
  total (morph template, escaped lang options) - test-enforced. Chat = SSE, Stop closes upstream.
- Stage V: one device name everywhere (`rowName`/`dname`); bandwidth_spikes: 24 h >= 2 GB AND >= 4x the prior median.

**Settings + private AI (Stage L)** - docs/private_ai.md: `settings.REGISTRY` (new setting = register(Setting(...)) +
`settings.<key>` locale key); secrets ai.key / ai.anthropic_key (env only); `GET/POST /api/settings {values}` (env-set keys
read-only); `/api/chat/preview` never calls the model; `/api/ai/test` = explicit click. /api/meta never exposes configured URLs.
Redaction via `scrub` in brain + RedactingProvider. WSL mirrored loopback DROPS connects to closed ports.

**Identification (Stage N)** - docs/identification.md: name label > hostname > announced > vendor; "Use this name" = POST /api/label.
**Family insights (Stage F)** - docs/family.md: `/api/screentime|weekly|bedtime`, `/report/weekly`; table `bedtime_rules`
= user data; alert `bedtime` (ack `bedtime:<id>:<night>`). Everything is an ESTIMATE for family conversations - keep that framing.
**Network health + suggestions + score (Stage H)** - docs/health.md: tables `health_samples`, `outages`, `score_history`
(pruned) + `suggestion_state` (USER). `GET /api/health|suggestions|score`; `POST /api/suggestions/<id> {status, days?}`;
alert `outage` ack (mac `network`, `outage:<id>`). `health.internet_probe` OFF by default. New suggestion kind = detector
+ KINDS + `sug.<kind>.*` keys (+ score deduction); never auto-applied.
**Phone / LAN mode (Stage M)** - docs/lan.md: OFF by default (`--lan`, setting `lan.enabled` on restart; 0.0.0.0 only
with `--bind-all`). Non-loopback (or `NETWARDEN_REQUIRE_AUTH=1`) needs a session; pairing code only in the URL FRAGMENT;
admin (`ADMIN_POSTS/GETS`) loopback only. Checks: NEVER bind a LAN address - inject `Handler.is_local_client` / REQUIRE_AUTH.
**Inbox, settings, backup, first run (Stage X)** - docs/dev/stagex.md: `#/inbox`, `#/settings`, `#/welcome`, palette; `/sw.js`
+ `/offline` (never caches /api/); autostart_windows.cmd. Admin-only (loopback): backup/restore, `/api/setup*`,
`/api/test/<src>`. Server texts never show a bare MAC: pass `naming.display_names(db, lang)` (test-scanned).
**People + presence (Stage P)** - docs/people.md: `/api/people|person|presence` + `web.PEOPLE_POSTS`; presence OFF per
person, ON = loopback + `confirm`; `presence.check_minutes` (5, >= 2) / `grace_minutes` (20); never on demo; restore never
turns it ON; AI lookups hide liveness of people without it. Notifications ONLY via `notify.route()`. AI: names -> [P1].
**Quiet hours, tuning, why, hygiene (Stage Q)** - docs/dev/stageq.md: settings `quiet.*` (off); `GET /api/notify|tuning|hygiene`,
`web.TUNING_POSTS` (restoring a legacy switch = loopback; whole-home "off" of `tuning.CRITICAL_KINDS` = loopback + `confirm`);
alerts carry `explain` (inbox/drawer: `why`); chat `alert {kind, mac, key}` -> redacted context.
**AI lookups (Stage A)** - docs/dev/ai_tools.md: settings `ai.tools` auto|off, `ai.max_tool_rounds` (4);
SSE `status|tool|note|suggest`; `GET /api/ai/questions`; refused tools -> `brain._NO_TOOLS`. Results = DATA.
**Map, live, since, speed (Stage T)** - docs/dev/stage_t.md: `live.poke(db)` after loops/Warmer/POSTs (no per-client
polling); streams 8 / 3 per client, never in DATA_GATE; `/api/overview` = `web._dataset()` parts; JSON GET ETag -> 304.
**Accessibility + degradation (Stage G)** - docs/dev/accessibility.md: WCAG 2.2 AA; tokens tested for contrast (never `#fff`
on fills); announce via `speak()` only; UI errors via `errText()` (never `e.message`); GET raising -> localized 500 / 503.
**Robustness (Stage K)** - docs/dev/hardening.md: fuzz `tests/fuzzkit.py` (`NETWARDEN_FUZZ=heavy|<n>`); source bodies via
`health.read_source_json` (16 MB / 60 s); stored errors via `health.error_text`; `store.DBError` -> CLI exit 2 / API 503
`err.db_*`; protocol errors = localized JSON 4xx (`Handler.send_error`); one DB conn per request (`_db()`); SIGTERM = Ctrl+C;
WAL capped + `store.checkpoint`. Legacy DB fixtures: `tests/fixtures/`. Soak: `scripts/soak.py`.
**Packaging + headless (round 6 D)** - docs/install.md (+ .zh-TW), docs/lan.md "Admin sessions": `__version__` = pyproject
(test); setuptools package; `store.DATA_DIR` (NETWARDEN_DB > NETWARDEN_DATA_DIR > checkout data/ > XDG). `Handler.admin` = local
or `sessions.admin` (`pair --admin`, 15 min); `remote` in /api/meta = NOT admin. Local = loopback AND no advertised proxy host
AND no `web.FORWARDED_HEADERS` (a proxy can forge Host). `/healthz` public, no DB/gate. Dockerfile,
deploy/*.yaml, scripts/install_linux.sh (`--root` for tests), .github/workflows/docker.yml: Docker NOT runnable here (static tests).
**HA add-on + ingress (round 6 H)** - docs/dev/ha_addon.md: Dockerfile target `addon` (root -> `addon.prepare_and_drop`);
options -> env (`addon.OPTION_ENV`). `Handler.ingress_proxy` (172.30.32.2; `run` in add-on mode / tests ONLY, never a setting):
that PEER = HA admin; X-Ingress-Path/X-Forwarded-* read from it only. URLs are base-aware (`__BASE__`/`base=`, `url()` in app.js,
relative manifest/css, sw.js scope): NEVER add a root-absolute URL to static/. Tests: tests/ingress_proxy.py.
**Static demo (round 9 W)** - docs/dev/static_demo.md: `DEMO` in app.js ONLY with data-static-demo + static/demo.js (`NWDemo.file` = builder
`static_name`, fixture-pinned); a NEW GET the page makes = add it to the builder (`PAGES`/`DEVICE_GETS`) or it 404s there; DEMO never POSTs.
10b/10c: `demo.HOUSEHOLDS`; `lastTag[k]` per dataset + `forgetTags()` on setLang; chat messages carry `lang`; outage ends >= `demo.ISP_CLEAR` ago.
**Plurals + language switch (10d)** - docs/dev/i18n.md: count = base + `_one` (+ ru `_few`/`_many`) via `i18n.tn()`/`TN()`, 2+ counts = "A: {a} · B: {b}";
checker plural_missing|forms|hedge (never-1 -> PLURAL_FIXED); `_one` drops `{n}` only where one == 1 (NOT ru/fr/pt-BR/hi); `i18n.num()`,
`list_sep`; new server text = `refresh()` or a `LANG_DEPS` row. A new chat chip in app.js = `ai_intents.CHIPS` (or offline_ai.SUMMARY_CHIPS) - test-enforced.
**Push (round 10 N)** - docs/notifications.md: tables push_channels (secrets column: NEVER in API/log/backup; log = shown_endpoint)
/ push_outbox (UNIQUE(channel,key) = dedupe + queue; new/resumed channel PRIMED) / push_log; admin-only `web.PUSH_GETS|POSTS`;
levels minimal|standard|detailed (scrub() + hashed id below detailed); env `NETWARDEN_NOTIFY_<n>_*` read-only (absent = row STALE, never
deleted); a kept secret never goes to a new host (`push_reenter`); send() = one total deadline; demo DB never sends.

## Dev environment

- Python >= 3.11 (CI: 3.11-3.15 on ubuntu-latest, `.github/workflows/ci.yml`); Linux, macOS or WSL2. Batch files CRLF.
- `CLAUDE.local.md` (gitignored, machine notes): read it first. `launch/` = internal (release_checklist.md, exec_files.txt = +x list).
- **Never read, print or modify `.env`** (ANTHROPIC_*, NETWARDEN_*, ...); code only checks presence. No sudo / system
  installs. Don't leave servers running. Never commit real MAC/IP addresses, hostnames, router models, usernames,
  home paths or emails: examples use `192.168.1.x`, `aa:bb:cc:..`, the demo home (tests/test_round6_o.py scans for leaks).

## How to run (from the project dir)

```bash
python3 -m netwarden run                       # THE command: dashboard :8787 + loops
python3 -m netwarden run --demo --offline-ai; bash scripts/start.sh [--demo]  # demo home, no loops; AdGuard + run
python3 -m netwarden status [--json] | demo | prune --days 30 --vacuum | health [--json] [--rebuild DAYS]  # CLI lang zh-Hant
python3 -m netwarden scan | ingest|traffic [--watch S] | alerts [--lang] [--json] | check --mac <mac>|--all | search tiktok | report
python3 -m netwarden run --lan; pair [--local] [--admin] [--list|--revoke ID]; backup [-o F] | restore F [--mode merge|replace] [--dry-run]
python3 -m netwarden notify list | test NAME | send-digest [--daily]   # push channels (round 10 N)
NETWARDEN_HEADLESS=1 NETWARDEN_HOST=0.0.0.0|<lan-ip> python3 -m netwarden run   # container mode; --version
bash scripts/adguard_dev.sh start; python3 scripts/dns_traffic.py   # DEV AdGuard (DNS :5354, API :3000); never for users
python3 -m netwarden.web --db data/demo.db; python3 -m netwarden.alerts --db data/demo.db  # must work; perf_db.py / soak.py: perf
python3 -m unittest discover -s tests          # 1412 tests, all must pass (+ node tests/js/*.js)
```
Windows: `scripts\start_windows.cmd` (:8787) / `start_demo_windows.cmd` (:8788). Manual checks: own `--offline-ai` server on 127.0.0.1:8799, COPY of the demo DB.

## Status & next steps

**Done:** MVP, i18n, demo; stages C P D1 D2 E1/E2 V L N F H M X V3 V4 Q A T U G K + review fixes; rounds 6 D/H/O/P/E, 7 L/C, 8 R,
CI1, 9 V/U/X/W, 10 N/P, 10b, 10c, 10d (tests `test_round*.py`). Standing rules from them: third-party code only in netwarden/vendor/, downloaded
data (manuf, threat feed) never in tree/wheel/image; AI cost (docs/dev/ai_cost.md): no cache breakpoint on the snapshot, `usage.Guard`
before EVERY tool round, re-check prices + bump PRICES_CHECKED; ghcr.io/liming-ting/netwarden + netwarden-addon (lower case);
AGPL-3.0-or-later, LICENSE hash-pinned (NEVER edit, no per-file headers), `netwarden.LICENSE|SOURCE_URL|COPYRIGHT` = ONE source; images
ONLY from v* tags; CI TZ=UTC + Asia/Taipei + `scripts/dev/tz_sweep.sh`; READMEs say the same; pages.yml (live demo) is run BY HAND.
**Next:** next release (launch/release_checklist.md step 17). Later: block_reason breakdown; HTTPS.

## Conventions
- stdlib only; plain, commented style of `discovery.py` / `dns_ingest.py`; new sources = `dns_ingest.Source`-like adapters.
- Python 3.11 syntax/stdlib only (CI runs 3.11, WSL has 3.12): no `f"{d["k"]}"`; tests/test_py311_compat.py guards it.
- Tests never call the real LLM or network (fake providers, ephemeral 127.0.0.1). Must pass on a fresh copy, no `.env`, in ANY zone
  at ANY hour (tz_sweep.sh; `.env` NETWARDEN_TZ beats TZ); zone-specific expectations under `tests/tzkit.pinned_tz`; pin demo
  clocks (`demo.build(path, now=)`); weekday stories assert both branches.
- No hard-coded UI/user-facing text: add a key to EVERY `netwarden/locales/*.json` (zh-Hant genuinely
  Traditional/Taiwanese, zh-Hans Simplified; zh punctuation ASCII , : ( )). Escape all HTML; CSV via `export.safe_cell`; never echo secrets.
