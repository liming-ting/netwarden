# Stage Q - quiet hours, alert tuning, "Why this alert?", router hygiene

Everything here is read-only toward the network: tuning and quiet hours only change what
netwarden *reminds* you of (rows in its own SQLite), never the router or firewall.

## Quiet hours (`quiet.py`, `notify.py`)

- Settings (registry group `quiet`, Settings page section "Quiet hours"): `quiet.enabled`
  (off by default), `quiet.start` / `quiet.end` ("HH:MM", local time, an end at or before
  the start crosses midnight; start == end = never quiet), `quiet.days` per-weekday
  overrides as text `"4=23:30-09:00,5=off"` (0 = Monday; the page shows one select per
  night: usual / different hours / none), `quiet.critical` (default on).
- A window belongs to the day it STARTS on (like bedtime rules): Friday's override is
  Friday night into Saturday morning.
- `notify.route()` stays THE one notification gate. Each event gets a stable key in
  `notify_log` (`sent` | `held` | `released`). Inside a window a non-critical event is
  `held`; alerts are still recorded and listed everywhere, only the pop-up waits.
- Critical = threat-list contact, a NEW router forward on a risky port, a NEWLY opened
  high-risk port, a DNS bypass by a new device (`notify.critical`); they bypass quiet
  hours while `quiet.critical` is on.
- `notify.release()` turns every finished window into ONE `quiet_summaries` row inside a
  `BEGIN IMMEDIATE` transaction (UNIQUE `win`): exactly once, also across restarts, two
  processes or threads. The run loop calls `notify.run()` every 60 s (no dashboard
  needed); `GET /api/notify` runs the same pass and returns
  `{quiet, deliver, held, summaries}`.
- The first batch on a database only primes (meta `notify.primed`): nothing old is
  held for a summary.
- Hold-or-send is judged at the event's OWN time too (`notify._window`: presence `ts`,
  an alert's `when`): an event first routed after its window ended (machine off
  overnight) but that happened inside it (<= `LATE_ROUTE`, 24 h) joins that window's
  summary instead of popping up in the morning. Adding late events to an existing summary
  clears its `seen_at` (it shows again).
- Dashboard: "While you were asleep" card on Overview and Inbox (Close = `POST
  /api/notify/seen {id, seen}` with Undo); a toast + optional system notification once -
  never while quiet hours are active (the card is there; the pop-up waits for the end).
- The "next window" text uses that night's own hours (weekday overrides).

## Alert tuning (`tuning.py`)

- Levels per alert kind (`threat exposure upnp visibility night bedtime spike change
  new outage`) and per device (all but `new`, `outage`): normal / less sensitive / off,
  off with a snooze `1h | 1d | 1w | forever`.
- Stored as acks: `(mac, "mute:<kind>")`, `(mac, "less:<kind>")`; device `"all"` = the
  whole kind; `until` NULL = until changed. A snoozed single inbox item keeps its own ack.
- "Less sensitive" keeps only the stronger alerts (`tuning.KEEPS`: malicious threats,
  high-risk ports, risky forwards, DoH bypass, >= 30 night lookups, 2x the bedtime
  minimum, >= 8x and >= 5 GB spikes, >= 2 new services, new devices with a real (not randomized)
  MAC, >= 10 min outages). `explain.py` states the stricter threshold.
- `GET /api/tuning` (every entry with kind name, target name, expiry, source
  tuning | snooze | setting); `POST /api/tuning {kind, mac?, level, for?}` ->
  `{before}`; `/api/tuning/undo {kind, mac, before}`; `/api/tuning/restore {id}` ->
  `{undo}`; `/api/tuning/restore_undo {undo}`. Errors `err.bad_tuning|no_tuning|bad_mac|
  tune_confirm`. Unknown fields are refused; Undo rows must carry real UTC timestamps
  (`tuning.clean_row`).
- **Security kinds** (`tuning.CRITICAL_KINDS`: threat, exposure, upnp): "off" for the WHOLE
  home (any snooze) is loopback only and needs `confirm: true` (the page asks first);
  the same for an Undo / restore_undo that would put such a row back. Per device and
  "less sensitive" stay open to a paired phone.
- The legacy switches `alerts.unusual_hours` / `family.bedtime_alerts` appear as "off"
  entries; turning one back on is loopback only (403 for a paired phone).
- Entry points: Tune on every alert row (Overview, Security, Inbox, device drawer), the
  "Tune this alert" button in each explanation, the Settings "Alert tuning" panel
  (Restore + Undo) and the palette ("Alert tuning", "Quiet hours").

## "Why this alert?" (`explain.py`)

- Deterministic and localized: `{rule, facts[], threshold, level, level_text, tune,
  ref}`. `alerts.localize` adds it to every alert as `"explain"` (a threat's own `why`
  is the threat list's reason text); inbox items and `/api/device` alerts carry it as
  `why`.
- Expandable under each row (`.why-btn` / `.why-box`, `aria-expanded`).
- "Ask AI about this alert" pre-fills the chat (never sends). On send, the request
  carries `alert: {kind, mac, key}`, `explain.find()` looks the alert up again, and its
  explanation (canonical English, through the redactor) goes into the system prompt;
  the offline provider answers with the localized explanation first.

## Router & network hygiene (`hygiene.py`)

- `GET /api/hygiene`: checks `upnp upnp_risky upnp_stale router dns_bypass exposure
  iot`, each pass | warn | fail | unknown with steps and the suggestion ids it links to.
  The Security page card shows them; nothing logs in to the router.
- Suggestions: existing ones are linked (`upnp:<P>:<n>`, `port:`, `doh:`); new kinds
  `upnp_stale` (medium, -3 points, cap 3), `firmware` and `iot_net` (low, no points:
  firmware is a reminder, trackers already cost points through the privacy grade). No
  finding is counted twice.

## i18n checker

`python3 -m netwarden.i18n --check` -> missing / extra keys, placeholder mismatches,
untranslated copies of English (brands / codes / units pass; reviewed exceptions in
`netwarden/locale_same_ok.json`), Simplified characters in zh-Hant (and the reverse),
mainland terms in zh-Hant (用戶端 is Taiwanese usage). Exit 1 on any problem. zh
locales use ASCII `, : ( )` (test-enforced).

## Autostart script

`scripts/autostart_windows.cmd` prints every message through a read-only inline
PowerShell helper (`:msg <key> [path]`) that reads `netwarden/locales/<lang>.json`.
Language = `NETWARDEN_LANG` > Windows UI culture (`Get-UICulture`; `NW_UI_CULTURE`
overrides it for tests) > en; codes are validated, unknown keys print the key.
`tests/test_autostart_msg.py` runs the matrix through powershell.exe from WSL (skipped
when unreachable).

## Demo

Quiet hours 23:00-07:00 on, with last night's summary (4 held events, released);
tuning acks for Chromecast (night off for a week), PS5 (spike off for a day) and the
robot vacuum (night less sensitive, no end); a leftover UPnP forward UDP 51413 ->
192.168.1.77 (no device) next to the camera's risky RTSP 554. All seeded once per demo DB
and never over a user edit (meta `demo_tuning`, `demo_quiet`). The demo's night alert is
hidden by its own bedtime rule (by design since Stage F); the test removes the rule to
check its explanation.

## Fixed on the way

- `cache.py` acks fingerprint used `MAX(until)` only: an earlier snooze that changed
  was invisible while a later one existed -> sums of `julianday()` now.
- Switching language on Settings / System did not refetch the server texts.
- Settings "Save" said "AI settings saved" for every section (`app.set.saved`).
