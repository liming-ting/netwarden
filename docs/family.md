# Family insights

Screen-time **estimates**, bedtime rules that **only notify**, "this week vs last week"
and a printable weekly report. Everything is computed locally from the DNS log netwarden
already has; nothing is blocked, paused or sent anywhere. The UI frames it as material
for a family conversation, not surveillance (`fam.note`, `digest.family_note`).

## Screen time: how it is estimated (`netwarden/screentime.py`)

1. **Which lookups count.** `classify(domain)` -> `(service id, screen category)` or None.
   Only services in a screen category count: video, social, games (`gaming`), shopping
   (+ food delivery), education (Stage F catalog: Junyi, Khan Academy, Classroom, Duolingo,
   ...) and "other" (news, dev, finance, gov). Never counted: routine traffic
   (`routine.is_routine`: connectivity, time, updates, certs, CDN), trackers / ads /
   telemetry (not a screen category), unknown domains, blocked lookups, and machine
   services (`MACHINE_SERVICES`: Anthropic/OpenAI APIs, PyPI, npm, Docker).
2. **Sessionisation.** Per device x service, the distinct lookup *minutes* are joined into
   sessions while the gap between two of them is <= the category's tolerance; a session
   ends `tail` seconds after its last lookup (apps keep a stream open without new
   lookups). A session needs >= `MIN_LOOKUP_MINUTES` (2) distinct minutes - one stray
   lookup (a link preview, a widget) is not screen time.

   | category | gap tolerance | tail |
   |---|---|---|
   | video, games | 15 min | 5 min |
   | education | 10 min | 3 min |
   | social, shopping | 8 min | 2 min |
   | other | 5 min | 1 min |

3. **No double counting, 60 min per hour.** Per local hour, the device's *real* time is
   the union of all its sessions (capped at 60 min); when apps overlap, their shares
   are scaled down to that union. Days are LOCAL days (`NETWARDEN_TZ` / `settings`
   time.timezone, else the system's `TZ` or /etc/localtime; half-hour offsets work).
4. **Aggregation.** Per device x service x day -> per member (`device_profiles.owner`;
   devices without an owner are "shared"), per category and per service. `compute()` is
   memoized in `netwarden.cache` (fingerprint + 30 s) and warmed by `runner.warm()`
   (via `alerts.compute` -> `family_summary`). 15 local days are computed once; every
   view slices them.

**Limits (shown in the UI as `fam.method`):** DNS caching (a phone that keeps a video
CDN connection may look up nothing for a while - the tail and gap tolerance only partly
cover it); VPNs, encrypted DNS (DoH/DoT, see visibility), mobile data or another
network hide use completely; background refreshes of a social app can look like a short
session; a shared device (the TV) is not a person; a device without an owner is
"shared". Treat the numbers as "about", rounded to minutes.

Validated on the demo home: planned sessions come out within ~5 minutes of the plan
(tablet YouTube 21:15-22:40 -> 21:20-22:44, Roblox 20:00-21:15 -> 20:00-21:18, Junyi
19:00-19:40 -> 19:00-19:42, Dad's Instagram 21:00-21:35 -> 21:04-21:35; the start
jitter is part of the plan); the TV's sparse lookups (every 7-13 min) still form one
evening session; Dad's phone is equal both weeks; the home is up ~30%.

## Bedtime / quiet-hours rules (`netwarden/bedtime.py`)

- Rule = name, ONE target (`owner` = every device of that person, or one `mac`), nights
  (weekday the window STARTS on, Mon=0 ... Sun=6; school nights = Sun-Thu), `start`/`end`
  HH:MM (end <= start crosses midnight), `min_minutes` (1-240) of estimated screen time
  inside the window before it alerts, `enabled`. Local user data: table `bedtime_rules`
  (max 50), never touched by the demo after its one seeded rule.
- Alert kind `bedtime` (last 24 h, enabled rules), one per device and night, ack key
  `bedtime:<rule id>:<night>` ("Got it" mutes that night only). Text names the top app.
- The generic `unusual_hours` alert is suppressed when an enabled rule covers that
  device for the whole unusual span (`suppress_night`).
- Preview: `POST /api/bedtime/preview {rule}` -> "In the last 7 days this would have
  alerted on: ...", without saving. The editor debounces it while the rule is edited.

## Week over week (`netwarden/weekly.py`)

"This week" = local midnight 6 days ago -> now; "last week" = the same span 7 days
earlier (so a Wednesday-noon view compares to last Wednesday noon). Household and per
device: DNS lookups, estimated minutes, tracker lookups, blocked share (points), new
services (non-routine, seen this week but not last), new devices. `has_history` needs
DNS data from the start of last week (else a gentle "not enough history" line).
`highlights()` = up to 5 plain-language lines (changes under 10% read as "about the same").

## API

| | |
|---|---|
| `GET /api/screentime?days=7&device=&owner=&lang=` | totals, by_day, categories, services, members, devices (with `today_text`), note, method. days 1-14 (400 `bad_days`), unknown device 404 |
| `GET /api/weekly?lang=` | compare() + localized `highlights`, `new_services` |
| `GET /api/bedtime?lang=` | rules (+ hits, summary, days_text), people, max_rules, note |
| `POST /api/bedtime {rule, restore?}` | create / update -> {ok, id, ...report}; 400 {error, field}; 404; 409 |
| `POST /api/bedtime/delete {id}` | -> {ok, deleted, ...report} (Undo = POST it back with restore) |
| `POST /api/bedtime/preview {rule}` | {hits, summary, devices, days_text} |
| `GET /report/weekly?lang=` | printable page (server-rendered, escaped, CSP, `/static/report.css|js`) |

Dashboard: section **Family** (`#/family`, key `8`, `g f`): kind note, "This week vs
last week" card, per-person cards (7-day bars, top apps), categories, top apps, bedtime
rules with an inline editor (day chips + presets, times, threshold, live preview, Undo),
"Printable weekly report". Device drawer: "Screen time (estimate)" card ("About 1 h 20 min
on YouTube today."). Weekly digest: "🛏️ Bedtime" and "👪 Family" sections.

## Demo story

The tablet stays online past the 22:00 school-night rule (>= 3 nights), the TV streams
Netflix in the evenings, and the home is ~30% busier than last week (last week =
`demo.echo_last_week` + the FAMILY plan). Perf DB: Stage F endpoints 14-20 ms warm, the
weekly report ~130 ms.
