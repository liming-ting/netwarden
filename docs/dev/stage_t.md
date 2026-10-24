# Stage T - network map, live updates, "Since your last visit", speed, undo

## Network map (`#/map`, Overview card)

- `static/map.js` = `NWMap.layout({groups, devices})`: a PURE function (no DOM), UMD
  (browser `window.NWMap`, node `module.exports`). Router at (0,0); the Internet and one
  cluster per group on a ring (Internet always at the top); each cluster a sunflower spiral.
  Deterministic, input-order independent, sizes grow in steps of 6 devices, so a new
  device takes the next free spot and nothing else moves. Node radius = log10 of traffic
  (or DNS lookups without ntopng), capped. 300 devices: ~0.15 ms.
- Check: `node tests/js/map_layout_test.js` (from Git Bash; WSL has no node, so the
  unittest wrapper skips there).
- app.js `viewMap()` decides groups (person / shared / nobody, or device type), the status
  ring (alert > blind spot > new > online > offline; `visibility` and `new` inbox items have
  their own rings) and draws SVG through the escaping `html` tag. Pan/zoom only rewrites
  `#mapvp`'s transform (wheel, drag, pinch, `+ - arrows 0` while the map has focus).
  Tooltip = text nodes only. Router node: hygiene status colour + UPnP mapping badge,
  links to Security; Internet node: health verdict, links to Network health.
- <= 640 px starts as the grouped list (toggle "Map / List"); the list is also the
  accessible alternative. Focus order = group by group, names sorted. Reduced motion: no
  enter animation. Print: controls hidden, map kept.

## Live updates (`GET /api/stream`, `live.py`)

- ONE `live.Detector` per DB file (`live.detector(path)`): a thread that runs only while a
  stream is open, wakes on `live.poke(path)` (run loops after each good run, the Warmer
  after each pass, the web server after every successful POST) or every 60 s, debounces
  0.4 s, takes ONE compact `live.snapshot()` (devices online map, current alert ids,
  inbox count, suggestion ids by status, presence states, health level, settings / notes
  fingerprints) and `diff()`s it into small typed events in a 256-event ring buffer.
  `computations` counts checks: it never scales with the number of streams.
- Events: `device_new|online|offline {mac}`, `alert_new {id,kind,mac,sev}`,
  `inbox_changed {count}`, `suggestion_changed {open}`, `presence_changed {person,state}`,
  `health_changed {level}`, `settings_changed`, `notes_changed`. Ids `<epoch>-<seq>`; the
  epoch changes when the detector starts from a fresh baseline (restart, or 120 s idle).
- Stream: `retry: 3000`, missed events (Last-Event-ID header or `?last=`) or `resync`, then
  `hello {id}`; `: hb` every 25 s (`Handler.STREAM_HEARTBEAT`, tests set 0.2); ends after
  30 min or when the session is revoked. Caps 8 total / 3 per client address -> 429
  `err.too_many_streams` + Retry-After. Host / LAN auth / security headers as every API
  request; NOT behind `DATA_GATE` (test-proven), no `cache.batch`. sw.js never touches /api/.
- Client: `LIVE_SETS` maps an event to the datasets to refetch (`refreshSome`), rows / nav
  counts flash 1.6 s. Indicator `#live`: live / reconnecting (backoff 1 s -> 30 s, jitter) /
  paused (tab hidden; catches up on return). While live, the full refresh drops from
  30 s to 5 min. Quiet hours stay on `/api/notify` toasts only.

## "Since your last visit" (`GET /api/since?t=<UTC ISO>`, `since.py`)

- localStorage `netwarden.visit.<db_id>` stamped every minute / on hide; sessionStorage
  keeps the visit's start across reloads. Nothing on a first visit or after < 10 min.
- Report: new devices (first_seen), alerts whose first routing in `notify_log` is after t
  (never routed = new; kind `new` excluded - it is a device), outages started, arrivals
  (presence ON only), suggestions whose effect showed after t. <= 5 items each, t clamped to
  30 days, future / bad -> 400 `err.bad_since`. Chips open the filtered view (Devices gets
  a "New since your last visit" filter chip). Dismiss = hidden until the next visit.
- Demo: `demo._seed_seen` marks the camera's old findings as seen 2 days ago, so a visit
  12 h ago shows ~1 device, the night's outages + backup spike, arrivals, 1 fix.

## Speed

- `GET /api/overview?lang=` = `{parts: {dataset: data}, etags: {dataset: tag}}` for the 14
  Overview datasets (`web.OVERVIEW`); `_dataset(name)` is the single source for both the
  bundle and each endpoint, so a part's tag equals that endpoint's ETag.
- Every JSON GET carries `ETag` (`web.tag_of`: hash minus a top-level `generated` stamp;
  the bundle's = hash of its tags) and answers 304 to a matching If-None-Match. Data is
  computed every time, so a 304 is never stale; still `cache-control: no-store`.
- `make_server(warm=True)` hashes the static assets in a background thread (cold reads on
  /mnt/c made the first /report/weekly ~1.3 s).
- Perf DB (300 devices, 100k events), `scripts/perf_db.py bench --warm`:

  | | before | after |
  |---|---|---|
  | warm Overview refresh | 13 requests: 195 ms first / 149 ms median | bundle: 74 / 69 ms |
  | /report/weekly first hit after warm-up | 1343 ms | 75 ms |

## Undo everywhere

Every `toast(msg, {undo})` also pushes onto `UNDO_STACK` (15 min, newest first); Ctrl/Cmd+Z
outside text fields runs the newest (the same function as its button). Added: bedtime
rule on/off, presence notification switches (alongside existing trust, ignore, rename,
label, owner, mute/snooze/sensitivity, ack, suggestion dismiss/snooze, bedtime edits).
