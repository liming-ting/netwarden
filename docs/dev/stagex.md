# Stage X - inbox, settings, backup, first run, offline shell

Everything here writes only the user's own notes in netwarden's SQLite; nothing on the
network changes. Admin endpoints (marked *) answer this computer only (loopback), like
`/api/settings` - a paired phone gets 403.

## Inbox (`inbox.py`, `#/inbox`, `g n`)
- `GET /api/inbox?lang=` -> `{items, counts, snooze_days}`: every alert kind + open
  suggestions in one list, worst first; each item carries `actions` and opaque `ref`s.
- `POST /api/inbox/act {action, items[<=200 refs], days?}` - all or nothing. Actions:
  `ack` ("Got it", the finding's own ack key), `mute` (`mute:<kind>` for that device),
  `trust` (ack `""`), `snooze` (ack with `until`, default setting `alerts.snooze_days`),
  `dismiss` / `done` (suggestions). `{action: "undo", undo: <action>, items}` reverses it.
- Keys: `j`/`k` move, `Enter` opens, `a t m d s` act, `x` select (bulk bar), `u` undo.
  Nav badge = open count. Empty state: "All caught up".

## Settings page (`#/settings`, `g e`)
- Groups from `settings.REGISTRY` (`settings.section.*`); each value shows its source
  (environment / saved here / default); env-set keys are read-only; secrets only ever
  show "configured". New alert switches `alerts.*` and `family.bedtime_alerts`.
- `POST /api/test/<adguard|pihole|ntopng|ai>` * (`conntest.py`): `{ok, ms}` or `{ok: false,
  error_kind}` from `conntest.ERROR_KINDS` (not_configured refused unreachable timeout auth
  http bad_response cloud offline). Uses the configured URL only; a cloud AI endpoint is
  never probed from this button (`cloud`; that stays the explicit `/api/ai/test`).

## Backup / restore (`backup.py`)
- `GET /api/backup` * -> `netwarden-backup` v1 JSON attachment: labels, profiles, acks,
  suggestions, bedtime_rules, settings (never secrets, never paired phones).
- `POST /api/backup/preview {backup, mode}` * -> per-section adds / changes / removes with
  samples; `POST /api/restore {backup, mode}` * applies it in one transaction.
  `mode` = `merge` (never removes) | `replace`. Strict schema, 1 MB, 5000 items/section.
- CLI: `python3 -m netwarden backup [-o FILE]`, `restore FILE [--mode merge|replace]
  [--dry-run] [--yes]` (prints the preview; `--mode replace` needs `--yes`).

## First-run wizard (`firstrun.py`, `#/welcome`)
- Shown when there is no device / DNS source (never on the demo DB). Steps dns, scan,
  language + time zone, AI (shows where data goes: local / lan / cloud), phone.
- `GET /api/setup`; `POST /api/setup {step?, done?}` *; `POST /api/setup/scan` * (one
  background sweep, single flight); `GET /api/setup/scan/status?job=`. Progress in meta
  `setup.step` / `setup.done` -> skippable and resumable.

## Palette, service worker, autostart
- Palette (`/`, Ctrl+K): navigation + actions (backup, scan, theme, language...),
  fuzzy subsequence match, the last 6 used shown first (localStorage).
- `/sw.js` registers only on `127.0.0.1` / `localhost`; caches the shell and serves
  `/offline` ("netwarden is not running" + how to start it) when the server is down.
  API responses are never cached.
- `scripts/autostart_windows.cmd install|uninstall|status [--dry-run]`: a Startup-folder
  shortcut that runs `start_windows.cmd` minimized without opening a browser
  (`NW_NO_OPEN=1`). No registry, no scheduled task, no admin rights.

## Names in server texts (`naming.py`)
`display_names(db, lang)` = the dashboard's name for every device (label > hostname >
announced > vendor + type), `relabel(obj, names)` replaces names that are bare MACs.
Used by alerts, inbox, privacy, screentime, weekly, score and suggestions;
`tests/test_stage_x.py` scans those endpoints for bare MACs.
