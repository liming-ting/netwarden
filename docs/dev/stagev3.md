# Stage V3 - verification and follow-ups after round 3

Tests: `tests/test_stage_v3.py`. Related docs: identification.md (unicast round), lan.md
(the WSL firewall).

## Cold start / warm performance

- **The warm-up order.** `runner.warm()` runs inside `cache.batch()` in this order:
  snapshot → alerts → nethealth → suggestions. That covers the inbox and the score,
  which build on them.
- **Requests never wait behind a recompute.** A request finds stale data instead
  (`cache.STALE_MAX` = 90 s) whenever another thread is recomputing the key, unless a
  user note changed.
- **Bandwidth.** `store.bandwidth_summary` / `_totals` are one streaming Python pass in
  `ts` order (`_bandwidth_scan`, ~3x faster than SQL window functions).
  `bandwidth_days` uses tuple rows and `bisect`. `alerts.bandwidth_spikes` first checks
  `store.bandwidth_days_floor`, a lower bound from ~10 indexed lookups. Only devices
  that could spike get the exact per-day sums: 1.9 s → 66 ms on the perf DB.
- **WSL /mnt/c reads are slow** (0.1-3 s on a busy machine). Three places used to do one
  per request:
  - `brain.load_env()`: every local time shown asks for NETWARDEN_TZ. The default file
    is now re-read at most every 2 s (`ENV_FILE_TTL`); real env vars still win at once.
  - `cache._file_stamps()`: re-stat at most every 2 s (`STAMP_TTL`).
  - `web.static_file()` / `asset_version()`: bytes cached per file, revalidated by one
    `stat()` at most every 2 s (`STATIC_RECHECK`); the hash is recomputed only on a change.

`scripts/perf_db.py bench [--warm]` on the 300-device perf DB. The review measured first
hits of ~3.7 s (inventory) and ~5.7 s (inbox).

| | before V3 | after V3 |
|---|---|---|
| page opened at startup, whole page (`--warm`) | ~4.7 s | 1.7-1.8 s |
| … its inventory / inbox request | 2.4 / 3.4 s | 1.2 / 1.7 s |
| startup warm-up pass | 6.1-8.2 s | 3.3-3.5 s |
| warm alerts / inbox / score / health (in a refresh cycle) | 200-235 / 225 / 120 / 125 ms | 20 / 21 / 20 / 18 ms |
| `index.html` / asset hash per page load | 0.5-3.5 s | < 1 ms after the first |
| cold (no warm-up) first inventory | 2.2-2.8 s | 1.7-2.8 s (noisy) |

Remaining: a warm parallel page refresh (11 requests) still takes about 1 s against
about 300 ms of summed request time. The cause is GIL contention with the keep-warm pass,
which recomputes everything older than 12 s every 20 s. `/report/weekly`'s first hit
can take about 1.5 s; later hits take about 16 ms.

## Smaller items

- **Weekly digest language.** Without `--lang` it uses `alerts.digest_language(db)`,
  which is the `ui.language` setting (env > dashboard > zh-Hant).
- **IPv6 redaction.** `redact.IPV6_RE` + `household_ipv6()` catch link-local, ULA,
  loopback and EUI-64 addresses (ff:fe in the interface id, even in a global prefix).
  Public and privacy-extension addresses and clock times stay.
- **`pair --local`.** No QR code; the text says the code is for another browser on this
  computer.
- **`pairing.lan_address()`.** It prefers the default-route interface. The old UDP trick
  connected to 10.254.254.254, WSL's DNS-tunnel address on loopback, and returned that
  address. `run --lan` and the WSL firewall advice would have used it.
- **Form fields.** Every `<input>/<textarea>/<select>` in the page files has an id or
  name (test-scanned; this was Chrome's console notice).
- **Autostart messages.** `scripts/autostart_windows.cmd` messages stay English: cmd.exe
  would need code-page switching and a JSON reader for 12 languages.
- **Demo.** A `netbios` status row (the round ran, no Windows machine but this one).

## Server notes (moved here from CLAUDE.md)

- `brain.ENV_KEYS` = the env keys brain reads; web request timeout 15 s.
- `web.Handler.DATA_GATE` = 2 data GETs at once (parallel SQLite reads contend).
- `DashboardServer.request_queue_size` 64: a 12-request page refresh overflowed the
  default backlog of 5 (one request then waited ~1 s).
- Stage Q also added `python3 -m netwarden.i18n --check` and the localized autostart.
