# Stage K - robustness and hardening

What was attacked, what broke, what was fixed and what is left. No new features. Every
check runs on 127.0.0.1 with private copies of the demo DB and the offline AI; nothing
here talks to a real host or the real LLM.

## 1. Input fuzzing (tests/test_stage_k_fuzz.py, tests/fuzzkit.py)

`fuzzkit` is a small stdlib fuzzer. It is seeded (`SEED`, so a failure replays) and uses
nasty strings (NUL, lone surrogates, RTL/line separators, 64 KB, `<script>`, `../`, SQL
quotes, format strings), nasty numbers (NaN/inf, 2**63, -0, bools), deep nesting and
mutations of valid payloads. `NETWARDEN_FUZZ=heavy` runs 40x the cases, or set a number.

- **Every POST endpoint** (~40 valid samples, one per route, so a new route without a
  sample shows up): 25 mutated bodies each, plus non-object bodies (arrays, strings,
  numbers, `null`, invalid UTF-8, BOM, 1 MB + 1). The expected result is a 4xx with a localized
  JSON `error`, never a 5xx or a traceback. The user tables are hashed before and after,
  and a rejected request must leave them unchanged.
- **Every GET with parameters** (~25 paths): fuzzed query values and repeated/unknown
  parameters, plus path tricks (`..`, `%2e%2e`, `//`, NUL, overlong, backslashes).
- **Protocol abuse** over a raw socket: HTTP/2 preface and bad versions -> 400,
  PUT/DELETE/PATCH/OPTIONS/TRACE/HEAD -> 405 (`allow: GET, POST`), a URL over 64 KB -> 414,
  too many or too long headers -> 431, a bad or missing Host -> 421, a bad `content-length`
  -> 400/413.
- A socket guard fails the test if anything connects to a non-loopback address.

**Found and fixed:**
- `http.server`'s own errors (501 unsupported method, 505 version, 414, 431, 400) came back as
  HTML pages and as 5xx codes. `Handler.send_error` now maps 501 to 405 and any other
  5xx to 400, and answers with localized JSON (`err.bad_method|bad_request|uri_too_long|
  headers_too_large`). A request line with a bogus version got a reply without a status line
  (HTTP/0.9), which is now fixed.
- A POST that raised an unexpected `TypeError`/`OverflowError`/`RecursionError`/`UnicodeError`
  from deep or odd JSON gave a 500. These now return 400 `bad_json`, and any other
  exception goes through `failure_answer` (localized, logged).
- Each request opened several SQLite connections (one per helper). It now uses one
  per request (`Handler._db()`), which is always closed in `finally`, even on errors and
  broken pipes.

Results: the normal suite runs 25 cases per endpoint in a few seconds. The heavy run
(`NETWARDEN_FUZZ=heavy`, all 44 `test_stage_k_*` tests via the `discover` command below)
passed in about 270 s.

## 2. Network-supplied data (tests/test_stage_k_parsers.py)

| Parser | Limits now | Fixed |
|---|---|---|
| mDNS / DNS wire | name pointers bounded, truncated packets refused | at most 1024 records kept per host |
| SSDP `LOCATION` | must be the responder's own private IP, 64 KB | control or whitespace characters anywhere are refused (urlsplit stripped a leading `\x00`) |
| UPnP XML (`identify.safe_xml`) | DTD / entities refused (billion laughs, XXE), UTF-16/32 ok, UTF-7 refused, deep or wide trees bounded | - |
| UPnP SOAP mappings | `ALLOWED_ACTIONS` only, cap 256 | lease values over 2**32-1 overflowed SQLite; now clamped (`upnp._lease`) |
| NetBIOS | fixed-size reads | - |
| AdGuard / Pi-hole / ntopng | `health.read_json`: 16 MB, 60 s per response, dict only; 1000 pages; fields typed and capped at 255 chars | an item of the wrong type crashed the whole poll; it is now skipped (`src.skipped`). NaN, bool and huge counters are refused. Non-JSON or oversized bodies raise a sanitized error and go to `source_status` |

All fetches already had connect/read timeouts. Now every body also has a total size and
a total-time cap, so a slow-drip server cannot hold a loop.

## 3. Database (tests/test_stage_k_db.py, tests/fixtures/)

**SQL audit.** Every f-string or `%` in SQL was checked. All of them interpolate fixed
fragments (column lists from code, `?` placeholders). No untrusted value is formatted into SQL.
One robustness fix: `search.py` passed one `?` per matching domain and could exceed
SQLite's variable limit on a big DB. It now uses `IN (SELECT value FROM json_each(?))`.

**Migrations.** The pre-round2, pre-round3 and pre-round4 tarballs were extracted under
/tmp. `tests/fixtures/make_legacy_db.py` (run with the old tree on `PYTHONPATH`) writes
the same user data into whatever schema that era had and dumps
`legacy_pre_round{2,3,4}.sql`. A fourth variant strips AUTOINCREMENT. The tests check:
- the migrated schema equals a fresh DB's schema;
- labels, profiles, acks, settings and rules are kept; the legacy vendor placeholder is cleared;
- `block_reason` is backfilled; people are created from owners;
- AUTOINCREMENT is kept above ids that acks still name;
- a second open changes nothing (identical dumps);
- snapshot, alerts, inbox, suggestions and backup all run.

The old eras' own `data/demo.db` files are migrated too (skipped when /tmp/nwk is gone).

**Damaged DB.** `store.connect()` now classifies failures as `store.DBError` with kind
`corrupt` (not a database / malformed), `locked` or `unreadable` (permissions,
directory, missing parent). Results:
- CLI (`netwarden <cmd>`, `netwarden.alerts`, `netwarden.web`): a localized message and
  exit code 2 instead of a traceback; corrupt adds a `restore <backup.json>` hint.
- API: 503 `err.db_corrupt` / `err.db_unreadable`; locked -> 503 `err.busy`.

## 4. Long-running stability (scripts/soak.py)

`scripts/soak.py` uses a demo copy under /tmp and the offline AI. It runs fake AdGuard and
ntopng servers on an ephemeral 127.0.0.1 port (40 queries per poll), and loops 30x faster
(dns 2 s, traffic 1 s, health 2 s, notify 2 s, prune every 60 s with 8-day retention).
2000 DNS events 20 days old are seeded, and the prune loop must remove them.

The client side:
- page workers send GETs plus label and ack POSTs;
- two live-stream clients;
- a "rude" client leaves connections half-open or abandons them mid-request.

It samples threads, RSS, fds, sockets, DB/WAL size, row counts, cache size,
subscribers and loop failures every minute. It exits with 1 if anything grows past `LIMITS`.

**Results** (WSL2, Python 3.12, after the fixes below):

| | realistic, 20 min | fixed data (`--events 0`), 12 min |
|---|---|---|
| requests ok / 4xx / 5xx | 8399 / 0 / 0 (+34 streams, 162 live events) | ~12000 / 0 / 0 |
| DNS events | 2.7k -> 15.2k (2000 expired rows pruned at the first pass) | 1629 flat |
| threads | 17-24, no trend | 17-19 |
| open fds / sockets | 29-43 / 6-15, no trend | 27-32 |
| RSS | 72 -> 126 MB, tracks the data (5.6x more rows) | 63 -> 71 MB, flat once the cache is full |
| cache | 64 entries (cap), ~195 KB; locks = entries | same |
| WAL | peak 7.3 MB (before the fix: 18 MB and growing) | peak 2.0 MB |
| loop failures | 0 | 0 |
| shutdown | 4.1 s; 1 thread left (main), no loop alive | 3.7 s |

Requests per minute fall in the realistic run (~950 -> ~150) only because each page
computes over 5x the rows at 30x the real ingest rate. With fixed data the rate stays at
~1000/min for the whole run. Verdict: no leak. Memory and time follow the data, and
retention bounds the data.

An earlier fixed-data attempt also tested a broken source by accident (the fake AdGuard
dropped the connection on an empty page). The DNS loop logged it sanitized, backed off to
16x its interval, and everything else kept running.

**Found and fixed:**
- **The WAL file only grew** (4 MB -> 18 MB in 20 min, and still rising). The loops and the
  dashboard always have a reader open, so SQLite's automatic checkpoint never gets a moment
  to reset the WAL. Fixes:
  - every connection sets `journal_size_limit` (`store.WAL_LIMIT_BYTES`, 8 MB);
  - `store.checkpoint(db)` (`wal_checkpoint(TRUNCATE)`, best effort) runs after each
    prune and once an hour from the notify loop (`runner.NotifyJob`), which always runs.
- `cache._key_locks` kept one lock per key ever asked for (every device, every search),
  so it grew forever. It is now trimmed to 4x `MAX_ENTRIES` (idle locks without a result).
- Per-request connection churn is described in section 1. Open fds stay flat.

## 5. Shutdown and restart (tests/test_stage_k_lifecycle.py)

- SIGTERM is treated as Ctrl+C (`web.on_sigterm`). Shutdown order is `web.stop_server`:
  1. the loops stop (each finishes its current transaction; a stuck job is left as a
     daemon after the timeout);
  2. the warm-up thread stops;
  3. the server closes, which ends the live streams.

  A second Ctrl+C during shutdown is ignored, so the shutdown is not cut in half.
- Tested in a child process: SIGTERM with an open live stream exits 0 within 8 s,
  prints "stopped", leaves no traceback and passes `integrity_check`. A restart on the same DB
  keeps the user's label. SIGINT also exits 0.
- A live-stream reconnect after a restart sends an old `last-event-id`. The new process
  has a new epoch, so the client gets `event: resync` and reloads.
- Presence, the quiet-hours ledger (`notify_log`) and the cache are rebuilt from the DB
  on start. Nothing important lives only in memory, so a restart resumes them. The Stage
  P and Q tests cover their logic. The warm-up pass runs again on start.

## Known limits

- A live stream that the browser dropped stays subscribed until its next heartbeat
  (25 s). A client that reloads very fast can briefly hit the per-client limit (429).
  The page backs off; the soak counts this as `stream_refused`, not as a failure.
- HTTP/0.9 requests (`GET /` without a version) get a bare body, as the protocol requires.
- The heavy fuzz and the soak are not part of the normal suite (time). Run them before
  a release:
  - `NETWARDEN_FUZZ=heavy python3 -m unittest discover -s tests -p 'test_stage_k_*.py'`
  - `python3 scripts/soak.py --minutes 20 --port 8799`
