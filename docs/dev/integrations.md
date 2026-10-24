# Integrations: compatibility and audit (round 9, stage V)

User docs: [../install.md](../install.md#data-sources-versions-and-settings),
[../pihole.md](../pihole.md), [../bandwidth.md](../bandwidth.md),
[../home_assistant.md](../home_assistant.md). Code: `dns_ingest.py` (`AdGuardHome`,
`PiHole`, `make_source`), `traffic_ingest.py` (`NtopngSource`), `health.py`
(`SourceError`, `tls_context`, `opener`, `error_kind`), `conntest.py`, `addon.py`.
Tests: `tests/test_round9_v.py` (+ `test_pihole.py`, `test_dns_ingest.py`,
`test_traffic_ingest.py`, `test_stage_x.py`, `test_round6_h.py`).

## Compatibility matrix (2026-10)

| integration | versions | how verified | docs read |
|---|---|---|---|
| AdGuard Home | v0.107.x (older v0.107 without `/control/querylog/config` fall back to `/control/querylog_info`) | **real**: dev instance v0.107.79 (`scripts/adguard_dev.sh`, read-only probes); fake server built from openapi.yaml + the probes | [openapi.yaml](https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml), [internal/querylog/http.go](https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/querylog/http.go), [internal/home/authhttp.go](https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/home/authhttp.go) |
| Pi-hole v6 | FTL v6.x, API "6.0" | docs + FTL source + fake server only (no real Pi-hole here) | [API reference](https://docs.pi-hole.net/api/), [specs/auth.yaml](https://github.com/pi-hole/FTL/blob/master/src/api/docs/content/specs/auth.yaml), [specs/queries.yaml](https://github.com/pi-hole/FTL/blob/master/src/api/docs/content/specs/queries.yaml), [specs/main.yaml](https://github.com/pi-hole/FTL/blob/master/src/api/docs/content/specs/main.yaml), [src/api/queries.c](https://github.com/pi-hole/FTL/blob/master/src/api/queries.c) |
| Pi-hole v5 | not supported (never was) | recognized via `GET /admin/api.php?versions` (`core_current`) -> kind `version` | - |
| ntopng | REST API v2 | docs + source + fake server only | [api_v2.html](https://www.ntop.org/guides/ntopng/api/rest/api_v2.html), [examples_v2.html](https://www.ntop.org/guides/ntopng/api/rest/examples_v2.html), [src/HTTPserver.cpp](https://github.com/ntop/ntopng/blob/dev/src/HTTPserver.cpp) |
| Home Assistant add-on | current Supervisor | static tests + CI image build (no Docker / HA here) | [add-on configuration](https://developers.home-assistant.io/docs/add-ons/configuration) (now redirects to contributors.home-assistant.io/apps/), [32-bit deprecation](https://www.home-assistant.io/blog/2025/05/22/deprecating-core-and-supervised-installation-methods-and-32-bit-systems/); earlier sources in [ha_addon.md](ha_addon.md) |

## What the docs say, and what netwarden does

### Pi-hole v6

- **Auth** (auth.yaml): `POST /api/auth {"password"}`; the SID may travel as `X-FTL-SID`,
  `sid` header, `sid` cookie or `?sid=` - we use `X-FTL-SID` (no CSRF needed, never in a
  URL that could be logged). Wrong password = 401 with `session.valid: false`; 2FA on
  without `totp` = 400 "No 2FA token found"; a bad 2FA token = 401 `unauthorized`
  "Invalid 2FA token"; 429 `rate_limiting` (login attempts) vs 429 `api_seats_exceeded`
  (hint: `webserver.api.max_sessions`). App passwords skip 2FA; creating one invalidates
  all sessions. -> netwarden reads the error body and maps each to its own kind (`auth`,
  `totp`, `rate_limited`, `seats`); a 64-hex password that fails is a v5 token
  (`token_v5`). It never sends a TOTP code (no way to keep it fresh unattended).
- **Sessions**: `DELETE /api/auth` 204 / 404 / 401; `GET /api/auth/sessions` lists
  `id, current_session, user_agent, last_active, ...`; `DELETE /api/auth/session/{id}`.
  -> one session per source object, renewed once on 401 (the old SID is logged out first,
  best effort); `close()` on CLI exit, loop stop and after "Test connection"; after each
  login our own idle (>= 600 s by the Pi-hole's clock) sessions - same `netwarden/`
  User-Agent - are ended (leftovers of a crash / SIGKILL). Live twins poll every 60 s and
  are never idle that long; other clients are never touched.
- **Queries** (queries.yaml, queries.c): newest first by id; `from` inclusive, `until`
  exclusive; `length` default 100, cap 10,000 (`API_QUERIES_MAX_ROWS`); `start` skips
  rows; `cursor` = newest id on page 1, echoed later; `disk=true` reads the on-disk
  database; `cursor: null` + no rows = privacy level 3; levels 1-2 replace domains with
  `hidden`. -> paging unchanged (it already matched); disk catch-up when
  `earliest_timestamp` > watermark + 60 s; `hidden` rows skipped, all-hidden or level 3 ->
  kind `log_off`.
- **URL**: users paste `http://pi.hole/admin/`; `/admin` and `/api` suffixes are stripped.
- **HTTPS**: v6 serves its own self-signed certificate -> verified by default,
  `PIHOLE_VERIFY_TLS=0` opt-in (unchanged), certificate / wrong-protocol errors -> kind
  `tls`. A CA-file option (Pi-hole's generated CA) was considered and left out: the
  certificate names `pi.hole`, which rarely matches the address people use.

### AdGuard Home

- `GET /control/querylog`: `older_than` (RFC 3339 nanoseconds, strictly older),
  `limit`, `offset` (not with `older_than`), `search`, `response_status` (deprecated ->
  `reason`). Response `{data, oldest}`; `oldest` = "" at the end. Dev instance: `limit=0`
  returns no rows (we never send < 1), `limit=100000` is accepted, a junk `older_than` is
  400. `elapsedMs` is a string. `question.name` is punycode, `question.unicode_name` the
  Unicode form (seen on the dev instance) -> we store the ASCII form for every source.
- `GET /control/querylog/config` `{enabled, interval, anonymize_client_ip, ignored,
  ignored_enabled}` (older: `/control/querylog_info`). A disabled log answers empty pages
  -> after a run that yielded nothing we check `enabled` and report kind `log_off` (also
  in "Test connection"). `anonymize_client_ip` is documented for users (it breaks per-device
  attribution) but not enforced.
- Auth (authhttp.go): no users = open; otherwise Basic auth or the `agh_session` cookie;
  failures are 401 without `WWW-Authenticate` (403 / 429 only on `POST /control/login`,
  which we don't use). -> Basic auth, unchanged. HTTPS: `ADGUARD_VERIFY_TLS=0` (new).
- `GET /control/clients` has `clients` (persistent, may be null) and `auto_clients`
  (`ip, name, source`); the query log already carries `client_info.name`, so we don't call it.

### ntopng

- REST v2 envelope `{rc, rc_str, rsp}`; `host/active.lua` params `ifid, currentPage,
  perPage, sortColumn, sortOrder, all, mode (all|local|remote|...)`; rc 0 / -1 / -2
  INVALID_INTERFACE / -6; `host/data.lua` also -3 NOT_GRANTED. Example responses have no
  `mac` and no `totalRows` on active hosts (handled since stage C).
- Auth (HTTPServer.cpp): `Authorization: Basic ...` or `Token <t>` / `Bearer <t>` (API
  tokens from user settings); unauthenticated requests get a **302 to /lua/login.lua**.
  -> `NTOPNG_TOKEN` (new), a final URL on `/lua/login.lua` = kind `auth`, rc -2 / -3 / -6
  carry a hint; `NTOPNG_VERIFY_TLS=0` (new). Community limits: the docs mark some
  endpoints Pro / Enterprise; `host/active.lua` is not marked, so Community should work
  (not verified on a real install).

### Home Assistant add-on

- config.yaml keys re-checked; HA deprecated i386 / armhf / armv7 (no builds after
  2025.12). `armv7` stays in `arch` while the release job builds it (existing installs);
  documented as untested.
- New optional options: `adguard_verify_tls`, `pihole_verify_tls`, `ntopng_verify_tls`
  (`bool?`, unset = verify; `addon.TLS_OPTIONS`) and `ntopng_token` (`password?`).
- No Supervisor API use (`hassio_api: false`) - unchanged.

## Everything a source can say -> one kind

`conntest.ERROR_KINDS` gained `tls rate_limited seats totp token_v5 version log_off`
(`err.conn_<kind>` in all 12 locales). Exceptions carry `kind` (`health.SourceError`,
`dns_ingest.PiHoleError`); stored source errors (English, sanitized) are mapped back by
`health.error_kind()` regexes, specific kinds first. Messages never contain the password,
token or SID (tests check). All requests send `User-Agent: netwarden/<version>`.

## Limits on data volume

- One page: 16 MB / 60 s (`health.read_json`, stage K). One ingest run: at most
  `dns_ingest.MAX_EVENTS_PER_RUN` = 100,000 events, newest first (`capped` in the result);
  the rest of a longer gap is skipped, the watermark moves to the newest.

## Not verified locally

- A real Pi-hole v6 (sessions, app passwords, 2FA, disk queries, privacy levels), a real
  Pi-hole v5, a real ntopng (token auth, login redirect, Community edition), AdGuard Home
  with HTTPS / a disabled log / newer than v0.107.79, a real Home Assistant Supervisor.
