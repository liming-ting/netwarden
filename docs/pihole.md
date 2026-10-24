# Using Pi-hole

[繁體中文](pihole.zh-TW.md)

netwarden can read the query log of **Pi-hole v6** instead of AdGuard Home. It uses Pi-hole
v6's built-in REST API (`/api/auth`, `/api/queries`) and **only reads the query log**: it never
changes Pi-hole's settings, lists or blocking rules, and it never touches your router.

## Versions

| Pi-hole | status |
|---|---|
| **v6** (FTL v6.x, REST API "6.0") | supported. Checked against the current API reference and FTL source (October 2026) with fake servers in the test suite; **not yet tested against a real Pi-hole** - reports welcome. |
| v5 and older (`admin/api.php`) | not supported: netwarden reads only the v6 REST API (v5 support never existed). It recognizes a v5 server and says so instead of failing with a vague error. |

## Settings (`.env` or the compose env file)

```ini
PIHOLE_URL=http://pi.hole          # or http://192.168.1.2, https://pi.hole (".../admin" is fine too)
PIHOLE_PASSWORD=...                # an app password is best (see below)
# PIHOLE_VERIFY_TLS=0              # only for HTTPS with Pi-hole's own self-signed certificate
# NETWARDEN_DNS_SOURCE=pihole      # only when both AdGuard and Pi-hole are configured; default is AdGuard
```

- **App password (recommended):** in Pi-hole's web interface open **Settings -> Web
  interface / API** (switch to *Expert* mode if you don't see it), click **Configure app
  password**, copy the password and press **Enable new app password**. It can be revoked
  on its own, and it is **the only way in when two-factor authentication (2FA) is on** -
  netwarden never asks for a 2FA code. Note: setting a new app password logs out all
  current Pi-hole sessions (netwarden simply logs in again).
- The web interface password works too (without 2FA).
- A Pi-hole v5 "API token" (64 hex characters) does **not** work with v6; netwarden tells
  you when it sees one.
- If Pi-hole has no password, leave `PIHOLE_PASSWORD` empty.
- **HTTPS:** certificates are **verified** by default. Pi-hole v6 serves HTTPS with its own
  self-signed certificate; on your home network the simplest choice is `http://`. If you
  want `https://` with that certificate, set `PIHOLE_VERIFY_TLS=0` (an explicit opt-in;
  only on a network you trust).
- **Privacy level** (Settings -> Privacy) must be 0 ("show everything"): at levels 1-3
  Pi-hole hides domains or clients and netwarden can't tell you anything per device. It
  says so in the status instead of showing an empty, "quiet" home.
- **Client names:** Pi-hole names clients from its DHCP leases, `/etc/hosts` / local DNS
  records and reverse DNS. netwarden uses those names as hints; your own labels in
  netwarden always win.
- One DNS source at a time: with both configured, pick with `NETWARDEN_DNS_SOURCE=adguard|pihole`.

## Run

```bash
python3 -m netwarden ingest        # ingest once + a per-device report
python3 -m netwarden run           # dashboard + ingest every 60 s
python3 -m netwarden status        # is "DNS (Pi-hole)" healthy, and how to fix it
```

The dashboard's **Settings -> Test connection** asks Pi-hole one cheap question (log in,
`GET /api/info/version`, log out) and explains any problem in plain words.

## Sessions

Pi-hole allows a limited number of API sessions ("seats", `webserver.api.max_sessions`).
netwarden logs in **once** per run (or once for the whole `run` loop) and reuses the
session; an expired session (HTTP 401) is renewed once; on exit it always logs out
(`DELETE /api/auth`). A session left behind by a crash or a forced kill (which can't log
out) is ended by the next start: netwarden lists the sessions and ends only **its own**
(same `netwarden/<version>` User-Agent) that have been idle for 10 minutes or more. Other
clients' sessions, including your browser's, are never touched.

## Query log details

- Paging follows FTL: the first page fixes a `cursor`, later pages pass it plus `start`;
  `from` (inclusive) starts at the last query already stored.
- FTL keeps the last 24 hours in memory. When netwarden was off for longer, the next run
  reads the gap from Pi-hole's on-disk database (`disk=true`).
- One run stores at most 100,000 queries (newest first): the first run on a busy Pi-hole
  starts from the recent past instead of loading months of history.
- Queries still waiting for an answer (`IN_PROGRESS`) are fetched again on the next run.

## Block status

Every query keeps Pi-hole's raw status (`reason`, for example `GRAVITY`, `FORWARDED`) plus a
unified `blocked` (0/1) and a short `block_reason`:

| Pi-hole status | block_reason |
|---|---|
| GRAVITY, GRAVITY_CNAME | blocklist |
| REGEX, REGEX_CNAME | regex |
| DENYLIST, DENYLIST_CNAME | denylist |
| EXTERNAL_BLOCKED_* | upstream |
| SPECIAL_DOMAIN | special |
| DBBUSY | busy |
| FORWARDED, CACHE, CACHE_STALE, RETRIED, ... | not blocked (NULL) |

AdGuard Home's `reason` maps to the same codes (FilteredBlackList -> blocklist,
FilteredSafeBrowsing -> safebrowsing, FilteredParental -> parental,
FilteredBlockedService -> service, FilteredInvalid -> invalid).

## Troubleshooting

| netwarden says | what to do |
|---|---|
| Login refused - check the user name, password or key | Wrong `PIHOLE_PASSWORD`. Create an app password and paste it again. |
| Two-factor login is on | Use an app password (2FA codes are never asked for). |
| That looks like a Pi-hole v5 API token | v6 uses the web password or an app password, not the v5 token. |
| This isn't a Pi-hole v6 API | `PIHOLE_URL` points at a Pi-hole v5 or at something else. Update Pi-hole to v6 or fix the address (`http://<pi-hole>`, no path needed). |
| Pi-hole has no free API session | Too many clients are logged in. Close other API tools or wait a few minutes; raise `webserver.api.max_sessions` in Pi-hole if you use many. |
| Too many login attempts | Pi-hole is rate-limiting logins after wrong passwords. Fix the password, wait a minute. |
| The HTTPS certificate isn't trusted | Use `http://` on your LAN, or set `PIHOLE_VERIFY_TLS=0`. |
| Connected, but the query log is off or hidden | Set Settings -> Privacy to "show everything" (level 0). |
| Every device shows up as the router | The router forwards all DNS to Pi-hole. Give Pi-hole's address to devices via DHCP (router or Pi-hole's own DHCP) instead. |

## Limits

- Devices are matched like with AdGuard: the client IP of each query is mapped to a MAC
  through known devices and the ARP table. Pi-hole must see each device's own IP. If every
  query is forwarded by the router, Pi-hole (and netwarden) only see the router.
- Compatibility details and sources: [dev/integrations.md](dev/integrations.md).
