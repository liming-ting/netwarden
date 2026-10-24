# Using Pi-hole

[繁體中文](pihole.zh-TW.md)

netwarden can read the query log of **Pi-hole v6** instead of AdGuard Home. It uses Pi-hole
v6's built-in REST API (`/api/auth`, `/api/queries`) and **only reads the query log**: it never
changes Pi-hole's settings, lists or blocking rules, and it never touches your router.

## Settings (`.env` or the compose env file)

```ini
PIHOLE_URL=http://pi.hole          # or http://192.168.1.2, https://pi.hole
PIHOLE_PASSWORD=...                # an app password is best (Settings -> Web interface / API -> App password)
# PIHOLE_VERIFY_TLS=0              # only for HTTPS with Pi-hole's own self-signed certificate
# NETWARDEN_DNS_SOURCE=pihole      # only when both AdGuard and Pi-hole are configured; default is AdGuard
```

- An **app password** is better than the main password: it can be revoked on its own and
  works with two-factor authentication.
- If Pi-hole has no password, leave `PIHOLE_PASSWORD` empty.
- HTTPS certificates are **verified** by default; use `PIHOLE_VERIFY_TLS=0` only on a LAN you trust.
- One DNS source at a time: with both configured, pick with `NETWARDEN_DNS_SOURCE=adguard|pihole`.

## Run

```bash
python3 -m netwarden ingest        # ingest once + a per-device report
python3 -m netwarden run           # dashboard + ingest every 60 s
python3 -m netwarden status        # is "DNS (Pi-hole)" healthy, and how to fix it
```

## Sessions

Pi-hole allows a limited number of API sessions. netwarden logs in **once** per run (or once
for the whole `run` loop) and reuses the session; an expired session (HTTP 401) is renewed
once; on exit it always logs out (`DELETE /api/auth`). If you see "no free API session
(HTTP 429)", close other API clients or wait a few minutes for old sessions to time out.

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

## Limits

- Pi-hole **v6** only (the FTL REST API); v5 and older have no such API.
- Devices are matched like with AdGuard: the client IP of each query is mapped to a MAC
  through known devices and the ARP table. Pi-hole must see each device's own IP. If every
  query is forwarded by the router, Pi-hole (and netwarden) only see the router.
