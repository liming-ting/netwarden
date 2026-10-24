# Network health, suggestion center, home network score

All three are read-only toward the network: netwarden never changes the router, AdGuard
or Pi-hole. The only things a user action writes are their own notes in SQLite (a
suggestion's status, an outage "Got it", the optional internet probe setting).

## Network health (`netwarden/nethealth.py`)

**Passive first.** DNS failure rate and speed come from the DNS events already ingested:
an *upstream* lookup is `cached = 0 AND blocked = 0`; it *failed* when `status` is
SERVFAIL / REFUSED (AdGuard), or for Pi-hole when FTL never got an answer (status NULL with
reason FORWARDED / RETRIED*). The DNS loop also reads the server's own counters every
5 min (`dns_ingest.record_stats`: AdGuard `/control/stats`, Pi-hole `/api/stats/summary`)
into meta `dns_server_stats` - upstreams keep their host name only, never a URL.

**The only active check** is the LAN's default gateway (`upnp.default_gateway()`, must be
a private address - `exposure.allowed`), once a minute from the `health` run loop:
`ping -n -q -c 3 -W 1 <ip>` via `subprocess.run` with a fixed argument list (the address
is validated as a literal IP first, never a shell), else a TCP connect to 80 / 443 / 53
(connected *or refused* = the router answered). Samples go to `health_samples`
(`ts, target, ok, latency_ms, loss, method`), pruned with the normal retention.

**Optional internet probe** - setting `health.internet_probe` (env
`NETWARDEN_INTERNET_PROBE`), `host:port`, **off by default**. A TCP connect only (nothing
is sent), once a minute, so "internet down" and "DNS down" can be told apart.

**Outages.** Per UTC minute: gateway answered? DNS failing (>= 3 failed upstream lookups
and >= 50% of them)? probe answered? A minute is bad if the gateway or the probe did not
answer, or DNS was failing. Runs of bad minutes (gaps <= 2 min bridged) lasting >= 2 min
are outages, with a probable cause:

| cause | rule |
|---|---|
| `router` | the gateway was down in >= half the bad minutes ("your router or Wi-Fi") |
| `isp` | the probe was down, or the gateway answered and there is no probe |
| `dns` | the probe got through - only DNS was broken |
| `unknown` | nothing was measuring the gateway (e.g. `run` was not running) |

`update_outages()` re-derives the last 3 h on every probe and merges into `outages`
(overlapping / adjacent rows grow or merge; an "ongoing" row closes once nothing ongoing
overlaps it). `netwarden health --rebuild DAYS` re-derives a longer window.

**Alert kind `outage`**: ongoing, or ended in the recent window; acked on the pseudo
device `network` with key `outage:<id>` (`POST /api/ack {"mac": "network", "domain":
"outage:12"}` - any other key for `network` is a 400). Digest section "🌐", offline AI
section, and top-level `network_health` in the LLM snapshot (local times + cause).

**Verdict** (`GET /api/health`): an ongoing outage -> `down_<cause>`; else the last hour:
gateway loss >= 5% -> `lossy`, latency >= 50 ms -> `slow_router`, DNS failing >= 5% ->
`dns_failing`, DNS >= 150 ms -> `dns_slow`; else `ok` (`idle` with no data at all). The
response also has a 10-min gateway series (24 h), DNS per local day (7 d), the server
counters, and the outage log (30 d) localized ("last night 02:13-02:20 · 7 min · ...").

## Suggestion center (`netwarden/suggestions.py`)

`detect(db, env)` asks every module what is actionable now and returns `active` +
`resolved` items with a **stable id**:

| kind | id | from | platforms |
|---|---|---|---|
| port | `port:<mac>:<n>` | opt-in port checks (exposure) | device, router |
| upnp | `upnp:<PROTO>:<n>` | risky UPnP mapping | router, device |
| threat | `threat:<mac>` | malicious / high-risk lookups (7 d) | adguard, pihole, device |
| doh | `doh:<mac>` | DNS bypass (visibility) | adguard, pihole, device |
| trackers / blocklist | `trackers` / `blocklist` | home privacy grade | adguard, pihole |
| ai_redact | `ai_redact` | cloud AI without redaction | netwarden |
| outages_isp / outages_router | same | >= 2 outages of that cause in 7 d | isp, router |
| names / owners | same | nameless devices / personal devices without an owner | netwarden |
| bedtime | `bedtime:<mac>` | night activity with no covering rule | netwarden, device |

Each has severity (high / medium / low), pillar, params, devices, copyable `rules`
(AdGuard + Pi-hole, the same validated generator as the privacy page) or `copy` (the
outage log for the ISP), and localized title / why / steps per platform
(`sug.<kind>.title|why|done|steps.<platform>`).

**Status** (table `suggestion_state`, user data, never pruned): open / done / dismissed /
snoozed (1-90 days, default 7) via `POST /api/suggestions/<id> {"status", "days"?}`
(415 / 400 `bad_status` `bad_snooze` `bad_suggestion` / 404). Nothing is ever applied.

**Took effect.** A suggestion that is no longer detected moves to *done* with the time the
data shows it changed: a port seen closed by a later check, a UPnP mapping gone from the
next snapshot, the first *blocked* lookup after the last one that got through (threat,
DoH), the tracker entries listed when the user marked it done showing up blocked, a label
/ profile / setting / bedtime rule saved. Marked done but still detected = "waiting".

## Home network score (`netwarden/score.py`)

Four pillars of 25 points: security, privacy, health, tidiness. Each loses points only for
what the data shows (port high 8 / medium 4, cap 16; UPnP 6, cap 12; threat 10, cap 20;
DoH 3; cloud AI without redaction 5; tracker grade B 4 / C 8 / D 13 / F 18; outages 4 each,
cap 15; router loss 5 / slow 3; DNS failing > 2% (outside logged outages - not counted
twice) 5 / slow 3; unnamed share x 12; owner-less personal share x 8; unreviewed new
devices 1 each, cap 5). A pillar netwarden cannot measure yet is left out and the rest
rescaled to 0-100; **dismissed suggestions cost nothing**. `GET /api/score`: score, level
(>= 80 ok, >= 60 warn), pillars, deductions, "how to raise it" (open suggestions only, with
the points each would win back), and the trend: `score_history` gets today's score from
the health loop every 15 min (and from the first GET of the day).

## Dashboard

`#/health` (key 4, `g h`): verdict hero, tiles, latency sparkline (SVG, red = no answer),
outage log, DNS speed / failure bars, internet probe form, server counters.
`#/suggestions` (key 5, `g t`): tabs open / done / snoozed / dismissed, expandable items
with platform tabs, steps, copy boxes and Done / Snooze 7 d / Dismiss / Reopen (Undo toast).
Overview: score card (pillars, 7-day bars, how to raise it, breakdown), "Next best steps"
(top 3), a Network tile. Nav badges: open suggestions, health when an outage is ongoing.
Phones: 4 sections in the bottom bar + "More" menu (Esc / outside click closes).

## Demo story

48 h of gateway pings; last night 02:13-02:20 local the camera's lookups SERVFAIL while
the router answers -> `isp` outage (7 min); yesterday 19:41 the router stops answering ->
`router` blip (3 min). AdGuard counters in meta. Seeded once (meta `demo_suggestions`):
`names` dismissed, `trackers` done (waiting). `score_history`: 14 days climbing by 12 to
today's score (+7 over the week).

## Performance (scripts/perf_db.py, 300 devices, 7 d of minute pings)

Warm: `/api/health` 19 ms, `/api/suggestions` 24 ms, `/api/score` 23 ms (cold first hit
~230 / ~300 / ~30 ms; `runner.warm` pre-computes the health picture).
