# Bandwidth per device (optional, via ntopng)

[繁體中文](bandwidth.zh-TW.md)

netwarden's main data source is the DNS log of AdGuard Home or Pi-hole. DNS tells you
*who a device talks to* and *how often it asks*, but **not how many bytes it moves**: a
device can look up a name once and then download 10 GB. So the "queries per day" charts
are query counts, not traffic, and the dashboard labels them that way.

If you want real bytes per device, netwarden can read them **read-only** from an
[ntopng](https://www.ntop.org/products/traffic-analysis/ntop/) instance you already run.
Without ntopng nothing changes; the bandwidth parts of the dashboard simply stay hidden.

## What ntopng needs

ntopng only counts what it can see. Run it where the traffic passes:

- on the **gateway** itself (a router running OpenWrt, pfSense, OPNsense, ...), or
- **bridged** between the router and the rest of the LAN, or
- on the **mirror port** (SPAN) of a managed switch.

netwarden never changes your network to get traffic: no ARP spoofing, no MITM, no router
changes. Where ntopng sits is your decision. Most consumer routers expose no per-device byte
counters at all, which is why netwarden does not scrape router web pages.

Set ntopng's local networks (`-m`) to your LAN, for example `192.168.1.0/24`.

## Connect it

Add to netwarden's environment (`.env`, the compose env file, or the add-on options):

```
NTOPNG_URL=http://<ntopng-host>:3000
NTOPNG_USER=...
NTOPNG_PASS=...
NTOPNG_IFID=0        # optional: ntopng interface id
# NTOPNG_TOKEN=...   # instead of user + password: an API token (ntopng user settings)
# NTOPNG_VERIFY_TLS=0  # only for https:// with a self-signed certificate
```

The ntopng user only needs to read the interface: netwarden calls one endpoint,
`GET /lua/rest/v2/get/host/active.lua` (REST API v2, local hosts, paged). Wrong
credentials make ntopng send its login page; netwarden then says "Login refused".
`NTOPNG_IFID` is the interface number ntopng shows in its interface menu (0 is the first);
a wrong one is reported as `INVALID_INTERFACE`.

`python3 -m netwarden run` then samples every 30 seconds. To sample on its own:
`python3 -m netwarden traffic --watch 30`. Totals and rates need at least two samples.
Without `NTOPNG_URL`, `netwarden traffic` prints a hint and exits with 0.

## What you get

- a **Traffic** column on the device list and a 7-day download/upload chart per device;
- a "large transfer" alert when a device moves at least 2 GB in 24 hours and at least 4x its
  usual amount;
- the AI (or the offline explainer) can relate uploads to what a device talks to.

ntopng reports cumulative counters; netwarden stores them as they are and computes usage
when it reads them (a counter that goes down means a restart, never negative usage).
Samples are pruned with the DNS log (`NETWARDEN_RETENTION_DAYS`, default 90 days).

Design notes (Traditional Chinese): [dev/bandwidth_investigation.md](dev/bandwidth_investigation.md).
