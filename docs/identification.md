# Device identification, UPnP exposure and routine traffic

## What netwarden sends on the network

Read-only. Only standard LAN discovery that phones, TVs and printers already do. Every
part runs with each discovery sweep (`run` every 15 min, `netwarden scan`) or on its own
via `netwarden identify`:

| What | Where | Limits |
|---|---|---|
| one mDNS query for 17 DNS-SD service types (QU bit) | 224.0.0.251:5353 | listen 3 s; ≤ 4000 packets |
| one SSDP M-SEARCH (`ssdp:all` + IGD) | 239.255.255.250:1900 | listen 3 s |
| HTTP GET of a UPnP description | only the responder's own private IP, `http://` only, no userinfo | 64 KB, 2.5 s, ≤ 3 per IP, ≤ 48 per run, no redirects, no proxy |
| SOAP `GetExternalIPAddress`, `GetStatusInfo`, `GetGenericPortMappingEntry` | the gateway's control URL (same private IP) | 32 KB / 3 s per call, ≤ 256 mappings, 30 s total |

`upnp.ALLOWED_ACTIONS` is enforced inside `soap_call()` before anything is sent, and
`tests/test_stage_n.py` scans `upnp.py` so that no other action name can creep in.
Answers from non-private addresses are dropped. XML with a DOCTYPE or ENTITY declaration
is refused (`identify.safe_xml`). Everything a device announces is hostile: it is cleaned
to one short line (`store.clean_text`, 96 chars) and always escaped by the UI.

## Evidence and how it is used

`device_identity` (mac, source, name, manufacturer, model, kind, detail, first/last_seen),
one row per device and source, merged with COALESCE, pruned by retention:

- `mdns`: names (`fn`, instance label), models (`md`/`model`/`ty`/`am`), service types
- `ssdp`: `friendlyName`, `manufacturer`, `modelName modelNumber`, `deviceType`
- `dhcp`: the router's reverse-DNS name from the sweep
- `dns`: the client name AdGuard Home / Pi-hole knows (refreshed at most hourly)

Uses:
- **Name.** `store.device_names` gives label > hostname > announced (mDNS, then SSDP) >
  vendor. The page's `dname()` uses the same order. An announced name is offered as
  `identity.suggested_name` in `/api/device`. "Use this name" posts the existing
  `/api/label`. A name is never applied automatically and never replaces a label.
- **Type.** `devicetype` gets an `ident` vote (0.8). An announced maker fills an empty or
  randomized vendor.
- **Drawer.** The drawer shows the model, "Identified via" tags, and an evidence card per
  source.
- **Brain / AI.** The brain snapshot carries `model` and `identified_via`. `redact` maps
  announced names to the device's `[D]` token.

## UPnP

- `upnp_snapshots` stores one row per check. The latest row is kept by prune.
- `upnp_mappings` stores first and last sighting per mapping.
- `upnp.mappings()` returns the mappings of the newest check. It returns nothing when that
  check found no UPnP gateway, so a user who turned UPnP off stops seeing old ports.
- "New" means first seen after the first check that answered.
- Risky ports: 22, 23, 80, 443, 445, 554, 3389, 5900 and 8080.
- Alert kind `upnp` lists risky or new mappings. The ack key is `upnp:<PROTO>:<port>`.
- The digest section is `digest.upnp`.
- `GET /api/upnp?lang=` returns {checked, available, gateway, external_ip,
  external_ip_masked, status, mappings[text, risky, new, muted, ...], summary, howto}.
- The external IP is stored locally and shown masked until the user clicks "Show".

## Routine traffic

`routine.py` contains `ROUTINE`, a map from domain suffix to one of these kinds:
connectivity, time, updates, certs, cdn and cloud. Only well-documented domains are listed.

- Routine domains never count as "started using".
- They never appear as new lookups in the timeline.
- The domain drawer has a calm "Routine traffic" card.
- Top domains get a green tag.
- The brain snapshot marks them as `routine: ...`.

## Unicast round (Stage V3)

Multicast replies rarely reach WSL (the Hyper-V firewall drops them). So the same round
also asks each private inventory IP directly. Those replies come back to the socket that
asked, and a stateful firewall lets them through. The round runs in parallel with the
multicast queries and has one deadline.

| What | Where | Limits |
|---|---|---|
| the mDNS service query + a PTR for the device's own `x.in-addr.arpa` (QU) | each inventory IP, UDP 5353 | ≤ 256 targets, 10 ms apart |
| unicast `M-SEARCH` (HOST = the device, no MX; UDA 1.1 §1.3.3) | each inventory IP + the gateway (also asked for its IGD), UDP 1900 | same; then the existing description / read-only UPnP path |
| NetBIOS node status for `*` (RFC 1002 4.2.17) | each inventory IP, UDP 137 | random txid; answers only from asked IPs |
| PTR via the system resolver | devices without a hostname | 16 threads, 2 s overall; ONLY if every `/etc/resolv.conf` nameserver is loopback / private (`resolver_is_local`) |

Targets come from `identify.inventory_targets`: never this computer, private IPv4 only.
A hostname-only mDNS reply (just the reverse PTR or an A record) still gives a name. The
new source is `netbios`. It is evidence of kind "computer", with the workgroup as detail,
and comes after mDNS and SSDP in `store.ANNOUNCED_SOURCES` / `identity_names`. Reverse
DNS answers are stored as `dhcp` evidence. The CLI and the JSON report counts and kinds
only.

When mDNS, SSDP and NetBIOS all stay silent, /api/status shows
`status.hint.ident_silent_unicast`: many devices simply don't answer, the Hyper-V
firewall may drop replies, and nothing is broken. If only the multicast round ran, the
older `status.hint.multicast_silent` is shown. A failing socket is recorded as an error,
and the error and staleness hints follow.

Real LAN, 2026-10-22, WSL mirrored:

- The sweep saw 2 devices besides this one.
- Multicast SSDP got 0 answers. Unicast SSDP got 1: the router, which was described as
  "network" and read over UPnP (7 mappings, 0 risky).
- mDNS (multicast + unicast) got 0 answers.
- NetBIOS got 0 answers.
- PTR: 1 asked, 0 names.

## Demo story

The TV announces itself over mDNS + SSDP, the printer over IPP, and the router is an IGD;
Dad's iPhone gets a suggested name. UPnP: the ipcam's TCP 554 mapping is new (~3 h, risky
-> alert), the PS5's UDP 3478 is benign; external IP 203.0.113.57.
