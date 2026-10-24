# netwarden as a Home Assistant add-on

[繁體中文版](home_assistant.zh-TW.md)

netwarden runs as a Home Assistant add-on (on Home Assistant OS or a Supervised
install) and opens in the Home Assistant sidebar. It finds the devices on your network,
reads per-device DNS from AdGuard Home or Pi-hole, and explains what it sees in plain
language. It is read-only: it never changes your router, firewall, AdGuard Home or
Pi-hole.

> Home Assistant **Container** and **Core** installs have no add-ons. Use the Docker
> image or the Linux install instead (docs/install.md).

## Install

1. In Home Assistant open **Settings > Add-ons > Add-on Store**, then the menu (⋮) >
   **Repositories**, and add:

   ```
   https://github.com/liming-ting/netwarden
   ```

2. Find **netwarden** in the store (refresh the page if it does not show up), click
   **Install**, then **Start**. Leave **Start on boot** on; **Show in sidebar** is on by
   default.
3. Click **Open web UI** or **netwarden** in the sidebar. Only Home Assistant
   administrators see the panel.

The add-on image is `ghcr.io/liming-ting/netwarden-addon` for amd64, aarch64 (64-bit Raspberry Pi)
and armv7. Updates show up in Home Assistant like any other add-on update. (Home Assistant
dropped 32-bit systems with release 2025.12; the armv7 image is still built for existing
installs, but it is untested.)

## Options

Set them on the add-on's **Configuration** tab, then restart the add-on. Unused optional
fields are hidden until you click **Show unused optional configuration options**.

| option | environment variable it stands for | notes |
|---|---|---|
| `language` | `NETWARDEN_LANG` | zh-Hant (default), en, zh-Hans, es, pt-BR, ja, de, fr, ko, ru, id, hi |
| `timezone` | `NETWARDEN_TZ` | IANA name; empty = Home Assistant's time zone |
| `dns_source` | `NETWARDEN_DNS_SOURCE` | `adguard` or `pihole` |
| `adguard_url` / `adguard_user` / `adguard_password` | `ADGUARD_URL` / `ADGUARD_USER` / `ADGUARD_PASS` | query log, read-only |
| `pihole_url` / `pihole_password` | `PIHOLE_URL` / `PIHOLE_PASSWORD` | Pi-hole v6; an app password is best |
| `ntopng_url` / `ntopng_user` / `ntopng_password` | `NTOPNG_URL` / `NTOPNG_USER` / `NTOPNG_PASS` | optional bytes per device |
| `ntopng_token` | `NTOPNG_TOKEN` | optional, instead of the ntopng user + password |
| `adguard_verify_tls` / `pihole_verify_tls` / `ntopng_verify_tls` | `ADGUARD_VERIFY_TLS` / `PIHOLE_VERIFY_TLS` / `NTOPNG_VERIFY_TLS` | leave unset (certificates are verified); off only for an `https://` address with the source's own self-signed certificate |
| `anthropic_api_key` | `ANTHROPIC_API_KEY` | optional; called only when you ask the AI |
| `ai_api_key` | `NETWARDEN_AI_KEY` | optional key of a local / private OpenAI-compatible server |
| `offline_ai` | `NETWARDEN_OFFLINE_AI` | never call any AI model |
| `lan_access` | `NETWARDEN_LAN` | open the dashboard to phones on the LAN (with pairing) |
| `retention_days` | `NETWARDEN_RETENTION_DAYS` | history kept, 8-3650 days (default 90) |

How they combine with the dashboard: **add-on option > dashboard setting > built-in
default** - the same order as environment variables everywhere else. A setting fixed by
an option shows as "set in the add-on options" in the dashboard and can't be edited
there; leave the option empty to manage it in the dashboard instead (for example the
AI server address and model, quiet hours, alert tuning). Passwords and keys stay in Home
Assistant's add-on options, are never sent to the browser and never written to the log.

### AdGuard Home or Pi-hole as add-ons

- **AdGuard Home add-on:** on its **Network** settings give the web interface a port
  (for example 3000), restart it, and set `adguard_url` to
  `http://<your Home Assistant IP>:3000` with the AdGuard Home login.
- **Pi-hole** elsewhere on the network: `dns_source: pihole`, `pihole_url:
  http://192.168.1.3` and its password.

Then check **Settings > Connection tests** in the dashboard.

## Ingress (the sidebar panel)

Home Assistant shows the dashboard through *ingress*: your browser talks to Home
Assistant only, and Home Assistant's Supervisor forwards the requests to the add-on.

- You are signed in by Home Assistant; netwarden asks for nothing else. Only
  administrators get the panel (`panel_admin`), and inside it you have netwarden's admin
  rights (settings, backups, port checks, pairing).
- netwarden trusts exactly one sender for this: the Supervisor's ingress proxy address
  (172.30.32.2). The forwarded headers (`X-Ingress-Path`, `X-Forwarded-*`) are ignored
  from anyone else, so a device on your LAN can't pretend to be Home Assistant.
- It works through Nabu Casa remote access too, because that goes through Home Assistant.
- The live updates (the green "Live" dot) and the weekly report work inside the panel.

## Phones and other computers (LAN access)

By default netwarden is reachable **only through Home Assistant**. To open it on a phone
browser directly:

1. Set `lan_access: true` and restart the add-on.
2. In the panel open **Settings**, card **Open on your phone**, click **Show pairing
   code** and scan the QR code with the phone on the same Wi-Fi.

The phone then opens `http://<Home Assistant IP>:8787`. Paired phones can see the
dashboard but not the admin actions; revoke them on the same card. This is plain HTTP:
use it on a trusted home network only. Through Home Assistant's app or Nabu Casa you can
also simply open the sidebar panel instead.

## What the add-on can and can't do

- **Network access:** it uses the host network (`host_network`) so discovery (ARP table,
  ping sweep, mDNS / SSDP) sees your LAN. It is not privileged, asks for no extra
  capabilities and has no access to the Home Assistant or Supervisor APIs. The image
  starts as root only to take ownership of its `/data` folder and then switches to an
  unprivileged user.
- **Port 8787** on the host is used by the add-on (loopback and the Supervisor's
  internal network; your LAN only with `lan_access`). Another program on that port stops
  the add-on from starting.
- **Backups:** `/data` (database, settings, pairing sessions) is in Home Assistant
  backups. The add-on is stopped briefly while a backup is taken (a consistent SQLite
  file).
- **Discovery** sees the network Home Assistant's host is on; devices behind another
  router, a guest Wi-Fi or a VLAN may be missing.
- **DNS** only shows devices that use AdGuard Home / Pi-hole. Phones with private DNS
  or browsers with DNS-over-HTTPS bypass it; netwarden points this out.
- **No AppArmor profile** is shipped yet (Home Assistant's default container profile
  applies), which lowers the add-on's security rating in the store a little.
- **Translations** other than English and Traditional Chinese are machine-assisted.
- The project was built with heavy AI assistance and is covered by a large automated
  test suite; the add-on itself was tested against a simulated Supervisor and ingress
  proxy only - it has not yet been tested on a real Home Assistant install.

## Troubleshooting

| symptom | what to do |
|---|---|
| The add-on does not appear in the store | Check the repository URL; reload the store page (⋮ > Check for updates). |
| The panel is blank / 502 Bad Gateway | Look at the add-on's **Log** tab. "Port 8787 is already in use": another program on the host uses it. |
| "No DNS data" / DNS source not configured | Set `adguard_url` or `pihole_url`, restart, then **Settings > Connection tests**. |
| A setting can't be changed in the dashboard | It is set by an add-on option; change or clear it on the Configuration tab. |
| A phone can't connect | `lan_access` on? Add-on restarted? Same Wi-Fi? Pair again (codes last 10 minutes). |
| AI answers say "offline mode" | No key set, or `offline_ai` is on. That is the private default. |

The log shows which options are set (names only), never their values.
