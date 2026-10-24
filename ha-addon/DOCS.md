# netwarden add-on

netwarden discovers the devices on your home network, reads per-device DNS from
AdGuard Home or Pi-hole, and explains what it sees in plain language. It is read-only:
it never changes your router, firewall, AdGuard Home or Pi-hole.

Full guide (also in Traditional Chinese): https://github.com/liming-ting/netwarden/blob/main/docs/home_assistant.md

## Getting started

1. Install the add-on and start it. Leave **Start on boot** on.
2. Click **Open web UI** (or **netwarden** in the sidebar). The dashboard opens inside
   Home Assistant; only Home Assistant administrators see it.
3. Without a DNS source netwarden still finds devices on the LAN. For "who talks to
   what", set `adguard_url` (or `dns_source: pihole` + `pihole_url`) and restart.

## Options

| option | what it does |
|---|---|
| `language` | Dashboard language (zh-Hant, en, zh-Hans, es, pt-BR, ja, de, fr, ko, ru, id, hi). Empty = choose it in the dashboard. |
| `timezone` | IANA name such as `Europe/Berlin`. Empty = Home Assistant's time zone. |
| `dns_source` | `adguard` or `pihole` (v6). |
| `adguard_url`, `adguard_user`, `adguard_password` | AdGuard Home's web address and login. netwarden reads the query log only. |
| `pihole_url`, `pihole_password` | Pi-hole v6 address and its web or app password. |
| `ntopng_url`, `ntopng_user`, `ntopng_password` | Optional: bytes per device from ntopng. |
| `ntopng_token` | Optional: an ntopng API token instead of user name and password. |
| `adguard_verify_tls`, `pihole_verify_tls`, `ntopng_verify_tls` | Leave unset (HTTPS certificates are verified). Turn off only for an `https://` address with the source's own self-signed certificate. |
| `anthropic_api_key` | Optional: AI answers from Claude, only when you ask in the AI page. |
| `ai_api_key` | Optional: key for a local / private OpenAI-compatible server (address and model are set in the dashboard's Settings). |
| `offline_ai` | Never call an AI model; the AI page uses its built-in offline summary. |
| `lan_access` | Also open the dashboard on this host's LAN address, port 8787, for phones. They must be paired first. |
| `retention_days` | DNS and traffic history kept (default 90, at least 8). |

An option you set here wins over the same setting in the dashboard (which then shows
it as set by the add-on). Leave an option empty to manage it in the dashboard instead.
Passwords and keys are stored by Home Assistant and never shown or logged by netwarden.

Restart the add-on after changing options.

## Phones and other computers

Turn on `lan_access` and restart. In the dashboard open **Settings**, card **Open on
your phone**, and click **Show pairing code**; scan the QR code with the phone (same
Wi-Fi). Plain HTTP: use it on a trusted home
network only. Without `lan_access`, netwarden is reachable only through Home Assistant.

## What to expect

- Discovery sees devices on the network Home Assistant's host is on. Devices behind
  another router, a guest Wi-Fi or a VLAN may not show up.
- "Who talks to what" needs AdGuard Home or Pi-hole to be the DNS server of your
  devices. Phones with private DNS / DNS-over-HTTPS bypass it (netwarden points this out).
- The AdGuard Home add-on: give its web interface a port in its Network settings and
  use `http://<your Home Assistant IP>:<that port>` as `adguard_url`.
- Translations other than English and Traditional Chinese are machine-assisted.

## Troubleshooting

- **The panel stays blank or shows 502:** open the add-on's **Log** tab. "Port 8787 is
  already in use" means another program on the Home Assistant host uses it (the add-on
  shares the host's network). A line `ingress: could not listen on ...` means the
  Supervisor network address could not be used - please report it with the log.
- **No DNS data on the dashboard:** set `adguard_url` (or `pihole_url`), then restart.
  **Settings > Connection tests** has a Test button for each source.
- **A phone asks for a code again:** pairing codes are valid for 10 minutes and once;
  show a new one.
- Logs never contain passwords, keys or pairing codes.
