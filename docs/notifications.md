# Push notifications

[繁體中文](notifications.zh-TW.md)

netwarden can send selected alerts and digests to your phone through a service you choose.
It is **off until you add a channel**, and a new channel starts **paused**: send a test,
then turn it on. A channel is one of the few things that make netwarden talk to a server
outside your network (the full list is in the README's
[privacy table](../README.md#privacy-what-can-leave-your-network-and-when)), and you can see exactly
what is sent: the editor shows the exact HTTP request (credentials masked) for a sample
message while you type.

Open **Settings > Notifications** (or press Ctrl+K and type "notifications"). Only an admin
can see, add, edit, test or delete channels: this computer, or an admin session
(`pair --admin`, see [lan.md](lan.md)). A paired phone in viewer mode sees nothing about
channels.

## Which service

| Service | Where the text goes | What you need |
|---|---|---|
| [ntfy](https://docs.ntfy.sh/publish/) | your ntfy server (stays at home) or ntfy.sh | server URL, topic; optional access token or user + password |
| [Gotify](https://gotify.net/docs/pushmsg) | your Gotify server | server URL, application token |
| [Home Assistant](https://www.home-assistant.io/integrations/notify/) | your Home Assistant, then its companion app | HA URL, long-lived access token, notify service |
| Webhook (JSON) | any URL you control (n8n, Node-RED, your own script) | URL; optional HMAC secret |
| [Discord](https://support.discord.com/hc/en-us/articles/228383668) | Discord (a company) | channel webhook URL |
| [Slack](https://api.slack.com/messaging/webhooks) | Slack (a company) | incoming-webhook URL |
| [Telegram](https://core.telegram.org/bots/tutorial) | Telegram (a company) | bot token from @BotFather, chat id |
| [LINE](https://developers.line.biz/en/docs/messaging-api/sending-messages/) | LINE (a company) | Messaging API channel access token, user / group id |
| [Matrix](https://spec.matrix.org/latest/client-server-api/#sending-events-to-a-room) | your homeserver (or a public one) | homeserver URL, access token, room id |

Self-hosted services keep everything on your network when the server is at home. For the
hosted ones, the page shows a note: the text passes through that company's servers.

Setup hints:

- **ntfy**: anyone who knows a public topic name can read it. On ntfy.sh pick a long random
  topic, or use your own server with an access token.
- **Telegram**: create a bot with @BotFather, send it any message, then click **Find my chat
  id** in the editor. netwarden calls Telegram's `getUpdates` once, only on that click.
- **LINE**: LINE Notify ended in March 2025; netwarden uses the **Messaging API** push
  message. Create a Messaging API channel for a LINE Official Account, issue a channel access
  token, and use your user id (starts with `U`, shown in the LINE Developers console) or a
  group id. **Quota**: push messages count against the official account's monthly free
  message allowance, which depends on your country and plan (for example a few hundred
  messages a month on free plans in some regions); after that, messages are refused or
  charged. Check *LINE Official Account Manager > Plans* for your numbers. A text message is
  at most 5,000 characters; netwarden cuts longer text. Keep the rate limit low.
- **Matrix**: use a dedicated bot account; messages are sent as `m.notice` (plain text, not
  end-to-end encrypted by netwarden).
- **Home Assistant**: see [below](#home-assistant-why-a-url-and-a-token) for why a URL and a
  token. Click **List notify services** to pick `mobile_app_<your_phone>`.

## What is sent, and when

Per channel you choose:

- **Categories**: security (threats, open ports, UPnP, DNS blind spots), new / changed
  devices, family (night activity, bedtime rules), network health (outages, bandwidth
  spikes), home score drops (10 points or more from one day to the next), and the weekly
  digest. Default: security, devices, health.
- **Minimum severity** of alerts (critical / high / medium / low).
- **Messages per hour** (1-60, default 10). Anything above it goes out as **one** summary
  message ("12 more alerts") instead of many.
- **Daily digest**: one short message a day at the digest time (home score, open inbox items).
- **Message language**: the dashboard's language or its own (12 languages).

Alerts follow everything you set in the dashboard: an alert you **muted, snoozed,
acknowledged or tuned down** is not sent (and a queued one is dropped when you do it).
Each event is sent **once** per channel, also across restarts. When a channel is created or
turned on, what is already there is not news: only new events are sent.

**Quiet hours** (Settings > Quiet hours) hold notifications; at the end of the window they
go out as **one** "while you were asleep" message. Per channel, "Urgent security alerts
during quiet hours" (on by default) still lets critical / high security alerts through.

Settings that apply to every channel: **Digest time** (default 08:00 local time,
`NETWARDEN_NOTIFY_DIGEST_TIME`) and **Weekly digest day**.

The text is **never written by an AI**: it is the same sentence the dashboard and the
quiet-hours summary use, built the same way every time.

## Privacy levels

| Level | Example | Never contains |
|---|---|---|
| **Minimal** | "1 new alert: Security. Open the dashboard for details." | names, addresses, domains |
| **Standard** (default) | "Living room TV contacted a threat-list domain: 🟠 High risk" | MAC or IP addresses, raw domains (a threat says "High risk" / "Known malicious" instead) |
| **Detailed** | adds the device's IP and MAC address, the domain, a link to the device | - |

Even at minimal and standard, anything that looks like an IPv4 / IPv6 or MAC address is
masked, also inside a device name you typed. **Detailed** on a channel outside your private
network (any hosted service, or a public server) needs an explicit confirmation.

A link to the dashboard is added only when you have set an advertised URL
(`lan.advertised_url`, Settings > Phone access); otherwise messages carry no link.

## Secrets

Tokens, passwords, webhook URLs (they contain a credential) and HMAC secrets are
**write-only**: the page shows "set" / "not set", and you can replace or remove them, but
never read them back. They are never in an API answer, a log line (logs show scheme + host
only, e.g. `https://ntfy.sh`), an error text, an export, a report, a backup or the static
demo. **Backups do not contain notification channels**: after a restore, add them again.
A saved secret is only ever sent to the server it was entered for: if you change a
channel's address to another host (or port, or http/https), enter its token / password
again.

## Defining channels with environment variables

For Docker / headless installs, up to 9 channels can come from the environment. The page
shows them as "managed by environment" (read-only), and their secrets are never written to
the database. `<n>` is 1-9:

| Variable | Meaning |
|---|---|
| `NETWARDEN_NOTIFY_<n>_TYPE` | `ntfy`, `gotify`, `homeassistant`, `webhook`, `discord`, `slack`, `telegram`, `line`, `matrix` (required) |
| `NETWARDEN_NOTIFY_<n>_NAME` | shown name (default `env-<n>`) |
| `NETWARDEN_NOTIFY_<n>_URL` / `_TOPIC` / `_TOKEN` / `_USER` / `_PASSWORD` / `_SECRET` / `_SERVICE` / `_CHAT_ID` / `_TO` / `_ROOM` / `_PIN` | the fields of that type (see the table above) |
| `NETWARDEN_NOTIFY_<n>_LEVEL` | `minimal`, `standard` (default), `detailed` |
| `NETWARDEN_NOTIFY_<n>_CATEGORIES` | comma list of `security,devices,family,health,score,digest` |
| `NETWARDEN_NOTIFY_<n>_MIN_SEVERITY` | `critical`, `high`, `medium`, `low` (default) |
| `NETWARDEN_NOTIFY_<n>_RATE` | messages per hour (default 10) |
| `NETWARDEN_NOTIFY_<n>_DAILY` | `1` = daily digest |
| `NETWARDEN_NOTIFY_<n>_QUIET_BYPASS` | `0` = hold even urgent security alerts in quiet hours |
| `NETWARDEN_NOTIFY_<n>_LANG` | message language, e.g. `en`, `zh-Hant` |

An environment channel is enabled as soon as it is valid; an invalid one is skipped and
logged once (without values). Example:

```bash
NETWARDEN_NOTIFY_1_TYPE=ntfy
NETWARDEN_NOTIFY_1_URL=https://ntfy.example.org
NETWARDEN_NOTIFY_1_TOPIC=home-3f9c2a71
NETWARDEN_NOTIFY_1_TOKEN=tk_...
```

## The webhook format

`POST` with `Content-Type: application/json`, schema `netwarden.notification/1` (fields are
only ever added within version 1):

```json
{
  "schema": "netwarden.notification/1",
  "id": "nw-3b1f0c9a27d44e8a6b51",
  "kind": "alert",
  "category": "devices",
  "severity": "low",
  "title": "netwarden · New or unknown devices",
  "body": "New device: Living room TV",
  "url": null,
  "lang": "en",
  "level": "standard",
  "sent_at": "2026-10-21T12:00:00.000000Z",
  "count": 1
}
```

`kind` is `alert`, `score`, `weekly`, `daily`, `summary` (quiet hours), `bundle` (rate
limit) or `test`; `severity` is `critical`, `high`, `medium` or `low`; `count` is the number
of alerts in a summary / bundle. The id is stable for the same event (below the detailed
level it is a hash, so it never carries a device address).

With an HMAC secret, two headers are added:

```
X-Netwarden-Timestamp: 1792584000
X-Netwarden-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + raw body)>
```

Verify it on the receiving side (and reject old timestamps), for example in Python:

```python
import hashlib, hmac
expected = "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(expected, request_signature)
```

The secret is never part of the URL.

## Delivery and safety

- Messages wait in a queue in netwarden's database: it never blocks the dashboard or the
  alert loop and survives restarts. A background loop delivers every 15 seconds.
- Only `http://` and `https://`, no `user:password@` in a URL, a size limit, 8 seconds of
  timeout. Redirects are **never** followed (the server must answer at the address you
  entered).
- At most 3 retries for temporary problems (timeouts, connection errors, HTTP 429 / 5xx),
  after 30 s, 2 min and 10 min with random jitter; a `Retry-After` header is honoured (up to
  an hour). A wrong token or address (401 / 403 / 404) is not retried.
- TLS certificates are always verified. For a self-hosted server with a **self-signed
  certificate**, enter its SHA-256 fingerprint as the pinned certificate; the certificate
  must then be exactly that one, checked before anything is sent. There is no switch to
  turn verification off. To get the fingerprint:
  `openssl s_client -connect host:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256`
- Each channel keeps a **delivery log** (time, what, delivered or an error class); the last
  error is shown in Settings in plain language with the next step.
- The demo home never sends anything (its example channels point at `.invalid` hosts).

## Home Assistant: why a URL and a token

As the Home Assistant add-on, netwarden could call notify services through the Supervisor
proxy, but only with `homeassistant_api: true`, which gives the add-on access to the whole
Home Assistant Core API and lowers the add-on's security rating. netwarden keeps that
permission **off**. Instead you enter your HA URL (e.g. `http://homeassistant.local:8123`)
and a **long-lived access token** (your HA profile > Security). Create a dedicated HA user
for it if you want to limit what the token can do; netwarden only calls
`GET /api/services` (on your click) and `POST /api/services/notify/<service>`.

## Command line

```bash
python3 -m netwarden notify list                  # channels, state, last delivery
python3 -m netwarden notify test "Phone"          # ONE test message
python3 -m netwarden notify send-digest [--daily] # queue a digest now and deliver it
```

The weekly `python3 -m netwarden alerts` (cron) prints the digest as before and never sends
notifications.

## Troubleshooting

| You see | What to do |
|---|---|
| "did not accept the token" (401) | create a new token, paste it, save |
| "refused access" (403) | the token may not post there (ntfy ACL, Gotify app, Slack channel) |
| "not found" (404) | the webhook was deleted or the URL is mistyped |
| "asks us to slow down" (429) | lower messages per hour; netwarden retries by itself |
| "answered with a redirect" | enter the final address (often `https://` instead of `http://`) |
| "certificate could not be verified" | self-signed: enter the pinned fingerprint |
| "does not match the pinned fingerprint" | you renewed the certificate: enter the new fingerprint |
| nothing arrives, no error | is the channel turned on? the category and minimum severity chosen? quiet hours? |
