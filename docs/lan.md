# Open the dashboard on your phone (LAN mode + pairing)

Off by default. With it off, netwarden listens on 127.0.0.1 only and behaves exactly
as before (no sessions, no cookies).

## Turning it on

```bash
python3 -m netwarden run --lan                 # also listen on this computer's LAN address
python3 -m netwarden run --lan --lan-host 192.168.1.13   # pick the address (must be private)
python3 -m netwarden run --lan --bind-all      # 0.0.0.0 instead (extra explicit flag)
python3 -m netwarden web --lan ...             # same flags on the dashboard-only CLI
```

Or the setting `lan.enabled` (System -> "Open on your phone" switch, env
`NETWARDEN_LAN`), read at the NEXT start (`web.lan_wanted`). `web.make_server(lan=True)`
keeps the loopback listener and adds a second ThreadingHTTPServer on the LAN address in a
daemon thread (`srv.extra`; always close with `web.close_server(srv)`). A public or
loopback `--lan-host` is refused (`web.LanError`, `pairing.is_lan_ip`: RFC 1918 +
link-local IPv4 only). The address is detected with a UDP `connect()` toward a private
address (no packet is sent).

## Who may do what (`web.Handler._auth`)

| client | needs | may |
|---|---|---|
| loopback | nothing (unless `NETWARDEN_REQUIRE_AUTH=1`) | everything |
| loopback + REQUIRE_AUTH | a session | everything |
| another device | a session | view, ack/mute, trust, labels/profile, bedtime, suggestions, chat, exports |
| another device | an ADMIN session (round 6) | everything |

Admin = `Handler.admin`: loopback (this computer's own browser), or a session redeemed
from an ADMIN code (`ADMIN_POSTS` / `ADMIN_GETS`, plus `_local_client()` in the
handlers): GET/POST `/api/settings`, `/api/ai/test`, `/api/check`,
`/api/pair/new|revoke|revoke_all`, GET `/api/pair/sessions`, backup/restore, setup.
An ordinary paired phone gets 403 there. `/api/meta`: `admin`, `admin_session` (an admin
on another device) and `remote` = NOT admin (the page hides admin actions on it).

### Admin sessions (headless installs, round 6)

A Pi / NAS / container has no browser of its own. `python3 -m netwarden pair --admin`
(a shell on the box, `docker exec netwarden netwarden pair --admin`) makes an admin
code: same format, same `/pair` page, 15 minutes (`pairing.ADMIN_CODE_TTL`), single use,
stored hashed, the same per-address + global rate limit. The session it opens is flagged
`sessions.admin = 1`, shows an **Admin** badge in the paired-devices list and
`pair --list`, and is revoked like any other (list, `pair --revoke ID` / `--revoke-all`).
Codes appear only on a terminal / stdout - never in an HTTP answer or the log file.

With `NETWARDEN_HEADLESS=1` (the image, the systemd unit) a start in LAN mode prints ONE
admin code to stdout while the install is unclaimed (`headless.claim_lines`); redeeming
any admin code sets meta `admin_claimed=1` and later starts print nothing.

The trade-off, said plainly: admin over plain HTTP means the session cookie crosses the
LAN unencrypted. Use it on a trusted home network only, revoke the admin session when
you are done, prefer this computer's browser or an SSH tunnel
(`ssh -L 8787:127.0.0.1:8787 box`, then http://127.0.0.1:8787 is loopback = admin), and
never expose netwarden to the internet.

Advertised URL (`lan.advertised_url` / `NETWARDEN_ADVERTISED_URL`, LAN mode only, read at
start): replaces the detected LAN address in the pairing QR and is answered as an extra
Host / Origin (Docker bridge networking, a reverse proxy). Once it adds a host
(`Handler.proxy_hosts`), NO loopback client is "this computer": a reverse proxy on the
same machine connects from loopback and may pass a visitor's forged `Host: 127.0.0.1`
through, so every browser needs a session (`pair --admin` for admin). A loopback request
with a forwarding header (`web.FORWARDED_HEADERS`) is another device in every mode.
Public without a session: `/pair`, POST `/api/pair`, `/favicon.ico`, and
`PUBLIC_STATIC` (app.css, pair.js, icon.svg, manifest, PNG icons). Pages without a
session -> 303 `/pair`; API -> 401 `{error, pair: true}` (app.js `needPair()` goes to /pair).
"Is this request local?" is `Handler.is_local_client` - injectable, which is how tests
(and manual checks) play a phone without binding a LAN address.

Host allowlist: loopback names + `Handler.lan_hosts` (exactly `<lan-ip>:<port>`, only in
LAN mode). POST: an Origin, if present, must match; from another device it is REQUIRED.
Every response (JSON, pages, files, 3xx/4xx/5xx) gets `SECURITY_HEADERS` in
`Handler.end_headers` (CSP with `frame-ancestors 'none'` + `manifest-src 'self'`,
X-Frame-Options, nosniff, Referrer-Policy no-referrer, COOP/CORP same-origin,
Permissions-Policy).

## Pairing (`netwarden/pairing.py`)

- Code: 10 chars from `CODE_ALPHABET` (no 0/O/1/I/L/U, ~49 bits), 10 min, single use
  (atomic `UPDATE ... WHERE used_at IS NULL`), at most 5 open, SHA-256 hash stored
  (`pair_codes`). Shown as `ABCDE-FGHJK`; case/space/dash-insensitive.
- QR of `http://<lan-ip>:<port>/pair#<code>`: the code is in the FRAGMENT only (never in
  a request line or a log). pair.js removes it from the address bar and POSTs JSON.
- Session: `secrets.token_urlsafe(32)`, hash stored (`sessions`), cookie `nw_session`
  `HttpOnly; SameSite=Strict; Path=/; Max-Age=30 d` (no `Secure`: plain HTTP). Sliding
  expiry: a session used >= 5 min after its last write gets +30 days and a re-sent cookie.
  Label = the user agent (hostile text; `device_label()` -> "iPhone · Safari").
  Max 50 (least recently used dropped). Expired rows go in `store.prune`.
- Wrong codes: `pairing.Limiter` (in memory): 5 misses / 15 min per address -> 15 min
  lockout (429 + `retry_after`, even for a right code); 30 misses from all addresses ->
  everyone waits. Secrets compared with `hmac.compare_digest`. Logs say "paired a new
  browser (session N)" - never a code or token.

CLI: `python3 -m netwarden pair [--local | --lan-host IP] [--port N] [--invert]` prints
the QR (Unicode half blocks, `qr.terminal`), URL and code; `--list`, `--revoke ID`,
`--revoke-all`. `--local` = 127.0.0.1 URL, for `NETWARDEN_REQUIRE_AUTH=1` (shared PCs).

`--local` prints no QR: a phone cannot open 127.0.0.1. Instead it says the code is for
another browser on this computer (`cli.pair.local_code`).

## WSL: the Hyper-V firewall (Stage V3)

Under WSL 2, Windows' Hyper-V firewall drops inbound LAN connections, so a phone cannot
reach `--lan`. `wslnet.is_wsl()` checks `/proc/version` for "microsoft". When it matches,
`run --lan`, `pair` and the pairing card (`/api/pair/sessions` -> `wsl_firewall`) show
the administrator PowerShell commands, built only from the int port and a validated
private subnet:

    New-NetFirewallHyperVRule -Name "netwarden-lan-8787" -DisplayName "netwarden (port 8787)" -Direction Inbound -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol TCP -LocalPorts 8787 -RemoteAddresses 192.168.1.0/24
    Remove-NetFirewallHyperVRule -Name "netwarden-lan-8787"

The syntax was checked against learn.microsoft.com: the WSL networking page (the
VMCreatorId) and the Hyper-V firewall cmdlet reference (`-RemoteAddresses` takes
`1.2.3.4/24`). netwarden never runs these commands. The page shows them in read-only
text areas with Copy buttons, inside a collapsible box that keeps its open state across
refreshes.

QR: `netwarden/vendor/qrcodegen.py` = nayuki/QR-Code-generator python (MIT), unchanged
below a 4-line provenance note (sha256 pinned in tests); `netwarden/qr.py` renders SVG
(served as a `data:` URI in an `<img>`) and terminal output. tests/test_stage_m.py has an
independent decoder (format BCH, masks, zigzag, de-interleave) that round-trips it.

## Phone experience

Bottom nav (4 + "More"), 52 px nav targets, 40 px buttons/inputs, 16 px inputs (no iOS
zoom), safe-area insets top/left/right/bottom, `overflow-x: clip`, no tap delay.
`static/manifest.webmanifest` (standalone) + `apple-touch-icon.png` / `icon-192/512.png`
(drawn by `scripts/make_icons.py`, stdlib rasterizer of icon.svg). On a paired phone the
System page shows "Connected from another device" + Sign out; AI settings, probe form
and port-check buttons are hidden/disabled (`S.meta.remote`).

Demo: two display-only phones (`demo._seed_sessions`, token_hash `demo:N` never matches
a cookie); a revoked one stays revoked across rebuilds.
