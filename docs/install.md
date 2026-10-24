# Installing netwarden

[繁體中文](install.zh-TW.md)

netwarden is one Python program (standard library only, no runtime dependencies) with a
web dashboard. It reads what your DNS filter (AdGuard Home or Pi-hole v6) already logs,
looks at your LAN, and explains it. It is **read-only toward your network**: it never
changes your router, firewall, AdGuard Home or Pi-hole settings.

Pick one:

| you have | use | sees the LAN? |
|---|---|---|
| a Linux box / Raspberry Pi / NAS with Docker | [Docker compose](#docker) with host networking | yes |
| Docker Desktop on Windows / macOS | [bridge compose](#docker-desktop-windows--macos) | no (DNS + AI + dashboard work) |
| a Linux box / Raspberry Pi without Docker | [the systemd installer](#linux--raspberry-pi-without-docker) | yes |
| a desktop for development / trying it | [from a checkout](#from-a-checkout-pip-pipx-development) | yes on Linux; little under WSL |

Honest limits for v0.1.0: discovery under WSL2 or Docker Desktop sees few or no devices
(they run in a VM); device names depend on what your devices announce; the AI part needs
an API key or a local model (without one you get an offline rule-based summary);
translations other than English and Traditional Chinese are machine-assisted. The project
was built with heavy AI assistance and is covered by a large automated test suite.

## Docker

Linux host, host networking (needed for discovery: ARP table, ping, mDNS/SSDP, UPnP).

```bash
git clone https://github.com/liming-ting/netwarden netwarden && cd netwarden
cp deploy/netwarden.env.example deploy/netwarden.env     # fill in AdGuard / Pi-hole
chmod 600 deploy/netwarden.env
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml logs netwarden     # the one-time admin code
```

Or without compose:

```bash
docker run -d --name netwarden --network host --restart unless-stopped --init \
  -e NETWARDEN_HOST=127.0.0.1 -e NETWARDEN_LAN=1 \
  --env-file deploy/netwarden.env -v netwarden-data:/data ghcr.io/liming-ting/netwarden:latest
```

With host networking always set `NETWARDEN_HOST=127.0.0.1` + `NETWARDEN_LAN=1` as above:
the image's default `0.0.0.0` would listen on **every** host interface (VPN or public
ones too) and put the pairing page beyond your LAN.

`deploy/compose.adguard.yaml` runs AdGuard Home (the official `adguard/adguardhome`
image) next to netwarden. Pointing your devices (or your router's DHCP DNS setting) at it
is a step you take yourself when you are ready.

### The image

- `python:3.12-slim-bookworm` + `iproute2`, `iputils-ping`, `tzdata`; no compiler.
- Runs as the unprivileged user `netwarden` (uid 10001); everything lives in the
  `/data` volume (database, caches). Port 8787.
- `HEALTHCHECK` calls `GET /healthz` (public, constant, touches no data).
- `docker stop` (SIGTERM) shuts down cleanly in about a second, also as PID 1.
- Logs go to stdout/stderr (`docker logs`), not to a file.
- Multi-arch: linux/amd64, linux/arm64, linux/arm/v7.

### Settings (environment)

Everything from `.env` works as environment variables (see
`deploy/netwarden.env.example`). Container-specific:

| variable | default in the image | meaning |
|---|---|---|
| `NETWARDEN_DB` | `/data/netwarden.db` | the database file (its folder holds caches too) |
| `NETWARDEN_HOST` | `0.0.0.0` | `127.0.0.1` = this machine only; a private LAN address or `0.0.0.0` = LAN mode (other devices must pair). Public addresses and names are refused. |
| `NETWARDEN_LAN` | – | `1` = also listen on the detected LAN address (use with `NETWARDEN_HOST=127.0.0.1` on host networking) |
| `NETWARDEN_PORT` | `8787` | the port |
| `NETWARDEN_ADVERTISED_URL` | – | the address phones should open when the detected one is wrong (bridge networking, reverse proxy), e.g. `http://192.168.1.20:8787` |
| `NETWARDEN_HEADLESS` | `1` | logs to stderr; prints one admin code until the install is claimed |

`ping` without root: Docker lets containers use unprivileged ICMP sockets; on hosts that
don't, netwarden falls back to TCP probes. `cap_add: [NET_RAW]` is optional, never required.

### Docker Desktop (Windows / macOS)

Containers run inside a VM, so netwarden cannot see your LAN (no discovery, no device
names from mDNS/SSDP, no router UPnP). What still works: DNS ingestion from AdGuard Home
or Pi-hole, the AI explanations, alerts and the dashboard. Use
`deploy/compose.bridge.yaml` and set `NETWARDEN_ADVERTISED_URL` (on this computer,
`http://localhost:8787`).

### Port 53 and systemd-resolved

On Ubuntu / Debian, `systemd-resolved` listens on 127.0.0.53:53 and AdGuard Home (or
Pi-hole) on the host network fails with "address already in use". By hand:

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

netwarden itself does not need port 53 (it only reads the DNS filter's log).

## Claim a headless install (admin from your browser)

On the machine itself, a browser at http://127.0.0.1:8787 is always admin. A Pi, NAS or
container has no such browser, so on its **first start** in LAN mode netwarden prints one
admin code to its log:

```
========================================================================
Claim this netwarden: sign in as admin from a browser on your home network

  Open http://192.168.1.20:8787/pair (or the address you use to reach this box, ...) and type the code ABCDE-FGHJK
  ...
  Works once, for 15 minutes (until 2026-01-01 12:15 UTC).
========================================================================
```

Read it with `docker logs netwarden` or `journalctl -u netwarden`, open `/pair` from a
browser on your LAN and type the code. That browser gets an **admin session** (badge
"Admin" under System -> Open on your phone). Once an admin code has been used, later
starts never print one again. A new code at any time, from a shell on the box:

```bash
docker exec netwarden netwarden pair --admin           # Docker
sudo -u netwarden netwarden pair --admin               # systemd install
python3 -m netwarden pair --admin                      # from a checkout
```

Ordinary phones (paired with a normal code, `netwarden pair`) can look, label, mute and
chat, but cannot change settings, pair devices or run port checks.

**The trade-off:** the dashboard speaks plain HTTP on your LAN, so an admin session's
cookie crosses the network unencrypted. Use admin over the LAN only on a home network
you trust, revoke the admin session when you are done (`netwarden pair --list`,
`--revoke ID`, or Revoke in the list), prefer an SSH tunnel
(`ssh -L 8787:127.0.0.1:8787 user@box`, then open http://127.0.0.1:8787 on your
computer), and **never expose netwarden to the internet** (no port forward on the router).

Reverse proxy: set `NETWARDEN_ADVERTISED_URL` to the proxy's address. A proxy connects
from 127.0.0.1 and may pass on whatever Host header a visitor sends, so once an
advertised URL is set **no browser counts as "this computer"** - every browser,
including one on the box itself, signs in (`netwarden pair --admin` for admin). A
loopback request carrying `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP` or
`Forwarded` is always treated as another device.

## Linux / Raspberry Pi without Docker

Needs `python3` >= 3.11 (Raspberry Pi OS bookworm and Ubuntu 24.04 have it), `ip` and
`ping` (`apt install iproute2 iputils-ping`). From a checkout:

```bash
sh scripts/install_linux.sh --dry-run      # shows every action, changes nothing
sudo sh scripts/install_linux.sh           # install + start the service
sudo nano /etc/netwarden/netwarden.env     # AdGuard / Pi-hole / AI key, then:
sudo systemctl restart netwarden
journalctl -u netwarden -b | grep -A8 '====='   # the one-time admin code
```

It installs the code to `/opt/netwarden/app`, data to `/var/lib/netwarden` (a dedicated
system user `netwarden`), settings to `/etc/netwarden/netwarden.env` (created once, never
overwritten), a `netwarden` command to `/usr/local/bin`, and a hardened unit
`netwarden.service` (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, no capabilities, only `/var/lib/netwarden` writable,
`Restart=on-failure`). The service listens on 127.0.0.1 and the LAN address
(`NETWARDEN_LAN=1`); set `NETWARDEN_LAN=0` in the env file for "this machine only" plus an
SSH tunnel.

## From a checkout (pip, pipx, development)

```bash
git clone https://github.com/liming-ting/netwarden netwarden && cd netwarden
python3 -m netwarden run --demo --offline-ai    # try it: a made-up home, no AI calls
python3 -m netwarden run                        # your network: http://127.0.0.1:8787
pipx install .                                  # or: pip install .  -> `netwarden run`
```

From a checkout the data lives in `./data`; an installed package uses
`~/.local/share/netwarden` (or `$XDG_DATA_HOME/netwarden`, `NETWARDEN_DATA_DIR`,
`NETWARDEN_DB`). `python3 -m netwarden --version` prints the version.

Commands print Traditional Chinese (zh-Hant) by default. Set `NETWARDEN_LANG=en` (or another
code from docs/home_assistant.md's language list) in `.env`, or pass `--lang en` to a single
command, e.g. `python3 -m netwarden scan --lang en`. The dashboard has its own language menu.

**Windows (development):** run it inside WSL2 (`scripts\start_windows.cmd`). With
mirrored networking WSL sees only part of the LAN; phones need a Windows firewall rule
that the dashboard shows you (docs/lan.md).

## Upgrade

- Docker: `docker compose -f deploy/compose.yaml pull && docker compose -f deploy/compose.yaml up -d`
  (the database migrates itself on start).
- systemd: update the checkout, `sudo sh scripts/install_linux.sh` again (keeps data and settings).
- pip / pipx: `pipx upgrade netwarden` / `pip install --upgrade .`.

## Backup and restore

Your own notes (names, owners, trust, rules, settings - no secrets, no phone sessions):

```bash
docker exec netwarden netwarden backup -o - > netwarden-backup.json
docker exec -i netwarden sh -c 'cat > /data/restore.json' < netwarden-backup.json
docker exec netwarden netwarden restore /data/restore.json --dry-run
```

Everything (including history): stop the container and copy the `/data` volume, e.g.
`docker run --rm -v netwarden-data:/data -v "$PWD":/out busybox tar czf /out/netwarden-data.tgz -C /data .`
For the systemd install: `sudo systemctl stop netwarden` and copy `/var/lib/netwarden`.

## Uninstall

- Docker: `docker compose -f deploy/compose.yaml down` (add `-v` to delete the data volume).
- systemd: `sudo sh scripts/install_linux.sh --uninstall` (keeps `/var/lib/netwarden` and
  `/etc/netwarden`; `--purge` deletes them and the user too).
- pip / pipx: `pipx uninstall netwarden`; the data stays in `~/.local/share/netwarden`.
