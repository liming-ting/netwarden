#!/bin/sh
# netwarden - install / uninstall as a systemd service on Linux (Debian, Ubuntu,
# Raspberry Pi OS, ...), without Docker. Run it from a source checkout:
#
#   sudo sh scripts/install_linux.sh               install or upgrade, start the service
#   sh scripts/install_linux.sh --dry-run          print every action, change nothing
#   sudo sh scripts/install_linux.sh --uninstall   remove it; KEEPS the data
#   sudo sh scripts/install_linux.sh --uninstall --purge   ... and deletes the data too
#   sh scripts/install_linux.sh --root /tmp/fake   install into a fake root (tests): no
#                                                  user, no chown, no systemctl
#
# What it puts where:
#   /opt/netwarden/app/netwarden   the code (replaced on upgrade)
#   /var/lib/netwarden             the database + caches (owned by the netwarden user)
#   /etc/netwarden/netwarden.env   your settings (created once, never overwritten)
#   /usr/local/bin/netwarden       `netwarden pair --admin`, `netwarden status`, ...
#   /etc/systemd/system/netwarden.service   a hardened unit, Restart=on-failure
#
# Read-only toward your network: it installs no packages, opens no firewall ports and
# changes nothing on your router or DNS filter. Needs python3 >= 3.11, `ip` and `ping`.
set -eu

ROOT=""
DRY=0
MODE=install
PURGE=0
PYTHON=${PYTHON:-/usr/bin/python3}

usage() {
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1 ;;
        --uninstall) MODE=uninstall ;;
        --purge) PURGE=1 ;;
        --root) [ $# -ge 2 ] || { echo "--root needs a directory" >&2; exit 2; }
                ROOT=${2%/}; shift ;;
        --root=*) ROOT=${1#--root=}; ROOT=${ROOT%/} ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done
if [ "$PURGE" = 1 ] && [ "$MODE" != uninstall ]; then
    echo "--purge only goes with --uninstall" >&2; exit 2
fi
case "$ROOT" in
    ""|/*) ;;
    *) echo "--root must be an absolute path" >&2; exit 2 ;;
esac

SRC=$(cd "$(dirname "$0")/.." && pwd)
APP=/opt/netwarden
DATA=/var/lib/netwarden
CONF=/etc/netwarden
UNIT=/etc/systemd/system/netwarden.service
BIN=/usr/local/bin/netwarden
USER_NAME=netwarden

# A real system (not a fake root) needs root, unless we only print.
REAL=0
if [ -z "$ROOT" ]; then REAL=1; fi
if [ "$REAL" = 1 ] && [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then
    echo "Run as root (sudo), or try --dry-run first." >&2; exit 1
fi

say() { printf '%s\n' "$*"; }
run() {  # print the action; do it unless --dry-run
    say "+ $*"
    [ "$DRY" = 1 ] || "$@"
}
write_file() {  # write_file PATH MODE  (content on stdin)
    say "+ write $1 (mode $2)"
    if [ "$DRY" = 1 ]; then cat >/dev/null; return; fi
    cat > "$1.tmp.$$" && chmod "$2" "$1.tmp.$$" && mv "$1.tmp.$$" "$1"
}

unit_text() {
    cat <<EOF
[Unit]
Description=netwarden - explains your home network in plain language
Documentation=https://github.com/liming-ting/netwarden/blob/main/docs/install.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER_NAME
Group=$USER_NAME
WorkingDirectory=$DATA
Environment=PYTHONPATH=$APP/app
Environment=NETWARDEN_DB=$DATA/netwarden.db
Environment=NETWARDEN_HEADLESS=1
Environment=NETWARDEN_LAN=1
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
# your settings; they override the lines above
EnvironmentFile=-$CONF/netwarden.env
ExecStart=$PYTHON -m netwarden run
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
KillSignal=SIGTERM

# Hardening: an unprivileged user that can write only its data directory. No
# capabilities: ping uses unprivileged ICMP sockets (net.ipv4.ping_group_range), and
# netwarden falls back to TCP probes where that is not allowed.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
# AF_NETLINK: "ip route" / "ip neigh"
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
ReadWritePaths=$DATA
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
}

# The CLI wrapper is Python, not sh: it reads the env file the way systemd's
# EnvironmentFile= does (values taken literally - a password with spaces, quotes, a
# dollar sign or a backtick is never expanded or run by a shell), so the CLI uses exactly
# the settings the service uses. Paths carry $ROOT so a fake-root install is testable.
wrapper_text() {
    cat <<EOF
#!$PYTHON
# netwarden CLI (installed by scripts/install_linux.sh): same database and settings as
# the service. Run admin commands as the service user, e.g.
#   sudo -u $USER_NAME netwarden pair --admin
import os
import sys

APP_DIR = "$ROOT$APP/app"
ENV_FILE = "$ROOT$CONF/netwarden.env"
DEFAULT_DB = "$DATA/netwarden.db"


def read_env_file(path):
    """KEY=VALUE lines like systemd's EnvironmentFile=: comments (# ;) and blank lines
    skipped, one pair of matching outer quotes removed, nothing else interpreted."""
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if not line or line[0] in "#;" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if key.replace("_", "a").isalnum() and not key[0].isdigit():
            out[key] = value
    return out


def main():
    os.environ.update(read_env_file(ENV_FILE))      # the file wins, as for the service
    os.environ.setdefault("NETWARDEN_DB", DEFAULT_DB)
    sys.path.insert(0, APP_DIR)
    from netwarden.__main__ import main as netwarden_main
    return netwarden_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
EOF
}

env_text() {
    cat <<EOF
# netwarden settings (read by the service and by $BIN). Every line is optional;
# see docs/install.md. Keep this file private: it may hold passwords and API keys.
# After a change:  sudo systemctl restart netwarden
#
#ADGUARD_URL=http://127.0.0.1:80
#ADGUARD_USER=admin
#ADGUARD_PASS=change-me
#NETWARDEN_DNS_SOURCE=pihole
#PIHOLE_URL=http://192.168.1.3
#PIHOLE_PASSWORD=change-me
#ANTHROPIC_API_KEY=sk-ant-...
#NETWARDEN_LANG=en
#NETWARDEN_PORT=8787
# The service listens on 127.0.0.1 and this machine's LAN address (NETWARDEN_LAN=1);
# other devices must pair. NETWARDEN_LAN=0 = this machine only (use an SSH tunnel).
#NETWARDEN_LAN=0
EOF
}

have_systemctl() { [ "$REAL" = 1 ] && command -v systemctl >/dev/null 2>&1; }

do_install() {
    "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null || {
        echo "netwarden needs $PYTHON >= 3.11 (set PYTHON=/path/to/python3 to pick another)" >&2
        exit 1; }
    [ -f "$SRC/netwarden/__main__.py" ] || { echo "run this from a netwarden checkout" >&2; exit 1; }
    for tool in ip ping; do
        command -v "$tool" >/dev/null 2>&1 || say "note: '$tool' not found - discovery will see less (Debian: apt install iproute2 iputils-ping)"
    done
    say "Installing netwarden from $SRC into ${ROOT:-/}"
    if [ "$REAL" = 1 ]; then
        if id "$USER_NAME" >/dev/null 2>&1; then
            say "  user $USER_NAME exists"
        else
            run useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
        fi
    fi
    if have_systemctl && systemctl is-active --quiet netwarden 2>/dev/null; then
        run systemctl stop netwarden   # upgrade: stop before the code is replaced
    fi
    run mkdir -p "$ROOT$APP/app" "$ROOT$DATA" "$ROOT$CONF" "$ROOT$(dirname "$UNIT")" "$ROOT$(dirname "$BIN")"
    run rm -rf "$ROOT$APP/app/netwarden"
    run cp -R "$SRC/netwarden" "$ROOT$APP/app/netwarden"
    run find "$ROOT$APP/app/netwarden" -name __pycache__ -type d -prune -exec rm -rf {} +
    run chmod -R u=rwX,go=rX "$ROOT$APP"
    if [ "$REAL" = 1 ]; then
        run chown "$USER_NAME:$USER_NAME" "$ROOT$DATA"
    fi
    run chmod 0750 "$ROOT$DATA"
    if [ -e "$ROOT$CONF/netwarden.env" ]; then
        say "  keeping $CONF/netwarden.env (your settings)"
    else
        env_text | write_file "$ROOT$CONF/netwarden.env" 0640
        if [ "$REAL" = 1 ]; then
            run chgrp "$USER_NAME" "$ROOT$CONF/netwarden.env"
        fi
    fi
    wrapper_text | write_file "$ROOT$BIN" 0755
    unit_text | write_file "$ROOT$UNIT" 0644
    if have_systemctl; then
        run systemctl daemon-reload
        run systemctl enable --now netwarden
        say ""
        if [ "$DRY" = 1 ]; then
            say "Dry run done: nothing was installed or started. Run it again with sudo and"
            say "without --dry-run to install."
            return
        fi
        say "Started. The one-time admin code for your browser is in the service log:"
        say "  journalctl -u netwarden -b | grep -A8 '====='"
        say "A new one at any time:  sudo -u $USER_NAME $BIN pair --admin"
    else
        say "(no systemctl here: service not started)"
    fi
    if [ "$DRY" = 1 ]; then say "Dry run done: nothing was changed."; else say "Done."; fi
}

do_uninstall() {
    say "Removing netwarden from ${ROOT:-/}"
    if have_systemctl; then
        run systemctl disable --now netwarden || true
    fi
    run rm -f "$ROOT$UNIT" "$ROOT$BIN"
    if have_systemctl; then
        run systemctl daemon-reload
    fi
    run rm -rf "$ROOT$APP"
    if [ "$PURGE" = 1 ]; then
        run rm -rf "$ROOT$DATA" "$ROOT$CONF"
        if [ "$REAL" = 1 ] && id "$USER_NAME" >/dev/null 2>&1; then
            run userdel "$USER_NAME"
        fi
    else
        say "Kept your data in $DATA and settings in $CONF (--purge deletes them)."
    fi
    if [ "$DRY" = 1 ]; then say "Dry run done: nothing was changed."; else say "Done."; fi
}

if [ "$DRY" = 1 ]; then say "(dry run: nothing is changed)"; fi
if [ "$MODE" = uninstall ]; then do_uninstall; else do_install; fi
