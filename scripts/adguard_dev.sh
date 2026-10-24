#!/usr/bin/env bash
# netwarden - dev AdGuard Home instance (the "Watch" data source)
#
# Runs AdGuard Home unprivileged inside WSL:
#   DNS    : 0.0.0.0:5354   (high port, no root; 5353 is taken by Windows mDNS
#                            because WSL mirrored networking shares ports with Windows)
#   Web/API: 127.0.0.1:3000 (local only)
#
#   scripts/adguard_dev.sh setup    first run: start, finish the install wizard via API,
#                                   write credentials to .env, point upstream at the router
#   scripts/adguard_dev.sh start | stop | status
#
# Binary  : ~/.local/opt/AdGuardHome/AdGuardHome (download + checksum: see README)
# Work dir: ~/.local/share/netwarden/adguard     (config, query log, stats)
set -euo pipefail

BIN="${ADGUARD_BIN:-$HOME/.local/opt/AdGuardHome/AdGuardHome}"
WORK="${ADGUARD_WORK:-$HOME/.local/share/netwarden/adguard}"
WEB_ADDR="127.0.0.1:3000"
DNS_PORT=5354
UPSTREAM="${ADGUARD_UPSTREAM:-192.168.1.1}"   # the router: same resolver devices use today
PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$PROJECT/.env"
PIDFILE="$WORK/AdGuardHome.pid"

running() { [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

start() {
    if running; then echo "AdGuard Home already running (pid $(cat "$PIDFILE"))"; return; fi
    mkdir -p "$WORK"
    setsid nohup "$BIN" -w "$WORK" --web-addr "$WEB_ADDR" --no-check-update \
        --pidfile "$PIDFILE" -l "$WORK/AdGuardHome.log" </dev/null >/dev/null 2>&1 &
    local pid=$!
    for _ in $(seq 1 25); do
        if curl -s -m 1 -o /dev/null "http://$WEB_ADDR/"; then
            echo "AdGuard Home started: web http://$WEB_ADDR  dns :$DNS_PORT  (log: $WORK/AdGuardHome.log)"
            return
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.2
    done
    echo "AdGuard Home failed to start - see $WORK/AdGuardHome.log" >&2
    tail -5 "$WORK/AdGuardHome.log" >&2
    return 1
}

stop() {
    if running; then kill "$(cat "$PIDFILE")"; echo "stopped"; else echo "not running"; fi
}

status() {
    if running; then echo "running (pid $(cat "$PIDFILE"))"; else echo "not running"; fi
}

setup() {
    if [[ -f "$WORK/AdGuardHome.yaml" ]]; then
        echo "already configured ($WORK/AdGuardHome.yaml) - use start/stop"; start; return
    fi
    # AdGuard's install wizard refuses to run without root, so we skip it by writing
    # the config ourselves. Fields we leave out keep AdGuard's built-in defaults.
    local user=netwarden pass hash
    pass="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
    hash="$(uv run -q --no-project --with bcrypt python3 -c \
        'import bcrypt, sys; print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())' "$pass")"
    mkdir -p "$WORK"
    cat > "$WORK/AdGuardHome.yaml" <<EOF
http:
  address: $WEB_ADDR
users:
  - name: $user
    password: $hash
dns:
  bind_hosts:
    - 0.0.0.0
  port: $DNS_PORT
  upstream_dns:
    - $UPSTREAM
querylog:
  enabled: true
  file_enabled: true
  interval: 2160h
schema_version: 34
EOF
    chmod 600 "$WORK/AdGuardHome.yaml"
    # Record the dev credentials for dns_ingest (.env is gitignored).
    touch "$ENV_FILE"
    sed -i '/^ADGUARD_\(URL\|USER\|PASS\)=/d' "$ENV_FILE"
    printf 'ADGUARD_URL=http://%s\nADGUARD_USER=%s\nADGUARD_PASS=%s\n' "$WEB_ADDR" "$user" "$pass" >> "$ENV_FILE"
    echo "configured: credentials written to $ENV_FILE, upstream DNS = $UPSTREAM"
    start
}

case "${1:-}" in
    setup) setup ;;
    start) start ;;
    stop) stop ;;
    status) status ;;
    *) echo "usage: $0 setup|start|stop|status" >&2; exit 2 ;;
esac
