#!/usr/bin/env bash
# netwarden - start everything inside WSL (or any Linux box on the LAN):
#   1. the dev AdGuard Home, if it is installed + set up and not running yet
#      (skipped for --demo, which needs no live data source);
#   2. `python3 -m netwarden run "$@"` - dashboard + background loops, one process.
#
#   bash scripts/start.sh                 # real data, http://127.0.0.1:8787
#   bash scripts/start.sh --demo --port 8788
#
# Ctrl+C stops netwarden (AdGuard keeps running; bash scripts/adguard_dev.sh stop).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

ADGUARD_BIN="${ADGUARD_BIN:-$HOME/.local/opt/AdGuardHome/AdGuardHome}"
ADGUARD_WORK="${ADGUARD_WORK:-$HOME/.local/share/netwarden/adguard}"

if [[ " $* " != *" --demo "* && -x "$ADGUARD_BIN" && -f "$ADGUARD_WORK/AdGuardHome.yaml" ]]; then
    if ! bash scripts/adguard_dev.sh status | grep -q '^running'; then
        bash scripts/adguard_dev.sh start || echo "AdGuard Home did not start - continuing without it" >&2
    fi
fi

exec python3 -m netwarden run "$@"
