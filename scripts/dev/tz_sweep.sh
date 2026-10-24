#!/usr/bin/env bash
# Run the unit tests under several time zones (developer helper; CI runs the suite under
# UTC and Asia/Taipei on every push, and the time-sensitive modules under the two zones
# below that are furthest from both - the "time zones" job calls this script).
#
#   bash scripts/dev/tz_sweep.sh                       # the default zones, full suite
#   bash scripts/dev/tz_sweep.sh Europe/Berlin UTC     # only these zones
#   TESTS="tests.test_cli tests.test_stage_q" bash scripts/dev/tz_sweep.sh   # only these modules
#
# Each run sets TZ (what CI and the C library use) AND NETWARDEN_TZ: a local .env that pins
# NETWARDEN_TZ would otherwise win over TZ and every run would test the same zone. The
# defaults: UTC (CI), Taipei (+8, the project's home), Los Angeles (-7/-8, DST), Kolkata
# (+5:30, a half-hour offset) and Auckland (+13, DST, past the date line). Exit 1 if any
# zone failed. Stdlib Python only; nothing is installed.
set -u
cd "$(dirname "$0")/../.." || exit 2
if [ "$#" -gt 0 ]; then
  zones=("$@")
else
  zones=(UTC Asia/Taipei America/Los_Angeles Asia/Kolkata Pacific/Auckland)
fi
if [ -n "${TESTS:-}" ]; then
  read -r -a args <<< "$TESTS"
else
  args=(discover -s tests)
fi
failed=()
for zone in "${zones[@]}"; do
  echo "== TZ=$zone"
  if ! TZ="$zone" NETWARDEN_TZ="$zone" "${PYTHON:-python3}" -m unittest "${args[@]}"; then
    failed+=("$zone")
  fi
done
if [ "${#failed[@]}" -gt 0 ]; then
  echo "FAILED in: ${failed[*]}"
  exit 1
fi
echo "OK in all ${#zones[@]} zones"
