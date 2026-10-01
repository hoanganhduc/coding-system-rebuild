#!/usr/bin/env bash
# No-secrets rehearsal for CI or a fresh VM: doctor, components, leak scans and
# every self-test.  Each check runs even when an earlier one fails, and the
# summary lists all failures, so one run shows every problem.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO"

failed=()
check() {
  local name="$1"
  shift
  echo "=== ci: $name ==="
  if "$@"; then
    echo "--- ci: $name passed"
  else
    echo "--- ci: $name FAILED"
    failed+=("$name")
    [[ "${GITHUB_ACTIONS:-}" == "true" ]] && echo "::error title=ci check failed::$name"
  fi
}

check doctor bash bin/doctor.sh
check components bash -c 'python3 -I -B bin/lib/component_paths.py --repository "$1" --home "$HOME" --source-fallback --require openclaw-bot >/dev/null 2>&1 || make -s components' _ "$REPO"
check leak-scan bash bin/leak-scan.sh
check leak-scan-history make -s leak-scan-history
check public-export-check make -s public-export-check
check tests python3 -B bin/run-test-suite.py

if ((${#failed[@]})); then
  echo "ci: FAILED: ${failed[*]}"
  exit 1
fi
echo "ci: all no-secrets checks passed"
