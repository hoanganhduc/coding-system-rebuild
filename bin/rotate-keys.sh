#!/usr/bin/env bash
# Fail-closed compatibility wrapper for retired in-place secret rotation.
#
#   bash bin/rotate-keys.sh --list
#
# Dynamic named, declared-field, and OpenClaw provider mutations are rejected:
# their historical targets do not prove the canonical/effective deployed value.
# The wrapper performs no prompts, live provider checks, service restarts, or
# recovery-set capture.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -eq 1 && ( "$1" == "--list" || "$1" == "list" ) ]]; then
  exec python3 "$REPO/bin/lib/rotate_secrets.py" list
fi

echo "ERROR: in-place secret rotation is disabled; update and verify the declared canonical authority with its native workflow" >&2
exit 2
