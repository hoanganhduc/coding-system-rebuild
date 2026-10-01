#!/usr/bin/env bash
# Wait a bounded interval for every real scheduler path to emit post-activation evidence.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMEOUT=150
MAX_AGE=180
STATE_DIR="$HOME/.local/state/coding-system/scheduler-canaries"
NOT_BEFORE_UNIX=""

usage() {
  echo "usage: $0 --not-before-unix UNIX [--timeout SECONDS] [--state-dir DIR]" >&2
}
while (($#)); do
  case "$1" in
    --timeout) shift; [[ $# -gt 0 && "$1" =~ ^[1-9][0-9]*$ ]] || { usage; exit 2; }; TIMEOUT="$1" ;;
    --state-dir) shift; [[ $# -gt 0 && "$1" == /* ]] || { usage; exit 2; }; STATE_DIR="$1" ;;
    --not-before-unix) shift; [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]] || { usage; exit 2; }; NOT_BEFORE_UNIX="$1" ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done
[[ -n "$NOT_BEFORE_UNIX" ]] || { usage; exit 2; }

deadline=$(( $(date +%s) + TIMEOUT ))
while (( $(date +%s) <= deadline )); do
  passed=1
  for scheduler in cron systemd openclaw; do
    python3 "$REPO/bin/scheduler-canary.py" verify \
      --scheduler "$scheduler" --state-dir "$STATE_DIR" \
      --max-age-seconds "$MAX_AGE" \
      --not-before-unix "$NOT_BEFORE_UNIX" >/dev/null 2>&1 || passed=0
  done
  if [[ "$passed" -eq 1 ]]; then
    echo "scheduler canaries: PASS (cron + systemd + OpenClaw)"
    exit 0
  fi
  sleep 5
done

echo "scheduler canaries: TECHNICAL_FAIL (no post-activation cron + systemd + OpenClaw evidence within ${TIMEOUT}s)" >&2
exit 2
