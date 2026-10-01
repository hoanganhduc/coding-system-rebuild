#!/usr/bin/bash -p
# Exact, read-only verification of every scheduler owned by this repository.
if [[ $- != *p* ]]; then
  exec /usr/bin/bash -p "$0" "$@"
fi
set -uo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE NODE_OPTIONS NODE_PATH \
  PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONINSPECT PYTHONWARNINGS \
  LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD
export PATH=/usr/bin:/bin

REPO="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
OPENCLAW_LOADER="$HOME/.local/share/coding-system/openclaw-launchers/loader.py"
OPENCLAW_EXECUTABLE_HELPER=""
OPENCLAW_EXECUTABLE_CONTRACT=""
resolve_openclaw_paths() {
  local report
  report="$(/usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$OPENCLAW_LOADER" --home "$HOME" --resolve-json)" || return 2
  mapfile -t paths < <(/usr/bin/python3 -I -B -c '
import json, sys
value = json.load(sys.stdin)
print(value.get("helper", "")); print(value.get("contract", ""))
' <<<"$report")
  [[ ${#paths[@]} -eq 2 ]] || return 2
  OPENCLAW_EXECUTABLE_HELPER="${paths[0]}"
  OPENCLAW_EXECUTABLE_CONTRACT="${paths[1]}"
}
openclaw_exact() {
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$OPENCLAW_LOADER" --home "$HOME" --exec -- "$@"
}
PROFILE="full"
NOT_BEFORE_UNIX=""

usage() {
  cat <<'EOF'
usage: bin/verify-schedulers.sh [--profile full|ci|status] [--not-before-unix UNIX]

full/status require live crontab, user-systemd, OpenClaw declarations, and
recent provider-free canaries. --not-before-unix additionally binds all three
canaries to the current restore activation boundary. ci validates declarations
without live state and does not accept --not-before-unix.
EOF
}

while (($#)); do
  case "$1" in
    --profile)
      shift
      [[ $# -gt 0 ]] || { usage >&2; exit 2; }
      PROFILE="$1"
      ;;
    --not-before-unix)
      shift
      [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]] || { usage >&2; exit 2; }
      NOT_BEFORE_UNIX="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done
case "$PROFILE" in full|ci|status) ;; *) usage >&2; exit 2 ;; esac
[[ "$PROFILE" != "ci" || -z "$NOT_BEFORE_UNIX" ]] || { usage >&2; exit 2; }

FAIL=0
ERROR=0
run_exact() {
  local label="$1"
  shift
  "$@"
  local rc=$?
  case "$rc" in
    0) printf 'PASS  %s\n' "$label" ;;
    1) printf 'DRIFT %s\n' "$label" >&2; FAIL=1 ;;
    *) printf 'ERROR %s (exit %s)\n' "$label" "$rc" >&2; ERROR=1 ;;
  esac
}

if [[ "$PROFILE" == "ci" ]]; then
  # A degraded install has no private owner settings, so the declaration is
  # checked with fixed synthetic schedule values; full/status use the real ones.
  run_exact "host schedule declarations" \
    /usr/bin/env CSR_OWNER_TIMEZONE=Etc/UTC \
      "CSR_RSS_DIGEST_ONCALENDAR=*-*-* 00/4:00:00 UTC" \
      /usr/bin/python3 -I -B "$REPO/bin/reconcile-host-schedules.py" --dry-run
  run_exact "host timer schedule declarations" \
    /usr/bin/env CSR_OWNER_TIMEZONE=Etc/UTC \
      "CSR_RSS_DIGEST_ONCALENDAR=*-*-* 00/4:00:00 UTC" \
      /usr/bin/python3 -I -B "$REPO/bin/reconcile-host-schedules.py" --scope systemd --dry-run
  run_exact "user systemd declarations" \
    /usr/bin/bash -p "$REPO/bin/reconcile-systemd-user-units.sh" --dry-run
  run_exact "OpenClaw cron declaration" \
    /usr/bin/python3 -I -B - "$REPO/system/schedules/openclaw-cron.v2.json" <<'PY'
import importlib.util
import pathlib
import sys

script = pathlib.Path(sys.argv[1]).parents[2] / "bin" / "openclaw-cron-v2.py"
spec = importlib.util.spec_from_file_location("openclaw_cron_v2", script)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
module.load_snapshot(pathlib.Path(sys.argv[1]))
print("OpenClaw cron v2: declaration valid")
PY
  if [[ "$ERROR" -ne 0 ]]; then
    echo "scheduler verification: TECHNICAL_FAIL (ci declarations)" >&2
    exit 2
  fi
  if [[ "$FAIL" -ne 0 ]]; then
    echo "scheduler verification: DRIFT (ci declarations)" >&2
    exit 1
  fi
  echo "scheduler verification: PASS (ci declarations; live execution not asserted)"
  exit 0
fi

resolve_openclaw_paths || {
  echo "ERROR OpenClaw scheduler: root-owned launcher selector is unavailable" >&2
  exit 2
}

[[ -x /usr/bin/crontab ]] \
  || { echo "ERROR host schedules: crontab is unavailable" >&2; ERROR=1; }
if ! /usr/bin/systemctl is-active --quiet cron.service 2>/dev/null; then
  echo "ERROR host schedules: cron.service is not active" >&2
  ERROR=1
else
  echo "PASS  host cron daemon active"
fi
if [[ -x /usr/bin/crontab ]]; then
  run_exact "host crontab declaration" \
    /usr/bin/python3 -I -B "$REPO/bin/reconcile-host-schedules.py" --verify
fi

if [[ ! -d /run/systemd/system ]]; then
  echo "ERROR user systemd: systemd is not the active init" >&2
  ERROR=1
else
  run_exact "user systemd enable/activity state" \
    /usr/bin/bash -p "$REPO/bin/reconcile-systemd-user-units.sh" --verify
  run_exact "user timer schedules" \
    /usr/bin/python3 -I -B "$REPO/bin/reconcile-host-schedules.py" --scope systemd --verify
fi

PRIVATE_SNAPSHOT="$HOME/.config/coding-system/openclaw-cron.v2.json"
PUBLIC_CANARY="$REPO/system/schedules/openclaw-cron.v2.json"
if ! openclaw_exact health --json >/dev/null 2>&1; then
  echo "ERROR OpenClaw scheduler: gateway is not healthy" >&2
  ERROR=1
else
  # bin/secrets-pack.sh exports this snapshot on every backup of a home that
  # has an OpenClaw config, so on such a home its absence is lost scheduler
  # state rather than a host that never declared any cron jobs.  Skipping the
  # check when the file is missing would let that loss verify as PASS.
  if [[ -L "$PRIVATE_SNAPSHOT" ]]; then
    echo "ERROR OpenClaw scheduler: private cron declarations are not a regular file" >&2
    ERROR=1
  elif [[ -f "$PRIVATE_SNAPSHOT" ]]; then
    run_exact "private OpenClaw cron declarations" \
      /usr/bin/python3 -I -B "$REPO/bin/openclaw-cron-v2.py" --home "$HOME" \
        --openclaw-helper "$OPENCLAW_EXECUTABLE_HELPER" \
        --openclaw-contract "$OPENCLAW_EXECUTABLE_CONTRACT" verify \
        --input "$PRIVATE_SNAPSHOT"
  elif [[ -f "$HOME/.openclaw/openclaw.json" ]]; then
    echo "ERROR OpenClaw scheduler: private cron declarations are absent" >&2
    ERROR=1
  fi
  run_exact "OpenClaw scheduler canary declaration" \
    /usr/bin/python3 -I -B "$REPO/bin/openclaw-cron-v2.py" --home "$HOME" \
      --openclaw-helper "$OPENCLAW_EXECUTABLE_HELPER" \
      --openclaw-contract "$OPENCLAW_EXECUTABLE_CONTRACT" verify \
      --input "$PUBLIC_CANARY" --no-prune-managed
fi

CANARY_STATE="$HOME/.local/state/coding-system/scheduler-canaries"
CANARY_BOUNDARY_ARGS=()
if [[ -n "$NOT_BEFORE_UNIX" ]]; then
  CANARY_BOUNDARY_ARGS=(--not-before-unix "$NOT_BEFORE_UNIX")
fi
for scheduler in cron systemd openclaw; do
  run_exact "$scheduler scheduler execution canary" \
    /usr/bin/python3 -I -B "$REPO/bin/scheduler-canary.py" verify \
      --scheduler "$scheduler" --state-dir "$CANARY_STATE" --max-age-seconds 900 \
      "${CANARY_BOUNDARY_ARGS[@]}"
done

if [[ "$ERROR" -ne 0 ]]; then
  echo "scheduler verification: TECHNICAL_FAIL" >&2
  exit 2
fi
if [[ "$FAIL" -ne 0 ]]; then
  echo "scheduler verification: DRIFT" >&2
  exit 1
fi
echo "scheduler verification: PASS"
