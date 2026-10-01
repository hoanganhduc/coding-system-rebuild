#!/usr/bin/env bash
# Apply recorded user-unit state; enabled units are started in the same operation.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STATE_FILE="$REPO/system/systemd/units.state"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-systemctl}"
MODE=enable-now
DRY_RUN=0
VERIFY=0

usage() {
  cat <<'EOF'
Usage: reconcile-systemd-user-units.sh [options]

Options:
  --state FILE             Unit-state TSV (default: system/systemd/units.state)
  --systemctl-bin CMD      systemctl executable (default: SYSTEMCTL_BIN or systemctl)
  --registration-only     Enable/disable units without starting enabled units
  --dry-run               Validate and print intended actions without systemctl calls
  --verify                Read-only exact state check; return 1 on drift
  -h, --help              Show this help
EOF
}

while (($#)); do
  case "$1" in
    --state)
      [[ $# -ge 2 ]] || { echo "systemd units: --state needs a value" >&2; exit 2; }
      STATE_FILE=$2
      shift 2
      ;;
    --systemctl-bin)
      [[ $# -ge 2 ]] || { echo "systemd units: --systemctl-bin needs a value" >&2; exit 2; }
      SYSTEMCTL_BIN=$2
      shift 2
      ;;
    --registration-only)
      MODE=registration-only
      shift
      ;;
    --dry-run)
      [[ "$VERIFY" -eq 0 ]] || { echo "systemd units: --dry-run and --verify are exclusive" >&2; exit 2; }
      DRY_RUN=1
      shift
      ;;
    --verify)
      [[ "$DRY_RUN" -eq 0 ]] || { echo "systemd units: --dry-run and --verify are exclusive" >&2; exit 2; }
      VERIFY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "systemd units: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -f "$STATE_FILE" ]] || { echo "systemd units: missing state file: $STATE_FILE" >&2; exit 2; }
if [[ "$SYSTEMCTL_BIN" == */* ]]; then
  [[ -x "$SYSTEMCTL_BIN" ]] || { echo "systemd units: executable not found: $SYSTEMCTL_BIN" >&2; exit 2; }
else
  requested_systemctl_bin=$SYSTEMCTL_BIN
  SYSTEMCTL_BIN=$(command -v "$requested_systemctl_bin") || {
    echo "systemd units: executable not found: $requested_systemctl_bin" >&2
    exit 2
  }
fi

declare -A SEEN=()
declare -a UNITS=() STATES=() ACTIVITIES=()
while IFS=$'\t' read -r unit state activity extra || [[ -n "${unit:-}" ]]; do
  [[ -z "${unit:-}" || "$unit" == \#* ]] && continue
  [[ -z "${extra:-}" ]] || { echo "systemd units: malformed state row for $unit" >&2; exit 2; }
  [[ "$unit" =~ ^[A-Za-z0-9_.@:-]+\.(service|timer|socket|path|target)$ ]] || {
    echo "systemd units: unsafe unit name: $unit" >&2
    exit 2
  }
  case "$state" in
    enabled|disabled|static) ;;
    *) echo "systemd units: invalid state for $unit: $state" >&2; exit 2 ;;
  esac
  case "${activity:-}" in
    ""|active|inactive|successful-oneshot) ;;
    *) echo "systemd units: invalid activity for $unit: $activity" >&2; exit 2 ;;
  esac
  [[ -z "${SEEN[$unit]:-}" ]] || { echo "systemd units: duplicate unit: $unit" >&2; exit 2; }
  SEEN[$unit]=1
  UNITS+=("$unit")
  STATES+=("$state")
  ACTIVITIES+=("${activity:-}")
done < "$STATE_FILE"

# bin/refresh-state.sh regenerates this file from the live user manager and
# skips every unit that manager does not answer for, so a zero-row state file
# is lost declarations rather than a host that declares no user units.
# Iterating an empty array would report PASS having verified nothing.
[[ "${#UNITS[@]}" -gt 0 ]] || {
  echo "systemd units: no unit declarations parsed from $STATE_FILE" >&2
  exit 2
}

if [[ "$VERIFY" -eq 1 ]]; then
  drift=0
  status_error=0
  for index in "${!UNITS[@]}"; do
    unit=${UNITS[$index]}
    expected=${STATES[$index]}
    expected_activity=${ACTIVITIES[$index]}
    actual=$("$SYSTEMCTL_BIN" --user is-enabled "$unit" 2>/dev/null || true)
    if [[ -z "$actual" ]]; then
      echo "systemd units: ERROR: could not read enable state for $unit" >&2
      status_error=1
    elif [[ "$actual" == "$expected" ]]; then
      echo "systemd units: current: $unit ($actual)"
    else
      echo "systemd units: drift: $unit ($actual != $expected)" >&2
      drift=1
    fi
    if [[ -z "$expected_activity" && "$expected" == enabled && "$unit" == *.timer ]]; then
      expected_activity=active
    elif [[ -z "$expected_activity" && "$expected" == disabled ]]; then
      expected_activity=inactive
    fi
    if [[ "$expected_activity" == active ]]; then
      active=$("$SYSTEMCTL_BIN" --user is-active "$unit" 2>/dev/null || true)
      if [[ -z "$active" ]]; then
        echo "systemd units: ERROR: could not read active state for $unit" >&2
        status_error=1
      elif [[ "$active" == active ]]; then
        echo "systemd units: current: $unit (active)"
      else
        echo "systemd units: drift: $unit ($active != active)" >&2
        drift=1
      fi
    elif [[ "$expected_activity" == inactive ]]; then
      active=$("$SYSTEMCTL_BIN" --user is-active "$unit" 2>/dev/null || true)
      if [[ -z "$active" ]]; then
        echo "systemd units: ERROR: could not read active state for $unit" >&2
        status_error=1
      elif [[ "$active" != inactive ]]; then
        echo "systemd units: drift: $unit ($active != inactive)" >&2
        drift=1
      fi
    elif [[ "$expected_activity" == successful-oneshot ]]; then
      active=$("$SYSTEMCTL_BIN" --user is-active "$unit" 2>/dev/null || true)
      result=$("$SYSTEMCTL_BIN" --user show --property Result --value "$unit" 2>/dev/null || true)
      if [[ "$active" == inactive && "$result" == success ]]; then
        echo "systemd units: current: $unit (successful oneshot)"
      elif [[ -z "$active" || -z "$result" ]]; then
        echo "systemd units: ERROR: could not read oneshot state for $unit" >&2
        status_error=1
      else
        echo "systemd units: drift: $unit ($active/$result != inactive/success)" >&2
        drift=1
      fi
    fi
  done
  [[ "$status_error" -eq 0 ]] || exit 2
  exit "$drift"
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  for index in "${!UNITS[@]}"; do
    unit=${UNITS[$index]}
    state=${STATES[$index]}
    case "$state:$MODE" in
      enabled:enable-now) echo "systemd units: would enable --now $unit" ;;
      enabled:registration-only) echo "systemd units: would enable $unit" ;;
      disabled:*) echo "systemd units: would disable --now $unit" ;;
      static:*) echo "systemd units: would verify static $unit" ;;
    esac
  done
  exit 0
fi

"$SYSTEMCTL_BIN" --user daemon-reload
for index in "${!UNITS[@]}"; do
  unit=${UNITS[$index]}
  state=${STATES[$index]}
  case "$state:$MODE" in
    enabled:enable-now) "$SYSTEMCTL_BIN" --user enable --now "$unit" ;;
    enabled:registration-only) "$SYSTEMCTL_BIN" --user enable "$unit" ;;
    disabled:*) "$SYSTEMCTL_BIN" --user disable --now "$unit" ;;
    static:*)
      actual=$("$SYSTEMCTL_BIN" --user is-enabled "$unit" 2>/dev/null || true)
      [[ "$actual" == static ]] || {
        echo "systemd units: $unit is $actual, expected static" >&2
        exit 2
      }
      ;;
  esac
done
echo "systemd units: reconciled (${#UNITS[@]} units; mode=$MODE)"
