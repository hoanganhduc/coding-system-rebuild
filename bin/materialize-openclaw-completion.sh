#!/usr/bin/env bash
# Generate OpenClaw Bash completion without trusting stale generated state.
set -euo pipefail

TARGET_HOME="${HOME_OVERRIDE:-$HOME}"
STATE_DIR="${OPENCLAW_STATE_DIR_OVERRIDE:-}"
OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"
DRY_RUN=0
VERIFY=0
TEMPORARY=""
GENERATION_ROOT=""

usage() {
  cat <<'EOF'
Usage: materialize-openclaw-completion.sh [options]

Options:
  --home DIR          Target home (default: HOME_OVERRIDE or HOME)
  --state-dir DIR     OpenClaw state directory (default: HOME/.openclaw)
  --openclaw-bin CMD  OpenClaw executable (default: OPENCLAW_BIN or openclaw)
  --dry-run           Generate and validate, but do not create or replace files
  --verify            Require the installed file to match freshly generated output
  -h, --help          Show this help
EOF
}

while (($#)); do
  case "$1" in
    --home)
      [[ $# -ge 2 ]] || { echo "materialize-openclaw-completion: --home needs a value" >&2; exit 2; }
      TARGET_HOME=$2
      shift 2
      ;;
    --state-dir)
      [[ $# -ge 2 ]] || { echo "materialize-openclaw-completion: --state-dir needs a value" >&2; exit 2; }
      STATE_DIR=$2
      shift 2
      ;;
    --openclaw-bin)
      [[ $# -ge 2 ]] || { echo "materialize-openclaw-completion: --openclaw-bin needs a value" >&2; exit 2; }
      OPENCLAW_BIN=$2
      shift 2
      ;;
    --dry-run)
      [[ "$VERIFY" -eq 0 ]] || { echo "materialize-openclaw-completion: --dry-run and --verify are exclusive" >&2; exit 2; }
      DRY_RUN=1
      shift
      ;;
    --verify)
      [[ "$DRY_RUN" -eq 0 ]] || { echo "materialize-openclaw-completion: --dry-run and --verify are exclusive" >&2; exit 2; }
      VERIFY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "materialize-openclaw-completion: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ "$TARGET_HOME" == /* ]] || {
  echo "materialize-openclaw-completion: target home must be absolute" >&2
  exit 2
}
STATE_DIR="${STATE_DIR:-$TARGET_HOME/.openclaw}"
[[ "$STATE_DIR" == /* ]] || {
  echo "materialize-openclaw-completion: state directory must be absolute" >&2
  exit 2
}

if [[ "$OPENCLAW_BIN" == */* ]]; then
  [[ -x "$OPENCLAW_BIN" ]] || {
    echo "materialize-openclaw-completion: executable not found: $OPENCLAW_BIN" >&2
    exit 2
  }
else
  requested_openclaw_bin=$OPENCLAW_BIN
  OPENCLAW_BIN=$(command -v "$requested_openclaw_bin") || {
    echo "materialize-openclaw-completion: executable not found: $requested_openclaw_bin" >&2
    exit 2
  }
fi

completion_dir="$STATE_DIR/completions"
destination="$completion_dir/openclaw.bash"

if [[ -L "$completion_dir" ]]; then
  echo "materialize-openclaw-completion: refusing symlink directory: $completion_dir" >&2
  exit 2
fi
if [[ -L "$destination" || ( -e "$destination" && ! -f "$destination" ) ]]; then
  echo "materialize-openclaw-completion: refusing non-regular destination: $destination" >&2
  exit 2
fi

cleanup() {
  [[ -z "${TEMPORARY:-}" ]] || rm -f -- "$TEMPORARY"
  if [[ -n "${GENERATION_ROOT:-}" && -d "$GENERATION_ROOT" ]]; then
    rm -rf -- "$GENERATION_ROOT"
  fi
}
trap cleanup EXIT

umask 077
if [[ "$DRY_RUN" -eq 1 || "$VERIFY" -eq 1 ]]; then
  TEMPORARY=$(mktemp "${TMPDIR:-/tmp}/openclaw-completion.XXXXXX")
else
  mkdir -p -- "$completion_dir"
  [[ ! -L "$completion_dir" && -d "$completion_dir" ]] || {
    echo "materialize-openclaw-completion: unsafe completion directory: $completion_dir" >&2
    exit 2
  }
  chmod 700 "$completion_dir"
  TEMPORARY=$(mktemp "$completion_dir/.openclaw.bash.XXXXXX")
fi

GENERATION_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/openclaw-completion-state.XXXXXX")
GENERATION_STATE="$GENERATION_ROOT/state"
GENERATION_CONFIG="$GENERATION_STATE/openclaw.json"
mkdir -p -- "$GENERATION_STATE"
printf '%s\n' '{"plugins":{"enabled":false}}' > "$GENERATION_CONFIG"
chmod 700 "$GENERATION_ROOT" "$GENERATION_STATE"
chmod 600 "$GENERATION_CONFIG"

HOME="$TARGET_HOME" OPENCLAW_STATE_DIR="$GENERATION_STATE" \
  OPENCLAW_CONFIG_PATH="$GENERATION_CONFIG" \
  "$OPENCLAW_BIN" completion --shell bash > "$TEMPORARY"
[[ -s "$TEMPORARY" ]] || {
  echo "materialize-openclaw-completion: generator returned empty output" >&2
  exit 2
}
bash -n "$TEMPORARY"
chmod 600 "$TEMPORARY"

if [[ -f "$destination" && ! -L "$destination" ]] && cmp -s "$TEMPORARY" "$destination"; then
  if [[ "$DRY_RUN" -eq 0 && "$VERIFY" -eq 0 ]]; then
    chmod 600 "$destination"
  fi
  if [[ "$VERIFY" -eq 1 ]]; then
    read -r destination_uid destination_mode destination_links < <(stat -c '%u %a %h' -- "$destination")
    [[ "$destination_uid" == "$(id -u)" && "$destination_mode" == 600 \
        && "$destination_links" == 1 ]] || {
      echo "materialize-openclaw-completion: installed completion metadata is unsafe" >&2
      exit 2
    }
  fi
  echo "materialize-openclaw-completion: current: $destination"
  exit 0
fi

if [[ "$VERIFY" -eq 1 ]]; then
  echo "materialize-openclaw-completion: installed completion is missing or stale" >&2
  exit 1
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "materialize-openclaw-completion: would install: $destination"
  exit 0
fi

mv -f -- "$TEMPORARY" "$destination"
TEMPORARY=""
echo "materialize-openclaw-completion: installed: $destination"
