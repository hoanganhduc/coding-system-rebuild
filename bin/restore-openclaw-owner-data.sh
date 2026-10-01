#!/usr/bin/bash -p
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP \
  LD_PRELOAD LD_LIBRARY_PATH

usage() {
  echo "Usage: $0 OPENCLAW_PRIVATE_ARCHIVE [PREFIX]" >&2
}

[[ $# -ge 1 && $# -le 2 ]] || { usage; exit 2; }
ARCHIVE="$1"
PREFIX="${2:-$HOME/.openclaw}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENCLAW_COMPONENT="${OPENCLAW_COMPONENT_DIR:-}"
if [[ -z "$OPENCLAW_COMPONENT" ]]; then
  OPENCLAW_COMPONENT="$(/usr/bin/python3 -I -B \
    "$REPO/bin/lib/component_paths.py" --repository "$REPO" --home "$HOME" \
    --source-fallback --require openclaw-bot)" \
    || { echo "owner-data restore: immutable OpenClaw component is unavailable" >&2; exit 2; }
fi
RESTORE="$OPENCLAW_COMPONENT/restore.sh"

[[ -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] \
  || { echo "owner-data restore: archive is missing or unsafe: $ARCHIVE" >&2; exit 2; }
[[ -x "$RESTORE" ]] \
  || { echo "owner-data restore: pinned component restore helper is unavailable" >&2; exit 2; }
if [[ -n "${OPENCLAW_BACKUP_PASSPHRASE_FILE:-}" ]]; then
  [[ -f "$OPENCLAW_BACKUP_PASSPHRASE_FILE" && ! -L "$OPENCLAW_BACKUP_PASSPHRASE_FILE" ]] \
    || { echo "owner-data restore: passphrase file is missing or unsafe" >&2; exit 2; }
fi

RESTORE_ARGS=(
  --archive "$ARCHIVE"
  --prefix "$PREFIX"
  --overlay-only
  --skip-services
)
SIGNED_OWNER_SHA256="${CSR_SIGNED_OWNER_DATA_SHA256:-}"
if [[ -n "$SIGNED_OWNER_SHA256" ]]; then
  [[ "$SIGNED_OWNER_SHA256" =~ ^[0-9a-f]{64}$ \
      && -n "${RECOVERY_SET:-}" \
      && -d "$RECOVERY_SET" \
      && ! -L "$RECOVERY_SET" ]] || {
    echo "owner-data restore: signed v2 owner authority is incomplete" >&2
    exit 2
  }
  RECOVERY_SET="$RECOVERY_SET" \
    /usr/bin/bash -p "$REPO/bin/verify-recovery-signature.sh" >/dev/null
  read -r SIGNED_OWNER_FILE VERIFIED_OWNER_SHA256 < <(
    /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
      "$REPO/bin/lib/recovery_tool.py" inspect-set-owner \
      --set-dir "$RECOVERY_SET" \
    | /usr/bin/python3 -I -S -B -c '
import json, re, sys
value = json.load(sys.stdin)
owner = value.get("owner_data") if isinstance(value, dict) else None
filename = owner.get("file") if isinstance(owner, dict) else None
digest = owner.get("sha256") if isinstance(owner, dict) else None
if not isinstance(filename, str) or re.fullmatch(r"openclaw-private-[0-9]{8}T[0-9]{6}Z[.]tar[.]gz[.]gpg", filename) is None:
    raise SystemExit(2)
if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit(2)
print(filename, digest)
'
  ) || {
    echo "owner-data restore: signed v2 owner record is invalid" >&2
    exit 2
  }
  [[ "$ARCHIVE" == "$RECOVERY_SET/$SIGNED_OWNER_FILE" \
      && "$SIGNED_OWNER_SHA256" == "$VERIFIED_OWNER_SHA256" ]] || {
    echo "owner-data restore: archive does not match signed v2 owner metadata" >&2
    exit 2
  }
  RESTORE_ARGS+=(
    --signed-recovery-set-v2-owner-sha256 "$SIGNED_OWNER_SHA256"
  )
fi

/usr/bin/bash -p "$RESTORE" "${RESTORE_ARGS[@]}"
echo "owner-data restore: verified overlay installed"
