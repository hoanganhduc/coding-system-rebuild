#!/usr/bin/env bash
# Upload one complete immutable recovery-set directory through rclone.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP \
  LD_PRELOAD LD_LIBRARY_PATH

REPO="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
DEST="${CSR_RCLONE_DEST:-}"
READBACK=""

die() { echo "offsite: $*" >&2; exit 2; }
cleanup() {
  if [[ -n "$READBACK" ]]; then
    if [[ ! -L "$READBACK" && -d "$READBACK" \
        && "$(/usr/bin/basename -- "$READBACK")" == csr-offsite-readback-* ]]; then
      /usr/bin/rm -rf -- "$READBACK"
    else
      echo "offsite: refusing unsafe readback cleanup" >&2
    fi
  fi
}
trap cleanup EXIT
[[ "${CSR_NO_OFFSITE:-0}" != "1" ]] || {
  echo "offsite: disabled (CSR_NO_OFFSITE=1)"
  exit 0
}
[[ -n "$DEST" ]] || DEST="$(/usr/bin/python3 -I -B "$REPO/bin/lib/owner_settings.py" get \
  --key CSR_RCLONE_DEST --path "$HOME/.secrets.env")" || die "the owner settings file is invalid"
[[ -n "$DEST" ]] || die "set CSR_RCLONE_DEST (an owner setting) to the rclone destination"
[[ -x /usr/bin/rclone && ! -L /usr/bin/rclone ]] \
  || die "fixed /usr/bin/rclone is not installed as a regular executable"

SET_DIR="${1:-}"
if [[ -z "$SET_DIR" ]]; then
  mapfile -d '' -t candidates < <(
    find -P "$HOME/secrets-out" -mindepth 2 -maxdepth 2 -type f \
      -name recovery-set.json -printf '%T@\t%h\0' 2>/dev/null | sort -zrn
  )
  ((${#candidates[@]} > 0)) || die "no recovery set found below $HOME/secrets-out"
  SET_DIR="${candidates[0]#*$'\t'}"
fi
[[ -d "$SET_DIR" && ! -L "$SET_DIR" ]] || die "recovery-set directory is missing or unsafe"
SET_DIR="$(cd -- "$SET_DIR" && pwd -P)"

RECOVERY_SET="$SET_DIR" /usr/bin/bash "$REPO/bin/verify-recovery-signature.sh" >/dev/null
/usr/bin/python3 -I -B - "$REPO/bin/lib" "$SET_DIR" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from recovery_tool import load_recovery_manifest

load_recovery_manifest(sys.argv[2])
PY

SET_ID="$(python3 - "$SET_DIR/recovery-set.json" <<'PY'
import json
import re
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
set_id = value.get("set_id", "")
if not isinstance(set_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{7,127}", set_id) is None:
    raise SystemExit(2)
print(set_id)
PY
)" || die "recovery set has an invalid set identity"
[[ "$(basename -- "$SET_DIR")" == "$SET_ID" ]] \
  || die "recovery-set directory name must equal its signed set identity"

remote_name="${DEST%%:*}:"
/usr/bin/rclone listremotes | /usr/bin/grep -Fqx -- "$remote_name" \
  || die "rclone remote $remote_name is not configured"
/usr/bin/rclone lsd "$DEST" >/dev/null \
  || die "cannot read the configured offsite destination: $DEST"
REMOTE_SET="$DEST/recovery-sets/$SET_ID"
if /usr/bin/rclone lsjson "$REMOTE_SET" --stat >/dev/null 2>&1; then
  die "refusing to overwrite an existing immutable recovery set: $REMOTE_SET"
fi

/usr/bin/rclone copy "$SET_DIR/" "$REMOTE_SET/" --immutable --no-traverse
# Exact inventory equality rejects both missing and injected remote objects.
/usr/bin/rclone check "$SET_DIR/" "$REMOTE_SET/"

# A provider-side checksum is not sufficient evidence that the retrievable
# bytes still authenticate. Fetch the exact remote tree, then run the normal
# signature and public-manifest inventory gates over those fetched bytes.
READBACK="$(/usr/bin/python3 -I -B "$REPO/bin/lib/secure_temp.py" \
  create --prefix csr-offsite-readback-)" \
  || die "cannot create protected remote readback directory"
/usr/bin/rclone copy "$REMOTE_SET/" "$READBACK/" --immutable --no-traverse
RECOVERY_SET="$READBACK" /usr/bin/bash \
  "$REPO/bin/verify-recovery-signature.sh" >/dev/null
/usr/bin/python3 -I -B - "$REPO/bin/lib" "$READBACK" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from recovery_tool import load_recovery_manifest

load_recovery_manifest(sys.argv[2])
PY
echo "offsite: uploaded and readback-checked immutable recovery set"
echo "  local:  $SET_DIR"
echo "  remote: $REMOTE_SET"
