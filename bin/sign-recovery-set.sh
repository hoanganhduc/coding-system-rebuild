#!/usr/bin/bash -p
# Attach and verify the detached recovery release signature required by Stage 0.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP \
  LD_PRELOAD LD_LIBRARY_PATH

REPO="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
SET_DIR="${1:-${RECOVERY_SET:-}}"
IDENTITY="coding-system-recovery"
NAMESPACE="coding-system-recovery-set-v1"
KEY_SHA256="c869a7314609cc6a6c167a3dc7e4f8456b7c0ac11eeb9dd091db0d99b3b82898"
PRIVATE_KEY="${CSR_RECOVERY_SIGNING_KEY_FILE:-$HOME/.config/coding-system/recovery-signing}"
PUBLIC_KEY="$REPO/system/recovery/recovery-signing-public-key.pub"
STAGE=""

cleanup() {
  case "$STAGE" in
    /run/user/"$(id -u)"/csr-recovery-sign-*|/dev/shm/csr-recovery-"$(id -u)"/csr-recovery-sign-*)
      rm -rf -- "$STAGE"
      ;;
    "") ;;
    *) echo "sign-recovery-set: refusing unsafe staging cleanup" >&2 ;;
  esac
}
trap cleanup EXIT

[[ -n "$SET_DIR" && -d "$SET_DIR" && ! -L "$SET_DIR" ]] \
  || { echo "sign-recovery-set: recovery-set directory is missing or unsafe" >&2; exit 2; }
SET_DIR="$(cd -- "$SET_DIR" && pwd -P)"
manifest="$SET_DIR/recovery-set.json"
signature="$SET_DIR/recovery-set.json.sig"
set_public_key="$SET_DIR/recovery-signing-public-key.pub"

for path in "$manifest" "$PUBLIC_KEY"; do
  [[ -f "$path" && ! -L "$path" ]] \
    || { echo "sign-recovery-set: required metadata is missing or unsafe" >&2; exit 2; }
  size="$(stat -c %s -- "$path")"
  [[ "$size" =~ ^[0-9]+$ && "$size" -gt 0 && "$size" -le 1048576 ]] \
    || { echo "sign-recovery-set: required metadata exceeds its bound" >&2; exit 2; }
done

# A normal signed set is a restorable-now release.  There is deliberately no
# implicit archival escape hatch: an archival generation needs a distinct,
# explicitly non-restorable contract and is rejected by the normal restore.
/usr/bin/python3 -I -B "$REPO/bin/verify-recovery-release.py" \
  --recovery-set "$SET_DIR"

if [[ -e "$signature" || -L "$signature" || -e "$set_public_key" || -L "$set_public_key" ]]; then
  [[ -f "$signature" && ! -L "$signature" && -f "$set_public_key" && ! -L "$set_public_key" ]] \
    || { echo "sign-recovery-set: incomplete detached-signature pair" >&2; exit 2; }
  RECOVERY_SET="$SET_DIR" /usr/bin/bash -p \
    "$REPO/bin/verify-recovery-signature.sh" >/dev/null
  echo "recovery-set signature: already valid"
  exit 0
fi

[[ -f "$PRIVATE_KEY" && ! -L "$PRIVATE_KEY" ]] \
  || { echo "sign-recovery-set: protected signing authority is missing or unsafe" >&2; exit 2; }
read -r key_uid key_mode key_links key_size < <(stat -c '%u %a %h %s' -- "$PRIVATE_KEY")
[[ "$key_uid" == "$(id -u)" && "$key_mode" == 600 && "$key_links" == 1 \
    && "$key_size" =~ ^[0-9]+$ && "$key_size" -gt 0 && "$key_size" -le 1048576 ]] \
  || { echo "sign-recovery-set: signing authority ownership/mode/link/size is unsafe" >&2; exit 2; }

actual_public_hash="$(sha256sum "$PUBLIC_KEY" | cut -d' ' -f1)"
[[ "$actual_public_hash" == "$KEY_SHA256" ]] \
  || { echo "sign-recovery-set: tracked public key differs from Stage-0 trust root" >&2; exit 2; }
derived_public="$(ssh-keygen -y -f "$PRIVATE_KEY")"
tracked_public="$(awk 'NR == 1 {print $1 " " $2}' "$PUBLIC_KEY")"
[[ "$derived_public" == "$tracked_public" ]] \
  || { echo "sign-recovery-set: signing authority does not match the trust root" >&2; exit 2; }

STAGE="$(python3 "$REPO/bin/lib/secure_temp.py" create --prefix csr-recovery-sign-)"
install -m 0600 "$manifest" "$STAGE/recovery-set.json"
ssh-keygen -Y sign -q -f "$PRIVATE_KEY" -n "$NAMESPACE" \
  "$STAGE/recovery-set.json"
printf '%s %s\n' "$IDENTITY" "$tracked_public" > "$STAGE/allowed-signers"
chmod 0600 "$STAGE/allowed-signers"
ssh-keygen -Y verify -q -f "$STAGE/allowed-signers" -I "$IDENTITY" \
  -n "$NAMESPACE" -s "$STAGE/recovery-set.json.sig" \
  < "$manifest" >/dev/null 2>&1 \
  || { echo "sign-recovery-set: detached signature self-check failed" >&2; exit 2; }

public_stage="$SET_DIR/.recovery-signing-public-key.pub.$$.tmp"
signature_stage="$SET_DIR/.recovery-set.json.sig.$$.tmp"
trap 'rm -f -- "${public_stage:-}" "${signature_stage:-}"; cleanup' EXIT
install -m 0444 "$PUBLIC_KEY" "$public_stage"
install -m 0444 "$STAGE/recovery-set.json.sig" "$signature_stage"
mv -- "$public_stage" "$set_public_key"
public_stage=""
mv -- "$signature_stage" "$signature"
signature_stage=""
RECOVERY_SET="$SET_DIR" /usr/bin/bash -p \
  "$REPO/bin/verify-recovery-signature.sh" >/dev/null
echo "recovery-set signature: created and verified"
