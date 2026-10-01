#!/usr/bin/env bash
# LEGACY-INCOMPLETE MIGRATION ONLY.
# Decrypt a historical AES ZIP into a protected staging home, validate every
# member, then repack it as a recovery set. The ZIP password is read from a
# protected file through stdin; it never appears in argv or the environment.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP \
  LD_PRELOAD LD_LIBRARY_PATH GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR \
  GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_DIR GIT_INDEX_FILE \
  GIT_OBJECT_DIRECTORY GIT_WORK_TREE
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
  GIT_TERMINAL_PROMPT=0 XDG_CONFIG_HOME=/nonexistent

REPO="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
safe_release_git() {
  /usr/bin/git --no-optional-locks \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null \
    -c credential.helper= "$@"
}
MANIFEST="$REPO/secrets/secrets-manifest.yaml"
ZIP="${LEGACY_ZIP:-${1:-}}"
OUT_ROOT="${2:-$HOME/secrets-out}"
PASSWORD_FILE="${LEGACY_PASSWORD_FILE:-}"
MASTER_KEY_FILE="${CSR_RECOVERY_MASTER_KEY_FILE:-$HOME/.config/coding-system/recovery-master.key}"
ESCROW_GENERATION="${CSR_ESCROW_GENERATION:-$HOME/.config/coding-system/escrow/current/escrow-generation.json}"
SIGNING_KEY_FILE="${CSR_RECOVERY_SIGNING_KEY_FILE:-$HOME/.config/coding-system/recovery-signing}"
PINNED_SIGNING_PUBLIC="$REPO/system/recovery/recovery-signing-public-key.pub"

[[ -n "$ZIP" && -f "$ZIP" ]] || { echo "ERROR: legacy ZIP is missing" >&2; exit 2; }
[[ -n "$PASSWORD_FILE" && -f "$PASSWORD_FILE" ]] || {
  echo "ERROR: set LEGACY_PASSWORD_FILE to a protected regular file" >&2
  exit 2
}
[[ -f "$MASTER_KEY_FILE" && -f "$ESCROW_GENERATION" ]] || {
  echo "ERROR: create/select the destination escrow generation first" >&2
  exit 2
}
/usr/bin/python3 -I -B "$REPO/bin/lib/recovery_tool.py" manifest-check \
  --manifest "$MANIFEST" >/dev/null

TMP="$(python3 "$REPO/bin/lib/secure_temp.py" create --prefix csr-legacy-import-)"
trap 'rm -rf "$TMP"' EXIT
chmod 700 "$TMP"

python3 "$REPO/bin/lib/legacy_zip_tool.py" test \
  --archive "$ZIP" --password-file "$PASSWORD_FILE"
python3 "$REPO/bin/lib/legacy_zip_tool.py" list --archive "$ZIP" \
  | python3 "$REPO/bin/lib/secrets_tool.py" verify-legacy-zip "$MANIFEST" >/dev/null
mkdir "$TMP/home"
python3 "$REPO/bin/lib/legacy_zip_tool.py" extract \
  --archive "$ZIP" --password-file "$PASSWORD_FILE" --output-dir "$TMP/home"

# A legacy ZIP predates both newly required manifest entries. Supply the
# destination-owned signing authority through a stable no-follow capture and
# require its derived Ed25519 public identity to match the repository-pinned
# trust root. Then migrate bounded legacy authorities, converge selectors, and
# generate the metadata-only source capability contract. If any synthesis or
# offline closure gate fails, do not publish a falsely complete generation.
/usr/bin/install -d -m 0700 "$TMP/home/.config/coding-system"
/usr/bin/python3 -I -B "$REPO/bin/lib/recovery_tool.py" \
  stage-legacy-signing-authority \
  --source-key "$SIGNING_KEY_FILE" \
  --destination-home "$TMP/home" \
  --trusted-public-key "$PINNED_SIGNING_PUBLIC" >/dev/null
CSR_SECRETS_HOME="$TMP/home" /usr/bin/python3 -I -B \
  "$REPO/bin/lib/secrets_tool.py" fixperms "$MANIFEST" >/dev/null
/usr/bin/python3 -I -B "$REPO/bin/materialize-secret-projections.py" \
  --home "$TMP/home" --migrate-vnu-legacy --migrate-remote-bridge-legacy \
  --migrate-aas-legacy
/usr/bin/python3 -I -B "$REPO/bin/verify-skill-credentials.py" \
  --home "$TMP/home" --repository "$REPO" \
  --output "$TMP/home/.config/coding-system/skill-credential-source-contract.json"

mkdir -p "$OUT_ROOT"
[[ -d "$OUT_ROOT" && ! -L "$OUT_ROOT" ]] \
  || { echo "ERROR: unsafe recovery-set output root" >&2; exit 2; }
OUT_ROOT="$(cd -- "$OUT_ROOT" && pwd -P)"
read -r out_uid out_mode < <(stat -c '%u %a' -- "$OUT_ROOT")
[[ "$out_uid" == "$(id -u)" && $((8#$out_mode & 8#022)) -eq 0 ]] || {
  echo "ERROR: recovery-set output root must be owned by the caller and not group/world writable" >&2
  exit 2
}
if [[ -n "$(safe_release_git -C "$REPO" status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "ERROR: repository worktree/index is not clean; cannot bind the imported set to HEAD" >&2
  exit 2
fi
/usr/bin/bash -p "$REPO/bin/verify-published-head.sh"
/usr/bin/python3 -I -B "$REPO/bin/verify-recovery-release.py"
COMMIT="$(safe_release_git -C "$REPO" rev-parse --verify 'HEAD^{commit}')"
NONCE="$(tr -d '-' < /proc/sys/kernel/random/uuid | cut -c1-16)"
SET_ID="csr-legacy-$(date -u +%Y%m%dt%H%M%Sz)-$NONCE"
FINAL_SET_DIR="$OUT_ROOT/$SET_ID"
SET_DIR="$OUT_ROOT/.stage-$SET_ID"
SET_PUBLISHED=0
[[ ! -e "$FINAL_SET_DIR" && ! -L "$FINAL_SET_DIR" \
    && ! -e "$SET_DIR" && ! -L "$SET_DIR" ]] || {
  echo "ERROR: imported recovery-set generation path already exists" >&2
  exit 2
}
cleanup_set() {
  if [[ "$SET_PUBLISHED" == 0 ]]; then
    case "$SET_DIR" in
      "$OUT_ROOT"/.stage-csr-legacy-*) [[ ! -L "$SET_DIR" ]] && rm -rf -- "$SET_DIR" ;;
      *) echo "ERROR: refusing unsafe incomplete imported-set cleanup" >&2 ;;
    esac
  fi
}
trap 'cleanup_set; rm -rf "$TMP"' EXIT
python3 "$REPO/bin/lib/recovery_tool.py" create-set \
  --manifest "$MANIFEST" \
  --source-home "$TMP/home" \
  --output-dir "$SET_DIR" \
  --master-key-file "$MASTER_KEY_FILE" \
  --escrow-manifest "$ESCROW_GENERATION" \
  --component-commit "$COMMIT" \
  --set-id "$SET_ID"
/usr/bin/bash -p "$REPO/bin/sign-recovery-set.sh" "$SET_DIR"
mv -T --no-clobber -- "$SET_DIR" "$FINAL_SET_DIR"
python3 - "$OUT_ROOT" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
SET_PUBLISHED=1
SET_DIR="$FINAL_SET_DIR"

echo "Legacy ZIP imported into a signed recovery set: $SET_DIR"
echo "The source ZIP remains labeled legacy-incomplete and is never a restore input."
