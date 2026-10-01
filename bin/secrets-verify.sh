#!/usr/bin/bash -p
# Verify the live manifest or authenticate/decrypt a recovery set without
# restoring it. Only share file paths are accepted; share values never enter
# argv or environment variables.
set -euo pipefail
if [[ $- != *p* ]]; then
  exec /usr/bin/bash -p "$0" "$@"
fi
umask 077
export PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP \
  LD_PRELOAD LD_LIBRARY_PATH

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO/secrets/secrets-manifest.yaml"

if [[ "${1:-}" == "--degraded" ]]; then
  exec /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$REPO/bin/lib/secrets_tool.py" degraded "$MANIFEST"
fi

SET_DIR="${RECOVERY_SET:-}"
if [[ -z "$SET_DIR" && -n "${1:-}" && -d "${1:-}" ]]; then
  SET_DIR="$1"
fi
if [[ -z "$SET_DIR" ]]; then
  if [[ -n "${1:-}" ]]; then
    echo "ERROR: archive verification now requires a recovery-set directory." >&2
    echo "Legacy ZIPs must use bin/secrets-import-legacy-zip.sh." >&2
    exit 2
  fi
  exec /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$REPO/bin/lib/secrets_tool.py" verify "$MANIFEST"
fi

SHARE_1="${CSR_ESCROW_SHARE_1_FILE:-}"
SHARE_2="${CSR_ESCROW_SHARE_2_FILE:-}"
[[ -n "$SHARE_1" && -n "$SHARE_2" ]] || {
  echo "ERROR: set CSR_ESCROW_SHARE_1_FILE and CSR_ESCROW_SHARE_2_FILE to protected share files" >&2
  exit 2
}

ARGS=(
  validate-set
  --set-dir "$SET_DIR"
  --manifest "$MANIFEST"
  --share-file "$SHARE_1"
  --share-file "$SHARE_2"
)
if [[ -n "${CSR_EXPECTED_RECOVERY_COMMIT:-}" ]]; then
  ARGS+=(--expected-component-commit "$CSR_EXPECTED_RECOVERY_COMMIT")
fi
exec /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
  "$REPO/bin/lib/recovery_tool.py" "${ARGS[@]}"
