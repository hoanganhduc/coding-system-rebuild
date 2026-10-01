#!/usr/bin/env bash
# Verify one descriptor-captured recovery signature tuple against the pinned
# repository trust root. The Python helper reads key/signature/manifest once.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SET_DIR="${RECOVERY_SET:-${1:-}}"

[[ -n "$SET_DIR" ]] \
  || { echo "verify-recovery-signature: RECOVERY_SET is required" >&2; exit 2; }

ARGS=(authenticate-signature --set-dir "$SET_DIR")
if [[ -n "${CSR_EXPECTED_RECOVERY_COMMIT:-}" ]]; then
  ARGS+=(--expected-component-commit "$CSR_EXPECTED_RECOVERY_COMMIT")
fi
exec /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
  "$REPO/bin/lib/recovery_tool.py" "${ARGS[@]}"
