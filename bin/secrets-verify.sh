#!/usr/bin/env bash
# Verify secrets against the manifest. Never prints values.
# Usage: bin/secrets-verify.sh            -> check live $HOME (presence + perms)
#        bin/secrets-verify.sh ZIPFILE    -> check archive listing
#        bin/secrets-verify.sh --degraded -> markdown missing->feature table
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO/secrets/secrets-manifest.yaml"

case "${1:-}" in
  --degraded)
    python3 "$REPO/bin/lib/secrets_tool.py" degraded "$MANIFEST" ;;
  "")
    python3 "$REPO/bin/lib/secrets_tool.py" verify "$MANIFEST" ;;
  *)
    SEVENZ="$(command -v 7zz || command -v 7z)" || { echo "need 7zz/7z" >&2; exit 2; }
    "$SEVENZ" l -ba -slt "$1" | sed -n 's/^Path = //p' \
      | python3 "$REPO/bin/lib/secrets_tool.py" verify-zip "$MANIFEST" ;;
esac
