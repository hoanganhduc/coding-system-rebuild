#!/usr/bin/env bash
# Restore secrets zip into $HOME (or HOME_OVERRIDE for tests) + permission fixups.
# Usage: SECRETS=/path.zip bin/secrets-restore.sh
# Env:   CSR_SECRETS_PASSWORD (else prompt), HOME_OVERRIDE (roundtrip tests)
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO/secrets/secrets-manifest.yaml"
ZIP="${SECRETS:?usage: SECRETS=/path/to/secrets.zip bin/secrets-restore.sh}"
DEST="${HOME_OVERRIDE:-$HOME}"
SEVENZ="$(command -v 7zz || command -v 7z || true)"
[[ -n "$SEVENZ" ]] || { echo "ERROR: no 7zz/7z — apt install 7zip" >&2; exit 2; }
[[ -f "$ZIP" ]] || { echo "ERROR: archive not found: $ZIP" >&2; exit 2; }

PW="${CSR_SECRETS_PASSWORD:-}"
if [[ -z "$PW" ]]; then read -rs -p "Secrets zip password: " PW; echo; fi

"$SEVENZ" t -p"$PW" "$ZIP" >/dev/null || { echo "ERROR: integrity/password test failed" >&2; exit 2; }
"$SEVENZ" x -y -o"$DEST" -p"$PW" "$ZIP" >/dev/null
if [[ "$DEST" == "$HOME" ]]; then
  python3 "$REPO/bin/lib/secrets_tool.py" fixperms "$MANIFEST"
  echo "--- post-restore verification ---"
  python3 "$REPO/bin/lib/secrets_tool.py" verify "$MANIFEST" || true
else
  ( cd "$DEST" && find . -type f -exec chmod 600 {} + )
  echo "restored into $DEST (test mode; uniform 0600)"
fi
echo "secrets restored from $ZIP"
