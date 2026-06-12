#!/usr/bin/env bash
# Pack all secrets-manifest entries into ONE AES-256 zip.
# Usage: bin/secrets-pack.sh [OUT_DIR]      (default ~/secrets-out)
# Env:   CSR_SECRETS_PASSWORD (else interactive double-entry prompt)
#        ALLOW_MISSING=1 demotes missing required entries to warnings
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO/secrets/secrets-manifest.yaml"
OUT_DIR="${1:-$HOME/secrets-out}"
SEVENZ="$(command -v 7zz || command -v 7z || true)"
[[ -n "$SEVENZ" ]] || { echo "ERROR: no 7zz/7z binary — apt install 7zip (and 7zip-standalone if available)" >&2; exit 2; }

PW="${CSR_SECRETS_PASSWORD:-}"
if [[ -z "$PW" ]]; then
  read -rs -p "Secrets zip password: " PW; echo
  read -rs -p "Repeat password: " PW2; echo
  [[ "$PW" == "$PW2" ]] || { echo "ERROR: passwords differ" >&2; exit 2; }
  [[ ${#PW} -ge 8 ]] || { echo "ERROR: password too short (>=8)" >&2; exit 2; }
fi

# refresh pack metadata (sha256s) into its live location so it rides in the zip
mkdir -p "$HOME/.config/coding-system"
python3 "$REPO/bin/lib/secrets_tool.py" meta "$MANIFEST" > "$HOME/.config/coding-system/secrets-meta.json"
chmod 600 "$HOME/.config/coding-system/secrets-meta.json"

# build file list (mktemp 0600, deleted on exit)
LIST="$(mktemp)"; chmod 600 "$LIST"
trap 'rm -f "$LIST"' EXIT
python3 "$REPO/bin/lib/secrets_tool.py" expand "$MANIFEST" > "$LIST"
N=$(wc -l < "$LIST")
[[ "$N" -gt 0 ]] || { echo "ERROR: empty file list" >&2; exit 2; }

mkdir -p "$OUT_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
ZIP="$OUT_DIR/coding-system-secrets-$STAMP.zip"
( cd "$HOME" && "$SEVENZ" a -tzip -mem=AES256 -mx=5 -p"$PW" "$ZIP" "@$LIST" >/dev/null )
chmod 600 "$ZIP"
"$SEVENZ" t -p"$PW" "$ZIP" >/dev/null || { echo "ERROR: archive integrity test failed" >&2; exit 2; }

# listing-vs-manifest check (zip filenames are not encrypted in zip format)
MISS=$("$SEVENZ" l -ba -slt -p"$PW" "$ZIP" | sed -n 's/^Path = //p' | sort | comm -23 <(sort "$LIST") -)
if [[ -n "$MISS" ]]; then
  echo "ERROR: files missing from archive:" >&2; echo "$MISS" >&2; exit 2
fi
echo "packed $N files -> $ZIP"
echo "REMINDER: store the password in your password manager; loss = unrecoverable."
