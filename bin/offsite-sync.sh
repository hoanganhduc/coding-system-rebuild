#!/usr/bin/env bash
# Upload an encrypted secrets zip off-machine via rclone and keep the newest 5.
#   bin/offsite-sync.sh [ZIPFILE]      (default: newest in ~/secrets-out)
# Env:
#   CSR_RCLONE_DEST  rclone remote:path  (default dropbox:Misc/coding-system-backups)
#   CSR_NO_OFFSITE=1 skip entirely (returns 0)
# The zip is AES-256 ciphertext; the remote only ever sees encrypted data.
set -uo pipefail
DEST="${CSR_RCLONE_DEST:-dropbox:Misc/coding-system-backups}"

# Exit code contract (consistent): 0 = uploaded OK, or explicitly disabled.
# Any "asked to sync but could not" condition is non-zero so callers/CI see it.
#   0 success or CSR_NO_OFFSITE=1   3 rclone missing   4 remote not configured
#   5 no zip to upload              6 rclone copy failed
[[ "${CSR_NO_OFFSITE:-0}" == "1" ]] && { echo "offsite: disabled (CSR_NO_OFFSITE=1)"; exit 0; }
command -v rclone >/dev/null || { echo "offsite: ERROR rclone not installed (set CSR_NO_OFFSITE=1 to opt out)" >&2; exit 3; }

ZIP="${1:-}"
[[ -n "$ZIP" ]] || ZIP=$(ls -t "$HOME"/secrets-out/coding-system-secrets-*.zip 2>/dev/null | head -1)
[[ -n "$ZIP" && -f "$ZIP" ]] || { echo "offsite: ERROR no zip to upload" >&2; exit 5; }

# verify the remote exists before trying (clear error if misconfigured)
remote="${DEST%%:*}:"
rclone listremotes 2>/dev/null | grep -qx "$remote" || {
  echo "offsite: ERROR rclone remote '$remote' not configured (rclone listremotes)" >&2; exit 4; }

if rclone copy --no-traverse "$ZIP" "$DEST/"; then
  echo "offsite: synced $(basename "$ZIP") -> $DEST"
  # zip names embed UTC timestamps -> lexicographic sort == chronological; keep newest 5
  rclone lsf "$DEST/" 2>/dev/null | grep '^coding-system-secrets-.*\.zip$' \
    | sort -r | tail -n +6 \
    | while read -r f; do rclone delete "$DEST/$f" && echo "offsite: pruned $f"; done
else
  echo "offsite: ERROR rclone copy FAILED" >&2; exit 6
fi
