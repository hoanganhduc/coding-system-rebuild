#!/usr/bin/env bash
# Upload an encrypted secrets zip off-machine via rclone and keep the 3 newest
# plus one newest snapshot per month.
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
  # zip names embed UTC timestamps -> lexicographic sort == chronological.
  rclone lsf "$DEST/" 2>/dev/null | grep '^coding-system-secrets-.*\.zip$' \
    | sort -r \
    | awk '
        {
          month=""
          if (match($0, /^coding-system-secrets-([0-9]{6})[0-9]{2}T/)) {
            month=substr($0, RSTART + 22, 6)
          }
          if (NR <= 3) {
            if (month != "") seen[month]=1
            next
          }
          if (month != "" && !(month in seen)) {
            seen[month]=1
            next
          }
          print
        }' \
    | while read -r f; do rclone delete "$DEST/$f" && echo "offsite: pruned $f"; done
else
  echo "offsite: ERROR rclone copy FAILED" >&2; exit 6
fi
