#!/usr/bin/env bash
set -euo pipefail

DEST="${CSR_OWNER_RCLONE_DEST:-dropbox:Misc/coding-system-backups/openclaw-owner}"
[[ "${CSR_NO_OFFSITE:-0}" == "1" ]] && { echo "owner offsite: disabled"; exit 0; }
command -v rclone >/dev/null \
  || { echo "owner offsite: ERROR rclone is unavailable" >&2; exit 3; }

ARCHIVE="${1:-}"
[[ -n "$ARCHIVE" ]] \
  || ARCHIVE="$(ls -1t "$HOME"/openclaw-backups/openclaw-private-*.tar.gz.gpg 2>/dev/null | head -1 || true)"
[[ -n "$ARCHIVE" && -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] \
  || { echo "owner offsite: ERROR no safe owner-data archive" >&2; exit 5; }

remote="${DEST%%:*}:"
rclone listremotes 2>/dev/null | grep -qx "$remote" \
  || { echo "owner offsite: ERROR remote '$remote' is unavailable" >&2; exit 4; }
rclone copy --no-traverse "$ARCHIVE" "$DEST/"
echo "owner offsite: synced $(basename "$ARCHIVE") -> $DEST"

# Keep the newest two, plus the newest archive from each older calendar month.
rclone lsf "$DEST/" 2>/dev/null \
  | grep '^openclaw-private-[0-9]\{8\}T[0-9]\{6\}Z\.tar\.gz\.gpg$' \
  | sort -r \
  | awk '
      {
        month=substr($0, 18, 6)
        if (NR <= 2) { seen[month]=1; next }
        if (!(month in seen)) { seen[month]=1; next }
        print
      }' \
  | while IFS= read -r obsolete; do
      rclone deletefile "$DEST/$obsolete"
      echo "owner offsite: pruned $obsolete"
    done
