#!/usr/bin/env bash
# Publish one encrypted owner-data archive immutably and stream-check readback.
set -euo pipefail

REPO="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
DEST="${CSR_OWNER_RCLONE_DEST:-}"
[[ "${CSR_NO_OFFSITE:-0}" != "1" ]] || { echo "owner offsite: disabled"; exit 0; }
[[ -n "$DEST" ]] || DEST="$(/usr/bin/python3 -I -B "$REPO/bin/lib/owner_settings.py" get \
  --key CSR_OWNER_RCLONE_DEST --path "$HOME/.secrets.env")" \
  || { echo "owner offsite: the owner settings file is invalid" >&2; exit 2; }
[[ -n "$DEST" ]] \
  || { echo "owner offsite: set CSR_OWNER_RCLONE_DEST (an owner setting) to the rclone destination" >&2; exit 2; }
command -v rclone >/dev/null 2>&1 \
  || { echo "owner offsite: rclone is unavailable" >&2; exit 3; }

ARCHIVE="${1:-}"
[[ -n "$ARCHIVE" ]] \
  || ARCHIVE="$(ls -1t "$HOME"/openclaw-backups/openclaw-private-*.tar.gz.gpg 2>/dev/null | head -1 || true)"
[[ -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] \
  || { echo "owner offsite: no safe owner-data archive" >&2; exit 5; }
base="$(basename -- "$ARCHIVE")"
[[ "$base" =~ ^openclaw-private-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.gpg$ ]] \
  || { echo "owner offsite: archive name is not canonical" >&2; exit 2; }

remote_name="${DEST%%:*}:"
rclone listremotes | grep -Fqx -- "$remote_name" \
  || { echo "owner offsite: remote $remote_name is unavailable" >&2; exit 4; }
rclone lsd "$DEST" >/dev/null \
  || { echo "owner offsite: destination is unreadable: $DEST" >&2; exit 4; }
remote_object="$DEST/$base"
if rclone lsjson "$remote_object" --stat >/dev/null 2>&1; then
  echo "owner offsite: refusing to overwrite immutable object: $remote_object" >&2
  exit 2
fi
rclone copyto "$ARCHIVE" "$remote_object" --immutable --no-traverse
local_hash="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
remote_hash="$(rclone cat "$remote_object" | sha256sum | cut -d' ' -f1)"
[[ "$remote_hash" == "$local_hash" ]] \
  || { echo "owner offsite: remote readback digest mismatch" >&2; exit 2; }
echo "owner offsite: immutable upload/readback verified: $remote_object"
