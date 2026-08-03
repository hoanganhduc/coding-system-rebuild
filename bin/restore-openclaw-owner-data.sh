#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 OPENCLAW_PRIVATE_ARCHIVE [PREFIX]" >&2
}

[[ $# -ge 1 && $# -le 2 ]] || { usage; exit 2; }
ARCHIVE="$1"
PREFIX="${2:-$HOME/.openclaw}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESTORE="$REPO/external/openclaw-bot/restore.sh"

[[ -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] \
  || { echo "owner-data restore: archive is missing or unsafe: $ARCHIVE" >&2; exit 2; }
[[ -x "$RESTORE" ]] \
  || { echo "owner-data restore: pinned component restore helper is unavailable" >&2; exit 2; }
if [[ -n "${OPENCLAW_BACKUP_PASSPHRASE_FILE:-}" ]]; then
  [[ -f "$OPENCLAW_BACKUP_PASSPHRASE_FILE" && ! -L "$OPENCLAW_BACKUP_PASSPHRASE_FILE" ]] \
    || { echo "owner-data restore: passphrase file is missing or unsafe" >&2; exit 2; }
fi

bash "$RESTORE" \
  --archive "$ARCHIVE" \
  --prefix "$PREFIX" \
  --overlay-only \
  --skip-services
echo "owner-data restore: verified overlay installed"
