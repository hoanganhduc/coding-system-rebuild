#!/usr/bin/env bash
# Unattended backup driver (cron). Reads the zip password from the password
# file, runs `make backup`, logs, and sends a Telegram alert on failure.
# Push is NOT automated unless CSR_AUTO_PUSH=1 (decision: manual review).
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="$HOME/.config/coding-system/backup.log"
PWFILE="$HOME/.config/coding-system/zip-password.txt"
RCLONE_DEST="${CSR_RCLONE_DEST:-dropbox:Misc/coding-system-backups}"
mkdir -p "$(dirname "$LOG")"

offsite_sync() {
  # upload the newest zip (ciphertext only) and keep the newest 5 remotely;
  # zip names embed UTC timestamps, so lexicographic sort == chronological
  command -v rclone >/dev/null || { echo "offsite: rclone not installed — skipped"; return 0; }
  local newest
  newest=$(ls -t "$HOME"/secrets-out/coding-system-secrets-*.zip 2>/dev/null | head -1)
  [ -n "$newest" ] || { echo "offsite: no local zip"; return 0; }
  if rclone copy --no-traverse "$newest" "$RCLONE_DEST/" 2>>"$LOG"; then
    echo "offsite: synced $(basename "$newest") -> $RCLONE_DEST"
    rclone lsf "$RCLONE_DEST/" 2>/dev/null | grep '^coding-system-secrets-.*\.zip$' \
      | sort -r | tail -n +6 \
      | while read -r f; do rclone delete "$RCLONE_DEST/$f" && echo "offsite: pruned $f"; done
  else
    echo "offsite: rclone copy FAILED"
    notify_fail
  fi
}

notify_fail() {
  # shellcheck disable=SC1090
  [ -f "$HOME/.secrets.env" ] && . "$HOME/.secrets.env"
  [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ] && \
    curl -s -m 20 "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
      -d chat_id="${TELEGRAM_CHAT_ID}" \
      -d text="coding-system auto-backup FAILED on $(hostname) at $(date -u +%FT%TZ) — see ~/.config/coding-system/backup.log" \
      >/dev/null || true
}

{
  echo "=== auto-backup $(date -u +%FT%TZ) ==="
  if [ ! -s "$PWFILE" ]; then
    # graceful degradation: capture + commit the public part; zip needs the
    # owner's password (run `make secrets-pack` manually after secret changes)
    echo "NOTE: no password file — running public capture only (zip skipped)"
    if make -C "$REPO" backup-public; then
      echo "auto-backup (public-only) OK — remember: secrets zip not refreshed"
      offsite_sync
      exit 0
    else
      echo "auto-backup (public-only) FAILED"
      notify_fail
      exit 1
    fi
  fi
  if CSR_SECRETS_PASSWORD="$(cat "$PWFILE")" make -C "$REPO" backup; then
    echo "auto-backup OK"
    if [ "${CSR_AUTO_PUSH:-0}" = "1" ] && git -C "$REPO" remote get-url origin >/dev/null 2>&1; then
      make -C "$REPO" push && echo "auto-push OK" || { echo "auto-push FAILED"; notify_fail; }
    fi
    # prune zips: keep 5 newest
    ls -t "$HOME"/secrets-out/coding-system-secrets-*.zip 2>/dev/null | tail -n +6 | xargs -r rm -f
    offsite_sync
  else
    echo "auto-backup FAILED"
    notify_fail
    exit 1
  fi
} >> "$LOG" 2>&1
