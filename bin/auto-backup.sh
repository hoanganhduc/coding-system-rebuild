#!/usr/bin/env bash
# Unattended backup driver (cron). Reads the zip password from the password
# file, runs `make backup`, logs, and sends a Telegram alert on failure.
# Push is NOT automated unless CSR_AUTO_PUSH=1 (decision: manual review).
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="$HOME/.config/coding-system/backup.log"
PWFILE="$HOME/.config/coding-system/zip-password.txt"
mkdir -p "$(dirname "$LOG")"

# `make backup` -> secrets-pack -> bin/offsite-sync.sh already uploads the zip,
# so the full-backup path needs no separate upload. The public-only fallback
# makes no zip and has nothing to sync.

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
      exit 0
    else
      echo "auto-backup (public-only) FAILED"
      notify_fail
      exit 1
    fi
  fi
  if CSR_SECRETS_PASSWORD="$(cat "$PWFILE")" make -C "$REPO" backup; then
    echo "auto-backup OK"
    # Owner-data snapshot (research data, sessions, memory, workspace git):
    # age-gated so any trigger cadence self-heals to at most one per 6 days.
    # Uses the same passphrase file as the zip; keeps the newest 2 archives.
    SNAP_DIR="$HOME/openclaw-backups"
    NEWEST="$(ls -1t "$SNAP_DIR"/openclaw-private-*.tar.gz.gpg 2>/dev/null | head -1)"
    if [ -z "$NEWEST" ] || [ -n "$(find "$NEWEST" -mtime +6 2>/dev/null)" ]; then
      FREE_GB=$(df -BG --output=avail "$HOME" | tail -1 | tr -dc '0-9')
      if [ "${FREE_GB:-0}" -lt 5 ]; then
        echo "data-snapshot SKIPPED: only ${FREE_GB}GB free (<5GB guard)"
        notify_fail
      elif ! make -C "$REPO" components >/dev/null 2>&1; then
        echo "data-snapshot FAILED: external component refresh failed"
        notify_fail
      elif OPENCLAW_BACKUP_PASSPHRASE_FILE="$PWFILE" \
           bash "$REPO/external/openclaw-bot/backup.sh" --output "$SNAP_DIR" --verify; then
        echo "data-snapshot OK"
        ls -1t "$SNAP_DIR"/openclaw-private-*.tar.gz.gpg 2>/dev/null | tail -n +3 | xargs -r rm -f
      else
        echo "data-snapshot FAILED"
        notify_fail
      fi
    else
      echo "data-snapshot fresh (<6 days) — skipped"
    fi
    # passphrase escrow: idempotent 2-of-N Shamir redistribution (re-escrows
    # automatically after rotation; upgrades 2-of-3 -> 2-of-4 when gdrive returns)
    if bash "$REPO/bin/escrow-passphrase.sh" ensure; then
      echo "escrow OK"
    else
      echo "escrow FAILED"
      notify_fail
    fi
    if [ "${CSR_AUTO_PUSH:-0}" = "1" ] && git -C "$REPO" remote get-url origin >/dev/null 2>&1; then
      make -C "$REPO" push && echo "auto-push OK" || { echo "auto-push FAILED"; notify_fail; }
    fi
    # prune local zips: keep 3 newest plus one newest snapshot per month
    # (offsite upload + remote prune done by
    # secrets-pack -> offsite-sync during `make backup`)
    ls -t "$HOME"/secrets-out/coding-system-secrets-*.zip 2>/dev/null \
      | awk '
          {
            file=$0; base=file; sub(/^.*\//, "", base)
            month=""
            if (match(base, /^coding-system-secrets-([0-9]{6})[0-9]{2}T/)) {
              month=substr(base, RSTART + 22, 6)
            }
            if (NR <= 3) {
              if (month != "") seen[month]=1
              next
            }
            if (month != "" && !(month in seen)) {
              seen[month]=1
              next
            }
            print file
          }' \
      | xargs -r rm -f
  else
    echo "auto-backup FAILED"
    notify_fail
    exit 1
  fi
} >> "$LOG" 2>&1
