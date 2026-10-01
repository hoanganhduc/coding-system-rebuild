#!/usr/bin/env bash
# Unattended public capture plus recovery-set/owner-data backup when safe.
# A recovery set is never bound to an unpublished commit. Push remains opt-in.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STATE="$HOME/.config/coding-system"
LOG="$STATE/backup.log"
MASTER="$STATE/recovery-master.key"
ESCROW="$STATE/escrow/current/escrow-generation.json"
OWNER_PASSPHRASE="$STATE/openclaw-owner-backup-passphrase.txt"
mkdir -p "$STATE"
chmod 700 "$STATE"

notify_fail() {
  # Best-effort notification. Credential values are parsed inside one isolated
  # process and never enter shell variables, environment, argv, or logs.
  /usr/bin/python3 -I -B - "$REPO/bin/lib" <<'PY' >/dev/null 2>&1 || true
import json
import os
from pathlib import Path
import socket
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, sys.argv[1])
from owner_settings import OwnerSettingsError, read_owner_private_bytes, read_owner_settings

home = Path(os.environ["HOME"])
try:
    owner = read_owner_settings(home / ".secrets.env", required=True)
    raw = read_owner_private_bytes(
        home / ".config/ai-agents-skills/secrets.json",
        required=True,
        max_bytes=1024 * 1024,
    )
    authority = json.loads(raw)
except (OwnerSettingsError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
    raise SystemExit(0)
chat = owner.get("TELEGRAM_CHAT_ID")
token = authority.get("TELEGRAM_BOT_TOKEN") if isinstance(authority, dict) else None
if not isinstance(chat, str) or not chat or not isinstance(token, str) or not token:
    raise SystemExit(0)
message = (
    "coding-system auto-backup FAILED on "
    f"{socket.gethostname()} at {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} "
    "— see ~/.config/coding-system/backup.log"
)
payload = urllib.parse.urlencode(
    {"chat_id": chat, "text": message}
).encode("ascii")
urllib.request.urlopen(
    urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage", data=payload, method="POST"
    ),
    timeout=20,
).read(1)
PY
}

owner_snapshot() {
  [[ -s "$OWNER_PASSPHRASE" && ! -L "$OWNER_PASSPHRASE" ]] || {
    echo "owner-data snapshot SKIPPED: protected owner-data passphrase is unavailable"
    return 0
  }
  local snapshot_dir newest free_gb
  snapshot_dir="$HOME/openclaw-backups"
  newest="$(ls -1t "$snapshot_dir"/openclaw-private-*.tar.gz.gpg 2>/dev/null | head -1 || true)"
  if [[ -n "$newest" && -z "$(find "$newest" -mtime +6 -print 2>/dev/null)" ]]; then
    echo "owner-data snapshot fresh (<6 days) — skipped"
    return 0
  fi
  free_gb="$(df -BG --output=avail "$HOME" | tail -1 | tr -dc '0-9')"
  [[ "${free_gb:-0}" -ge 5 ]] || {
    echo "owner-data snapshot FAILED: only ${free_gb:-0}GB free (<5GB guard)"
    return 1
  }
  make -C "$REPO" components >/dev/null 2>&1 || {
    echo "owner-data snapshot FAILED: component refresh failed"
    return 1
  }
  local openclaw_component
  openclaw_component="$(/usr/bin/python3 -I -B \
    "$REPO/bin/lib/component_paths.py" --repository "$REPO" --home "$HOME" \
    --require openclaw-bot)" || {
    echo "owner-data snapshot FAILED: immutable OpenClaw component is unavailable"
    return 1
  }
  OPENCLAW_BACKUP_PASSPHRASE_FILE="$OWNER_PASSPHRASE" \
    /usr/bin/bash -p "$openclaw_component/backup.sh" \
      --output "$snapshot_dir" --verify || return 1
  newest="$(ls -1t "$snapshot_dir"/openclaw-private-*.tar.gz.gpg | head -1)"
  bash "$REPO/bin/offsite-owner-sync.sh" "$newest" || return 1
  echo "owner-data snapshot + offsite readback OK"
}

status=0
{
  echo "=== auto-backup $(date -u +%FT%TZ) ==="
  if ! make -C "$REPO" backup-public; then
    echo "auto-backup FAILED: public capture/commit"
    status=1
  else
    echo "public capture/commit OK"
  fi

  if ((status == 0)) && [[ "${CSR_AUTO_PUSH:-0}" == "1" ]]; then
    if make -C "$REPO" push; then
      echo "opt-in public push OK"
    else
      echo "auto-backup FAILED: opt-in public push"
      status=1
    fi
  fi

  if ((status == 0)); then
    if [[ ! -s "$MASTER" || ! -f "$ESCROW" || -L "$MASTER" || -L "$ESCROW" ]]; then
      echo "recovery set PENDING: recovery master/current escrow generation unavailable"
      status=1
    elif /usr/bin/bash -p "$REPO/bin/verify-published-head.sh" >/dev/null 2>&1; then
      if /usr/bin/bash -p "$REPO/bin/secrets-pack.sh" \
          && /usr/bin/bash "$REPO/bin/offsite-sync.sh"; then
        echo "signed recovery set + immutable offsite readback OK"
      else
        echo "auto-backup FAILED: recovery-set creation or offsite readback"
        status=1
      fi
    else
      echo "recovery set PENDING: HEAD is not the published upstream tip"
      echo "review the public commit, run make push, then make secrets-pack && make offsite"
      status=1
    fi
  fi

  if ! owner_snapshot; then
    echo "auto-backup FAILED: owner-data snapshot/offsite"
    status=1
  fi

  if ((status == 0)); then
    echo "auto-backup COMPLETE"
  else
    echo "auto-backup INCOMPLETE"
  fi
} >>"$LOG" 2>&1

if ((status != 0)); then
  notify_fail
fi
exit "$status"
