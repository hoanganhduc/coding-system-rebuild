#!/usr/bin/env bash
# Serialize refresh -> capture -> leak scan -> exact commit (and optional secrets).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-public}"
case "$MODE" in
  public|full) ;;
  *) echo "usage: $0 [public|full]" >&2; exit 2 ;;
esac

LOCK_DIR="$HOME/.config/coding-system"
mkdir -p "$LOCK_DIR"
if [[ -L "$LOCK_DIR" || ! -d "$LOCK_DIR" ]]; then
  echo "backup: unsafe lock directory: $LOCK_DIR" >&2
  exit 2
fi
exec 9>"$LOCK_DIR/backup.lock"
if ! flock -n 9; then
  echo "backup: another public/secrets backup transaction is active" >&2
  exit 2
fi

bash "$REPO/bin/refresh-state.sh"
bash "$REPO/bin/sync.sh" --apply
bash "$REPO/bin/leak-scan.sh"
python3 "$REPO/bin/lib/stage_backup.py" \
  --repo "$REPO" \
  --commit-message "backup: $(date -u +%F) — manifest outputs only"

if [[ "$MODE" == full ]]; then
  bash "$REPO/bin/secrets-pack.sh"
  echo "backup complete — review with 'git show', publish with 'make push'"
fi
