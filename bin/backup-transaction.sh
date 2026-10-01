#!/usr/bin/env bash
# Serialize refresh -> capture -> leak scan -> exact public commit.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-public}"
case "$MODE" in
  public) ;;
  full)
    echo "backup: 'full' was unsafe because a new commit cannot be packed before publication" >&2
    echo "Use: make backup-public; review; make push; make secrets-pack; make offsite" >&2
    exit 2
    ;;
  *) echo "usage: $0 public" >&2; exit 2 ;;
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

echo "public backup complete — review with 'git show', then run 'make push' before 'make secrets-pack'"
