#!/usr/bin/env bash
# Manifest-driven capture: live system -> sanitized public tree.
# Usage: bin/sync.sh [--apply] [--manifest FILE]
# Dry-run (default) renders into .staging/ and never touches the repo trees.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLY=0
MANIFEST="$REPO/MANIFEST.yaml"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --dry-run) APPLY=0; shift ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

ARGS=(--repo "$REPO" --manifest "$MANIFEST")
if [[ "$APPLY" -eq 1 ]]; then
  ARGS+=(--apply)
else
  rm -rf "$REPO/.staging"
fi
python3 "$REPO/bin/lib/manifest_sync.py" "${ARGS[@]}"
rc=$?

# openclaw-bot awareness check (component owns ~/.openclaw public sync)
OCB="${OPENCLAW_BOT_DIR:-$HOME/openclaw-bot}"
if [[ -x "$OCB/sync.sh" ]]; then
  echo "--- openclaw-bot sync awareness (dry-run) ---"
  if ! "$OCB/sync.sh" --dry-run >/dev/null 2>&1; then
    echo "WARN: openclaw-bot sync.sh --dry-run reported issues (run it directly for details)"
  else
    echo "openclaw-bot dry-run: clean"
  fi
else
  echo "WARN: openclaw-bot component not found at $OCB"
fi
exit $rc
