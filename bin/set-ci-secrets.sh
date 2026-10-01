#!/usr/bin/env bash
# Set the GitHub Actions key secrets the rehearsal workflow uses, sourced from
# the live deployed config. Values are encrypted client-side by gh; never printed.
#   bash bin/set-ci-secrets.sh [--dry-run] [--repo OWNER/REPO]
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v gh >/dev/null || { echo "ERROR: gh CLI not found" >&2; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "ERROR: gh not authenticated (run: gh auth login)" >&2; exit 2; }
exec python3 "$REPO/bin/lib/set_ci_secrets.py" "$@"
