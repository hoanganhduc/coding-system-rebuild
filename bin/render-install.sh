#!/usr/bin/env bash
# Render repo artifacts into a home directory ({{ HOME }} substituted).
# Usage: bin/render-install.sh [--home DIR] [--render-only]
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$REPO/bin/lib/render_install.py" --repo "$REPO" "$@"
