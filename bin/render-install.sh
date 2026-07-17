#!/usr/bin/env bash
# Render repo artifacts into a home directory ({{ HOME }} substituted). A real
# render also installs and validates grok-proxy's immutable user/root release;
# --render-only retains the offline manifest copy and performs no sudo action.
# Usage: bin/render-install.sh [--home DIR] [--render-only]
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$REPO/bin/lib/render_install.py" --repo "$REPO" "$@"
