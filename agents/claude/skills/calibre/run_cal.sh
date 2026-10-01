#!/usr/bin/env bash
# Wrapper that sets PYTHONPATH and runs cal.py
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"

# Resolve workspace: /workspace inside sandbox → host path via OPENCLAW_WORKSPACE
if [[ -n "${OPENCLAW_WORKSPACE:-}" ]]; then
  WORKSPACE="$OPENCLAW_WORKSPACE"
elif [[ -d "{{ HOME }}/.openclaw/workspace" ]]; then
  WORKSPACE="{{ HOME }}/.openclaw/workspace"
else
  WORKSPACE="/workspace"
fi

# Install deps to workspace-local site-packages (persisted across sessions)
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
SITE_PACKAGES="$WORKSPACE/.local/lib/python${PY_VER}/site-packages"
if [[ ! -d "$SITE_PACKAGES/googleapiclient" ]]; then
  pip install -q --target="$SITE_PACKAGES" -r "$SKILL_DIR/requirements.txt" 2>/dev/null || true
fi

export PYTHONPATH="$SITE_PACKAGES:$SKILL_DIR:${PYTHONPATH:-}"
export OPENCLAW_WORKSPACE="$WORKSPACE"
export OPENCLAW_SECRETS_FILE="${OPENCLAW_SECRETS_FILE:-$WORKSPACE/.secrets.json}"

exec python3 "$SKILL_DIR/cal.py" "$@"
