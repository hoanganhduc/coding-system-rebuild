#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ASSISTANT_HOME="${VNTHUQUAN_ASSISTANT_HOME:-${CLAUDE_HOME:-$HOME/.claude}}"

export VNTHUQUAN_TARGET="${VNTHUQUAN_TARGET:-remote-claude}"
export VNTHUQUAN_ASSISTANT_HOME="$ASSISTANT_HOME"
export VNTHUQUAN_SOURCE_DIR="${VNTHUQUAN_SOURCE_DIR:-{{ HOME }}/vnthuquan}"
export VNTHUQUAN_CALIBRE_RUNNER="${VNTHUQUAN_CALIBRE_RUNNER:-$ASSISTANT_HOME/skills/_run.sh}"
export VNTHUQUAN_CALIBRE_SCRIPT="${VNTHUQUAN_CALIBRE_SCRIPT:-skills/calibre/run_cal.sh}"
export VNTHUQUAN_CALIBRE_CACHE_PATH="${VNTHUQUAN_CALIBRE_CACHE_PATH:-$ASSISTANT_HOME/data/calibre/cache/library.json}"

exec python3 "$SCRIPT_DIR/vnthuquan_wrapper.py" "$@"
