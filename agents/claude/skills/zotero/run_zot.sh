#!/bin/bash
# Run zot.py. Deps are in /workspace/.local/ (pip install --target /workspace/.local).
WS="${OPENCLAW_WORKSPACE:-/workspace}"
export PYTHONPATH="$WS/.local:$PYTHONPATH"
exec python3 "$(dirname "$0")/zot.py" "$@"
