#!/bin/bash
WS="${OPENCLAW_WORKSPACE:-/workspace}"
export PYTHONPATH="$WS/.local:$PYTHONPATH"
exec python3 "$(dirname "$0")/review.py" "$@"
