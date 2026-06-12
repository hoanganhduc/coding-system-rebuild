#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")" && pwd)"

export CLAUDE_RESEARCH_COMPUTE_WORKSPACE="$ROOT"
export CLAUDE_CALLER_CWD="${CLAUDE_CALLER_CWD:-${OLDPWD:-$PWD}}"
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"

exec python3 "$ROOT/modal_research_compute.py" "$@"
