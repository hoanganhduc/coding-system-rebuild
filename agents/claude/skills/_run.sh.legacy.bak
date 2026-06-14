#!/bin/bash
# Claude Code skill runner — self-contained version
# Usage: _run.sh <script> [args...]

CLAUDE_HOME="${CLAUDE_HOME:-$HOME/.claude}"

export OPENCLAW_WORKSPACE="${OPENCLAW_WORKSPACE:-$CLAUDE_HOME}"
export PYTHONPATH="$CLAUDE_HOME/.local:${HOME}/.local/lib/python3.12/site-packages:$PYTHONPATH"
export OPENCLAW_SECRETS_FILE="${OPENCLAW_SECRETS_FILE:-$CLAUDE_HOME/secrets.json}"
export PATH="$HOME/.local/bin:$CLAUDE_HOME/.local/bin:$CLAUDE_HOME/.local/venv_getscipapers/bin:$HOME/.venvs/bin:$PATH"

cd "$CLAUDE_HOME" || exit 1

script="$1"; shift
if [[ "$script" != /* ]]; then
    script="$CLAUDE_HOME/$script"
fi

exec bash "$script" "$@"
