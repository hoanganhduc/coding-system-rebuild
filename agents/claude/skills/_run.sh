#!/bin/bash
# Claude Code skill runner — self-contained version
# Usage: _run.sh <script> [args...]

CLAUDE_HOME="${CLAUDE_HOME:-$HOME/.claude}"

export OPENCLAW_WORKSPACE="${OPENCLAW_WORKSPACE:-$CLAUDE_HOME}"
export PYTHONPATH="$CLAUDE_HOME/.local:${HOME}/.local/lib/python3.12/site-packages:$PYTHONPATH"
export OPENCLAW_SECRETS_FILE="${OPENCLAW_SECRETS_FILE:-$CLAUDE_HOME/secrets.json}"
# ai-agents-skills convention secrets var: point AAS-aware skills (e.g. zotero, whose
# newer config prefers AAS_SECRETS_FILE) at the unified secrets file. Unconditional
# override so a session-set skill-specific value (e.g. send-email's) cannot hijack it.
# Scoped to this subprocess; send-email uses its own runner + SEND_EMAIL_SECRETS_FILE,
# so it is unaffected.
export AAS_SECRETS_FILE="$OPENCLAW_SECRETS_FILE"
export PATH="$HOME/.local/bin:$CLAUDE_HOME/.local/bin:$CLAUDE_HOME/.local/venv_getscipapers/bin:$HOME/.venvs/bin:$PATH"

cd "$CLAUDE_HOME" || exit 1

# The research_compute broker (modal-research-compute) is delivered by the
# ai-agents-skills installer to the runtime root and runs via run_skill.sh, which
# sets up the runtime workspace + PYTHONPATH. Forward broker invocations there so
# the documented `_run.sh skills/modal-research-compute/...` call reaches the
# installer-managed code; all other skills keep the in-place behavior below.
# GitHub Actions ToS compliance: the broker's gha lane runs only inside a private
# research repo's own committed experiment code (parameters are data, never
# executed), is budget-gated, and is the last automatic backend after local and
# Modal -- never a general compute pool.
if [[ "$1" == skills/modal-research-compute/* ]]; then
    runtime="${AAS_RUNTIME_ROOT:-$HOME/.local/share/ai-agents-skills/runtime}"
    if [[ -x "$runtime/run_skill.sh" ]]; then
        exec bash "$runtime/run_skill.sh" "$@"
    fi
fi

script="$1"; shift
if [[ "$script" != /* ]]; then
    script="$CLAUDE_HOME/$script"
fi

exec bash "$script" "$@"
