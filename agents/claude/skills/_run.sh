#!/bin/bash
# Claude Code skill runner — self-contained version
# Usage: _run.sh <script> [args...]

CLAUDE_HOME="${CLAUDE_HOME:-$HOME/.claude}"

export OPENCLAW_WORKSPACE="${OPENCLAW_WORKSPACE:-$CLAUDE_HOME}"
export PYTHONPATH="$CLAUDE_HOME/.local:${HOME}/.local/lib/python3.12/site-packages:$PYTHONPATH"
# Skills get credentials only through the managed launcher's own selectors, so a
# broad secrets file or a caller-chosen runtime root never reaches them.
unset OPENCLAW_SECRETS_FILE AAS_SECRETS_FILE
export AAS_RUNTIME_ROOT="$HOME/.local/share/ai-agents-skills/runtime"
export PATH="$HOME/.local/bin:$CLAUDE_HOME/.local/bin:$CLAUDE_HOME/.local/venv_getscipapers/bin:$HOME/.venvs/bin:$PATH"

cd "$CLAUDE_HOME" 2>/dev/null || cd /

# Forward credential-bearing skills through the owner-controlled managed launcher;
# they never fall back to a local copy.
launcher="$AAS_RUNTIME_ROOT/run_skill.sh"
require_launcher() {
  [[ -f "$launcher" && -x "$launcher" && ! -L "$launcher" ]] && return 0
  echo "_run.sh: the shared ai-agents-skills runtime is unavailable: $launcher" >&2
  exit 2
}
case "${1:-}" in
  skills/zotero/*|skills/calibre/*|skills/docling/*|skills/vnthuquan/*|skills/send-email/*|\
  skills/remote-bridge/*|skills/research-digest-wrapper/*|skills/submission-venue-selector/*|\
  skills/lean-research-library/*|skills/lean-explore-mcp/*|skills/axiom-axle-mcp/*|\
  skills/autonomous-research-loop-runtime/*)
    require_launcher
    exec "$launcher" "$@" ;;
  skills/modal-research-compute/*|skills/kaggle-research-compute/*|skills/hetzner-research-compute/*)
    require_launcher
    ws="${AAS_AUTOLOOP_COMPUTE_WORKSPACE:-$HOME/.openclaw/workspace}"
    [ -f "$ws/config/research-compute.toml" ] && cd "$ws"
    AAS_COMPUTE_SECRETS_FILE="${AAS_COMPUTE_SECRETS_FILE:-$HOME/.config/ai-agents-skills/compute.env}" \
      exec "$launcher" "$@" ;;
esac

script="$1"; shift
if [[ "$script" != /* ]]; then
    script="$CLAUDE_HOME/$script"
fi

exec bash "$script" "$@"
