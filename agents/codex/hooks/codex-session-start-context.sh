#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
Codex workflow reminders:
- Use ~/.codex/instructions/research-quick-actions.md for Claude-to-Codex command mapping and runtime command patterns.
- For deep research, keep stable S1..SN source ids, run Zotero cross-checks for paper-like sources, and preserve verification status in the final report.
- After failures, corrections, or non-obvious workarounds, consider logging durable learnings with self_improving_agent.
EOF
