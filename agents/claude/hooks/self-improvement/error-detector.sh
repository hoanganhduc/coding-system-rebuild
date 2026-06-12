#!/usr/bin/env bash
# Error detector — PostToolUse hook for Bash
# Scans tool output for error patterns and suggests logging.
# Input: JSON on stdin with tool_name, tool_input, tool_response, etc.
set -euo pipefail

# Read limited stdin — tool_response can be huge after large file reads.
# Only read first 8KB which is enough to find error patterns near the top.
INPUT=$(head -c 8192)
[[ -z "$INPUT" ]] && exit 0

# Extract tool response/output from JSON — use lightweight approach
PY=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)
if [[ -n "$PY" ]]; then
  OUTPUT=$(echo "$INPUT" | "$PY" -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    resp = d.get('tool_response', d.get('tool_output', ''))
    if isinstance(resp, dict):
        resp = resp.get('stdout', '') + resp.get('stderr', '') + resp.get('output', '')
    print(str(resp)[:4096])
except:
    pass
" 2>/dev/null || echo "")
else
  # Fallback: scan the raw input for error patterns directly
  OUTPUT="$INPUT"
fi

[[ -z "$OUTPUT" ]] && exit 0

# Check for error patterns
if echo "$OUTPUT" | grep -qiE '(error:|Error:|FATAL|fatal:|Traceback|Exception|ModuleNotFoundError|TypeError|ImportError|Permission denied|No such file|command not found|npm ERR!|SyntaxError|NameError|KeyError|ValueError|FileNotFoundError)'; then
  cat <<EOF
<self-improvement-error-detected>
An error was detected in the command output. After resolving this error, consider logging it:
  File: ~/.claude/learnings/ERRORS.md
  Format: [ERR-$(date -u +%Y%m%d)-XXX] with Summary, Error, Context, Suggested Fix
  Include Pattern-Key if this is a recurring error type.
</self-improvement-error-detected>
EOF
fi
