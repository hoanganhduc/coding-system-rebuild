#!/usr/bin/env bash
# Self-improvement activator + task router — UserPromptSubmit hook
# 1. Sets session title from first prompt
# 2. Routes research tasks to appropriate system (hook = 100% reliable)
# 3. Injects pending learnings summary
set -euo pipefail

LEARNINGS_DIR="$HOME/.claude/learnings"

# Read hook input from stdin (JSON with session_id, prompt, etc.)
INPUT=$(cat)

# --- Python command (try python3, fall back to python) ---
PY=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)
[[ -z "$PY" ]] && exit 0

# --- Extract prompt and session_id ---
SESSION_ID=$( echo "$INPUT" | "$PY" -c "import json,sys; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null || true)
FULL_PROMPT=$(echo "$INPUT" | "$PY" -c "import json,sys; print(json.load(sys.stdin).get('prompt',''))" 2>/dev/null || true)

# --- Session title (only on first prompt of a session) ---
TITLE_MARKER="/tmp/.claude-session-titled-${SESSION_ID}"

if [[ -n "$SESSION_ID" ]] && [[ ! -f "$TITLE_MARKER" ]]; then
  PROMPT_PREVIEW=$(echo "$FULL_PROMPT" | head -c 60)
  if [[ ${#FULL_PROMPT} -gt 60 ]]; then
    PROMPT_PREVIEW="${PROMPT_PREVIEW}..."
  fi
  if [[ -n "$PROMPT_PREVIEW" ]]; then
    # JSON-escape the prompt preview (quotes, backslashes, control chars)
    ESCAPED=$("$PY" -c "import json,sys; print(json.dumps(sys.stdin.read().strip()))" <<< "$PROMPT_PREVIEW" 2>/dev/null || echo "\"$PROMPT_PREVIEW\"")
    echo "{\"hookSpecificOutput\":{\"hookEventName\":\"UserPromptSubmit\",\"sessionTitle\":${ESCAPED}}}"
    touch "$TITLE_MARKER"
  fi
fi

# --- Task routing (pattern matching) ---
if [[ -n "$FULL_PROMPT" ]]; then
  PROMPT_LOWER=$(echo "$FULL_PROMPT" | tr '[:upper:]' '[:lower:]')

  # Priority 1: Multi-agent triggers → /research-team
  if echo "$PROMPT_LOWER" | grep -qE 'multi-agent review|panel review|deep review|stress-test.*proof|verify.*proof|find holes|attack.*problem|open problem|pre-submission|camera-ready|formalize.*lemma|lean proof|fix sorry'; then

    # Detect template hint
    TEMPLATE=""
    if echo "$PROMPT_LOWER" | grep -qE 'verify.*proof|stress-test|find holes'; then
      TEMPLATE="Lakatos Proof & Refutation"
    elif echo "$PROMPT_LOWER" | grep -qE 'attack.*problem|open problem|explore.*complex'; then
      TEMPLATE="Polya Multi-Strategy"
    elif echo "$PROMPT_LOWER" | grep -qE 'review.*draft|pre-submission|camera-ready|panel review|deep review|multi-agent review'; then
      TEMPLATE="Knuth Manuscript Review"
    elif echo "$PROMPT_LOWER" | grep -qE 'formalize|lean proof|fix sorry'; then
      TEMPLATE="Lean Formalization Team"
    elif echo "$PROMPT_LOWER" | grep -qE 'token slid|token jump|pspace|gadget|reconfiguration'; then
      TEMPLATE="Graph Reconfiguration Specialist"
    fi

    if [[ -n "$TEMPLATE" ]]; then
      echo "<task-routing>Detected: multi-agent research request. Action: Use /research-team skill. Suggested template: ${TEMPLATE}.</task-routing>"
    else
      echo "<task-routing>Detected: multi-agent research request. Action: Use /research-team skill.</task-routing>"
    fi

  # Priority 2: Single-agent triggers → @agent
  elif echo "$PROMPT_LOWER" | grep -qE 'check.*proof|verify.*step|is.*step.*correct|check.*correctness'; then
    echo "<task-routing>Detected: proof verification request. Action: Delegate to @proof-checker agent.</task-routing>"

  elif echo "$PROMPT_LOWER" | grep -qE 'related work|what.*known|literature|find.*papers.*about|survey.*citations|cite|who.*proved'; then
    echo "<task-routing>Detected: literature search request. Action: Delegate to @literature-scout agent.</task-routing>"

  elif echo "$PROMPT_LOWER" | grep -qE 'small cases|counterexample|compute.*chromatic|enumerate.*graph|check.*conjecture|brute.force'; then
    echo "<task-routing>Detected: mathematical exploration request. Action: Delegate to @math-explorer agent.</task-routing>"

  elif echo "$PROMPT_LOWER" | grep -qE 'review.*paper|review.*draft|review.*manuscript'; then
    # Single "review paper" without multi-agent qualifier → single reviewer
    echo "<task-routing>Detected: paper review request. Action: Delegate to @paper-reviewer agent.</task-routing>"
  fi
  # No match → no output, Claude decides on its own
fi

# --- Pending learnings count ---
pending=0
high=0

for f in "$LEARNINGS_DIR"/LEARNINGS.md "$LEARNINGS_DIR"/ERRORS.md "$LEARNINGS_DIR"/FEATURE_REQUESTS.md; do
  [[ -f "$f" ]] || continue
  p=$(grep -c '^\*\*Status\*\*: pending' "$f" 2>/dev/null || true)
  p=${p:-0}
  h=$(grep -B5 '^\*\*Status\*\*: pending' "$f" 2>/dev/null | grep -c 'Priority\*\*: \(high\|critical\)' 2>/dev/null || true)
  h=${h:-0}
  pending=$((pending + p))
  high=$((high + h))
done

if [[ "$pending" -gt 0 ]]; then
  cat <<EOF
<self-improvement-context>
Pending learnings: $pending ($high high/critical priority).
Files: ~/.claude/learnings/{LEARNINGS,ERRORS,FEATURE_REQUESTS}.md

After completing this task, evaluate if extractable knowledge emerged:
- Non-obvious solution discovered through investigation?
- Workaround for unexpected behavior?
- Error required debugging to resolve?
- User correction ("no, that's wrong", "actually it should be...")?

If yes: log to .learnings/ using the ID format [TYPE-YYYYMMDD-XXX].
If recurring (Pattern-Key match, Recurrence-Count >= 3): promote to CLAUDE.md or memory.
</self-improvement-context>
EOF
fi
