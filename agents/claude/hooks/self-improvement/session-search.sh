#!/usr/bin/env bash
# Session-logs search — search prior Claude Code and OpenClaw conversations
# Usage:
#   session-search.sh <query>                     — search all sources
#   session-search.sh <query> --source claude      — Claude Code only
#   session-search.sh <query> --source openclaw    — OpenClaw only
#   session-search.sh <query> --recent N           — last N days only (default: all)
#   session-search.sh <query> --context N          — lines of context (default: 1)
#   session-search.sh --list                       — list all sessions with dates and first prompt
#   session-search.sh --list --source claude       — list Claude Code sessions only
set -uo pipefail

CLAUDE_DIR="$HOME/.claude/projects/-home-ubuntu"
OPENCLAW_DIR="$HOME/.openclaw/agents/main/sessions"

QUERY=""
SOURCE="all"
RECENT_DAYS=0
CONTEXT=1
LIST_MODE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE="$2"; shift 2 ;;
    --recent) RECENT_DAYS="$2"; shift 2 ;;
    --context) CONTEXT="$2"; shift 2 ;;
    --list) LIST_MODE=true; shift ;;
    *) QUERY="$1"; shift ;;
  esac
done

# ── List mode ──────────────────────────────────────────────
if [[ "$LIST_MODE" == "true" ]]; then
  if [[ "$SOURCE" != "openclaw" ]]; then
    echo "=== Claude Code Sessions ($(ls "$CLAUDE_DIR"/*.jsonl 2>/dev/null | wc -l) files) ==="
    for f in "$CLAUDE_DIR"/*.jsonl; do
      [[ -f "$f" ]] || continue
      sid=$(basename "$f" .jsonl)
      # Get date from first user message timestamp or file mtime
      info=$(python3 -c "
import json, datetime
with open('$f') as fh:
    for line in fh:
        d = json.loads(line)
        if d.get('type') == 'user':
            msg = d.get('message', {})
            content = msg.get('content', '')
            if isinstance(content, list):
                text = ' '.join(c.get('text','') for c in content if c.get('type')=='text')
            else:
                text = str(content)
            text = text.replace('\n', ' ')[:80]
            print(text)
            break
" 2>/dev/null)
      mdate=$(date -r "$f" '+%Y-%m-%d %H:%M' 2>/dev/null)
      printf "  %s  %s  %s\n" "$mdate" "${sid:0:8}" "${info:-(no prompt)}"
    done
  fi

  if [[ "$SOURCE" != "claude" ]]; then
    echo ""
    echo "=== OpenClaw Sessions ($(ls "$OPENCLAW_DIR"/*.jsonl 2>/dev/null | wc -l) files) ==="
    for f in "$OPENCLAW_DIR"/*.jsonl; do
      [[ -f "$f" ]] || continue
      sid=$(basename "$f" .jsonl)
      info=$(python3 -c "
import json
with open('$f') as fh:
    for line in fh:
        d = json.loads(line)
        if d.get('type') == 'message':
            msg = d.get('message', {})
            if msg.get('role') == 'user':
                content = msg.get('content', [])
                if isinstance(content, list):
                    text = ' '.join(c.get('text','') for c in content if isinstance(c,dict) and c.get('type')=='text')
                else:
                    text = str(content)
                text = text.replace('\n', ' ')[:80]
                if not text.startswith('[cron:'):
                    print(text)
                    break
" 2>/dev/null)
      mdate=$(date -r "$f" '+%Y-%m-%d %H:%M' 2>/dev/null)
      printf "  %s  %s  %s\n" "$mdate" "${sid:0:8}" "${info:-(cron/system)}"
    done
  fi
  exit 0
fi

# ── Search mode ────────────────────────────────────────────
if [[ -z "$QUERY" ]]; then
  echo "Usage: session-search.sh <query> [--source claude|openclaw|all] [--recent N] [--context N]"
  echo "       session-search.sh --list [--source claude|openclaw]"
  exit 1
fi

# Build find time filter
FIND_TIME_ARGS=""
if [[ "$RECENT_DAYS" -gt 0 ]]; then
  FIND_TIME_ARGS="-mtime -${RECENT_DAYS}"
fi

results=0

# ── Search Claude Code sessions ────────────────────────────
if [[ "$SOURCE" == "all" || "$SOURCE" == "claude" ]]; then
  echo "=== Claude Code Sessions ==="
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    sid=$(basename "$f" .jsonl)
    # Extract text content from user and assistant messages, search with context
    matches=$(python3 -c "
import json, re, sys
query = sys.argv[1].lower()
ctx = int(sys.argv[2])
hits = []
with open('$f') as fh:
    for line in fh:
        d = json.loads(line)
        if d.get('type') not in ('user', 'assistant'):
            continue
        msg = d.get('message', {})
        role = msg.get('role', '')
        content = msg.get('content', '')
        if isinstance(content, list):
            texts = []
            for c in content:
                if isinstance(c, dict):
                    if c.get('type') == 'text':
                        texts.append(c['text'])
                    elif c.get('type') == 'tool_use':
                        texts.append(f'[tool: {c.get(\"name\",\"\")}]')
            text = '\n'.join(texts)
        else:
            text = str(content)
        lines = text.split('\n')
        for i, line_text in enumerate(lines):
            if query in line_text.lower():
                start = max(0, i - ctx)
                end = min(len(lines), i + ctx + 1)
                snippet = '\n'.join(lines[start:end]).strip()
                if len(snippet) > 300:
                    snippet = snippet[:300] + '...'
                hits.append(f'  [{role}] {snippet}')
if hits:
    print(f'\\n  Session: ${sid:0:8}...')
    for h in hits[:5]:
        print(h)
    if len(hits) > 5:
        print(f'  ... and {len(hits)-5} more matches')
    sys.exit(0)
sys.exit(1)
" "$QUERY" "$CONTEXT" 2>/dev/null) && {
      echo "$matches"
      results=$((results + 1))
    }
  done < <(find "$CLAUDE_DIR" -maxdepth 1 -name "*.jsonl" $FIND_TIME_ARGS 2>/dev/null | sort -r)
fi

# ── Search OpenClaw sessions ──────────────────────────────
if [[ "$SOURCE" == "all" || "$SOURCE" == "openclaw" ]]; then
  echo ""
  echo "=== OpenClaw Sessions ==="
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    sid=$(basename "$f" .jsonl)
    matches=$(python3 -c "
import json, sys
query = sys.argv[1].lower()
ctx = int(sys.argv[2])
hits = []
with open('$f') as fh:
    for line in fh:
        d = json.loads(line)
        if d.get('type') != 'message':
            continue
        msg = d.get('message', {})
        role = msg.get('role', '')
        if role not in ('user', 'assistant'):
            continue
        content = msg.get('content', [])
        if isinstance(content, list):
            texts = []
            for c in content:
                if isinstance(c, dict) and c.get('type') == 'text':
                    texts.append(c['text'])
            text = '\n'.join(texts)
        else:
            text = str(content)
        lines = text.split('\n')
        for i, line_text in enumerate(lines):
            if query in line_text.lower():
                start = max(0, i - ctx)
                end = min(len(lines), i + ctx + 1)
                snippet = '\n'.join(lines[start:end]).strip()
                if len(snippet) > 300:
                    snippet = snippet[:300] + '...'
                hits.append(f'  [{role}] {snippet}')
if hits:
    print(f'\\n  Session: ${sid:0:8}...')
    for h in hits[:5]:
        print(h)
    if len(hits) > 5:
        print(f'  ... and {len(hits)-5} more matches')
    sys.exit(0)
sys.exit(1)
" "$QUERY" "$CONTEXT" 2>/dev/null) && {
      echo "$matches"
      results=$((results + 1))
    }
  done < <(find "$OPENCLAW_DIR" -maxdepth 1 -name "*.jsonl" $FIND_TIME_ARGS 2>/dev/null | sort -r)
fi

echo ""
echo "Total: $results sessions with matches for '$QUERY'"
