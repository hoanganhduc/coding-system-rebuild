#!/usr/bin/env bash
# Self-improvement review — shows pending learnings summary
# Usage: bash ~/.claude/hooks/self-improvement/review.sh [--high-only]
set -uo pipefail

LEARNINGS_DIR="$HOME/.claude/learnings"
HIGH_ONLY="${1:-}"

echo "=== Pending Learnings Review ==="
echo ""

for f in ERRORS.md LEARNINGS.md FEATURE_REQUESTS.md; do
  filepath="$LEARNINGS_DIR/$f"
  [[ -f "$filepath" ]] || continue

  echo "--- $f ---"

  if [[ "$HIGH_ONLY" == "--high-only" ]]; then
    # Show only high/critical pending items
    grep -B10 '^\*\*Status\*\*: pending' "$filepath" 2>/dev/null | \
      grep -B5 'Priority\*\*: \(high\|critical\)' | \
      grep '^## \[' | \
      while read -r line; do
        echo "  $(echo "$line" | sed 's/^## //')"
      done
  else
    # Show all pending items with priority indicators
    grep -B10 '^\*\*Status\*\*: pending' "$filepath" 2>/dev/null | \
      grep '^## \[' | \
      while read -r line; do
        id=$(echo "$line" | sed 's/^## //')
        # Look up priority
        pri=$(grep -A3 "^$line" "$filepath" 2>/dev/null | grep 'Priority' | head -1 | sed 's/.*: //')
        case "$pri" in
          critical) icon="!!" ;;
          high)     icon="! " ;;
          medium)   icon="- " ;;
          *)        icon="  " ;;
        esac
        echo "  $icon $id"
      done
  fi
  echo ""
done

# Counts
total=$(grep -rc '^\*\*Status\*\*: pending' "$LEARNINGS_DIR"/*.md 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
promoted=$(grep -rc '^\*\*Status\*\*: promoted' "$LEARNINGS_DIR"/*.md 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
resolved=$(grep -rc '^\*\*Status\*\*: resolved' "$LEARNINGS_DIR"/*.md 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')

echo "Total: $total pending, $promoted promoted, $resolved resolved"
echo ""
echo "Actions:"
echo "  Resolve:  change **Status**: pending → resolved, add ### Resolution block"
echo "  Promote:  copy distilled rule to CLAUDE.md or memory/, change Status → promoted"
echo "  Log new:  append [TYPE-$(date -u +%Y%m%d)-XXX] entry to the appropriate file"
