#!/usr/bin/env bash
# PreCompact hook: logs context size before compaction.
# Exit 0 = allow compaction. Exit 2 = block compaction.
set -euo pipefail

# Log compaction event (useful for debugging context thrash)
echo "Context compaction triggered at $(date -Iseconds)" >> /tmp/claude-compact.log 2>/dev/null || true

# Allow compaction (exit 0). To block, exit 2.
exit 0
