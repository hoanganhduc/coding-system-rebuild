#!/usr/bin/env bash
set -euo pipefail
BASE="{{ HOME }}/.openclaw/workspace/skills/rss-news-digest"
DIGEST_DIR="{{ HOME }}/.openclaw/workspace/data/research/rss/digests"
# SESSION_DIR may be set by the caller; otherwise use the most recent session folder
SESSION_DIR=${SESSION_DIR:-$(ls -td {{ HOME }}/.openclaw/workspace/data/sessions/* 2>/dev/null | head -n1)}
if [ -z "$SESSION_DIR" ]; then
  SESSION_DIR="{{ HOME }}/.openclaw/workspace/data/sessions/unspecified_session"
  mkdir -p "$SESSION_DIR"
fi
SUMMARY="${SESSION_DIR}/last-summary.md"
# Resolve Python: prefer skill-local venv, then shared venv, then system python3
if [[ -x "${BASE}/.venv/bin/python" ]]; then
  PYTHON="${BASE}/.venv/bin/python"
elif [[ -x "{{ HOME }}/.venvs/bin/python" ]]; then
  PYTHON="{{ HOME }}/.venvs/bin/python"
else
  PYTHON="python3"
fi

# Run the digest for all tags and prioritize ai_research profile
"${PYTHON}" "${BASE}/rss_news_digest.py" run --all-tags --profile ai_research

# Build a short summary (top 5 lines per tag: title + url if present)
rm -f "${SUMMARY}" || true
echo "# RSS Digest Summary - $(date -u +'%Y-%m-%d %H:%M:%S UTC')" > "${SUMMARY}"
for f in "${DIGEST_DIR}"/rss-*.md; do
  [ -f "$f" ] || continue
  tag=$(basename "$f" .md | sed 's/^rss-//')
  # Skip the aggregate file to avoid double-counting items
  [[ "$tag" == "all" ]] && continue
  printf '\n## %s\n' "${tag}" >> "${SUMMARY}"
  # Extract up to 5 item titles (lines like "## 1. Title") and their links
  grep -E "^## [0-9]+\." "$f" | sed 's/^## [0-9]*\. /- /' | sed -n '1,5p' >> "${SUMMARY}" || true
done

# Also copy last summary to timestamped file for history
ts=$(date -u +"%Y%m%dT%H%M%SZ")
cp "${SUMMARY}" "${DIGEST_DIR}/summary-${ts}.md" || true
cp "${SUMMARY}" "${SESSION_DIR}/summary-${ts}.md" || true

# Print path for callers
echo "WROTE_SUMMARY:${SUMMARY}"
