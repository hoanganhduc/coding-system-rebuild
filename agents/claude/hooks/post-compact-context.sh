#!/usr/bin/env bash
# PostCompact hook: re-inject critical research context after compaction.
# Content is static — always output regardless of working directory.
set -euo pipefail

cat <<'EOF'
Post-compaction context refresh:
- Document lookup order: Zotero → Calibre → online (MANDATORY)
- Paper ingest: arXiv items must be itemType "manuscript", always assign collection
- Multi-result: show numbered list, ask user to pick, use --index N
- Math format: $$...$$ inline, ```math block. Never $...$ or \(...\)
- Skills runner: bash ~/.claude/skills/_run.sh skills/<skill>/run_<skill>.sh <args>
- zot.sh get takes a search query + --index, NEVER a Zotero key
- Always test changes before reporting done
EOF
