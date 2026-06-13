#!/usr/bin/env bash
# Fail if any tracked file that discusses GitHub Actions AS A COMPUTE BACKEND lacks the
# canonical ToS notice. Ordinary CI usage (rehearsal.yml, the blog's Jekyll build, the
# Codespaces install-degraded build) does NOT match the markers and is not flagged.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NOTICE="GitHub Actions ToS compliance"
MARKERS='gha_inrepo|github_actions_backend|experiment runner|offload[^.]*to[^.]*[Aa]ctions|[Aa]ctions[^.]*as[^.]*comput|github-actions-offload'
SELF="bin/tos-notice-check.sh"

fail=0; checked=0
while IFS= read -r rel; do
  [ "$rel" = "$SELF" ] && continue
  f="$REPO/$rel"
  grep -qiE "$MARKERS" "$f" 2>/dev/null || continue
  checked=$((checked + 1))
  if ! grep -q "$NOTICE" "$f" 2>/dev/null; then
    echo "MISSING ToS notice (mentions GHA-as-compute): $rel"
    fail=1
  fi
done < <(git -C "$REPO" ls-files '*.md' '*.py' '*.sh' '*.yml' '*.yaml')

echo "tos-notice-check: scanned $checked compute-backend file(s) -> $([ $fail -eq 0 ] && echo OK || echo FAIL)"
exit $fail
