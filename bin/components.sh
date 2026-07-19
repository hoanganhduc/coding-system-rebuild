#!/usr/bin/env bash
# Materialize pinned components into external/ per components.lock.
#   url@<sha>           -> clone via HTTPS, checkout sha, verify HEAD
#   url@LOCAL:<path>    -> symlink external/<name> to the live checkout (pre-publish mode)
# LOCAL=1 forces live checkouts for ALL components when present.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$REPO/external"
RC=0
while IFS='=' read -r name rest; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  url="${rest%@*}"; ref="${rest##*@}"
  # ai-agents-skills remains at the compatibility path used by existing skill
  # references.  An existing development checkout is never checked out or
  # cleaned here: phase 8 executes a root-owned materialization of the exact
  # pinned object instead of mutable worktree bytes.
  if [[ "$name" == "ai-agents-skills" ]]; then dest="$HOME/$name"; else dest="$REPO/external/$name"; fi
  if [[ "$ref" == LOCAL:* || "${LOCAL:-0}" == "1" ]]; then
    path="${ref#LOCAL:}"; path="${path/#\~/$HOME}"
    if [[ -d "$path" ]]; then
      ln -sfn "$path" "$dest"
      echo "component $name -> live checkout $path"
    else
      echo "WARN: $name live path missing: $path" >&2; RC=1
    fi
    continue
  fi
  if [[ "$name" == "ai-agents-skills" && "$ref" =~ ^[0-9a-f]{40}$ ]]; then
    if [[ -L "$dest" || ( -e "$dest" && ! -d "$dest" ) ]]; then
      echo "ERROR: ai-agents-skills compatibility checkout is unsafe: $dest" >&2
      RC=1
      continue
    fi
    if [[ ! -d "$dest/.git" ]]; then
      /usr/bin/git clone -q "$url" "$dest" \
        || { echo "WARN: clone failed for $name ($url) — skipping (degraded)" >&2; RC=1; continue; }
      /usr/bin/git -C "$dest" checkout -q --detach "$ref" \
        || { echo "ERROR: cannot checkout fresh $name@$ref" >&2; RC=1; continue; }
    elif ! GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git --no-replace-objects \
      -C "$dest" cat-file -e "$ref^{commit}" 2>/dev/null; then
      /usr/bin/git -C "$dest" fetch -q --no-tags origin "$ref" \
        || { echo "ERROR: cannot fetch pinned $name object $ref" >&2; RC=1; continue; }
    fi
    object=$(GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git --no-replace-objects \
      -C "$dest" rev-parse --verify "$ref^{commit}" 2>/dev/null) \
      || { echo "ERROR: cannot resolve pinned $name object" >&2; RC=1; continue; }
    [[ "$object" == "$ref" ]] \
      && echo "component $name object ${ref:0:12} available (worktree preserved)" \
      || { echo "ERROR: $name object != lock" >&2; RC=1; }
    continue
  fi
  if [[ ! -d "$dest/.git" ]]; then
    git clone -q "$url" "$dest" || { echo "WARN: clone failed for $name ($url) — skipping (degraded)" >&2; RC=1; continue; }
  else
    git -C "$dest" fetch -q origin || true
  fi
  git -C "$dest" checkout -q "$ref" || { echo "ERROR: cannot checkout $name@$ref" >&2; RC=1; continue; }
  head=$(git -C "$dest" rev-parse HEAD)
  [[ "$head" == "$ref"* ]] && echo "component $name @ ${head:0:12}" || { echo "ERROR: $name HEAD != lock" >&2; RC=1; }
done < "$REPO/components.lock"
exit $RC
