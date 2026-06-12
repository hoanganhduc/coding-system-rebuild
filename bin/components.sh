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
  dest="$REPO/external/$name"
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
  if [[ ! -d "$dest/.git" ]]; then
    git clone -q "$url" "$dest" || { echo "WARN: clone failed for $name ($url) — skipping (degraded)" >&2; RC=1; continue; }
  else
    git -C "$dest" fetch -q origin || true
  fi
  git -C "$dest" checkout -q "$ref" || { echo "ERROR: cannot checkout $name@$ref" >&2; RC=1; continue; }
  head=$(git -C "$dest" rev-parse HEAD)
  [[ "$head" == "$ref"* ]] && echo "component $name @ $head" || { echo "ERROR: $name HEAD != lock" >&2; RC=1; }
done < "$REPO/components.lock"
exit $RC
