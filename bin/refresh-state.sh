#!/usr/bin/env bash
# Refresh machine-derived state files in the repo (run by `make backup`, step 1).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$REPO/system/packages"
mkdir -p "$PKG/requirements" "$REPO/system/cron"

echo "-- npm globals"
npm ls -g --depth=0 --json 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
for name,info in sorted(d.get("dependencies",{}).items()):
    print("%s@%s" % (name, info.get("version","")))' > "$PKG/npm-globals.txt"

echo "-- pipx packages"
if command -v pipx >/dev/null; then
  pipx list --json 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
for name,meta in sorted(d.get("venvs",{}).items()):
    pkg=meta["metadata"]["main_package"]
    print("%s==%s" % (pkg["package"], pkg["package_version"]))' > "$PKG/pipx.txt" || true
fi

echo "-- pip freezes (4 environments)"
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
echo "python $PYV" > "$PKG/requirements/PYTHON_VERSION"
python3 -m pip freeze --path "$HOME/.openclaw/workspace/.local" \
  > "$PKG/requirements/workspace-local.txt" 2>/dev/null || echo "WARN: workspace-local freeze failed"
[ -x "$HOME/.venvs/bin/pip" ] && "$HOME/.venvs/bin/pip" freeze \
  > "$PKG/requirements/venvs.txt" 2>/dev/null || true
[ -x "$HOME/.local/share/docling-venv/bin/pip" ] && "$HOME/.local/share/docling-venv/bin/pip" freeze \
  > "$PKG/requirements/docling-venv.txt" 2>/dev/null || true
LE="$HOME/.codex/runtime/workspace/.venvs/lean-explore/bin/pip"
[ -x "$LE" ] && "$LE" freeze > "$PKG/requirements/lean-explore.txt" 2>/dev/null || true

echo "-- crontab template"
{ echo "# coding-system crontab template ({{ HOME }} substituted at install)"
  crontab -l 2>/dev/null | sed "s|$HOME|{{ HOME }}|g"
} > "$REPO/system/cron/crontab.template"

echo "-- units.state"
: > "$REPO/system/systemd/units.state"
for u in openclaw-gateway.service send-queue-worker.service \
         rss_news_digest_bot.service rss_news_digest_bot.timer \
         moltbook-relay.service moltbook-relay.timer xvfb-99.service; do
  state=$(systemctl --user is-enabled "$u" 2>/dev/null) || true
  [[ -n "$state" ]] || state="absent"
  printf '%s\t%s\n' "$u" "$state" >> "$REPO/system/systemd/units.state"
done

echo "-- docker image drift check (docker-images.txt is hand-curated)"
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  while IFS='|' read -r img cond; do
    [[ -z "$img" || "$img" == \#* ]] && continue
    docker image inspect "$img" >/dev/null 2>&1 || echo "WARN: pinned image not present locally: $img"
  done < "$PKG/docker-images.txt"
fi

echo "-- component drift"
while IFS='=' read -r name rest; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  ref="${rest##*@}"
  if [[ "$ref" == LOCAL:* ]]; then
    path="${ref#LOCAL:}"; path="${path/#\~/$HOME}"
    if [[ -d "$path/.git" ]]; then
      dirty=$(git -C "$path" status --porcelain 2>/dev/null | wc -l)
      [[ "$dirty" -gt 0 ]] && echo "WARN: component $name has $dirty uncommitted changes at $path"
    else
      echo "WARN: component $name at $path is not a git repo yet (publish pending)"
    fi
  fi
done < "$REPO/components.lock"
echo "refresh-state: done"
