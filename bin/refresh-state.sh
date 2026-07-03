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
for u in openclaw-gateway.service send-queue-worker.service syncthing.service \
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
# SHA-pinned components: if the live checkout at ~/<name> has moved past the
# pin AND its HEAD is pushed to origin, bump the pin in components.lock so a
# restore reproduces the current system. Unpushed or dirty HEADs only warn.
while IFS='=' read -r name rest; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  ref="${rest##*@}"
  if [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
    path="$HOME/$name"
    if [[ -d "$path/.git" ]]; then
      head=$(git -C "$path" rev-parse HEAD 2>/dev/null || true)
      dirty=$(git -C "$path" status --porcelain 2>/dev/null | wc -l)
      [[ "$dirty" -gt 0 ]] && echo "WARN: component $name has $dirty uncommitted changes at $path"
      if [[ -n "$head" && "$head" != "$ref" ]]; then
        if [[ -n "$(git -C "$path" branch -r --contains "$head" 2>/dev/null)" ]]; then
          sed -i "s|^$name=\(.*\)@$ref\$|$name=\1@$head|" "$REPO/components.lock"
          echo "pin-bump: $name ${ref:0:9} -> ${head:0:9}"
        else
          echo "WARN: component $name HEAD ${head:0:9} is ahead of pin ${ref:0:9} but NOT pushed — pin left unchanged"
        fi
      fi
    fi
  fi
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
