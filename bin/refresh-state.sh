#!/usr/bin/env bash
# Refresh machine-derived state files in the repo (run by `make backup`, step 1).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$REPO/system/packages"
mkdir -p "$PKG/requirements" "$REPO/system/cron"
mkdir -p "$REPO/.staging"
REFRESH_LEDGER="$REPO/.staging/refresh-output-paths.nul"
REFRESH_RECORDS="$REPO/.staging/refresh-output-records.json"
: > "$REFRESH_LEDGER"
/usr/bin/rm -f -- "$REFRESH_RECORDS"
record_output() {
  /usr/bin/chmod 0644 -- "$REPO/$1"
  printf '%s\0' "$1" >> "$REFRESH_LEDGER"
}

echo "-- npm globals"
npm ls -g --depth=0 --json 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
for name,info in sorted(d.get("dependencies",{}).items()):
    print("%s@%s" % (name, info.get("version","")))' > "$PKG/npm-globals.txt"
record_output system/packages/npm-globals.txt

echo "-- pipx packages"
if command -v pipx >/dev/null; then
  pipx list --json 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
for name,meta in sorted(d.get("venvs",{}).items()):
    pkg=meta["metadata"]["main_package"]
    print("%s==%s" % (pkg["package"], pkg["package_version"]))' > "$PKG/pipx.txt" || true
  record_output system/packages/pipx.txt
fi

echo "-- pip freezes (4 environments)"
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
echo "python $PYV" > "$PKG/requirements/PYTHON_VERSION"
record_output system/packages/requirements/PYTHON_VERSION
python3 -m pip freeze --path "$HOME/.openclaw/workspace/.local" \
  > "$PKG/requirements/workspace-local.txt" 2>/dev/null || echo "WARN: workspace-local freeze failed"
record_output system/packages/requirements/workspace-local.txt
if [ -x "$HOME/.venvs/bin/pip" ]; then
  "$HOME/.venvs/bin/pip" freeze > "$PKG/requirements/venvs.txt" 2>/dev/null || true
  record_output system/packages/requirements/venvs.txt
fi
if [ -x "$HOME/.local/share/docling-venv/bin/pip" ]; then
  "$HOME/.local/share/docling-venv/bin/pip" freeze \
    > "$PKG/requirements/docling-venv.txt" 2>/dev/null || true
  record_output system/packages/requirements/docling-venv.txt
fi
LE="$HOME/.codex/runtime/workspace/.venvs/lean-explore/bin/pip"
if [ -x "$LE" ]; then
  "$LE" freeze > "$PKG/requirements/lean-explore.txt" 2>/dev/null || true
  record_output system/packages/requirements/lean-explore.txt
fi

echo "-- crontab template"
{ echo "# coding-system crontab template ({{ HOME }} substituted at install)"
  crontab -l 2>/dev/null | sed "s|$HOME|{{ HOME }}|g"
} > "$REPO/system/cron/crontab.template"
record_output system/cron/crontab.template

echo "-- units.state"
: > "$REPO/system/systemd/units.state"
for u in openclaw-gateway.service send-queue-worker.service syncthing.service \
         rss_news_digest_bot.service rss_news_digest_bot.timer \
         moltbook-relay.service moltbook-relay.timer xvfb-99.service; do
  state=$(systemctl --user is-enabled "$u" 2>/dev/null) || true
  [[ -n "$state" ]] || state="absent"
  printf '%s\t%s\n' "$u" "$state" >> "$REPO/system/systemd/units.state"
done
record_output system/systemd/units.state

echo "-- docker image drift check (docker-images.txt is hand-curated)"
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  host_arch="$(uname -m)"; case "$host_arch" in aarch64|arm64) host_arch=arm64;; x86_64|amd64) host_arch=amd64;; esac
  while IFS='|' read -r img cond; do
    [[ -z "$img" || "$img" == \#* ]] && continue
    cond="${cond//[[:space:]]/}"
    # Pins are multi-arch; only flag the one matching this host's arch (a $HOST_arch-only VM will
    # legitimately not have the other-arch image).
    [[ -n "$cond" && "$cond" != any && "$cond" != "$host_arch" ]] && continue
    docker image inspect "$img" >/dev/null 2>&1 || echo "WARN: pinned image not present locally: $img"
  done < "$PKG/docker-images.txt"
fi

echo "-- component drift"
# SHA-pinned components: if the live checkout at ~/<name> has moved past the
# pin AND its HEAD is pushed to origin, bump the pin in components.lock so a
# restore reproduces the current system. Unpushed or dirty HEADs only warn.
COMPONENTS_CHANGED=0
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
          COMPONENTS_CHANGED=1
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
if [[ "$COMPONENTS_CHANGED" -eq 1 ]]; then
  record_output components.lock
fi
/usr/bin/python3 -I -B "$REPO/bin/lib/write_output_records.py" \
  --repo "$REPO" --ledger "$REFRESH_LEDGER" --output "$REFRESH_RECORDS"
echo "refresh-state: done"
