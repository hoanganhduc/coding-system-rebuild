#!/usr/bin/env bash
# Refresh machine-derived state files in the repo (run by `make backup`, step 1).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$REPO/system/packages"
OBS="$PKG/observed"
mkdir -p "$PKG/requirements" "$OBS/requirements" "$REPO/system/cron"
mkdir -p "$REPO/.staging"
REFRESH_LEDGER="$REPO/.staging/refresh-output-paths.nul"
REFRESH_RECORDS="$REPO/.staging/refresh-output-records.json"
: > "$REFRESH_LEDGER"
/usr/bin/rm -f -- "$REFRESH_RECORDS"
record_output() {
  /usr/bin/chmod 0644 -- "$REPO/$1"
  printf '%s\0' "$1" >> "$REFRESH_LEDGER"
}

echo "-- observed npm globals (release lock is not changed)"
npm ls -g --depth=0 --json 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
for name,info in sorted(d.get("dependencies",{}).items()):
    print("%s@%s" % (name, info.get("version","")))' > "$OBS/npm-globals.txt"
record_output system/packages/observed/npm-globals.txt

echo "-- pipx packages"
if command -v pipx >/dev/null; then
  pipx list --json 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
for name,meta in sorted(d.get("venvs",{}).items()):
    pkg=meta["metadata"]["main_package"]
    print("%s==%s" % (pkg["package"], pkg["package_version"]))' > "$OBS/pipx.txt" || true
  record_output system/packages/observed/pipx.txt
fi

echo "-- pip freezes (4 environments)"
# Prefer a host Python with pip (PATH may put a bare venv without pip first).
: > "$OBS/requirements/workspace-local.txt"
FREEZE_PY="${CSR_FREEZE_PYTHON:-}"
if [[ -z "$FREEZE_PY" ]]; then
  for candidate in /usr/bin/python3.12 /usr/bin/python3.11 /usr/bin/python3 python3; do
    if command -v "$candidate" >/dev/null 2>&1 \
        && "$candidate" -c 'import pip' 2>/dev/null; then
      FREEZE_PY=$(command -v "$candidate")
      break
    fi
  done
fi
if [[ -n "$FREEZE_PY" ]]; then
  PYV=$("$FREEZE_PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])')
  echo "python $PYV" > "$OBS/requirements/PYTHON_VERSION"
  record_output system/packages/observed/requirements/PYTHON_VERSION
  "$FREEZE_PY" -m pip freeze --path "$HOME/.openclaw/workspace/.local" \
    > "$OBS/requirements/workspace-local.txt" 2>/dev/null \
    || echo "WARN: workspace-local freeze failed"
else
  echo "WARN: no Python with pip found for freezes" >&2
fi
record_output system/packages/observed/requirements/workspace-local.txt
if [ -x "$HOME/.venvs/bin/pip" ]; then
  "$HOME/.venvs/bin/pip" freeze > "$OBS/requirements/venvs.txt" 2>/dev/null || true
  record_output system/packages/observed/requirements/venvs.txt
fi
if [ -x "$HOME/.local/share/docling-venv/bin/pip" ]; then
  "$HOME/.local/share/docling-venv/bin/pip" freeze \
    > "$OBS/requirements/docling-venv.txt" 2>/dev/null || true
  record_output system/packages/observed/requirements/docling-venv.txt
fi
LE="$HOME/.codex/runtime/workspace/.venvs/lean-explore/bin/pip"
if [ -x "$LE" ]; then
  "$LE" freeze > "$OBS/requirements/lean-explore.txt" 2>/dev/null || true
  record_output system/packages/observed/requirements/lean-explore.txt
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
         moltbook-relay.service moltbook-relay.timer xvfb-99.service \
         grok-remote-boot-revalidate.service; do
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

echo "-- component drift (release locks are not changed)"
# Backups capture observations but never promote a partial compatibility tuple.
# Promotion occurs only after the complete OpenClaw/component/image candidate
# passes the architecture and runtime gates.
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
          echo "DRIFT: component $name pushed HEAD ${head:0:9} differs from release pin ${ref:0:9}"
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
"$REPO/bin/check-closure-drift.py" --output "$OBS/closure-drift.json"
record_output system/packages/observed/closure-drift.json
/usr/bin/python3 -I -B "$REPO/bin/lib/write_output_records.py" \
  --repo "$REPO" --ledger "$REFRESH_LEDGER" --output "$REFRESH_RECORDS"
echo "refresh-state: done"
