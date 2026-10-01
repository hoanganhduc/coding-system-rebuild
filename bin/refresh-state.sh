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

echo "-- units.state"
# Refreshed first, so a user manager that cannot be read stops the refresh before
# any tracked file changes; rows are written to a temporary file and moved in only
# when every unit answered with a state the reconciler can replay.
# activity column, in the vocabulary bin/reconcile-systemd-user-units.sh verifies:
# a disabled unit is restored with `disable --now`, so its activity is inactive
# whatever it happens to be doing now; a oneshot that already exited cleanly reads
# as inactive but is not drift; everything else is judged by is-active alone.
unit_activity() {
  local unit=$1 state=$2 active result
  if [[ "$state" == disabled ]]; then
    echo inactive
    return
  fi
  active=$(systemctl --user is-active "$unit" 2>/dev/null) || true
  if [[ "$active" == active ]]; then
    echo active
    return
  fi
  result=$(systemctl --user show --property Result --value "$unit" 2>/dev/null) || true
  if [[ "$active" == inactive && "$result" == success ]]; then
    echo successful-oneshot
  else
    echo inactive
  fi
}
UNITS_TMP=$(/usr/bin/mktemp "$REPO/system/systemd/.units.state.XXXXXXXX")
CRONTAB_TMP=""
remove_temporary_outputs() {
  [[ -z "$UNITS_TMP" ]] || /usr/bin/rm -f -- "$UNITS_TMP"
  [[ -z "$CRONTAB_TMP" ]] || /usr/bin/rm -f -- "$CRONTAB_TMP"
}
trap remove_temporary_outputs EXIT
units_recorded=0
for u in openclaw-gateway.service send-queue-worker.service \
         openclaw-zulip-delivery-worker.service \
         openclaw-zalo-delivery-worker.service \
         openclaw-googlechat-delivery-worker.service \
         openclaw-whatsapp-delivery-worker.service \
         openclaw-sage-worker.service openclaw-manim-worker.service \
         openclaw-email-worker.service syncthing.service \
         rss_news_digest_bot.service rss_news_digest_bot.timer \
         moltbook-relay.service moltbook-relay.timer xvfb-99.service \
         grok-remote-boot-revalidate.service \
         coding-system-scheduler-canary.service \
         coding-system-scheduler-canary.timer \
         chatgpt-local-coder.service chatgpt-local-coder-tunnel.service \
         chatgpt-local-coder-tunnel-health.service \
         chatgpt-local-coder-tunnel-health.timer exit-forensics.service; do
  state=$(systemctl --user is-enabled "$u" 2>/dev/null) || true
  case "$state" in
    enabled|disabled|static) ;;
    not-found)
      # an "absent" row is rejected by the reconciler, so a unit the manager does
      # not know is reported rather than written into a state file that cannot be
      # replayed.
      echo "   WARN: $u absent from the user manager — not recorded"
      continue
      ;;
    "")
      echo "ERROR: the user service manager did not answer for $u; units.state is unchanged" >&2
      exit 2
      ;;
    *)
      echo "ERROR: $u has enable state '$state', which units.state cannot replay; units.state is unchanged" >&2
      exit 2
      ;;
  esac
  printf '%s\t%s\t%s\n' "$u" "$state" "$(unit_activity "$u" "$state")" \
    >> "$UNITS_TMP"
  units_recorded=$((units_recorded + 1))
done
if (( units_recorded == 0 )); then
  echo "ERROR: no user unit was found; units.state is unchanged" >&2
  exit 2
fi
/usr/bin/chmod 0644 -- "$UNITS_TMP"
/usr/bin/mv -fT -- "$UNITS_TMP" "$REPO/system/systemd/units.state"
UNITS_TMP=""
record_output system/systemd/units.state

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
# Only the public managed block reaches the repository. Lines the owner added by
# hand are private: they are adopted into the owner's private schedule file,
# which the recovery set carries, and restore renders them as their own block.
CRONTAB_TMP=$(/usr/bin/mktemp "$REPO/system/cron/.crontab.template.XXXXXXXX")
{ echo "# coding-system crontab template ({{ HOME }} substituted at install)"
  python3 "$REPO/bin/reconcile-host-schedules.py" --public-block | sed "s|$HOME|{{ HOME }}|g"
} > "$CRONTAB_TMP"
/usr/bin/chmod 0644 -- "$CRONTAB_TMP"
/usr/bin/mv -fT -- "$CRONTAB_TMP" "$REPO/system/cron/crontab.template"
CRONTAB_TMP=""
record_output system/cron/crontab.template
python3 "$REPO/bin/reconcile-host-schedules.py" --adopt-unmanaged
# Private system configuration (web server site, monit) joins the recovery set.
python3 "$REPO/bin/export-system-private.py"
# The host baseline a restored machine is compared with (private, recovery set).
python3 "$REPO/bin/verify-host-diff.py" capture

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
echo "-- promote updated CLIs into the software locks"
# A restore installs what this host ran at its last backup, never an older pin.
python3 "$REPO/bin/promote-installed-clis.py"
record_output system/software/ubuntu-24.04-amd64.lock.json
record_output system/software/ubuntu-24.04-arm64.lock.json
/usr/bin/python3 -I -B "$REPO/bin/lib/write_output_records.py" \
  --repo "$REPO" --ledger "$REFRESH_LEDGER" --output "$REFRESH_RECORDS"
echo "refresh-state: done"
