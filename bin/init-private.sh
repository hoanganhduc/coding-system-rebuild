#!/usr/bin/bash -p
# One-time (idempotent) private-side initialization on the SOURCE machine.
# Performs the source-machine mutations required before the first recovery backup:
#   (a) install a 7-Zip CLI (7zip + 7zip-standalone when available)
#   (b) migrate bounded legacy exports into data-only owner settings and
#       dedicated credential authorities, then verify the offline closure
#   (c) create + seed ~/.config/coding-system/leak-denylist.txt from live IDs
#   (d) record systemd user-unit enable states into system/systemd/units.state
#   (e) create/migrate the separately encrypted owner-data passphrase
#   (f) verify the pinned recovery signing authority
#   (g) create/publish/select an immutable 2-of-4 escrow generation
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT \
  LD_PRELOAD LD_LIBRARY_PATH GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM
IFS=$' \t\n'
REPO="$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

case "${1:-}" in
  -h|--help|help)
    /usr/bin/printf '%s\n' \
      "usage: bin/init-private.sh" \
      "Initialize source-only recovery authorities, capture state, and publish escrow." \
      "This command is idempotent but may install 7-Zip and publish escrow shares."
    exit 0
    ;;
  "") ;;
  *)
    /usr/bin/printf 'init-private: unsupported argument: %s\n' "$1" >&2
    exit 2
    ;;
esac

echo "== (a) 7-Zip CLI =="
if command -v 7zz >/dev/null || command -v 7z >/dev/null; then
  echo "already present: $(command -v 7zz || command -v 7z)"
else
  if /usr/bin/sudo -n true 2>/dev/null; then
    /usr/bin/sudo /usr/bin/apt-get install -y 7zip >/dev/null
    /usr/bin/sudo /usr/bin/apt-get install -y 7zip-standalone >/dev/null 2>&1 || true
    echo "installed: $(command -v 7zz || command -v 7z)"
  else
    echo "ERROR: need sudo to apt install 7zip — run: sudo apt-get install -y 7zip" >&2
    exit 2
  fi
fi

echo "== (b) bounded owner/credential migration =="
/usr/bin/python3 -I -B "$REPO/bin/migrate-owner-settings.py" --home "$HOME"
/usr/bin/python3 -I -B "$REPO/bin/materialize-secret-projections.py" \
  --home "$HOME" --migrate-vnu-legacy --migrate-remote-bridge-legacy \
  --migrate-aas-legacy
/usr/bin/python3 -I -B "$REPO/bin/lib/owner_settings.py" validate \
  --path "$HOME/.secrets.env"
/usr/bin/bash -n "$HOME/.bashrc" \
  || { echo "ERROR: bashrc syntax broken — restore ~/.bashrc.pre-coding-system" >&2; exit 2; }
/usr/bin/python3 -I -B "$REPO/bin/verify-skill-credentials.py" \
  --home "$HOME" --repository "$REPO" \
  --output "$HOME/.config/coding-system/skill-credential-verification.json"
echo "owner settings are data-only; bounded credential authorities resolve offline"

echo "== (c) leak denylist =="
/usr/bin/python3 -I -B "$REPO/bin/lib/init_private_state.py" ensure-directory \
  --path "$HOME/.config/coding-system"
DL="$HOME/.config/coding-system/leak-denylist.txt"
/usr/bin/python3 -I -B "$REPO/bin/lib/init_private_state.py" seed-denylist \
  --home "$HOME" --path "$DL"

echo "== (d) systemd units.state =="
/usr/bin/mkdir -p "$REPO/system/systemd"
units_state="$REPO/system/systemd/units.state"
units_state_tmp=$(/usr/bin/mktemp "$REPO/system/systemd/.units.state.XXXXXXXX")
cleanup_units_state() { /usr/bin/rm -f -- "$units_state_tmp"; }
trap cleanup_units_state EXIT
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
  active=$(/usr/bin/systemctl --user is-active "$unit" 2>/dev/null) || true
  if [[ "$active" == active ]]; then
    echo active
    return
  fi
  result=$(/usr/bin/systemctl --user show --property Result --value "$unit" 2>/dev/null) || true
  if [[ "$active" == inactive && "$result" == success ]]; then
    echo successful-oneshot
  else
    echo inactive
  fi
}
for u in openclaw-gateway.service send-queue-worker.service \
         openclaw-zulip-delivery-worker.service \
         openclaw-zalo-delivery-worker.service \
         openclaw-googlechat-delivery-worker.service \
         openclaw-whatsapp-delivery-worker.service \
         openclaw-sage-worker.service openclaw-manim-worker.service \
         openclaw-email-worker.service \
         syncthing.service grok-remote-boot-revalidate.service \
         rss_news_digest_bot.service rss_news_digest_bot.timer \
         moltbook-relay.service moltbook-relay.timer xvfb-99.service \
         coding-system-scheduler-canary.service \
         coding-system-scheduler-canary.timer; do
  state=$(/usr/bin/systemctl --user is-enabled "$u" 2>/dev/null) || true
  # an "absent" row is rejected by the reconciler, so a unit the manager does not
  # know is reported rather than written into a state file that cannot be replayed.
  if [[ -z "$state" ]]; then
    echo "absent from the user manager — not recorded: $u"
    continue
  fi
  printf '%s\t%s\t%s\n' "$u" "$state" "$(unit_activity "$u" "$state")" \
    >> "$units_state_tmp"
done
/usr/bin/chmod 0644 "$units_state_tmp"
/usr/bin/mv -fT -- "$units_state_tmp" "$units_state"
trap - EXIT
/usr/bin/cat "$units_state"

echo "== (e) owner-data archive authority =="
OWNER_PW="$HOME/.config/coding-system/openclaw-owner-backup-passphrase.txt"
LEGACY_PW="$HOME/.config/coding-system/zip-password.txt"
owner_pw_state=$(/usr/bin/python3 -I -B \
  "$REPO/bin/lib/init_private_state.py" ensure-owner-passphrase \
  --owner "$OWNER_PW" --legacy "$LEGACY_PW")
case "$owner_pw_state" in
  existing) echo "owner-data archive passphrase is present and safe" ;;
  migrated) echo "migrated the historical backup password into the owner-data-only authority" ;;
  generated) echo "generated a new owner-data archive passphrase authority" ;;
  *) echo "ERROR: invalid owner-data passphrase result" >&2; exit 2 ;;
esac

echo "== (f) recovery signing authority =="
SIGNING="$HOME/.config/coding-system/recovery-signing"
TRACKED_PUBLIC="$REPO/system/recovery/recovery-signing-public-key.pub"
/usr/bin/python3 -I -B "$REPO/bin/lib/init_private_state.py" verify-signing \
  --key "$SIGNING" --trusted-public "$TRACKED_PUBLIC" || {
    echo "Restore the signing key from authenticated recovery media; generating a different key would break the pinned Stage-0 trust root." >&2
    exit 2
  }
echo "recovery signing authority matches the pinned Stage-0 trust root"

echo "== (g) immutable 2-of-4 recovery escrow =="
ESCROW_ROOT="$HOME/.config/coding-system/escrow"
MASTER="$HOME/.config/coding-system/recovery-master.key"
CURRENT="$ESCROW_ROOT/current"
/usr/bin/python3 -I -B "$REPO/bin/lib/init_private_state.py" ensure-directory \
  --path "$ESCROW_ROOT"
master_present=0
if [[ -e "$MASTER" || -L "$MASTER" ]]; then
  /usr/bin/python3 -I -B "$REPO/bin/lib/init_private_state.py" \
    verify-private-file --path "$MASTER" --max-bytes 8192 --nonempty
  master_present=1
fi
if [[ "$master_present" -eq 0 ]]; then
  generation="$ESCROW_ROOT/generation-$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)"
  /usr/bin/bash -p "$REPO/bin/escrow-passphrase.sh" create-and-publish "$generation" "$MASTER" || {
    echo "ERROR: escrow publication did not complete; local shares were retained at $generation" >&2
    echo "Fix rclone/private-GitHub access, then run: bin/escrow-passphrase.sh publish-generation '$generation'" >&2
    exit 2
  }
elif [[ ! -f "$CURRENT/escrow-generation.json" ]]; then
  mapfile -d '' -t pending_generations < <(
    /usr/bin/find -P "$ESCROW_ROOT" -mindepth 2 -maxdepth 2 -type f \
      -name escrow-generation.json -print0
  )
  [[ ${#pending_generations[@]} -eq 1 ]] || {
    echo "ERROR: recovery master exists but no current generation is selected; found ${#pending_generations[@]} candidates" >&2
    exit 2
  }
  generation="$(/usr/bin/dirname -- "${pending_generations[0]}")"
  /usr/bin/bash -p "$REPO/bin/escrow-passphrase.sh" publish-generation "$generation" || exit 2
else
  selected_generation="$(/usr/bin/readlink -f -- "$CURRENT")"
  [[ -n "$selected_generation" ]] || { echo "ERROR: current escrow selector is broken" >&2; exit 2; }
  /usr/bin/bash -p "$REPO/bin/escrow-passphrase.sh" verify-distributed "$selected_generation" || exit 2
fi

echo "init-private: source recovery authorities and capture state are complete"
