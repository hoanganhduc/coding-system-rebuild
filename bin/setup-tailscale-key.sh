#!/usr/bin/bash -p
# One-command Tailscale auth-key setup for the next recovery set.
# Prompts for the key (paste from https://login.tailscale.com/admin/settings/keys:
# Reusable + Pre-approved, NOT ephemeral), writes the raw owner-private authority,
# creates a signed recovery set from the already-published repository HEAD,
# verifies the live authority, and syncs the encrypted set offsite.
set -euo pipefail
if [[ $- != *p* ]]; then
  exec /usr/bin/bash -p "$0" "$@"
fi
umask 077
export PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP \
  LD_PRELOAD LD_LIBRARY_PATH
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Generate the key first (browser): https://login.tailscale.com/admin/settings/keys"
echo "  -> Generate auth key: Reusable=on, Pre-approved=on, Ephemeral=off, expiry up to 90d"
echo
/usr/bin/python3 -I -B "$REPO/bin/configure-tailscale-authority.py"
set +e
/usr/bin/bash -p "$REPO/bin/apply-tailscale-authority.sh" --home "$HOME"
readiness_status=$?
set -e
case "$readiness_status" in
  0) ;;
  1) echo "ERROR: Tailscale rejected or cannot use the configured auth key; reauthentication is required" >&2; exit 1 ;;
  *) echo "ERROR: Tailscale authority could not be verified locally" >&2; exit 2 ;;
esac
echo
echo "Creating a signed immutable recovery set..."
/usr/bin/bash -p "$REPO/bin/secrets-pack.sh"
echo
echo "--- verification ---"
/usr/bin/bash -p "$REPO/bin/secrets-verify.sh"
echo
echo "Syncing the newest recovery set offsite with a remote readback check..."
/usr/bin/bash -p "$REPO/bin/offsite-sync.sh"
echo
echo "Done. Reminder: auth keys expire (<=90d). A rejected key is reported as"
echo "AUTH_INVALID / REAUTH_REQUIRED; re-run this script to refresh it."
