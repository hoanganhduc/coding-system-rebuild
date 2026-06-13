#!/usr/bin/env bash
# One-command Tailscale auth-key setup for the secrets archive.
# Prompts for the key (paste from https://login.tailscale.com/admin/settings/keys:
# Reusable + Pre-approved, NOT ephemeral), writes ~/.config/coding-system/tailscale.env,
# re-packs the secrets zip (asks for your zip password), verifies, and syncs offsite.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENVFILE="$HOME/.config/coding-system/tailscale.env"

echo "Generate the key first (browser): https://login.tailscale.com/admin/settings/keys"
echo "  -> Generate auth key: Reusable=on, Pre-approved=on, Ephemeral=off, expiry up to 90d"
echo
read -rs -p "Paste the auth key (tskey-auth-...): " TSKEY; echo
[[ "$TSKEY" == tskey-* ]] || { echo "ERROR: that does not look like a tailscale auth key (tskey-...)" >&2; exit 2; }
read -r -p "Node hostname for restored machines [openclaw]: " TSNAME
TSNAME="${TSNAME:-openclaw}"

mkdir -p "$(dirname "$ENVFILE")" && chmod 700 "$(dirname "$ENVFILE")"
printf 'TS_AUTHKEY=%s\nTS_HOSTNAME=%s\n' "$TSKEY" "$TSNAME" > "$ENVFILE"
chmod 600 "$ENVFILE"
echo "wrote $ENVFILE (0600)"
echo
echo "Re-packing the secrets zip (your zip password will be prompted)..."
bash "$REPO/bin/secrets-pack.sh"
echo
echo "--- verification ---"
bash "$REPO/bin/secrets-verify.sh" | grep -E 'tailscale|openclaw\.json|jobs\.json' || true
echo
echo "Syncing offsite (public capture + dropbox upload of the new zip)..."
bash "$REPO/bin/auto-backup.sh"
tail -n 5 "$HOME/.config/coding-system/backup.log"
echo
echo "Done. Reminder: auth keys expire (<=90d) — on an expired key, restores fall back"
echo "to an interactive 'sudo tailscale up --hostname $TSNAME'. Re-run this script to refresh."
