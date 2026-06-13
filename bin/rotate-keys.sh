#!/usr/bin/env bash
# One-command rotation of the Google + Z.AI API keys across all OpenClaw agents.
#
#   bash bin/rotate-keys.sh            # rotate both (prompts for each)
#   bash bin/rotate-keys.sh google     # rotate only google
#   bash bin/rotate-keys.sh zai        # rotate only zai
#
# Reads new keys via hidden prompts (never echoed, never in argv/ps/history),
# updates auth-profiles.json + models.json for every agent (sandbox->main deduped),
# backs up each file, then offers to restart the gateway and refresh the secrets zip.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROVIDERS=("$@")
[[ ${#PROVIDERS[@]} -gt 0 ]] || PROVIDERS=(google zai)

declare -a ENVSET=()
for p in "${PROVIDERS[@]}"; do
  case "$p" in
    google) hint="Google API key (starts with AIza...): " ;;
    zai)    hint="Z.AI API key: " ;;
    *)      hint="$p API key: " ;;
  esac
  read -rs -p "$hint" K; echo
  [[ -n "$K" ]] || { echo "ERROR: empty key for $p — aborting (no changes made)" >&2; exit 2; }
  if [[ "$p" == google && "$K" != AIza* ]]; then
    read -r -p "  That doesn't start with 'AIza' — use it anyway? [y/N] " yn
    [[ "$yn" == [yY] ]] || { echo "aborted"; exit 2; }
  fi
  export "NEWKEY_${p^^}=$K"
  ENVSET+=("NEWKEY_${p^^}")
done

echo
echo "Updating agent configs..."
python3 "$REPO/bin/lib/rotate_provider_keys.py" "${PROVIDERS[@]}"
# scrub the key values from this shell's environment
for e in "${ENVSET[@]}"; do unset "$e"; done

echo
read -r -p "Restart the OpenClaw gateway now so the new keys take effect? [Y/n] " r
if [[ "$r" != [nN] ]]; then
  if systemctl --user restart openclaw-gateway 2>/dev/null; then
    sleep 2
    systemctl --user is-active openclaw-gateway >/dev/null 2>&1 \
      && echo "gateway restarted (active)" || echo "WARN: gateway not active — check: journalctl --user -u openclaw-gateway -n 30"
  else
    echo "WARN: could not restart gateway (not running as a user service here?)"
  fi
fi

echo
read -r -p "Refresh the secrets zip so the backup holds the new keys? [Y/n] " z
if [[ "$z" != [nN] ]]; then
  bash "$REPO/bin/secrets-pack.sh"
fi

echo
echo "Done. Reminders:"
echo "  - Revoke the OLD keys at the provider consoles if you haven't already."
echo "  - Stale .bak/.sync-conflict files may still hold old keys (harmless once revoked)."
