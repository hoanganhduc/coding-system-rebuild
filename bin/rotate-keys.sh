#!/usr/bin/env bash
# Rotate ANY secret across every place it lives. Modes:
#
#   bash bin/rotate-keys.sh --list                 # show all rotatable secret ids
#   bash bin/rotate-keys.sh SECRET=ZOTERO_API_KEY  # named or field-in-file secret
#   bash bin/rotate-keys.sh PROVIDER=google        # an OpenClaw provider key
#   bash bin/rotate-keys.sh google zai             # shorthand: rotate these providers
#   bash bin/rotate-keys.sh                         # interactive picker
#
# New values are read via hidden prompts (never in argv/ps/history), updated in
# all targets (secrets.json mirrors, .secrets.env, auth-profiles + models.json,
# TOML configs), each file backed up, then optional gateway restart + zip re-pack.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="python3 $REPO/bin/lib/rotate_secrets.py"

# ---- collect the list of ids to rotate -------------------------------------
declare -a IDS=()
INTERACTIVE=0
for a in "$@"; do
  case "$a" in
    --list|list) $ENG list; exit 0 ;;
    SECRET=*|secret=*)     IDS+=("${a#*=}") ;;
    PROVIDER=*|provider=*) IDS+=("${a#*=}") ;;
    --*) echo "unknown flag: $a" >&2; exit 2 ;;
    *)   IDS+=("$a") ;;   # positional = provider/secret id (e.g. google)
  esac
done

if [[ ${#IDS[@]} -eq 0 ]]; then
  INTERACTIVE=1
  echo "Rotatable secrets:"; echo
  $ENG list
  echo
  read -r -p "Enter the secret id(s) to rotate (space-separated): " -a IDS
  [[ ${#IDS[@]} -gt 0 ]] || { echo "nothing selected"; exit 0; }
fi

# ---- validate ids up front (fail before prompting) -------------------------
for id in "${IDS[@]}"; do
  k=$($ENG kind "$id" 2>/dev/null || true)
  [[ "$k" != "unknown" && -n "$k" ]] || { echo "ERROR: unknown secret '$id' (run: bash bin/rotate-keys.sh --list)" >&2; exit 2; }
done

# ---- rotate each (hidden prompt, value via env, never echoed) ---------------
for id in "${IDS[@]}"; do
  echo
  read -rs -p "New value for $id: " V; echo
  [[ -n "$V" ]] || { echo "  empty — skipping $id"; continue; }
  if [[ "$id" == google && "$V" != AIza* ]]; then
    read -r -p "  Google keys start with 'AIza' — use anyway? [y/N] " yn
    [[ "$yn" == [yY] ]] || { echo "  skipped $id"; continue; }
  fi
  NEWSECRET_VALUE="$V" $ENG apply "$id"
  # test the new value against the real API (read-only; key never printed)
  printf '  test %s ... ' "$id"
  res=$(VERIFY_VALUE="$V" python3 "$REPO/bin/lib/verify_secret.py" "$id" 2>/dev/null || true)
  echo "$res"
  case "$res" in
    FAIL*) echo "  !! new $id did NOT pass its live test — could be a wrong value, OR a"
           echo "     rate-limited/exhausted provider. Re-check the value and the provider console."
           ROTATE_HAD_FAILURE=1 ;;
  esac
  unset V
done
: "${ROTATE_HAD_FAILURE:=0}"

# ---- post-actions ----------------------------------------------------------
echo
read -r -p "Restart the OpenClaw gateway so changes take effect? [Y/n] " r
if [[ "$r" != [nN] ]]; then
  systemctl --user restart openclaw-gateway 2>/dev/null && sleep 2 && \
    { systemctl --user is-active openclaw-gateway >/dev/null 2>&1 && echo "gateway active"; } \
    || echo "WARN: gateway not restarted/active — check: journalctl --user -u openclaw-gateway -n 30"
fi
echo
read -r -p "Refresh the secrets zip so the backup holds the new values? [Y/n] " z
[[ "$z" == [nN] ]] || bash "$REPO/bin/secrets-pack.sh"

echo
if [[ "${ROTATE_HAD_FAILURE:-0}" == "1" ]]; then
  echo "WARNING: at least one rotated secret FAILED its live test (see above)."
fi
echo "Done. If you rotated a ~/.secrets.env var, run 'source ~/.bashrc' in open shells."
echo "Reminder: revoke the OLD values at their providers; stale *.bak files may still hold them."
