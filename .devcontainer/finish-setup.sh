#!/usr/bin/env bash
# Complete the FULL replica from an uploaded encrypted secrets zip.
# Invoked by .devcontainer/upload-server.py. Never run automatically — only when the
# user uploads a zip. Env: SECRETS=<zip>, CSR_SECRETS_PASSWORD, START_GATEWAY=0|1.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
: "${SECRETS:?SECRETS (zip path) required}"
: "${CSR_SECRETS_PASSWORD:?password required}"

# GUARANTEE the uploaded zip is destroyed no matter how this script ends
# (success, error, or signal) — it is shredded then removed.
scrub_zip() { [[ -n "${SECRETS:-}" && -f "$SECRETS" ]] && { shred -u "$SECRETS" 2>/dev/null || rm -f "$SECRETS"; echo "uploaded zip scrubbed"; }; }
trap scrub_zip EXIT INT TERM

echo "== verifying uploaded archive =="
SEVENZ="$(command -v 7zz || command -v 7z || true)"
if [[ -z "$SEVENZ" ]]; then
  sudo apt-get update -qq && sudo apt-get install -y -qq 7zip >/dev/null 2>&1 || true
  SEVENZ="$(command -v 7zz || command -v 7z)"
fi
"$SEVENZ" t -p"$CSR_SECRETS_PASSWORD" "$SECRETS" >/dev/null 2>&1 \
  || { echo "ERROR: wrong password or corrupt archive — aborting"; exit 2; }  # trap scrubs the zip

echo "== completing install from secrets (phases 3..12, gateway NOT auto-started) =="
# Resume the installer from restore-secrets; this pulls images, completes the OpenClaw
# slice + skills, rebuilds python envs, and renders services. Gateway start is gated.
SECRETS="$SECRETS" CSR_SECRETS_PASSWORD="$CSR_SECRETS_PASSWORD" \
  CSR_NO_GATEWAY=1 PHASE=3 bash bin/install.sh
rc=$?
# the EXIT trap (scrub_zip) destroys the uploaded zip when this script returns

if [[ "${START_GATEWAY:-0}" == "1" && $rc -eq 0 ]]; then
  echo "============================================================"
  echo " STARTING OpenClaw gateway (LIVE)."
  echo " WARNING: it connects to your real channels (Telegram/Zulip/"
  echo " WhatsApp/...) with the SAME bot tokens and may conflict with"
  echo " your primary instance (e.g. Telegram getUpdates conflicts)."
  echo "============================================================"
  # resolve openclaw by full path: this runs in a non-login shell where the npm global
  # bin (~/.npm-global/bin) is NOT on PATH, so a bare `openclaw` fails with
  # "No such file or directory" and the gateway never starts. setsid so it survives.
  OPENCLAW="$(command -v openclaw || echo "$HOME/.npm-global/bin/openclaw")"
  pkill -f 'openclaw gateway' 2>/dev/null || true
  nohup setsid "$OPENCLAW" gateway --port 18789 >/tmp/openclaw-gateway.log 2>&1 </dev/null &
  sleep 3
  echo "gateway launched via $OPENCLAW (log: /tmp/openclaw-gateway.log; port 18789 forwarded)"
fi

echo "== finish-setup done (exit $rc). =="
exit $rc
