#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"
# Arch-aware Zotero Translation Server image (override with ZOTERO_TS_IMAGE):
#   arm64 -> zotero/translation-server (the official image is arm64)
#   amd64 -> ghcr.io/hoanganhduc/translation-server (custom amd64 build)
# Fallback: build from https://github.com/hoanganhduc/translation-server (ZOTERO_TS_BUILD=1).
case "$(uname -m)" in
  aarch64|arm64) export ZOTERO_TS_IMAGE="${ZOTERO_TS_IMAGE:-zotero/translation-server:latest}" ;;
  *)             export ZOTERO_TS_IMAGE="${ZOTERO_TS_IMAGE:-ghcr.io/hoanganhduc/translation-server:latest}" ;;
esac
if ! docker compose up -d; then
  if [[ "${ZOTERO_TS_BUILD:-0}" == "1" ]]; then
    echo "Pull/start failed — building translation-server from source (fallback)..."
    _ts_tmp="$(mktemp -d)"
    git clone --depth 1 https://github.com/hoanganhduc/translation-server "$_ts_tmp/ts" \
      && docker build -t local/translation-server:latest "$_ts_tmp/ts" \
      && ZOTERO_TS_IMAGE=local/translation-server:latest docker compose up -d
    rc=$?; rm -rf "$_ts_tmp"; [[ $rc -eq 0 ]] || exit $rc
  else
    echo "ERROR: could not start $ZOTERO_TS_IMAGE — set ZOTERO_TS_BUILD=1 to build from source, or set ZOTERO_TS_IMAGE." >&2
    exit 1
  fi
fi
echo "Translation Server starting on http://localhost:1969"
echo "Waiting for server to be ready..."
for i in $(seq 1 30); do
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:1969/ 2>/dev/null | grep -q "200\|404"; then
        echo "Translation Server is ready."
        exit 0
    fi
    sleep 2
done
echo "ERROR: Translation Server did not become ready in 60s"
exit 1
