#!/usr/bin/env bash
# Prove locked platform descriptors and bounded functional image behavior.
set -euo pipefail
umask 077

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
case "$(uname -m)" in
  aarch64|arm64) ARCH=arm64 ;;
  x86_64|amd64) ARCH=amd64 ;;
  *) echo "verify-oci-runtime: unsupported architecture" >&2; exit 2 ;;
esac

python3 "$REPO/system/software/pull-locked-images.py" \
  --arch "$ARCH" --verify-only

timeout 300 "$HOME/.local/bin/sage" -c 'print(2**10)' 2>/dev/null \
  | grep -qx 1024 \
  || { echo "verify-oci-runtime: SageMath calculation failed" >&2; exit 2; }

START_TRANSLATION="$HOME/.openclaw/workspace/skills/zotero/scripts/start-translation-server.sh"
[[ -x "$START_TRANSLATION" ]] \
  || { echo "verify-oci-runtime: Translation Server launcher is missing" >&2; exit 2; }
timeout 150 bash "$START_TRANSLATION" >/dev/null

response="$(mktemp "${TMPDIR:-/tmp}/csr-translation-probe.XXXXXXXX")"
cleanup() {
  case "$response" in
    "${TMPDIR:-/tmp}"/csr-translation-probe.*) rm -f -- "$response" ;;
    *) echo "verify-oci-runtime: refusing unsafe probe cleanup" >&2 ;;
  esac
}
trap cleanup EXIT
code="$(curl --silent --show-error --max-time 10 --output "$response" \
  --write-out '%{http_code}' --header 'Content-Type: text/plain' \
  --data-binary '' http://127.0.0.1:1969/web)"
[[ "$code" == 400 ]] \
  || { echo "verify-oci-runtime: Translation Server /web returned $code" >&2; exit 2; }
cmp -s -- "$response" <(printf 'POST data not provided\n') \
  || { echo "verify-oci-runtime: Translation Server /web contract changed" >&2; exit 2; }

echo "OCI runtime verification: PASS ($ARCH descriptors + SageMath + Translation Server)"
