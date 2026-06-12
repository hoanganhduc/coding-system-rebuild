#!/usr/bin/env bash
# Leak-scan canary self-test. Canaries are CONSTRUCTED at runtime in a temp dir
# (never committed — a stored fake token would trip the repo-level scan).
# Expects: every canary caught (exit 2 from scanner), clean dir passes (exit 0).
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T=$(mktemp -d /tmp/csr-canary.XXXXXX)
trap 'rm -rf "$T"' EXIT

# construct canaries by concatenation so no token-shaped literal exists in THIS file
P1="sk-"; P2="ghp_"; P3="AKIA"; P4="xoxb-"; P5="-----BEGIN "; P6="/home/"; P7="eyJ"
mkdir -p "$T/dirty" "$T/clean"
{
  echo "key = \"${P1}CANARY0123456789abcdefgh\""
  echo "token: ${P2}ABCDEFGHIJKLMNOPQRSTUVWX"
  echo "aws=${P3}ABCDEFGHIJKLMNOP"
  echo "slack=${P4}1234567890-abcdefghij"
  echo "${P5}RSA PRIVATE KEY-----"
  echo "path=${P6}ubuntu/.claude/secrets.json"
  echo "jwt=${P7}AAAAAAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBB.CCCCCCCCCCCC"
  echo "TELEGRAM_BOT_TOKEN=\"99999999:AA$(printf 'x%.0s' {1..30})\""
} > "$T/dirty/leaky.conf"
echo "nothing to see here, placeholder {{ TELEGRAM_BOT_TOKEN }}" > "$T/clean/ok.conf"

# denylist canary
DL=$(mktemp); echo "CANARY-PERSONAL-ID-424242" > "$DL"
echo "the id is CANARY-PERSONAL-ID-424242 ok" >> "$T/dirty/leaky.conf"

fail=0
if CSR_DENYLIST="$DL" "$REPO/bin/leak-scan.sh" "$T/dirty" >/dev/null 2>&1; then
  echo "FAIL: scanner did NOT flag the canary dir"; fail=1
else
  # count distinct finding classes caught
  out=$(CSR_DENYLIST="$DL" "$REPO/bin/leak-scan.sh" "$T/dirty" 2>&1 || true)
  for label in "openai" "github token" "aws" "slack" "private key" "home path" "jwt" "telegram" "denylist"; do
    echo "$out" | grep -qi "$label" || { echo "FAIL: canary class not caught: $label"; fail=1; }
  done
fi
if ! CSR_DENYLIST="$DL" "$REPO/bin/leak-scan.sh" "$T/clean" >/dev/null 2>&1; then
  echo "FAIL: scanner flagged a clean dir"; fail=1
fi
rm -f "$DL"
[[ $fail -eq 0 ]] && echo "leak-scan self-test: PASS (9 canary classes caught, clean dir passes)"
exit $fail
