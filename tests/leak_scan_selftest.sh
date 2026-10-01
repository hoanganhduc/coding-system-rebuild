#!/usr/bin/env bash
# Leak-scan canary self-test. Canaries are CONSTRUCTED at runtime in a temp dir
# (never committed — a stored fake token would trip the repo-level scan).
# Expects: every canary caught (exit 2 from scanner), clean dir passes (exit 0).
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T=$(mktemp -d /tmp/csr-canary.XXXXXX)
trap 'rm -rf "$T"' EXIT

# construct canaries by concatenation so no token-shaped literal exists in THIS file
AT="@"
P1="sk-"; P2="ghp_"; P3="AKIA"; P4="xoxb-"; P5="-----BEGIN "; P6="/home/"; P7="eyJ"; P8="n"
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
  echo "tailscale_node=${P8}CANARY012345CNTRL"
} > "$T/dirty/leaky.conf"
echo "nothing to see here, placeholder {{ TELEGRAM_BOT_TOKEN }}" > "$T/clean/ok.conf"
{
  echo "reserved example: someone@example.com and bot@users.noreply.github.com"
  echo "date 20260929 and version 1.2.3 and sha 0123abcd"
} >> "$T/clean/ok.conf"
# synthetic fixture values inside a test file are not identity leaks
mkdir -p "$T/clean/tests"
{
  echo "boot_id = '7c9e6679-7425-40de-944b-e07fc1f90ae7'"
  echo "pid_start = 123456789012"
  echo "home = '/home/alice/.config'; fake = '/home/.local/share'"
  echo "peer = '100.101.1.2'"
  echo "zero = '00000000-0000-0000-0000-000000000000'"
} > "$T/clean/tests/test_fixture.py"
echo '{"maximum": 2147483647}' > "$T/clean/limits.schema.json"
# an identifier read through a call is code, not a literal id
printf 'course_id = value.get("CANVAS_LMS_COURSE_ID")\nuser_id = config.get("zotero_user_id")\n' > "$T/clean/reader.py"
{
  echo "systemctl start user@1001.service; unit=user@UID.service"
  echo "MemoryMax=4294967296 GROK_PROVIDER_DEADLINE_NS=9000000000000000000"
  echo "(( 10#\$DEADLINE_NS <= 9223372036854775807 )) && [ \$x -lt 2147483647 ] && n=1000000000"
  echo "owner${AT}real-domain.test sample; docs mention /Users/iPhone/Documents"
} > "$T/clean/units.conf"

# identity-bearing classes (layer 4), again constructed so no literal lives here
AT="@"; TS=".ts"; NET=".net"; ON=".onion"; PH="345 678"; TC="trycloudflare"".com"
{
  echo "mail=someone.private${AT}privatecorp.org"
  echo "mac=/Users/alice/Library/prefs"
  echo "id=0f8fad5b-d9cb-469f-a165-70867728950e"
  echo "chat 1234567890123"
  echo "user_id: ABCD1234EFGH"
  echo "ip=100.101.102.103"
  echo "host=box.tail1234${TS}${NET}"
  echo "call +84 912 ${PH}"
  echo "hs=$(printf 'a%.0s' {1..56})${ON}"
  echo "tunnel=abc-def.${TC}"
} > "$T/dirty/identity.txt"
# UTF-16 text is invisible to grep; the canary hides a denylist entry and a tailnet name in it
printf 'utf16 CANARY-PERSONAL-ID-424242 box2.tail5678%s%s\n' "$TS" "$NET" | iconv -f UTF-8 -t UTF-16 > "$T/dirty/wide.txt"
# a text member inside a zip archive
mkdir -p "$T/zipsrc" && echo "zipped mail=zipped.person${AT}privatecorp.org" > "$T/zipsrc/inner.txt"
(cd "$T/zipsrc" && python3 -c "import zipfile; z=zipfile.ZipFile('$T/dirty/bundle.zip','w'); z.write('inner.txt'); z.close()")

# denylist canary
DL=$(mktemp); echo "CANARY-PERSONAL-ID-424242" > "$DL"
echo "the id is CANARY-PERSONAL-ID-424242 ok" >> "$T/dirty/leaky.conf"

fail=0
if CSR_DENYLIST="$DL" "$REPO/bin/leak-scan.sh" "$T/dirty" >/dev/null 2>&1; then
  echo "FAIL: scanner did NOT flag the canary dir"; fail=1
else
  # count distinct finding classes caught
  out=$(CSR_DENYLIST="$DL" "$REPO/bin/leak-scan.sh" "$T/dirty" 2>&1 || true)
  for label in "openai" "github token" "aws" "slack" "private key" "home path" "jwt" "telegram" "tailscale stable node" "denylist" \
               "email" "uuid" "long numeric" "identifier field" "cgnat" "tailnet" "phone" "onion" "tunnel" \
               "utf-16" "zip member"; do
    echo "$out" | grep -qi "$label" || { echo "FAIL: canary class not caught: $label"; fail=1; }
  done
  # output must locate findings without printing the values
  for value in "CANARY0123456789" "CANARY-PERSONAL-ID-424242" "someone.private" "tail1234" "privatecorp"; do
    echo "$out" | grep -q "$value" && { echo "FAIL: scanner printed a matched value: $value"; fail=1; }
  done
  # a tree whose only finding comes from layer 4 must still fail the scan
  mkdir -p "$T/only4" && echo "mail=lonely.person${AT}privatecorp.org" > "$T/only4/a.txt"
  if CSR_DENYLIST="$DL" "$REPO/bin/leak-scan.sh" "$T/only4" >/dev/null 2>&1; then
    echo "FAIL: a layer-4-only finding did not fail the scan"; fail=1
  fi
  # a failing layer-4 helper must fail the scan, not pass it silently
  if LEAKSCAN_EXTRA_FAULT=1 CSR_DENYLIST="$DL" "$REPO/bin/leak-scan.sh" "$T/clean" >/dev/null 2>&1; then
    echo "FAIL: a crashing layer-4 helper did not fail the scan"; fail=1
  fi
  # a missing layer-4 helper, or one that exits 2 without reporting a finding
  # (python's own exit code when it cannot run the file), must fail the scan
  for variant in missing silent-exit-2; do
    mkdir -p "$T/copy-$variant/bin/lib"
    cp "$REPO/bin/leak-scan.sh" "$T/copy-$variant/bin/"
    cp "$REPO/bin/lib/public_export.py" "$T/copy-$variant/bin/lib/"
    [[ $variant == silent-exit-2 ]] && printf 'import sys\nsys.exit(2)\n' > "$T/copy-$variant/bin/lib/leak_scan_extra.py"
    if CSR_DENYLIST="$DL" bash "$T/copy-$variant/bin/leak-scan.sh" "$T/clean" >/dev/null 2>&1; then
      echo "FAIL: a $variant layer-4 helper did not fail the scan"; fail=1
    fi
  done
  # reviewed exceptions (leak-scan-exceptions.yaml, the public-export format)
  # apply to one path, class and line only
  mkdir -p "$T/copy-exc/bin/lib" "$T/exc"
  cp "$REPO/bin/leak-scan.sh" "$T/copy-exc/bin/"
  cp "$REPO/bin/lib/public_export.py" "$REPO/bin/lib/leak_scan_extra.py" "$T/copy-exc/bin/lib/"
  printf 'first lonely.person%sprivatecorp.org\nsecond other.person%sprivatecorp.org\n' "$AT" "$AT" > "$T/exc/a.txt"
  exc_rule() { printf '  - {path: a.txt, class: email, line: %s, reason: selftest, proof: selftest}\n' "$1"; }
  { echo "exceptions:"; exc_rule 1; } > "$T/copy-exc/leak-scan-exceptions.yaml"
  exc_out=$(CSR_DENYLIST="$DL" bash "$T/copy-exc/bin/leak-scan.sh" "$T/exc" 2>&1)
  if ! echo "$exc_out" | grep -q "FINDING \[email\]: 1$"; then
    echo "FAIL: an exception for one line did not leave exactly the other line flagged"; fail=1
  fi
  { echo "exceptions:"; exc_rule 1; exc_rule 2; } > "$T/copy-exc/leak-scan-exceptions.yaml"
  if ! CSR_DENYLIST="$DL" bash "$T/copy-exc/bin/leak-scan.sh" "$T/exc" >/dev/null 2>&1; then
    echo "FAIL: exceptions for both lines did not clear the scan"; fail=1
  fi
  # another repository's reviewed exceptions apply only when the caller names it
  mkdir -p "$T/other-repo"
  { echo "exceptions:"; exc_rule 1; exc_rule 2; } > "$T/other-repo/leak-scan-exceptions.yaml"
  echo "exceptions: []" > "$T/copy-exc/leak-scan-exceptions.yaml"
  if CSR_DENYLIST="$DL" bash "$T/copy-exc/bin/leak-scan.sh" "$T/exc" >/dev/null 2>&1; then
    echo "FAIL: another repository's exceptions applied without being named"; fail=1
  fi
  if ! CSR_DENYLIST="$DL" CSR_LEAKSCAN_EXCEPTIONS_REPO="$T/other-repo" \
      bash "$T/copy-exc/bin/leak-scan.sh" "$T/exc" >/dev/null 2>&1; then
    echo "FAIL: the named repository's exceptions did not apply"; fail=1
  fi
  # CSR_REQUIRE_DENYLIST=1 must fail closed when the denylist is missing
  if CSR_REQUIRE_DENYLIST=1 CSR_DENYLIST="$T/no-such-denylist" "$REPO/bin/leak-scan.sh" "$T/clean" >/dev/null 2>&1; then
    echo "FAIL: missing denylist did not fail with CSR_REQUIRE_DENYLIST=1"; fail=1
  fi
fi
if ! CSR_DENYLIST="$DL" "$REPO/bin/leak-scan.sh" "$T/clean" >/dev/null 2>&1; then
  echo "FAIL: scanner flagged a clean dir"; fail=1
fi
rm -f "$DL"
[[ $fail -eq 0 ]] && echo "leak-scan self-test: PASS (21 canary classes caught, values never printed, clean dir passes)"
exit $fail
