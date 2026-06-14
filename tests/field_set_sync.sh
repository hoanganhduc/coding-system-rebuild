#!/usr/bin/env bash
# Guard: the leak-scanner's JSON-field backstop MUST cover every field name the
# openclaw-bot redactor treats as secret. If they diverge, a redaction regression
# on an uncovered field would pass the scanner silently (the incident class).
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OCB="${OPENCLAW_BOT_DIR:-$REPO/external/openclaw-bot}"
[ -f "$OCB/sync.sh" ] || { echo "FAIL: openclaw-bot not found at $OCB"; exit 2; }

# redactor field set: SECRET_FIELD_NAMES literals + SENSITIVE_KEY_RE alternatives
red=$(python3 - "$OCB/sync.sh" <<'EOF'
import re,sys
s=open(sys.argv[1]).read()
names=set()
m=re.search(r'SECRET_FIELD_NAMES\s*=\s*\{([^}]*)\}',s,re.S)
if m: names|= {x.strip().strip('"\'').lower() for x in m.group(1).split(',') if x.strip()}
m=re.search(r'SENSITIVE_KEY_RE\s*=\s*re\.compile\(r"\(([^)]*)\)"',s)
if m: names|= {x.strip().lower() for x in m.group(1).split('|')}
# normalize separators so api[_-]?key ~ apikey etc.
print("\n".join(sorted(re.sub(r'[\[\]_?-]','',n) for n in names if n)))
EOF
)
scan_alt=$(grep -oE "SECRET_FIELD_ALT='[^']*'" "$REPO/bin/leak-scan.sh" | sed "s/SECRET_FIELD_ALT='//;s/'//")
miss=0
while read -r f; do
  [ -z "$f" ] && continue
  # ignore non-field regex words that aren't real JSON field names
  case "$f" in jwt|allowfrom|pairing|chatid|audience|private) continue;; esac
  norm=$(echo "$scan_alt" | tr '|' '\n' | sed 's/[_-]//g' | tr 'A-Z' 'a-z')
  echo "$norm" | grep -qx "$f" || { echo "GAP: redactor field '$f' not covered by leak-scan SECRET_FIELD_ALT"; miss=1; }
done <<< "$red"
[ $miss -eq 0 ] && echo "field-set sync: OK (scanner covers every redactor secret field)"
exit $miss
