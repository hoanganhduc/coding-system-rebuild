#!/usr/bin/env bash
# Guard: the leak-scanner's JSON-field backstop MUST cover every field name the
# openclaw-bot redactor treats as secret. If they diverge, a redaction regression
# on an uncovered field would pass the scanner silently (the incident class).
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OCB="${OPENCLAW_BOT_DIR:-}"
if [[ -z "$OCB" ]]; then
  OCB="$(/usr/bin/python3 -I -B "$REPO/bin/lib/component_paths.py" \
    --repository "$REPO" --home "$HOME" --source-fallback --require openclaw-bot)"
fi
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

# Value coverage: every value the redactor rewrites as a secret must also trip the
# scanner, so a redaction regression cannot publish it unnoticed.  Samples are built
# at runtime from the redactor's own prefix list; MODEL_ID_RE (not a secret) and the
# catch-all LONG_ID_RE (any 24+ character run) are deliberately not required.
vmiss=0
T=$(mktemp -d /tmp/csr-valuesync.XXXXXX)
trap 'rm -rf "$T"' EXIT
while IFS=$'\t' read -r name value; do
  [ -z "$name" ] && continue
  d="$T/$name"; mkdir -p "$d"; printf 'value = %s\n' "$value" > "$d/sample.txt"
  if CSR_DENYLIST=/dev/null bash "$REPO/bin/leak-scan.sh" "$d" >/dev/null 2>&1; then
    echo "GAP: redactor value class '$name' not caught by leak-scan"; vmiss=1
  fi
done < <(python3 - "$OCB/sync.sh" <<'EOF'
import ast, sys
line = next(l for l in open(sys.argv[1]).read().splitlines() if l.startswith("SECRET_PREFIXES"))
def ev(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return ev(node.left) + ev(node.right)
    raise ValueError("unsupported SECRET_PREFIXES element")
for prefix in (ev(e) for e in ast.parse(line).body[0].value.elts):
    tag = "".join(c for c in prefix if c.isalnum())
    print(f"prefix-{tag}\t{prefix}Ab3x9_x9-x9x9x9x9x9x9x9x9x9")
    print(f"prefix-{tag}-project\t{prefix}proj-Ab3x9x9x9x9x9x9x9x9x9x9_x9")
print("google-key\tAI" + "za" + "B7" * 17 + "c")
print("opaque-key\t" + "0123456789abcdef" * 2 + "." + "AbCdEfGhIjKlMnOp")
print("tailnet-url\thttps://node.tail9f9f" + ".ts.net/path")
print("email\tleak.person" + "@" + "privatecorp.org")
EOF
)
[ $vmiss -eq 0 ] && echo "value sync: OK (scanner catches every redactor secret value class)"
exit $((miss | vmiss))
