#!/usr/bin/env bash
# Artifact-level leak scanner.
# Usage: bin/leak-scan.sh [TARGET_DIR]   (default: the repo working tree)
# Exit 2 on any finding. Values are masked in output.
#
# Layers:
#   1. generic secret patterns (token prefixes, JWT shape, PEM, AWS, home paths)
#   2. secret KEY NAMES from secrets/secrets-manifest.yaml + agents/*/**.keys
#      followed by a non-placeholder literal value
#   3. private denylist (~/.config/coding-system/leak-denylist.txt) — literal
#      personal IDs; ships in the secrets zip, never in the repo
#
# Exemptions (documented):
#   - .git/, external/, .staging/, secrets zips are never scanned as artifacts
#   - 40-hex rule skips components.lock and DECISIONS.md (pinned git SHAs)
#   - base64/40-hex rules skip *.lock and package-lock.json (integrity hashes)
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$REPO}"
DENYLIST="${CSR_DENYLIST:-$HOME/.config/coding-system/leak-denylist.txt}"

FINDINGS=0
mask() { sed -E 's/(.{0,40}:[0-9]+:.{0,12}).*/\1.../' ; }

list_files() {
  local skip=()
  # repo-internal exclusions only when scanning the repo itself; an explicit
  # TARGET (e.g. the staging tree or a canary dir) is scanned in full
  if [[ "$TARGET" == "$REPO" ]]; then
    skip=(! -path '*/external/*' ! -path '*/.staging/*')
  fi
  find "$TARGET" -type f \
    ! -path '*/.git/*' "${skip[@]}" \
    ! -name '*.zip' ! -path '*/secrets-out/*' ! -path '*/node_modules/*'
}

scan_pattern() { # $1=label $2=pattern $3=filename-skip regex $4=line-context-skip regex
  local label="$1" pat="$2" skip="${3:-^$}" ctx="${4:-LEAKSCAN-EXEMPT}"
  local hits
  hits=$(list_files | grep -Ev "$skip" | xargs -r grep -nIE -e "$pat" 2>/dev/null \
         | grep -v 'LEAKSCAN-EXEMPT' | grep -vE "$ctx" | head -50)
  if [[ -n "$hits" ]]; then
    echo "FINDING [$label]:"
    echo "$hits" | mask | sed 's/^/  /'
    FINDINGS=$((FINDINGS + $(echo "$hits" | wc -l)))
  fi
}

# 1 ---- generic patterns
scan_pattern "openai/deepseek-style key"  'sk-[A-Za-z0-9]{16,}'
scan_pattern "groq key"                   'gsk_[A-Za-z0-9]{16,}'
scan_pattern "perplexity key"             'pplx-[A-Za-z0-9]{16,}'
scan_pattern "github token"               '(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})'
scan_pattern "aws access key"             'AKIA[0-9A-Z]{16}'
scan_pattern "slack token"                'xox[bpas]-[A-Za-z0-9-]{10,}'
scan_pattern "jwt"                        'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
scan_pattern "private key block"          '-----BEGIN [A-Z ]*PRIVATE KEY-----'
scan_pattern "telegram bot token"         '[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}'
scan_pattern "google api key"             'AIza[0-9A-Za-z_-]{35}'
scan_pattern "gcp/firebase oauth client"  '[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com'
scan_pattern "openai rt/st token"         '\b[rs]t_[A-Za-z0-9_-]{20,}\b'
# Stable Tailscale node IDs expose private tailnet topology even though they are
# not bearer credentials.  Keep them out of the public source tree alongside
# the private devices.json registry that stores them.
scan_pattern "tailscale stable node id"   '\bn[A-Za-z0-9]{8,}CNTRL\b'
# credential stored as the JSON value of a secret-ish field (the blind spot that
# leaked the Google + Z.AI keys). The field set here MUST stay a superset of the
# redactor's SECRET_FIELD_NAMES + SENSITIVE_KEY_RE (tests/field_set_sync.sh enforces
# it). Case-insensitive; placeholders + the value pattern itself are exempt.
SECRET_FIELD_ALT='key|apikey|api_key|token|accountid|clientsecret|client_secret|access|refresh|bearer|secret|password|credential|sessionid|session_id|ownerid|owner_id|clientid|client_id|cookie|auth|serviceaccount|service_account|serviceaccountfile'
{
  hits=$(list_files | xargs -r grep -niIE "\"($SECRET_FIELD_ALT)\"[[:space:]]*:[[:space:]]*\"[A-Za-z0-9][A-Za-z0-9_.+/-]{19,}\"" 2>/dev/null \
    | grep -vE '\{\{ *[A-Za-z_]+ *\}\}' | grep -v 'LEAKSCAN-EXEMPT' | head -50)
  if [[ -n "$hits" ]]; then
    echo "FINDING [secret-shaped JSON field value]:"; echo "$hits" | mask | sed 's/^/  /'
    FINDINGS=$((FINDINGS + $(echo "$hits" | wc -l)))
  fi
}
# REBUILD-MANIFEST.json carries this string in its own forbidden-pattern list
scan_pattern "hardcoded home path"        '/home/ubuntu' 'REBUILD-MANIFEST\.json$'   # LEAKSCAN-EXEMPT (the pattern itself)
# 40-hex: skip lock/pin files entirely; skip lines whose context shows a public hash
# (git SHAs, S2 paper IDs, npm integrity) rather than a credential
scan_pattern "40-hex secret"              '\b[0-9a-f]{40}\b' \
  '(components\.lock|DECISIONS\.md|package-lock\.json|\.lock)$' \
  '(paperId|S2 hash|"sha"|SOURCE_COMMIT|commit|integrity|revision|github\.com|gitlab\.com|git\b)'

# 2 ---- key names followed by literal (non-placeholder) values
KEYNAMES=$(
  { [[ -f "$REPO/secrets/secrets-manifest.yaml" ]] && \
      grep -oE 'TELEGRAM_[A-Z_]+|OCRSPACE_API_KEY|LEANEXPLORE_API_KEY|TS_AUTHKEY' \
        "$REPO/secrets/secrets-manifest.yaml" 2>/dev/null; \
    cat "$REPO"/agents/*/*.keys 2>/dev/null; } | sort -u | grep -E '^[A-Z][A-Z0-9_]{4,}$' || true)
if [[ -n "$KEYNAMES" ]]; then
  PAT="($(echo "$KEYNAMES" | paste -sd'|'))"
  # /tests|fixtures/ paths exempt from THIS rule only (fake fixture values verified
  # 2026-06-12); generic prefix patterns + denylist still scan them
  hits=$(list_files | grep -vE '/(tests?|fixtures)/' \
        | xargs -r grep -nIE "${PAT}[\"']?\\s*[=:]\\s*[\"']?[A-Za-z0-9][^\"'{ ]{7,}" 2>/dev/null \
        | grep -vE '\{\{ *[A-Z_]+ *\}\}' | grep -v 'LEAKSCAN-EXEMPT' | head -50)
  if [[ -n "$hits" ]]; then
    echo "FINDING [named secret key with literal value]:"
    echo "$hits" | mask | sed 's/^/  /'
    FINDINGS=$((FINDINGS + $(echo "$hits" | wc -l)))
  fi
fi

# 3 ---- private denylist (literal personal IDs)
if [[ -f "$DENYLIST" ]]; then
  hits=$(list_files | xargs -r grep -nIFf "$DENYLIST" 2>/dev/null | grep -v 'LEAKSCAN-EXEMPT' | head -50)
  if [[ -n "$hits" ]]; then
    echo "FINDING [private denylist match]:"
    echo "$hits" | mask | sed 's/^/  /'
    FINDINGS=$((FINDINGS + $(echo "$hits" | wc -l)))
  fi
else
  echo "WARN: denylist not found at $DENYLIST (run bin/init-private.sh)" >&2
fi

if [[ $FINDINGS -gt 0 ]]; then
  echo "leak-scan: $FINDINGS finding(s) — ABORT" >&2
  exit 2
fi
echo "leak-scan: clean ($(list_files | wc -l) files scanned)"
