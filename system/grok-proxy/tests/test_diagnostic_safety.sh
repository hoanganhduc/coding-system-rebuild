#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail(){ printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_no_hostile_output(){
  local value="$1" label="$2"
  [[ "$value" != *SECRET-DIAGNOSTIC* ]] || fail "$label replayed the sentinel"
  value="${value//$'\033[36m'/}"
  value="${value//$'\033[31m'/}"
  value="${value//$'\033[32m'/}"
  value="${value//$'\033[33m'/}"
  value="${value//$'\033[0m'/}"
  [[ "$value" != *$'\033'* && "$value" != *$'\a'* && "$value" != *$'\r'* && "$value" != *$'\b'* ]] \
    || fail "$label replayed terminal control bytes"
}

export HOME="$tmp/home"
export XDG_STATE_HOME="$HOME/.local/state"
export GROK_TESTING=1
export GROK_TEST_CONTROL_DIR="$tmp/control"
mkdir -p "$HOME/grok-proxy" "$GROK_TEST_CONTROL_DIR" "$tmp/target"
chmod 700 "$HOME" "$HOME/grok-proxy" "$GROK_TEST_CONTROL_DIR"
cp "$ROOT/egress.sh" "$ROOT/grok-remote" "$tmp/target/"

. "$tmp/target/egress.sh"

# Compatibility model discovery admits only exact model identifiers. Hostile
# helper output is neither persisted nor replayed.
cat > "$tmp/models-cmd" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' \
  'grok-4.1' \
  'vendor/model@stable' \
  'grok-4.1' \
  'SECRET-DIAGNOSTIC with spaces' \
  $'\033]8;;attacker.invalid\aSECRET-DIAGNOSTIC\r\b'
EOF
chmod 700 "$tmp/models-cmd"
GROK_MODELS_CMD="$tmp/models-cmd"
export GROK_MODELS_CMD
models="$(models_via '' direct 2>"$tmp/models.err")"
[[ "$models" == $'grok-4.1\nvendor/model@stable' ]] \
  || fail "model discovery did not enforce the closed identifier grammar"
assert_no_hostile_output "$models$(<"$tmp/models.err")" "model discovery"

cat > "$tmp/models-oversize" <<'EOF'
#!/usr/bin/env bash
awk 'BEGIN { for (i = 0; i < 1048577; i++) printf "A" }'
EOF
chmod 700 "$tmp/models-oversize"
GROK_MODELS_CMD="$tmp/models-oversize"
set +e
oversize="$(models_via '' direct 2>"$tmp/oversize.err")"
oversize_rc=$?
set -e
(( oversize_rc != 0 )) || fail "oversized model output was accepted"
[[ -z "$oversize" && ! -s "$tmp/oversize.err" ]] \
  || fail "oversized model output reached diagnostics"

# Public IP and country probes return only normalized, closed-schema values.
eg_curl(){ printf 'ip=2001:0db8:0:0::1\nloc=VN\n'; }
[[ "$(egress_ip '')" == 2001:db8::1 ]] || fail "valid IPv6 was not normalized"
[[ "$(egress_country '')" == VN ]] || fail "valid country was not admitted"
eg_curl(){
  case "$2" in
    *cdn-cgi/trace) printf 'warp=off\n' ;;
    *api.ipify.org) printf '198.51.100.9' ;;
    *ipinfo.io/country) printf 'US' ;;
  esac
}
[[ "$(egress_ip '')" == 198.51.100.9 ]] || fail "valid IPv4 fallback was not admitted"
[[ "$(egress_country '')" == US ]] || fail "valid country fallback was not admitted"
eg_curl(){ printf '%s' $'ip=SECRET-DIAGNOSTIC\033\nloc=V\a\r\b\n'; }
set +e
invalid_ip="$(egress_ip '')"
invalid_country="$(egress_country '')"
set -e
invalid_probe="$invalid_ip$invalid_country"
[[ -z "$invalid_probe" ]] || fail "invalid IP/country probe output was admitted"
assert_no_hostile_output "$invalid_probe" "IP/country probe"

# Tailscaled failure diagnostics expose only a bounded byte count and digest.
IPHONE_LOG="$tmp/tailscaled.log"
printf '%s' $'\033]8;;attacker.invalid\aSECRET-DIAGNOSTIC\r\b' > "$IPHONE_LOG"
chmod 600 "$IPHONE_LOG"
fingerprint="$(iphone_log_fingerprint)"
[[ "$fingerprint" =~ ^log_bytes=[0-9]+\ log_sha256=[0-9a-f]{64}$ ]] \
  || fail "tailscaled log fingerprint had an invalid shape"
assert_no_hostile_output "$fingerprint" "tailscaled log fingerprint"

# Read-only status ignores hostile persisted metadata; mutating selection
# removes it without ever reflecting it to the terminal.
. "$tmp/target/grok-remote"
printf '%s' $'SECRET-DIAGNOSTIC\033]8;;attacker.invalid\a\r\b' > "$UNLOCKED"
printf '%s' $'SECRET-DIAGNOSTIC\033' > "$CHOICE"
set_active direct
rung_alive(){ return 0; }
egress_ip(){ printf '198.51.100.9'; }
status_out="$(cmd_status 2>&1)"
assert_no_hostile_output "$status_out" "compatibility status"
[[ -e "$UNLOCKED" && -e "$CHOICE" ]] \
  || fail "read-only status mutated invalid model metadata"

printf '%s\n' $'RUNG=local:SECRET-DIAGNOSTIC\033\nDEST=fixture@example\nSPORT=22' > "$STATE"
state_out="$(cmd_status 2>&1)"
assert_no_hostile_output "$state_out" "compatibility route state"
[[ "$state_out" == *"no egress selected"* ]] \
  || fail "hostile compatibility route state was not rejected"
! set_active $'local:SECRET-DIAGNOSTIC\033' fixture@example 22 \
  || fail "hostile compatibility route was persisted"

printf '%s' $'SECRET-DIAGNOSTIC\033' > "$SEEN"
selection_out="$(model_args iphone </dev/null 2>&1)"
assert_no_hostile_output "$selection_out" "model selection"
[[ ! -e "$UNLOCKED" && ! -e "$CHOICE" && ! -e "$SEEN" ]] \
  || fail "mutating model selection retained invalid metadata"

mkdir -p "$HOME/.grok"
printf '%s\n' 'default = "SECRET-DIAGNOSTIC with spaces"' > "$HOME/.grok/config.toml"
[[ -z "$(grok_default_model)" ]] || fail "invalid configured default model was admitted"

bad_model=$'SECRET-DIAGNOSTIC\033]8;;attacker.invalid\a'
set +e
caller_out="$(GROK_BIN=/bin/true main -m "$bad_model" 2>&1)"
caller_rc=$?
set -e
(( caller_rc == 2 )) || fail "invalid caller model did not fail admission"
assert_no_hostile_output "$caller_out" "caller model rejection"

set +e
host_out="$(GROK_BIN=/bin/true main --host "$bad_model" 2>&1)"
host_rc=$?
set -e
(( host_rc == 2 )) || fail "invalid caller host label did not fail admission"
assert_no_hostile_output "$host_out" "caller host rejection"

iphone_prepare_state
printf '%s\n' "$bad_model" > "$IPHONE_NODE_FILE"
set +e
bad_node="$(iphone_node)"
node_rc=$?
set -e
(( node_rc != 0 )) || fail "invalid persisted iPhone node was admitted"
[[ -z "$bad_node" ]] || fail "invalid persisted iPhone node reached output"

echo "PASS: compatibility diagnostics validate or fingerprint hostile external data"
