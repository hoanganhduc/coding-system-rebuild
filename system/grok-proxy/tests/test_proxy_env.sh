#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export HOME="$tmp/home"
mkdir -p "$HOME/grok-proxy"
mkdir -p "$tmp/target" "$tmp/bin"
cp "$ROOT/egress.sh" "$tmp/target/egress.sh"
cp "$ROOT/grok-remote" "$tmp/target/grok-remote"
install -m 700 "$ROOT/tests/fixtures/fake-curl" "$tmp/bin/curl"

export PATH="$tmp/bin:$PATH"
export FAKE_CURL_LOG="$tmp/curl.log"
export HTTPS_PROXY="http://wrong-proxy.invalid:9999"
export ALL_PROXY="http://another-wrong-proxy.invalid:9999"
. "$tmp/target/egress.sh"

[[ "$(egress_country 'socks5h://127.0.0.1:1080')" == VN ]]
IFS='|' read -r https all no < "$FAKE_CURL_LOG"
[[ "$https" == unset ]]
[[ "$all" == socks5h://127.0.0.1:1080 ]]
[[ "$no" == "$NOPROXY" ]]

: > "$FAKE_CURL_LOG"
[[ "$(egress_country '')" == VN ]]
IFS='|' read -r https all no < "$FAKE_CURL_LOG"
[[ "$https" == unset && "$all" == unset && "$no" == unset ]]

echo "PASS: probes clear inherited proxies and use only the intended route"

# The same rule must reach the Grok child itself, not just curl probes.
cat > "$tmp/bin/fake-grok" <<'EOF'
#!/usr/bin/env bash
printf '%s|%s|%s|%s|%s\n' \
  "${HTTPS_PROXY-unset}" "${ALL_PROXY-unset}" "${NO_PROXY-unset}" \
  "$([[ -e /proc/$$/fd/9 ]] && printf inherited || printf closed)" \
  "$( : > "$FAKE_CACHE_PATH"; stat -c %a "$FAKE_CACHE_PATH" )" > "$FAKE_GROK_LOG"
EOF
chmod 700 "$tmp/bin/fake-grok"

(
  umask 002
  export GROK_BIN="$tmp/bin/fake-grok"
  export FAKE_GROK_LOG="$tmp/grok-direct.log"
  export FAKE_CACHE_PATH="$tmp/direct-model-cache"
  . "$tmp/target/grok-remote"
  watch_egress(){ sleep 30; }
  model_args(){ :; }
  egress_ip(){ printf 'test'; }
  set_active direct
  exec 9>"$tmp/direct.lock"
  launch
)
IFS='|' read -r https all no fd mode < "$tmp/grok-direct.log"
[[ "$https" == unset && "$all" == unset && "$no" == unset && "$fd" == closed && "$mode" == 600 ]]

(
  umask 002
  export GROK_BIN="$tmp/bin/fake-grok"
  export FAKE_GROK_LOG="$tmp/grok-phone.log"
  export FAKE_CACHE_PATH="$tmp/phone-model-cache"
  . "$tmp/target/grok-remote"
  watch_egress(){ sleep 30; }
  model_args(){ :; }
  egress_ip(){ printf 'test'; }
  set_active iphone 100.64.0.99
  exec 9>"$tmp/phone.lock"
  launch
)
IFS='|' read -r https all no fd mode < "$tmp/grok-phone.log"
[[ "$https" == unset && "$all" == "$PROXY" && "$no" == "$NOPROXY" && "$fd" == closed && "$mode" == 600 ]]

echo "PASS: Grok children receive only the selected route, a private umask, and no session lock"

# Watchdog/deep probes invoke Grok through models_via() after launch has forked
# the watcher.  They must recreate the shared model cache privately even when
# the caller started grok-remote from a cooperative umask.
cat > "$tmp/bin/fake-grok-models" <<'EOF'
#!/usr/bin/env bash
: > "$FAKE_CACHE_PATH"
printf 'Available models:\n  * grok-4.5\n'
EOF
chmod 700 "$tmp/bin/fake-grok-models"

(
  umask 002
  export GROK_BIN="$tmp/bin/fake-grok-models"
  export GROK_MODELS_CACHE="$tmp/probe-model-cache"
  export FAKE_CACHE_PATH="$GROK_MODELS_CACHE"
  . "$tmp/target/egress.sh"
  [[ "$(models_via "$PROXY" iphone)" == grok-4.5 ]]
  [[ "$(stat -c %a "$GROK_MODELS_CACHE")" == 600 ]]
)

echo "PASS: watchdog model probes recreate Grok's shared cache privately"
