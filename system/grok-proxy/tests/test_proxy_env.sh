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
printf '%s|%s|%s|%s\n' \
  "${HTTPS_PROXY-unset}" "${ALL_PROXY-unset}" "${NO_PROXY-unset}" \
  "$([[ -e /proc/$$/fd/9 ]] && printf inherited || printf closed)" > "$FAKE_GROK_LOG"
EOF
chmod 700 "$tmp/bin/fake-grok"

(
  export GROK_BIN="$tmp/bin/fake-grok"
  export FAKE_GROK_LOG="$tmp/grok-direct.log"
  . "$tmp/target/grok-remote"
  watch_egress(){ sleep 30; }
  model_args(){ :; }
  egress_ip(){ printf 'test'; }
  set_active direct
  exec 9>"$tmp/direct.lock"
  launch
)
IFS='|' read -r https all no fd < "$tmp/grok-direct.log"
[[ "$https" == unset && "$all" == unset && "$no" == unset && "$fd" == closed ]]

(
  export GROK_BIN="$tmp/bin/fake-grok"
  export FAKE_GROK_LOG="$tmp/grok-phone.log"
  . "$tmp/target/grok-remote"
  watch_egress(){ sleep 30; }
  model_args(){ :; }
  egress_ip(){ printf 'test'; }
  set_active iphone 100.64.0.99
  exec 9>"$tmp/phone.lock"
  launch
)
IFS='|' read -r https all no fd < "$tmp/grok-phone.log"
[[ "$https" == unset && "$all" == "$PROXY" && "$no" == "$NOPROXY" && "$fd" == closed ]]

echo "PASS: Grok children receive only the selected route and do not inherit the session lock"
