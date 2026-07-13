#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
listener=""
cleanup(){
  [[ -n "$listener" ]] && kill "$listener" 2>/dev/null || true
  if [[ -s "$tmp/target/state/tailscaled.pid" ]]; then kill "$(cat "$tmp/target/state/tailscaled.pid")" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

port="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

mkdir -p "$tmp/target"
cp "$ROOT/egress.sh" "$tmp/target/egress.sh"
install -m 700 "$ROOT/tests/fixtures/fake-tailscale" "$tmp/fake-tailscale"
install -m 700 "$ROOT/tests/fixtures/fake-tailscaled.py" "$tmp/fake-tailscaled"
mkdir -p "$tmp/target/state"
printf '%s\n' n-test-phone > "$tmp/target/state/exit-node"
printf '%s\n' n-test-phone > "$tmp/target/state/ready"

(
  export GROK_PROXY_PORT="$port"
  export GROK_TAILSCALE_BIN="$tmp/fake-tailscale"
  export GROK_TAILSCALED_BIN="$tmp/fake-tailscaled"
  export GROK_IPHONE_STATE_DIR="$tmp/target/state"
  export GROK_IPHONE_EXIT_NODE="100.64.0.99"
  export FAKE_TAILSCALE_LOG="$tmp/tailscale.log"
  . "$tmp/target/egress.sh"
  exec 9>"$tmp/session.lock"
  flock -n 9
  iphone_up
  [[ "$(active_rung)" == iphone ]]
  iphone_alive
  # iphone_select_exit resolves the pinned node id to its Tailscale IP (set --exit-node rejects a raw
  # StableNodeID), so the sidecar is told the resolved 100.64.0.99, not the n-test-phone id.
  grep -q -- '--exit-node=100.64.0.99' "$tmp/tailscale.log"
  grep -q -- '--shields-up=true' "$tmp/tailscale.log"
  grep -q -- "--socket=$tmp/target/state/tailscaled.sock" "$tmp/tailscale.log"
  pid="$(pid_from_file "$IPHONE_PID")"
  pid_owns_proxy_port "$pid"
  [[ ! -e "/proc/$pid/fd/9" ]]
  printf '%s\n' n-wrong-phone > "$IPHONE_NODE_FILE"
  ! iphone_exit_online
  printf '%s\n' n-test-phone > "$IPHONE_NODE_FILE"
  iphone_down
  ! port_listening

  export FAKE_TAILSCALE_STATUS_JSON='{"BackendState":"Running","ExitNodeStatus":{"ID":"n-phone","Online":true,"TailscaleIPs":["100.64.0.99/32"]},"Peer":{"100.64.0.99":{"ID":"n-phone","HostName":"localhost","DNSName":"iphone-xr.example.ts.net.","TailscaleIPs":["100.64.0.99"]}}}'
  printf '%s\n' iphone-xr > "$IPHONE_NODE_FILE"
  iphone_start
  iphone_exit_online
  iphone_down
  unset FAKE_TAILSCALE_STATUS_JSON

  iphone_setup "100.64.0.99"
  [[ "$(cat "$IPHONE_NODE_FILE")" == n-test-phone ]]
  [[ "$(cat "$IPHONE_READY_FILE")" == n-test-phone ]]
  unset GROK_IPHONE_EXIT_NODE
  iphone_configured

  marker="$tmp/state-was-sourced"
  printf 'RUNG=$(touch %s)\nDEST=\nSPORT=22\n' "$marker" > "$STATE"
  ! active_rung
  [[ ! -e "$marker" ]]
)

# A different process owns the endpoint. The fake sidecar cannot bind, and the
# readiness check must reject the unrelated listener rather than accept any LISTEN.
python3 -m http.server "$port" --bind 0.0.0.0 >/dev/null 2>&1 &
listener=$!
for _ in $(seq 1 20); do ss -H -lnt "sport = :$port" | grep -q . && break; sleep 0.05; done
(
  export GROK_PROXY_PORT="$port"
  export GROK_TAILSCALE_BIN="$tmp/fake-tailscale"
  export GROK_TAILSCALED_BIN="$tmp/fake-tailscaled"
  export GROK_IPHONE_STATE_DIR="$tmp/target/state-wrong"
  export GROK_IPHONE_EXIT_NODE="100.64.0.99"
  . "$tmp/target/egress.sh"
  ! pid_owns_proxy_port "$listener"       # correct PID on 0.0.0.0 is not a loopback-only owner
  ! iphone_start
)
kill -0 "$listener"

echo "PASS: proxy readiness requires the expected process to own the listener"
