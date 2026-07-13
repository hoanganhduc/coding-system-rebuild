#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/target"
cp "$ROOT/egress.sh" "$tmp/target/egress.sh"
cp "$ROOT/grok-remote" "$tmp/target/grok-remote"
printf '%s\n' 'pc 100.64.0.2 user 22' > "$tmp/target/hosts.conf"

(
  export GROK_IPHONE_STATE_DIR="$tmp/no-phone"
  unset GROK_IPHONE_EXIT_NODE
  . "$tmp/target/egress.sh"
  build_ladder
  [[ "${LADDER[*]}" == 'local:pc vpn' ]]
)

(
  export GROK_IPHONE_STATE_DIR="$tmp/phone"
  export GROK_IPHONE_EXIT_NODE="100.64.0.99"
  mkdir -p "$GROK_IPHONE_STATE_DIR"
  printf '%s\n' n-test-phone > "$GROK_IPHONE_STATE_DIR/exit-node"
  printf '%s\n' n-test-phone > "$GROK_IPHONE_STATE_DIR/ready"
  . "$tmp/target/egress.sh"
  build_ladder
  [[ "${LADDER[*]}" == 'local:pc iphone vpn' ]]

  # A phone is re-probed even without an explicit model pin because its public
  # egress can change while the Tailscale peer remains online.
  REQUIRE_MODEL=""
  confirm_log="$tmp/confirm"
  rung_probe(){ printf '%s\n' "$1" > "$confirm_log"; }
  rung_alive(){ return 1; }
  rung_confirm iphone
  [[ "$(cat "$confirm_log")" == iphone ]]

  # Demotion resumes after the phone, at VPN, and forbids a direct fallback.
  set_active iphone 100.64.0.99
  rung_down(){ :; }
  select_egress(){ printf '%s %s\n' "$1" "$2" > "$tmp/demote"; }
  demote
  [[ "$(cat "$tmp/demote")" == '2 0' ]]
)

# A persistent phone sidecar is not reusable on peer liveness alone. Re-probe it
# before launch and reselect when its current Wi-Fi/cellular egress no longer qualifies.
(
  export GROK_IPHONE_STATE_DIR="$tmp/reuse-phone"
  export GROK_IPHONE_EXIT_NODE="100.64.0.99"
  . "$tmp/target/grok-remote"
  set_active iphone 100.64.0.99
  acquire_session_lock(){ :; }
  rung_alive(){ :; }
  rung_probe(){ printf '%s\n' "$1" > "$tmp/reuse-probe"; return 1; }
  rung_down(){ printf '%s\n' "$1" > "$tmp/reuse-down"; }
  select_egress(){ set_active vpn; }
  launch(){ active_rung > "$tmp/reuse-launch"; }
  main
)
[[ "$(cat "$tmp/reuse-probe")" == iphone ]]
[[ "$(cat "$tmp/reuse-down")" == iphone ]]
[[ "$(cat "$tmp/reuse-launch")" == vpn ]]

for stale in iphone vpn; do
  (
    export GROK_IPHONE_STATE_DIR="$tmp/stale-$stale"
    . "$tmp/target/grok-remote"
    set_active "$stale"
    acquire_session_lock(){ :; }
    rung_alive(){ return 1; }
    teardown_all(){ : > "$tmp/stale-$stale-down"; clear_active; }
    select_egress(){
      [[ -e "$tmp/stale-$stale-down" ]] || return 1
      set_active local:pc user@100.64.0.2 22
    }
    launch(){ active_rung > "$tmp/stale-$stale-launch"; }
    main
  )
  [[ "$(cat "$tmp/stale-$stale-launch")" == local:pc ]]
done

echo "PASS: iPhone ladder placement, re-probe, and fail-closed demotion are enforced"
