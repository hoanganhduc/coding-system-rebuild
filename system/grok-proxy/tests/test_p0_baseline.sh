#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail(){ printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Production has one fixed namespace. A user override would otherwise let the
# shell create/check one namespace while the root helper mutates another.
set +e
out="$(GROK_VPN_NETNS=alternate bash -c '. "$1/egress.sh"' _ "$ROOT" 2>&1)"
rc=$?
set -e
(( rc != 0 )) || fail "nondefault GROK_VPN_NETNS was accepted"
[[ "$out" == *"fixed to grokvpn"* ]] || fail "namespace rejection was not explicit"

# Invalid stability values must be normalized before arithmetic is attempted.
value="$(GROK_VPN_STABILITY_CHECKS=not-a-number ROOT="$ROOT" bash -c '
  . "$ROOT/egress.sh"
  printf "%s" "$VPN_STABILITY_CHECKS"
' 2>/dev/null)"
[[ "$value" == 3 ]] || fail "invalid stability count did not normalize to 3"

value="$(GROK_VPN_STABILITY_CHECKS=999 ROOT="$ROOT" bash -c '
  . "$ROOT/egress.sh"
  printf "%s" "$VPN_STABILITY_CHECKS"
' 2>/dev/null)"
[[ "$value" == 10 ]] || fail "stability count was not capped at 10"

# Stability means one unchanged exit identity, not merely N nonempty replies.
ROOT="$ROOT" COUNTER="$tmp/counter" bash -c '
  export GROK_VPN_STABILITY_CHECKS=2
  . "$ROOT/egress.sh"
  sleep(){ :; }
  printf 0 > "$COUNTER"
  eg_curl(){
    n=$(cat "$COUNTER"); n=$((n + 1)); printf "%s" "$n" > "$COUNTER"
    if (( n == 1 )); then printf "ip=198.51.100.10\n"; else printf "ip=198.51.100.11\n"; fi
  }
  ! vpn_stable
'

ROOT="$ROOT" COUNTER="$tmp/counter" bash -c '
  export GROK_VPN_STABILITY_CHECKS=2
  . "$ROOT/egress.sh"
  sleep(){ :; }
  eg_curl(){ printf "ip=198.51.100.10\n"; }
  vpn_stable
'

# No live environment value may select a path that later crosses sudo.
set +e
out="$(GROK_VPNGATE=/tmp/untrusted-helper bash -c '. "$1/egress.sh"' _ "$ROOT" 2>&1)"
rc=$?
set -e
(( rc != 0 )) || fail "GROK_VPNGATE selected a live privileged helper"
[[ "$out" == *"GROK_VPNGATE is not supported"* ]] || fail "privileged-path rejection was not explicit"

# Test substitution is a function-level, nonprivileged seam and is accepted
# only when the explicit test gate is present.
set +e
GROK_TEST_VPN_BROKER=/tmp/fake ROOT="$ROOT" bash -c '. "$ROOT/egress.sh"' >/dev/null 2>&1
rc=$?
set -e
(( rc != 0 )) || fail "test broker seam was accepted outside GROK_TESTING"

mode="$(GROK_TESTING=1 GROK_TEST_VPN_BROKER=/tmp/fake ROOT="$ROOT" bash -c '
  . "$ROOT/egress.sh"
  printf "%s" "$VPN_BROKER_MODE"
')"
[[ "$mode" == test ]] || fail "test broker seam was not isolated"

# Provider-up maps reached shell stages to fixed codes. The Python adapter
# separately normalizes pre-dispatch, guard, exec, and signal failures to 29.
# This function-level seam verifies exact stage selection and cleanup order.
ROOT="$ROOT" LEDGER="$tmp/provider-up-ledger" bash -c '
  . "$ROOT/egress.sh"
  fail_stage=0
  fail_internal=0
  fail_cleanup=0
  clear_calls=0
  selected_internal=local:fixture
  mark(){ printf " %s" "$1" >> "$LEDGER"; }
  provider_validate_context(){ mark context; (( fail_stage != 20 )); }
  provider_validate_rung(){ mark rung; (( fail_stage != 21 )); }
  provider_validate_frozen_rung(){ mark frozen; (( fail_stage != 22 )); }
  provider_internal_rung(){
    mark internal
    (( fail_internal == 0 )) || return 1
    printf %s "$selected_internal"
  }
  port_owner_pid(){ mark port; (( fail_stage == 24 )) && printf 123; return 0; }
  clear_active(){
    mark clear
    clear_calls=$((clear_calls + 1))
    (( fail_stage != 25 )) || return 1
    (( fail_cleanup == 0 || clear_calls == 1 ))
  }
  rung_up(){
    mark up
    case "$fail_stage" in
      26) return 1 ;;
      30|31|32|33|34|35) return "$fail_stage" ;;
    esac
    return 0
  }
  rung_alive(){ mark alive; (( fail_stage != 27 )); }
  rung_down(){ mark down; (( fail_cleanup == 0 )); }
  provider_write_inventory(){ mark inventory; (( fail_stage != 28 )); }
  expected_calls(){
    case "$1" in
      20) printf " context" ;;
      21) printf " context rung" ;;
      22) printf " context rung frozen" ;;
      23) printf " context rung frozen" ;;
      24) printf " context rung frozen internal port" ;;
      25) printf " context rung frozen internal port clear" ;;
      26) printf " context rung frozen internal port clear up down clear" ;;
      27) printf " context rung frozen internal port clear up alive down clear" ;;
      28) printf " context rung frozen internal port clear up alive inventory down clear" ;;
    esac
  }
  for expected in 20 21 22 23 24 25 26 27 28; do
    fail_stage=$expected
    clear_calls=0
    : > "$LEDGER"
    rung=home:fixture
    (( expected == 23 )) && rung=direct
    set +e
    provider_up_command "$rung" >/dev/null 2>&1
    rc=$?
    set -e
    (( rc == expected )) || exit 1
    [[ "$(cat "$LEDGER")" == "$(expected_calls "$expected")" ]] || exit 1
  done
  fail_stage=0
  fail_internal=1
  clear_calls=0
  : > "$LEDGER"
  set +e
  provider_up_command home:fixture >/dev/null 2>&1
  rc=$?
  set -e
  (( rc == 21 )) || exit 1
  [[ "$(cat "$LEDGER")" == " context rung frozen internal" ]] || exit 1
  fail_internal=0
  for expected in 26 27 28; do
    fail_stage=$expected
    fail_cleanup=1
    clear_calls=0
    : > "$LEDGER"
    set +e
    provider_up_command home:fixture >/dev/null 2>&1
    rc=$?
    set -e
    (( rc == expected )) || exit 1
    [[ "$(cat "$LEDGER")" == "$(expected_calls "$expected")" ]] || exit 1
  done
  fail_stage=0
  fail_cleanup=0
  clear_calls=0
  : > "$LEDGER"
  provider_up_command home:fixture >/dev/null 2>&1
  [[ "$(cat "$LEDGER")" == " context rung frozen internal port clear up alive inventory" ]]

  selected_internal=vpn
  for expected in 31 32 33 34; do
    fail_stage=$expected
    clear_calls=0
    : > "$LEDGER"
    set +e
    provider_up_command vpn >/dev/null 2>&1
    rc=$?
    set -e
    (( rc == expected )) || exit 1
    [[ "$(cat "$LEDGER")" == "$(expected_calls 26)" ]] || exit 1
  done
  for unexpected in 30 35; do
    fail_stage=$unexpected
    clear_calls=0
    : > "$LEDGER"
    set +e
    provider_up_command vpn >/dev/null 2>&1
    rc=$?
    set -e
    (( rc == 26 )) || exit 1
    [[ "$(cat "$LEDGER")" == "$(expected_calls 26)" ]] || exit 1
  done

  selected_internal=local:fixture
  for spoofed in 30 31 32 33 34; do
    fail_stage=$spoofed
    clear_calls=0
    : > "$LEDGER"
    set +e
    provider_up_command home:fixture >/dev/null 2>&1
    rc=$?
    set -e
    (( rc == 26 )) || exit 1
    [[ "$(cat "$LEDGER")" == "$(expected_calls 26)" ]] || exit 1
  done
'

# VPN startup assigns a closed provider-only code to each local substage.  A
# dependency's arbitrary status and output never cross the provider boundary.
ROOT="$ROOT" LEDGER="$tmp/vpn-up-ledger" bash -c '
  . "$ROOT/egress.sh"
  PROVIDER_MODE=1
  fail_stage=0
  mark(){ printf " %s" "$1" >> "$LEDGER"; }
  prepare_socks_runtime(){ mark prepare; return 0; }
  vpn_broker_call(){
    mark "broker:$1"
    [[ "$1" == down ]] && return 0
    (( fail_stage != 31 )) || return 71
  }
  vpn_tun_alive(){ mark tun; (( fail_stage != 32 )) || return 72; }
  socks_alive(){ mark relay; (( fail_stage != 33 )) || return 73; }
  set_active(){ mark state; (( fail_stage != 34 )) || return 74; }
  expected_calls(){
    case "$1" in
      31) printf " prepare broker:up" ;;
      32) printf " prepare broker:up tun broker:down" ;;
      33) printf " prepare broker:up tun relay broker:down" ;;
      34) printf " prepare broker:up tun relay state broker:down" ;;
    esac
  }
  for expected in 31 32 33 34; do
    fail_stage=$expected
    : > "$LEDGER"
    set +e
    vpn_up up >/dev/null 2>&1
    rc=$?
    set -e
    (( rc == expected )) || exit 1
    [[ "$(cat "$LEDGER")" == "$(expected_calls "$expected")" ]] || exit 1
  done

  # Feature-off and compatibility-handoff callers keep their historical
  # generic nonzero contract even though the same local substages are known.
  for mode in compatibility handoff; do
    PROVIDER_MODE=0
    HANDOFF_MODE=0
    [[ "$mode" == handoff ]] && HANDOFF_MODE=1
    for expected in 31 32 33 34; do
      fail_stage=$expected
      : > "$LEDGER"
      set +e
      vpn_up up >/dev/null 2>&1
      rc=$?
      set -e
      (( rc == 1 )) || exit 1
      [[ "$(cat "$LEDGER")" == "$(expected_calls "$expected")" ]] || exit 1
    done
  done
'

# Atomic state publication removes its exact temporary after rename failure.
ROOT="$ROOT" ACTIVE_STATE="$tmp/active.state" bash -c '
  . "$ROOT/egress.sh"
  STATE="$ACTIVE_STATE"
  mv(){ return 47; }
  set +e
  set_active vpn
  rc=$?
  set -e
  (( rc != 0 ))
  [[ ! -e "$STATE" && ! -L "$STATE" ]]
  ! compgen -G "$STATE.*" >/dev/null
'

# The VPN relay is privileged only through the fixed broker.  No compatibility
# or provider path may sudo-execute the user-selected release copy.
if grep -Eq 'sudo.*(python3|SOCKS_NETNS)' "$ROOT/egress.sh"; then
  fail "egress still sudo-executes a user-selected relay path"
fi
grep -q -- '--listen-port "$PORT"' "$ROOT/egress.sh" \
  || fail "egress did not bind relay ownership to the broker request port"

# Teardown tries every component but reports failure if any exact cleanup fails.
ROOT="$ROOT" bash -c '
  . "$ROOT/egress.sh"
  calls=""
  local_down(){ calls+=" local"; return 11; }
  iphone_down(){ calls+=" iphone"; return 12; }
  vpn_down(){ calls+=" vpn"; return 13; }
  clear_active(){ calls+=" state"; return 0; }
  set +e
  teardown_all
  rc=$?
  set -e
  [[ "$calls" == " local iphone vpn state" ]]
  (( rc != 0 ))
'

# Public compatibility commands must propagate the aggregate result.  Use
# isolated HOME/control paths and a failing test broker so no deployed state is
# read or mutated.
mkdir -p "$tmp/home" "$tmp/public-control"
chmod 700 "$tmp/home" "$tmp/public-control"
set +e
out="$(HOME="$tmp/home" XDG_STATE_HOME="$tmp/home/.local/state" \
  GROK_TESTING=1 GROK_TEST_CONTROL_DIR="$tmp/public-control" \
  GROK_TEST_VPN_BROKER=/bin/false \
  ROOT="$ROOT" bash -c '. "$ROOT/grok-remote"; main stop' 2>&1)"
rc=$?
set -e
(( rc != 0 )) || fail "public stop reported success after teardown failure"
[[ "$out" != *"egress torn down"* ]] || fail "public stop printed false success"
[[ "$out" == *"ownership state was preserved"* ]] \
  || fail "public stop failure did not explain recovery state"

# The stable fence survives loss of the live flock holder and blocks all legacy
# mutations until recovery clears it. Test paths require the explicit test gate.
control="$tmp/control"
mkdir -p "$control"
chmod 700 "$control"
printf '%s\n' '{"boot_id":"00000000-0000-0000-0000-000000000000","owner_epoch":"dead-test-epoch","phase":"READY","pid":999999,"pid_start_ticks":1,"release_id":"test-release","schema_version":1}' > "$control/recovery.fence"
chmod 600 "$control/recovery.fence"
set +e
out="$(GROK_TESTING=1 GROK_TEST_CONTROL_DIR="$control" ROOT="$ROOT" bash -c '
  . "$ROOT/egress.sh"
  standalone_mutation_lock
' 2>&1)"
rc=$?
set -e
(( rc != 0 )) || fail "legacy mutation ignored the durable recovery fence"
[[ "$out" == *"recovery fence"* ]] || fail "fence refusal was not explicit"

echo "PASS: P0 namespace, stability, privilege, teardown, and fence invariants hold"
