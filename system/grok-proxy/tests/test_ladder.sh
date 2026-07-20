#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export GROK_TESTING=1
export GROK_TEST_CONTROL_DIR="$tmp/control"
mkdir -p "$GROK_TEST_CONTROL_DIR"
chmod 700 "$GROK_TEST_CONTROL_DIR"
mkdir -p "$tmp/target"
cp "$ROOT/egress.sh" "$tmp/target/egress.sh"
mkdir -p "$tmp/target/grok_ms"
cp "$ROOT/grok_ms/ios_registry.py" "$tmp/target/grok_ms/ios_registry.py"
cp "$ROOT/grok-remote" "$tmp/target/grok-remote"
printf '%s\n' 'pc 100.64.0.2 user 22' > "$tmp/target/hosts.conf"

register_test_ios(){
  local directory="$1"
  mkdir -p "$directory"
  chmod 700 "$directory"
  printf '%s\n' '{"devices":[{"key":"iphone","stable_node_id":"n-test-phone"}],"schema_version":1}' \
    > "$directory/devices.json"
  chmod 600 "$directory/devices.json"
}

# Compatibility routing gives one device at most ten seconds and clips that
# attempt to the shared iOS-family deadline.
(
  export GROK_IPHONE_STATE_DIR="$tmp/ios-deadline-phone"
  . "$tmp/target/egress.sh"
  SECONDS=100
  IOS_FAMILY_DEADLINE_SECONDS=0
  ios_attempt_begin
  first_remaining="$(ios_attempt_remaining)"
  (( first_remaining > 0 && first_remaining <= 10 ))
  ios_attempt_end
  IOS_FAMILY_DEADLINE_SECONDS=$((SECONDS + 3))
  ios_attempt_begin
  family_remaining="$(ios_attempt_remaining)"
  (( family_remaining > 0 && family_remaining <= 3 ))
  IOS_ATTEMPT_DEADLINE_SECONDS="$SECONDS"
  ! ios_attempt_check
  IOS_FAMILY_DEADLINE_SECONDS="$SECONDS"
  ! ios_attempt_begin
)

(
  export GROK_IPHONE_STATE_DIR="$tmp/no-phone"
  unset GROK_IPHONE_EXIT_NODE
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  build_ladder
  [[ "${LADDER[*]}" == 'local:pc vpn' ]]
)

(
  export GROK_IPHONE_STATE_DIR="$tmp/phone"
  export GROK_IPHONE_EXIT_NODE="100.64.0.99"
  mkdir -p "$GROK_IPHONE_STATE_DIR"
  chmod 700 "$GROK_IPHONE_STATE_DIR"
  printf '%s\n' n-test-phone > "$GROK_IPHONE_STATE_DIR/exit-node"
  printf '%s\n' n-test-phone > "$GROK_IPHONE_STATE_DIR/ready"
  chmod 600 "$GROK_IPHONE_STATE_DIR/exit-node" "$GROK_IPHONE_STATE_DIR/ready"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  build_ladder
  [[ "${LADDER[*]}" == 'local:pc ios:iphone vpn' ]]

  # A phone is re-probed even without an explicit model pin because its public
  # egress can change while the Tailscale peer remains online.
  REQUIRE_MODEL=""
  confirm_log="$tmp/confirm"
  rung_probe_available(){ printf '%s\n' "$1" > "$confirm_log"; }
  rung_alive(){ return 1; }
  rung_confirm ios:iphone
  [[ "$(cat "$confirm_log")" == ios:iphone ]]

  # Demotion resumes after the phone, at VPN, and forbids a direct fallback.
  set_active ios:iphone n-test-phone
  rung_down(){ :; }
  select_egress(){ printf '%s %s\n' "$1" "$2" > "$tmp/demote"; }
  demote
  [[ "$(cat "$tmp/demote")" == '2 0' ]]
)

# A home route publishes its exact destination before starting the SSH effect.
# If state cannot be written, no control master or SOCKS listener is created.
(
  export GROK_IPHONE_STATE_DIR="$tmp/host-state-before-effect-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  tcp_ok(){ :; }
  set_active(){ : > "$tmp/host-state-before-effect-attempted"; return 1; }
  ssh(){ : > "$tmp/host-state-before-effect-ssh"; return 0; }
  ! local_up_one pc 100.64.0.2 user 22
  [[ -e "$tmp/host-state-before-effect-attempted" ]]
  [[ ! -e "$tmp/host-state-before-effect-ssh" && -z "$(active_rung 2>/dev/null || true)" ]]
)

# A new home route never unlinks an unexplained control path.  Callers must
# prove teardown first; an ownerless leftover blocks startup for recovery.
(
  export GROK_IPHONE_STATE_DIR="$tmp/host-unowned-control-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' sentinel > "$CTL"
  tcp_ok(){ :; }
  ssh(){ : > "$tmp/host-unowned-control-ssh"; return 0; }
  ! local_up_one pc 100.64.0.2 user 22
  [[ "$(cat "$CTL")" == sentinel ]]
  [[ ! -e "$tmp/host-unowned-control-ssh" \
     && -z "$(active_rung 2>/dev/null || true)" ]]
  rm -f "$CTL"
)

# The phone route publishes its cleanup identity before starting the sidecar.
# If startup and rollback both fail, the state remains available for recovery.
(
  export GROK_IPHONE_STATE_DIR="$tmp/phone-state-before-effect"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  iphone_configured(){ :; }
  iphone_node(){ printf '%s' n-test-phone; }
  iphone_start(){
    [[ "$(active_rung)" == iphone ]]
    [[ "$(active_dest)" == n-test-phone ]]
    : > "$tmp/phone-state-before-effect-started"
    return 1
  }
  iphone_down(){ : > "$tmp/phone-state-before-effect-down-failed"; return 1; }
  ! iphone_up
  [[ -e "$tmp/phone-state-before-effect-started" \
     && -e "$tmp/phone-state-before-effect-down-failed" ]]
  [[ "$(active_rung)" == iphone && "$(active_dest)" == n-test-phone ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

# Direct selection must propagate atomic state-publication failure rather than
# claim a route that has no ownership record.
(
  export GROK_IPHONE_STATE_DIR="$tmp/direct-publication-failure-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active(){ return 1; }
  ! rung_up direct
)

# If SSH startup fails after ownership publication and exact cleanup is also
# uncertain, retain the destination so a later stop/recovery can retry it.
(
  export GROK_IPHONE_STATE_DIR="$tmp/host-start-failure-retains-state-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  tcp_ok(){ :; }
  ssh(){ return 1; }
  local_down(){
    [[ "$(active_dest)" == user@100.64.0.2 ]]
    : > "$tmp/host-start-failure-local-down"
    return 1
  }
  ! local_up_one pc 100.64.0.2 user 22
  [[ -e "$tmp/host-start-failure-local-down" ]]
  [[ "$(active_rung)" == local:pc && "$(active_dest)" == user@100.64.0.2 ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

# Automatic selection treats a retained local startup identity as terminal.
# It must not overwrite that destination with another rung or direct fallback.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-host-start-uncertain-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  ALLOW_DIRECT=1
  begin_clean_route_transition(){ begin_recovery_transition; }
  learn_baseline(){ :; }
  build_ladder(){ LADDER=(local:pc iphone vpn); }
  rung_up(){
    if [[ "$1" == local:pc ]]; then
      set_active local:pc user@100.64.0.2 22
      return 1
    fi
    : > "$tmp/automatic-host-start-uncertain-next-rung"
    return 1
  }
  try_vpn_sequence(){ : > "$tmp/automatic-host-start-uncertain-vpn"; return 1; }
  ! select_egress
  [[ "$(active_rung)" == local:pc && "$(active_dest)" == user@100.64.0.2 ]]
  [[ ! -e "$tmp/automatic-host-start-uncertain-next-rung" \
     && ! -e "$tmp/automatic-host-start-uncertain-vpn" ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

# A local route that came up but failed its probe is likewise terminal when
# exact teardown fails; selection cannot continue over the occupied listener.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-host-probe-cleanup-failure-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  ALLOW_DIRECT=1
  begin_clean_route_transition(){ begin_recovery_transition; }
  learn_baseline(){ :; }
  build_ladder(){ LADDER=(local:pc iphone vpn); }
  rung_up(){
    [[ "$1" == local:pc ]] || { : > "$tmp/automatic-host-probe-next-rung"; return 1; }
    set_active local:pc user@100.64.0.2 22
  }
  rung_probe_available(){ return 1; }
  rung_down(){ [[ "$1" == local:pc ]] || return 97; return 1; }
  try_vpn_sequence(){ : > "$tmp/automatic-host-probe-vpn"; return 1; }
  ! select_egress
  [[ "$(active_rung)" == local:pc && "$(active_dest)" == user@100.64.0.2 ]]
  [[ ! -e "$tmp/automatic-host-probe-next-rung" \
     && ! -e "$tmp/automatic-host-probe-vpn" ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

# Automatic selection must retain VPN ownership when the last failed candidate
# cannot be torn down.  It may not erase that identity and fall back to direct.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-vpn-cleanup-failure-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  ALLOW_DIRECT=1
  begin_clean_route_transition(){ begin_recovery_transition; }
  learn_baseline(){ :; }
  build_ladder(){ LADDER=(vpn); }
  try_vpn_sequence(){ set_active vpn; return 1; }
  vpn_down(){ : > "$tmp/automatic-vpn-cleanup-failed"; return 1; }
  ! select_egress
  [[ -e "$tmp/automatic-vpn-cleanup-failed" ]]
  [[ "$(active_rung)" == vpn ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

# Empty STATE is not enough when provider residue remains.  The full selector
# reconciles all providers first and refuses every later rung/direct fallback
# when an ownerless SSH control path cannot be proved safe.
(
  export GROK_IPHONE_STATE_DIR="$tmp/ownerless-control-selection-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  printf '%s\n' sentinel > "$CTL"
  vpn_down(){ : > "$tmp/ownerless-control-selection-vpn-down"; }
  iphone_down(){ : > "$tmp/ownerless-control-selection-phone-down"; }
  learn_baseline(){ :; }
  build_ladder(){ LADDER=(local:pc iphone vpn); }
  rung_up(){ : > "$tmp/ownerless-control-selection-raised"; return 1; }
  try_vpn_sequence(){ : > "$tmp/ownerless-control-selection-vpn"; return 1; }
  ! select_egress
  [[ "$(cat "$CTL")" == sentinel ]]
  recovery_transition_pending
  [[ -e "$tmp/ownerless-control-selection-vpn-down" \
     && -e "$tmp/ownerless-control-selection-phone-down" ]]
  [[ ! -e "$tmp/ownerless-control-selection-raised" \
     && ! -e "$tmp/ownerless-control-selection-vpn" \
     && -z "$(active_rung 2>/dev/null || true)" ]]
  rm -f "$CTL" "$RECOVERY_MARKER"
)

# Selection itself requires empty ownership state.  This last-line guard keeps
# every caller from overwriting a route that it forgot to stop first.
(
  export GROK_IPHONE_STATE_DIR="$tmp/nonempty-selection-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active local:pc fixture@pc 22
  learn_baseline(){ :; }
  build_ladder(){ LADDER=(iphone vpn); }
  rung_up(){ : > "$tmp/nonempty-selection-raised"; return 1; }
  try_vpn_sequence(){ : > "$tmp/nonempty-selection-vpn"; return 1; }
  ! select_egress
  [[ "$(active_rung)" == local:pc ]]
  [[ ! -e "$tmp/nonempty-selection-raised" \
     && ! -e "$tmp/nonempty-selection-vpn" ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

# Demotion cannot start a lower rung until teardown of the current one is
# proven.  A failed stop retains ownership and aborts the ladder walk.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-demote-cleanup-failure-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active local:pc fixture@pc 22
  rung_down(){ : > "$tmp/automatic-demote-down-failed"; return 1; }
  select_egress(){ : > "$tmp/automatic-demote-selected"; return 0; }
  ! demote
  [[ -e "$tmp/automatic-demote-down-failed" ]]
  [[ "$(active_rung)" == local:pc ]]
  [[ ! -e "$tmp/automatic-demote-selected" ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

# Aggregate cleanup invokes the validated VPN owner before the real iPhone
# absence proof, then repeats the pass to prove the shared port is empty.
(
  export GROK_IPHONE_STATE_DIR="$tmp/vpn-before-phone-teardown-order"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active vpn
  vpn_listener=1
  local_down(){ printf '%s\n' local >> "$tmp/teardown-order"; }
  vpn_down(){ printf '%s\n' vpn >> "$tmp/teardown-order"; vpn_listener=0; }
  port_listening(){ (( vpn_listener == 1 )); }
  teardown_all
  [[ "$(cat "$tmp/teardown-order")" == $'vpn\nlocal\nvpn\nlocal' ]]
  [[ -z "$(active_rung 2>/dev/null || true)" ]]
)

# The phone owner must likewise run before VPN's no-ledger absence proof.  A
# fake broker rejects while the phone owns the shared port; owner-first cleanup
# makes one aggregate stop converge and publish empty state.
(
  export GROK_IPHONE_STATE_DIR="$tmp/phone-before-vpn-teardown-order"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  set_active iphone n-test-phone
  phone_listener=1
  iphone_down(){ printf 'iphone\n' >> "$tmp/phone-before-vpn-order"; phone_listener=0; }
  local_down(){ printf 'local\n' >> "$tmp/phone-before-vpn-order"; }
  vpn_down(){
    printf 'vpn\n' >> "$tmp/phone-before-vpn-order"
    (( phone_listener == 0 ))
  }
  teardown_all
  [[ "$(cat "$tmp/phone-before-vpn-order")" == \
     $'iphone\nlocal\nvpn\niphone\nlocal\nvpn' ]]
  [[ ! -e "$STATE" && ! -e "$RECOVERY_MARKER" ]]
)

# With no usable state, a recognized phone residue may make the fallback VPN
# proof fail on the reconciliation pass.  The phone is removed later in that
# pass and the authoritative second pass then succeeds.
(
  export GROK_IPHONE_STATE_DIR="$tmp/ownerless-phone-two-pass-teardown"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  phone_listener=1
  local_down(){ printf 'local\n' >> "$tmp/ownerless-phone-two-pass-order"; }
  vpn_down(){
    printf 'vpn\n' >> "$tmp/ownerless-phone-two-pass-order"
    (( phone_listener == 0 ))
  }
  iphone_down(){ printf 'iphone\n' >> "$tmp/ownerless-phone-two-pass-order"; phone_listener=0; }
  teardown_all
  [[ "$(cat "$tmp/ownerless-phone-two-pass-order")" == \
     $'local\nvpn\niphone\nlocal\nvpn\niphone' ]]
  [[ ! -e "$STATE" && ! -e "$RECOVERY_MARKER" ]]
)

# Truly ambiguous shared-port ownership remains a failure on both bounded
# passes.  The marker is retained and empty state is never falsely published.
(
  export GROK_IPHONE_STATE_DIR="$tmp/ambiguous-listener-two-pass-teardown"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  set_active direct
  local_down(){ printf 'local\n' >> "$tmp/ambiguous-listener-two-pass-order"; return 1; }
  vpn_down(){ printf 'vpn\n' >> "$tmp/ambiguous-listener-two-pass-order"; return 1; }
  iphone_down(){ printf 'iphone\n' >> "$tmp/ambiguous-listener-two-pass-order"; return 1; }
  ! teardown_all
  [[ "$(cat "$tmp/ambiguous-listener-two-pass-order")" == \
     $'local\nvpn\niphone\nlocal\nvpn\niphone' ]]
  [[ "$(active_rung)" == direct ]]
  recovery_transition_pending
  rm -f "$STATE" "$RECOVERY_MARKER"
)

# A persistent phone sidecar is not reusable on peer liveness alone. Re-probe it
# before launch and reselect when its current Wi-Fi/cellular egress no longer qualifies.
(
  export GROK_IPHONE_STATE_DIR="$tmp/reuse-phone"
  export GROK_IPHONE_EXIT_NODE="100.64.0.99"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  set_active iphone 100.64.0.99
  acquire_session_lock(){ :; }
  rung_alive(){ :; }
  rung_probe_available(){ printf '%s\n' "$1" > "$tmp/reuse-probe"; return 1; }
  rung_down(){ printf '%s\n' "$1" > "$tmp/reuse-down"; }
  select_egress(){ set_active vpn; }
  launch(){ active_rung > "$tmp/reuse-launch"; }
  main
)
[[ "$(cat "$tmp/reuse-probe")" == iphone ]]
[[ "$(cat "$tmp/reuse-down")" == iphone ]]
[[ "$(cat "$tmp/reuse-launch")" == vpn ]]

# If that automatic phone re-probe fails and its sidecar cannot be stopped,
# retain its ownership record and never enter reselection.
set +e
(
  export GROK_IPHONE_STATE_DIR="$tmp/reuse-phone-cleanup-failure"
  export GROK_IPHONE_EXIT_NODE="100.64.0.99"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active iphone 100.64.0.99
  acquire_session_lock(){ :; }
  rung_alive(){ :; }
  rung_probe_available(){ return 1; }
  rung_down(){ : > "$tmp/reuse-phone-cleanup-failed"; return 1; }
  select_egress(){ : > "$tmp/reuse-phone-cleanup-selected"; return 1; }
  launch(){ : > "$tmp/reuse-phone-cleanup-launched"; }
  main
)
reuse_phone_cleanup_failure_rc=$?
set -e
(( reuse_phone_cleanup_failure_rc != 0 ))
[[ -e "$tmp/reuse-phone-cleanup-failed" ]]
[[ "$(awk -F= '$1 == "RUNG" { print $2 }' "$tmp/target/.egress.state")" == iphone ]]
[[ ! -e "$tmp/reuse-phone-cleanup-selected" \
   && ! -e "$tmp/reuse-phone-cleanup-launched" ]]
rm -f "$tmp/target/.egress.state" "$tmp/target/.egress.recovery-required"

# A forced VPN sequence that cannot clean up its last failed candidate retains
# VPN ownership and exits instead of clearing state or launching Grok.
set +e
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-vpn-cleanup-failure-phone"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  try_vpn_sequence(){ set_active vpn; return 1; }
  rung_down(){
    [[ "$1" == vpn ]] || return 97
    : > "$tmp/forced-vpn-cleanup-failed"
    return 1
  }
  no_egress_help(){ : > "$tmp/forced-vpn-cleanup-help"; }
  launch(){ : > "$tmp/forced-vpn-cleanup-launched"; }
  main --vpn
)
forced_vpn_cleanup_failure_rc=$?
set -e
(( forced_vpn_cleanup_failure_rc != 0 ))
[[ -e "$tmp/forced-vpn-cleanup-failed" ]]
[[ "$(awk -F= '$1 == "RUNG" { print $2 }' "$tmp/target/.egress.state")" == vpn ]]
[[ ! -e "$tmp/forced-vpn-cleanup-help" \
   && ! -e "$tmp/forced-vpn-cleanup-launched" ]]
rm -f "$tmp/target/.egress.state" "$tmp/target/.egress.recovery-required"

# An explicitly forced phone is a route choice, not an automatic value test.
# If it offers the remembered model, an equal direct catalog must not make the
# healthy requested route look unavailable.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-equal-phone"
  register_test_ios "$GROK_IPHONE_STATE_DIR"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' grok-4.5 > "$CHOICE"
  printf '%s\n' grok-4.5 > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ printf '%s\n' grok-4.5 > "$BASELINE"; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == ios:iphone ]] && set_active ios:iphone n-test-phone; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5; }
  launch(){
    [[ "$(active_rung)" == ios:iphone ]]
    local -a selected=()
    mapfile -t selected < <(model_args ios:iphone "$@")
    [[ "${selected[*]}" == '-m grok-4.5' ]]
    printf '%s\n' accepted > "$tmp/forced-equal-launched"
  }
  main --iphone
)
[[ "$(cat "$tmp/forced-equal-launched")" == accepted ]]

# An explicitly forced home host is likewise a route choice.  Equal direct and
# host catalogs must not reject a healthy named route that offers the remembered
# model.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-equal-host-phone"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' grok-4.5 > "$CHOICE"
  printf '%s\n' grok-4.5 > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ printf '%s\n' grok-4.5 > "$BASELINE"; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == local:pc ]] && set_active local:pc fixture@pc 22; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5; }
  launch(){
    [[ "$(active_rung)" == local:pc ]]
    local -a selected=()
    mapfile -t selected < <(model_args local:pc "$@")
    [[ "${selected[*]}" == '-m grok-4.5' ]]
    printf '%s\n' accepted > "$tmp/forced-equal-host-launched"
  }
  main --host pc
)
[[ "$(cat "$tmp/forced-equal-host-launched")" == accepted ]]

# Reusing the exact named host still requires a forced-route model probe; a
# live SOCKS listener alone is not admission evidence.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-reuse-host-phone"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' grok-4.5 > "$CHOICE"
  set_active local:pc fixture@pc 22
  acquire_session_lock(){ :; }
  rung_alive(){ :; }
  egress_country(){ printf '%s' VN; }
  models_via(){ : > "$tmp/forced-reuse-host-probed"; printf '%s\n' grok-4.5; }
  rung_down(){ : > "$tmp/forced-reuse-host-down"; return 1; }
  rung_up(){ : > "$tmp/forced-reuse-host-up"; return 1; }
  select_egress(){ : > "$tmp/forced-reuse-host-select"; return 1; }
  launch(){
    [[ "$(active_rung)" == local:pc ]]
    printf '%s\n' retained > "$tmp/forced-reuse-host-launched"
  }
  main --host pc
)
[[ "$(cat "$tmp/forced-reuse-host-probed")" == "" ]]
[[ "$(cat "$tmp/forced-reuse-host-launched")" == retained ]]
[[ ! -e "$tmp/forced-reuse-host-down" && ! -e "$tmp/forced-reuse-host-up" \
   && ! -e "$tmp/forced-reuse-host-select" ]]

# Host admission uses the same explicit > environment > remembered model
# precedence as the forced phone.  Offering only the explicit model therefore
# proves that neither lower-priority value was used for qualification.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-explicit-host-phone"
  export GROK_REQUIRE_MODEL=grok-env
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' grok-choice > "$CHOICE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == local:pc ]] && set_active local:pc fixture@pc 22; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-explicit; }
  launch(){
    [[ "$*" == '-m grok-explicit' ]]
    printf '%s\n' explicit > "$tmp/forced-explicit-host-launched"
  }
  main --host pc -m grok-explicit
)
[[ "$(cat "$tmp/forced-explicit-host-launched")" == explicit ]]

# A reused forced host that lacks the explicit target is removed, retried once
# as the same route, then fails closed without launching or entering the ladder.
set +e
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-missing-host-phone"
  unset GROK_REQUIRE_MODEL
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' grok-choice > "$CHOICE"
  set_active local:pc fixture@pc 22
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ :; }
  rung_up(){
    [[ "$1" == local:pc ]] || return 97
    printf 'up:%s\n' "$1" >> "$tmp/forced-missing-host-route-log"
    set_active local:pc fixture@pc 22
  }
  rung_down(){
    [[ "$1" == local:pc ]] || return 97
    printf 'down:%s\n' "$1" >> "$tmp/forced-missing-host-route-log"
    clear_active
  }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-build; }
  select_egress(){ : > "$tmp/forced-missing-host-selected"; return 1; }
  launch(){ : > "$tmp/forced-missing-host-launched"; }
  main --host pc -m grok-4.5
)
forced_missing_host_rc=$?
set -e
(( forced_missing_host_rc != 0 ))
[[ "$(cat "$tmp/forced-missing-host-route-log")" == $'down:local:pc\nup:local:pc\ndown:local:pc' ]]
[[ ! -e "$tmp/forced-missing-host-launched" \
   && ! -e "$tmp/forced-missing-host-selected" ]]

# If the reused host no longer qualifies but its SSH master/listener cannot be
# stopped, retain the exact ownership record and exit.  Retrying or clearing
# state would lose the destination needed for a later exact cleanup.
set +e
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-reuse-host-down-failure-phone"
  unset GROK_REQUIRE_MODEL
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active local:pc fixture@pc 22
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  rung_alive(){ :; }
  rung_down(){
    [[ "$1" == local:pc ]] || return 97
    printf '%s\n' "$1" > "$tmp/forced-reuse-host-down-failure"
    return 1
  }
  rung_up(){ : > "$tmp/forced-reuse-host-down-failure-up"; return 1; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-build; }
  launch(){ : > "$tmp/forced-reuse-host-down-failure-launched"; }
  main --host pc -m grok-4.5
)
forced_reuse_host_down_failure_rc=$?
set -e
(( forced_reuse_host_down_failure_rc != 0 ))
[[ "$(cat "$tmp/forced-reuse-host-down-failure")" == local:pc ]]
[[ "$(awk -F= '$1 == "RUNG" { print $2 }' "$tmp/target/.egress.state")" == local:pc ]]
[[ ! -e "$tmp/forced-reuse-host-down-failure-up" \
   && ! -e "$tmp/forced-reuse-host-down-failure-launched" ]]
rm -f "$tmp/target/.egress.state" "$tmp/target/.egress.recovery-required"

# The same state-preservation rule applies after a fresh forced host came up
# but failed its model probe: a teardown failure must retain the exact route.
set +e
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-fresh-host-down-failure-phone"
  unset GROK_REQUIRE_MODEL
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){
    [[ "$1" == local:pc ]] || return 97
    set_active local:pc fixture@pc 22
  }
  rung_down(){
    [[ "$1" == local:pc ]] || return 97
    printf '%s\n' "$1" > "$tmp/forced-fresh-host-down-failure"
    return 1
  }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-build; }
  launch(){ : > "$tmp/forced-fresh-host-down-failure-launched"; }
  main --host pc -m grok-4.5
)
forced_fresh_host_down_failure_rc=$?
set -e
(( forced_fresh_host_down_failure_rc != 0 ))
[[ "$(cat "$tmp/forced-fresh-host-down-failure")" == local:pc ]]
[[ "$(awk -F= '$1 == "RUNG" { print $2 }' "$tmp/target/.egress.state")" == local:pc ]]
[[ ! -e "$tmp/forced-fresh-host-down-failure-launched" ]]
rm -f "$tmp/target/.egress.state" "$tmp/target/.egress.recovery-required"

# Successful exact admission cleanup owns state deletion itself; rung_down
# only proves that the provider stopped.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-discard-success-phone"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active local:pc fixture@pc 22
  rung_down(){ [[ "$1" == local:pc ]] || return 97; }
  discard_failed_exact_route local:pc
  [[ -z "$(active_rung 2>/dev/null || true)" ]]
)

# Routed model listing is preference-neutral for a forced host and receives its
# complete valid catalog without injecting or persisting a model choice.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-models-host-phone"
  unset GROK_REQUIRE_MODEL
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  : > "$CHOICE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == local:pc ]] && set_active local:pc fixture@pc 22; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5 grok-build; }
  launch(){
    [[ "$*" == models ]]
    local -a selected=()
    mapfile -t selected < <(model_args local:pc "$@")
    (( ${#selected[@]} == 0 ))
    [[ ! -s "$CHOICE" ]]
    [[ "$(tr '\n' ' ' < "$UNLOCKED")" == 'grok-4.5 grok-build ' ]]
  }
  main --host pc models
)

# The same explicit policy applies when the selected phone is already live:
# retain it instead of tearing it down and walking the automatic ladder.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-reuse-phone"
  register_test_ios "$GROK_IPHONE_STATE_DIR"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' grok-4.5 > "$CHOICE"
  printf '%s\n' grok-4.5 > "$BASELINE"
  set_active ios:iphone n-test-phone
  acquire_session_lock(){ :; }
  rung_alive(){ :; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5; }
  rung_down(){ : > "$tmp/forced-reuse-down"; return 1; }
  rung_up(){ : > "$tmp/forced-reuse-up"; return 1; }
  select_egress(){ : > "$tmp/forced-reuse-select"; return 1; }
  launch(){
    [[ "$(active_rung)" == ios:iphone ]]
    printf '%s\n' retained > "$tmp/forced-reuse-launched"
  }
  main --iphone
)
[[ "$(cat "$tmp/forced-reuse-launched")" == retained ]]
[[ ! -e "$tmp/forced-reuse-down" && ! -e "$tmp/forced-reuse-up" \
   && ! -e "$tmp/forced-reuse-select" ]]

# Explicit CLI model selection outranks both an environment pin and a remembered
# choice for forced-route admission and the final Grok argv.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-explicit-phone"
  register_test_ios "$GROK_IPHONE_STATE_DIR"
  export GROK_REQUIRE_MODEL=grok-env
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' grok-choice > "$CHOICE"
  printf '%s\n' grok-explicit > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == ios:iphone ]] && set_active ios:iphone n-test-phone; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-explicit; }
  launch(){
    [[ "$*" == '-m grok-explicit' ]]
    printf '%s\n' explicit > "$tmp/forced-explicit-launched"
  }
  main --iphone -m grok-explicit
)
[[ "$(cat "$tmp/forced-explicit-launched")" == explicit ]]

# Without an explicit CLI model, an existing environment pin outranks the
# remembered choice and stays aligned across admission, Grok argv, and repair.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-env-phone"
  register_test_ios "$GROK_IPHONE_STATE_DIR"
  export GROK_REQUIRE_MODEL=grok-env
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' grok-choice > "$CHOICE"
  rm -f "$SEEN"
  printf '%s\n' grok-choice grok-env > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == ios:iphone ]] && set_active ios:iphone n-test-phone; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-choice grok-env; }
  launch(){
    local -a selected=()
    mapfile -t selected < <(model_args ios:iphone "$@")
    [[ "${selected[*]}" == '-m grok-env' ]]
    [[ "$REQUIRE_MODEL" == grok-env && "$(cat "$CHOICE")" == grok-env ]]
  }
  main --iphone
)

# A forced phone must still fail closed when it does not offer the explicit
# target, and it must clean the route without launching Grok.
set +e
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-missing-phone"
  register_test_ios "$GROK_IPHONE_STATE_DIR"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' grok-build > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == ios:iphone ]] && set_active ios:iphone n-test-phone; }
  rung_down(){ printf '%s\n' cleaned > "$tmp/forced-missing-cleaned"; clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-build; }
  launch(){ : > "$tmp/forced-missing-launched"; }
  main --iphone -m grok-4.5
)
forced_missing_rc=$?
set -e
(( forced_missing_rc != 0 ))
[[ "$(cat "$tmp/forced-missing-cleaned")" == cleaned ]]
[[ ! -e "$tmp/forced-missing-launched" ]]

# With no explicit/environment pin, --pick-model receives the complete forced
# phone catalog even when it equals direct; only the selected choice is saved.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-picker-phone"
  register_test_ios "$GROK_IPHONE_STATE_DIR"
  unset GROK_REQUIRE_MODEL
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' grok-old > "$CHOICE"
  printf '%s\n' grok-4.5 grok-build grok-new > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == ios:iphone ]] && set_active ios:iphone n-test-phone; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5 grok-build grok-new; }
  interactive(){ :; }
  pick_model(){
    printf '%s\n' "$@" > "$tmp/forced-picker-options"
    printf '%s\n' grok-new > "$CHOICE"
  }
  launch(){
    local -a selected=()
    mapfile -t selected < <(model_args ios:iphone "$@")
    [[ "${selected[*]}" == '-m grok-new' ]]
  }
  main --iphone --pick-model
  [[ "$(cat "$CHOICE")" == grok-new ]]
)
[[ "$(tr '\n' ' ' < "$tmp/forced-picker-options")" == 'grok-4.5 grok-build grok-new ' ]]

# A routed model-listing subcommand is preference-neutral when no environment
# pin exists: it accepts any valid nonempty phone catalog and injects no model.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-models-phone"
  register_test_ios "$GROK_IPHONE_STATE_DIR"
  unset GROK_REQUIRE_MODEL
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  : > "$CHOICE"
  printf '%s\n' grok-4.5 > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == ios:iphone ]] && set_active ios:iphone n-test-phone; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5; }
  launch(){
    [[ "$*" == models ]]
    local -a selected=()
    mapfile -t selected < <(model_args ios:iphone "$@")
    (( ${#selected[@]} == 0 ))
    [[ ! -s "$CHOICE" ]]
  }
  main --iphone models
)

# An intentionally empty remembered choice remains "let grok decide" when the
# complete forced catalog was already seen; it is not replaced by a default.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-empty-choice-phone"
  register_test_ios "$GROK_IPHONE_STATE_DIR"
  unset GROK_REQUIRE_MODEL
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  : > "$CHOICE"
  printf '%s\n' grok-4.5 grok-build > "$SEEN"
  printf '%s\n' grok-4.5 grok-build > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == ios:iphone ]] && set_active ios:iphone n-test-phone; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5 grok-build; }
  launch(){
    local -a selected=()
    mapfile -t selected < <(model_args ios:iphone "$@")
    (( ${#selected[@]} == 0 ))
    [[ ! -s "$CHOICE" ]]
  }
  main --iphone
)

# Forced intent never bypasses country policy, and the model API is not probed
# after a known blocked exit is identified.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-blocked-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  UNLOCKED="$tmp/forced-blocked-unlocked"
  egress_country(){ printf '%s' DE; }
  models_via(){ : > "$tmp/forced-blocked-models-called"; printf '%s\n' grok-4.5; }
  ! rung_probe_forced iphone grok-4.5
  [[ ! -e "$tmp/forced-blocked-models-called" && ! -e "$UNLOCKED" ]]
)

# Once launch pins a model, deep phone confirmation continues to use the exact
# model predicate; another nonempty catalog is not enough to remain healthy.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-watchdog-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  BASELINE="$tmp/forced-watchdog-baseline"
  UNLOCKED="$tmp/forced-watchdog-unlocked"
  REQUIRE_MODEL=grok-4.5
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-build; }
  ! rung_confirm iphone
  [[ ! -s "$UNLOCKED" ]]
)

# Forced route intent must survive beyond initial admission.  With no model
# pin, the watchdog still accepts a healthy equal catalog through the forced
# predicate instead of reverting to automatic baseline-delta discovery.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-watchdog-unpinned-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  BASELINE="$tmp/forced-watchdog-unpinned-baseline"
  UNLOCKED="$tmp/forced-watchdog-unpinned-unlocked"
  FORCE_EXACT_ROUTE=iphone
  REQUIRE_MODEL=""
  printf '%s\n' grok-4.5 > "$BASELINE"
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5; }
  rung_confirm iphone
  [[ "$(cat "$UNLOCKED")" == grok-4.5 ]]
)

# If the explicitly selected phone does fail, its watchdog must tear down and
# retry only that route.  It must never silently demote the session to VPN.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-watchdog-failure-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  FORCE_EXACT_ROUTE=iphone
  WATCH_INTERVAL=0
  DEEP_EVERY=0
  RUNG_RETRIES=0
  set_active iphone
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles == 1 )); }
  rung_alive(){ return 1; }
  teardown_forced_exact(){ printf '%s\n' phone-only > "$tmp/forced-watchdog-torn-down"; clear_active; }
  demote(){ : > "$tmp/forced-watchdog-demoted"; return 1; }
  watch_egress
  [[ "$(cat "$tmp/forced-watchdog-torn-down")" == phone-only ]]
  [[ ! -e "$tmp/forced-watchdog-demoted" && -z "$(active_rung)" ]]
)

# The empty-state retry branch likewise reacquires only the forced phone and
# never invokes the automatic ladder.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-watchdog-reacquire-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  FORCE_EXACT_ROUTE=iphone
  WATCH_INTERVAL=0
  clear_active
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles == 1 )); }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  rung_up(){ [[ "$1" == iphone ]] || return 97; set_active iphone; }
  rung_confirm(){ [[ "$1" == iphone ]] || return 97; printf '%s\n' confirmed > "$tmp/forced-watchdog-reacquired"; }
  select_egress(){ : > "$tmp/forced-watchdog-auto-selected"; return 1; }
  watch_egress
  [[ "$(cat "$tmp/forced-watchdog-reacquired")" == confirmed ]]
[[ ! -e "$tmp/forced-watchdog-auto-selected" && "$(active_rung)" == iphone ]]
)

# A terminal forced-host failure is also exact-route-only: tear down and leave
# the state empty instead of demoting into the automatic phone/VPN ladder.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-watchdog-failure-host-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  FORCE_EXACT_ROUTE=local:pc
  WATCH_INTERVAL=0
  DEEP_EVERY=0
  RUNG_RETRIES=0
  set_active local:pc fixture@pc 22
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles == 1 )); }
  rung_alive(){ return 1; }
  teardown_forced_exact(){ printf '%s\n' host-only > "$tmp/forced-watchdog-host-torn-down"; clear_active; }
  demote(){ : > "$tmp/forced-watchdog-host-demoted"; return 1; }
  watch_egress
  [[ "$(cat "$tmp/forced-watchdog-host-torn-down")" == host-only ]]
  [[ ! -e "$tmp/forced-watchdog-host-demoted" && -z "$(active_rung)" ]]
)

# Empty-state recovery for a forced host retries only the same local label and
# does not call automatic selection.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-watchdog-reacquire-host-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  FORCE_EXACT_ROUTE=local:pc
  WATCH_INTERVAL=0
  clear_active
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles == 1 )); }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  rung_up(){ [[ "$1" == local:pc ]] || return 97; set_active local:pc fixture@pc 22; }
  rung_confirm(){ [[ "$1" == local:pc ]] || return 97; printf '%s\n' confirmed > "$tmp/forced-watchdog-host-reacquired"; }
  select_egress(){ : > "$tmp/forced-watchdog-host-auto-selected"; return 1; }
  watch_egress
  [[ "$(cat "$tmp/forced-watchdog-host-reacquired")" == confirmed ]]
  [[ ! -e "$tmp/forced-watchdog-host-auto-selected" \
     && "$(active_rung)" == local:pc ]]
)

# A forced-host in-place repair must stop, raise, and confirm only the exact
# requested host.  This exercises the repair cycle separately from terminal
# teardown and empty-state reacquisition.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-watchdog-repair-host-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  FORCE_EXACT_ROUTE=local:pc
  WATCH_INTERVAL=0
  DEEP_EVERY=0
  RUNG_RETRIES=1
  set_active local:pc fixture@pc 22
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles <= 2 )); }
  rung_alive(){ (( cycles >= 2 )); }
  rung_down(){
    [[ "$1" == local:pc ]] || return 97
    printf 'down:%s\n' "$1" >> "$tmp/forced-watchdog-host-repair-log"
  }
  rung_up(){
    [[ "$1" == local:pc ]] || return 97
    printf 'up:%s\n' "$1" >> "$tmp/forced-watchdog-host-repair-log"
    set_active local:pc fixture@pc 22
  }
  rung_confirm(){
    [[ "$1" == local:pc ]] || return 97
    printf 'confirm:%s\n' "$1" >> "$tmp/forced-watchdog-host-repair-log"
  }
  demote(){ : > "$tmp/forced-watchdog-host-repair-demoted"; return 1; }
  watch_egress
  [[ "$(cat "$tmp/forced-watchdog-host-repair-log")" == \
     $'down:local:pc\nup:local:pc\nconfirm:local:pc' ]]
  [[ ! -e "$tmp/forced-watchdog-host-repair-demoted" \
     && "$(active_rung)" == local:pc ]]
)

# If a forced-host repair cannot stop the old SSH listener, it retains route
# ownership and must not try to raise or confirm a replacement over that port.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-watchdog-repair-down-failure-host-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  FORCE_EXACT_ROUTE=local:pc
  WATCH_INTERVAL=0
  DEEP_EVERY=0
  RUNG_RETRIES=1
  set_active local:pc fixture@pc 22
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles == 1 )); }
  rung_alive(){ return 1; }
  rung_down(){
    [[ "$1" == local:pc ]] || return 97
    : > "$tmp/forced-watchdog-host-repair-down-failed"
    return 1
  }
  rung_up(){ : > "$tmp/forced-watchdog-host-repair-down-failure-up"; return 1; }
  rung_confirm(){ : > "$tmp/forced-watchdog-host-repair-down-failure-confirm"; return 1; }
  demote(){ : > "$tmp/forced-watchdog-host-repair-down-failure-demoted"; return 1; }
  watch_egress
  [[ -e "$tmp/forced-watchdog-host-repair-down-failed" ]]
  [[ "$(active_rung)" == local:pc ]]
  [[ ! -e "$tmp/forced-watchdog-host-repair-down-failure-up" \
     && ! -e "$tmp/forced-watchdog-host-repair-down-failure-confirm" \
     && ! -e "$tmp/forced-watchdog-host-repair-down-failure-demoted" ]]
)

# The same stop-before-raise rule protects automatic watchdog repair.  A
# failed local teardown must not let a replacement unlink/reuse its socket.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-watchdog-repair-down-failure-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  FORCE_EXACT_ROUTE=""
  WATCH_INTERVAL=0
  DEEP_EVERY=0
  RUNG_RETRIES=1
  set_active local:pc fixture@pc 22
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles == 1 )); }
  rung_alive(){ return 1; }
  rung_down(){
    [[ "$1" == local:pc ]] || return 97
    : > "$tmp/automatic-watchdog-repair-down-failed"
    return 1
  }
  rung_up(){ : > "$tmp/automatic-watchdog-repair-up"; return 1; }
  rung_confirm(){ : > "$tmp/automatic-watchdog-repair-confirm"; return 1; }
  demote(){ : > "$tmp/automatic-watchdog-repair-demoted"; return 1; }
  watch_egress
  [[ -e "$tmp/automatic-watchdog-repair-down-failed" ]]
  [[ "$(active_rung)" == local:pc ]]
  [[ ! -e "$tmp/automatic-watchdog-repair-up" \
     && ! -e "$tmp/automatic-watchdog-repair-confirm" \
     && ! -e "$tmp/automatic-watchdog-repair-demoted" ]]
)

# A terminal exact-route teardown that cannot stop the SSH listener preserves
# route ownership.  The watchdog must not enter empty-state reacquisition.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-watchdog-down-failure-host-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  FORCE_EXACT_ROUTE=local:pc
  WATCH_INTERVAL=0
  DEEP_EVERY=0
  RUNG_RETRIES=0
  set_active local:pc fixture@pc 22
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles == 1 )); }
  rung_alive(){ return 1; }
  local_down(){ : > "$tmp/forced-watchdog-host-local-down-failed"; return 1; }
  iphone_down(){ :; }
  vpn_down(){ :; }
  rung_up(){ : > "$tmp/forced-watchdog-host-down-failure-up"; return 1; }
  demote(){ : > "$tmp/forced-watchdog-host-down-failure-demoted"; return 1; }
  watch_egress
  [[ -e "$tmp/forced-watchdog-host-local-down-failed" ]]
  [[ "$(active_rung)" == local:pc ]]
  [[ ! -e "$tmp/forced-watchdog-host-down-failure-up" \
     && ! -e "$tmp/forced-watchdog-host-down-failure-demoted" ]]
)

# The real terminal exact-route helper clears state after every provider
# teardown succeeds; provider stubs do not clear it on the helper's behalf.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-watchdog-clean-success-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  set_active local:pc fixture@pc 22
  local_down(){ :; }
  iphone_down(){ :; }
  vpn_down(){ :; }
  teardown_forced_exact
  [[ -z "$(active_rung 2>/dev/null || true)" ]]
)

# The automatic predicate is deliberately unchanged: an equal catalog still
# adds no routing value when the caller did not force the phone or home host.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-equal-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  BASELINE="$tmp/automatic-baseline"
  UNLOCKED="$tmp/automatic-unlocked"
  printf '%s\n' grok-4.5 > "$BASELINE"
  models_via(){ printf '%s\n' grok-4.5; }
  egress_country(){ printf '%s' VN; }
  ! rung_probe iphone
  ! rung_probe local:pc
  [[ ! -s "$UNLOCKED" ]]
)

# Initial automatic selection follows configured route priority. A healthy
# first home route with a nonempty equal catalog must be committed immediately;
# later phone/VPN rungs and direct fallback must remain untouched.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-equal-home-priority-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  BASELINE="$tmp/automatic-equal-home-priority-baseline"
  UNLOCKED="$tmp/automatic-equal-home-priority-unlocked"
  ALLOW_DIRECT=1
  begin_clean_route_transition(){ begin_recovery_transition; }
  learn_baseline(){ printf '%s\n' grok-4.5 > "$BASELINE"; }
  build_ladder(){ LADDER=(local:windows iphone vpn); }
  rung_up(){
    if [[ "$1" == local:windows ]]; then
      set_active local:windows fixture@windows 22
      return 0
    fi
    : > "$tmp/automatic-equal-home-priority-later-rung"
    return 1
  }
  rung_probe(){ return 1; }
  rung_probe_available(){
    [[ "$1" == local:windows && -z "${2:-}" ]]
    printf '%s\n' grok-4.5 > "$UNLOCKED"
  }
  rung_down(){ clear_active; }
  try_vpn_sequence(){
    : > "$tmp/automatic-equal-home-priority-vpn"
    return 1
  }
  select_egress
  [[ "$(active_rung)" == local:windows ]]
  [[ "$(cat "$UNLOCKED")" == grok-4.5 ]]
  [[ ! -e "$tmp/automatic-equal-home-priority-later-rung" \
     && ! -e "$tmp/automatic-equal-home-priority-vpn" ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

# An unavailable earlier host is skipped, but the first later usable host still
# wins before phone, VPN, or direct fallback.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-next-home-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  BASELINE="$tmp/automatic-next-home-baseline"
  UNLOCKED="$tmp/automatic-next-home-unlocked"
  begin_clean_route_transition(){ begin_recovery_transition; }
  learn_baseline(){ printf '%s\n' grok-4.5 > "$BASELINE"; }
  build_ladder(){ LADDER=(local:arch local:windows iphone vpn); }
  rung_up(){
    printf '%s\n' "$1" >> "$tmp/automatic-next-home-order"
    [[ "$1" == local:arch ]] && return 1
    if [[ "$1" == local:windows ]]; then
      set_active local:windows fixture@windows 22
      return 0
    fi
    return 1
  }
  rung_probe_available(){ printf '%s\n' grok-4.5 > "$UNLOCKED"; }
  try_vpn_sequence(){ : > "$tmp/automatic-next-home-vpn"; return 1; }
  select_egress
  [[ "$(active_rung)" == local:windows ]]
  [[ "$(cat "$tmp/automatic-next-home-order")" == $'local:arch\nlocal:windows' ]]
  [[ ! -e "$tmp/automatic-next-home-vpn" ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

# A concrete automatic model requirement is passed to every route probe. A
# route that lacks it is cleaned up before the next candidate is admitted.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-required-model-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  BASELINE="$tmp/automatic-required-model-baseline"
  UNLOCKED="$tmp/automatic-required-model-unlocked"
  begin_clean_route_transition(){ begin_recovery_transition; }
  learn_baseline(){ printf '%s\n' grok-required > "$BASELINE"; }
  build_ladder(){ LADDER=(local:first local:second); }
  rung_up(){ set_active "$1" "fixture@${1#local:}" 22; }
  rung_probe_available(){
    [[ "${2:-}" == grok-required ]]
    [[ "$1" == local:first ]] && return 1
    printf '%s\n' grok-required > "$UNLOCKED"
  }
  rung_down(){
    printf '%s\n' "$1" > "$tmp/automatic-required-model-down"
    clear_active
  }
  select_egress 0 1 grok-required
  [[ "$(active_rung)" == local:second ]]
  [[ "$(cat "$tmp/automatic-required-model-down")" == local:first ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

# Direct fallback is catalog-qualified. It cannot satisfy a missing concrete
# model and remains prohibited when ALLOW_DIRECT is zero.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-direct-model-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  BASELINE="$tmp/automatic-direct-model-baseline"
  UNLOCKED="$tmp/automatic-direct-model-unlocked"
  baseline_value=grok-build
  begin_clean_route_transition(){ begin_recovery_transition; }
  build_ladder(){ LADDER=(); }
  learn_baseline(){ printf '%s\n' "$baseline_value" > "$BASELINE"; }
  ! select_egress 0 1 grok-required
  [[ -z "$(active_rung 2>/dev/null || true)" ]]
  baseline_value=grok-required
  select_egress 0 1 grok-required
  [[ "$(active_rung)" == direct ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
  ALLOW_DIRECT=0
  ! select_egress 0 1 grok-required
  [[ -z "$(active_rung 2>/dev/null || true)" ]]
  rm -f "$RECOVERY_MARKER"
)

# A prior direct fallback is not sticky. A later bare invocation tears down
# that state and re-walks preferred routes, passing an explicit model through
# to automatic admission.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-direct-rewalk-phone"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active direct
  acquire_session_lock(){ :; }
  rung_alive(){ :; }
  teardown_all(){ : > "$tmp/automatic-direct-rewalk-down"; clear_active; }
  select_egress(){
    printf '%s\n' "${3:-}" > "$tmp/automatic-direct-rewalk-model"
    set_active local:windows fixture@windows 22
  }
  launch(){ active_rung > "$tmp/automatic-direct-rewalk-launch"; }
  main -m grok-required
  [[ -e "$tmp/automatic-direct-rewalk-down" ]]
  [[ "$(cat "$tmp/automatic-direct-rewalk-model")" == grok-required ]]
  [[ "$(cat "$tmp/automatic-direct-rewalk-launch")" == local:windows ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

for stale in iphone vpn; do
  (
    export GROK_IPHONE_STATE_DIR="$tmp/stale-$stale"
    . "$tmp/target/grok-remote"
    rm -f "$RECOVERY_MARKER"
    begin_clean_route_transition(){ begin_recovery_transition; }
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

# A later automatic invocation cannot discard a stale local route when exact
# SSH teardown fails.  Preserve the destination and never enter reselection.
set +e
(
  export GROK_IPHONE_STATE_DIR="$tmp/stale-local-cleanup-failure-phone"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active local:pc fixture@pc 22
  acquire_session_lock(){ :; }
  rung_alive(){ return 1; }
  local_down(){ return 1; }
  iphone_down(){ :; }
  vpn_down(){ :; }
  select_egress(){ : > "$tmp/stale-local-cleanup-failure-selected"; return 1; }
  launch(){ : > "$tmp/stale-local-cleanup-failure-launched"; }
  main
)
stale_local_cleanup_failure_rc=$?
set -e
(( stale_local_cleanup_failure_rc != 0 ))
[[ "$(awk -F= '$1 == "RUNG" { print $2 }' "$tmp/target/.egress.state")" == local:pc ]]
[[ ! -e "$tmp/stale-local-cleanup-failure-selected" \
   && ! -e "$tmp/stale-local-cleanup-failure-launched" ]]
rm -f "$tmp/target/.egress.state" "$tmp/target/.egress.recovery-required"

# A malformed ownership file is still ownership uncertainty.  Forced routing
# must attempt aggregate cleanup and may not overwrite it with a fresh route.
set +e
(
  export GROK_IPHONE_STATE_DIR="$tmp/malformed-state-forced-host-phone"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' 'not-a-valid-state' > "$STATE"
  acquire_session_lock(){ :; }
  local_down(){ return 1; }
  iphone_down(){ :; }
  vpn_down(){ :; }
  rung_up(){ : > "$tmp/malformed-state-forced-host-up"; return 1; }
  learn_baseline(){ :; }
  launch(){ : > "$tmp/malformed-state-forced-host-launched"; }
  main --host pc
)
malformed_state_forced_host_rc=$?
set -e
(( malformed_state_forced_host_rc != 0 ))
[[ "$(cat "$tmp/target/.egress.state")" == not-a-valid-state ]]
[[ ! -e "$tmp/malformed-state-forced-host-up" \
   && ! -e "$tmp/malformed-state-forced-host-launched" ]]
rm -f "$tmp/target/.egress.state" "$tmp/target/.egress.recovery-required"

# Reuse accepts only the exact owned mode-0600 state shape.  A plausible RUNG
# line cannot hide missing, malformed, duplicate, extra, or symlinked fields.
(
  export GROK_IPHONE_STATE_DIR="$tmp/state-shape-validation-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  for payload in \
    $'RUNG=direct\n' \
    $'RUNG=direct\nDEST=\nSPORT=bad\n' \
    $'RUNG=direct\nDEST=\nSPORT=22\nEXTRA=value\n' \
    $'RUNG=direct\nRUNG=vpn\nDEST=\nSPORT=22\n'; do
    printf '%s' "$payload" > "$STATE"
    chmod 600 "$STATE"
    ! state_record_valid
    ! active_rung
  done
  valid_target="$tmp/state-shape-valid-target"
  printf 'RUNG=direct\nDEST=\nSPORT=22\n' > "$valid_target"
  chmod 600 "$valid_target"
  rm -f "$STATE"
  ln -s "$valid_target" "$STATE"
  ! state_record_valid
  ! active_rung
  rm -f "$STATE" "$valid_target"
)

# Even with no selected state, a partial cleanup publishes a durable recovery
# marker.  Later selection must retry cleanup instead of walking the ladder.
(
  export GROK_IPHONE_STATE_DIR="$tmp/empty-state-recovery-marker-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  declare -F recovery_transition_pending >/dev/null
  clear_active
  rm -f "$RECOVERY_MARKER"
  rm -f "$RECOVERY_MARKER"
  local_down(){ return 1; }
  iphone_down(){ :; }
  vpn_down(){ :; }
  ! teardown_all
  recovery_transition_pending
  select_egress(){ : > "$tmp/empty-state-recovery-marker-selected"; return 1; }
  ! ensure_selected_egress
  [[ ! -e "$tmp/empty-state-recovery-marker-selected" ]]
  rm -f "$RECOVERY_MARKER"
)

# The `ip` shortcut follows the same stale-route cleanup gate as a normal
# launch.  It cannot enter selection while a stale SSH listener is uncertain.
set +e
(
  export GROK_IPHONE_STATE_DIR="$tmp/ip-stale-local-cleanup-failure-phone"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active local:pc fixture@pc 22
  acquire_session_lock(){ :; }
  rung_alive(){ return 1; }
  local_down(){ return 1; }
  iphone_down(){ :; }
  vpn_down(){ :; }
  select_egress(){ : > "$tmp/ip-stale-local-selected"; return 1; }
  egress_ip(){ : > "$tmp/ip-stale-local-reported"; }
  main ip
)
ip_stale_local_cleanup_failure_rc=$?
set -e
(( ip_stale_local_cleanup_failure_rc != 0 ))
[[ "$(awk -F= '$1 == "RUNG" { print $2 }' "$tmp/target/.egress.state")" == local:pc ]]
[[ ! -e "$tmp/ip-stale-local-selected" \
   && ! -e "$tmp/ip-stale-local-reported" ]]
rm -f "$tmp/target/.egress.state" "$tmp/target/.egress.recovery-required"

# The actual sourced standalone select command uses the shared cleanup gate;
# this avoids release admission and network effects while testing its dispatch.
(
  export GROK_IPHONE_STATE_DIR="$tmp/standalone-select-stale-local-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  declare -F standalone_select_command >/dev/null
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active local:pc fixture@pc 22
  rung_alive(){ return 1; }
  local_down(){ return 1; }
  iphone_down(){ :; }
  vpn_down(){ :; }
  select_egress(){ : > "$tmp/standalone-select-stale-local-selected"; return 1; }
  standalone_mutation_lock(){ :; }
  ! standalone_select_command
  [[ "$(active_rung)" == local:pc ]]
  [[ ! -e "$tmp/standalone-select-stale-local-selected" ]]
  clear_active
  rm -f "$RECOVERY_MARKER"
)

# `stop` reports failure and preserves the exact local ownership record when
# the SSH master/listener cannot be proven stopped.
set +e
(
  export GROK_IPHONE_STATE_DIR="$tmp/stop-local-cleanup-failure-phone"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active local:pc fixture@pc 22
  acquire_session_lock(){ :; }
  local_down(){ return 1; }
  iphone_down(){ :; }
  vpn_down(){ :; }
  main stop
)
stop_local_cleanup_failure_rc=$?
set -e
(( stop_local_cleanup_failure_rc != 0 ))
[[ "$(awk -F= '$1 == "RUNG" { print $2 }' "$tmp/target/.egress.state")" == local:pc ]]
rm -f "$tmp/target/.egress.state" "$tmp/target/.egress.recovery-required"

# Aggregate stop is fail-closed even when the failed component is not the
# selected provider.  State changes only after every cleanup path succeeds.
set +e
(
  export GROK_IPHONE_STATE_DIR="$tmp/stop-unrelated-cleanup-failure-phone"
  . "$tmp/target/grok-remote"
  rm -f "$RECOVERY_MARKER"
  begin_clean_route_transition(){ begin_recovery_transition; }
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active direct
  acquire_session_lock(){ :; }
  local_down(){ return 1; }
  iphone_down(){ :; }
  vpn_down(){ :; }
  main stop
)
stop_unrelated_cleanup_failure_rc=$?
set -e
(( stop_unrelated_cleanup_failure_rc != 0 ))
[[ "$(awk -F= '$1 == "RUNG" { print $2 }' "$tmp/target/.egress.state")" == direct ]]
rm -f "$tmp/target/.egress.state" "$tmp/target/.egress.recovery-required"

# Aggregate cleanup must never use an iPhone DEST value as an SSH destination.
# A socket that is not owned by a local:* record remains untouched and blocks
# the transition without receiving an OpenSSH control command.
(
  export GROK_IPHONE_STATE_DIR="$tmp/iphone-state-local-control-mismatch-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  rm -f "$RECOVERY_MARKER"
  set_active iphone n-test-phone
  socket_ready="$tmp/iphone-state-local-control-ready"
  python3 - "$CTL" "$socket_ready" <<'PY' &
import socket
import sys
import time

control, ready = sys.argv[1:]
server = socket.socket(socket.AF_UNIX)
server.bind(control)
open(ready, "w", encoding="ascii").close()
try:
    time.sleep(30)
finally:
    server.close()
PY
  socket_pid=$!
  trap 'kill "$socket_pid" 2>/dev/null || true; wait "$socket_pid" 2>/dev/null || true' EXIT
  for _ in $(seq 1 100); do
    [[ -S "$CTL" && -e "$socket_ready" ]] && break
    sleep 0.01
  done
  [[ -S "$CTL" && -e "$socket_ready" ]]
  ssh(){ : > "$tmp/iphone-state-local-control-ssh"; }
  vpn_down(){ :; }
  iphone_down(){ :; }
  ! teardown_all
  recovery_transition_pending
  [[ "$(active_rung)" == iphone && "$(active_dest)" == n-test-phone ]]
  [[ -S "$CTL" && ! -e "$tmp/iphone-state-local-control-ssh" ]]
  kill "$socket_pid"
  wait "$socket_pid" 2>/dev/null || true
  trap - EXIT
  rm -f "$CTL" "$STATE" "$RECOVERY_MARKER"
)

# Transition publication is fail-before-effect.  If the marker cannot be
# published, aggregate cleanup does not touch any provider.
(
  export GROK_IPHONE_STATE_DIR="$tmp/recovery-marker-publication-failure-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  begin_recovery_transition(){ return 1; }
  local_down(){ : > "$tmp/recovery-marker-publication-local"; }
  vpn_down(){ : > "$tmp/recovery-marker-publication-vpn"; }
  iphone_down(){ : > "$tmp/recovery-marker-publication-iphone"; }
  ! teardown_all
  [[ ! -e "$tmp/recovery-marker-publication-local" \
     && ! -e "$tmp/recovery-marker-publication-vpn" \
     && ! -e "$tmp/recovery-marker-publication-iphone" ]]
)

# A failed state clear retains both the selected record and the durable marker.
(
  export GROK_IPHONE_STATE_DIR="$tmp/recovery-state-clear-failure-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  set_active direct
  local_down(){ :; }
  vpn_down(){ :; }
  iphone_down(){ :; }
  clear_active(){ return 1; }
  ! teardown_all
  recovery_transition_pending
  [[ "$(active_rung)" == direct ]]
  rm -f "$STATE" "$RECOVERY_MARKER"
)

# If publishing EMPTY cannot remove the marker, the state may be gone but the
# marker remains the durable instruction for the next cleanup-only cycle.
(
  export GROK_IPHONE_STATE_DIR="$tmp/recovery-marker-end-failure-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  set_active direct
  local_down(){ :; }
  vpn_down(){ :; }
  iphone_down(){ :; }
  end_recovery_transition(){ return 1; }
  ! teardown_all
  [[ ! -e "$STATE" ]]
  recovery_transition_pending
  rm -f "$RECOVERY_MARKER"
)

# An invalid marker is ownership uncertainty, not permission to clean or
# replace anything.  It fails before all provider effects and stays in place.
(
  export GROK_IPHONE_STATE_DIR="$tmp/invalid-recovery-marker-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  printf '%s\n' INVALID > "$RECOVERY_MARKER"
  chmod 600 "$RECOVERY_MARKER"
  local_down(){ : > "$tmp/invalid-recovery-marker-local"; }
  vpn_down(){ : > "$tmp/invalid-recovery-marker-vpn"; }
  iphone_down(){ : > "$tmp/invalid-recovery-marker-iphone"; }
  ! teardown_all
  [[ "$(cat "$RECOVERY_MARKER")" == INVALID ]]
  [[ ! -e "$tmp/invalid-recovery-marker-local" \
     && ! -e "$tmp/invalid-recovery-marker-vpn" \
     && ! -e "$tmp/invalid-recovery-marker-iphone" ]]
  rm -f "$RECOVERY_MARKER"
)

# A rejected repair that is stopped exactly must publish EMPTY before the next
# cycle.  The next cycle can then reacquire only the forced route.
(
  export GROK_IPHONE_STATE_DIR="$tmp/watchdog-rejected-repair-clean-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  FORCE_EXACT_ROUTE=local:pc
  WATCH_INTERVAL=0
  DEEP_EVERY=0
  RUNG_RETRIES=1
  set_active local:pc fixture@pc 22
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles <= 2 )); }
  rung_alive(){ return 1; }
  begin_clean_route_transition(){
    [[ ! -e "$STATE" && ! -e "$RECOVERY_MARKER" ]] || return 91
    : > "$tmp/watchdog-rejected-repair-proved-empty"
    begin_recovery_transition
  }
  rung_down(){
    [[ "$1" == local:pc ]] || return 97
    printf 'down\n' >> "$tmp/watchdog-rejected-repair-log"
  }
  rung_up(){
    [[ "$1" == local:pc ]] || return 97
    printf 'up\n' >> "$tmp/watchdog-rejected-repair-log"
    set_active local:pc fixture@pc 22
  }
  confirm_calls=0
  rung_confirm(){
    [[ "$1" == local:pc ]] || return 97
    printf 'confirm\n' >> "$tmp/watchdog-rejected-repair-log"
    confirm_calls=$((confirm_calls + 1))
    (( confirm_calls >= 2 ))
  }
  watch_egress
  [[ "$(cat "$tmp/watchdog-rejected-repair-log")" == \
     $'down\nup\nconfirm\ndown\nup\nconfirm' ]]
  [[ -e "$tmp/watchdog-rejected-repair-proved-empty" ]]
  [[ "$(active_rung)" == local:pc ]]
  ! recovery_transition_pending
)

# A rejected repair whose rollback cannot stop the replacement retains both
# state and marker.  Every later watchdog cycle is cleanup-only: no second
# raise, confirmation, or demotion may occur over the uncertain owner.
(
  export GROK_IPHONE_STATE_DIR="$tmp/watchdog-rejected-repair-uncertain-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  FORCE_EXACT_ROUTE=local:pc
  WATCH_INTERVAL=0
  DEEP_EVERY=0
  RUNG_RETRIES=1
  set_active local:pc fixture@pc 22
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles <= 2 )); }
  rung_alive(){ return 1; }
  down_calls=0
  rung_down(){
    [[ "$1" == local:pc ]] || return 97
    down_calls=$((down_calls + 1))
    printf 'down\n' >> "$tmp/watchdog-rejected-repair-uncertain-log"
    (( down_calls == 1 ))
  }
  rung_up(){
    printf 'up\n' >> "$tmp/watchdog-rejected-repair-uncertain-log"
    set_active local:pc fixture@pc 22
  }
  rung_confirm(){ printf 'confirm\n' >> "$tmp/watchdog-rejected-repair-uncertain-log"; return 1; }
  teardown_all(){ printf 'aggregate\n' >> "$tmp/watchdog-rejected-repair-uncertain-log"; return 1; }
  demote(){ : > "$tmp/watchdog-rejected-repair-uncertain-demote"; return 1; }
  watch_egress
  [[ "$(cat "$tmp/watchdog-rejected-repair-uncertain-log")" == \
     $'down\nup\nconfirm\ndown\naggregate' ]]
  [[ "$(active_rung)" == local:pc ]]
  recovery_transition_pending
  [[ ! -e "$tmp/watchdog-rejected-repair-uncertain-demote" ]]
  rm -f "$STATE" "$RECOVERY_MARKER"
)

# iphone-setup is itself an owned maintenance transaction.  It cannot report
# success when its final sidecar cleanup is uncertain.
(
  export GROK_IPHONE_STATE_DIR="$tmp/iphone-setup-active-route-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  set_active local:pc fixture@pc 22
  teardown_all(){ : > "$tmp/iphone-setup-active-route-torn-down"; }
  iphone_setup_action(){ : > "$tmp/iphone-setup-active-route-action"; }
  ! iphone_setup n-test-phone
  [[ "$(active_rung)" == local:pc ]]
  [[ ! -e "$RECOVERY_MARKER" \
     && ! -e "$tmp/iphone-setup-active-route-torn-down" \
     && ! -e "$tmp/iphone-setup-active-route-action" ]]
  clear_active
)

# With no selected route, setup owns its sidecar transaction and cannot report
# success when final cleanup is uncertain.
(
  export GROK_IPHONE_STATE_DIR="$tmp/iphone-setup-cleanup-failure-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  begin_clean_route_transition(){ begin_recovery_transition; }
  iphone_setup_action(){
    [[ "$1" == n-test-phone && "$(active_rung)" == iphone ]]
    recovery_transition_pending
    : > "$tmp/iphone-setup-action-ran"
  }
  local_down(){ :; }
  vpn_down(){ :; }
  iphone_down(){ return 1; }
  ! iphone_setup n-test-phone
  [[ -e "$tmp/iphone-setup-action-ran" && "$(active_rung)" == iphone ]]
  recovery_transition_pending
  rm -f "$STATE" "$RECOVERY_MARKER"
)

# Action failure still performs the complete transaction; with exact cleanup,
# setup returns failure while publishing EMPTY rather than a phantom phone.
(
  export GROK_IPHONE_STATE_DIR="$tmp/iphone-setup-action-failure-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  clear_active
  begin_clean_route_transition(){ begin_recovery_transition; }
  iphone_setup_action(){ return 42; }
  local_down(){ :; }
  vpn_down(){ :; }
  iphone_down(){ :; }
  ! iphone_setup n-test-phone
  [[ ! -e "$STATE" && ! -e "$RECOVERY_MARKER" ]]
)

# A pending compatibility VPN transition remains fenced when public handoff
# proves signed-bootstrap root cleanup has not committed. Handoff must not
# consume the marker or attempt user-side cleanup after that refusal.
(
  export GROK_IPHONE_STATE_DIR="$tmp/handoff-pending-vpn-recovery-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  set_active vpn
  begin_recovery_transition
  legacy_session_lock_check(){ :; }
  vpn_broker_call(){
    printf 'broker:%s\n' "$1" >> "$tmp/handoff-pending-vpn-recovery-log"
    [[ "$1" != migrate-legacy ]]
  }
  local_down(){ : > "$tmp/handoff-pending-vpn-recovery-local"; }
  vpn_down(){ : > "$tmp/handoff-pending-vpn-recovery-vpn"; }
  iphone_down(){ : > "$tmp/handoff-pending-vpn-recovery-iphone"; }
  ! compatibility_handoff_locked
  [[ "$(cat "$tmp/handoff-pending-vpn-recovery-log")" == \
     $'broker:migrate-legacy' ]]
  [[ "$(active_rung)" == vpn ]]
  recovery_transition_pending
  [[ ! -e "$tmp/handoff-pending-vpn-recovery-local" \
     && ! -e "$tmp/handoff-pending-vpn-recovery-vpn" \
     && ! -e "$tmp/handoff-pending-vpn-recovery-iphone" ]]
  rm -f "$STATE" "$RECOVERY_MARKER"
)

# A pending compatibility marker is consumed under the held legacy lock before
# warm handoff proceeds.  The final proof cannot leave the marker behind.
(
  export GROK_IPHONE_STATE_DIR="$tmp/handoff-pending-recovery-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  set_active local:pc fixture@pc 22
  begin_recovery_transition
  legacy_session_lock_check(){ :; }
  vpn_broker_call(){
    printf 'broker:%s\n' "$1" >> "$tmp/handoff-pending-recovery-log"
    if [[ "$1" == status ]]; then
      printf '%s\n' '{"ok":true,"active":false,"namespace_alive":false,"tun_alive":false,"host_tun_alive":false,"vpn_alive":false,"relay_alive":false,"relay_pid":null,"root_artifact_residue":false,"ledger":null}'
    fi
  }
  local_down(){ printf 'local\n' >> "$tmp/handoff-pending-recovery-log"; }
  vpn_down(){ printf 'vpn\n' >> "$tmp/handoff-pending-recovery-log"; }
  iphone_down(){ printf 'iphone\n' >> "$tmp/handoff-pending-recovery-log"; }
  clear_active(){ printf 'clear\n' >> "$tmp/handoff-pending-recovery-log"; rm -f "$STATE"; }
  port_owner_pid(){ return 0; }
  port_listening(){ return 1; }
  compatibility_handoff_locked
  [[ "$(cat "$tmp/handoff-pending-recovery-log")" == \
     $'broker:migrate-legacy\nlocal\nvpn\niphone\nlocal\nvpn\niphone\nclear\nbroker:migrate-legacy\nbroker:status\nclear' ]]
  [[ ! -e "$STATE" && ! -e "$RECOVERY_MARKER" ]]
)

# A typed compatibility iOS owner is a valid warm-handoff input.  The handoff
# consumes its exact state only after the same empty process/listener proof.
(
  export GROK_IPHONE_STATE_DIR="$tmp/handoff-typed-ios-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  set_active ios:iphone n-test-phone
  legacy_session_lock_check(){ :; }
  vpn_broker_call(){
    if [[ "$1" == status ]]; then
      printf '%s\n' '{"ok":true,"active":false,"namespace_alive":false,"tun_alive":false,"host_tun_alive":false,"vpn_alive":false,"relay_alive":false,"relay_pid":null,"root_artifact_residue":false,"ledger":null}'
    fi
  }
  local_down(){ :; }
  iphone_down(){ :; }
  pid_from_file(){ return 1; }
  port_owner_pid(){ return 0; }
  port_listening(){ return 1; }
  compatibility_handoff_locked
  [[ ! -e "$STATE" && ! -e "$RECOVERY_MARKER" ]]
)

# The actual standalone stop helper acquires its mutation lock and propagates
# the aggregate transaction through to a proved-empty result.
(
  export GROK_IPHONE_STATE_DIR="$tmp/standalone-stop-phone"
  . "$tmp/target/egress.sh"
  rm -f "$RECOVERY_MARKER"
  set_active direct
  standalone_mutation_lock(){ : > "$tmp/standalone-stop-locked"; }
  local_down(){ printf 'local\n' >> "$tmp/standalone-stop-log"; }
  vpn_down(){ printf 'vpn\n' >> "$tmp/standalone-stop-log"; }
  iphone_down(){ printf 'iphone\n' >> "$tmp/standalone-stop-log"; }
  standalone_stop_command
  [[ -e "$tmp/standalone-stop-locked" ]]
  [[ "$(cat "$tmp/standalone-stop-log")" == \
     $'local\nvpn\niphone\nlocal\nvpn\niphone' ]]
  [[ ! -e "$STATE" && ! -e "$RECOVERY_MARKER" ]]
)

echo "PASS: forced-route admission, exact reacquisition, and automatic ladder policy are enforced"
