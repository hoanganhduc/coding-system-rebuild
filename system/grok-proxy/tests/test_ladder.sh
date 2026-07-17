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

# An explicitly forced phone is a route choice, not an automatic value test.
# If it offers the remembered model, an equal direct catalog must not make the
# healthy requested route look unavailable.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-equal-phone"
  . "$tmp/target/grok-remote"
  clear_active
  printf '%s\n' grok-4.5 > "$CHOICE"
  printf '%s\n' grok-4.5 > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ printf '%s\n' grok-4.5 > "$BASELINE"; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == iphone ]] && set_active iphone; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5; }
  launch(){
    [[ "$(active_rung)" == iphone ]]
    local -a selected=()
    mapfile -t selected < <(model_args iphone "$@")
    [[ "${selected[*]}" == '-m grok-4.5' ]]
    printf '%s\n' accepted > "$tmp/forced-equal-launched"
  }
  main --iphone
)
[[ "$(cat "$tmp/forced-equal-launched")" == accepted ]]

# The same explicit policy applies when the selected phone is already live:
# retain it instead of tearing it down and walking the automatic ladder.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-reuse-phone"
  . "$tmp/target/grok-remote"
  clear_active
  printf '%s\n' grok-4.5 > "$CHOICE"
  printf '%s\n' grok-4.5 > "$BASELINE"
  set_active iphone
  acquire_session_lock(){ :; }
  rung_alive(){ :; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5; }
  rung_down(){ : > "$tmp/forced-reuse-down"; return 1; }
  rung_up(){ : > "$tmp/forced-reuse-up"; return 1; }
  select_egress(){ : > "$tmp/forced-reuse-select"; return 1; }
  launch(){
    [[ "$(active_rung)" == iphone ]]
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
  export GROK_REQUIRE_MODEL=grok-env
  . "$tmp/target/grok-remote"
  clear_active
  printf '%s\n' grok-choice > "$CHOICE"
  printf '%s\n' grok-explicit > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == iphone ]] && set_active iphone; }
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
  export GROK_REQUIRE_MODEL=grok-env
  . "$tmp/target/grok-remote"
  clear_active
  printf '%s\n' grok-choice > "$CHOICE"
  rm -f "$SEEN"
  printf '%s\n' grok-choice grok-env > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == iphone ]] && set_active iphone; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-choice grok-env; }
  launch(){
    local -a selected=()
    mapfile -t selected < <(model_args iphone "$@")
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
  . "$tmp/target/grok-remote"
  clear_active
  printf '%s\n' grok-build > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == iphone ]] && set_active iphone; }
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
  unset GROK_REQUIRE_MODEL
  . "$tmp/target/grok-remote"
  clear_active
  printf '%s\n' grok-old > "$CHOICE"
  printf '%s\n' grok-4.5 grok-build grok-new > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == iphone ]] && set_active iphone; }
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
    mapfile -t selected < <(model_args iphone "$@")
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
  unset GROK_REQUIRE_MODEL
  . "$tmp/target/grok-remote"
  clear_active
  : > "$CHOICE"
  printf '%s\n' grok-4.5 > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == iphone ]] && set_active iphone; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5; }
  launch(){
    [[ "$*" == models ]]
    local -a selected=()
    mapfile -t selected < <(model_args iphone "$@")
    (( ${#selected[@]} == 0 ))
    [[ ! -s "$CHOICE" ]]
  }
  main --iphone models
)

# An intentionally empty remembered choice remains "let grok decide" when the
# complete forced catalog was already seen; it is not replaced by a default.
(
  export GROK_IPHONE_STATE_DIR="$tmp/forced-empty-choice-phone"
  unset GROK_REQUIRE_MODEL
  . "$tmp/target/grok-remote"
  clear_active
  : > "$CHOICE"
  printf '%s\n' grok-4.5 grok-build > "$SEEN"
  printf '%s\n' grok-4.5 grok-build > "$BASELINE"
  acquire_session_lock(){ :; }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  learn_baseline(){ :; }
  rung_alive(){ return 1; }
  rung_up(){ [[ "$1" == iphone ]] && set_active iphone; }
  rung_down(){ clear_active; }
  egress_country(){ printf '%s' VN; }
  models_via(){ printf '%s\n' grok-4.5 grok-build; }
  launch(){
    local -a selected=()
    mapfile -t selected < <(model_args iphone "$@")
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
  BASELINE="$tmp/forced-watchdog-unpinned-baseline"
  UNLOCKED="$tmp/forced-watchdog-unpinned-unlocked"
  FORCE_IPHONE_ROUTE=1
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
  FORCE_IPHONE_ROUTE=1
  WATCH_INTERVAL=0
  DEEP_EVERY=0
  RUNG_RETRIES=0
  set_active iphone
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles == 1 )); }
  rung_alive(){ return 1; }
  teardown_all(){ printf '%s\n' phone-only > "$tmp/forced-watchdog-torn-down"; clear_active; }
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
  FORCE_IPHONE_ROUTE=1
  WATCH_INTERVAL=0
  clear_active
  cycles=0
  sleep(){ cycles=$((cycles + 1)); (( cycles == 1 )); }
  active_rung(){ state_value RUNG 2>/dev/null || true; }
  rung_up(){ [[ "$1" == iphone ]]; set_active iphone; }
  rung_confirm(){ [[ "$1" == iphone ]]; printf '%s\n' confirmed > "$tmp/forced-watchdog-reacquired"; }
  select_egress(){ : > "$tmp/forced-watchdog-auto-selected"; return 1; }
  watch_egress
  [[ "$(cat "$tmp/forced-watchdog-reacquired")" == confirmed ]]
  [[ ! -e "$tmp/forced-watchdog-auto-selected" && "$(active_rung)" == iphone ]]
)

# The automatic predicate is deliberately unchanged: an equal catalog still
# adds no routing value when the caller did not force the phone.
(
  export GROK_IPHONE_STATE_DIR="$tmp/automatic-equal-phone"
  . "$tmp/target/egress.sh"
  BASELINE="$tmp/automatic-baseline"
  UNLOCKED="$tmp/automatic-unlocked"
  printf '%s\n' grok-4.5 > "$BASELINE"
  models_via(){ printf '%s\n' grok-4.5; }
  egress_country(){ printf '%s' VN; }
  ! rung_probe iphone
  [[ ! -s "$UNLOCKED" ]]
)

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
