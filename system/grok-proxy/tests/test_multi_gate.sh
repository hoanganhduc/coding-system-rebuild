#!/usr/bin/env bash
set -euo pipefail

# The matrix assigns its own dispatch authority.  Ambient caller values must
# not change cases that intentionally exercise the absent/default path.
unset GROK_MULTI_SESSION GROK_MANAGED_PROFILE_AVAILABLE

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'chmod -R u+w "$tmp" 2>/dev/null || true; rm -rf "$tmp"' EXIT
printf '%s\n' '#!/usr/bin/env bash' 'printf '\''fake-grok:%s\n'\'' "$*"' > "$tmp/grok"
chmod 755 "$tmp/grok"

# Exercise dispatch through a real prefix-installed immutable release.  Source
# execution is intentionally forbidden, including under GROK_TESTING.
printf '%s\n' '#!/bin/sh' 'exit 0' > "$tmp/openvpn"
chmod 700 "$tmp/openvpn"
proc_fixture="$tmp/prefix/proc-fixture"
mkdir -p "$proc_fixture/sys/kernel/random" "$proc_fixture/self/net"
chmod 700 \
  "$proc_fixture" "$proc_fixture/sys" "$proc_fixture/sys/kernel" \
  "$proc_fixture/sys/kernel/random" "$proc_fixture/self" "$proc_fixture/self/net"
printf '%s\n' '11111111-1111-4111-8111-111111111111' \
  > "$proc_fixture/sys/kernel/random/boot_id"
printf '%s\n' '0::/' > "$proc_fixture/self/cgroup"
socket_header='  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode'
printf '%s\n' "$socket_header" > "$proc_fixture/self/net/tcp"
printf '%s\n' "$socket_header" > "$proc_fixture/self/net/tcp6"
chmod 600 \
  "$proc_fixture/sys/kernel/random/boot_id" "$proc_fixture/self/cgroup" \
  "$proc_fixture/self/net/tcp" "$proc_fixture/self/net/tcp6"
exec {proc_fd}<"$tmp/prefix/proc-fixture"
set +e
GROK_INSTALLER_INTERNAL_PROC_FD="$proc_fd" \
/usr/bin/python3 -I -B "$ROOT/install-release.py" install \
  --source "$ROOT" --prefix "$tmp/prefix" --home /home/caller \
  --test-openvpn-binary "$tmp/openvpn" --apply >/dev/null
install_rc=$?
set -e
exec {proc_fd}<&-
unset GROK_INSTALLER_INTERNAL_PROC_FD
(( install_rc == 0 )) || exit "$install_rc"
GATE="$tmp/prefix/home/caller/.local/bin/grok-remote"

# Help exposes the exact readiness command and the explicit compatibility
# escape that remains valid even after a managed profile is activated.
out="$(HOME=/home/caller GROK_TESTING=1 GROK_BIN="$tmp/grok" "$GATE" --help)"
[[ "$out" == *'grok-remote doctor --json'* ]]
[[ "$out" == *'GROK_MULTI_SESSION=0'* ]]

# A caller cannot forge the installer-owned admission marker.  The generated
# gate scrubs it when no root activation record exists.
out="$(HOME=/home/caller GROK_TESTING=1 \
  GROK_MANAGED_PROFILE_AVAILABLE=1 GROK_BIN="$tmp/grok" "$GATE" inspect)"
[[ "$out" == 'fake-grok:inspect' ]]

# Exact opt-in reaches the pure client classifier before compatibility code is
# sourced.  A local-only command therefore never evaluates a legacy provider
# override.  This test performs no route mutation.
out="$(HOME=/home/caller GROK_TESTING=1 GROK_MULTI_SESSION=1 \
  GROK_VPNGATE=/untrusted GROK_BIN="$tmp/grok" "$GATE" inspect)"
[[ "$out" == 'fake-grok:inspect' ]]

for mode in 0 1; do
  set +e
  out="$(HOME=/home/caller GROK_TESTING=1 GROK_MULTI_SESSION="$mode" \
    GROK_BIN="$tmp/grok" "$GATE" --direct --no-direct inspect 2>&1)"
  rc=$?
  set -e
  [[ $rc -ne 0 && ( "$out" == *'invalid'* || "$out" == *'contradictory'* ) ]]
done

for mode in explicit-off managed-fallback; do
  set +e
  if [[ "$mode" == explicit-off ]]; then
    out="$(HOME=/home/caller GROK_TESTING=1 GROK_MULTI_SESSION=0 \
      GROK_BIN="$tmp/grok" "$GATE" --direct inspect 2>&1)"
  else
    out="$(HOME=/home/caller GROK_TESTING=1 \
      GROK_BIN="$tmp/grok" "$GATE" --direct inspect 2>&1)"
  fi
  rc=$?
  set -e
  [[ $rc -eq 2 && "$out" == *'requires an active managed multi-session profile'* ]]
done

# Similar-looking values remain literal compatibility behavior for every
# command class, including the otherwise managed-only recovery command.
for command in inspect recover; do
  set +e
  out="$(HOME=/home/caller GROK_TESTING=1 GROK_MULTI_SESSION=true \
    GROK_VPNGATE=/untrusted GROK_BIN="$tmp/grok" "$GATE" "$command" 2>&1)"
  rc=$?
  set -e
  [[ $rc -ne 0 && "$out" == *'GROK_VPNGATE is not supported'* ]]
done

# A canonical activation for a different release is dormant: it must neither
# inject the private marker nor change the default compatibility behavior.
active_profile="$tmp/prefix/var/lib/grok-proxy/release-control/active-profile.json"
selected_release="$(basename "$(/usr/bin/readlink -f \
  "$tmp/prefix/home/caller/.local/lib/grok-proxy/current")")"
different_release="$(printf '0%.0s' {1..64})"
profile_sha="$(printf '1%.0s' {1..64})"
contract_sha="$(printf '2%.0s' {1..64})"
grok_sha="$(printf '3%.0s' {1..64})"
printf '{"activated_unix_ns":1,"contract_sha256":"%s","grok_release_id":"sha256:%s","model_id":"grok-test","profile_name":"default","profile_sha256":"%s","release_id":"%s","schema_version":1}\n' \
  "$contract_sha" "$grok_sha" "$profile_sha" "$different_release" \
  > "$active_profile"
chmod 444 "$active_profile"
out="$(HOME=/home/caller GROK_TESTING=1 \
  XDG_STATE_HOME="$tmp/prefix/home/caller/.local/state" \
  GROK_BIN="$tmp/grok" "$GATE" inspect)"
[[ "$out" == 'fake-grok:inspect' ]]

# The otherwise identical activation for the selected release makes the gate
# inject its private marker.  Its deliberately absent private profile is then
# rejected by the client, proving dispatch did not remain in compatibility.
chmod 644 "$active_profile"
printf '{"activated_unix_ns":1,"contract_sha256":"%s","grok_release_id":"sha256:%s","model_id":"grok-test","profile_name":"default","profile_sha256":"%s","release_id":"%s","schema_version":1}\n' \
  "$contract_sha" "$grok_sha" "$profile_sha" "$selected_release" \
  > "$active_profile"
chmod 444 "$active_profile"

# Presence is literal even when a current activation exists.  Similar-looking
# values must not acquire the managed-default authority reserved for an absent
# variable (or the exact qualification value `1`).
for mode in '' true 01 2; do
  out="$(HOME=/home/caller GROK_TESTING=1 GROK_MULTI_SESSION="$mode" \
    XDG_STATE_HOME="$tmp/prefix/home/caller/.local/state" \
    GROK_BIN="$tmp/grok" "$GATE" inspect)"
  [[ "$out" == 'fake-grok:inspect' ]]
done

# The generated gate must make the same literal decision before consulting
# current-boot managed admission state.
boot_inventory="$tmp/prefix/var/lib/grok-proxy/release-control/boot-inventory/$selected_release.json"
mv "$boot_inventory" "$boot_inventory.held"
for mode in '' true 01 2; do
  out="$(HOME=/home/caller GROK_TESTING=1 GROK_MULTI_SESSION="$mode" \
    XDG_STATE_HOME="$tmp/prefix/home/caller/.local/state" \
    GROK_BIN="$tmp/grok" "$GATE" inspect)"
  [[ "$out" == 'fake-grok:inspect' ]]
done
mv "$boot_inventory.held" "$boot_inventory"

# Explicit and nonliteral compatibility never inspect managed activation
# metadata, even when the dormant object itself is unsafe.
chmod 600 "$active_profile"
for mode in 0 true; do
  out="$(HOME=/home/caller GROK_TESTING=1 GROK_MULTI_SESSION="$mode" \
    XDG_STATE_HOME="$tmp/prefix/home/caller/.local/state" \
    GROK_BIN="$tmp/grok" "$GATE" inspect)"
  [[ "$out" == 'fake-grok:inspect' ]]
done
chmod 444 "$active_profile"

set +e
out="$(HOME=/home/caller GROK_TESTING=1 \
  XDG_STATE_HOME="$tmp/prefix/home/caller/.local/state" \
  GROK_BIN="$tmp/grok" "$GATE" inspect 2>&1)"
rc=$?
set -e
[[ $rc -ne 0 && "$out" == *'active managed profile is invalid'* ]]

# Exact profile commands bypass only the gate's activation admission read so
# doctor can report unsafe managed metadata through its closed JSON schema.
# Ordinary commands continue to fail at the gate for these same objects.
chmod 644 "$active_profile"
set +e
ordinary="$(HOME=/home/caller GROK_TESTING=1 \
  XDG_STATE_HOME="$tmp/prefix/home/caller/.local/state" \
  GROK_BIN="$tmp/grok" "$GATE" inspect 2>&1)"
ordinary_rc=$?
set -e
[[ $ordinary_rc -eq 78 && "$ordinary" == *'unsafe owner/mode'* ]]
set +e
out="$(HOME=/home/caller GROK_TESTING=1 \
  XDG_STATE_HOME="$tmp/prefix/home/caller/.local/state" \
  GROK_BIN="$tmp/grok" "$GATE" doctor --json 2>&1)"
rc=$?
set -e
[[ $rc -eq 2 ]]
python3 - "$out" <<'PY'
import json
import sys

value = json.loads(sys.argv[1])
assert value["schema_version"] == "grok-remote.profile-status.v1"
assert value["status"] == "blocked"
assert value["reason_code"] == "active_profile_invalid"
PY

chmod 644 "$active_profile"
rm "$active_profile"
printf '{}\n' > "$tmp/unsafe-activation-target"
ln -s "$tmp/unsafe-activation-target" "$active_profile"
set +e
out="$(HOME=/home/caller GROK_TESTING=1 \
  XDG_STATE_HOME="$tmp/prefix/home/caller/.local/state" \
  GROK_BIN="$tmp/grok" "$GATE" doctor --json 2>&1)"
rc=$?
set -e
[[ $rc -eq 2 ]]
python3 - "$out" <<'PY'
import json
import sys

value = json.loads(sys.argv[1])
assert value["schema_version"] == "grok-remote.profile-status.v1"
assert value["status"] == "blocked"
assert value["reason_code"] == "active_profile_invalid"
PY

rm "$active_profile"
printf '{"activated_unix_ns":1,"contract_sha256":"%s","grok_release_id":"sha256:%s","model_id":"grok-test","profile_name":"default","profile_sha256":"%s","release_id":"%s","schema_version":1}\n' \
  "$contract_sha" "$grok_sha" "$profile_sha" "$selected_release" \
  > "$active_profile"
chmod 444 "$active_profile"

release_evidence="$tmp/prefix/var/lib/grok-proxy/release-control/evidence/$selected_release.json"
mv "$release_evidence" "$release_evidence.held"
set +e
out="$(HOME=/home/caller GROK_TESTING=1 \
  XDG_STATE_HOME="$tmp/prefix/home/caller/.local/state" \
  GROK_BIN="$tmp/grok" "$GATE" doctor --json 2>&1)"
rc=$?
ordinary="$(HOME=/home/caller GROK_TESTING=1 \
  XDG_STATE_HOME="$tmp/prefix/home/caller/.local/state" \
  GROK_BIN="$tmp/grok" "$GATE" inspect 2>&1)"
ordinary_rc=$?
set -e
[[ $rc -eq 2 ]]
[[ $ordinary_rc -eq 78 && "$ordinary" == *'cannot open'* ]]
python3 - "$out" <<'PY'
import json
import sys

value = json.loads(sys.argv[1])
assert value["schema_version"] == "grok-remote.profile-status.v1"
assert value["status"] == "blocked"
assert value["reason_code"] == "release_evidence_invalid"
PY
mv "$release_evidence.held" "$release_evidence"

# The exact feature-off value wins over the injected marker and remains a
# deterministic compatibility escape.
out="$(HOME=/home/caller GROK_TESTING=1 GROK_MULTI_SESSION=0 \
  XDG_STATE_HOME="$tmp/prefix/home/caller/.local/state" \
  GROK_BIN="$tmp/grok" "$GATE" inspect)"
[[ "$out" == 'fake-grok:inspect' ]]

# Stable control/fence ownership follows the passwd database, not a caller's
# split HOME or XDG_STATE_HOME (the root broker uses the same derivation).
account_home="$(python3 -c 'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')"
control="$(HOME="$tmp/spoof-home" XDG_STATE_HOME="$tmp/spoof-xdg" \
  ROOT="$ROOT" bash -c '. "$ROOT/egress.sh"; printf "%s" "$CONTROL_DIR"')"
[[ "$control" == "$account_home/.local/state/grok-proxy/control" ]]

# Provider admission freezes the exact home tuple. Later hosts.conf mutation is
# ignored, and OpenSSH receives an option terminator before the destination.
owner=epoch-frozen-home
generation=3
port=11880
deadline_ns="$(python3 -c 'import time; print(time.monotonic_ns() + 60_000_000_000)')"
control_root="$tmp/control-home"
tag="$(python3 - "$owner" "$generation" "$port" <<'PY'
import hashlib
import sys

owner, generation, port = (value.encode("ascii") for value in sys.argv[1:])
print(hashlib.sha256(owner + b"\0" + generation + b"\0" + port).hexdigest()[:24])
PY
)"
runtime="$control_root/p/$tag"
mkdir -p "$runtime" "$tmp/home/grok-proxy"
chmod 700 "$control_root" "$control_root/p" "$runtime" "$tmp/home" "$tmp/home/grok-proxy"
HOME="$tmp/home" GROK_TESTING=1 GROK_TEST_CONTROL_DIR="$control_root" \
GROK_PROVIDER_MODE=1 GROK_PROVIDER_OWNER_EPOCH="$owner" \
GROK_INTERLOCK_OWNER_EPOCH="$owner" GROK_PROVIDER_TRANSITION_ID=transition-home \
GROK_PROVIDER_GENERATION="$generation" GROK_EGRESS_RUNTIME_DIR="$runtime" \
GROK_PROVIDER_INVENTORY="$runtime/inventory.json" GROK_PROXY_PORT="$port" \
GROK_PROVIDER_DEADLINE_NS="$deadline_ns" \
GROK_REQUIRE_MODEL=grok-test GROK_PROVIDER_CONTRACT_DIGEST="$(printf 'b%.0s' {1..64})" \
GROK_ACTIVE_RELEASE_ID="$(printf 'a%.0s' {1..64})" \
GROK_PROVIDER_HOME_LABEL=arch GROK_PROVIDER_HOME_HOST=100.64.0.10 \
GROK_PROVIDER_HOME_USER=alice GROK_PROVIDER_HOME_PORT=2200 \
ROOT="$ROOT" CAPTURE="$tmp/ssh.argv" bash -c '
  . "$ROOT/egress.sh"
  fence_owner_epoch(){ printf "%s" "$GROK_PROVIDER_OWNER_EPOCH"; }
  release_identity(){ printf "%s" "$GROK_ACTIVE_RELEASE_ID"; }
  provider_validate_context
  saved_digest="$GROK_PROVIDER_CONTRACT_DIGEST"
  GROK_PROVIDER_CONTRACT_DIGEST=bad
  ! provider_validate_context
  GROK_PROVIDER_CONTRACT_DIGEST="$saved_digest"
  saved_release="$GROK_ACTIVE_RELEASE_ID"
  GROK_ACTIVE_RELEASE_ID="$(printf "f%.0s" {1..64})"
  ! provider_validate_context
  GROK_ACTIVE_RELEASE_ID="$saved_release"
  provider_validate_frozen_rung home:arch
  CONF="$HOME/grok-proxy/hosts.conf"
  printf "arch attacker.invalid mallory 22\n" > "$CONF"
  tcp_ok(){ [[ "$1:$2" == 100.64.0.10:2200 ]]; }
  ssh(){ printf "%s\n" "$@" > "$CAPTURE"; }
  set_active(){ [[ "$1:$2:$3" == local:arch:alice@100.64.0.10:2200 ]]; }
  local_up arch
  [[ "$(tail -n 2 "$CAPTURE" | head -n 1)" == -- ]]
  [[ "$(tail -n 1 "$CAPTURE")" == alice@100.64.0.10 ]]
  python3 -c "import socket,time; s=socket.socket(socket.AF_UNIX); s.bind(\"$CTL\"); time.sleep(5)" &
  socket_pid=$!
  for _ in {1..100}; do [[ -S "$CTL" ]] && break; sleep 0.01; done
  [[ -S "$CTL" ]]
  rm -f "$STATE"
  ssh(){
    [[ "$*" == *" -O exit "* && "${*: -2:1}" == -- && "${*: -1}" == alice@100.64.0.10 ]] || return
    printf ok > "$CAPTURE.down"
  }
  local_down
  [[ -e "$CAPTURE.down" ]]
  kill "$socket_pid" 2>/dev/null || true
  wait "$socket_pid" 2>/dev/null || true
  GROK_PROVIDER_HOME_HOST=-oProxyCommand
  ! provider_validate_frozen_rung home:arch
  GROK_PROVIDER_VPN_NAMESPACE=grokvpn
  GROK_PROVIDER_VPN_MAX_TRIES="$VPN_MAX_TRIES"
  GROK_PROVIDER_VPN_RANKING_VERSION=vpngate-score-uptime-v1
  GROK_PROVIDER_VPN_COUNTRIES=
  GROK_PROVIDER_VPN_BLOCKED_COUNTRIES=CN
  GROK_VPN_NETNS=grokvpn
  VPNGATE_COUNTRIES=
  GROK_BLOCKED_CC=CN
  provider_validate_frozen_rung vpn
'

# Provider iOS selection always returns the frozen StableNodeID, while its
# canonical registry entry must still match that identity exactly.
phone="$tmp/iphone"
mkdir -p "$phone" "$tmp/runtime-phone"
chmod 700 "$phone" "$tmp/runtime-phone"
printf 'n-stable-phone\n' > "$phone/exit-node"
printf 'n-stable-phone\n' > "$phone/ready"
printf '%s\n' '{"devices":[{"key":"iphone-xr","stable_node_id":"n-stable-phone"}],"schema_version":1}' \
  > "$phone/devices.json"
chmod 600 "$phone/exit-node" "$phone/ready" "$phone/devices.json"
HOME="$tmp/home" GROK_TESTING=1 GROK_TEST_CONTROL_DIR="$tmp/control-phone" \
GROK_PROVIDER_MODE=1 GROK_PROVIDER_OWNER_EPOCH=epoch-phone \
GROK_INTERLOCK_OWNER_EPOCH=epoch-phone GROK_PROVIDER_TRANSITION_ID=transition-phone \
GROK_PROVIDER_GENERATION=4 GROK_EGRESS_RUNTIME_DIR="$tmp/runtime-phone" \
GROK_PROVIDER_INVENTORY="$tmp/runtime-phone/inventory.json" GROK_PROXY_PORT=11881 \
GROK_PROVIDER_DEADLINE_NS="$deadline_ns" \
GROK_REQUIRE_MODEL=grok-test GROK_PROVIDER_CONTRACT_DIGEST="$(printf 'c%.0s' {1..64})" \
GROK_ACTIVE_RELEASE_ID="$(printf 'd%.0s' {1..64})" \
GROK_PROVIDER_IOS_KEY=iphone-xr GROK_PROVIDER_IOS_NODE_ID=n-stable-phone \
GROK_IPHONE_STATE_DIR="$phone" \
ROOT="$ROOT" bash -c '
  . "$ROOT/egress.sh"
  provider_validate_frozen_rung ios:iphone-xr 1
  [[ "$(iphone_node)" == n-stable-phone ]]
  printf "%s\n" "{\"devices\":[{\"key\":\"iphone-xr\",\"stable_node_id\":\"n-mutated-phone\"}],\"schema_version\":1}" > "$IPHONE_REGISTRY_FILE"
  [[ "$(iphone_node)" == n-stable-phone ]]
  ! iphone_configured
  printf "sidecar log\n" > "$IPHONE_LOG"
  printf "RUNG=ios:iphone-xr\nDEST=n-stable-phone\nSPORT=22\n" > "$STATE"
  printf "{}\n" > "$GROK_PROVIDER_INVENTORY"
  chmod 600 "$IPHONE_LOG" "$STATE" "$GROK_PROVIDER_INVENTORY"
  provider_validate_context(){ :; }
  provider_stop_command ios:iphone-xr
  [[ ! -e "$EG_RUNTIME_DIR" ]]
'

echo "PASS: managed default, literal compatibility, and exact qualification/recover dispatch"
