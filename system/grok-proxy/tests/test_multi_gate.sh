#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'chmod -R u+w "$tmp" 2>/dev/null || true; rm -rf "$tmp"' EXIT
printf '%s\n' '#!/usr/bin/env bash' 'printf '\''fake-grok:%s\n'\'' "$*"' > "$tmp/grok"
chmod 755 "$tmp/grok"

# Exercise dispatch through a real prefix-installed immutable release.  Source
# execution is intentionally forbidden, including under GROK_TESTING.
printf '%s\n' '#!/bin/sh' 'exit 0' > "$tmp/openvpn"
chmod 700 "$tmp/openvpn"
/usr/bin/python3 -I -B "$ROOT/install-release.py" install \
  --source "$ROOT" --prefix "$tmp/prefix" --home /home/caller \
  --test-openvpn-binary "$tmp/openvpn" --apply >/dev/null
GATE="$tmp/prefix/home/caller/.local/bin/grok-remote"

# Exact opt-in reaches the pure client classifier before compatibility code is
# sourced.  A local-only command therefore never evaluates a legacy provider
# override.  This test performs no route mutation.
out="$(HOME=/home/caller GROK_TESTING=1 GROK_MULTI_SESSION=1 \
  GROK_VPNGATE=/untrusted GROK_BIN="$tmp/grok" "$GATE" inspect)"
[[ "$out" == 'fake-grok:inspect' ]]

# Similar-looking values remain literal compatibility behavior.
set +e
out="$(HOME=/home/caller GROK_TESTING=1 GROK_MULTI_SESSION=true \
  GROK_VPNGATE=/untrusted GROK_BIN="$tmp/grok" "$GATE" inspect 2>&1)"
rc=$?
set -e
[[ $rc -ne 0 && "$out" == *'GROK_VPNGATE is not supported'* ]]

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

# Provider iPhone selection always returns the frozen StableNodeID, while its
# credential/ready files must still match that identity exactly.
phone="$tmp/iphone"
mkdir -p "$phone" "$tmp/runtime-phone"
chmod 700 "$tmp/runtime-phone"
printf 'n-stable-phone\n' > "$phone/exit-node"
printf 'n-stable-phone\n' > "$phone/ready"
chmod 600 "$phone/exit-node" "$phone/ready"
HOME="$tmp/home" GROK_TESTING=1 GROK_TEST_CONTROL_DIR="$tmp/control-phone" \
GROK_PROVIDER_MODE=1 GROK_PROVIDER_OWNER_EPOCH=epoch-phone \
GROK_INTERLOCK_OWNER_EPOCH=epoch-phone GROK_PROVIDER_TRANSITION_ID=transition-phone \
GROK_PROVIDER_GENERATION=4 GROK_EGRESS_RUNTIME_DIR="$tmp/runtime-phone" \
GROK_PROVIDER_INVENTORY="$tmp/runtime-phone/inventory.json" GROK_PROXY_PORT=11881 \
GROK_PROVIDER_DEADLINE_NS="$deadline_ns" \
GROK_REQUIRE_MODEL=grok-test GROK_PROVIDER_CONTRACT_DIGEST="$(printf 'c%.0s' {1..64})" \
GROK_ACTIVE_RELEASE_ID="$(printf 'd%.0s' {1..64})" \
GROK_PROVIDER_IPHONE_NODE_ID=n-stable-phone GROK_IPHONE_STATE_DIR="$phone" \
ROOT="$ROOT" bash -c '
  . "$ROOT/egress.sh"
  provider_validate_frozen_rung iphone 1
  [[ "$(iphone_node)" == n-stable-phone ]]
  printf "n-mutated-phone\n" > "$IPHONE_NODE_FILE"
  [[ "$(iphone_node)" == n-stable-phone ]]
  ! iphone_configured
  printf "sidecar log\n" > "$IPHONE_LOG"
  printf "RUNG=iphone\nDEST=n-stable-phone\nSPORT=22\n" > "$STATE"
  printf "{}\n" > "$GROK_PROVIDER_INVENTORY"
  chmod 600 "$IPHONE_LOG" "$STATE" "$GROK_PROVIDER_INVENTORY"
  provider_validate_context(){ :; }
  provider_stop_command iphone
  [[ ! -e "$EG_RUNTIME_DIR" ]]
'

echo "PASS: GROK_MULTI_SESSION=1 or exact recover selects the pure multi-session lane"
