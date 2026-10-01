#!/usr/bin/env bash
# egress.sh — pick an egress for grok and hold it up, in preference order:
#
#   direct        no proxy at all
#   local:<label> ssh -D SOCKS through a home PC over Tailscale (hosts.conf order)
#   ios:<key>     a dedicated userspace Tailscale client using one registered iOS exit node
#   vpn           a VPN Gate server in an allowed region, isolated in netns 'grokvpn'
#
# Every rung presents grok with the SAME endpoint -- a SOCKS5 proxy on 127.0.0.1:$PORT --
# so a rung can be swapped underneath a running grok. grok fails closed on a dead proxy,
# retries silently for ~5.5 minutes and then resumes the in-flight turn, so any swap that
# completes inside that window is invisible to the session. The home-PC rung binds the
# port with `ssh -D`; the VPN rung binds it with socks-netns.py.
#
# A rung counts as working only when grok is actually offered $GROK_REQUIRE_MODEL through
# it. Reachability is deliberately NOT the test: the direct rung reaches grok.com perfectly
# well and is simply not offered grok-4.5, which is the whole reason this tool exists.
#
# Demotion only ever moves DOWN the ladder. Falling back to `direct` on a failure would
# silently downgrade the model and expose the VM's real region -- the exact failure this
# tool exists to prevent -- so `direct` is only ever used when it passes the probe up front.
#
# Deliberately not `set -e`: this file runs a long-lived watchdog whose whole job is to
# react to commands that fail. Failures are handled explicitly instead.
set -uo pipefail

EG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

require_frozen_egress_release(){
  local control=/var/lib/grok-proxy/release-control
  local -a admission
  local provider_command=0 provider_canary=0 canary_binding=0
  local canary_extra=0 rc=0 name
  if [[ "${GROK_TESTING:-0}" == 1 && -n "${GROK_TEST_ROOT_RELEASE_CONTROL:-}" ]]; then
    control="$GROK_TEST_ROOT_RELEASE_CONTROL"
  fi
  exec {EGRESS_SELF_RELEASE_LOCK_FD}<"$control/install.lock" \
    || return 78
  admission=(/usr/bin/python3 -I "$EG_DIR/grok_ms/release_admission.py" \
    "$EG_DIR" "$EG_DIR/egress.sh" "$EGRESS_SELF_RELEASE_LOCK_FD"
  )
  if [[ "${GROK_PROVIDER_MODE:-0}" == 1 && $# == 2 ]]; then
    case "$1" in
      provider-up|provider-next|provider-recover|provider-stop|provider-prove-empty)
        provider_command=1 ;;
    esac
  fi
  [[ -v GROK_RELEASE_CANARY_FD || -v GROK_RELEASE_CANARY_RELEASE_ID ]] \
    && canary_binding=1
  for name in GROK_RELEASE_CANARY_MODE GROK_RELEASE_RUNG_CANARY \
              GROK_RELEASE_CANARY_RUNG GROK_RELEASE_CANARY_ROUTE_PROFILE \
              GROK_RELEASE_CANARY_CONTRACT GROK_RELEASE_CANARY_GROK_RELEASE \
              GROK_RELEASE_CANARY_KIND GROK_RELEASE_CANARY_MODEL \
              GROK_RELEASE_CANARY_NONCE \
              GROK_RELEASE_CANARY_PROFILE_SHA256; do
    [[ -v $name ]] && canary_extra=1
  done
  if (( canary_binding == 1 || canary_extra == 1 )); then
    (( provider_command == 1 )) \
      && (( canary_binding == 1 && canary_extra == 0 )) \
      && [[ "${GROK_RELEASE_CANARY_FD:-}" =~ ^[0-9]+$ ]] \
      && (( GROK_RELEASE_CANARY_FD >= 3 )) \
      && [[ "${GROK_RELEASE_CANARY_RELEASE_ID:-}" =~ ^[0-9a-f]{64}$ ]] \
      || { exec {EGRESS_SELF_RELEASE_LOCK_FD}<&-; return 78; }
    admission+=("$GROK_RELEASE_CANARY_FD")
    provider_canary=1
  elif [[ "${GROK_HANDOFF_MODE:-0}" == 1 && $# == 1 \
     && "$1" == compatibility-handoff ]]; then
    admission+=(--public-recovery)
  elif (( provider_command == 1 )) \
       && [[ "$1" == provider-recover || "$1" == provider-prove-empty ]]; then
    admission+=(--public-recovery --provider-recovery)
  fi
  "${admission[@]}" || rc=$?
  if (( provider_command == 1 )); then
    exec {EGRESS_SELF_RELEASE_LOCK_FD}<&-
    if (( provider_canary == 1 )); then
      exec {GROK_RELEASE_CANARY_FD}<&-
    fi
    unset GROK_RELEASE_CANARY_FD GROK_RELEASE_CANARY_RELEASE_ID
  fi
  return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]] && ! require_frozen_egress_release "$@"; then
  printf '[egress] editable source tree is not executable; use ~/.local/bin/grok-remote\n' >&2
  exit 78
fi
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin
  unset PYTHONPATH PYTHONHOME BASH_ENV ENV
  while IFS= read -r variable; do unset "$variable"; done < <(compgen -A variable LD_)
fi

PRIVATE_DIR="$HOME/grok-proxy"
[[ -e "$EG_DIR/hosts.conf" || -e "$EG_DIR/id_grokproxy" ]] && PRIVATE_DIR="$EG_DIR"
CONF="$PRIVATE_DIR/hosts.conf"
KEY="$PRIVATE_DIR/id_grokproxy"

# The supervisor invokes a narrow generation-aware provider protocol.  Its
# mutable paths are isolated under a pre-created 0700 generation directory;
# ordinary/live callers cannot redirect compatibility state there.
PROVIDER_MODE=0
HANDOFF_MODE=0
if [[ "${GROK_HANDOFF_MODE:-0}" == 1 ]]; then
  HANDOFF_MODE=1
elif [[ -n "${GROK_HANDOFF_MODE:-}" && "${GROK_HANDOFF_MODE:-}" != 0 ]]; then
  printf '[egress] GROK_HANDOFF_MODE must be 0 or 1\n' >&2
  return 1 2>/dev/null || exit 1
fi
if [[ "${GROK_PROVIDER_MODE:-}" == 1 ]]; then
  (( HANDOFF_MODE == 0 )) || {
    printf '[egress] provider and compatibility-handoff modes are exclusive\n' >&2
    return 1 2>/dev/null || exit 1
  }
  PROVIDER_MODE=1
  for required in GROK_PROVIDER_OWNER_EPOCH GROK_PROVIDER_TRANSITION_ID \
                  GROK_PROVIDER_GENERATION GROK_EGRESS_RUNTIME_DIR \
                  GROK_PROVIDER_INVENTORY GROK_PROXY_PORT GROK_REQUIRE_MODEL \
                  GROK_PROVIDER_CONTRACT_DIGEST GROK_ACTIVE_RELEASE_ID \
                  GROK_PROVIDER_DEADLINE_NS; do
    [[ -n "${!required:-}" ]] || {
      printf '[egress] provider mode is missing %s\n' "$required" >&2
      return 1 2>/dev/null || exit 1
    }
  done
elif [[ -n "${GROK_EGRESS_RUNTIME_DIR:-}${GROK_PROVIDER_OWNER_EPOCH:-}${GROK_PROVIDER_TRANSITION_ID:-}${GROK_PROVIDER_GENERATION:-}${GROK_PROVIDER_INVENTORY:-}${GROK_PROVIDER_CONTRACT_DIGEST:-}${GROK_ACTIVE_RELEASE_ID:-}${GROK_PROVIDER_DEADLINE_NS:-}${GROK_PROVIDER_HOME_LABEL:-}${GROK_PROVIDER_HOME_HOST:-}${GROK_PROVIDER_HOME_USER:-}${GROK_PROVIDER_HOME_PORT:-}${GROK_PROVIDER_IOS_KEY:-}${GROK_PROVIDER_IOS_NODE_ID:-}${GROK_PROVIDER_IPHONE_NODE_ID:-}${GROK_PROVIDER_VPN_NAMESPACE:-}${GROK_PROVIDER_VPN_MAX_TRIES:-}${GROK_PROVIDER_VPN_RANKING_VERSION:-}${GROK_PROVIDER_VPN_COUNTRIES:-}${GROK_PROVIDER_VPN_BLOCKED_COUNTRIES:-}" ]]; then
  printf '[egress] provider runtime variables require GROK_PROVIDER_MODE=1\n' >&2
  return 1 2>/dev/null || exit 1
fi
EG_RUNTIME_DIR="${GROK_EGRESS_RUNTIME_DIR:-$EG_DIR}"
if (( PROVIDER_MODE == 1 )); then
  CTL="$EG_RUNTIME_DIR/c"
  STATE="$EG_RUNTIME_DIR/egress.state"
else
  CTL="$PRIVATE_DIR/.tunnel.ctl"
  STATE="$PRIVATE_DIR/.egress.state"
fi
# Compatibility mutations publish this fixed marker before teardown or route
# replacement effects.  Its presence is a durable instruction to recover,
# never permission to reuse or overwrite the recorded route.
RECOVERY_MARKER="$PRIVATE_DIR/.egress.recovery-required"

# Locks and the crash-persistent recovery fence must outlive any selected code
# release. Live callers cannot redirect them; the root broker derives the same
# location from the account database rather than caller-controlled HOME/XDG.
ACCOUNT_HOME="$(python3 -c 'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir, end="")')" \
  || { printf '[egress] cannot resolve the current account home\n' >&2; return 1 2>/dev/null || exit 1; }
[[ "$ACCOUNT_HOME" == /* ]] \
  || { printf '[egress] current account home is not absolute\n' >&2; return 1 2>/dev/null || exit 1; }
CONTROL_DIR="$ACCOUNT_HOME/.local/state/grok-proxy/control"
if [[ "${GROK_TESTING:-0}" == 1 && -n "${GROK_TEST_CONTROL_DIR:-}" ]]; then
  CONTROL_DIR="$GROK_TEST_CONTROL_DIR"
elif [[ -n "${GROK_TEST_CONTROL_DIR:-}" ]]; then
  printf '[egress] GROK_TEST_CONTROL_DIR requires GROK_TESTING=1\n' >&2
  return 1 2>/dev/null || exit 1
fi
if [[ -n "${GROK_SESSION_LOCK:-}" && "${GROK_TESTING:-0}" != 1 ]]; then
  printf '[egress] GROK_SESSION_LOCK is not supported in live operation\n' >&2
  return 1 2>/dev/null || exit 1
fi
SESSION_LOCK="${GROK_SESSION_LOCK:-$CONTROL_DIR/compatibility.lock}"
RECOVERY_FENCE="$CONTROL_DIR/recovery.fence"

# Privileged code is selected only from one installed root-owned broker path.
# A test broker is an explicitly non-live seam and is never passed through sudo.
if [[ -n "${GROK_VPNGATE:-}" ]]; then
  printf '[egress] GROK_VPNGATE is not supported; the VPN broker path is fixed\n' >&2
  return 1 2>/dev/null || exit 1
fi
VPN_BROKER="/usr/local/libexec/grok-proxy/vpn-broker"
VPN_BROKER_MODE=live
if [[ -n "${GROK_TEST_VPN_BROKER:-}" ]]; then
  if [[ "${GROK_TESTING:-0}" != 1 ]]; then
    printf '[egress] GROK_TEST_VPN_BROKER requires GROK_TESTING=1\n' >&2
    return 1 2>/dev/null || exit 1
  fi
  VPN_BROKER="$GROK_TEST_VPN_BROKER"
  VPN_BROKER_MODE=test
fi
SOCKS_RUNTIME_DIR="$CONTROL_DIR/compat-vpn"
SOCKS_PID="$SOCKS_RUNTIME_DIR/backend.pid"
(( PROVIDER_MODE == 0 )) || SOCKS_PID="$EG_RUNTIME_DIR/backend.pid"
# Production has one broker-owned namespace. A different user-side name would
# split liveness checks from the privileged resource and defeat fail-closed DNS.
NS=grokvpn
if [[ -n "${GROK_VPN_NETNS+x}" && "${GROK_VPN_NETNS}" != "$NS" ]]; then
  printf '[egress] GROK_VPN_NETNS is fixed to grokvpn\n' >&2
  return 1 2>/dev/null || exit 1
fi

PORT="${GROK_PROXY_PORT:-1080}"
PROXY="socks5h://127.0.0.1:$PORT"
NOPROXY="localhost,127.0.0.1,::1,100.64.0.0/10,.ts.net"
GROK_BIN="${GROK_BIN:-$HOME/.local/bin/grok}"

# The iPhone rung is a SECOND Tailscale identity in userspace-networking mode. It
# never changes the host's tailscale0 interface or default routes; only clients of
# its loopback SOCKS listener use the selected phone exit node. Credentials and
# LocalAPI state live outside this project tree with private permissions.
TAILSCALE_BIN="${GROK_TAILSCALE_BIN:-$(command -v tailscale 2>/dev/null || true)}"
TAILSCALED_BIN="${GROK_TAILSCALED_BIN:-$(command -v tailscaled 2>/dev/null || true)}"
PRIMARY_TAILSCALE_BIN="${GROK_PRIMARY_TAILSCALE_BIN:-$TAILSCALE_BIN}"
IPHONE_STATE_DIR="${GROK_IPHONE_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/grok-proxy/iphone}"
IPHONE_RUNTIME_DIR="$IPHONE_STATE_DIR"
(( PROVIDER_MODE == 0 )) || IPHONE_RUNTIME_DIR="$EG_RUNTIME_DIR"
IPHONE_STATE="$IPHONE_STATE_DIR/tailscaled.state"
IPHONE_SOCKET="$IPHONE_RUNTIME_DIR/tailscaled.sock"
(( PROVIDER_MODE == 0 )) || IPHONE_SOCKET="$IPHONE_RUNTIME_DIR/t"
IPHONE_PID="$IPHONE_RUNTIME_DIR/tailscaled.pid"
IPHONE_PID_IDENTITY="$IPHONE_RUNTIME_DIR/tailscaled.identity.json"
IPHONE_LOG="$IPHONE_RUNTIME_DIR/tailscaled.log"
IPHONE_NODE_FILE="$IPHONE_STATE_DIR/exit-node"
IPHONE_READY_FILE="$IPHONE_STATE_DIR/ready"
IPHONE_REGISTRY_FILE="$IPHONE_STATE_DIR/devices.json"
IOS_REGISTRY_PY="$EG_DIR/grok_ms/ios_registry.py"
IPHONE_HOSTNAME="${GROK_IPHONE_HOSTNAME:-grok-iphone-relay}"
IPHONE_AUTHKEY_FILE="${GROK_IPHONE_AUTHKEY_FILE:-}"
IOS_SELECTED_KEY=""
IOS_SELECTED_NODE_ID=""
IOS_ONLY=0
IOS_EXACT_KEY=""
IOS_ATTEMPT_DEADLINE_SECONDS=0
IOS_FAMILY_DEADLINE_SECONDS=0

# Clear protocol-specific proxy variables before setting the one intended route.
# curl prefers HTTPS_PROXY over ALL_PROXY, so inheriting a caller's environment
# could otherwise make probes measure a different path than Grok uses.
CLEAN_PROXY_ENV=(env
  -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY -u FTP_PROXY
  -u http_proxy -u https_proxy -u all_proxy -u no_proxy -u ftp_proxy)

BASELINE="$PRIVATE_DIR/.baseline.models"            # what the VM is offered with no tunnel at all
(( PROVIDER_MODE == 0 )) || BASELINE="$EG_RUNTIME_DIR/baseline.models"
BASELINE_TTL="${GROK_BASELINE_TTL:-21600}"        # re-measure the baseline once it is older than this (s)
UNLOCKED="$PRIVATE_DIR/.unlocked.models"            # models eligible on the selected route (normally its baseline delta)
(( PROVIDER_MODE == 0 )) || UNLOCKED="$EG_RUNTIME_DIR/unlocked.models"
# Optional pin. Left unset (the default), automatic selection accepts the first
# preferred route with any nonempty valid catalog. A pin requires that exact
# model during admission, repair, and demotion.
REQUIRE_MODEL="${GROK_REQUIRE_MODEL:-}"
RUNG_RETRIES="${GROK_RUNG_RETRIES:-2}"            # repairs of the same rung before demoting
WATCH_INTERVAL="${GROK_WATCH_INTERVAL:-10}"       # seconds between liveness checks
DEEP_EVERY="${GROK_DEEP_EVERY:-6}"                # every Nth check, prove real egress
VPN_MAX_TRIES="${GROK_VPN_MAX_TRIES:-6}"          # VPN Gate servers to walk before giving up
VPN_EXPLICIT_COUNTRIES="${VPNGATE_COUNTRIES:-${VPNGATE_COUNTRY:-}}"
VPN_PREFER_COUNTRIES="${VPNGATE_PREFER:-VN JP KR TH ID}"
ALLOW_DIRECT="${GROK_ALLOW_DIRECT:-1}"
VPN_STABILITY_CHECKS="${GROK_VPN_STABILITY_CHECKS:-3}"

# Conservative default deny for countries where the service itself is blocked.
# An explicit override remains frozen into the route contract for every rung.
GROK_BLOCKED_CC="${GROK_BLOCKED_CC-CN IR KP TM VE}"

c_cyan=$'\033[36m'; c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_rst=$'\033[0m'
eg_log(){  printf '%s[egress]%s %s\n' "$c_cyan" "$c_rst" "$*" >&2; }
eg_ok(){   printf '%s[egress]%s %s\n' "$c_grn"  "$c_rst" "$*" >&2; }
eg_warn(){ printf '%s[egress]%s %s\n' "$c_yel"  "$c_rst" "$*" >&2; }
eg_err(){  printf '%s[egress]%s %s\n' "$c_red"  "$c_rst" "$*" >&2; }

model_id_valid(){
  local value="${1-}"
  ( export LC_ALL=C; [[ "$value" =~ ^[A-Za-z0-9._:+/@-]{1,128}$ ]] )
}

home_label_valid(){
  local value="${1-}"
  ( export LC_ALL=C; [[ "$value" =~ ^[A-Za-z0-9._:+@-]{1,120}$ ]] )
}

ios_key_valid(){
  local value="${1-}"
  ( export LC_ALL=C; [[ "$value" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] )
}

ios_registry_command(){
  [[ -f "$IOS_REGISTRY_PY" && ! -L "$IOS_REGISTRY_PY" ]] || return 1
  python3 -I "$IOS_REGISTRY_PY" "$@" \
    --registry "$IPHONE_REGISTRY_FILE" \
    --legacy-node "$IPHONE_NODE_FILE" \
    --legacy-ready "$IPHONE_READY_FILE"
}

ios_devices(){
  ios_registry_command migrate >/dev/null && ios_registry_command devices
}

ios_node_for_key(){
  ios_key_valid "$1" || return 1
  ios_registry_command node "$1"
}

ios_select_context(){
  local key="$1" node=""
  ios_key_valid "$key" || return 1
  if (( PROVIDER_MODE == 1 )); then
    [[ "${GROK_PROVIDER_IOS_KEY:-}" == "$key" ]] || return 1
    node="${GROK_PROVIDER_IOS_NODE_ID:-}"
  else
    node="$(ios_node_for_key "$key")" || return 1
  fi
  route_token_valid "$node" || return 1
  IOS_SELECTED_KEY="$key"
  IOS_SELECTED_NODE_ID="$node"
}

ios_attempt_begin(){
  local deadline=$((SECONDS + 10))
  if (( IOS_FAMILY_DEADLINE_SECONDS > 0 \
        && IOS_FAMILY_DEADLINE_SECONDS < deadline )); then
    deadline="$IOS_FAMILY_DEADLINE_SECONDS"
  fi
  (( deadline > SECONDS )) || return 1
  IOS_ATTEMPT_DEADLINE_SECONDS="$deadline"
}

ios_attempt_end(){ IOS_ATTEMPT_DEADLINE_SECONDS=0; }

ios_attempt_remaining(){
  local remaining
  (( IOS_ATTEMPT_DEADLINE_SECONDS > 0 )) || return 1
  remaining=$((IOS_ATTEMPT_DEADLINE_SECONDS - SECONDS))
  (( remaining > 0 )) || return 1
  printf '%s' "$remaining"
}

ios_attempt_check(){
  (( IOS_ATTEMPT_DEADLINE_SECONDS == 0 )) || ios_attempt_remaining >/dev/null
}

route_token_valid(){
  local value="${1-}"
  ( export LC_ALL=C; [[ "$value" =~ ^[A-Za-z0-9._:+/@-]{1,256}$ ]] )
}

filter_model_ids(){
  LC_ALL=C awk '
    length($0) >= 1 && length($0) <= 128 && $0 ~ /^[A-Za-z0-9._:+\/@-]+$/ { print }
  ' | sort -u
}

model_state_file_valid(){
  local path="$1" size
  [[ -f "$path" && ! -L "$path" ]] || return 1
  size="$(stat -c %s -- "$path" 2>/dev/null)" || return 1
  [[ "$size" =~ ^[0-9]+$ ]] && (( size <= 65536 )) || return 1
  LC_ALL=C awk '
    length($0) == 0 || length($0) > 128 || $0 !~ /^[A-Za-z0-9._:+\/@-]+$/ { bad=1 }
    END { exit bad ? 1 : 0 }
  ' "$path"
}

sanitize_model_state_file(){
  local path="$1"
  [[ -e "$path" || -L "$path" ]] || return 0
  if ! model_state_file_valid "$path"; then
    eg_warn "invalid stored model metadata was ignored"
    return 1
  fi
}

discard_invalid_model_state_file(){
  local path="$1"
  if ! sanitize_model_state_file "$path"; then
    rm -f -- "$path"
    eg_warn "discarded invalid stored model metadata"
  fi
}

normalize_ip(){
  python3 - "$1" <<'PY' 2>/dev/null
import ipaddress
import sys

value = sys.argv[1]
if len(value.encode("utf-8", "strict")) > 64:
    raise SystemExit(1)
try:
    parsed = ipaddress.ip_address(value)
except ValueError:
    raise SystemExit(1)
print(str(parsed), end="")
PY
}

bounded_probe_output(){
  head -c 65537
}

iphone_log_fingerprint(){
  python3 - "$IPHONE_LOG" <<'PY' 2>/dev/null
import hashlib
import os
import stat
import sys

path = sys.argv[1]
flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(path, flags)
except OSError:
    print("log_unavailable")
    raise SystemExit(0)
try:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        print("log_unavailable")
        raise SystemExit(0)
    if info.st_size > 16 * 1024 * 1024:
        print(f"log_bytes={info.st_size} log_sha256=oversize")
        raise SystemExit(0)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        total += len(chunk)
        digest.update(chunk)
    print(f"log_bytes={total} log_sha256={digest.hexdigest()}")
finally:
    os.close(descriptor)
PY
}

ensure_control_dir(){
  local uid mode owner
  uid="$(id -u)"
  if [[ -e "$CONTROL_DIR" ]]; then
    [[ -d "$CONTROL_DIR" && ! -L "$CONTROL_DIR" ]] \
      || { eg_err "unsafe control directory: $CONTROL_DIR"; return 1; }
    owner="$(stat -c '%u' "$CONTROL_DIR" 2>/dev/null)"
    [[ "$owner" == "$uid" ]] \
      || { eg_err "control directory is not owned by the current user"; return 1; }
  else
    ( umask 077; mkdir -p "$CONTROL_DIR" ) || return 1
  fi
  chmod 700 "$CONTROL_DIR" || return 1
  mode="$(stat -c '%a' "$CONTROL_DIR" 2>/dev/null)"
  [[ "$mode" == 700 ]] || { eg_err "control directory must be mode 700"; return 1; }
}

fence_owner_epoch(){
  [[ -f "$RECOVERY_FENCE" && ! -L "$RECOVERY_FENCE" ]] || return 1
  local owner mode uid
  uid="$(id -u)"
  [[ "$(stat -c '%u' "$RECOVERY_FENCE" 2>/dev/null)" == "$uid" ]] || return 1
  mode="$(stat -c '%a' "$RECOVERY_FENCE" 2>/dev/null)"
  [[ "$mode" == 600 ]] || return 1
  # The supervisor publishes a canonical JSON fence.  Parse it as data and
  # require the exact typed record shape; never source an ownership file.
  owner="$(python3 - "$RECOVERY_FENCE" 2>/dev/null <<'PY'
import json, re, sys
try:
    with open(sys.argv[1], "rb") as handle:
        raw = handle.read(65537)
    if len(raw) > 65536:
        raise ValueError("oversized")
    value = json.loads(raw)
    expected = {
        "boot_id", "owner_epoch", "phase", "pid", "pid_start_ticks",
        "release_id", "schema_version",
    }
    if type(value) is not dict or set(value) != expected:
        raise ValueError("shape")
    owner = value["owner_epoch"]
    if type(owner) is not str or re.fullmatch(r"[A-Za-z0-9._:+@-]{1,256}", owner) is None:
        raise ValueError("owner")
    print(owner, end="")
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
PY
)" || return 1
  [[ "$owner" =~ ^[A-Za-z0-9._:+@-]{1,256}$ ]] || return 1
  printf '%s' "$owner"
}

# File presence is fail-closed. A malformed or stale-looking fence is recovery
# work, never permission for the compatibility lane to guess that it is safe.
interlock_check_mutation(){
  [[ -e "$RECOVERY_FENCE" ]] || return 0
  local owner=""
  owner="$(fence_owner_epoch)" || {
    eg_err "recovery fence is present but invalid — run gated recovery"
    return 1
  }
  if [[ -n "${GROK_INTERLOCK_OWNER_EPOCH:-}" && "$GROK_INTERLOCK_OWNER_EPOCH" == "$owner" ]]; then
    return 0
  fi
  eg_err "multi-session recovery fence is active — mutation refused"
  return 1
}

acquire_stable_mutation_lock(){
  command -v flock >/dev/null 2>&1 \
    || { eg_err "flock is required to protect the shared egress"; return 1; }
  ensure_control_dir || return 1
  exec 9>"$SESSION_LOCK" || return 1
  chmod 600 "$SESSION_LOCK" 2>/dev/null || return 1
  flock -n 9 || {
    eg_err "another grok-remote session owns the shared egress ($SESSION_LOCK)"
    return 1
  }
  interlock_check_mutation || { flock -u 9 2>/dev/null || true; return 1; }
}

release_identity(){
  python3 - "$EG_DIR/release.json" 2>/dev/null <<'PY'
import json, re, sys
try:
    with open(sys.argv[1], "rb") as handle:
        value = json.load(handle)
    release = value["release_id"]
    if type(release) is not str or re.fullmatch(r"[0-9a-f]{64}", release) is None:
        raise ValueError("release")
    print(release, end="")
except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
PY
}

provider_workspace_tag(){
  python3 - "$1" "$2" "$3" <<'PY'
import hashlib
import sys

owner, generation, port = (value.encode("ascii") for value in sys.argv[1:])
print(
    hashlib.sha256(owner + b"\0" + generation + b"\0" + port)
    .hexdigest()[:24],
    end="",
)
PY
}

provider_validate_context(){
  local allow_missing="${1:-0}"
  (( PROVIDER_MODE == 1 )) || { eg_err "provider command requires GROK_PROVIDER_MODE=1"; return 1; }
  local owner="$GROK_PROVIDER_OWNER_EPOCH" transition="$GROK_PROVIDER_TRANSITION_ID"
  local generation="$GROK_PROVIDER_GENERATION" expected resolved inventory release
  [[ "$owner" =~ ^[A-Za-z0-9._:+@-]{1,128}$ ]] \
    || { eg_err "invalid provider owner epoch"; return 1; }
  [[ "$transition" =~ ^[A-Za-z0-9._:+@-]{1,128}$ ]] \
    || { eg_err "invalid provider transition id"; return 1; }
  [[ "$generation" =~ ^[1-9][0-9]{0,18}$ ]] \
    || { eg_err "invalid provider generation"; return 1; }
  [[ "$PORT" =~ ^[0-9]+$ ]] && (( 10#$PORT >= 1024 && 10#$PORT <= 65535 )) \
    || { eg_err "invalid private provider port"; return 1; }
  [[ "$REQUIRE_MODEL" =~ ^[A-Za-z0-9._:+/@-]{1,128}$ ]] \
    || { eg_err "invalid concrete provider model"; return 1; }
  [[ "$GROK_PROVIDER_CONTRACT_DIGEST" =~ ^[0-9a-f]{64}$ ]] \
    || { eg_err "invalid provider contract digest"; return 1; }
  [[ "$GROK_ACTIVE_RELEASE_ID" =~ ^[0-9a-f]{64}$ ]] \
    || { eg_err "invalid provider release identity"; return 1; }
  [[ "${GROK_INTERLOCK_OWNER_EPOCH:-}" == "$owner" ]] \
    || { eg_err "provider interlock owner mismatch"; return 1; }
  expected="$CONTROL_DIR/p/$(provider_workspace_tag "$owner" "$generation" "$PORT")" \
    || { eg_err "cannot derive provider runtime tag"; return 1; }
  if [[ -e "$EG_RUNTIME_DIR" || -L "$EG_RUNTIME_DIR" ]]; then
    [[ -d "$EG_RUNTIME_DIR" && ! -L "$EG_RUNTIME_DIR" ]] \
      || { eg_err "provider runtime is not a real directory"; return 1; }
    [[ "$(stat -c '%u:%a' "$EG_RUNTIME_DIR" 2>/dev/null)" == "$(id -u):700" ]] \
      || { eg_err "provider runtime has unsafe owner or mode"; return 1; }
    resolved="$(readlink -f -- "$EG_RUNTIME_DIR" 2>/dev/null)" || return 1
  else
    (( allow_missing == 1 )) \
      || { eg_err "provider runtime is missing"; return 1; }
    resolved="$(readlink -m -- "$EG_RUNTIME_DIR" 2>/dev/null)" || return 1
  fi
  [[ "$resolved" == "$expected" ]] \
    || { eg_err "provider runtime does not match owner/generation/port"; return 1; }
  inventory="$(readlink -m -- "$GROK_PROVIDER_INVENTORY" 2>/dev/null)" || return 1
  [[ "$inventory" == "$expected/inventory.json" ]] \
    || { eg_err "provider inventory path is not generation-scoped"; return 1; }
  [[ ! -L "$GROK_PROVIDER_INVENTORY" ]] \
    || { eg_err "provider inventory must not be a link"; return 1; }
  [[ "$(fence_owner_epoch 2>/dev/null)" == "$owner" ]] \
    || { eg_err "provider does not own the durable recovery fence"; return 1; }
  release="$(release_identity)" \
    || { eg_err "provider release has no coherent release identity"; return 1; }
  [[ "$GROK_ACTIVE_RELEASE_ID" == "$release" ]] \
    || { eg_err "provider release identity mismatch"; return 1; }
  [[ "$GROK_PROVIDER_DEADLINE_NS" =~ ^[1-9][0-9]{0,18}$ ]] \
    && (( 10#$GROK_PROVIDER_DEADLINE_NS <= 9223372036854775807 )) \
    || { eg_err "invalid provider monotonic deadline"; return 1; }
}

provider_validate_country_list(){
  local value="$1" allow_empty="${2:-0}" country seen=" "
  if [[ -z "$value" ]]; then
    (( allow_empty == 1 ))
    return
  fi
  [[ "$value" =~ ^[A-Z]{2}(\ [A-Z]{2})*$ ]] || return 1
  for country in $value; do
    [[ "$seen" != *" $country "* ]] || return 1
    seen+="$country "
  done
}

provider_validate_frozen_rung(){
  local rung="$1" require_state="${2:-0}" label country
  case "$rung" in
    home:*)
      for required in GROK_PROVIDER_HOME_LABEL GROK_PROVIDER_HOME_HOST \
                      GROK_PROVIDER_HOME_USER GROK_PROVIDER_HOME_PORT; do
        [[ -n "${!required:-}" ]] \
          || { eg_err "provider home route is missing $required"; return 1; }
      done
      label="${rung#home:}"
      [[ "$GROK_PROVIDER_HOME_LABEL" == "$label" \
         && "$GROK_PROVIDER_HOME_LABEL" =~ ^[A-Za-z0-9._:+@-]{1,120}$ ]] \
        || { eg_err "provider home label mismatch"; return 1; }
      [[ "$GROK_PROVIDER_HOME_HOST" =~ ^[A-Za-z0-9._:+/@-]{1,255}$ \
         && "$GROK_PROVIDER_HOME_HOST" != -* ]] \
        || { eg_err "invalid frozen provider home host"; return 1; }
      [[ "$GROK_PROVIDER_HOME_USER" =~ ^[A-Za-z0-9._:+/@-]{1,128}$ \
         && "$GROK_PROVIDER_HOME_USER" != -* ]] \
        || { eg_err "invalid frozen provider home user"; return 1; }
      [[ "$GROK_PROVIDER_HOME_PORT" =~ ^[1-9][0-9]{0,4}$ ]] \
        && (( 10#$GROK_PROVIDER_HOME_PORT <= 65535 )) \
        || { eg_err "invalid frozen provider home port"; return 1; }
      ;;
    iphone)
      [[ "${GROK_PROVIDER_IPHONE_NODE_ID:-}" =~ ^[A-Za-z0-9._:+/@-]{1,256}$ ]] \
        || { eg_err "invalid frozen provider iPhone node ID"; return 1; }
      if (( require_state == 1 )); then
        iphone_configured \
          || { eg_err "frozen provider iPhone state no longer matches"; return 1; }
      fi
      ;;
    ios:*)
      label="${rung#ios:}"
      ios_key_valid "$label" \
        && [[ "${GROK_PROVIDER_IOS_KEY:-}" == "$label" ]] \
        && route_token_valid "${GROK_PROVIDER_IOS_NODE_ID:-}" \
        || { eg_err "invalid frozen provider iOS identity"; return 1; }
      IOS_SELECTED_KEY="$label"
      IOS_SELECTED_NODE_ID="$GROK_PROVIDER_IOS_NODE_ID"
      if (( require_state == 1 )); then
        iphone_configured \
          || { eg_err "frozen provider iOS registry no longer matches"; return 1; }
      fi
      ;;
    vpn)
      for required in GROK_PROVIDER_VPN_NAMESPACE GROK_PROVIDER_VPN_MAX_TRIES \
                      GROK_PROVIDER_VPN_RANKING_VERSION; do
        [[ -n "${!required:-}" ]] \
          || { eg_err "provider VPN route is missing $required"; return 1; }
      done
      [[ -v GROK_PROVIDER_VPN_COUNTRIES \
         && -v GROK_PROVIDER_VPN_BLOCKED_COUNTRIES ]] \
        || { eg_err "provider VPN route is missing its frozen country policy"; return 1; }
      [[ "${GROK_PROVIDER_VPN_NAMESPACE:-}" == grokvpn \
         && "${GROK_VPN_NETNS:-}" == grokvpn ]] \
        || { eg_err "provider VPN namespace mismatch"; return 1; }
      [[ "$GROK_PROVIDER_VPN_MAX_TRIES" =~ ^[1-8]$ \
         && "$GROK_PROVIDER_VPN_MAX_TRIES" == "$VPN_MAX_TRIES" ]] \
        || { eg_err "provider VPN max-tries mismatch"; return 1; }
      [[ "$GROK_PROVIDER_VPN_RANKING_VERSION" == vpngate-score-uptime-v1 ]] \
        || { eg_err "unsupported provider VPN ranking policy"; return 1; }
      provider_validate_country_list "$GROK_PROVIDER_VPN_COUNTRIES" 1 \
        || { eg_err "invalid provider VPN country list"; return 1; }
      provider_validate_country_list "${GROK_PROVIDER_VPN_BLOCKED_COUNTRIES:-}" 1 \
        || { eg_err "invalid provider VPN blocked-country list"; return 1; }
      [[ "${VPNGATE_COUNTRIES:-}" == "$GROK_PROVIDER_VPN_COUNTRIES" \
         && "$GROK_BLOCKED_CC" == "${GROK_PROVIDER_VPN_BLOCKED_COUNTRIES:-}" ]] \
        || { eg_err "provider VPN policy aliases mismatch"; return 1; }
      for country in $GROK_PROVIDER_VPN_COUNTRIES; do
        [[ " ${GROK_PROVIDER_VPN_BLOCKED_COUNTRIES:-} " != *" $country "* ]] \
          || { eg_err "provider VPN allowed/blocked countries overlap"; return 1; }
      done
      ;;
    *) eg_err "unsupported provider rung"; return 1 ;;
  esac
}

# Reject junk in the watchdog tunables so a bad value cannot kill the watchdog or divide by zero.
[[ "$WATCH_INTERVAL" =~ ^[1-9][0-9]*$ ]] || { eg_warn "GROK_WATCH_INTERVAL='$WATCH_INTERVAL' is not a positive integer — using 10"; WATCH_INTERVAL=10; }
[[ "$DEEP_EVERY" =~ ^(0|[1-9][0-9]*)$ ]] || { eg_warn "GROK_DEEP_EVERY='$DEEP_EVERY' is not a non-negative integer — using 6"; DEEP_EVERY=6; }
if [[ ! "$VPN_STABILITY_CHECKS" =~ ^(0|[1-9][0-9]*)$ ]]; then
  eg_warn "GROK_VPN_STABILITY_CHECKS='$VPN_STABILITY_CHECKS' is not a non-negative integer — using 3"
  VPN_STABILITY_CHECKS=3
elif (( VPN_STABILITY_CHECKS > 10 )); then
  eg_warn "GROK_VPN_STABILITY_CHECKS='$VPN_STABILITY_CHECKS' is above the safety cap — using 10"
  VPN_STABILITY_CHECKS=10
fi

# ---------------------------------------------------------------- state

set_active(){
  case "$1" in
    direct|iphone|vpn) ;;
    ios:*) ios_key_valid "${1#ios:}" && [[ -n "${2:-}" ]] || return 1 ;;
    local:*) home_label_valid "${1#local:}" && [[ -n "${2:-}" ]] || return 1 ;;
    *) return 1 ;;
  esac
  [[ -z "${2:-}" ]] || route_token_valid "$2" || return 1
  [[ "${3:-22}" =~ ^[1-9][0-9]{0,4}$ ]] \
    && (( 10#${3:-22} <= 65535 )) || return 1
  # Atomic: write a temp file in the state dir, then rename onto $STATE. A reader always sees a
  # complete fixed-format record, never a half-written one or executable shell input.
  local tmp; tmp="$(mktemp "$STATE.XXXXXX")" || return 1
  if printf 'RUNG=%s\nDEST=%s\nSPORT=%s\n' \
      "$1" "${2:-}" "${3:-22}" > "$tmp" \
      && mv -fT -- "$tmp" "$STATE"; then
    return 0
  fi
  rm -f -- "$tmp"
  return 1
}
state_value(){
  [[ -f "$STATE" ]] || return 1
  sed -n "s/^$1=//p" "$STATE" 2>/dev/null | head -1
}
state_record_valid(){
  python3 - "$STATE" "$(id -u)" <<'PY' >/dev/null 2>&1
import os
import re
import stat
import sys

path = sys.argv[1]
uid = int(sys.argv[2])
descriptor = -1
try:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != 0o600
        or not 1 <= info.st_size <= 1024
    ):
        raise ValueError("unsafe state metadata")
    raw = os.read(descriptor, 1025)
    if len(raw) != info.st_size or len(raw) > 1024:
        raise ValueError("unstable or oversized state")
finally:
    if descriptor >= 0:
        os.close(descriptor)

match = re.fullmatch(
    rb"RUNG=([^\n]*)\nDEST=([^\n]*)\nSPORT=([^\n]*)\n",
    raw,
)
if match is None:
    raise SystemExit(1)
rung, destination, sport_raw = (
    value.decode("ascii", "strict") for value in match.groups()
)
token = re.compile(r"[A-Za-z0-9._:+/@-]{1,256}\Z")
label = re.compile(r"[A-Za-z0-9._:+@-]{1,120}\Z")
ios_key = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
if rung.startswith("local:"):
    if label.fullmatch(rung[6:]) is None or token.fullmatch(destination) is None:
        raise SystemExit(1)
elif rung.startswith("ios:"):
    if ios_key.fullmatch(rung[4:]) is None or token.fullmatch(destination) is None:
        raise SystemExit(1)
elif rung not in {"direct", "iphone", "vpn"}:
    raise SystemExit(1)
elif destination and token.fullmatch(destination) is None:
    raise SystemExit(1)
if re.fullmatch(r"[1-9][0-9]{0,4}", sport_raw) is None:
    raise SystemExit(1)
if int(sport_raw) > 65535:
    raise SystemExit(1)
PY
}
active_rung(){
  state_record_valid || return 1
  local value; value="$(state_value RUNG)" || return 1
  case "$value" in
    direct|iphone|vpn) ;;
    ios:*) ios_key_valid "${value#ios:}" || return 1 ;;
    local:*) home_label_valid "${value#local:}" || return 1 ;;
    *) return 1 ;;
  esac
  printf '%s' "$value"
}
active_dest(){
  state_record_valid || return 1
  local value; value="$(state_value DEST)" || return 1
  [[ -z "$value" ]] || route_token_valid "$value" || return 1
  printf '%s' "$value"
}
clear_active(){ rm -f "$STATE"; }

recovery_marker_valid(){
  (( PROVIDER_MODE == 0 )) || return 1
  [[ -f "$RECOVERY_MARKER" && ! -L "$RECOVERY_MARKER" ]] || return 1
  [[ "$(stat -c '%u:%a' "$RECOVERY_MARKER" 2>/dev/null)" == "$(id -u):600" ]] \
    || return 1
  [[ "$(cat "$RECOVERY_MARKER" 2>/dev/null)" == RECOVERY_REQUIRED ]]
}

recovery_transition_pending(){
  (( PROVIDER_MODE == 0 )) || return 1
  [[ -e "$RECOVERY_MARKER" || -L "$RECOVERY_MARKER" ]]
}

begin_recovery_transition(){
  (( PROVIDER_MODE == 0 )) || return 0
  if recovery_transition_pending; then
    recovery_marker_valid
    return
  fi
  local tmp
  tmp="$(umask 077; mktemp "$RECOVERY_MARKER.XXXXXX")" || return 1
  if printf '%s\n' RECOVERY_REQUIRED > "$tmp" \
     && chmod 600 "$tmp" \
     && mv -fT -- "$tmp" "$RECOVERY_MARKER"; then
    return 0
  fi
  rm -f -- "$tmp"
  return 1
}

end_recovery_transition(){
  (( PROVIDER_MODE == 0 )) || return 0
  recovery_marker_valid || return 1
  rm -f -- "$RECOVERY_MARKER"
}

pid_from_file(){
  [[ -s "$1" ]] || return 1
  local pid; pid="$(cat "$1" 2>/dev/null)"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  printf '%s' "$pid"
}

pid_has_arg(){
  local pid="$1" expected="$2" arg
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  while IFS= read -r -d '' arg; do
    [[ "$arg" == "$expected" ]] && return 0
  done < "/proc/$pid/cmdline"
  return 1
}

# `port_listening` alone is unsafe: any stale or hostile process could own the
# shared endpoint. Activation requires the expected process to own the listener.
# The pid listening on 127.0.0.1:$PORT, or empty. The socks rung binds the port as ROOT (socks-netns.py
# stage 1 binds before it re-execs into the netns and drops privileges), so an unprivileged `ss` cannot
# enumerate that socket; the iphone/ssh rungs bind it unprivileged. Try plain ss first so the sudo-free
# rungs stay sudo-free, then fall back to `sudo -n ss` so the root-owned socks listener is still resolved.
port_owner_pid(){
  local out
  out="$(ss -H -lntp "sport = :$PORT" 2>/dev/null \
    | awk -v e="127.0.0.1:$PORT" '$4==e{if(match($0,/pid=[0-9]+/)){print substr($0,RSTART+4,RLENGTH-4);exit}}')"
  [[ -n "$out" ]] || out="$(sudo -n ss -H -lntp "sport = :$PORT" 2>/dev/null \
    | awk -v e="127.0.0.1:$PORT" '$4==e{if(match($0,/pid=[0-9]+/)){print substr($0,RSTART+4,RLENGTH-4);exit}}')"
  printf '%s' "$out"
}
pid_owns_proxy_port(){
  local pid="$1"
  [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null || return 1
  [[ "$(port_owner_pid)" == "$pid" ]]
}

# ---------------------------------------------------------------- probes

port_listening(){ ss -H -lnt "sport = :$PORT" 2>/dev/null | grep -q .; }
tcp_ok(){ [[ "$2" =~ ^[0-9]+$ ]] && timeout 5 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$1" "$2" 2>/dev/null; }

# One proxied (or direct) GET, shared by the egress probes. A rung passes its proxy as $1; direct passes
# "" so the request leaves untunneled.
eg_curl(){
  local proxy="$1" url="$2" tmax="${3:-20}"
  if (( IOS_ATTEMPT_DEADLINE_SECONDS > 0 )); then
    local ios_remaining=""
    ios_remaining="$(ios_attempt_remaining)" || return 1
    (( ios_remaining < tmax )) && tmax="$ios_remaining"
  fi
  if [[ -n "$proxy" ]]; then
    "${CLEAN_PROXY_ENV[@]}" ALL_PROXY="$proxy" NO_PROXY="$NOPROXY" no_proxy="$NOPROXY" \
      curl -s --max-time "$tmax" "$url" 2>/dev/null
  else
    "${CLEAN_PROXY_ENV[@]}" curl -s --max-time "$tmax" "$url" 2>/dev/null
  fi
}

# Public IP / country seen through a rung. Cloudflare's trace is the primary source: it stays reachable
# through VPN egresses that block or rate-limit the dedicated echo services (api.ipify.org and ipinfo.io
# are routinely refused from VPN Gate datacenter IPs), and it is the same infrastructure grok's own API
# sits behind -- so it tests the path that actually matters. The dedicated services are only a fallback.
# Empty from egress_ip means no working egress at all; egress_country may be empty just because the geo
# lookup was blocked, which rung_probe treats as "unknown", not "dead".
egress_ip(){
  local proxy="${1-$PROXY}" trace ip
  trace="$(eg_curl "$proxy" https://1.1.1.1/cdn-cgi/trace | bounded_probe_output)"
  (( ${#trace} <= 65536 )) || trace=""
  ip="$(sed -n 's/^ip=//p' <<<"$trace" | head -1)"
  [[ -n "$ip" ]] || ip="$(eg_curl "$proxy" https://api.ipify.org | head -c 257)"
  (( ${#ip} <= 256 )) || ip=""
  normalize_ip "$ip" || true
}
egress_country(){
  local proxy="${1-$PROXY}" trace cc
  trace="$(eg_curl "$proxy" https://1.1.1.1/cdn-cgi/trace | bounded_probe_output)"
  (( ${#trace} <= 65536 )) || trace=""
  cc="$(sed -n 's/^loc=//p' <<<"$trace" | head -1)"
  [[ -n "$cc" ]] || cc="$(eg_curl "$proxy" https://ipinfo.io/country | head -c 17)"
  ( export LC_ALL=C; [[ "$cc" =~ ^[A-Z]{2}$ ]] ) && printf '%s' "$cc"
}

country_allowed(){ [[ -n "$1" && " $GROK_BLOCKED_CC " != *" $1 "* ]]; }

# The model ids offered through a given egress, one per line, sorted. IMPORTANT: `grok models`
# CACHES its result in ~/.grok/models_cache.json and serves later calls FROM that cache without
# refetching. Without invalidating it, a per-rung probe returns whatever egress last wrote the cache
# (e.g. the direct baseline measured from this VM's blocked region) instead of the rung under test —
# so every VPN rung looks like it "unlocks nothing" and the ladder rejects them all. We therefore
# delete the cache before each call to force a real /v1/models fetch through the egress in force.
# One API round-trip, no inference tokens. GROK_MODELS_CMD overrides it for the tests.
GROK_MODELS_CACHE="${GROK_MODELS_CACHE:-$HOME/.grok/models_cache.json}"
models_via(){
  local proxy="${1-$PROXY}" rung="${2:-}" out probe_timeout=90
  if [[ "$rung" == ios:* ]]; then
    probe_timeout="$(ios_attempt_remaining)" || return 1
  fi
  # Grok recreates its shared model cache during this probe.  Watchdog probes
  # run in a child forked before the interactive launch path, so protect the
  # cache here as well as in launch() instead of relying on the caller's umask.
  umask 077
  if [[ -n "${GROK_MODELS_CMD:-}" ]]; then
    out="$(GROK_PROBE_RUNG="$rung" timeout "$probe_timeout" \
      bash -c "$GROK_MODELS_CMD" 2>/dev/null | head -c 1048577)"
    (( ${#out} <= 1048576 )) || return 1
    printf '%s\n' "$out" | filter_model_ids
    return
  fi
  rm -f "$GROK_MODELS_CACHE"   # force a fresh fetch through THIS egress, not grok's cached list
  if [[ -n "$proxy" ]]; then
    out="$("${CLEAN_PROXY_ENV[@]}" ALL_PROXY="$proxy" NO_PROXY="$NOPROXY" no_proxy="$NOPROXY" \
      timeout "$probe_timeout" "$GROK_BIN" models 2>/dev/null | head -c 1048577)"
  else
    out="$("${CLEAN_PROXY_ENV[@]}" timeout "$probe_timeout" "$GROK_BIN" models 2>/dev/null | head -c 1048577)"
  fi
  (( ${#out} <= 1048576 )) || return 1
  grep -oE '^[[:space:]]+[-*][[:space:]]+[^[:space:]]+' <<<"$out" \
    | awk '{print $2}' \
    | filter_model_ids
}

# What this VM is offered with no tunnel at all. Every rung is judged against it: a rung is worth
# using exactly when it unlocks a model this list does not have.
#
# Deliberately not a version comparison. The id space holds grok-4.20-0309-reasoning,
# grok-420-computer-v0, grok-build and grok-composer-2.5-fast, and carries no release date, so
# "pick the highest number" would cheerfully choose grok-420-computer-v0 as the newest chat model.
# What the region gate hides is, by definition, whatever the direct egress cannot see -- so that is
# what we test. Unlike a pinned name it never goes stale when xAI ships the next flagship.
#
# Cached with a TTL (GROK_BASELINE_TTL) and re-measured when stale or on a fresh selection, so a
# model that becomes available everywhere eventually joins the baseline instead of being mistaken
# for something a tunnel unlocked.
learn_baseline(){
  discard_invalid_model_state_file "$BASELINE"
  if [[ -f "$BASELINE" ]]; then
    local now mtime
    now="$(date +%s)"; mtime="$(stat -c %Y "$BASELINE" 2>/dev/null || echo 0)"
    (( now - mtime < BASELINE_TTL )) && return 0
    eg_log "the direct-egress baseline is stale (> ${BASELINE_TTL}s old) — re-measuring"
  fi
  eg_log "measuring the direct egress (what this VM sees with no tunnel) ..."
  models_via "" direct > "$BASELINE"
  if [[ ! -s "$BASELINE" ]]; then
    eg_warn "  the API is not reachable directly at all — treating the baseline as empty"
    : > "$BASELINE"
  else
    eg_log "  baseline: $(paste -sd, "$BASELINE")"
  fi
}

# A rung is accepted when it unlocks at least one model the direct egress does not offer.
# GROK_REQUIRE_MODEL pins a specific one instead, for when you know exactly what you want.
rung_unlocks(){
  local rung="$1" proxy="$2" got extra
  discard_invalid_model_state_file "$BASELINE"
  discard_invalid_model_state_file "$UNLOCKED"
  if [[ -n "$REQUIRE_MODEL" ]] && ! model_id_valid "$REQUIRE_MODEL"; then
    eg_warn "configured model id is invalid"
    return 1
  fi
  got="$(models_via "$proxy" "$rung")"
  if [[ -z "$got" ]]; then eg_warn "  $rung: the API is not reachable through it"; return 1; fi
  eg_log "  $rung offers: $(paste -sd, <<<"$got")"

  if [[ -n "$REQUIRE_MODEL" ]]; then
    local hit; hit="$(grep -ixF -- "$REQUIRE_MODEL" <<<"$got")"
    if [[ -n "$hit" ]]; then
      printf '%s\n' "$hit" > "$UNLOCKED"   # recorded so the pinned model is the one actually used
      eg_ok "$rung: offers $REQUIRE_MODEL"
      return 0
    fi
    eg_warn "  $rung: does not offer $REQUIRE_MODEL"; return 1
  fi

  learn_baseline
  extra="$(comm -23 <(printf '%s\n' "$got") "$BASELINE")"
  if [[ -z "$extra" ]]; then eg_warn "  $rung: nothing the VM cannot already see"; return 1; fi
  printf '%s\n' "$extra" > "$UNLOCKED"
  eg_ok "$rung: unlocks $(paste -sd, <<<"$extra")"
}

# Route preference is independent of catalog novelty. A route still has to
# pass country policy and a real model API probe, but it need not beat the
# direct baseline. When a concrete target is supplied, admit only that exact
# model; otherwise retain the complete valid catalog for the compatibility
# picker or a routed `grok models` command.
rung_offers_available(){
  local rung="$1" proxy="$2" required="${3:-}" got hit
  discard_invalid_model_state_file "$UNLOCKED"
  if [[ -n "$required" ]] && ! model_id_valid "$required"; then
    eg_warn "configured model id is invalid"
    return 1
  fi
  got="$(models_via "$proxy" "$rung")"
  if [[ -z "$got" ]]; then eg_warn "  $rung: the API is not reachable through it"; return 1; fi
  eg_log "  $rung offers: $(paste -sd, <<<"$got")"

  if [[ -n "$required" ]]; then
    hit="$(grep -ixF -- "$required" <<<"$got")"
    if [[ -z "$hit" ]]; then
      eg_warn "  $rung: does not offer $required"
      return 1
    fi
    printf '%s\n' "$hit" > "$UNLOCKED"
    eg_ok "$rung: offers $required"
    return 0
  fi

  printf '%s\n' "$got" > "$UNLOCKED"
  eg_ok "$rung: route has a usable model catalog"
}

# Retained as the explicit-route API used by compatibility callers and tests.
rung_offers_forced(){ rung_offers_available "$@"; }

# Country first (free, and rejects a whole class of useless exits), models second.
rung_probe(){
  local rung="$1" proxy="$PROXY" cc
  [[ "$rung" == direct ]] && proxy=""
  cc="$(egress_country "$proxy")"
  # A known blocked region never serves the gated models, so skip the probe. But an UNKNOWN country (the
  # geo lookup was blocked or rate-limited on this exit -- common on VPN Gate IPs) is NOT proof of a dead
  # egress: the model probe is the authoritative test, so fall through to it rather than discarding a
  # server that may well work. rung_unlocks rejects a genuinely unreachable API on its own.
  if [[ -n "$cc" ]] && ! country_allowed "$cc"; then
    eg_warn "  $rung: exits in $cc — the frozen country policy blocks this route"; return 1
  fi
  if [[ -n "$cc" ]]; then eg_log "  $rung: exits in $cc — asking grok what that unlocks"
  else eg_log "  $rung: egress country unknown — asking grok what it unlocks anyway"; fi
  rung_unlocks "$rung" "$proxy"
}

rung_probe_available(){
  local rung="$1" required="${2:-}" proxy="$PROXY" cc
  [[ "$rung" == direct ]] && proxy=""
  cc="$(egress_country "$proxy")"
  if [[ -n "$cc" ]] && ! country_allowed "$cc"; then
    eg_warn "  $rung: exits in $cc — the frozen country policy blocks this route"
    return 1
  fi
  if [[ -n "$cc" ]]; then eg_log "  $rung: exits in $cc — asking grok what it offers"
  else eg_log "  $rung: egress country unknown — asking grok what it offers anyway"; fi
  rung_offers_available "$rung" "$proxy" "$required"
}

# Explicit host/iPhone callers use the same availability predicate while
# adding their exact-route watchdog policy at the caller.
rung_probe_forced(){ rung_probe_available "$@"; }

# ---------------------------------------------------------------- rung: local PC

local_hosts(){
  local label host user sport
  while IFS=$'\t' read -r label host user sport; do
    home_label_valid "$label" || continue
    route_token_valid "$host" && [[ "$host" != -* ]] || continue
    route_token_valid "$user" && [[ "$user" != -* ]] || continue
    [[ "$sport" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$sport <= 65535 )) || continue
    printf '%s\t%s\t%s\t%s\n' "$label" "$host" "$user" "$sport"
  done < <(
    awk '!/^#/ && NF>=3 && $3 !~ /^CHANGE_ME/ {print $1"\t"$2"\t"$3"\t"(NF>=4?$4:22)}' "$CONF"
  )
}

local_up_one(){
  local label="$1" ip="$2" user="$3" sport="$4"
  home_label_valid "$label" || return 1
  route_token_valid "$ip" && [[ "$ip" != -* ]] || return 1
  route_token_valid "$user" && [[ "$user" != -* ]] || return 1
  [[ "$sport" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$sport <= 65535 )) || return 1
  # L3: pin the home PC's host key. If a repo-local known_hosts exists (populated once from the
  # key the setup script prints), enforce it strictly; otherwise pin-on-first-use into that same
  # repo-local file — never the user's global known_hosts — so a fresh install still connects.
  local khost="$PRIVATE_DIR/known_hosts" skc="accept-new"
  [[ -s "$khost" ]] && skc="yes"
  [[ "$ip" != -* && "$user" != -* ]] || return 1
  if ! tcp_ok "$ip" "$sport"; then eg_warn "  $label ($ip:$sport) not reachable over Tailscale"; return 1; fi
  if [[ -e "$CTL" || -L "$CTL" ]]; then
    eg_warn "  refusing to replace an unexplained SSH control path: $CTL"
    return 1
  fi
  # Persist the exact cleanup destination before starting the SSH effect.  If
  # publication fails, no listener is created; if startup is interrupted or
  # fails unclearly, ordinary recovery still has the destination it must use.
  set_active "local:$label" "$user@$ip" "$sport" || return 1
  # ControlPersist=yes, not a timeout: with a timeout the master self-terminates once no
  # SOCKS connection has been open for that long, which kills a perfectly healthy tunnel
  # while you sit reading grok's last answer. ServerAlive 5x3 notices a dead link in ~15s.
  if ssh -M -S "$CTL" -fnN \
      -o ControlPersist=yes \
      -o ExitOnForwardFailure=yes \
      -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
      -o StrictHostKeyChecking="$skc" \
      -o UserKnownHostsFile="$khost" \
      -o ConnectTimeout=8 -o BatchMode=yes \
      -i "$KEY" -p "$sport" -D "127.0.0.1:$PORT" -- "$user@$ip" 9>&-; then
    return 0
  fi
  # Clear the ownership record only after exact rollback succeeds.  A failed
  # rollback retains the destination for a later stop/recovery attempt.
  local_down && clear_active
  return 1
}

local_up(){
  local want="$1" label ip user sport
  if (( PROVIDER_MODE == 1 )); then
    [[ "$want" == "$GROK_PROVIDER_HOME_LABEL" ]] || return 1
    local_up_one "$GROK_PROVIDER_HOME_LABEL" "$GROK_PROVIDER_HOME_HOST" \
      "$GROK_PROVIDER_HOME_USER" "$GROK_PROVIDER_HOME_PORT"
    return
  fi
  while IFS=$'\t' read -r label ip user sport; do
    [[ "$label" == "$want" ]] || continue
    local_up_one "$label" "$ip" "$user" "$sport"
    return
  done < <(local_hosts)
  return 1
}

local_recorded_dest(){
  local rung
  rung="$(active_rung 2>/dev/null)" || return 1
  [[ "$rung" == local:* ]] || return 1
  active_dest
}

local_alive(){
  local dest; dest="$(local_recorded_dest 2>/dev/null || true)"
  if (( PROVIDER_MODE == 1 )) && [[ -z "$dest" ]]; then
    dest="$GROK_PROVIDER_HOME_USER@$GROK_PROVIDER_HOME_HOST"
  fi
  [[ -S "$CTL" && -n "$dest" ]] \
    && ssh -S "$CTL" -O check -o BatchMode=yes -- "$dest" >/dev/null 2>&1
}

local_down(){
  local dest rc=0; dest="$(local_recorded_dest 2>/dev/null || true)"
  if (( PROVIDER_MODE == 1 )) && [[ -z "$dest" ]]; then
    dest="$GROK_PROVIDER_HOME_USER@$GROK_PROVIDER_HOME_HOST"
  fi
  if [[ -S "$CTL" && -n "$dest" ]]; then
    if ! ssh -S "$CTL" -O exit -o BatchMode=yes -- "$dest" >/dev/null 2>&1; then
      # Preserve the only exact control handle while the master/listener may
      # still exist.  A stale socket is removable only after both checks prove
      # that it no longer controls a process or the scoped SOCKS listener.
      if local_alive || [[ -n "$(port_owner_pid)" ]]; then
        return 1
      fi
    fi
  elif [[ -e "$CTL" || -L "$CTL" ]]; then
    return 1
  fi
  rm -f -- "$CTL" || rc=1
  return "$rc"
}

# ---------------------------------------------------------------- rung: iPhone Tailscale exit node

iphone_prepare_state(){
  ( umask 077; mkdir -p "$IPHONE_STATE_DIR" ) || return 1
  chmod 700 "$IPHONE_STATE_DIR"
}

iphone_node(){
  local value=""
  if (( PROVIDER_MODE == 1 )); then
    value="${GROK_PROVIDER_IOS_NODE_ID:-${GROK_PROVIDER_IPHONE_NODE_ID:-}}"
  elif [[ -n "$IOS_SELECTED_NODE_ID" ]]; then
    value="$IOS_SELECTED_NODE_ID"
  elif [[ -s "$IPHONE_NODE_FILE" ]]; then
    value="$(head -1 "$IPHONE_NODE_FILE")"
  elif [[ -n "${GROK_IPHONE_EXIT_NODE:-}" ]]; then
    value="$GROK_IPHONE_EXIT_NODE"
  fi
  [[ -z "$value" ]] || route_token_valid "$value" || return 1
  printf '%s' "$value"
}

iphone_configured(){
  if (( PROVIDER_MODE == 1 )); then
    local configured=""
    [[ -n "${GROK_PROVIDER_IOS_KEY:-}" && -n "${GROK_PROVIDER_IOS_NODE_ID:-}" ]] \
      || return 1
    configured="$(ios_registry_command node "$GROK_PROVIDER_IOS_KEY")" || return 1
    [[ "$configured" == "$GROK_PROVIDER_IOS_NODE_ID" ]]
    return
  fi
  [[ -n "$(ios_devices 2>/dev/null)" ]]
}
iphone_cli(){ "$TAILSCALE_BIN" --socket="$IPHONE_SOCKET" "$@"; }

iphone_process_identity(){
  local action="$1" pid="${2:-0}"
  python3 - "$action" "$pid" "$IPHONE_PID_IDENTITY" \
    "$IPHONE_LOG" \
    "$TAILSCALED_BIN" \
    "--tun=userspace-networking" \
    "--socket=$IPHONE_SOCKET" \
    "--state=$IPHONE_STATE" \
    "--socks5-server=127.0.0.1:$PORT" <<'PY'
import errno
import json
import os
import pathlib
import secrets
import select
import signal
import stat
import sys

action = sys.argv[1]
try:
    requested_pid = int(sys.argv[2])
except ValueError:
    raise SystemExit(2)
record_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
required_args = tuple(sys.argv[5:])


def process_snapshot(pid):
    boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="ascii"
    ).strip()
    raw = pathlib.Path(f"/proc/{pid}/stat").read_bytes()
    if len(raw) > 4096:
        raise ValueError("oversized process stat")
    close = raw.rfind(b")")
    if close < 0:
        raise ValueError("malformed process stat")
    fields = raw[close + 2 :].split()
    if len(fields) < 20:
        raise ValueError("short process stat")
    start_ticks = int(fields[19])
    command = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
    if len(command) > 131072:
        raise ValueError("oversized process command line")
    argv = tuple(part.decode("utf-8", "surrogateescape") for part in command.split(b"\0") if part)
    return boot, start_ticks, argv


def secure_directory_fd():
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(record_path.parent, flags)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        os.close(descriptor)
        raise ValueError("unsafe iPhone runtime directory")
    return descriptor


def load_record():
    directory = secure_directory_fd()
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(record_path.name, flags, dir_fd=directory)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 1 <= info.st_size <= 1024
        ):
            raise ValueError("unsafe iPhone process identity")
        data = os.read(descriptor, 1025)
        if len(data) > 1024:
            raise ValueError("oversized iPhone process identity")
        value = json.loads(data.decode("ascii"))
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)
    if type(value) is not dict or set(value) != {
        "boot_id", "pid", "schema_version", "start_ticks"
    }:
        raise ValueError("invalid iPhone process identity fields")
    if (
        value["schema_version"] != 1
        or type(value["pid"]) is not int
        or value["pid"] < 1
        or type(value["start_ticks"]) is not int
        or value["start_ticks"] < 1
        or type(value["boot_id"]) is not str
        or len(value["boot_id"]) != 36
    ):
        raise ValueError("invalid iPhone process identity")
    return value


def write_record(pid, boot, start_ticks):
    directory = secure_directory_fd()
    temporary = f".{record_path.name}.{secrets.token_hex(12)}.tmp"
    descriptor = -1
    try:
        try:
            existing = os.stat(record_path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != os.getuid()
            or stat.S_IMODE(existing.st_mode) != 0o600
        ):
            raise ValueError("unsafe existing iPhone process identity")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
        payload = json.dumps(
            {
                "boot_id": boot,
                "pid": pid,
                "schema_version": 1,
                "start_ticks": start_ticks,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short iPhone process identity write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.rename(
            temporary,
            record_path.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def prepare_log():
    if log_path.parent != record_path.parent:
        raise ValueError("iPhone log and identity directories differ")
    directory = secure_directory_fd()
    descriptor = -1
    try:
        flags = (
            os.O_WRONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(log_path.name, flags, dir_fd=directory)
        except FileNotFoundError:
            descriptor = os.open(
                log_path.name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory,
            )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise ValueError("unsafe iPhone sidecar log")
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def exact_snapshot(record, *, require_command):
    try:
        boot, start_ticks, argv = process_snapshot(record["pid"])
    except (FileNotFoundError, ProcessLookupError):
        return None
    if (boot, start_ticks) != (record["boot_id"], record["start_ticks"]):
        return None
    if require_command and not all(argument in argv for argument in required_args):
        return None
    return boot, start_ticks, argv


try:
    if action == "prepare-log":
        prepare_log()
    elif action == "write":
        if requested_pid != os.getppid():
            raise ValueError("identity writer does not own the launch parent")
        before = process_snapshot(requested_pid)
        pidfd = os.pidfd_open(requested_pid, 0)
        try:
            after = process_snapshot(requested_pid)
            if before[:2] != after[:2]:
                raise ValueError("launch process identity changed")
            write_record(requested_pid, after[0], after[1])
        finally:
            os.close(pidfd)
    elif action == "adopt":
        try:
            before = process_snapshot(requested_pid)
        except (FileNotFoundError, ProcessLookupError):
            raise SystemExit(0)
        if not all(argument in before[2] for argument in required_args):
            raise ValueError("legacy iPhone process command does not match")
        try:
            pidfd = os.pidfd_open(requested_pid, 0)
        except ProcessLookupError:
            raise SystemExit(0)
        try:
            after = process_snapshot(requested_pid)
            if before[:2] != after[:2] or not all(
                argument in after[2] for argument in required_args
            ):
                raise ValueError("legacy iPhone process identity changed")
            readable, _, _ = select.select([pidfd], [], [], 0)
            if not readable:
                write_record(requested_pid, after[0], after[1])
        finally:
            os.close(pidfd)
    elif action == "recorded":
        record = load_record()
        if record["pid"] != requested_pid:
            raise SystemExit(1)
    elif action == "pid":
        print(load_record()["pid"], end="")
    elif action in {"alive", "stop"}:
        record = load_record()
        if record["pid"] != requested_pid:
            raise ValueError("iPhone PID and exact identity disagree")
        before = exact_snapshot(record, require_command=(action == "alive"))
        if before is None:
            raise SystemExit(1 if action == "alive" else 0)
        try:
            pidfd = os.pidfd_open(record["pid"], 0)
        except ProcessLookupError:
            raise SystemExit(1 if action == "alive" else 0)
        try:
            after = exact_snapshot(record, require_command=(action == "alive"))
            if after is None or after[:2] != before[:2]:
                raise SystemExit(1 if action == "alive" else 0)
            readable, _, _ = select.select([pidfd], [], [], 0)
            if action == "alive":
                raise SystemExit(1 if readable else 0)
            if not readable:
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                readable, _, _ = select.select([pidfd], [], [], 2.0)
            if not readable:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                readable, _, _ = select.select([pidfd], [], [], 1.0)
            if not readable:
                raise SystemExit(1)
        finally:
            os.close(pidfd)
    else:
        raise ValueError("unsupported iPhone process identity action")
except (OSError, ValueError, json.JSONDecodeError):
    raise SystemExit(2)
PY
}

iphone_process_alive(){
  local pid="${1:-}"
  [[ -n "$pid" ]] || pid="$(pid_from_file "$IPHONE_PID")" || return 1
  iphone_process_identity alive "$pid"
}

iphone_listener_alive(){
  local pid; pid="$(pid_from_file "$IPHONE_PID")" || return 1
  iphone_process_alive "$pid" && pid_owns_proxy_port "$pid"
}

iphone_status_json(){ iphone_cli status --json 2>/dev/null; }
iphone_backend_running(){ iphone_status_json | jq -e '.BackendState == "Running"' >/dev/null 2>&1; }
iphone_selected_exit_id(){
  iphone_status_json | jq -er '.ExitNodeStatus.ID | select(type == "string" and length > 0)' 2>/dev/null
}
# Wait for the sidecar backend to leave transient startup states before a caller decides whether it needs
# `up`. A freshly (re)started but already-enrolled backend is briefly in "Starting"/"NoState" and only
# then reaches "Running"; checking immediately misreads that as "not authenticated". Prints the settled
# BackendState ("Running" when healthy; a "needs action" state otherwise), breaking early on the states
# that genuinely need enrollment so first-time login is not delayed.
iphone_wait_backend(){
  local i st=""
  for i in $(seq 1 20); do
    ios_attempt_check || break
    st="$(iphone_status_json | jq -r '.BackendState // ""' 2>/dev/null)"
    case "$st" in Running|NeedsLogin|NeedsMachineAuth|Stopped) break ;; esac
    sleep 0.25
  done
  printf '%s' "$st"
}
# Resolve a pinned exit-node identifier to a value `tailscale set --exit-node` accepts. setup pins the
# phone's StableNodeID (stable across hostname changes), but --exit-node takes only an IP or hostname --
# so map the pin (StableNodeID, hostname, DNSName, or IP) to the peer's current Tailscale IP via status.
iphone_exit_ip_for(){
  local pin="$1" raw=""
  route_token_valid "$pin" || return 1
  raw="$(iphone_status_json | jq -r --arg p "$pin" '
    def norm: ascii_downcase | rtrimstr(".");
    def ip_of: .TailscaleIPs[]? | split("/")[0];
    ( [ (.Peer // {}) | .[]
        | select( .ID == $p
                  or ((.HostName // "") | norm) == ($p | norm)
                  or ((.DNSName // "") | norm) == ($p | norm)
                  or ((.DNSName // "") | norm | split(".")[0]) == ($p | norm)
                  or any(.TailscaleIPs[]?; split("/")[0] == $p) )
        | ip_of ]
      # The already-selected exit node is reported in ExitNodeStatus, not Peer -- fall back to it so a
      # re-select (or a status that only echoes the current exit) still resolves to a usable IP.
      + [ (.ExitNodeStatus // empty)
          | select( .ID == $p or any(.TailscaleIPs[]?; split("/")[0] == $p) )
          | ip_of ]
    ) | .[0] // empty' 2>/dev/null)" || return 1
  [[ -n "$raw" ]] || return 0
  normalize_ip "$raw"
}
iphone_exit_online(){
  local node; node="$(iphone_node)"
  iphone_status_json | jq -e --arg node "$node" '
    def normalized_name:
      ascii_downcase | rtrimstr(".");
    . as $status
    | .BackendState == "Running"
      and (.ExitNodeStatus.Online // false) == true
      and (
        .ExitNodeStatus.ID == $node
        or any(.ExitNodeStatus.TailscaleIPs[]?; split("/")[0] == $node)
        or any(.Peer[]?;
          .ID == $status.ExitNodeStatus.ID
          and (
            ((.HostName // "") | normalized_name) == ($node | normalized_name)
            or ((.DNSName // "") | normalized_name) == ($node | normalized_name)
            or ((.DNSName // "") | normalized_name | split(".")[0]) == ($node | normalized_name)
            or any(.TailscaleIPs[]?; split("/")[0] == $node)
          )
        )
      )' >/dev/null 2>&1
}

iphone_down(){
  local pid="" rc=0
  if [[ -L "$IPHONE_PID" ]]; then
    rc=1
  elif [[ -e "$IPHONE_PID" ]]; then
    pid="$(pid_from_file "$IPHONE_PID")" || rc=1
  fi
  [[ ! -L "$IPHONE_PID_IDENTITY" ]] || rc=1
  if [[ -z "$pid" && -e "$IPHONE_PID_IDENTITY" ]]; then
    pid="$(iphone_process_identity pid)" || rc=1
  fi
  if [[ -n "$pid" && ! -e "$IPHONE_PID_IDENTITY" && ! -L "$IPHONE_PID_IDENTITY" ]]; then
    # One-time upgrade path for a sidecar started by the previous release.
    # Adoption opens a pidfd and revalidates the complete expected argv before
    # publishing the durable start/boot identity; an unrelated PID is retained
    # fail-closed and never signalled.
    iphone_process_identity adopt "$pid" || rc=1
  fi
  if [[ -n "$pid" ]]; then
    if [[ -e "$IPHONE_PID_IDENTITY" ]]; then
      iphone_process_identity stop "$pid" || rc=1
    elif (( rc != 0 )); then
      : # Unsafe legacy identity: preserve all evidence and fail closed.
    fi
    wait "$pid" 2>/dev/null || true
  fi
  port_listening && rc=1
  if (( rc == 0 )); then
    rm -f "$IPHONE_PID" "$IPHONE_PID_IDENTITY" "$IPHONE_SOCKET" || rc=1
  else
    eg_err "  iPhone sidecar teardown did not prove process exit"
  fi
  return "$rc"
}

iphone_start(){
  [[ -n "$TAILSCALE_BIN" && -x "$TAILSCALE_BIN" ]] \
    || { eg_warn "  tailscale CLI is not installed"; return 1; }
  [[ -n "$TAILSCALED_BIN" && -x "$TAILSCALED_BIN" ]] \
    || { eg_warn "  tailscaled is not installed"; return 1; }
  command -v jq >/dev/null 2>&1 || { eg_warn "  jq is required for the iPhone rung"; return 1; }
  iphone_prepare_state || return 1
  if iphone_listener_alive && [[ -S "$IPHONE_SOCKET" ]]; then return 0; fi
  iphone_down || return 1
  iphone_process_identity prepare-log || return 1
  (
    umask 077
    exec 9>&-
    iphone_process_identity write "$BASHPID" || exit 125
    exec "$TAILSCALED_BIN" \
      --tun=userspace-networking \
      --port=0 \
      --state="$IPHONE_STATE" \
      --statedir="$IPHONE_STATE_DIR" \
      --socket="$IPHONE_SOCKET" \
      --socks5-server="127.0.0.1:$PORT"
  ) >>"$IPHONE_LOG" 2>&1 &
  local pid=$!
  local recorded=0
  local i
  for i in $(seq 1 40); do
    ios_attempt_check || break
    if iphone_process_identity recorded "$pid"; then recorded=1; break; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.025
  done
  if (( recorded == 0 )); then
    eg_warn "  iPhone Tailscale sidecar did not publish an exact process identity"
    iphone_down
    return 1
  fi
  ( umask 077; printf '%s\n' "$pid" > "$IPHONE_PID" )
  chmod 600 "$IPHONE_PID" "$IPHONE_LOG" 2>/dev/null || true
  for i in $(seq 1 40); do
    ios_attempt_check || break
    if [[ -S "$IPHONE_SOCKET" ]] && iphone_listener_alive; then return 0; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.25
  done
  eg_warn "  iPhone Tailscale sidecar did not acquire 127.0.0.1:$PORT"
  eg_warn "  tailscaled $(iphone_log_fingerprint)"
  iphone_down
  return 1
}

iphone_select_exit(){
  local node ip="" i; node="$(iphone_node)"
  [[ -n "$node" ]] || { eg_warn "  no iPhone exit node configured — run: grok-remote iphone-setup"; return 1; }
  # The pin is usually a StableNodeID, which `set --exit-node` rejects ("must be IP or hostname"). Resolve
  # it to the peer's Tailscale IP, retrying briefly so a just-started sidecar can sync the netmap first.
  for i in $(seq 1 20); do
    ios_attempt_check || break
    ip="$(iphone_exit_ip_for "$node")"
    [[ -n "$ip" ]] && break
    sleep 0.25
  done
  [[ -n "$ip" ]] || { eg_warn "  iPhone exit node '$node' is not in the sidecar tailnet (offline, unapproved, or not yet synced)"; return 1; }
  iphone_cli set --exit-node="$ip" --exit-node-allow-lan-access=false --shields-up=true >/dev/null \
    || { eg_warn "  cannot select iPhone exit node '$node' -> $ip (offline, unapproved, or ACL denied)"; return 1; }
  for i in $(seq 1 20); do
    ios_attempt_check || break
    iphone_exit_online && return 0
    sleep 0.25
  done
  eg_warn "  iPhone exit node '$node' is selected but not online"
  return 1
}

iphone_up(){
  local public_rung="${1:-iphone}" node
  if [[ "$public_rung" == ios:* ]]; then
    ios_select_context "${public_rung#ios:}" || return 1
  else
    iphone_configured || return 1
  fi
  node="$(iphone_node)" || return 1
  [[ -n "$node" ]] || return 1
  # Publish the sidecar cleanup identity before any process or listener effect.
  # Failed rollback keeps this record; successful rollback removes it.
  set_active "$public_rung" "$node" || return 1
  if ! iphone_start; then
    iphone_down && clear_active
    return 1
  fi
  # Let the just-started backend settle before judging it: an already-enrolled sidecar is briefly in
  # "Starting" and reading it too early wrongly reports "not authenticated".
  if [[ "$(iphone_wait_backend)" != Running ]]; then
    eg_warn "  iPhone sidecar is not authenticated — run: grok-remote iphone-setup"
    iphone_down && clear_active
    return 1
  fi
  if ! iphone_select_exit; then
    iphone_down && clear_active
    return 1
  fi
  return 0
}

iphone_alive(){ iphone_listener_alive && iphone_exit_online; }

iphone_detect_node(){
  [[ -n "$PRIMARY_TAILSCALE_BIN" && -x "$PRIMARY_TAILSCALE_BIN" ]] || return 1
  local -a nodes=()
  mapfile -t nodes < <("$PRIMARY_TAILSCALE_BIN" status --json 2>/dev/null | jq -r \
    '.Peer[] | select((.OS // "" | ascii_downcase) == "ios" and (.ExitNodeOption // false) == true) | .TailscaleIPs[0] // empty')
  if (( ${#nodes[@]} != 1 )); then
    eg_err "expected exactly one iOS peer in the primary tailnet; found ${#nodes[@]} — pass its IP or name explicitly"
    return 1
  fi
  normalize_ip "${nodes[0]}"
}

iphone_name_for_id(){
  local node="$1" value=""
  value="$(iphone_status_json | jq -r --arg node "$node" '
    [(.Peer // {})[] | select(.ID == $node)
      | (.DNSName // .HostName // empty)] | .[0] // empty' 2>/dev/null)"
  if [[ -z "$value" && -n "$PRIMARY_TAILSCALE_BIN" && -x "$PRIMARY_TAILSCALE_BIN" ]]; then
    value="$("$PRIMARY_TAILSCALE_BIN" status --json 2>/dev/null | jq -r --arg node "$node" '
      [(.Peer // {})[] | select(.ID == $node)
        | (.DNSName // .HostName // empty)] | .[0] // empty' 2>/dev/null)"
  fi
  [[ -n "$value" ]] && printf '%s' "$value"
}

iphone_save_node(){
  local node="$1" tmp old=""
  route_token_valid "$node" || return 1
  iphone_prepare_state || return 1
  old="$(head -1 "$IPHONE_NODE_FILE" 2>/dev/null || true)"
  tmp="$(mktemp "$IPHONE_NODE_FILE.XXXXXX")" || return 1
  printf '%s\n' "$node" > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$IPHONE_NODE_FILE"
  [[ -z "$old" || "$old" == "$node" ]] || rm -f "$IPHONE_READY_FILE"
}

iphone_publish_legacy_fallback(){
  local node="$1"
  if [[ -e "$IPHONE_NODE_FILE" || -L "$IPHONE_NODE_FILE" \
     || -e "$IPHONE_READY_FILE" || -L "$IPHONE_READY_FILE" ]]; then
    [[ -f "$IPHONE_NODE_FILE" && ! -L "$IPHONE_NODE_FILE" \
       && -f "$IPHONE_READY_FILE" && ! -L "$IPHONE_READY_FILE" \
       && "$(stat -c '%u:%a' "$IPHONE_NODE_FILE" 2>/dev/null)" == "$(id -u):600" \
       && "$(stat -c '%u:%a' "$IPHONE_READY_FILE" 2>/dev/null)" == "$(id -u):600" ]] \
      || return 1
    if [[ -s "$IPHONE_NODE_FILE" && -s "$IPHONE_READY_FILE" \
       && "$(head -1 "$IPHONE_NODE_FILE")" == "$(head -1 "$IPHONE_READY_FILE")" ]]; then
      return 0
    fi
  fi
  iphone_save_node "$node" || return 1
  ( umask 077; printf '%s\n' "$node" > "$IPHONE_READY_FILE" ) || return 1
  chmod 600 "$IPHONE_READY_FILE"
}

# One-time enrollment of the sidecar identity. Authentication is interactive by
# default; automation accepts only an auth-key FILE so the secret never appears in
# argv or shell history. This never changes the primary Tailscale daemon.
iphone_setup_action(){
  local node="$1" label="${2:-}" rc=0
  IOS_SELECTED_NODE_ID="$node"
  iphone_start || return 1
  # A re-enrolled sidecar reconnects from persisted state and reaches "Running" on its own; deciding it
  # needs `up` before it settles would re-run `up` needlessly (or bail for a TTY it does not need).
  local st; st="$(iphone_wait_backend)"
  if [[ "$st" != Running ]]; then
    # --reset makes `up` declarative-idempotent: on a phone switch the sidecar's persisted state still
    # carries the previous phone's --exit-node (a non-default pref), and a bare `up` that does not
    # re-mention it fails with "must mention all non-default flags". --reset clears unspecified prefs to
    # their defaults (the stale exit-node included) and applies exactly these; iphone_select_exit sets the
    # new exit-node right after. The node key is untouched, so an enrolled sidecar is never re-logged-in.
    local -a up_args=(up --reset --hostname="$IPHONE_HOSTNAME" --accept-dns=true --accept-routes=false --shields-up=true)
    if [[ -n "$IPHONE_AUTHKEY_FILE" ]]; then
      local key_mode=""
      [[ -f "$IPHONE_AUTHKEY_FILE" && ! -L "$IPHONE_AUTHKEY_FILE" && -r "$IPHONE_AUTHKEY_FILE" ]] \
        || { eg_err "GROK_IPHONE_AUTHKEY_FILE must be a readable regular file"; return 1; }
      key_mode="$(stat -c '%a' "$IPHONE_AUTHKEY_FILE" 2>/dev/null || true)"
      if [[ ! "$key_mode" =~ ^[0-7]{3,4}$ ]] || (( (8#$key_mode & 8#77) != 0 )); then
        eg_err "GROK_IPHONE_AUTHKEY_FILE must not be accessible by group or other users (chmod 600)"
        return 1
      fi
      up_args+=(--auth-key="file:$IPHONE_AUTHKEY_FILE")
    elif [[ ! -t 0 ]]; then
      eg_err "iphone-setup needs a TTY login or GROK_IPHONE_AUTHKEY_FILE"
      return 1
    fi
    iphone_cli "${up_args[@]}" || return 1
  fi
  if iphone_select_exit; then
    local stable_id=""
    stable_id="$(iphone_selected_exit_id)" \
      || { eg_warn "selected phone has no stable node ID in Tailscale status"; return 1; }
    IOS_SELECTED_NODE_ID="$stable_id"
    IOS_SELECTED_KEY="$(iphone_name_for_id "$stable_id")"
    if [[ -z "$IOS_SELECTED_KEY" ]]; then
      if [[ -n "$label" ]]; then
        IOS_SELECTED_KEY="$label"
      else
        eg_warn "selected device has no unique Tailscale DNS name; rerun with --label KEY"
        return 1
      fi
    fi
    eg_ok "iOS exit node '$node' is ready and resolved to its stable node ID"
  else
    eg_warn "sidecar identity is enrolled and '$node' is saved, but the phone is not usable yet"
    eg_warn "enable Run as Exit Node on the iPhone, approve it in Tailscale, then rerun iphone-setup"
    rc=1
  fi
  return "$rc"
}

iphone_setup(){
  local node="${1:-}" label="${2:-}" rc=0 existing="" rows="" count=0
  if [[ -n "$label" ]]; then
    ios_key_valid "$label" \
      || { eg_err "iOS device label has unsupported characters"; return 2; }
  fi
  if [[ -z "$node" ]]; then
    rows="$(ios_devices)" \
      || { eg_err "cannot read the registered iOS device registry"; return 1; }
    count="$(grep -c . <<<"$rows")"
    if (( count == 1 )); then
      node="$(cut -f2 <<<"$rows")"
    elif (( count > 1 )); then
      eg_err "multiple iOS devices are registered — pass a device selector"
      return 2
    else
      node="$(iphone_detect_node)" || return 1
    fi
  fi
  route_token_valid "$node" \
    || { eg_err "iOS exit-node IP/name has unsupported characters"; return 1; }

  # Setup is a maintenance transaction, not an exception to route ownership.
  # Recover a prior interrupted transition first, then publish fresh recovery
  # intent and the exact sidecar rung before any process/listener can appear.
  existing="$(active_rung 2>/dev/null || true)"
  if recovery_transition_pending; then
    eg_warn "recovering incomplete egress ownership before iphone-setup"
    teardown_all \
      || { eg_err "cannot run iphone-setup while prior recovery is incomplete"; return 1; }
  elif [[ -e "$STATE" || -L "$STATE" ]]; then
    if [[ -n "$existing" ]]; then
      eg_err "egress route '$existing' is selected — run 'grok-remote stop' before iphone-setup"
      return 1
    fi
    eg_warn "recovering malformed egress ownership before iphone-setup"
    teardown_all \
      || { eg_err "cannot run iphone-setup while prior recovery is incomplete"; return 1; }
  fi
  begin_clean_route_transition \
    || { eg_err "cannot prove an empty route before iphone-setup"; return 1; }
  if ! set_active iphone "$node"; then
    eg_err "cannot publish iphone-setup cleanup ownership"
    teardown_all >/dev/null 2>&1 || true
    return 1
  fi

  IOS_SELECTED_KEY=""
  IOS_SELECTED_NODE_ID=""
  iphone_setup_action "$node" "$label" || rc=$?
  if ! teardown_all; then
    eg_err "iphone-setup cleanup was incomplete; recovery ownership was retained"
    return 1
  fi
  (( rc == 0 )) || return "$rc"
  [[ -n "$IOS_SELECTED_NODE_ID" && -n "$IOS_SELECTED_KEY" ]] \
    || { eg_err "iphone-setup did not retain a verified device identity"; return 1; }
  local -a register_args=(register --node-id "$IOS_SELECTED_NODE_ID" --name-hint "$IOS_SELECTED_KEY")
  [[ -z "$label" ]] || register_args+=(--label "$label")
  local registered_key=""
  registered_key="$(ios_registry_command "${register_args[@]}")" \
    || { eg_err "cannot publish the iOS device registry"; return 1; }
  if ! iphone_publish_legacy_fallback "$IOS_SELECTED_NODE_ID"; then
    eg_warn "registered '$registered_key', but could not create the old-release fallback pin"
  fi
  eg_ok "registered iOS device '$registered_key'; future runs do not require iphone-setup"
}

iphone_list(){
  local rows="" status='{}' key node online exit_option qualified selected
  rows="$(ios_registry_command devices)" \
    || { eg_err "cannot read the registered iOS device registry"; return 1; }
  if [[ -z "$rows" ]]; then
    eg_log "no iOS devices are registered"
    return 0
  fi
  if [[ -n "$PRIMARY_TAILSCALE_BIN" && -x "$PRIMARY_TAILSCALE_BIN" ]]; then
    status="$("$PRIMARY_TAILSCALE_BIN" status --json 2>/dev/null || printf '{}')"
  fi
  selected="$ACCOUNT_HOME/.local/state/grok-proxy/release-control/selected-release.json"
  local position=0
  while IFS=$'\t' read -r key node; do
    [[ -n "$key" ]] || continue
    position=$((position + 1))
    read -r online exit_option < <(jq -r --arg node "$node" '
      [(.Peer // {})[] | select(.ID == $node)][0] as $peer
      | [($peer.Online // false), ($peer.ExitNodeOption // false)] | @tsv' <<<"$status" 2>/dev/null)
    qualified=no
    if [[ -f "$selected" && ! -L "$selected" ]] \
       && jq -e --arg rung "ios:$key" '
         any((.qualified_rungs // [])[]; .rung == $rung)' "$selected" >/dev/null 2>&1; then
      qualified=yes
    fi
    printf '%d\t%s\t%s\texit-node=%s\tmulti-session-qualified=%s\n' \
      "$position" "$key" "$([[ "$online" == true ]] && printf online || printf offline)" \
      "$([[ "$exit_option" == true ]] && printf yes || printf no)" "$qualified"
  done <<<"$rows"
}

iphone_registry_mutation_ready(){
  if recovery_transition_pending || [[ -e "$STATE" || -L "$STATE" ]]; then
    eg_err "an egress route or recovery transaction is active — run 'grok-remote stop' first"
    return 1
  fi
  teardown_all \
    || { eg_err "cannot prove empty routing state before registry mutation"; return 1; }
}

iphone_remove(){
  local key="$1"
  ios_key_valid "$key" || { eg_err "invalid iOS device key"; return 2; }
  iphone_registry_mutation_ready || return 1
  ios_registry_command remove "$key" \
    || { eg_err "cannot remove iOS device '$key'"; return 1; }
  eg_ok "removed iOS device '$key'"
}

iphone_reorder(){
  (( $# > 0 )) || { eg_err "iphone-reorder requires every registered key"; return 2; }
  local key
  for key in "$@"; do
    ios_key_valid "$key" || { eg_err "invalid iOS device key '$key'"; return 2; }
  done
  iphone_registry_mutation_ready || return 1
  ios_registry_command reorder "$@" \
    || { eg_err "iOS priority must be an exact permutation of registered keys"; return 1; }
  eg_ok "updated iOS device priority"
}

# ---------------------------------------------------------------- rung: VPN

prepare_socks_runtime(){
  (( PROVIDER_MODE == 1 )) && return 0
  ( umask 077; mkdir -p -- "$SOCKS_RUNTIME_DIR" ) || return 1
  [[ -d "$SOCKS_RUNTIME_DIR" && ! -L "$SOCKS_RUNTIME_DIR" \
     && "$(stat -c '%u:%a' "$SOCKS_RUNTIME_DIR" 2>/dev/null)" == "$(id -u):700" ]] \
    || { eg_err "unsafe compatibility VPN runtime directory"; return 1; }
}

socks_down(){
  # The relay is a broker-owned root transaction.  User code never signals or
  # unlinks it; this function is only the independent post-teardown proof.
  local status
  status="$(vpn_broker_call status 2>/dev/null)" || return 1
  python3 -c 'import json,sys; v=json.load(sys.stdin); raise SystemExit(1 if v.get("relay_alive") or v.get("relay_pid") is not None else 0)' \
    <<<"$status"
}

socks_process_alive(){
  local pid="${1:-}" status
  [[ "$pid" =~ ^[0-9]+$ ]] || pid="$(pid_from_file "$SOCKS_PID")" || return 1
  status="$(vpn_broker_call status 2>/dev/null)" || return 1
  python3 -c 'import json,sys; v=json.load(sys.stdin); p=int(sys.argv[1]); raise SystemExit(0 if v.get("relay_alive") is True and v.get("relay_pid") == p else 1)' \
    "$pid" <<<"$status"
}

socks_alive(){
  local status
  status="$(vpn_broker_call status 2>/dev/null)" || return 1
  python3 -c 'import json,sys; v=json.load(sys.stdin); raise SystemExit(0 if v.get("relay_alive") is True and isinstance(v.get("relay_pid"), int) else 1)' \
    <<<"$status"
}
vpn_root_empty(){
  local status
  status="$(vpn_broker_call status 2>/dev/null)" || return 1
  python3 -c 'import json,sys; v=json.load(sys.stdin); flags=("active","namespace_alive","tun_alive","host_tun_alive","vpn_alive","relay_alive","root_artifact_residue"); fields={"ok",*flags,"relay_pid","ledger"}; valid=type(v) is dict and set(v)==fields and v.get("ok") is True and all(type(v.get(name)) is bool for name in flags); residue=(not valid) or any(v.get(name) is True for name in flags) or v.get("ledger") is not None or v.get("relay_pid") is not None; raise SystemExit(1 if residue else 0)' \
    <<<"$status"
}
vpn_tun_alive(){
  local status
  status="$(vpn_broker_call status 2>/dev/null)" || return 1
  python3 -c 'import json,sys; v=json.load(sys.stdin); raise SystemExit(0 if v.get("active") is True and v.get("namespace_alive") is True and v.get("tun_alive") is True and v.get("vpn_alive") is True else 1)' \
    <<<"$status"
}

vpn_broker_call(){
  [[ $# == 1 ]] || {
    eg_err "invalid VPN broker request"
    return 1
  }
  local operation="$1"
  local request_mode owner generation release contract_digest max_tries
  local ranking countries blocked prefer countries_csv blocked_csv prefer_csv
  local caller_identity caller_pid caller_start caller_boot deadline_ns
  if (( PROVIDER_MODE == 1 )); then
    request_mode=supervisor
    owner="$GROK_PROVIDER_OWNER_EPOCH"
    generation="$GROK_PROVIDER_GENERATION"
    release="${GROK_ACTIVE_RELEASE_ID:-}"
  elif (( HANDOFF_MODE == 1 )); then
    if [[ "$operation" == migrate-legacy ]]; then
      request_mode=compatibility-handoff
    elif [[ "$operation" == status ]]; then
      request_mode=supervisor
    else
      eg_err "compatibility handoff permits only migration proof or status"
      return 1
    fi
    owner="$GROK_HANDOFF_OWNER_EPOCH"
    generation=1
    release="$GROK_HANDOFF_RELEASE_ID"
    contract_digest="$(printf '0%.0s' {1..64})"
    max_tries="$VPN_MAX_TRIES"
    ranking="vpngate-score-uptime-v1"
    countries="$VPN_EXPLICIT_COUNTRIES"
    blocked="$GROK_BLOCKED_CC"
    prefer="$VPN_PREFER_COUNTRIES"
  else
    request_mode=compatibility
    owner="compat-$(id -u)"
    generation=0
    release="$(release_identity)" || {
      eg_err "VPN broker requires an atomically installed release"
      return 1
    }
    contract_digest="$(printf '0%.0s' {1..64})"
    max_tries="$VPN_MAX_TRIES"
    ranking="vpngate-score-uptime-v1"
    countries="$VPN_EXPLICIT_COUNTRIES"
    blocked="$GROK_BLOCKED_CC"
    prefer="$VPN_PREFER_COUNTRIES"
  fi
  local -a argv=(
    --operation "$operation"
    --mode "$request_mode"
    --release-id "$release"
    --owner-epoch "$owner"
    --generation "$generation"
    --listen-port "$PORT"
  )
  if (( PROVIDER_MODE == 1 )); then
    contract_digest="$GROK_PROVIDER_CONTRACT_DIGEST"
    max_tries="$GROK_PROVIDER_VPN_MAX_TRIES"
    ranking="$GROK_PROVIDER_VPN_RANKING_VERSION"
    countries="$GROK_PROVIDER_VPN_COUNTRIES"
    blocked="$GROK_PROVIDER_VPN_BLOCKED_COUNTRIES"
    prefer="$GROK_PROVIDER_VPN_COUNTRIES"
  fi
  countries_csv="${countries// /,}"
  blocked_csv="${blocked// /,}"
  prefer_csv="${prefer// /,}"
  caller_pid="$$"
  caller_identity="$(python3 - "$caller_pid" <<'PY'
import pathlib, re, sys
pid = int(sys.argv[1])
raw = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
fields = raw[raw.rfind(")") + 2:].split()
boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
if len(fields) <= 19 or not fields[19].isdigit() or re.fullmatch(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", boot
) is None:
    raise SystemExit(1)
print(fields[19], boot)
PY
)" || { eg_err "cannot capture exact broker caller identity"; return 1; }
  read -r caller_start caller_boot <<<"$caller_identity"
  if (( PROVIDER_MODE == 1 )); then
    deadline_ns="$GROK_PROVIDER_DEADLINE_NS"
  else
    deadline_ns="$(python3 -c 'import time; print(time.monotonic_ns() + 600_000_000_000)')" \
      || { eg_err "cannot establish broker operation deadline"; return 1; }
  fi
  argv+=(
    --contract-digest "$contract_digest"
    --vpn-max-tries "$max_tries"
    --vpn-ranking-version "$ranking"
    --vpn-countries "$countries_csv"
    --vpn-blocked-countries "$blocked_csv"
    --vpn-prefer-countries "$prefer_csv"
    --caller-pid "$caller_pid"
    --caller-start-ticks "$caller_start"
    --caller-boot-id "$caller_boot"
    --deadline-monotonic-ns "$deadline_ns"
  )
  if [[ "$VPN_BROKER_MODE" == test ]]; then
    "$VPN_BROKER" "${argv[@]}" 9>&-
  else
    sudo -n "$VPN_BROKER" "${argv[@]}" 9>&-
  fi
}

# verb: "up" for the first server, "next" to blacklist the current one and take the next.
vpn_up(){
  local verb="${1:-up}" state_published=0
  case "$verb" in up|next|reset) ;; *) return 1 ;; esac
  prepare_socks_runtime || return 1
  # Compatibility mode has no supervisor-owned transition record, so publish
  # cleanup ownership before asking the root broker to create anything.
  if (( PROVIDER_MODE == 0 && HANDOFF_MODE == 0 )); then
    set_active vpn || return 1
    state_published=1
  fi
  if ! vpn_broker_call "$verb" >&2; then
    (( PROVIDER_MODE == 1 )) && return 31
    return 1
  fi
  if ! vpn_tun_alive; then
    eg_err "  broker did not prove the VPN relay generation active"
    vpn_broker_call down >/dev/null 2>&1 || true
    (( PROVIDER_MODE == 1 )) && return 32
    return 1
  fi
  if ! socks_alive; then
    eg_err "  broker did not prove the VPN relay generation active"
    vpn_broker_call down >/dev/null 2>&1 || true
    (( PROVIDER_MODE == 1 )) && return 33
    return 1
  fi
  if (( state_published == 0 )) && ! set_active "vpn"; then
    vpn_broker_call down >/dev/null 2>&1 || true
    (( PROVIDER_MODE == 1 )) && return 34
    return 1
  fi
  return 0
}

vpn_alive(){ vpn_tun_alive && socks_alive; }
vpn_down(){
  local rc=0
  if (( HANDOFF_MODE == 1 )); then
    vpn_root_empty
    return
  fi
  vpn_broker_call down >/dev/null 2>&1 || rc=1
  (( rc != 0 )) || socks_down || rc=1
  return "$rc"
}

# ---------------------------------------------------------------- rung dispatch

rung_alive(){
  case "$1" in
    direct)  return 0 ;;
    local:*) local_alive ;;
    iphone)  iphone_alive ;;
    ios:*)   ios_select_context "${1#ios:}" && iphone_alive ;;
    vpn)     vpn_alive ;;
    *)       return 1 ;;
  esac
}

rung_down(){
  case "$1" in
    direct)  return 0 ;;
    local:*) local_down ;;
    iphone)  iphone_down ;;
    ios:*)   iphone_down ;;
    vpn)     vpn_down ;;
  esac
}

rung_up(){
  case "$1" in
    direct)  set_active direct ;;
    local:*) local_up "${1#local:}" ;;
    iphone)  iphone_up iphone ;;
    ios:*)   iphone_up "$1" ;;
    vpn)     vpn_up up ;;
  esac
}

# Confirm a rung that was just (re)brought up is not merely alive but still
# serves the model the session is pinned to. A reconnected VPN or phone can
# land on a different public egress, so it is catalog-qualified even without a
# pin. A home PC with no pin has a stable region, so liveness remains enough.
rung_confirm(){
  if [[ "$1" == direct ]]; then return 0; fi
  if [[ -n "${FORCE_EXACT_ROUTE:-}" && "$1" == "$FORCE_EXACT_ROUTE" ]]; then
    rung_probe_forced "$1" "$REQUIRE_MODEL"
    return
  fi
  if [[ -n "$REQUIRE_MODEL" || "$1" == vpn || "$1" == iphone || "$1" == ios:* ]]; then
    rung_probe_available "$1" "$REQUIRE_MODEL"
  else
    rung_alive "$1"
  fi
}

teardown_provider_pass(){
  local selected="$1" rc=0
  case "$selected" in
    local:*)
      local_down || rc=1
      vpn_down || rc=1
      iphone_down || rc=1
      ;;
    vpn)
      vpn_down || rc=1
      local_down || rc=1
      iphone_down || rc=1
      ;;
    iphone)
      iphone_down || rc=1
      local_down || rc=1
      vpn_down || rc=1
      ;;
    ios:*)
      iphone_down || rc=1
      local_down || rc=1
      vpn_down || rc=1
      ;;
    *)
      local_down || rc=1
      vpn_down || rc=1
      iphone_down || rc=1
      ;;
  esac
  return "$rc"
}

teardown_all(){
  local rc=0 selected=""
  # Publish recovery intent before the first destructive action.  If marker
  # publication fails, leave every effect untouched and fail closed.
  begin_recovery_transition || return 1
  selected="$(active_rung 2>/dev/null || true)"
  # Every compatibility provider shares one port and both the phone and VPN
  # absence checks reject a listener owned by another provider.  Reconcile the
  # validated owner first, then attempt every other exact cleanup.  A second
  # pass is the authoritative empty proof after those shared-port effects have
  # had a chance to disappear.  For malformed/empty state the fixed first pass
  # still discovers and removes a safely identifiable phone or VPN owner; an
  # unidentifiable SSH control master remains fail-closed.
  teardown_provider_pass "$selected" || true
  teardown_provider_pass "$selected" || rc=1
  # State is the only durable cleanup handle.  Aggregate teardown is a
  # transaction: try every component, but publish the empty state only after
  # all three exact cleanup paths have succeeded.
  (( rc == 0 )) || return "$rc"
  clear_active || return 1
  end_recovery_transition
}

# Explicit-route recovery uses the same aggregate transaction.  Keeping this
# named wrapper makes its watchdog policy visible at the call site.
teardown_forced_exact(){
  teardown_all
}

stop_egress(){
  if teardown_all; then
    eg_ok "egress torn down"
    return 0
  fi
  eg_err "egress teardown failed; route state was left unchanged for recovery"
  return 1
}

# Reuse a healthy selected route.  A stale or malformed record must pass the
# aggregate teardown transaction before a new ladder walk can publish another
# owner.  Both public command front ends use this gate.
ensure_selected_egress(){
  local cur=""
  cur="$(active_rung 2>/dev/null || true)"
  if ! recovery_transition_pending \
     && [[ -n "$cur" && "$cur" != direct ]] && rung_alive "$cur"; then
    return 0
  fi
  if [[ "$cur" == direct ]]; then
    eg_log "rechecking preferred remote routes instead of reusing direct"
  fi
  if recovery_transition_pending || [[ -e "$STATE" || -L "$STATE" ]]; then
    eg_warn "discarding stale or invalid egress ownership before selection"
    if ! teardown_all; then
      eg_err "cannot select a replacement because teardown was incomplete"
      return 1
    fi
  fi
  select_egress
}

# EMPTY state is not itself proof that no legacy process, socket, listener, or
# broker residue exists.  Reconcile every provider first, then publish the
# transition marker that protects the upcoming startup/qualification window.
begin_clean_route_transition(){
  if recovery_transition_pending || [[ -e "$STATE" || -L "$STATE" ]]; then
    eg_err "cannot begin a clean route transition over existing ownership"
    return 1
  fi
  if ! teardown_all; then
    eg_err "cannot prove provider residue empty before route startup"
    return 1
  fi
  begin_recovery_transition
}

# ---------------------------------------------------------------- the ladder

# `direct` is not on the ladder. It is measured before the walk and is the
# qualified fallback only when no preferred remote route is usable.
LADDER=()
build_ladder(){
  LADDER=()
  local label registry_rows=""
  registry_rows="$(ios_devices)" \
    || { eg_err "cannot read the registered iOS device registry"; return 1; }
  if [[ -n "$IOS_EXACT_KEY" ]]; then
    ios_node_for_key "$IOS_EXACT_KEY" >/dev/null \
      || { eg_err "unknown iOS device '$IOS_EXACT_KEY'"; return 1; }
    LADDER+=("ios:$IOS_EXACT_KEY")
    return 0
  fi
  if (( IOS_ONLY == 0 )); then
    while IFS=$'\t' read -r label _ _ _; do LADDER+=("local:$label"); done < <(local_hosts)
  fi
  while IFS=$'\t' read -r label _; do
    [[ -z "$label" ]] || LADDER+=("ios:$label")
  done <<<"$registry_rows"
  (( IOS_ONLY == 1 )) || LADDER+=("vpn")
}

# The vpn entry is not one rung but a sequence: walk VPN Gate candidates until one both
# comes up and offers the model.
# A VPN Gate server can pass the one-shot probe and then die within seconds -- which grok experiences as
# a slow login (its settings fetch retries) ending on the grok-build fallback. Before committing the
# session to a server, confirm its egress holds across a few quick checks so a server that is already
# degrading is skipped in favour of the next candidate. GROK_VPN_STABILITY_CHECKS=0 disables the gate.
vpn_stable(){
  local checks="$VPN_STABILITY_CHECKS" i ip expected=""
  (( checks > 0 )) || return 0
  for (( i = 1; i <= checks; i++ )); do
    sleep 1
    ip="$(egress_ip "$PROXY")"
    if [[ -z "$ip" ]]; then
      eg_warn "  vpn: egress dropped mid-check ($i/$checks) — server is unstable, skipping it"
      return 1
    fi
    if [[ -z "$expected" ]]; then
      expected="$ip"
    elif [[ "$ip" != "$expected" ]]; then
      eg_warn "  vpn: exit identity changed during qualification — server is unstable, skipping it"
      return 1
    fi
  done
  eg_ok "  vpn: one exit identity held across $checks checks — committing"
  return 0
}

try_vpn_sequence(){
  local required="${1:-$REQUIRE_MODEL}" verb=up i=0
  while (( i < VPN_MAX_TRIES )); do
    if ! vpn_up "$verb"; then eg_warn "  no further VPN Gate server came up"; return 1; fi
    if rung_probe_available vpn "$required" && vpn_stable; then return 0; fi
    verb=next; i=$((i+1))
  done
  eg_warn "  exhausted $VPN_MAX_TRIES VPN Gate servers"
  return 1
}

# Walk the ladder from $1 (default: the top) and settle on the first usable
# route in configured priority order. $2=0 forbids direct fallback during
# demotion/reacquisition. $3 optionally requires one concrete model.
select_egress(){
  local start="${1:-0}" direct_fallback="${2:-1}" required="${3:-$REQUIRE_MODEL}"
  local i rung current direct_ok=0 ios_attempt=0
  IOS_FAMILY_DEADLINE_SECONDS=0
  if recovery_transition_pending || [[ -e "$STATE" || -L "$STATE" ]]; then
    current="$(active_rung 2>/dev/null || true)"
    eg_err "selection requires proved-empty ownership state${current:+ (currently $current)}"
    return 1
  fi
  begin_clean_route_transition \
    || { eg_err "cannot publish route-selection recovery intent"; return 1; }
  learn_baseline
  build_ladder || return 1
  for (( i = start; i < ${#LADDER[@]}; i++ )); do
    rung="${LADDER[$i]}"
    eg_log "trying rung: $rung"
    ios_attempt=0
    if [[ "$rung" == ios:* ]]; then
      if (( IOS_FAMILY_DEADLINE_SECONDS == 0 )); then
        IOS_FAMILY_DEADLINE_SECONDS=$((SECONDS + 60))
      fi
      if ! ios_attempt_begin; then
        eg_warn "  iOS family selection reached its 60-second cap"
        continue
      fi
      ios_attempt=1
    fi
    if [[ "$rung" == vpn ]]; then
      if try_vpn_sequence "$required"; then
        end_recovery_transition || return 1
        return 0
      fi
      if ! vpn_down; then
        eg_err "vpn selection failed and exact teardown was incomplete; aborting selection"
        return 1
      fi
      clear_active || return 1
      continue
    fi
    if ! rung_up "$rung"; then
      (( ios_attempt == 0 )) || ios_attempt_end
      current="$(active_rung 2>/dev/null || true)"
      if [[ -e "$STATE" || -L "$STATE" ]]; then
        eg_err "$rung startup retained cleanup ownership${current:+ as $current}; aborting selection"
        return 1
      fi
      continue
    fi
    if rung_probe_available "$rung" "$required"; then
      (( ios_attempt == 0 )) || ios_attempt_end
      end_recovery_transition || return 1
      return 0
    fi
    if ! rung_down "$rung"; then
      (( ios_attempt == 0 )) || ios_attempt_end
      eg_err "$rung probe failed and exact teardown was incomplete; aborting selection"
      return 1
    fi
    (( ios_attempt == 0 )) || ios_attempt_end
    clear_active || return 1
  done
  if [[ -s "$BASELINE" ]]; then
    if [[ -z "$required" ]] || grep -qxF -- "$required" "$BASELINE"; then
      direct_ok=1
    fi
  fi
  # Direct is a qualified initial fallback only, never a demotion target.
  if [[ "$direct_fallback" == 1 && "$ALLOW_DIRECT" == 1 ]]; then
    if (( direct_ok )); then
      eg_warn "no preferred remote route is usable — falling back to qualified direct"
      rm -f "$UNLOCKED"
      set_active direct || return 1
      end_recovery_transition || return 1
      return 0
    fi
    if [[ -n "$required" ]]; then
      eg_warn "direct fallback does not offer required model $required"
    else
      eg_warn "direct fallback has no usable model catalog"
    fi
  fi
  # A probing walk that comes up empty must not leave a rung named in the state: try_vpn_sequence
  # sets 'vpn' active before its probe, so without this the caller would see a phantom vpn rung.
  clear_active || return 1
  end_recovery_transition || return 1
  return 1
}

# Move strictly downward. Inside the vpn rung, "down" means the next VPN Gate server.
demote(){
  local cur
  cur="$(active_rung)" \
    || { eg_err "cannot demote without a valid selected route"; return 1; }
  begin_recovery_transition \
    || { eg_err "cannot publish demotion recovery intent"; return 1; }
  if [[ "$cur" == vpn ]]; then
    eg_warn "demoting to the next VPN Gate server"
    local verb=next i=0
    while (( i < VPN_MAX_TRIES )); do
      if ! vpn_up "$verb"; then break; fi
      if rung_probe_available vpn "$REQUIRE_MODEL" && vpn_stable; then
        end_recovery_transition || return 1
        return 0
      fi
      i=$((i+1))
    done
    eg_err "no VPN Gate server left"
    return 1
  fi
  if ! rung_down "$cur"; then
    eg_err "$cur teardown was incomplete; retaining ownership and refusing demotion"
    return 1
  fi
  clear_active || return 1
  end_recovery_transition || return 1
  # Resume the ladder just past the rung being abandoned. Deriving the index from the live ladder
  # (not a stashed LADDER_POS a reused session never set) is what stops a demote from re-probing
  # rungs above the current one. An unknown rung starts past the end -> fail closed, no fallback.
  build_ladder || return 1
  local from=${#LADDER[@]} i
  for (( i = 0; i < ${#LADDER[@]}; i++ )); do
    if [[ "${LADDER[$i]}" == "$cur" ]]; then from=$((i + 1)); break; fi
  done
  select_egress "$from" 0            # 0: no direct fallback — demoting into direct is a downgrade
}

# ---------------------------------------------------------------- watchdog

watch_reacquire(){
  local forced="${FORCE_EXACT_ROUTE:-}"
  if [[ -n "$forced" ]]; then
    begin_clean_route_transition || return 1
    if rung_up "$forced" && rung_confirm "$forced" \
       && end_recovery_transition; then
      return 0
    fi
    # Retain the exact route request across retries.  A failed partial startup
    # must be removed before the next attempt, and it must never fall through
    # to the automatic ladder.
    teardown_all >/dev/null 2>&1 || return 1
    return 1
  fi
  select_egress 0 0
}

watch_egress(){
  local cycle=0 fails=0 cur
  while sleep "$WATCH_INTERVAL"; do
    if recovery_transition_pending; then
      eg_err "route recovery is pending — retrying exact aggregate teardown"
      teardown_all >/dev/null 2>&1 || true
      fails=0
      continue
    fi
    cur="$(active_rung)"

    # No egress currently held (a prior round tore everything down to fail closed). Keep hunting:
    # a home PC may have woken, or a VPN region that serves the model may now be reachable.
    if [[ -z "$cur" ]]; then
      if watch_reacquire >/dev/null 2>&1; then
        eg_ok "acquired $(active_rung); grok will resume on its own"; fails=0
      fi
      continue
    fi
    [[ "$cur" == direct ]] && continue                # direct has nothing to supervise

    local healthy=1
    rung_alive "$cur" || healthy=0
    # Liveness is not proof of egress: a tun can be up while the far end blackholes. Prove
    # it for real now and then, which costs one HTTP GET and no API tokens.
    if (( healthy == 1 )); then
      cycle=$((cycle + 1))
      # DEEP_EVERY=0 disables the deep check (and avoids a divide-by-zero). A single egress_ip GET
      # can blip on its own, so only a run of empty replies is taken as the far end blackholing.
      if (( DEEP_EVERY > 0 && cycle % DEEP_EVERY == 0 )); then
        local ip="" t
        for t in 1 2 3; do ip="$(egress_ip)"; [[ -n "$ip" ]] && break; done
        if [[ -z "$ip" ]]; then
          eg_warn "$cur is up but has no egress (far end blackholing?)"
          healthy=0
        elif [[ "$cur" == iphone || "$cur" == ios:* ]] && ! rung_confirm "$cur"; then
          # A phone can move between Wi-Fi, cellular, and roaming egress without
          # the Tailscale peer itself going offline. Periodically re-probe the
          # selected model so a live but newly wrong-region phone is not trusted.
          eg_warn "iphone egress is live but no longer serves the pinned/unlocked model"
          healthy=0
        fi
      fi
    fi

    if (( healthy == 1 )); then fails=0; continue; fi

    fails=$((fails + 1))
    # The vpn rung is never repaired in place: reconnecting it with verb "up" would land on the SAME
    # dead server. It demotes instead, and demote takes the NEXT VPN Gate server. But a single-cycle
    # tun blip must not burn an otherwise-good server, so hold vpn for one grace cycle first -- grok
    # fails closed and retries meanwhile, so a blip that clears by the next check costs nothing.
    if [[ "$cur" == vpn ]]; then
      if (( fails < 2 )); then
        eg_warn "vpn down — holding one cycle before switching servers"
        continue
      fi
    elif (( fails <= RUNG_RETRIES )); then
      eg_warn "$cur down — repairing (attempt $fails/$RUNG_RETRIES)"
      if ! begin_recovery_transition; then
        eg_err "cannot publish $cur repair recovery intent"
        continue
      fi
      if ! rung_down "$cur"; then
        if [[ -n "${FORCE_EXACT_ROUTE:-}" && "$cur" == "$FORCE_EXACT_ROUTE" ]]; then
          eg_err "forced route $cur repair teardown was incomplete; retaining exact ownership"
        else
          eg_err "$cur repair teardown was incomplete; retaining ownership"
        fi
        continue
      fi
      # rung_confirm, not rung_alive: a reconnected VPN may have surfaced in a region that no longer
      # serves the pinned model, and "restored" must never mean "up but wrong region".
      if rung_up "$cur" && rung_confirm "$cur" \
         && end_recovery_transition; then
        eg_ok "$cur restored; grok will resume on its own"
        fails=0
      else
        if rung_down "$cur"; then
          if ! clear_active || ! end_recovery_transition; then
            eg_err "$cur failed repair cleanup could not publish empty ownership; recovery remains pending"
          fi
        else
          if [[ -n "${FORCE_EXACT_ROUTE:-}" && "$cur" == "$FORCE_EXACT_ROUTE" ]]; then
            eg_err "forced route $cur failed repair cleanup; retaining exact ownership"
          else
            eg_err "$cur failed repair cleanup; retaining ownership"
          fi
        fi
      fi
      continue
    fi

    if [[ -n "${FORCE_EXACT_ROUTE:-}" && "$cur" == "$FORCE_EXACT_ROUTE" ]]; then
      eg_err "forced route $cur failed — tearing it down; will retry only that route"
      if ! teardown_forced_exact; then
        eg_err "forced-route teardown was incomplete; continuing to fail closed"
      fi
    else
      eg_err "$cur failed — demoting"
      if demote; then
        eg_ok "now on $(active_rung); grok will resume on its own"
      else
        # Nothing serves the model right now. Fail closed: tear everything down so grok's port is not
        # left pointed at a wrong-region exit (it fails closed and retries), and so the state stops
        # falsely naming a rung. The empty-state branch above then re-walks the whole ladder each cycle.
        eg_err "no egress serves the model right now — tearing down; will keep retrying from the top"
        teardown_all
      fi
    fi
    fails=0
  done
}

# ---------------------------------------------------------------- generation-aware provider protocol

provider_validate_rung(){
  case "$1" in
    direct|iphone|vpn) return 0 ;;
    ios:[a-z0-9]*)
      ios_key_valid "${1#ios:}"
      ;;
    home:[A-Za-z0-9._:+@-]*)
      [[ "${1#home:}" =~ ^[A-Za-z0-9._:+@-]{1,120}$ ]]
      ;;
    *) return 1 ;;
  esac
}

provider_internal_rung(){
  case "$1" in
    home:*) printf 'local:%s' "${1#home:}" ;;
    ios:*) ios_key_valid "${1#ios:}" && printf '%s' "$1" ;;
    iphone|vpn|direct) printf '%s' "$1" ;;
    *) return 1 ;;
  esac
}

provider_write_inventory(){
  local public_rung="$1" pid path kind ios_node_id_sha256=""
  pid="$(port_owner_pid)"
  [[ "$pid" =~ ^[0-9]+$ ]] && [[ "$(stat -c %u "/proc/$pid" 2>/dev/null)" == "$(id -u)" ]] \
    || { eg_err "provider listener has no exact current-user owner"; return 1; }
  local -a specs=()
  for path in "$STATE:state" "$CTL:socket" "$SOCKS_PID:pid" \
              "$IPHONE_PID:pid" "$IPHONE_SOCKET:socket" "$IPHONE_LOG:log"; do
    kind="${path##*:}"; path="${path%:*}"
    [[ -e "$path" || -L "$path" ]] && specs+=("$kind=$path")
  done
  if [[ "$public_rung" == ios:* ]]; then
    route_token_valid "${GROK_PROVIDER_IOS_NODE_ID:-}" || return 1
    ios_node_id_sha256="$(printf '%s' "$GROK_PROVIDER_IOS_NODE_ID" | sha256sum | awk '{print $1}')" \
      || return 1
    [[ "$ios_node_id_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  fi
  python3 - "$GROK_PROVIDER_INVENTORY" "$EG_RUNTIME_DIR" \
    "$GROK_PROVIDER_OWNER_EPOCH" "$GROK_PROVIDER_TRANSITION_ID" \
    "$GROK_PROVIDER_GENERATION" "$public_rung" "$pid" \
    "$ios_node_id_sha256" "${specs[@]}" <<'PY'
import json, os, pathlib, stat, sys, tempfile

inventory = pathlib.Path(sys.argv[1])
runtime = pathlib.Path(sys.argv[2])
owner, transition, generation, rung, pid, ios_node_id_sha256 = sys.argv[3:9]
allowed = {"control", "inventory", "log", "pid", "socket", "state"}
paths = []
for spec in sys.argv[9:]:
    kind, separator, raw = spec.partition("=")
    if not separator or kind not in allowed:
        raise SystemExit(1)
    path = pathlib.Path(raw)
    try:
        path.relative_to(runtime)
    except ValueError:
        raise SystemExit(1)
    info = path.lstat()
    if path.is_symlink() or info.st_uid != os.getuid():
        raise SystemExit(1)
    paths.append({"kind": kind, "path": str(path)})
privileged = []
if rung == "vpn":
    privileged = [
        {"kind": "namespace", "name": "grokvpn", "broker_instance": transition},
        {"kind": "tun", "name": "tun-grok", "broker_instance": transition},
        {"kind": "vpn_daemon", "name": "openvpn", "broker_instance": transition},
    ]
record = {
    "generation": int(generation),
    "ios_node_id_sha256": ios_node_id_sha256 or None,
    "owner_epoch": owner,
    "paths": paths,
    "pids": [int(pid)],
    "privileged": privileged,
    "rung": rung,
    "schema_version": 1,
    "transition_id": transition,
}
data = json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"
if len(data) > 65536:
    raise SystemExit(1)
fd, name = tempfile.mkstemp(prefix=".inventory.", dir=runtime)
try:
    os.fchmod(fd, 0o600)
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("short inventory write")
        view = view[count:]
    os.fsync(fd)
    os.close(fd); fd = -1
    os.replace(name, inventory)
    directory = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    if fd >= 0:
        os.close(fd)
    try:
        os.unlink(name)
    except FileNotFoundError:
        pass
PY
}

provider_remove_inventory(){
  if [[ -e "$GROK_PROVIDER_INVENTORY" || -L "$GROK_PROVIDER_INVENTORY" ]]; then
    [[ -f "$GROK_PROVIDER_INVENTORY" && ! -L "$GROK_PROVIDER_INVENTORY" \
       && "$(stat -c %u "$GROK_PROVIDER_INVENTORY" 2>/dev/null)" == "$(id -u)" ]] \
      && rm -f -- "$GROK_PROVIDER_INVENTORY" || return 1
  fi
}

provider_remove_runtime_regular(){
  local path="$1" root resolved
  [[ -e "$path" || -L "$path" ]] || return 0
  root="$(readlink -m -- "$EG_RUNTIME_DIR")" || return 1
  resolved="$(readlink -m -- "$path")" || return 1
  [[ "$resolved" == "$root/"* && -f "$path" && ! -L "$path" \
     && "$(stat -c %u "$path" 2>/dev/null)" == "$(id -u)" ]] || return 1
  rm -f -- "$path"
}

provider_up_command(){
  local public_rung="$1" internal up_rc=0
  provider_validate_context || return 20
  provider_validate_rung "$public_rung" \
    || { eg_err "invalid provider rung"; return 21; }
  provider_validate_frozen_rung "$public_rung" 1 || return 22
  [[ "$public_rung" != direct ]] \
    || { eg_err "direct is owned by the unprivileged Python provider"; return 23; }
  internal="$(provider_internal_rung "$public_rung")" || return 21
  [[ -z "$(port_owner_pid)" ]] \
    || { eg_err "private provider port is already owned"; return 24; }
  clear_active || return 25
  rung_up "$internal" || up_rc=$?
  if (( up_rc != 0 )); then
    rung_down "$internal" >/dev/null 2>&1 || true
    clear_active >/dev/null 2>&1 || true
    case "$public_rung:$up_rc" in
      vpn:31|vpn:32|vpn:33|vpn:34) return "$up_rc" ;;
    esac
    return 26
  fi
  if ! rung_alive "$internal"; then
    rung_down "$internal" >/dev/null 2>&1 || true
    clear_active >/dev/null 2>&1 || true
    return 27
  fi
  if ! provider_write_inventory "$public_rung"; then
    rung_down "$internal" >/dev/null 2>&1 || true
    clear_active >/dev/null 2>&1 || true
    return 28
  fi
}

provider_next_command(){
  local public_rung="$1" before after rc=0
  provider_validate_context || return 1
  [[ "$public_rung" == vpn ]] \
    || { eg_err "provider-next is supported only for vpn"; return 1; }
  provider_validate_frozen_rung "$public_rung" 1 || return 1
  [[ -f "$GROK_PROVIDER_INVENTORY" && ! -L "$GROK_PROVIDER_INVENTORY" ]] \
    || { eg_err "provider-next requires an owned inventory"; return 1; }
  before="$(vpn_broker_call status)" \
    || { eg_err "cannot read the current broker generation"; return 1; }
  if ! vpn_up next; then
    vpn_down >/dev/null 2>&1 || true
    clear_active >/dev/null 2>&1 || true
    provider_remove_inventory >/dev/null 2>&1 || true
    return 1
  fi
  after="$(vpn_broker_call status)" || rc=1
  if (( rc == 0 )); then
    printf '%s\n%s\n' "$before" "$after" | python3 -c '
import json, sys
release, owner, generation, port, digest, max_tries, ranking, countries, blocked = sys.argv[1:]
records = [json.loads(line) for line in sys.stdin if line.strip()]
if len(records) != 2:
    raise SystemExit(1)
before, after = records
expected_owner = {
    "release_id": release,
    "owner_epoch": owner,
    "generation": int(generation),
    "listen_port": int(port),
    "contract_digest": digest,
}
expected_policy = {
    "max_tries": int(max_tries),
    "ranking_version": ranking,
    "countries": countries.split() if countries else [],
    "blocked_countries": blocked.split() if blocked else [],
    "prefer_countries": countries.split() if countries else [],
}
for status in records:
    if not all(status.get(name) is True for name in (
        "active", "namespace_alive", "tun_alive", "vpn_alive", "relay_alive"
    )):
        raise SystemExit(1)
    ledger = status.get("ledger")
    if type(ledger) is not dict or ledger.get("phase") != "ACTIVE":
        raise SystemExit(1)
    if any(ledger.get(name) != value for name, value in expected_owner.items()):
        raise SystemExit(1)
    if ledger.get("vpn_policy") != expected_policy:
        raise SystemExit(1)
if before["ledger"].get("relay") != after["ledger"].get("relay"):
    raise SystemExit(1)
if before.get("relay_pid") != after.get("relay_pid"):
    raise SystemExit(1)
if before["ledger"].get("vpn") == after["ledger"].get("vpn"):
    raise SystemExit(1)
' "$GROK_ACTIVE_RELEASE_ID" "$GROK_PROVIDER_OWNER_EPOCH" \
      "$GROK_PROVIDER_GENERATION" "$PORT" "$GROK_PROVIDER_CONTRACT_DIGEST" \
      "$GROK_PROVIDER_VPN_MAX_TRIES" "$GROK_PROVIDER_VPN_RANKING_VERSION" \
      "$GROK_PROVIDER_VPN_COUNTRIES" "${GROK_PROVIDER_VPN_BLOCKED_COUNTRIES:-}" || rc=1
  fi
  (( rc == 0 )) && provider_write_inventory "$public_rung" || rc=1
  if (( rc != 0 )); then
    vpn_down >/dev/null 2>&1 || true
    clear_active >/dev/null 2>&1 || true
    provider_remove_inventory >/dev/null 2>&1 || true
  fi
  return "$rc"
}

provider_stop_command(){
  local public_rung="$1" internal rc=0
  provider_validate_context || return 1
  provider_validate_rung "$public_rung" || return 1
  provider_validate_frozen_rung "$public_rung" 0 || return 1
  [[ "$public_rung" != direct ]] || return 1
  internal="$(provider_internal_rung "$public_rung")" || return 1
  rung_down "$internal" || rc=1
  clear_active || rc=1
  if [[ "$public_rung" == iphone || "$public_rung" == ios:* ]]; then
    provider_remove_runtime_regular "$IPHONE_LOG" || rc=1
  fi
  provider_remove_inventory || rc=1
  if [[ -e "$EG_RUNTIME_DIR" || -L "$EG_RUNTIME_DIR" ]]; then
    [[ -d "$EG_RUNTIME_DIR" && ! -L "$EG_RUNTIME_DIR" ]] \
      && rmdir -- "$EG_RUNTIME_DIR" 2>/dev/null || true
  fi
  return "$rc"
}

provider_recover_command(){
  local public_rung="$1" internal pid="" rc=0
  provider_validate_context 1 || return 1
  provider_validate_rung "$public_rung" || return 1
  provider_validate_frozen_rung "$public_rung" 0 || return 1
  internal="$(provider_internal_rung "$public_rung")" || return 1
  case "$public_rung" in
    home:*)
      local_down || rc=1
      ;;
    iphone|ios:*)
      pid="$(pid_from_file "$IPHONE_PID")" || true
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null \
         && ! iphone_process_alive "$pid"; then
        eg_err "refusing to recover iPhone PID with mismatched argv/runtime"
        return 1
      fi
      iphone_down || rc=1
      provider_remove_runtime_regular "$IPHONE_LOG" || rc=1
      ;;
    vpn)
      # `recover` reconstructs and releases exact root ledger identities.  It
      # deliberately does not use `down`, which rejects partial ledgers.
      vpn_broker_call recover >/dev/null || rc=1
      ;;
    *) return 1 ;;
  esac
  (( rc == 0 )) || return "$rc"
  clear_active || rc=1
  provider_remove_inventory || rc=1
  if [[ -e "$EG_RUNTIME_DIR" || -L "$EG_RUNTIME_DIR" ]]; then
    [[ -d "$EG_RUNTIME_DIR" && ! -L "$EG_RUNTIME_DIR" ]] \
      && rmdir -- "$EG_RUNTIME_DIR" 2>/dev/null || rc=1
  fi
  return "$rc"
}

provider_prove_empty_command(){
  local public_rung="$1" status
  provider_validate_context 1 || return 1
  provider_validate_rung "$public_rung" || return 1
  provider_validate_frozen_rung "$public_rung" 0 || return 1
  [[ -z "$(port_owner_pid)" ]] || return 1
  [[ ! -e "$CTL" && ! -L "$CTL" && ! -e "$SOCKS_PID" && ! -L "$SOCKS_PID" \
     && ! -e "$IPHONE_PID" && ! -L "$IPHONE_PID" \
     && ! -e "$IPHONE_SOCKET" && ! -L "$IPHONE_SOCKET" ]] || return 1
  if [[ "$public_rung" == vpn ]]; then
    status="$(vpn_broker_call status 2>/dev/null)" || return 1
    python3 -c 'import json,sys; v=json.load(sys.stdin); flags=("active","namespace_alive","tun_alive","host_tun_alive","vpn_alive","relay_alive","root_artifact_residue"); fields={"ok",*flags,"relay_pid","ledger"}; valid=type(v) is dict and set(v)==fields and v.get("ok") is True and all(type(v.get(name)) is bool for name in flags); residue=(not valid) or any(v.get(name) is True for name in flags) or v.get("ledger") is not None or v.get("relay_pid") is not None; raise SystemExit(1 if residue else 0)' \
      <<<"$status" || return 1
  fi
  [[ ! -e "$EG_RUNTIME_DIR" && ! -L "$EG_RUNTIME_DIR" ]]
}

compatibility_handoff_validate(){
  (( HANDOFF_MODE == 1 && PROVIDER_MODE == 0 )) || return 1
  [[ "${GROK_HANDOFF_OWNER_EPOCH:-}" =~ ^[A-Za-z0-9._:+@-]{1,128}$ ]] \
    || { eg_err "invalid compatibility-handoff owner"; return 1; }
  [[ "${GROK_HANDOFF_RELEASE_ID:-}" =~ ^[0-9a-f]{64}$ ]] \
    || { eg_err "invalid compatibility-handoff release"; return 1; }
  [[ "$(fence_owner_epoch 2>/dev/null)" == "$GROK_HANDOFF_OWNER_EPOCH" ]] \
    || { eg_err "compatibility-handoff does not own the recovery fence"; return 1; }
  [[ "$(release_identity 2>/dev/null)" == "$GROK_HANDOFF_RELEASE_ID" ]] \
    || { eg_err "compatibility-handoff release mismatch"; return 1; }
  [[ "$PORT" == 1080 ]] \
    || { eg_err "compatibility-handoff supports only the stable public port 1080"; return 1; }
}

LEGACY_LOCK_PID=""
LEGACY_LOCK_READ=""
LEGACY_LOCK_WRITE=""

release_legacy_session_lock(){
  if [[ -n "${LEGACY_LOCK_WRITE:-}" ]]; then
    printf 'STOP\n' >&"$LEGACY_LOCK_WRITE" 2>/dev/null || true
    exec {LEGACY_LOCK_WRITE}>&-
  fi
  if [[ -n "${LEGACY_LOCK_READ:-}" ]]; then
    exec {LEGACY_LOCK_READ}<&-
  fi
  if [[ -n "${LEGACY_LOCK_PID:-}" ]]; then
    wait "$LEGACY_LOCK_PID" 2>/dev/null || true
  fi
  LEGACY_LOCK_PID=""
  LEGACY_LOCK_READ=""
  LEGACY_LOCK_WRITE=""
}

acquire_legacy_session_lock(){
  local ready=""
  [[ -z "${LEGACY_LOCK_PID:-}" ]] || return 1
  coproc GROK_LEGACY_LOCK {
    exec python3 /dev/fd/3 "$PRIVATE_DIR" 3<<'PY'
import ctypes
import fcntl
import os
from pathlib import Path
import signal
import stat
import sys

parent_pid = os.getppid()
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
    raise OSError(ctypes.get_errno(), "cannot set parent-death signal")
if os.getppid() != parent_pid:
    raise RuntimeError("handoff parent exited during lock setup")

parent_path = Path(sys.argv[1])
directory_flags = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    | getattr(os, "O_NOFOLLOW", 0)
)
file_flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
allowed_modes = {0o600, 0o640, 0o644, 0o660, 0o664}
parent_fd = os.open(parent_path, directory_flags)
lock_fd = -1
try:
    parent_info = os.fstat(parent_fd)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or stat.S_IMODE(parent_info.st_mode) & 0o002
    ):
        raise RuntimeError("unsafe legacy lock parent")
    created = False
    try:
        lock_fd = os.open(".grok-remote.lock", file_flags, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            lock_fd = os.open(
                ".grok-remote.lock",
                file_flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            created = True
        except FileExistsError:
            lock_fd = os.open(".grok-remote.lock", file_flags, dir_fd=parent_fd)
    info = os.fstat(lock_fd)
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or mode not in allowed_modes
        or mode & 0o113
        or info.st_size != 0
        or info.st_nlink != 1
        or info.st_dev != parent_info.st_dev
    ):
        raise RuntimeError("unsafe legacy singleton lock")
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    named = os.stat(
        ".grok-remote.lock", dir_fd=parent_fd, follow_symlinks=False
    )
    if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
        raise RuntimeError("legacy singleton lock identity changed")
    os.fchmod(lock_fd, 0o600)
    os.fsync(lock_fd)
    if created:
        os.fsync(parent_fd)
    print("READY", flush=True)
    for command in sys.stdin:
        command = command.rstrip("\n")
        if command == "STOP":
            break
        if command != "CHECK":
            raise RuntimeError("invalid legacy lock-holder command")
        current = os.fstat(lock_fd)
        named = os.stat(
            ".grok-remote.lock", dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.getuid()
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_size != 0
            or (named.st_dev, named.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise RuntimeError("legacy singleton lock changed while held")
        print("HELD", flush=True)
finally:
    if lock_fd >= 0:
        os.close(lock_fd)
    os.close(parent_fd)
PY
  }
  LEGACY_LOCK_PID="$GROK_LEGACY_LOCK_PID"
  LEGACY_LOCK_READ="${GROK_LEGACY_LOCK[0]}"
  LEGACY_LOCK_WRITE="${GROK_LEGACY_LOCK[1]}"
  if ! IFS= read -r -t 5 -u "$LEGACY_LOCK_READ" ready || [[ "$ready" != READY ]]; then
    eg_err "cannot safely acquire the legacy grok-remote singleton lock"
    release_legacy_session_lock
    return 1
  fi
  legacy_session_lock_check
}

legacy_session_lock_check(){
  local reply=""
  [[ -n "${LEGACY_LOCK_PID:-}" && -n "${LEGACY_LOCK_READ:-}" \
     && -n "${LEGACY_LOCK_WRITE:-}" ]] || return 1
  kill -0 "$LEGACY_LOCK_PID" 2>/dev/null || return 1
  printf 'CHECK\n' >&"$LEGACY_LOCK_WRITE" 2>/dev/null || return 1
  IFS= read -r -t 5 -u "$LEGACY_LOCK_READ" reply || return 1
  [[ "$reply" == HELD ]]
}

compatibility_handoff_locked(){
  local rung="" pid=""
  legacy_session_lock_check || return 1
  # Public handoff remains nonmutating at the root boundary.  An orphaned
  # generation-zero ledger must first be retired by the signed bootstrap
  # package; this call proves that root cleanup has already committed.
  vpn_broker_call migrate-legacy >/dev/null || return 1
  legacy_session_lock_check || return 1
  if recovery_transition_pending; then
    recovery_marker_valid \
      || { eg_err "unsafe legacy recovery marker"; return 1; }
    eg_warn "completing pending compatibility recovery before handoff"
    legacy_session_lock_check && teardown_all \
      && legacy_session_lock_check || return 1
  fi
  if [[ -e "$STATE" || -L "$STATE" ]]; then
    [[ -f "$STATE" && ! -L "$STATE" \
       && "$(stat -c %u "$STATE" 2>/dev/null)" == "$(id -u)" ]] \
      || { eg_err "unsafe legacy egress state"; return 1; }
    rung="$(active_rung)" \
      || { eg_err "malformed legacy egress state"; return 1; }
  fi
  case "$rung" in
    local:*) legacy_session_lock_check && local_down \
               && legacy_session_lock_check || return 1 ;;
    iphone|ios:*|vpn|direct|"") ;;
    *) return 1 ;;
  esac
  if [[ "$rung" != local:* && ( -e "$CTL" || -L "$CTL" ) ]]; then
    eg_err "legacy SSH control socket is not owned by the recorded rung"
    return 1
  fi
  if [[ -L "$IPHONE_PID" || -L "$IPHONE_PID_IDENTITY" || -L "$IPHONE_SOCKET" ]]; then
    eg_err "unsafe legacy iPhone runtime link"
    return 1
  fi
  pid="$(pid_from_file "$IPHONE_PID")" || true
  if [[ -n "$pid" && ! -e "$IPHONE_PID_IDENTITY" ]]; then
    iphone_process_identity adopt "$pid" \
      || { eg_err "legacy iPhone PID cannot be adopted exactly"; return 1; }
  fi
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null \
     && ! iphone_process_alive "$pid"; then
    eg_err "legacy iPhone PID does not match its exact argv/runtime"
    return 1
  elif [[ -n "$pid" || -e "$IPHONE_PID_IDENTITY" || -e "$IPHONE_SOCKET" ]]; then
    legacy_session_lock_check && iphone_down \
      && legacy_session_lock_check || return 1
  fi
  # Repeat the authenticated migration after user-side teardown.  This closes
  # a legacy-launch/recreation window before the final status proof.
  legacy_session_lock_check || return 1
  vpn_broker_call migrate-legacy >/dev/null || return 1
  legacy_session_lock_check || return 1
  vpn_root_empty || return 1
  clear_active || return 1
  legacy_session_lock_check || return 1
  [[ ! -e "$CTL" && ! -L "$CTL" \
     && ! -e "$IPHONE_PID" && ! -L "$IPHONE_PID" \
     && ! -e "$IPHONE_PID_IDENTITY" && ! -L "$IPHONE_PID_IDENTITY" \
     && ! -e "$IPHONE_SOCKET" && ! -L "$IPHONE_SOCKET" \
     && ! -e "$SOCKS_PID" && ! -L "$SOCKS_PID" ]] || return 1
  [[ -z "$(port_owner_pid)" ]] || return 1
  ! port_listening || return 1
  ! recovery_transition_pending
}

compatibility_handoff_command(){
  local rc
  compatibility_handoff_validate || return 1
  acquire_legacy_session_lock || return 1
  compatibility_handoff_locked
  rc=$?
  release_legacy_session_lock
  return "$rc"
}

# ---------------------------------------------------------------- standalone CLI

standalone_mutation_lock(){
  acquire_stable_mutation_lock
}

standalone_select_command(){
  standalone_mutation_lock || return 1
  if ensure_selected_egress; then
    eg_ok "active: $(active_rung)  egress IP: $(egress_ip "$( [[ $(active_rung) == direct ]] && echo '' || echo "$PROXY" )")"
    return 0
  fi
  eg_err "no usable egress"
  return 1
}

standalone_stop_command(){
  standalone_mutation_lock || return 1
  stop_egress
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-status}" in
    provider-up) [[ $# == 2 ]] || exit 2
            provider_up_command "$2" ;;
    provider-next) [[ $# == 2 ]] || exit 2
            provider_next_command "$2" ;;
    provider-recover) [[ $# == 2 ]] || exit 2
            provider_recover_command "$2" ;;
    provider-stop) [[ $# == 2 ]] || exit 2
            provider_stop_command "$2" ;;
    provider-prove-empty) [[ $# == 2 ]] || exit 2
            provider_prove_empty_command "$2" ;;
    compatibility-handoff) [[ $# == 1 ]] || exit 2
            compatibility_handoff_command ;;
    select) standalone_select_command ;;
    watch)  standalone_mutation_lock || exit 1; watch_egress ;;
    status) r="$(active_rung)"; [[ -z "$r" ]] && { eg_log "no egress selected"; exit 0; }
            rung_alive "$r" && eg_ok "active: $r (alive)" || eg_warn "active: $r (DOWN)" ;;
    ip)     egress_ip; echo ;;
    stop)   standalone_stop_command ;;
    *)      echo "usage: $0 {select|watch|status|ip|stop|compatibility-handoff|provider-up RUNG|provider-next vpn|provider-recover RUNG|provider-stop RUNG|provider-prove-empty RUNG}" >&2; exit 1 ;;
  esac
fi
