#!/usr/bin/env bash
# egress.sh — pick an egress for grok and hold it up, in preference order:
#
#   direct        no proxy at all
#   local:<label> ssh -D SOCKS through a home PC over Tailscale (hosts.conf order)
#   iphone        a dedicated userspace Tailscale client using the iPhone as exit node
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
CONF="$EG_DIR/hosts.conf"
KEY="$EG_DIR/id_grokproxy"
CTL="$EG_DIR/.tunnel.ctl"
STATE="$EG_DIR/.egress.state"
SESSION_LOCK="${GROK_SESSION_LOCK:-$EG_DIR/.grok-remote.lock}"
VPNGATE="${GROK_VPNGATE:-$EG_DIR/vpngate-connect.sh}"
SOCKS_NETNS="$EG_DIR/socks-netns.py"
SOCKS_PID="$EG_DIR/.socks-netns.pid"
# Empty namespace = serve from the current one. Only the test harness does that; in normal
# use the VPN rung must egress from inside 'grokvpn', which is what keeps it fail-closed.
NS="${GROK_VPN_NETNS-grokvpn}"

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
IPHONE_STATE="$IPHONE_STATE_DIR/tailscaled.state"
IPHONE_SOCKET="$IPHONE_STATE_DIR/tailscaled.sock"
IPHONE_PID="$IPHONE_STATE_DIR/tailscaled.pid"
IPHONE_LOG="$IPHONE_STATE_DIR/tailscaled.log"
IPHONE_NODE_FILE="$IPHONE_STATE_DIR/exit-node"
IPHONE_READY_FILE="$IPHONE_STATE_DIR/ready"
IPHONE_HOSTNAME="${GROK_IPHONE_HOSTNAME:-grok-iphone-relay}"
IPHONE_AUTHKEY_FILE="${GROK_IPHONE_AUTHKEY_FILE:-}"

# Clear protocol-specific proxy variables before setting the one intended route.
# curl prefers HTTPS_PROXY over ALL_PROXY, so inheriting a caller's environment
# could otherwise make probes measure a different path than Grok uses.
CLEAN_PROXY_ENV=(env
  -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY -u FTP_PROXY
  -u http_proxy -u https_proxy -u all_proxy -u no_proxy -u ftp_proxy)

BASELINE="$EG_DIR/.baseline.models"               # what the VM is offered with no tunnel at all
BASELINE_TTL="${GROK_BASELINE_TTL:-21600}"        # re-measure the baseline once it is older than this (s)
UNLOCKED="$EG_DIR/.unlocked.models"               # what the active rung added on top of that
# Optional pin. Left unset (the default), a rung is accepted when it unlocks any model the direct
# egress cannot see -- see learn_baseline() for why that beats naming a model.
REQUIRE_MODEL="${GROK_REQUIRE_MODEL:-}"
RUNG_RETRIES="${GROK_RUNG_RETRIES:-2}"            # repairs of the same rung before demoting
WATCH_INTERVAL="${GROK_WATCH_INTERVAL:-10}"       # seconds between liveness checks
DEEP_EVERY="${GROK_DEEP_EVERY:-6}"                # every Nth check, prove real egress
VPN_MAX_TRIES="${GROK_VPN_MAX_TRIES:-6}"          # VPN Gate servers to walk before giving up
ALLOW_DIRECT="${GROK_ALLOW_DIRECT:-1}"

# EU (AI Act) + the countries where X itself is banned: grok-4.5 is not served from any of
# them, so an exit there is useless no matter how healthy the tunnel is.
GROK_BLOCKED_CC="${GROK_BLOCKED_CC-AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE CN IR KP TM VE}"

c_cyan=$'\033[36m'; c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_rst=$'\033[0m'
eg_log(){  printf '%s[egress]%s %s\n' "$c_cyan" "$c_rst" "$*" >&2; }
eg_ok(){   printf '%s[egress]%s %s\n' "$c_grn"  "$c_rst" "$*" >&2; }
eg_warn(){ printf '%s[egress]%s %s\n' "$c_yel"  "$c_rst" "$*" >&2; }
eg_err(){  printf '%s[egress]%s %s\n' "$c_red"  "$c_rst" "$*" >&2; }

# An empty namespace serves the VPN rung from the host namespace, which disables the fail-closed
# kill switch. Only the test harness wants that, and only when it opts in explicitly.
if [[ -z "$NS" && "${GROK_ALLOW_HOSTNS_EGRESS:-0}" != 1 ]]; then
  eg_err "GROK_VPN_NETNS is empty — that serves the VPN rung from the host namespace and disables the kill switch; set GROK_ALLOW_HOSTNS_EGRESS=1 to allow it"
  exit 1
fi

# Reject junk in the watchdog tunables so a bad value cannot kill the watchdog or divide by zero.
[[ "$WATCH_INTERVAL" =~ ^[1-9][0-9]*$ ]] || { eg_warn "GROK_WATCH_INTERVAL='$WATCH_INTERVAL' is not a positive integer — using 10"; WATCH_INTERVAL=10; }
[[ "$DEEP_EVERY" =~ ^(0|[1-9][0-9]*)$ ]] || { eg_warn "GROK_DEEP_EVERY='$DEEP_EVERY' is not a non-negative integer — using 6"; DEEP_EVERY=6; }

# ---------------------------------------------------------------- state

set_active(){
  case "$1" in direct|iphone|vpn|local:?*) ;; *) return 1 ;; esac
  [[ "$1" != *[$' \t\r\n']* ]] || return 1
  [[ "${2:-}" != *[$' \t\r\n']* && "${3:-22}" =~ ^[0-9]+$ ]] || return 1
  # Atomic: write a temp file in the state dir, then rename onto $STATE. A reader always sees a
  # complete fixed-format record, never a half-written one or executable shell input.
  local tmp; tmp="$(mktemp "$STATE.XXXXXX")" || return 1
  if printf 'RUNG=%s\nDEST=%s\nSPORT=%s\n' "$1" "${2:-}" "${3:-22}" > "$tmp"; then
    mv -f "$tmp" "$STATE"
  else
    rm -f "$tmp"; return 1
  fi
}
state_value(){
  [[ -f "$STATE" ]] || return 1
  sed -n "s/^$1=//p" "$STATE" 2>/dev/null | head -1
}
active_rung(){
  local value; value="$(state_value RUNG)" || return 1
  case "$value" in direct|iphone|vpn|local:?*) ;; *) return 1 ;; esac
  [[ "$value" != *[$' \t\r\n']* ]] || return 1
  printf '%s' "$value"
}
active_dest(){
  local value; value="$(state_value DEST)" || return 1
  [[ "$value" != *[$' \t\r\n']* ]] || return 1
  printf '%s' "$value"
}
clear_active(){ rm -f "$STATE"; }

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
  local proxy="$1" url="$2"
  if [[ -n "$proxy" ]]; then
    "${CLEAN_PROXY_ENV[@]}" ALL_PROXY="$proxy" NO_PROXY="$NOPROXY" no_proxy="$NOPROXY" \
      curl -s --max-time 20 "$url" 2>/dev/null
  else
    "${CLEAN_PROXY_ENV[@]}" curl -s --max-time 15 "$url" 2>/dev/null
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
  trace="$(eg_curl "$proxy" https://1.1.1.1/cdn-cgi/trace)"
  ip="$(sed -n 's/^ip=//p' <<<"$trace" | head -1)"
  [[ -n "$ip" ]] || ip="$(eg_curl "$proxy" https://api.ipify.org)"
  printf '%s' "$ip"
}
egress_country(){
  local proxy="${1-$PROXY}" trace cc
  trace="$(eg_curl "$proxy" https://1.1.1.1/cdn-cgi/trace)"
  cc="$(sed -n 's/^loc=//p' <<<"$trace" | head -1 | tr -d '[:space:]')"
  [[ -n "$cc" ]] || cc="$(eg_curl "$proxy" https://ipinfo.io/country | tr -d '[:space:]')"
  printf '%s' "$cc"
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
  local proxy="${1-$PROXY}" out
  if [[ -n "${GROK_MODELS_CMD:-}" ]]; then
    GROK_PROBE_RUNG="${2:-}" bash -c "$GROK_MODELS_CMD" | sort -u; return
  fi
  rm -f "$GROK_MODELS_CACHE"   # force a fresh fetch through THIS egress, not grok's cached list
  if [[ -n "$proxy" ]]; then
    out="$("${CLEAN_PROXY_ENV[@]}" ALL_PROXY="$proxy" NO_PROXY="$NOPROXY" no_proxy="$NOPROXY" \
      timeout 90 "$GROK_BIN" models 2>/dev/null)"
  else
    out="$("${CLEAN_PROXY_ENV[@]}" timeout 90 "$GROK_BIN" models 2>/dev/null)"
  fi
  grep -oE '^[[:space:]]+[-*][[:space:]]+[^[:space:]]+' <<<"$out" | awk '{print $2}' | sort -u
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
    eg_warn "  $rung: exits in $cc — the EU / X-banned block never serves the gated models"; return 1
  fi
  if [[ -n "$cc" ]]; then eg_log "  $rung: exits in $cc — asking grok what that unlocks"
  else eg_log "  $rung: egress country unknown — asking grok what it unlocks anyway"; fi
  rung_unlocks "$rung" "$proxy"
}

# ---------------------------------------------------------------- rung: local PC

local_hosts(){ awk '!/^#/ && NF>=3 && $3 !~ /^CHANGE_ME/ {print $1"\t"$2"\t"$3"\t"(NF>=4?$4:22)}' "$CONF"; }

local_up(){
  local want="$1" label ip user sport
  # L3: pin the home PC's host key. If a repo-local known_hosts exists (populated once from the
  # key the setup script prints), enforce it strictly; otherwise pin-on-first-use into that same
  # repo-local file — never the user's global known_hosts — so a fresh install still connects.
  local khost="$EG_DIR/known_hosts" skc="accept-new"
  [[ -s "$khost" ]] && skc="yes"
  while IFS=$'\t' read -r label ip user sport; do
    [[ "$label" == "$want" ]] || continue
    if ! tcp_ok "$ip" "$sport"; then eg_warn "  $label ($ip:$sport) not reachable over Tailscale"; return 1; fi
    rm -f "$CTL"
    # ControlPersist=yes, not a timeout: with a timeout the master self-terminates once no
    # SOCKS connection has been open for that long, which kills a perfectly healthy tunnel
    # while you sit reading grok's last answer. ServerAlive 5x3 notices a dead link in ~15s.
    ssh -M -S "$CTL" -fnN \
        -o ControlPersist=yes \
        -o ExitOnForwardFailure=yes \
        -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
        -o StrictHostKeyChecking="$skc" \
        -o UserKnownHostsFile="$khost" \
        -o ConnectTimeout=8 -o BatchMode=yes \
        -i "$KEY" -p "$sport" -D "127.0.0.1:$PORT" "$user@$ip" 9>&- || return 1
    set_active "local:$label" "$user@$ip" "$sport"
    return 0
  done < <(local_hosts)
  return 1
}

local_alive(){
  local dest; dest="$(active_dest)"
  [[ -S "$CTL" && -n "$dest" ]] && ssh -S "$CTL" -O check -o BatchMode=yes "$dest" >/dev/null 2>&1
}

local_down(){
  local dest; dest="$(active_dest)"
  [[ -S "$CTL" && -n "$dest" ]] && ssh -S "$CTL" -O exit -o BatchMode=yes "$dest" >/dev/null 2>&1
  rm -f "$CTL"
}

# ---------------------------------------------------------------- rung: iPhone Tailscale exit node

iphone_prepare_state(){
  ( umask 077; mkdir -p "$IPHONE_STATE_DIR" ) || return 1
  chmod 700 "$IPHONE_STATE_DIR"
}

iphone_node(){
  if [[ -s "$IPHONE_NODE_FILE" ]]; then
    head -1 "$IPHONE_NODE_FILE"
  elif [[ -n "${GROK_IPHONE_EXIT_NODE:-}" ]]; then
    printf '%s' "$GROK_IPHONE_EXIT_NODE"
  fi
}

iphone_configured(){
  [[ -s "$IPHONE_NODE_FILE" && -s "$IPHONE_READY_FILE" ]] || return 1
  [[ "$(head -1 "$IPHONE_NODE_FILE")" == "$(head -1 "$IPHONE_READY_FILE")" ]]
}
iphone_cli(){ "$TAILSCALE_BIN" --socket="$IPHONE_SOCKET" "$@"; }

iphone_process_alive(){
  local pid="${1:-}"
  [[ -n "$pid" ]] || pid="$(pid_from_file "$IPHONE_PID")" || return 1
  kill -0 "$pid" 2>/dev/null \
    && pid_has_arg "$pid" "$TAILSCALED_BIN" \
    && pid_has_arg "$pid" "--tun=userspace-networking" \
    && pid_has_arg "$pid" "--socket=$IPHONE_SOCKET" \
    && pid_has_arg "$pid" "--state=$IPHONE_STATE" \
    && pid_has_arg "$pid" "--socks5-server=127.0.0.1:$PORT"
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
  local pin="$1"
  iphone_status_json | jq -r --arg p "$pin" '
    def norm: ascii_downcase | rtrimstr(".");
    [ (.Peer // {}) | .[]
      | select( .ID == $p
                or ((.HostName // "") | norm) == ($p | norm)
                or ((.DNSName // "") | norm) == ($p | norm)
                or ((.DNSName // "") | norm | split(".")[0]) == ($p | norm)
                or any(.TailscaleIPs[]?; split("/")[0] == $p) )
      | .TailscaleIPs[]? | split("/")[0] ]
    | .[0] // empty' 2>/dev/null
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
  local pid=""
  pid="$(pid_from_file "$IPHONE_PID")" || true
  if [[ -n "$pid" ]] && iphone_process_alive "$pid"; then
    kill "$pid" 2>/dev/null || true
    local i
    for i in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
  fi
  rm -f "$IPHONE_PID" "$IPHONE_SOCKET"
}

iphone_start(){
  [[ -n "$TAILSCALE_BIN" && -x "$TAILSCALE_BIN" ]] \
    || { eg_warn "  tailscale CLI is not installed"; return 1; }
  [[ -n "$TAILSCALED_BIN" && -x "$TAILSCALED_BIN" ]] \
    || { eg_warn "  tailscaled is not installed"; return 1; }
  command -v jq >/dev/null 2>&1 || { eg_warn "  jq is required for the iPhone rung"; return 1; }
  iphone_prepare_state || return 1
  if iphone_listener_alive && [[ -S "$IPHONE_SOCKET" ]]; then return 0; fi
  iphone_down
  ( umask 077; : > "$IPHONE_LOG" ) || return 1
  (
    umask 077
    exec 9>&-
    exec "$TAILSCALED_BIN" \
      --tun=userspace-networking \
      --port=0 \
      --state="$IPHONE_STATE" \
      --statedir="$IPHONE_STATE_DIR" \
      --socket="$IPHONE_SOCKET" \
      --socks5-server="127.0.0.1:$PORT"
  ) >>"$IPHONE_LOG" 2>&1 &
  local pid=$!
  ( umask 077; printf '%s\n' "$pid" > "$IPHONE_PID" )
  chmod 600 "$IPHONE_PID" "$IPHONE_LOG" 2>/dev/null || true
  local i
  for i in $(seq 1 40); do
    if [[ -S "$IPHONE_SOCKET" ]] && iphone_listener_alive; then return 0; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.25
  done
  eg_warn "  iPhone Tailscale sidecar did not acquire 127.0.0.1:$PORT"
  tail -n 4 "$IPHONE_LOG" 2>/dev/null | sed 's/^/[tailscaled] /' >&2
  iphone_down
  return 1
}

iphone_select_exit(){
  local node ip="" i; node="$(iphone_node)"
  [[ -n "$node" ]] || { eg_warn "  no iPhone exit node configured — run: grok-remote iphone-setup"; return 1; }
  # The pin is usually a StableNodeID, which `set --exit-node` rejects ("must be IP or hostname"). Resolve
  # it to the peer's Tailscale IP, retrying briefly so a just-started sidecar can sync the netmap first.
  for i in $(seq 1 20); do ip="$(iphone_exit_ip_for "$node")"; [[ -n "$ip" ]] && break; sleep 0.25; done
  [[ -n "$ip" ]] || { eg_warn "  iPhone exit node '$node' is not in the sidecar tailnet (offline, unapproved, or not yet synced)"; return 1; }
  iphone_cli set --exit-node="$ip" --exit-node-allow-lan-access=false --shields-up=true >/dev/null \
    || { eg_warn "  cannot select iPhone exit node '$node' -> $ip (offline, unapproved, or ACL denied)"; return 1; }
  for i in $(seq 1 20); do iphone_exit_online && return 0; sleep 0.25; done
  eg_warn "  iPhone exit node '$node' is selected but not online"
  return 1
}

iphone_up(){
  iphone_configured || return 1
  iphone_start || return 1
  # Let the just-started backend settle before judging it: an already-enrolled sidecar is briefly in
  # "Starting" and reading it too early wrongly reports "not authenticated".
  if [[ "$(iphone_wait_backend)" != Running ]]; then
    eg_warn "  iPhone sidecar is not authenticated — run: grok-remote iphone-setup"
    iphone_down
    return 1
  fi
  iphone_select_exit || { iphone_down; return 1; }
  set_active iphone "$(iphone_node)"
}

iphone_alive(){ iphone_listener_alive && iphone_exit_online; }

iphone_detect_node(){
  [[ -n "$PRIMARY_TAILSCALE_BIN" && -x "$PRIMARY_TAILSCALE_BIN" ]] || return 1
  local -a nodes=()
  mapfile -t nodes < <("$PRIMARY_TAILSCALE_BIN" status --json 2>/dev/null | jq -r \
    '.Peer[] | select((.OS // "" | ascii_downcase) == "ios") | .TailscaleIPs[0] // empty')
  if (( ${#nodes[@]} != 1 )); then
    eg_err "expected exactly one iOS peer in the primary tailnet; found ${#nodes[@]} — pass its IP or name explicitly"
    return 1
  fi
  printf '%s' "${nodes[0]}"
}

iphone_save_node(){
  local node="$1" tmp old=""
  iphone_prepare_state || return 1
  old="$(head -1 "$IPHONE_NODE_FILE" 2>/dev/null || true)"
  tmp="$(mktemp "$IPHONE_NODE_FILE.XXXXXX")" || return 1
  printf '%s\n' "$node" > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$IPHONE_NODE_FILE"
  [[ -z "$old" || "$old" == "$node" ]] || rm -f "$IPHONE_READY_FILE"
}

# One-time enrollment of the sidecar identity. Authentication is interactive by
# default; automation accepts only an auth-key FILE so the secret never appears in
# argv or shell history. This never changes the primary Tailscale daemon.
iphone_setup(){
  local node="${1:-}" rc=0
  [[ -n "$node" ]] || node="$(iphone_node)"
  [[ -n "$node" ]] || node="$(iphone_detect_node)" || return 1
  [[ "$node" != *[$' \t\r\n']* ]] || { eg_err "iPhone exit-node IP/name cannot contain whitespace"; return 1; }
  port_listening && { eg_err "port $PORT is in use — run 'grok-remote stop' before iphone-setup"; return 1; }
  iphone_save_node "$node" || return 1
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
        || { eg_err "GROK_IPHONE_AUTHKEY_FILE must be a readable regular file"; iphone_down; return 1; }
      key_mode="$(stat -c '%a' "$IPHONE_AUTHKEY_FILE" 2>/dev/null || true)"
      if [[ ! "$key_mode" =~ ^[0-7]{3,4}$ ]] || (( (8#$key_mode & 8#77) != 0 )); then
        eg_err "GROK_IPHONE_AUTHKEY_FILE must not be accessible by group or other users (chmod 600)"
        iphone_down
        return 1
      fi
      up_args+=(--auth-key="file:$IPHONE_AUTHKEY_FILE")
    elif [[ ! -t 0 ]]; then
      eg_err "iphone-setup needs a TTY login or GROK_IPHONE_AUTHKEY_FILE"
      iphone_down
      return 1
    fi
    iphone_cli "${up_args[@]}" || { iphone_down; return 1; }
  fi
  if iphone_select_exit; then
    local stable_id=""
    stable_id="$(iphone_selected_exit_id)" \
      || { eg_warn "selected phone has no stable node ID in Tailscale status"; iphone_down; return 1; }
    iphone_save_node "$stable_id" || { iphone_down; return 1; }
    ( umask 077; printf '%s\n' "$stable_id" > "$IPHONE_READY_FILE" )
    chmod 600 "$IPHONE_READY_FILE"
    eg_ok "iPhone exit node '$node' is ready and pinned to its stable node ID"
  else
    eg_warn "sidecar identity is enrolled and '$node' is saved, but the phone is not usable yet"
    eg_warn "enable Run as Exit Node on the iPhone, approve it in Tailscale, then rerun iphone-setup"
    rc=1
  fi
  iphone_down
  return "$rc"
}

# ---------------------------------------------------------------- rung: VPN

socks_down(){
  local pid=""
  pid="$(pid_from_file "$SOCKS_PID")" || true
  if [[ -n "$pid" ]] && socks_process_alive "$pid"; then kill "$pid" 2>/dev/null || true; fi
  rm -f "$SOCKS_PID"
  # Reap an orphan the pidfile no longer tracks: a prior run that gave up (or whose pidfile was cleared)
  # can leave our proxy still holding 127.0.0.1:$PORT, which would block the next bind. Kill it by port
  # ownership -- but only ever a process that is our own socks-netns.py, never an unrelated listener.
  local owner; owner="$(port_owner_pid)"
  if [[ -n "$owner" && "$owner" != "$pid" ]] && pid_has_arg "$owner" "$SOCKS_NETNS"; then
    kill "$owner" 2>/dev/null || true
  fi
}

socks_process_alive(){
  local pid="${1:-}"
  [[ -n "$pid" ]] || pid="$(pid_from_file "$SOCKS_PID")" || return 1
  # The pidfile holds the STAGE 2 pid: socks-netns.py binds the port as root in the host netns, then
  # re-execs into the VPN netns as `--serve-fd N --user U --pidfile P`, dropping the --listen/--netns
  # tokens before it writes the pidfile. So identify our proxy by the two argv tokens that survive the
  # re-exec -- the script path and our pidfile path. Callers that need proof the port is actually being
  # served add pid_owns_proxy_port; asserting --listen/--netns here can never match and wrongly fails.
  kill -0 "$pid" 2>/dev/null \
    && pid_has_arg "$pid" "$SOCKS_NETNS" \
    && pid_has_arg "$pid" "$SOCKS_PID"
}

# The listener is bound in THIS namespace and only then handed to a process inside the VPN
# namespace, so grok can reach 127.0.0.1:$PORT while every packet leaves through the tun.
socks_up(){
  socks_down
  sudo -n python3 "$SOCKS_NETNS" --listen "127.0.0.1:$PORT" --netns "$NS" \
       --user "$(id -un)" --pidfile "$SOCKS_PID" 9>&- >/dev/null 2>&1 &
  local i pid=""
  for i in $(seq 1 24); do
    sleep 0.25
    pid="$(pid_from_file "$SOCKS_PID")" || continue
    if socks_process_alive "$pid" && pid_owns_proxy_port "$pid"; then return 0; fi
  done
  eg_err "  socks-netns.py did not come up on 127.0.0.1:$PORT"
  socks_down
  return 1
}

socks_alive(){
  local pid; pid="$(pid_from_file "$SOCKS_PID")" || return 1
  socks_process_alive "$pid" && pid_owns_proxy_port "$pid"
}
vpn_tun_alive(){
  # Empty namespace only short-circuits when host-namespace egress was explicitly allowed (startup
  # otherwise refuses to run); without the flag an empty NS falls through and fails closed.
  [[ -z "$NS" && "${GROK_ALLOW_HOSTNS_EGRESS:-0}" == 1 ]] && return 0
  sudo -n ip netns exec "$NS" ip link show tun-grok >/dev/null 2>&1
}

# verb: "up" for the first server, "next" to blacklist the current one and take the next.
vpn_up(){
  local verb="${1:-up}"
  sudo -n "$VPNGATE" "$verb" 9>&- >&2 || return 1
  socks_up || return 1
  set_active "vpn"
  return 0
}

vpn_alive(){ vpn_tun_alive && socks_alive; }
vpn_down(){ socks_down; sudo -n "$VPNGATE" down 9>&- >/dev/null 2>&1; }

# ---------------------------------------------------------------- rung dispatch

rung_alive(){
  case "$1" in
    direct)  return 0 ;;
    local:*) local_alive ;;
    iphone)  iphone_alive ;;
    vpn)     vpn_alive ;;
    *)       return 1 ;;
  esac
}

rung_down(){
  case "$1" in
    direct)  return 0 ;;
    local:*) local_down ;;
    iphone)  iphone_down ;;
    vpn)     vpn_down ;;
  esac
}

rung_up(){
  case "$1" in
    direct)  set_active direct; return 0 ;;
    local:*) local_up "${1#local:}" ;;
    iphone)  iphone_up ;;
    vpn)     vpn_up up ;;
  esac
}

# Confirm a rung that was just (re)brought up is not merely alive but still serves the model the
# session is pinned to. A reconnected VPN lands on a fresh server in a possibly different region, so
# "the tunnel is up" says nothing about capability; likewise any pinned model must be re-checked
# after a reconnect. A home PC with no pin has a stable region, so a liveness check is enough there.
rung_confirm(){
  if [[ "$1" == direct ]]; then return 0; fi
  if [[ -n "$REQUIRE_MODEL" || "$1" == vpn || "$1" == iphone ]]; then rung_probe "$1"; else rung_alive "$1"; fi
}

teardown_all(){ local_down; iphone_down; vpn_down; clear_active; }

# ---------------------------------------------------------------- the ladder

# `direct` is not on the ladder. It is the reference every rung is measured against, so it can
# never "beat" anything; it is the fallback taken only when no rung unlocks a thing (see below).
LADDER=()
build_ladder(){
  LADDER=()
  local label
  while IFS=$'\t' read -r label _ _ _; do LADDER+=("local:$label"); done < <(local_hosts)
  iphone_configured && LADDER+=("iphone")
  LADDER+=("vpn")
}

# The vpn entry is not one rung but a sequence: walk VPN Gate candidates until one both
# comes up and offers the model.
try_vpn_sequence(){
  local verb=up i=0
  while (( i < VPN_MAX_TRIES )); do
    if ! vpn_up "$verb"; then eg_warn "  no further VPN Gate server came up"; return 1; fi
    if rung_probe vpn; then return 0; fi
    verb=next; i=$((i+1))
  done
  eg_warn "  exhausted $VPN_MAX_TRIES VPN Gate servers"
  return 1
}

# Walk the ladder from $1 (default: the top) and settle on the first rung that unlocks something.
# $2=0 forbids the direct fallback: when demoting, the rung being abandoned HAD unlocked models, so
# landing on direct would silently downgrade the session and unmask the VM's region.
select_egress(){
  local start="${1:-0}" direct_fallback="${2:-1}" i rung
  learn_baseline
  build_ladder
  for (( i = start; i < ${#LADDER[@]}; i++ )); do
    rung="${LADDER[$i]}"
    eg_log "trying rung: $rung"
    if [[ "$rung" == vpn ]]; then
      try_vpn_sequence && return 0
      vpn_down
      continue
    fi
    if ! rung_up "$rung"; then continue; fi
    if rung_probe "$rung"; then return 0; fi
    rung_down "$rung"
  done
  # Nothing on the ladder offered anything the VM cannot already see. Routing buys nothing, so take
  # the cheapest path -- but only here, at selection time, never as a demotion.
  if [[ "$direct_fallback" == 1 && "$ALLOW_DIRECT" == 1 ]]; then
    eg_warn "no egress unlocks anything beyond the direct connection — falling back to direct"
    rm -f "$UNLOCKED"; set_active direct; return 0
  fi
  # A probing walk that comes up empty must not leave a rung named in the state: try_vpn_sequence
  # sets 'vpn' active before its probe, so without this the caller would see a phantom vpn rung.
  clear_active
  return 1
}

# Move strictly downward. Inside the vpn rung, "down" means the next VPN Gate server.
demote(){
  local cur; cur="$(active_rung)"
  if [[ "$cur" == vpn ]]; then
    eg_warn "demoting to the next VPN Gate server"
    local verb=next i=0
    while (( i < VPN_MAX_TRIES )); do
      if ! vpn_up "$verb"; then break; fi
      if rung_probe vpn; then return 0; fi
      i=$((i+1))
    done
    eg_err "no VPN Gate server left"
    return 1
  fi
  rung_down "$cur"
  # Resume the ladder just past the rung being abandoned. Deriving the index from the live ladder
  # (not a stashed LADDER_POS a reused session never set) is what stops a demote from re-probing
  # rungs above the current one. An unknown rung starts past the end -> fail closed, no fallback.
  build_ladder
  local from=${#LADDER[@]} i
  for (( i = 0; i < ${#LADDER[@]}; i++ )); do
    if [[ "${LADDER[$i]}" == "$cur" ]]; then from=$((i + 1)); break; fi
  done
  select_egress "$from" 0            # 0: no direct fallback — demoting into direct is a downgrade
}

# ---------------------------------------------------------------- watchdog

watch_egress(){
  local cycle=0 fails=0 cur
  while sleep "$WATCH_INTERVAL"; do
    cur="$(active_rung)"

    # No egress currently held (a prior round tore everything down to fail closed). Keep hunting:
    # a home PC may have woken, or a VPN region that serves the model may now be reachable.
    if [[ -z "$cur" ]]; then
      if select_egress 0 0 >/dev/null 2>&1; then
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
        elif [[ "$cur" == iphone ]] && ! rung_confirm iphone; then
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
      rung_down "$cur"
      # rung_confirm, not rung_alive: a reconnected VPN may have surfaced in a region that no longer
      # serves the pinned model, and "restored" must never mean "up but wrong region".
      if rung_up "$cur" && rung_confirm "$cur"; then
        eg_ok "$cur restored; grok will resume on its own"
        fails=0
      else
        rung_down "$cur"                              # do not leave a wrong-region tunnel up
      fi
      continue
    fi

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
    fails=0
  done
}

# ---------------------------------------------------------------- standalone CLI

standalone_mutation_lock(){
  command -v flock >/dev/null 2>&1 || { eg_err "flock is required to protect the shared egress"; return 1; }
  exec 9>"$SESSION_LOCK"
  flock -n 9 || { eg_err "another grok-remote session owns the shared egress ($SESSION_LOCK)"; return 1; }
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-status}" in
    select) standalone_mutation_lock || exit 1
            select_egress && { eg_ok "active: $(active_rung)  egress IP: $(egress_ip "$( [[ $(active_rung) == direct ]] && echo '' || echo "$PROXY" )")"; exit 0; }
            eg_err "no usable egress"; exit 1 ;;
    watch)  standalone_mutation_lock || exit 1; watch_egress ;;
    status) r="$(active_rung)"; [[ -z "$r" ]] && { eg_log "no egress selected"; exit 0; }
            rung_alive "$r" && eg_ok "active: $r (alive)" || eg_warn "active: $r (DOWN)" ;;
    ip)     egress_ip; echo ;;
    stop)   standalone_mutation_lock || exit 1; teardown_all; eg_ok "egress torn down" ;;
    *)      echo "usage: $0 {select|watch|status|ip|stop}" >&2; exit 1 ;;
  esac
fi
