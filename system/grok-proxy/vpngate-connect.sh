#!/usr/bin/env bash
# vpngate-connect.sh — FALLBACK egress for grok using a VPN Gate server in a region
# where grok-4.5 is available. It tries the preferred countries in order (VN first,
# then JP, KR, TH, ID, ... — see VPNGATE_PREFER), skips servers it cannot reach, and
# fails over to the next one until a tunnel comes up. EU and X-banned countries are
# never used, since grok-4.5 is not offered there (see GROK_BLOCKED_CC).
#
# The VPN runs inside a dedicated network namespace, so ONLY the command you run
# through it goes over the VPN. The rest of the VM (Tailscale, the OpenClaw
# gateway, your SSH session) keeps its normal route and is never touched.
#
#   sudo ./vpngate-connect.sh up               connect the VPN in netns 'grokvpn'
#   sudo ./vpngate-connect.sh next             blacklist the current server, take the next one
#   sudo ./vpngate-connect.sh reset            clear the session server blacklist (keep the tunnel)
#   sudo ./vpngate-connect.sh status           show state + egress IP
#   sudo ./vpngate-connect.sh down             disconnect and clean up
#   sudo ./vpngate-connect.sh run -- CMD ...    ensure up, then run CMD inside the netns
#
#   VPNGATE_COUNTRIES="VN JP"  force an ordered country list (overrides auto)
#   VPNGATE_PREFER / GROK_BLOCKED_CC / VPNGATE_CANDIDATES / VPNGATE_PER_TRY  tune it
#
# NOTE: this is a best-effort fallback for when no home PC is available. VPN Gate
# servers are volunteer/datacenter IPs, so grok.com may still bot-flag them even
# when the region is correct. Prefer the home-PC path (grok-remote) when possible.
# Data source: https://www.vpngate.net/  (public API returns a global server list).
set -euo pipefail
umask 077

NS=grokvpn
TUN=tun-grok
# NOTE: not /run — that is commonly mounted noexec, which blocks the --up script.
WORK=/var/lib/grok-vpngate
OVPN="$WORK/vpngate.ovpn"
UPSH="$WORK/up.sh"
PIDF="$WORK/openvpn.pid"
LOGF="$WORK/openvpn.log"
CANDF="$WORK/candidates.tsv"
CURF="$WORK/current.tsv"              # the candidate currently carrying traffic
FAILF="$WORK/failed.tsv"              # candidates that failed; never handed out again
API="https://www.vpngate.net/api/iphone/"
# Directory of this script, so build_candidates can find sanitize.awk shipped next to it.
SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P || true)"
SANITIZER="$SELF_DIR/sanitize.awk"

# grok-4.5 is region-gated ONLY against the EU (EU AI Act classes it a systemic-risk
# GPAI model) and the few countries where X/Twitter itself is banned. Egress through
# any of these will NOT unlock grok-4.5, so we never use a VPN Gate server there even
# when one is offered (e.g. Romania is an EU member state). ISO-3166 alpha-2, space-sep.
GROK_BLOCKED_CC="${GROK_BLOCKED_CC:-AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE CN IR KP TM VE}"

# Preferred egress countries, in order — all non-EU and confirmed to serve grok-4.5.
# VN first because it is the account's home region. In auto mode any OTHER non-blocked
# country VPN Gate happens to offer is appended after these (by server count), so the
# fallback uses every usable country, not just Vietnam.
VPNGATE_PREFER="${VPNGATE_PREFER:-VN JP KR TH ID}"

# Explicit ordered override, e.g. VPNGATE_COUNTRIES="VN JP". Falls back to the legacy
# single-country VPNGATE_COUNTRY, then to auto (VPNGATE_PREFER + any other usable ones).
VPNGATE_COUNTRIES="${VPNGATE_COUNTRIES:-${VPNGATE_COUNTRY:-}}"

CAND_MAX="${VPNGATE_CANDIDATES:-8}"   # most servers to actually try, across all countries
PER_TRY="${VPNGATE_PER_TRY:-15}"      # seconds to wait for each server's tunnel to come up

have(){ command -v "$1" >/dev/null 2>&1; }
need_root(){ [[ $EUID -eq 0 ]] || { echo "[vpngate] run with sudo" >&2; exit 1; }; }
secure_workdir(){ mkdir -p "$WORK"; chmod 700 "$WORK"; }

public_ipv4(){
  python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if address.version == 4 and address.is_global else 1)
PY
}

valid_port(){ [[ "$1" =~ ^[0-9]+$ && ${#1} -le 5 ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

# Cheap reachability probe (no nc on this VM). TCP only; UDP servers can't be probed
# this way so they are tried optimistically with a short openvpn connect timeout.
tcp_ok(){
  public_ipv4 "$1" && valid_port "$2" || return 1
  timeout 5 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$1" "$2" 2>/dev/null
}

ensure_openvpn(){
  have openvpn && return 0
  echo "[vpngate] installing openvpn ..." >&2
  if   have apt-get; then apt-get update -qq && apt-get install -y -qq openvpn
  elif have pacman;  then pacman -Sy --noconfirm openvpn
  elif have dnf;     then dnf install -y openvpn
  else echo "[vpngate] please install openvpn manually" >&2; exit 1; fi
}

netns_ok(){ ip netns exec "$NS" ip link show "$TUN" >/dev/null 2>&1; }

fetch_list(){
  secure_workdir
  echo "[vpngate] fetching VPN Gate server list ..." >&2
  # VPN Gate serves CRLF; strip CR once here so every downstream parse (and base64) is clean.
  curl -s --max-time 40 "$API" | tr -d '\r' > "$WORK/list.csv" || true
  # Fields: 1=HostName 2=IP 3=Score 5=Speed 7=CountryShort 15=OpenVPN_ConfigData_Base64
  [[ -s "$WORK/list.csv" ]] || { echo "[vpngate] could not fetch the server list" >&2; exit 1; }
  normalize_list
  [[ -s "$WORK/parsed.tsv" ]] || { echo "[vpngate] no usable servers in the fetched list" >&2; exit 1; }
}

# The public API supplies both an IP column and a base64 OpenVPN config. Treat the
# config as untrusted even after directive allowlisting: pin its one `remote` line
# to the independently validated public API IP, validate the port/protocol, and
# normalize the line before root OpenVPN sees it. Results are returned in the two
# globals below so the caller does not have to parse the config again.
REMOTE_PORT=""
REMOTE_PROTO=""
pin_remote(){
  local ovpn="$1" ip="$2" count proto_count port proto tmp
  REMOTE_PORT=""; REMOTE_PROTO=""
  public_ipv4 "$ip" || return 1
  count="$(awk '$1=="remote"{n++} END{print n+0}' "$ovpn")"
  [[ "$count" == 1 ]] || return 1
  proto_count="$(awk '$1=="proto"{n++} END{print n+0}' "$ovpn")"
  (( proto_count <= 1 )) || return 1
  port="$(awk '$1=="remote"{print $3; exit}' "$ovpn")"
  valid_port "$port" || return 1
  proto="$(awk '$1=="proto"{print tolower($2); exit}' "$ovpn")"
  : "${proto:=udp}"
  case "$proto" in
    udp|udp4|udp6|tcp|tcp4|tcp6|tcp-client|tcp4-client|tcp6-client) ;;
    *) return 1 ;;
  esac
  tmp="$(mktemp "$ovpn.remote.XXXXXX")" || return 1
  if awk -v ip="$ip" -v port="$port" \
      '$1=="remote"{print "remote " ip " " port; next} {print}' "$ovpn" > "$tmp"; then
    chmod 600 "$tmp"
    mv -f "$tmp" "$ovpn"
  else
    rm -f "$tmp"
    return 1
  fi
  REMOTE_PORT="$port"
  REMOTE_PROTO="$proto"
}

# Parse the raw VPN Gate CSV into a clean cc<TAB>ip<TAB>score<TAB>uptime<TAB>b64 table. The CSV is
# unquoted, so a comma inside CountryLong ("Korea, Republic of") or Message shifts naive
# field positions, and a trailing comma empties the last field. We therefore take IP=$2 and
# Score=$3 (before any comma-bearing field), CountryShort as the first two-letter field at
# index >=7 whose next field is numeric, and the config as the last long base64 field.
# Rows whose IP/Score do not validate (a comma in HostName misaligned them) are dropped.
normalize_list(){
  # Uptime (ms) is two fields after CountryShort (NumVpnSessions, then Uptime), so it is read relative to
  # the located cc index -- safe, since the comma-bearing fields (CountryLong before, Operator/Message
  # after) never fall between them. Missing/garbled uptime defaults to 0 (sorts last, as least-proven).
  awk -F',' 'NR>2 {
      ip=$2; score=$3; cc=""; b64=""; up=0
      for (i=7; i<NF; i++)
        if ($i ~ /^[A-Z][A-Z]$/ && $(i+1) ~ /^[0-9]+$/) {
          cc=$i; if ($(i+2) ~ /^[0-9]+$/) up=$(i+2); break
        }
      for (i=NF; i>=1; i--)
        if ($i ~ /^[A-Za-z0-9+\/=]+$/ && length($i) > 100) { b64=$i; break }
      if (cc != "" && b64 != "" &&
          ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ &&
          score ~ /^[0-9]+$/)
        print cc "\t" ip "\t" score "\t" up "\t" b64
    }' "$WORK/list.csv" > "$WORK/parsed.tsv"
}

# Ordered, de-duplicated list of countries to try. Explicit override wins; otherwise
# VPNGATE_PREFER, then any other country present in the list by descending server
# count. Countries in GROK_BLOCKED_CC (EU / X-banned) are always dropped.
country_order(){
  local avail blocked=" $GROK_BLOCKED_CC " base cc seen=" " out=()
  avail="$(cut -f1 "$WORK/parsed.tsv" | sort -u)"
  base="${VPNGATE_COUNTRIES:-$VPNGATE_PREFER}"
  for cc in $base; do
    if [[ "$blocked" == *" $cc "* ]]; then
      echo "[vpngate] skip $cc — grok-4.5 is not available there (EU / X-banned)" >&2; continue
    fi
    grep -qx "$cc" <<<"$avail" || continue
    [[ "$seen" == *" $cc "* ]] && continue
    out+=("$cc"); seen+="$cc "
  done
  if [[ -z "$VPNGATE_COUNTRIES" ]]; then           # auto: append the rest, most servers first
    while read -r _ cc; do
      [[ -z "$cc" || "$blocked" == *" $cc "* || "$seen" == *" $cc "* ]] && continue
      out+=("$cc"); seen+="$cc "
    done < <(cut -f1 "$WORK/parsed.tsv" | sort | uniq -c | sort -rn)
  fi
  [[ ${#out[@]} -gt 0 ]] && printf '%s\n' "${out[@]}"
}

# Decode the top servers of each chosen country and keep the ones we can actually
# reach (TCP pre-tested; UDP kept optimistically), longest uptime first (VPN Gate score
# as the tiebreaker within an uptime hour) to prefer proven-stable servers, capped at
# CAND_MAX. Writes cc<TAB>ip<TAB>port<TAB>proto<TAB>ovpn-path to $CANDF.
build_candidates(){
  : > "$CANDF"; rm -f "$WORK"/cand-*.ovpn
  [[ -f "$SANITIZER" ]] || { echo "[vpngate] sanitizer $SANITIZER missing — refusing to use untrusted configs" >&2; return 1; }
  local n=0 cc score ip b64 port proto ovpn
  while read -r cc; do
    [[ -z "$cc" ]] && continue
    echo "[vpngate] scanning $cc ..." >&2
    while IFS=$'\t' read -r uph score ip b64; do
      [[ $n -ge $CAND_MAX ]] && break 2
      ovpn="$WORK/cand-$cc-$ip.ovpn"
      echo "$b64" | tr -d '\r\n' | base64 -d > "$ovpn" 2>/dev/null || continue
      # The config is an untrusted download that openvpn runs as root, so allowlist-sanitize
      # it (keep only known-safe connectivity directives + PKI blocks, drop everything else)
      # before we ever hand it to openvpn. This stops a malicious server from smuggling an
      # --up / --tls-verify / --plugin hook. Fail closed: a rejected config skips the server.
      awk -f "$SANITIZER" "$ovpn" > "$ovpn.san" || { rm -f "$ovpn" "$ovpn.san"; continue; }
      mv -f "$ovpn.san" "$ovpn"
      if ! pin_remote "$ovpn" "$ip"; then
        echo "[vpngate]   rejected unsafe remote for $cc $ip" >&2
        rm -f "$ovpn"
        continue
      fi
      port="$REMOTE_PORT"; proto="$REMOTE_PROTO"
      if [[ "$proto" == tcp* ]] && ! tcp_ok "$ip" "$port"; then
        continue                                   # dead TCP server — skip fast
      fi
      printf '%s\t%s\t%s\t%s\t%s\n' "$cc" "$ip" "$port" "$proto" "$ovpn" >> "$CANDF"
      n=$((n+1))
      echo "[vpngate]   candidate $n: $cc $ip:$port/$proto (score $score, uptime ${uph}h)" >&2
    done < <(awk -F'\t' -v c="$cc" '$1==c {print int($4/3600000)"\t"$3"\t"$2"\t"$5}' \
               "$WORK/parsed.tsv" | sort -t$'\t' -k1,1nr -k2,2nr | head -12)
  done < <(country_order)
  [[ -s "$CANDF" ]] || { echo "[vpngate] no reachable server in any allowed country" >&2; return 1; }
}

write_upscript(){
  cat > "$UPSH" <<'UP'
#!/usr/bin/env bash
# openvpn --up: move the freshly created tun into the netns and configure the
# address + default route inside it. openvpn keeps the tun fd, so
# it goes on relaying even though the interface now lives in another namespace.
set -euo pipefail
NS=grokvpn
: "${dev:?up.sh: openvpn did not export dev}"
: "${ifconfig_local:?up.sh: openvpn did not export ifconfig_local}"
ip link set "$dev" netns "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$dev" up
if [[ -n "${ifconfig_remote:-}" ]]; then
  ip netns exec "$NS" ip addr add "$ifconfig_local" peer "$ifconfig_remote" dev "$dev"
  ip netns exec "$NS" ip route replace default via "$ifconfig_remote" dev "$dev"
else
  ip netns exec "$NS" ip addr add "$ifconfig_local/${ifconfig_netmask:-24}" dev "$dev"
  ip netns exec "$NS" ip route replace default dev "$dev"
fi
UP
  chmod +x "$UPSH"
}

# Kill the pid in a pidfile only if it really is our openvpn daemon, so a recycled PID that
# the kernel later handed to an unrelated process is never killed by mistake.
kill_openvpn_pid(){
  local pf="$1" p cmd
  [[ -f "$pf" ]] || return 0
  p="$(cat "$pf" 2>/dev/null || true)"
  [[ "$p" =~ ^[0-9]+$ ]] || return 0
  [[ -r "/proc/$p/cmdline" ]] || return 0          # process already gone -> nothing to kill
  # Group the read so a redirection failure (PID exits between the check and the read) goes to
  # /dev/null, not stderr -- `2>/dev/null` on `tr` alone does NOT suppress the shell's redirect error.
  cmd="$( { tr '\0' ' ' < "/proc/$p/cmdline"; } 2>/dev/null || true )"
  [[ "$cmd" == *openvpn*grok-vpngate* ]] && kill "$p" 2>/dev/null || true
}

# Kill any stale grok-vpngate openvpn and remove a leftover tun so a fresh attempt
# starts clean (earlier code piled up daemons that retried a dead server forever).
reap_openvpn(){
  kill_openvpn_pid "$PIDF"
  pkill -f "openvpn .*grok-vpngate" 2>/dev/null || true
  ip netns exec "$NS" ip link del "$TUN" 2>/dev/null || true
  ip link del "$TUN" 2>/dev/null || true
}

# Start openvpn for one candidate config and wait up to PER_TRY seconds for the tun
# to appear inside the netns. connect-retry-max 1 makes a dead server exit fast
# instead of backing off forever. Returns 0 iff the tunnel came up.
try_server(){
  local ovpn="$1" i p
  cp -f "$ovpn" "$OVPN"; rm -f "$PIDF"
  # A rejected config must fail over to the next candidate, not abort under set -e.
  if ! openvpn --config "$OVPN" \
    --dev "$TUN" --dev-type tun \
    --ifconfig-noexec --route-noexec \
    --script-security 2 --up "$UPSH" \
    --pull-filter ignore "setenv" \
    --mssfix 1360 \
    --connect-retry-max 1 --connect-timeout 10 \
    --daemon grok-vpngate --writepid "$PIDF" --log "$LOGF"; then
    return 1
  fi
  for i in $(seq 1 "$PER_TRY"); do
    netns_ok && return 0
    if [[ $i -ge 3 && -f "$PIDF" ]]; then          # openvpn already gave up? stop waiting
      p="$(cat "$PIDF" 2>/dev/null || true)"
      [[ -n "$p" ]] && ! kill -0 "$p" 2>/dev/null && break
    fi
    sleep 1
  done
  netns_ok
}

prepare_netns(){
  ip netns add "$NS" 2>/dev/null || true
  mkdir -p "/etc/netns/$NS"
  echo 'nameserver 1.1.1.1' > "/etc/netns/$NS/resolv.conf"
  # This script's umask is 077, so the file lands 0600 root:root -- but socks-netns.py drops privileges
  # inside the netns and reads /etc/resolv.conf (this file, bind-mounted by `ip netns exec`) to resolve
  # target hostnames. Without read access every getaddrinfo fails with gaierror -> the proxy answers
  # SOCKS "host unreachable", so grok cannot reach its API by name and silently falls back to grok-build.
  # The file holds only a public nameserver, so world-readable is correct and not a leak.
  chmod 644 "/etc/netns/$NS/resolv.conf"
}

# Is there a candidate left that has not already failed?
has_untried(){
  local cc ip port proto ovpn
  while IFS=$'\t' read -r cc ip port proto ovpn; do
    if ! grep -qxF "$ip:$port" "$FAILF" 2>/dev/null; then return 0; fi
  done < "$CANDF"
  return 1
}

# Keep the candidate list across `next` calls so failing over costs no extra API fetch.
# Refetch only when there is no list, or when every server on it has already failed.
ensure_candidates(){
  secure_workdir; touch "$FAILF"
  write_upscript
  if [[ -s "$CANDF" ]] && has_untried; then return 0; fi
  echo "[vpngate] (re)building the candidate list" >&2
  fetch_list
  build_candidates || exit 1
  # Do NOT clear $FAILF here. A refetch must KEEP the session blacklist so `next` cannot
  # re-hand a server that already failed (that caused an A->B->A loop). The blacklist is
  # reset only at session start (up / reset) and on down.
}

# Walk the candidates top to bottom, skipping any already marked failed, and stop at the
# first one whose tunnel actually comes up. The winner is recorded so `next` knows what to
# blacklist.
connect_from_candidates(){
  local cc ip port proto ovpn tried=0
  while IFS=$'\t' read -r cc ip port proto ovpn; do
    if grep -qxF "$ip:$port" "$FAILF" 2>/dev/null; then continue; fi
    tried=$((tried+1))
    echo "[vpngate] [$tried] connecting via $cc $ip:$port/$proto (isolated in netns '$NS') ..."
    if try_server "$ovpn"; then
      printf '%s\t%s\t%s\t%s\t%s\n' "$cc" "$ip" "$port" "$proto" "$ovpn" > "$CURF"
      echo "[vpngate] up via $cc $ip:$port/$proto. egress IP: $(ip netns exec "$NS" curl -s --max-time 20 https://api.ipify.org || echo '?')"
      return 0
    fi
    echo "[vpngate] $cc $ip:$port did not come up; marking it failed" >&2
    echo "$ip:$port" >> "$FAILF"
    reap_openvpn
  done < "$CANDF"
  return 1
}

up(){
  need_root; ensure_openvpn
  secure_workdir; : > "$FAILF"                       # fresh session: every server available again
  netns_ok && { echo "[vpngate] already up"; return 0; }
  reap_openvpn                                     # clear leftovers from earlier failed runs
  ensure_candidates
  prepare_netns
  connect_from_candidates && return 0
  echo "[vpngate] no VPN Gate server came up; last log lines:" >&2
  tail -n 15 "$LOGF" 2>/dev/null >&2
  exit 1
}

# Give up on the server we are on and take the next one. This is what the egress ladder
# calls when a VPN rung dies under a running grok: `--connect-retry-max 1` makes openvpn
# fail fast rather than sit reconnecting to a dead host, and we move on instead.
next(){
  need_root; ensure_openvpn
  if [[ -s "$CURF" ]]; then
    local cc ip port _proto _ovpn
    IFS=$'\t' read -r cc ip port _proto _ovpn < "$CURF"
    echo "[vpngate] dropping $cc $ip:$port and moving to the next server" >&2
    echo "$ip:$port" >> "$FAILF"
    rm -f "$CURF"
  fi
  reap_openvpn
  ensure_candidates
  prepare_netns
  connect_from_candidates && return 0
  echo "[vpngate] no further VPN Gate server available" >&2
  exit 1
}

# Clear the per-session server blacklist without tearing the tunnel down. grok-remote's
# tunnel-reuse path does not go through up() (which also clears it), so it calls this once
# at session start to forgive the servers that failed in the previous session.
reset(){
  need_root
  secure_workdir
  : > "$FAILF"
  echo "[vpngate] session server blacklist cleared" >&2
}

down(){
  need_root
  kill_openvpn_pid "$PIDF"
  pkill -f "openvpn .*grok-vpngate" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  rm -rf "/etc/netns/$NS"
  rm -f "$CURF" "$FAILF" "$PIDF" "$CANDF" "$WORK"/cand-*.ovpn   # a fresh session gets every server back
  echo "[vpngate] down"
}

status(){
  if netns_ok; then
    local cur=""
    [[ -s "$CURF" ]] && cur=" via $(cut -f1,2,3 "$CURF" | tr '\t' ' ')"
    echo "[vpngate] up (netns '$NS')$cur. egress IP: $(ip netns exec "$NS" curl -s --max-time 15 https://api.ipify.org || echo '?')"
    [[ -s "$FAILF" ]] && echo "[vpngate] servers already burned this session: $(wc -l < "$FAILF")"
  else
    echo "[vpngate] down"
  fi
}

run_cmd(){
  need_root
  [[ $# -gt 0 ]] || { echo "[vpngate] nothing to run" >&2; exit 1; }
  up
  local u="${SUDO_USER:-root}" uhome
  # $HOME here is root's (we are under sudo), so it must not be used to build the target
  # user's PATH -- that yielded /root/.local/bin and hid the user's own binaries.
  uhome="$(getent passwd "$u" | cut -d: -f6)"
  echo "[vpngate] running as '$u' inside netns '$NS'" >&2
  exec ip netns exec "$NS" runuser -u "$u" -- \
       env -u http_proxy -u https_proxy -u all_proxy -u no_proxy -u ftp_proxy \
           -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY -u FTP_PROXY \
           HOME="$uhome" \
           PATH="/usr/local/bin:/usr/bin:/bin:$uhome/.local/bin" \
           "$@"
}

# Guarded so the file can be sourced by the tests without running a command.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-}" in
    up)     up ;;
    next)   next ;;
    reset)  reset ;;
    down)   down ;;
    status) status ;;
    run)    shift; [[ "${1:-}" == "--" ]] && shift; run_cmd "$@" ;;
    *) echo "usage: sudo $0 {up|next|reset|down|status|run -- CMD ...}" >&2; exit 1 ;;
  esac
fi
