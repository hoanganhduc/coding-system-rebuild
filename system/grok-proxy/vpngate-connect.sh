#!/usr/bin/env bash
# vpngate-connect.sh — FALLBACK egress for grok using a Vietnamese VPN Gate server.
#
# The VPN runs inside a dedicated network namespace, so ONLY the command you run
# through it goes over the VPN. The rest of the VM (Tailscale, the OpenClaw
# gateway, your SSH session) keeps its normal route and is never touched.
#
#   sudo ./vpngate-connect.sh up               connect the VPN in netns 'grokvpn'
#   sudo ./vpngate-connect.sh status           show state + egress IP
#   sudo ./vpngate-connect.sh down             disconnect and clean up
#   sudo ./vpngate-connect.sh run -- CMD ...    ensure up, then run CMD inside the netns
#
# NOTE: this is a best-effort fallback for when no home PC is available. VPN Gate
# servers are volunteer/datacenter IPs, so grok.com may still bot-flag them even
# when the region is correct. Prefer the home-PC path (grok-remote) when possible.
# Data source: https://www.vpngate.net/  (public API returns a VN server list).
set -euo pipefail

NS=grokvpn
TUN=tun-grok
# NOTE: not /run — that is commonly mounted noexec, which blocks the --up script.
WORK=/var/lib/grok-vpngate
OVPN="$WORK/vpngate.ovpn"
UPSH="$WORK/up.sh"
PIDF="$WORK/openvpn.pid"
LOGF="$WORK/openvpn.log"
API="https://www.vpngate.net/api/iphone/"
COUNTRY="${VPNGATE_COUNTRY:-VN}"

have(){ command -v "$1" >/dev/null 2>&1; }
need_root(){ [[ $EUID -eq 0 ]] || { echo "[vpngate] run with sudo" >&2; exit 1; }; }

ensure_openvpn(){
  have openvpn && return 0
  echo "[vpngate] installing openvpn ..." >&2
  if   have apt-get; then apt-get update -qq && apt-get install -y -qq openvpn
  elif have pacman;  then pacman -Sy --noconfirm openvpn
  elif have dnf;     then dnf install -y openvpn
  else echo "[vpngate] please install openvpn manually" >&2; exit 1; fi
}

netns_ok(){ ip netns exec "$NS" ip link show "$TUN" >/dev/null 2>&1; }

fetch_config(){
  mkdir -p "$WORK"
  echo "[vpngate] fetching $COUNTRY server list ..." >&2
  curl -s --max-time 40 "$API" -o "$WORK/list.csv"
  # Fields: 1=HostName 2=IP 3=Score 5=Speed 7=CountryShort 15=OpenVPN_ConfigData_Base64
  local best host score
  best="$(awk -F',' -v c="$COUNTRY" 'NR>2 && $7==c && $15!="" {print $3"\t"$1"\t"$15}' \
            "$WORK/list.csv" | sort -k1,1 -nr | head -1)"
  [[ -n "$best" ]] || { echo "[vpngate] no $COUNTRY server with an OpenVPN config found" >&2; exit 1; }
  score="$(cut -f1 <<<"$best")"; host="$(cut -f2 <<<"$best")"
  echo "[vpngate] selected $host (score $score)" >&2
  # VPN Gate serves the CSV with CRLF, so the base64 field carries a trailing
  # \r that base64 -d rejects; strip CR (and any stray whitespace) first.
  cut -f3 <<<"$best" | tr -d '\r\n' | base64 -d > "$OVPN"
}

write_upscript(){
  cat > "$UPSH" <<'UP'
#!/usr/bin/env bash
# openvpn --up / --route-up: move the freshly created tun into the netns and
# configure the address + default route inside it. openvpn keeps the tun fd, so
# it goes on relaying even though the interface now lives in another namespace.
set -e
NS=grokvpn
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

up(){
  need_root; ensure_openvpn
  netns_ok && { echo "[vpngate] already up"; return 0; }
  fetch_config; write_upscript
  ip netns add "$NS" 2>/dev/null || true
  mkdir -p "/etc/netns/$NS"
  echo 'nameserver 1.1.1.1' > "/etc/netns/$NS/resolv.conf"
  echo "[vpngate] starting openvpn (isolated in netns '$NS') ..."
  openvpn --config "$OVPN" \
    --dev "$TUN" --dev-type tun \
    --ifconfig-noexec --route-noexec \
    --script-security 2 --up "$UPSH" --route-up "$UPSH" --up-restart \
    --daemon grok-vpngate --writepid "$PIDF" --log "$LOGF"
  for _ in $(seq 1 30); do netns_ok && break; sleep 1; done
  netns_ok || { echo "[vpngate] tunnel did not come up; last log lines:" >&2; tail -n 20 "$LOGF" 2>/dev/null >&2; exit 1; }
  echo "[vpngate] up. egress IP: $(ip netns exec "$NS" curl -s --max-time 20 https://api.ipify.org || echo '?')"
}

down(){
  need_root
  [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null || true
  pkill -f "openvpn .*grok-vpngate" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  rm -rf "/etc/netns/$NS"
  echo "[vpngate] down"
}

status(){
  if netns_ok; then
    echo "[vpngate] up (netns '$NS'). egress IP: $(ip netns exec "$NS" curl -s --max-time 15 https://api.ipify.org || echo '?')"
  else
    echo "[vpngate] down"
  fi
}

run_cmd(){
  need_root
  [[ $# -gt 0 ]] || { echo "[vpngate] nothing to run" >&2; exit 1; }
  up
  local u="${SUDO_USER:-root}"
  echo "[vpngate] running as '$u' inside netns '$NS'" >&2
  exec ip netns exec "$NS" runuser -u "$u" -- \
       env HOME="$(getent passwd "$u" | cut -d: -f6)" \
           PATH="/usr/local/bin:/usr/bin:/bin:$HOME/.local/bin" \
           ALL_PROXY= NO_PROXY= "$@"
}

case "${1:-}" in
  up)     up ;;
  down)   down ;;
  status) status ;;
  run)    shift; [[ "${1:-}" == "--" ]] && shift; run_cmd "$@" ;;
  *) echo "usage: sudo $0 {up|down|status|run -- CMD ...}" >&2; exit 1 ;;
esac
