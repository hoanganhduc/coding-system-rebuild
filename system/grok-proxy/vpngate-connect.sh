#!/usr/bin/env bash
# vpngate-connect.sh — FALLBACK egress for grok using a VPN Gate server in a region
# where grok-4.5 is available. It tries the preferred countries in order (VN first,
# then JP, KR, TH, ID, ... — see VPNGATE_PREFER), skips servers it cannot reach, and
# fails over to the next one until a tunnel comes up. Countries denied by the
# frozen GROK_BLOCKED_CC policy are never selected.
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
STARTF="$WORK/openvpn.start"
BOOTF="$WORK/openvpn.boot"
LOGF="$WORK/openvpn.log"
CANDF="$WORK/candidates.tsv"
CURF="$WORK/current.tsv"              # the candidate currently carrying traffic
FAILF="$WORK/failed.tsv"              # candidates that failed; never handed out again
ATTEMPTF="$WORK/attempts.tsv"          # durable transition-global OpenVPN launch budget
LISTF="$WORK/list.csv"
PARSEDF="$WORK/parsed.tsv"
NETNS_DIR="/etc/netns/$NS"
API="https://www.vpngate.net/api/iphone/"
# Directory of this script, so build_candidates can find sanitize.awk shipped next to it.
SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P || true)"
SANITIZER="$SELF_DIR/sanitize.awk"

# Conservative default deny for countries where the service itself is blocked.
# ISO-3166 alpha-2, space-separated; an explicit caller policy takes precedence.
GROK_BLOCKED_CC="${GROK_BLOCKED_CC-CN IR KP TM VE}"

# Preferred egress countries, in order. VN comes first because it is the account's
# home region. In auto mode any OTHER nonblocked
# country VPN Gate happens to offer is appended after these (by server count), so the
# fallback uses every usable country, not just Vietnam.
VPNGATE_PREFER="${VPNGATE_PREFER:-VN JP KR TH ID}"

# Explicit ordered override, e.g. VPNGATE_COUNTRIES="VN JP". Falls back to the legacy
# single-country VPNGATE_COUNTRY, then to auto (VPNGATE_PREFER + any other usable ones).
VPNGATE_COUNTRIES="${VPNGATE_COUNTRIES:-${VPNGATE_COUNTRY:-}}"
VPNGATE_ATTEMPT_SCOPE="${VPNGATE_ATTEMPT_SCOPE:-5b565a33b80b75dc462328a68cb5b57d31e3fe1a246438e70629059fcb8aca19}"

readonly CATALOG_MAX_BYTES=$((8 * 1024 * 1024))
readonly CONFIG_MAX_BYTES=$((1024 * 1024))
readonly CONFIG_B64_MAX_BYTES=1398104
readonly LOG_MAX_BYTES=$((8 * 1024 * 1024))
readonly STATE_MAX_BYTES=$((64 * 1024))
CAND_MAX="${VPNGATE_CANDIDATES:-8}"   # most servers to actually try, across all countries
PER_TRY="${VPNGATE_PER_TRY:-15}"      # seconds to wait for each server's tunnel to come up
[[ "$CAND_MAX" =~ ^[1-8]$ ]] \
  || { echo "[vpngate] VPNGATE_CANDIDATES must be between 1 and 8" >&2; return 2 2>/dev/null || exit 2; }
[[ "$PER_TRY" =~ ^([1-9]|1[0-5])$ ]] \
  || { echo "[vpngate] VPNGATE_PER_TRY must be between 1 and 15 seconds" >&2; return 2 2>/dev/null || exit 2; }

need_root(){ [[ $EUID -eq 0 ]] || { echo "[vpngate] run with sudo" >&2; exit 1; }; }
secure_workdir(){
  if [[ -e "$WORK" || -L "$WORK" ]]; then
    [[ -d "$WORK" && ! -L "$WORK" && "$(stat -c %u "$WORK" 2>/dev/null)" == "$EUID" ]] \
      || { echo "[vpngate] unsafe work directory: $WORK" >&2; return 1; }
  else
    mkdir -p -- "$WORK"
  fi
  chmod 700 -- "$WORK"
}

fsync_file(){
  /usr/bin/python3 - "$1" <<'PY'
import os, stat, sys
flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(sys.argv[1], flags)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise SystemExit(1)
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

fsync_directory(){
  /usr/bin/python3 - "$1" <<'PY'
import os, stat, sys
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(sys.argv[1], flags)
try:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise SystemExit(1)
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

bounded_log_writer(){
  /usr/bin/python3 -c '
import os, stat, sys
path, maximum_text = sys.argv[1:]
maximum = int(maximum_text)
flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags, 0o600)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise SystemExit(1)
    os.fchmod(fd, 0o600)
    kept = 0
    while True:
        chunk = os.read(0, 65536)
        if not chunk:
            break
        if kept < maximum:
            piece = chunk[:maximum - kept]
            view = memoryview(piece)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise SystemExit(1)
                view = view[written:]
            kept += len(piece)
    os.fsync(fd)
finally:
    os.close(fd)
' "$LOGF" "$LOG_MAX_BYTES"
}

log_fingerprint(){
  /usr/bin/python3 - "$LOGF" "$LOG_MAX_BYTES" <<'PY'
import hashlib, os, stat, sys
path, maximum_text = sys.argv[1:]
maximum = int(maximum_text)
flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
digest = hashlib.sha256()
total = 0
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_size > maximum:
        raise SystemExit(1)
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise SystemExit(1)
        digest.update(chunk)
finally:
    os.close(fd)
print(f"[vpngate] log_bytes={total} log_sha256={digest.hexdigest()}", file=sys.stderr)
PY
}

append_failed_server(){
  local value="$1" size=0
  [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]{1,5}$ ]] || return 1
  [[ ! -e "$FAILF" || ( -f "$FAILF" && ! -L "$FAILF" ) ]] || return 1
  [[ ! -e "$FAILF" ]] || size="$(stat -c %s "$FAILF")"
  (( size + ${#value} + 1 <= STATE_MAX_BYTES )) \
    || { echo "[vpngate] failed-server state reached its fixed bound" >&2; return 1; }
  printf '%s\n' "$value" >> "$FAILF"
}

# The broker serializes helper calls, but the ledger is independently locked and
# fsynced so a crash, refetch, or changing catalog cannot reset the number of
# OpenVPN launches already consumed by this provider generation.  Reservation is
# the linearization point and happens immediately before execing OpenVPN.
initialize_attempt_budget(){
  local reset="${1:-0}" outcome
  [[ "$VPNGATE_ATTEMPT_SCOPE" =~ ^[0-9a-f]{64}$ ]] || {
    echo "[vpngate] invalid transition attempt scope" >&2
    return 1
  }
  outcome="$(/usr/bin/python3 - "$ATTEMPTF" "$FAILF" "$WORK" \
      "$VPNGATE_ATTEMPT_SCOPE" "$reset" "$STATE_MAX_BYTES" <<'PY'
import fcntl, ipaddress, os, re, stat, sys

attempt_path, failed_path, work, scope, reset_text, maximum_text = sys.argv[1:]
maximum = int(maximum_text)
if re.fullmatch(r"[0-9a-f]{64}", scope) is None or reset_text not in {"0", "1"}:
    raise SystemExit(1)
flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(attempt_path, flags, 0o600)
try:
    fcntl.flock(fd, fcntl.LOCK_EX)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_size > maximum):
        raise SystemExit(1)
    data = os.read(fd, maximum + 1)
    if len(data) > maximum:
        raise SystemExit(1)
    header = f"scope\t{scope}\n".encode("ascii")
    new = not data or reset_text == "1"
    if new:
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, header)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    elif not data.startswith(header):
        raise SystemExit(1)
    else:
        try:
            rows = data.decode("ascii").splitlines()
        except UnicodeDecodeError:
            raise SystemExit(1)
        if not rows or rows[0] != f"scope\t{scope}":
            raise SystemExit(1)
        for index, row in enumerate(rows[1:], 1):
            fields = row.split("\t")
            if (
                len(fields) != 6
                or fields[0] != "attempt"
                or fields[1] != str(index)
                or re.fullmatch(r"[A-Z]{2}", fields[2]) is None
                or re.fullmatch(r"[0-9]{1,5}", fields[4]) is None
                or not 1 <= int(fields[4]) <= 65535
                or re.fullmatch(r"[a-z0-9-]{1,32}", fields[5]) is None
            ):
                raise SystemExit(1)
            try:
                if ipaddress.ip_address(fields[3]).version != 4:
                    raise SystemExit(1)
            except ValueError:
                raise SystemExit(1)
finally:
    os.close(fd)
if new:
    failed_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    failed_fd = os.open(failed_path, failed_flags, 0o600)
    try:
        failed_info = os.fstat(failed_fd)
        if not stat.S_ISREG(failed_info.st_mode) or failed_info.st_uid != os.geteuid():
            raise SystemExit(1)
        os.fchmod(failed_fd, 0o600)
        os.fsync(failed_fd)
    finally:
        os.close(failed_fd)
dir_fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
try:
    os.fsync(dir_fd)
finally:
    os.close(dir_fd)
print("new" if new else "existing")
PY
)" || { echo "[vpngate] unsafe or mismatched attempt ledger" >&2; return 1; }
  [[ "$outcome" == new || "$outcome" == existing ]]
}

reserve_server_attempt(){
  local cc="$1" ip="$2" port="$3" proto="$4"
  /usr/bin/python3 - "$ATTEMPTF" "$WORK" "$VPNGATE_ATTEMPT_SCOPE" \
      "$CAND_MAX" "$STATE_MAX_BYTES" "$cc" "$ip" "$port" "$proto" <<'PY'
import fcntl, ipaddress, os, re, stat, sys

path, work, scope, cap_text, maximum_text, cc, ip, port, proto = sys.argv[1:]
cap, maximum = int(cap_text), int(maximum_text)
if (re.fullmatch(r"[0-9a-f]{64}", scope) is None
        or re.fullmatch(r"[A-Z]{2}", cc) is None
        or re.fullmatch(r"[0-9]{1,5}", port) is None
        or not 1 <= int(port) <= 65535
        or re.fullmatch(r"[a-z0-9-]{1,32}", proto) is None):
    raise SystemExit(1)
try:
    if ipaddress.ip_address(ip).version != 4:
        raise SystemExit(1)
except ValueError:
    raise SystemExit(1)
flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
try:
    fcntl.flock(fd, fcntl.LOCK_EX)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_size > maximum):
        raise SystemExit(1)
    data = os.read(fd, maximum + 1)
    if len(data) > maximum:
        raise SystemExit(1)
    try:
        rows = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise SystemExit(1)
    if not rows or rows[0] != f"scope\t{scope}":
        raise SystemExit(1)
    for index, row in enumerate(rows[1:], 1):
        fields = row.split("\t")
        if (
            len(fields) != 6
            or fields[0] != "attempt"
            or fields[1] != str(index)
            or re.fullmatch(r"[A-Z]{2}", fields[2]) is None
            or re.fullmatch(r"[0-9]{1,5}", fields[4]) is None
            or not 1 <= int(fields[4]) <= 65535
            or re.fullmatch(r"[a-z0-9-]{1,32}", fields[5]) is None
        ):
            raise SystemExit(1)
        try:
            if ipaddress.ip_address(fields[3]).version != 4:
                raise SystemExit(1)
        except ValueError:
            raise SystemExit(1)
    count = len(rows) - 1
    if count >= cap:
        print(f"[vpngate] transition attempt budget exhausted ({cap})", file=sys.stderr)
        raise SystemExit(3)
    record = f"attempt\t{count + 1}\t{cc}\t{ip}\t{port}\t{proto}\n".encode("ascii")
    if len(data) + len(record) > maximum:
        raise SystemExit(1)
    os.lseek(fd, 0, os.SEEK_END)
    view = memoryview(record)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise SystemExit(1)
        view = view[written:]
    os.fsync(fd)
finally:
    os.close(fd)
dir_fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
try:
    os.fsync(dir_fd)
finally:
    os.close(dir_fd)
print(count + 1)
PY
}

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
  local owner mode
  [[ -f /usr/sbin/openvpn && ! -L /usr/sbin/openvpn && -x /usr/sbin/openvpn ]] \
    || { echo "[vpngate] fixed prerequisite /usr/sbin/openvpn is unavailable" >&2; return 1; }
  owner="$(stat -c %u /usr/sbin/openvpn 2>/dev/null)" || return 1
  mode="$(stat -c %a /usr/sbin/openvpn 2>/dev/null)" || return 1
  [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] \
    || { echo "[vpngate] unsafe /usr/sbin/openvpn ownership or mode" >&2; return 1; }
  (( (8#$mode & 8#022) == 0 )) \
    || { echo "[vpngate] /usr/sbin/openvpn is group/world writable" >&2; return 1; }
}

netns_ok(){ ip netns exec "$NS" ip link show "$TUN" >/dev/null 2>&1; }

egress_ipv4(){
  local address
  address="$(
    ip netns exec "$NS" curl -s --max-time 20 --max-filesize 64 \
      https://api.ipify.org 2>/dev/null
  )" || return 1
  public_ipv4 "$address" || return 1
  printf '%s' "$address"
}

fetch_list(){
  secure_workdir
  echo "[vpngate] fetching VPN Gate server list ..." >&2
  # VPN Gate serves CRLF; strip CR once here so every downstream parse (and base64) is clean.
  local tmp
  tmp="$(mktemp "$LISTF.XXXXXX")" || return 1
  if ! curl -s --max-time 40 --max-filesize "$CATALOG_MAX_BYTES" "$API" \
      | tr -d '\r' > "$tmp"; then
    rm -f -- "$tmp"
    echo "[vpngate] server list download failed or exceeded ${CATALOG_MAX_BYTES} bytes" >&2
    return 1
  fi
  if (( $(stat -c %s "$tmp") > CATALOG_MAX_BYTES )); then
    rm -f -- "$tmp"
    echo "[vpngate] server list exceeded ${CATALOG_MAX_BYTES} bytes" >&2
    return 1
  fi
  chmod 600 "$tmp"
  fsync_file "$tmp"
  mv -f -- "$tmp" "$LISTF"
  fsync_directory "$WORK"
  # Fields: 1=HostName 2=IP 3=Score 5=Speed 7=CountryShort 15=OpenVPN_ConfigData_Base64
  [[ -s "$LISTF" ]] || { echo "[vpngate] could not fetch the server list" >&2; exit 1; }
  normalize_list
  (( $(stat -c %s "$PARSEDF") <= CATALOG_MAX_BYTES )) \
    || { echo "[vpngate] normalized server list exceeded its fixed bound" >&2; return 1; }
  [[ -s "$PARSEDF" ]] || { echo "[vpngate] no usable servers in the fetched list" >&2; exit 1; }
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
    }' "$LISTF" > "$PARSEDF"
}

# Ordered, de-duplicated list of countries to try. Explicit override wins; otherwise
# VPNGATE_PREFER, then any other country present in the list by descending server
# count. Countries in GROK_BLOCKED_CC are always dropped.
country_order(){
  local avail blocked=" $GROK_BLOCKED_CC " base cc seen=" " out=()
  avail="$(cut -f1 "$PARSEDF" | sort -u)"
  base="${VPNGATE_COUNTRIES:-$VPNGATE_PREFER}"
  for cc in $base; do
    if [[ "$blocked" == *" $cc "* ]]; then
      echo "[vpngate] skip $cc — blocked by the frozen country policy" >&2; continue
    fi
    grep -qx "$cc" <<<"$avail" || continue
    [[ "$seen" == *" $cc "* ]] && continue
    out+=("$cc"); seen+="$cc "
  done
  if [[ -z "$VPNGATE_COUNTRIES" ]]; then           # auto: append the rest, most servers first
    while read -r _ cc; do
      [[ -z "$cc" || "$blocked" == *" $cc "* || "$seen" == *" $cc "* ]] && continue
      out+=("$cc"); seen+="$cc "
    done < <(cut -f1 "$PARSEDF" | sort | uniq -c | sort -rn)
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
  local n=0 probed=0 cc score ip b64 port proto ovpn
  while read -r cc; do
    [[ -z "$cc" ]] && continue
    echo "[vpngate] scanning $cc ..." >&2
    while IFS=$'\t' read -r uph score ip b64; do
      [[ $probed -ge $CAND_MAX ]] && break 2
      probed=$((probed+1))
      ovpn="$WORK/cand-$cc-$ip.ovpn"
      (( ${#b64} <= CONFIG_B64_MAX_BYTES )) || continue
      printf '%s' "$b64" | base64 -d > "$ovpn" 2>/dev/null || continue
      (( $(stat -c %s "$ovpn") <= CONFIG_MAX_BYTES )) \
        || { rm -f -- "$ovpn"; continue; }
      # The config is an untrusted download that openvpn runs as root, so allowlist-sanitize
      # it (keep only known-safe connectivity directives + PKI blocks, drop everything else)
      # before we ever hand it to openvpn. This stops a malicious server from smuggling an
      # --up / --tls-verify / --plugin hook. Fail closed: a rejected config skips the server.
      awk -f "$SANITIZER" "$ovpn" > "$ovpn.san" || { rm -f "$ovpn" "$ovpn.san"; continue; }
      (( $(stat -c %s "$ovpn.san") <= CONFIG_MAX_BYTES )) \
        || { rm -f -- "$ovpn" "$ovpn.san"; continue; }
      mv -f "$ovpn.san" "$ovpn"
      if ! pin_remote "$ovpn" "$ip"; then
        echo "[vpngate]   rejected unsafe remote for $cc $ip" >&2
        rm -f "$ovpn"
        continue
      fi
      (( $(stat -c %s "$ovpn") <= CONFIG_MAX_BYTES )) \
        || { rm -f -- "$ovpn"; continue; }
      port="$REMOTE_PORT"; proto="$REMOTE_PROTO"
      if [[ "$proto" == tcp* ]] && ! tcp_ok "$ip" "$port"; then
        continue                                   # dead TCP server — skip fast
      fi
      printf '%s\t%s\t%s\t%s\t%s\n' "$cc" "$ip" "$port" "$proto" "$ovpn" >> "$CANDF"
      n=$((n+1))
      echo "[vpngate]   candidate $n: $cc $ip:$port/$proto (score $score, uptime ${uph}h)" >&2
    done < <(awk -F'\t' -v c="$cc" '$1==c {print int($4/3600000)"\t"$3"\t"$2"\t"$5}' \
               "$PARSEDF" | sort -t$'\t' -k1,1nr -k2,2nr | head -12)
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

# OpenVPN ownership is a PID *and* /proc start-time identity.  No process-name
# scan is permitted: another OpenVPN instance on this host is outside this
# helper's resource graph and must be immune to teardown.
proc_start_ticks(){
  local pid="$1" raw tail
  [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/stat" ]] || return 1
  IFS= read -r raw < "/proc/$pid/stat" || return 1
  tail="${raw##*) }"
  set -- $tail
  [[ "${20:-}" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s' "${20}"
}

proc_state(){
  local pid="$1" raw tail
  [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/stat" ]] || return 1
  IFS= read -r raw < "/proc/$pid/stat" || return 1
  tail="${raw##*) }"
  set -- $tail
  [[ "${1:-}" =~ ^[A-Z]$ ]] || return 1
  printf '%s' "$1"
}

has_argv_pair(){
  local wanted_name="$1" wanted_value="$2"; shift 2
  local -a values=("$@")
  local i
  for (( i = 0; i + 1 < ${#values[@]}; i++ )); do
    [[ "${values[$i]}" == "$wanted_name" && "${values[$((i + 1))]}" == "$wanted_value" ]] && return 0
  done
  return 1
}

has_daemon_arg(){
  local argument
  for argument in "$@"; do
    [[ "$argument" == --daemon || "$argument" == --daemon=* ]] && return 0
  done
  return 1
}

openvpn_argv_matches(){
  local pid="$1"
  local -a argv=()
  [[ -r "/proc/$pid/cmdline" && "$(stat -c %u "/proc/$pid" 2>/dev/null)" == "$EUID" ]] || return 1
  mapfile -d '' -t argv < "/proc/$pid/cmdline" || return 1
  (( ${#argv[@]} > 0 )) && [[ "${argv[0]}" == /usr/sbin/openvpn ]] || return 1
  has_argv_pair --config "$OVPN" "${argv[@]}" \
    && has_argv_pair --dev "$TUN" "${argv[@]}" \
    && has_argv_pair --up "$UPSH" "${argv[@]}" \
    && ! has_daemon_arg "${argv[@]}"
}

identity_files_safe(){
  local file
  for file in "$PIDF" "$STARTF" "$BOOTF"; do
    [[ -f "$file" && ! -L "$file" \
       && "$(stat -c '%u:%a' "$file" 2>/dev/null)" == "$EUID:600" ]] || return 1
  done
}

openvpn_identity_values(){
  identity_files_safe || return 1
  OPENVPN_PID="$(cat "$PIDF" 2>/dev/null || true)"
  OPENVPN_START="$(cat "$STARTF" 2>/dev/null || true)"
  OPENVPN_BOOT="$(cat "$BOOTF" 2>/dev/null || true)"
  [[ "$OPENVPN_PID" =~ ^[1-9][0-9]*$ \
     && "$OPENVPN_START" =~ ^[1-9][0-9]*$ \
     && "$OPENVPN_BOOT" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
}

openvpn_identity_matches(){
  local now
  openvpn_identity_values || return 1
  [[ "$OPENVPN_BOOT" == "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" ]] || return 1
  now="$(proc_start_ticks "$OPENVPN_PID")" || return 1
  [[ "$now" == "$OPENVPN_START" ]] && openvpn_argv_matches "$OPENVPN_PID"
}

record_openvpn_identity(){
  local pid="$1" start="" boot="" pid_tmp="" start_tmp="" boot_tmp="" i
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  # The shell knows the non-daemonized child's PID at fork.  Wait only for its
  # exec boundary, then durably publish PID/start identity before doing any
  # readiness polling.  The broker's operation-group record covers this short
  # pre-publication interval if the helper itself is killed.
  for i in $(seq 1 100); do
    start="$(proc_start_ticks "$pid" 2>/dev/null || true)"
    if [[ -n "$start" ]] && openvpn_argv_matches "$pid"; then break; fi
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.01
  done
  [[ -n "$start" ]] && openvpn_argv_matches "$pid" || return 1
  boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
  [[ "$boot" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  pid_tmp="$(mktemp "$PIDF.XXXXXX")" || return 1
  start_tmp="$(mktemp "$STARTF.XXXXXX")" || { rm -f -- "$pid_tmp"; return 1; }
  boot_tmp="$(mktemp "$BOOTF.XXXXXX")" || { rm -f -- "$pid_tmp" "$start_tmp"; return 1; }
  if printf '%s\n' "$pid" > "$pid_tmp" \
     && printf '%s\n' "$start" > "$start_tmp" \
     && printf '%s\n' "$boot" > "$boot_tmp"; then
    chmod 600 "$pid_tmp" "$start_tmp" "$boot_tmp"
    fsync_file "$pid_tmp" && fsync_file "$start_tmp" && fsync_file "$boot_tmp" \
      || { rm -f -- "$pid_tmp" "$start_tmp" "$boot_tmp"; return 1; }
    mv -f -- "$start_tmp" "$STARTF"
    if [[ "${GROK_TESTING:-}" == 1 && "${VPNGATE_TEST_FAIL_IDENTITY_STAGE:-}" == after-start ]]; then
      rm -f -- "$pid_tmp" "$boot_tmp"
      return 1
    fi
    mv -f -- "$boot_tmp" "$BOOTF"
    if [[ "${GROK_TESTING:-}" == 1 && "${VPNGATE_TEST_FAIL_IDENTITY_STAGE:-}" == before-pid ]]; then
      rm -f -- "$pid_tmp"
      return 1
    fi
    # PID is the commit marker: it is renamed only after both companion
    # identities are durable.  The directory fsync commits all three renames.
    mv -f -- "$pid_tmp" "$PIDF"
    fsync_directory "$WORK"
  else
    rm -f -- "$pid_tmp" "$start_tmp" "$boot_tmp"
    return 1
  fi
  openvpn_identity_matches
}

remove_stale_identity_files(){
  local file changed=0
  for file in "$PIDF" "$STARTF" "$BOOTF"; do
    if [[ -e "$file" || -L "$file" ]]; then
      [[ -f "$file" && ! -L "$file" && "$(stat -c %u "$file" 2>/dev/null)" == "$EUID" ]] \
        || { echo "[vpngate] unsafe identity file: $file" >&2; return 1; }
      rm -f -- "$file"
      changed=1
    fi
  done
  (( changed == 0 )) || fsync_directory "$WORK"
}

signal_openvpn_pidfd(){
  local pid="$1" start="$2" boot="$3" requested_signal="$4"
  /usr/bin/python3 - "$pid" "$start" "$boot" "$requested_signal" "$OVPN" "$TUN" "$UPSH" <<'PY'
import os, signal, stat, sys

pid = int(sys.argv[1])
expected_start = int(sys.argv[2])
expected_boot = sys.argv[3]
requested = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL}[sys.argv[4]]
config, tun, upscript = sys.argv[5:]

try:
    pidfd = os.pidfd_open(pid, 0)
except ProcessLookupError:
    raise SystemExit(3)

def pair(argv, name, value):
    return any(argv[index:index + 2] == [name, value] for index in range(len(argv) - 1))

try:
    try:
        boot = open("/proc/sys/kernel/random/boot_id", encoding="ascii").read().strip()
        raw_stat = open(f"/proc/{pid}/stat", encoding="ascii").read()
        fields = raw_stat[raw_stat.rfind(")") + 2:].split()
        info = os.stat(f"/proc/{pid}")
        raw_argv = open(f"/proc/{pid}/cmdline", "rb").read(131073)
    except FileNotFoundError:
        raise SystemExit(3)
    if len(raw_argv) > 131072 or len(fields) <= 19:
        raise SystemExit(1)
    argv = [item.decode("utf-8", "surrogateescape") for item in raw_argv.rstrip(b"\0").split(b"\0") if item]
    if not (
        boot == expected_boot
        and fields[0] != "Z"
        and int(fields[19]) == expected_start
        and info.st_uid == os.geteuid()
        and argv
        and argv[0] == "/usr/sbin/openvpn"
        and pair(argv, "--config", config)
        and pair(argv, "--dev", tun)
        and pair(argv, "--up", upscript)
        and not any(arg == "--daemon" or arg.startswith("--daemon=") for arg in argv)
    ):
        raise SystemExit(1)
    try:
        signal.pidfd_send_signal(pidfd, requested)
    except ProcessLookupError:
        raise SystemExit(3)
finally:
    os.close(pidfd)
PY
}

kill_openvpn_exact(){
  local pid start now i
  if [[ ! -e "$PIDF" && ! -L "$PIDF" \
     && ! -e "$STARTF" && ! -L "$STARTF" \
     && ! -e "$BOOTF" && ! -L "$BOOTF" ]]; then
    return 0
  fi
  if ! openvpn_identity_values; then
    echo "[vpngate] incomplete or unsafe OpenVPN identity; refusing to signal" >&2
    return 1
  fi
  pid="$OPENVPN_PID"; start="$OPENVPN_START"
  if [[ "$OPENVPN_BOOT" != "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" ]]; then
    remove_stale_identity_files
    return
  fi
  now="$(proc_start_ticks "$pid")" || { remove_stale_identity_files; return; }
  if [[ "$now" != "$start" ]]; then
    # PID was recycled.  The current process is unrelated and must not be touched.
    remove_stale_identity_files
    return
  fi
  if [[ "$(proc_state "$pid" 2>/dev/null || true)" == Z ]]; then
    remove_stale_identity_files
    return
  fi
  if ! openvpn_argv_matches "$pid"; then
    echo "[vpngate] recorded PID/start now has foreign argv; refusing to signal PID $pid" >&2
    return 1
  fi
  local signal_rc=0
  signal_openvpn_pidfd "$pid" "$start" "$OPENVPN_BOOT" TERM || signal_rc=$?
  (( signal_rc == 0 || signal_rc == 3 )) \
    || { echo "[vpngate] OpenVPN identity changed after pidfd_open" >&2; return 1; }
  for i in $(seq 1 100); do
    [[ "$(proc_start_ticks "$pid" 2>/dev/null || true)" == "$start" \
       && "$(proc_state "$pid" 2>/dev/null || true)" != Z ]] || break
    sleep 0.05
  done
  if [[ "$(proc_start_ticks "$pid" 2>/dev/null || true)" == "$start" \
     && "$(proc_state "$pid" 2>/dev/null || true)" != Z ]]; then
    openvpn_argv_matches "$pid" \
      || { echo "[vpngate] OpenVPN identity changed during teardown" >&2; return 1; }
    signal_rc=0
    signal_openvpn_pidfd "$pid" "$start" "$OPENVPN_BOOT" KILL || signal_rc=$?
    (( signal_rc == 0 || signal_rc == 3 )) \
      || { echo "[vpngate] OpenVPN identity changed before SIGKILL" >&2; return 1; }
    for i in $(seq 1 100); do
      [[ "$(proc_start_ticks "$pid" 2>/dev/null || true)" == "$start" \
         && "$(proc_state "$pid" 2>/dev/null || true)" != Z ]] || break
      sleep 0.05
    done
  fi
  [[ "$(proc_start_ticks "$pid" 2>/dev/null || true)" != "$start" \
     || "$(proc_state "$pid" 2>/dev/null || true)" == Z ]] \
    || { echo "[vpngate] exact OpenVPN process remains after SIGKILL" >&2; return 1; }
  remove_stale_identity_files
}

# Remove only the recorded daemon and fixed tun.  No name-based process sweep.
reap_openvpn(){
  local rc=0
  kill_openvpn_exact || rc=1
  ip netns exec "$NS" ip link del "$TUN" 2>/dev/null || true
  return "$rc"
}

# Start openvpn for one candidate config and wait up to PER_TRY seconds for the tun
# to appear inside the netns. connect-retry-max 1 makes a dead server exit fast
# instead of backing off forever. Returns 0 iff the tunnel came up.
try_server(){
  local ovpn="$1" cc="$2" ip="$3" port="$4" proto="$5" i p attempt
  remove_stale_identity_files || return 1
  cp -f "$ovpn" "$OVPN"
  (( $(stat -c %s "$OVPN") <= CONFIG_MAX_BYTES )) \
    || { echo "[vpngate] selected config exceeded its fixed bound" >&2; return 1; }
  attempt="$(reserve_server_attempt "$cc" "$ip" "$port" "$proto")" || return 1
  echo "[vpngate] transition OpenVPN attempt $attempt/$CAND_MAX" >&2
  # A rejected config must fail over to the next candidate, not abort under set -e.
  /usr/sbin/openvpn --config "$OVPN" \
    --dev "$TUN" --dev-type tun \
    --ifconfig-noexec --route-noexec \
    --script-security 2 --up "$UPSH" \
    --pull-filter ignore "setenv" \
    --mssfix 1360 \
    --connect-retry-max 1 --connect-timeout 10 \
    </dev/null > >(bounded_log_writer >/dev/null 2>&1) 2>&1 &
  p=$!
  if ! record_openvpn_identity "$p"; then
    local child_start child_boot signal_rc=0
    child_start="$(proc_start_ticks "$p" 2>/dev/null || true)"
    child_boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
    if [[ "$child_start" =~ ^[1-9][0-9]*$ ]]; then
      signal_openvpn_pidfd "$p" "$child_start" "$child_boot" KILL || signal_rc=$?
      (( signal_rc == 0 || signal_rc == 3 )) || return 1
    fi
    wait "$p" 2>/dev/null || true
    return 1
  fi
  disown "$p" 2>/dev/null || true
  for i in $(seq 1 "$PER_TRY"); do
    if netns_ok && openvpn_identity_matches; then return 0; fi
    if [[ $i -ge 3 ]]; then                         # openvpn already gave up? stop waiting
      ! kill -0 "$p" 2>/dev/null && break
    fi
    sleep 1
  done
  netns_ok && openvpn_identity_matches
}

prepare_netns(){
  ip netns add "$NS" 2>/dev/null || true
  if [[ -e "$NETNS_DIR" || -L "$NETNS_DIR" ]]; then
    [[ -d "$NETNS_DIR" && ! -L "$NETNS_DIR" && "$(stat -c %u "$NETNS_DIR" 2>/dev/null)" == "$EUID" ]] \
      || { echo "[vpngate] unsafe namespace resolver directory" >&2; return 1; }
  else
    mkdir -p -- "$NETNS_DIR"
  fi
  echo 'nameserver 1.1.1.1' > "$NETNS_DIR/resolv.conf"
  # This script's umask is 077, so the file lands 0600 root:root -- but socks-netns.py drops privileges
  # inside the netns and reads /etc/resolv.conf (this file, bind-mounted by `ip netns exec`) to resolve
  # target hostnames. Without read access every getaddrinfo fails with gaierror -> the proxy answers
  # SOCKS "host unreachable", so grok cannot reach its API by name and silently falls back to grok-build.
  # The file holds only a public nameserver, so world-readable is correct and not a leak.
  chmod 644 "$NETNS_DIR/resolv.conf"
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
    if try_server "$ovpn" "$cc" "$ip" "$port" "$proto"; then
      printf '%s\t%s\t%s\t%s\t%s\n' "$cc" "$ip" "$port" "$proto" "$ovpn" > "$CURF"
      echo "[vpngate] up via $cc $ip:$port/$proto. egress IP: $(egress_ipv4 || echo '?')"
      return 0
    fi
    echo "[vpngate] $cc $ip:$port did not come up; marking it failed" >&2
    append_failed_server "$ip:$port" || return 1
    reap_openvpn || return 1
  done < "$CANDF"
  return 1
}

up(){
  need_root; ensure_openvpn
  secure_workdir
  initialize_attempt_budget 0
  if netns_ok; then
    openvpn_identity_matches \
      || { echo "[vpngate] tun exists without the exact recorded OpenVPN identity" >&2; return 1; }
    echo "[vpngate] already up"
    return 0
  fi
  reap_openvpn || return 1                         # clear leftovers from earlier failed runs
  ensure_candidates
  prepare_netns
  connect_from_candidates && return 0
  echo "[vpngate] no VPN Gate server came up; bounded log fingerprint:" >&2
  log_fingerprint || echo "[vpngate] log fingerprint unavailable" >&2
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
    append_failed_server "$ip:$port" || return 1
    rm -f "$CURF"
  fi
  reap_openvpn || return 1
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
  if [[ "${VPNGATE_PROVIDER_MODE:-0}" == 1 ]]; then
    initialize_attempt_budget 0
    echo "[vpngate] transition attempt budget and blacklist preserved" >&2
  else
    initialize_attempt_budget 1
    echo "[vpngate] session attempt budget and blacklist cleared" >&2
  fi
}

namespace_exists(){ ip netns exec "$NS" true >/dev/null 2>&1; }

safe_remove_owned_dir(){
  local path="$1" label="$2" parent
  [[ "$path" == /* && "$path" != / && "$path" != /var && "$path" != /var/lib && "$path" != /etc ]] \
    || { echo "[vpngate] unsafe $label cleanup path: $path" >&2; return 1; }
  if [[ ! -e "$path" && ! -L "$path" ]]; then return 0; fi
  [[ -d "$path" && ! -L "$path" && "$(stat -c %u "$path" 2>/dev/null)" == "$EUID" ]] \
    || { echo "[vpngate] unsafe $label directory: $path" >&2; return 1; }
  parent="${path%/*}"
  rm -rf --one-file-system -- "$path"
  fsync_directory "$parent"
}

root_residue_empty(){
  [[ ! -e "$WORK" && ! -L "$WORK" \
     && ! -e "$NETNS_DIR" && ! -L "$NETNS_DIR" ]] \
    && ! namespace_exists \
    && ! ip link show "$TUN" >/dev/null 2>&1
}

down(){
  need_root
  local rc=0
  kill_openvpn_exact || rc=1
  ip netns del "$NS" 2>/dev/null || true
  safe_remove_owned_dir "$NETNS_DIR" "namespace resolver" || rc=1
  # Preserve the work tree when exact process teardown failed: it contains the
  # identity needed for a retry/recovery.  A successful down removes the whole
  # dedicated directory, including configs, logs, lists and crash-time temps.
  (( rc != 0 )) || safe_remove_owned_dir "$WORK" "VPN work" || rc=1
  if (( rc == 0 )) && ! root_residue_empty; then
    echo "[vpngate] root residue remains after teardown" >&2
    rc=1
  fi
  (( rc == 0 )) || return "$rc"
  echo "[vpngate] down"
}

status(){
  if netns_ok; then
    openvpn_identity_matches \
      || { echo "[vpngate] inconsistent: tun exists without exact OpenVPN identity"; return 1; }
    local cur=""
    [[ -s "$CURF" ]] && cur=" via $(cut -f1,2,3 "$CURF" | tr '\t' ' ')"
    echo "[vpngate] up (netns '$NS')$cur. egress IP: $(egress_ipv4 || echo '?')"
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
