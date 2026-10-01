#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vpngate-connect.sh
. "$ROOT/vpngate-connect.sh"

# An explicitly empty frozen deny policy is valid and must survive the
# privileged helper boundary instead of being replaced with the built-in
# default. Use a clean shell because this test file has already sourced the
# helper's readonly constants.
GROK_BLOCKED_CC="" /bin/bash -c \
  '. "$1"; [[ -z "$GROK_BLOCKED_CC" ]]' _ "$ROOT/vpngate-connect.sh"

marker="VPNGATE_COMMAND_INTERPOLATION"
set +e
out="$(tcp_ok 8.8.8.8 "9; printf $marker #")"
rc=$?
set -e

if [[ "$out" == *"$marker"* || $rc -eq 0 ]]; then
  printf 'FAIL: untrusted port text reached bash -c (rc=%s, out=%q)\n' "$rc" "$out" >&2
  exit 1
fi

public_ipv4 8.8.8.8
! public_ipv4 127.0.0.1
! public_ipv4 100.64.0.1

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
config="$tmp/candidate.ovpn"
printf '%s\n' client 'remote 10.0.0.1 443' 'proto tcp-client' > "$config"
pin_remote "$config" 8.8.4.4
[[ "$REMOTE_PORT" == 443 && "$REMOTE_PROTO" == tcp-client ]]
grep -qxF 'remote 8.8.4.4 443' "$config"
! grep -q '10\.0\.0\.1' "$config"

printf '%s\n' client 'remote 1.1.1.1 443;touch' 'proto tcp' > "$config"
! pin_remote "$config" 8.8.4.4

printf '%s\n' client 'remote 1.1.1.1 443' 'remote 8.8.8.8 443' > "$config"
! pin_remote "$config" 8.8.4.4

printf '%s\n' client 'remote 1.1.1.1 443' 'proto udp' 'proto tcp' > "$config"
! pin_remote "$config" 8.8.4.4

# The root-executed OpenVPN sanitizer must reproduce OpenVPN's tokenization,
# retain only the closed allowlist, consume unknown blocks, and fail closed on
# either kind of unterminated inline block.  Exercise quoting, backslash
# escaping, the full isspace class, option spelling, and control-byte input.
SANITIZER="$ROOT/sanitize.awk"
hostile="$tmp/hostile.ovpn"
sanitized="$tmp/hostile.sanitized.ovpn"
expected="$tmp/hostile.expected.ovpn"
{
  printf '%s\n' 'client' 'remote "vpn.example" "443"' 'proto tcp-client'
  printf '%s\n' '"up" /tmp/ROOT_HOOK_SENTINEL' '\plugin /tmp/ROOT_HOOK_SENTINEL.so'
  printf '\vtls-verify /tmp/ROOT_HOOK_SENTINEL\n'
  printf '\froute-up /tmp/ROOT_HOOK_SENTINEL\n'
  printf '\rdown /tmp/ROOT_HOOK_SENTINEL\n'
  printf '%s\n' '--plugin /tmp/ROOT_HOOK_SENTINEL.so' 'script-security 2'
  printf '%s\n' 'setenv ROOT_HOOK_SENTINEL yes' 'management 127.0.0.1 1'
  printf '%s\n' 'auth-user-pass /tmp/ROOT_HOOK_SENTINEL' 'askpass /tmp/ROOT_HOOK_SENTINEL'
  printf '%s\n' '<unknown>' 'remote ROOT_HOOK_SENTINEL 9' '</unknown> trailing-data'
  printf '%s\n' '<ca>' 'ROOT_HOOK_SENTINEL_IS_INERT_PKI_DATA' '</ca> ignored-tail'
} > "$hostile"
LC_ALL=C awk -f "$SANITIZER" "$hostile" > "$sanitized"
printf '%s\n' \
  'client' \
  'remote vpn.example 443' \
  'proto tcp-client' \
  '<ca>' \
  'ROOT_HOOK_SENTINEL_IS_INERT_PKI_DATA' \
  '</ca>' > "$expected"
cmp -s "$expected" "$sanitized"

printf '%s\n' '<ca>' 'unterminated' > "$hostile"
! LC_ALL=C awk -f "$SANITIZER" "$hostile" > "$sanitized"
printf '%s\n' '<unknown>' 'unterminated' > "$hostile"
! LC_ALL=C awk -f "$SANITIZER" "$hostile" > "$sanitized"

/usr/bin/python3 - "$hostile" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(
    b"client\x00up /tmp/ROOT_HOOK_SENTINEL\n"
    b"remote 1.1.1.1 443\x00plugin /tmp/ROOT_HOOK_SENTINEL\n"
)
PY
set +e
LC_ALL=C awk -f "$SANITIZER" "$hostile" > "$sanitized"
nul_rc=$?
set -e
[[ "$nul_rc" -eq 3 ]]
[[ ! -s "$sanitized" ]]

! grep -Eq '(^|[[:space:]])pkill([[:space:]]|$)' "$ROOT/vpngate-connect.sh"
! grep -Eq 'apt-get|pacman|dnf[[:space:]]+install' "$ROOT/vpngate-connect.sh"
try_server_body="$(sed -n '/^try_server(){/,/^prepare_netns(){/p' "$ROOT/vpngate-connect.sh")"
grep -qF '/usr/sbin/openvpn --config' <<<"$try_server_body"
! grep -q -- '--daemon' <<<"$try_server_body"
# The persistent OpenVPN log drainer must not retain the root broker's captured
# stdout/stderr pipes after the short-lived helper returns.  Otherwise a
# successful tunnel can never reach EOF at the broker's bounded output gate.
/usr/bin/python3 - "$ROOT/vpngate-connect.sh" "$tmp/output-eof-work" <<'PY'
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import threading
import time

helper, work_text = sys.argv[1:]
work = Path(work_text)
pidfile = work / "fake-openvpn.pid"
parked = work / "helper.parked"
driver = r'''
set -euo pipefail
VPNGATE_CANDIDATES=1
VPNGATE_PER_TRY=1
. "$1"

WORK="$2"
mkdir -p -m 700 -- "$WORK"
OVPN="$WORK/vpngate.ovpn"
UPSH="$WORK/up.sh"
LOGF="$WORK/openvpn.log"
TEST_PIDF="$WORK/fake-openvpn.pid"
TEST_PARKED="$WORK/helper.parked"
candidate="$WORK/candidate.ovpn"
printf '%s\n' client 'remote 8.8.8.8 443' 'proto tcp' > "$candidate"

function /usr/sbin/openvpn {
  exec /usr/bin/python3 -c 'import time; time.sleep(30)'
}
remove_stale_identity_files(){ :; }
reserve_server_attempt(){ printf '1\n'; }
record_openvpn_identity(){ printf '%s\n' "$1" > "$TEST_PIDF"; }
netns_ok(){ return 0; }
openvpn_identity_matches(){ return 0; }

try_server "$candidate" US 8.8.8.8 443 tcp
fake_pid="$(cat "$TEST_PIDF")"
cleanup_fake(){
  kill "$fake_pid" 2>/dev/null || true
  wait "$fake_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup_fake EXIT

# Keep this process alive so the test can prove that captured EOF comes from
# descriptor closure, not from all descendants exiting.  Its own captures are
# closed first, matching the broker guard's acknowledgement wait.
exec 1>/dev/null 2>&1
printf 'parked\n' > "$TEST_PARKED"
IFS= read -r _ || true
'''

process = subprocess.Popen(
    ["/bin/bash", "-c", driver, "vpngate-eof-test", helper, str(work)],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    close_fds=True,
)
assert process.stdin is not None
assert process.stdout is not None
assert process.stderr is not None
captured = {"stdout": bytearray(), "stderr": bytearray()}


def drain(name, stream):
    try:
        while True:
            chunk = os.read(stream.fileno(), 65_536)
            if not chunk:
                return
            captured[name].extend(chunk)
    finally:
        stream.close()


drainers = [
    threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
    threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
]
for drainer in drainers:
    drainer.start()

fake_pid = None
fake_pidfd = None
try:
    ready_deadline = time.monotonic() + 5
    while not parked.exists():
        if process.poll() is not None:
            raise AssertionError(
                f"VPN EOF fixture exited before parking: rc={process.returncode}"
            )
        if time.monotonic() >= ready_deadline:
            raise AssertionError("VPN EOF fixture did not reach its parked state")
        time.sleep(0.01)

    raw_pid = pidfile.read_text(encoding="ascii").strip()
    if not raw_pid.isdecimal() or int(raw_pid) <= 1:
        raise AssertionError("VPN EOF fixture published an invalid fake PID")
    fake_pid = int(raw_pid)
    os.kill(fake_pid, 0)
    fake_pidfd = os.pidfd_open(fake_pid, 0)

    eof_deadline = time.monotonic() + 3
    for drainer in drainers:
        drainer.join(max(0.0, eof_deadline - time.monotonic()))
    if any(drainer.is_alive() for drainer in drainers):
        raise AssertionError(
            "persistent OpenVPN log writer retained broker capture descriptors"
        )
    if process.poll() is not None:
        raise AssertionError("VPN EOF fixture was not alive at captured EOF")
    os.kill(fake_pid, 0)
    if b"transition OpenVPN attempt 1/1" not in captured["stderr"]:
        raise AssertionError("real try_server path did not execute in VPN EOF fixture")
finally:
    try:
        process.stdin.write(b"cleanup\n")
        process.stdin.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        process.stdin.close()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    if fake_pid is None and pidfile.exists():
        cleanup_pid = pidfile.read_text(encoding="ascii").strip()
        if cleanup_pid.isdecimal() and int(cleanup_pid) > 1:
            fake_pid = int(cleanup_pid)
    if fake_pidfd is None and fake_pid is not None:
        try:
            fake_pidfd = os.pidfd_open(fake_pid, 0)
        except ProcessLookupError:
            pass
    if fake_pidfd is not None:
        exited, _, _ = select.select([fake_pidfd], [], [], 2)
        if not exited:
            signal.pidfd_send_signal(fake_pidfd, signal.SIGKILL)
            exited, _, _ = select.select([fake_pidfd], [], [], 2)
        os.close(fake_pidfd)
        if not exited:
            raise AssertionError("fake OpenVPN descendant survived fixture cleanup")
    if process.returncode != 0:
        raise AssertionError(f"VPN EOF fixture cleanup failed: rc={process.returncode}")
    for drainer in drainers:
        drainer.join(timeout=5)
    if any(drainer.is_alive() for drainer in drainers):
        raise AssertionError("VPN EOF capture drainer survived fixture cleanup")
PY
# Retain an exact source-shape assertion as a secondary, easy-to-diagnose gate.
grep -qF '> >(bounded_log_writer >/dev/null 2>&1) 2>&1 &' <<<"$try_server_body"
reap_body="$(sed -n '/^reap_openvpn(){/,/^}/p' "$ROOT/vpngate-connect.sh")"
! grep -qF 'ip link del "$TUN"' <<<"$reap_body"
has_daemon_arg --daemon arbitrary
has_daemon_arg --daemon=arbitrary
has_daemon_arg --daemon=
! has_daemon_arg --daemonize

# Every helper-produced byte stream has a fixed bound.  The bounded logger
# continues draining after the cap so OpenVPN cannot block on a full pipe.
WORK="$tmp/cap-work"; mkdir -m 700 "$WORK"
LOGF="$WORK/openvpn.log"
/usr/bin/python3 -c 'import os; os.write(1, b"x" * (8 * 1024 * 1024 + 4096))' \
  | bounded_log_writer
[[ "$(stat -c %s "$LOGF")" -eq "$LOG_MAX_BYTES" ]]

FAILF="$WORK/failed.tsv"
truncate -s "$STATE_MAX_BYTES" "$FAILF"
! append_failed_server 8.8.8.8:443
[[ "$(stat -c %s "$FAILF")" -eq "$STATE_MAX_BYTES" ]]

# Eight OpenVPN launches are one durable transition-global budget.  Different
# endpoints (including a refetched/changing catalog) cannot make a ninth launch
# reservable, and reinitializing the same provider scope preserves the count.
WORK="$tmp/attempt-work"; mkdir -m 700 "$WORK"
FAILF="$WORK/failed.tsv"; ATTEMPTF="$WORK/attempts.tsv"
VPNGATE_ATTEMPT_SCOPE="$(printf 'a%.0s' {1..64})"
initialize_attempt_budget 0
for index in $(seq 1 "$CAND_MAX"); do
  reserve_server_attempt US "8.8.8.$index" "$((4000 + index))" tcp >/dev/null
done
[[ "$(grep -c '^attempt	' "$ATTEMPTF")" -eq "$CAND_MAX" ]]
initialize_attempt_budget 0
[[ "$(grep -c '^attempt	' "$ATTEMPTF")" -eq "$CAND_MAX" ]]
! reserve_server_attempt JP 1.1.1.1 443 udp >/dev/null
[[ "$(grep -c '^attempt	' "$ATTEMPTF")" -eq "$CAND_MAX" ]]
printf 'attempt\t9\tUS\tnot-an-ip\t443\ttcp\n' >> "$ATTEMPTF"
! initialize_attempt_budget 0

LISTF="$WORK/list.csv"; PARSEDF="$WORK/parsed.tsv"
curl(){
  /usr/bin/python3 -c 'import os; os.write(1, b"A" * (8 * 1024 * 1024 + 1))'
}
! fetch_list
[[ ! -e "$LISTF" ]]
unset -f curl

CANDF="$WORK/candidates.tsv"; VPNGATE_COUNTRIES=US; VPNGATE_PREFER=""; GROK_BLOCKED_CC="DE"
/usr/bin/python3 - "$PARSEDF" "$CONFIG_B64_MAX_BYTES" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_text(
    "US\t8.8.8.8\t1\t1\t" + "A" * (int(sys.argv[2]) + 1) + "\n",
    encoding="ascii",
)
PY
! build_candidates
! compgen -G "$WORK/cand-*.ovpn" >/dev/null

# Country ordering must honor the explicit allowlist and the frozen deny as
# separate boundaries. Available-but-unlisted countries are not appended in
# explicit mode, and blocked entries never survive either explicit or default
# selection.
policy_matrix="$tmp/policy-matrix.tsv"
printf '%s\n' \
  $'DE\t1.1.1.1\t10\t1\tQQ==' \
  $'JP\t1.1.1.2\t9\t1\tQQ==' \
  $'US\t1.1.1.3\t8\t1\tQQ==' \
  $'CN\t1.1.1.4\t7\t1\tQQ==' \
  $'IR\t1.1.1.5\t6\t1\tQQ==' \
  $'KP\t1.1.1.6\t5\t1\tQQ==' \
  $'TM\t1.1.1.7\t4\t1\tQQ==' \
  $'VE\t1.1.1.8\t3\t1\tQQ==' > "$policy_matrix"
(
  PARSEDF="$policy_matrix"
  VPNGATE_COUNTRIES="JP CN"
  VPNGATE_PREFER=""
  GROK_BLOCKED_CC="CN IR KP TM VE"
  mapfile -t ordered < <(country_order)
  [[ "${ordered[*]}" == JP ]]
)
(
  PARSEDF="$policy_matrix"
  VPNGATE_COUNTRIES="DE JP"
  VPNGATE_PREFER=""
  GROK_BLOCKED_CC="DE"
  mapfile -t ordered < <(country_order)
  [[ "${ordered[*]}" == JP ]]
)
(
  PARSEDF="$policy_matrix"
  VPNGATE_COUNTRIES=""
  VPNGATE_PREFER="DE CN IR KP TM VE JP"
  GROK_BLOCKED_CC="CN IR KP TM VE"
  mapfile -t ordered < <(country_order)
  [[ " ${ordered[*]} " == *" DE "* ]]
  [[ " ${ordered[*]} " == *" JP "* ]]
  [[ " ${ordered[*]} " == *" US "* ]]
  for blocked_country in CN IR KP TM VE; do
    [[ " ${ordered[*]} " != *" $blocked_country "* ]]
  done
)

# Dead endpoints consume the same finite probe budget as reachable endpoints,
# keeping the broker's derived timeout valid even for a hostile catalog.
/usr/bin/python3 - "$PARSEDF" <<'PY'
import base64, pathlib, sys
config = base64.b64encode(b"client\nremote 1.1.1.1 443\nproto tcp\n").decode("ascii")
pathlib.Path(sys.argv[1]).write_text("".join(
    f"US\t1.1.1.{index}\t{100-index}\t1\t{config}\n" for index in range(1, 21)
), encoding="ascii")
PY
probe_count=0
tcp_ok(){ probe_count=$((probe_count+1)); return 1; }
! build_candidates
[[ "$probe_count" -eq "$CAND_MAX" ]]
unset -f tcp_ok

# START and BOOT may be visible after a crash, but PID is the final commit
# marker.  An injected rename-boundary failure must never publish PID.
WORK="$tmp/identity-work"; mkdir -m 700 "$WORK"
OVPN="$WORK/vpngate.ovpn"; UPSH="$WORK/up.sh"; TUN=tun-grok
PIDF="$WORK/openvpn.pid"; STARTF="$WORK/openvpn.start"; BOOTF="$WORK/openvpn.boot"
GROK_TESTING=1; VPNGATE_TEST_FAIL_IDENTITY_STAGE=before-pid
bash -c 'exec -a /usr/sbin/openvpn /usr/bin/python3 -c '\''import time; time.sleep(30)'\'' --config "$1" --dev "$2" --up "$3"' \
  _ "$OVPN" "$TUN" "$UPSH" & identity_process=$!
! record_openvpn_identity "$identity_process"
[[ ! -e "$PIDF" && -f "$STARTF" && -f "$BOOTF" ]]
kill -0 "$identity_process"
unset VPNGATE_TEST_FAIL_IDENTITY_STAGE GROK_TESTING
remove_stale_identity_files
identity_start="$(proc_start_ticks "$identity_process")"
identity_boot="$(cat /proc/sys/kernel/random/boot_id)"
signal_openvpn_pidfd "$identity_process" "$identity_start" "$identity_boot" TERM
wait "$identity_process" 2>/dev/null || true
! kill -0 "$identity_process" 2>/dev/null

# A poisoned identity record naming an unrelated live process must never cause
# name-based or PID-only teardown.
WORK="$tmp/foreign-work"
mkdir -m 700 "$WORK"
PIDF="$WORK/openvpn.pid"; STARTF="$WORK/openvpn.start"; BOOTF="$WORK/openvpn.boot"
OVPN="$WORK/vpngate.ovpn"; TUN=tun-grok
sleep 30 & foreign=$!
foreign_start="$(proc_start_ticks "$foreign")"
printf '%s\n' "$foreign" > "$PIDF"
printf '%s\n' "$foreign_start" > "$STARTF"
cat /proc/sys/kernel/random/boot_id > "$BOOTF"
chmod 600 "$PIDF" "$STARTF" "$BOOTF"
! kill_openvpn_exact
kill -0 "$foreign"
! reap_openvpn
kill -0 "$foreign"
current_boot="$(cat /proc/sys/kernel/random/boot_id)"
if [[ "${current_boot:0:1}" == 0 ]]; then old_boot="1${current_boot:1}"; else old_boot="0${current_boot:1}"; fi
printf '%s\n' "$old_boot" > "$BOOTF"
kill_openvpn_exact
kill -0 "$foreign"
[[ ! -e "$PIDF" && ! -e "$STARTF" && ! -e "$BOOTF" ]]
kill "$foreign"; wait "$foreign" 2>/dev/null || true

# A successful down removes the complete dedicated root artifact graph, not
# just the current candidate and pidfile.  A symlink inside the work directory
# is unlinked without following it.
WORK="$tmp/residue-work"
OVPN="$WORK/vpngate.ovpn"; UPSH="$WORK/up.sh"
PIDF="$WORK/openvpn.pid"; STARTF="$WORK/openvpn.start"; BOOTF="$WORK/openvpn.boot"
LOGF="$WORK/openvpn.log"; CANDF="$WORK/candidates.tsv"
CURF="$WORK/current.tsv"; FAILF="$WORK/failed.tsv"
ATTEMPTF="$WORK/attempts.tsv"
LISTF="$WORK/list.csv"; PARSEDF="$WORK/parsed.tsv"
NETNS_DIR="$tmp/netns/grokvpn"
mkdir -p -m 700 "$WORK/nested" "$NETNS_DIR"
for artifact in "$OVPN" "$UPSH" "$BOOTF" "$LOGF" "$CANDF" "$CURF" "$FAILF" "$ATTEMPTF" "$LISTF" "$PARSEDF" \
                "$WORK/cand-US-8.8.8.8.ovpn" "$WORK/nested/crash.tmp"; do
  printf 'artifact\n' > "$artifact"
done
printf '%s\n' 2147483647 > "$PIDF"
printf '%s\n' 1 > "$STARTF"
cat /proc/sys/kernel/random/boot_id > "$BOOTF"
chmod 600 "$PIDF" "$STARTF" "$BOOTF"
sentinel="$tmp/outside-sentinel"
printf 'keep\n' > "$sentinel"
ln -s "$sentinel" "$WORK/nested/external-link"
fake_ns=1; fake_tun=1
need_root(){ :; }
ip(){
  if [[ "${1:-}" == netns && "${2:-}" == del ]]; then fake_ns=0; fake_tun=0; return 0; fi
  if [[ "${1:-}" == netns && "${2:-}" == exec && "${4:-}" == true ]]; then (( fake_ns == 1 )); return; fi
  if [[ "${1:-}" == link && "${2:-}" == show ]]; then (( fake_tun == 1 )); return; fi
  return 1
}
down >/dev/null
[[ ! -e "$WORK" && ! -L "$WORK" && ! -e "$NETNS_DIR" && ! -L "$NETNS_DIR" ]]
[[ "$(cat "$sentinel")" == keep ]]

echo "PASS: VPN Gate input, exact process identity, unrelated immunity, and root residue hold"
