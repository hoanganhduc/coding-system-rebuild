#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LAUNCHER="$DIR/run-isolated.sh"
LEDGER_HELPER="$DIR/verification_ledger.py"

die() {
  echo "grok-test-preflight: $*" >&2
  exit 2
}

if [[ $# -eq 0 ]]; then
  exec /bin/bash "$LAUNCHER" --launch
fi
[[ $# -eq 1 && "$1" == "--isolated-payload" ]] \
  || die "tests accept no caller arguments; use the mandatory isolation launcher"
[[ "${GROK_TEST_ISOLATED:-0}" == "1" ]] \
  || die "isolated payload marker is absent"

verify_environment() {
  python3 - <<'PY'
import os

allowed = {
    "GROK_EXPECTED_CGROUP_REL",
    "GROK_EXPECTED_SUBREAPER_PID",
    "GROK_OUTER_CGROUP_NS",
    "GROK_OUTER_NET_NS",
    "GROK_OUTER_PID_NS",
    "GROK_OUTER_USER_NS",
    "GROK_TEST_CANDIDATE",
    "GROK_TEST_ISOLATION_BOUNDARY",
    "GROK_TEST_ISOLATED",
    "GROK_TEST_LEDGER",
    "GROK_TEST_SUBREAPER",
    "HOME",
    "LANG",
    "LC_ALL",
    "LOGNAME",
    "OLDPWD",
    "PATH",
    "PWD",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
    "SHLVL",
    "TMPDIR",
    "TZ",
    "USER",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
    "_",
}
unexpected = sorted(set(os.environ) - allowed)
if unexpected:
    raise SystemExit("unexpected inherited environment names: " + ",".join(unexpected))
expected = {
    "HOME": "/home/csr-test",
    "LOGNAME": "csr-test",
    "USER": "csr-test",
    "XDG_CACHE_HOME": "/home/csr-test/.cache",
    "XDG_CONFIG_HOME": "/home/csr-test/.config",
    "XDG_DATA_HOME": "/home/csr-test/.local/share",
    "XDG_RUNTIME_DIR": "/home/csr-test/.xdg-runtime",
    "XDG_STATE_HOME": "/home/csr-test/.local/state",
    "GROK_TEST_CANDIDATE": "/workspace/coding-system-rebuild",
    "GROK_TEST_LEDGER": "/artifacts/grok-test-results.jsonl",
    "GROK_TEST_ISOLATION_BOUNDARY": "reviewed-launcher-post-env-i-v1",
}
wrong = [name for name, value in expected.items() if os.environ.get(name) != value]
if wrong:
    raise SystemExit("synthetic environment mismatch: " + ",".join(sorted(wrong)))
for forbidden in (
    "DBUS_SESSION_BUS_ADDRESS",
    "SSH_AUTH_SOCK",
    "SUDO_COMMAND",
    "SUDO_GID",
    "SUDO_UID",
    "SUDO_USER",
):
    if forbidden in os.environ:
        raise SystemExit("forbidden live environment inherited: " + forbidden)
PY
}

verify_namespaces() {
  local kind current outer
  for kind in pid net user cgroup; do
    current="$(/usr/bin/readlink -- "/proc/self/ns/$kind")"
    case "$kind" in
      pid) outer="$GROK_OUTER_PID_NS" ;;
      net) outer="$GROK_OUTER_NET_NS" ;;
      user) outer="$GROK_OUTER_USER_NS" ;;
      cgroup) outer="$GROK_OUTER_CGROUP_NS" ;;
    esac
    [[ "$current" != "$outer" ]] \
      || die "$kind namespace is shared with the transient-unit host context"
  done
  [[ "$(< /proc/self/cgroup)" == "0::$GROK_EXPECTED_CGROUP_REL" ]] \
    || die "payload is outside its exact delegated cgroup"
  if [[ "${GROK_TEST_SUBREAPER:-0}" == "1" ]]; then
    [[ "${GROK_EXPECTED_SUBREAPER_PID:-}" =~ ^[0-9]+$ \
        && "$(/usr/bin/awk '{print $4}' "/proc/$$/stat")" == "$GROK_EXPECTED_SUBREAPER_PID" ]] \
      || die "test shell is not a direct child of the exact namespace subreaper"
  else
    [[ "$(/usr/bin/awk '{print $4}' "/proc/$$/stat")" == "1" ]] \
      || die "initial isolated payload is not a direct child of the namespace PID 1 monitor"
  fi
}

verify_network() {
  local links
  links="$(/usr/sbin/ip -o link show \
    | /usr/bin/awk -F': ' '{name=$2; sub(/@.*/, "", name); print name}')"
  [[ "$links" == "lo" ]] || die "private network namespace exposes a non-loopback link"
  /usr/sbin/ip -o link show dev lo | /usr/bin/grep -q '<LOOPBACK,UP' \
    || die "private loopback is down"
  [[ -z "$(/usr/sbin/ip -4 route show default)" ]] \
    || die "private network namespace has an IPv4 default route"
  [[ -z "$(/usr/sbin/ip -6 route show default)" ]] \
    || die "private network namespace has an IPv6 default route"
}

verify_mounts_and_masks() {
  local probe
  [[ "$(< /etc/machine-id)" == "0123456789abcdef0123456789abcdef" ]] \
    || die "synthetic machine identity is unavailable"
  [[ "$(< /proc/sys/kernel/random/boot_id)" == \
      "11111111-1111-4111-8111-111111111111" ]] \
    || die "synthetic boot identity is unavailable"
  python3 - <<'PY'
from pathlib import Path

required = {
    "/workspace/coding-system-rebuild": (None, "ro"),
    "/etc": (None, "ro"),
    "/usr/local": (None, "ro"),
    "/run": ("tmpfs", "rw"),
    "/tmp": ("tmpfs", "rw"),
    "/var": ("tmpfs", "rw"),
    "/sys/fs/cgroup": ("cgroup2", "rw"),
}
observed = {}
for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
    fields = line.split()
    try:
        separator = fields.index("-")
    except ValueError:
        continue
    mountpoint = fields[4].replace("\\040", " ")
    observed[mountpoint] = (fields[separator + 1], set(fields[5].split(",")))
for mountpoint, (filesystem, mode) in required.items():
    if mountpoint not in observed:
        raise SystemExit("required isolated mount is absent: " + mountpoint)
    actual_filesystem, options = observed[mountpoint]
    if filesystem is not None and actual_filesystem != filesystem:
        raise SystemExit("isolated mount has the wrong filesystem: " + mountpoint)
    if mode not in options:
        raise SystemExit("isolated mount has the wrong access mode: " + mountpoint)
PY
  probe="$GROK_TEST_CANDIDATE/.grok-verification-write-probe-$$"
  if ( : > "$probe" ) 2>/dev/null; then
    /usr/bin/rm -f -- "$probe"
    die "candidate repository is writable inside verification"
  fi
  [[ -z "$(/usr/bin/find /usr/local -mindepth 1 -print -quit 2>/dev/null)" ]] \
    || die "live /usr/local content is visible inside verification"
  for path in \
    /usr/local/libexec/grok-proxy \
    /usr/local/bin/grok-remote \
    /var/lib/grok-proxy \
    /run/grok-proxy \
    /run/grok-vpngate
  do
    [[ ! -e "$path" && ! -L "$path" ]] \
      || die "live Grok path is visible inside verification: $path"
  done
  [[ ! -S "$XDG_RUNTIME_DIR/bus" && ! -e /run/user ]] \
    || die "a live user bus is visible inside verification"
  [[ -z "$(/usr/bin/find /run /tmp -xdev -type s -iname '*grok*' -print -quit 2>/dev/null)" ]] \
    || die "a live Grok socket is visible inside verification"
}

verify_synthetic_home() {
  local path owner mode
  for path in \
    "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" \
    "$XDG_RUNTIME_DIR" "$XDG_STATE_HOME" /artifacts
  do
    [[ -d "$path" && ! -L "$path" ]] \
      || die "synthetic home/XDG path is not one real directory: $path"
    owner="$(/usr/bin/stat -c '%u' -- "$path")"
    mode="$(/usr/bin/stat -c '%a' -- "$path")"
    [[ "$owner" == "1000" && "$mode" == "700" ]] \
      || die "synthetic home/XDG path has unsafe ownership or mode: $path"
  done
}

verify_capabilities_dropped() {
  python3 - <<'PY'
from pathlib import Path

values = {}
for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
    if ":" in line:
        name, value = line.split(":", 1)
        values[name] = value.strip()
for name in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"):
    if int(values.get(name, "1"), 16) != 0:
        raise SystemExit("payload retained a Linux capability: " + name)
if values.get("NoNewPrivs") != "1":
    raise SystemExit("payload does not enforce no-new-privileges")
PY
}

verify_delegated_cgroup() {
  PYTHONPATH="$GROK_TEST_CANDIDATE/system/grok-proxy" python3 - <<'PY'
import os
from pathlib import Path

from grok_ms.process_scope import LinuxCgroupV2Scope

backend = LinuxCgroupV2Scope()
planned = backend.plan()
handle = None
try:
    handle = backend.create(planned)
finally:
    if handle is not None:
        handle.close()
    scope = Path(planned.scope_path)
    if scope.exists():
        try:
            (scope / "cgroup.kill").write_text("1\n", encoding="ascii")
        except OSError:
            pass
        os.rmdir(scope)
PY
}

verify_cgroup_limit_schema() {
  PYTHONPATH="$GROK_TEST_CANDIDATE/system/grok-proxy" python3 - <<'PY'
from grok_ms import qualification_verifier

limits = qualification_verifier.host_limits()
if not qualification_verifier._host_limits_valid(limits):
    raise SystemExit("exact isolated cgroup control schema is invalid")
PY
}

run_preflight() {
  [[ -x /usr/bin/python3 && -f "$LEDGER_HELPER" ]] \
    || die "fixed ledger helper is unavailable"
  if [[ "${GROK_TEST_SUBREAPER:-0}" != "1" ]]; then
    python3 "$LEDGER_HELPER" selftest \
      || die "fixed regression inventory self-test failed"
  fi
  verify_environment || die "environment scrub verification failed"
  verify_namespaces
  verify_network
  verify_mounts_and_masks
  verify_synthetic_home
  verify_capabilities_dropped || die "capability-drop verification failed"
  verify_cgroup_limit_schema || die "cgroup control-schema preflight failed"
  verify_delegated_cgroup || die "delegated cgroup preflight failed; no test is skipped"
}

run_preflight

if [[ "${GROK_TEST_SUBREAPER:-0}" != "1" ]]; then
  exec /usr/bin/env GROK_TEST_SUBREAPER=1 GROK_EXPECTED_SUBREAPER_PID="$$" \
    python3 "$DIR/subreaper_run.py" /bin/bash "$0" --isolated-payload
fi

LEDGER="$GROK_TEST_LEDGER"
unset GROK_TEST_LEDGER
if [[ -e "$LEDGER" || -L "$LEDGER" ]]; then
  die "result ledger existed before the fixed inventory started"
fi
(umask 077; : > "$LEDGER")

dump_failed_ledger() {
  local rc=$?
  if (( rc != 0 )); then
    echo "ERROR: Grok regression inventory failed; the trusted launcher will publish the partial exact ledger" >&2
  fi
}
trap dump_failed_ledger EXIT

python3 "$LEDGER_HELPER" record \
  --ledger "$LEDGER" \
  --case-id grok.preflight.isolation \
  --kind preflight \
  --status passed \
  --returncode 0

run_shell_case() {
  local case_id="$1" test_file="$2" rc
  echo "== [$case_id] $test_file =="
  if /bin/bash "$DIR/$test_file"; then
    python3 "$LEDGER_HELPER" record \
      --ledger "$LEDGER" --case-id "$case_id" --kind shell \
      --status passed --returncode 0
    return 0
  else
    rc=$?
    python3 "$LEDGER_HELPER" record \
      --ledger "$LEDGER" --case-id "$case_id" --kind shell \
      --status failed --returncode "$rc"
    return "$rc"
  fi
}

while IFS=$'\t' read -r case_id test_file; do
  [[ -n "$case_id" && -n "$test_file" ]] \
    || die "fixed shell case inventory is malformed"
  run_shell_case "$case_id" "$test_file"
done < <(python3 "$LEDGER_HELPER" list --kind shell)

while IFS=$'\t' read -r case_id test_file; do
  [[ -n "$case_id" && -n "$test_file" ]] \
    || die "fixed Python-script case inventory is malformed"
  echo "== [$case_id] $test_file =="
  if python3 "$DIR/$test_file"; then
    python3 "$LEDGER_HELPER" record \
      --ledger "$LEDGER" --case-id "$case_id" --kind python-script \
      --status passed --returncode 0
  else
    rc=$?
    python3 "$LEDGER_HELPER" record \
      --ledger "$LEDGER" --case-id "$case_id" --kind python-script \
      --status failed --returncode "$rc"
    exit "$rc"
  fi
done < <(python3 "$LEDGER_HELPER" list --kind python-script)

while IFS=$'\t' read -r case_id test_file; do
  [[ -n "$case_id" && -n "$test_file" ]] \
    || die "fixed unittest case inventory is malformed"
  echo "== [$case_id] $test_file =="
  python3 "$LEDGER_HELPER" run-unittest \
    --ledger "$LEDGER" --case-id "$case_id" --path "$DIR/$test_file"
done < <(python3 "$LEDGER_HELPER" list --kind unittest)

python3 "$LEDGER_HELPER" verify --ledger "$LEDGER"
echo "All grok-proxy regression tests passed; the trusted launcher will publish the exact ledger."
trap - EXIT
