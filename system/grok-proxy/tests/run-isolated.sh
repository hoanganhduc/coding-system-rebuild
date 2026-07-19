#!/usr/bin/env bash
# Mandatory fail-closed isolation launcher for the Grok regression inventory.
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"
REPO="$(cd -P "$SCRIPT_DIR/../../.." && pwd -P)"
CANDIDATE_MOUNT="/workspace/coding-system-rebuild"
BOUNDARY_MARKER="reviewed-launcher-post-env-i-v1"
CLEANUP_SCRATCH=""
CLEANUP_SERVICE=""
CLEANUP_LAUNCHER=""
CLEANUP_PAYLOAD=""
OUTPUT_DIR=""

die() {
  echo "grok-test-isolation: $*" >&2
  exit 2
}

require_executable() {
  [[ -x "$1" ]] || die "required executable is unavailable: $1"
}

service_cgroup_path() {
  local line relative root candidate
  IFS= read -r line < /proc/self/cgroup || die "cannot read service cgroup membership"
  [[ "$line" =~ ^0::(/.*)$ ]] \
    || die "transient unit is not in one unified cgroup-v2 hierarchy"
  relative="${BASH_REMATCH[1]}"
  root="$(/usr/bin/readlink -e -- /sys/fs/cgroup)" \
    || die "cgroup-v2 root is unavailable"
  candidate="$(/usr/bin/readlink -e -- "$root/${relative#/}")" \
    || die "transient unit cgroup is unavailable"
  [[ "$candidate" == "$root/"* ]] \
    || die "transient unit did not receive a dedicated cgroup"
  printf '%s\n' "$candidate"
}

require_numeric_cap() {
  local path maximum value
  path="$1"
  maximum="$2"
  [[ -r "$path" ]] || die "required cgroup cap is unavailable: $path"
  IFS= read -r value < "$path" || die "cannot read cgroup cap: $path"
  [[ "$value" =~ ^[0-9]+$ ]] || die "cgroup cap is not finite: $path"
  (( value <= maximum )) || die "cgroup cap exceeds launcher policy: $path"
}

verify_service_cgroup() {
  local scope owner quota period extra name
  local -a controls=(
    cgroup.max.depth cgroup.max.descendants
    memory.current memory.peak memory.high memory.max
    memory.swap.high memory.swap.max memory.zswap.max memory.events
    pids.current pids.peak pids.max pids.events
    cpu.idle cpu.max cpu.max.burst cpu.uclamp.max cpu.uclamp.min
    cpu.weight cpu.stat
  )
  scope="$1"
  owner="$(/usr/bin/stat -c '%u' -- "$scope")" \
    || die "cannot inspect delegated cgroup ownership"
  [[ "$owner" == "$(/usr/bin/id -u)" ]] \
    || die "transient unit cgroup is not delegated to the invoking user"
  [[ -w "$scope/cgroup.procs" ]] \
    || die "transient unit cgroup is not delegated writable"
  for name in "${controls[@]}"; do
    [[ -r "$scope/$name" ]] \
      || die "transient unit lacks required cgroup control: $name"
  done
  require_numeric_cap "$scope/memory.max" 6442450944
  require_numeric_cap "$scope/pids.max" 2048
  [[ "$(<"$scope/memory.swap.max")" == "0" ]] \
    || die "transient unit swap cap is not zero"
  read -r quota period extra < "$scope/cpu.max" \
    || die "cannot read transient unit CPU cap"
  [[ -z "${extra:-}" && "$quota" =~ ^[0-9]+$ && "$period" =~ ^[0-9]+$ ]] \
    || die "transient unit CPU cap is not finite"
  (( quota <= period * 4 )) \
    || die "transient unit CPU cap exceeds 400 percent"
}

cleanup_payload_cgroup() {
  local payload_path="$1" populated attempt
  [[ -d "$payload_path" ]] || return 0
  if [[ -r "$payload_path/cgroup.events" ]]; then
    populated="$(/usr/bin/awk '$1 == "populated" {print $2}' "$payload_path/cgroup.events")"
    if [[ "$populated" == "1" && -w "$payload_path/cgroup.kill" ]]; then
      printf '1\n' > "$payload_path/cgroup.kill" || true
    fi
    for attempt in $(/usr/bin/seq 1 100); do
      populated="$(/usr/bin/awk '$1 == "populated" {print $2}' "$payload_path/cgroup.events" 2>/dev/null || true)"
      [[ "$populated" == "0" ]] && break
      /usr/bin/sleep 0.01
    done
  fi
  /usr/bin/rmdir -- "$payload_path" 2>/dev/null \
    || { echo "grok-test-isolation: payload cgroup was not empty" >&2; return 2; }
}

cleanup_delegated_hierarchy() {
  local -a members=()
  [[ -n "$CLEANUP_SERVICE" && -n "$CLEANUP_LAUNCHER" ]] || return 0
  if [[ -n "$CLEANUP_PAYLOAD" ]]; then
    cleanup_payload_cgroup "$CLEANUP_PAYLOAD" || return 2
  fi
  mapfile -t members < "$CLEANUP_LAUNCHER/cgroup.procs" \
    || { echo "grok-test-isolation: cannot inspect launcher cgroup" >&2; return 2; }
  [[ ${#members[@]} -eq 1 && "${members[0]}" == "$$" ]] \
    || { echo "grok-test-isolation: launcher cgroup retained an unexpected process" >&2; return 2; }
  printf '%s\n' '-cpu -memory -pids' > "$CLEANUP_SERVICE/cgroup.subtree_control" \
    || { echo "grok-test-isolation: cannot disable delegated controllers" >&2; return 2; }
  [[ -z "$(<"$CLEANUP_SERVICE/cgroup.subtree_control")" ]] \
    || { echo "grok-test-isolation: delegated controllers remain enabled" >&2; return 2; }
  printf '%s\n' "$$" > "$CLEANUP_SERVICE/cgroup.procs" \
    || { echo "grok-test-isolation: cannot leave launcher cgroup" >&2; return 2; }
  /usr/bin/rmdir -- "$CLEANUP_LAUNCHER" \
    || { echo "grok-test-isolation: cannot remove launcher cgroup" >&2; return 2; }
  CLEANUP_PAYLOAD=""
  CLEANUP_LAUNCHER=""
  CLEANUP_SERVICE=""
}

cleanup_inside_unit() {
  local prior_rc=$? cleanup_rc=0
  trap - EXIT
  set +e
  cleanup_delegated_hierarchy || cleanup_rc=2
  if [[ -n "$CLEANUP_SCRATCH" && "$CLEANUP_SCRATCH" == /tmp/grok-coding-verify.* ]]; then
    /usr/bin/chmod -R u+w -- "$CLEANUP_SCRATCH" 2>/dev/null || cleanup_rc=2
    /usr/bin/rm -rf -- "$CLEANUP_SCRATCH" || cleanup_rc=2
  fi
  if (( prior_rc != 0 )); then
    exit "$prior_rc"
  fi
  exit "$cleanup_rc"
}

verify_reviewed_launcher_boundary() {
  local path owner group links mode
  for path in \
    "$SCRIPT_PATH" \
    "$SCRIPT_DIR/run.sh" \
    "$SCRIPT_DIR/verification_ledger.py"
  do
    [[ -f "$path" && ! -L "$path" ]] \
      || die "reviewed launcher boundary contains an unsafe file: $path"
    read -r owner group links mode < <(/usr/bin/stat -c '%u %g %h %a' -- "$path") \
      || die "cannot inspect reviewed launcher boundary: $path"
    [[ "$owner" == "$(/usr/bin/id -u)" \
        && "$group" == "$(/usr/bin/id -g)" \
        && "$links" == "1" ]] \
      || die "reviewed launcher boundary has an unexpected identity: $path"
    (( (8#$mode & 0002) == 0 )) \
      || die "reviewed launcher boundary is world-writable: $path"
  done
}

validate_output_directory() {
  local path canonical owner group links mode
  path="$1"
  [[ "$path" == /* && ${#path} -le 4096 && -d "$path" && ! -L "$path" ]] \
    || die "result output directory is not one real absolute directory"
  canonical="$(/usr/bin/readlink -e -- "$path")" \
    || die "cannot resolve result output directory"
  [[ "$canonical" == "$path" ]] \
    || die "result output directory is not canonical"
  read -r owner group links mode < <(/usr/bin/stat -c '%u %g %h %a' -- "$path") \
    || die "cannot inspect result output directory"
  [[ "$owner" == "$(/usr/bin/id -u)" \
      && "$group" == "$(/usr/bin/id -g)" \
      && "$links" == "2" \
      && "$mode" == "700" ]] \
    || die "result output directory has an unsafe identity or mode"
  [[ -z "$(/usr/bin/find "$path" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
    || die "result output directory is not empty"
}

prepare_output_directory() {
  local requested
  requested="${GROK_TEST_OUTPUT_DIR:-}"
  if [[ -n "$requested" ]]; then
    OUTPUT_DIR="$requested"
  else
    OUTPUT_DIR="$(/usr/bin/mktemp -d /tmp/grok-verification-results.XXXXXX)" \
      || die "cannot create result output directory"
    /usr/bin/chmod 700 "$OUTPUT_DIR"
  fi
  validate_output_directory "$OUTPUT_DIR"
  printf 'grok-test-results: output-directory=%s\n' "$OUTPUT_DIR"
}

launch_transient_unit() {
  local uid runtime_dir unit
  require_executable /usr/bin/systemd-run
  require_executable /usr/bin/unshare
  require_executable /usr/bin/bwrap
  require_executable /usr/sbin/ip
  verify_reviewed_launcher_boundary
  prepare_output_directory
  [[ ! -L "$REPO" && -f "$REPO/system/grok-proxy/tests/run.sh" ]] \
    || die "candidate repository path is not one real source tree"

  uid="$(/usr/bin/id -u)"
  runtime_dir="/run/user/$uid"
  [[ -d "$runtime_dir" && -S "$runtime_dir/bus" ]] \
    || die "an active systemd user manager is required; no test is skipped"
  unit="grok-coding-verify-${uid}-$$-${RANDOM}"

  # This reviewed, caller-owned, single-link launcher is the explicit
  # pre-isolation trust boundary.  Its only caller-state use is the user bus
  # needed to create and monitor the unit.  Guarantees about scrubbed caller
  # state begin at env -i; inside_transient_unit and run.sh assert that boundary.
  XDG_RUNTIME_DIR="$runtime_dir" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus" \
  exec /usr/bin/systemd-run --user --quiet --wait --collect --pipe \
    --expand-environment=no \
    --service-type=exec --unit="$unit" \
    --property=Delegate=yes \
    --property=MemoryMax=6442450944 \
    --property=MemorySwapMax=0 \
    --property=TasksMax=2048 \
    --property=CPUQuota=400% \
    --property=RuntimeMaxSec=45min \
    --property=TimeoutStopSec=30s \
    --property=KillMode=control-group \
    --property=OOMPolicy=stop \
    --property=UMask=0022 \
    /usr/bin/env -i \
      PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      LANG=C.UTF-8 LC_ALL=C.UTF-8 \
      GROK_TEST_ISOLATION_BOUNDARY="$BOUNDARY_MARKER" \
      /bin/bash "$SCRIPT_PATH" --inside-unit "$REPO" "$OUTPUT_DIR"
}

inside_transient_unit() {
  local requested_repo canonical_repo output_dir service_scope
  local host_pid_ns host_net_ns host_user_ns host_cgroup_ns
  [[ $# -eq 2 ]] || die "invalid transient-unit launcher arguments"
  [[ "${GROK_TEST_ISOLATION_BOUNDARY:-}" == "$BOUNDARY_MARKER" ]] \
    || die "reviewed launcher trust-boundary marker is absent"
  [[ ! -v HOME && ! -v XDG_RUNTIME_DIR && ! -v DBUS_SESSION_BUS_ADDRESS ]] \
    || die "the transient unit inherited caller home or bus state"
  requested_repo="$1"
  output_dir="$2"
  canonical_repo="$(/usr/bin/readlink -e -- "$requested_repo")" \
    || die "candidate repository disappeared before isolation"
  [[ "$canonical_repo" == "$REPO" && ! -L "$requested_repo" ]] \
    || die "candidate repository identity changed before isolation"
  validate_output_directory "$output_dir"

  service_scope="$(service_cgroup_path)"
  verify_service_cgroup "$service_scope"
  printf '16\n' > "$service_scope/cgroup.max.depth" \
    || die "cannot cap isolated cgroup depth"
  printf '512\n' > "$service_scope/cgroup.max.descendants" \
    || die "cannot cap isolated cgroup descendants"
  [[ "$(<"$service_scope/cgroup.max.depth")" == "16" \
      && "$(<"$service_scope/cgroup.max.descendants")" == "512" ]] \
    || die "isolated cgroup hierarchy caps were not applied"

  host_pid_ns="$(/usr/bin/readlink -- /proc/self/ns/pid)"
  host_net_ns="$(/usr/bin/readlink -- /proc/self/ns/net)"
  host_user_ns="$(/usr/bin/readlink -- /proc/self/ns/user)"
  host_cgroup_ns="$(/usr/bin/readlink -- /proc/self/ns/cgroup)"
  exec /usr/bin/unshare --user --map-current-user --cgroup \
    /bin/bash "$SCRIPT_PATH" --inside-private-setup \
      "$canonical_repo" "$output_dir" "$service_scope" \
      "$host_pid_ns" "$host_net_ns" "$host_user_ns" "$host_cgroup_ns"
}

inside_private_setup() {
  local canonical_repo output_dir service_scope
  local outer_pid_ns outer_net_ns outer_user_ns outer_cgroup_ns
  local launcher_name launcher_path payload_name payload_path
  local scratch rc cleanup_rc outcome publish_rc cc_target
  [[ $# -eq 7 ]] || die "invalid private setup arguments"
  canonical_repo="$1"
  output_dir="$2"
  service_scope="$3"
  outer_pid_ns="$4"
  outer_net_ns="$5"
  outer_user_ns="$6"
  outer_cgroup_ns="$7"
  [[ "${GROK_TEST_ISOLATION_BOUNDARY:-}" == "$BOUNDARY_MARKER" \
      && "$(< /proc/self/cgroup)" == "0::/" \
      && "$(/usr/bin/readlink -- /proc/self/ns/pid)" == "$outer_pid_ns" \
      && "$(/usr/bin/readlink -- /proc/self/ns/net)" == "$outer_net_ns" \
      && "$(/usr/bin/readlink -- /proc/self/ns/user)" != "$outer_user_ns" \
      && "$(/usr/bin/readlink -- /proc/self/ns/cgroup)" != "$outer_cgroup_ns" ]] \
    || die "private setup namespaces do not match the reviewed boundary"
  validate_output_directory "$output_dir"
  verify_service_cgroup "$service_scope"

  launcher_name="grok-verify-launcher-$$-${RANDOM}"
  payload_name="grok-verify-payload-$$-${RANDOM}"
  launcher_path="$service_scope/$launcher_name"
  payload_path="$service_scope/$payload_name"
  CLEANUP_SERVICE="$service_scope"
  CLEANUP_LAUNCHER="$launcher_path"
  CLEANUP_PAYLOAD="$payload_path"
  trap cleanup_inside_unit EXIT
  [[ -z "$(<"$service_scope/cgroup.subtree_control")" ]] \
    || die "transient service cgroup already delegates unexpected controllers"
  /usr/bin/mkdir -- "$launcher_path" \
    || die "cannot create the reviewed launcher cgroup"
  printf '%s\n' "$$" > "$launcher_path/cgroup.procs" \
    || die "cannot enter the reviewed launcher cgroup"
  [[ "$(< /proc/self/cgroup)" == "0::/$launcher_name" ]] \
    || die "private cgroup namespace did not retain its service root"
  printf '%s\n' '+cpu +memory +pids' > "$service_scope/cgroup.subtree_control" \
    || die "cannot enable exact delegated controllers"
  [[ "$(<"$service_scope/cgroup.subtree_control")" == "cpu memory pids" ]] \
    || die "delegated controller set is not exact"
  /usr/bin/mkdir -- "$payload_path" \
    || die "cannot create the isolated delegated payload cgroup"
  printf '%s\n' "$(<"$service_scope/memory.max")" > "$payload_path/memory.max"
  printf '0\n' > "$payload_path/memory.swap.max"
  printf '%s\n' "$(<"$service_scope/pids.max")" > "$payload_path/pids.max"
  printf '%s\n' "$(<"$service_scope/cpu.max")" > "$payload_path/cpu.max"
  printf '16\n' > "$payload_path/cgroup.max.depth"
  printf '512\n' > "$payload_path/cgroup.max.descendants"
  verify_service_cgroup "$payload_path"

  scratch="$(/usr/bin/mktemp -d /tmp/grok-coding-verify.XXXXXX)" \
    || die "cannot create isolated verification scratch directory"
  [[ "$scratch" == /tmp/grok-coding-verify.* && ! -L "$scratch" ]] \
    || die "scratch directory identity is invalid"
  CLEANUP_SCRATCH="$scratch"
  /usr/bin/chmod 700 "$scratch"
  /usr/bin/mkdir -p \
    "$scratch/artifacts" \
    "$scratch/etc/alternatives" \
    "$scratch/home/.cache" \
    "$scratch/home/.config" \
    "$scratch/home/.local/share" \
    "$scratch/home/.local/state" \
    "$scratch/home/.xdg-runtime" \
    "$scratch/mask"
  /usr/bin/chmod 700 \
    "$scratch/artifacts" \
    "$scratch/home" \
    "$scratch/home/.cache" \
    "$scratch/home/.config" \
    "$scratch/home/.local" \
    "$scratch/home/.local/share" \
    "$scratch/home/.local/state" \
    "$scratch/home/.xdg-runtime"
  /usr/bin/chmod 555 "$scratch/mask"
  printf '%s\n' \
    'root:x:0:0:isolated verification:/home/csr-test:/bin/bash' \
    'csr-test:x:1000:1000:unprivileged verification:/home/csr-test:/bin/bash' \
    > "$scratch/etc/passwd"
  printf '%s\n' 'root:x:0:' 'csr-test:x:1000:' > "$scratch/etc/group"
  printf '%s\n' \
    'passwd: files' \
    'group: files' \
    'shadow: files' \
    'hosts: files' \
    > "$scratch/etc/nsswitch.conf"
  printf '%s\n' '127.0.0.1 localhost' '::1 localhost' > "$scratch/etc/hosts"
  printf '%s\n' '0123456789abcdef0123456789abcdef' > "$scratch/etc/machine-id"
  printf '%s\n' '11111111-1111-4111-8111-111111111111' > "$scratch/proc-boot-id"
  /usr/bin/cp -- /usr/bin/false "$scratch/false"
  /usr/bin/cp -- /usr/bin/true "$scratch/true"
  : > "$scratch/etc/resolv.conf"
  /usr/bin/ln -s /usr/bin/mawk "$scratch/etc/alternatives/awk"
  /usr/bin/ln -s /usr/bin/mawk "$scratch/etc/alternatives/nawk"
  cc_target="$(/usr/bin/readlink -e -- /usr/bin/cc)" \
    || die "cannot resolve the required C compiler alternative"
  [[ "$cc_target" == /usr/bin/* && -x "$cc_target" ]] \
    || die "the required C compiler alternative is outside /usr/bin"
  /usr/bin/ln -s "$cc_target" "$scratch/etc/alternatives/cc"
  /usr/bin/ln -s /usr/share/zoneinfo/UTC "$scratch/etc/localtime"
  /usr/bin/ln -s /proc/mounts "$scratch/etc/mtab"
  /usr/bin/chmod 444 \
    "$scratch/etc/passwd" "$scratch/etc/group" \
    "$scratch/etc/nsswitch.conf" "$scratch/etc/hosts" \
    "$scratch/etc/machine-id" "$scratch/etc/resolv.conf" \
    "$scratch/proc-boot-id"
  /usr/bin/chmod 555 "$scratch/false" "$scratch/true"
  /usr/bin/chmod 555 "$scratch/etc" "$scratch/etc/alternatives"

  set +e
  launch_sandbox \
    "$canonical_repo" "$scratch" "$service_scope" \
    "$launcher_name" "$payload_name" \
    "$outer_pid_ns" "$outer_net_ns" "$outer_user_ns" "$outer_cgroup_ns"
  rc=$?
  set -e
  set +e
  cleanup_delegated_hierarchy
  cleanup_rc=$?
  set -e
  if (( cleanup_rc != 0 && rc == 0 )); then
    rc=2
  fi
  outcome=failed
  (( rc == 0 )) && outcome=passed
  set +e
  /usr/bin/python3 "$canonical_repo/system/grok-proxy/tests/verification_ledger.py" \
    publish \
    --ledger "$scratch/artifacts/grok-test-results.jsonl" \
    --output-dir "$output_dir" \
    --outcome "$outcome" \
    --returncode "$rc"
  publish_rc=$?
  set -e
  (( publish_rc == 0 )) \
    || die "validated result ledger could not be published atomically"
  exit "$rc"
}

launch_sandbox() {
  local repo scratch service_scope launcher_name payload_name payload_path
  local outer_pid_ns outer_net_ns outer_user_ns outer_cgroup_ns
  local -a lib64_args bwrap_args
  [[ $# -eq 9 ]] || die "invalid cgroup-namespace launcher arguments"
  repo="$1"
  scratch="$2"
  service_scope="$3"
  launcher_name="$4"
  payload_name="$5"
  outer_pid_ns="$6"
  outer_net_ns="$7"
  outer_user_ns="$8"
  outer_cgroup_ns="$9"
  payload_path="$service_scope/$payload_name"
  [[ "$(/usr/bin/readlink -- /proc/self/ns/pid)" == "$outer_pid_ns" \
      && "$(/usr/bin/readlink -- /proc/self/ns/net)" == "$outer_net_ns" \
      && "$(/usr/bin/readlink -- /proc/self/ns/user)" != "$outer_user_ns" \
      && "$(/usr/bin/readlink -- /proc/self/ns/cgroup)" != "$outer_cgroup_ns" \
      && "$(< /proc/self/cgroup)" == "0::/$launcher_name" ]] \
    || die "private setup namespace identity changed before sandbox launch"
  [[ -d "$payload_path" && -w "$payload_path/cgroup.procs" ]] \
    || die "delegated runner cgroup is unavailable before sandbox launch"

  lib64_args=()
  if [[ -d /usr/lib64 ]]; then
    lib64_args=(--symlink usr/lib64 /lib64)
  fi
  bwrap_args=(
    --unshare-user
    --unshare-pid
    --unshare-net
    --unshare-ipc
    --unshare-uts
    --uid 1000
    --gid 1000
    --die-with-parent
    --new-session
    --hostname grok-verification
    --cap-drop ALL
    --clearenv
    --ro-bind /usr /usr
    --ro-bind "$scratch/false" /usr/bin/false
    --ro-bind "$scratch/true" /usr/bin/true
    --symlink usr/bin /bin
    --symlink usr/sbin /sbin
    --symlink usr/lib /lib
    "${lib64_args[@]}"
    --proc /proc
    --ro-bind "$scratch/proc-boot-id" /proc/sys/kernel/random/boot_id
    --dev /dev
    --tmpfs /run
    --tmpfs /tmp
    --tmpfs /var
    --dir /root
    --dir /home
    --dir /home/csr-test
    --bind "$scratch/home" /home/csr-test
    --ro-bind "$scratch/etc" /etc
    --ro-bind "$scratch/mask" /usr/local
    --dir /sys
    --dir /sys/fs
    --dir /sys/fs/cgroup
    --bind "$service_scope" /sys/fs/cgroup
    --dir /workspace
    --ro-bind "$repo" "$CANDIDATE_MOUNT"
    --dir /artifacts
    --bind "$scratch/artifacts" /artifacts
    --chdir "$CANDIDATE_MOUNT"
    --setenv HOME /home/csr-test
    --setenv USER csr-test
    --setenv LOGNAME csr-test
    --setenv PATH /usr/bin:/bin:/usr/sbin:/sbin
    --setenv LANG C.UTF-8
    --setenv LC_ALL C.UTF-8
    --setenv TZ UTC
    --setenv TMPDIR /tmp
    --setenv XDG_CACHE_HOME /home/csr-test/.cache
    --setenv XDG_CONFIG_HOME /home/csr-test/.config
    --setenv XDG_DATA_HOME /home/csr-test/.local/share
    --setenv XDG_STATE_HOME /home/csr-test/.local/state
    --setenv XDG_RUNTIME_DIR /home/csr-test/.xdg-runtime
    --setenv PYTHONDONTWRITEBYTECODE 1
    --setenv PYTHONHASHSEED 0
    --setenv GROK_TEST_ISOLATED 1
    --setenv GROK_TEST_ISOLATION_BOUNDARY "$BOUNDARY_MARKER"
    --setenv GROK_TEST_CANDIDATE "$CANDIDATE_MOUNT"
    --setenv GROK_TEST_LEDGER /artifacts/grok-test-results.jsonl
    --setenv GROK_EXPECTED_CGROUP_REL "/$payload_name"
    --setenv GROK_OUTER_PID_NS "$outer_pid_ns"
    --setenv GROK_OUTER_NET_NS "$outer_net_ns"
    --setenv GROK_OUTER_USER_NS "$outer_user_ns"
    --setenv GROK_OUTER_CGROUP_NS "$outer_cgroup_ns"
    /bin/bash "$CANDIDATE_MOUNT/system/grok-proxy/tests/run-isolated.sh" \
      --sandbox-init "$launcher_name" "$payload_name"
  )
  /usr/bin/bwrap "${bwrap_args[@]}"
}

sandbox_init() {
  local launcher_name payload_name payload_path
  [[ $# -eq 2 \
      && "$1" =~ ^grok-verify-launcher-[0-9]+-[0-9]+$ \
      && "$2" =~ ^grok-verify-payload-[0-9]+-[0-9]+$ ]] \
    || die "invalid isolated sandbox initializer arguments"
  launcher_name="$1"
  payload_name="$2"
  payload_path="/sys/fs/cgroup/$payload_name"
  [[ "$(/usr/bin/id -u)" == "1000" \
      && "$(< /proc/self/cgroup)" == "0::/$launcher_name" ]] \
    || die "private user/cgroup namespace setup failed"
  [[ "${GROK_TEST_ISOLATION_BOUNDARY:-}" == "$BOUNDARY_MARKER" \
      && -d "$payload_path" && -w "$payload_path/cgroup.procs" ]] \
    || die "post-bwrap trust boundary or delegated runner is unavailable"
  printf '%s\n' "$$" > "$payload_path/cgroup.procs" \
    || die "cannot enter the exact isolated payload cgroup"
  [[ "$(< /proc/self/cgroup)" == "0::/$payload_name" ]] \
    || die "payload did not enter its exact capped cgroup"
  exec /bin/bash "$CANDIDATE_MOUNT/system/grok-proxy/tests/run.sh" \
    --isolated-payload
}

case "${1:---launch}" in
  --launch)
    [[ $# -eq 0 || $# -eq 1 ]] || die "invalid launcher arguments"
    launch_transient_unit
    ;;
  --inside-unit)
    shift
    inside_transient_unit "$@"
    ;;
  --inside-private-setup)
    shift
    inside_private_setup "$@"
    ;;
  --sandbox-init)
    shift
    sandbox_init "$@"
    ;;
  *)
    die "unknown launcher mode"
    ;;
esac
