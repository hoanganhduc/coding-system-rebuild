#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

has_delegated_cgroup() {
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$DIR/.." python3 - <<'PY'
from grok_ms.process_scope import LinuxCgroupV2Scope, ScopeError

try:
    LinuxCgroupV2Scope().plan()
except (OSError, ScopeError):
    raise SystemExit(1)
PY
}

if ! has_delegated_cgroup; then
  if [[ "${GROK_TEST_DELEGATED_REEXEC:-0}" == "1" ]]; then
    echo "ERROR: transient Delegate=yes service did not provide a delegated cgroup-v2 parent" >&2
    exit 2
  fi
  if [[ ! -x /usr/bin/systemd-run ]]; then
    echo "ERROR: Grok integration tests require delegated cgroup v2 or systemd-run" >&2
    exit 2
  fi
  runtime_dir="/run/user/$(/usr/bin/id -u)"
  if [[ ! -S "$runtime_dir/bus" ]]; then
    echo "ERROR: Grok integration tests require an active systemd user manager" >&2
    exit 2
  fi
  export XDG_RUNTIME_DIR="$runtime_dir"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
  reexec_environment=(
    --setenv=HOME="$HOME"
    --setenv=PATH="$PATH"
    --setenv=XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR"
    --setenv=DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS"
  )
  for name in GROK_RUN_ROOT_CGROUP_TEST SUDO_USER SUDO_UID SUDO_GID; do
    if [[ -v "$name" ]]; then
      reexec_environment+=("--setenv=$name=${!name}")
    fi
  done
  exec /usr/bin/systemd-run --user \
    --quiet --wait --collect --pipe --service-type=exec \
    --property=Delegate=yes --same-dir \
    "${reexec_environment[@]}" \
    /usr/bin/env GROK_TEST_DELEGATED_REEXEC=1 PYTHONDONTWRITEBYTECODE=1 \
    /bin/bash "$0"
fi

if [[ "${GROK_TEST_SUBREAPER:-0}" != "1" ]]; then
  GROK_TEST_SUBREAPER=1 exec python3 "$DIR/subreaper_run.py" bash "$0"
fi

for test_file in \
  test_p0_baseline.sh \
  test_vpngate_input.sh \
  test_listener_ownership.sh \
  test_ladder.sh \
  test_session_lock.sh \
  test_proxy_env.sh \
  test_diagnostic_safety.sh \
  test_multi_gate.sh
do
  echo "== $test_file =="
  bash "$DIR/$test_file"
done

echo "== test_socks_relay.py =="
python3 "$DIR/test_socks_relay.py"

echo "== test_grok_ms_core.py =="
python3 "$DIR/test_grok_ms_core.py"

echo "== test_grok_ms_config.py =="
python3 "$DIR/test_grok_ms_config.py"

echo "== test_grok_ms_client.py =="
python3 "$DIR/test_grok_ms_client.py"

echo "== test_grok_ms_process_scope.py =="
python3 "$DIR/test_grok_ms_process_scope.py"

echo "== test_grok_ms_frontend.py =="
python3 "$DIR/test_grok_ms_frontend.py"

echo "== test_grok_ms_providers.py =="
python3 "$DIR/test_grok_ms_providers.py"

echo "== test_grok_ms_supervisor.py =="
python3 "$DIR/test_grok_ms_supervisor.py"

echo "== test_live_multi_verify.py =="
python3 "$DIR/test_live_multi_verify.py"

echo "== test_multi_feature_e2e.py =="
python3 "$DIR/test_multi_feature_e2e.py"

echo "== test_vpn_broker.py =="
python3 "$DIR/test_vpn_broker.py"

echo "== test_release_installer.py =="
python3 "$DIR/test_release_installer.py"

echo "== test_install_pipeline.py =="
python3 "$DIR/test_install_pipeline.py"

echo "== test_source_backup_pipeline.py =="
python3 "$DIR/test_source_backup_pipeline.py"

echo "All grok-proxy regression tests passed."
