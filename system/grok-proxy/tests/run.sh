#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
