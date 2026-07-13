#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for test_file in \
  test_vpngate_input.sh \
  test_listener_ownership.sh \
  test_ladder.sh \
  test_session_lock.sh \
  test_proxy_env.sh
do
  echo "== $test_file =="
  bash "$DIR/$test_file"
done

echo "All grok-proxy regression tests passed."
