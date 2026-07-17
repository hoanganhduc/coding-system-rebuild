#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
holder=""
cleanup(){
  [[ -n "$holder" ]] && kill "$holder" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

GROK_TESTING=1 GROK_TEST_CONTROL_DIR="$tmp/control" READY="$tmp/ready" ROOT="$ROOT" bash -c '
  . "$ROOT/grok-remote"
  acquire_session_lock
  : > "$READY"
  sleep 10
' &
holder=$!
for _ in $(seq 1 40); do [[ -e "$tmp/ready" ]] && break; sleep 0.05; done
[[ -e "$tmp/ready" ]]

set +e
out="$(GROK_TESTING=1 GROK_TEST_CONTROL_DIR="$tmp/control" ROOT="$ROOT" bash -c '. "$ROOT/grok-remote"; acquire_session_lock' 2>&1)"
rc=$?
set -e
[[ $rc -ne 0 ]]
[[ "$out" == *'another grok-remote session owns'* ]]

set +e
out="$(GROK_TESTING=1 GROK_TEST_CONTROL_DIR="$tmp/control" ROOT="$ROOT" \
  bash -c '. "$ROOT/grok-remote"; main stop' 2>&1)"
rc=$?
set -e
[[ $rc -ne 0 && "$out" == *'another grok-remote session owns'* ]]

set +e
out="$(GROK_TESTING=1 GROK_TEST_CONTROL_DIR="$tmp/control" ROOT="$ROOT" \
  bash -c '. "$ROOT/egress.sh"; standalone_mutation_lock && teardown_all' 2>&1)"
rc=$?
set -e
[[ $rc -ne 0 && "$out" == *'another grok-remote session owns'* ]]

kill "$holder"
wait "$holder" 2>/dev/null || true
holder=""
GROK_TESTING=1 GROK_TEST_CONTROL_DIR="$tmp/control" ROOT="$ROOT" bash -c '. "$ROOT/grok-remote"; acquire_session_lock'

echo "PASS: concurrent launches and mutating stop commands cannot race the shared egress"
