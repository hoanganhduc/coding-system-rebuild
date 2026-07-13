#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vpngate-connect.sh
. "$ROOT/vpngate-connect.sh"

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

echo "PASS: VPN Gate host/port input is validated and pinned"
