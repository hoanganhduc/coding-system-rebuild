#!/usr/bin/env bash
# Strict preflight for the only supported substrates: Ubuntu 24.04 arm64/amd64.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCKCTL="$REPO/system/software/lockctl.py"
FAIL=0
ok()   { printf 'OK    %s\n' "$1"; }
warn() { printf 'WARN  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAIL=1; }

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]]; then
    ok "OS: ${PRETTY_NAME:-Ubuntu 24.04}"
  else
    fail "supported OS is Ubuntu 24.04 (found ${PRETTY_NAME:-unknown})"
  fi
else
  fail "cannot read /etc/os-release"
fi

case "$(uname -m)" in
  aarch64|arm64) ARCH=arm64 ;;
  x86_64|amd64) ARCH=amd64 ;;
  *) ARCH=unsupported; fail "supported architectures are arm64/amd64 (found $(uname -m))" ;;
esac
[[ "$ARCH" == unsupported ]] || ok "architecture: $ARCH"

AVAIL_GB=$(df -BG --output=avail "$HOME" 2>/dev/null | tail -1 | tr -dc '0-9')
if [[ -z "$AVAIL_GB" ]]; then
  fail "cannot determine free disk space"
elif (( AVAIL_GB < 60 )); then
  warn "only ${AVAIL_GB}GB free (full image/tool closure recommends at least 60GB)"
else
  ok "disk: ${AVAIL_GB}GB free"
fi

for tool in curl git make python3 gpg jq; do
  command -v "$tool" >/dev/null 2>&1 && ok "tool: $tool" || fail "missing bootstrap tool: $tool"
done
python3 -c 'import yaml' 2>/dev/null && ok "python3-yaml" || fail "missing python3-yaml"
SEVENZ=$(command -v 7zz || command -v 7z || true)
[[ -n "$SEVENZ" ]] && ok "7-Zip: $SEVENZ" || fail "missing 7zz/7z (needed for legacy recovery imports)"

if [[ "$ARCH" != unsupported ]] && python3 "$LOCKCTL" --arch "$ARCH" validate; then
  ok "software and OCI locks"
else
  fail "software/OCI lock validation failed"
fi

if command -v curl >/dev/null 2>&1 && curl -fsSI -m 10 https://github.com >/dev/null 2>&1; then
  ok "network: github.com reachable"
else
  fail "network: github.com is unreachable"
fi

command -v docker >/dev/null 2>&1 && ok "docker present" || warn "docker absent (locked prepare installs it)"
command -v node >/dev/null 2>&1 && ok "node $(node --version 2>/dev/null)" || warn "node absent (locked prepare installs it)"

if command -v loginctl >/dev/null 2>&1; then
  linger=$(loginctl show-user "$USER" -p Linger --value 2>/dev/null || echo "?")
  [[ "$linger" == yes ]] && ok "linger enabled" || warn "linger is not enabled (required by persistent user services)"
fi
sudo -n true 2>/dev/null && ok "passwordless/cached sudo" || warn "sudo will prompt during restoration"
id -nG | grep -qw docker && ok "docker group member" || warn "not yet a docker group member"

if [[ $FAIL -eq 0 ]]; then
  echo "doctor: ready for ubuntu-24.04/${ARCH}"
else
  echo "doctor: blockers found" >&2
  exit 1
fi
