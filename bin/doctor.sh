#!/usr/bin/env bash
# Preflight checks. Exit 1 on hard blockers; warnings otherwise.
set -uo pipefail
FAIL=0
ok()   { printf 'OK    %s\n' "$1"; }
warn() { printf 'WARN  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAIL=1; }

# OS / arch
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] && ok "OS: $PRETTY_NAME" || warn "not Ubuntu ($PRETTY_NAME) — apt phases may differ"
  [[ "${VERSION_ID:-}" == "24.04" ]] || warn "tested on Ubuntu 24.04 (this: ${VERSION_ID:-?})"
else
  fail "cannot read /etc/os-release"
fi
ARCH=$(uname -m)
ok "arch: $ARCH"
case "$ARCH" in
  x86_64|aarch64) ok "SageMath docker image available for $ARCH" ;;
  *) warn "no pinned SageMath docker image for $ARCH" ;;
esac

# disk
AVAIL_GB=$(df -BG --output=avail "$HOME" | tail -1 | tr -dc '0-9')
if (( AVAIL_GB < 60 )); then warn "only ${AVAIL_GB}GB free (recommend >=60GB for full install)"; else ok "disk: ${AVAIL_GB}GB free"; fi

# network
curl -sI -m 10 https://github.com >/dev/null 2>&1 && ok "network: github reachable" || fail "no network to github.com"

# tools
for t in git make python3; do command -v "$t" >/dev/null && ok "tool: $t" || fail "missing: $t (apt install $t)"; done
python3 -c 'import yaml' 2>/dev/null && ok "python3-yaml" || fail "missing python3-yaml (apt install python3-yaml)"
SEVENZ="$(command -v 7zz || command -v 7z || true)"
[[ -n "$SEVENZ" ]] && ok "7-Zip: $SEVENZ" || fail "no 7zz/7z (apt install 7zip; secrets ops impossible without it)"
command -v docker >/dev/null && ok "docker present" || warn "docker absent (make prepare installs it)"
command -v node >/dev/null && ok "node $(node --version 2>/dev/null)" || warn "node absent (make prepare installs it)"

# session
if command -v loginctl >/dev/null; then
  L=$(loginctl show-user "$USER" -p Linger --value 2>/dev/null || echo "?")
  [[ "$L" == "yes" ]] && ok "linger enabled" || warn "linger not enabled (loginctl enable-linger $USER — needed for user services at boot)"
fi
sudo -n true 2>/dev/null && ok "passwordless sudo" || warn "sudo needs a password — apt phases will prompt"
id -nG | grep -qw docker && ok "docker group member" || warn "not in docker group (prepare adds; re-login or sg docker needed)"

[[ $FAIL -eq 0 ]] && echo "doctor: ready" || { echo "doctor: blockers found" >&2; exit 1; }
