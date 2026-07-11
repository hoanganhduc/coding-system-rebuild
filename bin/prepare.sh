#!/usr/bin/env bash
# Install all software dependencies. Everything runs by default; SKIP_* env vars
# opt out of heavy or unwanted steps. Idempotent: each step checks before acting.
#
# Toggles: SKIP_APT SKIP_LATEX SKIP_CALIBRE SKIP_CHROMIUM SKIP_TAILSCALE SKIP_NODE
#          SKIP_NPM_GLOBALS SKIP_PIPX SKIP_RUST SKIP_BUN SKIP_LEAN SKIP_MODAL
#          SKIP_DOCKER SKIP_DOCKER_IMAGES SKIP_GROK
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$REPO/system/packages"
ARCH=$(uname -m)
step() { echo; echo "=== prepare: $1 ==="; }
skip() { [[ "${!1:-0}" == "1" ]] && { echo "(skipped via $1)"; return 0; } || return 1; }

step "apt base packages"
if ! skip SKIP_APT; then
  base=$(grep -vE '^\s*(#|$)' "$PKG/apt.txt" | grep -vE '^(texlive-full|calibre|chromium|chromium-driver)$')
  # Drop packages already provided by a preinstalled tool. On a fresh machine
  # these are absent and stay in the list; on CI runners / re-runs, docker.io and
  # gh are preinstalled and would break apt with a conflicting-packages error.
  command -v docker >/dev/null && base=$(echo "$base" | grep -vx 'docker.io' || true)
  command -v gh     >/dev/null && base=$(echo "$base" | grep -vx 'gh' || true)
  sudo apt-get update -qq
  # shellcheck disable=SC2086
  sudo apt-get install -y -qq $base
  sudo apt-get install -y -qq 7zip-standalone 2>/dev/null || true
fi

step "xtradeb PPA (chromium, chromium-driver, calibre — stock 24.04 lacks chromium debs)"
if ! skip SKIP_CHROMIUM; then
  if ! apt-cache policy chromium 2>/dev/null | grep -q xtradeb; then
    sudo apt-get install -y -qq software-properties-common
    sudo add-apt-repository -y ppa:xtradeb/apps
    sudo apt-get update -qq
  fi
  sudo apt-get install -y -qq chromium chromium-driver
fi
if ! skip SKIP_CALIBRE; then sudo apt-get install -y -qq calibre; fi

step "TeX Live full (~5.5GB) — SKIP_LATEX=1 to skip"
if ! skip SKIP_LATEX; then
  dpkg -s texlive-full >/dev/null 2>&1 || sudo apt-get install -y -qq texlive-full
fi

step "tailscale (official install script — not in default repos)"
if ! skip SKIP_TAILSCALE; then
  command -v tailscale >/dev/null || curl -fsSL https://tailscale.com/install.sh | sh
fi

step "node 22 (NodeSource) + npm prefix"
if ! skip SKIP_NODE; then
  if ! command -v node >/dev/null || [[ "$(node --version | cut -d. -f1 | tr -d v)" -lt 22 ]]; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y -qq nodejs
  fi
  npm config set prefix "$HOME/.npm-global"
fi

step "npm global packages (pinned)"
if ! skip SKIP_NPM_GLOBALS; then
  while read -r pkg; do
    [[ -z "$pkg" || "$pkg" == \#* ]] && continue
    name="${pkg%@*}"; ver="${pkg##*@}"
    have=$(npm ls -g --depth=0 "$name" 2>/dev/null | grep -o "$name@[0-9][^ ]*" | cut -d@ -f2 || true)
    if [[ "$have" != "$ver" ]]; then
      echo "npm -g $name@$ver (have: ${have:-none})"
      npm install -g "$name@$ver"
    fi
  done < "$PKG/npm-globals.txt"
fi

step "grok CLI (xAI Grok Build TUI — official installer, not in package repos)"
if ! skip SKIP_GROK; then
  # captured at 0.2.93; the installer pulls latest and grok self-updates thereafter
  command -v grok >/dev/null || [[ -x "$HOME/.grok/bin/grok" ]] || \
    curl -fsSL https://x.ai/cli/install.sh | bash
fi

step "pipx tools"
if ! skip SKIP_PIPX; then
  command -v pipx >/dev/null || sudo apt-get install -y -qq pipx
  pipx ensurepath >/dev/null 2>&1 || true
  while read -r spec; do
    [[ -z "$spec" || "$spec" == \#* ]] && continue
    name="${spec%%==*}"
    pipx list 2>/dev/null | grep -q "package $name " || pipx install "$spec" || pipx install "$name"
  done < "$PKG/pipx.txt"
fi

step "rust toolchain (qmd build dependency)"
if ! skip SKIP_RUST; then
  command -v cargo >/dev/null || [[ -x "$HOME/.cargo/bin/cargo" ]] || \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
fi

step "bun runtime (qmd build dependency)"
if ! skip SKIP_BUN; then
  command -v bun >/dev/null || [[ -x "$HOME/.bun/bin/bun" ]] || \
    curl -fsSL https://bun.sh/install | bash
fi

step "elan / Lean toolchain manager (toolchains lazy-install per project pin)"
if ! skip SKIP_LEAN; then
  [[ -x "$HOME/.elan/bin/elan" ]] || \
    curl -fsSL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
fi

step "modal CLI"
if ! skip SKIP_MODAL; then
  command -v modal >/dev/null || python3 -m pip install --user --break-system-packages modal
fi

step "docker engine"
if ! skip SKIP_DOCKER; then
  command -v docker >/dev/null || sudo apt-get install -y -qq docker.io
  id -nG | grep -qw docker || { sudo usermod -aG docker "$USER"; echo "NOTE: added to docker group — image pulls use 'sg docker'"; }
fi

step "docker images (~15GB total) — SKIP_DOCKER_IMAGES=1 to skip"
if ! skip SKIP_DOCKER_IMAGES; then
  dockercmd() { if docker info >/dev/null 2>&1; then docker "$@"; else sg docker -c "docker $*"; fi; }
  while IFS='|' read -r img cond; do
    [[ -z "$img" || "$img" == \#* ]] && continue
    case "$cond" in
      arm64) [[ "$ARCH" == "aarch64" ]] || { echo "skip $img (arm64-only, this is $ARCH)"; continue; } ;;
      amd64) [[ "$ARCH" == "x86_64"  ]] || { echo "skip $img (amd64-only)"; continue; } ;;
    esac
    dockercmd image inspect "$img" >/dev/null 2>&1 || { echo "pull $img"; dockercmd pull "$img"; }
  done < "$PKG/docker-images.txt"
fi

echo; echo "prepare: complete"
