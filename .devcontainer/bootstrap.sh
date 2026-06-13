#!/usr/bin/env bash
# Codespaces create-time setup: build a DEGRADED (no-secrets) interactive replica.
# Same surface as the GitHub Actions `install-degraded` job. Uploading secrets later
# (via the web form on port 8099) is optional and upgrades this to a full replica.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

echo "=================================================================="
echo " coding-system-rebuild — Codespaces degraded build (no secrets)"
echo "=================================================================="

# install.sh's phase-1 doctor hard-fails (exit 1) without these, aborting the whole
# build before apt even runs. The CI 'install-degraded' job installs them first
# (.github/workflows/rehearsal.yml); the devcontainers base image + node/python/gh
# features ship none of them, so the Codespace bootstrap must match CI to reach parity.
sudo apt-get update -qq
sudo apt-get install -y -qq make 7zip python3-yaml

# the optional upload form needs Flask
python3 -m pip install --quiet flask 2>/dev/null \
  || python3 -m pip install --quiet --break-system-packages flask 2>/dev/null \
  || echo "WARN: could not install flask — the upload form may not start"

# Degraded install: software + components (public) + render + python + systemd-render +
# verify. Keep create FAST and resilient: besides texlive (5.5GB) and the multi-GB docker
# images, also defer the heavy / network-fragile installers an interactive degraded replica
# does not need at create time — chromium + calibre (xtradeb PPA), tailscale, rust, bun,
# elan/Lean. prepare.sh runs under `set -e`, so any one of these failing would otherwise
# abort the whole build. Install them later if a skill needs them, e.g.:
#   SKIP_APT=1 SKIP_NODE=1 SKIP_NPM_GLOBALS=1 SKIP_PIPX=1 SKIP_MODAL=1 SKIP_DOCKER=1 \
#   SKIP_DOCKER_IMAGES=1 bash bin/prepare.sh        # (unset the SKIP_* you want)
SKIP_LATEX=1 SKIP_DOCKER_IMAGES=1 \
  SKIP_CHROMIUM=1 SKIP_CALIBRE=1 SKIP_TAILSCALE=1 SKIP_RUST=1 SKIP_BUN=1 SKIP_LEAN=1 \
  bash bin/install.sh || true

cat <<'EOF'

==================================================================
 Degraded replica is ready — you can test live right now, e.g.:
   make verify              # health checks (degraded)
   make test                # roundtrip + scanners
   bash ~/.claude/skills/_run.sh skills/zotero/run_zot.sh doctor
 To upgrade to the FULL secret-backed replica:
   open the forwarded "Secret upload form" (port 8099) and upload
   your encrypted secrets zip + password. (Optional — the zip is
   never stored on GitHub; it is scrubbed after use.)
==================================================================
EOF
