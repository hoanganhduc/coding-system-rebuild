#!/usr/bin/env bash
# Install the locked Ubuntu 24.04 software closure.  Remote installers are
# never executed from a pipe: every standalone artifact is downloaded and
# SHA-256 verified by system/software/lockctl.py before use.
#
# Toggles: SKIP_APT SKIP_LATEX SKIP_CALIBRE SKIP_CHROMIUM SKIP_TAILSCALE
#          SKIP_NODE SKIP_NPM_GLOBALS SKIP_PIPX SKIP_RUST SKIP_BUN SKIP_LEAN
#          SKIP_MODAL SKIP_DOCKER SKIP_DOCKER_IMAGES SKIP_GROK SKIP_KIMI
#          SKIP_ANTIGRAVITY SKIP_CLASSROOM50
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$REPO/system/packages"
LOCKCTL="$REPO/system/software/lockctl.py"
PULL_IMAGES="$REPO/system/software/pull-locked-images.py"
NPM_CLOSURE="$REPO/system/software/npm-closure"
NPM_CLOSURECTL="$NPM_CLOSURE/closurectl.py"
GROK_BOOTSTRAP_PROVISIONER="$REPO/bin/provision-grok-bootstrap.py"

case "$(uname -m)" in
  aarch64|arm64) LOCK_ARCH=arm64 ;;
  x86_64|amd64) LOCK_ARCH=amd64 ;;
  *) echo "prepare: unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac

step() { printf '\n=== prepare: %s ===\n' "$1"; }
skip() { [[ "${!1:-0}" == "1" ]] && { echo "(skipped via $1)"; return 0; } || return 1; }
die() { echo "prepare: $*" >&2; exit 2; }
locked_version() { python3 "$LOCKCTL" --arch "$LOCK_ARCH" artifact "$1" version; }
fetch_locked() { python3 "$LOCKCTL" --arch "$LOCK_ARCH" fetch "$1" "$2" >/dev/null; }
# Every apt call retries transient mirror failures.
APT_OPTIONS=(-o Acquire::Retries=5)
apt_entry() {
  local package="$1" line
  line=$(grep -E "^${package//./\\.}(>=|=|@)" "$PKG/apt.lock.txt" || true)
  [[ -n "$line" ]] || die "package is not locked: $package"
  printf '%s\n' "$line"
}
# Packages install at the newest available version; afterwards each must meet
# its lock entry: name>=version is a minimum, name@origin a build from that PPA.
require_locked_versions() {
  local package entry installed
  for package in "$@"; do
    entry=$(apt_entry "$package")
    installed=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null) || installed=""
    [[ -n "$installed" ]] || die "$package is not installed"
    case "$entry" in
      "$package>="*)
        dpkg --compare-versions "$installed" ge "${entry#"$package>="}" \
          || die "$package $installed is older than its locked minimum ${entry#"$package>="}"
        ;;
      "$package@"*)
        [[ "$installed" == *"${entry#"$package@"}"* ]] \
          || die "$package $installed is not a ${entry#"$package@"} build"
        ;;
      *) die "unsupported apt lock entry: $entry" ;;
    esac
  done
}
version_line() {
  "$@" --version </dev/null 2>&1 | head -n 1
}
safe_link() {
  local target="$1" link="$2"
  if [[ -e "$link" && ! -L "$link" ]]; then
    die "refusing to replace non-symlink executable: $link"
  fi
  ln -sfn -- "$target" "$link"
}
remove_npm_stage() {
  local stage="$1"
  case "$stage" in
    "$HOME/.npm-global/closures/".stage-*)
      [[ ! -L "$stage" ]] || die "refusing symlinked npm staging cleanup: $stage"
      [[ -e "$stage" ]] || return 0
      chmod -R u+rwX -- "$stage"
      rm -rf -- "$stage"
      ;;
    *) die "refusing unsafe npm staging cleanup: $stage" ;;
  esac
}

lock_validation=(--arch "$LOCK_ARCH" validate)
[[ "${CSR_REQUIRE_RELEASE_QUALIFIED:-0}" != "1" ]] \
  || lock_validation+=(--require-complete)
python3 "$LOCKCTL" "${lock_validation[@]}"

TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/csr-prepare.XXXXXXXX")
NODE_STAGE=""
NPM_STAGE=""
cleanup() {
  case "$TMP_ROOT" in
    "${TMPDIR:-/tmp}"/csr-prepare.*) rm -rf -- "$TMP_ROOT" ;;
    *) echo "prepare: refusing unsafe temporary cleanup: $TMP_ROOT" >&2 ;;
  esac
  case "$NODE_STAGE" in
    "$HOME/.npm-global/".node-stage-*) rm -rf -- "$NODE_STAGE" ;;
    "") ;;
    *) echo "prepare: refusing unsafe Node staging cleanup: $NODE_STAGE" >&2 ;;
  esac
  case "$NPM_STAGE" in
    "$HOME/.npm-global/closures/".stage-*) remove_npm_stage "$NPM_STAGE" ;;
    "") ;;
    *) echo "prepare: refusing unsafe npm staging cleanup: $NPM_STAGE" >&2 ;;
  esac
}
trap cleanup EXIT

step "locked Ubuntu 24.04 packages"
if ! skip SKIP_APT; then
  mapfile -t base_packages < <(
    while IFS= read -r spec; do
      [[ -z "$spec" || "$spec" == \#* ]] && continue
      package=${spec%%[>=@]*}
      case "$package" in
        caddy|chromium|chromium-driver|calibre|texlive-full|tailscale) continue ;;
        docker-ce|docker-ce-cli|containerd.io|docker-buildx-plugin|docker-compose-plugin|docker-ce-rootless-extras) continue ;;
      esac
      printf '%s\n' "$package"
    done < "$PKG/apt.lock.txt"
  )
  sudo apt-get "${APT_OPTIONS[@]}" update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTIONS[@]}" install -y -qq "${base_packages[@]}"
  require_locked_versions "${base_packages[@]}"
fi

step "xtradeb packages (Chromium and Calibre)"
if [[ "${SKIP_CHROMIUM:-0}" != 1 || "${SKIP_CALIBRE:-0}" != 1 ]]; then
  # The PPA source and its signing key are locked in this repository, so the
  # restore never depends on a Launchpad API call to fetch the key.
  sudo install -o root -g root -m 0644 \
    "$PKG/apt-sources/xtradeb-ubuntu-apps-noble.sources" \
    /etc/apt/sources.list.d/xtradeb-ubuntu-apps-noble.sources
  sudo apt-get "${APT_OPTIONS[@]}" update -qq
fi
if ! skip SKIP_CHROMIUM; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTIONS[@]}" install -y -qq \
    chromium chromium-driver
  require_locked_versions chromium chromium-driver
fi
if ! skip SKIP_CALIBRE; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTIONS[@]}" install -y -qq calibre
  require_locked_versions calibre
fi

step "TeX Live full"
if ! skip SKIP_LATEX; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTIONS[@]}" install -y -qq texlive-full
  require_locked_versions texlive-full
fi

step "Tailscale signed apt repository"
if ! skip SKIP_TAILSCALE; then
  fetch_locked tailscale-keyring "$TMP_ROOT/tailscale-keyring.gpg"
  fetch_locked tailscale-source "$TMP_ROOT/tailscale.list"
  sudo install -o root -g root -m 0644 "$TMP_ROOT/tailscale-keyring.gpg" \
    /usr/share/keyrings/tailscale-archive-keyring.gpg
  sudo install -o root -g root -m 0644 "$TMP_ROOT/tailscale.list" \
    /etc/apt/sources.list.d/tailscale.list
  sudo apt-get "${APT_OPTIONS[@]}" update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTIONS[@]}" install -y -qq tailscale
  require_locked_versions tailscale
fi

step "Caddy web server (locked Cloudsmith source)"
if ! skip SKIP_CADDY; then
  sudo install -o root -g root -m 0644 \
    "$PKG/apt-sources/caddy-stable-archive-keyring.gpg" \
    /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  sudo install -o root -g root -m 0644 "$PKG/apt-sources/caddy-stable.list" \
    /etc/apt/sources.list.d/caddy-stable.list
  sudo apt-get "${APT_OPTIONS[@]}" update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTIONS[@]}" install -y -qq caddy
  require_locked_versions caddy
fi

step "Ollama (locked release)"
if ! skip SKIP_OLLAMA; then
  ollama_version="$(locked_version ollama)"
  if ! /usr/local/bin/ollama --version 2>&1 | grep -qF "$ollama_version"; then
    fetch_locked ollama "$TMP_ROOT/ollama.tar.zst"
    sudo tar --zstd -xf "$TMP_ROOT/ollama.tar.zst" -C /usr/local
  fi
  id ollama >/dev/null 2>&1 \
    || sudo useradd -r -s /bin/false -U -m -d /usr/share/ollama ollama
  for group in render video; do
    if getent group "$group" >/dev/null; then sudo usermod -a -G "$group" ollama; fi
  done
fi

step "GNU Prolog (locked source, built once)"
if ! skip SKIP_GPROLOG; then
  gprolog_version="$(locked_version gprolog)"
  if ! /usr/local/bin/gprolog --version 2>/dev/null | grep -qF " $gprolog_version"; then
    fetch_locked gprolog "$TMP_ROOT/gprolog.tar.gz"
    tar -xzf "$TMP_ROOT/gprolog.tar.gz" -C "$TMP_ROOT"
    ( cd "$TMP_ROOT/gprolog-$gprolog_version/src" \
      && ./configure --prefix="/usr/local/gprolog-$gprolog_version" \
        --with-links-dir=/usr/local/bin >/dev/null \
      && make -s -j"$(nproc)" >/dev/null \
      && sudo make -s install >/dev/null )
  fi
fi

step "VeraCrypt console (locked package)"
if ! skip SKIP_VERACRYPT; then
  veracrypt_version="$(locked_version veracrypt-console)"
  if ! veracrypt --text --version 2>/dev/null | grep -qF "$veracrypt_version"; then
    fetch_locked veracrypt-console "$TMP_ROOT/veracrypt-console.deb"
    sudo DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTIONS[@]}" install -y -qq \
      "$TMP_ROOT/veracrypt-console.deb"
  fi
fi

step "Node.js locked binary distribution"
OPENCLAW_CLOSURE_BUILDER="$REPO/bin/lib/openclaw_closure.py"
node_version=$(locked_version node)
node_sha256=$(python3 "$LOCKCTL" --arch "$LOCK_ARCH" artifact node sha256)
# Node, the npm agent CLIs and the OpenClaw launcher are built and owned by
# the user, never by root, under ~/.local/share/coding-system.
node_root="$HOME/.local/share/coding-system/node-generations/sha256-${LOCK_ARCH}-${node_sha256}"
if ! skip SKIP_NODE; then
  fetch_locked node "$TMP_ROOT/node.tar.xz"
  node_report="$TMP_ROOT/node-generation.json"
  if ! (
    set -o pipefail
    /usr/bin/dd if="$TMP_ROOT/node.tar.xz" bs=1048576 status=none \
      | /usr/bin/env -i \
          PATH=/usr/bin:/bin LANG=C LC_ALL=C HOME=/ \
          /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
            "$OPENCLAW_CLOSURE_BUILDER" publish-node \
            --repository "$REPO" --arch "$LOCK_ARCH" \
      > "$node_report"
  ); then
    die "cannot construct the locked Node generation"
  fi
  reported_node_root=$(python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["node_root"])' \
    "$node_report")
  [[ "$reported_node_root" == "$node_root" ]] \
    || die "Node generation path differs from its platform lock"
fi
if [[ "${SKIP_NODE:-0}" != 1 || "${SKIP_NPM_GLOBALS:-0}" != 1 ]]; then
  [[ -x "$node_root/bin/node" && "$($node_root/bin/node --version)" == "v${node_version}" ]] \
    || die "locked Node generation is unavailable"
  mkdir -p "$HOME/.npm-global/bin"
  for executable in node npm npx corepack; do
    [[ -x "$node_root/bin/$executable" ]] || die "Node generation lacks $executable"
    safe_link "$node_root/bin/$executable" "$HOME/.npm-global/bin/$executable"
  done
  export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"
  npm config set prefix "$HOME/.npm-global"
  [[ "$(node --version)" == "v${node_version}" ]] || die "locked Node is not first on PATH"
fi

step "transitively locked npm agent CLI closure"
if ! skip SKIP_NPM_GLOBALS; then
  command -v npm >/dev/null || die "npm missing; cannot install agent CLIs"
  python3 "$NPM_CLOSURECTL" validate
  expected_node=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["engines"]["node"])' \
    "$NPM_CLOSURE/package.json")
  expected_npm=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["engines"]["npm"])' \
    "$NPM_CLOSURE/package.json")
  [[ "$(node --version 2>/dev/null || true)" == "v${expected_node}" ]] || \
    die "npm closure requires Node ${expected_node}"
  [[ "$(npm --version 2>/dev/null || true)" == "$expected_npm" ]] || \
    die "npm closure requires npm ${expected_npm}"

  npm_root="$HOME/.npm-global"
  for directory in "$npm_root" "$npm_root/bin"; do
    [[ ! -L "$directory" ]] || die "refusing symlinked npm authority directory: $directory"
    install -d -m 0755 "$directory"
  done
  source_hash=$(python3 "$NPM_CLOSURECTL" source-digest)
  for artifact_id in codewhale-codew codewhale-cli codewhale-tui; do
    fetch_locked "$artifact_id" "$TMP_ROOT/$artifact_id"
  done
  closure_report="$TMP_ROOT/npm-closure.json"
  if ! (
    set -o pipefail
    /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C HOME="$HOME" \
      /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
        "$OPENCLAW_CLOSURE_BUILDER" emit-artifacts \
        --repository "$REPO" --arch "$LOCK_ARCH" --directory "$TMP_ROOT" \
      | /usr/bin/env -i \
          PATH=/usr/bin:/bin LANG=C LC_ALL=C HOME=/ \
          /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
            "$OPENCLAW_CLOSURE_BUILDER" build-closure \
            --repository "$REPO" --arch "$LOCK_ARCH" --node-root "$node_root" \
      > "$closure_report"
  ); then
    die "cannot construct the locked npm CLI closure"
  fi
  closure_root=$(python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["closure_root"])' \
    "$closure_report")
  [[ "$closure_root" == "$HOME/.local/share/coding-system/npm-closures/sha256-${LOCK_ARCH}-${source_hash}-"* \
      && -d "$closure_root" && ! -L "$closure_root" ]] \
    || die "npm closure path differs from its locked source"
  python3 "$NPM_CLOSURECTL" verify-install "$closure_root" --arch "$LOCK_ARCH" --immutable
  safe_link "$closure_root" "$npm_root/cli-current"

  # Preserve an old npm-global package tree once, then publish compatibility
  # links expected by OpenClaw services and existing topology declarations.
  module_root="$npm_root/lib/node_modules"
  [[ ! -L "$npm_root/lib" ]] || die "refusing symlinked npm compatibility directory"
  install -d -m 0755 "$npm_root/lib"
  if [[ -e "$module_root" || -L "$module_root" ]]; then
    [[ -d "$module_root" && ! -L "$module_root" ]] || \
      die "npm global compatibility root is not a regular directory: $module_root"
    if [[ ! -f "$module_root/.csr-closure-id" || -L "$module_root/.csr-closure-id" ]]; then
      legacy_root="$npm_root/legacy"
      [[ ! -L "$legacy_root" ]] || die "refusing symlinked npm legacy directory"
      install -d -m 0700 "$legacy_root"
      legacy_modules="$legacy_root/node_modules-$(date -u +%Y%m%dT%H%M%SZ)-$$"
      [[ ! -e "$legacy_modules" && ! -L "$legacy_modules" ]] || \
        die "npm legacy destination already exists: $legacy_modules"
      mv -- "$module_root" "$legacy_modules"
      echo "preserved legacy npm globals at $legacy_modules"
    fi
  fi
  install -d -m 0755 "$module_root"
  package_map="$TMP_ROOT/npm-direct-packages.tsv"
  python3 "$NPM_CLOSURECTL" emit-packages "$closure_root" --arch "$LOCK_ARCH" \
    --immutable > "$package_map"
  while IFS=$'\t' read -r package_name package_target; do
    [[ -n "$package_name" && -n "$package_target" ]] || die "invalid npm direct-package map"
    package_link="$module_root/$package_name"
    package_parent=${package_link%/*}
    [[ ! -L "$package_parent" ]] || die "refusing symlinked npm package scope: $package_parent"
    install -d -m 0755 "$package_parent"
    safe_link "$package_target" "$package_link"
  done < "$package_map"
  if [[ -e "$module_root/.csr-closure-id" ]]; then
    [[ -f "$module_root/.csr-closure-id" && ! -L "$module_root/.csr-closure-id" ]] || \
      die "npm compatibility marker is not a regular file"
    chmod u+w "$module_root/.csr-closure-id"
  fi
  printf '%s\n' "$closure_root" > "$module_root/.csr-closure-id"
  chmod 0444 "$module_root/.csr-closure-id"

  bin_map="$TMP_ROOT/npm-cli-bins.tsv"
  python3 "$NPM_CLOSURECTL" emit-bins "$closure_root" --arch "$LOCK_ARCH" \
    --immutable > "$bin_map"
  while IFS=$'\t' read -r executable executable_target; do
    [[ -n "$executable" && -n "$executable_target" ]] || die "invalid npm CLI bin map"
    safe_link "$executable_target" "$npm_root/bin/$executable"
  done < "$bin_map"
fi

step "pipx tools"
if ! skip SKIP_PIPX; then
  echo "Aider is installed offline from the digest-locked Python wheelhouse in phase 9"
fi

step "Rust toolchain"
if ! skip SKIP_RUST; then
  rustup_version=$(locked_version rustup-init)
  wanted_rustc=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["cli_versions"]["rustc"])' \
    "$REPO/system/software/ubuntu-24.04-${LOCK_ARCH}.lock.json")
  if ! command -v rustup >/dev/null || [[ "$(version_line rustup)" != "rustup ${rustup_version}"* ]]; then
    fetch_locked rustup-init "$TMP_ROOT/rustup-init"
    chmod 0700 "$TMP_ROOT/rustup-init"
    "$TMP_ROOT/rustup-init" -y --no-modify-path --default-toolchain "$wanted_rustc"
  else
    rustup toolchain install "$wanted_rustc" --profile minimal
    rustup default "$wanted_rustc"
  fi
fi

step "Bun runtime"
if ! skip SKIP_BUN; then
  bun_version=$(locked_version bun)
  if [[ ! -x "$HOME/.bun/bin/bun" ]] || [[ "$($HOME/.bun/bin/bun --version 2>/dev/null || true)" != "$bun_version" ]]; then
    fetch_locked bun "$TMP_ROOT/bun.zip"
    install -d -m 0755 "$TMP_ROOT/bun-unpack" "$HOME/.bun/bin"
    unzip -q "$TMP_ROOT/bun.zip" -d "$TMP_ROOT/bun-unpack"
    bun_binary=$(find "$TMP_ROOT/bun-unpack" -type f -name bun -print -quit)
    [[ -n "$bun_binary" ]] || die "verified Bun archive lacks the bun executable"
    install -m 0755 "$bun_binary" "$HOME/.bun/bin/bun"
    [[ "$($HOME/.bun/bin/bun --version)" == "$bun_version" ]] || die "Bun version probe failed"
  fi
fi

step "elan / Lean toolchain manager"
if ! skip SKIP_LEAN; then
  elan_version=$(locked_version elan)
  if [[ ! -x "$HOME/.elan/bin/elan" ]] || [[ "$(version_line "$HOME/.elan/bin/elan")" != "elan ${elan_version}"* ]]; then
    fetch_locked elan "$TMP_ROOT/elan.tar.gz"
    install -d -m 0755 "$TMP_ROOT/elan-unpack"
    tar -xzf "$TMP_ROOT/elan.tar.gz" -C "$TMP_ROOT/elan-unpack"
    elan_init=$(find "$TMP_ROOT/elan-unpack" -type f -name elan-init -print -quit)
    [[ -n "$elan_init" ]] || die "verified elan archive lacks elan-init"
    chmod 0700 "$elan_init"
    "$elan_init" -y --default-toolchain none --no-modify-path
    [[ "$(version_line "$HOME/.elan/bin/elan")" == "elan ${elan_version}"* ]] || \
      die "elan version probe failed"
  fi
fi

step "Kimi and Grok native CLIs"
if ! skip SKIP_KIMI; then
  kimi_version=$(locked_version kimi)
  if [[ ! -x "$HOME/.kimi-code/bin/kimi" ]] || \
      [[ "$(version_line "$HOME/.kimi-code/bin/kimi")" != "$kimi_version" ]]; then
    fetch_locked kimi "$TMP_ROOT/kimi"
    install -d -m 0700 "$HOME/.kimi-code/bin"
    install -m 0755 "$TMP_ROOT/kimi" "$HOME/.kimi-code/bin/kimi"
    [[ "$(version_line "$HOME/.kimi-code/bin/kimi")" == "$kimi_version" ]] || \
      die "Kimi version probe failed"
  fi
fi

step "Antigravity native CLI"
if ! skip SKIP_ANTIGRAVITY; then
  agy_version=$(locked_version antigravity-agy)
  if [[ ! -x "$HOME/.local/bin/agy" ]] || \
      [[ "$(version_line "$HOME/.local/bin/agy")" != "$agy_version" ]]; then
    fetch_locked antigravity-agy "$TMP_ROOT/antigravity.tar.gz"
    install -d -m 0755 "$TMP_ROOT/antigravity-unpack" "$HOME/.local/bin"
    tar -xzf "$TMP_ROOT/antigravity.tar.gz" -C "$TMP_ROOT/antigravity-unpack"
    [[ -f "$TMP_ROOT/antigravity-unpack/antigravity" ]] || \
      die "verified Antigravity archive lacks the antigravity executable"
    install -m 0755 "$TMP_ROOT/antigravity-unpack/antigravity" "$HOME/.local/bin/agy"
    [[ "$(version_line "$HOME/.local/bin/agy")" == "$agy_version" ]] || \
      die "Antigravity version probe failed"
  fi
fi

step "Classroom50 teacher extension"
if ! skip SKIP_CLASSROOM50; then
  gh_teacher_version=$(locked_version gh-teacher)
  gh_data_root="${XDG_DATA_HOME:-$HOME/.local/share}/gh"
  gh_extension_root="$gh_data_root/extensions"
  gh_teacher_root="$gh_extension_root/gh-teacher"
  gh_teacher="$gh_teacher_root/gh-teacher"
  for path in "$gh_data_root" "$gh_extension_root" "$gh_teacher_root"; do
    [[ ! -L "$path" && ( ! -e "$path" || -d "$path" ) ]] \
      || die "unsafe GitHub CLI extension directory: $path"
  done
  install -d -m 0755 "$gh_teacher_root"
  if [[ -L "$gh_teacher" || ( -e "$gh_teacher" && ! -f "$gh_teacher" ) ]]; then
    die "unsafe gh-teacher extension destination: $gh_teacher"
  fi
  gh_teacher_expected_sha=$(python3 "$LOCKCTL" --arch "$LOCK_ARCH" \
    artifact gh-teacher sha256)
  gh_teacher_actual_sha=$(sha256sum "$gh_teacher" 2>/dev/null | cut -d' ' -f1 || true)
  if [[ ! -x "$gh_teacher" || "$gh_teacher_actual_sha" != "$gh_teacher_expected_sha" ]]; then
    fetch_locked gh-teacher "$TMP_ROOT/gh-teacher"
    chmod 0700 "$TMP_ROOT/gh-teacher"
    [[ "$(version_line "$TMP_ROOT/gh-teacher")" == "gh-teacher version v${gh_teacher_version} "* ]] \
      || die "downloaded gh-teacher version probe failed"
    install -m 0755 "$TMP_ROOT/gh-teacher" "$gh_teacher"
  fi
  [[ "$(sha256sum "$gh_teacher" | cut -d' ' -f1)" == "$gh_teacher_expected_sha" ]] \
    || die "installed gh-teacher digest differs from the platform lock"
  [[ "$(version_line "$gh_teacher")" == "gh-teacher version v${gh_teacher_version} "* ]] \
    || die "installed gh-teacher version probe failed"
fi
if ! skip SKIP_GROK; then
  grok_version=$(locked_version grok)
  if [[ ! -x "$HOME/.grok/bin/grok" ]] || \
      [[ "$(version_line "$HOME/.grok/bin/grok")" != "grok ${grok_version}"* ]]; then
    fetch_locked grok "$TMP_ROOT/grok"
    install -d -m 0700 "$HOME/.grok/bin"
    install -m 0755 "$TMP_ROOT/grok" "$HOME/.grok/bin/grok"
    [[ "$(version_line "$HOME/.grok/bin/grok")" == "grok ${grok_version}"* ]] || \
      die "Grok version probe failed"
  fi
fi

step "Grok signed bootstrap trust anchor"
if ! skip SKIP_GROK; then
  # Refresh the interactive ticket here; the provisioner itself deliberately
  # uses only noninteractive, fixed-argument sudo calls at the trust boundary.
  sudo -v
  python3 -I -B "$GROK_BOOTSTRAP_PROVISIONER"
fi

step "Modal CLI"
if ! skip SKIP_MODAL; then
  echo "Modal is installed offline from the digest-locked Python wheelhouse in phase 9"
fi

step "Docker engine"
if ! skip SKIP_DOCKER; then
  if dpkg-query -W -f='${Status}' docker.io 2>/dev/null | grep -q 'install ok installed'; then
    die "Ubuntu docker.io conflicts with the locked Docker CE profile; remove it before restoration"
  fi
  fetch_locked docker-apt-key "$TMP_ROOT/docker.asc"
  printf '%s\n' \
    'Types: deb' \
    'URIs: https://download.docker.com/linux/ubuntu' \
    'Suites: noble' \
    'Components: stable' \
    "Architectures: $LOCK_ARCH" \
    'Signed-By: /etc/apt/keyrings/docker.asc' \
    > "$TMP_ROOT/docker.sources"
  # A source written by Docker's own install instructions names another keyring
  # for the same repository, which apt rejects; set it aside for the locked one.
  if [[ -f /etc/apt/sources.list.d/docker.list ]] \
      && grep -q 'download.docker.com/linux/ubuntu' /etc/apt/sources.list.d/docker.list; then
    sudo install -d -o root -g root -m 0755 /var/backups/coding-system
    sudo mv -f /etc/apt/sources.list.d/docker.list /var/backups/coding-system/docker.list
    echo "NOTE: moved the previous Docker apt source to /var/backups/coding-system/docker.list"
  fi
  sudo install -d -o root -g root -m 0755 /etc/apt/keyrings
  sudo install -o root -g root -m 0644 "$TMP_ROOT/docker.asc" /etc/apt/keyrings/docker.asc
  sudo install -o root -g root -m 0644 "$TMP_ROOT/docker.sources" /etc/apt/sources.list.d/docker.sources
  DOCKER_PACKAGES=(docker-ce docker-ce-cli containerd.io docker-buildx-plugin
                   docker-compose-plugin docker-ce-rootless-extras)
  sudo apt-get "${APT_OPTIONS[@]}" update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTIONS[@]}" install -y -qq \
    "${DOCKER_PACKAGES[@]}"
  require_locked_versions "${DOCKER_PACKAGES[@]}"
  sudo systemctl enable --now docker
  if ! id -nG | grep -qw docker; then
    sudo usermod -aG docker "$USER"
    echo "NOTE: added $USER to the docker group; the locked image helper uses sudo until the next login"
  fi
fi

step "digest-only OCI image pull"
if [[ "${CSR_DEFER_IMAGE_PULL:-0}" == "1" ]]; then
  echo "(deferred until restored registry credentials are available)"
elif ! skip SKIP_DOCKER_IMAGES; then
  [[ "${SKIP_DOCKER:-0}" != 1 ]] || die "SKIP_DOCKER_IMAGES=0 requires Docker"
  python3 "$PULL_IMAGES" --arch "$LOCK_ARCH"
fi

echo
echo "prepare: complete for ubuntu-24.04/${LOCK_ARCH}"
