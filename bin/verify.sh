#!/usr/bin/env bash
# Post-install checks with an explicit profile. Full is fail-closed and proves
# the effective OpenClaw runtime; ci records exactly which live checks are absent.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin:$HOME/.npm-global/bin:$HOME/.local/bin"
export PATH
PKG="$REPO/system/packages"
PROFILE="full"
if [[ "${1:-}" == "--smoke" ]]; then
  PROFILE="smoke"
elif [[ "${1:-}" == "--profile" && -n "${2:-}" ]]; then
  PROFILE="$2"
fi
case "$PROFILE" in full|ci|smoke) ;; *) echo "usage: $0 [--smoke|--profile full|ci]" >&2; exit 2;; esac
SMOKE_ONLY=0; [[ "$PROFILE" == "smoke" ]] && SMOKE_ONLY=1
DEGRADED=0; [[ "$PROFILE" == "ci" ]] && DEGRADED=1
AAS_RESTORE_AGENTS="codex,claude,deepseek,copilot,opencode,antigravity,grok,kimi"
VERIFY_STARTED_AT_UNIX="$(date +%s)"
if [[ -z "${CODING_SYSTEM_RESTORE_RUN_ID:-}" ]]; then
  CODING_SYSTEM_RESTORE_RUN_ID="$(/usr/bin/python3 -I -B -c 'import secrets; print(secrets.token_hex(32))')"
fi
if [[ -z "${CODING_SYSTEM_RESTORE_RUN_STARTED_AT_UNIX:-}" ]]; then
  CODING_SYSTEM_RESTORE_RUN_STARTED_AT_UNIX="$VERIFY_STARTED_AT_UNIX"
fi
export CODING_SYSTEM_RESTORE_RUN_ID CODING_SYSTEM_RESTORE_RUN_STARTED_AT_UNIX
PASS=0; FAILN=0; SKIP=0
declare -a PASS_LABELS=() FAIL_LABELS=() SKIP_LABELS=()
ok()   { printf 'OK    %s\n' "$1"; PASS=$((PASS+1)); PASS_LABELS+=("$1"); }
bad()  { printf 'FAIL  %s\n' "$1"; FAILN=$((FAILN+1)); FAIL_LABELS+=("$1"); }
skp()  { printf 'SKIP  %s\n' "$1"; SKIP=$((SKIP+1)); SKIP_LABELS+=("$1"); }

EXPECTED_EVIDENCE_COMMIT=""
if [[ "$PROFILE" == "full" ]]; then
  EXPECTED_EVIDENCE_COMMIT="${CSR_EXPECTED_RECOVERY_COMMIT:-}"
  if [[ -z "$EXPECTED_EVIDENCE_COMMIT" ]]; then
    EXPECTED_EVIDENCE_COMMIT="$(/usr/bin/python3 -I -B - \
      "$HOME/.local/state/coding-system/restore/last-successful-commit" <<'PY' 2>/dev/null || true
import os
from pathlib import Path
import re
import stat
import sys

path = Path(sys.argv[1])
descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > 129
    ):
        raise SystemExit(2)
    value = os.read(descriptor, 130).decode("ascii").strip()
finally:
    os.close(descriptor)
if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) is None:
    raise SystemExit(2)
print(value)
PY
)"
  fi
  [[ "$EXPECTED_EVIDENCE_COMMIT" =~ ^[0-9a-f]{40}$ \
      || "$EXPECTED_EVIDENCE_COMMIT" =~ ^[0-9a-f]{64}$ ]] \
    || bad "authenticated repository commit is available for evidence binding"
fi

# --- environment probes ----------------------------------------------------------
# The live host has a user systemd session, cron, restored secrets, and the npm
# global bin on PATH. CI limitations are declared by --profile ci, never inferred.
# /run/systemd/system exists iff systemd is the init (this is how sd_booted() works).
# `systemctl --user` returns 0 even in containers where systemd is NOT running, so it is
# not a usable probe — check the directory instead.
have_user_systemd() { [[ -d /run/systemd/system ]]; }
have_cron()         { pgrep -x cron >/dev/null 2>&1 || pgrep -x crond >/dev/null 2>&1; }
# Keep system tools ahead of user-scoped agent CLI bins in this non-login shell.
for d in "$(npm config get prefix 2>/dev/null)/bin" "$HOME/.npm-global/bin"; do
  [[ -d "$d" ]] && case ":$PATH:" in *":$d:"*) ;; *) PATH="$PATH:$d";; esac
done
case "$(uname -m)" in
  aarch64|arm64) LOCK_ARCH=arm64 ;;
  x86_64|amd64) LOCK_ARCH=amd64 ;;
  *) LOCK_ARCH=unsupported ;;
esac
echo "--- platform/software lock integrity ---"
OPENCLAW_LOADER="$HOME/.local/share/coding-system/openclaw-launchers/loader.py"
if [[ -L "$HOME/.npm-global/bin/openclaw" && -f "$OPENCLAW_LOADER" \
    && ! -L "$OPENCLAW_LOADER" ]]; then
  if /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
      "$OPENCLAW_LOADER" --home "$HOME" --arch "$LOCK_ARCH" >/dev/null; then
    ok "OpenClaw uses the full-transitive executable contract"
  else
    bad "OpenClaw full-transitive executable contract"
  fi
elif [[ "$DEGRADED" == "1" ]]; then
  skp "OpenClaw full-transitive executable contract (degraded)"
else
  bad "OpenClaw full-transitive executable contract"
fi
lock_args=(--arch "$LOCK_ARCH" validate)
[[ "$PROFILE" != full ]] || lock_args+=(--require-complete)
if [[ "$LOCK_ARCH" != unsupported ]] \
    && python3 "$REPO/system/software/lockctl.py" "${lock_args[@]}"; then
  ok "Ubuntu 24.04/$LOCK_ARCH lock is internally consistent"
else
  bad "software lock integrity/platform selection"
fi
SOFTWARE_REPORT="$HOME/.local/state/coding-system/restore/installed-software.json"
if [[ "$DEGRADED" == "1" ]]; then
  if python3 "$REPO/bin/verify-installed-software.py" --repository "$REPO" \
      --architecture "$LOCK_ARCH" --profile source --output "$SOFTWARE_REPORT" >/dev/null; then
    ok "apt/native CLI declarations are structurally verifiable (ci)"
  else
    bad "apt/native CLI declaration verification"
  fi
else
  if python3 "$REPO/bin/verify-installed-software.py" --repository "$REPO" \
      --architecture "$LOCK_ARCH" --profile full --output "$SOFTWARE_REPORT" >/dev/null; then
    ok "exact apt package and native CLI closure"
  else
    bad "exact apt package and native CLI closure"
  fi
fi
echo "--- transitive npm CLI closure ---"
NPM_CLOSURE="$REPO/system/software/npm-closure"
NPM_CLOSURECTL="$NPM_CLOSURE/closurectl.py"
source_hash=$(python3 "$NPM_CLOSURECTL" source-digest 2>/dev/null || true)
current_link="$HOME/.npm-global/cli-current"
closure_root=$(readlink "$current_link" 2>/dev/null || true)
closure_prefix="$HOME/.npm-global/closures/sha256-${source_hash}-"
expected_tree_hash=${closure_root#"$closure_prefix"}
if [[ "$source_hash" =~ ^[0-9a-f]{64}$ \
    && -L "$current_link" \
    && "$closure_root" == "$closure_prefix$expected_tree_hash" \
    && "$expected_tree_hash" =~ ^[0-9a-f]{64}$ ]] \
    && python3 "$NPM_CLOSURECTL" verify-install "$closure_root" \
      --arch "$LOCK_ARCH" --immutable >/dev/null; then
  ok "npm direct/transitive package closure is exact and immutable"
  expected_node=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["engines"]["node"])' \
    "$NPM_CLOSURE/package.json")
  expected_npm=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["engines"]["npm"])' \
    "$NPM_CLOSURE/package.json")
  [[ "$(node --version 2>/dev/null || true)" == "v${expected_node}" ]] \
    && ok "Node $expected_node for npm closure" || bad "Node differs from npm closure pin"
  [[ "$(npm --version 2>/dev/null || true)" == "$expected_npm" ]] \
    && ok "npm $expected_npm for npm closure" || bad "npm differs from npm closure pin"

  # CodeWhale's npm wrapper is integrity-locked, while its three native files
  # are independently bound to the platform artifact lock.
  codewhale_root="$closure_root/node_modules/codewhale"
  codewhale_manifest="$codewhale_root/package.json"
  codewhale_downloads="$codewhale_root/bin/downloads"
  codewhale_version=$(python3 -c '
import json, sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
print(manifest.get("version", "") if manifest.get("name") == "codewhale" else "")
' "$codewhale_manifest" 2>/dev/null || true)
  locked_codewhale=$(python3 "$REPO/system/software/lockctl.py" --arch "$LOCK_ARCH" \
    artifact codewhale-cli version 2>/dev/null || true)
  if [[ -d "$codewhale_root" && ! -L "$codewhale_root" \
      && -f "$codewhale_manifest" && ! -L "$codewhale_manifest" \
      && -d "$codewhale_downloads" && ! -L "$codewhale_downloads" \
      && -n "$locked_codewhale" && "$codewhale_version" == "$locked_codewhale" ]]; then
    ok "CodeWhale npm wrapper identity/version $codewhale_version"
  else
    bad "CodeWhale npm wrapper identity/version or native-download directory"
  fi
  codewhale_artifacts=(codewhale-codew codewhale-cli codewhale-tui)
  codewhale_targets=(codew codewhale codewhale-tui)
  for index in "${!codewhale_artifacts[@]}"; do
    artifact_id=${codewhale_artifacts[$index]}
    target_name=${codewhale_targets[$index]}
    expected_version=$(python3 "$REPO/system/software/lockctl.py" --arch "$LOCK_ARCH" \
      artifact "$artifact_id" version 2>/dev/null || true)
    expected_sha=$(python3 "$REPO/system/software/lockctl.py" --arch "$LOCK_ARCH" \
      artifact "$artifact_id" sha256 2>/dev/null || true)
    target="$codewhale_downloads/$target_name"
    marker="$target.version"
    actual_sha=$(sha256sum "$target" 2>/dev/null | cut -d' ' -f1 || true)
    if [[ "$expected_version" == "$codewhale_version" \
        && "$expected_sha" =~ ^[0-9a-f]{64}$ \
        && -f "$target" && ! -L "$target" && -x "$target" \
        && -f "$marker" && ! -L "$marker" \
        && "$actual_sha" == "$expected_sha" ]] \
        && cmp -s -- "$marker" <(printf '%s' "$expected_version"); then
      ok "CodeWhale locked native asset $target_name@$expected_version"
    else
      bad "CodeWhale locked native asset $target_name"
    fi
  done

  if [[ "$SMOKE_ONLY" == "0" ]]; then
    actual_tree_hash=$(python3 "$NPM_CLOSURECTL" tree-digest "$closure_root" 2>/dev/null || true)
    [[ "$actual_tree_hash" == "$expected_tree_hash" ]] \
      && ok "npm installed tree matches its content address" \
      || bad "npm installed tree differs from its content address"
  fi

  bin_map=$(python3 "$NPM_CLOSURECTL" emit-bins "$closure_root" \
    --arch "$LOCK_ARCH" --immutable 2>/dev/null || true)
  while IFS=$'\t' read -r executable executable_target; do
    [[ -z "$executable" ]] && continue
    executable_link="$HOME/.npm-global/bin/$executable"
    if [[ -L "$executable_link" && "$(readlink "$executable_link")" == "$executable_target" ]]; then
      ok "declared npm bin $executable"
    else
      bad "declared npm bin $executable does not target locked closure"
    fi
  done <<< "$bin_map"

  package_map=$(python3 "$NPM_CLOSURECTL" emit-packages "$closure_root" \
    --arch "$LOCK_ARCH" --immutable 2>/dev/null || true)
  marker=$(cat "$HOME/.npm-global/lib/node_modules/.csr-closure-id" 2>/dev/null || true)
  [[ "$marker" == "$closure_root" ]] \
    && ok "npm compatibility tree identifies current closure" \
    || bad "npm compatibility tree marker differs from current closure"
  while IFS=$'\t' read -r package_name package_target; do
    [[ -z "$package_name" ]] && continue
    package_link="$HOME/.npm-global/lib/node_modules/$package_name"
    if [[ -L "$package_link" && "$(readlink "$package_link")" == "$package_target" ]]; then
      ok "npm compatibility package $package_name"
    else
      bad "npm compatibility package $package_name does not target locked closure"
    fi
  done <<< "$package_map"
else
  bad "npm direct/transitive package closure missing or invalid"
fi
[[ $SMOKE_ONLY -eq 1 ]] && { echo "smoke: $PASS ok, $FAILN fail"; exit $((FAILN>0)); }

echo "--- offline Python wheel closure ---"
PYTHON_LOCK="$REPO/system/python-closure/ubuntu-24.04-$LOCK_ARCH.lock.json"
PYTHON_WHEELHOUSE="$HOME/.cache/coding-system/python-wheelhouse/$LOCK_ARCH"
PYTHON_PROVENANCE="$PYTHON_WHEELHOUSE.provenance.json"
if [[ "$DEGRADED" == "1" ]]; then
  if python3 "$REPO/bin/install-python-closure.py" validate \
      --lock "$PYTHON_LOCK" >/dev/null; then
    ok "Python closure declarations are structurally valid (ci)"
    skp "Python wheelhouse extraction and eight installed inventories (ci)"
  else
    bad "Python closure declaration integrity"
  fi
else
  if python3 "$REPO/bin/extract-python-wheelhouse.py" verify-directory \
      --directory "$PYTHON_WHEELHOUSE" \
      --platform "linux/$LOCK_ARCH" \
      --lock "$REPO/system/software/images.lock.json" \
      --provenance "$PYTHON_PROVENANCE" >/dev/null \
    && python3 "$REPO/bin/install-python-closure.py" verify-all \
      --lock "$PYTHON_LOCK" \
      --images-lock "$REPO/system/software/images.lock.json" \
      --wheelhouse "$PYTHON_WHEELHOUSE" \
      --provenance "$PYTHON_PROVENANCE" \
      --home "$HOME" \
      --python python3 >/dev/null; then
    ok "Python OCI provenance + exact eight-environment inventories"
  else
    bad "Python OCI provenance or exact eight-environment inventories"
  fi
fi

echo "--- symlink topology ---"
# Without -e, an absent or zero-row symlinks.tsv makes the loop body never run
# and leaves FAILN untouched, so every declared symlink verifies as PASS.
if [[ ! -s "$REPO/system/symlinks.tsv" ]] \
  || ! /usr/bin/grep -qvE '^[[:space:]]*(#|$)' "$REPO/system/symlinks.tsv"; then
  bad "symlink declarations ($REPO/system/symlinks.tsv is absent or declares nothing)"
fi
while IFS=$'\t' read -r link target; do
  [[ -z "$link" || "$link" == \#* ]] && continue
  l="${link//\{\{ HOME \}\}/$HOME}"; t="${target//\{\{ HOME \}\}/$HOME}"
  if [[ -L "$l" && "$(readlink "$l")" == "$t" ]]; then ok "symlink $l"; else bad "symlink $l -> $t"; fi
done < "$REPO/system/symlinks.tsv"

echo "--- exact scheduler closure ---"
SCHEDULER_CANARY_PASSED=0
if [[ "$DEGRADED" == "1" ]]; then
  /usr/bin/bash -p "$REPO/bin/verify-schedulers.sh" --profile ci >/dev/null \
    && ok "scheduler declarations (ci; live state not asserted)" \
    || bad "scheduler declarations (ci)"
else
  scheduler_verify_args=(--profile full)
  if [[ -n "${CSR_SCHEDULER_NOT_BEFORE_UNIX:-}" ]]; then
    scheduler_verify_args+=(
      --not-before-unix "$CSR_SCHEDULER_NOT_BEFORE_UNIX"
    )
  fi
  if /usr/bin/bash -p "$REPO/bin/verify-schedulers.sh" "${scheduler_verify_args[@]}"; then
    SCHEDULER_CANARY_PASSED=1
    ok "host/systemd/OpenClaw schedules + execution canaries"
  else
    bad "host/systemd/OpenClaw scheduler closure"
  fi
fi
# Scheduled code runs through the selector from a sealed generation the owner
# owns, never from a root-owned tree (bin/publish-repository-generation.sh).
selector_target="$(/usr/bin/readlink "$HOME/.local/share/coding-system/repository" 2>/dev/null || true)"
case "$selector_target" in
  "$HOME/.local/share/coding-system/repository-generations/"*-*)
    generation_id="${selector_target##*/}"
    if /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
        "$REPO/bin/lib/repository_generation.py" verify --owner \
        --commit "${generation_id%%-*}" --tree "${generation_id#*-}" \
        --path "$selector_target" >/dev/null 2>&1; then
      ok "scheduled code runs from the owner's sealed generation ${generation_id:0:12}"
    else
      bad "owner repository generation failed verification: ${generation_id:0:12}"
    fi
    ;;
  *)
    [[ "$DEGRADED" == "1" ]] \
      && skp "repository selector is not an owner generation (degraded)" \
      || bad "repository selector does not point at an owner generation"
    ;;
esac

echo "--- configured MCP closure ---"
MCP_REPORT="$HOME/.local/state/coding-system/restore/mcp-verification.json"
mkdir -p "$(dirname "$MCP_REPORT")"
chmod 700 "$(dirname "$MCP_REPORT")"
rm -f -- "$MCP_REPORT"
if [[ "$DEGRADED" == "1" ]]; then
  if python3 "$REPO/bin/verify-configured-mcps.py" --repository "$REPO" \
      --root "$HOME" --mode declared --output "$MCP_REPORT" >/dev/null; then
    ok "MCP declarations are closed or explicitly inert (ci)"
  else
    bad "MCP declaration closure"
  fi
else
  if python3 "$REPO/bin/verify-configured-mcps.py" --repository "$REPO" \
      --root "$HOME" --mode full --path "$PATH" --timeout 20 \
      --output "$MCP_REPORT" >/dev/null; then
    ok "every enabled configured MCP completed initialize + tools/list"
  else
    bad "enabled configured MCP handshake closure"
  fi
fi

echo "--- generated shell completion ---"
if [[ "$DEGRADED" == "1" ]]; then
  skp "OpenClaw Bash completion (degraded)"
elif bash "$REPO/bin/materialize-openclaw-completion.sh" --verify >/dev/null; then
  ok "OpenClaw Bash completion is current and syntactically valid"
else
  bad "OpenClaw Bash completion missing, stale, or unsafe"
fi

echo "--- secrets ---"
if [[ "$DEGRADED" == "1" ]]; then
  skp "required secrets (degraded)"
else
  if /usr/bin/bash -p "$REPO/bin/secrets-verify.sh" >/dev/null; then
    ok "required secrets present"
  else
    bad "required secrets verification failed"
  fi
fi

SKILL_CREDENTIAL_REPORT="$HOME/.local/state/coding-system/restore/skill-credential-verification.json"
if [[ "$DEGRADED" == "1" ]]; then
  skp "skill credential authority/projection/resolver closure (degraded)"
else
  /usr/bin/install -d -m 0700 "$(dirname "$SKILL_CREDENTIAL_REPORT")"
  /usr/bin/rm -f -- "$SKILL_CREDENTIAL_REPORT"
  if /usr/bin/python3 -I -B "$REPO/bin/verify-skill-credentials.py" \
      --repository "$REPO" --home "$HOME" \
      --expect-source-capabilities \
        "$HOME/.config/coding-system/skill-credential-source-contract.json" \
      --output "$SKILL_CREDENTIAL_REPORT"; then
    ok "skill credential authority/projection/resolver closure"
  else
    bad "skill credential authority/projection/resolver closure"
  fi
fi

echo "--- Classroom50 restore closure ---"
CLASSROOM50_REPORT="$HOME/.local/state/coding-system/restore/classroom50-verification.json"
install -d -m 0700 "$(dirname "$CLASSROOM50_REPORT")"
rm -f -- "$CLASSROOM50_REPORT"
classroom50_args=(
  --repository "$REPO" --home "$HOME" --architecture "$LOCK_ARCH"
  --output "$CLASSROOM50_REPORT"
)
if [[ "$DEGRADED" == "1" ]]; then
  classroom50_args+=(--profile source)
else
  classroom50_args+=(--profile full)
fi
python3 "$REPO/bin/verify-classroom50.py" "${classroom50_args[@]}" >/dev/null
classroom50_rc=$?
classroom50_status=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["status"])' \
  "$CLASSROOM50_REPORT" 2>/dev/null || echo UNKNOWN)
case "$classroom50_rc" in
  0) ok "Classroom50 component/software/runtime/config state ($classroom50_status)" ;;
  1) ok "Classroom50 technical closure; nontechnical status=$classroom50_status" ;;
  *) bad "Classroom50 technical closure ($classroom50_status)" ;;
esac

echo "--- skill smokes ---"
if python3 "$REPO/bin/install-vendor-skills.py" --check --home "$HOME" >/dev/null 2>&1; then
  ok "pinned vendor skills match their lock"
else
  bad "pinned vendor skills are missing or differ from their lock"
fi
if [[ "${DEGRADED:-0}" == "1" ]]; then
  skp "zotero doctor / digest / sage / LeanExplore MCP (degraded)"
else
  if timeout 420 bash "$REPO/bin/verify-oci-runtime.sh" >/dev/null; then
    ok "locked OCI platform descriptors + SageMath + Translation Server"
  else
    bad "locked OCI platform descriptors or functional image smoke"
  fi
  if python3 "$REPO/bin/verify-lean-explore-mcp.py" \
      --command "$HOME/.local/bin/lean-explore-mcp-api" --timeout 20 >/dev/null; then
    ok "LeanExplore MCP initialize + tool inventory"
  else
    bad "LeanExplore MCP initialize + tool inventory"
  fi
  if [[ -x "$HOME/.openclaw/workspace/skills/zotero/run_zot.sh" ]]; then
    timeout 120 bash "$HOME/.openclaw/workspace/skills/zotero/run_zot.sh" doctor >/dev/null 2>&1 \
      && ok "zotero doctor" || bad "zotero doctor"
  else
    bad "OpenClaw Zotero runtime missing"
  fi
fi

echo "--- host diff against the reference baseline ---"
if [[ "$PROFILE" == "full" && -f "$HOME/.config/coding-system/host-baseline.json" ]]; then
  /usr/bin/python3 -I -B "$REPO/bin/verify-host-diff.py" >/dev/null 2>&1 \
    && ok "host matches its reference baseline, apart from approved exceptions" \
    || bad "host differs from its reference baseline (run bin/verify-host-diff.py)"
else
  skp "host diff (no reference baseline)"
fi

echo "--- components ---"
for c in openclaw-bot ai-agents-skills; do
  if [[ "$c" == "ai-agents-skills" ]]; then
    pin=$(/usr/bin/sed -n 's|^ai-agents-skills=.*@\([0-9a-f]\{40\}\)$|\1|p' "$REPO/components.lock")
    if [[ -d "$HOME/$c/.git" && "$pin" =~ ^[0-9a-f]{40}$ ]] \
      && /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C HOME=/nonexistent \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
        /usr/bin/git --no-replace-objects --no-optional-locks \
          -C "$HOME/$c" cat-file -e "$pin^{commit}" 2>/dev/null; then
      ok "component object present: ~/$c@${pin:0:12}"
    else
      [[ "$DEGRADED" == "1" ]] \
        && skp "component object absent: ~/$c (ci)" \
        || bad "component object absent: ~/$c"
    fi
    helper_digest=$(/usr/bin/sed -n 's/^  AAS_HELPER_SHA256="\([0-9a-f]\{64\}\)"$/\1/p' "$REPO/bin/install.sh")
    helper="$HOME/.local/share/coding-system/install-helpers/aas-component-$helper_digest.py"
    immutable="$HOME/.local/share/coding-system/components/ai-agents-skills/$pin"
    owner_uid=$(/usr/bin/id -u)
    if [[ "$helper_digest" =~ ^[0-9a-f]{64}$ && -e "$helper" ]]; then
      helper_hash=$(/usr/bin/sha256sum "$helper" 2>/dev/null | /usr/bin/cut -d' ' -f1 || true)
      if [[ -f "$helper" && ! -L "$helper" \
          && "$(/usr/bin/stat -c '%u:%a:%h' "$helper" 2>/dev/null)" == "$owner_uid:444:1" \
          && "$helper_hash" == "$helper_digest" ]]; then
        ok "component materializer bound: ${helper_digest:0:12}"
      else
        bad "component materializer authority/hash invalid"
      fi
    else
      [[ "$DEGRADED" == "1" ]] \
        && skp "component materializer not installed (ci)" \
        || bad "component materializer not installed"
    fi
    if [[ "$pin" =~ ^[0-9a-f]{40}$ && -e "$immutable" ]]; then
      if [[ -d "$immutable" && ! -L "$immutable" \
          && "$(/usr/bin/stat -c '%u:%a' "$immutable" 2>/dev/null)" == "$owner_uid:555" \
          && -f "$immutable/installer/bootstrap.sh" \
          && ! -L "$immutable/installer/bootstrap.sh" \
          && "$(/usr/bin/stat -c '%u:%a:%h' "$immutable/installer/bootstrap.sh" 2>/dev/null)" == "$owner_uid:555:1" ]]; then
        ok "component immutable authority: ${pin:0:12}"
      else
        bad "component immutable authority invalid: ${pin:0:12}"
      fi
    else
      [[ "$DEGRADED" == "1" ]] \
        && skp "component immutable authority not installed (ci)" \
        || bad "component immutable authority not installed"
    fi
  else
    if [[ -d "$REPO/external/$c/.git" ]]; then
      ok "component present: external/$c"
    elif [[ "$DEGRADED" == "1" ]]; then
      skp "component absent: external/$c (ci)"
    else
      bad "component absent: external/$c"
    fi
  fi
done

echo "--- installed ai-agents-skills state and runtime ---"
AAS_PIN=$(/usr/bin/sed -n 's|^ai-agents-skills=.*@\([0-9a-f]\{40\}\)$|\1|p' "$REPO/components.lock")
AAS_IMMUTABLE="$HOME/.local/share/coding-system/components/ai-agents-skills/$AAS_PIN"
AAS_RUNTIME_REPORT="$HOME/.local/state/coding-system/restore/aas-installed-runtime-smoke.json"
if [[ "$DEGRADED" == "1" ]]; then
  skp "installed ai-agents-skills state/runtime smoke (ci)"
elif [[ ! "$AAS_PIN" =~ ^[0-9a-f]{40}$ \
    || ! -d "$AAS_IMMUTABLE" || -L "$AAS_IMMUTABLE" \
    || ! -f "$AAS_IMMUTABLE/installer/bootstrap.sh" \
    || -L "$AAS_IMMUTABLE/installer/bootstrap.sh" ]]; then
  bad "immutable ai-agents-skills verifier unavailable"
else
  AAS_VERIFY_ENV=(
    PATH="$HOME/.npm-global/bin:$HOME/.local/bin:/usr/bin:/bin"
    LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC HOME="$HOME"
    USER="$(/usr/bin/id -un)" LOGNAME="$(/usr/bin/id -un)"
    SHELL=/bin/sh TMPDIR=/tmp
    XDG_CONFIG_HOME="$HOME/.config" XDG_DATA_HOME="$HOME/.local/share"
    XDG_CACHE_HOME="$HOME/.cache" XDG_STATE_HOME="$HOME/.local/state"
    AAS_PYTHON=/usr/bin/python3
    AAS_RUNTIME_PYTHON="$HOME/.local/share/coding-system/python-closure/shared/bin/python"
    PYTHONDONTWRITEBYTECODE=1
    PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1
  )
  if (
    cd "$AAS_IMMUTABLE" || exit 2
    /usr/bin/env -i "${AAS_VERIFY_ENV[@]}" \
      /bin/sh "$AAS_IMMUTABLE/installer/bootstrap.sh" \
        --root "$HOME" --agents "$AAS_RESTORE_AGENTS" verify >/dev/null
  ); then
    ok "all requested non-OpenClaw ai-agents-skills targets match managed state"
  else
    bad "requested non-OpenClaw ai-agents-skills managed state"
  fi

  install -d -m 0700 "$(dirname "$AAS_RUNTIME_REPORT")"
  rm -f -- "$AAS_RUNTIME_REPORT"
  AAS_RUNTIME_TMP=$(mktemp \
    "$(dirname "$AAS_RUNTIME_REPORT")/.aas-installed-runtime-smoke.XXXXXXXX" \
    2>/dev/null || true)
  if [[ -z "$AAS_RUNTIME_TMP" ]]; then
    bad "could not stage installed ai-agents-skills runtime-smoke evidence"
  else
    chmod 0600 "$AAS_RUNTIME_TMP"
    if (
      cd "$AAS_IMMUTABLE" || exit 2
      /usr/bin/env -i "${AAS_VERIFY_ENV[@]}" \
        /bin/sh "$AAS_IMMUTABLE/installer/bootstrap.sh" \
          --root "$HOME" --agents "$AAS_RESTORE_AGENTS" --json \
          installed-runtime-smoke --require-complete-coverage
    ) > "$AAS_RUNTIME_TMP" \
      && python3 - "$AAS_RUNTIME_TMP" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    report = json.load(stream)
valid = (
    report.get("schema") == "ai-agents-skills.installed-runtime-smoke.v1"
    and report.get("schema_version") == 1
    and report.get("mode") == "installed"
    and report.get("status") == "ok"
    and isinstance(report.get("checked"), int)
    and not isinstance(report.get("checked"), bool)
    and report["checked"] > 0
    and report.get("unknown_coverage_count") == 0
    and report.get("missing_managed_runtime_count") == 0
)
raise SystemExit(0 if valid else 1)
PY
    then
      mv -f -- "$AAS_RUNTIME_TMP" "$AAS_RUNTIME_REPORT"
      chmod 0600 "$AAS_RUNTIME_REPORT"
      ok "installed ai-agents-skills runtime smoke has complete declared coverage"
    else
      rm -f -- "$AAS_RUNTIME_TMP"
      bad "installed ai-agents-skills runtime smoke or coverage"
    fi
  fi
fi

echo "--- OpenClaw effective runtime closure ($PROFILE) ---"
OPENCLAW_RUNTIME_PASSED=0
OPENCLAW_RUNTIME_REPORT="$HOME/.local/state/coding-system/restore/openclaw-runtime-verification.json"
install -d -m 0700 "$(dirname "$OPENCLAW_RUNTIME_REPORT")"
rm -f -- "$OPENCLAW_RUNTIME_REPORT"
if [[ "$PROFILE" != "smoke" ]]; then
  if python3 "$REPO/bin/verify-openclaw-runtime.py" --profile "$PROFILE" \
      --output "$OPENCLAW_RUNTIME_REPORT"; then
    OPENCLAW_RUNTIME_PASSED=1
    ok "OpenClaw effective runtime closure ($PROFILE)"
  else
    bad "OpenClaw effective runtime closure ($PROFILE)"
  fi
fi

echo "--- target-neutral agent readiness ---"
TARGET_REPORT="$HOME/.local/state/coding-system/restore/target-state.json"
install -d -m 0700 "$(dirname "$TARGET_REPORT")"
rm -f -- "$TARGET_REPORT"
TARGET_MANIFEST="$HOME/.local/share/coding-system/components/ai-agents-skills/$AAS_PIN/manifest/target-state.yaml"
if [[ "$DEGRADED" == "1" && ! -f "$TARGET_MANIFEST" \
    && -f "$HOME/ai-agents-skills/manifest/target-state.yaml" ]]; then
  TARGET_MANIFEST="$HOME/ai-agents-skills/manifest/target-state.yaml"
fi
if [[ ! -f "$TARGET_MANIFEST" ]]; then
  [[ "$DEGRADED" == "1" ]] && skp "target-state manifest unavailable in CI" \
    || bad "target-state manifest unavailable"
else
  target_args=(
    --manifest "$TARGET_MANIFEST" --root "$HOME"
    --path "$HOME/.local/bin:$PATH"
  )
  if [[ "$DEGRADED" == "1" ]]; then
    target_args+=(--readiness-phase pre-runtime)
  else
    target_args+=(
      --readiness-phase full
      --mcp-report "$MCP_REPORT"
      --runtime-smoke-report "$AAS_RUNTIME_REPORT"
      --openclaw-runtime-report "$OPENCLAW_RUNTIME_REPORT"
    )
    [[ "$OPENCLAW_RUNTIME_PASSED" == "1" ]] \
      && target_args+=(--openclaw-runtime-passed)
    [[ "$SCHEDULER_CANARY_PASSED" == "1" ]] && target_args+=(--scheduler-canary-passed)
  fi
  python3 "$REPO/bin/verify-target-state.py" "${target_args[@]}" --output "$TARGET_REPORT"
  target_rc=$?
  target_status=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' \
    "$TARGET_REPORT" 2>/dev/null || echo UNKNOWN)
  case "$target_rc" in
    0) ok "agent target state ($target_status)" ;;
    1) ok "agent target software/config technical state; nontechnical status=$target_status" ;;
    *) bad "agent target technical state ($target_status)" ;;
  esac
fi

echo
echo "verify: $PASS ok, $FAILN fail, $SKIP skipped"
if [[ "$PROFILE" != "smoke" && "$LOCK_ARCH" != unsupported ]]; then
  EVIDENCE_OUTPUT="$HOME/.local/state/coding-system/restore/verification-evidence.v1.json"
  evidence_args=(
    --repository "$REPO" --output "$EVIDENCE_OUTPUT"
    --profile "$PROFILE" --architecture "$LOCK_ARCH"
    --restore-run-id "$CODING_SYSTEM_RESTORE_RUN_ID"
    --run-started-at-unix "$CODING_SYSTEM_RESTORE_RUN_STARTED_AT_UNIX"
    --target-report "$TARGET_REPORT"
    --classroom50-report "$CLASSROOM50_REPORT"
  )
  [[ -z "$EXPECTED_EVIDENCE_COMMIT" ]] \
    || evidence_args+=(--expected-commit "$EXPECTED_EVIDENCE_COMMIT")
  for label in "${PASS_LABELS[@]}"; do evidence_args+=(--pass-label "$label"); done
  for label in "${FAIL_LABELS[@]}"; do evidence_args+=(--fail-label "$label"); done
  for label in "${SKIP_LABELS[@]}"; do evidence_args+=(--skip-label "$label"); done
  python3 "$REPO/bin/write-verification-evidence.py" "${evidence_args[@]}" \
    || { echo "FAIL  could not persist verification evidence" >&2; FAILN=$((FAILN+1)); }
fi
exit $((FAILN>0))
