#!/usr/bin/env bash
# Full restore orchestrator for a fresh Ubuntu machine (12 gated phases).
# Usage: SECRETS=/path/to/secrets.zip bin/install.sh   (degraded without SECRETS)
# Env:   PHASE=n  resume from phase n;  SKIP_* forwarded to prepare.sh
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
START="${PHASE:-1}"
DEGRADED_MODE=0
[[ -z "${SECRETS:-}" ]] && DEGRADED_MODE=1
export DEGRADED_MODE

phase() { echo; echo "########## PHASE $1: $2 ##########"; }
gate()  { echo "---- gate: $1"; }
skip_enabled() { [[ "${!1:-0}" == "1" ]]; }

structured_grok_release_gate() {
  /usr/bin/python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

RID = re.compile(r"^[0-9a-f]{64}$")
SCHEMA_VERSION = 2
OUTPUT_LIMIT = 1024 * 1024


class GateError(RuntimeError):
    pass


def require_root_directory(path: Path) -> None:
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or (info.st_uid, info.st_gid) != (0, 0)
        or stat.S_IMODE(info.st_mode) != 0o755
    ):
        raise GateError(f"unsafe installed release directory: {path}")


def run_json(command: list[str], label: str) -> dict[str, object]:
    def metadata(stream: object) -> tuple[int, str]:
        stream.flush()
        size = os.fstat(stream.fileno()).st_size
        stream.seek(0)
        digest = hashlib.sha256()
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return size, digest.hexdigest()

    with tempfile.TemporaryFile(mode="w+b") as stdout_stream, tempfile.TemporaryFile(
        mode="w+b"
    ) as stderr_stream:
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_stream,
                stderr=stderr_stream,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout_size, stdout_sha256 = metadata(stdout_stream)
            stderr_size, stderr_sha256 = metadata(stderr_stream)
            raise GateError(
                f"{label} timed out; stdout_bytes={stdout_size} "
                f"stdout_sha256={stdout_sha256} stderr_bytes={stderr_size} "
                f"stderr_sha256={stderr_sha256}"
            ) from exc
        stdout_size, stdout_sha256 = metadata(stdout_stream)
        stderr_size, stderr_sha256 = metadata(stderr_stream)
        if (
            result.returncode != 0
            or stdout_size > OUTPUT_LIMIT
            or stderr_size > OUTPUT_LIMIT
        ):
            raise GateError(
                f"{label} failed; returncode={result.returncode} "
                f"stdout_bytes={stdout_size} stdout_sha256={stdout_sha256} "
                f"stderr_bytes={stderr_size} stderr_sha256={stderr_sha256}"
            )
        stdout_stream.seek(0)
        try:
            value = json.loads(stdout_stream.read(OUTPUT_LIMIT + 1))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GateError(f"{label} did not return JSON") from exc
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise GateError(f"{label} schema is invalid")
    return value


def validate_status(
    value: dict[str, object], release_id: str, label: str
) -> list[object]:
    expected = {
        "active_release_id": release_id,
        "active_release_valid": True,
        "active_root_release_id": release_id,
        "active_user_release_id": release_id,
        "release_access_policy_valid": True,
        "rollback_denied": False,
        "rollback_eligibility_complete": True,
    }
    if any(value.get(name) != expected_value for name, expected_value in expected.items()):
        raise GateError(f"{label} is not one coherent admitted release")
    eligible = value.get("rollback_eligible_releases")
    if not isinstance(eligible, list) or release_id not in eligible:
        raise GateError(f"{label} has incomplete rollback eligibility")
    if value.get("exposed_user_releases") != [release_id]:
        raise GateError(f"{label} user release exposure is not exact")
    return eligible


try:
    root = Path("/usr/local/libexec/grok-proxy")
    releases = root / "releases"
    current = root / "current"
    require_root_directory(root)
    require_root_directory(releases)
    selector_info = current.lstat()
    if (
        not stat.S_ISLNK(selector_info.st_mode)
        or (selector_info.st_uid, selector_info.st_gid) != (0, 0)
    ):
        raise GateError("installed root release selector is unsafe")
    target = os.readlink(current)
    parts = Path(target).parts
    if len(parts) != 2 or parts[0] != "releases" or RID.fullmatch(parts[1]) is None:
        raise GateError("installed root release selector target is invalid")
    release_id = parts[1]
    dispatcher = releases / release_id / "install-release.py"
    dispatcher_info = dispatcher.lstat()
    if (
        dispatcher.is_symlink()
        or not stat.S_ISREG(dispatcher_info.st_mode)
        or (dispatcher_info.st_uid, dispatcher_info.st_gid) != (0, 0)
        or dispatcher_info.st_nlink != 1
        or stat.S_IMODE(dispatcher_info.st_mode) & 0o022
    ):
        raise GateError("installed release status dispatcher is unsafe")
    status = run_json(
        [
            "/usr/bin/sudo",
            "-n",
            "--",
            "/usr/bin/python3",
            "-I",
            "-B",
            str(dispatcher),
            "status",
        ],
        "installed immutable release status",
    )
    eligible = validate_status(status, release_id, "installed immutable release status")

    bootstrap = Path("/usr/local/libexec/grok-proxy/bootstrap")
    bootstrap_store = Path("/usr/local/libexec/grok-proxy/bootstrap-releases")
    require_root_directory(bootstrap)
    require_root_directory(bootstrap_store)
    bootstrap_binary = bootstrap / "grok-bootstrap"
    binary_info = bootstrap_binary.lstat()
    if (
        bootstrap_binary.is_symlink()
        or not stat.S_ISREG(binary_info.st_mode)
        or (binary_info.st_uid, binary_info.st_gid) != (0, 0)
        or stat.S_IMODE(binary_info.st_mode) != 0o555
        or binary_info.st_nlink != 1
    ):
        raise GateError("trusted Grok bootstrap executable is unsafe")
    bootstrap_lock = bootstrap / "update.lock"
    lock_info = bootstrap_lock.lstat()
    if (
        bootstrap_lock.is_symlink()
        or not stat.S_ISREG(lock_info.st_mode)
        or (lock_info.st_uid, lock_info.st_gid) != (0, 0)
        or stat.S_IMODE(lock_info.st_mode) != 0o600
        or lock_info.st_nlink != 1
        or lock_info.st_size != 0
    ):
        raise GateError("trusted Grok bootstrap update lock is unsafe")
    bootstrap_selector = bootstrap / "selected-release"
    selector_info = bootstrap_selector.lstat()
    selector_raw = bootstrap_selector.read_bytes()
    if (
        bootstrap_selector.is_symlink()
        or not stat.S_ISREG(selector_info.st_mode)
        or (selector_info.st_uid, selector_info.st_gid) != (0, 0)
        or stat.S_IMODE(selector_info.st_mode) != 0o444
        or selector_info.st_nlink != 1
        or re.fullmatch(rb"[0-9a-f]{64}\n", selector_raw) is None
    ):
        raise GateError("trusted Grok bootstrap selector is unsafe")
    bootstrap_release_id = selector_raw[:-1].decode("ascii")
    bootstrap_release = bootstrap_store / bootstrap_release_id
    release_info = bootstrap_release.lstat()
    if (
        bootstrap_release.is_symlink()
        or not stat.S_ISDIR(release_info.st_mode)
        or (release_info.st_uid, release_info.st_gid) != (0, 0)
        or stat.S_IMODE(release_info.st_mode) != 0o555
    ):
        raise GateError("signed Grok bootstrap release is unsafe")
    artifacts = {"dispatcher.pyz", "release-manifest.sig", "release-manifest.txt"}
    if {entry.name for entry in bootstrap_release.iterdir()} != artifacts:
        raise GateError("signed Grok bootstrap release shape is invalid")
    for name in artifacts:
        artifact = bootstrap_release / name
        artifact_info = artifact.lstat()
        if (
            artifact.is_symlink()
            or not stat.S_ISREG(artifact_info.st_mode)
            or (artifact_info.st_uid, artifact_info.st_gid) != (0, 0)
            or stat.S_IMODE(artifact_info.st_mode) != 0o444
            or artifact_info.st_nlink != 1
        ):
            raise GateError(f"signed Grok bootstrap artifact is unsafe: {name}")
    bootstrap_status = run_json(
        [
            "/usr/bin/sudo",
            "-n",
            "--",
            str(bootstrap_binary),
            "--release-dir",
            str(bootstrap_release),
            "--",
            "status",
        ],
        "signed native bootstrap status",
    )
    bootstrap_eligible = validate_status(
        bootstrap_status, release_id, "signed native bootstrap status"
    )

    records = (
        {
            "case_id": "install.phase6.grok-install",
            "install_result_valid": True,
            "release_id": release_id,
            "schema_version": 1,
            "status": "passed",
        },
        {
            "active_release_id": release_id,
            "bootstrap_release_id": bootstrap_release_id,
            "case_id": "install.phase6.grok-bootstrap-status",
            "rollback_eligible_releases": bootstrap_eligible,
            "schema_version": 1,
            "signed_dispatcher_status_valid": True,
            "status": "passed",
        },
        {
            "active_release_id": release_id,
            "active_release_valid": True,
            "active_root_release_id": release_id,
            "active_user_release_id": release_id,
            "case_id": "install.phase6.grok-status",
            "exposed_user_releases": [release_id],
            "release_access_policy_valid": True,
            "rollback_denied": False,
            "rollback_eligible_releases": eligible,
            "rollback_eligibility_complete": True,
            "schema_version": 1,
            "status": "passed",
        },
    )
    for record in records:
        print(
            "CSR_GATE_JSON "
            + json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        )
except (GateError, OSError, subprocess.SubprocessError) as exc:
    print(f"install-grok-gate: {exc}", file=sys.stderr)
    raise SystemExit(2)
PY
}

if [[ $DEGRADED_MODE -eq 1 ]]; then
  echo "*** DEGRADED MODE: no SECRETS archive provided ***"
  echo "*** the following features will not work until secrets are restored: ***"
  bash "$REPO/bin/secrets-verify.sh" --degraded || true
fi

# 1 ─ bootstrap checks
if (( START <= 1 )); then
  phase 1 "doctor preflight"
  bash "$REPO/bin/doctor.sh"
  mkdir -p "$HOME/.config/coding-system"
fi

# 2 ─ system software
if (( START <= 2 )); then
  phase 2 "prepare (software + images; SKIP_* toggles apply)"
  bash "$REPO/bin/prepare.sh"
  gate "binaries respond"
  for b in git jq pandoc python3; do command -v "$b" >/dev/null || { echo "FAIL: $b missing"; exit 2; }; done
  skip_enabled SKIP_NODE || command -v node >/dev/null || { echo "FAIL: node missing"; exit 2; }
  { skip_enabled SKIP_NODE || skip_enabled SKIP_NPM_GLOBALS; } || command -v npm >/dev/null || { echo "FAIL: npm missing"; exit 2; }
  skip_enabled SKIP_DOCKER || command -v docker >/dev/null || { echo "FAIL: docker missing"; exit 2; }
fi

# 3 ─ secrets
if (( START <= 3 )); then
  if [[ $DEGRADED_MODE -eq 0 ]]; then
    phase 3 "restore secrets"
    SECRETS="$SECRETS" bash "$REPO/bin/secrets-restore.sh"
    gate "required secrets present"
    bash "$REPO/bin/secrets-verify.sh"
    if [[ -f "$HOME/.config/coding-system/tailscale.env" ]]; then
      # shellcheck disable=SC1091
      . "$HOME/.config/coding-system/tailscale.env"
      # TS_HOSTNAME keeps the funnel URLs (https://<name>.<tailnet>.ts.net/...)
      # working after restore — the webhook channels depend on the node name
      [[ -n "${TS_AUTHKEY:-}" ]] && \
        sudo tailscale up --authkey "$TS_AUTHKEY" ${TS_HOSTNAME:+--hostname "$TS_HOSTNAME"} || true
    fi
  else
    phase 3 "restore secrets — SKIPPED (degraded)"
  fi
fi

# 4 ─ (toolchains are part of prepare.sh; placeholder retained for numbering)

# 5 ─ components
if (( START <= 5 )); then
  phase 5 "components (openclaw-bot, ai-agents-skills)"
  bash "$REPO/bin/components.sh" || [[ $DEGRADED_MODE -eq 1 ]]
fi

# 6 ─ render public configs
if (( START <= 6 )); then
  phase 6 "render-install (configs, shell blocks, scripts, symlinks, atomic Grok release)"
  bash "$REPO/bin/render-install.sh"
  gate "grok-proxy user/root selectors name one validated immutable release"
  structured_grok_release_gate
  # ~/.local/bin wrappers from system/bin
  mkdir -p "$HOME/.local/bin"
  for f in "$REPO"/system/bin/*; do
    [[ -f "$f" && "$(basename "$f")" != usr-local-bin.tsv ]] || continue
    sed "s|{{ HOME }}|$HOME|g" "$f" > "$HOME/.local/bin/$(basename "$f")"
    chmod +x "$HOME/.local/bin/$(basename "$f")"
  done
fi

# 7 ─ OpenClaw slice (delegated component)
if (( START <= 7 )); then
  phase 7 "OpenClaw slice via openclaw-bot"
  if [[ -x "$REPO/external/openclaw-bot/install.sh" ]]; then
    SHA_BEFORE=$(sha256sum "$HOME/.openclaw/secrets.json" 2>/dev/null | cut -d' ' -f1 || true)
    bash "$REPO/external/openclaw-bot/install.sh" --prefix "$HOME/.openclaw" --skip-docker --skip-services --skip-config
    # the "don't clobber restored secrets" gate only applies when secrets were
    # actually restored (non-degraded); in degraded mode there is no live
    # secrets.json to protect and the component renders one from its template.
    if [[ $DEGRADED_MODE -eq 0 ]]; then
      gate "restored secrets untouched"
      SHA_AFTER=$(sha256sum "$HOME/.openclaw/secrets.json" 2>/dev/null | cut -d' ' -f1 || true)
      [[ "$SHA_BEFORE" == "$SHA_AFTER" ]] || { echo "FAIL: openclaw-bot install clobbered restored secrets.json"; exit 2; }
    fi
    if [[ -d "$HOME/.openclaw/npm/projects" ]]; then
      for p in "$HOME/.openclaw/npm/projects"/*/; do
        [[ -f "$p/package.json" ]] && (cd "$p" && npm install --silent || echo "WARN: npm install failed in $p")
      done
    fi
    gate "openclaw config has no dangling openclaw-src references"
    grep -q 'openclaw-src' "$HOME/.openclaw/openclaw.json" 2>/dev/null && { echo "FAIL: openclaw.json references openclaw-src"; exit 2; } || true
  else
    echo "WARN: openclaw-bot component unavailable — OpenClaw slice skipped"
  fi
fi

# 8 ─ skills via ai-agents-skills
if (( START <= 8 )); then
  phase 8 "skills via ai-agents-skills installer"
  AAS_HOME="$HOME/ai-agents-skills"
  AAS_HELPER_SOURCE="$REPO/bin/lib/aas_component.py"
  AAS_HELPER_SHA256="516b6840f2f1be73018d39c666f21380c2c8604c2b98a44598d1241e0e1f7aad"
  AAS_HELPER_ROOT="/usr/local/libexec/coding-system/install-helpers"
  AAS_COMPONENT_ROOT="/usr/local/libexec/coding-system/components/ai-agents-skills"
  [[ -d "$AAS_HOME" && ! -L "$AAS_HOME" \
      && -d "$AAS_HOME/.git" && ! -L "$AAS_HOME/.git" ]] \
    || { echo "FAIL: ai-agents-skills object repository is unavailable or unsafe"; exit 2; }
  [[ -f "$AAS_HELPER_SOURCE" && ! -L "$AAS_HELPER_SOURCE" ]] \
    || { echo "FAIL: immutable ai-agents-skills materializer is unavailable"; exit 2; }
  # Bind the helper through stdin before root sees it.  A bounded no-follow
  # opener validates one regular-file descriptor, the root transaction accepts
  # only its build-time digest, and
  # every later privileged invocation uses the resulting root-owned immutable
  # pathname.  A concurrent replacement of the checkout path therefore either
  # leaves the opened bytes unchanged or fails the digest gate; it can never
  # become Python executed by root.
  AAS_BOUND_HELPER="$(
    set -o pipefail
    /usr/bin/timeout 10s /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /usr/bin/python3 -I -B -c '
import hashlib
import os
import stat
import sys

path, expected = sys.argv[1:]
flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
descriptor = os.open(path, flags)
try:
    information = os.fstat(descriptor)
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_nlink != 1
        or information.st_size <= 0
        or information.st_size > 1024 * 1024
    ):
        raise SystemExit(2)
    chunks = []
    remaining = information.st_size
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            raise SystemExit(2)
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise SystemExit(2)
finally:
    os.close(descriptor)
payload = b"".join(chunks)
if hashlib.sha256(payload).hexdigest() != expected:
    raise SystemExit(2)
sys.stdout.buffer.write(payload)
sys.stdout.buffer.flush()
' "$AAS_HELPER_SOURCE" "$AAS_HELPER_SHA256" \
    | /usr/bin/timeout 30s /usr/bin/sudo -n -- \
      /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /bin/sh -eu -c '
        expected=$1
        case "$expected" in
          *[!0-9a-f]*)
            exit 2
            ;;
        esac
        test "${#expected}" -eq 64 || exit 2
        root=/usr/local/libexec/coding-system/install-helpers
        target=$root/aas-component-$expected.py

        require_root_dir() {
          path=$1
          test ! -L "$path" && test -d "$path" \
            && test "$(/usr/bin/stat -c %u:%g:%a -- "$path")" = 0:0:755
        }
        for path in /usr /usr/local /usr/local/libexec; do
          require_root_dir "$path" || exit 2
        done
        for path in /usr/local/libexec/coding-system "$root"; do
          if test ! -e "$path" && test ! -L "$path"; then
            /usr/bin/mkdir -m 0755 -- "$path"
          fi
          require_root_dir "$path" || exit 2
        done

        verify_target() {
          test ! -L "$target" && test -f "$target" \
            && test "$(/usr/bin/stat -c %u:%g:%a:%h -- "$target")" = 0:0:444:1 \
            && test "$(/usr/bin/stat -c %s -- "$target")" -gt 0 \
            && test "$(/usr/bin/stat -c %s -- "$target")" -le 1048576 \
            && actual=$(/usr/bin/sha256sum -- "$target") \
            && test "${actual%% *}" = "$expected"
        }
        stage=$(/usr/bin/mktemp "$root/.stage-$expected.XXXXXXXX")
        trap '\''/usr/bin/rm -f -- "$stage"'\'' 0 1 2 3 15
        /usr/bin/dd of="$stage" bs=1048577 count=1 iflag=fullblock status=none
        test "$(/usr/bin/stat -c %s -- "$stage")" -gt 0 \
          && test "$(/usr/bin/stat -c %s -- "$stage")" -le 1048576 \
          || exit 2
        actual=$(/usr/bin/sha256sum -- "$stage")
        test "${actual%% *}" = "$expected" || exit 2
        /usr/bin/chown 0:0 -- "$stage"
        /usr/bin/chmod 0444 -- "$stage"
        /usr/bin/sync -f "$stage"
        if test -e "$target" || test -L "$target"; then
          verify_target || exit 2
        elif /usr/bin/ln -- "$stage" "$target" 2>/dev/null; then
          :
        else
          verify_target || exit 2
        fi
        /usr/bin/rm -f -- "$stage"
        stage=
        trap - 0 1 2 3 15
        /usr/bin/sync -f "$root"
        verify_target || exit 2
        /usr/bin/printf "%s\n" "$target"
      ' sh "$AAS_HELPER_SHA256"
  )" || { echo "FAIL: cannot bind immutable ai-agents-skills materializer"; exit 2; }
  [[ "$AAS_BOUND_HELPER" == "$AAS_HELPER_ROOT/aas-component-$AAS_HELPER_SHA256.py" ]] \
    || { echo "FAIL: immutable ai-agents-skills materializer path is invalid"; exit 2; }
  AAS_HELPER="$AAS_BOUND_HELPER"
  mapfile -t AAS_LOCK_LINES < <(grep '^ai-agents-skills=' "$REPO/components.lock")
  [[ ${#AAS_LOCK_LINES[@]} -eq 1 ]] \
    || { echo "FAIL: components.lock must contain one ai-agents-skills pin"; exit 2; }
  AAS_PIN="${AAS_LOCK_LINES[0]##*@}"
  [[ "$AAS_PIN" =~ ^[0-9a-f]{40}$ ]] \
    || { echo "FAIL: ai-agents-skills pin is not one full commit SHA"; exit 2; }
  AAS_GIT_ENV=(
    PATH=/usr/bin:/bin LANG=C LC_ALL=C HOME=/nonexistent
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0
  )
  AAS_OBJECT="$(/usr/bin/timeout 30s /usr/bin/env -i "${AAS_GIT_ENV[@]}" \
    /usr/bin/git --no-replace-objects --no-optional-locks \
      -C "$AAS_HOME" rev-parse --verify "$AAS_PIN^{commit}" 2>/dev/null)" \
    || { echo "FAIL: cannot resolve pinned ai-agents-skills object"; exit 2; }
  [[ "$AAS_OBJECT" == "$AAS_PIN" ]] \
    || { echo "FAIL: resolved ai-agents-skills object does not match its pin"; exit 2; }
  AAS_TREE="$(/usr/bin/timeout 30s /usr/bin/env -i "${AAS_GIT_ENV[@]}" \
    /usr/bin/git --no-replace-objects --no-optional-locks \
      -C "$AAS_HOME" rev-parse --verify "$AAS_PIN^{tree}" 2>/dev/null)" \
    || { echo "FAIL: cannot resolve pinned ai-agents-skills tree"; exit 2; }
  [[ "$AAS_TREE" =~ ^[0-9a-f]{40}$ ]] \
    || { echo "FAIL: ai-agents-skills tree identity is invalid"; exit 2; }
  /usr/bin/timeout 60s /usr/bin/env -i "${AAS_GIT_ENV[@]}" \
    /usr/bin/git --no-replace-objects --no-optional-locks \
      -C "$AAS_HOME" fsck --strict --no-dangling --no-reflogs "$AAS_PIN" \
      >/dev/null 2>&1 \
    || { echo "FAIL: pinned ai-agents-skills object closure is invalid"; exit 2; }
  if ! (
    set -o pipefail
    /usr/bin/timeout 30s /usr/bin/env -i "${AAS_GIT_ENV[@]}" \
      /usr/bin/git --no-replace-objects --no-optional-locks \
        -C "$AAS_HOME" ls-tree -rz --full-tree "$AAS_PIN" \
    | /usr/bin/timeout 30s /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
        /usr/bin/python3 -I -B "$AAS_HELPER" validate-archive-source "$AAS_PIN"
  ); then
    echo "FAIL: pinned ai-agents-skills Git tree is unsafe"
    exit 2
  fi

  AAS_ROOT_ENV=(PATH=/usr/bin:/bin LANG=C LC_ALL=C)
  AAS_STAGE="$(/usr/bin/sudo -n -- /usr/bin/env -i "${AAS_ROOT_ENV[@]}" \
    /usr/bin/python3 -I -B "$AAS_HELPER" prepare "$AAS_PIN")" \
    || { echo "FAIL: cannot prepare immutable ai-agents-skills materialization"; exit 2; }
  [[ "$AAS_STAGE" == "$AAS_COMPONENT_ROOT/.stage-$AAS_PIN-"[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f] ]] \
    || { echo "FAIL: immutable ai-agents-skills staging path is invalid"; exit 2; }
  aas_cleanup_stage() {
    if [[ -n "${AAS_STAGE:-}" \
        && "$AAS_STAGE" == "$AAS_COMPONENT_ROOT/.stage-$AAS_PIN-"* ]]; then
      /usr/bin/sudo -n -- /usr/bin/env -i "${AAS_ROOT_ENV[@]}" \
        /usr/bin/python3 -I -B "$AAS_HELPER" discard "$AAS_PIN" "$AAS_STAGE" \
        >/dev/null 2>&1 || true
    fi
  }
  trap aas_cleanup_stage EXIT
  if ! (
    set -o pipefail
    umask 022
    /usr/bin/timeout 60s /usr/bin/env -i "${AAS_GIT_ENV[@]}" \
      /usr/bin/python3 -I -B "$AAS_HELPER" emit-raw-tar \
        "$AAS_PIN" "$AAS_HOME" \
    | /usr/bin/sudo -n -- /usr/bin/env -i "${AAS_ROOT_ENV[@]}" \
        /usr/bin/tar --extract --file=- --directory="$AAS_STAGE" \
          --no-same-owner --same-permissions --delay-directory-restore \
          --no-overwrite-dir
  ); then
    echo "FAIL: cannot extract pinned ai-agents-skills object"
    exit 2
  fi
  if ! (
    set -o pipefail
    /usr/bin/timeout 30s /usr/bin/env -i "${AAS_GIT_ENV[@]}" \
      /usr/bin/git --no-replace-objects --no-optional-locks \
        -C "$AAS_HOME" ls-tree -rz --full-tree "$AAS_PIN" \
    | /usr/bin/sudo -n -- /usr/bin/env -i "${AAS_ROOT_ENV[@]}" \
        /usr/bin/python3 -I -B "$AAS_HELPER" verify-extracted \
          "$AAS_PIN" "$AAS_STAGE"
  ); then
    echo "FAIL: extracted ai-agents-skills tree differs from its Git object"
    exit 2
  fi
  AAS_IMMUTABLE="$(/usr/bin/sudo -n -- /usr/bin/env -i "${AAS_ROOT_ENV[@]}" \
    /usr/bin/python3 -I -B "$AAS_HELPER" publish "$AAS_PIN" "$AAS_STAGE")" \
    || { echo "FAIL: cannot publish immutable ai-agents-skills object"; exit 2; }
  [[ "$AAS_IMMUTABLE" == "$AAS_COMPONENT_ROOT/$AAS_PIN" ]] \
    || { echo "FAIL: immutable ai-agents-skills publication path is invalid"; exit 2; }
  AAS_STAGE=""
  trap - EXIT
  /usr/bin/sudo -n -- /usr/bin/env -i "${AAS_ROOT_ENV[@]}" \
    /usr/bin/python3 -I -B "$AAS_HELPER" verify "$AAS_PIN" >/dev/null \
    || { echo "FAIL: immutable ai-agents-skills object failed verification"; exit 2; }
  printf 'CSR_GATE_JSON {"case_id":"install.phase8.aas-pin","closed_environment":true,"commit":"%s","execution_source":"root-owned-pinned-object","schema_version":1,"source_root":"%s","status":"passed","tree":"%s"}\n' \
    "$AAS_PIN" "$AAS_IMMUTABLE" "$AAS_TREE"

  # The compatibility checkout supplies only the cryptographic Git object.
  # Installer execution and any reference-mode output are anchored to the
  # stable root-owned content-addressed materialization.
  AAS_USER="$(/usr/bin/id -un)"
  AAS_CLOSED_ENV=(
    PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
    HOME="$HOME" USER="$AAS_USER" LOGNAME="$AAS_USER" SHELL=/bin/sh TMPDIR=/tmp
    XDG_CONFIG_HOME="$HOME/.config" XDG_DATA_HOME="$HOME/.local/share"
    XDG_CACHE_HOME="$HOME/.cache" XDG_STATE_HOME="$HOME/.local/state"
    AAS_PYTHON=/usr/bin/python3 PYTHONDONTWRITEBYTECODE=1
    PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1
  )
  AAS_PHRASE="I understand the installation and uninstall process"
  (
    cd "$AAS_IMMUTABLE"
    /usr/bin/env -i "${AAS_CLOSED_ENV[@]}" AAS_INSTALL_CONFIRM="$AAS_PHRASE" \
      /bin/sh "$AAS_IMMUTABLE/installer/bootstrap.sh" install \
        --skills modal-research-compute --runtime-profile auto \
        --apply --real-system --backup-replace
  )
  echo 'CSR_GATE_JSON {"case_id":"install.phase8.aas-install","schema_version":1,"status":"passed"}'
  (
    cd "$AAS_IMMUTABLE"
    /usr/bin/env -i "${AAS_CLOSED_ENV[@]}" \
      /bin/sh "$AAS_IMMUTABLE/installer/bootstrap.sh" verify
  )
  echo 'CSR_GATE_JSON {"case_id":"install.phase8.aas-verify","schema_version":1,"status":"passed"}'
  phase 8b "re-overlay zip secrets (idempotent re-extract) + clobber checks"
  if [[ $DEGRADED_MODE -eq 0 ]]; then
    SECRETS="$SECRETS" bash "$REPO/bin/secrets-restore.sh"
  fi
  gate "_run.sh intact"
  if [[ -f "$HOME/.config/coding-system/run_sh.sha256" && -f "$HOME/.claude/skills/_run.sh" ]]; then
    want=$(cat "$HOME/.config/coding-system/run_sh.sha256")
    have=$(sha256sum "$HOME/.claude/skills/_run.sh" | cut -d' ' -f1)
    [[ "$want" == "$have" ]] || { echo "FAIL: _run.sh changed during phase 8"; exit 2; }
  fi
fi

# 9 ─ python environments
if (( START <= 9 )); then
  phase 9 "python environments from pip freezes"
  RQ="$REPO/system/packages/requirements"
  mkdir -p "$HOME/.openclaw/workspace/.local"
  [[ -s "$RQ/workspace-local.txt" ]] && python3 -m pip install -q --target "$HOME/.openclaw/workspace/.local" -r "$RQ/workspace-local.txt" || true
  if [[ -s "$RQ/venvs.txt" ]]; then
    [[ -d "$HOME/.venvs" ]] || python3 -m venv "$HOME/.venvs"
    "$HOME/.venvs/bin/pip" install -q -r "$RQ/venvs.txt" || true
  fi
  if [[ -s "$RQ/docling-venv.txt" ]]; then
    [[ -d "$HOME/.local/share/docling-venv" ]] || python3 -m venv "$HOME/.local/share/docling-venv"
    "$HOME/.local/share/docling-venv/bin/pip" install -q -r "$RQ/docling-venv.txt" || true
  fi
  if [[ -s "$RQ/lean-explore.txt" ]]; then
    LV="$HOME/.codex/runtime/workspace/.venvs/lean-explore"
    [[ -d "$LV" ]] || python3 -m venv "$LV"
    "$LV/bin/pip" install -q -r "$RQ/lean-explore.txt" || true
  fi
  gate "import smoke"
  PYTHONPATH="$HOME/.openclaw/workspace/.local" python3 -c 'import requests' || { echo "FAIL: workspace-local imports broken"; exit 2; }
fi

# 10 ─ docker images (already handled by prepare; re-check)
if (( START <= 10 )); then
  phase 10 "docker images check"
  if skip_enabled SKIP_DOCKER || skip_enabled SKIP_DOCKER_IMAGES; then
    echo "(skipped via SKIP_DOCKER/SKIP_DOCKER_IMAGES)"
  else
    ARCH="$(uname -m)"
    command -v docker >/dev/null || { echo "FAIL: docker missing"; exit 2; }
    while IFS='|' read -r img cond; do
      [[ -z "$img" || "$img" == \#* ]] && continue
      case "$cond" in
        arm64) [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] || continue ;;
        amd64) [[ "$ARCH" == "x86_64" ]] || continue ;;
      esac
      docker image inspect "$img" >/dev/null 2>&1 || { echo "FAIL: docker image missing: $img"; exit 2; }
    done < "$REPO/system/packages/docker-images.txt"
  fi
fi

# 11 ─ services + cron
if (( START <= 11 )); then
  phase 11 "systemd user units + crontab (apply recorded enable states)"
  mkdir -p "$HOME/.config/systemd/user"
  for f in "$REPO"/system/systemd/user/* ; do
    [[ -f "$f" ]] || { # drop-in dirs
      [[ -d "$f" ]] && { mkdir -p "$HOME/.config/systemd/user/$(basename "$f")"; \
        for g in "$f"/*; do sed "s|{{ HOME }}|$HOME|g" "$g" > "$HOME/.config/systemd/user/$(basename "$f")/$(basename "$g")"; done; }; continue; }
    sed "s|{{ HOME }}|$HOME|g" "$f" > "$HOME/.config/systemd/user/$(basename "$f")"
  done
  # tolerate the absence of a user systemd/DBUS session (CI runners, containers):
  # units are still rendered to disk; only the live registration is skipped.
  if systemctl --user daemon-reload 2>/dev/null; then
    while IFS=$'\t' read -r unit want; do
      [[ -z "$unit" ]] && continue
      case "$want" in
        enabled)  systemctl --user enable "$unit" >/dev/null 2>&1 || true ;;
        disabled) systemctl --user disable "$unit" >/dev/null 2>&1 || true ;;
      esac
    done < "$REPO/system/systemd/units.state"
  else
    echo "WARN: no user systemd session — units rendered to ~/.config/systemd/user but not registered"
  fi
  sudo loginctl enable-linger "$USER" 2>/dev/null || true
  if [[ "${CSR_NO_GATEWAY:-0}" == "1" ]]; then
    echo "(CSR_NO_GATEWAY=1: services rendered, gateway NOT started — start it manually for a live demo)"
  elif [[ $DEGRADED_MODE -eq 0 ]]; then
    systemctl --user start openclaw-gateway 2>/dev/null || echo "WARN: gateway did not start (check journalctl --user -u openclaw-gateway)"
  else
    echo "(degraded: services rendered + enable-states applied, nothing started)"
  fi
  # crontab inside a marker block, preserving any user lines outside it
  if command -v crontab >/dev/null; then
    TMP=$(mktemp)
    { { crontab -l 2>/dev/null || true; } | sed '/# >>> coding-system >>>/,/# <<< coding-system <<</d'
      echo "# >>> coding-system >>>"
      grep -v '^#' "$REPO/system/cron/crontab.template" | sed "s|{{ HOME }}|$HOME|g"
      echo "# <<< coding-system <<<"
    } > "$TMP"
    crontab "$TMP" 2>/dev/null || echo "WARN: could not install crontab (no cron daemon?)"
    rm -f "$TMP"
  else
    echo "WARN: crontab not available — skipping host cron install"
  fi
fi

# 12 ─ verification
if (( START <= 12 )); then
  phase 12 "post-install fixes note + verify"
  cat <<'EONOTE'
Post-install manual verifications (see docs/TROUBLESHOOTING.md):
  * Google Chat threading: VERIFY by sending a threaded message before applying
    any unthread patch (live extension may already handle it).
  * Zulip stays disabled by default; re-enable runbook is in TROUBLESHOOTING.
  * Zalo net.js shim: only if gateway logs show the missing-module error.
EONOTE
  DEGRADED="$DEGRADED_MODE" bash "$REPO/bin/verify.sh"
  if [[ $DEGRADED_MODE -eq 1 ]]; then
    echo; echo "*** install finished in DEGRADED MODE — missing features: ***"
    bash "$REPO/bin/secrets-verify.sh" --degraded || true
  fi
fi
echo; echo "install: done"
