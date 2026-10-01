#!/usr/bin/bash -p
# Full restore orchestrator for a fresh Ubuntu machine (12 gated phases).
# Authenticated use is internal to bin/restore.sh after Stage-0; no set is degraded.
# Env:   PHASE=n  resume from phase n;  SKIP_* forwarded to prepare.sh
set -euo pipefail
if [[ $- != *p* ]]; then
  exec /usr/bin/bash -p "$0" "$@"
fi
export PYTHONDONTWRITEBYTECODE=1
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
INSTALL_SCRIPT_SOURCE="${BASH_SOURCE[0]}"
DESCRIPTOR_BOUND_INSTALL=0
STAGE0_GENERATION_CANDIDATE="${CSR_STAGE0_REPOSITORY_GENERATION:-}"
STAGE0_TREE_CANDIDATE="${CSR_STAGE0_REPOSITORY_TREE:-}"
RECOVERY_SET="${RECOVERY_SET:-${SECRETS:-}}"
export RECOVERY_SET
DEGRADED_MODE=0
[[ -z "$RECOVERY_SET" ]] && DEGRADED_MODE=1
export DEGRADED_MODE
if [[ -n "${CSR_INSTALL_REPO_ROOT:-}" ]]; then
  DESCRIPTOR_BOUND_INSTALL=1
  REPO="$CSR_INSTALL_REPO_ROOT"
  unset CSR_INSTALL_REPO_ROOT
  [[ "$REPO" == /* && "$REPO" != / && -d "$REPO" && ! -L "$REPO" ]] \
    || { echo "ERROR: invalid descriptor-bound install root" >&2; exit 2; }
  canonical_repo="$(cd -- "$REPO" && pwd -P)"
  [[ "$canonical_repo" == "$REPO" ]] \
    || { echo "ERROR: non-canonical descriptor-bound install root" >&2; exit 2; }
  [[ "$INSTALL_SCRIPT_SOURCE" =~ ^/proc/self/fd/[0-9]+$ ]] \
    || { echo "ERROR: descriptor-bound install did not use a held installer" >&2; exit 2; }
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
    "$INSTALL_SCRIPT_SOURCE" <<'PY' \
    || { echo "ERROR: installer entry point is not immutable and sealed" >&2; exit 2; }
import fcntl
import os
import stat
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
try:
    info = os.fstat(descriptor)
    required = (
        fcntl.F_SEAL_SEAL
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_WRITE
    )
    try:
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as exc:
        raise SystemExit("ERROR: installer entry point is not immutable and sealed") from exc
    if not stat.S_ISREG(info.st_mode) or seals & required != required:
        raise SystemExit("ERROR: installer entry point is not immutable and sealed")
finally:
    os.close(descriptor)
PY
  # Only an authenticated install takes code authority from this repository, and
  # the sealed-handoff gate below already forces it into this branch, so
  # the published generation stays mandatory wherever it carries authority.
  # Degraded CI has no Stage-0 publication and can already reach the plain
  # checkout through the branch below, so requiring one there only breaks it.
  if [[ $DEGRADED_MODE -eq 0 ]]; then
    [[ "$STAGE0_GENERATION_CANDIDATE" == "$REPO" \
        && "$STAGE0_TREE_CANDIDATE" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ \
        && "$REPO" == "/usr/local/libexec/coding-system/repository-generations/"* ]] \
      || { echo "ERROR: descriptor-bound repository-generation identity is invalid" >&2; exit 2; }
    /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
      "$REPO/bin/lib/repository_generation.py" verify \
      --commit "${CSR_STAGE0_VERIFIED_COMMIT:-}" \
      --tree "$STAGE0_TREE_CANDIDATE" --path "$REPO" >/dev/null \
      || { echo "ERROR: authenticated repository generation failed verification" >&2; exit 2; }
  fi
else
  REPO="$(cd "$(dirname "$INSTALL_SCRIPT_SOURCE")/.." && pwd -P)"
fi
START="${PHASE:-1}"
[[ "$START" =~ ^([1-9]|1[0-2])$ ]] \
  || { echo "ERROR: PHASE must be an integer from 1 through 12" >&2; exit 2; }
if [[ $DEGRADED_MODE -eq 0 && $DESCRIPTOR_BOUND_INSTALL -ne 1 ]]; then
  echo "ERROR: authenticated restore requires the sealed installer handoff" >&2
  exit 2
fi
AAS_RESTORE_AGENTS="codex,claude,deepseek,copilot,opencode,antigravity,grok,kimi"
case "$(/usr/bin/uname -m)" in
  aarch64|arm64) LOCK_ARCH=arm64 ;;
  x86_64|amd64) LOCK_ARCH=amd64 ;;
  *) echo "ERROR: unsupported install architecture: $(/usr/bin/uname -m)" >&2; exit 2 ;;
esac

# Authenticated installation is only an internal continuation of bin/restore.sh.
# The trusted caller supplies both the already authenticated commit and its
# protected recovery snapshot. A bare direct invocation must not derive code
# authority from unsigned HEAD or execute a verifier selected by that HEAD.
# A full restore must also prove that the privileged Grok bootstrap release is
# published before phase 1. Degraded CI validates declarations separately and
# intentionally has no production recovery media or release assets.
if [[ $DEGRADED_MODE -eq 0 ]]; then
  RESTORE_CODE_COMMIT="${CSR_EXPECTED_RECOVERY_COMMIT:-}"
  [[ "$RESTORE_CODE_COMMIT" =~ ^[0-9a-f]{40}$ \
      || "$RESTORE_CODE_COMMIT" =~ ^[0-9a-f]{64}$ ]] \
    || { echo "ERROR: authenticated install must be entered through bin/restore.sh" >&2; exit 2; }
  [[ "${CSR_STAGE0_VERIFIED_COMMIT:-}" == "$RESTORE_CODE_COMMIT" ]] \
    || { echo "ERROR: authenticated install requires the Stage-0 verified commit" >&2; exit 2; }
  RECOVERY_SNAPSHOT_MARKER="${CSR_RESTORE_RECOVERY_SNAPSHOT:-}"
  [[ -n "$RECOVERY_SNAPSHOT_MARKER" && "$RECOVERY_SET" == "$RECOVERY_SNAPSHOT_MARKER" ]] \
    || { echo "ERROR: authenticated install requires the protected restore snapshot" >&2; exit 2; }

  [[ "$STAGE0_GENERATION_CANDIDATE" == "$REPO" \
      && "$STAGE0_TREE_CANDIDATE" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] \
    || { echo "ERROR: authenticated install lost its repository-generation identity" >&2; exit 2; }
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$REPO/bin/lib/repository_generation.py" verify \
    --commit "$RESTORE_CODE_COMMIT" --tree "$STAGE0_TREE_CANDIDATE" \
    --path "$REPO" >/dev/null \
    || { echo "ERROR: full restore requires the exact immutable commit generation" >&2; exit 2; }
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$REPO/bin/lib/recovery_tool.py" check-snapshot \
    --snapshot-dir "$RECOVERY_SET" >/dev/null

  RECOVERY_SET="$RECOVERY_SET" /usr/bin/bash -p "$REPO/bin/verify-recovery-signature.sh"
  # Grok has no published bootstrap release yet; SKIP_GROK=1 restores
  # everything else and leaves Grok uninstalled.
  if [[ "${SKIP_GROK:-0}" == "1" ]]; then
    echo "NOTE: SKIP_GROK=1, so this restore does not install Grok" >&2
  else
    /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
      "$REPO/bin/provision-grok-bootstrap.py" --require-qualified-lock
  fi
fi

# prepare.sh installs user-scoped executables in these two roots, but a child
# process cannot update this orchestrator's PATH. Admit them only after the
# authenticated checkout/recovery gate has completed.
export PATH="$PATH:/usr/local/sbin:/usr/local/bin:$HOME/.npm-global/bin:$HOME/.local/bin"

if [[ $DEGRADED_MODE -eq 0 ]]; then
  # Re-derive the owner member from signed v2 metadata. Ambient OWNER_DATA and
  # REQUIRE_OWNER_DATA values can never replace or grant this authority.
  read -r SIGNED_OWNER_FILE SIGNED_OWNER_REQUIREMENT SIGNED_OWNER_SHA256 < <(
    /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
      "$REPO/bin/lib/recovery_tool.py" inspect-set-owner \
      --set-dir "$RECOVERY_SET" \
    | /usr/bin/python3 -I -S -B -c '
import json, re, sys
value = json.load(sys.stdin)
if not isinstance(value, dict) or set(value) != {"owner_data"}:
    raise SystemExit(2)
owner = value["owner_data"]
if owner is None:
    print("- none -")
    raise SystemExit(0)
filename = owner.get("file") if isinstance(owner, dict) else None
requirement = owner.get("requirement") if isinstance(owner, dict) else None
digest = owner.get("sha256") if isinstance(owner, dict) else None
if not isinstance(filename, str) or re.fullmatch(r"openclaw-private-[0-9]{8}T[0-9]{6}Z[.]tar[.]gz[.]gpg", filename) is None:
    raise SystemExit(2)
if requirement not in {"agent-private-capability", "history-only"}:
    raise SystemExit(2)
if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit(2)
print(filename, requirement, digest)
'
  ) || {
    echo "ERROR: signed owner-data record is invalid" >&2
    exit 2
  }
  unset OWNER_DATA REQUIRE_OWNER_DATA CSR_OWNER_DATA_REQUIREMENT \
    CSR_SIGNED_OWNER_DATA_SHA256
  OWNER_DATA=""
  if [[ "$SIGNED_OWNER_FILE" != "-" ]]; then
    OWNER_DATA="$RECOVERY_SET/$SIGNED_OWNER_FILE"
    [[ -f "$OWNER_DATA" && ! -L "$OWNER_DATA" ]] \
      || { echo "ERROR: signed owner-data archive is missing or unsafe" >&2; exit 2; }
    REQUIRE_OWNER_DATA=1
    CSR_OWNER_DATA_REQUIREMENT="$SIGNED_OWNER_REQUIREMENT"
    CSR_SIGNED_OWNER_DATA_SHA256="$SIGNED_OWNER_SHA256"
    export OWNER_DATA REQUIRE_OWNER_DATA CSR_OWNER_DATA_REQUIREMENT \
      CSR_SIGNED_OWNER_DATA_SHA256
  elif [[ "$SIGNED_OWNER_REQUIREMENT" != "none" \
      || "$SIGNED_OWNER_SHA256" != "-" ]]; then
    echo "ERROR: signed owner-data record is invalid" >&2
    exit 2
  fi
else
  # Degraded/local install has no signed recovery authority. It may consume an
  # explicitly named archive, but it never auto-selects a "latest" file.
  OWNER_DATA="${OWNER_DATA:-}"
  if [[ -n "$OWNER_DATA" && ( ! -f "$OWNER_DATA" || -L "$OWNER_DATA" ) ]]; then
    echo "ERROR: explicit OWNER_DATA archive is missing or unsafe: $OWNER_DATA" >&2
    exit 2
  fi
  if [[ -z "$OWNER_DATA" && "${REQUIRE_OWNER_DATA:-0}" == "1" ]]; then
    echo "ERROR: REQUIRE_OWNER_DATA=1 but no explicit OWNER_DATA archive is available" >&2
    exit 2
  fi
fi

phase() { echo; echo "########## PHASE $1: $2 ##########"; }

OPENCLAW_LOADER="$HOME/.local/share/coding-system/openclaw-launchers/loader.py"
OPENCLAW_EXECUTABLE_HELPER=""
OPENCLAW_EXECUTABLE_CONTRACT=""
resolve_openclaw_executable_paths() {
  [[ -n "$OPENCLAW_EXECUTABLE_HELPER" && -n "$OPENCLAW_EXECUTABLE_CONTRACT" ]] \
    && return 0
  local report
  report="$(/usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$OPENCLAW_LOADER" --home "$HOME" --arch "$LOCK_ARCH" --resolve-json)" \
    || { echo "FAIL: OpenClaw launcher selector is unavailable" >&2; return 2; }
  mapfile -t resolved_openclaw_paths < <(
    /usr/bin/python3 -I -B -c '
import json, sys
value = json.load(sys.stdin)
if value.get("schema") != "coding-system.openclaw-launcher-selector/v1":
    raise SystemExit(2)
print(value.get("helper", ""))
print(value.get("contract", ""))
' <<<"$report"
  )
  [[ ${#resolved_openclaw_paths[@]} -eq 2 \
      && "${resolved_openclaw_paths[0]}" == "$HOME/.local/share/coding-system/openclaw-launchers/generations/"*/converge-openclaw-executable.py \
      && "${resolved_openclaw_paths[1]}" == "$HOME/.local/share/coding-system/openclaw-launchers/generations/"*/contract.json ]] \
    || { echo "FAIL: OpenClaw launcher paths are invalid" >&2; return 2; }
  OPENCLAW_EXECUTABLE_HELPER="${resolved_openclaw_paths[0]}"
  OPENCLAW_EXECUTABLE_CONTRACT="${resolved_openclaw_paths[1]}"
}
openclaw_executable_contract() {
  local action="${1:-verify}" arguments=()
  [[ "$action" == apply || "$action" == verify ]] \
    || { echo "FAIL: invalid OpenClaw executable contract action" >&2; return 2; }
  [[ "$action" == apply ]] && arguments+=(--apply)
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$OPENCLAW_LOADER" --home "$HOME" --arch "$LOCK_ARCH" \
    "${arguments[@]}"
}
openclaw_exact() {
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$OPENCLAW_LOADER" --home "$HOME" --arch "$LOCK_ARCH" \
    --exec -- "$@"
}

OPENCLAW_WRITERS_QUIESCED=0
OPENCLAW_QUIESCENCE_STATE=""
quiesce_openclaw_writers() {
  # Owner/auth/config state and actionable workspace queues must not be
  # overlaid beneath either the gateway or the host queue worker.
  [[ $OPENCLAW_WRITERS_QUIESCED -eq 0 ]] || return 0
  local nonce
  nonce="$(/usr/bin/python3 -I -B -c 'import secrets; print(secrets.token_hex(16))')"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] \
    || { echo "FAIL: could not create install quiescence identifier" >&2; return 2; }
  OPENCLAW_QUIESCENCE_STATE="$HOME/.local/state/coding-system/restore/service-state-${nonce}.state"
  /usr/bin/bash -p "$REPO/bin/secret-restore-quiescence.sh" \
    --quiesce --state-file "$OPENCLAW_QUIESCENCE_STATE"
  OPENCLAW_WRITERS_QUIESCED=1
}

release_openclaw_quiescence_state() {
  [[ $OPENCLAW_WRITERS_QUIESCED -eq 1 ]] || return 0
  /usr/bin/bash -p "$REPO/bin/secret-restore-quiescence.sh" \
    --resume --state-file "$OPENCLAW_QUIESCENCE_STATE"
  OPENCLAW_WRITERS_QUIESCED=0
  OPENCLAW_QUIESCENCE_STATE=""
}

# Writers are quiesced unconditionally in phases 7 and 8 but resumed only on the
# non-degraded path, so a degraded run or any earlier failure would leave the
# gateway and the queue worker stopped with an orphaned state file.  The release
# is idempotent, so the normal in-band call still owns the happy path.
trap release_openclaw_quiescence_state EXIT

gate()  { echo "---- gate: $1"; }
# Host schedule declarations name private owner settings (~/.secrets.env); a full
# install checks them before anything is activated rather than failing afterwards.
preflight_host_schedules() {
  python3 "$REPO/bin/reconcile-host-schedules.py" --dry-run >/dev/null \
    || { echo "FAIL: host schedule declarations need their owner settings in ~/.secrets.env (docs/SECRETS.md)" >&2; exit 2; }
}
skip_enabled() { [[ "${!1:-0}" == "1" ]]; }
# Scheduled jobs and the shell's owner-settings loader run code through this
# selector, never through a mutable checkout. An authenticated restore points it
# at the immutable repository generation it verified; a degraded install at its
# own source tree.
select_repository() {
  local selector="$HOME/.local/share/coding-system/repository" temporary target="$REPO"
  install -d -m 0700 "$HOME/.local/share/coding-system"
  [[ ! -e "$selector" || -L "$selector" ]] \
    || { echo "FAIL: repository selector is not a symlink: $selector" >&2; exit 2; }
  # Scheduled code runs from a generation the owner owns, copied from the
  # verified Stage-0 generation, so later updates need no root
  # (bin/publish-repository-generation.sh).  The root-owned Stage-0 generation
  # serves only this restore's system steps.
  if [[ $DEGRADED_MODE -eq 0 ]]; then
    target="$(
      set -o pipefail
      /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
        "$REPO/bin/lib/repository_generation.py" emit-generation --path "$REPO" \
        --commit "$RESTORE_CODE_COMMIT" --tree "$STAGE0_TREE_CANDIDATE" \
      | /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
        "$REPO/bin/lib/repository_generation.py" publish --owner \
        --commit "$RESTORE_CODE_COMMIT" --tree "$STAGE0_TREE_CANDIDATE"
    )" || { echo "FAIL: cannot publish the owner's repository generation" >&2; exit 2; }
    [[ "$target" == "$HOME/.local/share/coding-system/repository-generations/$RESTORE_CODE_COMMIT-$STAGE0_TREE_CANDIDATE" ]] \
      || { echo "FAIL: owner repository generation path differs from its identity" >&2; exit 2; }
  fi
  temporary="$(mktemp -u "$HOME/.local/share/coding-system/.repository.XXXXXXXX")"
  ln -s -- "$target" "$temporary"
  mv -fT -- "$temporary" "$selector"
}

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
  /usr/bin/bash -p "$REPO/bin/secrets-verify.sh" --degraded || true
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
  CSR_DEFER_IMAGE_PULL=1 bash "$REPO/bin/prepare.sh"
  if ! skip_enabled SKIP_NODE && ! skip_enabled SKIP_NPM_GLOBALS; then
    gate "OpenClaw npm selector and descriptor target are owner-safe"
    openclaw_executable_contract apply
  fi
  gate "binaries respond"
  for b in git jq pandoc python3; do command -v "$b" >/dev/null || { echo "FAIL: $b missing"; exit 2; }; done
  skip_enabled SKIP_NODE || command -v node >/dev/null || { echo "FAIL: node missing"; exit 2; }
  { skip_enabled SKIP_NODE || skip_enabled SKIP_NPM_GLOBALS; } || command -v npm >/dev/null || { echo "FAIL: npm missing"; exit 2; }
  { skip_enabled SKIP_NODE || skip_enabled SKIP_NPM_GLOBALS; } \
    || openclaw_exact --version >/dev/null \
    || { echo "FAIL: exact OpenClaw executable boundary is unavailable"; exit 2; }
  skip_enabled SKIP_DOCKER || command -v docker >/dev/null || { echo "FAIL: docker missing"; exit 2; }
fi

# `usermod -aG docker` changes the account database, not this already-running
# shell's supplementary groups.  Re-enter once through the standard `sg`
# helper so later image and sandbox gates work during the same one-command
# restore.  Only file paths (never share values) are inherited in the env.
if [[ "${SKIP_DOCKER:-0}" != "1" \
    && "${CSR_DOCKER_GROUP_REEXEC:-0}" != "1" \
    && ! " $(id -nG) " =~ [[:space:]]docker[[:space:]] \
    && " $(id -nG "$USER") " =~ [[:space:]]docker[[:space:]] ]]; then
  export PHASE=3 CSR_DOCKER_GROUP_REEXEC=1
  if (( DESCRIPTOR_BOUND_INSTALL == 1 )); then
    # Keep executing the same sealed memfd that restore.sh authenticated.  The
    # standard sg helper preserves inherited descriptors; a repository path
    # must never replace this authority at the new supplementary-group edge.
    export CSR_REEXEC_INSTALL="$INSTALL_SCRIPT_SOURCE"
    export CSR_INSTALL_REPO_ROOT="$REPO"
  else
    export CSR_REEXEC_INSTALL="$REPO/bin/install.sh"
    unset CSR_INSTALL_REPO_ROOT
  fi
  echo "---- gate: re-entering the installer with the newly granted docker group"
  exec /usr/bin/sg docker -c 'exec /usr/bin/bash -p "$CSR_REEXEC_INSTALL"'
fi

# 3 ─ secrets
if (( START <= 3 )); then
  if [[ $DEGRADED_MODE -eq 0 ]]; then
    phase 3 "restore secrets"
    /usr/bin/bash -p "$REPO/bin/secrets-restore.sh"
    gate "required secrets present"
    /usr/bin/bash -p "$REPO/bin/secrets-verify.sh"
    set +e
    /usr/bin/bash -p "$REPO/bin/apply-tailscale-authority.sh" --home "$HOME"
    TAILSCALE_READINESS_RC=$?
    set -e
    case "$TAILSCALE_READINESS_RC" in
      0) echo 'CSR_GATE_JSON {"case_id":"install.phase3.tailscale-readiness","schema_version":1,"status":"passed"}' ;;
      1) echo "NOTICE: Tailscale is NOT_CONFIGURED or REAUTH_REQUIRED; continuing without a false-ready result" ;;
      *) echo "FAIL: Tailscale authority/readiness verification failed" >&2; exit 2 ;;
    esac
    preflight_host_schedules
  else
    phase 3 "restore secrets — SKIPPED (degraded)"
  fi
fi

# 4 ─ registry-authenticated immutable OCI images
if (( START <= 4 )); then
  phase 4 "pull locked OCI images after Docker credentials are restored"
  if skip_enabled SKIP_DOCKER_IMAGES; then
    echo "(skipped via SKIP_DOCKER_IMAGES)"
  else
    skip_enabled SKIP_DOCKER \
      && { echo "FAIL: image closure requires Docker" >&2; exit 2; }
    python3 "$REPO/system/software/pull-locked-images.py" --arch "$LOCK_ARCH"
  fi
fi

# 5 ─ components
if (( START <= 5 )); then
  phase 5 "components (openclaw-bot, ai-agents-skills, vnu-eoffice, course_management_toolkit)"
  bash "$REPO/bin/components.sh" || [[ $DEGRADED_MODE -eq 1 ]]
fi
COMPONENT_PATH_ARGS=(--repository "$REPO" --home "$HOME")
if (( DEGRADED_MODE == 1 )); then
  COMPONENT_PATH_ARGS+=(--source-fallback)
else
  COMPONENT_PATH_ARGS+=(--require)
fi
OPENCLAW_COMPONENT="$(/usr/bin/python3 -I -B \
  "$REPO/bin/lib/component_paths.py" "${COMPONENT_PATH_ARGS[@]}" openclaw-bot)" \
  || { echo "FAIL: immutable openclaw-bot component is unavailable" >&2; exit 2; }
COURSE_COMPONENT="$(/usr/bin/python3 -I -B \
  "$REPO/bin/lib/component_paths.py" "${COMPONENT_PATH_ARGS[@]}" course_management_toolkit)" \
  || { echo "FAIL: immutable course component is unavailable" >&2; exit 2; }
export OPENCLAW_COMPONENT_DIR="$OPENCLAW_COMPONENT"
export COURSE_COMPONENT_DIR="$COURSE_COMPONENT"

# 6 ─ render public configs
if (( START <= 6 )); then
  phase 6 "render-install (configs, shell blocks, scripts, symlinks, atomic Grok release)"
  select_repository
  RENDER_ARGS=()
  if skip_enabled SKIP_GROK; then
    echo "  (Grok bootstrap, release and gates skipped via SKIP_GROK)"
    RENDER_ARGS+=(--skip-grok-release)
  else
    gate "qualified Grok bootstrap package and signed dispatcher"
    python3 -I -B "$REPO/bin/provision-grok-bootstrap.py" --verify-installed
  fi
  bash "$REPO/bin/render-install.sh" "${RENDER_ARGS[@]}"
  # Templates are intentionally skip-if-existing. Reconcile the bounded
  # selector table separately so repeat restores retain user-owned Codex
  # settings while still selecting every restored credential authority.
  /usr/bin/python3 -I -B "$REPO/bin/migrate-codex-config.py" \
    --config "$HOME/.codex/config.toml" --home "$HOME"
  if ! skip_enabled SKIP_GROK; then
    gate "grok-proxy user/root selectors name one validated immutable release"
    structured_grok_release_gate
  fi
  # ~/.local/bin wrappers from system/bin
  install -d -m 0755 "$HOME/.local/bin"
  for f in "$REPO"/system/bin/*; do
    wrapper_name="$(basename "$f")"
    [[ -f "$f" && "$wrapper_name" != usr-local-bin.tsv \
        && "$wrapper_name" != copilot ]] || continue
    destination="$HOME/.local/bin/$(basename "$f")"
    [[ ! -L "$destination" && ( ! -e "$destination" || -f "$destination" ) ]] \
      || { echo "FAIL: unsafe local wrapper destination: $destination" >&2; exit 2; }
    temporary="$(mktemp "$HOME/.local/bin/.wrapper.XXXXXXXX")"
    sed "s|{{ HOME }}|$HOME|g" "$f" > "$temporary"
    chmod 0755 "$temporary"
    mv -f -- "$temporary" "$destination"
  done
  # ~/.local/libexec helpers from system/libexec, rendered like the wrappers
  while IFS= read -r -d '' f; do
    relative="${f#"$REPO/system/libexec/"}"
    destination="$HOME/.local/libexec/$relative"
    install -d -m 0755 "$(dirname "$destination")"
    [[ ! -L "$destination" && ( ! -e "$destination" || -f "$destination" ) ]] \
      || { echo "FAIL: unsafe libexec destination: $destination" >&2; exit 2; }
    temporary="$(mktemp "$(dirname "$destination")/.libexec.XXXXXXXX")"
    sed "s|{{ HOME }}|$HOME|g" "$f" > "$temporary"
    chmod 0755 "$temporary"
    mv -f -- "$temporary" "$destination"
  done < <(find "$REPO/system/libexec" -type f -print0 2>/dev/null | sort -z)
fi

# 7 ─ OpenClaw slice (delegated component)
if (( START <= 7 )); then
  phase 7 "OpenClaw slice via openclaw-bot"
  quiesce_openclaw_writers
  /usr/bin/python3 -I -B "$REPO/bin/materialize-secret-projections.py" --home "$HOME" \
    --migrate-vnu-legacy --migrate-remote-bridge-legacy --migrate-aas-legacy
  if [[ -x "$OPENCLAW_COMPONENT/install.sh" ]]; then
    # Owner state is the older overlay. Restore it first, then converge the
    # tested public component and exact plugin generation on top so an archive
    # can never roll runnable skill code or package locks backward.
    if [[ -n "$OWNER_DATA" ]]; then
      OPENCLAW_BACKUP_PASSPHRASE_FILE="${OPENCLAW_BACKUP_PASSPHRASE_FILE:-$HOME/.config/coding-system/openclaw-owner-backup-passphrase.txt}" \
        /usr/bin/bash -p "$REPO/bin/restore-openclaw-owner-data.sh" "$OWNER_DATA"
    else
      echo "NOTICE: no owner-data archive; continuing with an explicit fresh owner-state baseline"
    fi
    SHA_BEFORE=$(sha256sum "$HOME/.openclaw/secrets.json" 2>/dev/null | cut -d' ' -f1 || true)
    bash "$OPENCLAW_COMPONENT/install.sh" \
      --prefix "$HOME/.openclaw" \
      --skip-docker \
      --skip-services \
      --skip-openclaw-install \
      --convergent
    # the "don't clobber restored secrets" gate only applies when secrets were
    # actually restored (non-degraded); in degraded mode there is no live
    # secrets.json to protect and the component renders one from its template.
    if [[ $DEGRADED_MODE -eq 0 ]]; then
      gate "restored secrets untouched"
      SHA_AFTER=$(sha256sum "$HOME/.openclaw/secrets.json" 2>/dev/null | cut -d' ' -f1 || true)
      [[ "$SHA_BEFORE" == "$SHA_AFTER" ]] || { echo "FAIL: openclaw-bot install clobbered restored secrets.json"; exit 2; }
    fi
    MIGRATE_ARGS=(
      --config "$HOME/.openclaw/openclaw.json"
      --lock "$REPO/system/openclaw/compatibility.lock.json"
      --classroom50-allowlist-file "$HOME/.secrets.env"
    )
    [[ $DEGRADED_MODE -eq 1 ]] && MIGRATE_ARGS+=(--degraded)
    python3 "$REPO/bin/migrate-openclaw-config.py" "${MIGRATE_ARGS[@]}"
    openclaw_exact config validate >/dev/null
    [[ -d "$HOME/.openclaw/npm/projects" ]] \
      || { echo "FAIL: required OpenClaw npm project closure is missing"; exit 2; }
    for p in "$HOME/.openclaw/npm/projects"/*/; do
      [[ -f "$p/package.json" && -f "$p/package-lock.json" ]] \
        || { echo "FAIL: required npm project has no package.json/package-lock.json: $p"; exit 2; }
      # Errors only: a quiet success, but a failure says why.
      (cd "$p" && npm ci --ignore-scripts --omit=dev --no-audit --no-fund --loglevel=error)
    done
    while IFS= read -r plugin_spec; do
      [[ -n "$plugin_spec" ]] || continue
      openclaw_exact plugins install --pin --force "$plugin_spec" >/dev/null
    done < <(python3 -c \
      'import json,sys; print(*json.load(open(sys.argv[1]))["required_plugin_packages"], sep="\n")' \
      "$REPO/system/openclaw/skill-closure.json")
    openclaw_exact plugins doctor >/dev/null
    if [[ $DEGRADED_MODE -eq 0 ]]; then
      OPENCLAW_AUTH_REPORT="$HOME/.local/state/coding-system/restore/openclaw-agent-auth.json"
      install -d -m 0700 "$(dirname "$OPENCLAW_AUTH_REPORT")"
      python3 "$OPENCLAW_COMPONENT/scripts/openclaw_auth_closure.py" migrate \
        --prefix "$HOME/.openclaw" --home "$HOME" \
        --expected-version "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["openclaw"]["observed_version"])' "$OPENCLAW_COMPONENT/REBUILD-MANIFEST.json")" \
        --output "$OPENCLAW_AUTH_REPORT" >/dev/null
      echo 'CSR_GATE_JSON {"case_id":"install.phase7.openclaw-agent-auth","schema_version":1,"status":"passed"}'
    else
      echo "NOTICE: OpenClaw agent-auth migration is deferred in degraded mode"
    fi
    openclaw_exact exec-policy set --host sandbox --security allowlist \
      --ask on-miss --ask-fallback deny --json >/dev/null
    gate "openclaw config has no dangling openclaw-src references"
    grep -q 'openclaw-src' "$HOME/.openclaw/openclaw.json" 2>/dev/null && { echo "FAIL: openclaw.json references openclaw-src"; exit 2; } || true
    gate "OpenClaw Bash completion materialized"
    /usr/bin/bash -p "$REPO/bin/materialize-openclaw-completion.sh" \
      --openclaw-bin "$HOME/.local/bin/openclaw"
  else
    echo "WARN: openclaw-bot component unavailable — OpenClaw slice skipped"
  fi
fi

# 8 ─ skills via ai-agents-skills
if (( START <= 8 )); then
  phase 8 "skills via ai-agents-skills installer"
  if [[ -L "$HOME/.npm-global/bin/openclaw" || $DEGRADED_MODE -eq 0 ]]; then
    gate "OpenClaw executable contract before shared runtime attestation"
    openclaw_executable_contract apply
  fi
  AAS_HOME="$HOME/ai-agents-skills"
  AAS_HELPER_SOURCE="$REPO/bin/lib/aas_component.py"
  AAS_HELPER_SHA256="be484adbebcb612513a7d9f2410473e2a2d864b8c8e0534ab3e575d56d5755dc"
  AAS_HELPER_ROOT="$HOME/.local/share/coding-system/install-helpers"
  AAS_COMPONENT_ROOT="$HOME/.local/share/coding-system/components/ai-agents-skills"
  [[ -d "$AAS_HOME" && ! -L "$AAS_HOME" \
      && -d "$AAS_HOME/.git" && ! -L "$AAS_HOME/.git" ]] \
    || { echo "FAIL: ai-agents-skills object repository is unavailable or unsafe"; exit 2; }
  [[ -f "$AAS_HELPER_SOURCE" && ! -L "$AAS_HELPER_SOURCE" ]] \
    || { echo "FAIL: immutable ai-agents-skills materializer is unavailable"; exit 2; }
  # ai-agents-skills never uses root: no privilege escalation, no root-owned
  # tree.  The helper and the pinned tree it materializes belong to the owner.
  # Bind the helper through stdin first.  A bounded no-follow opener validates
  # one regular-file descriptor, the binder accepts only its build-time digest,
  # and every later helper invocation uses the resulting read-only copy.  A
  # concurrent replacement of the checkout path therefore either leaves the
  # opened bytes unchanged or fails the digest gate.
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
    | /usr/bin/timeout 30s \
      /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /bin/sh -eu -c '
        expected=$1
        root=$2
        case "$expected" in
          *[!0-9a-f]*)
            exit 2
            ;;
        esac
        test "${#expected}" -eq 64 || exit 2
        case "$root" in
          /*) ;;
          *) exit 2 ;;
        esac
        owner=$(/usr/bin/id -u)
        test "$owner" -ne 0 || exit 2
        target=$root/aas-component-$expected.py

        require_owned_dir() {
          path=$1
          test ! -L "$path" && test -d "$path" || return 1
          test "$(/usr/bin/stat -c %u -- "$path")" = "$owner" || return 1
          mode=$(/usr/bin/stat -c %a -- "$path")
          test $(( 0$mode & 022 )) -eq 0
        }
        /usr/bin/mkdir -p -m 0700 -- "$root"
        require_owned_dir "$root" || exit 2

        verify_target() {
          test ! -L "$target" && test -f "$target" \
            && test "$(/usr/bin/stat -c %u:%a:%h -- "$target")" = "$owner:444:1" \
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
      ' sh "$AAS_HELPER_SHA256" "$AAS_HELPER_ROOT"
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

  AAS_HELPER_ENV=(PATH=/usr/bin:/bin LANG=C LC_ALL=C)
  AAS_STAGE="$(/usr/bin/env -i "${AAS_HELPER_ENV[@]}" \
    /usr/bin/python3 -I -B "$AAS_HELPER" prepare "$AAS_PIN")" \
    || { echo "FAIL: cannot prepare immutable ai-agents-skills materialization"; exit 2; }
  [[ "$AAS_STAGE" == "$AAS_COMPONENT_ROOT/.stage-$AAS_PIN-"[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f] ]] \
    || { echo "FAIL: immutable ai-agents-skills staging path is invalid"; exit 2; }
  aas_cleanup_stage() {
    if [[ -n "${AAS_STAGE:-}" \
        && "$AAS_STAGE" == "$AAS_COMPONENT_ROOT/.stage-$AAS_PIN-"* ]]; then
      /usr/bin/env -i "${AAS_HELPER_ENV[@]}" \
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
    | /usr/bin/env -i "${AAS_HELPER_ENV[@]}" \
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
    | /usr/bin/env -i "${AAS_HELPER_ENV[@]}" \
        /usr/bin/python3 -I -B "$AAS_HELPER" verify-extracted \
          "$AAS_PIN" "$AAS_STAGE"
  ); then
    echo "FAIL: extracted ai-agents-skills tree differs from its Git object"
    exit 2
  fi
  AAS_IMMUTABLE="$(/usr/bin/env -i "${AAS_HELPER_ENV[@]}" \
    /usr/bin/python3 -I -B "$AAS_HELPER" publish "$AAS_PIN" "$AAS_STAGE")" \
    || { echo "FAIL: cannot publish immutable ai-agents-skills object"; exit 2; }
  [[ "$AAS_IMMUTABLE" == "$AAS_COMPONENT_ROOT/$AAS_PIN" ]] \
    || { echo "FAIL: immutable ai-agents-skills publication path is invalid"; exit 2; }
  AAS_STAGE=""
  trap - EXIT
  /usr/bin/env -i "${AAS_HELPER_ENV[@]}" \
    /usr/bin/python3 -I -B "$AAS_HELPER" verify "$AAS_PIN" >/dev/null \
    || { echo "FAIL: immutable ai-agents-skills object failed verification"; exit 2; }
  printf 'CSR_GATE_JSON {"case_id":"install.phase8.aas-pin","closed_environment":true,"commit":"%s","execution_source":"owner-pinned-object","schema_version":1,"source_root":"%s","status":"passed","tree":"%s"}\n' \
    "$AAS_PIN" "$AAS_IMMUTABLE" "$AAS_TREE"

  # The compatibility checkout supplies only the cryptographic Git object.
  # Installer execution and any reference-mode output are anchored to the
  # stable, owner-owned, content-addressed materialization.
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
  # Phase 8 may be resumed directly. Re-apply the bounded phase-6 retirement
  # before the shared runtime is installed so historical Claude-local runtime
  # bytes can never become the fallback execution path.
  /usr/bin/python3 -B "$REPO/bin/lib/render_install.py" \
    --repo "$REPO" --home "$HOME" --retire-claude-runtime-only
  AAS_TARGET_HOMES=(
    "$HOME/.codex"
    "$HOME/.claude"
    "$HOME/.deepseek"
    "$HOME/.copilot"
    "$HOME/.config/opencode"
    "$HOME/.gemini/antigravity-cli"
    "$HOME/.grok"
    "$HOME/.kimi-code"
  )
  for AAS_TARGET_HOME in "${AAS_TARGET_HOMES[@]}"; do
    [[ ! -L "$AAS_TARGET_HOME" \
        && ( ! -e "$AAS_TARGET_HOME" || -d "$AAS_TARGET_HOME" ) ]] \
      || { echo "FAIL: unsafe ai-agents-skills target home: $AAS_TARGET_HOME"; exit 2; }
    install -d -m 0700 "$AAS_TARGET_HOME"
  done
  (
    cd "$AAS_IMMUTABLE"
    /usr/bin/env -i "${AAS_CLOSED_ENV[@]}" AAS_INSTALL_CONFIRM="$AAS_PHRASE" \
      /bin/sh "$AAS_IMMUTABLE/installer/bootstrap.sh" \
        --root "$HOME" --agents "$AAS_RESTORE_AGENTS" install \
        --profile complete-restore \
        --artifact-profile workflow-artifacts \
        --runtime-profile full \
        --require-all-requested-agents \
        --require-complete-install \
        --apply --real-system --backup-replace \
        --post-install-smoke verify
  )
  echo 'CSR_GATE_JSON {"case_id":"install.phase8.aas-install","schema_version":1,"status":"passed"}'
  AAS_SHARED_RUNTIME="$HOME/.local/share/ai-agents-skills/runtime"
  AAS_RUNTIME_DIGEST_PAIRS=(
    "$AAS_IMMUTABLE/canonical/runtime/runners/run_skill.sh|$AAS_SHARED_RUNTIME/run_skill.sh"
    "$AAS_IMMUTABLE/canonical/runtime/runners/load_secret_env.py|$AAS_SHARED_RUNTIME/load_secret_env.py"
  )
  for AAS_RUNTIME_DIGEST_PAIR in "${AAS_RUNTIME_DIGEST_PAIRS[@]}"; do
    IFS='|' read -r AAS_RUNTIME_SOURCE AAS_RUNTIME_TARGET \
      <<< "$AAS_RUNTIME_DIGEST_PAIR"
    [[ -f "$AAS_RUNTIME_SOURCE" && ! -L "$AAS_RUNTIME_SOURCE" \
        && -f "$AAS_RUNTIME_TARGET" && ! -L "$AAS_RUNTIME_TARGET" \
        && "$(/usr/bin/stat -c '%u:%h' "$AAS_RUNTIME_TARGET")" == "$(/usr/bin/id -u):1" ]] \
      || { echo "FAIL: shared ai-agents-skills runtime file is unsafe"; exit 2; }
    AAS_RUNTIME_EXPECTED_SHA256="$(/usr/bin/sha256sum "$AAS_RUNTIME_SOURCE" | /usr/bin/cut -d' ' -f1)"
    AAS_RUNTIME_OBSERVED_SHA256="$(/usr/bin/sha256sum "$AAS_RUNTIME_TARGET" | /usr/bin/cut -d' ' -f1)"
    [[ "$AAS_RUNTIME_EXPECTED_SHA256" == "$AAS_RUNTIME_OBSERVED_SHA256" ]] \
      || { echo "FAIL: installed shared runtime differs from pinned ai-agents-skills source"; exit 2; }
  done
  [[ -x "$AAS_SHARED_RUNTIME/run_skill.sh" ]] \
    || { echo "FAIL: shared ai-agents-skills runtime runner is not executable"; exit 2; }
  CLAUDE_RETIRED_ENTRYPOINTS=(
    "$HOME/.claude/skills/zotero/run_zot.sh"
    "$HOME/.claude/skills/zotero/run_zot.bat"
    "$HOME/.claude/skills/zotero/zot.py"
    "$HOME/.claude/skills/zotero/send_file.sh"
    "$HOME/.claude/skills/zotero/send_telegram.sh"
    "$HOME/.claude/skills/zotero/send_queue_worker.sh"
    "$HOME/.claude/skills/zotero/job_queue_worker.sh"
    "$HOME/.claude/skills/zotero/lib/config.py"
    "$HOME/.claude/skills/calibre/run_cal.sh"
    "$HOME/.claude/skills/calibre/cal.py"
    "$HOME/.claude/skills/calibre/lib/config.py"
    "$HOME/.claude/skills/vnthuquan/run_vnthuquan.sh"
    "$HOME/.claude/skills/vnthuquan/vnthuquan_wrapper.py"
  )
  for CLAUDE_RETIRED_ENTRYPOINT in "${CLAUDE_RETIRED_ENTRYPOINTS[@]}"; do
    [[ ! -e "$CLAUDE_RETIRED_ENTRYPOINT" && ! -L "$CLAUDE_RETIRED_ENTRYPOINT" ]] \
      || { echo "FAIL: retired Claude-local runtime entrypoint remains"; exit 2; }
  done
  echo 'CSR_GATE_JSON {"case_id":"install.phase8.shared-runtime","schema_version":1,"status":"passed"}'
  # Install the Copilot shadow launcher only after its pinned shared secret
  # loader exists. A phase-6 interruption therefore leaves the raw npm CLI in
  # place instead of a launcher whose dependency has not arrived yet.
  COPILOT_WRAPPER_SOURCE="$REPO/system/bin/copilot"
  COPILOT_WRAPPER_DESTINATION="$HOME/.local/bin/copilot"
  [[ -f "$COPILOT_WRAPPER_SOURCE" && ! -L "$COPILOT_WRAPPER_SOURCE" ]] \
    || { echo "FAIL: managed Copilot wrapper source is unavailable"; exit 2; }
  [[ ! -L "$COPILOT_WRAPPER_DESTINATION" \
      && ( ! -e "$COPILOT_WRAPPER_DESTINATION" \
        || -f "$COPILOT_WRAPPER_DESTINATION" ) ]] \
    || { echo "FAIL: unsafe Copilot wrapper destination"; exit 2; }
  COPILOT_CLOSURE_MARKER="$HOME/.npm-global/lib/node_modules/.csr-closure-id"
  [[ -f "$COPILOT_CLOSURE_MARKER" && ! -L "$COPILOT_CLOSURE_MARKER" ]] \
    || { echo "FAIL: exact npm closure marker is unavailable for Copilot"; exit 2; }
  mapfile -t COPILOT_CLOSURE_LINES < "$COPILOT_CLOSURE_MARKER"
  [[ "${#COPILOT_CLOSURE_LINES[@]}" -eq 1 ]] \
    || { echo "FAIL: exact npm closure marker is malformed"; exit 2; }
  COPILOT_CLOSURE_ROOT="${COPILOT_CLOSURE_LINES[0]}"
  COPILOT_SOURCE_HASH="$(
    /usr/bin/python3 -I -B "$REPO/system/software/npm-closure/closurectl.py" source-digest
  )"
  COPILOT_CLOSURE_PREFIX="$HOME/.local/share/coding-system/npm-closures/sha256-$LOCK_ARCH-$COPILOT_SOURCE_HASH-"
  COPILOT_TREE_HASH="${COPILOT_CLOSURE_ROOT#"$COPILOT_CLOSURE_PREFIX"}"
  [[ "$COPILOT_SOURCE_HASH" =~ ^[0-9a-f]{64}$ \
      && "$COPILOT_CLOSURE_ROOT" == "$COPILOT_CLOSURE_PREFIX$COPILOT_TREE_HASH" \
      && "$COPILOT_TREE_HASH" =~ ^[0-9a-f]{64}$ \
      && -d "$COPILOT_CLOSURE_ROOT" && ! -L "$COPILOT_CLOSURE_ROOT" ]] \
    || { echo "FAIL: exact npm closure identity is invalid for Copilot"; exit 2; }
  /usr/bin/python3 -I -B "$REPO/system/software/npm-closure/closurectl.py" \
    verify-install "$COPILOT_CLOSURE_ROOT" --arch "$LOCK_ARCH" --immutable >/dev/null
  COPILOT_LOADER_RESOLVED="$COPILOT_CLOSURE_ROOT/node_modules/@github/copilot/npm-loader.js"
  COPILOT_COMPATIBILITY_LOADER="$HOME/.npm-global/lib/node_modules/@github/copilot/npm-loader.js"
  [[ -f "$COPILOT_LOADER_RESOLVED" && ! -L "$COPILOT_LOADER_RESOLVED" \
      && "$(readlink -f -- "$COPILOT_COMPATIBILITY_LOADER" 2>/dev/null || true)" \
        == "$COPILOT_LOADER_RESOLVED" ]] \
    || { echo "FAIL: Copilot loader does not match the exact npm closure"; exit 2; }
  COPILOT_WRAPPER_TEMPORARY="$(mktemp "$HOME/.local/bin/.copilot.XXXXXXXX")"
  /usr/bin/python3 -I -B - \
    "$COPILOT_WRAPPER_SOURCE" "$COPILOT_WRAPPER_TEMPORARY" \
    "$HOME" "$COPILOT_LOADER_RESOLVED" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
home = sys.argv[3]
loader = sys.argv[4]
rendered = (
    source.read_text(encoding="utf-8")
    .replace("{{ HOME }}", home)
    .replace("{{ COPILOT_LOADER }}", loader)
)
if "{{ HOME }}" in rendered or "{{ COPILOT_LOADER }}" in rendered:
    raise SystemExit("Copilot launcher rendering left an unresolved placeholder")
destination.write_text(rendered, encoding="utf-8")
PY
  chmod 0755 "$COPILOT_WRAPPER_TEMPORARY"
  mv -f -- "$COPILOT_WRAPPER_TEMPORARY" "$COPILOT_WRAPPER_DESTINATION"
  [[ -x "$COPILOT_WRAPPER_DESTINATION" && ! -L "$COPILOT_WRAPPER_DESTINATION" ]] \
    || { echo "FAIL: managed Copilot wrapper was not installed"; exit 2; }
  echo 'CSR_GATE_JSON {"case_id":"install.phase8.copilot-wrapper","schema_version":1,"status":"passed"}'
  # Codex remains self-contained: install the same pinned runtime under
  # ~/.codex so its skills never depend on another agent's home or on the
  # multi-agent shared runtime root.
  (
    cd "$AAS_IMMUTABLE"
    /usr/bin/env -i "${AAS_CLOSED_ENV[@]}" AAS_INSTALL_CONFIRM="$AAS_PHRASE" \
      /bin/sh "$AAS_IMMUTABLE/installer/bootstrap.sh" \
        --root "$HOME" --agents codex install \
        --no-skills --runtime-profile full \
        --runtime-root "$HOME/.codex/runtime" \
        --require-all-requested-agents \
        --require-complete-install \
        --apply --real-system --backup-replace
  )
  [[ -x "$HOME/.codex/runtime/run_skill.sh" ]] \
    || { echo "FAIL: Codex self-contained runtime runner was not installed"; exit 2; }
  [[ -f "$HOME/.codex/runtime/load_secret_env.py" \
      && ! -L "$HOME/.codex/runtime/load_secret_env.py" ]] \
    || { echo "FAIL: Codex self-contained secret loader was not installed"; exit 2; }
  python3 -I -B - \
    "$HOME/.codex/config.toml" \
    "$HOME/.codex/runtime" \
    "$HOME/.local/share/coding-system/python-closure/shared/bin/python" \
    "$HOME/.config/ai-agents-skills/compute.env" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as stream:
    config = tomllib.load(stream)
configured = config.get("shell_environment_policy", {}).get("set", {})
if configured.get("AAS_RUNTIME_ROOT") != sys.argv[2]:
    raise SystemExit("Codex config does not select its private runtime root")
if configured.get("AAS_RUNTIME_PYTHON") != sys.argv[3]:
    raise SystemExit("Codex config does not select its managed Python closure")
if configured.get("AAS_COMPUTE_SECRETS_FILE") != sys.argv[4]:
    raise SystemExit("Codex config does not select its restored compute authority")
PY
  echo 'CSR_GATE_JSON {"case_id":"install.phase8.codex-runtime","schema_version":1,"status":"passed"}'
  (
    cd "$AAS_IMMUTABLE"
    /usr/bin/env -i "${AAS_CLOSED_ENV[@]}" \
      /bin/sh "$AAS_IMMUTABLE/installer/bootstrap.sh" \
        --root "$HOME" --agents "$AAS_RESTORE_AGENTS" verify
  )
  echo 'CSR_GATE_JSON {"case_id":"install.phase8.aas-verify","schema_version":1,"status":"passed"}'

  # Pinned third-party skills that ai-agents-skills does not ship
  # (system/software/vendor-skills.lock.json): only missing copies are written.
  python3 "$REPO/bin/install-vendor-skills.py" --home "$HOME" >/dev/null \
    || { echo "FAIL: pinned vendor skills could not be installed" >&2; exit 2; }

  # OpenClaw is intentionally excluded from the normal multi-target install.
  # Derive every eligible non-runtime skill file from the pinned AAS manifests,
  # then use the native v2 target gate (probe -> dry-run manifest -> approval ->
  # apply) while the gateway is stopped. Classroom50 bootstraps the canary
  # evidence; every remaining skill uses the managed-skill action class.
  quiesce_openclaw_writers

  OPENCLAW_GATE_PARENT="$HOME/.local/state/coding-system/restore"
  [[ ! -L "$OPENCLAW_GATE_PARENT" \
      && ( ! -e "$OPENCLAW_GATE_PARENT" || -d "$OPENCLAW_GATE_PARENT" ) ]] \
    || { echo "FAIL: unsafe OpenClaw target-gate state directory" >&2; exit 2; }
  install -d -m 0700 "$OPENCLAW_GATE_PARENT"
  OPENCLAW_GATE_STAGE="$(mktemp -d "$OPENCLAW_GATE_PARENT/.openclaw-skills.XXXXXXXX")"
  chmod 0700 "$OPENCLAW_GATE_STAGE"
  OPENCLAW_PATH="$HOME/.npm-global/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  mapfile -t OPENCLAW_SKILL_FILES < <(
    /usr/bin/python3 -I -B "$REPO/bin/openclaw-skill-inventory.py" \
      --aas-root "$AAS_IMMUTABLE" --format lines
  )
  [[ ${#OPENCLAW_SKILL_FILES[@]} -gt 0 \
      && "${OPENCLAW_SKILL_FILES[0]}" == "classroom50" ]] \
    || { echo "FAIL: pinned OpenClaw skill-file inventory has no canary" >&2; exit 2; }

  for OPENCLAW_SKILL in "${OPENCLAW_SKILL_FILES[@]}"; do
    OPENCLAW_SKILL_STAGE="$OPENCLAW_GATE_STAGE/$OPENCLAW_SKILL"
    install -d -m 0700 "$OPENCLAW_SKILL_STAGE"
    OPENCLAW_PROBE="$OPENCLAW_SKILL_STAGE/probe.json"
    OPENCLAW_MANIFEST="$OPENCLAW_SKILL_STAGE/manifest.json"
    OPENCLAW_APPROVED="$OPENCLAW_SKILL_STAGE/approved.json"
    OPENCLAW_APPLIED="$OPENCLAW_SKILL_STAGE/applied.json"
    OPENCLAW_ACTION_CLASS="managed-skill-file"
    OPENCLAW_PROBE_SKILL="classroom50"
    OPENCLAW_PROBE_EXTRA=(--include-canary)
    OPENCLAW_EXPECTED_EVIDENCE=5
    if [[ "$OPENCLAW_SKILL" == "classroom50" ]]; then
      OPENCLAW_ACTION_CLASS="canary-skill-file"
      OPENCLAW_PROBE_SKILL="classroom50"
      OPENCLAW_PROBE_EXTRA=()
      OPENCLAW_EXPECTED_EVIDENCE=4
    fi
    (
      cd "$AAS_IMMUTABLE"
      /usr/bin/env -i "${AAS_CLOSED_ENV[@]}" PATH="$OPENCLAW_PATH" \
        /bin/sh "$AAS_IMMUTABLE/installer/bootstrap.sh" \
          --root "$HOME" --json openclaw-target-probe \
          --openclaw-bin "$HOME/.npm-global/bin/openclaw" \
          --skill "$OPENCLAW_PROBE_SKILL" "${OPENCLAW_PROBE_EXTRA[@]}" \
          >"$OPENCLAW_PROBE"
    )
    chmod 0600 "$OPENCLAW_PROBE"
    mapfile -t OPENCLAW_EVIDENCE_PATHS < <(
      /usr/bin/python3 -I -B - "$OPENCLAW_PROBE" "$OPENCLAW_SKILL_STAGE" <<'PY'
import json
import os
from pathlib import Path
import sys

probe_path = Path(sys.argv[1])
stage = Path(sys.argv[2])
probe = json.loads(probe_path.read_text(encoding="utf-8"))
if probe.get("status") != "ok" or not isinstance(probe.get("evidence"), list):
    raise SystemExit("OpenClaw target probe did not produce v2 evidence")
for index, item in enumerate(probe["evidence"]):
    destination = stage / f"evidence-{index}.json"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(item, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(destination)
PY
    )
    [[ ${#OPENCLAW_EVIDENCE_PATHS[@]} -eq $OPENCLAW_EXPECTED_EVIDENCE ]] \
      || { echo "FAIL: OpenClaw target probe returned an unexpected evidence set for $OPENCLAW_SKILL" >&2; exit 2; }
    OPENCLAW_EVIDENCE_ARGS=()
    for OPENCLAW_EVIDENCE_PATH in "${OPENCLAW_EVIDENCE_PATHS[@]}"; do
      OPENCLAW_EVIDENCE_ARGS+=(--evidence "$OPENCLAW_EVIDENCE_PATH")
    done
    (
      cd "$AAS_IMMUTABLE"
      /usr/bin/env -i "${AAS_CLOSED_ENV[@]}" PATH="$OPENCLAW_PATH" \
        /bin/sh "$AAS_IMMUTABLE/installer/bootstrap.sh" \
          --root "$HOME" --json openclaw-target-dry-run-manifest \
          --skill "$OPENCLAW_SKILL" --action-class "$OPENCLAW_ACTION_CLASS" \
          "${OPENCLAW_EVIDENCE_ARGS[@]}" >"$OPENCLAW_MANIFEST"
      /usr/bin/env -i "${AAS_CLOSED_ENV[@]}" PATH="$OPENCLAW_PATH" \
        /bin/sh "$AAS_IMMUTABLE/installer/bootstrap.sh" \
          --root "$HOME" --json openclaw-target-approve-manifest \
          --manifest "$OPENCLAW_MANIFEST" \
          --reviewer coding-system-rebuild >"$OPENCLAW_APPROVED"
      /usr/bin/env -i "${AAS_CLOSED_ENV[@]}" PATH="$OPENCLAW_PATH" \
        /bin/sh "$AAS_IMMUTABLE/installer/bootstrap.sh" \
          --root "$HOME" --json openclaw-target-apply-manifest \
          --manifest "$OPENCLAW_APPROVED" --apply --real-system \
          --confirm-openclaw-real-write \
          "I understand OpenClaw real-system skill-file writes" >"$OPENCLAW_APPLIED"
    )
    chmod 0600 "$OPENCLAW_MANIFEST" "$OPENCLAW_APPROVED" "$OPENCLAW_APPLIED"
    [[ -f "$HOME/.openclaw/skills/$OPENCLAW_SKILL/SKILL.md" \
        && ! -L "$HOME/.openclaw/skills/$OPENCLAW_SKILL/SKILL.md" ]] \
      || { echo "FAIL: gated OpenClaw skill is missing or unsafe: $OPENCLAW_SKILL" >&2; exit 2; }
    /usr/bin/env -i "${AAS_CLOSED_ENV[@]}" PATH="$OPENCLAW_PATH" \
      OPENCLAW_STATE_DIR="$HOME/.openclaw" \
      "$HOME/.npm-global/bin/openclaw" skills list --json \
      | /usr/bin/python3 -I -B -c 'import json,sys; wanted=sys.argv[1]; data=json.load(sys.stdin); raise SystemExit(0 if any(item.get("name") == wanted and item.get("source") == "openclaw-managed" for item in data.get("skills", []) if isinstance(item, dict)) else 1)' "$OPENCLAW_SKILL" \
      || { echo "FAIL: native OpenClaw loader does not report $OPENCLAW_SKILL" >&2; exit 2; }
  done
  echo 'CSR_GATE_JSON {"case_id":"install.phase8.openclaw-skill-closure-v2-gate","schema_version":1,"status":"passed"}'

  TARGET_STATE_REPORT="$HOME/.local/state/coding-system/restore/target-state.json"
  install -d -m 0700 "$(dirname "$TARGET_STATE_REPORT")"
  set +e
  python3 "$REPO/bin/verify-target-state.py" \
    --manifest "$AAS_IMMUTABLE/manifest/target-state.yaml" \
    --root "$HOME" --path "$HOME/.local/bin:$PATH" --readiness-phase pre-runtime \
    --output "$TARGET_STATE_REPORT"
  TARGET_STATE_RC=$?
  set -e
  case "$TARGET_STATE_RC" in
    0) echo 'CSR_GATE_JSON {"case_id":"install.phase8.target-state","schema_version":1,"status":"passed"}' ;;
    1) echo 'NOTICE: target software is technically ready; one or more native sessions require reauthentication or configuration' ;;
    *) echo "FAIL: target-state verification found a technical failure" >&2; exit 2 ;;
  esac
  phase 8b "re-overlay recovery-set authorities (idempotent) + clobber checks"
  if [[ $DEGRADED_MODE -eq 0 ]]; then
    /usr/bin/bash -p "$REPO/bin/secrets-restore.sh"
  fi
  /usr/bin/python3 -I -B "$REPO/bin/materialize-secret-projections.py" \
    --home "$HOME" --migrate-vnu-legacy --migrate-remote-bridge-legacy \
    --migrate-aas-legacy
  if [[ $DEGRADED_MODE -eq 0 ]]; then
    # Phase 8b intentionally re-overlays an authenticated recovery set.  Old
    # generations can therefore recreate legacy auth JSON after phase 7; import
    # it again before any runtime or final verifier can observe a false source.
    OPENCLAW_AUTH_REPORT="$HOME/.local/state/coding-system/restore/openclaw-agent-auth.json"
    python3 "$OPENCLAW_COMPONENT/scripts/openclaw_auth_closure.py" migrate \
      --prefix "$HOME/.openclaw" --home "$HOME" \
      --expected-version "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["openclaw"]["observed_version"])' "$OPENCLAW_COMPONENT/REBUILD-MANIFEST.json")" \
      --output "$OPENCLAW_AUTH_REPORT" >/dev/null
    echo 'CSR_GATE_JSON {"case_id":"install.phase8b.openclaw-agent-auth","schema_version":1,"status":"passed"}'
  fi
  /usr/bin/bash -p "$REPO/bin/materialize-openclaw-runtime.sh"
  gate "_run.sh intact"
  if [[ -f "$HOME/.config/coding-system/run_sh.sha256" && -f "$HOME/.claude/skills/_run.sh" ]]; then
    want=$(cat "$HOME/.config/coding-system/run_sh.sha256")
    have=$(sha256sum "$HOME/.claude/skills/_run.sh" | cut -d' ' -f1)
    [[ "$want" == "$have" ]] || { echo "FAIL: _run.sh changed during phase 8"; exit 2; }
  fi
fi

# 9 ─ python environments
if (( START <= 9 )); then
  phase 9 "digest-locked offline Python wheel closure"
  PYTHON_LOCK="$REPO/system/python-closure/ubuntu-24.04-$LOCK_ARCH.lock.json"
  PYTHON_WHEELHOUSE="$HOME/.cache/coding-system/python-wheelhouse/$LOCK_ARCH"
  PYTHON_PROVENANCE="$PYTHON_WHEELHOUSE.provenance.json"
  python3 "$REPO/bin/install-python-closure.py" validate --lock "$PYTHON_LOCK"
  if [[ $DEGRADED_MODE -eq 1 ]]; then
    echo "NOTICE: degraded restore validates Python declarations only; locked OCI extraction is not claimed"
    echo 'CSR_GATE_JSON {"case_id":"install.phase9.python-closure","schema_version":1,"status":"skipped","reason":"degraded-no-runtime-artifacts"}'
  else
    python3 "$REPO/bin/extract-python-wheelhouse.py" extract \
      --lock "$REPO/system/software/images.lock.json" \
      --arch "$LOCK_ARCH" \
      --destination "$PYTHON_WHEELHOUSE" \
      --provenance "$PYTHON_PROVENANCE" \
      --replace
    python3 "$REPO/bin/install-python-closure.py" install-all \
      --lock "$PYTHON_LOCK" \
      --images-lock "$REPO/system/software/images.lock.json" \
      --wheelhouse "$PYTHON_WHEELHOUSE" \
      --provenance "$PYTHON_PROVENANCE" \
      --home "$HOME" \
      --python python3 \
      --replace-unmanaged
    python3 "$REPO/bin/install-python-closure.py" verify-all \
      --lock "$PYTHON_LOCK" \
      --images-lock "$REPO/system/software/images.lock.json" \
      --wheelhouse "$PYTHON_WHEELHOUSE" \
      --provenance "$PYTHON_PROVENANCE" \
      --home "$HOME" \
      --python python3
    echo 'CSR_GATE_JSON {"case_id":"install.phase9.python-closure","schema_version":1,"status":"passed"}'

    # Exercise the installed, managed runtime tree only after its exact Python
    # environments and compatibility links exist.  This report is consumed by
    # the target-state gate; an old report is never trusted across restores.
    AAS_PIN_PHASE9=$(/usr/bin/sed -n \
      's|^ai-agents-skills=.*@\([0-9a-f]\{40\}\)$|\1|p' "$REPO/components.lock")
    AAS_IMMUTABLE_PHASE9="$HOME/.local/share/coding-system/components/ai-agents-skills/$AAS_PIN_PHASE9"
    [[ "$AAS_PIN_PHASE9" =~ ^[0-9a-f]{40}$ \
        && -d "$AAS_IMMUTABLE_PHASE9" && ! -L "$AAS_IMMUTABLE_PHASE9" \
        && -f "$AAS_IMMUTABLE_PHASE9/installer/bootstrap.sh" \
        && ! -L "$AAS_IMMUTABLE_PHASE9/installer/bootstrap.sh" ]] \
      || { echo "FAIL: immutable ai-agents-skills source is unavailable for runtime smoke"; exit 2; }
    AAS_RUNTIME_REPORT="$HOME/.local/state/coding-system/restore/aas-installed-runtime-smoke.json"
    install -d -m 0700 "$(dirname "$AAS_RUNTIME_REPORT")"
    AAS_RUNTIME_REPORT_TMP=$(mktemp \
      "$(dirname "$AAS_RUNTIME_REPORT")/.aas-installed-runtime-smoke.XXXXXXXX")
    chmod 0600 "$AAS_RUNTIME_REPORT_TMP"
    if ! (
      cd "$AAS_IMMUTABLE_PHASE9"
      /usr/bin/env -i \
        PATH="$HOME/.npm-global/bin:$HOME/.local/bin:/usr/bin:/bin" \
        LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC HOME="$HOME" USER="$(/usr/bin/id -un)" \
        LOGNAME="$(/usr/bin/id -un)" SHELL=/bin/sh TMPDIR=/tmp \
        XDG_CONFIG_HOME="$HOME/.config" XDG_DATA_HOME="$HOME/.local/share" \
        XDG_CACHE_HOME="$HOME/.cache" XDG_STATE_HOME="$HOME/.local/state" \
        AAS_PYTHON=/usr/bin/python3 \
        AAS_RUNTIME_PYTHON="$HOME/.local/share/coding-system/python-closure/shared/bin/python" \
        PYTHONDONTWRITEBYTECODE=1 \
        PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 \
        /bin/sh "$AAS_IMMUTABLE_PHASE9/installer/bootstrap.sh" \
          --root "$HOME" --agents "$AAS_RESTORE_AGENTS" --json \
          installed-runtime-smoke --require-complete-coverage
    ) > "$AAS_RUNTIME_REPORT_TMP"; then
      rm -f -- "$AAS_RUNTIME_REPORT_TMP"
      echo "FAIL: installed ai-agents-skills runtime smoke failed" >&2
      exit 2
    fi
    python3 - "$AAS_RUNTIME_REPORT_TMP" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    report = json.load(stream)
if (
    report.get("schema") != "ai-agents-skills.installed-runtime-smoke.v1"
    or report.get("schema_version") != 1
    or report.get("mode") != "installed"
    or report.get("status") != "ok"
    or not isinstance(report.get("checked"), int)
    or isinstance(report.get("checked"), bool)
    or report["checked"] <= 0
    or report.get("unknown_coverage_count") != 0
    or report.get("missing_managed_runtime_count") != 0
):
    raise SystemExit("installed ai-agents-skills runtime smoke report is not passing")
PY
    mv -f -- "$AAS_RUNTIME_REPORT_TMP" "$AAS_RUNTIME_REPORT"
    chmod 0600 "$AAS_RUNTIME_REPORT"
    echo 'CSR_GATE_JSON {"case_id":"install.phase9.aas-installed-runtime-smoke","schema_version":1,"status":"passed"}'

    # Prove Codex can execute a provider-free runtime-backed skill using only
    # its private runtime selection.  HOME points at an isolated probe root
    # where the normal multi-agent shared runtime path is deliberately absent.
    CODEX_SMOKE_HOME="$HOME/.local/state/coding-system/restore/codex-isolated-home"
    CODEX_SMOKE_OUTPUT="$HOME/.local/state/coding-system/restore/codex-runtime-smoke"
    CODEX_SHARED_PROBE="$CODEX_SMOKE_HOME/.local/share/ai-agents-skills/runtime"
    install -d -m 0700 "$CODEX_SMOKE_HOME" "$CODEX_SMOKE_OUTPUT"
    [[ ! -e "$CODEX_SHARED_PROBE" && ! -L "$CODEX_SHARED_PROBE" ]] \
      || { echo "FAIL: Codex isolated smoke unexpectedly has a shared runtime" >&2; exit 2; }
    CODEX_SMOKE_FILE="$CODEX_SMOKE_OUTPUT/unnamed_claim.lean"
    [[ ! -L "$CODEX_SMOKE_FILE" ]] \
      || { echo "FAIL: unsafe Codex runtime-smoke output" >&2; exit 2; }
    rm -f -- "$CODEX_SMOKE_FILE"
    /usr/bin/env -i \
      PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
      HOME="$CODEX_SMOKE_HOME" USER="$AAS_USER" LOGNAME="$AAS_USER" \
      SHELL=/bin/sh TMPDIR=/tmp \
      AAS_RUNTIME_ROOT="$HOME/.codex/runtime" \
      AAS_RUNTIME_PYTHON="$HOME/.local/share/coding-system/python-closure/shared/bin/python" \
      PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 \
      "$HOME/.codex/runtime/run_skill.sh" \
        skills/formal-skeleton-helper/run_formal_skeleton.sh \
        --output-dir "$CODEX_SMOKE_OUTPUT" >/dev/null
    [[ ! -e "$CODEX_SHARED_PROBE" && ! -L "$CODEX_SHARED_PROBE" ]] \
      && [[ -f "$CODEX_SMOKE_FILE" && ! -L "$CODEX_SMOKE_FILE" ]] \
      && /usr/bin/grep -q '^theorem unnamed_claim : Prop := by$' "$CODEX_SMOKE_FILE" \
      || { echo "FAIL: Codex private runtime isolated smoke failed" >&2; exit 2; }
    echo 'CSR_GATE_JSON {"case_id":"install.phase9.codex-private-runtime-smoke","schema_version":1,"status":"passed"}'
  fi
  if [[ $DEGRADED_MODE -eq 0 ]]; then
    gate "bounded Calibre metadata bootstrap"
    /usr/bin/timeout --signal=TERM --kill-after=15s 180s \
      bash "$HOME/.openclaw/workspace/skills/calibre/run_cal.sh" sync --force
    python3 - "$HOME/.openclaw/workspace/data/calibre/cache/metadata.db" <<'PY'
import sqlite3
import sys
path = sys.argv[1]
connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
try:
    if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise SystemExit("Calibre metadata.db failed post-bootstrap quick_check")
    connection.execute("SELECT 1 FROM books LIMIT 1").fetchone()
finally:
    connection.close()
PY
  fi
fi

# 10 ─ docker images (already handled by prepare; re-check)
if (( START <= 10 )); then
  phase 10 "digest-selected Docker image closure"
  if skip_enabled SKIP_DOCKER || skip_enabled SKIP_DOCKER_IMAGES; then
    echo "(skipped via SKIP_DOCKER/SKIP_DOCKER_IMAGES)"
  else
    command -v docker >/dev/null || { echo "FAIL: docker missing"; exit 2; }
    case "$(uname -m)" in aarch64|arm64) IMAGE_ARCH=arm64 ;; x86_64|amd64) IMAGE_ARCH=amd64 ;; *) exit 2 ;; esac
    python3 "$REPO/system/software/pull-locked-images.py" \
      --arch "$IMAGE_ARCH" --verify-only
  fi
fi

gate "OpenClaw compatibility tuple before service startup"
if [[ $DEGRADED_MODE -eq 1 ]]; then
  python3 "$REPO/bin/verify-openclaw-compat.py" --static-only
elif skip_enabled SKIP_DOCKER || skip_enabled SKIP_DOCKER_IMAGES; then
  echo "FAIL: a full restore cannot skip the locked OpenClaw sandbox image" >&2
  exit 2
else
  python3 "$REPO/bin/verify-openclaw-compat.py"
fi

# 11 ─ generated state, scheduler declarations, then activation
if (( START <= 11 )); then
  phase 11 "completion + logical schedules + exact user-service activation"
  [[ $DEGRADED_MODE -eq 1 ]] || preflight_host_schedules
  [[ -x "$OPENCLAW_COMPONENT/install.sh" ]] \
    || { echo "FAIL: reviewed OpenClaw service installer is unavailable" >&2; exit 2; }
  # This one-command restore invocation is the user's service-activation
  # confirmation.  The component still requires its exact token when invoked
  # standalone, and renders descriptor-bound generational host workers.
  /usr/bin/bash -p "$OPENCLAW_COMPONENT/install.sh" \
    --prefix "$HOME/.openclaw" \
    --services-only \
    --install-reviewed-services INSTALL_REVIEWED_USER_SERVICES

  UNIT_ROOT="$HOME/.config/systemd/user"
  install -d -m 0700 "$UNIT_ROOT"
  # Captured units name the node they ran with; a restored host has the locked
  # node under ~/.npm-global instead of a system /usr/bin/node.
  NODE_FOR_UNITS=/usr/bin/node
  [[ -x /usr/bin/node ]] || NODE_FOR_UNITS="$HOME/.npm-global/bin/node"
  # chatgpt-local-coder works in ~/Research and logs to its state directory.
  install -d -m 0755 "$HOME/Research"
  install -d -m 0700 "$HOME/.local/state/chatgpt-local-coder"
  while IFS= read -r -d '' f; do
    relative="${f#"$REPO/system/systemd/user/"}"
    case "$relative" in
      moltbook-relay.service|moltbook-relay.timer|openclaw-email-worker.service|\
      openclaw-gateway.service|openclaw-gateway.service.d/10-moltbook-env.conf|\
      openclaw-googlechat-delivery-worker.service|\
      openclaw-manim-worker.service|openclaw-sage-worker.service|\
      openclaw-whatsapp-delivery-worker.service|\
      openclaw-zalo-delivery-worker.service|\
      openclaw-zulip-delivery-worker.service|\
      rss_news_digest_bot.service|rss_news_digest_bot.timer|\
      send-queue-worker.service|xvfb-99.service)
        # Installed above by the component transaction together with the exact
        # content-addressed OPENCLAW_LIBEXEC generation it references.
        continue
        ;;
    esac
    destination="$UNIT_ROOT/$relative"
    [[ ! -L "$destination" ]] || { echo "FAIL: refusing symlink user-unit destination: $destination" >&2; exit 2; }
    install -d -m 0700 "$(dirname "$destination")"
    temporary="$(mktemp "$(dirname "$destination")/.unit.XXXXXXXX")"
    sed -e "s|{{ HOME }}|$HOME|g" -e "s|/usr/bin/node |$NODE_FOR_UNITS |g" "$f" > "$temporary"
    grep -q '{{ [A-Z_][A-Z_]* }}' "$temporary" \
      && { echo "FAIL: unresolved systemd template placeholder: $f" >&2; exit 2; }
    chmod 0600 "$temporary"
    mv -f "$temporary" "$destination"
  done < <(find "$REPO/system/systemd/user" -type f -print0 | sort -z)
  # The component installer rewrites timer units on every run, so each declared
  # timer schedule is a drop-in that it leaves alone (D3), written before any
  # timer is enabled.  Degraded installs have no owner schedule settings.
  [[ $DEGRADED_MODE -eq 1 ]] \
    || python3 "$REPO/bin/reconcile-host-schedules.py" --scope systemd
  # System services (web server, monitoring, Tor, Ollama, the forms tmux server):
  # public units plus the owner's private configuration from the recovery set.
  [[ $DEGRADED_MODE -eq 1 ]] \
    || sudo /usr/bin/python3 -I -B "$REPO/bin/apply-host-services.py" --repository "$REPO" --home "$HOME" \
      --user "$(id -un)" --group "$(id -gn)"

  /usr/bin/bash -p "$REPO/bin/materialize-openclaw-completion.sh" \
    --openclaw-bin "$HOME/.local/bin/openclaw"
  sudo loginctl enable-linger "$USER" \
    || { [[ $DEGRADED_MODE -eq 1 ]] && echo "WARN: could not enable linger in degraded mode" || exit 2; }

  # Registration is converged before any restored job can fire.  Full mode
  # starts only the gateway first; logical OpenClaw jobs are then reconciled,
  # and only afterward are all enabled timers/services activated.
  bash "$REPO/bin/reconcile-systemd-user-units.sh" --registration-only
  if [[ $DEGRADED_MODE -eq 1 ]]; then
    echo "(degraded: units registered, schedulers and gateway intentionally inactive)"
  else
    systemctl --user restart openclaw-gateway.service \
      || { echo "FAIL: gateway restart failed (check journalctl --user -u openclaw-gateway)" >&2; exit 2; }
    ready=0
    for _ in $(seq 1 60); do
      if openclaw_exact health --json >/dev/null 2>&1; then ready=1; break; fi
      sleep 1
    done
    [[ "$ready" -eq 1 ]] \
      || { echo "FAIL: gateway did not become healthy within 60 seconds" >&2; exit 2; }

    resolve_openclaw_executable_paths
    PRIVATE_CRON="$HOME/.config/coding-system/openclaw-cron.v2.json"
    LEGACY_CRON="$HOME/.openclaw/cron/jobs.json.migrated"
    PUBLIC_CANARY="$REPO/system/schedules/openclaw-cron.v2.json"
    if [[ ! -f "$PRIVATE_CRON" && -f "$LEGACY_CRON" ]]; then
      install -d -m 0700 "$(dirname "$PRIVATE_CRON")"
      /usr/bin/python3 -I -B "$REPO/bin/openclaw-cron-v2.py" --home "$HOME" \
        --openclaw-helper "$OPENCLAW_EXECUTABLE_HELPER" \
        --openclaw-contract "$OPENCLAW_EXECUTABLE_CONTRACT" adapt-legacy \
        --input "$LEGACY_CRON" --output "$PRIVATE_CRON"
      chmod 0600 "$PRIVATE_CRON"
    fi
    if [[ -f "$PRIVATE_CRON" ]]; then
      /usr/bin/python3 -I -B "$REPO/bin/openclaw-cron-v2.py" --home "$HOME" \
        --openclaw-helper "$OPENCLAW_EXECUTABLE_HELPER" \
        --openclaw-contract "$OPENCLAW_EXECUTABLE_CONTRACT" import \
        --input "$PRIVATE_CRON"
    else
      /usr/bin/python3 -I -B "$REPO/bin/openclaw-cron-v2.py" --home "$HOME" \
        --openclaw-helper "$OPENCLAW_EXECUTABLE_HELPER" \
        --openclaw-contract "$OPENCLAW_EXECUTABLE_CONTRACT" import \
        --input "$PUBLIC_CANARY"
    fi
    /usr/bin/python3 -I -B "$REPO/bin/openclaw-cron-v2.py" --home "$HOME" \
      --openclaw-helper "$OPENCLAW_EXECUTABLE_HELPER" \
      --openclaw-contract "$OPENCLAW_EXECUTABLE_CONTRACT" import \
      --input "$PUBLIC_CANARY" --no-prune-managed

    bash "$REPO/bin/reconcile-systemd-user-units.sh"
    # Full activation has already converged the desired unit state.  Release
    # the durable pre-install record only now, after all credential/config
    # mutations are complete and no early service start can race them.
    release_openclaw_quiescence_state
    # Hand-added crontab lines become the owner's private block before reconcile.
    python3 "$REPO/bin/reconcile-host-schedules.py" --adopt-unmanaged
    python3 "$REPO/bin/reconcile-host-schedules.py"
    openclaw_exact sandbox recreate --all --force >/dev/null
    # Evidence from an earlier restore must not satisfy this run.  The JSON
    # contract records whole seconds, so bind to the next whole second after
    # every scheduler has been reconciled and activated.
    CSR_SCHEDULER_NOT_BEFORE_UNIX=$(( $(date +%s) + 1 ))
    export CSR_SCHEDULER_NOT_BEFORE_UNIX
    bash "$REPO/bin/wait-scheduler-canaries.sh" \
      --not-before-unix "$CSR_SCHEDULER_NOT_BEFORE_UNIX"
  fi
fi

# 12 ─ verification
if (( START <= 12 )); then
  phase 12 "post-install fixes note + verify"
  RESTORE_RUN_STARTED_AT_UNIX="$(date +%s)"
  RESTORE_RUN_ID="$(/usr/bin/python3 -I -B -c 'import secrets; print(secrets.token_hex(32))')"
  [[ "$RESTORE_RUN_ID" =~ ^[0-9a-f]{64}$ ]] \
    || { echo "FAIL: could not create restore verification run ID" >&2; exit 2; }
  export CODING_SYSTEM_RESTORE_RUN_ID="$RESTORE_RUN_ID"
  export CODING_SYSTEM_RESTORE_RUN_STARTED_AT_UNIX="$RESTORE_RUN_STARTED_AT_UNIX"
  RESTORE_REPORT_OUTPUT="$HOME/.local/state/coding-system/restore/restore-report.v1.json"
  [[ ! -L "$RESTORE_REPORT_OUTPUT" \
      && ( ! -e "$RESTORE_REPORT_OUTPUT" || -f "$RESTORE_REPORT_OUTPUT" ) ]] \
    || { echo "FAIL: unsafe restore report destination" >&2; exit 2; }
  rm -f -- "$RESTORE_REPORT_OUTPUT"
  if [[ -L "$HOME/.npm-global/bin/openclaw" || $DEGRADED_MODE -eq 0 ]]; then
    gate "OpenClaw executable contract remains exact"
    openclaw_executable_contract verify
  fi
  if [[ $DEGRADED_MODE -eq 0 ]] && (( START > 11 )); then
    # A direct PHASE=12 resume has no in-process phase-11 boundary. Establish a
    # boundary for this resumed run and require a new event from every active
    # scheduler before accepting the final verification.
    CSR_SCHEDULER_NOT_BEFORE_UNIX=$(( $(date +%s) + 1 ))
    export CSR_SCHEDULER_NOT_BEFORE_UNIX
    bash "$REPO/bin/wait-scheduler-canaries.sh" \
      --not-before-unix "$CSR_SCHEDULER_NOT_BEFORE_UNIX"
  fi
  cat <<'EONOTE'
Post-install manual verifications (see docs/TROUBLESHOOTING.md):
  * Google Chat threading: VERIFY by sending a threaded message before applying
    any unthread patch (live extension may already handle it).
  * Zulip stays disabled by default; re-enable runbook is in TROUBLESHOOTING.
  * Zalo net.js shim: only if gateway logs show the missing-module error.
EONOTE
  if [[ $DEGRADED_MODE -eq 1 ]]; then
    /usr/bin/bash "$REPO/bin/verify.sh" --profile ci
  else
    /usr/bin/bash "$REPO/bin/verify.sh" --profile full
  fi
  REPORT_PROFILE=full
  [[ $DEGRADED_MODE -eq 1 ]] && REPORT_PROFILE=ci
  OWNER_DATA_STATUS=restored
  [[ -n "$OWNER_DATA" ]] || OWNER_DATA_STATUS=fresh-baseline
  [[ $DEGRADED_MODE -eq 0 ]] || OWNER_DATA_STATUS=NOT_CONFIGURED
  report_args=(
    --repository "$REPO" --profile "$REPORT_PROFILE" \
    --target-report "$HOME/.local/state/coding-system/restore/target-state.json" \
    --classroom50-report "$HOME/.local/state/coding-system/restore/classroom50-verification.json" \
    --verification-evidence "$HOME/.local/state/coding-system/restore/verification-evidence.v1.json" \
    --restore-run-id "$RESTORE_RUN_ID" \
    --owner-data-status "$OWNER_DATA_STATUS" \
    --output "$RESTORE_REPORT_OUTPUT"
  )
  [[ $DEGRADED_MODE -eq 1 ]] \
    || report_args+=(--expected-commit "$RESTORE_CODE_COMMIT")
  /usr/bin/python3 -I -B "$REPO/bin/write-restore-report.py" "${report_args[@]}"
  [[ -f "$RESTORE_REPORT_OUTPUT" && ! -L "$RESTORE_REPORT_OUTPUT" ]] \
    || { echo "FAIL: final restore report was not created" >&2; exit 2; }
  if [[ $DEGRADED_MODE -eq 1 ]]; then
    echo; echo "*** install finished in DEGRADED MODE — missing features: ***"
    /usr/bin/bash -p "$REPO/bin/secrets-verify.sh" --degraded || true
  fi
fi
echo; echo "install: done"
