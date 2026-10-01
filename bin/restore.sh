#!/usr/bin/bash -p
# One-command repository restore entry point after the bare-host bootstrap.
set -euo pipefail
if [[ $- != *p* ]]; then
  exec /usr/bin/bash -p "$0" "$@"
fi
export PYTHONDONTWRITEBYTECODE=1
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
IFS=$' \t\n'
unset BASH_ENV CDPATH ENV GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR \
  GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_DIR GIT_INDEX_FILE \
  GIT_OBJECT_DIRECTORY GIT_WORK_TREE LD_LIBRARY_PATH LD_PRELOAD PYTHONHOME \
  PYTHONINSPECT PYTHONPATH PYTHONSTARTUP PYTHONUSERBASE MAKEFLAGS MAKEFILES \
  GNUMAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES MAKE_RESTARTS MAKE_TERMERR \
  MAKE_TERMOUT

RESTORE_SCRIPT_SOURCE="${BASH_SOURCE[0]}"
DESCRIPTOR_BOUND_RESTORE=0
STAGE0_GENERATION_CANDIDATE="${CSR_STAGE0_REPOSITORY_GENERATION:-}"
STAGE0_TREE_CANDIDATE="${CSR_STAGE0_REPOSITORY_TREE:-}"
if [[ -n "${CSR_RESTORE_REPO_ROOT:-}" ]]; then
  DESCRIPTOR_BOUND_RESTORE=1
  REPO="$CSR_RESTORE_REPO_ROOT"
  unset CSR_RESTORE_REPO_ROOT
  [[ "$REPO" == /* && "$REPO" != / && -d "$REPO" && ! -L "$REPO" ]] \
    || { echo "restore: invalid descriptor-bound repository root" >&2; exit 2; }
  canonical_repo="$(cd -- "$REPO" && pwd -P)"
  [[ "$canonical_repo" == "$REPO" ]] \
    || { echo "restore: descriptor-bound repository root is not canonical" >&2; exit 2; }
  [[ "$RESTORE_SCRIPT_SOURCE" =~ ^/proc/self/fd/[0-9]+$ ]] \
    || { echo "restore: Stage-0 did not provide a held restore entry point" >&2; exit 2; }
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
    "$RESTORE_SCRIPT_SOURCE" <<'PY' \
    || { echo "restore: Stage-0 entry point is not an immutable sealed file" >&2; exit 2; }
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
        raise SystemExit(
            "restore: Stage-0 entry point is not an immutable sealed file"
        ) from exc
    if not stat.S_ISREG(info.st_mode) or seals & required != required:
        raise SystemExit("restore: Stage-0 entry point is not an immutable sealed file")
finally:
    os.close(descriptor)
PY
  [[ "$STAGE0_GENERATION_CANDIDATE" == "$REPO" \
      && "$STAGE0_TREE_CANDIDATE" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ \
      && "$REPO" == "/usr/local/libexec/coding-system/repository-generations/"* ]] \
    || { echo "restore: Stage-0 repository-generation identity is invalid" >&2; exit 2; }
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$REPO/bin/lib/repository_generation.py" verify \
    --commit "${CSR_STAGE0_VERIFIED_COMMIT:-}" \
    --tree "$STAGE0_TREE_CANDIDATE" --path "$REPO" >/dev/null \
    || { echo "restore: authenticated repository generation failed verification" >&2; exit 2; }
else
  REPO="$(cd "$(dirname "$RESTORE_SCRIPT_SOURCE")/.." && pwd -P)"
fi
INBOX="${CSR_RESTORE_INBOX:-$HOME/secrets-restore-inbox}"
RESOLVE_ONLY=0
EXPLICIT_SET="${RECOVERY_SET:-}"
RECOVERY_TOOL="$REPO/bin/lib/recovery_tool.py"
RECOVERY_SNAPSHOT=""
STAGE0_RECOVERY_SNAPSHOT_CANDIDATE="${CSR_STAGE0_RECOVERY_SNAPSHOT:-}"
# Owner data is selected only from authenticated recovery-set v2 metadata.
# Ambient values and legacy inbox placement never influence a signed restore.
unset OWNER_DATA REQUIRE_OWNER_DATA CSR_OWNER_DATA_REQUIREMENT \
  CSR_SIGNED_OWNER_DATA_SHA256

cleanup() {
  local snapshot
  for snapshot in "$RECOVERY_SNAPSHOT"; do
    [[ -n "$snapshot" && -d "$snapshot" ]] || continue
    /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
      "$RECOVERY_TOOL" remove-snapshot \
      --snapshot-dir "$snapshot" >/dev/null 2>&1 \
      || echo "restore: protected recovery snapshot retained for manual cleanup: $snapshot" >&2
  done
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
usage: bin/restore.sh [--resolve-only] [--inbox DIR] [--recovery-set DIR]

Stage 0 invokes this internal handoff. It auto-selects exactly one recovery-set
directory below ~/secrets-restore-inbox, validates it, and runs the gated
installer. Operators start or resume with restore-ubuntu.sh.
EOF
}

while (($#)); do
  case "$1" in
    --resolve-only) RESOLVE_ONLY=1 ;;
    --inbox)
      shift
      [[ $# -gt 0 ]] || { echo "restore: --inbox needs a directory" >&2; exit 2; }
      INBOX="$1"
      ;;
    --recovery-set)
      shift
      [[ $# -gt 0 ]] || { echo "restore: --recovery-set needs a directory" >&2; exit 2; }
      EXPLICIT_SET="$1"
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "restore: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

canonical_directory() {
  local path="$1"
  [[ -d "$path" && ! -L "$path" ]] || return 1
  (cd -- "$path" && pwd -P)
}

resolve_set() {
  local selected manifest
  if [[ -n "$EXPLICIT_SET" ]]; then
    selected="$(canonical_directory "$EXPLICIT_SET")" \
      || { echo "restore: unsafe or missing recovery-set directory: $EXPLICIT_SET" >&2; return 2; }
    [[ -f "$selected/recovery-set.json" && ! -L "$selected/recovery-set.json" ]] \
      || { echo "restore: recovery-set.json is missing or unsafe: $selected" >&2; return 2; }
    printf '%s\n' "$selected"
    return 0
  fi
  [[ -d "$INBOX" && ! -L "$INBOX" ]] \
    || { echo "restore: inbox is missing or unsafe: $INBOX" >&2; return 2; }
  mapfile -d '' -t manifests < <(
    find -P "$INBOX" -mindepth 2 -maxdepth 2 -type f -name recovery-set.json -print0 | sort -z
  )
  if ((${#manifests[@]} == 0)); then
    echo "restore: no recovery set found below $INBOX" >&2
    return 2
  fi
  if ((${#manifests[@]} != 1)); then
    echo "restore: ambiguous inbox; found ${#manifests[@]} recovery sets below $INBOX" >&2
    return 2
  fi
  manifest="${manifests[0]}"
  [[ ! -L "$manifest" ]] || { echo "restore: recovery-set manifest may not be a symlink" >&2; return 2; }
  selected="$(canonical_directory "$(dirname -- "$manifest")")" \
    || { echo "restore: recovery-set parent is unsafe" >&2; return 2; }
  printf '%s\n' "$selected"
}

SET_DIR="$(resolve_set)" || exit $?
if ((RESOLVE_ONLY)); then
  printf '%s\n' "$SET_DIR"
  exit 0
fi

STAGE0_VERIFIED_COMMIT_CANDIDATE="${CSR_STAGE0_VERIFIED_COMMIT:-}"
[[ "$STAGE0_VERIFIED_COMMIT_CANDIDATE" =~ ^[0-9a-f]{40}$ \
    || "$STAGE0_VERIFIED_COMMIT_CANDIDATE" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "restore: authenticated restore must start with restore-ubuntu.sh" >&2; exit 2; }
(( DESCRIPTOR_BOUND_RESTORE == 1 )) \
  || { echo "restore: authenticated restore requires the sealed Stage-0 entry point" >&2; exit 2; }

if [[ -z "${CSR_ESCROW_SHARE_1_FILE:-}" && -z "${CSR_ESCROW_SHARE_2_FILE:-}" ]]; then
  mapfile -d '' -t DISCOVERED_SHARES < <(
    /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
      "$REPO/bin/resolve-escrow-shares.py" \
      --set-dir "$SET_DIR" --inbox "$INBOX" --null
  )
  [[ ${#DISCOVERED_SHARES[@]} -eq 2 ]] || {
    echo "restore: automatic escrow-share discovery failed" >&2
    exit 2
  }
  export CSR_ESCROW_SHARE_1_FILE="${DISCOVERED_SHARES[0]}"
  export CSR_ESCROW_SHARE_2_FILE="${DISCOVERED_SHARES[1]}"
elif [[ -z "${CSR_ESCROW_SHARE_1_FILE:-}" || -z "${CSR_ESCROW_SHARE_2_FILE:-}" ]]; then
  echo "restore: set both escrow share-file variables or neither" >&2
  exit 2
fi

[[ $EUID -ne 0 ]] || { echo "restore: run as the target user, not root" >&2; exit 2; }
command -v flock >/dev/null || { echo "restore: flock is required (util-linux)" >&2; exit 2; }
command -v python3 >/dev/null || { echo "restore: python3 is required" >&2; exit 2; }

[[ -f "$RECOVERY_TOOL" && ! -L "$RECOVERY_TOOL" ]] \
  || { echo "restore: recovery-set validator is not installed" >&2; exit 2; }
# Freeze all signed metadata and encrypted artifacts before authentication.
# Every later consumer receives this owner-only, read-only snapshot rather than
# reopening mutable removable/FUSE recovery media.
if [[ -n "$STAGE0_RECOVERY_SNAPSHOT_CANDIDATE" ]]; then
  [[ "$SET_DIR" == "$STAGE0_RECOVERY_SNAPSHOT_CANDIDATE" ]] \
    || { echo "restore: Stage-0 snapshot marker does not match RECOVERY_SET" >&2; exit 2; }
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$RECOVERY_TOOL" check-snapshot \
    --snapshot-dir "$SET_DIR" >/dev/null
  RECOVERY_SNAPSHOT="$SET_DIR"
else
  RECOVERY_SNAPSHOT="$(mktemp -d "/tmp/csr-recovery-snapshot.$(id -u).XXXXXXXX")"
  chmod 0700 "$RECOVERY_SNAPSHOT"
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$RECOVERY_TOOL" snapshot-set \
    --set-dir "$SET_DIR" --output-dir "$RECOVERY_SNAPSHOT" >/dev/null
fi
SET_DIR="$RECOVERY_SNAPSHOT"
export RECOVERY_SET="$SET_DIR"
export CSR_RESTORE_RECOVERY_SNAPSHOT="$SET_DIR"
# Authenticate and fully decrypt/validate the set before trusting its
# repository pointer.  Share values remain behind protected file descriptors.
RECOVERY_SET="$SET_DIR" /usr/bin/bash -p "$REPO/bin/secrets-verify.sh"

read -r SIGNED_OWNER_FILE SIGNED_OWNER_REQUIREMENT SIGNED_OWNER_SHA256 < <(
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$RECOVERY_TOOL" inspect-set-owner --set-dir "$SET_DIR" \
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
  echo "restore: signed owner-data record is invalid" >&2
  exit 2
}
if [[ "$SIGNED_OWNER_FILE" == "-" ]]; then
  [[ "$SIGNED_OWNER_REQUIREMENT" == "none" && "$SIGNED_OWNER_SHA256" == "-" ]] \
    || { echo "restore: signed owner-data record is invalid" >&2; exit 2; }
else
  OWNER_DATA="$SET_DIR/$SIGNED_OWNER_FILE"
  [[ -f "$OWNER_DATA" && ! -L "$OWNER_DATA" ]] \
    || { echo "restore: signed owner-data member is missing or unsafe" >&2; exit 2; }
  REQUIRE_OWNER_DATA=1
  CSR_OWNER_DATA_REQUIREMENT="$SIGNED_OWNER_REQUIREMENT"
  CSR_SIGNED_OWNER_DATA_SHA256="$SIGNED_OWNER_SHA256"
  export OWNER_DATA REQUIRE_OWNER_DATA CSR_OWNER_DATA_REQUIREMENT \
    CSR_SIGNED_OWNER_DATA_SHA256
fi

EXPECTED_COMMIT="$(/usr/bin/python3 -I -B - "$SET_DIR/recovery-set.json" <<'PY'
import json
import re
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
commit = value.get("components", {}).get("coding-system-rebuild", {}).get("commit", "")
if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit) is None:
    raise SystemExit(2)
print(commit)
PY
)" || { echo "restore: recovery set has no canonical repository commit" >&2; exit 2; }
[[ "$STAGE0_VERIFIED_COMMIT_CANDIDATE" == "$EXPECTED_COMMIT" ]] \
  || { echo "restore: Stage-0 commit differs from the signed recovery commit" >&2; exit 2; }
export CSR_EXPECTED_RECOVERY_COMMIT="$EXPECTED_COMMIT"
[[ "$STAGE0_TREE_CANDIDATE" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] \
  || { echo "restore: authenticated repository tree identity is invalid" >&2; exit 2; }
/usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
  "$REPO/bin/lib/repository_generation.py" verify \
  --commit "$EXPECTED_COMMIT" --tree "$STAGE0_TREE_CANDIDATE" \
  --path "$REPO" >/dev/null \
  || { echo "restore: repository generation no longer matches the recovery set" >&2; exit 2; }

STATE_ROOT="$HOME/.local/state/coding-system/restore"
mkdir -p "$STATE_ROOT"
[[ -d "$STATE_ROOT" && ! -L "$STATE_ROOT" ]] \
  || { echo "restore: unsafe restore-state directory" >&2; exit 2; }
chmod 700 "$STATE_ROOT"
LOCK_FILE="$STATE_ROOT/restore.lock"
if [[ ! -e "$LOCK_FILE" && ! -L "$LOCK_FILE" ]]; then
  (umask 077; set -o noclobber; : > "$LOCK_FILE") 2>/dev/null || true
fi
/usr/bin/python3 -I -B - "$LOCK_FILE" <<'PY'
import os
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])
info = path.lstat()
if (
    path.is_symlink()
    or not stat.S_ISREG(info.st_mode)
    or info.st_uid != os.getuid()
    or info.st_nlink != 1
    or stat.S_IMODE(info.st_mode) != 0o600
):
    raise SystemExit("restore: unsafe restore lock file")
PY
exec 9<>"$LOCK_FILE"
flock -n 9 || { echo "restore: another restore is already running" >&2; exit 2; }

export RECOVERY_SET="$SET_DIR"
export CSR_REQUIRE_RELEASE_QUALIFIED=1
/usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
  "$REPO" "$EXPECTED_COMMIT" <<'PY'
import fcntl
import os
from pathlib import Path
import stat
import sys


class HandoffError(RuntimeError):
    pass


repository = Path(sys.argv[1])
commit = sys.argv[2]
entrypoint = repository / "bin/install.sh"
source_fd = -1
sealed_fd = -1
try:
    root_info = repository.stat()
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != 0
        or stat.S_IMODE(root_info.st_mode) != 0o555
    ):
        raise HandoffError("repository generation root has unsafe metadata")
    source_fd = os.open(
        entrypoint,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    before = os.fstat(source_fd)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_nlink != 1
        or before.st_dev != root_info.st_dev
        or stat.S_IMODE(before.st_mode) != 0o555
        or before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
        or before.st_size > 4 * 1024 * 1024
    ):
        raise HandoffError("installer entry point has unsafe metadata")
    source = bytearray()
    while len(source) <= 4 * 1024 * 1024:
        block = os.read(source_fd, min(64 * 1024, 4 * 1024 * 1024 + 1 - len(source)))
        if not block:
            break
        source.extend(block)
    after = os.fstat(source_fd)
    if len(source) > 4 * 1024 * 1024 or (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise HandoffError("installer entry point changed while it was opened")
    path_info = entrypoint.lstat()
    if (path_info.st_dev, path_info.st_ino) != (after.st_dev, after.st_ino):
        raise HandoffError("installer pathname changed after checkout verification")

    sealed_fd = os.memfd_create(
        "csr-authenticated-install",
        getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0),
    )
    view = memoryview(source)
    while view:
        written = os.write(sealed_fd, view)
        view = view[written:]
    os.lseek(sealed_fd, 0, os.SEEK_SET)
    fcntl.fcntl(
        sealed_fd,
        fcntl.F_ADD_SEALS,
        fcntl.F_SEAL_SEAL
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_WRITE,
    )
    os.set_inheritable(sealed_fd, True)
    environment = dict(os.environ)
    environment["CSR_INSTALL_REPO_ROOT"] = os.fspath(repository)
    os.execve(
        "/usr/bin/bash",
        ["/usr/bin/bash", "-p", f"/proc/self/fd/{sealed_fd}"],
        environment,
    )
except (OSError, HandoffError) as exc:
    raise SystemExit(f"restore: authenticated installer handoff failed: {exc}")
finally:
    if source_fd >= 0:
        os.close(source_fd)
    if sealed_fd >= 0:
        os.close(sealed_fd)
PY
SUCCESS_TMP="$(mktemp "$STATE_ROOT/.last-successful-commit.XXXXXXXX")"
printf '%s\n' "$EXPECTED_COMMIT" > "$SUCCESS_TMP"
chmod 600 "$SUCCESS_TMP"
mv -f "$SUCCESS_TMP" "$STATE_ROOT/last-successful-commit"
echo "restore: complete; verification was emitted by bin/install.sh"
