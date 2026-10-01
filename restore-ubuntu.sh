#!/usr/bin/bash -p
# Stage-0 bootstrap for a bare Ubuntu 24.04 amd64/arm64 host.
#
# Place this trusted script in ~/secrets-restore-inbox with exactly one
# recovery-set directory and exactly two matching files below
# escrow/<generation-id>/, then run it as the intended owner account. It installs only the small bootstrap
# substrate, checks out the exact repository commit named by the recovery set,
# then hands control to the repository restore entry point.
#
# Bash imports exported functions before reading a script. Direct execution
# uses privileged mode in the shebang; documented explicit invocations use
# `/usr/bin/bash -p` so startup hooks are disabled before this trust root is
# parsed. The envelope retains privileged mode across internal re-entry.
if [[ $- != *p* ]]; then
  /usr/bin/bash -p "$0" "$@"
else
set -euo pipefail
umask 077

# Stage-0 is a trust root.  Never resolve authentication or checkout tooling
# through an inherited user-writable PATH.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
IFS=$' \t\n'
unset BASH_ENV CDPATH ENV GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR \
  GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_DIR GIT_INDEX_FILE \
  GIT_OBJECT_DIRECTORY GIT_WORK_TREE LD_LIBRARY_PATH LD_PRELOAD PYTHONHOME \
  PYTHONINSPECT PYTHONPATH PYTHONSTARTUP PYTHONUSERBASE MAKEFLAGS MAKEFILES \
  GNUMAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES MAKE_RESTARTS MAKE_TERMERR \
  MAKE_TERMOUT

die() { echo "restore-ubuntu: $*" >&2; exit 2; }
note() { printf 'restore-ubuntu: %s\n' "$*"; }
REQUESTED_PHASE="${PHASE:-}"
if [[ -n "$REQUESTED_PHASE" \
    && ! "$REQUESTED_PHASE" =~ ^([1-9]|1[0-2])$ ]]; then
  die "PHASE must be an integer from 1 through 12"
fi
STAGE0_TEST_SNAPSHOT_TAG="${CSR_STAGE0_TEST_SNAPSHOT_TAG:-}"
if [[ -n "$STAGE0_TEST_SNAPSHOT_TAG" \
    && ! "$STAGE0_TEST_SNAPSHOT_TAG" =~ ^[0-9a-f]{32}$ ]]; then
  die "CSR_STAGE0_TEST_SNAPSHOT_TAG has an invalid test-run identity"
fi
CLONE_STAGE=""
CLONE_STAGE_PREFIX=""
ALLOWED_SIGNERS=""
RECOVERY_SNAPSHOT=""
cleanup() {
  if [[ -n "$CLONE_STAGE" ]]; then
    if [[ -n "$CLONE_STAGE_PREFIX" && "$CLONE_STAGE" == "$CLONE_STAGE_PREFIX"* ]]; then
      rm -rf -- "$CLONE_STAGE"
    else
      echo "restore-ubuntu: refusing unsafe clone-stage cleanup: $CLONE_STAGE" >&2
    fi
  fi
  case "$ALLOWED_SIGNERS" in
    /tmp/csr-bootstrap-signers.*) rm -f -- "$ALLOWED_SIGNERS" ;;
    "") ;;
    *) echo "restore-ubuntu: refusing unsafe signature-file cleanup: $ALLOWED_SIGNERS" >&2 ;;
  esac
  if [[ -n "$RECOVERY_SNAPSHOT" && -d "$RECOVERY_SNAPSHOT" ]]; then
    /usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
      "$RECOVERY_SNAPSHOT" "$(id -u)" <<'PY' >/dev/null 2>&1 || \
      echo "restore-ubuntu: protected recovery snapshot retained: $RECOVERY_SNAPSHOT" >&2
import os
from pathlib import Path
import re
import stat
import sys

path = Path(sys.argv[1])
uid = int(sys.argv[2])
if (
    path.parent != Path("/tmp")
    or re.fullmatch(
        rf"csr-recovery-snapshot\.{uid}\.(?:[0-9a-f]{{32}}\.)?[A-Za-z0-9_-]+",
        path.name,
    )
    is None
):
    raise SystemExit(2)
descriptor = os.open(
    path,
    os.O_RDONLY
    | os.O_DIRECTORY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0),
)
try:
    info = os.fstat(descriptor)
    if info.st_uid != uid or not stat.S_ISDIR(info.st_mode):
        raise SystemExit(2)
    names = os.listdir(descriptor)
    os.fchmod(descriptor, 0o700)
    for name in names:
        member = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISREG(member.st_mode):
            raise SystemExit(2)
        os.unlink(name, dir_fd=descriptor)
finally:
    os.close(descriptor)
os.rmdir(path)
PY
  fi
}
trap cleanup EXIT

CHECK_ONLY=0
case "${1:-}" in
  "") ;;
  --check-only) CHECK_ONLY=1 ;;
  -h|--help)
    cat <<'EOF'
Usage: restore-ubuntu.sh [--check-only]

Validate one complete signed recovery set (and, for --check-only, exactly two
matching escrow shares) on Ubuntu 24.04 amd64/arm64.  Without --check-only,
install the bootstrap packages, check out the signed repository commit, and
run the one-command restore.
EOF
    exit 0
    ;;
  *) die "unknown argument: $1" ;;
esac

[[ $(id -u) -ne 0 ]] || die "run as the intended non-root owner; sudo is requested only for bootstrap packages"
[[ -r /etc/os-release ]] || die "cannot read /etc/os-release"
# Root owns this standard system file; sourcing it avoids assuming Python is
# already present on an otherwise minimal Ubuntu image.
# shellcheck disable=SC1091
. /etc/os-release
OS_ID=${ID:-}
OS_VERSION=${VERSION_ID:-}
[[ "$OS_ID" == ubuntu && "$OS_VERSION" == 24.04 ]] || \
  die "supported host is Ubuntu 24.04; found ${OS_ID:-unknown} ${OS_VERSION:-unknown}"

case "$(uname -m)" in
  aarch64|arm64) RESTORE_ARCH=arm64 ;;
  x86_64|amd64) RESTORE_ARCH=amd64 ;;
  *) die "supported architectures are arm64 and amd64; found $(uname -m)" ;;
esac

INBOX=${CSR_RESTORE_INBOX:-"$HOME/secrets-restore-inbox"}
if [[ -n "${RECOVERY_SET:-}" ]]; then
  RECOVERY_DIR=${RECOVERY_SET%/}
  [[ -d "$RECOVERY_DIR" && ! -L "$RECOVERY_DIR" \
      && -f "$RECOVERY_DIR/recovery-set.json" \
      && ! -L "$RECOVERY_DIR/recovery-set.json" ]] || \
    die "RECOVERY_SET must name a directory containing recovery-set.json"
else
  [[ -d "$INBOX" && ! -L "$INBOX" ]] || die "recovery inbox does not exist or is unsafe: $INBOX"
  mapfile -d '' RECOVERY_MANIFESTS < <(
    find -P "$INBOX" -mindepth 1 -maxdepth 2 -type f -name recovery-set.json -print0
  )
  [[ ${#RECOVERY_MANIFESTS[@]} -eq 1 ]] || \
    die "expected exactly one recovery-set.json under $INBOX; found ${#RECOVERY_MANIFESTS[@]}"
  RECOVERY_DIR=$(dirname "${RECOVERY_MANIFESTS[0]}")
fi
RECOVERY_DIR=$(cd -- "$RECOVERY_DIR" && pwd -P) \
  || die "cannot canonicalize recovery-set directory"

SIGNING_IDENTITY="coding-system-recovery"
SIGNING_NAMESPACE="coding-system-recovery-set-v1"
SIGNING_KEY_SHA256="c869a7314609cc6a6c167a3dc7e4f8456b7c0ac11eeb9dd091db0d99b3b82898"
SIGNING_KEY="$RECOVERY_DIR/recovery-signing-public-key.pub"
RECOVERY_SIGNATURE="$RECOVERY_DIR/recovery-set.json.sig"

BOOTSTRAP_PACKAGES=(
  ca-certificates
  curl
  git
  make
  python3
  python3-yaml
  gnupg
  openssh-client
  jq
  7zip
)
BOOTSTRAPPED=0
if ! command -v python3 >/dev/null 2>&1 || ! command -v ssh-keygen >/dev/null 2>&1; then
  (( ! CHECK_ONLY )) || die "python3 is absent; omit --check-only to install the bootstrap substrate"
  note "installing the signed Ubuntu bootstrap substrate"
  sudo -v
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${BOOTSTRAP_PACKAGES[@]}"
  BOOTSTRAPPED=1
fi

# Freeze the closed recovery inventory before signature verification.  The
# source may be removable storage or FUSE-backed; all later reads use this
# owner-only snapshot copied through one held no-follow directory descriptor.
RECOVERY_SOURCE_DIR="$RECOVERY_DIR"
RECOVERY_SNAPSHOT="$(/usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
  "$RECOVERY_SOURCE_DIR" "$STAGE0_TEST_SNAPSHOT_TAG" <<'PY'
import os
from pathlib import Path
import json
import re
import shutil
import stat
import sys
import tempfile

source_path = Path(os.path.abspath(sys.argv[1]))
test_tag = sys.argv[2]
metadata_limit = 1024 * 1024
archive_limit = 2 * 1024 * 1024 * 1024
owner_archive_limit = 8 * 1024 * 1024 * 1024
owner_name_pattern = re.compile(
    r"openclaw-private-[0-9]{8}T[0-9]{6}Z[.]tar[.]gz[.]gpg"
)
metadata_required = {
    "recovery-set.json",
    "recovery-set.json.sig",
    "recovery-signing-public-key.pub",
}
base_required = metadata_required | {
    "escrow-generation.json",
    "keys.json.gpg",
    "secrets.tar.gpg",
    "private-state.tar.gpg",
}


def open_directory(path: Path) -> int:
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeError("duplicate recovery manifest key")
        value[key] = item
    return value


def snapshot_contract(directory_fd: int) -> tuple[frozenset[str], frozenset[str], str | None]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open("recovery-set.json", flags, dir_fd=directory_fd)
    try:
        before = os.fstat(descriptor)
        linked = os.stat(
            "recovery-set.json", dir_fd=directory_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
            or before.st_nlink != 1
            or not 0 < before.st_size <= metadata_limit
        ):
            raise RuntimeError("unsafe recovery manifest")
        raw = bytearray()
        while len(raw) <= metadata_limit:
            chunk = os.read(descriptor, min(64 * 1024, metadata_limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if len(raw) != before.st_size or identity(before) != identity(after):
            raise RuntimeError("recovery manifest changed while reading")
    finally:
        os.close(descriptor)
    try:
        public = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("invalid recovery manifest") from exc
    if not isinstance(public, dict) or public.get("schema") != "coding-system.recovery-set.v2":
        raise RuntimeError("Stage-0 requires recovery-set v2")
    if "owner_data" not in public:
        raise RuntimeError("recovery-set v2 lacks owner-data metadata")
    owner = public["owner_data"]
    owner_name = None
    if owner is not None:
        if not isinstance(owner, dict) or set(owner) != {
            "file",
            "sha256",
            "size",
            "openclaw_version",
            "requirement",
            "created_at",
            "source_state_hmac_sha256",
            "capture_policy",
        }:
            raise RuntimeError("invalid owner-data metadata")
        owner_name = owner.get("file")
        if (
            not isinstance(owner_name, str)
            or owner_name_pattern.fullmatch(owner_name) is None
            or not isinstance(owner.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", owner["sha256"]) is None
            or type(owner.get("size")) is not int
            or not 0 < owner["size"] <= owner_archive_limit
            or not isinstance(owner.get("openclaw_version"), str)
            or re.fullmatch(
                r"[0-9A-Za-z][0-9A-Za-z.+~_-]{0,127}",
                owner["openclaw_version"],
            )
            is None
            or owner.get("requirement")
            not in {"agent-private-capability", "history-only"}
            or not isinstance(owner.get("created_at"), str)
            or not owner["created_at"].endswith("Z")
            or not isinstance(owner.get("source_state_hmac_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", owner["source_state_hmac_sha256"])
            is None
            or owner.get("capture_policy")
            not in {"fresh-native-snapshot", "reviewed-prebuilt-override"}
        ):
            raise RuntimeError("invalid owner-data metadata")
    required = set(base_required)
    allowed = set(base_required) | {"restore-ubuntu.sh"}
    if owner_name is not None:
        required.add(owner_name)
        allowed.add(owner_name)
    return frozenset(required), frozenset(allowed), owner_name


source = open_directory(source_path)
snapshot_path = Path(
    tempfile.mkdtemp(
        prefix=(
            f"csr-recovery-snapshot.{os.geteuid()}.{test_tag}."
            if test_tag
            else f"csr-recovery-snapshot.{os.geteuid()}."
        ),
        dir="/tmp",
    )
)
snapshot_path.chmod(0o700)
destination = open_directory(snapshot_path)
try:
    required, allowed, owner_name = snapshot_contract(source)
    names_before = frozenset(os.listdir(source))
    if not required.issubset(names_before) or not names_before.issubset(allowed):
        raise RuntimeError("recovery set inventory is not closed and complete")
    for name in sorted(names_before):
        if name == owner_name:
            limit = owner_archive_limit
        else:
            limit = archive_limit if name.endswith(".gpg") else metadata_limit
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        source_member = os.open(name, flags, dir_fd=source)
        destination_member = -1
        try:
            before = os.fstat(source_member)
            linked = os.stat(name, dir_fd=source, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or not stat.S_ISREG(linked.st_mode)
                or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
                or before.st_nlink != 1
                or not 0 < before.st_size <= limit
            ):
                raise RuntimeError(f"unsafe recovery member: {name}")
            destination_member = os.open(
                name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o400,
                dir_fd=destination,
            )
            copied = 0
            while True:
                chunk = os.read(source_member, 1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > limit:
                    raise RuntimeError(f"recovery member exceeds bound: {name}")
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_member, view)
                    view = view[written:]
            after = os.fstat(source_member)
            if copied != before.st_size or identity(before) != identity(after):
                raise RuntimeError(f"recovery member changed while copying: {name}")
            os.fchmod(destination_member, 0o400)
            os.fsync(destination_member)
        finally:
            os.close(source_member)
            if destination_member >= 0:
                os.close(destination_member)
    if frozenset(os.listdir(source)) != names_before:
        raise RuntimeError("recovery inventory changed while copying")
    os.fchmod(destination, 0o500)
    os.fsync(destination)
except BaseException:
    os.close(source)
    os.close(destination)
    snapshot_path.chmod(0o700)
    shutil.rmtree(snapshot_path)
    raise
else:
    os.close(source)
    os.close(destination)
print(snapshot_path)
PY
)" || die "could not create a stable recovery-set snapshot"
RECOVERY_DIR="$RECOVERY_SNAPSHOT"
SIGNING_KEY="$RECOVERY_DIR/recovery-signing-public-key.pub"
RECOVERY_SIGNATURE="$RECOVERY_DIR/recovery-set.json.sig"

# Deterministic check-only synchronization for the hostile-source regression.
# It can only pause; it cannot alter or bypass any authentication decision.
if [[ -n "${CSR_STAGE0_TEST_PAUSE_AFTER_SNAPSHOT:-}" ]]; then
  (( CHECK_ONLY )) || die "Stage-0 snapshot test synchronization requires --check-only"
  pause_marker="$CSR_STAGE0_TEST_PAUSE_AFTER_SNAPSHOT"
  [[ "$pause_marker" == /tmp/* && ! -e "$pause_marker.ready" \
      && ! -L "$pause_marker.ready" ]] \
    || die "unsafe Stage-0 snapshot test marker"
  (umask 077; set -o noclobber; : > "$pause_marker.ready") 2>/dev/null \
    || die "cannot publish Stage-0 snapshot test marker"
  for _snapshot_wait in {1..200}; do
    [[ -f "$pause_marker.continue" && ! -L "$pause_marker.continue" ]] && break
    sleep 0.05
  done
  [[ -f "$pause_marker.continue" && ! -L "$pause_marker.continue" ]] \
    || die "Stage-0 snapshot test synchronization timed out"
fi

for path in "$SIGNING_KEY" "$RECOVERY_SIGNATURE" "$RECOVERY_DIR/recovery-set.json"; do
  [[ -f "$path" && ! -L "$path" ]] || die "signed recovery metadata is missing or unsafe: $path"
  size=$(/usr/bin/stat -c %s -- "$path")
  [[ "$size" =~ ^[0-9]+$ && "$size" -gt 0 && "$size" -le 1048576 ]] \
    || die "signed recovery metadata exceeds its bound: $path"
done
actual_key_sha256=$(/usr/bin/sha256sum "$SIGNING_KEY" | /usr/bin/cut -d' ' -f1)
[[ "$actual_key_sha256" == "$SIGNING_KEY_SHA256" ]] \
  || die "recovery signing public key does not match the pinned Stage-0 trust anchor"
public_key=$(/usr/bin/awk 'NR == 1 {print $1 " " $2}' "$SIGNING_KEY")
[[ "$public_key" == ssh-ed25519\ * ]] || die "unsupported recovery signing key"
ALLOWED_SIGNERS=$(/usr/bin/mktemp /tmp/csr-bootstrap-signers.XXXXXXXX)
chmod 0600 "$ALLOWED_SIGNERS"
printf '%s %s\n' "$SIGNING_IDENTITY" "$public_key" > "$ALLOWED_SIGNERS"
/usr/bin/ssh-keygen -Y verify -q -f "$ALLOWED_SIGNERS" -I "$SIGNING_IDENTITY" \
  -n "$SIGNING_NAMESPACE" -s "$RECOVERY_SIGNATURE" \
  < "$RECOVERY_DIR/recovery-set.json" >/dev/null 2>&1 \
  || die "recovery-set signature is invalid"
rm -f -- "$ALLOWED_SIGNERS"
ALLOWED_SIGNERS=""

bootstrap_record=""
bootstrap_rc=0
bootstrap_record="$(/usr/bin/python3 - "$RECOVERY_DIR/recovery-set.json" <<'PY'
import json
import re
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
record = value.get("bootstrap")
if not isinstance(record, dict):
    raise SystemExit(3)
name = record.get("file")
digest = record.get("sha256")
size = record.get("size")
if (
    name != "restore-ubuntu.sh"
    or not isinstance(digest, str)
    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    or isinstance(size, bool)
    or not isinstance(size, int)
    or not 0 < size <= 1048576
):
    raise SystemExit(2)
print(name, digest, size)
PY
)" || bootstrap_rc=$?
if [[ "$bootstrap_rc" -ne 0 ]]; then
  die "signed recovery set has no valid Stage-0 bootstrap binding"
else
  read -r bootstrap_file bootstrap_sha bootstrap_size <<<"$bootstrap_record"
fi
if [[ -n "$bootstrap_file" ]]; then
  embedded_bootstrap="$RECOVERY_DIR/$bootstrap_file"
  [[ -f "$embedded_bootstrap" && ! -L "$embedded_bootstrap" ]] \
    || die "signed Stage-0 bootstrap artifact is missing or unsafe"
  [[ "$(/usr/bin/stat -c %s -- "$embedded_bootstrap")" == "$bootstrap_size" \
      && "$(/usr/bin/sha256sum "$embedded_bootstrap" | /usr/bin/cut -d' ' -f1)" == "$bootstrap_sha" ]] \
    || die "signed Stage-0 bootstrap artifact digest/size mismatch"
  [[ "$(/usr/bin/sha256sum "$0" | /usr/bin/cut -d' ' -f1)" == "$bootstrap_sha" ]] \
    || die "executed Stage-0 script does not match the signed recovery set"
fi

# The signature authenticates the public manifest; now bind every encrypted
# artifact and the embedded escrow metadata to that exact signed byte string.
# Also require the two share files that the next stage will consume.  This is a
# structural/digest check only: share values are never placed in argv output or
# the environment, and payload decryption remains in the recovery engine.
/usr/bin/python3 -I -B -X pycache_prefix=/dev/null - "$RECOVERY_DIR" "$INBOX" \
  "${CSR_ESCROW_SHARE_1_FILE:-}" "${CSR_ESCROW_SHARE_2_FILE:-}" <<'PY' \
  || die "signed recovery artifacts or escrow shares are incomplete or unsafe"
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

set_dir = Path(sys.argv[1])
inbox = Path(sys.argv[2])
explicit = [value for value in sys.argv[3:5] if value]
metadata_limit = 1024 * 1024
archive_limit = 2 * 1024 * 1024 * 1024
owner_archive_limit = 8 * 1024 * 1024 * 1024
owner_name_pattern = re.compile(
    r"openclaw-private-[0-9]{8}T[0-9]{6}Z[.]tar[.]gz[.]gpg"
)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def read_regular(path: Path, limit: int, *, secret: bool = False) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= limit
            or (secret and before.st_uid != os.geteuid())
            or (secret and stat.S_IMODE(before.st_mode) & 0o077)
        ):
            raise ValueError("unsafe regular file")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ValueError("file exceeds bound")
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if total != before.st_size or identity(before) != identity(after):
            raise ValueError("file changed while reading")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def hash_regular(path: Path, limit: int) -> tuple[int, str]:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= limit
        ):
            raise ValueError("unsafe artifact")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError("artifact exceeds bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if total != before.st_size or identity(before) != identity(after):
            raise ValueError("artifact changed while hashing")
        return total, digest.hexdigest()
    finally:
        os.close(descriptor)


def load_json(raw: bytes):
    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError("JSON root is not an object")
    return value


public_raw, _ = read_regular(set_dir / "recovery-set.json", metadata_limit)
public = load_json(public_raw)
expected_public_fields = {
    "schema",
    "set_id",
    "created_at",
    "components",
    "escrow_generation",
    "secrets_manifest",
    "artifacts",
    "owner_data",
}
if "bootstrap" in public:
    expected_public_fields.add("bootstrap")
if (
    public.get("schema") != "coding-system.recovery-set.v2"
    or set(public) != expected_public_fields
):
    raise SystemExit(2)

owner = public["owner_data"]
owner_name = None
if owner is not None:
    if not isinstance(owner, dict) or set(owner) != {
        "file",
        "sha256",
        "size",
        "openclaw_version",
        "requirement",
        "created_at",
        "source_state_hmac_sha256",
        "capture_policy",
    }:
        raise SystemExit(2)
    owner_name = owner.get("file")
    if (
        not isinstance(owner_name, str)
        or owner_name_pattern.fullmatch(owner_name) is None
        or not isinstance(owner.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", owner["sha256"]) is None
        or type(owner.get("size")) is not int
        or not 0 < owner["size"] <= owner_archive_limit
        or not isinstance(owner.get("openclaw_version"), str)
        or re.fullmatch(
            r"[0-9A-Za-z][0-9A-Za-z.+~_-]{0,127}", owner["openclaw_version"]
        )
        is None
        or owner.get("requirement")
        not in {"agent-private-capability", "history-only"}
        or not isinstance(owner.get("created_at"), str)
        or not owner["created_at"].endswith("Z")
        or not isinstance(owner.get("source_state_hmac_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", owner["source_state_hmac_sha256"])
        is None
        or owner.get("capture_policy")
        not in {"fresh-native-snapshot", "reviewed-prebuilt-override"}
    ):
        raise SystemExit(2)
    size, digest = hash_regular(set_dir / owner_name, owner_archive_limit)
    if size != owner["size"] or digest != owner["sha256"]:
        raise SystemExit(2)

artifacts = public.get("artifacts")
expected_artifacts = {
    "keys": "keys.json.gpg",
    "secrets": "secrets.tar.gpg",
    "private_state": "private-state.tar.gpg",
}
if not isinstance(artifacts, dict) or set(artifacts) != set(expected_artifacts):
    raise SystemExit(2)
for label, filename in expected_artifacts.items():
    record = artifacts[label]
    if (
        not isinstance(record, dict)
        or set(record) != {"file", "sha256", "size"}
        or record.get("file") != filename
        or not isinstance(record.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        or isinstance(record.get("size"), bool)
        or not isinstance(record.get("size"), int)
        or not 0 < record["size"] <= archive_limit
    ):
        raise SystemExit(2)
    size, digest = hash_regular(set_dir / filename, archive_limit)
    if size != record["size"] or digest != record["sha256"]:
        raise SystemExit(2)

expected_inventory = {
    "recovery-set.json",
    "recovery-set.json.sig",
    "recovery-signing-public-key.pub",
    "escrow-generation.json",
    *expected_artifacts.values(),
}
if "bootstrap" in public:
    expected_inventory.add("restore-ubuntu.sh")
if owner_name is not None:
    expected_inventory.add(owner_name)
if {entry.name for entry in os.scandir(set_dir)} != expected_inventory:
    raise SystemExit(2)

escrow_raw, _ = read_regular(set_dir / "escrow-generation.json", metadata_limit)
escrow_reference = public.get("escrow_generation")
if (
    not isinstance(escrow_reference, dict)
    or set(escrow_reference) != {"generation_id", "file", "manifest_sha256"}
    or escrow_reference.get("file") != "escrow-generation.json"
    or hashlib.sha256(escrow_raw).hexdigest() != escrow_reference.get("manifest_sha256")
):
    raise SystemExit(2)
escrow = load_json(escrow_raw)
records = escrow.get("share_records")
generation_id = escrow.get("generation_id")
if (
    escrow.get("schema") != "coding-system.escrow-generation.v1"
    or escrow.get("threshold") != 2
    or escrow.get("shares") != 4
    or generation_id != escrow_reference.get("generation_id")
    or not isinstance(generation_id, str)
    or re.fullmatch(r"[a-z0-9][a-z0-9._-]{7,127}", generation_id) is None
    or not isinstance(records, list)
    or len(records) != 4
):
    raise SystemExit(2)
by_digest = {}
expected_names = set()
for record in records:
    if (
        not isinstance(record, dict)
        or set(record) != {"index", "file", "sha256"}
        or type(record.get("index")) is not int
        or record["index"] not in range(1, 5)
        or not isinstance(record.get("file"), str)
        or re.fullmatch(r"share-0[1-4]\.txt", record["file"]) is None
        or not isinstance(record.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        or record["sha256"] in by_digest
        or record["file"] in expected_names
    ):
        raise SystemExit(2)
    by_digest[record["sha256"]] = record
    expected_names.add(record["file"])
if {record["index"] for record in records} != {1, 2, 3, 4}:
    raise SystemExit(2)

if explicit:
    if len(explicit) != 2:
        raise SystemExit(2)
    share_paths = [Path(value) for value in explicit]
else:
    escrow_root = inbox / "escrow"
    share_root = escrow_root / generation_id
    for private_directory in (inbox, escrow_root, share_root):
        info = private_directory.lstat()
        if (
            private_directory.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise SystemExit(2)
    actual_names = {entry.name for entry in os.scandir(share_root)}
    if not actual_names.issubset(expected_names):
        raise SystemExit(2)
    share_paths = [share_root / name for name in sorted(actual_names)]
if len(share_paths) != 2:
    raise SystemExit(2)

indexes = set()
inodes = set()
for share_path in share_paths:
    raw, info = read_regular(share_path, 8192, secret=True)
    digest = hashlib.sha256(raw).hexdigest()
    record = by_digest.get(digest)
    if record is None:
        raise SystemExit(2)
    try:
        tag, index_text, _payload = raw.decode("ascii").strip().split(":", 2)
        encoded_index = int(index_text)
    except (UnicodeDecodeError, ValueError):
        raise SystemExit(2)
    if tag != "shamir-v1" or encoded_index != record["index"]:
        raise SystemExit(2)
    indexes.add(encoded_index)
    inodes.add((info.st_dev, info.st_ino))
if len(indexes) != 2 or len(inodes) != 2:
    raise SystemExit(2)
PY

RESTORE_COMMIT=$(/usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
  "$RECOVERY_DIR/recovery-set.json" <<'PY'
import json
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
try:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    commit = manifest["components"]["coding-system-rebuild"]["commit"]
except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
    raise SystemExit(f"restore-ubuntu: invalid recovery-set repository pointer: {exc}")
if not isinstance(commit, str) or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit) is None:
    raise SystemExit("restore-ubuntu: coding-system-rebuild commit must be exact lowercase 40- or 64-hex")
print(commit)
PY
)

note "host ubuntu-24.04/${RESTORE_ARCH}"
note "recovery set $RECOVERY_DIR"
note "repository commit $RESTORE_COMMIT"
if (( CHECK_ONLY )); then
  note "Stage-0 structural check complete: signed artifacts and exactly two escrow shares are present"
  note "encrypted payload decryption was not attempted; no packages, repository, or restored state changed"
  exit 0
fi

if (( ! BOOTSTRAPPED )); then
  note "converging the signed Ubuntu bootstrap substrate"
  sudo -v
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${BOOTSTRAP_PACKAGES[@]}"
fi

REPO_URL=${CSR_REPOSITORY_URL:-https://github.com/hoanganhduc/coding-system-rebuild.git}
[[ "$REPO_URL" == https://* ]] || die "CSR_REPOSITORY_URL must use HTTPS"
REPO_TARGET=${CSR_REPOSITORY_DIR:-"$HOME/coding-system-rebuild"}
REPO_TARGET=$(/usr/bin/python3 -I -B -X pycache_prefix=/dev/null -c \
  'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' \
  "$REPO_TARGET")
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=""
safe_git() {
  /usr/bin/env -i \
    HOME=/ PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    GIT_TERMINAL_PROMPT=0 XDG_CONFIG_HOME=/dev/null \
    /usr/bin/git --no-optional-locks \
      -c core.hooksPath=/dev/null -c core.fsmonitor=false \
      -c protocol.allow=never -c protocol.https.allow=always \
      -c protocol.ext.allow=never -c protocol.file.allow=never \
      -c credential.helper= -c core.sshCommand=/bin/false "$@"
}
safe_object_git() {
  /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 60s \
    /usr/bin/env -i \
      HOME=/ PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
      GIT_TERMINAL_PROMPT=0 XDG_CONFIG_HOME=/dev/null \
      /usr/bin/git --no-optional-locks \
        -c core.hooksPath=/dev/null -c core.fsmonitor=false \
        -c core.commitGraph=false -c core.multiPackIndex=false \
        -c core.alternateRefsCommand= -c fsck.skipList=/dev/null \
        -c protocol.allow=never -c protocol.file.allow=never \
        -c credential.helper= -c core.sshCommand=/bin/false \
        "$@"
}
validate_clone_parent() {
  local target="$1"
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
    "$target" "$(id -u)" <<'PY'
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

target = Path(sys.argv[1])
owner = int(sys.argv[2])
if not target.is_absolute() or not target.name or target.name in {".", ".."}:
    raise SystemExit("clone destination is invalid")
parent = target.parent
if parent != Path(os.path.realpath(parent)) or not parent.is_dir():
    raise SystemExit("clone destination parent is non-canonical or missing")
for ancestor in (parent, *parent.parents):
    information = ancestor.lstat()
    if ancestor.is_symlink() or not stat.S_ISDIR(information.st_mode):
        raise SystemExit("clone destination has an unsafe ancestor")
    if information.st_uid not in {0, owner}:
        raise SystemExit("clone destination ancestor has an unsafe owner")
    mode = stat.S_IMODE(information.st_mode)
    if mode & stat.S_ISVTX:
        continue
    if mode & 0o022:
        raise SystemExit("clone destination ancestor is group/world-writable")
filesystem = subprocess.run(
    ["/usr/bin/stat", "-f", "-c", "%T", os.fspath(parent)],
    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    timeout=5,
    check=False,
)
if filesystem.returncode != 0 or filesystem.stdout.strip().lower().startswith(
    ("fuse", "nfs", "cifs", "smb", "9p", "ceph", "afs")
):
    raise SystemExit("clone destination storage is unavailable or remote")
PY
}
rename_clone_noreplace() {
  local source="$1" destination="$2"
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
    "$source" "$destination" <<'PY'
import ctypes
import os
import sys

source, destination = map(os.fsencode, sys.argv[1:])
libc = ctypes.CDLL(None, use_errno=True)
try:
    renameat2 = libc.renameat2
except AttributeError as exc:
    raise SystemExit("renameat2 is unavailable on this supported Ubuntu host") from exc
renameat2.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
]
renameat2.restype = ctypes.c_int
if renameat2(-100, source, -100, destination, 1) != 0:
    error = ctypes.get_errno()
    raise SystemExit(f"cannot install authenticated checkout without replacement: {os.strerror(error)}")
PY
}
exchange_clone_atomically() {
  local source="$1" destination="$2"
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
    "$source" "$destination" <<'PY'
import ctypes
import os
from pathlib import Path
import stat
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
if source.parent != destination.parent or source.name in {"", ".", ".."} \
        or destination.name in {"", ".", ".."}:
    raise SystemExit("authenticated checkout exchange paths are invalid")
parent_fd = os.open(
    source.parent,
    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) \
    | getattr(os, "O_NOFOLLOW", 0),
)
try:
    for name in (source.name, destination.name):
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode):
            raise SystemExit("authenticated checkout exchange target is not a directory")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise SystemExit("renameat2 is unavailable on this supported Ubuntu host") from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(
        parent_fd,
        os.fsencode(source.name),
        parent_fd,
        os.fsencode(destination.name),
        2,  # RENAME_EXCHANGE
    ) != 0:
        error = ctypes.get_errno()
        raise SystemExit(f"cannot atomically exchange authenticated checkout: {os.strerror(error)}")
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
}
preflight_git_storage() {
  local repository="$1"
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
    "$repository" "$(id -u)" <<'PY'
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


class PreflightError(RuntimeError):
    pass


LOCAL_FILESYSTEM_TYPES = frozenset(
    {
        "bcachefs", "btrfs", "ext2", "ext2/ext3", "ext3", "ext4",
        "f2fs", "jfs", "nilfs2", "overlay", "overlayfs", "reiserfs",
        "tmpfs", "xfs", "zfs",
    }
)


def require_private_owner(info: os.stat_result, label: str, owner: int) -> None:
    mode = stat.S_IMODE(info.st_mode)
    if (
        info.st_uid != owner
        or mode & 0o022
        or mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
    ):
        raise PreflightError(f"{label} is writable by another principal")


def decode_mount_field(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def storage_snapshot(root: Path) -> tuple[str, str, str]:
    try:
        lines = Path("/proc/self/mountinfo").read_text(
            encoding="utf-8", errors="surrogateescape"
        ).splitlines()
    except OSError as exc:
        raise PreflightError("mount table is unavailable") from exc
    ancestors = []
    nested = []
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
            device = fields[2]
            mountpoint = Path(decode_mount_field(fields[4]))
            filesystem_type = fields[separator + 1].lower()
        except (IndexError, ValueError) as exc:
            raise PreflightError("mount table contains an invalid record") from exc
        if mountpoint == root or mountpoint.is_relative_to(root):
            nested.append(mountpoint)
        if root == mountpoint or root.is_relative_to(mountpoint):
            ancestors.append((mountpoint, filesystem_type, device))
    if nested:
        raise PreflightError("checkout contains a nested or direct mount")
    if not ancestors:
        raise PreflightError("checkout backing mount could not be identified")
    mountpoint, filesystem_type, device = max(
        ancestors, key=lambda item: len(item[0].parts)
    )
    if filesystem_type not in LOCAL_FILESYSTEM_TYPES:
        raise PreflightError("checkout backing filesystem is not an admitted local type")
    return os.fspath(mountpoint), filesystem_type, device


def require_safe_ancestors(path: Path, owner: int) -> None:
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if ancestor.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise PreflightError("checkout has an unsafe path ancestor")
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid not in {0, owner}:
            raise PreflightError("checkout ancestor is owned by another principal")
        if mode & stat.S_ISVTX:
            continue
        if mode & 0o022:
            raise PreflightError("checkout ancestor is group/world-writable")


def run() -> None:
    repository = Path(sys.argv[1])
    owner = int(sys.argv[2])
    if owner != os.geteuid():
        raise PreflightError("checkout owner identity changed")
    absolute = Path(os.path.abspath(repository))
    if absolute != Path(os.path.realpath(repository)) or not absolute.is_dir():
        raise PreflightError("checkout path is non-canonical or unsafe")
    require_safe_ancestors(absolute, owner)
    storage_before = storage_snapshot(absolute)
    checkout_device = absolute.lstat().st_dev
    filesystem = subprocess.run(
        ["/usr/bin/stat", "-f", "-c", "%T", os.fspath(absolute)],
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
        check=False,
    )
    if filesystem.returncode != 0:
        raise PreflightError("checkout filesystem could not be identified")
    if filesystem.stdout.strip().lower() not in LOCAL_FILESYSTEM_TYPES:
        raise PreflightError("checkout filesystem is not an admitted local type")

    git_directory = absolute / ".git"
    git_info = git_directory.lstat()
    if git_directory.is_symlink() or not stat.S_ISDIR(git_info.st_mode):
        raise PreflightError("checkout requires a self-contained .git directory")
    for current, directories, files in os.walk(
        git_directory, topdown=True, followlinks=False
    ):
        current_path = Path(current)
        current_info = current_path.lstat()
        if (
            current_path.is_symlink()
            or not stat.S_ISDIR(current_info.st_mode)
            or current_info.st_dev != checkout_device
        ):
            raise PreflightError("Git metadata contains an unsafe directory")
        require_private_owner(current_info, "Git metadata directory", owner)
        for name in directories + files:
            member = (current_path / name).lstat()
            if member.st_dev != checkout_device:
                raise PreflightError("Git metadata crosses a filesystem boundary")
            if stat.S_ISLNK(member.st_mode) or not (
                stat.S_ISDIR(member.st_mode) or stat.S_ISREG(member.st_mode)
            ):
                raise PreflightError("Git metadata contains an unsafe entry")
            require_private_owner(member, "Git metadata entry", owner)
            if stat.S_ISREG(member.st_mode) and member.st_nlink != 1:
                raise PreflightError("Git metadata contains a linked file")

    forbidden = (
        git_directory / "commondir",
        git_directory / "config.worktree",
        git_directory / "objects/info/alternates",
        git_directory / "objects/info/http-alternates",
    )
    if any(os.path.lexists(path) for path in forbidden):
        raise PreflightError("external Git object storage is forbidden")
    if any(path.name.endswith(".promisor") for path in git_directory.rglob("*")):
        raise PreflightError("partial-clone Git object storage is forbidden")

    if storage_snapshot(absolute) != storage_before:
        raise PreflightError("checkout mount identity changed during preflight")

    config = subprocess.run(
        [
            "/usr/bin/git",
            "--no-optional-locks",
            "-c",
            "core.commitGraph=false",
            "-c",
            "core.multiPackIndex=false",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "credential.helper=",
            "-c",
            "core.sshCommand=/bin/false",
            "-C",
            os.fspath(absolute),
            "config",
            "--local",
            "--no-includes",
            "--null",
            "--name-only",
            "--list",
        ],
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": "/",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "XDG_CONFIG_HOME": "/dev/null",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
    if config.returncode != 0:
        raise PreflightError("local Git configuration could not be inspected")
    keys = {
        value.decode("utf-8", "surrogateescape").casefold()
        for value in config.stdout.split(b"\0")
        if value
    }
    if any(
        key.startswith(("include.", "includeif."))
        or key.startswith("fsck.")
        or key in {"extensions.partialclone", "extensions.worktreeconfig"}
        or (key.startswith("remote.") and key.endswith(".promisor"))
        for key in keys
    ):
        raise PreflightError(
            "Git includes, fsck overrides, and partial-clone configuration are forbidden"
        )


try:
    run()
except (OSError, PreflightError, subprocess.SubprocessError) as exc:
    raise SystemExit(f"checkout preflight: {exc}")
PY
}
verify_exact_checkout() {
  local repository="$1" commit="$2"
  local verifier_repository="${3:-$repository}" verifier_commit="${4:-$commit}"
  local migration_root="${5:-}"
  local verifier_arguments=(--repository "$repository" --commit "$commit")
  [[ -z "$migration_root" ]] \
    || verifier_arguments+=(--allow-untracked-root "$migration_root")
  preflight_git_storage "$repository" || return 2
  safe_object_git -C "$repository" fsck \
    --strict --no-reflogs --no-cache --full "$commit" >/dev/null || return 2
  safe_object_git -C "$verifier_repository" cat-file blob \
    "$verifier_commit:bin/verify-exact-checkout.py" \
    | /usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
        "${verifier_arguments[@]}" || return 2
}
if [[ -d "$SCRIPT_DIR/.git" && ! -L "$SCRIPT_DIR/.git" ]]; then
  if verify_exact_checkout "$SCRIPT_DIR" "$RESTORE_COMMIT" >/dev/null 2>&1; then
    current=$(safe_object_git -C "$SCRIPT_DIR" rev-parse HEAD)
    if [[ "$current" == "$RESTORE_COMMIT" ]]; then
      REPO_DIR=$SCRIPT_DIR
    fi
  fi
fi

EXISTING_COMMIT=""
if [[ -z "$REPO_DIR" && ( -e "$REPO_TARGET" || -L "$REPO_TARGET" ) ]]; then
  [[ -d "$REPO_TARGET/.git" && ! -L "$REPO_TARGET" \
      && ! -L "$REPO_TARGET/.git" ]] \
    || die "repository target exists but is not a self-contained Git checkout: $REPO_TARGET"
  if verify_exact_checkout "$REPO_TARGET" "$RESTORE_COMMIT" >/dev/null 2>&1; then
    current=$(safe_object_git -C "$REPO_TARGET" rev-parse HEAD 2>/dev/null || true)
    if [[ "$current" == "$RESTORE_COMMIT" ]]; then
      REPO_DIR=$REPO_TARGET
    fi
  fi
  if [[ -z "$REPO_DIR" ]]; then
    preflight_git_storage "$REPO_TARGET" >/dev/null \
      || die "existing repository storage or metadata is unsafe: $REPO_TARGET"
    EXISTING_COMMIT=$(safe_object_git -C "$REPO_TARGET" rev-parse --verify HEAD 2>/dev/null || true)
    [[ "$EXISTING_COMMIT" =~ ^[0-9a-f]{40}$ \
        || "$EXISTING_COMMIT" =~ ^[0-9a-f]{64}$ ]] \
      || die "existing repository has no immutable current commit"
    [[ "$EXISTING_COMMIT" != "$RESTORE_COMMIT" ]] \
      || die "existing repository is not the exact protected commit tree"
  fi
fi

if [[ -z "$REPO_DIR" ]]; then
  validate_clone_parent "$REPO_TARGET" \
    || die "repository destination parent is unsafe"
  CLONE_STAGE_PREFIX="${REPO_TARGET}.stage-"
  CLONE_STAGE=$(/usr/bin/mktemp -d "${CLONE_STAGE_PREFIX}XXXXXXXX") \
    || die "cannot create private repository staging directory"
  /usr/bin/chmod 0700 "$CLONE_STAGE"
  safe_git init -q "$CLONE_STAGE"
  safe_git -C "$CLONE_STAGE" remote add origin "$REPO_URL"
  safe_git -C "$CLONE_STAGE" fetch -q --depth 1 origin "$RESTORE_COMMIT"
  safe_git -C "$CLONE_STAGE" checkout -q --detach FETCH_HEAD
  verify_exact_checkout "$CLONE_STAGE" "$RESTORE_COMMIT" >/dev/null \
    || die "fetched repository is not the exact protected commit tree"
  actual=$(safe_object_git -C "$CLONE_STAGE" rev-parse HEAD)
  [[ "$actual" == "$RESTORE_COMMIT" ]] || die "fetched repository commit does not match recovery set"
  validate_clone_parent "$REPO_TARGET" \
    || die "repository destination parent changed before activation"
  if [[ -n "$EXISTING_COMMIT" ]]; then
    # The verifier comes from the new authenticated commit.  The sole legacy
    # exception admits a structurally safe top-level external/ tree so older
    # releases can migrate away from in-repository third-party checkouts.  No
    # old checkout code or component content is executed.
    verify_exact_checkout \
      "$REPO_TARGET" "$EXISTING_COMMIT" \
      "$CLONE_STAGE" "$RESTORE_COMMIT" external >/dev/null \
      || die "existing repository is not an exact migratable commit tree"
    exchange_clone_atomically "$CLONE_STAGE" "$REPO_TARGET" \
      || die "cannot atomically upgrade authenticated repository checkout"
    verify_exact_checkout "$REPO_TARGET" "$RESTORE_COMMIT" >/dev/null \
      || die "activated repository failed exact post-exchange verification"
    # After RENAME_EXCHANGE, the staging pathname names the fully validated old
    # checkout.  It is no longer authoritative and is removed before handoff.
    /usr/bin/rm -rf -- "$CLONE_STAGE"
  else
    rename_clone_noreplace "$CLONE_STAGE" "$REPO_TARGET" \
      || die "cannot atomically install authenticated repository checkout"
  fi
  CLONE_STAGE=""
  CLONE_STAGE_PREFIX=""
  REPO_DIR=$REPO_TARGET
fi

# Deterministic synchronization for authenticated-tree race tests.  The pause
# is deliberately before generation construction: replacing any checkout
# helper, transitive import, or data file here must not affect the raw blobs
# selected by the already authenticated commit/tree object IDs.
if [[ -n "${CSR_STAGE0_TEST_PAUSE_BEFORE_HANDOFF:-}" ]]; then
  pause_marker="$CSR_STAGE0_TEST_PAUSE_BEFORE_HANDOFF"
  [[ "$pause_marker" == /tmp/* && ! -e "$pause_marker.ready" \
      && ! -L "$pause_marker.ready" ]] \
    || die "unsafe Stage-0 handoff test marker"
  (umask 077; set -o noclobber; : > "$pause_marker.ready") 2>/dev/null \
    || die "cannot publish Stage-0 handoff test marker"
  for _handoff_wait in {1..200}; do
    [[ -f "$pause_marker.continue" && ! -L "$pause_marker.continue" ]] && break
    /usr/bin/sleep 0.05
  done
  [[ -f "$pause_marker.continue" && ! -L "$pause_marker.continue" ]] \
    || die "Stage-0 handoff test synchronization timed out"
fi

REPOSITORY_TREE="$(safe_object_git -C "$REPO_DIR" \
  rev-parse --verify "$RESTORE_COMMIT^{tree}")" \
  || die "cannot resolve the authenticated repository tree"
[[ "$REPOSITORY_TREE" =~ ^[0-9a-f]{40}$ \
    || "$REPOSITORY_TREE" =~ ^[0-9a-f]{64}$ ]] \
  || die "authenticated repository tree identity is invalid"

# The materializer is itself selected from the authenticated Git object, then
# copied through stdin into a root-owned content-addressed helper path before
# either its emitter or privileged receiver is executed.  No checkout pathname
# becomes Python at the privilege boundary.
GENERATION_HELPER_OBJECT="bin/lib/repository_generation.py"
GENERATION_HELPER_SHA256="$(
  set -o pipefail
  safe_object_git -C "$REPO_DIR" cat-file blob \
    "$RESTORE_COMMIT:$GENERATION_HELPER_OBJECT" \
    | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1
)" || die "cannot digest the authenticated repository-generation helper"
[[ "$GENERATION_HELPER_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || die "authenticated repository-generation helper digest is invalid"
GENERATION_HELPER_ROOT="/usr/local/libexec/coding-system/install-helpers"
BOUND_GENERATION_HELPER="$(
  set -o pipefail
  safe_object_git -C "$REPO_DIR" cat-file blob \
    "$RESTORE_COMMIT:$GENERATION_HELPER_OBJECT" \
    | /usr/bin/timeout 30s /usr/bin/sudo -n -- \
      /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /bin/sh -eu -c '
        expected=$1
        case "$expected" in *[!0-9a-f]*) exit 2 ;; esac
        test "${#expected}" -eq 64 || exit 2
        root=/usr/local/libexec/coding-system/install-helpers
        target=$root/repository-generation-$expected.py

        require_root_dir() {
          test ! -L "$1" && test -d "$1" \
            && test "$(/usr/bin/stat -c %u:%g:%a -- "$1")" = 0:0:755
        }
        for directory in /usr /usr/local /usr/local/libexec; do
          require_root_dir "$directory" || exit 2
        done
        for directory in /usr/local/libexec/coding-system "$root"; do
          if test ! -e "$directory" && test ! -L "$directory"; then
            /usr/bin/mkdir -m 0755 -- "$directory"
          fi
          require_root_dir "$directory" || exit 2
        done
        verify_target() {
          test ! -L "$target" && test -f "$target" \
            && test "$(/usr/bin/stat -c %u:%g:%a:%h -- "$target")" = 0:0:444:1 \
            && test "$(/usr/bin/stat -c %s -- "$target")" -gt 0 \
            && test "$(/usr/bin/stat -c %s -- "$target")" -le 2097152 \
            && actual=$(/usr/bin/sha256sum -- "$target") \
            && test "${actual%% *}" = "$expected"
        }
        stage=$(/usr/bin/mktemp "$root/.repository-generation-$expected.XXXXXXXX")
        trap '\''/usr/bin/rm -f -- "$stage"'\'' 0 1 2 3 15
        /usr/bin/dd of="$stage" bs=2097153 count=1 iflag=fullblock status=none
        test "$(/usr/bin/stat -c %s -- "$stage")" -gt 0 \
          && test "$(/usr/bin/stat -c %s -- "$stage")" -le 2097152 \
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
      ' sh "$GENERATION_HELPER_SHA256"
)" || die "cannot bind the authenticated repository-generation helper"
[[ "$BOUND_GENERATION_HELPER" == \
    "$GENERATION_HELPER_ROOT/repository-generation-$GENERATION_HELPER_SHA256.py" ]] \
  || die "root-owned repository-generation helper path is invalid"

REPOSITORY_GENERATION="$(
  set -o pipefail
  /usr/bin/timeout 180s /usr/bin/env -i \
    PATH=/usr/bin:/bin LANG=C LC_ALL=C HOME=/ \
    /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
      "$BOUND_GENERATION_HELPER" emit \
      --repository "$REPO_DIR" --commit "$RESTORE_COMMIT" \
      --tree "$REPOSITORY_TREE" \
    | /usr/bin/timeout 180s /usr/bin/sudo -n -- \
      /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C HOME=/ \
      /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
        "$BOUND_GENERATION_HELPER" publish \
        --commit "$RESTORE_COMMIT" --tree "$REPOSITORY_TREE"
)" || die "cannot publish the authenticated repository generation"
EXPECTED_GENERATION="/usr/local/libexec/coding-system/repository-generations/${RESTORE_COMMIT}-${REPOSITORY_TREE}"
[[ "$REPOSITORY_GENERATION" == "$EXPECTED_GENERATION" ]] \
  || die "published repository-generation path differs from its identity"
/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C HOME=/ \
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$BOUND_GENERATION_HELPER" verify \
    --commit "$RESTORE_COMMIT" --tree "$REPOSITORY_TREE" \
    --path "$REPOSITORY_GENERATION" >/dev/null \
  || die "published repository generation failed exact verification"

REPO_DIR="$REPOSITORY_GENERATION"
[[ -f "$REPO_DIR/Makefile" && -x "$REPO_DIR/bin/doctor.sh" ]] || \
  die "authenticated repository generation lacks restoration entry points"
note "handing off to the authenticated restore entry point"
RESTORE_USER="$(/usr/bin/id -un)"
RESTORE_UID="$(/usr/bin/id -u)"
RESTORE_ENV=(
  HOME="$HOME" USER="$RESTORE_USER" LOGNAME="$RESTORE_USER"
  PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8
  TERM="${TERM:-dumb}"
  RECOVERY_SET="$RECOVERY_DIR"
  CSR_RESTORE_INBOX="$INBOX"
  CSR_STAGE0_RECOVERY_SNAPSHOT="$RECOVERY_SNAPSHOT"
  CSR_STAGE0_VERIFIED_COMMIT="$RESTORE_COMMIT"
  CSR_STAGE0_REPOSITORY_TREE="$REPOSITORY_TREE"
  CSR_STAGE0_REPOSITORY_GENERATION="$REPOSITORY_GENERATION"
)
[[ -z "$REQUESTED_PHASE" ]] || RESTORE_ENV+=(PHASE="$REQUESTED_PHASE")
[[ -z "${CSR_ESCROW_SHARE_1_FILE:-}" ]] \
  || RESTORE_ENV+=(CSR_ESCROW_SHARE_1_FILE="$CSR_ESCROW_SHARE_1_FILE")
[[ -z "${CSR_ESCROW_SHARE_2_FILE:-}" ]] \
  || RESTORE_ENV+=(CSR_ESCROW_SHARE_2_FILE="$CSR_ESCROW_SHARE_2_FILE")
RESTORE_RUNTIME_DIR="/run/user/$RESTORE_UID"
if [[ -d "$RESTORE_RUNTIME_DIR" && ! -L "$RESTORE_RUNTIME_DIR" \
    && "$(/usr/bin/stat -c '%u:%a' "$RESTORE_RUNTIME_DIR" 2>/dev/null)" == "$RESTORE_UID:700" ]]; then
  RESTORE_ENV+=(
    XDG_RUNTIME_DIR="$RESTORE_RUNTIME_DIR"
    DBUS_SESSION_BUS_ADDRESS="unix:path=$RESTORE_RUNTIME_DIR/bus"
  )
fi
/usr/bin/env -i "${RESTORE_ENV[@]}" \
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
    "$REPO_DIR" "$RESTORE_COMMIT" <<'PY' \
  || die "repository restore target failed"
import fcntl
import os
from pathlib import Path
import stat
import sys


class HandoffError(RuntimeError):
    pass


repository = Path(sys.argv[1])
commit = sys.argv[2]
entrypoint = repository / "bin/restore.sh"
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
        or before.st_size > 2 * 1024 * 1024
    ):
        raise HandoffError("restore entry point has unsafe metadata")
    source = bytearray()
    while len(source) <= 2 * 1024 * 1024:
        block = os.read(source_fd, min(64 * 1024, 2 * 1024 * 1024 + 1 - len(source)))
        if not block:
            break
        source.extend(block)
    after = os.fstat(source_fd)
    if len(source) > 2 * 1024 * 1024 or (
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
        raise HandoffError("restore entry point changed while it was opened")
    path_info = entrypoint.lstat()
    if (path_info.st_dev, path_info.st_ino) != (after.st_dev, after.st_ino):
        raise HandoffError("restore entry point pathname changed after verification")

    sealed_fd = os.memfd_create(
        "csr-authenticated-restore",
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
    environment["CSR_RESTORE_REPO_ROOT"] = os.fspath(repository)
    os.execve(
        "/usr/bin/bash",
        ["/usr/bin/bash", "-p", f"/proc/self/fd/{sealed_fd}"],
        environment,
    )
except (OSError, HandoffError) as exc:
    raise SystemExit(f"restore-ubuntu: authenticated handoff failed: {exc}")
finally:
    if source_fd >= 0:
        os.close(source_fd)
    if sealed_fd >= 0:
        os.close(sealed_fd)
PY
note "repository restore completed"
fi
