#!/usr/bin/bash -p
# Recovery escrow entry point. New recovery sets use immutable 2-of-4
# generations and file-only recovery. The historical ZIP passphrase operations
# remain below as explicitly labelled compatibility commands.
#
# Splits ~/.config/coding-system/zip-password.txt into a 2-of-4 Shamir set
# (bin/lib/shamir.py) and distributes one share per independent location:
#   local   ~/.config/coding-system/passphrase-share-local.txt
#   dropbox <CSR_RCLONE_DEST>/escrow/passphrase-share-dropbox.txt
#   gdrive  <CSR_ESCROW_GDRIVE>/escrow/passphrase-share-gdrive.txt
#   github  private repo <CSR_ESCROW_GH_REPO> : generations/<id>/...
# Any single location reveals nothing; any TWO reconstruct the passphrase.
# A local manifest records sha256(passphrase) so rotation auto-re-escrows.
#
# New usage:
#   escrow-passphrase.sh create-generation GENERATION_DIR MASTER_KEY_FILE
#   escrow-passphrase.sh create-and-publish GENERATION_DIR MASTER_KEY_FILE
#   escrow-passphrase.sh publish-generation GENERATION_DIR
#   escrow-passphrase.sh verify-distributed GENERATION_DIR
#   escrow-passphrase.sh fetch-share GENERATION_MANIFEST SHARE_INDEX OUTPUT_FILE
#   escrow-passphrase.sh validate-generation GENERATION_DIR
#   escrow-passphrase.sh recover-to GENERATION_MANIFEST SHARE1 SHARE2 MASTER_KEY_FILE
#
# Legacy aliases retained for old ZIPs: ensure, check, recover.
set -uo pipefail
umask 077
export PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT \
  LD_PRELOAD LD_LIBRARY_PATH GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM
IFS=$' \t\n'

REPO="$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
CFG="$HOME/.config/coding-system"
PWFILE="$CFG/zip-password.txt"
LOCAL_SHARE="$CFG/passphrase-share-local.txt"
MANIFEST="$CFG/escrow-manifest.json"
SHAMIR="$REPO/bin/lib/shamir.py"
DROPBOX_DEST="${CSR_RCLONE_DEST:-}"
GDRIVE_DEST="${CSR_ESCROW_GDRIVE:-}"
GH_REPO="${CSR_ESCROW_GH_REPO:-}"
MODE="${1:-ensure}"

case "$MODE" in
  -h|--help|help)
    /usr/bin/sed -n '9,24p' "$0"
    exit 0
    ;;
esac

case "$MODE" in
  create-generation)
    [ "$#" -eq 3 ] || {
      echo "usage: $0 create-generation GENERATION_DIR MASTER_KEY_FILE" >&2
      exit 2
    }
    exec python3 "$REPO/bin/lib/recovery_tool.py" create-escrow \
      --output-dir "$2" --master-key-out "$3"
    ;;
  validate-generation)
    [ "$#" -eq 2 ] || {
      echo "usage: $0 validate-generation GENERATION_DIR" >&2
      exit 2
    }
    exec python3 "$REPO/bin/lib/recovery_tool.py" validate-escrow \
      --manifest "$2/escrow-generation.json" --share-dir "$2"
    ;;
  recover-to)
    [ "$#" -eq 5 ] || {
      echo "usage: $0 recover-to GENERATION_MANIFEST SHARE1 SHARE2 MASTER_KEY_FILE" >&2
      exit 2
    }
    exec python3 "$REPO/bin/lib/recovery_tool.py" recover-escrow \
      --manifest "$2" --share-file "$3" --share-file "$4" \
      --master-key-out "$5"
    ;;
esac

pw_hash() { sha256sum "$PWFILE" | awk '{print $1}'; }

escrow_location() { # escrow_location NAME: from the environment, else the owner settings file
  local value="${!1:-}"
  [[ -n "$value" ]] || value="$(/usr/bin/python3 -I -B "$REPO/bin/lib/owner_settings.py" get \
    --key "$1" --path "$HOME/.secrets.env")" || return 2
  [[ -n "$value" ]] || { echo "escrow: set $1 (an owner setting)" >&2; return 2; }
  printf '%s\n' "$value"
}

require_escrow_locations() {
  DROPBOX_DEST="$(escrow_location CSR_RCLONE_DEST)" \
    && GDRIVE_DEST="$(escrow_location CSR_ESCROW_GDRIVE)" \
    && GH_REPO="$(escrow_location CSR_ESCROW_GH_REPO)"
}

validate_github_repo_name() {
  [[ "$GH_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]
}

require_private_github_repo() { # require_private_github_repo <allow-create:0|1>
  local allow_create="${1:-0}" metadata full_name private extra
  validate_github_repo_name || {
    echo "github escrow: invalid exact owner/repository name" >&2
    return 2
  }
  metadata=$(gh api "repos/$GH_REPO" --jq '.full_name + "\t" + (.private|tostring)' 2>/dev/null) || {
    if [[ "$allow_create" != "1" ]]; then
      echo "github escrow: exact repository does not exist; set CSR_ESCROW_ALLOW_GITHUB_REPO_CREATE=1 for an intentional private-repo creation" >&2
      return 2
    fi
    gh repo create "$GH_REPO" --private \
      -d "Shamir escrow shares (threshold 2; each share alone reveals nothing)" \
      >/dev/null || {
        echo "github escrow: explicit private repository creation failed" >&2
        return 2
      }
    metadata=$(gh api "repos/$GH_REPO" --jq '.full_name + "\t" + (.private|tostring)' 2>/dev/null) || {
      echo "github escrow: cannot verify the repository created by GitHub" >&2
      return 2
    }
  }
  IFS=$'\t' read -r full_name private extra <<<"$metadata"
  if [[ "$full_name" != "$GH_REPO" || "$private" != "true" || -n "${extra:-}" ]]; then
    echo "github escrow: refusing upload unless the exact existing repository is private" >&2
    return 2
  fi
}

new_escrow_die() {
  echo "escrow distribution: $*" >&2
  return 2
}

require_new_escrow_tools() {
  local command_name
  for command_name in python3 rclone gh stat mktemp id sha256sum cut cmp; do
    command -v "$command_name" >/dev/null 2>&1 \
      || new_escrow_die "required command is unavailable: $command_name" \
      || return 2
  done
}

secure_tmpfs_directory() {
  local candidate filesystem temporary
  local -a candidates=()
  [[ -n "${CSR_ESCROW_TMPFS_ROOT:-}" ]] && candidates+=("$CSR_ESCROW_TMPFS_ROOT")
  [[ -n "${XDG_RUNTIME_DIR:-}" ]] && candidates+=("$XDG_RUNTIME_DIR")
  candidates+=("/run/user/$(id -u)" "/dev/shm")
  for candidate in "${candidates[@]}"; do
    [[ -d "$candidate" && ! -L "$candidate" ]] || continue
    filesystem=$(stat -f -c '%T' -- "$candidate" 2>/dev/null) || continue
    [[ "$filesystem" == "tmpfs" ]] || continue
    temporary=$(mktemp -d "$candidate/csr-escrow.XXXXXXXX") || continue
    chmod 700 "$temporary" || { rmdir "$temporary" 2>/dev/null || true; continue; }
    if [[ ! -L "$temporary" \
      && "$(stat -c '%u' -- "$temporary" 2>/dev/null)" == "$(id -u)" \
      && "$(stat -c '%a' -- "$temporary" 2>/dev/null)" == "700" ]]; then
      printf '%s\n' "$temporary"
      return 0
    fi
    rmdir "$temporary" 2>/dev/null || true
  done
  new_escrow_die "no owner-only tmpfs staging root is available"
}

snapshot_generation_files() { # snapshot_generation_files <source-dir> <destination-dir> <name>...
  local source_dir="$1" destination_dir="$2"
  shift 2
  python3 - "$source_dir" "$destination_dir" "$@" <<'PY'
import os
import stat
import sys

source, destination, *names = sys.argv[1:]
allowed = {
    "escrow-generation.json",
    "share-01.txt",
    "share-02.txt",
    "share-03.txt",
    "share-04.txt",
}
if not names or any(name not in allowed for name in names) or len(set(names)) != len(names):
    raise SystemExit("escrow distribution: invalid generation snapshot inventory")

directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
source_fd = os.open(source, directory_flags)
destination_fd = os.open(destination, directory_flags)
try:
    source_info = os.fstat(source_fd)
    if source_info.st_uid != os.getuid() or stat.S_IMODE(source_info.st_mode) & 0o077:
        raise SystemExit("escrow distribution: generation directory must be owner-only")
    for name in names:
        input_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        input_fd = os.open(name, input_flags, dir_fd=source_fd)
        try:
            before = os.fstat(input_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
                raise SystemExit("escrow distribution: generation input is not an owner regular file")
            if name.startswith("share-") and stat.S_IMODE(before.st_mode) & 0o077:
                raise SystemExit("escrow distribution: generation share permissions are too broad")
            if before.st_size > 1024 * 1024:
                raise SystemExit("escrow distribution: generation input exceeds the size bound")
            chunks = []
            total = 0
            while True:
                chunk = os.read(input_fd, min(65536, 1024 * 1024 + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > 1024 * 1024:
                    raise SystemExit("escrow distribution: generation input exceeds the size bound")
            after = os.fstat(input_fd)
            stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
                raise SystemExit("escrow distribution: generation input changed while reading")
            payload = b"".join(chunks)
        finally:
            os.close(input_fd)
        output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        output_fd = os.open(name, output_flags, 0o600, dir_fd=destination_fd)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(output_fd, view)
                view = view[written:]
            os.fsync(output_fd)
        finally:
            os.close(output_fd)
    os.fsync(destination_fd)
finally:
    os.close(destination_fd)
    os.close(source_fd)
PY
}

escrow_generation_id() { # escrow_generation_id <manifest>
  PYTHONPATH="$REPO/bin/lib" python3 - "$1" <<'PY'
import sys
from recovery_tool import load_escrow_manifest

manifest = load_escrow_manifest(sys.argv[1])
if any(record["file"] != f"share-{record['index']:02d}.txt" for record in manifest["share_records"]):
    raise SystemExit("escrow distribution: manifest share filenames do not match their indexes")
print(manifest["generation_id"])
PY
}

validate_one_share() { # validate_one_share <manifest> <index> <share-file>
  PYTHONPATH="$REPO/bin/lib" python3 - "$1" "$2" "$3" <<'PY'
import sys
from pathlib import Path
from recovery_tool import _read_share, load_escrow_manifest

manifest = load_escrow_manifest(sys.argv[1])
index = int(sys.argv[2])
if index not in range(1, 5):
    raise SystemExit("escrow distribution: share index must be 1, 2, 3, or 4")
line = _read_share(Path(sys.argv[3]), manifest["share_records"])
if int(line.split(":", 2)[1]) != index:
    raise SystemExit("escrow distribution: fetched share has the wrong index")
PY
}

write_protected_copy() { # write_protected_copy <source> <exclusive-output>
  PYTHONPATH="$REPO/bin/lib" python3 - "$1" "$2" <<'PY'
import sys
from pathlib import Path
from recovery_tool import RecoveryError, _atomic_write, _read_regular_bytes

source, output = sys.argv[1:]
try:
    payload = _read_regular_bytes(Path(source), max_bytes=8192, secret=True)
    _atomic_write(Path(output), payload, 0o600)
except RecoveryError as error:
    raise SystemExit("escrow distribution: " + str(error)) from error
PY
}

rclone_object_exists() { # rclone_object_exists <remote-object>
  rclone lsjson "$1" --stat --files-only >/dev/null 2>&1
}

require_rclone_object_absent() { # require_rclone_object_absent <remote-object>
  if rclone_object_exists "$1"; then
    new_escrow_die "refusing to overwrite an existing immutable remote object: $1"
    return 2
  fi
}

rclone_put_immutable() { # rclone_put_immutable <local-file> <remote-object>
  require_rclone_object_absent "$2" || return 2
  rclone copyto --immutable --no-traverse "$1" "$2" >/dev/null \
    || new_escrow_die "immutable rclone upload failed: $2"
}

rclone_read_to() { # rclone_read_to <remote-object> <protected-local-file>
  [[ ! -e "$2" && ! -L "$2" ]] \
    || { new_escrow_die "refusing to overwrite a readback file"; return 2; }
  if ! rclone copyto "$1" "$2" >/dev/null; then
    rm -f -- "$2"
    new_escrow_die "rclone readback failed: $1"
    return 2
  fi
  chmod 600 "$2" || return 2
}

github_object_exists() { # github_object_exists <path>
  gh api "repos/$GH_REPO/contents/$1" --jq .sha >/dev/null 2>&1
}

require_github_object_absent() { # require_github_object_absent <path>
  if github_object_exists "$1"; then
    new_escrow_die "refusing to overwrite an existing immutable GitHub object: $1"
    return 2
  fi
}

github_put_immutable() { # github_put_immutable <path> <local-file> <tmpfs-dir>
  local path="$1" file="$2" temporary="$3" payload_file
  require_github_object_absent "$path" || return 2
  payload_file="$temporary/github-upload-$(printf '%s' "$path" | sha256sum | cut -d' ' -f1).json"
  python3 - "$path" "$file" "$payload_file" <<'PY'
import base64
import json
import os
import sys

path, source, output = sys.argv[1:]
with open(source, "rb") as stream:
    content = stream.read(1024 * 1024 + 1)
if len(content) > 1024 * 1024:
    raise SystemExit("escrow distribution: GitHub object exceeds the size bound")
payload = {
    "message": "escrow: publish immutable " + path,
    "content": base64.b64encode(content).decode("ascii"),
}
descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("ascii")
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  if ! gh api -X PUT "repos/$GH_REPO/contents/$path" --input "$payload_file" --silent; then
    new_escrow_die "immutable GitHub upload failed: $path"
    return 2
  fi
  rm -f -- "$payload_file"
}

github_read_to() { # github_read_to <path> <protected-local-file>
  [[ ! -e "$2" && ! -L "$2" ]] \
    || { new_escrow_die "refusing to overwrite a GitHub readback file"; return 2; }
  ( umask 077; : > "$2" ) || return 2
  if ! gh api "repos/$GH_REPO/contents/$1" \
      -H 'Accept: application/vnd.github.raw+json' >"$2"; then
    rm -f -- "$2"
    new_escrow_die "GitHub readback failed: $1"
    return 2
  fi
  chmod 600 "$2" || return 2
}

copy_and_compare_manifest() { # copy_and_compare_manifest <expected> <actual>
  cmp -s -- "$1" "$2" \
    || { new_escrow_die "remote escrow-generation.json differs from the validated generation"; return 2; }
}

verify_distributed_generation() ( # verify_distributed_generation <generation-dir>
  local generation_dir="$1" manifest generation_id prefix temporary
  local dropbox_manifest gdrive_manifest github_manifest
  manifest="$generation_dir/escrow-generation.json"
  temporary=$(secure_tmpfs_directory) || return 2
  trap 'rm -rf -- "$temporary"' EXIT
  snapshot_generation_files "$generation_dir" "$temporary" \
    escrow-generation.json share-01.txt || return 2
  generation_id=$(escrow_generation_id "$temporary/escrow-generation.json") || return 2
  prefix="generations/$generation_id"
  require_private_github_repo 0 || return 2

  dropbox_manifest="$temporary/dropbox-escrow-generation.json"
  gdrive_manifest="$temporary/gdrive-escrow-generation.json"
  github_manifest="$temporary/github-escrow-generation.json"
  rclone_read_to "${DROPBOX_DEST%/}/$prefix/escrow-generation.json" "$dropbox_manifest" || return 2
  rclone_read_to "${GDRIVE_DEST%/}/$prefix/escrow-generation.json" "$gdrive_manifest" || return 2
  github_read_to "$prefix/escrow-generation.json" "$github_manifest" || return 2
  copy_and_compare_manifest "$temporary/escrow-generation.json" "$dropbox_manifest" || return 2
  copy_and_compare_manifest "$temporary/escrow-generation.json" "$gdrive_manifest" || return 2
  copy_and_compare_manifest "$temporary/escrow-generation.json" "$github_manifest" || return 2

  rclone_read_to "${DROPBOX_DEST%/}/$prefix/share-02.txt" "$temporary/share-02.txt" || return 2
  rclone_read_to "${GDRIVE_DEST%/}/$prefix/share-03.txt" "$temporary/share-03.txt" || return 2
  github_read_to "$prefix/share-04.txt" "$temporary/share-04.txt" || return 2
  python3 "$REPO/bin/lib/recovery_tool.py" validate-escrow \
    --manifest "$temporary/escrow-generation.json" --share-dir "$temporary" \
    >/dev/null || return 2
  echo "escrow distribution verified: $generation_id (four share hashes; all six pairs)"
  rm -rf -- "$temporary"
  trap - EXIT
)

retire_published_source_shares() { # retire_published_source_shares <generation-dir> <validated-snapshot>
  python3 - "$1" "$2" <<'PY'
import hashlib
import os
import stat
import sys

source, snapshot = sys.argv[1:]
directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
source_fd = os.open(source, directory_flags)
snapshot_fd = os.open(snapshot, directory_flags)

def digest_file(directory_fd, name):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise SystemExit("escrow distribution: refusing to retire an unsafe source share")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                return info, digest.digest()
            digest.update(chunk)
    finally:
        os.close(descriptor)

try:
    for name in ("share-02.txt", "share-03.txt", "share-04.txt"):
        source_info, source_digest = digest_file(source_fd, name)
        _, snapshot_digest = digest_file(snapshot_fd, name)
        current = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (source_info.st_dev, source_info.st_ino):
            raise SystemExit("escrow distribution: source share changed before retirement")
        if source_digest != snapshot_digest:
            raise SystemExit("escrow distribution: source share differs from the published snapshot")
    for name in ("share-02.txt", "share-03.txt", "share-04.txt"):
        os.unlink(name, dir_fd=source_fd)
    os.fsync(source_fd)
finally:
    os.close(snapshot_fd)
    os.close(source_fd)
PY
}

select_current_generation() { # select_current_generation <generation-dir>
  local generation_dir="$1" escrow_root current temporary basename
  escrow_root="$CFG/escrow"
  generation_dir=$(cd -P -- "$generation_dir" && pwd) || return 2
  if [[ "$(dirname -- "$generation_dir")" != "$escrow_root" ]]; then
    echo "escrow current generation not selected (generation is outside $escrow_root)"
    return 0
  fi
  [[ -d "$escrow_root" && ! -L "$escrow_root" ]] \
    || { new_escrow_die "escrow root is missing or unsafe"; return 2; }
  escrow_root=$(cd -P -- "$escrow_root" && pwd) || return 2
  [[ "$(dirname -- "$generation_dir")" == "$escrow_root" ]] \
    || { new_escrow_die "current generation must be a direct child of $escrow_root"; return 2; }
  [[ ! -L "$generation_dir" \
      && "$(stat -c '%u:%a' -- "$generation_dir")" == "$(id -u):700" ]] \
    || { new_escrow_die "current generation directory ownership/mode is unsafe"; return 2; }
  basename=$(basename -- "$generation_dir")
  current="$escrow_root/current"
  if [[ -e "$current" || -L "$current" ]]; then
    [[ -L "$current" ]] \
      || { new_escrow_die "refusing to replace a non-symlink current generation"; return 2; }
  fi
  temporary="$escrow_root/.current-$$-$RANDOM"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] || return 2
  ln -s -- "$basename" "$temporary"
  mv -Tf -- "$temporary" "$current"
  echo "escrow current generation selected: $basename"
}

publish_generation() ( # publish_generation <generation-dir>
  local generation_dir="$1" generation_id prefix temporary
  require_new_escrow_tools || return 2
  temporary=$(secure_tmpfs_directory) || return 2
  trap 'rm -rf -- "$temporary"' EXIT
  snapshot_generation_files "$generation_dir" "$temporary" \
    escrow-generation.json share-01.txt share-02.txt share-03.txt share-04.txt || return 2
  python3 "$REPO/bin/lib/recovery_tool.py" validate-escrow \
    --manifest "$temporary/escrow-generation.json" --share-dir "$temporary" \
    >/dev/null || return 2
  generation_id=$(escrow_generation_id "$temporary/escrow-generation.json") || return 2
  prefix="generations/$generation_id"
  require_private_github_repo 0 || return 2

  require_rclone_object_absent "${DROPBOX_DEST%/}/$prefix/share-02.txt" || return 2
  require_rclone_object_absent "${DROPBOX_DEST%/}/$prefix/escrow-generation.json" || return 2
  require_rclone_object_absent "${GDRIVE_DEST%/}/$prefix/share-03.txt" || return 2
  require_rclone_object_absent "${GDRIVE_DEST%/}/$prefix/escrow-generation.json" || return 2
  require_github_object_absent "$prefix/share-04.txt" || return 2
  require_github_object_absent "$prefix/escrow-generation.json" || return 2

  rclone_put_immutable "$temporary/share-02.txt" \
    "${DROPBOX_DEST%/}/$prefix/share-02.txt" || return 2
  rclone_put_immutable "$temporary/escrow-generation.json" \
    "${DROPBOX_DEST%/}/$prefix/escrow-generation.json" || return 2
  rclone_put_immutable "$temporary/share-03.txt" \
    "${GDRIVE_DEST%/}/$prefix/share-03.txt" || return 2
  rclone_put_immutable "$temporary/escrow-generation.json" \
    "${GDRIVE_DEST%/}/$prefix/escrow-generation.json" || return 2
  github_put_immutable "$prefix/share-04.txt" "$temporary/share-04.txt" "$temporary" || return 2
  github_put_immutable "$prefix/escrow-generation.json" \
    "$temporary/escrow-generation.json" "$temporary" || return 2

  verify_distributed_generation "$generation_dir" || return 2
  retire_published_source_shares "$generation_dir" "$temporary" || return 2
  select_current_generation "$generation_dir" || return 2
  echo "escrow generation published immutably: $generation_id"
  rm -rf -- "$temporary"
  trap - EXIT
)

fetch_distributed_share() ( # fetch_distributed_share <manifest> <index> <exclusive-output>
  local manifest="$1" index="$2" output="$3" generation_dir generation_id prefix temporary source
  require_new_escrow_tools || return 2
  [[ "$index" =~ ^[1-4]$ ]] || { new_escrow_die "share index must be 1, 2, 3, or 4"; return 2; }
  [[ "$(basename -- "$manifest")" == "escrow-generation.json" && ! -L "$manifest" ]] \
    || { new_escrow_die "manifest must be a regular escrow-generation.json"; return 2; }
  generation_dir=$(cd -P -- "$(dirname -- "$manifest")" 2>/dev/null && pwd) \
    || { new_escrow_die "generation manifest directory is unavailable"; return 2; }
  temporary=$(secure_tmpfs_directory) || return 2
  trap 'rm -rf -- "$temporary"' EXIT
  snapshot_generation_files "$generation_dir" "$temporary" escrow-generation.json || return 2
  generation_id=$(escrow_generation_id "$temporary/escrow-generation.json") || return 2
  prefix="generations/$generation_id"
  source="$temporary/share-0$index.txt"
  case "$index" in
    1) snapshot_generation_files "$generation_dir" "$temporary" share-01.txt || return 2 ;;
    2)
      DROPBOX_DEST="$(escrow_location CSR_RCLONE_DEST)" || return 2
      rclone_read_to "${DROPBOX_DEST%/}/$prefix/share-02.txt" "$source" || return 2
      ;;
    3)
      GDRIVE_DEST="$(escrow_location CSR_ESCROW_GDRIVE)" || return 2
      rclone_read_to "${GDRIVE_DEST%/}/$prefix/share-03.txt" "$source" || return 2
      ;;
    4)
      GH_REPO="$(escrow_location CSR_ESCROW_GH_REPO)" || return 2
      require_private_github_repo 0 || return 2
      github_read_to "$prefix/share-04.txt" "$source" || return 2
      ;;
  esac
  validate_one_share "$temporary/escrow-generation.json" "$index" "$source" || return 2
  write_protected_copy "$source" "$output" || return 2
  echo "escrow share $index written to protected file: $output"
  rm -rf -- "$temporary"
  trap - EXIT
)

gh_put() { # gh_put <path-in-repo> <local-file>
  local path="$1" file="$2" sha
  require_private_github_repo 0 || return 2
  sha=$(gh api "repos/$GH_REPO/contents/$path" --jq .sha 2>/dev/null || true)
  if [[ -n "$sha" && "${CSR_ESCROW_ALLOW_GITHUB_OVERWRITE:-0}" != "1" ]]; then
    echo "github escrow: refusing to overwrite existing generation object: $path" >&2
    return 2
  fi
  python3 - "$path" "$file" "$sha" <<'PY' \
    | gh api -X PUT "repos/$GH_REPO/contents/$path" --input - >/dev/null
import base64, json, pathlib, sys
path, filename, sha = sys.argv[1:]
payload = {
    "message": "escrow: update " + path,
    "content": base64.b64encode(pathlib.Path(filename).read_bytes()).decode("ascii"),
}
if sha:
    payload["sha"] = sha
json.dump(payload, sys.stdout)
PY
}

case "$MODE" in
  create-and-publish|publish-generation|verify-distributed|check|ensure)
    require_escrow_locations || exit 2
    ;;
esac

case "$MODE" in
  create-and-publish)
    [ "$#" -eq 3 ] || {
      echo "usage: $0 create-and-publish GENERATION_DIR MASTER_KEY_FILE" >&2
      exit 2
    }
    (
      set -e
      umask 077
      require_new_escrow_tools
      python3 "$REPO/bin/lib/recovery_tool.py" create-escrow \
        --output-dir "$2" --master-key-out "$3"
      publish_generation "$2"
    )
    exit $?
    ;;
  publish-generation)
    [ "$#" -eq 2 ] || {
      echo "usage: $0 publish-generation GENERATION_DIR" >&2
      exit 2
    }
    ( set -e; umask 077; publish_generation "$2" )
    exit $?
    ;;
  verify-distributed)
    [ "$#" -eq 2 ] || {
      echo "usage: $0 verify-distributed GENERATION_DIR" >&2
      exit 2
    }
    ( set -e; umask 077; require_new_escrow_tools; verify_distributed_generation "$2" )
    exit $?
    ;;
  fetch-share)
    [ "$#" -eq 4 ] || {
      echo "usage: $0 fetch-share GENERATION_MANIFEST SHARE_INDEX OUTPUT_FILE" >&2
      exit 2
    }
    ( set -e; umask 077; fetch_distributed_share "$2" "$3" "$4" )
    exit $?
    ;;
esac

case "$MODE" in
  recover)
    echo "WARNING: legacy ZIP recovery; use recover-to for recovery sets" >&2
    shift
    [ $# -eq 3 ] || {
      echo "usage: $0 recover SHARE_FILE SHARE_FILE OUTPUT_FILE" >&2
      exit 2
    }
    exec python3 "$REPO/bin/lib/recovery_tool.py" recover-legacy \
      --share-file "$1" --share-file "$2" --output "$3"
    ;;

  check)
    echo "WARNING: checking legacy mutable ZIP escrow; recovery sets require validate-generation" >&2
    rc=0
    [ -s "$PWFILE" ] || { echo "check: passphrase file missing"; exit 1; }
    [ -s "$LOCAL_SHARE" ] || { echo "check: local share missing"; rc=1; }
    if [ -s "$MANIFEST" ]; then
      grep -q "\"sha256\": \"$(pw_hash)\"" "$MANIFEST" || { echo "check: passphrase rotated since escrow"; rc=1; }
    else
      echo "check: manifest missing"; rc=1
    fi
    rclone lsf "$DROPBOX_DEST/escrow/passphrase-share-dropbox.txt" >/dev/null 2>&1 || { echo "check: dropbox share missing"; rc=1; }
    github_path=$(python3 - "$MANIFEST" <<'PY'
import json, pathlib, re, sys
path = "passphrase-share-github.txt"
try:
    value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    path = value.get("github_path", path)
except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
    pass
if not isinstance(path, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", path) or ".." in path.split("/"):
    raise SystemExit(2)
print(path)
PY
    ) || { echo "check: invalid github share path"; rc=1; github_path=""; }
    if [[ -n "$github_path" ]]; then
      require_private_github_repo 0 >/dev/null 2>&1 \
        && gh api "repos/$GH_REPO/contents/$github_path" --jq .sha >/dev/null 2>&1 \
        || { echo "check: private github share missing or repository is unsafe"; rc=1; }
    fi
    if grep -q '"gdrive"' "$MANIFEST" 2>/dev/null; then
      rclone lsf "$GDRIVE_DEST/escrow/passphrase-share-gdrive.txt" >/dev/null 2>&1 || { echo "check: gdrive share missing"; rc=1; }
      n_loc=4
    else
      n_loc=3
      timeout 20 rclone lsf "$GDRIVE_DEST" --max-depth 1 >/dev/null 2>&1 &&         echo "check: NOTE gdrive is reachable but not escrowed yet - next ensure upgrades to 2-of-4"
    fi
    [ "$rc" -eq 0 ] && echo "escrow check: ok (2-of-$n_loc across local+dropbox+github$( [ "$n_loc" -eq 4 ] && echo '+gdrive'))"
    exit "$rc" ;;

  ensure)
    echo "WARNING: maintaining legacy mutable ZIP escrow; new backups require create-generation" >&2
    [ -s "$PWFILE" ] || { echo "ensure: passphrase file missing: $PWFILE" >&2; exit 2; }
    if bash "$0" check >/dev/null 2>&1; then
      echo "escrow: current (shares present per manifest, hash matches)"
      exit 0
    fi
    require_private_github_repo "${CSR_ESCROW_ALLOW_GITHUB_REPO_CREATE:-0}" || exit 2
    # Location set is dynamic: local + dropbox + github always; gdrive joins
    # automatically once its rclone token is reconnected (2-of-3 -> 2-of-4).
    HAVE_GDRIVE=0
    timeout 20 rclone lsf "$GDRIVE_DEST" --max-depth 1 >/dev/null 2>&1 && HAVE_GDRIVE=1
    N=$((3 + HAVE_GDRIVE))
    echo "escrow: (re)distributing 2-of-$N shares"
    umask 077
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    generation_id="${CSR_LEGACY_ESCROW_GENERATION_ID:-legacy-$(date -u +%Y%m%dt%H%M%Sz)-$(tr -d '-' </proc/sys/kernel/random/uuid | cut -c1-16)}"
    [[ "$generation_id" =~ ^[a-z0-9][a-z0-9._-]{7,127}$ ]] || {
      echo "ensure: invalid legacy escrow generation id" >&2
      exit 2
    }
    github_path="generations/$generation_id/passphrase-share-github.txt"
    github_manifest_path="generations/$generation_id/escrow-manifest.json"
    tr -d '\n' < "$PWFILE" | python3 "$SHAMIR" split 2 "$N" > "$tmp/shares" || exit 2
    sed -n 1p "$tmp/shares" > "$LOCAL_SHARE"
    sed -n 2p "$tmp/shares" > "$tmp/dropbox.txt"
    sed -n 3p "$tmp/shares" > "$tmp/github.txt"
    chmod 600 "$LOCAL_SHARE"
    rclone copyto "$tmp/dropbox.txt" "$DROPBOX_DEST/escrow/passphrase-share-dropbox.txt" || { echo "ensure: dropbox upload failed" >&2; exit 2; }
    gh_put "$github_path" "$tmp/github.txt" || { echo "ensure: github upload failed" >&2; exit 2; }
    LOCS='"local", "dropbox", "github:'"$GH_REPO/$github_path"'"'
    if [ "$HAVE_GDRIVE" -eq 1 ]; then
      sed -n 4p "$tmp/shares" > "$tmp/gdrive.txt"
      rclone copyto "$tmp/gdrive.txt" "$GDRIVE_DEST/escrow/passphrase-share-gdrive.txt" || { echo "ensure: gdrive upload failed" >&2; exit 2; }
      LOCS="$LOCS"', "gdrive"'
    else
      echo "escrow: NOTE gdrive token dead - running 2-of-3; reconnect with 'rclone config reconnect ${GDRIVE_DEST%%:*}:' to auto-upgrade to 2-of-4"
    fi
    printf '{\n  "schema": "csr-escrow-v1",\n  "generation_id": "%s",\n  "k": 2,\n  "n": %s,\n  "sha256": "%s",\n  "github_path": "%s",\n  "locations": [%s],\n  "updated": "%s"\n}\n' \
      "$generation_id" "$N" "$(pw_hash)" "$github_path" "$LOCS" "$(date -u +%FT%TZ)" > "$MANIFEST"
    chmod 600 "$MANIFEST"
    gh_put "$github_manifest_path" "$MANIFEST" || { echo "ensure: github manifest upload failed" >&2; exit 2; }
    echo "escrow: done (2-of-$N)"
    exit 0 ;;

  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
