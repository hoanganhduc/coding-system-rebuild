#!/usr/bin/env python3
"""Materialize one authenticated Git commit as an immutable repository generation.

The unprivileged side emits a bounded stream of raw Git blobs.  The privileged
side never opens the checkout or its object database: it reconstructs the tree
from that stream, re-hashes every blob, seals the result, and publishes the
completion marker last.

Two authorities hold generations.  Stage-0 publishes a root-owned one under
/usr/local/libexec, used only by the restore's system steps.  The code that
runs day to day, through the repository selector, comes from a generation owned
by the user under ~/.local/share/coding-system (``--owner``), which the owner
publishes and updates without root.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
from typing import BinaryIO


GENERATION_BASE = Path("/usr/local/libexec")
GENERATION_PARTS = ("coding-system", "repository-generations")
# The owner's authority, relative to the owner's home directory.
OWNER_GENERATION_PARTS = (".local", "share", "coding-system", "repository-generations")
STREAM_MAGIC = b"CSR-REPOSITORY-GENERATION-v1\n"
MANIFEST_NAME = ".csr-generation.json"
MARKER_NAME = ".csr-generation-complete"
MANIFEST_SCHEMA = "coding-system.repository-generation/v1"
OID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
TREE_RECORD_RE = re.compile(
    rb"(100644|100755|120000) blob ([0-9a-f]{40}(?:[0-9a-f]{24})?)\t([^\0]+)\Z"
)
MAX_HEADER_BYTES = 16 * 1024
MAX_INVENTORY_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_SYMLINK_BYTES = 4096
AT_FDCWD = -100
RENAME_NOREPLACE = 1


class GenerationError(RuntimeError):
    """A redaction-safe immutable-generation failure."""


def _require_oid(value: str, label: str) -> str:
    if OID_RE.fullmatch(value) is None:
        raise GenerationError(f"{label} is not a full Git object ID")
    return value


def _safe_path(value: str) -> str:
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise GenerationError("Git tree contains a non-UTF-8 path") from exc
    pure = PurePosixPath(value)
    if (
        not value
        or len(encoded) > MAX_PATH_BYTES
        or pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or value in {MANIFEST_NAME, MARKER_NAME}
        or value.startswith(MANIFEST_NAME + "/")
        or value.startswith(MARKER_NAME + "/")
    ):
        raise GenerationError("Git tree contains an unsafe or reserved path")
    return value


def _safe_link(path: str, payload: bytes) -> str:
    if not payload or len(payload) > MAX_SYMLINK_BYTES or b"\0" in payload:
        raise GenerationError("Git tree contains an invalid symbolic link")
    try:
        target = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise GenerationError("Git tree contains a non-UTF-8 symbolic link") from exc
    pure = PurePosixPath(target)
    if pure.is_absolute() or any(part in {"", "."} for part in pure.parts):
        raise GenerationError("Git tree contains an unsafe symbolic link")
    resolved = PurePosixPath(path).parent.joinpath(pure)
    depth = 0
    for part in resolved.parts:
        if part == "..":
            depth -= 1
        else:
            depth += 1
        if depth < 0:
            raise GenerationError("Git tree contains an escaping symbolic link")
    return target


def _blob_hasher(oid: str, size: int) -> object:
    digest = hashlib.sha1() if len(oid) == 40 else hashlib.sha256()
    digest.update(f"blob {size}\0".encode("ascii"))
    return digest


def _git_object_digest(kind: str, payload: bytes, oid_length: int) -> str:
    if oid_length == 40:
        digest = hashlib.sha1()
    elif oid_length == 64:
        digest = hashlib.sha256()
    else:
        raise GenerationError("Git object format is unsupported")
    digest.update(f"{kind} {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def reconstruct_tree_oid(entries: list[dict[str, object]], expected_tree: str) -> str:
    """Rebuild every nested Git tree object from the privileged-side inventory."""

    expected_tree = _require_oid(expected_tree, "repository tree")
    oid_length = len(expected_tree)
    root: dict[bytes, object] = {}
    for entry in entries:
        try:
            path = _safe_path(str(entry["path"]))
            mode = str(entry["git_mode"])
            oid = str(entry["oid"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GenerationError("repository generation entry cannot form a Git tree") from exc
        if mode not in {"100644", "100755", "120000"} or len(oid) != oid_length \
                or OID_RE.fullmatch(oid) is None:
            raise GenerationError("repository generation object format is inconsistent")
        parts = [part.encode("utf-8", "strict") for part in PurePosixPath(path).parts]
        node = root
        for component in parts[:-1]:
            existing = node.get(component)
            if existing is None:
                child: dict[bytes, object] = {}
                node[component] = child
                node = child
            elif isinstance(existing, dict):
                node = existing
            else:
                raise GenerationError("repository generation has a file/directory prefix conflict")
        leaf = parts[-1]
        if leaf in node:
            raise GenerationError("repository generation has a duplicate or prefix-conflicting path")
        node[leaf] = (mode, oid)

    def hash_node(node: dict[bytes, object]) -> str:
        direct: list[tuple[bytes, bool, str, str]] = []
        for name, value in node.items():
            if isinstance(value, dict):
                direct.append((name, True, "40000", hash_node(value)))
            else:
                mode, oid = value
                direct.append((name, False, str(mode), str(oid)))
        # Git's base-name comparison treats a tree as if its name has a
        # trailing slash and a non-tree as if its name has a trailing NUL.
        direct.sort(key=lambda item: item[0] + (b"/" if item[1] else b"\0"))
        payload = bytearray()
        for name, _is_tree, mode, oid in direct:
            try:
                raw_oid = bytes.fromhex(oid)
            except ValueError as exc:
                raise GenerationError("repository generation contains an invalid object ID") from exc
            if len(raw_oid) * 2 != oid_length:
                raise GenerationError("repository generation mixes Git object formats")
            payload.extend(mode.encode("ascii") + b" " + name + b"\0" + raw_oid)
        return _git_object_digest("tree", bytes(payload), oid_length)

    return hash_node(root)


def parse_inventory(raw: bytes) -> list[dict[str, object]]:
    if not raw or len(raw) > MAX_INVENTORY_BYTES or not raw.endswith(b"\0"):
        raise GenerationError("Git tree inventory is empty, oversized, or truncated")
    records = raw[:-1].split(b"\0")
    if not records or len(records) > MAX_ENTRIES:
        raise GenerationError("Git tree inventory exceeds its entry bound")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    previous = b""
    for raw_record in records:
        match = TREE_RECORD_RE.fullmatch(raw_record)
        if match is None:
            raise GenerationError(
                "Git tree contains an unsupported object, mode, or path"
            )
        raw_path = match.group(3)
        if previous and raw_path <= previous:
            raise GenerationError("Git tree inventory is not strictly ordered")
        previous = raw_path
        try:
            path = _safe_path(raw_path.decode("utf-8", "strict"))
        except UnicodeDecodeError as exc:
            raise GenerationError("Git tree contains a non-UTF-8 path") from exc
        if path in seen:
            raise GenerationError("Git tree contains a duplicate path")
        seen.add(path)
        result.append(
            {
                "git_mode": match.group(1).decode("ascii"),
                "oid": match.group(2).decode("ascii"),
                "path": path,
            }
        )
    return result


def _git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": "/",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "XDG_CONFIG_HOME": "/dev/null",
    }


def _git_command(repository: Path, *arguments: str) -> list[str]:
    return [
        "/usr/bin/git",
        "--no-replace-objects",
        "--no-optional-locks",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.multiPackIndex=false",
        "-c",
        "core.alternateRefsCommand=",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "credential.helper=",
        "-c",
        "core.sshCommand=/bin/false",
        "-C",
        os.fspath(repository),
        *arguments,
    ]


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, 64 * 1024))
        if not chunk:
            raise GenerationError("raw Git blob stream ended early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_json_line(stream: BinaryIO, value: object) -> None:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if len(payload) > MAX_HEADER_BYTES:
        raise GenerationError("repository generation record is oversized")
    stream.write(payload + b"\n")


def emit_stream(
    repository: Path, commit: str, tree: str, output: BinaryIO
) -> None:
    """Emit authenticated raw blobs without Git archive/attribute transforms."""

    commit = _require_oid(commit, "repository commit")
    tree = _require_oid(tree, "repository tree")
    repository = Path(repository)
    try:
        root_info = repository.lstat()
        git_info = (repository / ".git").lstat()
    except OSError as exc:
        raise GenerationError("repository object store is unavailable") from exc
    if (
        not repository.is_absolute()
        or repository.is_symlink()
        or not stat.S_ISDIR(root_info.st_mode)
        or (repository / ".git").is_symlink()
        or not stat.S_ISDIR(git_info.st_mode)
    ):
        raise GenerationError("repository object store is unsafe")
    actual_tree = subprocess.run(
        _git_command(repository, "rev-parse", "--verify", f"{commit}^{{tree}}"),
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if actual_tree.returncode != 0 or actual_tree.stdout.strip() != tree.encode("ascii"):
        raise GenerationError("repository commit/tree identity disagrees")
    inventory = subprocess.run(
        _git_command(repository, "ls-tree", "-rz", "-r", "--full-tree", commit),
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    if inventory.returncode != 0 or len(inventory.stdout) > MAX_INVENTORY_BYTES:
        raise GenerationError("cannot read repository Git tree inventory")
    records = parse_inventory(inventory.stdout)
    process = subprocess.Popen(
        _git_command(repository, "cat-file", "--batch"),
        env=_git_environment(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert process.stdin is not None and process.stdout is not None
    total = 0
    try:
        output.write(STREAM_MAGIC)
        _write_json_line(
            output,
            {
                "commit": commit,
                "count": len(records),
                "schema": MANIFEST_SCHEMA,
                "tree": tree,
            },
        )
        for record in records:
            oid = str(record["oid"])
            process.stdin.write(oid.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline(256)
            fields = header.rstrip(b"\n").split()
            if (
                len(header) > 255
                or not header.endswith(b"\n")
                or len(fields) != 3
                or fields[0] != oid.encode("ascii")
                or fields[1] != b"blob"
                or not fields[2].isdigit()
            ):
                raise GenerationError("Git returned an invalid blob record")
            size = int(fields[2])
            total += size
            if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                raise GenerationError("repository Git blobs exceed their bounds")
            if record["git_mode"] == "120000" and size > MAX_SYMLINK_BYTES:
                raise GenerationError("repository symbolic link exceeds its bound")
            payload = _read_exact(process.stdout, size)
            if process.stdout.read(1) != b"\n":
                raise GenerationError("Git blob record is not terminated")
            digest = _blob_hasher(oid, size)
            digest.update(payload)
            if digest.hexdigest() != oid:
                raise GenerationError("Git blob content disagrees with its object ID")
            if record["git_mode"] == "120000":
                _safe_link(str(record["path"]), payload)
            _write_json_line(output, {**record, "size": size})
            output.write(payload)
            output.write(b"\n")
        output.write(b"END\n")
        output.flush()
        process.stdin.close()
        if process.wait(timeout=60) != 0:
            raise GenerationError("Git raw-blob transport failed")
    except BaseException:
        try:
            process.stdin.close()
        except (OSError, ValueError):
            pass
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()


def _read_json_line(stream: BinaryIO) -> dict[str, object]:
    line = stream.readline(MAX_HEADER_BYTES + 2)
    if not line.endswith(b"\n") or len(line) > MAX_HEADER_BYTES + 1:
        raise GenerationError("repository generation stream record is truncated")
    try:
        value = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GenerationError("repository generation stream record is invalid") from exc
    if not isinstance(value, dict):
        raise GenerationError("repository generation stream record is invalid")
    return value


def _require_directory(path: Path, uid: int, gid: int, mode: int) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise GenerationError(f"repository generation directory is unavailable: {path}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or (info.st_uid, info.st_gid) != (uid, gid)
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise GenerationError(f"repository generation directory is unsafe: {path}")
    return info


def ensure_generation_root(
    *,
    base: Path = GENERATION_BASE,
    parts: tuple[str, ...] = GENERATION_PARTS,
    uid: int = 0,
    gid: int = 0,
) -> Path:
    current = Path(base)
    _require_directory(current, uid, gid, 0o755)
    for name in parts:
        current = current / name
        created = False
        try:
            os.mkdir(current, 0o755)
            created = True
        except FileExistsError:
            pass
        if created:
            os.chown(current, uid, gid)
            os.chmod(current, 0o755)
            _fsync_directory(current.parent)
        _require_directory(current, uid, gid, 0o755)
    return current


def _require_owned_directory(path: Path, uid: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise GenerationError(f"repository generation directory is unavailable: {path}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise GenerationError(f"repository generation directory is unsafe: {path}")


def owner_generation_root(*, home: Path, uid: int, gid: int, create: bool) -> Path:
    """Return ~/.local/share/coding-system/repository-generations of the owner.

    Its ancestors need only be owner-controlled; the root itself is exactly mode
    0755 and owned by the owner, like the Stage-0 authority.
    """

    current = Path(home)
    _require_owned_directory(current, uid)
    last = len(OWNER_GENERATION_PARTS) - 1
    for index, name in enumerate(OWNER_GENERATION_PARTS):
        current = current / name
        if create:
            try:
                os.mkdir(current, 0o755 if index == last else 0o700)
            except FileExistsError:
                pass
            else:
                if index == last:
                    os.chmod(current, 0o755)
                _fsync_directory(current.parent)
        if index == last:
            _require_directory(current, uid, gid, 0o755)
        else:
            _require_owned_directory(current, uid)
    return current


def require_generation_root(
    *,
    base: Path = GENERATION_BASE,
    parts: tuple[str, ...] = GENERATION_PARTS,
    uid: int = 0,
    gid: int = 0,
) -> Path:
    current = Path(base)
    _require_directory(current, uid, gid, 0o755)
    for name in parts:
        current = current / name
        _require_directory(current, uid, gid, 0o755)
    return current


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _generation_name(commit: str, tree: str) -> str:
    return f"{_require_oid(commit, 'repository commit')}-{_require_oid(tree, 'repository tree')}"


def _create_stage(root: Path, commit: str, tree: str, uid: int, gid: int) -> Path:
    prefix = f".stage-{_generation_name(commit, tree)}-"
    for _attempt in range(128):
        stage = root / (prefix + secrets.token_hex(12))
        try:
            os.mkdir(stage, 0o700)
        except FileExistsError:
            continue
        os.chown(stage, uid, gid)
        os.chmod(stage, 0o700)
        _fsync_directory(root)
        return stage
    raise GenerationError("cannot allocate a repository generation stage")


def _mkdir_parents(stage: Path, relative: str, uid: int, gid: int) -> None:
    current = stage
    for part in PurePosixPath(relative).parent.parts:
        current = current / part
        try:
            os.mkdir(current, 0o700)
            os.chown(current, uid, gid)
        except FileExistsError:
            info = current.lstat()
            if current.is_symlink() or not stat.S_ISDIR(info.st_mode):
                raise GenerationError("repository generation parent is unsafe")


def _remove_stage(root: Path, stage: Path, uid: int, gid: int) -> None:
    if not os.path.lexists(stage):
        return
    if stage.parent != root or not stage.name.startswith(".stage-"):
        raise GenerationError("refusing unsafe repository stage cleanup")
    info = stage.lstat()
    if stage.is_symlink() or not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != (uid, gid):
        raise GenerationError("refusing unsafe repository stage cleanup")
    for directory, dirnames, _filenames in os.walk(stage, topdown=True, followlinks=False):
        os.chmod(directory, 0o700)
        for name in dirnames:
            child = Path(directory) / name
            child_info = child.lstat()
            if stat.S_ISDIR(child_info.st_mode) and not child.is_symlink():
                os.chmod(child, 0o700)
    shutil.rmtree(stage)
    _fsync_directory(root)


def _manifest_bytes(value: dict[str, object]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _write_regular(path: Path, payload: bytes, mode: int, uid: int, gid: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _receive_stage(
    stream: BinaryIO,
    root: Path,
    commit: str,
    tree: str,
    uid: int,
    gid: int,
) -> tuple[Path, dict[str, object]]:
    if stream.read(len(STREAM_MAGIC)) != STREAM_MAGIC:
        raise GenerationError("repository generation stream has the wrong magic")
    header = _read_json_line(stream)
    if set(header) != {"commit", "count", "schema", "tree"} or (
        header.get("schema") != MANIFEST_SCHEMA
        or header.get("commit") != commit
        or header.get("tree") != tree
        or not isinstance(header.get("count"), int)
        or not 0 < int(header["count"]) <= MAX_ENTRIES
    ):
        raise GenerationError("repository generation stream identity is invalid")
    stage = _create_stage(root, commit, tree, uid, gid)
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    previous = ""
    total = 0
    try:
        for _index in range(int(header["count"])):
            record = _read_json_line(stream)
            if set(record) != {"git_mode", "oid", "path", "size"}:
                raise GenerationError("repository generation entry header is invalid")
            mode = record.get("git_mode")
            oid = record.get("oid")
            path_value = record.get("path")
            size = record.get("size")
            if (
                mode not in {"100644", "100755", "120000"}
                or not isinstance(oid, str)
                or OID_RE.fullmatch(oid) is None
                or not isinstance(path_value, str)
                or not isinstance(size, int)
                or size < 0
                or size > MAX_FILE_BYTES
            ):
                raise GenerationError("repository generation entry header is invalid")
            path_value = _safe_path(path_value)
            if path_value in seen or (previous and path_value <= previous):
                raise GenerationError("repository generation entries are not unique and ordered")
            previous = path_value
            seen.add(path_value)
            total += size
            if total > MAX_TOTAL_BYTES or (mode == "120000" and size > MAX_SYMLINK_BYTES):
                raise GenerationError("repository generation payload exceeds its bound")
            payload = _read_exact(stream, size)
            if stream.read(1) != b"\n":
                raise GenerationError("repository generation payload is not terminated")
            object_digest = _blob_hasher(oid, size)
            object_digest.update(payload)
            if object_digest.hexdigest() != oid:
                raise GenerationError("repository generation blob has the wrong object ID")
            _mkdir_parents(stage, path_value, uid, gid)
            destination = stage / path_value
            sha256 = hashlib.sha256(payload).hexdigest()
            manifest_entry: dict[str, object] = {
                "git_mode": mode,
                "oid": oid,
                "path": path_value,
                "sha256": sha256,
                "size": size,
            }
            if mode == "120000":
                target = _safe_link(path_value, payload)
                os.symlink(target, destination)
                os.lchown(destination, uid, gid)
                manifest_entry["target"] = target
            else:
                _write_regular(
                    destination,
                    payload,
                    0o555 if mode == "100755" else 0o444,
                    uid,
                    gid,
                )
            entries.append(manifest_entry)
        if stream.read(4) != b"END\n" or stream.read(1):
            raise GenerationError("repository generation stream has trailing data")
        if reconstruct_tree_oid(entries, tree) != tree:
            raise GenerationError(
                "repository generation inventory does not reconstruct the authenticated Git tree"
            )
        manifest: dict[str, object] = {
            "commit": commit,
            "entries": entries,
            "schema": MANIFEST_SCHEMA,
            "tree": tree,
        }
        _write_regular(stage / MANIFEST_NAME, _manifest_bytes(manifest), 0o444, uid, gid)
        return stage, manifest
    except BaseException:
        _remove_stage(root, stage, uid, gid)
        raise


def _walk_entries(root: Path) -> dict[str, os.stat_result]:
    result: dict[str, os.stat_result] = {}
    root_device = root.lstat().st_dev
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        parent = Path(directory)
        for name in list(dirnames):
            child = parent / name
            info = child.lstat()
            relative = child.relative_to(root).as_posix()
            if info.st_dev != root_device:
                raise GenerationError("repository generation crosses a device boundary")
            result[relative] = info
            if stat.S_ISLNK(info.st_mode):
                dirnames.remove(name)
        for name in filenames:
            child = parent / name
            info = child.lstat()
            if info.st_dev != root_device:
                raise GenerationError("repository generation crosses a device boundary")
            result[child.relative_to(root).as_posix()] = info
        if len(result) > MAX_ENTRIES * 2:
            raise GenerationError("repository generation contains too many entries")
    return result


def _expected_directories(entries: list[dict[str, object]]) -> set[str]:
    return {
        parent.as_posix()
        for entry in entries
        for parent in PurePosixPath(str(entry["path"])).parents
        if parent.as_posix() != "."
    }


def _verify_tree(
    root: Path,
    manifest: dict[str, object],
    *,
    uid: int,
    gid: int,
    published: bool,
) -> None:
    _require_directory(root, uid, gid, 0o555 if published else 0o700)
    entries_value = manifest.get("entries")
    if (
        set(manifest) != {"commit", "entries", "schema", "tree"}
        or manifest.get("schema") != MANIFEST_SCHEMA
        or not isinstance(entries_value, list)
    ):
        raise GenerationError("repository generation manifest is invalid")
    entries = entries_value
    expected_dirs = _expected_directories(entries)
    expected_paths = {str(entry["path"]) for entry in entries}
    expected_paths.add(MANIFEST_NAME)
    if published:
        expected_paths.add(MARKER_NAME)
    actual = _walk_entries(root)
    actual_dirs = {
        path for path, info in actual.items() if stat.S_ISDIR(info.st_mode)
    }
    actual_nondirs = set(actual) - actual_dirs
    if actual_dirs != expected_dirs or actual_nondirs != expected_paths:
        raise GenerationError("repository generation contains missing or extra entries")
    root_device = root.lstat().st_dev
    for path in expected_dirs:
        info = actual[path]
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_dev != root_device
            or (info.st_uid, info.st_gid) != (uid, gid)
            or stat.S_IMODE(info.st_mode) != 0o555
        ):
            raise GenerationError("repository generation directory metadata is invalid")
    manifest_payload = _manifest_bytes(manifest)
    if (root / MANIFEST_NAME).read_bytes() != manifest_payload:
        raise GenerationError("repository generation manifest bytes changed")
    for entry in entries:
        path = root / str(entry["path"])
        info = path.lstat()
        if (info.st_uid, info.st_gid) != (uid, gid) or info.st_dev != root_device:
            raise GenerationError("repository generation entry authority changed")
        mode = str(entry["git_mode"])
        if mode == "120000":
            target = str(entry.get("target", ""))
            if (
                not stat.S_ISLNK(info.st_mode)
                or info.st_nlink != 1
                or os.readlink(path) != target
                or hashlib.sha256(os.fsencode(target)).hexdigest() != entry["sha256"]
            ):
                raise GenerationError("repository generation symbolic link changed")
            continue
        expected_mode = 0o555 if mode == "100755" else 0o444
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != expected_mode
            or info.st_size != entry["size"]
        ):
            raise GenerationError("repository generation file metadata changed")
        digest = hashlib.sha256()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            while True:
                block = os.read(descriptor, 64 * 1024)
                if not block:
                    break
                digest.update(block)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_ctime_ns
            ):
                raise GenerationError("repository generation file changed during verification")
        finally:
            os.close(descriptor)
        if digest.hexdigest() != entry["sha256"]:
            raise GenerationError("repository generation file bytes changed")


def _seal_stage(stage: Path, manifest: dict[str, object], uid: int, gid: int) -> None:
    entries = manifest["entries"]
    assert isinstance(entries, list)
    directories = _expected_directories(entries)
    for directory in sorted(directories, key=lambda item: item.count("/"), reverse=True):
        path = stage / directory
        os.chown(path, uid, gid)
        os.chmod(path, 0o555)
        _fsync_directory(path)
    _verify_tree(stage, manifest, uid=uid, gid=gid, published=False)


def _rename_noreplace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise GenerationError("renameat2(RENAME_NOREPLACE) is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if renameat2(AT_FDCWD, os.fsencode(source), AT_FDCWD, os.fsencode(target), RENAME_NOREPLACE) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(code, os.strerror(code), target)
        raise GenerationError(f"cannot publish repository generation: {os.strerror(code)}")


def _load_manifest(path: Path, commit: str, tree: str) -> dict[str, object]:
    try:
        payload = path.read_bytes()
        if not payload or len(payload) > MAX_INVENTORY_BYTES:
            raise GenerationError("repository generation manifest size is invalid")
        value = json.loads(payload)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GenerationError("repository generation manifest is unavailable or invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("commit") != commit
        or value.get("tree") != tree
        or _manifest_bytes(value) != payload
    ):
        raise GenerationError("repository generation manifest identity changed")
    return value


def _marker_bytes(commit: str, tree: str, manifest_payload: bytes) -> bytes:
    return _manifest_bytes(
        {
            "commit": commit,
            "manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
            "schema": MANIFEST_SCHEMA,
            "tree": tree,
        }
    )


def verify_generation(
    root: Path,
    commit: str,
    tree: str,
    *,
    uid: int = 0,
    gid: int = 0,
) -> Path:
    target = root / _generation_name(commit, tree)
    manifest = _load_manifest(target / MANIFEST_NAME, commit, tree)
    marker_payload = _marker_bytes(commit, tree, _manifest_bytes(manifest))
    try:
        marker_info = (target / MARKER_NAME).lstat()
        marker_bytes = (target / MARKER_NAME).read_bytes()
    except OSError as exc:
        raise GenerationError("repository generation completion marker is missing") from exc
    if (
        not stat.S_ISREG(marker_info.st_mode)
        or marker_info.st_nlink != 1
        or (marker_info.st_uid, marker_info.st_gid) != (uid, gid)
        or stat.S_IMODE(marker_info.st_mode) != 0o444
        or marker_bytes != marker_payload
    ):
        raise GenerationError("repository generation completion marker changed")
    _verify_tree(target, manifest, uid=uid, gid=gid, published=True)
    return target


def publish_stream(
    stream: BinaryIO,
    root: Path,
    commit: str,
    tree: str,
    *,
    uid: int = 0,
    gid: int = 0,
) -> Path:
    root = Path(root)
    lock_path = root / ".publish.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchown(lock_fd, uid, gid)
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        stage, manifest = _receive_stage(stream, root, commit, tree, uid, gid)
        try:
            _seal_stage(stage, manifest, uid, gid)
            manifest_payload = _manifest_bytes(manifest)
            # The completion marker is the final filesystem member created in
            # the hidden stage.  Seal and verify the complete stage before the
            # single atomic rename makes it visible at its generation name.
            _write_regular(
                stage / MARKER_NAME,
                _marker_bytes(commit, tree, manifest_payload),
                0o444,
                uid,
                gid,
            )
            os.chmod(stage, 0o555)
            _fsync_directory(stage)
            _verify_tree(stage, manifest, uid=uid, gid=gid, published=True)
            target = root / _generation_name(commit, tree)
            if os.path.lexists(target):
                published = verify_generation(root, commit, tree, uid=uid, gid=gid)
                if _load_manifest(published / MANIFEST_NAME, commit, tree) != manifest:
                    raise GenerationError("published repository generation differs from its Git tree")
                _remove_stage(root, stage, uid, gid)
                return published
            try:
                _rename_noreplace(stage, target)
            except FileExistsError:
                published = verify_generation(root, commit, tree, uid=uid, gid=gid)
                if _load_manifest(published / MANIFEST_NAME, commit, tree) != manifest:
                    raise GenerationError("concurrent repository generation disagreed")
                _remove_stage(root, stage, uid, gid)
                return published
            _fsync_directory(root)
            return verify_generation(root, commit, tree, uid=uid, gid=gid)
        except BaseException:
            if os.path.lexists(stage):
                _remove_stage(root, stage, uid, gid)
            raise
    finally:
        os.close(lock_fd)


def emit_generation(
    path: Path,
    commit: str,
    tree: str,
    output: BinaryIO,
    *,
    uid: int,
    gid: int,
) -> None:
    """Re-emit one verified generation as the raw-blob publication stream.

    The receiving publisher re-hashes every blob and reconstructs the Git tree,
    so a copy into the owner's authority is checked exactly as the first
    publication was.
    """

    commit = _require_oid(commit, "repository commit")
    tree = _require_oid(tree, "repository tree")
    path = Path(path)
    if verify_generation(path.parent, commit, tree, uid=uid, gid=gid) != path:
        raise GenerationError("repository generation path differs from its identity")
    entries = _load_manifest(path / MANIFEST_NAME, commit, tree)["entries"]
    assert isinstance(entries, list)
    output.write(STREAM_MAGIC)
    _write_json_line(
        output,
        {"commit": commit, "count": len(entries), "schema": MANIFEST_SCHEMA, "tree": tree},
    )
    for entry in entries:
        relative = str(entry["path"])
        if entry["git_mode"] == "120000":
            payload = os.fsencode(os.readlink(path / relative))
        else:
            descriptor = os.open(
                path / relative, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            with os.fdopen(descriptor, "rb") as stream:
                payload = stream.read(MAX_FILE_BYTES + 1)
        _write_json_line(
            output,
            {
                "git_mode": entry["git_mode"],
                "oid": entry["oid"],
                "path": relative,
                "size": len(payload),
            },
        )
        output.write(payload)
        output.write(b"\n")
    output.write(b"END\n")
    output.flush()


def _owner() -> tuple[int, int, Path]:
    uid, gid = os.geteuid(), os.getegid()
    if uid == 0:
        raise GenerationError("the owner's repository generation is never published by root")
    home = os.environ.get("HOME") or pwd.getpwuid(uid).pw_dir
    if not os.path.isabs(home):
        raise GenerationError("the owner's HOME is not an absolute path")
    return uid, gid, Path(home)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    emit = commands.add_parser("emit")
    emit.add_argument("--repository", type=Path, required=True)
    emit.add_argument("--commit", required=True)
    emit.add_argument("--tree", required=True)
    emit_copy = commands.add_parser("emit-generation")
    emit_copy.add_argument("--path", type=Path, required=True)
    emit_copy.add_argument("--commit", required=True)
    emit_copy.add_argument("--tree", required=True)
    emit_copy.add_argument("--owner", action="store_true", help="the source is the owner's generation")
    publish = commands.add_parser("publish")
    publish.add_argument("--commit", required=True)
    publish.add_argument("--tree", required=True)
    publish.add_argument("--owner", action="store_true", help="publish into the owner's authority, without root")
    verify = commands.add_parser("verify")
    verify.add_argument("--commit", required=True)
    verify.add_argument("--tree", required=True)
    verify.add_argument("--path", type=Path)
    verify.add_argument("--owner", action="store_true", help="verify in the owner's authority")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "emit":
        emit_stream(arguments.repository, arguments.commit, arguments.tree, sys.stdout.buffer)
        return 0
    if arguments.command == "emit-generation":
        uid, gid = _owner()[:2] if arguments.owner else (0, 0)
        emit_generation(
            arguments.path, arguments.commit, arguments.tree, sys.stdout.buffer, uid=uid, gid=gid
        )
        return 0
    if arguments.command == "publish" and arguments.owner:
        uid, gid, home = _owner()
        root = owner_generation_root(home=home, uid=uid, gid=gid, create=True)
        print(publish_stream(sys.stdin.buffer, root, arguments.commit, arguments.tree, uid=uid, gid=gid))
    elif arguments.command == "publish":
        if os.geteuid() != 0 or os.getegid() != 0:
            raise GenerationError("Stage-0 repository generation publication requires root")
        root = ensure_generation_root()
        print(publish_stream(sys.stdin.buffer, root, arguments.commit, arguments.tree))
    elif arguments.owner:
        uid, gid, home = _owner()
        root = owner_generation_root(home=home, uid=uid, gid=gid, create=False)
        target = verify_generation(root, arguments.commit, arguments.tree, uid=uid, gid=gid)
        if arguments.path is not None and arguments.path != target:
            raise GenerationError("repository generation path differs from its identity")
        print(target)
    else:
        root = require_generation_root()
        target = verify_generation(root, arguments.commit, arguments.tree)
        if arguments.path is not None and arguments.path != target:
            raise GenerationError("repository generation path differs from its identity")
        print(target)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GenerationError, OSError, subprocess.SubprocessError) as exc:
        print(f"repository-generation: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
