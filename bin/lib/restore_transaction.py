#!/usr/bin/env python3
"""Crash-consistent, attack-resistant application of a staged recovery tree.

This module deliberately keeps the durable journal metadata-only.  Original
file bytes are held in owner-only backup files on the destination filesystem.
An uncommitted transaction is rolled back before a later restore can begin;
a committed transaction is only cleanup work.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
from typing import Iterator


TRANSACTION_SCHEMA = "coding-system.restore-transaction.v1"
TRANSACTION_STATE_PATH = ".local/state/coding-system/recovery-transactions"
TRANSACTION_RE = re.compile(r"tx-[0-9a-f]{32}\Z")
BACKUP_RE = re.compile(r"[0-9]{6}\.bak\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_JOURNAL_BYTES = 32 * 1024 * 1024
_DIR_FLAGS = (
    os.O_RDONLY
    | os.O_DIRECTORY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FLAGS = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)
_CREATE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class RestoreTransactionError(RuntimeError):
    """A redaction-safe restore transaction failure."""


def _safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise RestoreTransactionError("invalid restore transaction path")
    if value.startswith("/") or len(value.encode("utf-8")) > 4096:
        raise RestoreTransactionError("unsafe restore transaction path")
    parts = value.split("/")
    if any(
        part in ("", ".", "..") or len(part.encode("utf-8")) > 255
        for part in parts
    ):
        raise RestoreTransactionError("unsafe restore transaction path")
    if PurePosixPath(value).as_posix() != value:
        raise RestoreTransactionError("non-canonical restore transaction path")
    reserved = TRANSACTION_STATE_PATH
    if value == reserved or value.startswith(reserved + "/"):
        raise RestoreTransactionError("restore input overlaps transaction state")
    return value


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise RestoreTransactionError("short write in restore transaction")
        view = view[written:]


def _read_all(descriptor: int, limit: int) -> bytes:
    output: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
        if not chunk:
            return b"".join(output)
        output.append(chunk)
        total += len(chunk)
        if total > limit:
            raise RestoreTransactionError("restore transaction file exceeds its bound")


def _hash_open_file(descriptor: int, limit: int = MAX_FILE_BYTES) -> tuple[str, int]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise RestoreTransactionError("restore file exceeds its bound")
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest(), total


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
        stat.S_IMODE(info.st_mode),
        info.st_uid,
        info.st_gid,
    )


def _open_absolute_directory(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    descriptor = os.open("/", _DIR_FLAGS)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, _DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise RestoreTransactionError("unsafe or unavailable restore directory") from exc


def _validate_directory(
    descriptor: int,
    *,
    uid: int,
    device: int,
    owner_only: bool = False,
    allow_shared_write: bool = False,
) -> os.stat_result:
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_dev != device:
        raise RestoreTransactionError("unsafe restore directory ownership or device")
    if not allow_shared_write and stat.S_IMODE(info.st_mode) & 0o022:
        raise RestoreTransactionError("restore directory is writable by another principal")
    if owner_only and stat.S_IMODE(info.st_mode) & 0o077:
        raise RestoreTransactionError("restore transaction directory is not owner-only")
    return info


def _open_child_directory(
    parent_fd: int,
    component: str,
    *,
    uid: int,
    device: int,
    allow_shared_write: bool = False,
) -> int:
    try:
        descriptor = os.open(component, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise RestoreTransactionError("unsafe restore path ancestor") from exc
    try:
        _validate_directory(
            descriptor,
            uid=uid,
            device=device,
            allow_shared_write=allow_shared_write,
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _destination_root(path: Path) -> tuple[int, os.stat_result]:
    try:
        linked = path.lstat()
    except OSError as exc:
        raise RestoreTransactionError("restore destination must already exist") from exc
    if path.is_symlink() or not stat.S_ISDIR(linked.st_mode):
        raise RestoreTransactionError("restore destination is not a real directory")
    descriptor = _open_absolute_directory(path)
    actual = os.fstat(descriptor)
    if (linked.st_dev, linked.st_ino) != (actual.st_dev, actual.st_ino):
        os.close(descriptor)
        raise RestoreTransactionError("restore destination changed while opening")
    if actual.st_uid != os.geteuid():
        os.close(descriptor)
        raise RestoreTransactionError("restore destination is not owned by this user")
    if stat.S_IMODE(actual.st_mode) & 0o022:
        os.close(descriptor)
        raise RestoreTransactionError(
            "restore destination is writable by another principal"
        )
    return descriptor, actual


def _stage_root(path: Path) -> tuple[int, os.stat_result]:
    try:
        linked = path.lstat()
    except OSError as exc:
        raise RestoreTransactionError("restore staging directory is unavailable") from exc
    if path.is_symlink() or not stat.S_ISDIR(linked.st_mode):
        raise RestoreTransactionError("restore staging path is not a real directory")
    descriptor = _open_absolute_directory(path)
    actual = os.fstat(descriptor)
    if (linked.st_dev, linked.st_ino) != (actual.st_dev, actual.st_ino):
        os.close(descriptor)
        raise RestoreTransactionError("restore staging directory changed while opening")
    if actual.st_uid != os.geteuid() or stat.S_IMODE(actual.st_mode) & 0o077:
        os.close(descriptor)
        raise RestoreTransactionError("restore staging directory is not owner-only")
    return descriptor, actual


def _ensure_state_directory(
    root_fd: int, destination_info: os.stat_result
) -> int:
    descriptor = os.dup(root_fd)
    components = TRANSACTION_STATE_PATH.split("/")
    try:
        for index, component in enumerate(components):
            try:
                child = os.open(component, _DIR_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                    child = os.open(component, _DIR_FLAGS, dir_fd=descriptor)
                except OSError as exc:
                    raise RestoreTransactionError(
                        "cannot create restore transaction state directory"
                    ) from exc
                os.fchmod(child, 0o700)
                os.fsync(child)
            except OSError as exc:
                raise RestoreTransactionError(
                    "unsafe restore transaction state directory"
                ) from exc
            _validate_directory(
                child,
                uid=destination_info.st_uid,
                device=destination_info.st_dev,
                owner_only=index == len(components) - 1,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_lock(state_fd: int, uid: int, device: int) -> int:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(".lock", flags, 0o600, dir_fd=state_fd)
    except OSError as exc:
        raise RestoreTransactionError("cannot open restore transaction lock") from exc
    try:
        info = os.fstat(descriptor)
        linked = os.stat(".lock", dir_fd=state_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_dev != device
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise RestoreTransactionError("unsafe restore transaction lock")
        os.fsync(state_fd)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _locked_destination(
    destination: Path,
) -> Iterator[tuple[int, int, os.stat_result]]:
    root_fd, destination_info = _destination_root(destination)
    state_fd = -1
    lock_fd = -1
    try:
        state_fd = _ensure_state_directory(root_fd, destination_info)
        lock_fd = _open_lock(
            state_fd, destination_info.st_uid, destination_info.st_dev
        )
        yield root_fd, state_fd, destination_info
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        if state_fd >= 0:
            os.close(state_fd)
        os.close(root_fd)


def _metadata_from_open_file(
    descriptor: int, *, uid: int, device: int, expected_mode: int | None = None
) -> dict:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != uid
        or before.st_dev != device
        or before.st_nlink != 1
        or before.st_size > MAX_FILE_BYTES
    ):
        raise RestoreTransactionError("unsafe restore regular file")
    if stat.S_IMODE(before.st_mode) & 0o022:
        raise RestoreTransactionError("restore file is writable by another principal")
    if expected_mode is not None and stat.S_IMODE(before.st_mode) != expected_mode:
        raise RestoreTransactionError("restore file mode changed unexpectedly")
    digest, size = _hash_open_file(descriptor)
    after = os.fstat(descriptor)
    if _identity(before) != _identity(after) or size != after.st_size:
        raise RestoreTransactionError("restore file changed during inspection")
    return {
        "sha256": digest,
        "size": size,
        "mode": stat.S_IMODE(after.st_mode),
        "uid": after.st_uid,
        "gid": after.st_gid,
        "device": after.st_dev,
        "inode": after.st_ino,
        "mtime_ns": after.st_mtime_ns,
        "ctime_ns": after.st_ctime_ns,
    }


def _runtime_identity(metadata: dict) -> tuple[int, ...]:
    return (
        metadata["device"],
        metadata["inode"],
        metadata["size"],
        metadata["mtime_ns"],
        metadata["ctime_ns"],
        1,
        metadata["mode"],
        metadata["uid"],
        metadata["gid"],
    )


def _open_relative_file(
    root_fd: int,
    relative: str,
    *,
    uid: int,
    device: int,
    allow_shared_write: bool = False,
) -> int:
    components = _safe_relative(relative).split("/")
    descriptor = os.dup(root_fd)
    file_fd = -1
    try:
        for component in components[:-1]:
            child = _open_child_directory(
                descriptor,
                component,
                uid=uid,
                device=device,
                allow_shared_write=allow_shared_write,
            )
            os.close(descriptor)
            descriptor = child
        file_fd = os.open(components[-1], _READ_FLAGS, dir_fd=descriptor)
        return file_fd
    except OSError as exc:
        if file_fd >= 0:
            os.close(file_fd)
        raise RestoreTransactionError("unsafe or unavailable restore file") from exc
    finally:
        os.close(descriptor)


def _scan_parent_directories(
    root_fd: int,
    relative: str,
    *,
    uid: int,
    device: int,
) -> tuple[list[str], bool]:
    components = _safe_relative(relative).split("/")
    descriptor = os.dup(root_fd)
    missing: list[str] = []
    parent_missing = False
    prefix: list[str] = []
    try:
        for component in components[:-1]:
            prefix.append(component)
            if parent_missing:
                missing.append("/".join(prefix))
                continue
            try:
                child = _open_child_directory(
                    descriptor, component, uid=uid, device=device
                )
            except RestoreTransactionError as exc:
                try:
                    os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    parent_missing = True
                    missing.append("/".join(prefix))
                    continue
                raise exc
            os.close(descriptor)
            descriptor = child
        return missing, parent_missing
    finally:
        os.close(descriptor)


def _inspect_destination_file(
    root_fd: int,
    relative: str,
    *,
    uid: int,
    device: int,
) -> dict:
    missing_dirs, parent_missing = _scan_parent_directories(
        root_fd, relative, uid=uid, device=device
    )
    if parent_missing:
        return {"exists": False, "parent_missing": True, "missing_dirs": missing_dirs}
    components = relative.split("/")
    descriptor = os.dup(root_fd)
    try:
        for component in components[:-1]:
            child = _open_child_directory(
                descriptor, component, uid=uid, device=device
            )
            os.close(descriptor)
            descriptor = child
        try:
            linked = os.stat(components[-1], dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return {"exists": False, "parent_missing": False, "missing_dirs": []}
        if not stat.S_ISREG(linked.st_mode):
            raise RestoreTransactionError("unsafe non-regular restore destination")
        file_fd = os.open(components[-1], _READ_FLAGS, dir_fd=descriptor)
        try:
            metadata = _metadata_from_open_file(file_fd, uid=uid, device=device)
        finally:
            os.close(file_fd)
        if (linked.st_dev, linked.st_ino) != (
            metadata["device"],
            metadata["inode"],
        ):
            raise RestoreTransactionError("restore destination changed during inspection")
        return {
            "exists": True,
            "parent_missing": False,
            "missing_dirs": [],
            **metadata,
        }
    finally:
        os.close(descriptor)


def _validate_no_path_prefixes(paths: list[str]) -> None:
    ordered = sorted(paths)
    for index, value in enumerate(ordered[:-1]):
        if ordered[index + 1].startswith(value + "/"):
            raise RestoreTransactionError("a restore file is an ancestor of another file")


def _preflight(
    stage_fd: int,
    stage_info: os.stat_result,
    root_fd: int,
    destination_info: os.stat_result,
    modes: dict[str, int | None],
    *,
    replace: bool,
    replace_paths: frozenset[str],
) -> tuple[list[dict], list[str]]:
    if not modes:
        raise RestoreTransactionError("restore plan declares no files")
    if len(modes) > MAX_ENTRIES:
        raise RestoreTransactionError("restore plan has too many files")
    paths = [_safe_relative(value) for value in modes]
    if len(set(paths)) != len(paths):
        raise RestoreTransactionError("restore plan contains duplicate paths")
    _validate_no_path_prefixes(paths)
    normalized_replace_paths = frozenset(
        _safe_relative(value) for value in replace_paths
    )
    if not normalized_replace_paths.issubset(paths):
        raise RestoreTransactionError("replace path is outside the restore plan")
    settable_groups = {os.getegid(), *os.getgroups()}
    if os.geteuid() != 0 and destination_info.st_gid not in settable_groups:
        raise RestoreTransactionError("cannot preserve restore destination ownership")
    plan: list[dict] = []
    created_dirs: set[str] = set()
    total = 0
    for relative in sorted(paths):
        mode = modes[relative]
        if mode is not None and (type(mode) is not int or not 0 <= mode <= 0o777):
            raise RestoreTransactionError("invalid restore destination mode")
        source = None
        if mode is not None:
            source_fd = _open_relative_file(
                stage_fd,
                relative,
                uid=stage_info.st_uid,
                device=stage_info.st_dev,
                allow_shared_write=True,
            )
            try:
                source = _metadata_from_open_file(
                    source_fd, uid=stage_info.st_uid, device=stage_info.st_dev
                )
            finally:
                os.close(source_fd)
            total += source["size"]
            if total > MAX_TOTAL_BYTES:
                raise RestoreTransactionError("restore plan exceeds its total size bound")
        old = _inspect_destination_file(
            root_fd,
            relative,
            uid=destination_info.st_uid,
            device=destination_info.st_dev,
        )
        if mode is None and not old["exists"]:
            # Deleting an already absent regular file is a converged no-op.
            continue
        if (
            old["exists"]
            and os.geteuid() != 0
            and old["gid"] not in settable_groups
        ):
            raise RestoreTransactionError("cannot preserve restored file ownership")
        if mode is not None:
            created_dirs.update(old["missing_dirs"])
        if (
            source is not None
            and
            old["exists"]
            and (old["sha256"], old["size"]) != (source["sha256"], source["size"])
            and not replace
            and relative not in normalized_replace_paths
        ):
            raise RestoreTransactionError(f"divergent destination file: {relative}")
        # A deletion carries no source to compare against, so the divergence
        # check above cannot fire for it.  Removing a file the owner still has
        # must demand the same authorization as overwriting a divergent one.
        if (
            mode is None
            and old["exists"]
            and not replace
            and relative not in normalized_replace_paths
        ):
            raise RestoreTransactionError(f"divergent destination file: {relative}")
        plan.append(
            {
                "path": relative,
                "source": source,
                "new": (
                    {"exists": False}
                    if source is None
                    else {
                        "sha256": source["sha256"],
                        "size": source["size"],
                        "mode": mode,
                        "uid": destination_info.st_uid,
                        "gid": destination_info.st_gid,
                    }
                ),
                "old": old,
            }
        )
    ordered_dirs = sorted(created_dirs, key=lambda item: (item.count("/"), item))
    return plan, ordered_dirs


def _same_runtime_file(left: dict, right: dict) -> bool:
    keys = (
        "device",
        "inode",
        "size",
        "mtime_ns",
        "ctime_ns",
        "mode",
        "uid",
        "gid",
    )
    return left.get("exists") and right.get("exists") and all(
        left[key] == right[key] for key in keys
    ) and left["sha256"] == right["sha256"]


def _public_file_metadata(metadata: dict) -> dict:
    return {
        key: metadata[key]
        for key in ("sha256", "size", "mode", "uid", "gid")
    }


def _matches_public_metadata(current: dict, expected: dict) -> bool:
    return bool(current.get("exists")) and all(
        current.get(key) == expected.get(key)
        for key in ("sha256", "size", "mode", "uid", "gid")
    )


def _matches_target_metadata(current: dict, expected: dict) -> bool:
    if expected == {"exists": False}:
        return not current.get("exists", False)
    return _matches_public_metadata(current, expected)


def _copy_fd(source_fd: int, destination_fd: int, expected: dict) -> None:
    before = os.fstat(source_fd)
    if _identity(before) != _runtime_identity(expected):
        raise RestoreTransactionError("restore source changed after preflight")
    os.lseek(source_fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_FILE_BYTES:
            raise RestoreTransactionError("restore source exceeds its bound")
        digest.update(chunk)
        _write_all(destination_fd, chunk)
    after = os.fstat(source_fd)
    if (
        _identity(before) != _identity(after)
        or total != expected["size"]
        or digest.hexdigest() != expected["sha256"]
    ):
        raise RestoreTransactionError("restore source changed while copying")


def _open_transaction_directory(
    state_fd: int,
    name: str,
    *,
    uid: int,
    device: int,
) -> int:
    try:
        descriptor = os.open(name, _DIR_FLAGS, dir_fd=state_fd)
    except OSError as exc:
        raise RestoreTransactionError("unsafe restore transaction directory") from exc
    try:
        info = _validate_directory(
            descriptor, uid=uid, device=device, owner_only=True
        )
        linked = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        if (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino):
            raise RestoreTransactionError(
                "restore transaction directory changed while opening"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _create_transaction_directory(
    state_fd: int, name: str, *, uid: int, device: int
) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=state_fd)
        os.fsync(state_fd)
    except OSError as exc:
        raise RestoreTransactionError("cannot create restore transaction") from exc
    return _open_transaction_directory(
        state_fd, name, uid=uid, device=device
    )


def _create_backup_directory(
    transaction_fd: int, *, uid: int, device: int
) -> int:
    try:
        os.mkdir("backups", 0o700, dir_fd=transaction_fd)
        os.fsync(transaction_fd)
        descriptor = os.open("backups", _DIR_FLAGS, dir_fd=transaction_fd)
    except OSError as exc:
        raise RestoreTransactionError("cannot create restore backup directory") from exc
    try:
        _validate_directory(
            descriptor, uid=uid, device=device, owner_only=True
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _create_backup(
    backup_fd: int,
    name: str,
    source_fd: int,
    expected: dict,
    *,
    uid: int,
    device: int,
) -> None:
    try:
        output_fd = os.open(name, _CREATE_FLAGS, 0o600, dir_fd=backup_fd)
    except OSError as exc:
        raise RestoreTransactionError("cannot create restore backup") from exc
    success = False
    try:
        _copy_fd(source_fd, output_fd, expected)
        os.fchmod(output_fd, 0o600)
        os.fsync(output_fd)
        info = os.fstat(output_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_dev != device
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise RestoreTransactionError("restore backup violated its boundary")
        success = True
    finally:
        os.close(output_fd)
        if not success:
            try:
                os.unlink(name, dir_fd=backup_fd)
                os.fsync(backup_fd)
            except FileNotFoundError:
                pass


def _json_unique(raw: bytes) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise RestoreTransactionError("duplicate restore journal key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RestoreTransactionError("invalid restore transaction journal") from exc
    if not isinstance(value, dict):
        raise RestoreTransactionError("invalid restore transaction journal mapping")
    return value


def _write_journal(transaction_fd: int, journal: dict) -> None:
    raw = (json.dumps(journal, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    if len(raw) > MAX_JOURNAL_BYTES:
        raise RestoreTransactionError("restore transaction journal exceeds its bound")
    temporary = "journal.json.new"
    try:
        descriptor = os.open(temporary, _CREATE_FLAGS, 0o600, dir_fd=transaction_fd)
    except FileExistsError:
        _unlink_safe_regular(
            transaction_fd,
            temporary,
            uid=journal["destination"]["uid"],
            device=journal["destination"]["device"],
        )
        descriptor = os.open(temporary, _CREATE_FLAGS, 0o600, dir_fd=transaction_fd)
    except OSError as exc:
        raise RestoreTransactionError("cannot create restore transaction journal") from exc
    success = False
    try:
        _write_all(descriptor, raw)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        success = True
    finally:
        os.close(descriptor)
        if not success:
            try:
                os.unlink(temporary, dir_fd=transaction_fd)
            except FileNotFoundError:
                pass
    try:
        os.replace(
            temporary,
            "journal.json",
            src_dir_fd=transaction_fd,
            dst_dir_fd=transaction_fd,
        )
        os.fsync(transaction_fd)
    except OSError as exc:
        raise RestoreTransactionError("cannot publish restore transaction journal") from exc


def _read_regular_at(
    parent_fd: int,
    name: str,
    *,
    uid: int,
    device: int,
    limit: int,
    mode: int,
) -> bytes:
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise RestoreTransactionError("cannot open restore transaction file") from exc
    try:
        info = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_dev != device
            or info.st_nlink != 1
            or info.st_size > limit
            or stat.S_IMODE(info.st_mode) != mode
            or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise RestoreTransactionError("unsafe restore transaction file")
        raw = _read_all(descriptor, limit)
        after = os.fstat(descriptor)
        if _identity(info) != _identity(after):
            raise RestoreTransactionError("restore transaction file changed while reading")
        return raw
    finally:
        os.close(descriptor)


def _validate_public_metadata(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "sha256",
        "size",
        "mode",
        "uid",
        "gid",
    }:
        raise RestoreTransactionError("invalid restore journal file metadata")
    if not isinstance(value["sha256"], str) or not SHA256_RE.fullmatch(
        value["sha256"]
    ):
        raise RestoreTransactionError("invalid restore journal digest")
    if type(value["size"]) is not int or not 0 <= value["size"] <= MAX_FILE_BYTES:
        raise RestoreTransactionError("invalid restore journal size")
    if type(value["mode"]) is not int or not 0 <= value["mode"] <= 0o777:
        raise RestoreTransactionError("invalid restore journal mode")
    if any(type(value[key]) is not int or value[key] < 0 for key in ("uid", "gid")):
        raise RestoreTransactionError("invalid restore journal ownership")
    return value


def _validate_journal(
    value: dict, transaction_name: str, destination_info: os.stat_result
) -> dict:
    if set(value) != {
        "schema",
        "transaction_id",
        "state",
        "outcome",
        "destination",
        "entries",
        "created_directories",
    } or value.get("schema") != TRANSACTION_SCHEMA:
        raise RestoreTransactionError("unsupported restore transaction journal")
    if value.get("transaction_id") != transaction_name or not TRANSACTION_RE.fullmatch(
        transaction_name
    ):
        raise RestoreTransactionError("restore transaction identity mismatch")
    state = value.get("state")
    outcome = value.get("outcome")
    if state not in {"prepared", "applying", "committed"}:
        raise RestoreTransactionError("invalid restore transaction state")
    if (state == "committed" and outcome not in {"applied", "rolled-back"}) or (
        state != "committed" and outcome is not None
    ):
        raise RestoreTransactionError("invalid restore transaction outcome")
    expected_destination = {
        "device": destination_info.st_dev,
        "inode": destination_info.st_ino,
        "uid": destination_info.st_uid,
        "gid": destination_info.st_gid,
    }
    if value.get("destination") != expected_destination:
        raise RestoreTransactionError("restore transaction belongs to another destination")
    entries = value.get("entries")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_ENTRIES:
        raise RestoreTransactionError("invalid restore transaction entries")
    seen: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict) or set(entry) != {"path", "new", "old"}:
            raise RestoreTransactionError("invalid restore transaction entry")
        relative = _safe_relative(entry["path"])
        if relative in seen:
            raise RestoreTransactionError("duplicate restore transaction entry")
        seen.add(relative)
        if entry["new"] != {"exists": False}:
            _validate_public_metadata(entry["new"])
        old = entry["old"]
        if not isinstance(old, dict) or set(old) not in (
            {"exists"},
            {"exists", "sha256", "size", "mode", "uid", "gid", "backup"},
        ):
            raise RestoreTransactionError("invalid old-file restore metadata")
        if type(old.get("exists")) is not bool:
            raise RestoreTransactionError("invalid old-file restore existence flag")
        if old["exists"]:
            _validate_public_metadata(
                {key: old[key] for key in ("sha256", "size", "mode", "uid", "gid")}
            )
            if old["backup"] != f"{index:06d}.bak":
                raise RestoreTransactionError("invalid restore backup identity")
        elif set(old) != {"exists"}:
            raise RestoreTransactionError("missing restore path cannot name a backup")
    _validate_no_path_prefixes(list(seen))
    directories = value.get("created_directories")
    if not isinstance(directories, list) or len(directories) > MAX_ENTRIES * 16:
        raise RestoreTransactionError("invalid created-directory restore metadata")
    normalized = [_safe_relative(item) for item in directories]
    if len(set(normalized)) != len(normalized) or normalized != sorted(
        normalized, key=lambda item: (item.count("/"), item)
    ):
        raise RestoreTransactionError("created restore directories are not canonical")
    for directory in normalized:
        if not any(
            entry_path.startswith(directory + "/") for entry_path in seen
        ):
            raise RestoreTransactionError("unrelated directory in restore journal")
    return value


def _load_journal(
    transaction_fd: int, transaction_name: str, destination_info: os.stat_result
) -> dict:
    raw = _read_regular_at(
        transaction_fd,
        "journal.json",
        uid=destination_info.st_uid,
        device=destination_info.st_dev,
        limit=MAX_JOURNAL_BYTES,
        mode=0o600,
    )
    return _validate_journal(_json_unique(raw), transaction_name, destination_info)


def _unlink_safe_regular(
    parent_fd: int, name: str, *, uid: int, device: int
) -> None:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or info.st_dev != device
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RestoreTransactionError("unsafe file in restore transaction cleanup")
    os.unlink(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _cleanup_transaction(
    state_fd: int,
    name: str,
    *,
    uid: int,
    device: int,
    preparing: bool = False,
    crash_at: str | None = None,
) -> None:
    if not preparing:
        cleanup_name = ".cleanup-" + name
        try:
            try:
                os.stat(cleanup_name, dir_fd=state_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RestoreTransactionError(
                    "restore cleanup transaction already exists"
                )
            os.rename(
                name,
                cleanup_name,
                src_dir_fd=state_fd,
                dst_dir_fd=state_fd,
            )
            os.fsync(state_fd)
        except OSError as exc:
            raise RestoreTransactionError(
                "cannot publish restore transaction cleanup"
            ) from exc
        name = cleanup_name
        _cutpoint("after_cleanup_published", crash_at)
    transaction_fd = _open_transaction_directory(
        state_fd, name, uid=uid, device=device
    )
    transaction_identity = os.fstat(transaction_fd)
    try:
        entries = set(os.listdir(transaction_fd))
        allowed = {"backups", "journal.json", "journal.json.new"}
        if not entries.issubset(allowed):
            raise RestoreTransactionError("unexpected file in restore transaction")
        if "backups" in entries:
            backup_fd = _open_child_directory(
                transaction_fd, "backups", uid=uid, device=device
            )
            try:
                if stat.S_IMODE(os.fstat(backup_fd).st_mode) & 0o077:
                    raise RestoreTransactionError(
                        "restore backup directory is not owner-only"
                    )
                for backup in os.listdir(backup_fd):
                    if not BACKUP_RE.fullmatch(backup):
                        raise RestoreTransactionError("unexpected restore backup file")
                    _unlink_safe_regular(
                        backup_fd, backup, uid=uid, device=device
                    )
                os.fsync(backup_fd)
            finally:
                os.close(backup_fd)
            os.rmdir("backups", dir_fd=transaction_fd)
            os.fsync(transaction_fd)
        for filename in ("journal.json.new", "journal.json"):
            if filename in entries:
                _unlink_safe_regular(
                    transaction_fd, filename, uid=uid, device=device
                )
        if os.listdir(transaction_fd):
            raise RestoreTransactionError("restore transaction cleanup is incomplete")
    finally:
        os.close(transaction_fd)
    linked = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
    if (linked.st_dev, linked.st_ino) != (
        transaction_identity.st_dev,
        transaction_identity.st_ino,
    ):
        raise RestoreTransactionError(
            "restore transaction directory changed before cleanup"
        )
    os.rmdir(name, dir_fd=state_fd)
    os.fsync(state_fd)


def _prepare_transaction(
    root_fd: int,
    state_fd: int,
    destination_info: os.stat_result,
    plan: list[dict],
    created_directories: list[str],
) -> tuple[str, dict]:
    transaction_name = "tx-" + secrets.token_hex(16)
    preparing_name = ".preparing-" + transaction_name
    transaction_fd = _create_transaction_directory(
        state_fd,
        preparing_name,
        uid=destination_info.st_uid,
        device=destination_info.st_dev,
    )
    completed = False
    try:
        backup_fd = _create_backup_directory(
            transaction_fd,
            uid=destination_info.st_uid,
            device=destination_info.st_dev,
        )
        try:
            journal_entries = []
            for index, entry in enumerate(plan, start=1):
                old = entry["old"]
                if old["exists"]:
                    current = _inspect_destination_file(
                        root_fd,
                        entry["path"],
                        uid=destination_info.st_uid,
                        device=destination_info.st_dev,
                    )
                    if not _same_runtime_file(current, old):
                        raise RestoreTransactionError(
                            "restore destination changed before backup"
                        )
                    source_fd = _open_relative_file(
                        root_fd,
                        entry["path"],
                        uid=destination_info.st_uid,
                        device=destination_info.st_dev,
                    )
                    try:
                        backup_name = f"{index:06d}.bak"
                        _create_backup(
                            backup_fd,
                            backup_name,
                            source_fd,
                            old,
                            uid=destination_info.st_uid,
                            device=destination_info.st_dev,
                        )
                    finally:
                        os.close(source_fd)
                    old_public = {
                        "exists": True,
                        **_public_file_metadata(old),
                        "backup": backup_name,
                    }
                else:
                    old_public = {"exists": False}
                journal_entries.append(
                    {
                        "path": entry["path"],
                        "new": entry["new"],
                        "old": old_public,
                    }
                )
            os.fsync(backup_fd)
        finally:
            os.close(backup_fd)
        journal = {
            "schema": TRANSACTION_SCHEMA,
            "transaction_id": transaction_name,
            "state": "prepared",
            "outcome": None,
            "destination": {
                "device": destination_info.st_dev,
                "inode": destination_info.st_ino,
                "uid": destination_info.st_uid,
                "gid": destination_info.st_gid,
            },
            "entries": journal_entries,
            "created_directories": created_directories,
        }
        _write_journal(transaction_fd, journal)
        try:
            os.stat(transaction_name, dir_fd=state_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RestoreTransactionError("restore transaction already exists")
        os.rename(
            preparing_name,
            transaction_name,
            src_dir_fd=state_fd,
            dst_dir_fd=state_fd,
        )
        os.fsync(state_fd)
        completed = True
        return transaction_name, journal
    finally:
        os.close(transaction_fd)
        if not completed:
            try:
                _cleanup_transaction(
                    state_fd,
                    preparing_name,
                    uid=destination_info.st_uid,
                    device=destination_info.st_dev,
                    preparing=True,
                )
            except FileNotFoundError:
                pass


def _open_parent(
    root_fd: int,
    relative: str,
    *,
    uid: int,
    device: int,
) -> tuple[int, str]:
    components = _safe_relative(relative).split("/")
    descriptor = os.dup(root_fd)
    try:
        for component in components[:-1]:
            child = _open_child_directory(
                descriptor, component, uid=uid, device=device
            )
            os.close(descriptor)
            descriptor = child
        return descriptor, components[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _open_parent_if_exists(
    root_fd: int,
    relative: str,
    *,
    uid: int,
    device: int,
) -> tuple[int | None, str]:
    """Open a parent for idempotent cleanup, accepting a missing ancestor."""
    components = _safe_relative(relative).split("/")
    descriptor = os.dup(root_fd)
    try:
        for component in components[:-1]:
            try:
                child = os.open(component, _DIR_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                os.close(descriptor)
                return None, components[-1]
            except OSError as exc:
                raise RestoreTransactionError("unsafe restore path ancestor") from exc
            try:
                _validate_directory(child, uid=uid, device=device)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor, components[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _create_planned_directory(
    root_fd: int,
    relative: str,
    *,
    destination_info: os.stat_result,
) -> None:
    parent_fd, name = _open_parent(
        root_fd,
        relative,
        uid=destination_info.st_uid,
        device=destination_info.st_dev,
    )
    try:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RestoreTransactionError("planned restore directory appeared concurrently")
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        child_fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        try:
            os.fchown(child_fd, destination_info.st_uid, destination_info.st_gid)
            os.fchmod(child_fd, 0o700)
            _validate_directory(
                child_fd,
                uid=destination_info.st_uid,
                device=destination_info.st_dev,
            )
            os.fsync(child_fd)
        finally:
            os.close(child_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        raise RestoreTransactionError("cannot create planned restore directory") from exc
    finally:
        os.close(parent_fd)


def _install_open_source(
    source_fd: int,
    source_expected: dict,
    parent_fd: int,
    name: str,
    target: dict,
    temporary: str,
    *,
    crash_at: str | None = None,
    crash_label: str | None = None,
) -> None:
    try:
        output_fd = os.open(temporary, _CREATE_FLAGS, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        raise RestoreTransactionError("cannot create temporary restore file") from exc
    success = False
    try:
        _copy_fd(source_fd, output_fd, source_expected)
        os.fchown(output_fd, target["uid"], target["gid"])
        os.fchmod(output_fd, target["mode"])
        os.fsync(output_fd)
        written = os.fstat(output_fd)
        if (
            not stat.S_ISREG(written.st_mode)
            or written.st_nlink != 1
            or written.st_uid != target["uid"]
            or written.st_gid != target["gid"]
            or stat.S_IMODE(written.st_mode) != target["mode"]
            or written.st_size != target["size"]
        ):
            raise RestoreTransactionError("temporary restore file failed verification")
        success = True
    finally:
        os.close(output_fd)
        if not success:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileNotFoundError:
                pass
    if crash_label is not None:
        _cutpoint(crash_label, crash_at)
    try:
        os.replace(
            temporary,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    except OSError as exc:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileNotFoundError:
            pass
        raise RestoreTransactionError("cannot publish restored file") from exc


def _verify_source_unchanged(
    stage_fd: int, stage_info: os.stat_result, entry: dict
) -> None:
    source_fd = _open_relative_file(
        stage_fd,
        entry["path"],
        uid=stage_info.st_uid,
        device=stage_info.st_dev,
        allow_shared_write=True,
    )
    try:
        metadata = _metadata_from_open_file(
            source_fd, uid=stage_info.st_uid, device=stage_info.st_dev
        )
    finally:
        os.close(source_fd)
    if _runtime_identity(metadata) != _runtime_identity(entry["source"]):
        raise RestoreTransactionError("restore source changed after preflight")


def _cutpoint(label: str, crash_at: str | None) -> None:
    if crash_at == label:
        os._exit(97)


def _apply_prepared_transaction(
    root_fd: int,
    state_fd: int,
    destination_info: os.stat_result,
    stage_fd: int,
    stage_info: os.stat_result,
    transaction_name: str,
    journal: dict,
    plan: list[dict],
    *,
    crash_at: str | None,
) -> None:
    transaction_fd = _open_transaction_directory(
        state_fd,
        transaction_name,
        uid=destination_info.st_uid,
        device=destination_info.st_dev,
    )
    try:
        journal["state"] = "applying"
        _write_journal(transaction_fd, journal)
        _cutpoint("after_applying", crash_at)
        for relative in journal["created_directories"]:
            _create_planned_directory(
                root_fd, relative, destination_info=destination_info
            )
        _cutpoint("after_directories", crash_at)
        for index, entry in enumerate(plan, start=1):
            current = _inspect_destination_file(
                root_fd,
                entry["path"],
                uid=destination_info.st_uid,
                device=destination_info.st_dev,
            )
            if entry["old"]["exists"]:
                if not _same_runtime_file(current, entry["old"]):
                    raise RestoreTransactionError(
                        "restore destination changed after preflight"
                    )
            elif current["exists"] or current["parent_missing"]:
                raise RestoreTransactionError(
                    "missing restore destination changed after preflight"
                )
            if entry["old"]["exists"] and _matches_target_metadata(
                current, entry["new"]
            ):
                if entry["source"] is not None:
                    _verify_source_unchanged(stage_fd, stage_info, entry)
            else:
                parent_fd, name = _open_parent(
                    root_fd,
                    entry["path"],
                    uid=destination_info.st_uid,
                    device=destination_info.st_dev,
                )
                try:
                    if entry["new"] == {"exists": False}:
                        _cutpoint(f"during_target_{index}", crash_at)
                        try:
                            os.unlink(name, dir_fd=parent_fd)
                            os.fsync(parent_fd)
                        except OSError as exc:
                            raise RestoreTransactionError(
                                "cannot publish restored deletion"
                            ) from exc
                    else:
                        source_fd = _open_relative_file(
                            stage_fd,
                            entry["path"],
                            uid=stage_info.st_uid,
                            device=stage_info.st_dev,
                            allow_shared_write=True,
                        )
                        try:
                            _install_open_source(
                                source_fd,
                                entry["source"],
                                parent_fd,
                                name,
                                entry["new"],
                                f".csr-restore-{transaction_name}-{index:06d}",
                                crash_at=crash_at,
                                crash_label=f"during_target_{index}",
                            )
                        finally:
                            os.close(source_fd)
                finally:
                    os.close(parent_fd)
                installed = _inspect_destination_file(
                    root_fd,
                    entry["path"],
                    uid=destination_info.st_uid,
                    device=destination_info.st_dev,
                )
                if not _matches_target_metadata(installed, entry["new"]):
                    raise RestoreTransactionError("restored file failed verification")
            _cutpoint(f"after_target_{index}", crash_at)
        os.fsync(root_fd)
        _cutpoint("after_targets", crash_at)
        journal["state"] = "committed"
        journal["outcome"] = "applied"
        _write_journal(transaction_fd, journal)
        _cutpoint("after_committed", crash_at)
    finally:
        os.close(transaction_fd)


def _open_backup_directory(
    transaction_fd: int, destination_info: os.stat_result
) -> int:
    return _open_child_directory(
        transaction_fd,
        "backups",
        uid=destination_info.st_uid,
        device=destination_info.st_dev,
    )


def _validate_transaction_temporary(
    root_fd: int,
    relative: str,
    temporary: str,
    *,
    destination_info: os.stat_result,
) -> bool:
    parent_fd, _name = _open_parent_if_exists(
        root_fd,
        relative,
        uid=destination_info.st_uid,
        device=destination_info.st_dev,
    )
    if parent_fd is None:
        return False
    try:
        try:
            info = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != destination_info.st_uid
            or info.st_dev != destination_info.st_dev
            or info.st_nlink != 1
            or info.st_size > MAX_FILE_BYTES
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise RestoreTransactionError("unsafe stale restore temporary file")
        return True
    finally:
        os.close(parent_fd)


def _remove_transaction_temporary(
    root_fd: int,
    relative: str,
    temporary: str,
    *,
    destination_info: os.stat_result,
) -> None:
    parent_fd, _name = _open_parent_if_exists(
        root_fd,
        relative,
        uid=destination_info.st_uid,
        device=destination_info.st_dev,
    )
    if parent_fd is None:
        return
    try:
        try:
            info = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != destination_info.st_uid
            or info.st_dev != destination_info.st_dev
            or info.st_nlink != 1
            or info.st_size > MAX_FILE_BYTES
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise RestoreTransactionError("unsafe stale restore temporary file")
        os.unlink(temporary, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _rollback_transaction(
    root_fd: int,
    state_fd: int,
    destination_info: os.stat_result,
    transaction_name: str,
    journal: dict,
    *,
    crash_at: str | None = None,
) -> None:
    transaction_fd = _open_transaction_directory(
        state_fd,
        transaction_name,
        uid=destination_info.st_uid,
        device=destination_info.st_dev,
    )
    backup_fd = -1
    try:
        backup_fd = _open_backup_directory(transaction_fd, destination_info)
        backup_metadata: dict[str, dict] = {}
        current_metadata: dict[str, dict] = {}
        stale_temporaries: list[tuple[str, str]] = []
        # Validate every backup and destination before changing any destination.
        for index, entry in enumerate(journal["entries"], start=1):
            old = entry["old"]
            if old["exists"]:
                descriptor = os.open(old["backup"], _READ_FLAGS, dir_fd=backup_fd)
                try:
                    metadata = _metadata_from_open_file(
                        descriptor,
                        uid=destination_info.st_uid,
                        device=destination_info.st_dev,
                        expected_mode=0o600,
                    )
                finally:
                    os.close(descriptor)
                if (metadata["sha256"], metadata["size"]) != (
                    old["sha256"],
                    old["size"],
                ):
                    raise RestoreTransactionError("restore backup digest mismatch")
                backup_metadata[entry["path"]] = metadata
            current = _inspect_destination_file(
                root_fd,
                entry["path"],
                uid=destination_info.st_uid,
                device=destination_info.st_dev,
            )
            if old["exists"]:
                if current["parent_missing"]:
                    raise RestoreTransactionError(
                        "pre-existing restore parent disappeared"
                    )
                if current["exists"] and not (
                    _matches_public_metadata(current, old)
                    or _matches_target_metadata(current, entry["new"])
                ):
                    raise RestoreTransactionError(
                        "destination diverged before restore rollback"
                    )
            elif current["exists"] and not _matches_target_metadata(
                current, entry["new"]
            ):
                raise RestoreTransactionError(
                    "new restore destination diverged before rollback"
                )
            current_metadata[entry["path"]] = current
            for temporary in (
                f".csr-restore-{transaction_name}-{index:06d}",
                f".csr-rollback-{transaction_name}-{index:06d}",
            ):
                if _validate_transaction_temporary(
                    root_fd,
                    entry["path"],
                    temporary,
                    destination_info=destination_info,
                ):
                    stale_temporaries.append((entry["path"], temporary))

        for relative, temporary in stale_temporaries:
            _remove_transaction_temporary(
                root_fd,
                relative,
                temporary,
                destination_info=destination_info,
            )

        for index, entry in enumerate(journal["entries"], start=1):
            old = entry["old"]
            current = current_metadata[entry["path"]]
            if old["exists"]:
                if not _matches_public_metadata(current, old):
                    parent_fd, name = _open_parent(
                        root_fd,
                        entry["path"],
                        uid=destination_info.st_uid,
                        device=destination_info.st_dev,
                    )
                    try:
                        descriptor = os.open(
                            old["backup"], _READ_FLAGS, dir_fd=backup_fd
                        )
                        try:
                            _install_open_source(
                                descriptor,
                                backup_metadata[entry["path"]],
                                parent_fd,
                                name,
                                {
                                    key: old[key]
                                    for key in ("sha256", "size", "mode", "uid", "gid")
                                },
                                f".csr-rollback-{transaction_name}-{index:06d}",
                                crash_at=crash_at,
                                crash_label=f"rollback_during_target_{index}",
                            )
                        finally:
                            os.close(descriptor)
                    finally:
                        os.close(parent_fd)
            elif current["exists"]:
                parent_fd, name = _open_parent(
                    root_fd,
                    entry["path"],
                    uid=destination_info.st_uid,
                    device=destination_info.st_dev,
                )
                try:
                    os.unlink(name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except OSError as exc:
                    raise RestoreTransactionError(
                        "cannot remove partially restored file"
                    ) from exc
                finally:
                    os.close(parent_fd)
            _cutpoint(f"rollback_after_target_{index}", crash_at)

        for relative in reversed(journal["created_directories"]):
            parent_fd, name = _open_parent_if_exists(
                root_fd,
                relative,
                uid=destination_info.st_uid,
                device=destination_info.st_dev,
            )
            if parent_fd is None:
                continue
            try:
                try:
                    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != destination_info.st_uid
                    or info.st_dev != destination_info.st_dev
                    or stat.S_IMODE(info.st_mode) != 0o700
                ):
                    raise RestoreTransactionError(
                        "unsafe created directory during restore rollback"
                    )
                try:
                    os.rmdir(name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except OSError as exc:
                    raise RestoreTransactionError(
                        "created restore directory is no longer empty"
                    ) from exc
            finally:
                os.close(parent_fd)
        os.fsync(root_fd)
        journal["state"] = "committed"
        journal["outcome"] = "rolled-back"
        _write_journal(transaction_fd, journal)
        _cutpoint("rollback_after_committed", crash_at)
    finally:
        if backup_fd >= 0:
            os.close(backup_fd)
        os.close(transaction_fd)


def _recover_existing(
    root_fd: int,
    state_fd: int,
    destination_info: os.stat_result,
    *,
    crash_at: str | None = None,
) -> None:
    names = sorted(os.listdir(state_fd))
    preparing = [name for name in names if name.startswith(".preparing-")]
    cleanup = [name for name in names if name.startswith(".cleanup-")]
    transactions = [name for name in names if TRANSACTION_RE.fullmatch(name)]
    unknown = [
        name
        for name in names
        if name != ".lock"
        and name not in preparing
        and name not in cleanup
        and name not in transactions
    ]
    if unknown:
        raise RestoreTransactionError("unexpected entry in restore transaction state")
    for name in preparing:
        suffix = name.removeprefix(".preparing-")
        if not TRANSACTION_RE.fullmatch(suffix):
            raise RestoreTransactionError("invalid preparing restore transaction")
        _cleanup_transaction(
            state_fd,
            name,
            uid=destination_info.st_uid,
            device=destination_info.st_dev,
            preparing=True,
        )
    for name in cleanup:
        suffix = name.removeprefix(".cleanup-")
        if not TRANSACTION_RE.fullmatch(suffix):
            raise RestoreTransactionError("invalid cleanup restore transaction")
        _cleanup_transaction(
            state_fd,
            name,
            uid=destination_info.st_uid,
            device=destination_info.st_dev,
            preparing=True,
        )
    if len(transactions) > 1:
        raise RestoreTransactionError("multiple restore transactions require inspection")
    for name in transactions:
        transaction_fd = _open_transaction_directory(
            state_fd,
            name,
            uid=destination_info.st_uid,
            device=destination_info.st_dev,
        )
        try:
            # An interrupted atomic journal replacement is never authoritative.
            if "journal.json.new" in os.listdir(transaction_fd):
                _unlink_safe_regular(
                    transaction_fd,
                    "journal.json.new",
                    uid=destination_info.st_uid,
                    device=destination_info.st_dev,
                )
            journal = _load_journal(transaction_fd, name, destination_info)
        finally:
            os.close(transaction_fd)
        if journal["state"] != "committed":
            _rollback_transaction(
                root_fd,
                state_fd,
                destination_info,
                name,
                journal,
                crash_at=crash_at,
            )
        _cleanup_transaction(
            state_fd,
            name,
            uid=destination_info.st_uid,
            device=destination_info.st_dev,
        )


def recover_pending_transactions(
    destination: Path | str, *, _test_crash_at: str | None = None
) -> None:
    """Recover or clean every transaction before another restore begins."""
    destination = Path(destination)
    with _locked_destination(destination) as (
        root_fd,
        state_fd,
        destination_info,
    ):
        _recover_existing(
            root_fd,
            state_fd,
            destination_info,
            crash_at=_test_crash_at,
        )


def transactional_apply(
    stage: Path | str,
    destination: Path | str,
    modes: dict[str, int | None],
    *,
    replace: bool,
    replace_paths: frozenset[str] = frozenset(),
    _test_crash_at: str | None = None,
) -> None:
    """Atomically apply a staged tree with durable crash rollback."""
    stage = Path(stage)
    destination = Path(destination)
    stage_fd, stage_info = _stage_root(stage)
    try:
        with _locked_destination(destination) as (
            root_fd,
            state_fd,
            destination_info,
        ):
            _recover_existing(root_fd, state_fd, destination_info)
            plan, created_directories = _preflight(
                stage_fd,
                stage_info,
                root_fd,
                destination_info,
                modes,
                replace=replace,
                replace_paths=replace_paths,
            )
            if not plan:
                return
            transaction_name, journal = _prepare_transaction(
                root_fd,
                state_fd,
                destination_info,
                plan,
                created_directories,
            )
            _cutpoint("after_prepared", _test_crash_at)
            try:
                _apply_prepared_transaction(
                    root_fd,
                    state_fd,
                    destination_info,
                    stage_fd,
                    stage_info,
                    transaction_name,
                    journal,
                    plan,
                    crash_at=_test_crash_at,
                )
            except BaseException as apply_error:
                try:
                    transaction_fd = _open_transaction_directory(
                        state_fd,
                        transaction_name,
                        uid=destination_info.st_uid,
                        device=destination_info.st_dev,
                    )
                    try:
                        authoritative = _load_journal(
                            transaction_fd, transaction_name, destination_info
                        )
                    finally:
                        os.close(transaction_fd)
                    if authoritative["state"] != "committed":
                        _rollback_transaction(
                            root_fd,
                            state_fd,
                            destination_info,
                            transaction_name,
                            authoritative,
                        )
                    _cleanup_transaction(
                        state_fd,
                        transaction_name,
                        uid=destination_info.st_uid,
                        device=destination_info.st_dev,
                    )
                except BaseException as rollback_error:
                    raise RestoreTransactionError(
                        "restore failed and durable rollback requires the next restore"
                    ) from rollback_error
                raise apply_error
            _cleanup_transaction(
                state_fd,
                transaction_name,
                uid=destination_info.st_uid,
                device=destination_info.st_dev,
                crash_at=_test_crash_at,
            )
    finally:
        os.close(stage_fd)
