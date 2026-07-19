#!/usr/bin/env python3
"""Publish one pinned ai-agents-skills Git tree as immutable root-owned input."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile


COMPONENT_BASE = Path("/usr/local/libexec")
COMPONENT_ROOT = COMPONENT_BASE / "coding-system/components/ai-agents-skills"
COMPONENT_PARTS = ("coding-system", "components", "ai-agents-skills")
PIN_RE = re.compile(r"^[0-9a-f]{40}$")
STAGE_RE = re.compile(r"^\.stage-([0-9a-f]{40})-([0-9a-f]{24})$")
TREE_RECORD_RE = re.compile(
    rb"(100644|100755) blob ([0-9a-f]{40})\t([^\0]+)\Z"
)
REQUIRED_EXECUTABLE = "installer/bootstrap.sh"
MAX_TREE_RECORD_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
AT_FDCWD = -100
RENAME_NOREPLACE = 1


class ComponentError(RuntimeError):
    pass


def require_pin(value: str) -> str:
    if PIN_RE.fullmatch(value) is None:
        raise ComponentError("component pin is not one full SHA-1 commit ID")
    return value


def _raise_walk_error(error: OSError) -> None:
    raise ComponentError(
        f"cannot inspect immutable component tree: {error.filename}: {error.strerror}"
    ) from error


def _require_directory(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ComponentError(f"cannot inspect component directory {path}: {exc}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or (info.st_uid, info.st_gid) != (uid, gid)
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise ComponentError(f"component directory has unsafe authority: {path}")
    return info


def ensure_component_root(
    *,
    base: Path = COMPONENT_BASE,
    parts: tuple[str, ...] = COMPONENT_PARTS,
    uid: int = 0,
    gid: int = 0,
) -> Path:
    """Create only missing descendants of an already trusted fixed base."""

    current = Path(base)
    _require_directory(current, uid=uid, gid=gid, mode=0o755)
    for name in parts:
        if not name or name in {".", ".."} or "/" in name:
            raise ComponentError("component directory name is invalid")
        current = current / name
        created = False
        try:
            os.mkdir(current, 0o755)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise ComponentError(f"cannot create component directory {current}: {exc}") from exc
        _require_directory(current, uid=uid, gid=gid, mode=0o755)
        if created:
            _fsync_directory(current)
            _fsync_directory(current.parent)
    return current


def validate_archive_source(raw: bytes, pin: str) -> dict[str, tuple[int, str]]:
    """Reject links, submodules, unsafe names, and an incomplete bootstrap tree."""

    require_pin(pin)
    if not raw or len(raw) > MAX_TREE_RECORD_BYTES or not raw.endswith(b"\0"):
        raise ComponentError("pinned Git tree inventory is empty, oversized, or truncated")
    records = raw[:-1].split(b"\0")
    if len(records) > MAX_ENTRIES:
        raise ComponentError("pinned Git tree inventory exceeds its entry limit")
    paths: set[str] = set()
    expected: dict[str, tuple[int, str]] = {}
    for record in records:
        match = TREE_RECORD_RE.fullmatch(record)
        if match is None:
            raise ComponentError("pinned Git tree contains a link, submodule, or invalid entry")
        try:
            path = match.group(3).decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ComponentError("pinned Git tree contains a non-UTF-8 path") from exc
        pure = PurePosixPath(path)
        if (
            pure.is_absolute()
            or not pure.parts
            or len(path.encode("utf-8")) > 4096
            or any(part in {"", ".", ".."} for part in pure.parts)
            or path in paths
        ):
            raise ComponentError("pinned Git tree contains an unsafe or duplicate path")
        paths.add(path)
        expected[path] = (
            0o755 if match.group(1) == b"100755" else 0o644,
            match.group(2).decode("ascii"),
        )
    if expected.get(REQUIRED_EXECUTABLE, (None,))[0] != 0o755:
        raise ComponentError("pinned Git tree lacks its executable installer bootstrap")
    return expected


def _git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _git_command(repo: Path, *arguments: str) -> list[str]:
    return [
        "/usr/bin/git",
        "--no-replace-objects",
        "--no-optional-locks",
        "-C",
        str(repo),
        *arguments,
    ]


def _read_exact(stream: object, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise ComponentError("Git blob stream ended before its declared size")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def emit_raw_tar(repo: Path, pin: str, output: object) -> None:
    """Emit raw Git blobs without checkout/archive attribute transformations."""

    pin = require_pin(pin)
    repo = Path(repo)
    try:
        repo_info = repo.lstat()
        git_info = (repo / ".git").lstat()
    except OSError as exc:
        raise ComponentError(f"cannot inspect ai-agents-skills object repository: {exc}") from exc
    if (
        not repo.is_absolute()
        or repo.is_symlink()
        or not stat.S_ISDIR(repo_info.st_mode)
        or (repo / ".git").is_symlink()
        or not stat.S_ISDIR(git_info.st_mode)
    ):
        raise ComponentError("ai-agents-skills object repository is unsafe")
    try:
        inventory = subprocess.run(
            _git_command(repo, "ls-tree", "-rz", "--full-tree", pin),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ComponentError("pinned Git tree inventory timed out") from exc
    if inventory.returncode != 0 or len(inventory.stdout) > MAX_TREE_RECORD_BYTES:
        raise ComponentError("cannot read the pinned Git tree inventory")
    expected = validate_archive_source(inventory.stdout, pin)
    process = subprocess.Popen(
        _git_command(repo, "cat-file", "--batch"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_git_environment(),
    )
    assert process.stdin is not None and process.stdout is not None
    try:
        with tarfile.open(fileobj=output, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            directories = {
                parent.as_posix()
                for path in expected
                for parent in PurePosixPath(path).parents
                if parent.as_posix() != "."
            }
            for name in sorted(directories, key=lambda value: (value.count("/"), value)):
                information = tarfile.TarInfo(name + "/")
                information.type = tarfile.DIRTYPE
                information.mode = 0o755
                information.uid = information.gid = 0
                information.uname = information.gname = "root"
                information.mtime = 0
                archive.addfile(information)
            total_bytes = 0
            for path, (mode, expected_oid) in expected.items():
                process.stdin.write(expected_oid.encode("ascii") + b"\n")
                process.stdin.flush()
                header = process.stdout.readline(256)
                fields = header.rstrip(b"\n").split()
                if (
                    len(header) > 255
                    or not header.endswith(b"\n")
                    or len(fields) != 3
                    or fields[0].decode("ascii", "replace") != expected_oid
                    or fields[1] != b"blob"
                    or not fields[2].isdigit()
                ):
                    raise ComponentError(f"Git returned an invalid blob header: {path}")
                size = int(fields[2])
                total_bytes += size
                if size > MAX_FILE_BYTES or total_bytes > MAX_TOTAL_BYTES:
                    raise ComponentError("pinned Git blobs exceed their size bounds")
                data = _read_exact(process.stdout, size)
                if process.stdout.read(1) != b"\n":
                    raise ComponentError(f"Git blob record is not terminated: {path}")
                digest = hashlib.sha1(f"blob {size}\0".encode("ascii") + data).hexdigest()
                if digest != expected_oid:
                    raise ComponentError(f"Git blob content disagrees with its object ID: {path}")
                information = tarfile.TarInfo(path)
                information.type = tarfile.REGTYPE
                information.mode = mode
                information.uid = information.gid = 0
                information.uname = information.gname = "root"
                information.mtime = 0
                information.size = size
                archive.addfile(information, io.BytesIO(data))
        process.stdin.close()
        returncode = process.wait(timeout=30)
        if returncode != 0:
            raise ComponentError("Git raw-blob transport failed")
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


def create_stage(root: Path, pin: str, *, uid: int = 0, gid: int = 0) -> Path:
    require_pin(pin)
    _require_directory(root, uid=uid, gid=gid, mode=0o755)
    for _attempt in range(128):
        stage = root / f".stage-{pin}-{secrets.token_hex(12)}"
        try:
            os.mkdir(stage, 0o700)
        except FileExistsError:
            continue
        os.chown(stage, uid, gid)
        os.chmod(stage, 0o700)
        _require_directory(stage, uid=uid, gid=gid, mode=0o700)
        _fsync_directory(root)
        return stage
    raise ComponentError("cannot allocate a unique component staging directory")


def _stage_for(root: Path, pin: str, stage: Path) -> Path:
    pin = require_pin(pin)
    stage = Path(stage)
    match = STAGE_RE.fullmatch(stage.name)
    if not stage.is_absolute() or stage.parent != root or match is None or match.group(1) != pin:
        raise ComponentError("component staging path is outside its fixed authority")
    return stage


def _tree_entries(
    root: Path,
    *,
    uid: int,
    gid: int,
) -> tuple[list[Path], list[Path]]:
    root_info = root.lstat()
    device = root_info.st_dev
    directories: list[Path] = []
    files: list[Path] = []
    total_bytes = 0
    entries = 0
    for directory, dirnames, filenames in os.walk(
        root, topdown=True, followlinks=False, onerror=_raise_walk_error
    ):
        dirnames.sort()
        filenames.sort()
        parent = Path(directory)
        for name in dirnames:
            child = parent / name
            info = child.lstat()
            entries += 1
            if (
                child.is_symlink()
                or not stat.S_ISDIR(info.st_mode)
                or info.st_dev != device
                or (info.st_uid, info.st_gid) != (uid, gid)
            ):
                raise ComponentError(f"component contains an unsafe directory: {child}")
            directories.append(child)
        for name in filenames:
            child = parent / name
            info = child.lstat()
            entries += 1
            total_bytes += info.st_size
            if (
                child.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or info.st_dev != device
                or info.st_nlink != 1
                or (info.st_uid, info.st_gid) != (uid, gid)
                or info.st_size < 0
                or info.st_size > MAX_FILE_BYTES
            ):
                raise ComponentError(f"component contains an unsafe file: {child}")
            files.append(child)
        if entries > MAX_ENTRIES or total_bytes > MAX_TOTAL_BYTES:
            raise ComponentError("component tree exceeds its inventory bounds")
    return directories, files


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def verify_extracted_archive(
    root: Path,
    raw: bytes,
    pin: str,
    stage: Path,
    *,
    uid: int = 0,
    gid: int = 0,
) -> None:
    """Bind extracted bytes and modes back to every exact Git blob record."""

    expected = validate_archive_source(raw, pin)
    stage = _stage_for(root, pin, stage)
    _require_directory(stage, uid=uid, gid=gid, mode=0o700)
    _directories, files = _tree_entries(stage, uid=uid, gid=gid)
    actual_paths = {path.relative_to(stage).as_posix() for path in files}
    if actual_paths != set(expected):
        raise ComponentError("extracted component file set differs from the pinned Git tree")
    for path in files:
        relative = path.relative_to(stage).as_posix()
        expected_mode, expected_oid = expected[relative]
        info = path.lstat()
        actual_mode = stat.S_IMODE(info.st_mode)
        expected_executable = expected_mode == 0o755
        if (
            actual_mode & 0o7000
            or bool(actual_mode & 0o111) is not expected_executable
            or (actual_mode & 0o111) not in {0, 0o111}
        ):
            raise ComponentError(f"extracted component mode differs from Git: {relative}")
        digest = hashlib.sha1(f"blob {info.st_size}\0".encode("ascii"))
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        if digest.hexdigest() != expected_oid:
            raise ComponentError(f"extracted component blob differs from Git: {relative}")


def _seal_stage(root: Path, *, uid: int, gid: int) -> None:
    if stat.S_IMODE(root.lstat().st_mode) != 0o700:
        raise ComponentError("component staging root mode is unsafe")
    directories, files = _tree_entries(root, uid=uid, gid=gid)
    for path in files:
        mode = stat.S_IMODE(path.lstat().st_mode)
        if mode & 0o7000 or (mode & 0o111) not in {0, 0o111}:
            raise ComponentError(f"Git archive file mode is invalid: {path}")
        os.chmod(path, 0o555 if mode & 0o111 else 0o444)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for path in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        mode = stat.S_IMODE(path.lstat().st_mode)
        if mode & 0o7000 or mode & 0o111 != 0o111:
            raise ComponentError(f"Git archive directory mode is invalid: {path}")
        os.chmod(path, 0o555)
        _fsync_directory(path)
    os.chmod(root, 0o555)
    _fsync_directory(root)


def _sealed_manifest(
    root: Path,
    *,
    uid: int,
    gid: int,
) -> dict[str, tuple[object, ...]]:
    _require_directory(root, uid=uid, gid=gid, mode=0o555)
    directories, files = _tree_entries(root, uid=uid, gid=gid)
    manifest: dict[str, tuple[object, ...]] = {}
    for path in directories:
        if stat.S_IMODE(path.lstat().st_mode) != 0o555:
            raise ComponentError(f"immutable component directory mode changed: {path}")
        manifest[path.relative_to(root).as_posix()] = ("directory", 0o555)
    for path in files:
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if mode not in {0o444, 0o555}:
            raise ComponentError(f"immutable component file mode changed: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        manifest[path.relative_to(root).as_posix()] = (
            "file",
            mode,
            info.st_size,
            digest.hexdigest(),
        )
    required = root / REQUIRED_EXECUTABLE
    if manifest.get(REQUIRED_EXECUTABLE, ())[:2] != ("file", 0o555):
        raise ComponentError("immutable component installer bootstrap is absent or inert")
    return manifest


def _rename_noreplace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise ComponentError("renameat2(RENAME_NOREPLACE) is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(target),
        RENAME_NOREPLACE,
    )
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(code, os.strerror(code), target)
        raise ComponentError(
            f"cannot publish immutable component without replacement: {os.strerror(code)}"
        )


def _remove_stage(root: Path, pin: str, stage: Path, *, uid: int, gid: int) -> None:
    stage = _stage_for(root, pin, stage)
    if not os.path.lexists(stage):
        return
    info = stage.lstat()
    if stage.is_symlink() or not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != (uid, gid):
        raise ComponentError("refusing to discard an unsafe component stage")
    for directory, dirnames, _filenames in os.walk(
        stage, topdown=True, followlinks=False, onerror=_raise_walk_error
    ):
        os.chmod(directory, 0o700)
        for name in dirnames:
            child = Path(directory) / name
            child_info = child.lstat()
            if child.is_symlink() or not stat.S_ISDIR(child_info.st_mode):
                raise ComponentError("refusing to discard a stage containing a link")
    shutil.rmtree(stage)
    _fsync_directory(root)


def publish_stage(
    root: Path,
    pin: str,
    stage: Path,
    *,
    uid: int = 0,
    gid: int = 0,
) -> Path:
    pin = require_pin(pin)
    _require_directory(root, uid=uid, gid=gid, mode=0o755)
    stage = _stage_for(root, pin, stage)
    _require_directory(stage, uid=uid, gid=gid, mode=0o700)
    _seal_stage(stage, uid=uid, gid=gid)
    staged_manifest = _sealed_manifest(stage, uid=uid, gid=gid)
    target = root / pin
    if os.path.lexists(target):
        if _sealed_manifest(target, uid=uid, gid=gid) != staged_manifest:
            raise ComponentError("published component does not match the pinned Git tree")
        _remove_stage(root, pin, stage, uid=uid, gid=gid)
        return target
    try:
        _rename_noreplace(stage, target)
    except FileExistsError:
        if _sealed_manifest(target, uid=uid, gid=gid) != staged_manifest:
            raise ComponentError("concurrent component publication disagreed")
        _remove_stage(root, pin, stage, uid=uid, gid=gid)
    _fsync_directory(root)
    _sealed_manifest(target, uid=uid, gid=gid)
    return target


def verify_component(
    root: Path,
    pin: str,
    *,
    uid: int = 0,
    gid: int = 0,
) -> Path:
    pin = require_pin(pin)
    _require_directory(root, uid=uid, gid=gid, mode=0o755)
    target = root / pin
    _sealed_manifest(target, uid=uid, gid=gid)
    return target


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-archive-source")
    validate.add_argument("pin")
    emit = subparsers.add_parser("emit-raw-tar")
    emit.add_argument("pin")
    emit.add_argument("repo", type=Path)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("pin")
    publish = subparsers.add_parser("publish")
    publish.add_argument("pin")
    publish.add_argument("stage", type=Path)
    extracted = subparsers.add_parser("verify-extracted")
    extracted.add_argument("pin")
    extracted.add_argument("stage", type=Path)
    verify = subparsers.add_parser("verify")
    verify.add_argument("pin")
    discard = subparsers.add_parser("discard")
    discard.add_argument("pin")
    discard.add_argument("stage", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "validate-archive-source":
        raw = sys.stdin.buffer.read(MAX_TREE_RECORD_BYTES + 1)
        validate_archive_source(raw, args.pin)
        return 0
    if args.command == "emit-raw-tar":
        emit_raw_tar(args.repo, args.pin, sys.stdout.buffer)
        return 0
    if os.geteuid() != 0 or os.getegid() != 0:
        raise ComponentError("immutable component publication requires root")
    root = ensure_component_root()
    if args.command == "prepare":
        print(create_stage(root, args.pin))
    elif args.command == "verify-extracted":
        raw = sys.stdin.buffer.read(MAX_TREE_RECORD_BYTES + 1)
        verify_extracted_archive(root, raw, args.pin, args.stage)
    elif args.command == "publish":
        print(publish_stage(root, args.pin, args.stage))
    elif args.command == "verify":
        print(verify_component(root, args.pin))
    elif args.command == "discard":
        _remove_stage(root, args.pin, args.stage, uid=0, gid=0)
    else:
        raise AssertionError("unreachable command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ComponentError as exc:
        print(f"aas-component: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
