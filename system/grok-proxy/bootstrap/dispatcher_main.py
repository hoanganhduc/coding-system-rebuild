#!/usr/bin/env python3
"""Signed zipapp entry point for the closed installer dispatcher."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import runpy
import secrets
import shutil
import stat
import sys
from typing import Iterator
import zipfile


REQUIRED_TOP_LEVEL = (
    "install-release.py",
    "grok-remote",
    "egress.sh",
    "socks-netns.py",
    "vpngate-connect.sh",
    "sanitize.awk",
)
BROKER_CANDIDATES = ("vpn-broker", "vpn-broker.py")
PACKAGE_ROOT = "grok_ms"
EXCLUDED_PACKAGE_PARTS = frozenset({"__pycache__", "tests", "test"})
MANDATORY_PACKAGE_FILES = frozenset(
    {
        "grok_ms/__init__.py",
        "grok_ms/release_admission.py",
        "grok_ms/managed_profile.py",
        "grok_ms/rung_admission.py",
    }
)
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_FILES = 4096
MAX_PATH_BYTES = 512
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
FAILURE_MESSAGE = b"grok-dispatcher: EXTRACTION_FAILURE\n"


class DispatcherExtractionError(RuntimeError):
    """The signed archive is not the closed dispatcher shape."""


def _safe_relative_path(value: str) -> bool:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    if not encoded or len(encoded) > MAX_PATH_BYTES:
        return False
    if value.startswith("/") or value.endswith("/"):
        return False
    for byte in encoded:
        if not (
            ord("A") <= byte <= ord("Z")
            or ord("a") <= byte <= ord("z")
            or ord("0") <= byte <= ord("9")
            or byte in b"/._-"
        ):
            return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _allowed_member(name: str) -> bool:
    if name == "__main__.py" or name in REQUIRED_TOP_LEVEL:
        return True
    if name in BROKER_CANDIDATES:
        return True
    parts = name.split("/")
    return (
        len(parts) >= 2
        and parts[0] == PACKAGE_ROOT
        and name.endswith(".py")
        and all(
            part not in EXCLUDED_PACKAGE_PARTS and not part.startswith(".")
            for part in parts
        )
    )


def _entry_mode(information: zipfile.ZipInfo) -> int:
    raw_mode = information.external_attr >> 16
    mode = stat.S_IMODE(raw_mode)
    if stat.S_IFMT(raw_mode) != stat.S_IFREG or mode not in {0o644, 0o755}:
        raise DispatcherExtractionError("archive member has unsafe mode or type")
    return mode


def _validated_entries(archive: zipfile.ZipFile) -> list[tuple[zipfile.ZipInfo, int]]:
    if archive.comment != b"":
        raise DispatcherExtractionError("archive comment is forbidden")
    entries = archive.infolist()
    if not entries or len(entries) > MAX_FILES:
        raise DispatcherExtractionError("archive file-count bound violated")

    names: list[str] = []
    total = 0
    validated: list[tuple[zipfile.ZipInfo, int]] = []
    for information in entries:
        name = information.filename
        if (
            not _safe_relative_path(name)
            or not _allowed_member(name)
            or information.is_dir()
            or information.create_system != 3
            or information.date_time != FIXED_ZIP_TIME
            or information.compress_type != zipfile.ZIP_STORED
            or information.compress_size != information.file_size
            or information.file_size < 0
            or information.file_size > MAX_FILE_BYTES
            or information.extra != b""
            or information.comment != b""
            or information.flag_bits & 0x09
        ):
            raise DispatcherExtractionError("archive member violates closed format")
        mode = _entry_mode(information)
        names.append(name)
        total += information.file_size
        if total > MAX_ARCHIVE_BYTES:
            raise DispatcherExtractionError("archive aggregate size bound violated")
        validated.append((information, mode))

    if names != sorted(names) or len(names) != len(set(names)):
        raise DispatcherExtractionError("archive members are duplicated or unsorted")
    present = set(names)
    required = {"__main__.py", *REQUIRED_TOP_LEVEL, *MANDATORY_PACKAGE_FILES}
    if not required.issubset(present):
        raise DispatcherExtractionError("archive lacks a required dispatcher member")
    if sum(name in present for name in BROKER_CANDIDATES) != 1:
        raise DispatcherExtractionError("archive broker selection is ambiguous")
    return validated


def _write_all(file_descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(file_descriptor, data[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise DispatcherExtractionError("short extraction write")
        offset += written


def _open_parent(
    root_descriptor: int,
    parts: list[str],
    *,
    expected_uid: int,
    expected_gid: int,
) -> int:
    descriptor = os.dup(root_descriptor)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=descriptor)
            information = os.fstat(child)
            if (
                not stat.S_ISDIR(information.st_mode)
                or information.st_uid != expected_uid
                or information.st_gid != expected_gid
                or stat.S_IMODE(information.st_mode) != 0o700
            ):
                os.close(child)
                raise DispatcherExtractionError("unsafe extraction directory")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _extract_entry(
    archive: zipfile.ZipFile,
    information: zipfile.ZipInfo,
    mode: int,
    root_descriptor: int,
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    parts = information.filename.split("/")
    parent = _open_parent(
        root_descriptor,
        parts[:-1],
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    file_descriptor = -1
    try:
        file_descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        os.fchown(file_descriptor, expected_uid, expected_gid)
        total = 0
        with archive.open(information, "r") as source:
            while True:
                chunk = source.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > information.file_size:
                    raise DispatcherExtractionError("archive member expanded unexpectedly")
                _write_all(file_descriptor, chunk)
        if total != information.file_size:
            raise DispatcherExtractionError("archive member was truncated")
        os.fchmod(file_descriptor, mode)
        opened = os.fstat(file_descriptor)
        named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(named.st_mode)
            or named.st_nlink != 1
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
            or (named.st_uid, named.st_gid) != (expected_uid, expected_gid)
            or stat.S_IMODE(named.st_mode) != mode
        ):
            raise DispatcherExtractionError("extracted member changed identity")
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        os.close(parent)


@contextmanager
def extracted_dispatcher(
    archive_path: str | os.PathLike[str],
    *,
    run_parent: Path = Path("/run"),
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> Iterator[Path]:
    """Extract one validated signed dispatcher beneath a trusted runtime root."""

    parent_information = run_parent.lstat()
    if (
        run_parent.is_symlink()
        or not stat.S_ISDIR(parent_information.st_mode)
        or parent_information.st_uid != expected_uid
        or parent_information.st_gid != expected_gid
        or stat.S_IMODE(parent_information.st_mode) & 0o022
    ):
        raise DispatcherExtractionError("runtime extraction parent is unsafe")
    parent_descriptor = os.open(
        run_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    root_descriptor = -1
    temporary_name = ""
    try:
        opened_parent = os.fstat(parent_descriptor)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            parent_information.st_dev,
            parent_information.st_ino,
        ):
            raise DispatcherExtractionError("runtime extraction parent changed")
        for _attempt in range(16):
            temporary_name = f".grok-bootstrap-{secrets.token_hex(16)}"
            try:
                os.mkdir(temporary_name, 0o700, dir_fd=parent_descriptor)
                break
            except FileExistsError:
                temporary_name = ""
        if not temporary_name:
            raise DispatcherExtractionError("cannot allocate extraction directory")
        root_descriptor = os.open(
            temporary_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
        os.fchown(root_descriptor, expected_uid, expected_gid)
        os.fchmod(root_descriptor, 0o700)
        root_information = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_information.st_mode)
            or (root_information.st_uid, root_information.st_gid)
            != (expected_uid, expected_gid)
            or stat.S_IMODE(root_information.st_mode) != 0o700
        ):
            raise DispatcherExtractionError("temporary extraction root is unsafe")

        with zipfile.ZipFile(archive_path, "r") as archive:
            entries = _validated_entries(archive)
            for information, mode in entries:
                _extract_entry(
                    archive,
                    information,
                    mode,
                    root_descriptor,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                )
        named_root = os.stat(
            temporary_name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (named_root.st_dev, named_root.st_ino) != (
            root_information.st_dev,
            root_information.st_ino,
        ):
            raise DispatcherExtractionError("temporary extraction root changed")
        yield run_parent / temporary_name
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)
        if temporary_name:
            shutil.rmtree(temporary_name, dir_fd=parent_descriptor)
        os.close(parent_descriptor)


def main() -> int:
    if os.geteuid() != 0:
        os.write(2, FAILURE_MESSAGE)
        return 126
    try:
        with extracted_dispatcher(sys.argv[0]) as source:
            runpy.run_path(os.fspath(source / "install-release.py"), run_name="__main__")
    except (DispatcherExtractionError, OSError, zipfile.BadZipFile):
        os.write(2, FAILURE_MESSAGE)
        return 126
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
