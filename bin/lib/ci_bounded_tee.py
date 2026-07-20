#!/usr/bin/python3
"""Copy stdin to stdout and one newly created CI log under a hard byte limit."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys


MAXIMUM_LIMIT = 16 * 1024 * 1024
PREFIX_LIMIT = 1024 * 1024


class CaptureError(RuntimeError):
    """The bounded capture contract failed."""


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise CaptureError("short-write")
        view = view[written:]


def _snapshot(information: os.stat_result) -> tuple[int, ...]:
    return (
        information.st_dev,
        information.st_ino,
        information.st_mode,
        information.st_uid,
        information.st_gid,
        information.st_nlink,
        information.st_size,
        information.st_mtime_ns,
        information.st_ctime_ns,
    )


def _leaf(path: Path) -> str:
    if path.is_absolute() or len(path.parts) != 1 or path.name in {"", ".", ".."}:
        raise CaptureError("unsafe-path")
    return path.name


def _read_prefix(directory: int, path: Path, maximum: int) -> bytes:
    name = _leaf(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = -1
    try:
        named_before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=directory)
        opened_before = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise CaptureError("unsafe-prefix") from exc
    try:
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_uid != os.geteuid()
            or opened_before.st_nlink != 1
            or opened_before.st_size < 0
            or opened_before.st_size > maximum
            or _snapshot(named_before) != _snapshot(opened_before)
        ):
            raise CaptureError("unsafe-prefix")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise CaptureError("unsafe-prefix")
        opened_after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            _snapshot(opened_before) != _snapshot(opened_after)
            or _snapshot(opened_after) != _snapshot(named_after)
        ):
            raise CaptureError("unsafe-prefix")
        return b"".join(chunks)
    except OSError as exc:
        raise CaptureError("unsafe-prefix") from exc
    finally:
        os.close(descriptor)


def _create_output(directory: int, path: Path) -> int:
    name = _leaf(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory)
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as exc:
        if "descriptor" in locals():
            os.close(descriptor)
        raise CaptureError("unsafe-output") from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o600
        or _snapshot(opened) != _snapshot(named)
    ):
        os.close(descriptor)
        raise CaptureError("unsafe-output")
    return descriptor


def capture(output: Path, limit: int, prefix: Path | None = None) -> bool:
    """Create ``output`` and return true only when its byte limit is not exceeded."""

    if limit < 1 or limit > MAXIMUM_LIMIT:
        raise CaptureError("invalid-limit")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(".", directory_flags)
    try:
        prefix_bytes = (
            _read_prefix(directory, prefix, min(PREFIX_LIMIT, limit))
            if prefix is not None
            else b""
        )
        descriptor = _create_output(directory, output)
    finally:
        os.close(directory)
    remaining_limit = limit - len(prefix_bytes)
    total = 0
    overflow = False
    try:
        _write_all(descriptor, prefix_bytes)
        while True:
            chunk = os.read(0, min(64 * 1024, remaining_limit + 1 - total))
            if not chunk:
                break
            remaining = remaining_limit - total
            admitted = chunk[:remaining]
            if admitted:
                _write_all(descriptor, admitted)
                _write_all(1, admitted)
                total += len(admitted)
            if len(chunk) > len(admitted):
                overflow = True
                break
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return not overflow


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prefix", type=Path)
    parser.add_argument("--limit", type=int, required=True)
    args = parser.parse_args()
    try:
        complete = capture(args.output, args.limit, args.prefix)
    except (CaptureError, OSError):
        print("bounded-stream: capture failed", file=sys.stderr)
        return 2
    if not complete:
        print("bounded-stream: output limit exceeded", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
