#!/usr/bin/env python3
"""Bind a NUL producer ledger to exact regular-file bytes and modes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile


class RecordError(RuntimeError):
    pass


def safe_relative(raw: bytes) -> str:
    value = os.fsdecode(raw)
    if not value or os.path.isabs(value):
        raise RecordError(f"unsafe output path: {value!r}")
    normalized = os.path.normpath(value).replace(os.sep, "/")
    if normalized in ("", ".", "..") or normalized.startswith("../"):
        raise RecordError(f"unsafe output path: {value!r}")
    if any(part in ("", ".", "..", ".git") for part in value.split("/")):
        raise RecordError(f"unsafe output path: {value!r}")
    return normalized


def regular_record(path: Path) -> dict[str, object]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RecordError(f"output is not a regular file: {path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    linked = path.lstat()
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        stat.S_IMODE(value.st_mode),
    )
    if (
        path.is_symlink()
        or not stat.S_ISREG(linked.st_mode)
        or identity(before) != identity(after)
        or identity(after) != identity(linked)
    ):
        raise RecordError(f"output changed while it was recorded: {path}")
    data = b"".join(chunks)
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "mode": stat.S_IMODE(after.st_mode),
    }


def write_atomic(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".refresh-records-", dir=path.parent)
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "ascii"
        )
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RecordError("short write while publishing output records")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        parent = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    repo = Path(args.repo).resolve()
    ledger = Path(args.ledger)
    raw = ledger.read_bytes()
    paths = [safe_relative(item) for item in raw.split(b"\0") if item]
    if len(paths) != len(set(paths)):
        raise RecordError("producer ledger contains duplicate paths")
    value = {
        "schema_version": 1,
        "ledger_sha256": hashlib.sha256(raw).hexdigest(),
        "records": {path: regular_record(repo / path) for path in sorted(paths)},
    }
    write_atomic(Path(args.output), value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
