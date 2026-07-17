"""Bounded no-follow reads for immutable and runtime metadata."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any


class SecureFileError(ValueError):
    pass


def read_secure_json(
    path: Path,
    *,
    expected_uid: int,
    expected_mode: int,
    maximum: int = 65_536,
) -> dict[str, Any]:
    if type(maximum) is not int or maximum < 2:
        raise ValueError("maximum must be an integer of at least two bytes")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != expected_mode
        ):
            raise SecureFileError(f"unsafe owner/type/mode for metadata: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise SecureFileError(f"oversized metadata: {path}")
        data = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecureFileError(f"invalid JSON metadata {path}: {exc}") from exc
    if type(value) is not dict:
        raise SecureFileError(f"metadata is not an object: {path}")
    return value


__all__ = ["SecureFileError", "read_secure_json"]
