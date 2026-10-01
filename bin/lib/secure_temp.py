#!/usr/bin/env python3
"""Owner-only temporary directories for recovery plaintext.

Recovery archives contain credentials in plaintext while they are being built,
validated, or restored.  The default tempfile location is commonly persistent
``/tmp``.  This module therefore admits only a validated tmpfs root by default.
Using a persistent filesystem requires both an explicit root and the exact
``CSR_RECOVERY_ALLOW_PERSISTENT_TMP=1`` acknowledgement.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Iterator


TMPDIR_ENV = "CSR_RECOVERY_TMPDIR"
PERSISTENT_OVERRIDE_ENV = "CSR_RECOVERY_ALLOW_PERSISTENT_TMP"
_MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")


class SecureTempError(RuntimeError):
    """A redaction-safe temporary-storage contract failure."""


def _unescape_mount_field(value: str) -> str:
    return _MOUNT_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _filesystem_type(path: Path, mountinfo_path: Path = Path("/proc/self/mountinfo")) -> str:
    try:
        resolved = path.resolve(strict=True)
        lines = mountinfo_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise SecureTempError("cannot determine recovery temporary filesystem") from exc

    best_length = -1
    best_type = ""
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
            mount_point = Path(_unescape_mount_field(fields[4]))
            filesystem = fields[separator + 1]
        except (ValueError, IndexError):
            continue
        try:
            resolved.relative_to(mount_point)
        except ValueError:
            continue
        length = len(mount_point.parts)
        if length > best_length:
            best_length = length
            best_type = filesystem
    if not best_type:
        raise SecureTempError("cannot determine recovery temporary filesystem")
    return best_type


def _open_validated_root(path: Path, *, require_tmpfs: bool) -> int:
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SecureTempError("recovery temporary root is unavailable or unsafe") from exc
    try:
        opened = os.fstat(descriptor)
        linked = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(linked.st_mode)
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & 0o077
        ):
            raise SecureTempError(
                "recovery temporary root must be an owner-only directory"
            )
        if require_tmpfs and _filesystem_type(Path(f"/proc/self/fd/{descriptor}")) != "tmpfs":
            raise SecureTempError("recovery temporary root is not on tmpfs")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _resolved_descriptor_path(descriptor: int) -> Path:
    try:
        return Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
    except OSError as exc:
        raise SecureTempError("recovery temporary root changed during validation") from exc


def _ensure_dev_shm_root() -> Path:
    parent = Path("/dev/shm")
    name = f"csr-recovery-{os.geteuid()}"
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_fd = os.open(parent, flags)
    except OSError as exc:
        raise SecureTempError("owner-only tmpfs recovery root is unavailable") from exc
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    finally:
        os.close(parent_fd)
    return parent / name


def select_secure_temp_root() -> Path:
    """Return a validated owner-only temporary root.

    An explicitly configured root is authoritative: an unsafe value is an
    error, never a reason to silently fall back elsewhere.
    """

    configured = os.environ.get(TMPDIR_ENV)
    allow_persistent = os.environ.get(PERSISTENT_OVERRIDE_ENV) == "1"
    if configured:
        candidate = Path(configured)
        descriptor = _open_validated_root(
            candidate, require_tmpfs=not allow_persistent
        )
        try:
            return _resolved_descriptor_path(descriptor)
        finally:
            os.close(descriptor)

    candidates: list[Path] = []
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        candidates.append(Path(runtime))
    candidates.append(Path(f"/run/user/{os.geteuid()}"))
    for candidate in candidates:
        try:
            descriptor = _open_validated_root(candidate, require_tmpfs=True)
        except SecureTempError:
            continue
        try:
            return _resolved_descriptor_path(descriptor)
        finally:
            os.close(descriptor)

    try:
        candidate = _ensure_dev_shm_root()
        descriptor = _open_validated_root(candidate, require_tmpfs=True)
    except SecureTempError:
        candidate = None
    else:
        try:
            return _resolved_descriptor_path(descriptor)
        finally:
            os.close(descriptor)

    if allow_persistent:
        raise SecureTempError(
            f"{PERSISTENT_OVERRIDE_ENV}=1 also requires an owner-only {TMPDIR_ENV}"
        )
    raise SecureTempError(
        "no owner-only tmpfs is available; set CSR_RECOVERY_TMPDIR to an "
        "owner-only directory and explicitly acknowledge persistent plaintext "
        "with CSR_RECOVERY_ALLOW_PERSISTENT_TMP=1"
    )


@contextmanager
def secure_temporary_directory(*, prefix: str) -> Iterator[str]:
    root = select_secure_temp_root()
    with tempfile.TemporaryDirectory(prefix=prefix, dir=root) as temporary:
        os.chmod(temporary, 0o700)
        yield temporary


def create_secure_temp_directory(*, prefix: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", prefix):
        raise SecureTempError("invalid recovery temporary-directory prefix")
    root = select_secure_temp_root()
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=root))
    os.chmod(path, 0o700)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("create", choices=("create",))
    parser.add_argument("--prefix", default="csr-recovery-")
    arguments = parser.parse_args(argv)
    try:
        print(create_secure_temp_directory(prefix=arguments.prefix))
        return 0
    except (SecureTempError, OSError) as exc:
        print(f"secure recovery temporary storage: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
