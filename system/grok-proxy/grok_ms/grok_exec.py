"""Secure Grok executable identity and exact-descriptor execution helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import AbstractSet, Mapping, NoReturn, Sequence


_RELEASE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_HASH_CHUNK = 1024 * 1024
_MAX_FIXTURE_SCRIPT = 1024 * 1024
_MAX_MODEL_CACHE = 1024 * 1024
_REPAIRABLE_MODEL_CACHE_MODE = 0o664


class GrokExecutableError(ValueError):
    """The selected Grok executable is unsafe or changed during verification."""


def normalize_grok_model_cache(path: Path) -> bool:
    """Make one known cooperative cache mode private through its exact inode."""

    if not path.is_absolute() or path.name != "models_cache.json":
        raise GrokExecutableError("Grok model cache path is invalid")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_descriptor = os.open(path.parent, directory_flags)
    except FileNotFoundError:
        try:
            path.parent.lstat()
        except FileNotFoundError:
            return False
        raise GrokExecutableError("Grok model cache parent changed during normalization")
    except OSError as exc:
        raise GrokExecutableError("Grok model cache parent has an unsafe identity") from exc
    try:
        parent_before = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or parent_before.st_uid != os.getuid()
            or stat.S_IMODE(parent_before.st_mode) & 0o002
        ):
            raise GrokExecutableError("Grok model cache parent has an unsafe identity")
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path.name, file_flags, dir_fd=parent_descriptor)
        except FileNotFoundError:
            try:
                os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return False
            raise GrokExecutableError("Grok model cache changed during normalization")
        except OSError as exc:
            raise GrokExecutableError("Grok model cache has an unsafe identity") from exc
        try:
            before = os.fstat(descriptor)
            mode = stat.S_IMODE(before.st_mode)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or before.st_nlink != 1
                or not 0 <= before.st_size <= _MAX_MODEL_CACHE
            ):
                raise GrokExecutableError("Grok model cache has an unsafe identity")
            if mode & 0o022:
                if mode != _REPAIRABLE_MODEL_CACHE_MODE:
                    raise GrokExecutableError("Grok model cache has an unsafe mode")
                try:
                    os.fchmod(descriptor, 0o600)
                except OSError as exc:
                    raise GrokExecutableError(
                        "Grok model cache mode cannot be normalized"
                    ) from exc
            after = os.fstat(descriptor)
            try:
                named = os.stat(
                    path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                parent_named = path.parent.lstat()
            except OSError as exc:
                raise GrokExecutableError(
                    "Grok model cache changed during normalization"
                ) from exc

            stable_file = lambda value: (
                value.st_dev,
                value.st_ino,
                value.st_uid,
                value.st_gid,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
            )
            stable_parent = lambda value: (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_uid,
                value.st_gid,
            )
            if (
                stable_file(before) != stable_file(after)
                or stable_file(after) != stable_file(named)
                or stat.S_IMODE(after.st_mode) & 0o022
                or after.st_mode != named.st_mode
                or stable_parent(parent_before) != stable_parent(os.fstat(parent_descriptor))
                or stable_parent(parent_before) != stable_parent(parent_named)
            ):
                raise GrokExecutableError(
                    "Grok model cache changed during normalization"
                )
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)
    return True


def _fixture_script_exec(
    descriptor: int,
    argv: Sequence[str],
    environment: Mapping[str, str],
) -> NoReturn:
    """Delegate bounded shebang fixtures to the one descriptor bootstrap."""

    info = os.fstat(descriptor)
    if info.st_size > _MAX_FIXTURE_SCRIPT:
        raise GrokExecutableError("script Grok fixture exceeds its execution bound")
    data = os.pread(descriptor, info.st_size, 0)
    first = data.splitlines()[0] if data else b""
    if first not in {
        b"#!/usr/bin/env python3",
        b"#!/usr/bin/env bash",
        b"#!/usr/bin/env sh",
        b"#!/usr/bin/python3",
        b"#!/bin/bash",
        b"#!/bin/sh",
    }:
        raise GrokExecutableError("unsupported Grok fixture shebang")
    inherited = os.dup(descriptor)
    try:
        os.set_inheritable(inherited, True)
        helper = Path(__file__).with_name("fd_exec.py")
        os.execve(
            "/usr/bin/python3",
            [
                "/usr/bin/python3",
                "-I",
                str(helper),
                str(inherited),
                *list(argv),
            ],
            dict(environment),
        )
    finally:
        os.close(inherited)


def _normalize_allowed_owner_uids(
    allowed_owner_uids: AbstractSet[int] | None,
) -> frozenset[int]:
    if allowed_owner_uids is None:
        return frozenset((0, os.getuid()))
    if not allowed_owner_uids or any(
        type(uid) is not int or uid < 0 for uid in allowed_owner_uids
    ):
        raise GrokExecutableError("allowed Grok executable owners are invalid")
    return frozenset(allowed_owner_uids)


def _digest_fd(
    descriptor: int,
    allowed_owner_uids: frozenset[int],
) -> tuple[str, os.stat_result]:
    before = os.fstat(descriptor)
    mode = stat.S_IMODE(before.st_mode)
    if not stat.S_ISREG(before.st_mode):
        raise GrokExecutableError("Grok executable is not a regular file")
    if before.st_uid not in allowed_owner_uids:
        raise GrokExecutableError("Grok executable has an unexpected owner")
    if mode & 0o022:
        raise GrokExecutableError("Grok executable is group/world writable")
    if mode & 0o111 == 0:
        raise GrokExecutableError("Grok executable has no execute bit")
    if before.st_size <= 0:
        raise GrokExecutableError("Grok executable is empty")

    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(descriptor, min(_HASH_CHUNK, before.st_size - offset), offset)
        if not chunk:
            raise GrokExecutableError("Grok executable changed while hashing")
        digest.update(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after:
        raise GrokExecutableError("Grok executable changed while hashing")
    return "sha256:" + digest.hexdigest(), after


@dataclass(slots=True)
class VerifiedGrokExecutable:
    """An owned descriptor whose current bytes match one contract identity."""

    descriptor: int
    path: Path
    release_id: str
    allowed_owner_uids: frozenset[int]

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        allowed_owner_uids: AbstractSet[int] | None = None,
    ) -> "VerifiedGrokExecutable":
        owners = _normalize_allowed_owner_uids(allowed_owner_uids)
        if not path.is_absolute():
            raise GrokExecutableError("GROK_BIN must be an absolute path")
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise GrokExecutableError(f"cannot resolve Grok executable: {exc}") from exc
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(resolved, flags)
        except OSError as exc:
            raise GrokExecutableError(f"cannot open Grok executable: {exc}") from exc
        try:
            release_id, _ = _digest_fd(descriptor, owners)
            os.set_inheritable(descriptor, False)
            return cls(descriptor, resolved, release_id, owners)
        except BaseException:
            os.close(descriptor)
            raise

    @classmethod
    def adopt(
        cls,
        descriptor: int,
        expected_release_id: str,
        *,
        display_path: Path | None = None,
        allowed_owner_uids: AbstractSet[int] | None = None,
    ) -> "VerifiedGrokExecutable":
        if type(expected_release_id) is not str or _RELEASE_ID.fullmatch(expected_release_id) is None:
            raise GrokExecutableError("invalid expected Grok executable identity")
        owners = _normalize_allowed_owner_uids(allowed_owner_uids)
        os.set_inheritable(descriptor, False)
        actual, _ = _digest_fd(descriptor, owners)
        if actual != expected_release_id:
            raise GrokExecutableError("Grok executable descriptor does not match the contract")
        if display_path is None:
            try:
                candidate = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
            except OSError:
                candidate = Path("/proc/self/fd/grok")
            if not candidate.is_absolute():
                candidate = Path("/proc/self/fd/grok")
            display_path = candidate
        return cls(descriptor, display_path, actual, owners)

    def verify(self) -> None:
        actual, _ = _digest_fd(self.descriptor, self.allowed_owner_uids)
        if actual != self.release_id:
            raise GrokExecutableError("Grok executable changed after contract construction")

    def close(self) -> None:
        if self.descriptor < 0:
            return
        descriptor = self.descriptor
        self.descriptor = -1
        os.close(descriptor)

    def __enter__(self) -> "VerifiedGrokExecutable":
        return self

    def __exit__(self, _kind, _value, _traceback) -> None:
        self.close()

    def exec(
        self,
        argv: Sequence[str],
        environment: Mapping[str, str],
    ) -> NoReturn:
        """Revalidate and execute this exact open inode, never its mutable path."""

        self.verify()
        arguments = list(argv)
        if not arguments:
            raise GrokExecutableError("Grok executable argv is empty")
        try:
            os.execve(self.descriptor, arguments, dict(environment))
        except OSError as exc:
            # Linux fexecve with FD_CLOEXEC cannot launch a shebang script because
            # the interpreter needs the descriptor-backed path. Production Grok
            # is ELF; this narrow fallback keeps deterministic script fixtures.
            if exc.errno != 2 or os.pread(self.descriptor, 2, 0) != b"#!":
                raise
        _fixture_script_exec(self.descriptor, arguments, environment)


def grok_release_id(path: Path) -> str:
    with VerifiedGrokExecutable.open(path) as executable:
        return executable.release_id


__all__ = [
    "GrokExecutableError",
    "VerifiedGrokExecutable",
    "grok_release_id",
    "normalize_grok_model_cache",
]
