#!/usr/bin/env python3
"""Secure local-state operations used by ``bin/init-private.sh``.

The shell entry point intentionally delegates secret reads and writes here so
they are descriptor-bound, reject links/unsafe metadata, and fail if a source
changes while it is being inspected.  No command prints secret material.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

LIB_DIR = Path(__file__).resolve().parent
if os.fspath(LIB_DIR) not in sys.path:
    sys.path.insert(0, os.fspath(LIB_DIR))

from owner_settings import (
    OwnerSettingsError,
    _open_bound_parent,
    read_owner_settings,
)
MAX_KEYS_BYTES = 1024 * 1024
RECOVERY_SIGNING_KEY_SHA256 = (
    "c869a7314609cc6a6c167a3dc7e4f8456b7c0ac11eeb9dd091db0d99b3b82898"
)
MAX_PRIVATE_FILE_BYTES = 1024 * 1024
MAX_PASSPHRASE_BYTES = 4096
MAX_DENYLIST_BYTES = 1024 * 1024
PRIVATE_FILE_FLAGS = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)
DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class InitPrivateError(RuntimeError):
    """A redaction-safe private-state contract failure."""


def _stable_identity(information: os.stat_result) -> tuple[int, ...]:
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


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise InitPrivateError("private-state write did not make progress")
        view = view[written:]


def _validate_private_payload(payload: bytes) -> None:
    body = payload[:-1] if payload.endswith(b"\n") else payload
    if (
        not payload
        or len(payload) > MAX_PASSPHRASE_BYTES
        or b"\x00" in payload
        or b"\n" in body
        or any(byte < 0x20 and byte not in (0x0A,) for byte in payload)
        or len(body) < 32
    ):
        raise InitPrivateError("owner archive passphrase has an invalid shape")


def _read_private_file(
    path: Path,
    *,
    required: bool = False,
    max_bytes: int = MAX_PRIVATE_FILE_BYTES,
    owner_only: bool = True,
) -> bytes | None:
    """Read an owner-only regular file through stable bound descriptors."""

    descriptors: list[int] = []
    descriptor = -1
    try:
        parent, descriptors, filename = _open_bound_parent(path)
        try:
            descriptor = os.open(filename, PRIVATE_FILE_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            if required:
                raise InitPrivateError("required private file is missing")
            return None
        before = os.fstat(descriptor)
        linked_before = os.stat(filename, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(linked_before.st_mode)
            or (before.st_dev, before.st_ino)
            != (linked_before.st_dev, linked_before.st_ino)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or (
                stat.S_IMODE(before.st_mode) != 0o600
                if owner_only
                else stat.S_IMODE(before.st_mode) & 0o022
            )
            or before.st_size > max_bytes
        ):
            raise InitPrivateError("private file metadata is unsafe")
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise InitPrivateError("private file was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise InitPrivateError("private file exceeded its inspected size")
        after = os.fstat(descriptor)
        linked_after = os.stat(filename, dir_fd=parent, follow_symlinks=False)
        if (
            _stable_identity(before) != _stable_identity(after)
            or _stable_identity(linked_before) != _stable_identity(linked_after)
            or (after.st_dev, after.st_ino)
            != (linked_after.st_dev, linked_after.st_ino)
        ):
            raise InitPrivateError("private file changed while reading")
        return b"".join(chunks)
    except FileNotFoundError as exc:
        if required:
            raise InitPrivateError("required private file is missing") from exc
        return None
    except OwnerSettingsError as exc:
        raise InitPrivateError("private file ancestry is unsafe") from exc
    except OSError as exc:
        raise InitPrivateError("private file path is unsafe or unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for parent_descriptor in reversed(descriptors):
            os.close(parent_descriptor)


def _ensure_private_directory(path: Path) -> None:
    """Create/validate one owner-only directory without following links."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    components = [part for part in absolute.parts if part != os.sep]
    if not components:
        raise InitPrivateError("private directory path is invalid")
    current = os.open(os.sep, DIRECTORY_FLAGS)
    try:
        for index, component in enumerate(components):
            if component in ("", ".", ".."):
                raise InitPrivateError("private directory path is invalid")
            final = index == len(components) - 1
            try:
                next_descriptor = os.open(
                    component, DIRECTORY_FLAGS, dir_fd=current
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                    os.fsync(current)
                    next_descriptor = os.open(
                        component, DIRECTORY_FLAGS, dir_fd=current
                    )
                except OSError as exc:
                    raise InitPrivateError(
                        "private directory cannot be created safely"
                    ) from exc
            except OSError as exc:
                raise InitPrivateError("private directory path is unsafe") from exc
            information = os.fstat(next_descriptor)
            if not stat.S_ISDIR(information.st_mode):
                os.close(next_descriptor)
                raise InitPrivateError("private directory path is unsafe")
            if final:
                if information.st_uid != os.geteuid():
                    os.close(next_descriptor)
                    raise InitPrivateError("private directory has the wrong owner")
                if stat.S_IMODE(information.st_mode) != 0o700:
                    os.fchmod(next_descriptor, 0o700)
                    information = os.fstat(next_descriptor)
                if stat.S_IMODE(information.st_mode) != 0o700:
                    os.close(next_descriptor)
                    raise InitPrivateError("private directory mode is unsafe")
            elif information.st_mode & 0o022:
                safe_sticky_root = (
                    information.st_uid == 0
                    and information.st_mode & stat.S_ISVTX
                    and information.st_mode & stat.S_IWOTH
                )
                if not safe_sticky_root:
                    os.close(next_descriptor)
                    raise InitPrivateError("private directory ancestry is unsafe")
            os.close(current)
            current = next_descriptor
    finally:
        os.close(current)


def _create_exclusive_private(path: Path, payload: bytes) -> bool:
    """Create a 0600 file and return False when another valid file won."""

    descriptors: list[int] = []
    descriptor = -1
    try:
        parent, descriptors, filename = _open_bound_parent(path)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(filename, flags, 0o600, dir_fd=parent)
        except FileExistsError:
            return False
        _write_all(descriptor, payload)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.fsync(parent)
        return True
    except OwnerSettingsError as exc:
        raise InitPrivateError("private output ancestry is unsafe") from exc
    except OSError as exc:
        raise InitPrivateError("private output cannot be created safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for parent_descriptor in reversed(descriptors):
            os.close(parent_descriptor)


def ensure_owner_passphrase(owner: Path, legacy: Path) -> str:
    existing = _read_private_file(owner, max_bytes=MAX_PASSPHRASE_BYTES)
    if existing is not None:
        _validate_private_payload(existing)
        return "existing"

    legacy_payload = _read_private_file(legacy, max_bytes=MAX_PASSPHRASE_BYTES)
    if legacy_payload is None:
        payload = (secrets.token_urlsafe(48) + "\n").encode("ascii")
        outcome = "generated"
    else:
        _validate_private_payload(legacy_payload)
        payload = legacy_payload.rstrip(b"\n") + b"\n"
        outcome = "migrated"

    if not _create_exclusive_private(owner, payload):
        winner = _read_private_file(
            owner, required=True, max_bytes=MAX_PASSPHRASE_BYTES
        )
        assert winner is not None
        _validate_private_payload(winner)
        return "existing"
    verified = _read_private_file(
        owner, required=True, max_bytes=MAX_PASSPHRASE_BYTES
    )
    if verified is None or not secrets.compare_digest(verified, payload):
        raise InitPrivateError("owner archive passphrase verification failed")
    return outcome


def _read_optional_json(path: Path) -> dict[str, object] | None:
    # These legacy skill configs contain identifiers used only to seed the
    # leak denylist.  Several historical installs used mode 0644, so admit
    # read-only-to-others metadata while still rejecting any group/world write.
    raw = _read_private_file(path, owner_only=False)
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InitPrivateError("private JSON configuration is invalid") from exc
    if not isinstance(value, dict):
        raise InitPrivateError("private JSON configuration has the wrong shape")
    return value


def _private_directory_names(path: Path) -> list[str]:
    descriptors: list[int] = []
    directory = -1
    try:
        parent, descriptors, filename = _open_bound_parent(path)
        try:
            directory = os.open(filename, DIRECTORY_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            return []
        information = os.fstat(directory)
        if (
            information.st_uid != os.geteuid()
            or stat.S_IMODE(information.st_mode) & 0o077
        ):
            raise InitPrivateError("private directory metadata is unsafe")
        return sorted(os.listdir(directory))
    except OwnerSettingsError as exc:
        raise InitPrivateError("private directory ancestry is unsafe") from exc
    except OSError as exc:
        raise InitPrivateError("private directory cannot be inspected safely") from exc
    finally:
        if directory >= 0:
            os.close(directory)
        for parent_descriptor in reversed(descriptors):
            os.close(parent_descriptor)


def _render_denylist(entries: set[str]) -> bytes:
    normalized: list[str] = []
    for entry in sorted(entries):
        if (
            not entry
            or entry != entry.strip()
            or "\n" in entry
            or "\r" in entry
            or "\x00" in entry
            or len(entry.encode("utf-8")) > 4096
        ):
            raise InitPrivateError("denylist entry has an invalid shape")
        normalized.append(entry)
    payload = "".join(f"{entry}\n" for entry in normalized).encode("utf-8")
    if len(payload) > MAX_DENYLIST_BYTES:
        raise InitPrivateError("denylist exceeds its size bound")
    return payload


def _replace_private_file(path: Path, payload: bytes) -> None:
    descriptors: list[int] = []
    descriptor = -1
    temporary = f".{path.name}.tmp-{secrets.token_hex(8)}"
    try:
        parent, descriptors, filename = _open_bound_parent(path)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary, flags, 0o600, dir_fd=parent)
        _write_all(descriptor, payload)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, filename, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    except OwnerSettingsError as exc:
        raise InitPrivateError("private output ancestry is unsafe") from exc
    except OSError as exc:
        raise InitPrivateError("private output cannot be replaced safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if descriptors:
            try:
                os.unlink(temporary, dir_fd=descriptors[-1])
            except FileNotFoundError:
                pass
        for parent_descriptor in reversed(descriptors):
            os.close(parent_descriptor)


def seed_denylist(home: Path, path: Path) -> int:
    try:
        owner = read_owner_settings(home / ".secrets.env", required=True)
    except OwnerSettingsError as exc:
        raise InitPrivateError("owner settings cannot be read safely") from exc

    entries: set[str] = set()
    # Private identifiers and the owner's schedule and storage locations; the
    # timezone alone is country-level and is not treated as private.
    for key in (
        "TELEGRAM_CHAT_ID",
        "MOLBOOK_AGENT_ID",
        "CSR_RSS_DIGEST_ONCALENDAR",
        "CSR_RCLONE_DEST",
        "CSR_OWNER_RCLONE_DEST",
        "CSR_ESCROW_GDRIVE",
        "CSR_ESCROW_GH_REPO",
    ):
        if owner.get(key):
            entries.add(owner[key])

    config_candidates = (
        home / ".codex/runtime/workspace/skills/zotero/config.json",
        home / ".codex/runtime/workspace/skills/calibre/config.json",
        home / ".claude/skills/zotero/config.json",
        home / ".claude/skills/calibre/config.json",
        home / ".openclaw/workspace/skills/zotero/config.json",
        home / ".openclaw/workspace/skills/calibre/config.json",
    )
    identifier_name = re.compile(r"(user_id|folder_id|library_id)", re.I)
    for candidate in config_candidates:
        data = _read_optional_json(candidate)
        if data is None:
            continue
        for key, value in data.items():
            if identifier_name.search(key) and isinstance(value, (str, int)):
                rendered = str(value)
                if len(rendered) >= 6:
                    entries.add(rendered)

    openclaw = _read_private_file(home / ".openclaw/openclaw.json")
    if openclaw is not None:
        try:
            text = openclaw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InitPrivateError("OpenClaw configuration is not UTF-8") from exc
        entries.update(
            match.group(1)
            for match in re.finditer(
                r"https://[a-z0-9-]+\.(tail[0-9a-f]+)\.ts\.net", text
            )
        )

    for filename in _private_directory_names(
        home / ".config/openclaw/google-chat"
    ):
        match = re.fullmatch(r"(.+)-[0-9a-f]{12}\.json", filename)
        if match:
            entries.add(match.group(1))

    existing = _read_private_file(path, max_bytes=MAX_DENYLIST_BYTES)
    if existing is not None:
        try:
            existing_text = existing.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InitPrivateError("existing denylist is not UTF-8") from exc
        entries.update(line.strip() for line in existing_text.splitlines() if line.strip())

    _replace_private_file(path, _render_denylist(entries))
    return len(entries)


def _public_ed25519_identity(raw: bytes) -> bytes:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise InitPrivateError("recovery signing public key is not ASCII") from exc
    if len(lines) != 1:
        raise InitPrivateError("recovery signing public key shape is invalid")
    fields = lines[0].split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise InitPrivateError("unsupported recovery signing public key")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InitPrivateError("recovery signing public key shape is invalid") from exc
    if not decoded:
        raise InitPrivateError("recovery signing public key shape is invalid")
    return f"{fields[0]} {fields[1]}".encode("ascii")


def _read_public_regular(path: Path, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        linked = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InitPrivateError("pinned public trust root is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            path.is_symlink()
            or not stat.S_ISREG(linked.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or (linked.st_dev, linked.st_ino) != (before.st_dev, before.st_ino)
            or before.st_size > max_bytes
        ):
            raise InitPrivateError("pinned public trust root is unsafe")
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise InitPrivateError("pinned public trust root was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise InitPrivateError("pinned public trust root exceeded its inspected size")
        after = os.fstat(descriptor)
        if _stable_identity(before) != _stable_identity(after):
            raise InitPrivateError("pinned public trust root changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _derive_ed25519_public_identity(descriptor: int) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        result = subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-y",
                "-f",
                f"/proc/self/fd/{descriptor}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(descriptor,),
            env={
                "HOME": "/",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            start_new_session=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InitPrivateError(
            "recovery signing public-key derivation could not run"
        ) from exc
    if result.returncode != 0 or len(result.stdout) > MAX_KEYS_BYTES:
        raise InitPrivateError("recovery signing authority is unusable")
    return _public_ed25519_identity(result.stdout)


def verify_signing_authority(
    key: Path,
    trusted_public: Path,
    *,
    expected_public_sha256: str = RECOVERY_SIGNING_KEY_SHA256,
) -> None:
    private_raw = _read_private_file(
        key, required=True, max_bytes=MAX_PRIVATE_FILE_BYTES
    )
    trusted_raw = _read_public_regular(trusted_public, max_bytes=MAX_KEYS_BYTES)
    assert private_raw is not None
    if (
        not re.fullmatch(r"[0-9a-f]{64}", expected_public_sha256)
        or not secrets.compare_digest(
            hashlib.sha256(trusted_raw).hexdigest(), expected_public_sha256
        )
    ):
        raise InitPrivateError("recovery signing public trust root is not pinned")
    trusted_identity = _public_ed25519_identity(trusted_raw)

    if not hasattr(os, "memfd_create"):
        raise InitPrivateError("sealed in-memory signing-key verification is unavailable")
    descriptor = os.memfd_create(
        "csr-recovery-signing",
        getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0),
    )
    try:
        _write_all(descriptor, private_raw)
        os.fchmod(descriptor, 0o600)
        seal_mask = (
            getattr(fcntl, "F_SEAL_SEAL", 0)
            | getattr(fcntl, "F_SEAL_SHRINK", 0)
            | getattr(fcntl, "F_SEAL_GROW", 0)
            | getattr(fcntl, "F_SEAL_WRITE", 0)
        )
        if not seal_mask or not hasattr(fcntl, "F_ADD_SEALS"):
            raise InitPrivateError("sealed in-memory signing-key verification is unavailable")
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seal_mask)
        derived_identity = _derive_ed25519_public_identity(descriptor)
    finally:
        os.close(descriptor)
    if not secrets.compare_digest(derived_identity, trusted_identity):
        raise InitPrivateError("recovery signing authority differs from the pinned trust root")


def verify_private_file(path: Path, *, max_bytes: int, nonempty: bool) -> bool:
    payload = _read_private_file(path, max_bytes=max_bytes)
    if payload is None:
        return False
    if nonempty and not payload:
        raise InitPrivateError("private file is empty")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    directory = subparsers.add_parser("ensure-directory")
    directory.add_argument("--path", type=Path, required=True)

    passphrase = subparsers.add_parser("ensure-owner-passphrase")
    passphrase.add_argument("--owner", type=Path, required=True)
    passphrase.add_argument("--legacy", type=Path, required=True)

    denylist = subparsers.add_parser("seed-denylist")
    denylist.add_argument("--home", type=Path, required=True)
    denylist.add_argument("--path", type=Path, required=True)

    signing = subparsers.add_parser("verify-signing")
    signing.add_argument("--key", type=Path, required=True)
    signing.add_argument("--trusted-public", type=Path, required=True)

    private_file = subparsers.add_parser("verify-private-file")
    private_file.add_argument("--path", type=Path, required=True)
    private_file.add_argument("--max-bytes", type=int, default=MAX_PRIVATE_FILE_BYTES)
    private_file.add_argument("--nonempty", action="store_true")

    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "ensure-directory":
            _ensure_private_directory(arguments.path)
        elif arguments.command == "ensure-owner-passphrase":
            print(ensure_owner_passphrase(arguments.owner, arguments.legacy))
        elif arguments.command == "seed-denylist":
            count = seed_denylist(arguments.home, arguments.path)
            print(f"denylist has {count} entries")
        elif arguments.command == "verify-signing":
            verify_signing_authority(arguments.key, arguments.trusted_public)
        else:
            if not 0 < arguments.max_bytes <= MAX_PRIVATE_FILE_BYTES:
                raise InitPrivateError("private file size bound is invalid")
            if not verify_private_file(
                arguments.path,
                max_bytes=arguments.max_bytes,
                nonempty=arguments.nonempty,
            ):
                raise InitPrivateError("required private file is missing")
    except (InitPrivateError, OSError, ValueError) as exc:
        print(f"init-private state: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
