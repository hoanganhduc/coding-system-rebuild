#!/usr/bin/env python3
"""Parse the private, data-only owner-settings file without shell evaluation."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys


MAX_OWNER_SETTINGS_BYTES = 64 * 1024
MAX_OWNER_SETTING_VALUE_BYTES = 4096
OWNER_SETTING_KEYS = (
    "CLASSROOM50_ORG_ALLOWLIST",
    "TELEGRAM_CHAT_ID",
    "MOLBOOK_AGENT_ID",
    "MOLTBOOK_ALLOWLIST",
    "MOLTBOOK_AUTONOMOUS",
    "MOLTBOOK_COLOR",
    "MOLTBOOK_PROFILE",
    "MOLTBOOK_URL",
    "MOLTBOOK_WORKSPACE",
    "CSR_OWNER_TIMEZONE",
    "CSR_RSS_DIGEST_ONCALENDAR",
    "CSR_RCLONE_DEST",
    "CSR_OWNER_RCLONE_DEST",
    "CSR_ESCROW_GDRIVE",
    "CSR_ESCROW_GH_REPO",
)
OWNER_SETTING_KEY_SET = frozenset(OWNER_SETTING_KEYS)
KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
FORBIDDEN_VALUE_FRAGMENTS = ("$(", "${", "`", ";", "<(", ">(")


class OwnerSettingsError(ValueError):
    """The owner-settings file is unsafe or outside its data contract."""


def _metadata_snapshot(information: os.stat_result) -> tuple[int, ...]:
    """Return the security-relevant identity/content snapshot for one file."""

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


def _parent_metadata_is_safe(information: os.stat_result) -> bool:
    if not stat.S_ISDIR(information.st_mode) or information.st_uid not in (
        0,
        os.getuid(),
    ):
        return False
    writable = stat.S_IMODE(information.st_mode) & 0o022
    if not writable:
        return True
    # A root-owned sticky directory (normally /tmp) prevents another user from
    # replacing an owner-controlled child.  All other group/world-writable
    # ancestry is rejected.
    return bool(
        information.st_uid == 0
        and information.st_mode & stat.S_ISVTX
        and information.st_mode & stat.S_IWOTH
    )


def _open_bound_parent(path: Path) -> tuple[int, list[int], str]:
    """Open every ancestor with openat/O_NOFOLLOW and return the final parent."""

    absolute = os.path.abspath(os.fspath(path))
    components = [component for component in absolute.split(os.sep) if component]
    if not components:
        raise OwnerSettingsError("owner settings path is invalid")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors: list[int] = []
    try:
        current = os.open(os.sep, directory_flags)
        descriptors.append(current)
        if not _parent_metadata_is_safe(os.fstat(current)):
            raise OwnerSettingsError("owner settings parent metadata is unsafe")
        for component in components[:-1]:
            if component in (".", ".."):
                raise OwnerSettingsError("owner settings path is invalid")
            current = os.open(component, directory_flags, dir_fd=current)
            descriptors.append(current)
            if not _parent_metadata_is_safe(os.fstat(current)):
                raise OwnerSettingsError("owner settings parent metadata is unsafe")
        return descriptors[-1], descriptors, components[-1]
    except (OSError, OwnerSettingsError) as exc:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        if isinstance(exc, OwnerSettingsError):
            raise
        if isinstance(exc, FileNotFoundError):
            raise
        raise OwnerSettingsError("owner settings parent cannot be opened safely") from exc


def _validate_value(value: str) -> None:
    if (
        not value
        or value != value.strip()
        or len(value.encode("utf-8")) > MAX_OWNER_SETTING_VALUE_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or any(fragment in value for fragment in FORBIDDEN_VALUE_FRAGMENTS)
    ):
        raise OwnerSettingsError("owner setting value is invalid")


def parse_owner_settings(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OwnerSettingsError("owner settings are not UTF-8") from exc
    values: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            continue
        if raw != raw.strip() or "=" not in raw:
            raise OwnerSettingsError("owner settings must use literal KEY=value lines")
        key, value = raw.split("=", 1)
        if (
            KEY_RE.fullmatch(key) is None
            or key not in OWNER_SETTING_KEY_SET
            or key in values
        ):
            raise OwnerSettingsError("owner setting name is unsupported or duplicated")
        _validate_value(value)
        values[key] = value
    return values


def render_owner_settings(values: dict[str, str]) -> bytes:
    if set(values) - OWNER_SETTING_KEY_SET:
        raise OwnerSettingsError("owner setting name is unsupported")
    for value in values.values():
        _validate_value(value)
    lines = ["# coding-system private owner settings; literal KEY=value data only\n"]
    lines.extend(f"{key}={values[key]}\n" for key in OWNER_SETTING_KEYS if key in values)
    return "".join(lines).encode("utf-8")


def read_owner_private_bytes(
    path: Path, *, required: bool = False, max_bytes: int = MAX_OWNER_SETTINGS_BYTES
) -> bytes | None:
    """Read one owner-private file through the same bound, stable descriptor."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    try:
        parent, descriptors, filename = _open_bound_parent(path)
        descriptor = os.open(filename, flags, dir_fd=parent)
    except FileNotFoundError:
        for parent_descriptor in reversed(descriptors):
            os.close(parent_descriptor)
        if required:
            raise OwnerSettingsError("owner-private file is missing")
        return None
    except OwnerSettingsError:
        raise
    except OSError as exc:
        for parent_descriptor in reversed(descriptors):
            os.close(parent_descriptor)
        raise OwnerSettingsError("owner settings cannot be opened safely") from exc
    try:
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) != 0o600
            or information.st_nlink != 1
            or information.st_size > max_bytes
        ):
            raise OwnerSettingsError("owner-private file metadata is unsafe")
        before = _metadata_snapshot(information)
        remaining = information.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise OwnerSettingsError("owner-private file is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OwnerSettingsError("owner-private file changed while reading")
        if _metadata_snapshot(os.fstat(descriptor)) != before:
            raise OwnerSettingsError("owner-private file changed while reading")
    finally:
        os.close(descriptor)
        for parent_descriptor in reversed(descriptors):
            os.close(parent_descriptor)
    return b"".join(chunks)


def read_owner_settings(path: Path, *, required: bool = False) -> dict[str, str]:
    payload = read_owner_private_bytes(path, required=required)
    return {} if payload is None else parse_owner_settings(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("emit0", "get", "validate"))
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--key", choices=OWNER_SETTING_KEYS, help="the setting printed by get")
    arguments = parser.parse_args(argv)
    if arguments.command == "get" and arguments.key is None:
        parser.error("get needs --key")
    try:
        values = read_owner_settings(arguments.path)
    except OwnerSettingsError:
        print("owner-settings: invalid private settings file", file=sys.stderr)
        return 2
    if arguments.command == "emit0":
        output = sys.stdout.buffer
        for key in OWNER_SETTING_KEYS:
            if key not in values:
                continue
            output.write(key.encode("ascii") + b"\0")
            output.write(values[key].encode("utf-8") + b"\0")
        output.flush()
    elif arguments.command == "get":
        print(values.get(arguments.key, ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
