#!/usr/bin/env python3
"""Boundedly migrate shell exports into data-only owner/credential authorities."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys

LIB = Path(__file__).resolve().parent / "lib"
if os.fspath(LIB) not in sys.path:
    sys.path.insert(0, os.fspath(LIB))
from owner_settings import (  # noqa: E402
    OWNER_SETTING_KEYS,
    OWNER_SETTING_KEY_SET,
    OwnerSettingsError,
    render_owner_settings,
)


MARK_BEGIN = "# >>> coding-system secrets >>>"
MARK_END = "# <<< coding-system secrets <<<"
MOLTBOOK_AUTHORITY_KEY = "MOLTBOOK_API_KEY"
AAS_LEGACY_KEYS = (
    "CALIBRE_GDRIVE_FOLDER_ID",
    "GDRIVE_CREDENTIALS",
    "TELEGRAM_BOT_TOKEN",
    "WEBDAV_PASSWORD",
    "ZOTERO_API_KEY",
    "HCLOUD_TOKEN",
    "HCLOUD_SSH_KEYS",
    "KAGGLE_API_TOKEN",
    "KAGGLE_CONFIG_DIR",
    "AXLE_API_KEY",
    "LEANEXPLORE_API_KEY",
    "OCR_SPACE_API_KEY",
    "OCR_SPACE_KEY",
    "OCRSPACE_API_KEY",
    "OCRSPACE_KEY",
    "OPENCLAW_S2_API_KEY",
    "SEMANTIC_SCHOLAR_API_KEY",
    "UNPAYWALL_EMAIL",
    "ZENODO_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "DEEPSEEK_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROK_API_KEY",
    "KIMI_API_KEY",
    "MOONSHOT_API_KEY",
    "OPENAI_API_KEY",
    "OPENCODE_API_KEY",
    "XAI_API_KEY",
    "COPILOT_GITHUB_TOKEN",
    "COPILOT_PROVIDER_API_KEY",
    "COPILOT_PROVIDER_BEARER_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "ZULIP_ORG_URL",
    "ZULIP_EMAIL",
    "ZULIP_API_KEY",
    "VNU_EOFFICE_USERNAME",
    "VNU_EOFFICE_PASSWORD",
    "VNU_STATE_HMAC_KEY",
)
MIGRATABLE_KEYS = frozenset((*OWNER_SETTING_KEYS, *AAS_LEGACY_KEYS, MOLTBOOK_AUTHORITY_KEY))
ASSIGNMENT = re.compile(
    r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*\Z"
)
SECRET_SHAPED = re.compile(
    r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API|CHAT_ID)", re.I
)
# Old loaders that sourced the owner-settings data file as shell; the managed
# block replaces them wherever they appear.
LEGACY_LOADER_LINES = frozenset((
    "[ -f ~/.secrets.env ] && . ~/.secrets.env",
    '[ -f "$HOME/.secrets.env" ] && . "$HOME/.secrets.env"',
    '[[ -f "$HOME/.secrets.env" ]] && . "$HOME/.secrets.env"',
))
# Any other line that sources the data file as shell must be removed by hand.
SHELL_SOURCE = re.compile(
    r"""(?:^|[\s;&|({])(?:\.|source)\s+["']?(?:~|\$HOME|\$\{HOME\})/\.secrets\.env(?:["'\s;&|)]|$)"""
)
# The only loader line that may differ between loader versions: its key allowlist.
LOADER_CASE_LINE = re.compile(r" {8}[A-Z][A-Z0-9_]*(?:\|[A-Z][A-Z0-9_]*)*\) ;;\n")


class MigrationError(RuntimeError):
    """A redaction-safe owner-settings migration failure."""


def _literal_value(raw: str) -> str:
    if any(fragment in raw for fragment in ("$", "`", "\x00", ";", "<(", ">(")):
        raise MigrationError("legacy owner setting is not literal data")
    try:
        tokens = shlex.split(raw, comments=False, posix=True)
    except ValueError as exc:
        raise MigrationError("legacy owner setting is not literal data") from exc
    if len(tokens) != 1 or not tokens[0]:
        raise MigrationError("legacy owner setting is not one literal value")
    return tokens[0]


def _merge(values: dict[str, str], key: str, value: str) -> None:
    if key in values and values[key] != value:
        raise MigrationError("legacy owner setting sources conflict")
    values[key] = value


def _parse_legacy_settings(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MigrationError("legacy owner settings are not UTF-8") from exc
    values: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = ASSIGNMENT.fullmatch(raw)
        if match is None or match.group(1) not in MIGRATABLE_KEYS:
            raise MigrationError("legacy owner settings contain unsupported syntax or names")
        _merge(values, match.group(1), _literal_value(match.group(2)))
    return values


def _safe_regular(path: Path, *, modes: frozenset[int]) -> tuple[bytes, int]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MigrationError("migration input is unavailable or unsafe") from exc
    try:
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) not in modes
            or information.st_nlink != 1
            or information.st_size > 1024 * 1024
        ):
            raise MigrationError("migration input metadata is unsafe")
        snapshot = (
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
        payload = b""
        while len(payload) < information.st_size:
            block = os.read(descriptor, min(65536, information.st_size - len(payload)))
            if not block:
                raise MigrationError("migration input is truncated")
            payload += block
        if os.read(descriptor, 1):
            raise MigrationError("migration input changed while reading")
        final = os.fstat(descriptor)
        if snapshot != (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_uid,
            final.st_gid,
            final.st_nlink,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ):
            raise MigrationError("migration input changed while reading")
    finally:
        os.close(descriptor)
    return payload, stat.S_IMODE(information.st_mode)


def _optional_private(path: Path) -> bytes | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return _safe_regular(path, modes=frozenset({0o600}))[0]


def _optional_regular(
    path: Path, *, modes: frozenset[int]
) -> tuple[bytes, int] | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return _safe_regular(path, modes=modes)


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    if path.exists() and path.is_symlink():
        raise MigrationError("migration output is unsafe")
    temporary = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, mode)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise MigrationError("migration output write failed")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _safe_loader_block() -> list[str]:
    source = (
        Path(__file__).resolve().parents[1] / "system/shell/bashrc.block.sh"
    ).read_text(encoding="utf-8")
    start_marker = (
        "# coding-system: private owner settings are data, never executable shell."
    )
    terminator = "export CSR_OWNER_SETTINGS_STATUS CSR_OWNER_SETTINGS_RC\n"
    start = source.index(start_marker)
    end = source.index(terminator, start) + len(terminator)
    return [MARK_BEGIN + "\n", *source[start:end].splitlines(keepends=True), MARK_END + "\n"]


def _is_managed_loader(lines: list[str]) -> bool:
    """The current loader, or an earlier one that differs only in its key allowlist."""
    current = _safe_loader_block()[1:-1]
    return len(lines) == len(current) and all(
        line == expected
        or (LOADER_CASE_LINE.fullmatch(line) and LOADER_CASE_LINE.fullmatch(expected))
        for line, expected in zip(lines, current)
    )


def _bash_parses(payload: bytes) -> bool:
    result = subprocess.run(
        ["/usr/bin/bash", "-n"],
        input=payload,
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    return result.returncode == 0


def _collect_managed_lines(lines: list[str], collected: dict[str, str]) -> None:
    if _is_managed_loader(lines):
        return
    for original in lines:
        line = original.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#") or line.strip() in LEGACY_LOADER_LINES:
            continue
        match = ASSIGNMENT.fullmatch(line)
        if match and match.group(1) in MIGRATABLE_KEYS:
            _merge(collected, match.group(1), _literal_value(match.group(2)))
            continue
        raise MigrationError("bashrc owner-settings block contains unsupported commands")


def _migrate_bashrc(payload: bytes, collected: dict[str, str]) -> bytes:
    try:
        lines = payload.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise MigrationError("bashrc is not UTF-8") from exc
    output: list[str] = []
    insertion: int | None = None
    inside_managed = False
    managed_lines: list[str] = []
    for original in lines:
        line = original.rstrip("\r\n")
        if line.strip() == MARK_BEGIN:
            if inside_managed:
                raise MigrationError("bashrc owner-settings markers are invalid")
            inside_managed = True
            if insertion is None:
                insertion = len(output)
            continue
        if line.strip() == MARK_END:
            if not inside_managed:
                raise MigrationError("bashrc owner-settings markers are invalid")
            _collect_managed_lines(managed_lines, collected)
            inside_managed = False
            continue
        if inside_managed:
            managed_lines.append(original)
            continue
        if line.strip() in LEGACY_LOADER_LINES:
            continue
        match = ASSIGNMENT.fullmatch(line)
        if match and match.group(1) in MIGRATABLE_KEYS:
            _merge(collected, match.group(1), _literal_value(match.group(2)))
            if insertion is None:
                insertion = len(output)
            continue
        if match and (
            match.group(1).startswith(("MOLTBOOK_", "MOLBOOK_"))
            or SECRET_SHAPED.search(match.group(1))
        ):
            raise MigrationError("bashrc contains an unsupported credential export")
        output.append(original)
    if inside_managed:
        raise MigrationError("bashrc owner-settings markers are invalid")
    if any(
        not line.lstrip().startswith("#") and SHELL_SOURCE.search(line.rstrip("\r\n"))
        for line in output
    ):
        raise MigrationError("bashrc still sources ~/.secrets.env as shell; remove that line by hand")
    if output and not output[-1].endswith("\n"):
        output[-1] += "\n"
    if insertion is None:
        insertion = len(output)
    return "".join(output[:insertion] + _safe_loader_block() + output[insertion:]).encode(
        "utf-8"
    )


def _migrate_profile(payload: bytes, collected: dict[str, str]) -> bytes:
    """Remove bounded private assignments without installing a shell loader."""

    try:
        lines = payload.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise MigrationError("profile is not UTF-8") from exc
    output: list[str] = []
    inside_managed = False
    managed_lines: list[str] = []
    for original in lines:
        line = original.rstrip("\r\n")
        if line.strip() == MARK_BEGIN:
            if inside_managed:
                raise MigrationError("profile owner-settings markers are invalid")
            inside_managed = True
            continue
        if line.strip() == MARK_END:
            if not inside_managed:
                raise MigrationError("profile owner-settings markers are invalid")
            _collect_managed_lines(managed_lines, collected)
            inside_managed = False
            continue
        if inside_managed:
            managed_lines.append(original)
            continue
        match = ASSIGNMENT.fullmatch(line)
        if match and match.group(1) in MIGRATABLE_KEYS:
            _merge(collected, match.group(1), _literal_value(match.group(2)))
            continue
        if match and (
            match.group(1).startswith(("MOLTBOOK_", "MOLBOOK_"))
            or SECRET_SHAPED.search(match.group(1))
        ):
            raise MigrationError("profile contains an unsupported credential export")
        output.append(original)
    if inside_managed:
        raise MigrationError("profile owner-settings markers are invalid")
    return "".join(output).encode("utf-8")


def _sanitized_rollback(payload: bytes, collected: dict[str, str]) -> bytes:
    return _migrate_profile(payload, collected)


def _metadata_snapshot(information: os.stat_result) -> tuple[int, ...]:
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


def _open_home_leaf(
    home_fd: int, name: str, *, modes: frozenset[int]
) -> tuple[int, bytes, tuple[int, ...]]:
    if "/" in name or name in ("", ".", ".."):
        raise MigrationError("migration leaf name is unsafe")
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=home_fd,
    )
    try:
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) not in modes
            or information.st_nlink != 1
            or information.st_size > 1024 * 1024
        ):
            raise MigrationError("migration input metadata is unsafe")
        snapshot = _metadata_snapshot(information)
        chunks: list[bytes] = []
        remaining = information.st_size
        while remaining:
            block = os.read(descriptor, min(65536, remaining))
            if not block:
                raise MigrationError("migration input is truncated")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise MigrationError("migration input changed while reading")
        if _metadata_snapshot(os.fstat(descriptor)) != snapshot:
            raise MigrationError("migration input changed while reading")
        return descriptor, b"".join(chunks), snapshot
    except BaseException:
        os.close(descriptor)
        raise


def _preflight_npmrc_duplicate(home: Path) -> tuple[int, ...] | None:
    """Approve removal only when the retired duplicate equals its authority."""

    home_fd = os.open(
        home, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        try:
            duplicate_fd, duplicate, snapshot = _open_home_leaf(
                home_fd, ".npmrc.pre-coding-system", modes=frozenset({0o600})
            )
        except FileNotFoundError:
            return None
        try:
            try:
                authority_fd, authority, _ = _open_home_leaf(
                    home_fd, ".npmrc", modes=frozenset({0o600})
                )
            except FileNotFoundError as exc:
                raise MigrationError(
                    "retired npm credential backup has no authority"
                ) from exc
            try:
                if authority != duplicate:
                    raise MigrationError(
                        "retired npm credential backup diverges from its authority"
                    )
            finally:
                os.close(authority_fd)
            return snapshot
        finally:
            os.close(duplicate_fd)
    finally:
        os.close(home_fd)


def _retire_npmrc_duplicate(home: Path, approved: tuple[int, ...]) -> None:
    home_fd = os.open(
        home, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    duplicate_fd: int | None = None
    try:
        authority_fd, authority, _ = _open_home_leaf(
            home_fd, ".npmrc", modes=frozenset({0o600})
        )
        try:
            duplicate_fd, duplicate, observed = _open_home_leaf(
                home_fd, ".npmrc.pre-coding-system", modes=frozenset({0o600})
            )
        finally:
            os.close(authority_fd)
        if observed != approved or duplicate != authority:
            raise MigrationError("retired npm credential backup changed during removal")
        named = os.stat(
            ".npmrc.pre-coding-system", dir_fd=home_fd, follow_symlinks=False
        )
        if _metadata_snapshot(named) != observed:
            raise MigrationError("retired npm credential backup changed during removal")
        if _metadata_snapshot(os.fstat(duplicate_fd)) != observed:
            raise MigrationError("retired npm credential backup changed during removal")
        os.unlink(".npmrc.pre-coding-system", dir_fd=home_fd)
        unlinked = os.fstat(duplicate_fd)
        if (
            unlinked.st_dev != observed[0]
            or unlinked.st_ino != observed[1]
            or unlinked.st_nlink != 0
        ):
            raise MigrationError("retired npm credential backup removal raced")
        os.fsync(home_fd)
    finally:
        if duplicate_fd is not None:
            os.close(duplicate_fd)
        os.close(home_fd)


def _read_moltbook_authority(path: Path) -> str | None:
    payload = _optional_private(path)
    if payload is None:
        return None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MigrationError("Moltbook authority is not UTF-8") from exc
    value: str | None = None
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            continue
        match = re.fullmatch(r"MOLTBOOK_API_KEY=(.+)", raw)
        if match is None or value is not None:
            raise MigrationError("Moltbook authority has unsupported fields")
        value = _literal_value(match.group(1))
    return value


def migrate(home: Path) -> None:
    home = home.expanduser().absolute()
    information = home.lstat()
    if home.is_symlink() or not stat.S_ISDIR(information.st_mode) or information.st_uid != os.getuid():
        raise MigrationError("home is unsafe")
    shell_modes = frozenset({0o600, 0o640, 0o644, 0o660, 0o664})
    bashrc = home / ".bashrc"
    profile = home / ".profile"
    bashrc_input = _optional_regular(bashrc, modes=shell_modes)
    profile_input = _optional_regular(profile, modes=shell_modes)
    collected: dict[str, str] = {}
    dotenv = home / ".secrets.env"
    dotenv_payload = _optional_private(dotenv)
    if dotenv_payload is not None:
        collected.update(_parse_legacy_settings(dotenv_payload))
    rendered_bashrc = (
        _migrate_bashrc(bashrc_input[0], collected)
        if bashrc_input is not None
        else None
    )
    rendered_profile = (
        _migrate_profile(profile_input[0], collected)
        if profile_input is not None
        else None
    )
    if (
        rendered_bashrc is not None
        and bashrc_input is not None
        and _bash_parses(bashrc_input[0])
        and not _bash_parses(rendered_bashrc)
    ):
        raise MigrationError("the migrated bashrc would not parse; bashrc left unchanged")

    bashrc_backup = home / ".bashrc.pre-coding-system"
    bashrc_backup_input = _optional_regular(bashrc_backup, modes=shell_modes)
    bashrc_backup_payload = (
        _sanitized_rollback(bashrc_backup_input[0], collected)
        if bashrc_backup_input is not None
        else (
            _sanitized_rollback(bashrc_input[0], collected)
            if bashrc_input is not None
            else None
        )
    )
    profile_backup = home / ".profile.pre-coding-system"
    profile_backup_input = _optional_regular(profile_backup, modes=shell_modes)
    profile_backup_payload = (
        _sanitized_rollback(profile_backup_input[0], collected)
        if profile_backup_input is not None
        else (
            _sanitized_rollback(profile_input[0], collected)
            if profile_input is not None
            else None
        )
    )
    npmrc_duplicate_snapshot = _preflight_npmrc_duplicate(home)

    moltbook_value = collected.pop(MOLTBOOK_AUTHORITY_KEY, None)
    moltbook_path = home / ".openclaw/moltbook.env"
    current_moltbook = _read_moltbook_authority(moltbook_path)
    if moltbook_value is not None and current_moltbook not in (None, moltbook_value):
        raise MigrationError("legacy Moltbook credential conflicts with its authority")

    owner_values = {
        key: collected.pop(key)
        for key in OWNER_SETTING_KEYS
        if key in collected
    }
    owner_payload = render_owner_settings(owner_values)
    owner_payload += b"".join(
        f"{key}={collected[key]}\n".encode("utf-8")
        for key in AAS_LEGACY_KEYS
        if key in collected
    )

    if bashrc_backup_payload is not None:
        _atomic_write(bashrc_backup, bashrc_backup_payload, 0o600)
    if profile_backup_payload is not None:
        _atomic_write(profile_backup, profile_backup_payload, 0o600)
    _atomic_write(dotenv, owner_payload, 0o600)
    if moltbook_value is not None and current_moltbook is None:
        _atomic_write(
            moltbook_path,
            (
                "# coding-system managed Moltbook gateway authority\n"
                f"MOLTBOOK_API_KEY={moltbook_value}\n"
            ).encode("utf-8"),
            0o600,
        )
    if rendered_profile is not None and profile_input is not None:
        _atomic_write(profile, rendered_profile, profile_input[1])
    if rendered_bashrc is not None and bashrc_input is not None:
        _atomic_write(bashrc, rendered_bashrc, bashrc_input[1])
    if npmrc_duplicate_snapshot is not None:
        _retire_npmrc_duplicate(home, npmrc_duplicate_snapshot)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    arguments = parser.parse_args(argv)
    try:
        migrate(arguments.home)
    except MigrationError as error:
        print(f"owner-settings migration: {error}", file=sys.stderr)
        return 2
    except (OwnerSettingsError, OSError):
        print("owner-settings migration: unsafe, unsupported, or conflicting input", file=sys.stderr)
        return 2
    print("owner-settings migration: canonical data and credential authorities ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
