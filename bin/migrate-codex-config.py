#!/usr/bin/env python3
"""Converge Codex's public runtime/credential selectors without replacing config."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import tomllib


SELECTOR_PATHS = {
    "AAS_RUNTIME_ROOT": ".codex/runtime",
    "AAS_RUNTIME_PYTHON": ".local/share/coding-system/python-closure/shared/bin/python",
    "AAS_SECRETS_FILE": ".config/ai-agents-skills/secrets.json",
    "AAS_CALIBRE_SECRETS_FILE": ".config/ai-agents-skills/calibre-secrets.json",
    "AAS_ZOTERO_SECRETS_FILE": ".config/ai-agents-skills/zotero-secrets.json",
    "AAS_FILE_DELIVERY_SECRETS_FILE": (
        ".config/ai-agents-skills/file-delivery-queue.json"
    ),
    "AAS_COMPUTE_SECRETS_FILE": ".config/ai-agents-skills/compute.env",
    "AAS_SKILL_SECRETS_FILE": ".config/ai-agents-skills/skill.env",
    "AAS_PROVIDER_SECRETS_FILE": ".config/ai-agents-skills/providers.env",
    "REMOTE_BRIDGE_SECRETS_FILE": ".config/remote-bridge/secrets.json",
    "SEND_EMAIL_SECRETS_FILE": ".config/send-email/secrets.json",
    "GOOGLE_CLASSROOM_CREDENTIALS": ".config/course/google-classroom/credentials.json",
    "GOOGLE_CLASSROOM_TOKEN": ".config/course/google-classroom/token.pickle",
    "CANVAS_CONFIG_PATH": ".config/course/canvas/config.json",
    "GETSCIPAPERS_CONFIG_DIR": ".config/getscipapers",
    "GETSCIPAPERS_SKILL_CONFIG": (
        ".openclaw/workspace/data/research/getscipapers_bot/state/config.json"
    ),
    "GH_CONFIG_DIR": ".config/gh",
}
RETIRED_SET_KEYS = frozenset(
    {
        "AAS_ALLOW_EXTERNAL_SECRETS_FILE",
        "AAS_ZOTERO_SKILL_SECRETS_FILE",
        "OPENCLAW_SECRETS_FILE",
    }
)
REQUIRED_EXCLUDES = tuple((*SELECTOR_PATHS, *sorted(RETIRED_SET_KEYS)))
TABLE = "[shell_environment_policy]"
SET_TABLE = "[shell_environment_policy.set]"
TABLE_LINE = re.compile(r"^[ \t]*\[([^]\r\n]+)\][ \t]*(?:#.*)?$")
SET_ASSIGNMENT = re.compile(r"^[ \t]*set[ \t]*=")
EXCLUDE_ASSIGNMENT = re.compile(r"^[ \t]*exclude[ \t]*=")


class MigrationError(RuntimeError):
    """A redaction-safe Codex configuration migration failure."""


def _require_home(path: Path) -> Path:
    path = path.expanduser().absolute()
    try:
        info = path.lstat()
    except OSError as exc:
        raise MigrationError("Codex selector home is unavailable") from exc
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise MigrationError("Codex selector home is unsafe")
    return path


def _read_config(path: Path) -> tuple[str, os.stat_result]:
    try:
        named = path.lstat()
    except OSError as exc:
        raise MigrationError("Codex config is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(named.st_mode)
        or named.st_uid != os.getuid()
        or named.st_nlink != 1
        or not 0 < named.st_size <= 1024 * 1024
    ):
        raise MigrationError("Codex config is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise MigrationError("Codex config changed during inspection")
        payload = b""
        while len(payload) <= 1024 * 1024:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            payload += chunk
        if len(payload) > 1024 * 1024:
            raise MigrationError("Codex config exceeds its size bound")
    finally:
        os.close(descriptor)
    try:
        return payload.decode("utf-8"), named
    except UnicodeDecodeError as exc:
        raise MigrationError("Codex config is not UTF-8") from exc


def _selector_values(home: Path) -> dict[str, str]:
    return {key: str(home / relative) for key, relative in SELECTOR_PATHS.items()}


def _inline_set(values: dict[str, str]) -> str:
    body = ", ".join(
        f"{key} = {json.dumps(value, ensure_ascii=True)}"
        for key, value in values.items()
    )
    return f"set = {{ {body} }}\n"


def _inline_exclude(values: list[str]) -> str:
    body = ", ".join(json.dumps(value, ensure_ascii=True) for value in values)
    return f"exclude = [{body}]\n"


def _table_bounds(lines: list[str], table_name: str) -> tuple[int, int] | None:
    start = None
    for index, line in enumerate(lines):
        match = TABLE_LINE.fullmatch(line.rstrip("\r\n"))
        if match is None:
            continue
        current = match.group(1).strip()
        if start is None:
            if current == table_name:
                start = index
        else:
            return start, index
    return None if start is None else (start, len(lines))


def _render(text: str, home: Path) -> str:
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise MigrationError("Codex config is invalid TOML") from exc
    policy = document.get("shell_environment_policy", {})
    if not isinstance(policy, dict):
        raise MigrationError("Codex shell environment policy is invalid")
    existing = policy.get("set", {})
    if not isinstance(existing, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in existing.items()
    ):
        raise MigrationError("Codex shell environment selector table is invalid")
    excluded = policy.get("exclude", [])
    if not isinstance(excluded, list) or any(
        not isinstance(value, str) for value in excluded
    ):
        raise MigrationError("Codex shell environment exclusion list is invalid")
    merged = {
        key: value for key, value in existing.items() if key not in RETIRED_SET_KEYS
    }
    merged.update(_selector_values(home))
    assignment = _inline_set(merged)
    merged_excludes = list(dict.fromkeys((*excluded, *REQUIRED_EXCLUDES)))
    exclude_assignment = _inline_exclude(merged_excludes)
    lines = text.splitlines(keepends=True)

    policy_bounds = _table_bounds(lines, "shell_environment_policy")
    set_bounds = _table_bounds(lines, "shell_environment_policy.set")
    if set_bounds is not None:
        if policy_bounds is None:
            raise MigrationError("Codex shell environment policy table is missing")
        start, end = set_bounds
        replacement = [SET_TABLE + "\n"]
        replacement.extend(
            f"{key} = {json.dumps(value, ensure_ascii=True)}\n"
            for key, value in merged.items()
        )
        lines[start:end] = replacement
    elif policy_bounds is not None:
        start, end = policy_bounds
        assignments = [
            index for index in range(start + 1, end)
            if SET_ASSIGNMENT.match(lines[index])
        ]
        if len(assignments) > 1:
            raise MigrationError("Codex selector assignment is ambiguous")
        if assignments:
            lines[assignments[0]] = assignment
        elif existing:
            raise MigrationError("Codex selector syntax is unsupported")
        else:
            lines.insert(end, assignment)
    else:
        if existing:
            raise MigrationError("Codex selector syntax is unsupported")
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += "\n"
        if lines and lines[-1].strip():
            lines.append("\n")
        lines.extend((TABLE + "\n", assignment))

    policy_bounds = _table_bounds(lines, "shell_environment_policy")
    if policy_bounds is None:  # pragma: no cover - every branch above creates it
        raise MigrationError("rendered Codex shell environment policy is missing")
    start, end = policy_bounds
    exclusion_assignments = [
        index
        for index in range(start + 1, end)
        if EXCLUDE_ASSIGNMENT.match(lines[index])
    ]
    if len(exclusion_assignments) > 1:
        raise MigrationError("Codex exclusion assignment is ambiguous")
    if exclusion_assignments:
        lines[exclusion_assignments[0]] = exclude_assignment
    else:
        lines.insert(start + 1, exclude_assignment)

    rendered = "".join(lines)
    try:
        confirmed = tomllib.loads(rendered)
        confirmed_policy = confirmed["shell_environment_policy"]
        selected = confirmed_policy["set"]
        confirmed_excludes = confirmed_policy["exclude"]
    except (tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise MigrationError("rendered Codex selector configuration is invalid") from exc
    if any(selected.get(key) != value for key, value in _selector_values(home).items()):
        raise MigrationError("rendered Codex selectors are incomplete")
    if RETIRED_SET_KEYS.intersection(selected):
        raise MigrationError("rendered Codex selectors retain an unsafe legacy key")
    if not isinstance(confirmed_excludes, list) or any(
        key not in confirmed_excludes for key in REQUIRED_EXCLUDES
    ):
        raise MigrationError("rendered Codex selector exclusions are incomplete")
    return rendered


def _atomic_write(path: Path, text: str) -> None:
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def migrate(config: Path, home: Path) -> bool:
    home = _require_home(home)
    try:
        config = config.expanduser().absolute()
        config.relative_to(home)
    except ValueError as exc:
        raise MigrationError("Codex config escapes the selected home") from exc
    text, information = _read_config(config)
    rendered = _render(text, home)
    changed = rendered != text or stat.S_IMODE(information.st_mode) != 0o600
    if changed:
        _atomic_write(config, rendered)
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    args = parser.parse_args()
    try:
        changed = migrate(args.config, args.home)
    except MigrationError as exc:
        print(f"migrate-codex-config: {exc}", file=os.sys.stderr)
        return 2
    print("Codex selector configuration: " + ("updated" if changed else "current"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
