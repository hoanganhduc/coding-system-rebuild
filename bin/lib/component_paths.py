#!/usr/bin/env python3
"""Resolve immutable component checkouts outside the authenticated repository."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


COMMIT = re.compile(r"[0-9a-f]{40}\Z")
NAMES = frozenset({"openclaw-bot", "course_management_toolkit"})


class ComponentPathError(RuntimeError):
    pass


def component_pin(repository: Path, name: str) -> str:
    if name not in NAMES:
        raise ComponentPathError("unsupported immutable component name")
    try:
        lines = (repository / "components.lock").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ComponentPathError("component lock is unavailable") from exc
    matches = []
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == name:
            matches.append(value.rsplit("@", 1)[-1])
    if len(matches) != 1 or COMMIT.fullmatch(matches[0]) is None:
        raise ComponentPathError(f"{name} does not have one exact commit pin")
    return matches[0]


def installed_component_path(repository: Path, home: Path, name: str) -> Path:
    return (
        home
        / ".local/share/coding-system/components"
        / name
        / component_pin(repository, name)
    )


def source_component_path(repository: Path, name: str) -> Path:
    return repository / "external" / name


def _head(path: Path) -> str | None:
    try:
        completed = subprocess.run(
            [
                "/usr/bin/git",
                "--no-optional-locks",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "protocol.allow=never",
                "-C",
                os.fspath(path),
                "rev-parse",
                "--verify",
                "HEAD^{commit}",
            ],
            env={
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "HOME": "/",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "XDG_CONFIG_HOME": "/dev/null",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def resolve_component_path(
    repository: Path,
    home: Path,
    name: str,
    *,
    source_fallback: bool = False,
    require: bool = False,
) -> Path:
    pin = component_pin(repository, name)
    installed = installed_component_path(repository, home, name)
    candidates = [installed]
    if source_fallback:
        candidates.append(source_component_path(repository, name))
    for candidate in candidates:
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ComponentPathError("cannot inspect immutable component path") from exc
        if candidate.is_symlink() or not candidate.is_dir():
            raise ComponentPathError("immutable component path is not a real directory")
        if _head(candidate) == pin:
            return candidate
        raise ComponentPathError("component checkout does not match its exact lock")
    if require:
        raise ComponentPathError(f"immutable {name} checkout is unavailable")
    return installed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--source-fallback", action="store_true")
    parser.add_argument("--require", action="store_true")
    parser.add_argument("name", choices=sorted(NAMES))
    arguments = parser.parse_args(argv)
    try:
        path = resolve_component_path(
            arguments.repository,
            arguments.home,
            arguments.name,
            source_fallback=arguments.source_fallback,
            require=arguments.require,
        )
    except ComponentPathError as exc:
        print(f"component path: {exc}", file=sys.stderr)
        return 2
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
