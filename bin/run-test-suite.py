#!/usr/bin/env python3
"""Run every command of the Makefile test target and report all failures.

`make test` stops at the first failing command, so one red file hides every
later one.  This runner executes each recipe command on its own, in order and
from the repository root, keeps going, prints the tail of each failure and a
summary, and exits 1 when anything failed.  The Makefile test target stays the
single list of tests.

Usage: bin/run-test-suite.py [--makefile PATH] [--target NAME] [--tail LINES]
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"


def recipe_commands(makefile: Path, target: str) -> list[str]:
    """Return the shell commands of one target, joining continuation lines."""

    lines = makefile.read_text(encoding="utf-8").splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if re.match(rf"^{re.escape(target)}:", line))
    except StopIteration:
        raise SystemExit(f"run-test-suite: no {target}: target in {makefile}") from None
    commands: list[str] = []
    current = ""
    for line in lines[start + 1:]:
        if not line.startswith("\t"):
            if line.strip():
                break
            continue
        text = line[1:]
        if not current:
            text = text.lstrip("@-")
        current = f"{current}\n{text}" if current else text
        if not text.endswith("\\"):
            commands.append(current)
            current = ""
    if current:
        commands.append(current)
    return commands


def shell_text(command: str, repository: Path) -> str:
    return (
        command.replace("$(REPO)", str(repository))
        .replace("$(HOME)", os.environ.get("HOME", ""))
        .replace("$$", "$")
    )


def run(commands: list[str], repository: Path, tail: int) -> list[str]:
    failed: list[str] = []
    for number, command in enumerate(commands, 1):
        text = shell_text(command, repository)
        label = text.splitlines()[-1].strip()
        if IN_ACTIONS:
            print(f"::group::[{number}/{len(commands)}] {label}", flush=True)
        started = time.monotonic()
        completed = subprocess.run(
            ["bash", "-c", text],
            cwd=repository,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            check=False,
        )
        seconds = time.monotonic() - started
        output = completed.stdout
        if IN_ACTIONS:
            print(output, end="" if output.endswith("\n") or not output else "\n")
            print("::endgroup::", flush=True)
        status = "PASS" if completed.returncode == 0 else f"FAIL rc={completed.returncode}"
        print(f"{status:<10} {seconds:7.1f}s  {label}", flush=True)
        if completed.returncode != 0:
            failed.append(label)
            for line in output.splitlines()[-tail:]:
                print(f"    | {line}")
            if IN_ACTIONS:
                print(f"::error title=test failed::{label}", flush=True)
    return failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--makefile", type=Path, default=ROOT / "Makefile")
    parser.add_argument("--target", default="test")
    parser.add_argument("--tail", type=int, default=40)
    arguments = parser.parse_args(argv)
    repository = arguments.makefile.resolve().parent
    commands = recipe_commands(arguments.makefile, arguments.target)
    failed = run(commands, repository, arguments.tail)
    print(f"test suite: {len(commands) - len(failed)} of {len(commands)} commands passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
