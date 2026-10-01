#!/usr/bin/env python3
"""Promote locked CLIs and npm globals to the newer versions installed on this host.

Backups run this (bin/refresh-state.sh), so a restore installs the versions the
host ran at its last backup. A tool whose new release cannot be fetched keeps
its locked version, and the backup continues.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


REPO = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LOCKCTL = _load("csr_lockctl", REPO / "system/software/lockctl.py")
CLOSURECTL = _load("csr_closurectl", REPO / "system/software/npm-closure/closurectl.py")
VERIFIER = _load("csr_installed_software", REPO / "bin/verify-installed-software.py")


def installed_version(home: Path, name: str) -> str | None:
    executable = next(
        (path for path in VERIFIER.candidate_paths(home, name) if VERIFIER.runnable(path)), None
    )
    if executable is None:
        return None
    returncode, output = VERIFIER.run_bounded(VERIFIER.version_command(name, executable))
    match = VERIFIER.VERSION_TOKEN.search(output) if returncode == 0 else None
    return match.group(1) if match else None


def installed_npm_versions() -> dict[str, str]:
    """Top-level npm globals as the user's npm reports them."""
    try:
        completed = subprocess.run(
            ["npm", "ls", "-g", "--depth=0", "--json"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        dependencies = json.loads(completed.stdout or "{}").get("dependencies", {})
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {}
    return {
        name: info["version"]
        for name, info in dependencies.items()
        if isinstance(info, dict) and isinstance(info.get("version"), str)
    }


def newer(observed: str, floor: str) -> bool:
    try:
        return LOCKCTL.version_tuple(observed) > LOCKCTL.version_tuple(floor)
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--home", type=Path, default=Path.home())
    arguments = parser.parse_args(argv)
    floors = LOCKCTL.load_profile("arm64")["cli_versions"]
    for cli, identifier in sorted(LOCKCTL.CLI_ARTIFACTS.items()):
        floor = str(floors.get(cli, "")).removeprefix(">=")
        observed = installed_version(arguments.home, cli)
        if observed is None or not floor or not newer(observed, floor):
            continue
        try:
            LOCKCTL.promote_artifact(identifier, observed)
        except (LOCKCTL.LockError, OSError) as exc:
            print(f"WARN: {cli} {observed} stays locked at {floor}: {exc}", file=sys.stderr)
            continue
        print(f"promoted {cli} {floor} -> {observed}")
    lock = json.loads((LOCKCTL.SOFTWARE / "npm-globals.lock.json").read_text(encoding="utf-8"))
    installed = installed_npm_versions()
    # The npm CLI closure must move with its request list, so npm promotions are
    # undone together when the closure cannot be re-resolved.
    npm_files = [
        LOCKCTL.SOFTWARE / "npm-globals.lock.json",
        LOCKCTL.ROOT / "system/packages/npm-globals.txt",
        LOCKCTL.SOFTWARE / "ubuntu-24.04-amd64.lock.json",
        LOCKCTL.SOFTWARE / "ubuntu-24.04-arm64.lock.json",
    ]
    snapshot = {path: path.read_bytes() for path in npm_files}
    promoted = []
    for package in lock["packages"]:
        name, floor = package["name"], package["version"]
        observed = installed.get(name)
        if name in LOCKCTL.NPM_TUPLE_MANAGED or observed is None or not newer(observed, floor):
            continue
        try:
            LOCKCTL.promote_npm(name, observed)
        except (LOCKCTL.LockError, OSError) as exc:
            print(f"WARN: {name} {observed} stays locked at {floor}: {exc}", file=sys.stderr)
            continue
        promoted.append(f"{name} {floor} -> {observed}")
    if promoted:
        try:
            CLOSURECTL.relock()
        except CLOSURECTL.ClosureError as exc:
            for path, data in snapshot.items():
                path.write_bytes(data)
            print(f"WARN: npm globals stay locked as before: {exc}", file=sys.stderr)
            return 0
        for line in promoted:
            print(f"promoted {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
