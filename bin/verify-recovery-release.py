#!/usr/bin/env python3
"""Refuse normal recovery releases until every restore artifact is qualified.

This gate is intentionally offline.  It validates both supported architecture
closures and, when a recovery set is supplied, binds that set to the exact
clean published repository HEAD that is being qualified.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
FIXED_ENV = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "XDG_CONFIG_HOME": "/nonexistent",
}


class ReleaseQualificationError(RuntimeError):
    """A non-secret recovery release qualification failure."""


def _run(command: list[str], label: str) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=FIXED_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseQualificationError(f"{label} could not run") from exc
    if completed.returncode != 0:
        # Child diagnostics may contain credential-bearing remote URLs or
        # provider parser input. Keep this release boundary intentionally
        # stable and redaction-safe.
        raise ReleaseQualificationError(f"{label} is not qualified")
    return completed.stdout.decode("utf-8", "strict").strip()


def _head() -> str:
    head = _run(
        ["/usr/bin/git", "-C", os.fspath(ROOT), "rev-parse", "--verify", "HEAD^{commit}"],
        "repository HEAD",
    )
    if COMMIT_RE.fullmatch(head) is None:
        raise ReleaseQualificationError("repository HEAD is not an immutable commit")
    status = _run(
        [
            "/usr/bin/git",
            "-C",
            os.fspath(ROOT),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        "repository cleanliness check",
    )
    if status:
        raise ReleaseQualificationError(
            "repository worktree/index is not clean; recovery releases bind only to HEAD"
        )
    _run(
        ["/usr/bin/bash", "-p", os.fspath(ROOT / "bin/verify-published-head.sh")],
        "published repository HEAD",
    )
    return head


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ReleaseQualificationError(f"cannot load release verifier: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validate_oci_closure() -> None:
    runtime = _load_module(
        "csr_python_runtime_release_gate",
        ROOT / "system/python-closure/runtime_lib.py",
    )
    lock = ROOT / "system/software/images.lock.json"
    try:
        for architecture in ("amd64", "arm64"):
            runtime.load_locked_image(lock, architecture)
    except Exception as exc:
        raise ReleaseQualificationError(
            "both-architecture python-wheelhouse OCI closure is not qualified"
        ) from exc


def _validate_recovery_binding(recovery_set: Path, head: str) -> None:
    recovery = _load_module(
        "csr_recovery_release_gate",
        ROOT / "bin/lib/recovery_tool.py",
    )
    try:
        manifest = recovery.load_recovery_manifest(recovery_set)
        bound = manifest["components"]["coding-system-rebuild"]["commit"]
    except Exception as exc:
        raise ReleaseQualificationError("recovery-set manifest is invalid") from exc
    if bound != head:
        raise ReleaseQualificationError(
            "recovery set is not bound to the exact qualified repository HEAD"
        )


def qualify(recovery_set: Path | None = None) -> str:
    head = _head()
    _run(
        [
            "/usr/bin/python3",
            "-I",
            "-B",
            os.fspath(ROOT / "bin/provision-grok-bootstrap.py"),
            "--require-qualified-lock",
        ],
        "Grok bootstrap release",
    )
    for architecture in ("amd64", "arm64"):
        _run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                os.fspath(ROOT / "system/software/lockctl.py"),
                "--arch",
                architecture,
                "validate",
                "--require-complete",
            ],
            f"Ubuntu 24.04/{architecture} software and OCI closure",
        )
        _run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                os.fspath(ROOT / "bin/install-python-closure.py"),
                "validate",
                "--lock",
                os.fspath(
                    ROOT
                    / f"system/python-closure/ubuntu-24.04-{architecture}.lock.json"
                ),
                "--require-qualified",
            ],
            f"Ubuntu 24.04/{architecture} Python closure",
        )
    _validate_oci_closure()
    if recovery_set is not None:
        _validate_recovery_binding(recovery_set, head)
    return head


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recovery-set", type=Path)
    arguments = parser.parse_args(argv)
    try:
        head = qualify(arguments.recovery_set)
    except ReleaseQualificationError as exc:
        print(f"recovery release: ARTIFACT_UNAVAILABLE: {exc}", file=sys.stderr)
        return 2
    print(f"recovery release: qualified for amd64 and arm64 at {head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
