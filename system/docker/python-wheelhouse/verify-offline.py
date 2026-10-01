#!/usr/bin/env python3
"""Offline-install and smoke-test every environment from an extracted wheelhouse."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from wheelhouse_lib import ENVIRONMENTS, WheelhouseError, canonical_name, validate_wheelhouse


SMOKES: dict[str, list[str]] = {
    "workspace": [
        "import ebooklib, googleapiclient, modal, requests",
    ],
    "shared": [
        "import feedparser, networkx, pyzotero",
    ],
    "docling-cpu": [
        "import docling, docling_mcp, torch, torchvision; assert '+cpu' in torch.__version__; assert '+cpu' in torchvision.__version__; assert not torch.cuda.is_available()",
    ],
    "lean-explore": [
        "import lean_explore, mcp",
    ],
    "getscipapers": [
        "import crossref.restful, getscipapers_hoanganhduc",
    ],
    "course-management": [
        "import course_hoanganhduc",
    ],
}
CLI_SMOKES: dict[str, list[str]] = {
    "getscipapers": ["getscipapers", "--help"],
    "aider": ["aider", "--version"],
    "modal": ["modal", "--version"],
    "course-management": ["course", "--help"],
}


class VerifyError(RuntimeError):
    """An offline install, inventory check, or smoke failed."""


def run(command: list[str], *, env: dict[str, str], timeout: int = 180) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
        timeout=timeout,
    )
    if result.returncode != 0:
        output = (result.stderr or result.stdout).strip()[-4000:]
        raise VerifyError(f"command failed ({result.returncode}): {' '.join(command)}: {output}")
    return result


def verify_environment(root: Path, environment: str, work: Path, host_python: str) -> None:
    manifest = json.loads((root / environment / "manifest.json").read_text(encoding="utf-8"))
    expected = {canonical_name(str(item["name"])): str(item["version"]) for item in manifest["artifacts"]}
    venv = work / environment
    clean_env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("PIP_") and key not in {"PYTHONHOME", "PYTHONPATH"}
    }
    clean_env.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    run([host_python, "-m", "venv", "--without-pip", str(venv)], env=clean_env)
    wheels = sorted(str(path) for path in (root / environment).glob("*.whl"))
    if not wheels:
        raise VerifyError(f"environment has no wheels: {environment}")
    run(
        [
            host_python,
            "-m",
            "pip",
            "--python",
            str(venv / "bin/python"),
            "install",
            "--no-index",
            "--no-deps",
            *wheels,
        ],
        env=clean_env,
        timeout=900,
    )
    run(
        [host_python, "-m", "pip", "--python", str(venv / "bin/python"), "check"],
        env=clean_env,
    )
    inventory_code = """
import importlib.metadata as metadata
import json, re
def canonical(value):
    return re.sub(r'[-_.]+', '-', value).lower()
print(json.dumps({canonical(d.metadata['Name']): d.version for d in metadata.distributions()}, sort_keys=True))
"""
    inventory_result = run(
        [str(venv / "bin/python"), "-I", "-c", inventory_code],
        env=clean_env,
    )
    try:
        observed = json.loads(inventory_result.stdout)
    except json.JSONDecodeError as exc:
        raise VerifyError(f"invalid installed inventory for {environment}") from exc
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        mismatched = sorted(name for name in set(expected) & set(observed) if expected[name] != observed[name])
        raise VerifyError(
            f"exact inventory mismatch for {environment}: missing={missing}, extra={extra}, versions={mismatched}"
        )
    for code in SMOKES.get(environment, []):
        run([str(venv / "bin/python"), "-I", "-c", code], env=clean_env)
    command = CLI_SMOKES.get(environment)
    if command:
        run([str(venv / "bin" / command[0]), *command[1:]], env=clean_env)
    print(f"offline environment OK: {environment} ({len(expected)} distributions)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--platform", required=True, choices=("linux/amd64", "linux/arm64"))
    parser.add_argument("--python", default="python3")
    args = parser.parse_args(argv)
    try:
        validate_wheelhouse(args.wheelhouse, args.platform)
        with tempfile.TemporaryDirectory(prefix="python-wheelhouse-offline-") as temporary:
            verify_root = Path(temporary)
            for environment in ENVIRONMENTS:
                verify_environment(args.wheelhouse, environment, verify_root, args.python)
        print(f"offline wheelhouse OK: {args.platform}")
        return 0
    except (WheelhouseError, VerifyError, OSError, subprocess.SubprocessError) as exc:
        print(f"verify-python-wheelhouse: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
