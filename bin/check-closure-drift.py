#!/usr/bin/python3
"""Report release-lock drift without mutating restoration inputs."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


REPO = Path(__file__).resolve().parents[1]
LOCK_PATH = REPO / "system/openclaw/compatibility.lock.json"


def run(*argv: str, timeout: int = 20) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return proc.returncode, proc.stdout.strip()


def component_path(name: str) -> Path | None:
    # The installer consumes the checkout under this repository. A separate
    # ~/name tree may be an older authoring checkout and is not restore state.
    candidates = (REPO / "external" / name, Path.home() / name)
    return next((path for path in candidates if (path / ".git").exists()), None)


def component_observation(name: str) -> dict[str, Any]:
    path = component_path(name)
    if path is None:
        return {"available": False}
    _, head = run("git", "-C", str(path), "rev-parse", "HEAD")
    rc, porcelain = run("git", "-C", str(path), "status", "--porcelain")
    return {
        "available": bool(head),
        "commit": head or None,
        "dirty": rc != 0 or bool(porcelain),
        "source": str(path),
    }


def installed_openclaw() -> str | None:
    rc, raw = run("npm", "ls", "-g", "--depth=0", "--json")
    if rc not in (0, 1) or not raw:
        return None
    try:
        return json.loads(raw).get("dependencies", {}).get("openclaw", {}).get("version")
    except json.JSONDecodeError:
        return None


def image_observation(image: str) -> dict[str, Any]:
    rc, raw = run("docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}")
    if rc != 0:
        return {"present": False}
    try:
        digests = json.loads(raw)
    except json.JSONDecodeError:
        digests = []
    return {"present": True, "repo_digests": sorted(digests or [])}


def upstream_observation(lock: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    rc, version = run("npm", "view", "openclaw", "version", timeout=30)
    result["openclaw_latest"] = version if rc == 0 else None

    component_name = lock["component"]["name"]
    url = None
    for line in (REPO / "components.lock").read_text().splitlines():
        if line.startswith(component_name + "="):
            url = line.split("=", 1)[1].rsplit("@", 1)[0]
            break
    rc, remote = run("git", "ls-remote", url or "", "HEAD", timeout=30)
    result["component_default_head"] = remote.split()[0] if rc == 0 and remote else None
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare the live installation with the immutable OpenClaw release tuple."
    )
    parser.add_argument("--output", type=Path, help="also write canonical JSON to this path")
    parser.add_argument("--upstream", action="store_true", help="query upstream release heads")
    parser.add_argument("--fail-on-drift", action="store_true")
    args = parser.parse_args()

    lock = json.loads(LOCK_PATH.read_text())
    component = component_observation(lock["component"]["name"])
    observed = {
        "openclaw_version": installed_openclaw(),
        "component": component,
        "sandbox": image_observation(lock["sandbox"]["image"]),
    }
    drift = {
        "openclaw": observed["openclaw_version"] not in (None, lock["openclaw"]["version"]),
        "component": bool(component.get("commit"))
        and component.get("commit") != lock["component"]["commit"],
        "component_dirty": bool(component.get("dirty")),
        "sandbox_missing": not observed["sandbox"]["present"],
    }
    report: dict[str, Any] = {
        "schema_version": 1,
        "policy": "observe-only; promote the complete tested tuple, never partial pins",
        "release": {
            "openclaw_version": lock["openclaw"]["version"],
            "component_commit": lock["component"]["commit"],
            "sandbox_image": lock["sandbox"]["image"],
        },
        "observed": observed,
        "drift": drift,
    }
    if args.upstream:
        report["upstream"] = upstream_observation(lock)
        report["drift"]["openclaw_upstream"] = report["upstream"]["openclaw_latest"] not in (
            None,
            lock["openclaw"]["version"],
        )
        report["drift"]["component_upstream"] = report["upstream"][
            "component_default_head"
        ] not in (None, lock["component"]["commit"])

    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        tmp = args.output.with_name(args.output.name + f".tmp.{os.getpid()}")
        tmp.write_text(encoded)
        os.chmod(tmp, 0o644)
        os.replace(tmp, args.output)
    sys.stdout.write(encoded)
    any_drift = any(value for value in drift.values())
    return 1 if args.fail_on_drift and any_drift else 0


if __name__ == "__main__":
    raise SystemExit(main())
