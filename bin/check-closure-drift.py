#!/usr/bin/python3
"""Report release-lock drift without mutating restoration inputs."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.fspath(REPO / "bin/lib"))
from component_paths import (  # noqa: E402
    ComponentPathError,
    _head,
    installed_component_path,
)

GENERATION_REFERENCE = re.compile(
    r"/\.local/libexec/openclaw-bot/generations/([0-9a-f]{64})(?![0-9a-f])"
)
HOST_RUNTIME_SCHEMA = "openclaw.host-runtime/v1"


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


def running_generations(home: Path) -> list[str]:
    """Host-runtime generations that the installed user units execute from."""
    units = home / ".config/systemd/user"
    found: set[str] = set()
    if units.is_dir() and not units.is_symlink():
        for path in sorted(units.rglob("*")):
            if (
                path.suffix in {".service", ".timer", ".conf"}
                and path.is_file()
                and not path.is_symlink()
            ):
                text = path.read_text(encoding="utf-8", errors="replace")
                found.update(GENERATION_REFERENCE.findall(text))
    return sorted(found)


def host_artifact_sources(component: Path) -> dict[str, str]:
    """Destination -> source file, read as data from the component's HOST_ARTIFACTS."""
    tree = ast.parse(
        (component / "scripts/service_transaction.py").read_text(encoding="utf-8")
    )
    for node in tree.body:
        if isinstance(node, ast.AnnAssign):
            target = node.target
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        else:
            continue
        if isinstance(target, ast.Name) and target.id == "HOST_ARTIFACTS" and node.value:
            return {
                destination: source
                for destination, source, _interpreter in ast.literal_eval(node.value)
            }
    raise ValueError("component does not declare HOST_ARTIFACTS")


def generation_commit(
    home: Path, generation: str, component: Path, commit: str | None
) -> tuple[str | None, str | None]:
    """The store commit whose files built a generation, and its OpenClaw version."""
    manifest_path = (
        home / ".local/libexec/openclaw-bot/generations" / generation / "MANIFEST.json"
    )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        version = manifest["externalRuntime"]["version"]
        if (
            commit is None
            or manifest.get("schema") != HOST_RUNTIME_SCHEMA
            or manifest.get("generation") != generation
        ):
            return None, version
        sources = host_artifact_sources(component)
        artifacts = manifest["artifacts"]
        if set(artifacts) != set(sources):
            return None, version
        for destination, record in artifacts.items():
            payload = (component / sources[destination]).read_bytes()
            if hashlib.sha256(payload).hexdigest() != record["sha256"]:
                return None, version
    except (OSError, ValueError, SyntaxError, KeyError, TypeError):
        return None, None
    return commit, version


def component_observation(repository: Path, home: Path, name: str) -> dict[str, Any]:
    # The installer runs the immutable store copy at the locked commit, and the
    # services run the host generation it built; development checkouts are not
    # restore state.
    generations = running_generations(home)
    observation: dict[str, Any] = {
        "available": False,
        "generations": generations,
        "running_commit": None,
        "openclaw_version": None,
    }
    try:
        path = installed_component_path(repository, home, name)
    except ComponentPathError:
        return observation
    observation["source"] = str(path)
    if path.is_symlink() or not path.is_dir():
        return observation
    head = _head(path)
    rc, porcelain = run("/usr/bin/git", "--no-optional-locks", "-C", str(path), "status", "--porcelain")
    observation.update(available=bool(head), commit=head, dirty=rc != 0 or bool(porcelain))
    if len(generations) == 1:
        observation["running_commit"], observation["openclaw_version"] = generation_commit(
            home, generations[0], path, head
        )
    return observation


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


def upstream_observation(repository: Path, lock: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    rc, version = run("npm", "view", "openclaw", "version", timeout=30)
    result["openclaw_latest"] = version if rc == 0 else None

    component_name = lock["component"]["name"]
    url = None
    for line in (repository / "components.lock").read_text().splitlines():
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
    parser.add_argument("--repository", type=Path, default=REPO)
    parser.add_argument("--home", type=Path, default=Path.home())
    args = parser.parse_args()

    repository = args.repository.resolve()
    lock = json.loads((repository / "system/openclaw/compatibility.lock.json").read_text())
    component = component_observation(repository, args.home, lock["component"]["name"])
    observed = {
        "openclaw_version": installed_openclaw(),
        "component": component,
        "sandbox": image_observation(lock["sandbox"]["image"]),
    }
    drift = {
        "openclaw": observed["openclaw_version"] not in (None, lock["openclaw"]["version"]),
        "component": bool(component["generations"])
        and component["running_commit"] != lock["component"]["commit"],
        "component_dirty": bool(component.get("dirty")),
        "generation_mixed": len(component["generations"]) > 1,
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
        report["upstream"] = upstream_observation(repository, lock)
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
