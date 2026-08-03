#!/usr/bin/env python3
"""Fail-closed verification for the tested OpenClaw compatibility tuple."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _run(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _git_blob(repository: Path, commit: str, relative: str) -> bytes | None:
    result = subprocess.run(
        ["git", "-C", str(repository), "show", f"{commit}:{relative}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def _component_pin(repo: Path) -> str | None:
    pins = []
    for line in (repo / "components.lock").read_text(encoding="utf-8").splitlines():
        if line.startswith("openclaw-bot="):
            pins.append(line.rsplit("@", 1)[-1])
    return pins[0] if len(pins) == 1 else None


def _npm_pin(repo: Path) -> str | None:
    pins = []
    for line in (repo / "system/packages/npm-globals.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("openclaw@"):
            pins.append(line.removeprefix("openclaw@"))
    return pins[0] if len(pins) == 1 else None


def verify_static(repo: Path, lock: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if lock.get("schema_version") != 1:
        failures.append("compatibility lock schema_version must be 1")
        return failures

    openclaw = lock.get("openclaw", {})
    component = lock.get("component", {})
    sandbox = lock.get("sandbox", {})
    if _npm_pin(repo) != openclaw.get("version"):
        failures.append("OpenClaw npm pin differs from compatibility lock")
    commit = component.get("commit")
    if not isinstance(commit, str) or COMMIT.fullmatch(commit) is None:
        failures.append("component commit is not one full Git commit")
    elif _component_pin(repo) != commit:
        failures.append("openclaw-bot component pin differs from compatibility lock")

    component_repo = repo / "external/openclaw-bot"
    template_blob = (
        _git_blob(component_repo, commit, "config/openclaw.json.template")
        if isinstance(commit, str) and COMMIT.fullmatch(commit)
        else None
    )
    if template_blob is None:
        failures.append("locked OpenClaw config template Git blob is missing")
    else:
        expected_hash = component.get("config_template_sha256")
        if _sha256_bytes(template_blob) != expected_hash:
            failures.append("locked OpenClaw config template hash differs from compatibility lock")
        try:
            configured_image = json.loads(template_blob)["agents"]["defaults"]["sandbox"]["docker"]["image"]
        except (KeyError, TypeError, json.JSONDecodeError):
            failures.append("locked OpenClaw config template has no valid sandbox image")
        else:
            if configured_image != sandbox.get("image"):
                failures.append("locked config template sandbox image differs from compatibility lock")

    manifest_blob = (
        _git_blob(component_repo, commit, "REBUILD-MANIFEST.json")
        if isinstance(commit, str) and COMMIT.fullmatch(commit)
        else None
    )
    if manifest_blob is None:
        failures.append("locked component rebuild manifest Git blob is missing")
    else:
        try:
            observed_version = json.loads(manifest_blob)["openclaw"]["observed_version"]
        except (KeyError, TypeError, json.JSONDecodeError):
            failures.append("locked component rebuild manifest is invalid")
        else:
            if observed_version != openclaw.get("version"):
                failures.append("component OpenClaw version differs from compatibility lock")

    closure_path = repo / "system/openclaw/skill-closure.json"
    if not closure_path.is_file() or _sha256(closure_path) != lock.get("skill_closure_sha256"):
        failures.append("skill dependency closure hash differs from compatibility lock")

    image = sandbox.get("image")
    index_digest = sandbox.get("index_digest")
    if not isinstance(index_digest, str) or SHA256.fullmatch(index_digest) is None:
        failures.append("sandbox index digest is invalid")
    if not isinstance(image, str) or not image.endswith(f"@{index_digest}"):
        failures.append("sandbox image is not pinned by the locked index digest")
    platforms = sandbox.get("platform_digests")
    if not isinstance(platforms, dict) or set(platforms) != {"linux/amd64", "linux/arm64"}:
        failures.append("sandbox platform digest set must be exactly amd64 and arm64")
    elif any(not isinstance(value, str) or SHA256.fullmatch(value) is None for value in platforms.values()):
        failures.append("one or more sandbox platform digests are invalid")
    return failures


def verify_live(repo: Path, home: Path, lock: dict[str, Any], online: bool) -> list[str]:
    failures: list[str] = []
    expected_version = lock["openclaw"]["version"]
    result = _run(["openclaw", "--version"])
    if result.returncode != 0 or expected_version not in result.stdout.split():
        failures.append(f"installed OpenClaw is not {expected_version}")

    component_repo = repo / "external/openclaw-bot"
    result = _run(["git", "-C", str(component_repo), "rev-parse", "HEAD"])
    if result.returncode != 0 or result.stdout.strip() != lock["component"]["commit"]:
        failures.append("installed openclaw-bot checkout is not the locked commit")
    result = _run(["git", "-C", str(component_repo), "status", "--porcelain"])
    if result.returncode != 0 or result.stdout.strip():
        failures.append("installed openclaw-bot checkout is dirty")

    schema = _run(["openclaw", "config", "schema"], timeout=60)
    if schema.returncode != 0 or _sha256_bytes(schema.stdout.encode()) != lock["openclaw"].get(
        "config_schema_sha256"
    ):
        failures.append("installed OpenClaw config schema differs from compatibility lock")

    live_config = home / ".openclaw/openclaw.json"
    if not live_config.is_file():
        failures.append("live OpenClaw config is missing")
    else:
        try:
            live_image = _read_json(live_config)["agents"]["defaults"]["sandbox"]["docker"]["image"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            failures.append("live OpenClaw config has no valid sandbox image")
        else:
            if live_image != lock["sandbox"]["image"]:
                failures.append("live sandbox image differs from compatibility lock")

    image = lock["sandbox"]["image"]
    result = _run(["docker", "image", "inspect", image])
    if result.returncode != 0:
        failures.append("locked sandbox image is absent from the local Docker daemon")

    if online:
        npm = _run(
            ["npm", "view", f"openclaw@{expected_version}", "dist.integrity", "--json"],
            timeout=60,
        )
        try:
            observed_integrity = json.loads(npm.stdout)
        except json.JSONDecodeError:
            observed_integrity = None
        if npm.returncode != 0 or observed_integrity != lock["openclaw"].get("npm_integrity"):
            failures.append("OpenClaw npm integrity differs from compatibility lock")
        result = _run(["docker", "manifest", "inspect", image], timeout=90)
        if result.returncode != 0:
            failures.append("cannot inspect locked sandbox manifest")
        else:
            try:
                manifest = json.loads(result.stdout)
                observed = {
                    f"linux/{entry['platform']['architecture']}": entry["digest"]
                    for entry in manifest.get("manifests", [])
                    if entry.get("platform", {}).get("os") == "linux"
                }
            except (KeyError, TypeError, json.JSONDecodeError):
                failures.append("locked sandbox manifest is malformed")
            else:
                if observed != lock["sandbox"]["platform_digests"]:
                    failures.append("sandbox manifest platform digests differ from compatibility lock")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    lock_path = args.repo / "system/openclaw/compatibility.lock.json"
    try:
        lock = _read_json(lock_path)
        failures = verify_static(args.repo, lock)
        if not args.static_only:
            failures.extend(verify_live(args.repo, args.home, lock, not args.offline))
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        failures = [f"compatibility verification error: {exc}"]
    payload = {
        "schema_version": 1,
        "status": "passed" if not failures else "failed",
        "failures": failures,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    elif failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
    else:
        print("OpenClaw compatibility tuple: passed")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
