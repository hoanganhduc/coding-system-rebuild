#!/usr/bin/env python3
"""Atomically converge live OpenClaw compatibility and least-privilege policy."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time


def read_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    args = parser.parse_args()

    config = read_object(args.config)
    lock = read_object(args.lock)
    expected = lock["sandbox"]["image"]  # type: ignore[index]
    if not isinstance(expected, str) or "@sha256:" not in expected:
        raise ValueError("compatibility lock sandbox image is not immutable")
    changed = False

    agents = config.get("agents")
    if not isinstance(agents, dict):
        raise ValueError("OpenClaw agents configuration is invalid")
    sandboxes: list[dict[str, object]] = []
    defaults = agents.get("defaults")
    if not isinstance(defaults, dict):
        raise ValueError("OpenClaw default agent configuration is invalid")
    default_sandbox = defaults.get("sandbox")
    if not isinstance(default_sandbox, dict):
        raise ValueError("OpenClaw default sandbox configuration is invalid")
    sandboxes.append(default_sandbox)
    listed = agents.get("list", [])
    if not isinstance(listed, list):
        raise ValueError("OpenClaw agent list is invalid")
    for agent in listed:
        if isinstance(agent, dict) and isinstance(agent.get("sandbox"), dict):
            sandboxes.append(agent["sandbox"])

    for sandbox in sandboxes:
        docker = sandbox.get("docker")
        if not isinstance(docker, dict):
            continue
        dangerous_external_binds = docker.pop("dangerouslyAllowExternalBindSources", None)
        if dangerous_external_binds is not None:
            changed = True
        if dangerous_external_binds is True and docker.get("binds"):
            docker["binds"] = []
            changed = True
        for key, value in (
            ("image", expected),
            ("user", "1001:1001"),
            ("pidsLimit", 512),
            ("memory", "4g"),
            ("memorySwap", "4g"),
            ("cpus", 2),
            ("readOnlyRoot", True),
        ):
            if docker.get(key) != value:
                docker[key] = value
                changed = True

    model = defaults.get("model")
    if isinstance(model, dict) and isinstance(model.get("fallbacks"), list):
        forbidden_fallbacks = {"groq/openai/gpt-oss-120b"}
        filtered_fallbacks = [
            value for value in model["fallbacks"] if value not in forbidden_fallbacks
        ]
        if filtered_fallbacks != model["fallbacks"]:
            model["fallbacks"] = filtered_fallbacks
            changed = True

    tools = config.setdefault("tools", {})
    if not isinstance(tools, dict):
        raise ValueError("OpenClaw tools configuration is invalid")
    elevated = tools.setdefault("elevated", {})
    exec_policy = tools.setdefault("exec", {})
    if not isinstance(elevated, dict) or not isinstance(exec_policy, dict):
        raise ValueError("OpenClaw execution policy is invalid")
    for target, key, value in (
        (elevated, "enabled", False),
        (exec_policy, "host", "sandbox"),
        (exec_policy, "security", "allowlist"),
        (exec_policy, "ask", "on-miss"),
        (exec_policy, "strictInlineEval", True),
    ):
        if target.get(key) != value:
            target[key] = value
            changed = True

    channels = config.get("channels", {})
    if not isinstance(channels, dict):
        raise ValueError("OpenClaw channels configuration is invalid")
    googlechat = channels.get("googlechat")
    if isinstance(googlechat, dict) and googlechat.get("enabled") is True:
        if googlechat.get("groupPolicy") != "allowlist":
            googlechat["groupPolicy"] = "allowlist"
            changed = True
        current_allow = googlechat.get("groupAllowFrom", [])
        if not isinstance(current_allow, list):
            raise ValueError("Google Chat groupAllowFrom must be a list")
        filtered_allow = [entry for entry in current_allow if str(entry).strip() != "*"]
        if filtered_allow != current_allow:
            googlechat["groupAllowFrom"] = filtered_allow
            changed = True

    if not changed:
        print(f"OpenClaw config compatibility and policy: current: {args.config}")
        return 0

    mode = stat.S_IMODE(args.config.stat().st_mode)
    backup = args.config.with_name(
        f"{args.config.name}.bak.compat-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    )
    shutil.copy2(args.config, backup)
    os.chmod(backup, mode)
    payload = (json.dumps(config, indent=2, ensure_ascii=False) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(
        dir=args.config.parent, prefix=f".{args.config.name}."
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, args.config)
        directory = os.open(args.config.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"OpenClaw config compatibility and policy: updated: {args.config}")
    print(f"OpenClaw config compatibility and policy: backup: {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
