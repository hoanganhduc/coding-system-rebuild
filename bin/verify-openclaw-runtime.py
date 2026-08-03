#!/usr/bin/python3
"""Fail-closed verification of the effective OpenClaw skill environment."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from typing import Any


REPO = Path(__file__).resolve().parents[1]


def command(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def json_command(argv: list[str], failures: list[str], label: str, timeout: int = 60) -> Any:
    try:
        result = command(argv, timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        failures.append(f"{label}: command failed: {exc}")
        return None
    if result.returncode != 0:
        failures.append(f"{label}: exited {result.returncode}")
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        failures.append(f"{label}: output was not JSON")
        return None


def names(values: Any) -> set[str]:
    if not isinstance(values, list):
        return set()
    return {
        str(value.get("name")) if isinstance(value, dict) else str(value)
        for value in values
    }


def validate_manifest(closure: dict[str, Any], failures: list[str]) -> None:
    if closure.get("schema_version") != 1:
        failures.append("skill closure schema_version is not 1")
    required = closure.get("required_eligible_skills")
    if not isinstance(required, list) or not required or len(required) != len(set(required)):
        failures.append("required skill inventory is absent or contains duplicates")
    plugins = closure.get("required_plugins")
    if not isinstance(plugins, dict) or not plugins:
        failures.append("required plugin inventory is absent")
    channels = closure.get("required_channels")
    if not isinstance(channels, list) or not channels:
        failures.append("required channel inventory is absent")


def verify_config(home: Path, closure: dict[str, Any], lock: dict[str, Any], failures: list[str]) -> None:
    path = home / ".openclaw/openclaw.json"
    try:
        config = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"OpenClaw config cannot be read: {exc}")
        return

    security = closure["security"]
    tools = config.get("tools", {})
    elevated = tools.get("elevated", {})
    exec_policy = tools.get("exec", {})
    if elevated.get("enabled") is not security["elevated_enabled"]:
        failures.append("elevated-tool policy differs from closure")
    if exec_policy.get("host") != security["exec_host"]:
        failures.append("exec host differs from closure")
    if exec_policy.get("security") != security["exec_security"]:
        failures.append("exec security differs from closure")
    if exec_policy.get("ask") != security["exec_ask"]:
        failures.append("exec approval mode differs from closure")
    if exec_policy.get("strictInlineEval") is not security["strict_inline_eval"]:
        failures.append("inline-eval approval policy differs from closure")

    googlechat = config.get("channels", {}).get("googlechat", {})
    if googlechat.get("enabled") is True:
        if googlechat.get("groupPolicy") != security["googlechat_group_policy"]:
            failures.append("Google Chat group policy is not owner-allowlisted")
        if any(str(value).strip() == "*" for value in googlechat.get("groupAllowFrom", [])):
            failures.append("Google Chat group allowlist contains a wildcard")

    expected_image = lock["sandbox"]["image"]
    resources = closure["sandbox"]
    agents = config.get("agents", {})
    default_agent = agents.get("defaults", {})
    default_docker = default_agent.get("sandbox", {}).get("docker", {})
    candidates = [("defaults", default_docker)]
    for agent in agents.get("list", []):
        if not isinstance(agent, dict):
            continue
        override = agent.get("sandbox", {}).get("docker", {})
        if not isinstance(override, dict):
            override = {}
        candidates.append((str(agent.get("id", "unknown")), {**default_docker, **override}))
    for label, docker in candidates:
        if not isinstance(docker, dict) or not docker:
            failures.append(f"sandbox {label} has no effective Docker configuration")
            continue
        if closure["forbid_external_bind_override"] and docker.get(
            "dangerouslyAllowExternalBindSources"
        ) is True:
            failures.append(f"sandbox {label} enables external bind override")
        expected = {
            "image": expected_image,
            "user": resources["runtime_user"],
            "pidsLimit": resources["pids_limit"],
            "memory": resources["memory"],
            "memorySwap": resources["memory_swap"],
            "cpus": resources["cpus"],
            "readOnlyRoot": True,
        }
        for key, value in expected.items():
            if docker.get(key) != value:
                failures.append(f"sandbox {label} {key} differs from closure")
    fallback_models = default_agent.get("model", {}).get("fallbacks", [])
    forbidden = set(closure["forbidden_model_fallbacks"])
    active_forbidden = sorted(forbidden.intersection(fallback_models))
    if active_forbidden:
        failures.append("forbidden weak model fallbacks: " + ", ".join(active_forbidden))


def verify_skills(closure: dict[str, Any], failures: list[str], report: dict[str, Any]) -> None:
    data = json_command(["openclaw", "skills", "check", "--json"], failures, "skills check")
    if not isinstance(data, dict):
        return
    eligible = names(data.get("eligible"))
    required = set(closure["required_eligible_skills"])
    missing = sorted(required - eligible)
    unexpected = sorted(eligible - required)
    if missing:
        failures.append("required skills not eligible: " + ", ".join(missing))
    if unexpected:
        failures.append("eligible skill inventory drift: " + ", ".join(unexpected))
    blocked = names(data.get("blocked"))
    missing_requirements = names(data.get("missingRequirements"))
    if blocked:
        failures.append("blocked skills: " + ", ".join(sorted(blocked)))
    if missing_requirements:
        failures.append("skills missing requirements: " + ", ".join(sorted(missing_requirements)))
    classifications: dict[str, str] = {}
    for name in sorted(eligible):
        classifications[name] = "required-ready"
    for name in sorted(names(data.get("disabled")) - eligible):
        classifications[name] = "disabled-optional"
    for name in sorted(names(data.get("notInjected")) & eligible):
        classifications[name] = "ready-command-only"
    for name in sorted(blocked | missing_requirements):
        classifications[name] = "failed-required"
    report["skills"] = {
        "summary": data.get("summary", {}),
        "classifications": classifications,
    }


def verify_plugins(closure: dict[str, Any], failures: list[str]) -> None:
    doctor = command(["openclaw", "plugins", "doctor"], timeout=60)
    if doctor.returncode != 0:
        failures.append("plugin doctor failed")
    data = json_command(["openclaw", "plugins", "list", "--json"], failures, "plugins list")
    if not isinstance(data, dict):
        return
    observed = {
        item.get("id"): item
        for item in data.get("plugins", [])
        if isinstance(item, dict) and item.get("id")
    }
    for plugin, version in closure["required_plugins"].items():
        item = observed.get(plugin)
        if not item or item.get("status") != "loaded" or item.get("version") != version:
            failures.append(f"plugin {plugin} is not loaded at {version}")


def verify_channels(closure: dict[str, Any], failures: list[str]) -> None:
    data = json_command(
        ["openclaw", "channels", "status", "--probe", "--json", "--timeout", "15000"],
        failures,
        "channel probes",
        timeout=45,
    )
    if not isinstance(data, dict):
        return
    channels = data.get("channels", {})
    for channel in closure["required_channels"]:
        status = channels.get(channel)
        if not isinstance(status, dict) or not status.get("configured") or not status.get("running"):
            failures.append(f"channel {channel} is not configured and running")
            continue
        probe = status.get("probe")
        if isinstance(probe, dict) and probe.get("ok") is not True:
            failures.append(f"channel {channel} credential probe failed")
        if channel == "whatsapp" and not status.get("connected"):
            failures.append("channel whatsapp is not connected")


def verify_security(closure: dict[str, Any], failures: list[str]) -> None:
    data = json_command(
        ["openclaw", "security", "audit", "--deep", "--json"],
        failures,
        "deep security audit",
        timeout=90,
    )
    if isinstance(data, dict):
        critical = data.get("summary", {}).get("critical")
        if not isinstance(critical, int) or critical > closure["security"]["maximum_critical"]:
            failures.append(f"deep security audit has {critical!r} critical findings")


def verify_image(closure: dict[str, Any], lock: dict[str, Any], failures: list[str]) -> None:
    resources = closure["sandbox"]
    image = lock["sandbox"]["image"]
    argv = [
        "docker", "run", "--rm", "--read-only", "--network", "none",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", str(resources["pids_limit"]),
        "--memory", resources["memory"], "--memory-swap", resources["memory_swap"],
        "--cpus", str(resources["cpus"]),
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m",
        "--tmpfs", "/var/tmp:rw,nosuid,nodev,noexec,size=64m",
        "--tmpfs", "/run:rw,nosuid,nodev,noexec,size=64m",
        "--tmpfs", "/workspace:rw,nosuid,nodev,size=256m,uid=1001,gid=1001,mode=0700",
        image, "verify-openclaw-sandbox",
    ]
    try:
        result = command(argv, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        failures.append(f"sandbox image contract failed: {exc}")
        return
    if result.returncode != 0:
        failures.append(f"sandbox image contract exited {result.returncode}")


def verify_host_artifacts(home: Path, closure: dict[str, Any], failures: list[str]) -> None:
    for relative in closure["required_host_artifacts"]:
        path = home / relative
        if not path.exists():
            failures.append(f"required host artifact missing: ~/{relative}")
    runner = home / ".codex/runtime/run_skill.sh"
    if runner.exists() and not os.access(runner, os.X_OK):
        failures.append("Codex runtime runner is not executable")

    metadata = closure["calibre_metadata"]
    database = home / metadata["path"]
    if not database.is_file():
        failures.append("Calibre metadata database is missing")
        return
    try:
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
            check = connection.execute("PRAGMA quick_check").fetchone()
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (metadata["required_table"],),
            ).fetchone()
    except sqlite3.Error as exc:
        failures.append(f"Calibre metadata database is invalid: {exc}")
        return
    if check != (metadata["quick_check"],) or table != (1,):
        failures.append("Calibre metadata database failed its closure contract")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("full", "ci"), default="full")
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    closure = json.loads((REPO / "system/openclaw/skill-closure.json").read_text())
    lock = json.loads((REPO / "system/openclaw/compatibility.lock.json").read_text())
    failures: list[str] = []
    report: dict[str, Any] = {"schema_version": 1, "profile": args.profile}
    validate_manifest(closure, failures)
    skipped: list[str] = []
    if args.profile == "full":
        config_validation = command(["openclaw", "config", "validate"], timeout=60)
        if config_validation.returncode != 0:
            failures.append("OpenClaw config validation failed")
        health = json_command(["openclaw", "health", "--json"], failures, "gateway health")
        if not isinstance(health, dict):
            failures.append("gateway health is unavailable")
        verify_config(args.home, closure, lock, failures)
        verify_host_artifacts(args.home, closure, failures)
        verify_plugins(closure, failures)
        verify_skills(closure, failures, report)
        verify_channels(closure, failures)
        verify_security(closure, failures)
        verify_image(closure, lock, failures)
    else:
        skipped = [
            "live config and gateway",
            "secret-backed channel probes",
            "live skill registry and plugin loading",
            "Calibre owner data and Codex runtime",
            "sandbox image execution",
            "deep security audit",
        ]

    report["status"] = "passed" if not failures else "failed"
    report["failures"] = failures
    report["skipped"] = skipped
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        tmp = args.output.with_name(args.output.name + f".tmp.{os.getpid()}")
        tmp.write_text(encoded)
        os.chmod(tmp, 0o644)
        os.replace(tmp, args.output)
    print(encoded, end="")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
