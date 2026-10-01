#!/usr/bin/python3
"""Fail-closed verification of the effective OpenClaw skill environment."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any


REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "bin/lib"
if os.fspath(LIB) not in sys.path:
    sys.path.insert(0, os.fspath(LIB))
from component_paths import ComponentPathError, resolve_component_path  # noqa: E402
AUTH_REPORT_SCHEMA = "openclaw.agent-auth-closure/v2"
AUTH_METADATA_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
AUTH_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def configured_runtime_user(resources: dict[str, Any]) -> str:
    if resources.get("runtime_user") != "host-owner":
        raise ValueError("sandbox runtime_user must be host-owner")
    return f"{os.getuid()}:{os.getgid()}"


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
        try:
            runtime_user = configured_runtime_user(resources)
        except ValueError as exc:
            failures.append(str(exc))
            return
        expected = {
            "image": expected_image,
            "user": runtime_user,
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
    expected_contract = lock["sandbox"].get("contract")
    image_default_user = resources.get("image_default_user")
    if not isinstance(image_default_user, str) or not image_default_user.replace(":", "").isdigit():
        failures.append("sandbox image default user declaration is invalid")
        return
    image_uid, image_gid = image_default_user.split(":", 1)
    inspected = command(
        [
            "docker", "image", "inspect", "--format",
            "{{ index .Config.Labels \"io.hoanganhduc.openclaw-sandbox.contract\" }}",
            image,
        ],
        timeout=30,
    )
    if inspected.returncode != 0:
        failures.append("locked sandbox image metadata is unavailable")
        return
    if not isinstance(expected_contract, int) or inspected.stdout.strip() != str(expected_contract):
        failures.append("locked sandbox image contract differs from compatibility lock")
        return
    argv = [
        "docker", "run", "--rm", "--read-only", "--network", "none",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", str(resources["pids_limit"]),
        "--memory", resources["memory"], "--memory-swap", resources["memory_swap"],
        "--cpus", str(resources["cpus"]),
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m",
        "--tmpfs", "/var/tmp:rw,nosuid,nodev,noexec,size=64m",
        "--tmpfs", "/run:rw,nosuid,nodev,noexec,size=64m",
        "--tmpfs",
        f"/workspace:rw,nosuid,nodev,size=256m,uid={image_uid},gid={image_gid},mode=0700",
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


def sanitize_agent_auth_report(value: object) -> dict[str, Any]:
    """Admit only the helper's metadata schema before it reaches a file or log."""

    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema",
            "status",
            "runtimeVersion",
            "verificationMode",
            "openclawExecuted",
            "networkEnabled",
            "agents",
            "failureCount",
            "failures",
        }
        or value.get("schema") != AUTH_REPORT_SCHEMA
        or value.get("status") != "PASS"
        or not isinstance(value.get("runtimeVersion"), str)
        or AUTH_METADATA_NAME_RE.fullmatch(value["runtimeVersion"]) is None
        or value.get("verificationMode") != "offline-structural-only"
        or value.get("openclawExecuted") is not False
        or value.get("networkEnabled") is not False
        or value.get("failureCount") != 0
        or isinstance(value.get("failureCount"), bool)
        or value.get("failures") != []
        or not isinstance(value.get("agents"), list)
        or not value["agents"]
    ):
        raise ValueError("OpenClaw agent-auth helper metadata is invalid")
    sanitized_agents: list[dict[str, Any]] = []
    seen_agents: set[str] = set()
    for agent in value["agents"]:
        if (
            not isinstance(agent, dict)
            or set(agent) != {
                "agentId",
                "status",
                "canonicalStore",
                "reasons",
            }
            or not isinstance(agent.get("agentId"), str)
            or AUTH_AGENT_ID_RE.fullmatch(agent["agentId"]) is None
            or agent["agentId"] in seen_agents
            or agent.get("status") != "PASS"
            or agent.get("reasons") != []
        ):
            raise ValueError("OpenClaw agent-auth helper agent metadata is invalid")
        seen_agents.add(agent["agentId"])
        store = agent.get("canonicalStore")
        store_keys = {
            "exists",
            "integrity",
            "schemaVersion",
            "appVersion",
            "authStoreRows",
            "profileCount",
            "configured",
            "authorityJsonValid",
            "executableSecretRefFree",
            "credentialSourceKinds",
            "redactionSentinelFree",
            "device",
            "inode",
            "size",
            "mtimeNs",
            "ctimeNs",
        }
        if not isinstance(store, dict) or set(store) != store_keys:
            raise ValueError("OpenClaw agent-auth helper store metadata is invalid")
        exists = store.get("exists")
        if not isinstance(exists, bool):
            raise ValueError("OpenClaw agent-auth helper store metadata is invalid")
        if exists:
            if (
                store.get("integrity") is not True
                or isinstance(store.get("schemaVersion"), bool)
                or store.get("schemaVersion") != 1
                or (
                    store.get("appVersion") is not None
                    and store.get("appVersion") != value["runtimeVersion"]
                )
                or store.get("configured") is not True
                or store.get("authorityJsonValid") is not True
                or store.get("executableSecretRefFree") is not True
                or store.get("redactionSentinelFree") is not True
                or not isinstance(store.get("credentialSourceKinds"), list)
                or not all(
                    isinstance(kind, str)
                    for kind in store["credentialSourceKinds"]
                )
                or store["credentialSourceKinds"]
                != sorted(set(store["credentialSourceKinds"]))
                or any(
                    kind not in {"env", "file"}
                    for kind in store["credentialSourceKinds"]
                )
                or any(
                    isinstance(store.get(key), bool)
                    or not isinstance(store.get(key), int)
                    or store[key] < 0
                    for key in (
                        "authStoreRows",
                        "profileCount",
                        "device",
                        "inode",
                        "size",
                        "mtimeNs",
                        "ctimeNs",
                    )
                )
                or store["profileCount"] <= 0
            ):
                raise ValueError("OpenClaw agent-auth helper store metadata is invalid")
        elif any(store.get(key) is not None for key in store_keys - {"exists"}):
            raise ValueError("OpenClaw agent-auth helper store metadata is invalid")
        sanitized_agents.append(
            {
                "agentId": agent["agentId"],
                "status": "PASS",
                "canonicalStore": dict(store),
                "reasons": [],
            }
        )
    return {
        "schema": AUTH_REPORT_SCHEMA,
        "status": "PASS",
        "runtimeVersion": value["runtimeVersion"],
        "verificationMode": "offline-structural-only",
        "openclawExecuted": False,
        "networkEnabled": False,
        "agents": sanitized_agents,
        "failureCount": 0,
        "failures": [],
    }


def verify_agent_auth(home: Path, failures: list[str], report: dict[str, Any]) -> None:
    try:
        component_root = resolve_component_path(
            REPO, home, "openclaw-bot", source_fallback=True, require=True
        )
        helper = component_root / "scripts/openclaw_auth_closure.py"
        manifest_path = component_root / "REBUILD-MANIFEST.json"
        component = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected_version = component["openclaw"]["observed_version"]
    except (
        OSError,
        KeyError,
        TypeError,
        ComponentPathError,
        json.JSONDecodeError,
    ):
        failures.append("OpenClaw auth closure metadata is unavailable")
        return
    try:
        result = command(
            [
                sys.executable,
                os.fspath(helper),
                "verify",
                "--prefix",
                os.fspath(home / ".openclaw"),
                "--home",
                os.fspath(home),
                "--expected-version",
                str(expected_version),
            ],
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired):
        failures.append("OpenClaw agent-auth closure command failed")
        return
    try:
        auth_report = json.loads(result.stdout)
    except json.JSONDecodeError:
        failures.append("OpenClaw agent-auth closure output was not JSON")
        return
    try:
        sanitized = sanitize_agent_auth_report(auth_report)
    except ValueError:
        failures.append("OpenClaw agent-auth closure output metadata is invalid")
        return
    if result.returncode != 0:
        failures.append("OpenClaw agent-auth closure failed")
        return
    report["agent_auth"] = sanitized


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
        verify_agent_auth(args.home, failures, report)
        verify_host_artifacts(args.home, closure, failures)
        verify_plugins(closure, failures)
        verify_skills(closure, failures, report)
        verify_channels(closure, failures)
        verify_security(closure, failures)
        verify_image(closure, lock, failures)
    else:
        skipped = [
            "live config and gateway",
            "canonical OpenClaw agent-auth store",
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
        args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=args.output.parent, prefix=f".{args.output.name}."
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, args.output)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
    print(encoded, end="")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
