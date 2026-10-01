#!/usr/bin/env python3
"""Validate MCP policy and handshake every enabled restored MCP server.

The report deliberately excludes command arguments, environment values, server
stderr, and tool descriptions so a failing credential-bearing server cannot
turn verification output into a secret exfiltration channel.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib
from typing import Any


POLICY_SCHEMA = "coding-system.mcp-policy.v1"
REPORT_SCHEMA = "coding-system.mcp-verification.v1"
PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", PROTOCOL_VERSION}
MAX_STREAM_BYTES = 1024 * 1024
MAX_MESSAGES = 64
FORBIDDEN_FLOATING_COMMANDS = {"bash", "npx", "npm", "pnpx", "sh", "uv", "uvx"}


class VerificationError(RuntimeError):
    """A redaction-safe validation or handshake failure."""


def safe_relative(raw: str, label: str) -> PurePosixPath:
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts or raw.startswith("~"):
        raise VerificationError(f"{label} is not a safe relative path")
    return path


def read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read {label}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must contain an object")
    return value


def load_policy(path: Path) -> dict[str, Any]:
    policy = read_json(path, "MCP policy")
    if policy.get("schema") != POLICY_SCHEMA or not isinstance(policy.get("targets"), dict):
        raise VerificationError("MCP policy schema is invalid")
    if not policy["targets"]:
        raise VerificationError("MCP policy declares no targets")
    for target, contract in policy["targets"].items():
        if not isinstance(target, str) or not target or not isinstance(contract, dict):
            raise VerificationError("MCP policy target contract is invalid")
        if contract.get("format") not in {"claude-json", "codex-toml", "deepseek-json"}:
            raise VerificationError(f"MCP policy format is invalid for {target}")
        for key in ("sourceConfig", "installedConfig"):
            safe_relative(str(contract.get(key, "")), f"{target}.{key}")
        for key in ("expectedEnabled", "expectedDisabled"):
            values = contract.get(key)
            if not isinstance(values, list) or not all(isinstance(item, str) and item for item in values):
                raise VerificationError(f"MCP policy {key} is invalid for {target}")
            if len(values) != len(set(values)):
                raise VerificationError(f"MCP policy {key} contains duplicates for {target}")
        omitted = contract.get("intentionallyOmitted")
        if not isinstance(omitted, dict) or not all(
            isinstance(name, str) and name and isinstance(reason, str) and reason
            for name, reason in omitted.items()
        ):
            raise VerificationError(f"MCP omission policy is invalid for {target}")
        declared = set(contract["expectedEnabled"]) | set(contract["expectedDisabled"])
        if len(declared) != len(contract["expectedEnabled"]) + len(contract["expectedDisabled"]):
            raise VerificationError(f"MCP enabled/disabled policy overlaps for {target}")
        if declared & set(omitted):
            raise VerificationError(f"MCP configured/omitted policy overlaps for {target}")
        # An owner exception may keep a server whose launcher fetches code at run time.
        floating = contract.get("floatingAllowed", {})
        if not isinstance(floating, dict) or not all(
            isinstance(name, str) and name and isinstance(reason, str) and reason
            for name, reason in floating.items()
        ):
            raise VerificationError(f"MCP floating exception policy is invalid for {target}")
        if not set(floating) <= declared:
            raise VerificationError(f"MCP floating exception names an undeclared server for {target}")
    return policy


def _server(
    target: str,
    name: str,
    raw: Any,
    *,
    enabled: bool,
    floating: bool = False,
) -> dict[str, Any]:
    if not isinstance(name, str) or not name or not isinstance(raw, dict):
        raise VerificationError(f"invalid MCP server declaration for {target}")
    command = raw.get("command")
    url = raw.get("url")
    args = raw.get("args", [])
    environment = raw.get("env", {})
    if command is not None and (not isinstance(command, str) or not command):
        raise VerificationError(f"invalid MCP command for {target}.{name}")
    if url is not None and (not isinstance(url, str) or not url):
        raise VerificationError(f"invalid MCP URL for {target}.{name}")
    if (command is None) == (url is None):
        raise VerificationError(f"MCP server must declare exactly one transport for {target}.{name}")
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise VerificationError(f"invalid MCP arguments for {target}.{name}")
    if not isinstance(environment, dict) or not all(
        isinstance(key, str)
        and key
        and "/" not in key
        and "=" not in key
        and isinstance(value, str)
        for key, value in environment.items()
    ):
        raise VerificationError(f"invalid MCP environment for {target}.{name}")
    if not floating and command is not None and Path(command).name in FORBIDDEN_FLOATING_COMMANDS:
        raise VerificationError(f"floating or shell MCP launcher is forbidden for {target}.{name}")
    if not floating and any("@latest" in item for item in args):
        raise VerificationError(f"floating MCP argument is forbidden for {target}.{name}")
    if url is not None and not url.startswith("https://"):
        raise VerificationError(f"non-HTTPS MCP URL is forbidden for {target}.{name}")
    return {
        "target": target,
        "name": name,
        "enabled": enabled,
        "transport": "stdio" if command is not None else "http",
        "command": command,
        "args": args,
        "env": environment,
    }


def load_servers(
    path: Path, target: str, format_name: str, floating_allowed: frozenset[str] = frozenset()
) -> list[dict[str, Any]]:
    if format_name == "codex-toml":
        try:
            document = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise VerificationError(f"cannot read MCP config for {target}") from exc
        raw_servers = document.get("mcp_servers")
    else:
        document = read_json(path, f"MCP config for {target}")
        raw_servers = document.get("mcpServers" if format_name == "claude-json" else "servers")
    if not isinstance(raw_servers, dict):
        raise VerificationError(f"MCP config has no server map for {target}")
    servers = []
    for name, raw in raw_servers.items():
        if not isinstance(raw, dict):
            raise VerificationError(f"invalid MCP server declaration for {target}")
        enabled = bool(raw.get("enabled", True)) and not bool(raw.get("disabled", False))
        servers.append(_server(target, name, raw, enabled=enabled, floating=name in floating_allowed))
    return servers


def expand_home(value: str, home: Path) -> str:
    return value.replace("{{ HOME }}", str(home))


def normalized_server(server: dict[str, Any], home: Path) -> tuple[Any, ...]:
    """Return a comparison-only shape; callers never serialize its values."""
    return (
        server["name"],
        server["enabled"],
        server["transport"],
        expand_home(server["command"], home) if server["command"] is not None else None,
        tuple(expand_home(item, home) for item in server["args"]),
        tuple(sorted((key, expand_home(value, home)) for key, value in server["env"].items())),
    )


def resolve_command(raw: str, home: Path, search_path: str) -> str:
    expanded = expand_home(raw, home)
    if "\x00" in expanded:
        raise VerificationError("MCP launcher is invalid")
    if "/" in expanded:
        candidate = Path(expanded)
        if not candidate.is_absolute():
            raise VerificationError("relative MCP launcher paths are forbidden")
    else:
        located = shutil.which(expanded, path=search_path)
        if located is None:
            raise VerificationError("MCP launcher is missing")
        candidate = Path(located)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise VerificationError("MCP launcher is missing") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise VerificationError("MCP launcher is not executable")
    return str(candidate)


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass


def encode_message(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"


def handshake(server: dict[str, Any], home: Path, search_path: str, timeout: float) -> dict[str, Any]:
    if server["transport"] != "stdio":
        raise VerificationError("enabled HTTP MCP transport is outside the offline restore closure")
    command = resolve_command(str(server["command"]), home, search_path)
    arguments = [expand_home(item, home) for item in server["args"]]
    # MCPs receive a closed baseline rather than every provider credential in
    # the verifier's ambient environment. A server-specific secret must be
    # projected explicitly by its reviewed config or loaded by its launcher.
    environment = {
        "HOME": str(home),
        "PATH": search_path,
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
    }
    for key in ("TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"):
        if os.environ.get(key):
            environment[key] = os.environ[key]
    for key, value in server["env"].items():
        environment[key] = expand_home(value, home)
    try:
        process = subprocess.Popen(
            [command, *arguments],
            cwd=home,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise VerificationError("MCP launcher could not start") from exc
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    deadline = time.monotonic() + timeout
    stdout_buffer = bytearray()
    stdout_bytes = 0
    stderr_bytes = 0
    message_count = 0

    def send(value: dict[str, Any]) -> None:
        try:
            process.stdin.write(encode_message(value))
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise VerificationError("MCP transport closed during request") from exc

    def receive(identifier: int) -> dict[str, Any]:
        nonlocal message_count, stderr_bytes, stdout_bytes
        while time.monotonic() < deadline:
            if process.poll() is not None and not stdout_buffer:
                raise VerificationError("MCP server exited before responding")
            remaining = max(0.0, deadline - time.monotonic())
            ready, _, _ = select.select(
                [process.stdout.fileno(), process.stderr.fileno()], [], [], min(0.25, remaining)
            )
            for descriptor in ready:
                block = os.read(descriptor, 65536)
                if descriptor == process.stderr.fileno():
                    stderr_bytes += len(block)
                    if stderr_bytes > MAX_STREAM_BYTES:
                        raise VerificationError("MCP stderr exceeded its bound")
                else:
                    stdout_bytes += len(block)
                    if stdout_bytes > MAX_STREAM_BYTES:
                        raise VerificationError("MCP stdout exceeded its bound")
                    stdout_buffer.extend(block)
            while b"\n" in stdout_buffer:
                raw, _, remainder = stdout_buffer.partition(b"\n")
                stdout_buffer[:] = remainder
                if not raw.strip():
                    continue
                message_count += 1
                if message_count > MAX_MESSAGES:
                    raise VerificationError("MCP emitted too many messages")
                try:
                    response = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise VerificationError("MCP emitted invalid JSON") from exc
                if not isinstance(response, dict):
                    raise VerificationError("MCP emitted a non-object response")
                if response.get("id") == identifier:
                    if "error" in response or not isinstance(response.get("result"), dict):
                        raise VerificationError("MCP returned a JSON-RPC error")
                    return response["result"]
        raise VerificationError("MCP handshake timed out")

    try:
        send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "coding-system-verifier", "version": "1"},
                },
            }
        )
        initialized = receive(1)
        protocol = initialized.get("protocolVersion")
        server_info = initialized.get("serverInfo")
        if protocol not in SUPPORTED_PROTOCOL_VERSIONS or not isinstance(server_info, dict):
            raise VerificationError("MCP initialize response is incompatible")
        send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = receive(2).get("tools")
        if not isinstance(tools, list):
            raise VerificationError("MCP tool inventory is invalid")
        if any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in tools):
            raise VerificationError("MCP tool inventory is malformed")
        return {
            "protocolVersion": protocol,
            "serverInfoPresent": True,
            "toolCount": len(tools),
            "stdoutBytes": stdout_bytes,
            "stderrBytes": stderr_bytes,
        }
    finally:
        terminate(process)


def verify(
    policy: dict[str, Any],
    repository: Path,
    home: Path,
    mode: str,
    search_path: str,
    timeout: float,
) -> dict[str, Any]:
    target_reports: dict[str, Any] = {}
    overall = "PASS"
    for target, contract in sorted(policy["targets"].items()):
        relative = contract["sourceConfig"] if mode == "declared" else contract["installedConfig"]
        base = repository if mode == "declared" else home
        config_path = base / Path(*safe_relative(relative, f"{target}.config").parts)
        try:
            try:
                info = config_path.lstat()
            except OSError as exc:
                raise VerificationError(f"MCP config is missing for {target}") from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise VerificationError(f"MCP config is unsafe for {target}")
            try:
                config_path.resolve(strict=True).relative_to(base.resolve())
            except (OSError, ValueError) as exc:
                raise VerificationError(f"MCP config escapes its authority root for {target}") from exc
            floating = contract.get("floatingAllowed", {})
            servers = load_servers(config_path, target, contract["format"], frozenset(floating))
            by_name = {item["name"]: item for item in servers}
            if len(by_name) != len(servers):
                raise VerificationError(f"duplicate MCP server names for {target}")
            missing_enabled = sorted(set(contract["expectedEnabled"]) - set(by_name))
            missing_disabled = sorted(set(contract["expectedDisabled"]) - set(by_name))
            wrongly_disabled = sorted(
                name for name in contract["expectedEnabled"] if name in by_name and not by_name[name]["enabled"]
            )
            wrongly_enabled = sorted(
                name for name in contract["expectedDisabled"] if name in by_name and by_name[name]["enabled"]
            )
            present_omissions = sorted(set(contract["intentionallyOmitted"]) & set(by_name))
            declared_names = set(contract["expectedEnabled"]) | set(contract["expectedDisabled"])
            unexpected = sorted(set(by_name) - declared_names)
            if missing_enabled or missing_disabled or wrongly_disabled or wrongly_enabled or present_omissions or unexpected:
                raise VerificationError(f"MCP policy/config mismatch for {target}")
            if mode == "full":
                source_path = repository / Path(
                    *safe_relative(contract["sourceConfig"], f"{target}.sourceConfig").parts
                )
                try:
                    source_info = source_path.lstat()
                    source_path.resolve(strict=True).relative_to(repository.resolve())
                except (OSError, ValueError) as exc:
                    raise VerificationError(f"MCP source config is missing or unsafe for {target}") from exc
                if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISREG(source_info.st_mode):
                    raise VerificationError(f"MCP source config is missing or unsafe for {target}")
                source_servers = load_servers(source_path, target, contract["format"], frozenset(floating))
                if sorted(normalized_server(item, home) for item in source_servers) != sorted(
                    normalized_server(item, home) for item in servers
                ):
                    raise VerificationError(f"installed MCP config differs from its signed source for {target}")
            server_reports = []
            for server in sorted(servers, key=lambda item: item["name"]):
                public = {
                    "name": server["name"],
                    "configured": True,
                    "enabled": server["enabled"],
                    "transport": server["transport"],
                }
                if server["name"] in floating:
                    public["floating"] = floating[server["name"]]
                if not server["enabled"]:
                    public["status"] = "INTENTIONALLY_DISABLED"
                elif mode == "declared":
                    public["status"] = "DECLARED"
                else:
                    try:
                        public["handshake"] = handshake(server, home, search_path, timeout)
                        public["status"] = "PASS"
                    except VerificationError as exc:
                        public["status"] = "TECHNICAL_FAIL"
                        public["reason"] = str(exc)
                        overall = "TECHNICAL_FAIL"
                server_reports.append(public)
            target_reports[target] = {
                "status": "PASS" if all(
                    item["status"] in {"PASS", "DECLARED", "INTENTIONALLY_DISABLED"}
                    for item in server_reports
                ) else "TECHNICAL_FAIL",
                "configConfigured": True,
                "servers": server_reports,
                "intentionallyOmitted": [
                    {"name": name, "reason": reason}
                    for name, reason in sorted(contract["intentionallyOmitted"].items())
                ],
            }
        except VerificationError as exc:
            overall = "TECHNICAL_FAIL"
            target_reports[target] = {
                "status": "TECHNICAL_FAIL",
                "configConfigured": config_path.is_file(),
                "reason": str(exc),
                "servers": [],
                "intentionallyOmitted": [
                    {"name": name, "reason": reason}
                    for name, reason in sorted(contract["intentionallyOmitted"].items())
                ],
            }
    return {
        "schema": REPORT_SCHEMA,
        "status": overall,
        "mode": mode,
        "targets": target_reports,
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def main() -> int:
    repository_default = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=repository_default)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--root", type=Path, default=Path.home())
    parser.add_argument("--mode", choices=("declared", "full"), default="full")
    parser.add_argument("--path", default=os.environ.get("PATH", ""))
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 60:
        print("verify-configured-mcps: timeout must be between 1 and 60 seconds", file=sys.stderr)
        return 2
    repository = args.repository.resolve()
    policy_path = args.policy or repository / "system/software/mcp-policy.json"
    try:
        policy = load_policy(policy_path)
        report = verify(policy, repository, args.root.resolve(), args.mode, args.path, args.timeout)
    except VerificationError as exc:
        print(f"verify-configured-mcps: {exc}", file=sys.stderr)
        return 2
    if args.output:
        write_report(args.output, report)
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
