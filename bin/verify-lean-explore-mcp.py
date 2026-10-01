#!/usr/bin/env python3
"""Perform a bounded LeanExplore stdio initialize + tools/list handshake."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time


MAX_STREAM_BYTES = 1024 * 1024
PROTOCOL_VERSION = "2025-06-18"


class HandshakeError(RuntimeError):
    pass


def encode_message(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def run_handshake(command: Path, timeout: float) -> dict[str, object]:
    if command.is_symlink() or not command.is_file() or not os.access(command, os.X_OK):
        raise HandshakeError("LeanExplore MCP launcher is missing or unsafe")
    process = subprocess.Popen(
        [str(command)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    stderr_digest = hashlib.sha256()
    stderr_bytes = 0
    stdout_buffer = bytearray()
    deadline = time.monotonic() + timeout

    def send(value: dict) -> None:
        try:
            process.stdin.write(encode_message(value))
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise HandshakeError("LeanExplore MCP transport closed during request") from exc

    def receive(identifier: int) -> dict:
        nonlocal stderr_bytes
        messages = 0
        while time.monotonic() < deadline:
            if process.poll() is not None and not stdout_buffer:
                raise HandshakeError(
                    f"LeanExplore MCP exited before response; returncode={process.returncode}; "
                    f"stderr_bytes={stderr_bytes}; stderr_sha256={stderr_digest.hexdigest()}"
                )
            remaining = max(0.0, deadline - time.monotonic())
            ready, _, _ = select.select(
                [process.stdout.fileno(), process.stderr.fileno()], [], [], min(0.5, remaining)
            )
            for descriptor in ready:
                block = os.read(descriptor, 65536)
                if descriptor == process.stderr.fileno():
                    stderr_bytes += len(block)
                    if stderr_bytes > MAX_STREAM_BYTES:
                        raise HandshakeError("LeanExplore MCP stderr exceeded its bound")
                    stderr_digest.update(block)
                else:
                    stdout_buffer.extend(block)
                    if len(stdout_buffer) > MAX_STREAM_BYTES:
                        raise HandshakeError("LeanExplore MCP stdout exceeded its bound")
            while b"\n" in stdout_buffer:
                raw, _, remainder = stdout_buffer.partition(b"\n")
                stdout_buffer[:] = remainder
                if not raw.strip():
                    continue
                messages += 1
                if messages > 32:
                    raise HandshakeError("LeanExplore MCP emitted too many unsolicited messages")
                try:
                    value = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise HandshakeError("LeanExplore MCP emitted invalid JSON") from exc
                if not isinstance(value, dict):
                    raise HandshakeError("LeanExplore MCP emitted a non-object response")
                if value.get("id") == identifier:
                    if "error" in value or not isinstance(value.get("result"), dict):
                        raise HandshakeError("LeanExplore MCP returned a JSON-RPC error")
                    return value["result"]
        raise HandshakeError(
            f"LeanExplore MCP handshake timed out; stderr_bytes={stderr_bytes}; "
            f"stderr_sha256={stderr_digest.hexdigest()}"
        )

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
        send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = receive(2).get("tools")
        if not isinstance(tools, list) or not tools:
            raise HandshakeError("LeanExplore MCP returned no tool inventory")
        tool_names = sorted(
            item.get("name") for item in tools if isinstance(item, dict) and isinstance(item.get("name"), str)
        )
        required = {"search", "search_summary", "get_source_code"}
        if not required.issubset(tool_names):
            raise HandshakeError("LeanExplore MCP tool inventory is incomplete")
        server = initialized.get("serverInfo")
        if initialized.get("protocolVersion") != PROTOCOL_VERSION or not isinstance(server, dict):
            raise HandshakeError("LeanExplore MCP initialize response is incompatible")
        return {
            "schema": "coding-system.mcp-handshake.v1",
            "status": "PASS",
            "protocolVersion": initialized["protocolVersion"],
            "server": {
                "name": str(server.get("name", "")),
                "version": str(server.get("version", "")),
            },
            "tools": tool_names,
        }
    finally:
        terminate(process)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--command", type=Path, default=Path.home() / ".local/bin/lean-explore-mcp-api"
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 60:
        print("verify-lean-explore-mcp: timeout must be between 1 and 60 seconds", file=sys.stderr)
        return 2
    try:
        report = run_handshake(args.command, args.timeout)
    except (HandshakeError, OSError, subprocess.SubprocessError) as exc:
        print(f"verify-lean-explore-mcp: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
