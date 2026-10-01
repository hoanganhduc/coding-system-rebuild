import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "verify-configured-mcps.py"
POLICY = ROOT / "system" / "software" / "mcp-policy.json"


class McpConfigVerifierTests(unittest.TestCase):
    def write_policy(
        self,
        root: Path,
        *,
        format_name: str = "claude-json",
        enabled: list[str] | None = None,
        disabled: list[str] | None = None,
        omitted: dict[str, str] | None = None,
        floating: dict[str, str] | None = None,
    ) -> Path:
        policy = {
            "schema": "coding-system.mcp-policy.v1",
            "targets": {
                "fixture": {
                    "format": format_name,
                    "sourceConfig": "source/config.json",
                    "installedConfig": ".fixture/mcp.json",
                    "expectedEnabled": enabled or [],
                    "expectedDisabled": disabled or [],
                    "intentionallyOmitted": omitted or {},
                }
            },
        }
        if floating is not None:
            policy["targets"]["fixture"]["floatingAllowed"] = floating
        path = root / "policy.json"
        path.write_text(json.dumps(policy), encoding="utf-8")
        return path

    def write_server(self, path: Path, *, fail: bool = False) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if fail:
            source = """#!/usr/bin/python3
import os, sys
sys.stderr.write(os.environ.get("FIXTURE_SECRET", ""))
sys.stderr.flush()
raise SystemExit(9)
"""
        else:
            source = """#!/usr/bin/python3
import json, os, sys
secret = os.environ.get("FIXTURE_SECRET", "")
ambient = os.environ.get("MCP_AMBIENT_SECRET_CANARY", "")
sys.stderr.write(secret)
sys.stderr.flush()
for line in sys.stdin:
    message = json.loads(line)
    if message.get("method") == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": secret, "version": secret},
            },
        }), flush=True)
    elif message.get("method") == "tools/list":
        tools = [{"name": secret or "fixture", "description": secret}]
        if ambient:
            tools.append({"name": ambient})
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"tools": tools},
        }), flush=True)
"""
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    def mirror_source(self, root: Path, config: Path) -> None:
        source = root / "source/config.json"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(config.read_text(encoding="utf-8"), encoding="utf-8")

    def run_verifier(
        self, repository: Path, home: Path, policy: Path, *extra: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--repository",
                str(repository),
                "--root",
                str(home),
                "--policy",
                str(policy),
                "--path",
                "/usr/bin:/bin",
                "--timeout",
                "3",
                *extra,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={**os.environ, "MCP_AMBIENT_SECRET_CANARY": "ambient-secret-must-not-reach-server"},
        )

    def test_floating_launcher_needs_an_owner_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source/config.json"
            source.parent.mkdir(parents=True)
            source.write_text(
                json.dumps({"mcpServers": {"thinking": {"command": "npx", "args": ["-y", "@example/server"]}}}),
                encoding="utf-8",
            )

            def declared(policy: Path) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["python3", str(SCRIPT), "--repository", str(root), "--policy", str(policy), "--mode", "declared"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

            refused = declared(self.write_policy(root, enabled=["thinking"]))
            self.assertEqual(refused.returncode, 2)
            self.assertIn("floating or shell MCP launcher is forbidden", refused.stdout)

            accepted = declared(
                self.write_policy(root, enabled=["thinking"], floating={"thinking": "owner keeps the live server"})
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            server = json.loads(accepted.stdout)["targets"]["fixture"]["servers"][0]
            self.assertEqual(server["status"], "DECLARED")
            self.assertEqual(server["floating"], "owner keeps the live server")

            undeclared = declared(
                self.write_policy(root, enabled=["thinking"], floating={"thinking": "kept", "other": "not declared"})
            )
            self.assertEqual(undeclared.returncode, 2)
            self.assertIn("floating exception", undeclared.stderr)

    def test_repository_policy_declares_closed_inert_or_owner_excepted_servers(self) -> None:
        completed = subprocess.run(
            ["python3", str(SCRIPT), "--repository", str(ROOT), "--policy", str(POLICY), "--mode", "declared"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "PASS")
        # A floating launcher (npx, uvx, a shell) is kept only as an explicit owner
        # exception with a recorded reason; every other server is closed or inert.
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        for name, target in report["targets"].items():
            exceptions = policy["targets"][name].get("floatingAllowed", {})
            for server in target["servers"]:
                with self.subTest(target=name, server=server["name"]):
                    self.assertEqual(server.get("floating"), exceptions.get(server["name"]))
        source = "\n".join(
            (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "agents/claude/.mcp.json",
                "agents/codex/config.toml.template",
                "agents/deepseek/mcp.json",
            )
        )
        self.assertNotIn("deepseek-tui", source)

        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        verification = (ROOT / "bin/verify.sh").read_text(encoding="utf-8")
        self.assertIn("--readiness-phase pre-runtime", install)
        self.assertIn('verify-configured-mcps.py" --repository', verification)
        self.assertIn("--readiness-phase full", verification)
        self.assertIn('--mcp-report "$MCP_REPORT"', verification)
        self.assertIn("--scheduler-canary-passed", verification)

    def test_every_enabled_lean_explore_target_uses_the_csr_adapter(self) -> None:
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        enabled_targets = {
            name
            for name, target in policy["targets"].items()
            if "lean-explore" in target["expectedEnabled"]
        }
        self.assertEqual(enabled_targets, {"codex", "deepseek"})

        for name in sorted(enabled_targets):
            with self.subTest(target=name):
                target = policy["targets"][name]
                source = ROOT / target["sourceConfig"]
                raw = source.read_text(encoding="utf-8")
                if target["format"] == "codex-toml":
                    server = tomllib.loads(raw)["mcp_servers"]["lean-explore"]
                else:
                    server = json.loads(raw)["servers"]["lean-explore"]
                self.assertEqual(
                    server["command"],
                    "{{ HOME }}/.local/bin/lean-explore-mcp-api",
                )
                self.assertEqual(server.get("args", []), [])
                self.assertNotIn("mcp serve --backend api", raw)
                self.assertNotIn("--api-key", raw)

    def test_full_handshake_redacts_environment_stderr_server_info_and_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            server = home / "bin/server"
            self.write_server(server)
            secret = "mcp-secret-canary-never-report"
            config = home / ".fixture/mcp.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "safe": {
                                "command": str(server),
                                "args": [],
                                "env": {"FIXTURE_SECRET": secret},
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            self.mirror_source(root, config)
            policy = self.write_policy(root, enabled=["safe"])
            completed = self.run_verifier(root, home, policy, "--mode", "full")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn(secret, completed.stdout + completed.stderr)
            report = json.loads(completed.stdout)
            server_report = report["targets"]["fixture"]["servers"][0]
            self.assertEqual(server_report["status"], "PASS")
            self.assertEqual(server_report["handshake"]["toolCount"], 1)
            self.assertTrue(server_report["handshake"]["serverInfoPresent"])

    def test_server_failure_reports_only_a_redacted_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            server = home / "bin/server"
            self.write_server(server, fail=True)
            secret = "stderr-secret-canary-never-report"
            config = home / ".fixture/mcp.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "broken": {
                                "command": str(server),
                                "env": {"FIXTURE_SECRET": secret},
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            self.mirror_source(root, config)
            policy = self.write_policy(root, enabled=["broken"])
            completed = self.run_verifier(root, home, policy, "--mode", "full")
            self.assertEqual(completed.returncode, 2)
            self.assertNotIn(secret, completed.stdout + completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["targets"]["fixture"]["servers"][0]["status"], "TECHNICAL_FAIL")

    def test_enabled_http_transport_fails_while_disabled_transport_is_inert(self) -> None:
        for enabled, expected_returncode, expected_status in (
            (True, 2, "TECHNICAL_FAIL"),
            (False, 0, "INTENTIONALLY_DISABLED"),
        ):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home = root / "home"
                config = home / ".fixture/mcp.json"
                config.parent.mkdir(parents=True)
                config.write_text(
                    json.dumps(
                        {
                            "mcpServers": {
                                "remote": {
                                    "url": "https://example.invalid/mcp",
                                    "enabled": enabled,
                                }
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                self.mirror_source(root, config)
                policy = self.write_policy(
                    root,
                    enabled=["remote"] if enabled else [],
                    disabled=[] if enabled else ["remote"],
                )
                completed = self.run_verifier(root, home, policy, "--mode", "full")
                self.assertEqual(completed.returncode, expected_returncode)
                report = json.loads(completed.stdout)
                self.assertEqual(report["targets"]["fixture"]["servers"][0]["status"], expected_status)

    def test_intentionally_omitted_server_cannot_silently_reappear(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            server = home / "bin/server"
            self.write_server(server)
            config = home / ".fixture/mcp.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                json.dumps({"mcpServers": {"floating": {"command": str(server)}}}),
                encoding="utf-8",
            )
            self.mirror_source(root, config)
            policy = self.write_policy(root, omitted={"floating": "not in the closure"})
            completed = self.run_verifier(root, home, policy, "--mode", "full")
            self.assertEqual(completed.returncode, 2)
            self.assertIn("policy/config mismatch", completed.stdout)

    def test_installed_server_command_must_match_signed_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            server = home / "bin/server"
            self.write_server(server)
            config = home / ".fixture/mcp.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                json.dumps({"mcpServers": {"safe": {"command": str(server)}}}),
                encoding="utf-8",
            )
            self.mirror_source(root, config)
            config.write_text(
                json.dumps({"mcpServers": {"safe": {"command": "/usr/bin/false"}}}),
                encoding="utf-8",
            )
            policy = self.write_policy(root, enabled=["safe"])
            completed = self.run_verifier(root, home, policy, "--mode", "full")
            self.assertEqual(completed.returncode, 2)
            self.assertIn("differs from its signed source", completed.stdout)

    def test_symlinked_config_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            outside = root / "outside.json"
            outside.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
            config = home / ".fixture/mcp.json"
            config.parent.mkdir(parents=True)
            config.symlink_to(outside)
            source = root / "source/config.json"
            source.parent.mkdir(parents=True)
            source.write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
            policy = self.write_policy(root)
            completed = self.run_verifier(root, home, policy, "--mode", "full")
            self.assertEqual(completed.returncode, 2)
            self.assertIn("config is unsafe", completed.stdout)


if __name__ == "__main__":
    unittest.main()
