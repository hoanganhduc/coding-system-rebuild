#!/usr/bin/env python3
"""Regression checks for fail-closed closure phases in bin/install.sh."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InstallClosureTests(unittest.TestCase):
    def test_component_cannot_downgrade_openclaw_and_plugins_use_lockfiles(self) -> None:
        source = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        self.assertIn(
            'export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"', source
        )
        self.assertIn("openclaw missing from the restored command path", source)
        self.assertIn("--skip-openclaw-install", source)
        self.assertIn("--convergent", source)
        self.assertIn("npm ci --ignore-scripts --omit=dev", source)
        self.assertIn('openclaw plugins install --pin --force "$plugin_spec"', source)
        self.assertNotIn("npm install --silent || echo", source)
        self.assertIn("openclaw exec-policy set --host sandbox", source)
        self.assertIn("systemctl --user restart openclaw-gateway", source)
        self.assertIn("openclaw sandbox recreate --all --force", source)
        owner_restore = source.index("restore-openclaw-owner-data.sh")
        component_converge = source.index("--convergent", owner_restore)
        self.assertLess(owner_restore, component_converge)

    def test_required_python_environments_are_not_suppressed(self) -> None:
        source = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        phase_nine = source.split("# 9 ─", 1)[1].split("# 10 ─", 1)[0]
        self.assertNotIn("|| true", phase_nine)

    def test_backup_refresh_observes_drift_without_rewriting_release_locks(self) -> None:
        source = (ROOT / "bin/refresh-state.sh").read_text(encoding="utf-8")
        self.assertIn('OBS="$PKG/observed"', source)
        self.assertIn('> "$OBS/npm-globals.txt"', source)
        self.assertIn('> "$OBS/requirements/workspace-local.txt"', source)
        self.assertNotIn('> "$PKG/npm-globals.txt"', source)
        self.assertNotIn('> "$PKG/requirements/workspace-local.txt"', source)
        self.assertIn("check-closure-drift.py", source)
        self.assertNotIn("git ls-remote", source)

        drift_source = (ROOT / "bin/check-closure-drift.py").read_text(
            encoding="utf-8"
        )
        self.assertLess(
            drift_source.index('REPO / "external" / name'),
            drift_source.index("Path.home() / name"),
        )

    def test_compatibility_is_gated_before_services(self) -> None:
        source = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        compatibility = source.index("verify-openclaw-compat.py")
        services = source.index("# 11 ─")
        self.assertLess(compatibility, services)
        self.assertIn('verify-openclaw-compat.py" --static-only', source)
        self.assertIn("a full restore cannot skip the locked OpenClaw sandbox image", source)
        gate = source.split(
            'gate "OpenClaw compatibility tuple before service startup"', 1
        )[1].split("# 11 ─", 1)[0]
        self.assertLess(
            gate.index("[[ $DEGRADED_MODE -eq 1 ]]"),
            gate.index("skip_enabled SKIP_DOCKER"),
        )

    def test_verifier_requires_an_explicit_profile_and_effective_runtime_gate(self) -> None:
        source = (ROOT / "bin/verify.sh").read_text(encoding="utf-8")
        self.assertIn('PROFILE="full"', source)
        self.assertNotIn("have_user_systemd || DEGRADED=1", source)
        self.assertIn("verify-openclaw-runtime.py", source)
        runtime = (ROOT / "bin/verify-openclaw-runtime.py").read_text(encoding="utf-8")
        for command in (
            '"skills", "check", "--json"',
            '"channels", "status", "--probe"',
            '"plugins", "doctor"',
            '"security", "audit", "--deep", "--json"',
            '"docker", "run", "--rm", "--read-only"',
        ):
            self.assertIn(command, runtime)

    def test_shared_queue_worker_is_not_owned_by_the_zotero_skill(self) -> None:
        service = (ROOT / "system/systemd/user/send-queue-worker.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("/.openclaw/workspace/scripts/job_queue_worker.sh", service)
        self.assertNotIn("/skills/zotero/job_queue_worker.sh", service)

    def test_config_migration_removes_open_access_and_bounds_sandboxes(self) -> None:
        lock = ROOT / "system/openclaw/compatibility.lock.json"
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "openclaw.json"
            config.write_text(
                json.dumps(
                    {
                        "agents": {
                            "defaults": {
                                "model": {"fallbacks": ["strong", "groq/openai/gpt-oss-120b"]},
                                "sandbox": {"docker": {"image": "old"}},
                            },
                            "list": [
                                {
                                    "id": "worker",
                                    "sandbox": {
                                        "docker": {
                                            "image": "latest",
                                            "dangerouslyAllowExternalBindSources": True,
                                            "binds": ["/outside:/outside:rw"],
                                        }
                                    },
                                },
                                {"id": "review", "sandbox": {"mode": "all"}},
                            ],
                        },
                        "channels": {
                            "googlechat": {
                                "enabled": True,
                                "groupPolicy": "open",
                                "groupAllowFrom": ["owner", "*"],
                            }
                        },
                        "tools": {
                            "elevated": {"enabled": True},
                            "exec": {"security": "full", "ask": "off"},
                        },
                    }
                )
            )
            subprocess.run(
                [
                    "python3",
                    str(ROOT / "bin/migrate-openclaw-config.py"),
                    "--config",
                    str(config),
                    "--lock",
                    str(lock),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            migrated = json.loads(config.read_text())
            channel = migrated["channels"]["googlechat"]
            self.assertEqual(channel["groupPolicy"], "allowlist")
            self.assertEqual(channel["groupAllowFrom"], ["owner"])
            self.assertFalse(migrated["tools"]["elevated"]["enabled"])
            self.assertEqual(migrated["tools"]["exec"]["host"], "sandbox")
            self.assertEqual(migrated["tools"]["exec"]["security"], "allowlist")
            self.assertEqual(migrated["tools"]["exec"]["ask"], "on-miss")
            for agent in (
                migrated["agents"]["defaults"],
                migrated["agents"]["list"][0],
            ):
                docker = agent["sandbox"]["docker"]
                self.assertEqual(docker["pidsLimit"], 512)
                self.assertEqual(docker["memory"], "4g")
                self.assertEqual(docker["memorySwap"], "4g")
                self.assertEqual(docker["cpus"], 2)
                self.assertEqual(docker["user"], "1001:1001")
                self.assertTrue(docker["readOnlyRoot"])
            worker_docker = migrated["agents"]["list"][0]["sandbox"]["docker"]
            self.assertNotIn("dangerouslyAllowExternalBindSources", worker_docker)
            self.assertEqual(worker_docker["binds"], [])
            self.assertEqual(migrated["agents"]["defaults"]["model"]["fallbacks"], ["strong"])


if __name__ == "__main__":
    unittest.main()
