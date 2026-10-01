import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import unittest

from test_copilot_wrapper import CopilotWrapperTests


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "verify-target-state.py"


def runtime_credential_authorities() -> dict[str, object]:
    return {
        "file-delivery-queue": {
            "kind": "strict-json-file",
            "path": ".config/ai-agents-skills/file-delivery-queue.json",
            "pointer_env": "AAS_FILE_DELIVERY_SECRETS_FILE",
            "schema_version": 1,
            "exact_keys": [
                "version",
                "hmac_key_hex",
                "allowed",
                "max_job_age_seconds",
                "max_media_bytes",
                "replay_ledger_dir",
                "replay_retention_seconds",
                "max_replay_entries",
            ],
            "restore_policy": "authority",
            "generation_policy": "explicit-allowlist-required",
            "replay_ledger_field": {
                "exact_value": "aas-host-state:file-delivery-replay",
                "resolution": (
                    "authority-home/.local/state/ai-agents-skills/"
                    "file-delivery-replay"
                ),
                "legacy_migration": (
                    "rewrite-old-default-only-preserve-other-fields-reject-conflicts"
                ),
            },
            "replay_ledger": {
                "default_path": (
                    ".local/state/ai-agents-skills/file-delivery-replay"
                ),
                "must_be_outside_agent_workspace": True,
                "mode": "0700",
                "restore_policy": "state-continuity",
                "backup_required": True,
                "retention_contract": (
                    "used_at+replay_retention_seconds-strictly-before-now"
                ),
                "retention_minimum": "max_job_age_seconds+60",
                "entry_bound_field": "max_replay_entries",
            },
            "distinct_from": (
                ".openclaw/workspace/.config/file-delivery/secrets.json"
            ),
            "readiness_when_absent": "NOT_CONFIGURED",
        }
    }


class TargetStateVerifierTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        manifest = {
            "schema": "ai-agents-skills.target-state.v3",
            "schema_version": 3,
            "runtime_credential_authorities": runtime_credential_authorities(),
            "targets": {
                "codex": {
                    "home": ".codex",
                    "cli_candidates": ["codex"],
                    "version_argv": ["--version"],
                    "runtime_requirements": ["python-runtime", "git-cli", "node-runtime"],
                    "credential_authorities": [
                        {"kind": "file", "path": ".codex/auth.json", "restore_policy": "portable-session"}
                    ],
                    "readiness": ["cli-version", "managed-skill-visibility", "runtime-smoke", "auth-structural"],
                },
                "copilot": {
                    "home": ".copilot",
                    "cli_candidates": ["copilot"],
                    "version_argv": ["--version"],
                    "runtime_requirements": ["git-cli", "github-cli", "node-runtime"],
                    "credential_authorities": [
                        {"kind": "native-store", "path": ".copilot", "restore_policy": "reauth-if-nonportable"}
                    ],
                    "readiness": ["cli-version", "managed-skill-visibility", "auth-native"],
                },
            },
        }
        path = root / "target-state.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def fake_cli(self, directory: Path, name: str) -> None:
        path = directory / name
        path.write_text("#!/bin/sh\nprintf '%s\\n' '" + name + " 1.0'\n", encoding="utf-8")
        path.chmod(0o755)

    def add_skill(self, home: Path, target_home: str) -> None:
        target_name = {
            ".codex": "codex",
            ".claude": "claude",
            ".deepseek": "deepseek",
            ".copilot": "copilot",
            ".config/opencode": "opencode",
            ".gemini/antigravity-cli": "antigravity",
            ".grok": "grok",
            ".kimi-code": "kimi",
            ".openclaw": "openclaw",
        }.get(target_home, Path(target_home).name.lstrip("."))
        skill_name = "canary"
        if target_name == "antigravity":
            skill = home / target_home / "skills" / f"{skill_name}.md"
        else:
            skill = home / target_home / "skills" / skill_name / "SKILL.md"
        skill.parent.mkdir(parents=True, mode=0o700)
        body = f"---\nname: {skill_name}\n---\n"
        skill.write_text(body, encoding="utf-8")
        digest = "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()
        state_dir = home / ".ai-agents-skills"
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        source_root = home / ".test-aas-source"
        source = source_root / "canonical" / "skills" / skill_name / "SKILL.md"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(body, encoding="utf-8")
        manifest_dir = source_root / "manifest"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        profiles_path = manifest_dir / "profiles.yaml"
        profiles_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "profiles": {"complete-restore": {"skills": ["*"]}},
                }
            ),
            encoding="utf-8",
        )
        skills_path = manifest_dir / "skills.yaml"
        if skills_path.exists():
            skills_manifest = json.loads(skills_path.read_text(encoding="utf-8"))
        else:
            skills_manifest = {"schema_version": 1, "skills": {}}
        spec = skills_manifest["skills"].setdefault(skill_name, {"supported_agents": []})
        if target_name not in spec["supported_agents"]:
            spec["supported_agents"].append(target_name)
        skills_path.write_text(json.dumps(skills_manifest), encoding="utf-8")
        (manifest_dir / "runtime.yaml").write_text(
            json.dumps({"schema_version": 1, "skills": {}}),
            encoding="utf-8",
        )
        if target_name == "openclaw":
            run_id = "fixture-openclaw"
            manifest_id = "target_manifest_fixture"
            action_id = "target_action_fixture"
            key = f"{manifest_id}:{action_id}"
            relative_path = f"skills/{skill_name}/SKILL.md"
            planned = {
                "key": key,
                "manifest_id": manifest_id,
                "action_id": action_id,
                "action_class": "canary-skill-file",
                "operation": "create",
                "skill": skill_name,
                "relative_path": relative_path,
                "canonical_source_hash": digest,
                "expected_hash": digest,
                "pre_state": {"exists": False, "kind": "missing"},
                "current_pre_state": {"exists": False, "kind": "missing"},
                "drift": False,
                "blocked": False,
                "reason": "ready",
            }
            info = skill.stat()
            installed_signature = {
                "exists": True,
                "kind": "file",
                "hash": digest,
                "device": info.st_dev,
                "inode": info.st_ino,
                "size": info.st_size,
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "nlink": info.st_nlink,
                "mtime_ns": info.st_mtime_ns,
                "ctime_ns": info.st_ctime_ns,
            }
            record = {
                "key": key,
                "manifest_id": manifest_id,
                "action_id": action_id,
                "action_class": "canary-skill-file",
                "skill": skill_name,
                "relative_path": relative_path,
                "installed_hash": digest,
                "installed_signature": installed_signature,
                "source_hash": digest,
                "canonical_source_hash": digest,
                "attestation": "created",
                "created_parent_dirs": [f"skills/{skill_name}"],
                "run_id": run_id,
            }
            state = {
                "schema_version": 1,
                "artifacts": [record],
                "runs": [
                    {
                        "run_id": run_id,
                        "manifest_id": manifest_id,
                        "action_count": 1,
                    }
                ],
                "transactions": [
                    {
                        "run_id": run_id,
                        "manifest_id": manifest_id,
                        "status": "applied",
                        "actions": [planned],
                    }
                ],
            }
            state_path = state_dir / "openclaw-target-state.json"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            state_path.chmod(0o600)
            return

        run_id = f"fixture-{target_name}"
        key = f"{target_name}:{skill_name}:{skill}"
        record = {
            "key": key,
            "agent": target_name,
            "artifact_type": "skill-file",
            "skill": skill_name,
            "artifact": str(skill),
            "source_path": str(source),
            "canonical_source_sha256": digest,
            "managed": True,
            "applied": True,
            "operation": "create",
            "install_mode": "copy",
            "installed_signature": {
                "exists": True,
                "kind": "file",
                "hash": digest,
            },
            "run_id": run_id,
        }
        state_path = state_dir / "state.json"
        if state_path.exists():
            state = json.loads(state_path.read_text(encoding="utf-8"))
        else:
            state = {
                "schema_version": 2,
                "artifacts": [],
                "runs": [],
                "uninstall_records": [],
            }
        state["artifacts"] = [
            item for item in state["artifacts"] if item.get("key") != key
        ] + [record]
        state["runs"] = [
            item for item in state["runs"] if item.get("run_id") != run_id
        ] + [{"run_id": run_id, "action_count": 1}]
        state_path.write_text(json.dumps(state), encoding="utf-8")
        state_path.chmod(0o600)
        runs_dir = state_dir / "runs"
        runs_dir.mkdir(mode=0o700, exist_ok=True)
        receipt = runs_dir / f"{run_id}.json"
        receipt.write_text(
            json.dumps({"run_id": run_id, "actions": [record]}),
            encoding="utf-8",
        )
        receipt.chmod(0o600)

    def add_common_runtimes(self, bindir: Path) -> None:
        for command in ("python3", "git", "node", "gh"):
            self.fake_cli(bindir, command)

    def openclaw_agent_auth_fixture(
        self,
        root: Path,
        home: Path,
        *,
        inherited_agent: bool = False,
    ) -> tuple[Path, Path, Path]:
        manifest = {
            "schema": "ai-agents-skills.target-state.v3",
            "schema_version": 3,
            "runtime_credential_authorities": runtime_credential_authorities(),
            "targets": {
                "openclaw": {
                    "home": ".openclaw",
                    "cli_candidates": ["openclaw"],
                    "version_argv": ["--version"],
                    "runtime_requirements": ["python-runtime"],
                    "credential_authorities": [
                        {
                            "kind": "glob",
                            "path": ".openclaw/agents/*/agent/openclaw-agent.sqlite",
                            "restore_policy": "authority",
                            "evidence": "agent-auth-closure",
                        }
                    ],
                    "evidence_contracts": {
                        "agent-auth-closure": {
                            "source": "openclaw-runtime-report",
                            "source_schema_version": 1,
                            "source_profile": "full",
                            "source_status": "passed",
                            "payload_key": "agent_auth",
                            "report_fields": [
                                "schema",
                                "status",
                                "runtimeVersion",
                                "verificationMode",
                                "openclawExecuted",
                                "networkEnabled",
                                "agents",
                                "failureCount",
                                "failures",
                            ],
                            "report_schema": "openclaw.agent-auth-closure/v2",
                            "expected_runtime_version": "2026.7.1-2",
                            "report_status": "PASS",
                            "verification_mode": "offline-structural-only",
                            "openclaw_executed": False,
                            "network_enabled": False,
                            "agent_fields": [
                                "agentId",
                                "status",
                                "canonicalStore",
                                "reasons",
                            ],
                            "canonical_store_fields": [
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
                            ],
                            "canonical_store_schema_version": 1,
                            "canonical_store_app_version_policy": (
                                "null-or-exact-runtime-version"
                            ),
                            "credential_source_kinds_allowed": ["env", "file"],
                            "provider_calls_allowed": False,
                        }
                    },
                    "readiness": [
                        "cli-version",
                        "managed-skill-visibility",
                        "auth-structural",
                        "agent-auth-closure",
                    ],
                }
            },
        }
        manifest_path = root / "openclaw-agent-auth-target.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        store = home / ".openclaw/agents/main/agent/openclaw-agent.sqlite"
        store.parent.mkdir(parents=True, mode=0o700)
        # Deliberately not text or JSON: the generic verifier must trust only the
        # pinned helper's integrity/schema metadata for this SQLite authority.
        store.write_bytes(b"SQLite fixture bytes\x00\xff")
        store.chmod(0o600)
        store_info = store.stat()

        def agent(agent_id: str, exists: bool) -> dict[str, object]:
            return {
                "agentId": agent_id,
                "status": "PASS",
                "canonicalStore": {
                    "exists": exists,
                    "integrity": True if exists else None,
                    "schemaVersion": 1 if exists else None,
                    "appVersion": None,
                    "authStoreRows": 1 if exists else None,
                    "profileCount": 1 if exists else None,
                    "configured": True if exists else None,
                    "authorityJsonValid": True if exists else None,
                    "executableSecretRefFree": True if exists else None,
                    "credentialSourceKinds": [] if exists else None,
                    "redactionSentinelFree": True if exists else None,
                    "device": store_info.st_dev if exists else None,
                    "inode": store_info.st_ino if exists else None,
                    "size": store_info.st_size if exists else None,
                    "mtimeNs": store_info.st_mtime_ns if exists else None,
                    "ctimeNs": store_info.st_ctime_ns if exists else None,
                },
                "reasons": [],
            }

        agents = [agent("main", True)]
        if inherited_agent:
            agents.append(agent("review", False))
        report = home / ".local/state/coding-system/restore/openclaw-runtime-verification.json"
        report.parent.mkdir(parents=True, mode=0o700)
        report.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "profile": "full",
                    "status": "passed",
                    "failures": [],
                    "skipped": [],
                    "agent_auth": {
                        "schema": "openclaw.agent-auth-closure/v2",
                        "status": "PASS",
                        "runtimeVersion": "2026.7.1-2",
                        "verificationMode": "offline-structural-only",
                        "openclawExecuted": False,
                        "networkEnabled": False,
                        "agents": agents,
                        "failureCount": 0,
                        "failures": [],
                    },
                }
            ),
            encoding="utf-8",
        )
        report.chmod(0o600)
        return manifest_path, report, store

    def projected_copilot_fixture(self, root: Path, home: Path) -> tuple[Path, Path]:
        helper = CopilotWrapperTests()
        launcher = helper.render(home)
        helper.add_secret_loader(home)
        self.add_skill(home, ".copilot")
        manifest = json.loads(self.fixture(root).read_text(encoding="utf-8"))
        manifest["targets"].pop("codex")
        manifest["targets"]["copilot"]["credential_authorities"] = [
            {
                "kind": "strict-env-file",
                "path": ".config/ai-agents-skills/providers/copilot.env",
                "allowed_keys": ["GH_TOKEN"],
                "keys": ["GH_TOKEN"],
                "restore_policy": "target-scoped-projection",
            }
        ]
        manifest["targets"]["copilot"]["readiness"] = [
            "cli-version",
            "managed-skill-visibility",
            "auth-native",
            "credential-projection",
        ]
        manifest["targets"]["copilot"]["credential_projection"] = {
            "launcher": ".local/bin/copilot",
            "launcher_source": "system/bin/copilot",
            "closure_loader": ".npm-global/lib/node_modules/@github/copilot/npm-loader.js",
            "authority": ".config/ai-agents-skills/providers/copilot.env",
            "pointer_env": "AAS_PROVIDER_SECRETS_FILE",
            "argv": ["--csr-credential-probe"],
        }
        manifest_path = root / "projected-copilot.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, launcher

    def run_verifier(
        self,
        home: Path,
        manifest: Path,
        bindir: Path,
        *extra: str,
        path_value: str | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        arguments = list(extra)
        if (
            "--readiness-phase" not in arguments
            and "--runtime-smoke-report" not in arguments
        ):
            report = home / ".local/state/coding-system/restore/aas-runtime-smoke.json"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(
                json.dumps(
                    {
                        "schema": "ai-agents-skills.installed-runtime-smoke.v1",
                        "schema_version": 1,
                        "status": "ok",
                        "mode": "installed",
                        "checked": 3,
                        "unknown_coverage_count": 0,
                        "missing_managed_runtime_count": 0,
                        "declared_exclusions": [],
                        "results": [{"status": "ok"}],
                    }
                ),
                encoding="utf-8",
            )
            report.chmod(0o600)
            arguments.extend(["--runtime-smoke-report", str(report)])
        environment = os.environ.copy()
        environment.update(extra_env or {})
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--manifest",
                str(manifest),
                "--root",
                str(home),
                "--aas-source-root",
                str(home / ".test-aas-source"),
                "--path",
                path_value
                or os.pathsep.join((str(home / ".local/bin"), str(bindir))),
                *arguments,
            ],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_runtime_credential_authority_contract_is_validated_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()

            completed = self.run_verifier(
                home,
                self.fixture(root),
                bindir,
                "--allow-missing-target",
                "codex",
                "--allow-missing-target",
                "copilot",
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            queue = report["runtime_credential_authorities"][
                "file-delivery-queue"
            ]
            self.assertEqual(queue["status"], "PASS")
            self.assertEqual(
                queue["exact_keys"],
                runtime_credential_authorities()["file-delivery-queue"][
                    "exact_keys"
                ],
            )
            self.assertEqual(queue["readiness_when_absent"], "NOT_CONFIGURED")
            self.assertTrue(queue["replay_ledger"]["backup_required"])

    def test_runtime_credential_authority_contract_cannot_be_removed_or_weakened(self) -> None:
        mutations = (
            (
                "removed",
                lambda value: value.pop("runtime_credential_authorities"),
            ),
            (
                "missing-key",
                lambda value: value["runtime_credential_authorities"]
                ["file-delivery-queue"]["exact_keys"].remove("max_replay_entries"),
            ),
            (
                "wrong-boundary",
                lambda value: value["runtime_credential_authorities"]
                ["file-delivery-queue"].update(
                    {"distinct_from": ".config/ai-agents-skills/secrets.json"}
                ),
            ),
            (
                "extra-authority",
                lambda value: value["runtime_credential_authorities"].update(
                    {"unreviewed": {}}
                ),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home, bindir = root / "home", root / "bin"
                bindir.mkdir()
                value = json.loads(self.fixture(root).read_text(encoding="utf-8"))
                mutate(value)
                manifest = root / f"target-state-{label}.json"
                manifest.write_text(json.dumps(value), encoding="utf-8")

                completed = self.run_verifier(home, manifest, bindir)

                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stdout, "")
                self.assertIn("target-state", completed.stderr)

    def test_reports_reauth_without_exposing_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.add_common_runtimes(bindir)
            self.fake_cli(bindir, "codex")
            self.fake_cli(bindir, "copilot")
            self.add_skill(home, ".codex")
            self.add_skill(home, ".copilot")
            secret = "canary-secret-never-print"
            auth = home / ".codex/auth.json"
            auth.write_text(json.dumps({"token": secret}), encoding="utf-8")
            auth.chmod(0o600)
            completed = self.run_verifier(home, self.fixture(root), bindir)
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertNotIn(secret, completed.stdout + completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["schema"], "coding-system.target-verification.v2")
            self.assertEqual(report["targets"]["codex"]["status"], "PASS")
            self.assertEqual(report["targets"]["copilot"]["status"], "REAUTH_REQUIRED")
            self.assertEqual(report["targets"]["codex"]["runtime_status"], "PASS")

    def test_copilot_accepts_backed_target_scoped_provider_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.add_common_runtimes(bindir)
            helper = CopilotWrapperTests()
            launcher = helper.render(home)
            helper.add_secret_loader(home)
            self.fake_cli(home / ".npm-global/bin", "copilot")
            self.add_skill(home, ".copilot")
            manifest = json.loads(self.fixture(root).read_text(encoding="utf-8"))
            manifest["targets"].pop("codex")
            manifest["targets"]["copilot"]["credential_authorities"].append(
                {
                    "kind": "strict-env-file",
                    "path": ".config/ai-agents-skills/providers/copilot.env",
                    "allowed_keys": [
                        "COPILOT_GITHUB_TOKEN",
                        "COPILOT_PROVIDER_API_KEY",
                        "COPILOT_PROVIDER_BEARER_TOKEN",
                        "GH_TOKEN",
                        "GITHUB_TOKEN",
                    ],
                    "keys": [
                        "COPILOT_GITHUB_TOKEN",
                        "COPILOT_PROVIDER_API_KEY",
                        "COPILOT_PROVIDER_BEARER_TOKEN",
                        "GH_TOKEN",
                        "GITHUB_TOKEN",
                    ],
                    "restore_policy": "target-scoped-projection",
                }
            )
            manifest["targets"]["copilot"]["readiness"].append(
                "credential-projection"
            )
            manifest["targets"]["copilot"]["credential_projection"] = {
                "launcher": ".local/bin/copilot",
                "launcher_source": "system/bin/copilot",
                "closure_loader": ".npm-global/lib/node_modules/@github/copilot/npm-loader.js",
                "authority": ".config/ai-agents-skills/providers/copilot.env",
                "pointer_env": "AAS_PROVIDER_SECRETS_FILE",
                "argv": ["--csr-credential-probe"],
            }
            manifest_path = root / "copilot.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            provider = home / ".config/ai-agents-skills/providers/copilot.env"
            provider.parent.mkdir(parents=True)
            secret = "target-state-secret-never-print"
            provider.write_text(f"GH_TOKEN={secret}\n", encoding="utf-8")
            provider.chmod(0o600)

            shared_provider = home / ".config/ai-agents-skills/providers.env"
            shared_provider.write_text(
                "OPENAI_API_KEY=$(touch must-not-run)\n", encoding="utf-8"
            )
            shared_provider.chmod(0o600)
            completed = self.run_verifier(
                home,
                manifest_path,
                bindir,
                path_value=os.pathsep.join(
                    (
                        str(home / ".npm-global/bin"),
                        str(bindir),
                        str(home / ".local/bin"),
                    )
                ),
                extra_env={"AAS_PROVIDER_SECRETS_FILE": str(shared_provider)},
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn(secret, completed.stdout + completed.stderr)
            self.assertNotIn("touch must-not-run", completed.stdout + completed.stderr)
            self.assertFalse((home / "must-not-run").exists())
            report = json.loads(completed.stdout)
            self.assertEqual(report["targets"]["copilot"]["status"], "PASS")
            self.assertEqual(
                report["targets"]["copilot"]["cli"]["command"], str(launcher)
            )
            projected = report["targets"]["copilot"]["credential_authorities"][1]
            self.assertEqual(projected["matched_keys"], ["GH_TOKEN"])

    def test_copilot_templated_closure_loader_binds_the_locked_source(self) -> None:
        # ai-agents-skills names where the locked closure lives as a template and
        # the compatibility link as the way to find it.
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "closurectl_for_test", ROOT / "system/software/npm-closure/closurectl.py"
        )
        assert spec is not None and spec.loader is not None
        closurectl = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(closurectl)
        locked_source = closurectl.source_digest()
        for source, expected in ((locked_source, "PASS"), ("c" * 64, "TECHNICAL_FAIL")):
            with self.subTest(source=source[:8]), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home, bindir = root / "home", root / "bin"
                bindir.mkdir()
                self.add_common_runtimes(bindir)
                helper = CopilotWrapperTests()
                helper.render(home, source=source)
                helper.add_secret_loader(home)
                self.add_skill(home, ".copilot")
                manifest = json.loads(self.fixture(root).read_text(encoding="utf-8"))
                manifest["targets"].pop("codex")
                keys = ["COPILOT_GITHUB_TOKEN", "COPILOT_PROVIDER_API_KEY",
                        "COPILOT_PROVIDER_BEARER_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]
                manifest["targets"]["copilot"]["credential_authorities"].append({
                    "kind": "strict-env-file",
                    "path": ".config/ai-agents-skills/providers/copilot.env",
                    "allowed_keys": keys, "keys": keys,
                    "restore_policy": "target-scoped-projection",
                })
                manifest["targets"]["copilot"]["readiness"].append("credential-projection")
                manifest["targets"]["copilot"]["credential_projection"] = {
                    "launcher": ".local/bin/copilot",
                    "launcher_source": "system/bin/copilot",
                    "closure_loader": (
                        ".local/share/coding-system/npm-closures/"
                        "sha256-{arch}-{source_sha256}-{tree_sha256}"
                        "/node_modules/@github/copilot/npm-loader.js"
                    ),
                    "compatibility_loader": ".npm-global/lib/node_modules/@github/copilot/npm-loader.js",
                    "authority": ".config/ai-agents-skills/providers/copilot.env",
                    "pointer_env": "AAS_PROVIDER_SECRETS_FILE",
                    "argv": ["--csr-credential-probe"],
                }
                manifest_path = root / "copilot.json"
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                provider = home / ".config/ai-agents-skills/providers/copilot.env"
                provider.parent.mkdir(parents=True)
                provider.write_text("GH_TOKEN=templated-secret\n", encoding="utf-8")
                provider.chmod(0o600)
                completed = self.run_verifier(
                    home, manifest_path, bindir,
                    path_value=os.pathsep.join(
                        (str(home / ".npm-global/bin"), str(bindir), str(home / ".local/bin"))
                    ),
                )
                report = json.loads(completed.stdout)
                projection = next(item for item in report["targets"]["copilot"]["readiness"]
                                  if item["check"] == "credential-projection")
                self.assertEqual(projection["status"], expected, completed.stdout)
                if expected != "PASS":
                    self.assertEqual(projection["reason"], "projection-launcher-source-invalid")

    def test_copilot_strict_provider_authority_fails_closed_on_unsafe_input(self) -> None:
        for body, mode in (
            ("GH_TOKEN=must-not-leak\n", 0o644),
            ("GH_TOKEN=duplicate\nGH_TOKEN=must-not-leak\n", 0o600),
            ("UNKNOWN_PROVIDER_KEY=must-not-leak\n", 0o600),
            ("GH_TOKEN=" + "x" * 65_528 + "must-not-leak\n", 0o600),
        ):
            with self.subTest(mode=oct(mode), body=body.split("=", 1)[0]), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home, bindir = root / "home", root / "bin"
                bindir.mkdir()
                self.add_common_runtimes(bindir)
                self.fake_cli(bindir, "copilot")
                self.add_skill(home, ".copilot")
                manifest = json.loads(self.fixture(root).read_text(encoding="utf-8"))
                manifest["targets"].pop("codex")
                manifest["targets"]["copilot"]["credential_authorities"] = [
                    {
                        "kind": "strict-env-file",
                        "path": ".config/ai-agents-skills/providers/copilot.env",
                        "allowed_keys": ["GH_TOKEN"],
                        "keys": ["GH_TOKEN"],
                        "restore_policy": "target-scoped-projection",
                    }
                ]
                manifest_path = root / "copilot.json"
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                provider = home / ".config/ai-agents-skills/providers/copilot.env"
                provider.parent.mkdir(parents=True)
                provider.write_text(body, encoding="utf-8")
                provider.chmod(mode)

                completed = self.run_verifier(home, manifest_path, bindir)

                self.assertEqual(completed.returncode, 2)
                self.assertNotIn("must-not-leak", completed.stdout + completed.stderr)
                self.assertFalse((home / "must-not-run").exists())
                report = json.loads(completed.stdout)
                self.assertEqual(
                    report["targets"]["copilot"]["status"], "TECHNICAL_FAIL"
                )

    def test_copilot_strict_authority_rejects_each_parent_symlink_level(self) -> None:
        for symlink_level in ("config", "authority-parent"):
            with self.subTest(symlink_level=symlink_level), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home, bindir = root / "home", root / "bin"
                bindir.mkdir()
                self.add_common_runtimes(bindir)
                self.fake_cli(bindir, "copilot")
                self.add_skill(home, ".copilot")
                manifest = json.loads(self.fixture(root).read_text(encoding="utf-8"))
                manifest["targets"].pop("codex")
                manifest["targets"]["copilot"]["credential_authorities"] = [
                    {
                        "kind": "strict-env-file",
                        "path": ".config/ai-agents-skills/providers/copilot.env",
                        "allowed_keys": ["GH_TOKEN"],
                        "keys": ["GH_TOKEN"],
                        "restore_policy": "target-scoped-projection",
                    }
                ]
                manifest_path = root / "copilot-symlink.json"
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                if symlink_level == "config":
                    target = home / "real-config/ai-agents-skills"
                    target.mkdir(parents=True)
                    (home / ".config").symlink_to(home / "real-config")
                else:
                    (home / ".config").mkdir(parents=True)
                    target = home / "real-aas"
                    target.mkdir()
                    (home / ".config/ai-agents-skills").symlink_to(target)
                provider = target / "providers/copilot.env"
                provider.parent.mkdir()
                provider.write_text("GH_TOKEN=must-not-leak\n", encoding="utf-8")
                provider.chmod(0o600)

                completed = self.run_verifier(home, manifest_path, bindir)

                self.assertEqual(completed.returncode, 2)
                self.assertNotIn("must-not-leak", completed.stdout + completed.stderr)
                report = json.loads(completed.stdout)
                self.assertEqual(report["targets"]["copilot"]["status"], "TECHNICAL_FAIL")

    def test_copilot_projection_rejects_tampered_always_pass_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.add_common_runtimes(bindir)
            manifest, launcher = self.projected_copilot_fixture(root, home)
            provider = home / ".config/ai-agents-skills/providers/copilot.env"
            provider.parent.mkdir(parents=True)
            provider.write_text("GH_TOKEN=must-not-leak\n", encoding="utf-8")
            provider.chmod(0o600)
            launcher.write_text(
                "#!/bin/sh\nprintf '%s\\n' 'copilot credential projection: PASS'\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)

            completed = self.run_verifier(home, manifest, bindir)

            self.assertEqual(completed.returncode, 2)
            self.assertNotIn("must-not-leak", completed.stdout + completed.stderr)
            report = json.loads(completed.stdout)
            readiness = report["targets"]["copilot"]["readiness"]
            projection = next(item for item in readiness if item["check"] == "credential-projection")
            self.assertEqual(projection["reason"], "projection-launcher-tampered")

    def test_insecure_authority_and_missing_cli_are_technical_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.add_common_runtimes(bindir)
            self.fake_cli(bindir, "codex")
            self.add_skill(home, ".codex")
            self.add_skill(home, ".copilot")
            auth = home / ".codex/auth.json"
            auth.write_text(json.dumps({"token": "fixture"}), encoding="utf-8")
            auth.chmod(0o644)
            completed = self.run_verifier(home, self.fixture(root), bindir)
            report = json.loads(completed.stdout)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(report["targets"]["codex"]["status"], "TECHNICAL_FAIL")
            self.assertEqual(report["targets"]["copilot"]["cli"]["reason"], "cli-missing")

    def test_empty_or_shape_invalid_credential_file_is_a_technical_failure(self) -> None:
        for payload in ("", "  \n", "{}", "not-json"):
            with self.subTest(payload=repr(payload)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home, bindir = root / "home", root / "bin"
                bindir.mkdir()
                self.add_common_runtimes(bindir)
                self.fake_cli(bindir, "codex")
                self.add_skill(home, ".codex")
                auth = home / ".codex/auth.json"
                auth.write_text(payload, encoding="utf-8")
                auth.chmod(0o600)
                completed = self.run_verifier(
                    home, self.fixture(root), bindir, "--allow-missing-target", "copilot"
                )
                report = json.loads(completed.stdout)
                self.assertEqual(completed.returncode, 2)
                authority = report["targets"]["codex"]["credential_authorities"][0]
                self.assertFalse(authority["structurally_valid"])
                self.assertNotIn(payload.strip(), completed.stdout + completed.stderr) if payload.strip() else None

    def test_explicit_unsupported_target_is_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.add_common_runtimes(bindir)
            self.fake_cli(bindir, "codex")
            self.add_skill(home, ".codex")
            auth = home / ".codex/auth.json"
            auth.write_text(json.dumps({"token": "fixture"}), encoding="utf-8")
            auth.chmod(0o600)
            completed = self.run_verifier(
                home, self.fixture(root), bindir, "--allow-missing-target", "copilot"
            )
            report = json.loads(completed.stdout)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(report["targets"]["copilot"]["status"], "NOT_APPLICABLE")

    def test_declared_skips_are_reported_with_their_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.add_common_runtimes(bindir)
            self.fake_cli(bindir, "codex")
            self.add_skill(home, ".codex")
            self.add_skill(home, ".copilot")
            auth = home / ".codex/auth.json"
            auth.write_text(json.dumps({"token": "fixture"}), encoding="utf-8")
            auth.chmod(0o600)
            # Copilot's CLI is absent: a declared skip records why instead of failing.
            completed = self.run_verifier(
                home, self.fixture(root), bindir,
                "--skip", "copilot:cli=the lock names another tool",
                "--skip", "codex:runtime:node-runtime=no Node on this host",
            )
            report = json.loads(completed.stdout)
            self.assertNotEqual(completed.returncode, 2, completed.stderr)
            copilot = report["targets"]["copilot"]
            self.assertEqual(copilot["cli"], {"status": "SKIPPED", "reason": "the lock names another tool"})
            self.assertIn(
                {"check": "cli-version", "status": "SKIPPED", "reason": "the lock names another tool"},
                copilot["readiness"],
            )
            node = next(item for item in report["targets"]["codex"]["runtime_requirements"]
                        if item["requirement"] == "node-runtime")
            self.assertEqual(node, {"requirement": "node-runtime", "status": "SKIPPED",
                                    "reason": "no Node on this host"})
            # A whole target can be skipped too, and skips never hide a real failure.
            completed = self.run_verifier(
                home, self.fixture(root), bindir, "--skip", "copilot=degraded restore"
            )
            report = json.loads(completed.stdout)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(report["targets"]["copilot"],
                             {"status": "SKIPPED", "reason": "degraded restore"})
            completed = self.run_verifier(home, self.fixture(root), bindir)
            self.assertEqual(completed.returncode, 2)

    def test_skip_selectors_must_name_declared_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.add_common_runtimes(bindir)
            for selector in (
                "unknown-target=reason",
                "codex:runtime:sagemath=reason",
                "codex:everything=reason",
                "codex:cli",
                "codex:cli=",
            ):
                with self.subTest(selector=selector):
                    completed = self.run_verifier(
                        home, self.fixture(root), bindir, "--skip", selector
                    )
                    self.assertEqual(completed.returncode, 2)
                    self.assertIn("skip", completed.stderr)

    def test_codewhale_skills_follow_its_configured_skills_dir(self) -> None:
        manifest = {
            "schema": "ai-agents-skills.target-state.v3",
            "schema_version": 3,
            "runtime_credential_authorities": runtime_credential_authorities(),
            "targets": {
                name: {
                    "home": home_dir,
                    "cli_candidates": [name],
                    "version_argv": ["--version"],
                    "runtime_requirements": ["python-runtime", "git-cli"],
                    "credential_authorities": [],
                    "readiness": ["cli-version", "managed-skill-visibility"],
                }
                for name, home_dir in (("deepseek", ".deepseek"), ("codewhale", ".codewhale"))
            },
        }
        for configured in (True, False):
            with self.subTest(configured=configured), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home, bindir = root / "home", root / "bin"
                bindir.mkdir()
                self.add_common_runtimes(bindir)
                self.fake_cli(bindir, "deepseek")
                self.fake_cli(bindir, "codewhale")
                self.add_skill(home, ".deepseek")
                (home / ".codewhale").mkdir(mode=0o700)
                config = home / ".codewhale/config.toml"
                config.write_text(
                    'skills_dir = "~/.deepseek/skills"\n' if configured else "\n",
                    encoding="utf-8",
                )
                config.chmod(0o600)
                path = root / "target-state.json"
                path.write_text(json.dumps(manifest), encoding="utf-8")
                completed = self.run_verifier(home, path, bindir)
                report = json.loads(completed.stdout)
                visibility = next(item for item in report["targets"]["codewhale"]["readiness"]
                                  if item["check"] == "managed-skill-visibility")
                if configured:
                    self.assertEqual(visibility["status"], "PASS", completed.stdout)
                    self.assertEqual(visibility["skills_from"], "deepseek")
                else:
                    self.assertEqual(visibility["status"], "TECHNICAL_FAIL")
                    self.assertNotIn("skills_from", visibility)

    def test_arbitrary_visible_skill_without_installer_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.add_common_runtimes(bindir)
            self.fake_cli(bindir, "codex")
            arbitrary = home / ".codex/skills/canary/SKILL.md"
            arbitrary.parent.mkdir(parents=True)
            arbitrary.write_text("---\nname: canary\n---\n", encoding="utf-8")
            auth = home / ".codex/auth.json"
            auth.write_text(json.dumps({"token": "fixture"}), encoding="utf-8")
            auth.chmod(0o600)
            manifest = json.loads(self.fixture(root).read_text(encoding="utf-8"))
            manifest["targets"].pop("copilot")
            manifest_path = root / "codex-only.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            completed = self.run_verifier(home, manifest_path, bindir)

            self.assertEqual(completed.returncode, 2, completed.stderr)
            report = json.loads(completed.stdout)
            managed = next(
                item
                for item in report["targets"]["codex"]["readiness"]
                if item["check"] == "managed-skill-visibility"
            )
            self.assertEqual(managed["status"], "TECHNICAL_FAIL")
            self.assertEqual(managed["reason"], "installer-state-missing")

    def test_managed_skill_receipt_chain_rejects_tampering(self) -> None:
        for mutation in ("receipt", "installed-file", "source-content", "source-authority"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home, bindir = root / "home", root / "bin"
                bindir.mkdir()
                self.add_common_runtimes(bindir)
                self.fake_cli(bindir, "codex")
                self.add_skill(home, ".codex")
                auth = home / ".codex/auth.json"
                auth.write_text(json.dumps({"token": "fixture"}), encoding="utf-8")
                auth.chmod(0o600)
                manifest = json.loads(self.fixture(root).read_text(encoding="utf-8"))
                manifest["targets"].pop("copilot")
                manifest_path = root / "codex-only.json"
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                state_path = home / ".ai-agents-skills/state.json"
                state = json.loads(state_path.read_text(encoding="utf-8"))
                record = state["artifacts"][0]
                receipt_path = (
                    home / ".ai-agents-skills/runs" / f"{record['run_id']}.json"
                )
                if mutation == "receipt":
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    receipt["actions"][0]["managed"] = False
                    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                    receipt_path.chmod(0o600)
                elif mutation == "installed-file":
                    Path(record["artifact"]).write_text(
                        "---\nname: canary\ntampered: true\n---\n",
                        encoding="utf-8",
                    )
                elif mutation == "source-content":
                    Path(record["source_path"]).write_text(
                        "---\nname: canary\nsource-tampered: true\n---\n",
                        encoding="utf-8",
                    )
                else:
                    outside = home / "outside-source/SKILL.md"
                    outside.parent.mkdir(parents=True)
                    outside.write_text("---\nname: canary\n---\n", encoding="utf-8")
                    record["source_path"] = str(outside)
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    receipt["actions"][0] = record
                    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                    receipt_path.chmod(0o600)
                    state_path.write_text(json.dumps(state), encoding="utf-8")
                    state_path.chmod(0o600)

                completed = self.run_verifier(home, manifest_path, bindir)

                self.assertEqual(completed.returncode, 2, completed.stderr)
                report = json.loads(completed.stdout)
                managed = next(
                    item
                    for item in report["targets"]["codex"]["readiness"]
                    if item["check"] == "managed-skill-visibility"
                )
                self.assertEqual(managed["status"], "TECHNICAL_FAIL")
                self.assertEqual(managed["reason"], "managed-skill-receipt-mismatch")

    def test_managed_skill_receipts_must_cover_complete_restore_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.add_common_runtimes(bindir)
            self.fake_cli(bindir, "codex")
            self.add_skill(home, ".codex")
            auth = home / ".codex/auth.json"
            auth.write_text(json.dumps({"token": "fixture"}), encoding="utf-8")
            auth.chmod(0o600)
            manifest = json.loads(self.fixture(root).read_text(encoding="utf-8"))
            manifest["targets"].pop("copilot")
            manifest_path = root / "codex-only.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            skills_path = home / ".test-aas-source/manifest/skills.yaml"
            skills = json.loads(skills_path.read_text(encoding="utf-8"))
            skills["skills"]["missing-required-skill"] = {"supported_agents": ["codex"]}
            skills_path.write_text(json.dumps(skills), encoding="utf-8")

            completed = self.run_verifier(home, manifest_path, bindir)

            self.assertEqual(completed.returncode, 2, completed.stderr)
            report = json.loads(completed.stdout)
            managed = next(
                item
                for item in report["targets"]["codex"]["readiness"]
                if item["check"] == "managed-skill-visibility"
            )
            self.assertEqual(managed["reason"], "complete-restore-inventory-incomplete")
            self.assertEqual(managed["missing_skills"], ["missing-required-skill"])

    def test_openclaw_managed_skill_requires_applied_digest_bound_transaction(self) -> None:
        manifest = {
            "schema": "ai-agents-skills.target-state.v3",
            "schema_version": 3,
            "runtime_credential_authorities": runtime_credential_authorities(),
            "targets": {
                "openclaw": {
                    "home": ".openclaw",
                    "cli_candidates": ["openclaw"],
                    "version_argv": ["--version"],
                    "runtime_requirements": ["python-runtime"],
                    "credential_authorities": [],
                    "readiness": ["cli-version", "managed-skill-visibility"],
                }
            },
        }
        for mutation in (
            "trivial-state",
            "pending-transaction",
            "installed-file",
            "installed-identity",
            "source-content",
            "inventory-omission",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home, bindir = root / "home", root / "bin"
                bindir.mkdir()
                self.fake_cli(bindir, "openclaw")
                self.fake_cli(bindir, "python3")
                self.add_skill(home, ".openclaw")
                manifest_path = root / "openclaw.json"
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                state_path = home / ".ai-agents-skills/openclaw-target-state.json"
                state = json.loads(state_path.read_text(encoding="utf-8"))
                if mutation == "trivial-state":
                    state = {
                        "schema_version": 1,
                        "artifacts": [{"key": "fixture"}],
                        "runs": [],
                        "transactions": [],
                    }
                elif mutation == "pending-transaction":
                    state["transactions"][0]["status"] = "pending"
                elif mutation == "installed-file":
                    (home / ".openclaw/skills/canary/SKILL.md").write_text(
                        "---\nname: canary\ntampered: true\n---\n",
                        encoding="utf-8",
                    )
                elif mutation == "installed-identity":
                    target = home / ".openclaw/skills/canary/SKILL.md"
                    replacement = target.with_name("replacement.md")
                    replacement.write_bytes(target.read_bytes())
                    replacement.replace(target)
                elif mutation == "source-content":
                    (home / ".test-aas-source/canonical/skills/canary/SKILL.md").write_text(
                        "---\nname: canary\nsource-tampered: true\n---\n",
                        encoding="utf-8",
                    )
                else:
                    skills_path = home / ".test-aas-source/manifest/skills.yaml"
                    skills = json.loads(skills_path.read_text(encoding="utf-8"))
                    skills["skills"]["silently-omitted"] = {
                        "supported_agents": ["openclaw"]
                    }
                    skills_path.write_text(json.dumps(skills), encoding="utf-8")
                state_path.write_text(json.dumps(state), encoding="utf-8")
                state_path.chmod(0o600)

                completed = self.run_verifier(home, manifest_path, bindir)

                self.assertEqual(completed.returncode, 2, completed.stderr)
                report = json.loads(completed.stdout)
                managed = next(
                    item
                    for item in report["targets"]["openclaw"]["readiness"]
                    if item["check"] == "managed-skill-visibility"
                )
                self.assertEqual(managed["status"], "TECHNICAL_FAIL")

    def test_openclaw_identical_adoption_attestation_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.fake_cli(bindir, "openclaw")
            self.fake_cli(bindir, "python3")
            self.add_skill(home, ".openclaw")
            manifest = {
                "schema": "ai-agents-skills.target-state.v3",
                "schema_version": 3,
                "runtime_credential_authorities": runtime_credential_authorities(),
                "targets": {
                    "openclaw": {
                        "home": ".openclaw",
                        "cli_candidates": ["openclaw"],
                        "version_argv": ["--version"],
                        "runtime_requirements": ["python-runtime"],
                        "credential_authorities": [],
                        "readiness": ["cli-version", "managed-skill-visibility"],
                    }
                },
            }
            manifest_path = root / "openclaw.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            state_path = home / ".ai-agents-skills/openclaw-target-state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            record = state["artifacts"][0]
            record["attestation"] = "adopted-identical"
            record["created_parent_dirs"] = []
            action = state["transactions"][0]["actions"][0]
            action["operation"] = "no-op"
            action["pre_state"] = record["installed_signature"]
            action["current_pre_state"] = record["installed_signature"]
            action["reason"] = "ready-to-adopt"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            state_path.chmod(0o600)
            skills_path = home / ".test-aas-source/manifest/skills.yaml"
            skills = json.loads(skills_path.read_text(encoding="utf-8"))
            skills["skills"]["runtime-backed"] = {"supported_agents": ["openclaw"]}
            skills_path.write_text(json.dumps(skills), encoding="utf-8")
            runtime_path = home / ".test-aas-source/manifest/runtime.yaml"
            runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
            runtime["skills"]["runtime-backed"] = {}
            runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

            completed = self.run_verifier(home, manifest_path, bindir)

            self.assertEqual(completed.returncode, 1, completed.stderr)
            report = json.loads(completed.stdout)
            managed = next(
                item
                for item in report["targets"]["openclaw"]["readiness"]
                if item["check"] == "managed-skill-visibility"
            )
            self.assertEqual(managed["status"], "PASS")
            self.assertEqual(managed["reason"], "openclaw-target-receipt-verified")

    def test_multiple_cli_surfaces_are_not_collapsed_into_one_candidate_probe(self) -> None:
        manifest = {
            "schema": "ai-agents-skills.target-state.v3",
            "schema_version": 3,
            "runtime_credential_authorities": runtime_credential_authorities(),
            "targets": {
                "google": {
                    "home": ".google",
                    "runtime_requirements": ["python-runtime"],
                    "readiness": ["cli-version", "managed-skill-visibility"],
                    "surfaces": [
                        {
                            "id": "antigravity",
                            "cli_candidates": ["present-cli"],
                            "version_argv": ["--version"],
                            "credential_authorities": [],
                        },
                        {
                            "id": "gemini",
                            "cli_candidates": ["missing-cli"],
                            "version_argv": ["--version"],
                            "credential_authorities": [],
                        },
                    ],
                }
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = root / "target-state.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            bindir = root / "bin"
            bindir.mkdir()
            self.fake_cli(bindir, "present-cli")
            self.fake_cli(bindir, "python3")
            self.add_skill(root, ".google")
            completed = self.run_verifier(root, manifest_path, bindir)
            report = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["targets"]["google"]["status"], "TECHNICAL_FAIL")
        self.assertEqual(
            [surface["status"] for surface in report["targets"]["google"]["surfaces"]],
            ["NOT_CONFIGURED", "TECHNICAL_FAIL"],
        )

    def test_unknown_runtime_or_readiness_contract_is_rejected(self) -> None:
        for field, value in (("runtime_requirements", ["floating-runtime"]), ("readiness", ["cli-version", "managed-skill-visibility", "unknown-check"])):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = json.loads(self.fixture(root).read_text(encoding="utf-8"))
                manifest["targets"]["codex"][field] = value
                path = root / "invalid.json"
                path.write_text(json.dumps(manifest), encoding="utf-8")
                bindir = root / "bin"
                bindir.mkdir()
                completed = self.run_verifier(root, path, bindir)
                self.assertEqual(completed.returncode, 2)
                self.assertIn("unsupported", completed.stderr)
                self.assertEqual(completed.stdout, "")

    def test_deprecated_restricted_target_evidence_declaration_is_rejected(self) -> None:
        manifest = {
            "schema": "ai-agents-skills.target-state.v3",
            "schema_version": 3,
            "runtime_credential_authorities": runtime_credential_authorities(),
            "targets": {
                "openclaw": {
                    "home": ".openclaw",
                    "cli_candidates": ["openclaw"],
                    "version_argv": ["--version"],
                    "runtime_requirements": ["python-runtime"],
                    "credential_authorities": [
                        {"kind": "file", "path": ".openclaw/secrets.json", "restore_policy": "authority"}
                    ],
                    "readiness": [
                        "cli-version",
                        "managed-skill-visibility",
                        "restricted-target-evidence",
                        "mcp-handshake",
                        "scheduler-canary",
                        "auth-structural",
                    ],
                }
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.fake_cli(bindir, "openclaw")
            self.fake_cli(bindir, "python3")
            self.add_skill(home, ".openclaw")
            secret = home / ".openclaw/secrets.json"
            secret.write_text(json.dumps({"token": "fixture"}), encoding="utf-8")
            secret.chmod(0o600)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            completed = self.run_verifier(home, manifest_path, bindir)

            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, "")
            self.assertIn("unsupported readiness", completed.stderr)

    def test_agent_auth_evidence_binds_sqlite_store_without_parsing_it_as_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.fake_cli(bindir, "openclaw")
            self.fake_cli(bindir, "python3")
            self.add_skill(home, ".openclaw")
            manifest, evidence, _store = self.openclaw_agent_auth_fixture(
                root, home, inherited_agent=True
            )
            completed = self.run_verifier(
                home,
                manifest,
                bindir,
                "--openclaw-runtime-report",
                str(evidence),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            check = next(
                item
                for item in report["targets"]["openclaw"]["readiness"]
                if item["check"] == "agent-auth-closure"
            )
            self.assertEqual(check["status"], "PASS")
            self.assertEqual(check["agent_count"], 2)
            self.assertEqual(check["canonical_store_count"], 1)
            self.assertEqual(check["provider_calls"], 0)

    def test_agent_auth_evidence_rejects_runtime_and_store_mismatch(self) -> None:
        for mutation in ("runtime", "extra-store", "replaced-store"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home, bindir = root / "home", root / "bin"
                bindir.mkdir()
                self.fake_cli(bindir, "openclaw")
                self.fake_cli(bindir, "python3")
                self.add_skill(home, ".openclaw")
                manifest, evidence, _store = self.openclaw_agent_auth_fixture(root, home)
                if mutation == "runtime":
                    value = json.loads(evidence.read_text(encoding="utf-8"))
                    value["agent_auth"]["runtimeVersion"] = "2099.1.1"
                    evidence.write_text(json.dumps(value), encoding="utf-8")
                    evidence.chmod(0o600)
                else:
                    if mutation == "extra-store":
                        extra = home / ".openclaw/agents/extra/agent/openclaw-agent.sqlite"
                        extra.parent.mkdir(parents=True, mode=0o700)
                        extra.write_bytes(b"not parsed")
                        extra.chmod(0o600)
                    else:
                        store = home / ".openclaw/agents/main/agent/openclaw-agent.sqlite"
                        replacement = store.with_name("replacement.sqlite")
                        replacement.write_bytes(b"replacement is not the verified database")
                        replacement.chmod(0o600)
                        os.replace(replacement, store)
                completed = self.run_verifier(
                    home,
                    manifest,
                    bindir,
                    "--openclaw-runtime-report",
                    str(evidence),
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                report = json.loads(completed.stdout)
                check = next(
                    item
                    for item in report["targets"]["openclaw"]["readiness"]
                    if item["check"] == "agent-auth-closure"
                )
                self.assertEqual(check["status"], "TECHNICAL_FAIL")

    def test_agent_auth_schema_versions_reject_json_booleans(self) -> None:
        for mutation in ("outer", "store", "manifest"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home, bindir = root / "home", root / "bin"
                bindir.mkdir()
                self.fake_cli(bindir, "openclaw")
                self.fake_cli(bindir, "python3")
                self.add_skill(home, ".openclaw")
                manifest, evidence, _store = self.openclaw_agent_auth_fixture(root, home)
                if mutation == "manifest":
                    value = json.loads(manifest.read_text(encoding="utf-8"))
                    value["targets"]["openclaw"]["evidence_contracts"][
                        "agent-auth-closure"
                    ]["source_schema_version"] = True
                    manifest.write_text(json.dumps(value), encoding="utf-8")
                else:
                    value = json.loads(evidence.read_text(encoding="utf-8"))
                    if mutation == "outer":
                        value["schema_version"] = True
                    else:
                        value["agent_auth"]["agents"][0]["canonicalStore"][
                            "schemaVersion"
                        ] = True
                    evidence.write_text(json.dumps(value), encoding="utf-8")
                    evidence.chmod(0o600)
                completed = self.run_verifier(
                    home,
                    manifest,
                    bindir,
                    "--openclaw-runtime-report",
                    str(evidence),
                )
                self.assertEqual(completed.returncode, 2)

    def test_agent_auth_evidence_must_be_fresh_private_and_never_leaks_input(self) -> None:
        for mutation in ("stale", "broad-mode"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home, bindir = root / "home", root / "bin"
                bindir.mkdir()
                self.fake_cli(bindir, "openclaw")
                self.fake_cli(bindir, "python3")
                self.add_skill(home, ".openclaw")
                manifest, evidence, _store = self.openclaw_agent_auth_fixture(root, home)
                secret = "evidence-secret-never-print"
                value = json.loads(evidence.read_text(encoding="utf-8"))
                value["untrusted_extra"] = secret
                evidence.write_text(json.dumps(value), encoding="utf-8")
                evidence.chmod(0o600)
                if mutation == "stale":
                    old = time.time() - 600
                    os.utime(evidence, (old, old))
                else:
                    evidence.chmod(0o644)
                completed = self.run_verifier(
                    home,
                    manifest,
                    bindir,
                    "--openclaw-runtime-report",
                    str(evidence),
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertNotIn(secret, completed.stdout + completed.stderr)

    def test_agent_auth_evidence_is_deferred_during_pre_runtime_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.fake_cli(bindir, "openclaw")
            self.fake_cli(bindir, "python3")
            self.add_skill(home, ".openclaw")
            manifest, _evidence, _store = self.openclaw_agent_auth_fixture(root, home)
            completed = self.run_verifier(
                home,
                manifest,
                bindir,
                "--readiness-phase",
                "pre-runtime",
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            report = json.loads(completed.stdout)
            check = next(
                item
                for item in report["targets"]["openclaw"]["readiness"]
                if item["check"] == "agent-auth-closure"
            )
            self.assertEqual(check["status"], "NOT_CONFIGURED")
            self.assertEqual(check["reason"], "deferred-pre-runtime")

    def test_inventory_only_agent_and_github_integration_are_reported_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            home.mkdir()
            bindir.mkdir()
            for command in ("python3", "git", "aider", "gh"):
                self.fake_cli(bindir, command)
            manifest = {
                "schema": "ai-agents-skills.target-state.v3",
                "schema_version": 3,
                "runtime_credential_authorities": runtime_credential_authorities(),
                "targets": {
                    "aider": {
                        "aliases": ["aider-chat"],
                        "home": ".aider",
                        "cli_candidates": ["aider"],
                        "version_argv": ["--version"],
                        "runtime_requirements": ["python-runtime", "git-cli"],
                        "inventory_only": True,
                        "credential_authorities": [],
                        "credential_state": "native-unconfigured",
                        "restore_policy": "reauth-native-configuration",
                        "readiness_when_authority_absent": "NOT_CONFIGURED",
                        "readiness": ["cli-version", "auth-native"],
                    }
                },
                "software_integrations": {
                    "github-cli": {
                        "cli_candidates": ["gh"],
                        "version_argv": ["--version"],
                        "classification": "non-agent-integration",
                        "credential_authorities": [
                            {
                                "kind": "file",
                                "path": ".config/gh/hosts.yml",
                                "restore_policy": "portable-session",
                                "fallback_policy": "reauth-if-nonportable",
                                "structure": "github-hosts-v1",
                            }
                        ],
                        "readiness": ["cli-version", "auth-structural"],
                        "declared_exclusion": (
                            "non-agent integration; managed-skill visibility is not applicable"
                        ),
                    }
                },
            }
            manifest_path = root / "inventory-target-state.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            missing_auth = self.run_verifier(
                home,
                manifest_path,
                bindir,
                "--readiness-phase",
                "pre-runtime",
            )
            self.assertEqual(missing_auth.returncode, 1, missing_auth.stderr)
            report = json.loads(missing_auth.stdout)
            self.assertEqual(report["targets"]["aider"]["status"], "NOT_CONFIGURED")
            self.assertEqual(
                report["software_integrations"]["github-cli"]["auth_status"],
                "REAUTH_REQUIRED",
            )

            hosts = home / ".config/gh/hosts.yml"
            hosts.parent.mkdir(parents=True)
            secret = "github-token-never-report"
            hosts.write_text(f"github.com:\n  oauth_token: {secret}\n", encoding="utf-8")
            hosts.chmod(0o600)
            restored = self.run_verifier(
                home,
                manifest_path,
                bindir,
                "--readiness-phase",
                "pre-runtime",
            )
            self.assertEqual(restored.returncode, 1, restored.stderr)
            self.assertNotIn(secret, restored.stdout + restored.stderr)
            restored_report = json.loads(restored.stdout)
            self.assertEqual(
                restored_report["software_integrations"]["github-cli"]["status"],
                "PASS",
            )

            hosts.write_text("github.com: {}\n", encoding="utf-8")
            invalid_shape = self.run_verifier(
                home,
                manifest_path,
                bindir,
                "--readiness-phase",
                "pre-runtime",
            )
            self.assertEqual(invalid_shape.returncode, 2)
            invalid_report = json.loads(invalid_shape.stdout)
            self.assertEqual(
                invalid_report["software_integrations"]["github-cli"]["status"],
                "TECHNICAL_FAIL",
            )

            hosts.write_text(f"github.com:\n  oauth_token: {secret}\n", encoding="utf-8")
            os.link(hosts, root / "github-hosts-second-link")
            hardlinked = self.run_verifier(
                home,
                manifest_path,
                bindir,
                "--readiness-phase",
                "pre-runtime",
            )
            self.assertEqual(hardlinked.returncode, 2)
            hardlinked_report = json.loads(hardlinked.stdout)
            self.assertEqual(
                hardlinked_report["software_integrations"]["github-cli"]["status"],
                "TECHNICAL_FAIL",
            )
            self.assertNotIn(secret, hardlinked.stdout + hardlinked.stderr)

    def test_inventory_only_and_software_integration_contracts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            home.mkdir()
            bindir.mkdir()
            for command in ("python3", "git", "aider", "gh"):
                self.fake_cli(bindir, command)
            base = {
                "schema": "ai-agents-skills.target-state.v3",
                "schema_version": 3,
                "runtime_credential_authorities": runtime_credential_authorities(),
                "targets": {
                    "aider": {
                        "home": ".aider",
                        "cli_candidates": ["aider"],
                        "version_argv": ["--version"],
                        "runtime_requirements": ["python-runtime", "git-cli"],
                        "inventory_only": True,
                        "credential_authorities": [],
                        "credential_state": "native-unconfigured",
                        "restore_policy": "reauth-native-configuration",
                        "readiness_when_authority_absent": "NOT_CONFIGURED",
                        "readiness": ["cli-version", "auth-native"],
                    }
                },
                "software_integrations": {
                    "github-cli": {
                        "cli_candidates": ["gh"],
                        "version_argv": ["--version"],
                        "classification": "non-agent-integration",
                        "credential_authorities": [
                            {
                                "kind": "file",
                                "path": ".config/gh/hosts.yml",
                                "restore_policy": "portable-session",
                                "structure": "github-hosts-v1",
                            }
                        ],
                        "readiness": ["cli-version", "auth-structural"],
                        "declared_exclusion": "managed skills are not applicable",
                    }
                },
            }
            for label, mutate in (
                (
                    "inventory",
                    lambda value: value["targets"]["aider"].pop("credential_state"),
                ),
                (
                    "integration",
                    lambda value: value["software_integrations"]["github-cli"].update(
                        {"credential_authorities": []}
                    ),
                ),
            ):
                with self.subTest(label=label):
                    value = json.loads(json.dumps(base))
                    mutate(value)
                    manifest_path = root / f"invalid-{label}.json"
                    manifest_path.write_text(json.dumps(value), encoding="utf-8")
                    completed = self.run_verifier(
                        home,
                        manifest_path,
                        bindir,
                        "--readiness-phase",
                        "pre-runtime",
                    )
                    self.assertEqual(completed.returncode, 2)

    def test_pre_runtime_phase_records_external_checks_as_deferred(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = json.loads(self.fixture(root).read_text(encoding="utf-8"))
            manifest["targets"]["codex"]["readiness"].append("mcp-handshake")
            path = root / "manifest-pre.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.add_common_runtimes(bindir)
            self.fake_cli(bindir, "codex")
            self.add_skill(home, ".codex")
            auth = home / ".codex/auth.json"
            auth.write_text(json.dumps({"token": "fixture"}), encoding="utf-8")
            auth.chmod(0o600)
            completed = self.run_verifier(
                home,
                path,
                bindir,
                "--allow-missing-target",
                "copilot",
                "--readiness-phase",
                "pre-runtime",
            )
            report = json.loads(completed.stdout)
            self.assertEqual(completed.returncode, 1)
            check = next(
                item for item in report["targets"]["codex"]["readiness"] if item["check"] == "mcp-handshake"
            )
            self.assertEqual(check["status"], "NOT_CONFIGURED")
            self.assertEqual(check["reason"], "deferred-pre-runtime")
            runtime_check = next(
                item for item in report["targets"]["codex"]["readiness"] if item["check"] == "runtime-smoke"
            )
            self.assertEqual(runtime_check["status"], "NOT_CONFIGURED")
            self.assertEqual(runtime_check["reason"], "deferred-pre-runtime")

    def test_full_runtime_smoke_requires_versioned_passing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, bindir = root / "home", root / "bin"
            bindir.mkdir()
            self.add_common_runtimes(bindir)
            self.fake_cli(bindir, "codex")
            self.add_skill(home, ".codex")
            auth = home / ".codex/auth.json"
            auth.write_text(json.dumps({"token": "fixture"}), encoding="utf-8")
            auth.chmod(0o600)
            manifest = json.loads(self.fixture(root).read_text(encoding="utf-8"))
            manifest["targets"].pop("copilot")
            manifest_path = root / "codex-only.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            missing = self.run_verifier(
                home,
                manifest_path,
                bindir,
                "--runtime-smoke-report",
                str(home / "missing.json"),
            )
            self.assertEqual(missing.returncode, 2, missing.stderr)
            missing_report = json.loads(missing.stdout)
            missing_check = next(
                item
                for item in missing_report["targets"]["codex"]["readiness"]
                if item["check"] == "runtime-smoke"
            )
            self.assertEqual(missing_check["reason"], "runtime-smoke-report-missing")

            evidence = home / "runtime-smoke.json"
            evidence.write_text(
                json.dumps(
                    {
                        "schema": "ai-agents-skills.installed-runtime-smoke.v1",
                        "schema_version": 1,
                        "status": "failed",
                        "mode": "installed",
                        "checked": 1,
                        "unknown_coverage_count": 1,
                        "missing_managed_runtime_count": 0,
                        "declared_exclusions": [],
                        "results": [{"status": "failed"}],
                    }
                ),
                encoding="utf-8",
            )
            evidence.chmod(0o600)
            failed = self.run_verifier(
                home,
                manifest_path,
                bindir,
                "--runtime-smoke-report",
                str(evidence),
            )
            self.assertEqual(failed.returncode, 2, failed.stderr)
            failed_report = json.loads(failed.stdout)
            failed_check = next(
                item
                for item in failed_report["targets"]["codex"]["readiness"]
                if item["check"] == "runtime-smoke"
            )
            self.assertEqual(failed_check["status"], "TECHNICAL_FAIL")
            self.assertEqual(failed_check["unknown_coverage_count"], 1)



class TargetCliPathTests(unittest.TestCase):
    """The target-state check searches the directories the managed shell uses."""

    def test_every_shell_cli_directory_is_on_the_target_check_path(self) -> None:
        block = (ROOT / "system/shell/bashrc.block.sh").read_text(encoding="utf-8")
        wanted = set()
        for match in re.finditer(r'export PATH="?([^"\n]*)"?', block):
            for part in match.group(1).split(":"):
                part = part.replace("{{ HOME }}", "$HOME").replace("$BUN_INSTALL", "$HOME/.bun")
                if part.startswith("$HOME/"):
                    wanted.add(part)
        if '. "$HOME/.cargo/env"' in block:
            wanted.add("$HOME/.cargo/bin")
        self.assertIn("$HOME/.kimi-code/bin", wanted)
        for script in ("bin/install.sh", "bin/verify.sh"):
            source = (ROOT / script).read_text(encoding="utf-8")
            found = re.search(r'TARGET_CLI_PATH="([^"]+)"', source)
            self.assertIsNotNone(found, script)
            self.assertEqual(wanted - set(found.group(1).split(":")), set(), script)
            self.assertIn('--path "$TARGET_CLI_PATH:$PATH"', source, script)


if __name__ == "__main__":
    unittest.main()
