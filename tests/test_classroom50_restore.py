#!/usr/bin/env python3
"""Focused Classroom50 one-command restore contract tests."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/verify-classroom50.py"
MATERIALIZER_SCRIPT = ROOT / "bin/materialize-openclaw-classroom50.py"
SPEC = importlib.util.spec_from_file_location("verify_classroom50", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
MATERIALIZER_SPEC = importlib.util.spec_from_file_location(
    "materialize_openclaw_classroom50", MATERIALIZER_SCRIPT
)
assert MATERIALIZER_SPEC and MATERIALIZER_SPEC.loader
MATERIALIZER = importlib.util.module_from_spec(MATERIALIZER_SPEC)
MATERIALIZER_SPEC.loader.exec_module(MATERIALIZER)


class Classroom50RestoreTests(unittest.TestCase):
    def test_openclaw_credential_selectors_are_reachable_only_from_main(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            workspace = home / ".openclaw/workspace"
            main_selectors = {
                "AAS_COMPUTE_SECRETS_FILE": "/workspace/.config/ai-agents-skills/compute.env",
                "AAS_PROVIDER_SECRETS_FILE": "/workspace/.config/ai-agents-skills/providers.env",
                "GOOGLE_CLASSROOM_CREDENTIALS": (
                    "/workspace/.config/course/google-classroom/credentials.json"
                ),
                "GOOGLE_CLASSROOM_TOKEN": (
                    "/workspace/.config/course/google-classroom/token.pickle"
                ),
                "CANVAS_CONFIG_PATH": "/workspace/.config/course/canvas/config.json",
                "GETSCIPAPERS_CONFIG_DIR": "/workspace/.config/getscipapers",
                "GETSCIPAPERS_SKILL_CONFIG": (
                    "/workspace/data/research/getscipapers_bot/state/config.json"
                ),
                "GH_CONFIG_DIR": "/workspace/.config/gh",
                "CLASSROOM50_ORG_ALLOWLIST": "foundation50,fixture-org",
            }
            config = {
                "agents": {
                    "defaults": {
                        "sandbox": {
                            "docker": {
                                "env": {"XDG_DATA_HOME": "/workspace/.local-data"},
                                "user": f"{os.getuid()}:{os.getgid()}",
                            }
                        },
                        "workspace": str(workspace),
                    },
                    "list": [
                        {
                            "id": "main",
                            "sandbox": {"docker": {"env": main_selectors}},
                            "skills": ["main-skill"],
                            "workspace": str(workspace),
                        },
                        {
                            "id": "review",
                            "sandbox": {
                                "docker": {
                                    "env": {"MOLTBOOK_AUTH": "/workspace/moltbook-auth.json"}
                                }
                            },
                            "skills": [],
                            "workspace": str(home / ".openclaw/workspace-review"),
                        },
                    ],
                }
            }
            default_docker, observed = MODULE.openclaw_main_environment(
                config, workspace
            )
            self.assertEqual(default_docker["env"]["XDG_DATA_HOME"], "/workspace/.local-data")
            self.assertEqual(observed, main_selectors)

            invalid_cases = (
                (
                    "retired-remote-bridge-main",
                    lambda value: value["agents"]["list"][0]["sandbox"]["docker"][
                        "env"
                    ].__setitem__(
                        "REMOTE_BRIDGE_SECRETS_FILE",
                        "/workspace/secrets/remote-bridge/secrets.json",
                    ),
                    "main sandbox exposes a retired credential selector",
                ),
                (
                    # Sandboxed send-email reaches the host queue instead of the
                    # authority, so main may no longer select that file either.
                    "retired-send-email-main",
                    lambda value: value["agents"]["list"][0]["sandbox"]["docker"][
                        "env"
                    ].__setitem__(
                        "SEND_EMAIL_SECRETS_FILE",
                        "/workspace/.config/send-email/secrets.json",
                    ),
                    "main sandbox exposes a retired credential selector",
                ),
                (
                    "retired-main-selector",
                    lambda value: value["agents"]["list"][0]["sandbox"]["docker"][
                        "env"
                    ].__setitem__(
                        "AAS_SKILL_SECRETS_FILE", "/workspace/stale-skill.env"
                    ),
                    "main sandbox exposes a retired credential selector",
                ),
                (
                    "default-leak",
                    lambda value: value["agents"]["defaults"]["sandbox"]["docker"][
                        "env"
                    ].__setitem__("GH_CONFIG_DIR", "/workspace/.config/gh"),
                    "default sandbox exposes",
                ),
                (
                    "auxiliary-leak",
                    lambda value: value["agents"]["list"][1]["sandbox"]["docker"][
                        "env"
                    ].__setitem__("CANVAS_CONFIG_PATH", "/workspace/stale-canvas.json"),
                    "auxiliary sandbox exposes",
                ),
                (
                    "auxiliary-skills",
                    lambda value: value["agents"]["list"][1].__setitem__(
                        "skills", ["course-canvas"]
                    ),
                    "auxiliary agent advertises skills",
                ),
                (
                    "unreachable-main",
                    lambda value: value["agents"]["list"][0].__setitem__(
                        "workspace", str(home / ".openclaw/workspace-review")
                    ),
                    "main workspace cannot reach",
                ),
            )
            for name, mutate, reason in invalid_cases:
                with self.subTest(name=name):
                    candidate = json.loads(json.dumps(config))
                    mutate(candidate)
                    with self.assertRaisesRegex(MODULE.VerificationError, reason):
                        MODULE.openclaw_main_environment(candidate, workspace)

    def test_exact_component_artifact_and_python_authorities(self) -> None:
        self.assertEqual(
            MODULE.component_pin(ROOT),
            (MODULE.EXPECTED_COMPONENT_URL, MODULE.EXPECTED_COMPONENT_COMMIT),
        )
        for architecture in ("amd64", "arm64"):
            checks = MODULE.validate_declarations(ROOT, architecture)
            self.assertEqual(
                checks,
                [
                    "component-pin",
                    "gh-teacher-lock",
                    "course-python-route",
                    "configuration-authority",
                    "nine-target-skill-routing",
                ]
                + (["openclaw-sandbox-course-runtime"] if MODULE.sandbox_embeds_course_runtime(ROOT) else []),
            )
            lock = json.loads(
                (ROOT / f"system/software/ubuntu-24.04-{architecture}.lock.json").read_text()
            )
            teacher = next(item for item in lock["artifacts"] if item["id"] == "gh-teacher")
            self.assertEqual(teacher, MODULE.locked_teacher(ROOT, architecture))
            self.assertEqual(lock["cli_versions"]["gh-teacher"], teacher["version"])
            self.assertTrue(teacher["url"].startswith(MODULE.TEACHER_RELEASES))
            with tempfile.TemporaryDirectory() as temporary:
                forged = Path(temporary)
                (forged / "system/software").mkdir(parents=True)
                teacher_url = teacher["url"]
                (forged / f"system/software/ubuntu-24.04-{architecture}.lock.json").write_text(
                    json.dumps(lock).replace(teacher_url, teacher_url.replace("foundation50", "someone-else")),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(MODULE.VerificationError, "reviewed authority"):
                    MODULE.locked_teacher(forged, architecture)
            python_lock = json.loads(
                (ROOT / f"system/python-closure/ubuntu-24.04-{architecture}.lock.json").read_text()
            )
            self.assertEqual(
                python_lock["environments"]["course-management"]["installPath"],
                ".course_venv",
            )

    def test_allowlist_is_optional_but_invalid_values_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ, {}, clear=True
        ):
            home = Path(temporary)
            self.assertEqual(MODULE.allowlist_status(home), "NOT_CONFIGURED")
            authority = home / ".secrets.env"
            authority.write_text("CLASSROOM50_ORG_ALLOWLIST=foundation50,fixture-org\n")
            authority.chmod(0o600)
            self.assertEqual(MODULE.allowlist_status(home), "PASS")
            # The owner-settings file is data-only, so the legacy shell-export
            # form is no longer read as a value.
            authority.write_text('export CLASSROOM50_ORG_ALLOWLIST="foundation50"\n')
            with self.assertRaises(MODULE.VerificationError):
                MODULE.allowlist_status(home)
            authority.write_text("CLASSROOM50_ORG_ALLOWLIST=good,,bad\n")
            with self.assertRaises(MODULE.VerificationError):
                MODULE.allowlist_status(home)
            authority.write_text("CLASSROOM50_ORG_ALLOWLIST=two values\n")
            with self.assertRaises(MODULE.VerificationError):
                MODULE.allowlist_status(home)

    def test_source_profile_reports_nontechnical_missing_runtime_state(self) -> None:
        architecture = MODULE.ARCHITECTURES[os.uname().machine.lower()]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ, {}, clear=True
        ):
            output = Path(temporary) / "report.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--repository",
                    str(ROOT),
                    "--home",
                    temporary,
                    "--profile",
                    "source",
                    "--architecture",
                    architecture,
                    "--output",
                    str(output),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env={"PATH": os.environ.get("PATH", "")},
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report["technicalStatus"], "PASS")
            self.assertEqual(report["authentication"], "REAUTH_REQUIRED")
            self.assertEqual(report["orgAllowlist"], "NOT_CONFIGURED")

    def test_installer_is_digest_and_version_gated_and_service_token_is_not_authority(self) -> None:
        prepare = (ROOT / "bin/prepare.sh").read_text()
        section = prepare.split('step "Classroom50 teacher extension"', 1)[1].split(
            'if ! skip SKIP_GROK', 1
        )[0]
        self.assertIn("fetch_locked gh-teacher", section)
        self.assertIn("gh_teacher_expected_sha", section)
        self.assertIn("downloaded gh-teacher version probe failed", section)
        self.assertIn("installed gh-teacher digest differs", section)
        self.assertIn("installed gh-teacher version probe failed", section)
        manifest = yaml.safe_load((ROOT / "secrets/secrets-manifest.yaml").read_text())
        self.assertTrue(
            any(
                "CLASSROOM50_ORG_ALLOWLIST" in entry.get("feature", "")
                for entry in manifest["entries"]
            )
        )
        self.assertFalse(
            any("CLASSROOM50_SERVICE_TOKEN" in entry["path"] for entry in manifest["entries"])
        )

    def test_classroom50_skill_is_routed_to_all_nine_agents(self) -> None:
        install = (ROOT / "bin/install.sh").read_text()
        self.assertIn(
            'AAS_RESTORE_AGENTS="codex,claude,deepseek,copilot,opencode,antigravity,grok,kimi"',
            install,
        )
        ordered_gate = [
            install.index("openclaw-target-probe"),
            install.index("openclaw-target-dry-run-manifest"),
            install.index("openclaw-target-approve-manifest"),
            install.index("openclaw-target-apply-manifest"),
        ]
        self.assertEqual(ordered_gate, sorted(ordered_gate))
        self.assertIn("--apply --real-system", install)
        self.assertIn("I understand OpenClaw real-system skill-file writes", install)
        self.assertEqual(set(MODULE.CLASSROOM50_SKILL_PATHS), {
            "codex", "claude", "deepseek", "copilot", "opencode",
            "antigravity", "grok", "kimi", "openclaw",
        })
        self.assertEqual(
            MODULE.CLASSROOM50_SKILL_PATHS["openclaw"],
            ".openclaw/skills/classroom50/SKILL.md",
        )

    def test_runtime_gate_requires_classroom50_on_all_nine_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            for agent, relative_path in MODULE.CLASSROOM50_SKILL_PATHS.items():
                if agent == "openclaw":
                    continue
                skill = home / relative_path
                skill.parent.mkdir(parents=True, exist_ok=True)
                skill.write_text("---\nname: classroom50\n---\n")
            with self.assertRaisesRegex(MODULE.VerificationError, "openclaw"):
                MODULE.verify_skill_targets(home)
            openclaw = home / MODULE.CLASSROOM50_SKILL_PATHS["openclaw"]
            openclaw.parent.mkdir(parents=True, exist_ok=True)
            canonical = "---\nname: classroom50\n---\n\ngh teacher --help\n"
            expected = MODULE._render_openclaw_skill(canonical)
            openclaw.write_bytes(expected)
            self.assertEqual(
                set(MODULE.verify_skill_targets(home, expected_openclaw=expected)),
                set(MODULE.CLASSROOM50_SKILL_PATHS),
            )
            openclaw.write_text("---\nname: classroom50\n---\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.VerificationError, "openclaw"):
                MODULE.verify_skill_targets(home, expected_openclaw=expected)

    def test_wheelhouse_builds_course_package_from_the_component_commit(self) -> None:
        inputs = json.loads(
            (ROOT / "system/docker/python-wheelhouse/build-inputs.json").read_text()
        )
        source = next(item for item in inputs["gitWheels"] if item["name"] == "course-hoanganhduc")
        self.assertTrue(source["requirement"].endswith("@" + MODULE.EXPECTED_COMPONENT_COMMIT))
        self.assertEqual(source["version"], "0.4.0")
        environment = inputs["environments"]["course-management"]
        self.assertEqual(environment["requirements"], ["course-hoanganhduc==0.4.0"])
        self.assertEqual(environment["requiredGitWheels"], ["course-hoanganhduc"])

    def test_sandbox_course_runtime_is_required_only_from_its_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            sandbox = repository / "system/docker/openclaw-sandbox"
            sandbox.mkdir(parents=True)
            (sandbox / "Dockerfile").write_text("FROM base\n", encoding="utf-8")
            (sandbox / "verify.sh").write_text("true\n", encoding="utf-8")
            lock = repository / "system/openclaw/compatibility.lock.json"
            lock.parent.mkdir(parents=True)
            lock.write_text(json.dumps({"sandbox": {"contract": 1}}), encoding="utf-8")
            self.assertFalse(MODULE.sandbox_embeds_course_runtime(repository))
            self.assertEqual(MODULE.validate_sandbox_course_runtime(repository), [])

            lock.write_text(json.dumps({"sandbox": {"contract": 3}}), encoding="utf-8")
            self.assertTrue(MODULE.sandbox_embeds_course_runtime(repository))
            with self.assertRaisesRegex(MODULE.VerificationError, "course-management runtime"):
                MODULE.validate_sandbox_course_runtime(repository)
            runtime = "/opt/coding-system/python-closure/course-management"
            (sandbox / "Dockerfile").write_text(f"COPY x {runtime}\n", encoding="utf-8")
            (sandbox / "verify.sh").write_text(
                f"{runtime}/bin/python -m course_hoanganhduc.c50_agent --help\n", encoding="utf-8"
            )
            self.assertEqual(
                MODULE.validate_sandbox_course_runtime(repository), ["openclaw-sandbox-course-runtime"]
            )

            lock.write_text(json.dumps({"sandbox": {"contract": True}}), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.VerificationError, "sandbox contract"):
                MODULE.sandbox_embeds_course_runtime(repository)

    def test_openclaw_sandbox_embeds_and_smokes_course_management(self) -> None:
        if not MODULE.sandbox_embeds_course_runtime(ROOT):
            self.skipTest("the locked sandbox contract predates the embedded course runtime (D14)")
        dockerfile = (ROOT / "system/docker/openclaw-sandbox/Dockerfile").read_text(
            encoding="utf-8"
        )
        verifier = (ROOT / "system/docker/openclaw-sandbox/verify.sh").read_text(
            encoding="utf-8"
        )
        closure = json.loads(
            (ROOT / "system/openclaw/skill-closure.json").read_text(encoding="utf-8")
        )
        self.assertIn(
            "/closure/python-wheelhouse/course-management", dockerfile
        )
        self.assertIn(
            "/opt/coding-system/python-closure/course-management", dockerfile
        )
        self.assertIn("verify_isolated_inventory course-management", verifier)
        self.assertIn("course_hoanganhduc.c50_agent --help", verifier)
        self.assertIn("classroom50", closure["required_eligible_skills"])

    def test_locked_teacher_binary_is_projected_atomically_for_openclaw(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            source = home / ".local/share/gh/extensions/gh-teacher/gh-teacher"
            source.parent.mkdir(parents=True)
            payload = b"#!/bin/sh\nprintf 'fixture teacher\\n'\n"
            source.write_bytes(payload)
            source.chmod(0o755)
            workspace = home / ".openclaw/workspace"
            workspace.mkdir(parents=True)
            python_generation = home / "python-generation"
            python_generation.mkdir()
            (workspace / ".local").symlink_to(python_generation)
            expected_digest = hashlib.sha256(payload).hexdigest()
            with (
                mock.patch.object(
                    MATERIALIZER,
                    "_locked_artifact",
                    return_value=(expected_digest, "1.25.1"),
                ),
                mock.patch.object(
                    MATERIALIZER,
                    "_probe",
                    side_effect=["gh-teacher version v1.25.1 fixture", "teacher help"],
                ),
                mock.patch.object(MATERIALIZER.shutil, "which", return_value="/usr/bin/gh"),
            ):
                destination = MATERIALIZER.materialize(ROOT, home, "amd64")
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
            self.assertEqual(
                destination,
                workspace / ".local-data/gh/extensions/gh-teacher/gh-teacher",
            )
            self.assertTrue((workspace / ".local").is_symlink())

    def test_openclaw_runtime_materializer_invokes_classroom_projection(self) -> None:
        helper = (ROOT / "bin/materialize-openclaw-runtime.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("materialize-openclaw-classroom50.py", helper)
        self.assertLess(
            helper.index("materialize-secret-projections.py"),
            helper.index("materialize-openclaw-classroom50.py"),
        )


if __name__ == "__main__":
    unittest.main()
