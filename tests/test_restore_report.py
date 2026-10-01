#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "write_restore_report", ROOT / "bin/write-restore-report.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
RUN_ID = "a" * 64


class RestoreReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.architecture = MODULE.ARCHITECTURES[platform.machine().lower()]
        self.commit = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    def test_supported_architectures_are_explicit(self) -> None:
        self.assertEqual(MODULE.ARCHITECTURES["aarch64"], "arm64")
        self.assertEqual(MODULE.ARCHITECTURES["x86_64"], "amd64")
        self.assertNotIn("riscv64", MODULE.ARCHITECTURES)

    def test_install_binds_and_invalidates_final_report_per_run(self) -> None:
        source = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        generated = "RESTORE_RUN_ID=\"$(/usr/bin/python3 -I -B -c 'import secrets; print(secrets.token_hex(32))')\""
        exported = 'export CODING_SYSTEM_RESTORE_RUN_ID="$RESTORE_RUN_ID"'
        started = 'RESTORE_RUN_STARTED_AT_UNIX="$(date +%s)"'
        exported_started = (
            'export CODING_SYSTEM_RESTORE_RUN_STARTED_AT_UNIX="$RESTORE_RUN_STARTED_AT_UNIX"'
        )
        removed = 'rm -f -- "$RESTORE_REPORT_OUTPUT"'
        verification = 'bash "$REPO/bin/verify.sh" --profile'
        report_binding = '--restore-run-id "$RESTORE_RUN_ID"'
        self.assertIn(generated, source)
        self.assertIn(started, source)
        self.assertLess(source.index(exported), source.index(verification))
        self.assertLess(source.index(exported_started), source.index(verification))
        self.assertLess(source.index(removed), source.index(verification))
        self.assertGreater(source.index(report_binding), source.index(verification))

    def ci_gates(self) -> list[tuple[str, str]]:
        return [
            (
                f"Ubuntu 24.04/{self.architecture} lock is internally consistent",
                "PASS",
            ),
            ("npm direct/transitive package closure is exact and immutable", "PASS"),
            (
                "Classroom50 technical closure; nontechnical status=REAUTH_REQUIRED",
                "PASS",
            ),
            (
                "apt/native CLI declarations are structurally verifiable (ci)",
                "PASS",
            ),
            ("Python closure declarations are structurally valid (ci)", "PASS"),
            ("scheduler declarations (ci; live state not asserted)", "PASS"),
            ("MCP declarations are closed or explicitly inert (ci)", "PASS"),
            ("OpenClaw effective runtime closure (ci)", "PASS"),
            (
                "agent target software/config technical state; nontechnical status=REAUTH_REQUIRED",
                "PASS",
            ),
            ("OpenClaw Bash completion (degraded)", "NOT_CONFIGURED"),
            ("required secrets (degraded)", "NOT_CONFIGURED"),
            (
                "skill credential authority/projection/resolver closure (degraded)",
                "NOT_CONFIGURED",
            ),
            (
                "zotero doctor / digest / sage / LeanExplore MCP (degraded)",
                "NOT_CONFIGURED",
            ),
            (
                "component object absent: ~/ai-agents-skills (ci)",
                "NOT_CONFIGURED",
            ),
            (
                "installed ai-agents-skills state/runtime smoke (ci)",
                "NOT_CONFIGURED",
            ),
        ]

    def full_gates(self) -> list[tuple[str, str]]:
        return [
            (
                f"Ubuntu 24.04/{self.architecture} lock is internally consistent",
                "PASS",
            ),
            ("npm direct/transitive package closure is exact and immutable", "PASS"),
            ("Classroom50 component/software/runtime/config state (PASS)", "PASS"),
            ("exact apt package and native CLI closure", "PASS"),
            ("Python OCI provenance + exact eight-environment inventories", "PASS"),
            ("host/systemd/OpenClaw schedules + execution canaries", "PASS"),
            ("every enabled configured MCP completed initialize + tools/list", "PASS"),
            ("OpenClaw Bash completion is current and syntactically valid", "PASS"),
            ("required secrets present", "PASS"),
            ("skill credential authority/projection/resolver closure", "PASS"),
            ("locked OCI platform descriptors + SageMath + Translation Server", "PASS"),
            ("component object present: ~/ai-agents-skills@aaaaaaaaaaaa", "PASS"),
            (
                "all requested non-OpenClaw ai-agents-skills targets match managed state",
                "PASS",
            ),
            (
                "installed ai-agents-skills runtime smoke has complete declared coverage",
                "PASS",
            ),
            ("OpenClaw effective runtime closure (full)", "PASS"),
            ("agent target state (PASS)", "PASS"),
        ]

    def evidence_command(
        self,
        evidence: Path,
        gates: list[tuple[str, str]] | None = None,
        profile: str = "ci",
        *,
        target: Path | None = None,
        classroom50: Path | None = None,
        run_started_at_unix: int | None = None,
    ) -> list[str]:
        target = target or evidence.parent / "target-state.json"
        classroom50 = classroom50 or evidence.parent / "classroom50.json"
        run_started_at_unix = run_started_at_unix or int(time.time()) - 1
        command = [
            "python3",
            str(ROOT / "bin/write-verification-evidence.py"),
            "--repository",
            str(ROOT),
            "--output",
            str(evidence),
            "--profile",
            profile,
            "--architecture",
            self.architecture,
            "--restore-run-id",
            RUN_ID,
            "--run-started-at-unix",
            str(run_started_at_unix),
            "--target-report",
            str(target),
            "--classroom50-report",
            str(classroom50),
        ]
        option = {
            "PASS": "--pass-label",
            "FAIL": "--fail-label",
            "NOT_CONFIGURED": "--skip-label",
        }
        default_gates = self.ci_gates() if profile == "ci" else self.full_gates()
        for label, status in default_gates if gates is None else gates:
            command.extend((option[status], label))
        if profile == "full":
            command.extend(("--expected-commit", self.commit))
        return command

    def write_evidence(
        self,
        evidence: Path,
        gates: list[tuple[str, str]] | None = None,
        profile: str = "ci",
    ) -> tuple[Path, Path]:
        target = evidence.parent / "target-state.json"
        classroom50 = evidence.parent / "classroom50.json"
        if profile == "full":
            self.write_target_report(target, "PASS")
            self.write_classroom_report(classroom50, "PASS")
        else:
            self.write_target_report(target, "REAUTH_REQUIRED")
            self.write_classroom_report(classroom50, "REAUTH_REQUIRED")
        subprocess.run(
            self.evidence_command(
                evidence,
                gates,
                profile,
                target=target,
                classroom50=classroom50,
            ),
            check=True,
            stdout=subprocess.DEVNULL,
        )
        return target, classroom50

    def report_command(
        self,
        evidence: Path,
        output: Path,
        target: Path,
        classroom50: Path,
        run_id: str = RUN_ID,
    ) -> list[str]:
        return [
            "python3",
            str(ROOT / "bin/write-restore-report.py"),
            "--repository",
            str(ROOT),
            "--profile",
            "ci",
            "--verification-evidence",
            str(evidence),
            "--target-report",
            str(target),
            "--classroom50-report",
            str(classroom50),
            "--restore-run-id",
            run_id,
            "--owner-data-status",
            "NOT_CONFIGURED",
            "--output",
            str(output),
        ]

    @staticmethod
    def write_classroom_report(path: Path, status: str = "REAUTH_REQUIRED") -> None:
        path.write_text(
            json.dumps(
                {
                    "schema": "coding-system.classroom50-verification/v1",
                    "technicalStatus": "PASS",
                    "status": status,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    @staticmethod
    def write_target_report(path: Path, status: str = "REAUTH_REQUIRED") -> None:
        path.write_text(
            json.dumps(
                {
                    "schema": "coding-system.target-verification.v2",
                    "status": status,
                    "technicalStatus": (
                        "FAIL" if status in {"TECHNICAL_FAIL", "AUTH_INVALID"} else "PASS"
                    ),
                    "readiness_phase": "full",
                    "targets": {},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    def test_report_consumes_fresh_run_bound_complete_gate_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence.json"
            output = root / "report.json"
            target, classroom50 = self.write_evidence(evidence)

            subprocess.run(
                self.report_command(evidence, output, target, classroom50),
                check=True,
                stdout=subprocess.DEVNULL,
            )
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["technicalStatus"], "PASS")
            self.assertEqual(report["restoreRunId"], RUN_ID)
            self.assertEqual(report["classroom50Status"], "REAUTH_REQUIRED")
            self.assertEqual(report["verification"]["classroom50"], "REAUTH_REQUIRED")
            self.assertEqual(
                report["verificationEvidence"]["gateInventory"],
                MODULE.expected_gate_ids("ci"),
            )
            self.assertGreaterEqual(report["verificationEvidence"]["ageSeconds"], 0)
            self.assertFalse(report["releaseReady"])
            self.assertNotIn("softwareLock", report["verification"])

    def test_report_rejects_wrong_commit_run_and_stale_evidence(self) -> None:
        mutations = (
            ("repositoryCommit", "0" * 40),
            ("restoreRunId", "b" * 64),
            ("observedAtUnix", 1),
        )
        for field, replacement in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = root / "evidence.json"
                output = root / "report.json"
                target, classroom50 = self.write_evidence(evidence)
                value = json.loads(evidence.read_text(encoding="utf-8"))
                value[field] = replacement
                if field == "observedAtUnix":
                    value["observedAt"] = MODULE.utc_timestamp(replacement)
                evidence.write_text(json.dumps(value) + "\n", encoding="utf-8")

                rejected = subprocess.run(
                    self.report_command(evidence, output, target, classroom50),
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(output.exists())

    def test_report_rejects_inconsistent_counts_duplicate_labels_and_missing_gate(self) -> None:
        def inconsistent_counts(value: dict) -> None:
            value["counts"]["pass"] += 1

        def duplicate_label(value: dict) -> None:
            value["gates"].append(dict(value["gates"][0]))
            value["counts"]["pass"] += 1

        def missing_gate(value: dict) -> None:
            index = next(
                index
                for index, item in enumerate(value["gates"])
                if item["label"] == "MCP declarations are closed or explicitly inert (ci)"
            )
            value["gates"].pop(index)
            value["counts"]["pass"] -= 1
            value["gateInventory"].remove("mcp-closure")

        for name, mutate in (
            ("counts", inconsistent_counts),
            ("duplicate", duplicate_label),
            ("missing", missing_gate),
        ):
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = root / "evidence.json"
                output = root / "report.json"
                target, classroom50 = self.write_evidence(evidence)
                value = json.loads(evidence.read_text(encoding="utf-8"))
                mutate(value)
                evidence.write_text(json.dumps(value) + "\n", encoding="utf-8")
                rejected = subprocess.run(
                    self.report_command(evidence, output, target, classroom50),
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(output.exists())

    def test_report_rejects_sidecar_replacement_and_permission_drift(self) -> None:
        for mutation in ("replace", "mode"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = root / "evidence.json"
                output = root / "report.json"
                target, classroom50 = self.write_evidence(evidence)
                if mutation == "replace":
                    value = json.loads(classroom50.read_text(encoding="utf-8"))
                    value["replacementCanary"] = True
                    classroom50.write_text(json.dumps(value) + "\n", encoding="utf-8")
                    classroom50.chmod(0o600)
                else:
                    classroom50.chmod(0o644)

                rejected = subprocess.run(
                    self.report_command(evidence, output, target, classroom50),
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(output.exists())

    def test_evidence_producer_rejects_unbound_or_unsafe_sidecars(self) -> None:
        for case in ("gate-disagreement", "public-mode", "pre-run"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = root / "evidence.json"
                target = root / "target-state.json"
                classroom50 = root / "classroom50.json"
                self.write_target_report(target)
                self.write_classroom_report(
                    classroom50,
                    "PASS" if case == "gate-disagreement" else "REAUTH_REQUIRED",
                )
                run_started = int(time.time()) - 1
                if case == "public-mode":
                    classroom50.chmod(0o644)
                elif case == "pre-run":
                    old = run_started - 10
                    os.utime(classroom50, (old, old))
                rejected = subprocess.run(
                    self.evidence_command(
                        evidence,
                        target=target,
                        classroom50=classroom50,
                        run_started_at_unix=run_started,
                    ),
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(evidence.exists())

    def test_ci_can_bind_an_explicitly_unavailable_target_without_stale_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence.json"
            output = root / "report.json"
            target = root / "target-state.json"
            classroom50 = root / "classroom50.json"
            self.write_classroom_report(classroom50)
            gates = [
                item
                for item in self.ci_gates()
                if not item[0].startswith("agent target ")
            ]
            gates.append(("target-state manifest unavailable in CI", "NOT_CONFIGURED"))
            subprocess.run(
                self.evidence_command(
                    evidence,
                    gates,
                    target=target,
                    classroom50=classroom50,
                ),
                check=True,
                stdout=subprocess.DEVNULL,
            )
            value = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertFalse(value["sidecars"]["target"]["present"])
            subprocess.run(
                self.report_command(evidence, output, target, classroom50),
                check=True,
                stdout=subprocess.DEVNULL,
            )
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["targetStatus"], "NOT_CONFIGURED")

    def test_evidence_producer_rejects_duplicate_and_incomplete_pass_inventory(self) -> None:
        duplicate = self.ci_gates() + [self.ci_gates()[0]]
        incomplete = self.ci_gates()[:-1]
        for name, gates in (("duplicate", duplicate), ("incomplete", incomplete)):
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                evidence = Path(temporary) / "evidence.json"
                rejected = subprocess.run(
                    self.evidence_command(evidence, gates),
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(evidence.exists())

    def test_evidence_producer_accepts_complete_full_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence.json"
            target = root / "target-state.json"
            classroom50 = root / "classroom50.json"
            self.write_target_report(target, "PASS")
            self.write_classroom_report(classroom50, "PASS")
            subprocess.run(
                self.evidence_command(
                    evidence,
                    profile="full",
                    target=target,
                    classroom50=classroom50,
                ),
                check=True,
                stdout=subprocess.DEVNULL,
            )
            value = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(value["gateInventory"], MODULE.expected_gate_ids("full"))
            self.assertEqual(value["counts"]["notConfigured"], 0)
            self.assertEqual(set(value["sidecars"]), {"classroom50", "target"})
            self.assertEqual(value["sidecars"]["target"]["restoreRunId"], RUN_ID)
            self.assertEqual(
                value["sidecars"]["classroom50"]["repositoryCommit"], self.commit
            )

    def write_decoy_repository(self, path: Path) -> str:
        """Build a second real repository so an honoured redirect is observable."""
        path.mkdir()
        git = [
            "git",
            "-C",
            str(path),
            "-c",
            "init.defaultBranch=main",
            "-c",
            "user.name=decoy",
            "-c",
            "user.email=decoy@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ]
        environment = {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": str(path),
            "PATH": "/usr/bin:/bin",
        }
        (path / "decoy.txt").write_text("decoy\n", encoding="utf-8")
        for arguments in (["init", "-q"], ["add", "decoy.txt"], ["commit", "-q", "-m", "decoy"]):
            subprocess.run([*git, *arguments], check=True, env=environment)
        return subprocess.run(
            [*git, "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            env=environment,
        ).stdout.strip()

    def test_evidence_and_report_ignore_ambient_git_redirects_and_path_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hostile_bin = root / "hostile-bin"
            hostile_bin.mkdir()
            marker = root / "hostile-git-ran"
            fake_git = hostile_bin / "git"
            fake_git.write_text(
                f"#!/usr/bin/env bash\n: > {marker}\nprintf '%s\\n' {'0' * 40}\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            evidence = root / "evidence.json"
            output = root / "report.json"
            target = root / "target-state.json"
            classroom50 = root / "classroom50.json"
            self.write_target_report(target)
            self.write_classroom_report(classroom50)
            decoy = root / "hostile-repository"
            self.assertNotEqual(self.write_decoy_repository(decoy), self.commit)
            environment = {
                **os.environ,
                "PATH": f"{hostile_bin}:/usr/bin:/bin",
                "GIT_DIR": str(decoy / ".git"),
                "GIT_WORK_TREE": str(decoy),
                "GIT_CONFIG_GLOBAL": str(root / "hostile-gitconfig"),
            }

            produced = subprocess.run(
                self.evidence_command(
                    evidence,
                    target=target,
                    classroom50=classroom50,
                ),
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(produced.returncode, 0, produced.stderr)
            reported = subprocess.run(
                self.report_command(evidence, output, target, classroom50),
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(reported.returncode, 0, reported.stderr)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["repositoryCommit"],
                self.commit,
            )
            self.assertFalse(marker.exists())

    def test_full_evidence_rejects_authenticated_commit_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence.json"
            target = root / "target-state.json"
            classroom50 = root / "classroom50.json"
            self.write_target_report(target, "PASS")
            self.write_classroom_report(classroom50, "PASS")
            command = self.evidence_command(
                evidence,
                profile="full",
                target=target,
                classroom50=classroom50,
            )
            command[command.index("--expected-commit") + 1] = "0" * 40

            rejected = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(evidence.exists())


if __name__ == "__main__":
    unittest.main()
