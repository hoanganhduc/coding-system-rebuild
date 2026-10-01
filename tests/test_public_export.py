#!/usr/bin/env python3
"""Tests for the history-free public export boundary."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "bin/lib/public_export.py"
SPEC = importlib.util.spec_from_file_location("public_export", HELPER)
assert SPEC is not None and SPEC.loader is not None
public_export = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = public_export
SPEC.loader.exec_module(public_export)


class PublicExportTests(unittest.TestCase):
    def git(self, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def fixture(self, base: Path) -> Path:
        repo = base / "repo"
        repo.mkdir()
        (repo / "bin/lib").mkdir(parents=True)
        (repo / "docs").mkdir()
        (repo / "tests").mkdir()
        (repo / "agents/claude/skills/demo").mkdir(parents=True)
        (repo / "agents/claude").mkdir(exist_ok=True)
        (repo / "agents/copilot").mkdir(parents=True, exist_ok=True)
        (repo / "agents/codex").mkdir(parents=True, exist_ok=True)
        (repo / "system/packages/observed").mkdir(parents=True)
        (repo / ".learnings").mkdir()
        (repo / ".planning").mkdir()
        (repo / ".staging").mkdir()
        (repo / "external/component").mkdir(parents=True)
        (repo / "secrets").mkdir()

        (repo / "README.md").write_text("# Public fixture\n", encoding="utf-8")
        (repo / "Makefile").write_text("help:\n\t@echo ok\n", encoding="utf-8")
        (repo / "docs/PUBLIC-EXPORT.md").write_text("public docs\n", encoding="utf-8")
        (repo / "bin/public-export.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (repo / "bin/lib/public_export.py").write_text("VALUE = 1\n", encoding="utf-8")
        (repo / "tests/test_public_export.py").write_text("def test_ok(): pass\n", encoding="utf-8")
        (repo / "agents/claude/skills/demo/SKILL.md").write_text(
            "public skill\n", encoding="utf-8"
        )
        (repo / "public-export-exceptions.yaml").write_text(
            "exceptions: []\n", encoding="utf-8"
        )
        (repo / "bin/leak-scan.sh").write_text(
            "#!/usr/bin/env bash\nexit 0\n", encoding="utf-8"
        )
        (repo / "bin/leak-scan.sh").chmod(0o755)

        private_paths = {
            ".learnings/ERRORS.md": "incident ledger\n",
            ".planning/PLAN.md": "private plan\n",
            ".staging/tmp.txt": "staged\n",
            ".staging-symlinks-observed.tsv": "local path\n",
            "agents/claude/settings.local.json": "{}\n",
            "agents/copilot/config.json": "{}\n",
            "agents/codex/auth.json.keys": "tokens\n",
            "system/packages/observed/closure-drift.json": "{}\n",
            "external/component/file.txt": "vendored\n",
            "secrets/secrets-manifest.yaml": "entries: []\n",
        }
        for rel, content in private_paths.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(content, encoding="utf-8")

        self.assertEqual(self.git(repo, "init", "-q").returncode, 0)
        self.git(repo, "config", "user.name", "Public Export Test")
        self.git(repo, "config", "user.email", "public-export@example.invalid")
        self.assertEqual(self.git(repo, "add", "-A").returncode, 0)
        self.assertEqual(self.git(repo, "commit", "-qm", "base").returncode, 0)
        return repo

    def test_export_filters_private_paths_and_has_no_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.fixture(Path(temporary))
            output = Path(temporary) / "export"
            result = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "export",
                    "--repo",
                    str(repo),
                    "--output",
                    str(output),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((output / "README.md").exists())
            self.assertFalse((output / ".git").exists())
            for rel in (
                ".learnings/ERRORS.md",
                ".planning/PLAN.md",
                ".staging-symlinks-observed.tsv",
                "agents/claude/skills/demo/SKILL.md",
                "agents/claude/settings.local.json",
                "agents/copilot/config.json",
                "agents/codex/auth.json.keys",
                "system/packages/observed/closure-drift.json",
                "external/component/file.txt",
                "secrets/secrets-manifest.yaml",
            ):
                self.assertFalse((output / rel).exists(), rel)

    def test_head_export_refuses_dirty_tree_and_unsafe_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.fixture(Path(temporary))
            (repo / "README.md").write_text("dirty\n", encoding="utf-8")
            output = Path(temporary) / "export"
            result = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "export",
                    "--repo",
                    str(repo),
                    "--output",
                    str(output),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("clean source tree", result.stderr)

            commit = self.git(repo, "rev-parse", "HEAD").stdout.strip()
            unsafe = repo / "public-export"
            result = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "export",
                    "--repo",
                    str(repo),
                    "--output",
                    str(unsafe),
                    "--ref",
                    commit,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("inside the source repository", result.stderr)

    def test_verify_catches_privacy_canaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.fixture(Path(temporary))
            target = Path(temporary) / "target"
            target.mkdir()
            (target / "README.md").write_text(
                "mail owner@real-domain.test\n"
                "uuid 123e4567-e89b-12d3-a456-426614174000\n"
                "chat_id = \"123456789\"\n"
                "path " + "/home/" + "fixture-user/private\n",
                encoding="utf-8",
            )
            findings = public_export.verify_export(
                repo,
                target,
                repo / "public-export-exceptions.yaml",
                leak_scan=False,
            )
            classes = {finding.klass for finding in findings}
            self.assertIn("email", classes)
            self.assertIn("uuid", classes)
            self.assertIn("long_numeric_id", classes)
            self.assertIn("home_path", classes)
            self.assertIn("id_field", classes)

    def test_documented_exception_allows_fake_public_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.fixture(Path(temporary))
            target = Path(temporary) / "target"
            target.mkdir()
            (target / "README.md").write_text(
                "uuid 123e4567-e89b-12d3-a456-426614174000\n",
                encoding="utf-8",
            )
            exceptions = Path(temporary) / "exceptions.yaml"
            exceptions.write_text(
                "exceptions:\n"
                "  - path: README.md\n"
                "    class: uuid\n"
                "    line: 1\n"
                "    reason: synthetic documented fixture\n"
                "    proof: RFC 4122 sample UUID\n",
                encoding="utf-8",
            )
            findings = public_export.verify_export(repo, target, exceptions, leak_scan=False)
            self.assertEqual(findings, [])

    def test_unused_exception_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.fixture(Path(temporary))
            target = Path(temporary) / "target"
            target.mkdir()
            (target / "README.md").write_text("clean\n", encoding="utf-8")
            exceptions = Path(temporary) / "exceptions.yaml"
            exceptions.write_text(
                "exceptions:\n"
                "  - path: README.md\n"
                "    class: uuid\n"
                "    line: 1\n"
                "    reason: stale exception\n"
                "    proof: no longer needed\n",
                encoding="utf-8",
            )
            findings = public_export.verify_export(repo, target, exceptions, leak_scan=False)
            self.assertEqual({finding.klass for finding in findings}, {"uuid"})
            self.assertIn("unused", findings[0].message)

    def test_exception_matches_exact_line_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.fixture(Path(temporary))
            target = Path(temporary) / "target"
            target.mkdir()
            (target / "README.md").write_text(
                "uuid 123e4567-e89b-12d3-a456-426614174000\n"
                "uuid 223e4567-e89b-12d3-a456-426614174000\n",
                encoding="utf-8",
            )
            exceptions = Path(temporary) / "exceptions.yaml"
            exceptions.write_text(
                "exceptions:\n"
                "  - path: README.md\n"
                "    class: uuid\n"
                "    line: 1\n"
                "    reason: synthetic documented fixture\n"
                "    proof: RFC 4122 sample UUID\n",
                encoding="utf-8",
            )
            findings = public_export.verify_export(repo, target, exceptions, leak_scan=False)
            self.assertEqual([(finding.klass, finding.line) for finding in findings], [("uuid", 2)])

    def test_failed_export_leaves_final_output_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.fixture(Path(temporary))
            (repo / "README.md").write_text("private path " + "/home/" + "fixture-user\n", encoding="utf-8")
            self.assertEqual(self.git(repo, "add", "README.md").returncode, 0)
            self.assertEqual(self.git(repo, "commit", "-qm", "leaky").returncode, 0)
            output = Path(temporary) / "export"
            result = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "export",
                    "--repo",
                    str(repo),
                    "--output",
                    str(output),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertTrue(not output.exists() or not any(output.iterdir()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
