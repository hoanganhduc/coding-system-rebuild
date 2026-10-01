#!/usr/bin/env python3
"""Regression tests for exact, producer-ledger-only backup commits."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "bin/lib/stage_backup.py"


class ExactBackupStagingTests(unittest.TestCase):
    def git(self, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def fixture(self, base: Path) -> Path:
        repo = base / "repo"
        (repo / "system/grok-proxy/.planning").mkdir(parents=True)
        (repo / "system/packages").mkdir(parents=True)
        (repo / ".staging").mkdir()
        self.assertEqual(self.git(repo, "init", "-q").returncode, 0)
        self.git(repo, "config", "user.name", "Backup Test")
        self.git(repo, "config", "user.email", "backup@example.invalid")
        (repo / "MANIFEST.yaml").write_text(
            """schema: coding-system.manifest.v1
entries:
  - id: grokproxy-scripts
    root: grok-proxy
    match: [new.txt]
    class: public-copy
    dest_dir: system/grok-proxy
    authoritative: true
    preserve_dest: [.planning, .learnings]
""",
            encoding="utf-8",
        )
        (repo / "system/grok-proxy/old.txt").write_text("old\n", encoding="utf-8")
        (repo / "system/grok-proxy/.planning/plan.md").write_text(
            "tracked plan\n", encoding="utf-8"
        )
        (repo / "system/packages/generated.txt").write_text(
            "old generated\n", encoding="utf-8"
        )
        (repo / "unrelated.txt").write_text("unchanged\n", encoding="utf-8")
        (repo / "pre-staged.txt").write_text("base\n", encoding="utf-8")
        self.assertEqual(self.git(repo, "add", "-A").returncode, 0)
        self.assertEqual(self.git(repo, "commit", "-qm", "base").returncode, 0)

        (repo / "system/grok-proxy/old.txt").unlink()
        (repo / "system/grok-proxy/new.txt").write_text("new\n", encoding="utf-8")
        (repo / "system/grok-proxy/new.txt").chmod(0o644)
        (repo / "system/grok-proxy/.planning/plan.md").write_text(
            "private planning edit\n", encoding="utf-8"
        )
        (repo / "system/packages/generated.txt").write_text(
            "fresh generated\n", encoding="utf-8"
        )
        (repo / "system/packages/generated.txt").chmod(0o644)
        (repo / "unrelated.txt").write_text("unrelated work\n", encoding="utf-8")
        (repo / "untracked-note.txt").write_text("unrelated note\n", encoding="utf-8")
        (repo / "pre-staged.txt").write_text("user staged work\n", encoding="utf-8")
        self.assertEqual(self.git(repo, "add", "pre-staged.txt").returncode, 0)

        manifest_raw = (repo / "MANIFEST.yaml").read_bytes()
        captured = (repo / "system/grok-proxy/new.txt").read_bytes()
        report = {
            "errors": [],
            "applied": True,
            "outputs": 1,
            "output_paths": ["system/grok-proxy/new.txt"],
            "output_records": {
                "system/grok-proxy/new.txt": {
                    "sha256": hashlib.sha256(captured).hexdigest(),
                    "size": len(captured),
                    "mode": 0o644,
                }
            },
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        }
        (repo / ".staging/sync-report.json").write_text(
            json.dumps(report), encoding="utf-8"
        )
        refresh_ledger = b"system/packages/generated.txt\0"
        (repo / ".staging/refresh-output-paths.nul").write_bytes(refresh_ledger)
        refreshed = (repo / "system/packages/generated.txt").read_bytes()
        (repo / ".staging/refresh-output-records.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "ledger_sha256": hashlib.sha256(refresh_ledger).hexdigest(),
                    "records": {
                        "system/packages/generated.txt": {
                            "sha256": hashlib.sha256(refreshed).hexdigest(),
                            "size": len(refreshed),
                            "mode": 0o644,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        return repo

    def test_commit_contains_only_generated_paths_and_preserves_user_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self.fixture(Path(td))
            result = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "--repo",
                    str(repo),
                    "--commit-message",
                    "backup fixture",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            committed = set(
                self.git(repo, "show", "--pretty=", "--name-only", "HEAD").stdout.splitlines()
            )
            self.assertEqual(
                committed,
                {
                    "system/grok-proxy/new.txt",
                    "system/grok-proxy/old.txt",
                    "system/packages/generated.txt",
                },
            )
            self.assertEqual(
                self.git(repo, "diff", "--cached", "--name-only").stdout.splitlines(),
                ["pre-staged.txt"],
            )
            unstaged = set(self.git(repo, "status", "--short").stdout.splitlines())
            self.assertIn(" M system/grok-proxy/.planning/plan.md", unstaged)
            self.assertIn(" M unrelated.txt", unstaged)
            self.assertIn("?? untracked-note.txt", unstaged)

    def test_pre_staged_generated_path_fails_without_committing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self.fixture(Path(td))
            self.assertEqual(
                self.git(repo, "add", "system/packages/generated.txt").returncode, 0
            )
            before = self.git(repo, "rev-parse", "HEAD").stdout.strip()
            result = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "--repo",
                    str(repo),
                    "--commit-message",
                    "must not commit",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("already have staged changes", result.stderr)
            self.assertEqual(self.git(repo, "rev-parse", "HEAD").stdout.strip(), before)

    def test_output_mutation_after_producer_record_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self.fixture(Path(td))
            before = self.git(repo, "rev-parse", "HEAD").stdout.strip()
            (repo / "system/grok-proxy/new.txt").write_text(
                "changed after capture\n", encoding="utf-8"
            )
            result = subprocess.run(
                [sys.executable, str(HELPER), "--repo", str(repo)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("changed before staging", result.stderr)
            self.assertEqual(self.git(repo, "rev-parse", "HEAD").stdout.strip(), before)

    def test_reappearing_authoritative_stale_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self.fixture(Path(td))
            (repo / "system/grok-proxy/old.txt").write_text(
                "reappeared\n", encoding="utf-8"
            )
            result = subprocess.run(
                [sys.executable, str(HELPER), "--repo", str(repo)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("stale path reappeared", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
