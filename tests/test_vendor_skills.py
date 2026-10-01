#!/usr/bin/env python3
"""Pinned third-party skills are reinstalled only where missing, never over local edits."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/install-vendor-skills.py"
LOCK = ROOT / "system/software/vendor-skills.lock.json"


def git(directory: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(directory), *arguments],
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


class VendorSkillTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, Path]:
        source = root / "source"
        (source / "skills/alpha").mkdir(parents=True)
        (source / "skills/beta/scripts").mkdir(parents=True)
        (source / "skills/alpha/SKILL.md").write_text("# alpha\n", encoding="utf-8")
        tool = source / "skills/beta/scripts/run.sh"
        tool.write_text("#!/bin/sh\necho beta\n", encoding="utf-8")
        tool.chmod(0o755)
        (source / "skills/beta/SKILL.md").write_text("# beta\n", encoding="utf-8")
        (source / "skills/unlisted").mkdir()
        (source / "skills/unlisted/SKILL.md").write_text("# not pinned\n", encoding="utf-8")
        git(source, "init", "-q")
        git(source, "add", "-A")
        git(source, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
            "commit", "-q", "-m", "fixture")
        lock = root / "lock.json"
        lock.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "sources": [
                        {
                            "id": "fixture-skills",
                            "repository": "https://example.invalid/skills.git",
                            "commit": git(source, "rev-parse", "HEAD"),
                            "license": "Apache-2.0",
                            "source_dir": "skills",
                            "skills": ["alpha", "beta"],
                            "targets": [".agent-a/skills", ".agent-b/skills", ".agent-c/skills"],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        home = root / "home"
        (home / ".agent-a").mkdir(parents=True)
        (home / ".agent-b/skills/alpha").mkdir(parents=True)
        (home / ".agent-b/skills/alpha/SKILL.md").write_text("# alpha\n", encoding="utf-8")
        (home / ".agent-b/skills/beta").mkdir()
        (home / ".agent-b/skills/beta/SKILL.md").write_text("# beta, edited by the owner\n", encoding="utf-8")
        return source, lock, home

    def run_script(self, lock: Path, home: Path, source: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SCRIPT), "--lock", str(lock), "--home", str(home),
             "--source-checkout", str(source), *extra],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_missing_skills_are_installed_and_local_edits_are_kept(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source, lock, home = self.fixture(Path(temporary))
            check = self.run_script(lock, home, source, "--check")
            self.assertEqual(check.returncode, 1, check.stderr)

            completed = self.run_script(lock, home, source)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)["fixture-skills"]
            self.assertEqual(report[".agent-a/skills"], {"alpha": "installed", "beta": "installed"})
            self.assertEqual(report[".agent-b/skills"], {"alpha": "current", "beta": "modified"})
            self.assertEqual(report[".agent-c/skills"], "agent-absent")

            installed = home / ".agent-a/skills"
            self.assertEqual((installed / "alpha/SKILL.md").read_text(encoding="utf-8"), "# alpha\n")
            self.assertTrue(os.access(installed / "beta/scripts/run.sh", os.X_OK))
            self.assertFalse((installed / "unlisted").exists())
            self.assertEqual(
                (home / ".agent-b/skills/beta/SKILL.md").read_text(encoding="utf-8"),
                "# beta, edited by the owner\n",
            )
            self.assertFalse((home / ".agent-c").exists())

            # the owner's edit still differs from the pin, so the check reports it
            self.assertEqual(self.run_script(lock, home, source, "--check").returncode, 1)
            (home / ".agent-b/skills/beta/SKILL.md").write_text("# beta\n", encoding="utf-8")
            (home / ".agent-b/skills/beta/scripts").mkdir()
            (home / ".agent-b/skills/beta/scripts/run.sh").write_text("#!/bin/sh\necho beta\n", encoding="utf-8")
            (home / ".agent-b/skills/beta/scripts/run.sh").chmod(0o755)
            self.assertEqual(self.run_script(lock, home, source, "--check").returncode, 0)

    def test_source_that_is_not_the_pinned_commit_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source, lock, home = self.fixture(Path(temporary))
            (source / "skills/alpha/SKILL.md").write_text("# changed upstream\n", encoding="utf-8")
            git(source, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                "commit", "-q", "-am", "moved on")
            completed = self.run_script(lock, home, source)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("pinned commit", completed.stderr)
            self.assertFalse((home / ".agent-a/skills").exists())

    def test_symlinked_skill_destination_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source, lock, home = self.fixture(Path(temporary))
            elsewhere = Path(temporary) / "elsewhere"
            elsewhere.mkdir()
            (home / ".agent-a/skills").mkdir()
            (home / ".agent-a/skills/alpha").symlink_to(elsewhere)
            completed = self.run_script(lock, home, source)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("unsafe", completed.stderr)
            self.assertEqual(list(elsewhere.iterdir()), [])

    def test_checked_in_lock_pins_one_full_commit_per_source(self) -> None:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        self.assertEqual(lock["schema_version"], 1)
        for source in lock["sources"]:
            self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["repository"].startswith("https://github.com/"))
            self.assertTrue(source["license"])
            self.assertTrue(source["skills"])
            for target in source["targets"]:
                self.assertFalse(target.startswith("/") or ".." in target.split("/"))


if __name__ == "__main__":
    unittest.main()
