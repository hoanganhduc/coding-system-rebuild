#!/usr/bin/env python3
"""Tests for immutable out-of-repository component resolution."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "bin/lib/component_paths.py"
SPEC = importlib.util.spec_from_file_location("csr_component_paths", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ImmutableComponentPathTests(unittest.TestCase):
    def git_fixture(self, path: Path) -> str:
        path.mkdir(parents=True)
        (path / "payload.txt").write_text("synthetic component\n", encoding="utf-8")
        subprocess.run(["/usr/bin/git", "init", "-q"], cwd=path, check=True)
        subprocess.run(["/usr/bin/git", "add", "."], cwd=path, check=True)
        subprocess.run(
            [
                "/usr/bin/git",
                "-c",
                "user.name=Component Test",
                "-c",
                "user.email=component@example.invalid",
                "commit",
                "-qm",
                "synthetic component",
            ],
            cwd=path,
            check=True,
        )
        return subprocess.run(
            ["/usr/bin/git", "rev-parse", "HEAD"],
            cwd=path,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    def test_installed_path_is_content_addressed_and_same_set_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            home = root / "home"
            repository.mkdir()
            home.mkdir()
            scratch = root / "scratch"
            commit = self.git_fixture(scratch)
            (repository / "components.lock").write_text(
                f"openclaw-bot=https://example.invalid/openclaw.git@{commit}\n",
                encoding="utf-8",
            )
            installed = (
                home
                / ".local/share/coding-system/components/openclaw-bot"
                / commit
            )
            installed.parent.mkdir(parents=True)
            subprocess.run(
                ["/usr/bin/git", "clone", "-q", str(scratch), str(installed)],
                check=True,
            )
            first = MODULE.resolve_component_path(
                repository, home, "openclaw-bot", require=True
            )
            second = MODULE.resolve_component_path(
                repository, home, "openclaw-bot", require=True
            )
            self.assertEqual(first, installed)
            self.assertEqual(second, installed)
            self.assertNotIn(repository, installed.parents)

    def test_source_fallback_is_explicit_and_must_match_exact_pin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            home = root / "home"
            source = repository / "external/openclaw-bot"
            home.mkdir(parents=True)
            commit = self.git_fixture(source)
            (repository / "components.lock").write_text(
                f"openclaw-bot=https://example.invalid/openclaw.git@{commit}\n",
                encoding="utf-8",
            )
            with self.assertRaises(MODULE.ComponentPathError):
                MODULE.resolve_component_path(
                    repository, home, "openclaw-bot", require=True
                )
            self.assertEqual(
                MODULE.resolve_component_path(
                    repository,
                    home,
                    "openclaw-bot",
                    source_fallback=True,
                    require=True,
                ),
                source,
            )
            (source / "next.txt").write_text("next\n", encoding="utf-8")
            subprocess.run(["/usr/bin/git", "add", "."], cwd=source, check=True)
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-c",
                    "user.name=Component Test",
                    "-c",
                    "user.email=component@example.invalid",
                    "commit",
                    "-qm",
                    "next",
                ],
                cwd=source,
                check=True,
            )
            with self.assertRaisesRegex(MODULE.ComponentPathError, "exact lock"):
                MODULE.resolve_component_path(
                    repository,
                    home,
                    "openclaw-bot",
                    source_fallback=True,
                    require=True,
                )

    def test_component_materializer_never_targets_repository_external(self) -> None:
        source = (ROOT / "bin/components.sh").read_text(encoding="utf-8")
        self.assertIn(".local/share/coding-system/components", source)
        self.assertNotIn('dest="$REPO/external/$name"', source)
        self.assertIn("verify-exact-checkout.py", source)
        self.assertIn("--no-clobber", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
