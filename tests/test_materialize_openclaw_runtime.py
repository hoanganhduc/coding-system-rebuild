#!/usr/bin/env python3
"""Tests for derived OpenClaw runtime configuration materialization."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "bin/materialize-openclaw-runtime.sh"


class MaterializeOpenClawRuntimeTests(unittest.TestCase):
    def run_helper(self, home: Path) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["HOME"] = str(home)
        return subprocess.run(
            ["bash", str(HELPER)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
        )

    def test_materializes_research_compute_config_with_private_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            source = (
                home
                / ".local/share/ai-agents-skills/runtime/workspace/config/research-compute.toml"
            )
            source.parent.mkdir(parents=True)
            source.write_text(
                'install_id = "fixture"\n'
                'broker_state_root = "../../memories/research-compute"\n'
                'default_materialize_root = ".research-compute"\n',
                encoding="utf-8",
            )

            result = self.run_helper(home)

            self.assertEqual(result.returncode, 0, result.stdout)
            destination = home / ".openclaw/workspace/config/research-compute.toml"
            materialized = destination.read_text(encoding="utf-8")
            self.assertIn('install_id = "fixture"', materialized)
            self.assertIn(
                'broker_state_root = "data/research/research-compute"',
                materialized,
            )
            self.assertIn(
                'default_materialize_root = ".research-compute"', materialized
            )
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_missing_optional_source_is_reported_without_creating_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)

            result = self.run_helper(home)

            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("optional source absent", result.stdout)
            self.assertFalse(
                (home / ".openclaw/workspace/config/research-compute.toml").exists()
            )

    def test_missing_state_root_is_inserted_before_the_first_table(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            source = (
                home
                / ".local/share/ai-agents-skills/runtime/workspace/config/research-compute.toml"
            )
            source.parent.mkdir(parents=True)
            source.write_text(
                'install_id = "fixture"\n\n'
                '[gha]\n'
                'enabled = false\n',
                encoding="utf-8",
            )

            result = self.run_helper(home)

            self.assertEqual(result.returncode, 0, result.stdout)
            destination = home / ".openclaw/workspace/config/research-compute.toml"
            materialized = destination.read_text(encoding="utf-8")
            state_root = 'broker_state_root = "data/research/research-compute"'
            self.assertLess(materialized.index(state_root), materialized.index("[gha]"))
            self.assertEqual(materialized.count(state_root), 1)

    def test_materializes_getscipapers_credentials_for_the_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            credential = home / ".config/getscipapers/crossref/credentials.json"
            credential.parent.mkdir(parents=True)
            credential.write_text('{"fixture": true}\n', encoding="utf-8")

            result = self.run_helper(home)

            self.assertEqual(result.returncode, 0, result.stdout)
            destination = (
                home
                / ".openclaw/workspace/secrets/getscipapers/crossref/credentials.json"
            )
            self.assertEqual(
                destination.read_text(encoding="utf-8"), '{"fixture": true}\n'
            )
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertNotIn('{"fixture": true}', result.stdout)

    def test_materializes_modal_credentials_at_sandbox_home_with_private_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            source = home / ".modal.toml"
            source.write_text(
                '[default]\ntoken_id = "fixture-id"\ntoken_secret = "fixture-secret"\n',
                encoding="utf-8",
            )
            source.chmod(0o600)

            first = self.run_helper(home)
            second = self.run_helper(home)

            self.assertEqual(first.returncode, 0, first.stdout)
            self.assertEqual(second.returncode, 0, second.stdout)
            destination = home / ".openclaw/workspace/.modal.toml"
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertIn("current", second.stdout)
            self.assertNotIn("fixture-secret", first.stdout + second.stdout)

    def test_workspace_local_freeze_covers_registered_document_skills(self) -> None:
        requirements = (
            ROOT / "system/packages/requirements/workspace-local.txt"
        ).read_text(encoding="utf-8")
        self.assertIn("PyMuPDF==1.27.2.2", requirements)
        self.assertIn("pylatexenc==2.10", requirements)
        self.assertIn("modal==1.5.3", requirements)

    def test_getscipapers_install_is_pinned_and_not_failure_suppressed(self) -> None:
        requirements = (
            ROOT / "system/packages/requirements/getscipapers.txt"
        ).read_text(encoding="utf-8")
        pinned_commit = "59a3da24bfbf7c5a5c59" + "d19b0a6d4beeea22daef"
        self.assertIn(
            "git+https://github.com/hoanganhduc/getscipapers.git@" + pinned_commit,
            requirements,
        )
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        self.assertIn('GSP_VENV="$HOME/.openclaw/workspace/.local/venv_getscipapers"', install)
        self.assertIn('"$GSP_VENV/bin/pip" install -q -r "$RQ/getscipapers.txt"', install)
        self.assertNotIn(
            '"$GSP_VENV/bin/pip" install -q -r "$RQ/getscipapers.txt" || true',
            install,
        )
        wrapper = (ROOT / "system/bin/getscipapers").read_text(encoding="utf-8")
        self.assertIn("venv_getscipapers", wrapper)
        self.assertIn('PYTHON="$VENV/bin/python"', wrapper)
        self.assertIn('ENTRYPOINT="$VENV/bin/getscipapers"', wrapper)


if __name__ == "__main__":
    unittest.main()
