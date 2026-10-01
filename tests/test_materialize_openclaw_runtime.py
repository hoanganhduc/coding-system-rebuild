#!/usr/bin/env python3
"""Tests for derived OpenClaw runtime configuration materialization."""

from __future__ import annotations

import json
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
            ["bash", str(HELPER), "--allow-missing-classroom50"],
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
            source.chmod(0o644)

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
            self.assertIn("secret projections: converged", result.stdout)
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
            source.chmod(0o644)

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
            credential = home / ".config/getscipapers/ablesci/credentials.json"
            credential.parent.mkdir(parents=True)
            credential.write_text('{"fixture": true}\n', encoding="utf-8")
            credential.chmod(0o600)

            result = self.run_helper(home)

            self.assertEqual(result.returncode, 0, result.stdout)
            destination = (
                home
                / ".openclaw/workspace/.config/getscipapers/ablesci/credentials.json"
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
            self.assertIn("secret projections: converged", second.stdout)
            self.assertNotIn("fixture-secret", first.stdout + second.stdout)

    def test_zotero_compose_materialization_preserves_aas_managed_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            lock = json.loads(
                (ROOT / "system/software/images.lock.json").read_text(encoding="utf-8")
            )
            platform_name = (
                "linux/arm64"
                if os.uname().machine in {"aarch64", "arm64"}
                else "linux/amd64"
            )
            reference = next(
                image["reference"]
                for image in lock["images"]
                if "zotero-translation-server" in image["roles"]
                and platform_name in image["platforms"]
            )
            managed_roots = (
                home / ".codex/runtime/workspace/skills/zotero",
                home / ".local/share/ai-agents-skills/runtime/workspace/skills/zotero",
            )
            sentinels: dict[Path, bytes] = {}
            for index, skill_root in enumerate(managed_roots):
                helper = skill_root / "scripts/start-translation-server.sh"
                helper.parent.mkdir(parents=True)
                payload = f"#!/bin/sh\n# managed-{index}\n# {reference}\n".encode()
                helper.write_bytes(payload)
                helper.chmod(0o755)
                sentinels[helper] = payload

            openclaw_root = home / ".openclaw/workspace/skills/zotero"
            openclaw_root.mkdir(parents=True)
            claude_root = home / ".claude/skills/zotero"
            claude_helper = claude_root / "scripts/start-translation-server.sh"
            claude_helper.parent.mkdir(parents=True)
            claude_helper.write_text("claude-owned\n", encoding="utf-8")

            result = self.run_helper(home)

            self.assertEqual(result.returncode, 0, result.stdout)
            for helper, payload in sentinels.items():
                self.assertEqual(helper.read_bytes(), payload)
                compose = helper.parent.parent / "docker-compose.yml"
                self.assertIn(
                    "${ZOTERO_TS_IMAGE:?ZOTERO_TS_IMAGE must be set}",
                    compose.read_text(encoding="utf-8"),
                )
            self.assertEqual(
                (openclaw_root / "scripts/start-translation-server.sh").read_bytes(),
                (ROOT / "agents/claude/skills/zotero/scripts/start-translation-server.sh").read_bytes(),
            )
            self.assertEqual(claude_helper.read_text(encoding="utf-8"), "claude-owned\n")
            self.assertFalse((claude_root / "docker-compose.yml").exists())

    def test_workspace_local_freeze_covers_registered_document_skills(self) -> None:
        requirements = (
            ROOT / "system/packages/requirements/workspace-local.txt"
        ).read_text(encoding="utf-8")
        self.assertIn("PyMuPDF==1.27.2.2", requirements)
        self.assertIn("pylatexenc==2.10", requirements)
        self.assertIn("modal==1.5.3", requirements)

    def test_getscipapers_is_installed_from_the_offline_python_closure(self) -> None:
        requirements = (
            ROOT / "system/packages/requirements/getscipapers.txt"
        ).read_text(encoding="utf-8")
        pinned_commit = "8a4f60e712cf1f20859e" + "784c10ec68c37e899880"
        self.assertIn(
            "git+https://github.com/hoanganhduc/getscipapers.git@" + pinned_commit,
            requirements,
        )
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        self.assertIn('"$REPO/bin/install-python-closure.py" install-all', install)
        self.assertNotIn("venv_getscipapers", install)
        self.assertNotRegex(install, r"pip\s+install")
        wrapper = (ROOT / "system/bin/getscipapers").read_text(encoding="utf-8")
        self.assertIn("python-closure/getscipapers", wrapper)
        self.assertIn('PYTHON="$VENV/bin/python"', wrapper)
        self.assertIn('ENTRYPOINT="$VENV/bin/getscipapers"', wrapper)

    def test_prepare_defers_aider_and_modal_to_the_offline_closure(self) -> None:
        prepare = (ROOT / "bin/prepare.sh").read_text(encoding="utf-8")
        self.assertNotRegex(prepare, r"pipx\s+install")
        self.assertNotRegex(prepare, r"python3\s+-m\s+pip\s+install")
        self.assertIn("Aider is installed offline", prepare)
        self.assertIn("Modal is installed offline", prepare)


if __name__ == "__main__":
    unittest.main()
