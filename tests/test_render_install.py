#!/usr/bin/env python3
"""Regression tests for byte-exact public artifact rendering."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "bin/lib/render_install.py"
SPEC = importlib.util.spec_from_file_location("render_install_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RENDER_INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER_INSTALL)


class RenderInstallTests(unittest.TestCase):
    def test_skip_grok_release_renders_without_the_root_grok_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir()
            commands: list[list[str]] = []

            def fake_run(command, **_kwargs):
                commands.append(list(command))
                return subprocess.CompletedProcess(command, 0)

            argv = ["render_install.py", "--repo", str(ROOT), "--home", str(home), "--skip-grok-release"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(RENDER_INSTALL.subprocess, "run", side_effect=fake_run),
                mock.patch.object(
                    RENDER_INSTALL,
                    "install_grok_proxy_release",
                    side_effect=AssertionError("the root Grok release must not be installed"),
                ),
            ):
                self.assertEqual(RENDER_INSTALL.main(), 0)
            self.assertTrue((home / "grok-proxy").is_dir())
            self.assertTrue(all(command[:2] == ["/usr/bin/sudo", "-n"] for command in commands))

    def test_identical_crlf_text_is_not_a_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bat"
            destination = root / "home" / "target.bat"
            source.write_bytes(b"@echo off\r\nexit /b 0\r\n")
            destination.parent.mkdir()
            destination.write_bytes(source.read_bytes())
            report = {
                "installed": 0,
                "skipped_existing": [],
                "placeholders": [],
                "conflicts": [],
            }

            RENDER_INSTALL.install_file(
                str(source), str(destination), str(root / "home"), report
            )

            self.assertEqual(report["installed"], 1)
            self.assertEqual(report["conflicts"], [])
            self.assertFalse(Path(f"{destination}.new").exists())

    def test_byte_identical_claude_local_runtime_is_retired(self) -> None:
        source = ROOT / "agents/claude/skills/zotero/run_zot.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            target = home / ".claude/skills/zotero/run_zot.sh"
            target.parent.mkdir(parents=True)
            target.write_bytes(source.read_bytes())
            target.chmod(0o755)

            retired = RENDER_INSTALL.retire_stale_claude_runtime(
                str(ROOT), str(home)
            )

            self.assertEqual(retired, 1)
            self.assertFalse(target.exists())

    def test_divergent_claude_runtime_blocks_all_retirement(self) -> None:
        exact_source = ROOT / "agents/claude/skills/calibre/run_cal.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            exact = home / ".claude/skills/calibre/run_cal.sh"
            exact.parent.mkdir(parents=True)
            exact.write_bytes(exact_source.read_bytes())
            exact.chmod(0o755)
            divergent = home / ".claude/skills/zotero/run_zot.sh"
            divergent.parent.mkdir(parents=True)
            divergent.write_text("#!/bin/sh\nexit 73\n", encoding="utf-8")
            divergent.chmod(0o755)

            with self.assertRaises(
                RENDER_INSTALL.ClaudeRuntimeRetirementError
            ):
                RENDER_INSTALL.retire_stale_claude_runtime(str(ROOT), str(home))

            self.assertTrue(exact.exists())
            self.assertTrue(divergent.exists())

    def test_rendered_home_contains_only_claude_shared_runtime_shim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            completed = subprocess.run(
                [
                    "python3",
                    str(MODULE_PATH),
                    "--repo",
                    str(ROOT),
                    "--home",
                    str(home),
                    "--render-only",
                ],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((home / ".claude/skills/_run.sh").is_file())
            for relative in (
                ".claude/skills/zotero/run_zot.sh",
                ".claude/skills/zotero/send_telegram.sh",
                ".claude/skills/calibre/run_cal.sh",
                ".claude/skills/vnthuquan/run_vnthuquan.sh",
            ):
                self.assertFalse((home / relative).exists(), relative)
            self.assertTrue((home / ".claude/skills/zotero/config.json").is_file())
            self.assertTrue((home / ".claude/skills/calibre/config.json").is_file())

    def test_credential_templates_render_with_their_declared_mode(self) -> None:
        # The recovery manifest declares 0600 for these configs (an api_key goes
        # inside); a render without secrets must not leave them wider.
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            completed = subprocess.run(
                ["python3", str(MODULE_PATH), "--repo", str(ROOT), "--home", str(home),
                 "--render-only"],
                check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            for relative in (".codewhale/config.toml", ".deepseek/config.toml"):
                self.assertEqual((home / relative).stat().st_mode & 0o777, 0o600, relative)
            # A template declared 0644 keeps that mode.
            zotero = home / ".claude/skills/zotero/config.json"
            self.assertNotEqual(zotero.stat().st_mode & 0o777, 0o600)

    def test_render_sanitizes_shell_rollbacks_without_duplicating_npm_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".bashrc").write_text(
                "export KIMI_API_KEY=render-canary\n# keep bashrc\n",
                encoding="utf-8",
            )
            (home / ".profile").write_text("# keep profile\n", encoding="utf-8")
            npmrc = home / ".npmrc"
            npmrc.write_text(
                "//registry.example/:_authToken=npm-render-canary\n",
                encoding="utf-8",
            )
            npmrc.chmod(0o600)

            completed = subprocess.run(
                [
                    "python3",
                    str(MODULE_PATH),
                    "--repo",
                    str(ROOT),
                    "--home",
                    str(home),
                    "--render-only",
                ],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            bash_backup = home / ".bashrc.pre-coding-system"
            profile_backup = home / ".profile.pre-coding-system"
            self.assertEqual(bash_backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(profile_backup.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("render-canary", bash_backup.read_text(encoding="utf-8"))
            self.assertEqual(
                npmrc.read_text(encoding="utf-8"),
                "//registry.example/:_authToken=npm-render-canary\n",
            )
            self.assertFalse((home / ".npmrc.pre-coding-system").exists())


if __name__ == "__main__":
    unittest.main()
