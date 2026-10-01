#!/usr/bin/env python3
"""Focused tests for installed-software exact-version verification."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_installed_software", ROOT / "bin/verify-installed-software.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InstalledSoftwareVerifierTests(unittest.TestCase):
    def test_version_match_requires_a_token_boundary(self) -> None:
        self.assertTrue(MODULE.output_has_exact_version("tool version 1.2.3", "1.2.3"))
        self.assertTrue(MODULE.output_has_exact_version("v1.2.3", "1.2.3"))
        self.assertFalse(MODULE.output_has_exact_version("tool 1.2.30", "1.2.3"))
        self.assertFalse(MODULE.output_has_exact_version("tool 11.2.3", "1.2.3"))
        self.assertFalse(MODULE.output_has_exact_version("tool 1.2.3-rc1", "1.2.3"))

    def test_skipped_cli_is_reported_and_not_failed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}):
            records = MODULE.verify_clis(
                Path(directory), {"grok": "1.0.0", "kimi": "2.0.0"}, skipped=frozenset({"grok"})
            )
        by_name = {record["name"]: record for record in records}
        self.assertEqual(by_name["grok"]["status"], "SKIPPED")
        self.assertIn("SKIP_GROK", by_name["grok"]["reason"])
        self.assertEqual(by_name["kimi"]["status"], "FAIL")
        self.assertEqual(MODULE.skipped_clis({"SKIP_GROK": "1"}), frozenset({"grok"}))
        self.assertEqual(
            MODULE.skipped_clis({"SKIP_OLLAMA": "1", "SKIP_GPROLOG": "1", "SKIP_VERACRYPT": "1"}),
            frozenset({"ollama", "gprolog", "veracrypt"}),
        )
        self.assertEqual(MODULE.skipped_clis({"SKIP_GROK": "yes"}), frozenset())

    def test_apt_lock_entries_are_minimums_or_ppa_builds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "apt.lock"
            path.write_text("# comment\ncurl>=8.5.0-2\ncalibre@xtradeb\ngit=1:2.43.0\n", encoding="utf-8")
            self.assertEqual(
                MODULE.apt_specs(path),
                {"curl": (">=", "8.5.0-2"), "calibre": ("@", "xtradeb"), "git": ("=", "1:2.43.0")},
            )
            for bad in ("curl", "curl>=", "curl@", "Curl>=1"):
                with self.subTest(entry=bad):
                    path.write_text(bad + "\n", encoding="utf-8")
                    with self.assertRaises(MODULE.VerificationError):
                        MODULE.apt_specs(path)

    def test_apt_entry_is_met_by_newer_versions_and_ppa_builds_only(self) -> None:
        self.assertTrue(MODULE.apt_satisfied((">=", "8.5.0-2ubuntu10.11"), "8.5.0-2ubuntu10.15"))
        self.assertTrue(MODULE.apt_satisfied((">=", "8.5.0-2ubuntu10.11"), "8.5.0-2ubuntu10.11"))
        self.assertFalse(MODULE.apt_satisfied((">=", "8.5.0-2ubuntu10.15"), "8.5.0-2ubuntu10.11"))
        self.assertFalse(MODULE.apt_satisfied((">=", "1:2.43.0-1"), "2.43.0-1"))
        self.assertTrue(MODULE.apt_satisfied(("@", "xtradeb"), "154.0.8037.57-1xtradeb1.2404.1"))
        self.assertFalse(MODULE.apt_satisfied(("@", "xtradeb"), "7.6.0+ds-1build1"))
        self.assertTrue(MODULE.apt_satisfied(("=", "1.0-1"), "1.0-1"))
        self.assertFalse(MODULE.apt_satisfied(("=", "1.0-1"), "1.0-2"))
        for spec in ((">=", "1.0"), ("@", "xtradeb"), ("=", "1.0")):
            self.assertFalse(MODULE.apt_satisfied(spec, None))

    def test_cli_minimum_version_accepts_newer_releases(self) -> None:
        self.assertTrue(MODULE.output_meets_version("Docker version 29.7.2, build 1a2b3c4", ">=29.3.0"))
        self.assertTrue(MODULE.output_meets_version("1.102.3\n  tailscale commit: x", ">=1.102.3"))
        self.assertFalse(MODULE.output_meets_version("Docker version 29.7.2, build 1a2b3c4", ">=29.8.0"))
        self.assertFalse(MODULE.output_meets_version("gh version 2.9.0 (2024-01-01)", ">=2.45.0"))
        self.assertFalse(MODULE.output_meets_version("no version here", ">=1.0"))
        self.assertTrue(MODULE.output_meets_version("tool 1.2.3", "1.2.3"))
        self.assertFalse(MODULE.output_meets_version("tool 1.2.30", "1.2.3"))

    @staticmethod
    def tool(path: Path, output: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"#!/bin/sh\necho '{output}'\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_updated_cli_still_passes_and_an_older_one_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            self.tool(home / ".kimi-code/bin/kimi", "kimi, version 2.1.1")
            self.tool(home / ".local/bin/agy", "1.0.9")
            with mock.patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}):
                records = {
                    record["name"]: record
                    for record in MODULE.verify_clis(home, {"kimi": "0.31.1", "agy": "1.1.10"})
                }
        self.assertEqual(records["kimi"]["status"], "PASS")
        self.assertEqual(records["kimi"]["observed"], "2.1.1")
        self.assertEqual(records["agy"]["status"], "FAIL")

    def test_cli_is_found_where_it_is_actually_installed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            # pipx exposes ~/.local/bin/aider as a symlink into its venv
            target = self.tool(home / ".local/share/pipx/venvs/aider-chat/bin/aider", "aider 0.86.2")
            (home / ".local/bin").mkdir(parents=True)
            (home / ".local/bin/aider").symlink_to(target)
            # a system-wide node found on PATH instead of ~/.npm-global/bin
            system = Path(directory) / "usr-bin"
            self.tool(system / "node", "v22.23.2")
            with mock.patch.dict(os.environ, {"PATH": f"{system}:/usr/bin:/bin"}):
                records = {
                    record["name"]: record
                    for record in MODULE.verify_clis(home, {"aider": "0.86.2", "node": "22.23.2"})
                }
        self.assertEqual(records["aider"]["status"], "PASS")
        self.assertEqual(records["node"]["status"], "PASS")
        self.assertEqual(records["node"]["path"], str(system / "node"))

    def test_apt_lock_rejects_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "apt.lock"
            path.write_text("git=1\ngit=2\n", encoding="utf-8")
            with self.assertRaises(MODULE.VerificationError):
                MODULE.apt_specs(path)

    def test_source_profile_validates_both_platform_declarations(self) -> None:
        for architecture in ("amd64", "arm64"):
            lock = MODULE.load_lock(ROOT, architecture)
            self.assertEqual(lock["host"]["architecture"], architecture)
            self.assertIn("docker", lock["cli_versions"])
            self.assertIn("modal", lock["cli_versions"])


if __name__ == "__main__":
    unittest.main()
