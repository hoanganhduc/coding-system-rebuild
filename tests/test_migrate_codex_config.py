#!/usr/bin/env python3
"""Tests for non-destructive Codex selector convergence."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "bin/migrate-codex-config.py"
SPEC = importlib.util.spec_from_file_location("migrate_codex_config", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MigrateCodexConfigTests(unittest.TestCase):
    def test_full_install_converges_existing_config_after_render(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        render = install.index('bash "$REPO/bin/render-install.sh"')
        migrate = install.index('"$REPO/bin/migrate-codex-config.py"')
        phase_seven = install.index('# 7 ─ OpenClaw slice')
        self.assertLess(render, migrate)
        self.assertLess(migrate, phase_seven)

    def write(self, home: Path, payload: str, mode: int = 0o600) -> Path:
        path = home / ".codex/config.toml"
        path.parent.mkdir(mode=0o700)
        path.write_text(payload, encoding="utf-8")
        path.chmod(mode)
        return path

    def assert_selectors(self, path: Path, home: Path) -> dict:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        selected = document["shell_environment_policy"]["set"]
        for key, relative in MODULE.SELECTOR_PATHS.items():
            self.assertEqual(selected[key], str(home / relative))
        return document

    def test_adds_selectors_without_replacing_existing_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            path = self.write(
                home,
                'model = "fixture"\n\n[shell_environment_policy]\n'
                'exclude = ["AAS_SECRETS_FILE"]\n\n'
                '[mcp_servers.keep-me]\ncommand = "kept"\n',
                0o644,
            )
            self.assertTrue(MODULE.migrate(path, home))
            document = self.assert_selectors(path, home)
            self.assertEqual(document["model"], "fixture")
            self.assertEqual(document["mcp_servers"]["keep-me"]["command"], "kept")
            excluded = document["shell_environment_policy"]["exclude"]
            self.assertEqual(excluded[0], "AAS_SECRETS_FILE")
            self.assertTrue(set(MODULE.REQUIRED_EXCLUDES).issubset(excluded))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            before = path.read_bytes()
            self.assertFalse(MODULE.migrate(path, home))
            self.assertEqual(path.read_bytes(), before)

    def test_merges_existing_inline_selector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            path = self.write(
                home,
                '[shell_environment_policy]\nset = { USER_SETTING = "keep", '
                'AAS_COMPUTE_SECRETS_FILE = "/stale" }\n',
            )
            document = self.assert_selectors_after_migrate(path, home)
            self.assertEqual(document["shell_environment_policy"]["set"]["USER_SETTING"], "keep")

    def assert_selectors_after_migrate(self, path: Path, home: Path) -> dict:
        self.assertTrue(MODULE.migrate(path, home))
        return self.assert_selectors(path, home)

    def test_merges_existing_selector_subtable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            path = self.write(
                home,
                '[shell_environment_policy]\nexclude = []\n\n'
                '[shell_environment_policy.set]\nUSER_SETTING = "keep"\n\n'
                '[notice]\nhide_rate_limit_model_nudge = true\n',
            )
            document = self.assert_selectors_after_migrate(path, home)
            self.assertEqual(document["shell_environment_policy"]["set"]["USER_SETTING"], "keep")
            self.assertTrue(document["notice"]["hide_rate_limit_model_nudge"])

    def test_repairs_stale_selectors_and_retires_unsafe_legacy_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            stale = {
                key: f"/attacker/{key.lower()}" for key in MODULE.SELECTOR_PATHS
            }
            stale.update(
                {
                    "USER_SETTING": "keep",
                    "AAS_ALLOW_EXTERNAL_SECRETS_FILE": "/attacker/broad.env",
                    "AAS_ZOTERO_SKILL_SECRETS_FILE": "/attacker/zotero.env",
                    "OPENCLAW_SECRETS_FILE": "/attacker/openclaw.json",
                }
            )
            assignments = ", ".join(
                f"{key} = {value!r}" for key, value in stale.items()
            )
            path = self.write(
                home,
                "[shell_environment_policy]\n"
                "exclude = [\"USER_ENV\"]\n"
                f"set = {{ {assignments} }}\n",
            )

            document = self.assert_selectors_after_migrate(path, home)

            policy = document["shell_environment_policy"]
            self.assertEqual(policy["set"]["USER_SETTING"], "keep")
            self.assertFalse(MODULE.RETIRED_SET_KEYS.intersection(policy["set"]))
            self.assertEqual(policy["exclude"][0], "USER_ENV")
            self.assertTrue(
                set(MODULE.REQUIRED_EXCLUDES).issubset(policy["exclude"])
            )

    def test_restore_completes_the_selector_contract_from_the_tracked_template(self) -> None:
        # The template is captured from the running host, which may predate the
        # selector contract.  install.sh phase 6 migrates the rendered config on
        # every restore, so the contract must hold after that migration.
        template = (ROOT / "agents/codex/config.toml.template").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            path = self.write(home, template.replace("{{ HOME }}", str(home)))
            MODULE.migrate(path, home)
            self.assert_selectors(path, home)
            self.assertFalse(MODULE.migrate(path, home))
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        self.assertIn(
            '"$REPO/bin/migrate-codex-config.py" \\\n    --config "$HOME/.codex/config.toml" --home "$HOME"',
            install,
        )

    def test_rejects_symlink_and_invalid_selector_type(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            target = self.write(home, '[shell_environment_policy]\nset = "bad"\n')
            with self.assertRaisesRegex(MODULE.MigrationError, "selector table"):
                MODULE.migrate(target, home)
            target.unlink()
            outside = home / "outside"
            outside.write_text("model = \"x\"\n", encoding="utf-8")
            target.symlink_to(outside)
            with self.assertRaisesRegex(MODULE.MigrationError, "unsafe"):
                MODULE.migrate(target, home)


if __name__ == "__main__":
    unittest.main()
