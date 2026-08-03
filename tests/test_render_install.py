#!/usr/bin/env python3
"""Regression tests for byte-exact public artifact rendering."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "bin/lib/render_install.py"
SPEC = importlib.util.spec_from_file_location("render_install_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RENDER_INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER_INSTALL)


class RenderInstallTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
