#!/usr/bin/env python3
"""Static regression checks for the OpenClaw compatibility tuple."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "bin" / "verify-openclaw-compat.py"
LOCK = ROOT / "system" / "openclaw" / "compatibility.lock.json"


class OpenClawCompatibilityTests(unittest.TestCase):
    def test_checked_in_tuple_is_internally_consistent(self) -> None:
        self.assertTrue(CHECKER.is_file())
        self.assertTrue(LOCK.is_file())
        spec = importlib.util.spec_from_file_location("compat", CHECKER)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        failures = module.verify_static(ROOT, lock)
        self.assertEqual(failures, [])

    def test_image_is_content_addressed_for_both_supported_architectures(self) -> None:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        sandbox = lock["sandbox"]
        self.assertRegex(sandbox["image"], r"@sha256:[0-9a-f]{64}$")
        self.assertEqual(set(sandbox["platform_digests"]), {"linux/amd64", "linux/arm64"})
        for digest in sandbox["platform_digests"].values():
            self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
