#!/usr/bin/env python3
"""The suite runner executes every test command and reports all failures."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "bin/run-test-suite.py"
SPEC = importlib.util.spec_from_file_location("run_test_suite", RUNNER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

MAKEFILE = (
    "REPO := here\n\n"
    "test: ## fixture\n"
    "\t@echo first\n"
    "\t@false\n"
    "\t@value=$$(echo joined); \\\n"
    "\t  test \"$$value\" = joined\n"
    "\t@sh -c 'echo late-failure; exit 3'\n"
    "\t@echo last\n"
    "\n"
    "other:\n"
    "\t@echo not-part-of-test\n"
)


class RunTestSuiteTests(unittest.TestCase):
    def test_commands_join_continuations_and_stop_at_the_next_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            makefile = Path(temporary) / "Makefile"
            makefile.write_text(MAKEFILE, encoding="utf-8")
            commands = MODULE.recipe_commands(makefile, "test")
        self.assertEqual(len(commands), 5)
        self.assertEqual(commands[0], "echo first")
        self.assertIn("\\\n", commands[2])
        self.assertNotIn("not-part-of-test", "\n".join(commands))

    def test_every_command_runs_and_all_failures_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            makefile = Path(temporary) / "Makefile"
            makefile.write_text(MAKEFILE, encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-B", str(RUNNER), "--makefile", str(makefile)],
                capture_output=True,
                text=True,
                check=False,
                env={"PATH": "/usr/bin:/bin", "HOME": temporary},
            )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("3 of 5 commands passed", completed.stdout)
        self.assertIn("FAILED: false", completed.stdout)
        self.assertIn("late-failure", completed.stdout)
        self.assertIn("PASS", completed.stdout.split("echo last")[0].rsplit("\n", 1)[-1])

    def test_ci_runs_every_check_and_the_full_suite(self) -> None:
        ci = (ROOT / "bin/ci.sh").read_text(encoding="utf-8")
        for check in ("doctor", "components", "leak-scan", "leak-scan-history", "public-export-check", "tests"):
            self.assertIn(f"check {check} ", ci)
        self.assertIn("bin/run-test-suite.py", ci)
        self.assertNotIn("set -e\n", ci)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("\t@bash bin/ci.sh\n", makefile)


if __name__ == "__main__":
    unittest.main()
