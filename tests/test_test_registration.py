#!/usr/bin/env python3
"""Tests that every test file is actually wired into the Makefile test target.

Without this check the suite is opt-in: a test file can be added to tests/ and
never run, so silence is indistinguishable from coverage.  Nine files had
accumulated in that state, one of them permanently red.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / "Makefile"
TESTS = ROOT / "tests"


def makefile_recipe(target: str) -> str:
    """Return the recipe body of a single Makefile target."""
    lines = MAKEFILE.read_text().splitlines()
    body: list[str] = []
    collecting = False
    for line in lines:
        if re.match(rf"^{re.escape(target)}:", line):
            collecting = True
            continue
        if collecting:
            if line.startswith("\t"):
                body.append(line)
            elif line.strip():
                break
    return "\n".join(body)


class TestRegistration(unittest.TestCase):
    def test_every_test_file_is_referenced_by_the_test_target(self) -> None:
        recipe = makefile_recipe("test")
        self.assertTrue(recipe, "Makefile test: target has no recipe")
        unwired = sorted(
            path.name
            for path in TESTS.glob("test_*.py")
            if path.name not in recipe
        )
        self.assertEqual(
            unwired,
            [],
            "test files present in tests/ but never run by `make test`: "
            + ", ".join(unwired),
        )

    def test_shell_suites_are_referenced_by_the_test_target(self) -> None:
        recipe = makefile_recipe("test")
        unwired = sorted(
            path.name
            for path in TESTS.glob("*.sh")
            if path.name not in recipe
        )
        self.assertEqual(
            unwired,
            [],
            "shell suites present in tests/ but never run by `make test`: "
            + ", ".join(unwired),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
