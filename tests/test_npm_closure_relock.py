#!/usr/bin/env python3
"""The npm CLI closure is re-resolved when backups move npm globals forward."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CLOSURE = ROOT / "system/software/npm-closure"

# A stand-in for `npm install --package-lock-only`: it moves each direct record
# to the version package.json asks for, as the registry would.
FAKE_NPM = """#!/usr/bin/env python3
import json, os, sys
# npm refuses one file as both the user and the global configuration
if os.environ["npm_config_userconfig"] == os.environ["npm_config_globalconfig"]:
    sys.exit(1)
package = json.load(open("package.json"))
lock = json.load(open("package-lock.json"))
lock["packages"][""]["dependencies"] = package["dependencies"]
for name, version in package["dependencies"].items():
    record = lock["packages"]["node_modules/" + name]
    record["version"] = version
    base = name.split("/")[-1]
    record["resolved"] = f"https://registry.npmjs.org/{name}/-/{base}-{version}.tgz"
json.dump(lock, open("package-lock.json", "w"), indent=2)
open("package-lock.json", "a").write("\\n")
"""


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NpmClosureRelockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.closurectl = load("csr_closurectl_relock", CLOSURE / "closurectl.py")
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in ("package.json", "package-lock.json"):
            shutil.copy2(CLOSURE / name, self.root / name)
        self.requested = self.root / "npm-globals.txt"
        shutil.copy2(ROOT / "system/packages/npm-globals.txt", self.requested)
        for name, value in (
            ("PACKAGE_JSON", self.root / "package.json"),
            ("PACKAGE_LOCK", self.root / "package-lock.json"),
            ("PACKAGE_LIST", self.requested),
        ):
            patcher = mock.patch.object(self.closurectl, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.npm = self.root / "fake-npm"

    def bump_request(self, name: str, version: str) -> None:
        lines = self.requested.read_text(encoding="utf-8").splitlines()
        lines = [f"{name}@{version}" if line.rsplit("@", 1)[0] == name else line for line in lines]
        self.requested.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_relock_follows_the_request_list_and_keeps_the_contract(self) -> None:
        self.npm.write_text(FAKE_NPM, encoding="utf-8")
        self.npm.chmod(0o755)
        self.bump_request("@openai/codex", "999.0.0")
        self.closurectl.relock(npm=str(self.npm))
        package, lock, requested = self.closurectl.source_contract()
        self.assertEqual(package["dependencies"]["@openai/codex"], "999.0.0")
        self.assertEqual(lock["packages"]["node_modules/@openai/codex"]["version"], "999.0.0")
        self.assertEqual(requested["@openai/codex"], "999.0.0")

    def test_failed_resolution_leaves_the_closure_untouched(self) -> None:
        self.npm.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        self.npm.chmod(0o755)
        before = {name: (self.root / name).read_bytes() for name in ("package.json", "package-lock.json")}
        self.bump_request("@openai/codex", "999.0.0")
        with self.assertRaises(self.closurectl.ClosureError):
            self.closurectl.relock(npm=str(self.npm))
        self.assertEqual(
            {name: (self.root / name).read_bytes() for name in ("package.json", "package-lock.json")},
            before,
        )


if __name__ == "__main__":
    unittest.main()
