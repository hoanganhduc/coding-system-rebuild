#!/usr/bin/env python3
"""Backups move artifact-locked CLIs to the versions the host runs."""

from __future__ import annotations

import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURES = ("amd64", "arm64")


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LockPromotionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lockctl = load("csr_lockctl_promotion", ROOT / "system/software/lockctl.py")
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.software = Path(directory.name)
        for name in ("ubuntu-24.04-amd64.lock.json", "ubuntu-24.04-arm64.lock.json", "npm-globals.lock.json"):
            shutil.copy2(ROOT / "system/software" / name, self.software / name)
        patcher = mock.patch.object(self.lockctl, "SOFTWARE", self.software)
        patcher.start()
        self.addCleanup(patcher.stop)

    def texts(self) -> dict[str, str]:
        return {
            architecture: (self.software / f"ubuntu-24.04-{architecture}.lock.json").read_text(encoding="utf-8")
            for architecture in ARCHITECTURES
        }

    def test_promotion_rehashes_every_platform_and_raises_the_floor(self) -> None:
        before = self.texts()
        old = self.lockctl.get_artifact("arm64", "kimi")["version"]
        fetched: list[str] = []

        def sha256_of(url: str) -> str:
            fetched.append(url)
            return f"{len(fetched):064x}"

        self.lockctl.promote_artifact("kimi", "99.0.0", sha256_of=sha256_of, today="2026-10-01")

        after = self.texts()
        for architecture in ARCHITECTURES:
            with self.subTest(architecture=architecture):
                artifact = self.lockctl.get_artifact(architecture, "kimi")
                self.assertEqual(artifact["version"], "99.0.0")
                self.assertIn("/99.0.0/", artifact["url"])
                self.assertNotIn(old, artifact["url"])
                self.assertIn(artifact["url"], fetched)
                self.assertIn(artifact["sha256"], {f"{1:064x}", f"{2:064x}"})
                self.assertIn("2026-10-01", artifact["evidence"])
                profile = self.lockctl.load_profile(architecture)
                self.assertEqual(profile["cli_versions"]["kimi"], "99.0.0")
                # Only the promoted entry and its floor change; every other byte stays.
                added = [
                    line for line in difflib.ndiff(
                        before[architecture].splitlines(), after[architecture].splitlines()
                    )
                    if line.startswith("+ ")
                ]
                self.assertEqual(len(added), 5, added)
                old_profile = json.loads(before[architecture])
                self.assertEqual(
                    [item for item in old_profile["artifacts"] if item["id"] != "kimi"],
                    [item for item in profile["artifacts"] if item["id"] != "kimi"],
                )
                self.assertEqual(old_profile["manifests"], profile["manifests"])
        self.assertEqual(len(fetched), 2)

    def test_unverified_artifact_keeps_its_marker_through_promotion(self) -> None:
        # The grok entry's evidence is non-ASCII and marks it unverified.
        self.lockctl.promote_artifact("grok", "99.0.0", sha256_of=lambda _url: "d" * 64, today="2026-10-01")
        for architecture in ARCHITECTURES:
            artifact = self.lockctl.get_artifact(architecture, "grok")
            self.assertEqual(artifact["version"], "99.0.0")
            self.assertTrue(artifact["evidence"].startswith("UNVERIFIED"))

    def test_failed_download_leaves_every_lock_untouched(self) -> None:
        before = self.texts()

        def sha256_of(url: str) -> str:
            if "x64" in url:
                raise self.lockctl.LockError("download failed")
            return "b" * 64

        with self.assertRaises(self.lockctl.LockError):
            self.lockctl.promote_artifact("kimi", "99.0.0", sha256_of=sha256_of, today="2026-10-01")
        self.assertEqual(self.texts(), before)

    def test_older_equal_or_malformed_versions_are_refused(self) -> None:
        before = self.texts()
        current = self.lockctl.get_artifact("arm64", "kimi")["version"]
        for version in ("0.0.1", current, "99.0.0-beta", "../99.0.0"):
            with self.subTest(version=version):
                with self.assertRaises(self.lockctl.LockError):
                    self.lockctl.promote_artifact(
                        "kimi", version, sha256_of=lambda _url: "c" * 64, today="2026-10-01"
                    )
        self.assertEqual(self.texts(), before)

    def test_backup_promotes_only_installed_tools_newer_than_the_lock(self) -> None:
        promoter = load("csr_promote_installed", ROOT / "bin/promote-installed-clis.py")
        floors = self.lockctl.load_profile("arm64")["cli_versions"]
        observed = {"kimi": "99.0.0", "node": floors["node"], "agy": None}
        calls: list[tuple[str, str]] = []
        with (
            mock.patch.object(promoter, "installed_version", side_effect=lambda _home, name: observed.get(name)),
            mock.patch.object(promoter, "installed_npm_versions", return_value={}),
            mock.patch.object(promoter.LOCKCTL, "SOFTWARE", self.software),
            mock.patch.object(
                promoter.LOCKCTL,
                "promote_artifact",
                side_effect=lambda identifier, version, **_kwargs: calls.append((identifier, version)),
            ),
        ):
            self.assertEqual(promoter.main(["--home", "/nonexistent"]), 0)
        self.assertEqual(calls, [("kimi", "99.0.0")])


class NpmPromotionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lockctl = load("csr_lockctl_npm_promotion", ROOT / "system/software/lockctl.py")
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for relative in (
            "system/software/npm-globals.lock.json",
            "system/software/ubuntu-24.04-amd64.lock.json",
            "system/software/ubuntu-24.04-arm64.lock.json",
            "system/packages/npm-globals.txt",
        ):
            (self.root / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, self.root / relative)
        for name, value in (("ROOT", self.root), ("SOFTWARE", self.root / "system/software")):
            patcher = mock.patch.object(self.lockctl, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def files(self) -> dict[str, bytes]:
        return {str(path.relative_to(self.root)): path.read_bytes() for path in sorted(self.root.rglob("*")) if path.is_file()}

    def test_npm_promotion_updates_lock_request_and_platform_digests_together(self) -> None:
        lock = json.loads((self.root / "system/software/npm-globals.lock.json").read_text(encoding="utf-8"))
        entry = next(item for item in lock["packages"] if item["name"] == "@openai/codex")
        old = entry["version"]
        self.lockctl.promote_npm(
            "@openai/codex", "999.0.0", integrity_of=lambda _name, _version: "sha512-" + "A" * 86 + "==",
            today="2026-10-01",
        )
        lock = json.loads((self.root / "system/software/npm-globals.lock.json").read_text(encoding="utf-8"))
        entry = next(item for item in lock["packages"] if item["name"] == "@openai/codex")
        self.assertEqual(entry["version"], "999.0.0")
        self.assertEqual(entry["integrity"], "sha512-" + "A" * 86 + "==")
        requested = (self.root / "system/packages/npm-globals.txt").read_text(encoding="utf-8").splitlines()
        self.assertIn("@openai/codex@999.0.0", requested)
        self.assertNotIn(f"@openai/codex@{old}", requested)
        self.assertEqual(self.lockctl.validate_npm_lock(), [])
        for architecture in ARCHITECTURES:
            manifests = {
                item["path"]: item["sha256"]
                for item in self.lockctl.load_profile(architecture)["manifests"]
            }
            for relative in ("system/packages/npm-globals.txt", "system/software/npm-globals.lock.json"):
                self.assertEqual(
                    manifests[relative],
                    hashlib.sha256((self.root / relative).read_bytes()).hexdigest(),
                )

    def test_openclaw_older_and_failed_npm_promotions_change_nothing(self) -> None:
        before = self.files()
        good = lambda _name, _version: "sha512-" + "B" * 86 + "=="  # noqa: E731

        def failing(_name: str, _version: str) -> str:
            raise self.lockctl.LockError("registry unavailable")

        for name, version, integrity_of in (
            ("openclaw", "2099.1.1", good),
            ("@openai/codex", "0.0.1", good),
            ("@openai/codex", "999.0.0", failing),
            ("not-in-the-lock", "1.0.0", good),
        ):
            with self.subTest(name=name, version=version):
                with self.assertRaises(self.lockctl.LockError):
                    self.lockctl.promote_npm(name, version, integrity_of=integrity_of, today="2026-10-01")
        self.assertEqual(self.files(), before)

    def test_backup_promotes_only_newer_npm_globals_outside_the_openclaw_tuple(self) -> None:
        promoter = load("csr_promote_installed_npm", ROOT / "bin/promote-installed-clis.py")
        lock = json.loads((self.root / "system/software/npm-globals.lock.json").read_text(encoding="utf-8"))
        locked = {item["name"]: item["version"] for item in lock["packages"]}
        installed = {
            "@openai/codex": "999.0.0",
            "openclaw": "2099.1.1",
            "@github/copilot": locked["@github/copilot"],
            "@tobilu/qmd": "2.5.3",
        }
        calls: list[tuple[str, str]] = []
        with (
            mock.patch.object(promoter, "installed_version", return_value=None),
            mock.patch.object(promoter, "installed_npm_versions", return_value=installed),
            mock.patch.object(promoter.LOCKCTL, "SOFTWARE", self.root / "system/software"),
            mock.patch.object(promoter.LOCKCTL, "ROOT", self.root),
            mock.patch.object(
                promoter.LOCKCTL,
                "promote_npm",
                side_effect=lambda name, version, **_kwargs: calls.append((name, version)),
            ),
            mock.patch.object(promoter.CLOSURECTL, "relock") as relock,
        ):
            self.assertEqual(promoter.main(["--home", "/nonexistent"]), 0)
        self.assertEqual(calls, [("@openai/codex", "999.0.0")])
        relock.assert_called_once()

    def test_npm_promotion_is_undone_when_the_closure_cannot_follow(self) -> None:
        promoter = load("csr_promote_installed_npm_undo", ROOT / "bin/promote-installed-clis.py")
        before = self.files()

        def promote(name: str, version: str, **_kwargs: object) -> None:
            self.lockctl.promote_npm(
                name, version, integrity_of=lambda _n, _v: "sha512-" + "C" * 86 + "==", today="2026-10-01"
            )

        with (
            mock.patch.object(promoter, "installed_version", return_value=None),
            mock.patch.object(promoter, "installed_npm_versions", return_value={"@openai/codex": "999.0.0"}),
            mock.patch.object(promoter.LOCKCTL, "SOFTWARE", self.root / "system/software"),
            mock.patch.object(promoter.LOCKCTL, "ROOT", self.root),
            mock.patch.object(promoter.LOCKCTL, "promote_npm", side_effect=promote),
            mock.patch.object(
                promoter.CLOSURECTL, "relock", side_effect=promoter.CLOSURECTL.ClosureError("registry down")
            ),
        ):
            self.assertEqual(promoter.main(["--home", "/nonexistent"]), 0)
        self.assertEqual(self.files(), before)


if __name__ == "__main__":
    unittest.main()
