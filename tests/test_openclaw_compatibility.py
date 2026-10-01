#!/usr/bin/env python3
"""Static regression checks for the OpenClaw compatibility tuple."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "bin" / "verify-openclaw-compat.py"
LOCK = ROOT / "system" / "openclaw" / "compatibility.lock.json"


def load_checker():
    spec = importlib.util.spec_from_file_location("compat", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(directory: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(directory), *arguments],
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


IDENTITY = ("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid")
SAGEMATH = {
    "linux/amd64": "example/sagemath@sha256:" + "b" * 64,
    "linux/arm64": "ghcr.io/example/sagemath@sha256:" + "c" * 64,
}


def pin(repo: Path, commit: str) -> None:
    (repo / "components.lock").write_text(
        f"openclaw-bot=https://github.com/hoanganhduc/openclaw-bot.git@{commit}\n",
        encoding="utf-8",
    )


def make_fixture(root: Path, units: list[str]) -> tuple[Path, Path, dict]:
    """A repository and a component checkout that pass verify_static together."""
    version = "2026.7.1-2"
    digest = "sha256:" + "a" * 64
    image = f"ghcr.io/example/openclaw-sandbox@{digest}"
    repo = root / "repo"
    component = repo / "external/openclaw-bot"
    (component / "systemd/user").mkdir(parents=True)
    for unit in units:
        (component / "systemd/user" / unit).write_text(f"[Unit]\nDescription={unit}\n", encoding="utf-8")
    template = json.dumps({"agents": {"defaults": {"sandbox": {"docker": {"image": image}}}}})
    (component / "config").mkdir()
    (component / "config/openclaw.json.template").write_text(template, encoding="utf-8")
    manifest = {
        "observed_version": version,
        "sagemath_image": SAGEMATH["linux/amd64"],
        "sagemath_image_arm64": SAGEMATH["linux/arm64"],
    }
    (component / "REBUILD-MANIFEST.json").write_text(json.dumps({"openclaw": manifest}), encoding="utf-8")
    git(component, "init", "-q")
    git(component, "add", "-A")
    git(component, *IDENTITY, "commit", "-q", "-m", "fixture")
    commit = git(component, "rev-parse", "HEAD")
    pin(repo, commit)
    (repo / "system/packages").mkdir(parents=True)
    (repo / "system/packages/npm-globals.txt").write_text(f"openclaw@{version}\n", encoding="utf-8")
    (repo / "system/openclaw").mkdir(parents=True)
    (repo / "system/openclaw/skill-closure.json").write_text("{}\n", encoding="utf-8")
    (repo / "system/software").mkdir(parents=True)
    (repo / "system/software/images.lock.json").write_text(
        json.dumps(
            {
                "images": [
                    {"id": f"sagemath-{platform[6:]}", "reference": reference, "roles": ["sagemath"],
                     "platforms": {platform: "sha256:" + "d" * 64}}
                    for platform, reference in SAGEMATH.items()
                ]
            }
        ),
        encoding="utf-8",
    )
    lock = {
        "schema_version": 1,
        "openclaw": {"version": version},
        "component": {
            "name": "openclaw-bot",
            "commit": commit,
            "config_template_sha256": sha256(template.encode()),
            "unit_template_sha256": {
                unit: sha256(f"[Unit]\nDescription={unit}\n".encode()) for unit in units
            },
        },
        "skill_closure_sha256": sha256(b"{}\n"),
        "sandbox": {
            "contract": 1,
            "image": image,
            "index_digest": digest,
            "platform_digests": {"linux/amd64": digest, "linux/arm64": digest},
        },
    }
    return repo, component, lock


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
        self.assertEqual(sandbox["contract"], 1)
        self.assertRegex(sandbox["image"], r"@sha256:[0-9a-f]{64}$")
        self.assertEqual(set(sandbox["platform_digests"]), {"linux/amd64", "linux/arm64"})
        for digest in sandbox["platform_digests"].values():
            self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")

        dockerfile = (
            ROOT / "system/docker/openclaw-sandbox/Dockerfile"
        ).read_text(encoding="utf-8")
        self.assertIn('io.hoanganhduc.openclaw-sandbox.contract="1"', dockerfile)
        verifier = (ROOT / "bin/verify-openclaw-compat.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("locked sandbox image contract differs", verifier)

    def test_split_worker_templates_are_content_addressed(self) -> None:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        digests = lock["component"]["unit_template_sha256"]
        self.assertEqual(
            set(digests),
            {
                "openclaw-email-worker.service",
                "openclaw-googlechat-delivery-worker.service",
                "openclaw-manim-worker.service",
                "openclaw-sage-worker.service",
                "openclaw-whatsapp-delivery-worker.service",
                "openclaw-zalo-delivery-worker.service",
                "openclaw-zulip-delivery-worker.service",
                "send-queue-worker.service",
            },
        )
        for value in digests.values():
            self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_worker_unit_digests_come_from_the_locked_component_commit(self) -> None:
        # The component owns its worker units (D13): the lock hashes the unit templates
        # at the locked commit, and this repository keeps no copies of them.
        module = load_checker()
        units = sorted(module.COMPONENT_WORKER_UNITS)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, component, lock = make_fixture(root, units)
            with mock.patch.dict(os.environ, {"HOME": str(root / "home")}):
                self.assertEqual(module.verify_static(repo, lock), [])

                # a copy of a unit in this repository is not what the lock describes
                (repo / "system/systemd/user").mkdir(parents=True)
                (repo / "system/systemd/user" / units[0]).write_text("stale copy\n", encoding="utf-8")
                self.assertEqual(module.verify_static(repo, lock), [])
                # nor is an uncommitted edit in the component checkout
                (component / "systemd/user" / units[2]).write_text("edited\n", encoding="utf-8")
                self.assertEqual(module.verify_static(repo, lock), [])

                changed = copy.deepcopy(lock)
                changed["component"]["unit_template_sha256"][units[0]] = "0" * 64
                self.assertEqual(
                    module.verify_static(repo, changed),
                    [f"component worker unit template hash differs: {units[0]}"],
                )

                git(component, "rm", "-q", f"systemd/user/{units[1]}")
                git(component, *IDENTITY, "commit", "-q", "-m", "drop a unit")
                missing = copy.deepcopy(lock)
                missing["component"]["commit"] = git(component, "rev-parse", "HEAD")
                pin(repo, missing["component"]["commit"])
                self.assertEqual(
                    module.verify_static(repo, missing),
                    [f"component worker unit template is missing: {units[1]}"],
                )

    def test_component_sagemath_images_are_the_locked_images(self) -> None:
        # The component's worker runs the SageMath images its manifest records; they
        # must be the digests this repository pulls from the image lock.
        module = load_checker()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, component, lock = make_fixture(root, sorted(module.COMPONENT_WORKER_UNITS))
            images_lock = repo / "system/software/images.lock.json"
            with mock.patch.dict(os.environ, {"HOME": str(root / "home")}):
                self.assertEqual(module.verify_static(repo, lock), [])

                locked = json.loads(images_lock.read_text(encoding="utf-8"))
                locked["images"][1]["reference"] = "ghcr.io/example/sagemath@sha256:" + "e" * 64
                images_lock.write_text(json.dumps(locked), encoding="utf-8")
                self.assertEqual(
                    module.verify_static(repo, lock),
                    ["component SageMath image differs from the image lock: linux/arm64"],
                )

                locked["images"][1]["reference"] = SAGEMATH["linux/arm64"]
                images_lock.write_text(json.dumps(locked), encoding="utf-8")
                manifest = json.loads((component / "REBUILD-MANIFEST.json").read_text(encoding="utf-8"))
                manifest["openclaw"]["sagemath_image"] = "example/sagemath:10.8"
                (component / "REBUILD-MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
                git(component, *IDENTITY, "commit", "-q", "-am", "run the tag")
                tagged = copy.deepcopy(lock)
                tagged["component"]["commit"] = git(component, "rev-parse", "HEAD")
                pin(repo, tagged["component"]["commit"])
                self.assertEqual(
                    module.verify_static(repo, tagged),
                    ["component SageMath image differs from the image lock: linux/amd64"],
                )


if __name__ == "__main__":
    unittest.main()
