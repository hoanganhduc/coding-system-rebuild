#!/usr/bin/env python3
"""Focused contract and offline-install tests for the Python wheel closure."""

from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/install-python-closure.py"
FIXTURES = ROOT / "tests/fixtures/python-closure"
SPEC = importlib.util.spec_from_file_location("install_python_closure", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
sys.path.insert(0, str(ROOT / "system/docker/python-wheelhouse"))
sys.path.insert(0, str(ROOT / "system/python-closure"))
import runtime_lib as RUNTIME
import wheelhouse_lib as WHEELHOUSE


def fixture(architecture: str) -> dict[str, object]:
    return json.loads(
        (FIXTURES / f"ubuntu-24.04-{architecture}.synthetic.lock.json").read_text(
            encoding="utf-8"
        )
    )


def wheel_bytes(name: str = "closure_demo", version: str = "1.0.0") -> bytes:
    package = name.replace("-", "_")
    dist_info = f"{package}-{version}.dist-info"
    files: dict[str, bytes] = {
        f"{package}/__init__.py": (
            f"__version__ = {version!r}\n\n"
            "def main():\n"
            "    return 0\n"
        ).encode(),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {name.replace('_', '-')}\n"
            f"Version: {version}\n"
            "Summary: synthetic closure test wheel\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: coding-system-rebuild-tests\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n\n"
        ).encode(),
        f"{dist_info}/entry_points.txt": (
            "[console_scripts]\n"
            f"{name.replace('_', '-')} = {package}:main\n"
        ).encode(),
    }
    records = []
    for path, content in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        records.append(f"{path},sha256={digest},{len(content)}")
    records.append(f"{dist_info}/RECORD,,")
    files[f"{dist_info}/RECORD"] = ("\n".join(records) + "\n").encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return output.getvalue()


def build_wheelhouse(root: Path, architecture: str) -> None:
    root.mkdir()
    for environment in WHEELHOUSE.ENVIRONMENTS:
        directory = root / environment
        directory.mkdir()
        name = "closure-demo" if environment == "workspace" else f"demo-{environment}"
        filename = f"{name.replace('-', '_')}-1.0.0-py3-none-any.whl"
        (directory / filename).write_bytes(wheel_bytes(name))
        if environment == "docling-cpu":
            for package, version in (("torch", "2.11.0+cpu"), ("torchvision", "0.26.0+cpu")):
                filename = f"{package}-{version}-py3-none-any.whl"
                (directory / filename).write_bytes(wheel_bytes(package, version))
    WHEELHOUSE.build_manifests(root, f"linux/{architecture}")


def qualify_environment(
    value: dict[str, object], wheelhouse: Path, environment_name: str = "workspace"
) -> None:
    value["wheelhouseManifestSha256"] = WHEELHOUSE.sha256_file(wheelhouse / "manifest.json")
    environment = value["environments"][environment_name]
    manifest_path = wheelhouse / environment_name / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    environment["manifestSha256"] = WHEELHOUSE.sha256_file(manifest_path)
    environment["artifacts"] = manifest["artifacts"]


def qualify_all(value: dict[str, object], wheelhouse: Path) -> None:
    for environment_name in WHEELHOUSE.ENVIRONMENTS:
        environment = value["environments"][environment_name]
        environment["qualification"] = {"state": "qualified", "blockers": []}
        qualify_environment(value, wheelhouse, environment_name)
    value["qualification"] = {"state": "qualified", "blockers": []}


def write_image_authorities(root: Path, wheelhouse: Path, architecture: str) -> tuple[Path, Path]:
    index_digest = "sha256:" + "1" * 64
    platform_digest = "sha256:" + "2" * 64
    images_lock = root / "images.lock.json"
    images_lock.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "images": [
                    {
                        "id": "python-wheelhouse",
                        "roles": ["python-wheelhouse"],
                        "repository": "ghcr.io/example/python-wheelhouse",
                        "reference": f"ghcr.io/example/python-wheelhouse@{index_digest}",
                        "index_digest": index_digest,
                        "platforms": {f"linux/{architecture}": platform_digest},
                        "evidence": "synthetic test authority",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    receipt = root / "wheelhouse.provenance.json"
    image = RUNTIME.load_locked_image(images_lock, architecture)
    RUNTIME.write_provenance(receipt, RUNTIME.expected_provenance(image, wheelhouse))
    return images_lock, receipt


class PythonClosureContractTests(unittest.TestCase):
    def test_content_attestation_binds_cache_bytecode_directories_and_root_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary) / "generation"
            cache = generation / "package/__pycache__"
            cache.mkdir(parents=True)
            (generation / "package/__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
            generated = cache / "__init__.cpython-312.pyc"
            generated.write_bytes(b"runtime cache one")

            baseline = MODULE.installed_content_manifest(generation)
            generated.write_bytes(b"runtime cache two")
            self.assertNotEqual(MODULE.installed_content_manifest(generation), baseline)

            generated.write_bytes(b"runtime cache one")
            cache.chmod(0o777)
            self.assertNotEqual(MODULE.installed_content_manifest(generation), baseline)
            cache.chmod(0o755)

            rogue = generation / "rogue.pyc"
            rogue.write_bytes(b"importable sourceless authority")
            with_rogue = MODULE.installed_content_manifest(generation)
            self.assertNotEqual(with_rogue, baseline)

            rogue.unlink()
            generation.chmod(0o700)
            self.assertNotEqual(MODULE.installed_content_manifest(generation), baseline)

    def test_generation_freeze_blocks_runtime_cache_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary) / "generation"
            package = generation / "lib/python3.12/site-packages/package"
            package.mkdir(parents=True)
            module = package / "module.py"
            module.write_text("VALUE = 1\n", encoding="utf-8")
            executable = generation / "bin/tool"
            executable.parent.mkdir()
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)

            MODULE.freeze_generation_contents(generation)

            self.assertEqual(stat.S_IMODE(package.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(module.stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(generation.stat().st_mode), 0o755)

    def test_both_platform_fixtures_and_production_locks_validate(self) -> None:
        for architecture in ("amd64", "arm64"):
            normalized = MODULE.validate_lock(fixture(architecture))
            self.assertEqual(normalized["platform"], f"ubuntu-24.04-{architecture}")
            self.assertEqual(
                set(normalized["environments"]),
                {
                    "workspace",
                    "shared",
                    "docling-cpu",
                    "lean-explore",
                    "getscipapers",
                    "aider",
                    "modal",
                    "course-management",
                },
            )
            # The production locks carry the promoted CI wheelhouse: every
            # environment names its exact wheels under one root manifest digest.
            production, _ = MODULE.load_lock(
                ROOT / f"system/python-closure/ubuntu-24.04-{architecture}.lock.json"
            )
            self.assertEqual(production["qualification"]["state"], "qualified")
            self.assertRegex(production["wheelhouseManifestSha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(
                all(
                    environment["qualification"]["state"] == "qualified"
                    and environment["artifacts"]
                    for environment in production["environments"].values()
                )
            )
            image = RUNTIME.load_locked_image(
                ROOT / "system/software/images.lock.json", architecture
            )
            self.assertEqual(image["platform"], f"linux/{architecture}")

    def test_rejects_unhashed_duplicate_sdist_and_legacy_url_authority(self) -> None:
        cases = []
        unhashed = fixture("arm64")
        unhashed["environments"]["workspace"]["artifacts"][0]["sha256"] = ""
        cases.append((unhashed, "sha256"))

        duplicate = fixture("arm64")
        duplicate["environments"]["workspace"]["artifacts"].append(
            deepcopy(duplicate["environments"]["workspace"]["artifacts"][0])
        )
        cases.append((duplicate, "duplicate"))

        sdist = fixture("arm64")
        artifact = sdist["environments"]["workspace"]["artifacts"][0]
        artifact["filename"] = "closure_demo-1.0.0.tar.gz"
        cases.append((sdist, "wheel"))

        legacy_url = fixture("arm64")
        legacy_url["environments"]["workspace"]["artifacts"][0]["url"] = (
            "https://artifacts.example.invalid/closure_demo.whl"
        )
        cases.append((legacy_url, "unexpected fields"))

        for value, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(MODULE.ClosureError, message):
                MODULE.validate_lock(value)

    def test_rejects_mismatched_tags_and_wrong_architecture(self) -> None:
        wrong_tags = fixture("arm64")
        wrong_tags["environments"]["workspace"]["artifacts"][0]["tags"] = [
            "cp312-cp312-manylinux_2_17_aarch64"
        ]
        with self.assertRaisesRegex(MODULE.ClosureError, "exactly equal"):
            MODULE.validate_lock(wrong_tags)

        wrong_arch = fixture("arm64")
        artifact = wrong_arch["environments"]["workspace"]["artifacts"][0]
        artifact["filename"] = "closure_demo-1.0.0-cp312-cp312-manylinux_2_17_x86_64.whl"
        artifact["tags"] = ["cp312-cp312-manylinux_2_17_x86_64"]
        with self.assertRaisesRegex(MODULE.ClosureError, "incompatible with arm64"):
            MODULE.validate_lock(wrong_arch)

    def test_universal_py2_py3_wheel_is_accepted_for_python3(self) -> None:
        value = fixture("arm64")
        artifact = value["environments"]["workspace"]["artifacts"][0]
        artifact["filename"] = "closure_demo-1.0.0-py2.py3-none-any.whl"
        artifact["tags"] = ["py2-none-any", "py3-none-any"]
        MODULE.validate_lock(value)

    def test_docling_cpu_profile_rejects_accelerator_distribution(self) -> None:
        value = fixture("arm64")
        workspace = value["environments"]["workspace"]
        workspace["qualification"] = {
            "state": "pending-artifacts",
            "blockers": ["Synthetic fixture."],
        }
        workspace["manifestSha256"] = None
        workspace["artifacts"] = []
        docling = value["environments"]["docling-cpu"]
        docling["qualification"] = {"state": "qualified", "blockers": []}
        docling["manifestSha256"] = "1" * 64
        artifact = fixture("arm64")["environments"]["workspace"]["artifacts"][0]
        artifact["name"] = "nvidia-cuda-runtime"
        artifact["filename"] = "nvidia_cuda_runtime-1.0.0-py3-none-any.whl"
        docling["artifacts"] = [artifact]
        with self.assertRaisesRegex(MODULE.ClosureError, "CPU-only"):
            MODULE.validate_lock(value)

    def test_canonical_manifests_and_extraction_receipt_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheelhouse = root / "wheelhouse"
            build_wheelhouse(wheelhouse, "arm64")
            value = fixture("arm64")
            qualify_environment(value, wheelhouse)
            lock = MODULE.validate_lock(value)
            images_lock, receipt = write_image_authorities(root, wheelhouse, "arm64")
            MODULE.validate_wheelhouse_against_lock(
                lock,
                wheelhouse=wheelhouse,
                provenance=receipt,
                images_lock=images_lock,
                environments=["workspace"],
            )
            receipt.chmod(0o600)
            receipt.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ClosureError, "receipt"):
                MODULE.validate_wheelhouse_against_lock(
                    lock,
                    wheelhouse=wheelhouse,
                    provenance=receipt,
                    images_lock=images_lock,
                    environments=["workspace"],
                )

    def test_qualified_lock_matches_all_eight_canonical_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheelhouse = root / "wheelhouse"
            build_wheelhouse(wheelhouse, "arm64")
            value = fixture("arm64")
            qualify_all(value, wheelhouse)
            lock = MODULE.validate_lock(value)
            images_lock, receipt = write_image_authorities(root, wheelhouse, "arm64")
            source = MODULE.validate_wheelhouse_against_lock(
                lock,
                wheelhouse=wheelhouse,
                provenance=receipt,
                images_lock=images_lock,
                environments=list(WHEELHOUSE.ENVIRONMENTS),
            )
            self.assertEqual(
                set(source["environments"]), set(WHEELHOUSE.ENVIRONMENTS)
            )

    def test_atomic_activation_rolls_back_a_direct_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generation = root / "generation"
            generation.mkdir()
            (generation / "new").write_text("new", encoding="utf-8")
            target = root / "target"
            target.mkdir()
            (target / "old").write_text("old", encoding="utf-8")

            def fail() -> None:
                raise RuntimeError("post-activation verification failed")

            with self.assertRaisesRegex(RuntimeError, "post-activation"):
                MODULE.activate_generation(generation, target, fail)
            self.assertFalse(target.is_symlink())
            self.assertEqual((target / "old").read_text(encoding="utf-8"), "old")
            self.assertFalse((target / "new").exists())
            self.assertFalse(
                any(path.name.startswith(".target.rollback-") for path in root.iterdir())
            )

    def test_activation_replace_fault_restores_existing_target_without_stranding_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generation = root / "generation"
            generation.mkdir()
            (generation / "new").write_text("new", encoding="utf-8")
            target = root / "target"
            target.mkdir()
            (target / "old").write_text("old", encoding="utf-8")
            real_replace = os.replace
            injected = False

            def fail_new_link(source: object, destination: object) -> None:
                nonlocal injected
                source_path = Path(source)
                if (
                    not injected
                    and Path(destination) == target
                    and source_path.name.startswith(".target.next-")
                ):
                    injected = True
                    raise OSError("injected activation replace failure")
                real_replace(source, destination)

            with mock.patch.object(MODULE.os, "replace", side_effect=fail_new_link):
                with self.assertRaisesRegex(OSError, "injected activation"):
                    MODULE.activate_generation(generation, target, lambda: None)

            self.assertTrue(injected)
            self.assertFalse(target.is_symlink())
            self.assertEqual((target / "old").read_text(encoding="utf-8"), "old")
            self.assertTrue(generation.is_dir())
            self.assertFalse(
                any(
                    path.name.startswith((".target.next-", ".target.rollback-"))
                    for path in root.iterdir()
                )
            )

    def test_activation_rename_commit_then_interrupt_restores_existing_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generation = root / "generation"
            generation.mkdir()
            target = root / "target"
            target.mkdir()
            (target / "old").write_text("old", encoding="utf-8")
            real_rename = os.rename
            injected = False

            def rename_then_interrupt(source: object, destination: object) -> None:
                nonlocal injected
                real_rename(source, destination)
                if not injected and Path(source) == target:
                    injected = True
                    raise KeyboardInterrupt("rename committed before interruption")

            with mock.patch.object(MODULE.os, "rename", side_effect=rename_then_interrupt):
                with self.assertRaisesRegex(KeyboardInterrupt, "rename committed"):
                    MODULE.activate_generation(generation, target, lambda: None)

            self.assertTrue(injected)
            self.assertFalse(target.is_symlink())
            self.assertEqual((target / "old").read_text(encoding="utf-8"), "old")
            self.assertFalse(
                any(path.name.startswith(".target.rollback-") for path in root.iterdir())
            )

    def test_activation_replace_commit_then_interrupt_removes_new_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generation = root / "generation"
            generation.mkdir()
            target = root / "target"
            real_replace = os.replace
            injected = False

            def replace_then_interrupt(source: object, destination: object) -> None:
                nonlocal injected
                real_replace(source, destination)
                if not injected and Path(destination) == target:
                    injected = True
                    raise KeyboardInterrupt("replace committed before interruption")

            with mock.patch.object(MODULE.os, "replace", side_effect=replace_then_interrupt):
                with self.assertRaisesRegex(KeyboardInterrupt, "replace committed"):
                    MODULE.activate_generation(generation, target, lambda: None)

            self.assertTrue(injected)
            self.assertFalse(os.path.lexists(target))

    def test_unmarked_symlink_is_not_treated_as_managed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "foreign"
            destination.mkdir()
            target = root / "target"
            target.symlink_to(destination, target_is_directory=True)
            self.assertFalse(MODULE._is_managed_target(target))

    def test_workspace_projection_is_relative_and_sandbox_portable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            specs = MODULE.compatibility_links(home)
            for executable in (
                home / ".local/share/coding-system/python-closure/aider/bin/aider",
                home / ".local/share/coding-system/python-closure/modal/bin/modal",
            ):
                executable.parent.mkdir(parents=True, exist_ok=True)
                executable.write_text("#!/bin/sh\n", encoding="utf-8")
                executable.chmod(0o755)
            for target, _link_value in specs.values():
                if target.name in {"aider", "modal"} and target.parent.name == "bin":
                    continue
                else:
                    target.mkdir(parents=True, exist_ok=True)
            MODULE.activate_compatibility_links(home, replace_unmanaged=True)
            workspace_link = home / ".openclaw/workspace/.local"
            self.assertEqual(
                workspace_link.readlink(),
                Path(".python-closure/workspace/lib/python3.12/site-packages"),
            )
            self.assertFalse(str(workspace_link.readlink()).startswith(str(home)))
            aas_runtime_link = (
                home / ".local/share/ai-agents-skills/runtime/workspace/.local"
            )
            self.assertEqual(
                aas_runtime_link.readlink(),
                home / ".local/share/coding-system/python-closure/shared",
            )
            MODULE.verify_compatibility_links(home)

    def test_compatibility_batch_fault_restores_every_existing_user_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            specs = MODULE.compatibility_links(home)
            for target, _link_value in specs.values():
                if target.name in {"aider", "modal"} and target.parent.name == "bin":
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("#!/bin/sh\n", encoding="utf-8")
                    target.chmod(0o755)
                else:
                    target.mkdir(parents=True, exist_ok=True)

            original_files: dict[Path, bytes] = {}
            original_directories: set[Path] = set()
            for index, link in enumerate(specs):
                link.parent.mkdir(parents=True, exist_ok=True)
                if link.name in {"aider", "modal"} and link.parent.name == "bin":
                    content = f"user executable {index}\n".encode()
                    link.write_bytes(content)
                    original_files[link] = content
                else:
                    link.mkdir(parents=True, exist_ok=True)
                    (link / ".user-state").write_text(str(index), encoding="utf-8")
                    original_directories.add(link)

            fault_link = list(specs)[3]
            real_replace = os.replace
            injected = False

            def fail_mid_batch(source: object, destination: object) -> None:
                nonlocal injected
                if (
                    not injected
                    and Path(destination) == fault_link
                    and Path(source).name.startswith(f".{fault_link.name}.next-")
                ):
                    injected = True
                    raise OSError("injected compatibility activation failure")
                real_replace(source, destination)

            with mock.patch.object(MODULE.os, "replace", side_effect=fail_mid_batch):
                with self.assertRaisesRegex(OSError, "injected compatibility"):
                    MODULE.activate_compatibility_links(home, replace_unmanaged=True)

            self.assertTrue(injected)
            for link, content in original_files.items():
                self.assertFalse(link.is_symlink())
                self.assertEqual(link.read_bytes(), content)
            for link in original_directories:
                self.assertFalse(link.is_symlink())
                self.assertTrue((link / ".user-state").is_file())
            leftovers = [
                path
                for path in home.rglob("*")
                if ".next-" in path.name or ".rollback-" in path.name
            ]
            self.assertEqual(leftovers, [])

    def test_compatibility_rename_commit_then_interrupt_restores_original_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            specs = MODULE.compatibility_links(home)
            for target, _link_value in specs.values():
                if target.name in {"aider", "modal"} and target.parent.name == "bin":
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("#!/bin/sh\n", encoding="utf-8")
                    target.chmod(0o755)
                else:
                    target.mkdir(parents=True, exist_ok=True)
            originals: dict[Path, str] = {}
            for index, link in enumerate(specs):
                link.parent.mkdir(parents=True, exist_ok=True)
                link.mkdir(parents=True, exist_ok=True)
                value = f"original-{index}"
                (link / ".state").write_text(value, encoding="utf-8")
                originals[link] = value

            first_link = next(iter(specs))
            real_rename = os.rename
            injected = False

            def rename_then_interrupt(source: object, destination: object) -> None:
                nonlocal injected
                real_rename(source, destination)
                if not injected and Path(source) == first_link:
                    injected = True
                    raise KeyboardInterrupt("compatibility rename committed")

            with mock.patch.object(MODULE.os, "rename", side_effect=rename_then_interrupt):
                with self.assertRaisesRegex(KeyboardInterrupt, "compatibility rename"):
                    MODULE.activate_compatibility_links(home, replace_unmanaged=True)

            self.assertTrue(injected)
            for link, value in originals.items():
                self.assertFalse(link.is_symlink())
                self.assertEqual((link / ".state").read_text(encoding="utf-8"), value)


class PythonClosureInstallTests(unittest.TestCase):
    def test_install_all_rejects_a_pending_lock_before_any_install(self) -> None:
        architecture = MODULE._machine_architecture(platform.machine())
        pending = json.loads(
            (ROOT / f"system/python-closure/ubuntu-24.04-{architecture}.lock.json").read_text(
                encoding="utf-8"
            )
        )
        pending["qualification"] = {"state": "pending-artifacts", "blockers": ["fixture"]}
        pending["wheelhouseManifestSha256"] = None
        for environment in pending["environments"].values():
            environment.update(
                qualification={"state": "pending-artifacts", "blockers": ["fixture"]},
                manifestSha256=None,
                artifacts=[],
            )
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / f"ubuntu-24.04-{architecture}.lock.json"
            lock.write_text(json.dumps(pending), encoding="utf-8")
            result = self.run_pending_install(lock)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not qualified", result.stderr)

    def run_pending_install(self, lock: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "install-all",
                "--lock",
                str(lock),
                "--images-lock",
                str(ROOT / "system/software/images.lock.json"),
                "--wheelhouse",
                "/nonexistent/wheelhouse",
                "--provenance",
                "/nonexistent/provenance.json",
                "--python",
                sys.executable,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_offline_install_verify_inventory_and_idempotence(self) -> None:
        architecture = MODULE._machine_architecture(platform.machine())
        value = fixture(architecture)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheelhouse = root / "wheelhouse"
            build_wheelhouse(wheelhouse, architecture)
            qualify_environment(value, wheelhouse)
            lock_path = root / "synthetic.lock.json"
            lock_path.write_text(json.dumps(value), encoding="utf-8")
            images_lock, receipt = write_image_authorities(root, wheelhouse, architecture)
            target = root / "workspace-venv"

            command = [
                sys.executable,
                str(SCRIPT),
                "install",
                "--lock",
                str(lock_path),
                "--environment",
                "workspace",
                "--target",
                str(target),
                "--wheelhouse",
                str(wheelhouse),
                "--provenance",
                str(receipt),
                "--images-lock",
                str(images_lock),
                "--python",
                sys.executable,
            ]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(json.loads(first.stdout)["status"], "installed")
            self.assertTrue(target.is_symlink())
            imported = subprocess.run(
                [
                    str(target / "bin/python"),
                    "-I",
                    "-c",
                    "import closure_demo; print(closure_demo.__version__)",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(imported.stdout.strip(), "1.0.0")

            second = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(
                json.loads(second.stdout)["environments"]["workspace"], "unchanged"
            )

            verify = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "verify",
                    "--lock",
                    str(lock_path),
                    "--environment",
                    "workspace",
                    "--target",
                    str(target),
                    "--wheelhouse",
                    str(wheelhouse),
                    "--provenance",
                    str(receipt),
                    "--images-lock",
                    str(images_lock),
                    "--python",
                    sys.executable,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertEqual(
                json.loads(verify.stdout)["environments"]["workspace"],
                {"closure-demo": "1.0.0"},
            )

            site_packages = subprocess.run(
                [
                    str(target / "bin/python"),
                    "-I",
                    "-c",
                    "import sysconfig; print(sysconfig.get_path('purelib'))",
                ],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            rogue = Path(site_packages) / "rogue-9.0.dist-info"
            Path(site_packages).chmod(0o755)
            rogue.mkdir()
            (rogue / "METADATA").write_text(
                "Metadata-Version: 2.1\nName: rogue\nVersion: 9.0\n\n", encoding="utf-8"
            )
            failed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "verify",
                    "--lock",
                    str(lock_path),
                    "--environment",
                    "workspace",
                    "--target",
                    str(target),
                    "--wheelhouse",
                    str(wheelhouse),
                    "--provenance",
                    str(receipt),
                    "--images-lock",
                    str(images_lock),
                    "--python",
                    sys.executable,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(failed.returncode, 2)
            self.assertIn("extra=rogue", failed.stderr)

    def test_verification_rejects_module_and_generated_entry_point_byte_tampering(self) -> None:
        architecture = MODULE._machine_architecture(platform.machine())
        value = fixture(architecture)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheelhouse = root / "wheelhouse"
            build_wheelhouse(wheelhouse, architecture)
            qualify_environment(value, wheelhouse)
            lock_path = root / "synthetic.lock.json"
            lock_path.write_text(json.dumps(value), encoding="utf-8")
            images_lock, receipt = write_image_authorities(root, wheelhouse, architecture)
            target = root / "workspace-venv"
            command = [
                sys.executable,
                str(SCRIPT),
                "install",
                "--lock",
                str(lock_path),
                "--environment",
                "workspace",
                "--target",
                str(target),
                "--wheelhouse",
                str(wheelhouse),
                "--provenance",
                str(receipt),
                "--images-lock",
                str(images_lock),
                "--python",
                sys.executable,
            ]
            installed = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            verify_command = [*command]
            verify_command[2] = "verify"

            site_packages = subprocess.run(
                [
                    str(target / "bin/python"),
                    "-I",
                    "-c",
                    "import sysconfig; print(sysconfig.get_path('purelib'))",
                ],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            module = Path(site_packages) / "closure_demo/__init__.py"
            original_module = module.read_bytes()
            module.chmod(0o644)
            module.write_bytes(original_module + b"# module byte tamper\n")
            module_failure = subprocess.run(
                verify_command, capture_output=True, text=True, check=False
            )
            self.assertEqual(module_failure.returncode, 2)
            self.assertIn("package/module or entry-point bytes differ", module_failure.stderr)

            module.write_bytes(original_module)
            module.chmod(0o444)
            clean = subprocess.run(
                verify_command, capture_output=True, text=True, check=False
            )
            self.assertEqual(clean.returncode, 0, clean.stderr)

            entry_point = target / "bin/closure-demo"
            self.assertTrue(entry_point.is_file())
            original_entry_point = entry_point.read_bytes()
            entry_point.chmod(0o755)
            entry_point.write_bytes(original_entry_point + b"# entry-point byte tamper\n")
            entry_point_failure = subprocess.run(
                verify_command, capture_output=True, text=True, check=False
            )
            self.assertEqual(entry_point_failure.returncode, 2)
            self.assertIn(
                "package/module or entry-point bytes differ", entry_point_failure.stderr
            )


if __name__ == "__main__":
    unittest.main()
