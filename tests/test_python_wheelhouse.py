#!/usr/bin/env python3
"""Focused contract tests for the artifact-only Python wheelhouse."""

from __future__ import annotations

import base64
from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
LIB_DIR = ROOT / "system/docker/python-wheelhouse"
import sys
sys.path.insert(0, str(LIB_DIR))
import wheelhouse_lib as LIB
sys.path.insert(0, str(ROOT / "system/python-closure"))
import runtime_lib as RUNTIME

EXTRACT_SPEC = importlib.util.spec_from_file_location(
    "extract_python_wheelhouse", ROOT / "bin/extract-python-wheelhouse.py"
)
assert EXTRACT_SPEC and EXTRACT_SPEC.loader
EXTRACT = importlib.util.module_from_spec(EXTRACT_SPEC)
EXTRACT_SPEC.loader.exec_module(EXTRACT)


def wheel_bytes(name: str, version: str = "1.0.0") -> bytes:
    distribution = name.replace("-", "_")
    dist_info = f"{distribution}-{version}.dist-info"
    files: dict[str, bytes] = {
        f"{distribution}/__init__.py": f"__version__ = {version!r}\n".encode(),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {name}\n"
            f"Version: {version}\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: coding-system-rebuild-test\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n\n"
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


def synthetic_wheelhouse(root: Path, platform_name: str = "linux/amd64") -> None:
    root.mkdir()
    for environment in LIB.ENVIRONMENTS:
        directory = root / environment
        directory.mkdir()
        name = f"demo-{environment}"
        filename = f"{name.replace('-', '_')}-1.0.0-py3-none-any.whl"
        (directory / filename).write_bytes(wheel_bytes(name))
        if environment == "docling-cpu":
            for package, version in (("torch", "2.11.0+cpu"), ("torchvision", "0.26.0+cpu")):
                cpu_filename = f"{package}-{version}-py3-none-any.whl"
                (directory / cpu_filename).write_bytes(wheel_bytes(package, version))
    LIB.build_manifests(root, platform_name)


def tar_wheelhouse(root: Path) -> io.BytesIO:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        archive.add(root, arcname="wheelhouse", recursive=True)
    output.seek(0)
    return output


class WheelhouseManifestTests(unittest.TestCase):
    def test_canonical_manifests_bind_all_wheel_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "wheelhouse"
            synthetic_wheelhouse(root)
            index = LIB.validate_wheelhouse(root, "linux/amd64")
            self.assertEqual([item["name"] for item in index["environments"]], list(LIB.ENVIRONMENTS))
            wheel = next((root / "workspace").glob("*.whl"))
            wheel.write_bytes(wheel.read_bytes() + b"tampered")
            with self.assertRaisesRegex(LIB.WheelhouseError, "inspect wheel|inventory|digest"):
                LIB.validate_wheelhouse(root, "linux/amd64")

    def test_docling_rejects_accelerator_and_non_cpu_torch(self) -> None:
        for package, version in (("nvidia-cuda-runtime", "1.0.0"), ("torch", "2.11.0")):
            with self.subTest(package=package), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "wheelhouse"
                synthetic_wheelhouse(root)
                directory = root / "docling-cpu"
                if package == "torch":
                    next(directory.glob("torch-2.11.0+cpu-*.whl")).unlink()
                filename = f"{package.replace('-', '_')}-{version}-py3-none-any.whl"
                (directory / filename).write_bytes(wheel_bytes(package, version))
                with self.assertRaisesRegex(LIB.WheelhouseError, "accelerator|non-CPU"):
                    LIB.build_manifests(root, "linux/amd64")

    def test_docling_requires_both_cpu_torch_wheels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "wheelhouse"
            synthetic_wheelhouse(root)
            next((root / "docling-cpu").glob("torchvision-*.whl")).unlink()
            with self.assertRaisesRegex(LIB.WheelhouseError, "missing required CPU wheels"):
                LIB.build_manifests(root, "linux/amd64")


class LockedExtractionTests(unittest.TestCase):
    def test_selects_exact_digest_only_platform_image(self) -> None:
        digest = "sha256:" + "1" * 64
        platform_digest = "sha256:" + "2" * 64
        value = {
            "schema_version": 1,
            "images": [
                {
                    "id": "python-wheelhouse",
                    "roles": ["python-wheelhouse"],
                    "repository": "ghcr.io/example/python-wheelhouse",
                    "reference": f"ghcr.io/example/python-wheelhouse@{digest}",
                    "index_digest": digest,
                    "platforms": {"linux/amd64": platform_digest},
                    "evidence": "candidate workflow",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "images.lock.json"
            lock.write_text(json.dumps(value), encoding="utf-8")
            selected = EXTRACT.load_locked_image(lock, "amd64")
            self.assertEqual(selected["platform_digest"], platform_digest)
            value["images"][0]["reference"] = "ghcr.io/example/python-wheelhouse:latest"
            lock.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(EXTRACT.ExtractError, "digest-only"):
                EXTRACT.load_locked_image(lock, "amd64")

    def test_registry_index_binds_raw_and_platform_digests(self) -> None:
        platform_digest = "sha256:" + "2" * 64
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "digest": platform_digest,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "platform": {"os": "linux", "architecture": "amd64"},
                }
            ],
        }
        raw = json.dumps(manifest, separators=(",", ":")).encode()
        image = {
            "reference": "ghcr.io/example/wheels@sha256:" + "0" * 64,
            "index_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "platform_digest": platform_digest,
            "platform": "linux/amd64",
        }
        with mock.patch.object(EXTRACT, "run_bounded", return_value=raw):
            EXTRACT.verify_registry_manifest(["docker"], image)
        broken = dict(image, platform_digest="sha256:" + "3" * 64)
        with mock.patch.object(EXTRACT, "run_bounded", return_value=raw), self.assertRaisesRegex(
            EXTRACT.ExtractError, "absent or ambiguous"
        ):
            EXTRACT.verify_registry_manifest(["docker"], broken)

    def test_extraction_receipt_binds_image_lock_and_root_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheelhouse = root / "wheelhouse"
            synthetic_wheelhouse(wheelhouse)
            digest = "sha256:" + "1" * 64
            lock = root / "images.lock.json"
            value = {
                "schema_version": 1,
                "images": [
                    {
                        "id": "python-wheelhouse",
                        "roles": ["python-wheelhouse"],
                        "repository": "ghcr.io/example/python-wheelhouse",
                        "reference": f"ghcr.io/example/python-wheelhouse@{digest}",
                        "index_digest": digest,
                        "platforms": {"linux/amd64": "sha256:" + "2" * 64},
                        "evidence": "synthetic",
                    }
                ],
            }
            lock.write_text(json.dumps(value), encoding="utf-8")
            image = RUNTIME.load_locked_image(lock, "amd64")
            receipt = root / "receipt.json"
            RUNTIME.write_provenance(
                receipt, RUNTIME.expected_provenance(image, wheelhouse)
            )
            RUNTIME.verify_provenance(
                receipt,
                wheelhouse=wheelhouse,
                images_lock=lock,
                architecture="amd64",
            )
            value["images"][0]["evidence"] = "changed lock bytes"
            lock.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "receipt differs"):
                RUNTIME.verify_provenance(
                    receipt,
                    wheelhouse=wheelhouse,
                    images_lock=lock,
                    architecture="amd64",
                )

    def test_bounded_tar_extract_accepts_contract_and_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            synthetic_wheelhouse(source)
            destination = base / "destination"
            destination.mkdir()
            EXTRACT.extract_bounded_tar(tar_wheelhouse(source), destination)
            LIB.validate_wheelhouse(destination, "linux/amd64")

            hostile = io.BytesIO()
            with tarfile.open(fileobj=hostile, mode="w") as archive:
                value = b"escape"
                info = tarfile.TarInfo("wheelhouse/../escape")
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
            hostile.seek(0)
            with self.assertRaisesRegex(EXTRACT.ExtractError, "unsafe archive path"):
                EXTRACT.extract_bounded_tar(hostile, base / "hostile")

    def test_bounded_tar_rejects_links_and_undeclared_paths(self) -> None:
        cases = []
        link_tar = io.BytesIO()
        with tarfile.open(fileobj=link_tar, mode="w") as archive:
            root = tarfile.TarInfo("wheelhouse")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            item = tarfile.TarInfo("wheelhouse/link")
            item.type = tarfile.SYMTYPE
            item.linkname = "/etc/passwd"
            archive.addfile(item)
        link_tar.seek(0)
        cases.append(link_tar)

        extra_tar = io.BytesIO()
        with tarfile.open(fileobj=extra_tar, mode="w") as archive:
            root = tarfile.TarInfo("wheelhouse")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            value = b"no"
            item = tarfile.TarInfo("wheelhouse/unexpected.txt")
            item.size = len(value)
            archive.addfile(item, io.BytesIO(value))
        extra_tar.seek(0)
        cases.append(extra_tar)

        for value in cases:
            with self.subTest(), tempfile.TemporaryDirectory() as temporary, self.assertRaises(EXTRACT.ExtractError):
                EXTRACT.extract_bounded_tar(value, Path(temporary))


class DeliveryDefinitionTests(unittest.TestCase):
    def test_artifact_image_and_native_workflow_are_fail_closed(self) -> None:
        dockerfile = (LIB_DIR / "Dockerfile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/python-wheelhouse.yml").read_text(encoding="utf-8")
        offline_verifier = (LIB_DIR / "verify-offline.py").read_text(encoding="utf-8")
        inputs = json.loads((LIB_DIR / "build-inputs.json").read_text(encoding="utf-8"))
        self.assertIn("FROM scratch AS artifact", dockerfile)
        final = dockerfile.split("FROM scratch AS artifact", 1)[1]
        self.assertNotRegex(final, r"\bRUN\b|apt-get|pip install")
        self.assertIn("ubuntu-24.04-arm", workflow)
        self.assertIn("ubuntu-24.04", workflow)
        self.assertIn("--no-index", offline_verifier)
        self.assertIn("github.event_name == 'workflow_dispatch'", workflow)
        self.assertNotIn("github.event_name != 'pull_request'", workflow)
        self.assertNotIn("images.lock.json'", workflow)
        self.assertEqual(len(inputs["pureSdistWheels"]), 6)
        self.assertTrue(all(re.search(r"@[0-9a-f]{40}$", item["requirement"]) for item in inputs["gitWheels"]))
        self.assertTrue(
            all(
                spec["strategy"] == ("frozen-no-deps" if name == "getscipapers" else "resolve")
                for name, spec in inputs["environments"].items()
            )
        )
        docling = inputs["environments"]["docling-cpu"]
        self.assertTrue(all("+cpu" in pin for pin in docling["cpuPyTorch"]))
        self.assertEqual(
            inputs["environments"]["getscipapers"]["supplementalRequirements"],
            ["Pygments==2.20.0"],
        )
        self.assertEqual(
            inputs["environments"]["getscipapers"]["requiredGitWheels"],
            ["getscipapers-hoanganhduc", "crossrefapi"],
        )
        self.assertEqual(
            inputs["environments"]["course-management"]["requiredGitWheels"],
            ["course-hoanganhduc"],
        )

    def test_restore_uses_only_the_locked_offline_python_path(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        prepare = (ROOT / "bin/prepare.sh").read_text(encoding="utf-8")
        verify = (ROOT / "bin/verify.sh").read_text(encoding="utf-8")
        phase_nine = install.split("# 9 ─ python environments", 1)[1].split(
            "# 10 ─ docker images", 1
        )[0]
        self.assertIn("extract-python-wheelhouse.py", phase_nine)
        self.assertIn("install-python-closure.py\" install-all", phase_nine)
        self.assertIn("install-python-closure.py\" verify-all", phase_nine)
        self.assertNotRegex(phase_nine, r"pip\s+install")
        self.assertNotRegex(prepare, r"pipx\s+install|python3\s+-m\s+pip\s+install")
        self.assertIn("install-python-closure.py\" verify-all", verify)

    def test_openclaw_sandbox_uses_isolated_canonical_wheel_environments(self) -> None:
        lock = json.loads(
            (ROOT / "system/openclaw/compatibility.lock.json").read_text(encoding="utf-8")
        )
        if lock["sandbox"]["contract"] < 3:
            self.skipTest("the locked sandbox contract predates the canonical wheel environments (D14)")
        dockerfile = (
            ROOT / "system/docker/openclaw-sandbox/Dockerfile"
        ).read_text(encoding="utf-8")
        verifier = (
            ROOT / "system/docker/openclaw-sandbox/verify.sh"
        ).read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github/workflows/openclaw-sandbox.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("build-wheelhouse.py", dockerfile)
        self.assertIn('--platform "linux/${TARGETARCH}"', dockerfile)
        for environment in ("docling-cpu", "lean-explore"):
            self.assertIn(
                f"/opt/coding-system/python-closure/{environment}", dockerfile
            )
            self.assertIn(
                f"verify_isolated_inventory {environment}", verifier
            )
        self.assertIn(
            "ENV HOME=/workspace OPENCLAW_WORKSPACE=/workspace", dockerfile
        )
        self.assertIn("--no-index --no-deps --no-compile", dockerfile)
        self.assertIn("metadata.distributions()", verifier)
        self.assertIn('assert "+cpu" in torch.__version__', verifier)
        self.assertIn("system/docker/python-wheelhouse/**", workflow)
        self.assertIn("system/packages/requirements/**", workflow)
        self.assertIn("--network none", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
