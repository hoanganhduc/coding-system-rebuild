#!/usr/bin/env python3
"""Regression tests for the bare-host Grok bootstrap artifact closure."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
BIN = REPO / "bin"
sys.path.insert(0, str(BIN))

from lib.grok_bootstrap_release import (  # noqa: E402
    AUTHORIZATION_NAMES,
    DER_PREFIX,
    ReleaseError,
    SIGNED_NAMES,
    artifact_record,
    canonical_json,
    core_artifact_names,
    load_lock,
    open_artifact_set,
    open_verified_artifact,
    release_authorization_payload,
    validate_lock,
    verify_artifact,
    verify_signed_dispatcher,
    verify_signed_dispatcher_descriptors,
)


LOCK = REPO / "system/grok-proxy/bootstrap/release.lock.json"
PROVISIONER = BIN / "provision-grok-bootstrap.py"
PROMOTER = BIN / "promote-grok-bootstrap-release.py"
EXPORTER = BIN / "export-signed-grok-dispatcher.py"
BUILD_BUNDLE = REPO / "system/grok-proxy/bootstrap/build_bundle.py"


class GrokBootstrapLockTests(unittest.TestCase):
    def test_checked_in_pending_lock_is_real_and_blocks_provisioning(self) -> None:
        lock = load_lock(LOCK)
        self.assertEqual(lock["state"], "pending-publication")
        self.assertEqual(
            lock["trust_anchor"],
            {
                "key_id": "grok-dispatch-prod-2026-07-v1",
                "public_key_hex": "b8b25772f3f7a192d7ee7cd20b3f6c00f93d2e580ee518feb6a91c7e21aa2b81",
            },
        )
        expected_authorization_key = " ".join(
            (REPO / "system/recovery/recovery-signing-public-key.pub")
            .read_text(encoding="ascii")
            .split()[:2]
        )
        self.assertEqual(
            lock["release_authorization_anchor"],
            {
                "identity": "coding-system-rebuild",
                "namespace": "grok-bootstrap-release-authorization",
                "public_key": expected_authorization_key,
            },
        )
        self.assertIn(
            "bc6c611f32a1420558cf3ff4e01a813f13dfcb526800dd8d3cf211be8275a08e",
            lock["pending_reason"],
        )
        checked = subprocess.run(
            [sys.executable, "-I", "-B", str(PROVISIONER), "--check-lock"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr.decode("utf-8"))
        provisioned = subprocess.run(
            [sys.executable, "-I", "-B", str(PROVISIONER)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(provisioned.returncode, 3)
        self.assertIn(b"ARTIFACT_UNAVAILABLE", provisioned.stderr)
        qualified_gate = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(PROVISIONER),
                "--require-qualified-lock",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(qualified_gate.returncode, 3)
        self.assertIn(b"ARTIFACT_UNAVAILABLE", qualified_gate.stderr)

    def test_qualified_lock_rejects_non_repository_asset_url(self) -> None:
        version = "1.1.0+test"
        tag = "grok-bootstrap-v1.1.0-test"
        names = {
            "dispatcher.pyz",
            "release-authorization.json",
            "release-authorization.sig",
            "release-manifest.sig",
            "release-manifest.txt",
            f"grok-bootstrap_{version}_amd64.deb",
            f"grok-bootstrap_{version}_arm64.deb",
        }
        artifacts = {
            name: {
                "name": name,
                "sha256": "a" * 64,
                "size": 1,
                "url": f"https://example.invalid/{name}",
            }
            for name in names
        }
        value = {
            "$schema": "release-lock.schema.json",
            "schema_version": "grok-bootstrap-release-lock.v1",
            "state": "qualified",
            "release_authorization_anchor": {
                "identity": "coding-system-rebuild",
                "namespace": "grok-bootstrap-release-authorization",
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMhRCwEen79Czp0YyfreBiMsG1WUk4G0NbuefxH6BQaH",
            },
            "trust_anchor": {
                "key_id": "test-key",
                "public_key_hex": "b" * 64,
            },
            "release": {
                "artifacts": artifacts,
                "authorization_id": "e" * 64,
                "package_version": version,
                "signed_application_id": "c" * 64,
                "source_commit": "d" * 40,
                "tag": tag,
            },
        }
        with self.assertRaisesRegex(ReleaseError, "repository-controlled"):
            validate_lock(value)

    def test_skip_grok_turns_off_only_the_grok_gates_and_release(self) -> None:
        install = (BIN / "install.sh").read_text(encoding="utf-8")
        before_phase_one = install[: install.index("# 1 ─ bootstrap checks")]
        self.assertLess(
            before_phase_one.index('if [[ "${SKIP_GROK:-0}" == "1" ]]; then'),
            before_phase_one.index("--require-qualified-lock"),
        )
        phase_six = install[install.index("# 6 ─ render public configs"): install.index("# 7 ─ OpenClaw slice")]
        guard = phase_six.index("if skip_enabled SKIP_GROK; then")
        self.assertLess(guard, phase_six.index("--verify-installed"))
        self.assertIn('RENDER_ARGS+=(--skip-grok-release)', phase_six)
        self.assertIn('bash "$REPO/bin/render-install.sh" "${RENDER_ARGS[@]}"', phase_six)
        self.assertLess(
            phase_six.index("if ! skip_enabled SKIP_GROK; then"),
            phase_six.index("  structured_grok_release_gate"),
        )

    def test_one_command_restore_and_release_workflows_keep_the_grok_gates(self) -> None:
        prepare = (BIN / "prepare.sh").read_text(encoding="utf-8")
        install = (BIN / "install.sh").read_text(encoding="utf-8")
        rehearsal = (REPO / ".github/workflows/rehearsal.yml").read_text(
            encoding="utf-8"
        )
        build = (REPO / ".github/workflows/grok-bootstrap-build.yml").read_text(
            encoding="utf-8"
        )
        promote = (REPO / ".github/workflows/grok-bootstrap-promote.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('python3 -I -B "$GROK_BOOTSTRAP_PROVISIONER"', prepare)
        self.assertIn(
            'python3 -I -B "$REPO/bin/provision-grok-bootstrap.py" --verify-installed',
            install,
        )
        qualified_gate = install.index(
            '"$REPO/bin/provision-grok-bootstrap.py" --require-qualified-lock'
        )
        phase_one = install.index('# 1 ─ bootstrap checks')
        self.assertLess(qualified_gate, phase_one)
        self.assertIn('if [[ $DEGRADED_MODE -eq 0 ]]; then', install[:qualified_gate])
        self.assertIn("bin/provision-grok-bootstrap.py --check-lock", rehearsal)
        self.assertIn("tests/test_grok_bootstrap_provision.py", rehearsal)
        self.assertIn("runner: ubuntu-24.04", build)
        self.assertIn("runner: ubuntu-24.04-arm", build)
        self.assertIn(
            "uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d", build
        )
        self.assertIn("persist-credentials: false", build)
        self.assertIn("environment: grok-bootstrap-build", build)
        self.assertNotIn("PRIVATE_KEY", build)
        self.assertNotIn("signing-key", build)
        self.assertIn("draft release must initially contain exactly", promote)
        self.assertIn("environment: grok-bootstrap-verify", promote)
        self.assertIn("environment: grok-bootstrap-publish", promote)
        self.assertIn('publish_review.get("prevent_self_review") is not True', promote)
        self.assertIn("gh attestation verify", promote)
        self.assertIn("--signer-workflow", promote)
        self.assertIn("trap cleanup EXIT", promote)
        self.assertIn("releases/assets/$asset_id", promote)
        self.assertIn("upload_and_record", promote)
        self.assertIn("persist-credentials: false", promote)
        self.assertNotRegex(build + promote, r"uses:\s+[^\s]+@v[0-9]+(?:\s|$)")
        self.assertIn("promote-grok-bootstrap-release.py", promote)
        self.assertNotIn("PRIVATE_KEY", promote)
        self.assertNotIn("signing-key", promote)


@unittest.skipUnless(
    Path("/usr/bin/openssl").is_file()
    and Path("/usr/bin/dpkg-deb").is_file()
    and Path("/usr/bin/ssh-keygen").is_file(),
    "OpenSSL, OpenSSH, and dpkg-deb are required",
)
class GrokBootstrapPromotionTests(unittest.TestCase):
    VERSION = "1.1.0+test"
    SOURCE_COMMIT = "1" * 40
    TAG = "grok-bootstrap-v1.1.0-test"
    KEY_ID = "promotion-test-key"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="grok-bootstrap-promotion-")
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(mode=0o700)
        self.key = self.root / "key.pem"
        self._checked(
            [
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(self.key),
            ]
        )
        public_der = self._checked(
            [
                "/usr/bin/openssl",
                "pkey",
                "-in",
                str(self.key),
                "-pubout",
                "-outform",
                "DER",
            ]
        ).stdout
        self.assertTrue(public_der.startswith(DER_PREFIX))
        self.public_key_hex = public_der[len(DER_PREFIX) :].hex()
        self.authorization_key = self.root / "authorization-key"
        self._checked(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "grok authorization test",
                "-f",
                str(self.authorization_key),
            ]
        )
        self.authorization_public_key = " ".join(
            (self.authorization_key.with_suffix(".pub"))
            .read_text(encoding="ascii")
            .split()[:2]
        )
        self.authorization_anchor = {
            "identity": "coding-system-rebuild",
            "namespace": "grok-bootstrap-release-authorization",
            "public_key": self.authorization_public_key,
        }
        self.base_lock = self.root / "base-lock.json"
        self.base_lock.write_text(
            json.dumps(
                {
                    "$schema": "release-lock.schema.json",
                    "schema_version": "grok-bootstrap-release-lock.v1",
                    "state": "pending-publication",
                    "release_authorization_anchor": self.authorization_anchor,
                    "trust_anchor": {
                        "key_id": self.KEY_ID,
                        "public_key_hex": self.public_key_hex,
                    },
                    "pending_intent": {
                        "authorization_schema": "grok-bootstrap-release-authorization-v1",
                        "minimum_package_version": "1.1.0",
                        "operation": "initial-qualification",
                        "required_architectures": ["amd64", "arm64"],
                        "signed_application_id": "0" * 64,
                        "workflow_ref": "refs/heads/main",
                    },
                    "pending_reason": "test assets are not published",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self._build_signed_dispatcher()
        base_value = json.loads(self.base_lock.read_text(encoding="utf-8"))
        base_value["pending_intent"]["signed_application_id"] = self.release_id
        self.base_lock.write_bytes(canonical_json(base_value))
        for architecture in ("amd64", "arm64"):
            self._build_minimal_deb(architecture)
        self._build_release_authorization()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _checked(self, command: list[str]) -> subprocess.CompletedProcess[bytes]:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))
        return completed

    def _build_signed_dispatcher(self) -> None:
        source = self.root / "source"
        output = self.root / "signed"
        source.mkdir()
        output.mkdir()
        (source / "__main__.py").write_text("print('signed test')\n", encoding="utf-8")
        release = Path(
            self._checked(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(BUILD_BUNDLE),
                    "--source",
                    str(source),
                    "--output",
                    str(output),
                    "--key-id",
                    self.KEY_ID,
                    "--signing-key",
                    str(self.key),
                ]
            ).stdout.decode("utf-8").strip()
        )
        self.signed_release = release
        self.release_id = release.name
        for path in release.iterdir():
            shutil.copyfile(path, self.artifacts / path.name)

    def _build_minimal_deb(
        self,
        architecture: str,
        *,
        public_key_hex: str | None = None,
        destination_root: Path | None = None,
    ) -> None:
        stage = self.root / f"deb-{architecture}-{len(list(self.root.glob(f'deb-{architecture}-*')))}"
        control = stage / "DEBIAN"
        control.mkdir(parents=True)
        stage.chmod(0o755)
        control.chmod(0o755)
        (control / "control").write_text(
            "\n".join(
                [
                    "Package: grok-bootstrap",
                    f"Version: {self.VERSION}",
                    f"Architecture: {architecture}",
                    "Section: admin",
                    "Priority: optional",
                    "Maintainer: Grok Bootstrap Maintainers <root@localhost>",
                    "Depends: python3 (>= 3.10), binutils, libssl3t64 | libssl3",
                    f"X-Grok-Source-Commit: {self.SOURCE_COMMIT}",
                    "Description: authenticated pre-import Grok release bootstrap",
                    " Installs one closed package-owned bootstrap generation.",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (control / "control").chmod(0o644)
        payload = stage / "usr/lib/grok-bootstrap-package"
        activator = stage / "usr/libexec/grok-bootstrap-package"
        payload.mkdir(parents=True)
        activator.mkdir(parents=True)
        (stage / "usr").chmod(0o755)
        (stage / "usr/lib").chmod(0o755)
        (stage / "usr/libexec").chmod(0o755)
        anchor = self.public_key_hex if public_key_hex is None else public_key_hex
        native = payload / "grok-bootstrap"
        native.write_bytes(
            b"\x7fELF-test\x00"
            + self.KEY_ID.encode("ascii")
            + b"\x00"
            + anchor.encode("ascii")
            + b"\x00"
        )
        native.chmod(0o555)
        for path, raw, mode in (
            (payload / "grok-bootstrap-publisher.py", b"# publisher\n", 0o444),
            (payload / "grok-bootstrap-publisher", b"ELF-publisher\n", 0o555),
            (activator / "activate_package.py", b"# activator\n", 0o444),
            (
                activator / "grok-bootstrap-package-activate",
                b"ELF-activator\n",
                0o555,
            ),
        ):
            path.write_bytes(raw)
            path.chmod(mode)
        payload.chmod(0o555)
        activator.chmod(0o555)
        destination_directory = self.artifacts if destination_root is None else destination_root
        destination = destination_directory / f"grok-bootstrap_{self.VERSION}_{architecture}.deb"
        if destination.exists():
            destination.unlink()
        self._checked(
            [
                "/usr/bin/dpkg-deb",
                "--build",
                "--root-owner-group",
                "--uniform-compression",
                "--threads-max=1",
                "-Zgzip",
                "-z9",
                "-Snone",
                str(stage),
                str(destination),
            ]
        )

    def _build_release_authorization(self) -> None:
        records = {
            name: artifact_record(self.artifacts / name, tag=self.TAG)
            for name in core_artifact_names(self.VERSION)
        }
        payload = release_authorization_payload(
            artifacts=records,
            package_version=self.VERSION,
            signed_application_id=self.release_id,
            source_commit=self.SOURCE_COMMIT,
            tag=self.TAG,
            trust_anchor={
                "key_id": self.KEY_ID,
                "public_key_hex": self.public_key_hex,
            },
            authorization_anchor=self.authorization_anchor,
        )
        authorization = self.artifacts / "release-authorization.json"
        signature = self.artifacts / "release-authorization.sig"
        authorization.write_bytes(canonical_json(payload))
        signed = self._checked(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(self.authorization_key),
                "-n",
                self.authorization_anchor["namespace"],
                str(authorization),
            ]
        )
        self.assertIn(b"Signing file", signed.stderr)
        os.replace(authorization.with_suffix(".json.sig"), signature)

    def test_promotion_emits_a_real_dual_arch_lock_and_detects_tampering(self) -> None:
        output = self.root / "candidate.json"
        completed = self._checked(
            [
                sys.executable,
                "-I",
                "-B",
                str(PROMOTER),
                "--artifact-dir",
                str(self.artifacts),
                "--tag",
                self.TAG,
                "--package-version",
                self.VERSION,
                "--source-commit",
                self.SOURCE_COMMIT,
                "--base-lock",
                str(self.base_lock),
                "--output",
                str(output),
            ]
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["signed_application_id"], self.release_id)
        lock = load_lock(output, require_qualified=True)
        self.assertEqual(lock["release"]["signed_application_id"], self.release_id)
        verify_signed_dispatcher(
            self.artifacts,
            key_id=self.KEY_ID,
            public_key_hex=self.public_key_hex,
            expected_release_id=self.release_id,
            require_exact_inventory=False,
        )
        dispatcher = self.artifacts / "dispatcher.pyz"
        dispatcher.write_bytes(dispatcher.read_bytes() + b"tamper")
        with self.assertRaisesRegex(ReleaseError, "differs from its release lock"):
            verify_artifact(dispatcher, lock["release"]["artifacts"]["dispatcher.pyz"])

    def test_signed_dispatcher_export_needs_no_private_key(self) -> None:
        exported = self.root / "public-export"
        specification = importlib.util.spec_from_file_location(
            "grok_signed_export_test", EXPORTER
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        module.export_signed_dispatcher(
            self.signed_release,
            exported,
            self.release_id,
            lock_path=self.base_lock,
        )
        self.assertEqual({path.name for path in exported.iterdir()}, set(SIGNED_NAMES))
        self.assertNotIn(self.key.name, {path.name for path in exported.iterdir()})
        verify_signed_dispatcher(
            exported,
            key_id=self.KEY_ID,
            public_key_hex=self.public_key_hex,
            expected_release_id=self.release_id,
        )

    def test_signed_dispatcher_verification_uses_held_descriptors(self) -> None:
        held_root = self.root / "held-signed"
        held_root.mkdir(mode=0o700)
        for name in SIGNED_NAMES:
            shutil.copyfile(self.artifacts / name, held_root / name)
        directory_fd, descriptors = open_artifact_set(held_root, set(SIGNED_NAMES))
        try:
            original = held_root / "release-manifest.txt"
            renamed = held_root / "release-manifest.original"
            original.rename(renamed)
            original.write_text("attacker replacement\n", encoding="ascii")
            verified = verify_signed_dispatcher_descriptors(
                descriptors,
                key_id=self.KEY_ID,
                public_key_hex=self.public_key_hex,
                expected_release_id=self.release_id,
            )
            self.assertEqual(verified, self.release_id)
        finally:
            for descriptor in descriptors.values():
                os.close(descriptor)
            os.close(directory_fd)

    def _promote(self, output: Path, *, base_lock: Path | None = None) -> subprocess.CompletedProcess[bytes]:
        command = [
            sys.executable,
            "-I",
            "-B",
            str(PROMOTER),
            "--artifact-dir",
            str(self.artifacts),
            "--tag",
            self.TAG,
            "--package-version",
            self.VERSION,
            "--source-commit",
            self.SOURCE_COMMIT,
            "--base-lock",
            str(self.base_lock if base_lock is None else base_lock),
            "--output",
            str(output),
        ]
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )

    def test_promotion_rejects_any_debian_maintainer_script(self) -> None:
        package = self.artifacts / f"grok-bootstrap_{self.VERSION}_amd64.deb"
        extracted = self.root / "maintainer-script-package"
        self._checked(["/usr/bin/dpkg-deb", "--raw-extract", str(package), str(extracted)])
        preinst = extracted / "DEBIAN/preinst"
        preinst.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        preinst.chmod(0o755)
        replacement = self.root / package.name
        self._checked(
            [
                "/usr/bin/dpkg-deb",
                "--build",
                "--root-owner-group",
                "--uniform-compression",
                "--threads-max=1",
                "-Zgzip",
                "-z9",
                "-Snone",
                str(extracted),
                str(replacement),
            ]
        )
        os.replace(replacement, package)
        completed = self._promote(self.root / "maintainer-script-candidate.json")
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"maintainer script", completed.stderr)

    def test_promotion_rejects_wrong_embedded_public_key(self) -> None:
        self._build_minimal_deb("amd64", public_key_hex="f" * 64)
        completed = self._promote(self.root / "wrong-key-candidate.json")
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"embed the locked trust anchor", completed.stderr)

    def test_promotion_rejects_wrong_authorization_signature(self) -> None:
        wrong_key = self.root / "wrong-authorization-key"
        self._checked(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(wrong_key),
            ]
        )
        self._checked(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(wrong_key),
                "-n",
                self.authorization_anchor["namespace"],
                str(self.artifacts / "release-authorization.json"),
            ]
        )
        os.replace(
            self.artifacts / "release-authorization.json.sig",
            self.artifacts / "release-authorization.sig",
        )
        completed = self._promote(self.root / "wrong-signature-candidate.json")
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"release authorization signature is invalid", completed.stderr)

    def test_promotion_rejects_qualified_to_qualified_transition(self) -> None:
        first = self.root / "first-candidate.json"
        self.assertEqual(self._promote(first).returncode, 0)
        second = self._promote(self.root / "second-candidate.json", base_lock=first)
        self.assertEqual(second.returncode, 2)
        self.assertIn(b"qualified-to-qualified", second.stderr)

    def test_promotion_rejects_version_below_pending_intent(self) -> None:
        value = json.loads(self.base_lock.read_text(encoding="utf-8"))
        value["pending_intent"]["minimum_package_version"] = "9.0.0"
        minimum_lock = self.root / "minimum-lock.json"
        minimum_lock.write_bytes(canonical_json(value))
        completed = self._promote(
            self.root / "downgrade-candidate.json", base_lock=minimum_lock
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"below the pending intent minimum", completed.stderr)

    def test_authorization_request_is_canonical_and_excludes_a_signature(self) -> None:
        core = self.root / "core"
        core.mkdir(mode=0o700)
        for name in core_artifact_names(self.VERSION):
            shutil.copyfile(self.artifacts / name, core / name)
        output = self.root / "authorization-request.json"
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(PROMOTER),
                "--emit-authorization-request",
                "--artifact-dir",
                str(core),
                "--tag",
                self.TAG,
                "--package-version",
                self.VERSION,
                "--source-commit",
                self.SOURCE_COMMIT,
                "--base-lock",
                str(self.base_lock),
                "--output",
                str(output),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))
        value = json.loads(output.read_text(encoding="ascii"))
        self.assertEqual(output.read_bytes(), canonical_json(value))
        self.assertEqual(set(value["artifacts"]), set(core_artifact_names(self.VERSION)))
        self.assertNotIn("signature", value)


class GrokBootstrapHeldDescriptorTests(unittest.TestCase):
    def test_symlink_swap_cannot_turn_root_import_into_a_read_primitive(self) -> None:
        specification = importlib.util.spec_from_file_location(
            "grok_bootstrap_provision_test", PROVISIONER
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix="grok-held-descriptor-") as temporary:
            root = Path(temporary)
            source = root / "source.deb"
            sentinel = root / "root-only-sentinel"
            original = b"authorized-public-artifact"
            secret = b"ROOT-ONLY-SECRET-MUST-NOT-LEAK"
            source.write_bytes(original)
            sentinel.write_bytes(secret)
            sentinel.chmod(0o000)
            descriptor = open_verified_artifact(source)
            commands: list[list[str]] = []
            imported: list[bytes] = []

            def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                commands.append(command)
                held = kwargs.get("stdin")
                self.assertIsInstance(held, int)
                imported.append(os.pread(held, 4096, 0))
                return subprocess.CompletedProcess(command, 0, b"", b"")

            try:
                source.unlink()
                source.symlink_to(sentinel)
                with self.assertRaises(PermissionError):
                    source.read_bytes()
                with mock.patch.object(module.subprocess, "run", side_effect=fake_run):
                    module._copy_descriptor_to_root(descriptor, root / "root-stage")
            finally:
                os.close(descriptor)
                sentinel.chmod(0o600)
            self.assertEqual(imported, [original])
            self.assertNotIn(secret, imported)
            flattened = [item for command in commands for item in command]
            self.assertNotIn("/usr/bin/dpkg", flattened)
            self.assertNotIn(str(module.PUBLISHER), flattened)


if __name__ == "__main__":
    unittest.main()
