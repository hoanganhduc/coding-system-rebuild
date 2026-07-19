#!/usr/bin/env python3
"""Regression tests for pinned ai-agents-skills materialization."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "bin/lib/aas_component.py"
SPEC = importlib.util.spec_from_file_location("aas_component_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AAS_COMPONENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AAS_COMPONENT)
PIN = "a" * 40


def make_writable(root: Path) -> None:
    if not root.exists():
        return
    for directory, dirnames, _filenames in os.walk(root, topdown=True):
        os.chmod(directory, 0o700)
        for name in dirnames:
            child = Path(directory) / name
            if not child.is_symlink():
                os.chmod(child, 0o700)


class AasComponentTests(unittest.TestCase):
    def fixture(self, base: Path) -> tuple[Path, int, int]:
        uid = os.geteuid()
        gid = os.getegid()
        authority = base / "authority"
        authority.mkdir(mode=0o755)
        root = AAS_COMPONENT.ensure_component_root(
            base=authority,
            parts=("coding-system", "components", "ai-agents-skills"),
            uid=uid,
            gid=gid,
        )
        return root, uid, gid

    def populate(self, stage: Path, marker: bytes = b"fixture\n") -> None:
        installer = stage / "installer"
        installer.mkdir(mode=0o755)
        bootstrap = installer / "bootstrap.sh"
        bootstrap.write_bytes(b"#!/bin/sh\nexit 0\n")
        bootstrap.chmod(0o755)
        payload = stage / "payload.txt"
        payload.write_bytes(marker)
        payload.chmod(0o644)

    def test_archive_inventory_rejects_links_and_requires_bootstrap(self) -> None:
        valid = (
            b"100755 blob "
            + b"1" * 40
            + b"\tinstaller/bootstrap.sh\0"
            + b"100644 blob "
            + b"2" * 40
            + b"\tpayload.txt\0"
        )
        AAS_COMPONENT.validate_archive_source(valid, PIN)

        linked = b"120000 blob " + b"3" * 40 + b"\tunsafe-link\0"
        with self.assertRaisesRegex(AAS_COMPONENT.ComponentError, "link, submodule"):
            AAS_COMPONENT.validate_archive_source(valid + linked, PIN)
        with self.assertRaisesRegex(AAS_COMPONENT.ComponentError, "bootstrap"):
            AAS_COMPONENT.validate_archive_source(
                b"100644 blob " + b"4" * 40 + b"\tpayload.txt\0",
                PIN,
            )

    def test_phase8_uses_only_immutable_source_and_closed_python(self) -> None:
        source = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        phase = source.split('# 8 ─ skills via ai-agents-skills', 1)[1].split(
            '# 9 ─ python environments', 1
        )[0]
        self.assertNotIn('$AAS_HOME/installer/bootstrap.sh', phase)
        for required in (
            'AAS_HELPER_SOURCE="$REPO/bin/lib/aas_component.py"',
            'AAS_BOUND_HELPER=',
            'os.O_NOFOLLOW | os.O_NONBLOCK',
            "information.st_nlink != 1",
            '/usr/bin/timeout 30s /usr/bin/sudo -n',
            'AAS_HELPER="$AAS_BOUND_HELPER"',
            'emit-raw-tar',
            'verify-extracted',
            'cd "$AAS_IMMUTABLE"',
            '/usr/bin/env -i "${AAS_CLOSED_ENV[@]}"',
            'AAS_INSTALL_CONFIRM="$AAS_PHRASE"',
            'AAS_PYTHON=/usr/bin/python3',
            'PYTHONNOUSERSITE=1',
            'PYTHONSAFEPATH=1',
        ):
            self.assertIn(required, phase)

        digest_line = next(
            line.strip()
            for line in phase.splitlines()
            if line.strip().startswith('AAS_HELPER_SHA256="')
        )
        declared_digest = digest_line.split('"', 2)[1]
        actual_digest = hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest()
        self.assertEqual(declared_digest, actual_digest)
        binding_end = phase.index('AAS_HELPER="$AAS_BOUND_HELPER"')
        first_privileged_helper = phase.index(
            '/usr/bin/python3 -I -B "$AAS_HELPER"'
        )
        self.assertLess(binding_end, first_privileged_helper)
        self.assertNotIn(
            '/usr/bin/python3 -I -B "$AAS_HELPER_SOURCE"',
            phase,
        )
        verification = (ROOT / "bin/verify.sh").read_text(encoding="utf-8")
        self.assertIn("component materializer authority/hash invalid", verification)
        self.assertIn("component immutable authority invalid", verification)
        self.assertIn("/usr/bin/sha256sum", verification)
        self.assertIn("/usr/bin/stat", verification)
        self.assertIn("/usr/bin/git --no-replace-objects --no-optional-locks", verification)
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", verification)

    def test_raw_transport_does_not_apply_checkout_attributes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()

            def git(*arguments: str) -> None:
                result = subprocess.run(
                    ["/usr/bin/git", "-C", str(repo), *arguments],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())

            git("init", "-q")
            git("config", "user.name", "AAS Component Test")
            git("config", "user.email", "aas-component@example.invalid")
            (repo / ".gitattributes").write_text("*.bat text eol=crlf\n", encoding="ascii")
            (repo / "installer").mkdir()
            bootstrap = repo / "installer/bootstrap.sh"
            bootstrap.write_bytes(b"#!/bin/sh\nexit 0\n")
            bootstrap.chmod(0o755)
            (repo / "make.bat").write_bytes(b"@echo off\necho raw\n")
            git("add", ".")
            git("commit", "-qm", "fixture")
            pin = subprocess.check_output(
                ["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"],
                text=True,
            ).strip()
            output = io.BytesIO()
            AAS_COMPONENT.emit_raw_tar(repo, pin, output)
            output.seek(0)
            with tarfile.open(fileobj=output, mode="r:") as archive:
                stream = archive.extractfile("make.bat")
                assert stream is not None
                self.assertEqual(stream.read(), b"@echo off\necho raw\n")

    def test_extracted_tree_is_bound_to_git_blob_ids_and_modes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root, uid, gid = self.fixture(base)
            try:
                stage = AAS_COMPONENT.create_stage(root, PIN, uid=uid, gid=gid)
                self.populate(stage)

                def record(mode: bytes, path: str, data: bytes) -> bytes:
                    import hashlib

                    digest = hashlib.sha1(
                        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
                    ).hexdigest()
                    return mode + b" blob " + digest.encode("ascii") + b"\t" + path.encode() + b"\0"

                inventory = record(
                    b"100755",
                    "installer/bootstrap.sh",
                    b"#!/bin/sh\nexit 0\n",
                ) + record(b"100644", "payload.txt", b"fixture\n")
                AAS_COMPONENT.verify_extracted_archive(
                    root, inventory, PIN, stage, uid=uid, gid=gid
                )
                (stage / "payload.txt").write_bytes(b"changed\n")
                with self.assertRaisesRegex(
                    AAS_COMPONENT.ComponentError,
                    "blob differs",
                ):
                    AAS_COMPONENT.verify_extracted_archive(
                        root, inventory, PIN, stage, uid=uid, gid=gid
                    )
                AAS_COMPONENT._remove_stage(root, PIN, stage, uid=uid, gid=gid)
            finally:
                make_writable(base)

    def test_publish_is_immutable_idempotent_and_conflict_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root, uid, gid = self.fixture(base)
            try:
                stage = AAS_COMPONENT.create_stage(root, PIN, uid=uid, gid=gid)
                self.populate(stage)
                target = AAS_COMPONENT.publish_stage(
                    root, PIN, stage, uid=uid, gid=gid
                )
                self.assertEqual(
                    AAS_COMPONENT.verify_component(root, PIN, uid=uid, gid=gid),
                    target,
                )
                self.assertEqual(target.stat().st_mode & 0o777, 0o555)
                self.assertEqual(
                    (target / "installer/bootstrap.sh").stat().st_mode & 0o777,
                    0o555,
                )
                self.assertEqual((target / "payload.txt").stat().st_mode & 0o777, 0o444)

                repeat = AAS_COMPONENT.create_stage(root, PIN, uid=uid, gid=gid)
                self.populate(repeat)
                self.assertEqual(
                    AAS_COMPONENT.publish_stage(
                        root, PIN, repeat, uid=uid, gid=gid
                    ),
                    target,
                )
                self.assertFalse(repeat.exists())

                conflict = AAS_COMPONENT.create_stage(root, PIN, uid=uid, gid=gid)
                self.populate(conflict, marker=b"different\n")
                with self.assertRaisesRegex(
                    AAS_COMPONENT.ComponentError,
                    "does not match",
                ):
                    AAS_COMPONENT.publish_stage(
                        root, PIN, conflict, uid=uid, gid=gid
                    )
                self.assertEqual((target / "payload.txt").read_bytes(), b"fixture\n")
                AAS_COMPONENT._remove_stage(
                    root, PIN, conflict, uid=uid, gid=gid
                )
            finally:
                make_writable(base)

    def test_stage_rejects_symlink_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root, uid, gid = self.fixture(base)
            try:
                stage = AAS_COMPONENT.create_stage(root, PIN, uid=uid, gid=gid)
                self.populate(stage)
                (stage / "unsafe").symlink_to("payload.txt")
                with self.assertRaisesRegex(AAS_COMPONENT.ComponentError, "unsafe file"):
                    AAS_COMPONENT.publish_stage(
                        root, PIN, stage, uid=uid, gid=gid
                    )
                AAS_COMPONENT._remove_stage(root, PIN, stage, uid=uid, gid=gid)
            finally:
                make_writable(base)


if __name__ == "__main__":
    unittest.main(verbosity=2)
