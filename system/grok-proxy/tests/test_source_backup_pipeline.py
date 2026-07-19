#!/usr/bin/env python3
"""Regression tests for Grok's authoring-source and backup ownership."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


_TEST_PATH = Path(__file__).resolve()
_REPO_CANDIDATES = (
    _TEST_PATH.parents[3],
    _TEST_PATH.parents[1].parent / "coding-system-rebuild",
)
REPO_ROOT = next(
    (
        candidate
        for candidate in _REPO_CANDIDATES
        if (candidate / "bin/lib/manifest_sync.py").is_file()
    ),
    _REPO_CANDIDATES[0],
)
SYNC = REPO_ROOT / "bin/lib/manifest_sync.py"
SOURCE = REPO_ROOT / "system/grok-proxy"

SYNC_SPEC = importlib.util.spec_from_file_location("manifest_sync_under_test", SYNC)
assert SYNC_SPEC is not None and SYNC_SPEC.loader is not None
MANIFEST_SYNC = importlib.util.module_from_spec(SYNC_SPEC)
SYNC_SPEC.loader.exec_module(MANIFEST_SYNC)


class AuthoritativeCaptureTests(unittest.TestCase):
    def make_fixture(self, base: Path) -> tuple[Path, Path]:
        repo = base / "repo"
        home = base / "home"
        private = home / "grok-proxy"
        destination = repo / "system/grok-proxy"
        (private / "grok_ms").mkdir(parents=True)
        (private / "tests").mkdir()
        (private / "grok_ms/__pycache__").mkdir()
        destination.mkdir(parents=True)
        (repo / "secrets").mkdir()

        (private / "grok-remote").write_text("#!/bin/sh\necho current\n", encoding="utf-8")
        (private / "grok-remote").chmod(0o755)
        (private / "grok_ms/client.py").write_text("CURRENT = True\n", encoding="utf-8")
        (private / "tests/keep.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (private / "grok_ms/__pycache__/client.pyc").write_bytes(b"generated")
        (private / "hosts.conf").write_text("private topology\n", encoding="utf-8")
        (private / ".model.choice").write_text("private-model\n", encoding="utf-8")

        (destination / "grok_ms").mkdir()
        (destination / "tests").mkdir()
        (destination / "grok-remote").write_text("#!/bin/sh\necho stale\n", encoding="utf-8")
        (destination / "grok_ms/client.py").write_text("CURRENT = False\n", encoding="utf-8")
        (destination / "grok_ms/removed.py").write_text("STALE = True\n", encoding="utf-8")
        (destination / "tests/keep.sh").write_text("stale\n", encoding="utf-8")
        (destination / "tests/removed.sh").write_text("stale\n", encoding="utf-8")
        (destination / "LOCAL-NOTES.md").write_text("not manifest-owned\n", encoding="utf-8")
        (destination / ".planning").mkdir()
        (destination / ".planning/keep.md").write_text(
            "repository-local plan\n", encoding="utf-8"
        )
        (destination / ".planning").chmod(0o750)
        os.utime(destination / ".planning/keep.md", ns=(1_700_000_000_123_456_789,) * 2)
        os.utime(destination / ".planning", ns=(1_700_000_001_123_456_789,) * 2)

        (repo / "MANIFEST.yaml").write_text(
            """schema: coding-system.manifest.v1
home_placeholder: "{{ HOME }}"
roots: [grok-proxy]
entries:
  - id: grokproxy-scripts
    root: grok-proxy
    match: [grok-remote, grok_ms, tests]
    exclude: ["**/__pycache__", "**/__pycache__/**", "**/*.pyc"]
    class: public-copy
    dest_dir: system/grok-proxy
    authoritative: true
    preserve_dest: [.planning, .learnings]
    source_transaction_lock: .grok-source-restore.lock
    source_transaction_marker: .grok-source-restore.json
  - id: grokproxy-private
    root: grok-proxy
    match: [hosts.conf]
    class: private-archive
  - id: grokproxy-generated
    root: grok-proxy
    match: [".model.choice", ".grok-source-restore*", "**/__pycache__", "**/__pycache__/**", "**/*.pyc"]
    class: exclude-generated
""",
            encoding="utf-8",
        )
        (repo / "secrets/secrets-manifest.yaml").write_text(
            "entries:\n  - {path: grok-proxy/hosts.conf, mode: '0600'}\n",
            encoding="utf-8",
        )
        return repo, home

    def test_authoritative_capture_rejects_unclassified_nested_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            manifest = repo / "MANIFEST.yaml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    ', "**/__pycache__", "**/__pycache__/**", "**/*.pyc"',
                    "",
                ),
                encoding="utf-8",
            )
            before = (repo / "system/grok-proxy/grok-remote").read_bytes()

            result = self.run_sync(repo, home)

            self.assertEqual(result.returncode, 2)
            self.assertIn("authoritative source path is unclassified", result.stderr)
            self.assertEqual(
                (repo / "system/grok-proxy/grok-remote").read_bytes(), before
            )

    def test_authoritative_capture_rejects_duplicate_classification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            manifest = repo / "MANIFEST.yaml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8")
                + """  - id: grokproxy-duplicate
    root: grok-proxy
    match: [grok_ms]
    class: exclude-generated
""",
                encoding="utf-8",
            )
            before = (repo / "system/grok-proxy/grok-remote").read_bytes()

            result = self.run_sync(repo, home)

            self.assertEqual(result.returncode, 2)
            self.assertIn(
                "authoritative source path is multiply classified", result.stderr
            )
            self.assertEqual(
                (repo / "system/grok-proxy/grok-remote").read_bytes(), before
            )

    def test_authoritative_classification_records_walk_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source = base / "grok-proxy"
            source.mkdir()
            entry = {
                "id": "grokproxy-scripts",
                "root": "grok-proxy",
                "match": ["grok-remote"],
                "class": "public-copy",
                "dest_dir": "system/grok-proxy",
                "authoritative": True,
            }

            def denied_walk(*_args: object, **kwargs: object):
                def iterator():
                    kwargs["onerror"](
                        PermissionError(
                            13,
                            "permission denied",
                            str(source / "denied"),
                        )
                    )
                    return
                    yield

                return iterator()

            with (
                mock.patch.object(MANIFEST_SYNC, "HOME", str(base)),
                mock.patch.object(MANIFEST_SYNC.os, "walk", denied_walk),
            ):
                errors = MANIFEST_SYNC.preflight_authoritative_classification(
                    [entry]
                )
            self.assertEqual(len(errors), 1)
            self.assertIn("cannot classify authoritative source tree", errors[0])

    def test_authoritative_stage_fsync_fails_closed_on_walk_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td) / "stage"
            stage.mkdir()

            def denied_walk(*_args: object, **kwargs: object):
                def iterator():
                    kwargs["onerror"](
                        PermissionError(
                            13,
                            "permission denied",
                            str(stage / "denied"),
                        )
                    )
                    return
                    yield

                return iterator()

            with (
                mock.patch.object(MANIFEST_SYNC.os, "walk", denied_walk),
                self.assertRaisesRegex(
                    MANIFEST_SYNC.SyncError,
                    "cannot inspect authoritative tree",
                ),
            ):
                MANIFEST_SYNC._fsync_real_tree(str(stage))

    def run_sync(
        self, repo: Path, home: Path, manifest: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["CSR_HOME_OVERRIDE"] = str(home)
        command = [sys.executable, str(SYNC), "--repo", str(repo), "--apply"]
        if manifest is not None:
            command.extend(("--manifest", str(manifest)))
        return subprocess.run(
            command,
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    def test_authoritative_capture_exactly_mirrors_public_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            private = home / "grok-proxy"
            private_before = {
                name: (private / name).read_bytes()
                for name in ("hosts.conf", ".model.choice")
            }
            destination = repo / "system/grok-proxy"
            preserved_before = {
                name: (
                    os.lstat(destination / name).st_mode & 0o777,
                    os.lstat(destination / name).st_mtime_ns,
                )
                for name in (".planning", ".planning/keep.md")
            }

            result = self.run_sync(repo, home)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (destination / "grok-remote").read_text(encoding="utf-8"),
                "#!/bin/sh\necho current\n",
            )
            self.assertEqual(
                (destination / "grok_ms/client.py").read_text(encoding="utf-8"),
                "CURRENT = True\n",
            )
            self.assertEqual(
                os.lstat(destination / "grok-remote").st_mode & 0o777, 0o755
            )
            self.assertEqual(
                os.lstat(destination / "grok_ms/client.py").st_mode & 0o777,
                0o644,
            )
            self.assertFalse((destination / "grok_ms/removed.py").exists())
            self.assertFalse((destination / "tests/removed.sh").exists())
            self.assertFalse((destination / "grok_ms/__pycache__").exists())
            self.assertFalse((destination / "LOCAL-NOTES.md").exists())
            self.assertEqual(
                (destination / ".planning/keep.md").read_text(encoding="utf-8"),
                "repository-local plan\n",
            )
            self.assertEqual(
                preserved_before,
                {
                    name: (
                        os.lstat(destination / name).st_mode & 0o777,
                        os.lstat(destination / name).st_mtime_ns,
                    )
                    for name in (".planning", ".planning/keep.md")
                },
            )
            self.assertFalse((destination / "hosts.conf").exists())
            self.assertFalse((destination / ".model.choice").exists())
            self.assertEqual(
                private_before,
                {
                    name: (private / name).read_bytes()
                    for name in ("hosts.conf", ".model.choice")
                },
            )

    def test_missing_required_source_root_fails_before_repository_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            source = home / "grok-proxy"
            for path in sorted((source / "grok_ms").rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                else:
                    path.rmdir()
            (source / "grok_ms").rmdir()
            destination = repo / "system/grok-proxy"
            before = (destination / "grok-remote").read_bytes()

            result = self.run_sync(repo, home)

            self.assertEqual(result.returncode, 2)
            self.assertIn("authoritative source path is missing", result.stderr)
            self.assertEqual((destination / "grok-remote").read_bytes(), before)
            self.assertTrue((destination / "grok_ms/removed.py").is_file())

    def test_late_public_validation_failure_does_not_publish_partial_capture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            source = home / "grok-proxy"
            destination = repo / "system/grok-proxy"
            before = {
                path.relative_to(destination): path.read_bytes()
                for path in destination.rglob("*")
                if path.is_file()
            }
            (source / "grok-remote").write_text(
                "#!/bin/sh\necho replacement\n", encoding="utf-8"
            )
            (source / "tests/keep.sh").write_bytes(b"\x7fELFhostile")

            result = self.run_sync(repo, home)

            self.assertEqual(result.returncode, 2)
            self.assertIn("ELF binary in public class", result.stderr)
            self.assertEqual(
                before,
                {
                    path.relative_to(destination): path.read_bytes()
                    for path in destination.rglob("*")
                    if path.is_file()
                },
            )

    def test_destination_symlink_is_replaced_without_following_its_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            destination = repo / "system/grok-proxy"
            external = Path(td) / "external"
            external.mkdir()
            (external / "sentinel").write_text("untouched\n", encoding="utf-8")
            for path in sorted((destination / "tests").rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                else:
                    path.rmdir()
            (destination / "tests").rmdir()
            (destination / "tests").symlink_to(external, target_is_directory=True)

            result = self.run_sync(repo, home)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((destination / "tests").is_symlink())
            self.assertEqual(
                (destination / "tests/keep.sh").read_text(encoding="utf-8"),
                "#!/bin/sh\nexit 0\n",
            )
            self.assertEqual(
                (external / "sentinel").read_text(encoding="utf-8"), "untouched\n"
            )

    def test_whole_authoritative_destination_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            destination = repo / "system/grok-proxy"
            shutil.rmtree(destination)
            external = Path(td) / "external"
            (external / ".planning").mkdir(parents=True)
            secret = external / ".planning/secret.md"
            secret.write_text("external-only\n", encoding="utf-8")
            destination.symlink_to(external, target_is_directory=True)

            result = self.run_sync(repo, home)

            self.assertEqual(result.returncode, 2)
            self.assertIn("must be a real directory", result.stderr)
            self.assertTrue(destination.is_symlink())
            self.assertEqual(secret.read_text(encoding="utf-8"), "external-only\n")

    def test_custom_manifest_apply_does_not_replace_global_symlink_report(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            custom = repo / "grok-only.yaml"
            custom.write_bytes((repo / "MANIFEST.yaml").read_bytes())
            global_report = repo / ".staging-symlinks-observed.tsv"
            global_report.write_text("global topology\n", encoding="utf-8")

            result = self.run_sync(repo, home, custom)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                global_report.read_text(encoding="utf-8"), "global topology\n"
            )
            self.assertTrue((repo / ".staging/symlinks-observed.tsv").is_file())

    def test_atomic_exchange_never_leaves_authoritative_destination_absent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, _home = self.make_fixture(Path(td))
            destination = repo / "system/grok-proxy"
            stage_root = repo / ".staging/authoritative-fault"
            staged = stage_root / "system/grok-proxy"
            staged.mkdir(parents=True)
            (staged / "grok-remote").write_text("new snapshot\n", encoding="utf-8")
            original_exchange = MANIFEST_SYNC._rename_exchange

            def terminate_after_exchange(left: str, right: str) -> None:
                original_exchange(left, right)
                raise SystemExit(137)

            entry = {
                "dest_dir": "system/grok-proxy",
                "preserve_dest": [".planning", ".learnings"],
            }
            with mock.patch.object(
                MANIFEST_SYNC, "_rename_exchange", side_effect=terminate_after_exchange
            ):
                with self.assertRaises(SystemExit):
                    MANIFEST_SYNC.publish_authoritative_entry(
                        str(repo), str(stage_root), entry
                    )

            self.assertTrue(destination.is_dir())
            self.assertEqual(
                (destination / "grok-remote").read_text(encoding="utf-8"),
                "new snapshot\n",
            )
            self.assertTrue(staged.is_dir())
            self.assertIn("stale", (staged / "grok-remote").read_text(encoding="utf-8"))

    def test_capture_lock_rejects_a_concurrent_second_capture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            MANIFEST_SYNC._acquire_capture_lock(str(repo))

            result = self.run_sync(repo, home)

            self.assertEqual(result.returncode, 2)
            self.assertIn("another capture is active", result.stderr)

    def test_incomplete_source_restore_and_active_restore_lock_block_capture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            source = home / "grok-proxy"
            destination = repo / "system/grok-proxy"
            before = (destination / "grok-remote").read_bytes()
            marker = source / ".grok-source-restore.json"
            marker.write_text("incomplete\n", encoding="ascii")
            marker.chmod(0o600)
            blocked = self.run_sync(repo, home)
            self.assertEqual(blocked.returncode, 2)
            self.assertIn("source restore is incomplete", blocked.stderr)
            self.assertEqual((destination / "grok-remote").read_bytes(), before)
            marker.unlink()

            lock = source / ".grok-source-restore.lock"
            descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                active = self.run_sync(repo, home)
            finally:
                os.close(descriptor)
            self.assertEqual(active.returncode, 2)
            self.assertIn("interlock refused", active.stderr)
            self.assertEqual((destination / "grok-remote").read_bytes(), before)

    def test_preserved_write_at_exchange_rolls_back_publication(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, _home = self.make_fixture(Path(td))
            destination = repo / "system/grok-proxy"
            stage_root = repo / ".staging/authoritative-preserve-race"
            staged = stage_root / "system/grok-proxy"
            staged.mkdir(parents=True)
            (staged / "grok-remote").write_text("new snapshot\n", encoding="utf-8")
            entry = {
                "dest_dir": "system/grok-proxy",
                "preserve_dest": [".planning"],
            }
            original = MANIFEST_SYNC._rename_exchange
            changed = False

            def exchange_after_write(left: str, right: str) -> None:
                nonlocal changed
                if not changed:
                    changed = True
                    (destination / ".planning/keep.md").write_text(
                        "concurrent plan\n", encoding="utf-8"
                    )
                original(left, right)

            with mock.patch.object(
                MANIFEST_SYNC, "_rename_exchange", side_effect=exchange_after_write
            ):
                with self.assertRaises(MANIFEST_SYNC.SyncError):
                    MANIFEST_SYNC.publish_authoritative_entry(
                        str(repo), str(stage_root), entry
                    )

            self.assertEqual(
                (destination / ".planning/keep.md").read_text(encoding="utf-8"),
                "concurrent plan\n",
            )
            self.assertIn(
                "stale", (destination / "grok-remote").read_text(encoding="utf-8")
            )

    def test_post_exchange_fsync_failure_restores_previous_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, _home = self.make_fixture(Path(td))
            destination = repo / "system/grok-proxy"
            stage_root = repo / ".staging/authoritative-fsync-fault"
            staged = stage_root / "system/grok-proxy"
            staged.mkdir(parents=True)
            (staged / "grok-remote").write_text("new snapshot\n", encoding="utf-8")
            entry = {"dest_dir": "system/grok-proxy", "preserve_dest": []}
            original_exchange = MANIFEST_SYNC._rename_exchange
            original_fsync = MANIFEST_SYNC._fsync_directory
            exchanged = False
            failed = False

            def exchange(left: str, right: str) -> None:
                nonlocal exchanged
                original_exchange(left, right)
                exchanged = True

            def fsync_after_exchange(path: str) -> None:
                nonlocal failed
                if exchanged and not failed:
                    failed = True
                    raise OSError("injected fsync failure")
                original_fsync(path)

            with (
                mock.patch.object(MANIFEST_SYNC, "_rename_exchange", side_effect=exchange),
                mock.patch.object(
                    MANIFEST_SYNC, "_fsync_directory", side_effect=fsync_after_exchange
                ),
            ):
                with self.assertRaises(OSError):
                    MANIFEST_SYNC.publish_authoritative_entry(
                        str(repo), str(stage_root), entry
                    )

            self.assertTrue(failed)
            self.assertIn(
                "stale", (destination / "grok-remote").read_text(encoding="utf-8")
            )

    def test_sync_wrapper_does_not_unlink_an_active_capture_lock(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            (repo / "bin/lib").mkdir(parents=True)
            shutil.copy2(REPO_ROOT / "bin/sync.sh", repo / "bin/sync.sh")
            shutil.copy2(SYNC, repo / "bin/lib/manifest_sync.py")
            MANIFEST_SYNC._acquire_capture_lock(str(repo))
            lock = repo / ".staging/capture.lock"
            before = lock.stat().st_ino
            environment = dict(os.environ)
            environment["CSR_HOME_OVERRIDE"] = str(home)
            environment["OPENCLAW_BOT_DIR"] = str(Path(td) / "absent-component")

            result = subprocess.run(
                ["/bin/bash", str(repo / "bin/sync.sh"), "--dry-run"],
                env=environment,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertEqual(lock.stat().st_ino, before)
            self.assertIn("another capture is active", result.stderr)


class DirectSourceExecutionTests(unittest.TestCase):
    def test_unfrozen_source_frontend_refuses_production_execution(self) -> None:
        result = subprocess.run(
            [str(SOURCE / "grok-remote"), "--help"],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 78)
        self.assertIn("editable source tree is not executable", result.stderr)

    def test_unfrozen_source_multi_frontend_refuses_production_execution(self) -> None:
        environment = dict(os.environ)
        environment["GROK_MULTI_SESSION"] = "1"
        result = subprocess.run(
            [str(SOURCE / "grok-remote"), "--help"],
            env=environment,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 78)
        self.assertIn("editable source tree is not executable", result.stderr)

    def test_unfrozen_source_recover_refuses_before_python_dispatch(self) -> None:
        for marker in (None, "0"):
            environment = dict(os.environ)
            if marker is not None:
                environment["GROK_MULTI_SESSION"] = marker
            with self.subTest(marker=marker):
                result = subprocess.run(
                    [str(SOURCE / "grok-remote"), "recover"],
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 78)
                self.assertIn(
                    "editable source tree is not executable",
                    result.stderr,
                )

    def test_testing_variable_cannot_authorize_editable_frontends(self) -> None:
        environment = dict(os.environ)
        environment["GROK_TESTING"] = "1"
        for executable, arguments in (
            (SOURCE / "grok-remote", ["--help"]),
            (SOURCE / "egress.sh", ["status"]),
        ):
            with self.subTest(executable=executable.name):
                result = subprocess.run(
                    [str(executable), *arguments],
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 78)
                self.assertIn("editable source tree is not executable", result.stderr)

    def test_pythonpath_shadow_module_cannot_bypass_source_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            Path(td, "hashlib.py").write_text(
                "raise SystemExit(0)\n", encoding="utf-8"
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = td
            result = subprocess.run(
                [str(SOURCE / "grok-remote"), "--help"],
                env=environment,
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 78)
            self.assertIn("editable source tree is not executable", result.stderr)

    def test_unfrozen_source_egress_refuses_standalone_execution(self) -> None:
        result = subprocess.run(
            [str(SOURCE / "egress.sh"), "status"],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 78)
        self.assertIn("editable source tree is not executable", result.stderr)


if __name__ == "__main__":
    unittest.main()
