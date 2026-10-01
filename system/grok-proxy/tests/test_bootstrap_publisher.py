#!/usr/bin/env python3
"""Focused tests for the administrative signed-application publisher."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import shutil
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import unittest


PROXY_ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_ROOT = PROXY_ROOT / "bootstrap"
BUILDER = BOOTSTRAP_ROOT / "build_bundle.py"
PUBLISHER = BOOTSTRAP_ROOT / "publish_signed_application.py"
NATIVE_SOURCE = BOOTSTRAP_ROOT / "bootstrap.c"
LAUNCHER_SOURCE = BOOTSTRAP_ROOT / "isolated_python_launcher.c"
OPENSSL = Path("/usr/bin/openssl")
KEY_ID = "publisher-test-key"
DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
TEST_MODE_ENV = "GROK_BOOTSTRAP_PUBLISHER_TEST_MODE"
CONTROL_ROOT = Path("/usr/local/libexec/grok-proxy/bootstrap")
PACKAGE_BUILD_INPUTS = (
    "Makefile",
    "activate_package.py",
    "bootstrap.c",
    "isolated_python_launcher.c",
    "publish_signed_application.py",
)


class BootstrapPublisherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc")
        pkg_config = shutil.which("pkg-config")
        if not OPENSSL.is_file() or compiler is None or pkg_config is None:
            raise unittest.SkipTest("OpenSSL, a C compiler, and pkg-config are required")
        cls._class_temporary = tempfile.TemporaryDirectory(
            prefix="grok-bootstrap-publisher-class-", dir=Path.home()
        )
        cls.class_root = Path(cls._class_temporary.name)
        cls.key = cls.class_root / "signing-key.pem"
        cls._checked(
            [
                os.fspath(OPENSSL),
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                os.fspath(cls.key),
            ]
        )
        public = cls._checked(
            [
                os.fspath(OPENSSL),
                "pkey",
                "-in",
                os.fspath(cls.key),
                "-pubout",
                "-outform",
                "DER",
            ]
        ).stdout
        if not public.startswith(DER_PREFIX) or len(public) != len(DER_PREFIX) + 32:
            raise AssertionError("unexpected Ed25519 public-key encoding")
        cls.public_key_hex = public[len(DER_PREFIX) :].hex()
        cls.package_source = cls.class_root / "package-source"
        cls.package_source.mkdir(mode=0o700)
        for name in PACKAGE_BUILD_INPUTS:
            source = BOOTSTRAP_ROOT / name
            information = source.lstat()
            if (
                source.is_symlink()
                or not stat.S_ISREG(information.st_mode)
                or information.st_nlink != 1
            ):
                raise AssertionError(f"unsafe package build input: {name}")
            shutil.copy2(source, cls.package_source / name, follow_symlinks=False)
        cls.native = cls.class_root / "grok-bootstrap"
        cflags = shlex.split(
            cls._checked([pkg_config, "--cflags", "openssl"]).stdout.decode("ascii")
        )
        libraries = shlex.split(
            cls._checked([pkg_config, "--libs", "openssl"]).stdout.decode("ascii")
        )
        cls._checked(
            [
                compiler,
                "-std=c11",
                "-O2",
                "-DGROK_BOOTSTRAP_TEST_BUILD=1",
                f'-DGROK_BOOTSTRAP_KEY_ID="{KEY_ID}"',
                f'-DGROK_BOOTSTRAP_PUBLIC_KEY_HEX="{cls.public_key_hex}"',
                *cflags,
                os.fspath(NATIVE_SOURCE),
                "-o",
                os.fspath(cls.native),
                *libraries,
            ]
        )
        cls.release_one = cls._build_release("one", b"VALUE = 1\n")
        cls.release_two = cls._build_release("two", b"VALUE = 2\n")

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "class_root"):
            cls._make_removable(cls.class_root)
        if hasattr(cls, "_class_temporary"):
            cls._class_temporary.cleanup()

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix="grok-bootstrap-publisher-case-", dir=self.class_root
        )
        self.test_root = Path(self._temporary.name)
        self.control = (
            self.test_root / "usr/local/libexec/grok-proxy/bootstrap"
        )
        self.store = self.test_root / "usr/local/libexec/grok-proxy/bootstrap-releases"
        self.release_control = (
            self.test_root / "var/lib/grok-proxy/release-control"
        )
        self.control.mkdir(parents=True, mode=0o755)
        self.store.mkdir(parents=True, mode=0o755)
        self.release_control.mkdir(parents=True, mode=0o755)
        for leaf in (self.control, self.store, self.release_control):
            current = leaf
            while current != self.test_root:
                current.chmod(0o755)
                current = current.parent
        self.control.chmod(0o755)
        self.store.chmod(0o755)
        self.release_control.chmod(0o755)
        self.update_lock = self.control / "update.lock"
        self.update_lock.touch(mode=0o600)
        self.update_lock.chmod(0o600)
        self.operation_lock = self.release_control / "operation.lock"
        self.operation_lock.touch(mode=0o600)
        self.operation_lock.chmod(0o600)
        (self.release_control / "runner-scopes").mkdir(mode=0o700)
        shutil.copy2(self.native, self.control / "grok-bootstrap")
        (self.control / "grok-bootstrap").chmod(0o555)
        signed_inputs = self.test_root / "signed-inputs"
        signed_inputs.mkdir(mode=0o755)
        release_one = signed_inputs / type(self).release_one.name
        release_two = signed_inputs / type(self).release_two.name
        shutil.copytree(type(self).release_one, release_one, copy_function=shutil.copy2)
        shutil.copytree(type(self).release_two, release_two, copy_function=shutil.copy2)
        release_one.chmod(0o555)
        release_two.chmod(0o555)
        self.release_one = release_one
        self.release_two = release_two

    def tearDown(self) -> None:
        self._make_removable(self.test_root)
        self._temporary.cleanup()

    @staticmethod
    def _make_removable(root: Path) -> None:
        for path in sorted(
            root.rglob("*"), key=lambda item: len(item.parts), reverse=True
        ):
            try:
                information = path.lstat()
                if not stat.S_ISLNK(information.st_mode):
                    path.chmod(0o700 if stat.S_ISDIR(information.st_mode) else 0o600)
            except FileNotFoundError:
                pass
        try:
            root.chmod(0o700)
        except FileNotFoundError:
            pass

    @staticmethod
    def _checked(command: list[str]) -> subprocess.CompletedProcess:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"command failed: {command!r}\n"
                f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
            )
        return completed

    @classmethod
    def _build_release(cls, label: str, payload: bytes) -> Path:
        source = cls.class_root / f"source-{label}"
        output = cls.class_root / f"output-{label}"
        source.mkdir()
        output.mkdir()
        (source / "__main__.py").write_bytes(payload)
        completed = cls._checked(
            [
                sys.executable,
                "-B",
                os.fspath(BUILDER),
                "--source",
                os.fspath(source),
                "--output",
                os.fspath(output),
                "--key-id",
                KEY_ID,
                "--signing-key",
                os.fspath(cls.key),
                "--openssl",
                os.fspath(OPENSSL),
            ]
        )
        return Path(completed.stdout.decode("ascii").strip())

    def _command(self, *arguments: str) -> list[str]:
        return [
            sys.executable,
            "-B",
            os.fspath(PUBLISHER),
            "--test-root",
            os.fspath(self.test_root),
            *arguments,
        ]

    def _run(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            self._command(*arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                TEST_MODE_ENV: "1",
            },
            check=False,
            timeout=30,
        )

    def _publish(self, release: Path) -> subprocess.CompletedProcess:
        selector = self.control / "selected-release"
        expected = (
            selector.read_text(encoding="ascii").strip()
            if selector.exists()
            else "none"
        )
        return self._run(
            "publish",
            "--signed-application",
            os.fspath(release),
            "--expected-current",
            expected,
        )

    def _selected(self) -> str:
        return (self.control / "selected-release").read_text(encoding="ascii").strip()

    def test_first_publish_is_sealed_audited_and_idempotent(self) -> None:
        first = self._publish(self.release_one)
        self.assertEqual(first.returncode, 0, first.stderr.decode("ascii"))
        result = json.loads(first.stdout)
        self.assertTrue(result["changed"])
        self.assertTrue(result["published"])
        self.assertEqual(self._selected(), self.release_one.name)
        installed = self.store / self.release_one.name
        self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o555)
        self.assertEqual(installed.stat().st_uid, os.geteuid())
        self.assertEqual(
            sorted(path.name for path in installed.iterdir()),
            ["dispatcher.pyz", "release-manifest.sig", "release-manifest.txt"],
        )
        for artifact in installed.iterdir():
            information = artifact.stat()
            self.assertEqual(stat.S_IMODE(information.st_mode), 0o444)
            self.assertEqual(information.st_nlink, 1)
        committed = list((self.control / "selector-audit").glob("*.committed.json"))
        self.assertEqual(len(committed), 1)

        replay = self._publish(self.release_one)
        self.assertEqual(replay.returncode, 0, replay.stderr.decode("ascii"))
        replay_result = json.loads(replay.stdout)
        self.assertFalse(replay_result["changed"])
        self.assertFalse(replay_result["published"])
        self.assertEqual(
            len(list((self.control / "selector-audit").glob("*.committed.json"))),
            1,
        )

    def test_conflicting_existing_release_fails_without_selector_change(self) -> None:
        first = self._publish(self.release_one)
        self.assertEqual(first.returncode, 0, first.stderr.decode("ascii"))
        installed = self.store / self.release_one.name
        signature = installed / "release-manifest.sig"
        installed.chmod(0o755)
        signature.chmod(0o644)
        signature.write_bytes(bytes(64))
        signature.chmod(0o444)
        installed.chmod(0o555)

        conflict = self._publish(self.release_one)
        self.assertEqual(conflict.returncode, 2)
        self.assertIn(b"conflicting signed application", conflict.stderr)
        self.assertEqual(self._selected(), self.release_one.name)

    def test_existing_update_lock_serializes_publisher(self) -> None:
        descriptor = os.open(self.update_lock, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        process = subprocess.Popen(
            self._command(
                "publish",
                "--signed-application",
                os.fspath(self.release_one),
                "--expected-current",
                "none",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                TEST_MODE_ENV: "1",
            },
        )
        try:
            time.sleep(0.2)
            self.assertIsNone(process.poll())
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            stdout, stderr = process.communicate(timeout=30)
        finally:
            os.close(descriptor)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        self.assertEqual(process.returncode, 0, stderr.decode("ascii"))
        self.assertTrue(json.loads(stdout)["published"])

    def test_failure_before_selector_rename_retains_old_and_new_releases(self) -> None:
        first = self._publish(self.release_one)
        self.assertEqual(first.returncode, 0, first.stderr.decode("ascii"))
        failed = self._run(
            "--test-fail-before-selector-rename",
            "publish",
            "--signed-application",
            os.fspath(self.release_two),
            "--expected-current",
            self.release_one.name,
        )
        self.assertEqual(failed.returncode, 2)
        self.assertIn(b"injected failure", failed.stderr)
        self.assertEqual(self._selected(), self.release_one.name)
        self.assertTrue((self.store / self.release_one.name).is_dir())
        self.assertTrue((self.store / self.release_two.name).is_dir())
        audit = self.control / "selector-audit"
        pending = audit / "pending.json"
        self.assertTrue(pending.is_file())
        self.assertEqual(
            list(self.control.glob(".selected-release-*")),
            [],
        )
        pending_record = json.loads(pending.read_text(encoding="ascii"))
        partial_selector = self.control / pending_record["selector_stage"]
        partial_selector.write_bytes(b"partial")
        partial_selector.chmod(0o600)

        recovered = self._publish(self.release_two)
        self.assertEqual(recovered.returncode, 0, recovered.stderr.decode("ascii"))
        self.assertEqual(self._selected(), self.release_two.name)
        self.assertFalse(pending.exists())
        self.assertFalse(partial_selector.exists())
        self.assertTrue(
            list((self.control / "selector-audit").glob("*.aborted.json"))
        )

        failed_after = self._run(
            "--test-fail-after-selector-rename",
            "select",
            "--release-id",
            self.release_one.name,
            "--expected-current",
            self.release_two.name,
            "--reason",
            "rollback",
        )
        self.assertEqual(failed_after.returncode, 2)
        self.assertIn(b"injected failure after", failed_after.stderr)
        self.assertEqual(self._selected(), self.release_one.name)
        reconciled = self._run(
            "select",
            "--release-id",
            self.release_one.name,
            "--expected-current",
            self.release_one.name,
            "--reason",
            "rollback",
        )
        self.assertEqual(reconciled.returncode, 0, reconciled.stderr.decode("ascii"))
        self.assertFalse(pending.exists())

    def test_partial_audit_stage_and_large_history_do_not_wedge_updates(self) -> None:
        first = self._publish(self.release_one)
        self.assertEqual(first.returncode, 0, first.stderr.decode("ascii"))
        audit = self.control / "selector-audit"
        partial = audit / "pending.tmp"
        partial.write_bytes(b'{"partial":')
        partial.chmod(0o600)
        for index in range(4100):
            history = audit / f"retained-{index}.committed.json"
            history.write_bytes(b"{}\n")
            history.chmod(0o444)

        replay = self._publish(self.release_one)
        self.assertEqual(replay.returncode, 0, replay.stderr.decode("ascii"))
        self.assertFalse(partial.exists())
        self.assertEqual(self._selected(), self.release_one.name)

    def test_interlock_blocks_rotation_but_allows_publication_then_safe_rollback(
        self,
    ) -> None:
        first = self._publish(self.release_one)
        self.assertEqual(first.returncode, 0, first.stderr.decode("ascii"))
        deny = self.release_control / "rollback-deny.json"
        deny.write_bytes(b"{}\n")
        deny.chmod(0o444)

        blocked = self._publish(self.release_two)
        self.assertEqual(blocked.returncode, 2)
        self.assertIn(b"recovery interlock is active", blocked.stderr)
        self.assertEqual(self._selected(), self.release_one.name)
        self.assertTrue((self.store / self.release_two.name).is_dir())

        deny.unlink()
        selected = self._run(
            "select",
            "--release-id",
            self.release_two.name,
            "--expected-current",
            self.release_one.name,
            "--reason",
            "reselect",
        )
        self.assertEqual(selected.returncode, 0, selected.stderr.decode("ascii"))
        self.assertEqual(self._selected(), self.release_two.name)
        rolled_back = self._run(
            "select",
            "--release-id",
            self.release_one.name,
            "--expected-current",
            self.release_two.name,
            "--reason",
            "rollback",
        )
        self.assertEqual(
            rolled_back.returncode, 0, rolled_back.stderr.decode("ascii")
        )
        self.assertEqual(self._selected(), self.release_one.name)
        self.assertTrue((self.store / self.release_one.name).is_dir())
        self.assertTrue((self.store / self.release_two.name).is_dir())

    def test_runner_journal_and_unsafe_interlocks_fail_closed(self) -> None:
        first = self._publish(self.release_one)
        self.assertEqual(first.returncode, 0, first.stderr.decode("ascii"))
        scopes = self.release_control / "runner-scopes"
        (scopes / "active.json").write_bytes(b"{}\n")
        blocked = self._publish(self.release_two)
        self.assertEqual(blocked.returncode, 2)
        self.assertIn(b"runner-scope recovery journal", blocked.stderr)
        self.assertEqual(self._selected(), self.release_one.name)

        (scopes / "active.json").unlink()
        (self.release_control / "rung-canary.json").symlink_to("missing")
        unsafe = self._run(
            "select",
            "--release-id",
            self.release_two.name,
            "--expected-current",
            self.release_one.name,
            "--reason",
            "reselect",
        )
        self.assertEqual(unsafe.returncode, 2)
        self.assertIn(b"recovery interlock is active", unsafe.stderr)
        self.assertEqual(self._selected(), self.release_one.name)

    def test_unsafe_source_and_lock_metadata_are_rejected(self) -> None:
        unsafe_source = self.test_root / self.release_one.name
        shutil.copytree(self.release_one, unsafe_source, copy_function=shutil.copy2)
        unsafe_source.chmod(0o755)
        (unsafe_source / "dispatcher.pyz").chmod(0o644)
        unsafe_source.chmod(0o555)
        bad_source = self._publish(unsafe_source)
        self.assertEqual(bad_source.returncode, 2)
        self.assertIn(b"artifact metadata is unsafe", bad_source.stderr)

        invalid_parent = self.test_root / "invalid-manifest"
        invalid_parent.mkdir(mode=0o755)
        invalid_manifest = invalid_parent / self.release_one.name
        shutil.copytree(
            self.release_one, invalid_manifest, copy_function=shutil.copy2
        )
        manifest = invalid_manifest / "release-manifest.txt"
        signature = invalid_manifest / "release-manifest.sig"
        invalid_manifest.chmod(0o755)
        manifest.chmod(0o644)
        manifest.write_bytes(manifest.read_bytes().replace(b"\n", b"\x0b", 1))
        manifest.chmod(0o444)
        signature.chmod(0o644)
        self._checked(
            [
                os.fspath(OPENSSL),
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                os.fspath(self.key),
                "-in",
                os.fspath(manifest),
                "-out",
                os.fspath(signature),
            ]
        )
        signature.chmod(0o444)
        invalid_manifest.chmod(0o555)
        noncanonical = self._publish(invalid_manifest)
        self.assertEqual(noncanonical.returncode, 2)
        self.assertIn(b"manifest", noncanonical.stderr)

        self.update_lock.chmod(0o644)
        bad_lock = self._publish(self.release_one)
        self.assertEqual(bad_lock.returncode, 2)
        self.assertIn(b"update lock authority is unsafe", bad_lock.stderr)
        self.assertFalse((self.control / "selected-release").exists())

    def test_source_symlink_ancestor_and_fifo_artifact_are_rejected(self) -> None:
        escaped_source = (
            self.test_root
            / ".."
            / type(self).release_one.relative_to(self.class_root)
        )
        escaped = self._publish(escaped_source)
        self.assertEqual(escaped.returncode, 2)
        self.assertIn(b"test path authority is unsafe", escaped.stderr)

        real_parent = self.test_root / "real-signed-inputs"
        real_parent.mkdir(mode=0o755)
        linked_release = real_parent / self.release_one.name
        shutil.copytree(
            self.release_one, linked_release, copy_function=shutil.copy2
        )
        linked_release.chmod(0o555)
        linked_parent = self.test_root / "linked-signed-inputs"
        linked_parent.symlink_to(real_parent.name)
        linked = self._publish(linked_parent / self.release_one.name)
        self.assertEqual(linked.returncode, 2)
        self.assertIn(b"path authority is unsafe", linked.stderr)

        fifo_parent = self.test_root / "fifo-signed-inputs"
        fifo_parent.mkdir(mode=0o755)
        fifo_release = fifo_parent / self.release_one.name
        shutil.copytree(self.release_one, fifo_release, copy_function=shutil.copy2)
        fifo_release.chmod(0o755)
        dispatcher = fifo_release / "dispatcher.pyz"
        dispatcher.unlink()
        os.mkfifo(dispatcher, 0o444)
        fifo_release.chmod(0o555)
        fifo = self._publish(fifo_release)
        self.assertEqual(fifo.returncode, 2)
        self.assertIn(b"artifact metadata is unsafe", fifo.stderr)

    def test_missing_operation_lock_blocks_even_the_first_selector(self) -> None:
        self.operation_lock.unlink()
        blocked = self._publish(self.release_one)
        self.assertEqual(blocked.returncode, 2)
        self.assertIn(b"operation lock is unsafe", blocked.stderr)
        self.assertTrue((self.store / self.release_one.name).is_dir())
        self.assertFalse((self.control / "selected-release").exists())

        self.operation_lock.touch(mode=0o600)
        self.operation_lock.chmod(0o644)
        wrong_mode = self._publish(self.release_one)
        self.assertEqual(wrong_mode.returncode, 2)
        self.assertIn(b"operation lock is unsafe", wrong_mode.stderr)
        self.operation_lock.unlink()
        self.operation_lock.symlink_to("runner-scopes")
        linked = self._publish(self.release_one)
        self.assertEqual(linked.returncode, 2)
        self.assertIn(b"operation lock is unsafe", linked.stderr)

    def test_incomplete_package_update_blocks_publication_and_selection(self) -> None:
        pending = self.control / "package-update.pending"
        pending.write_bytes(b"package update in progress\n")
        pending.chmod(0o444)
        blocked = self._publish(self.release_one)
        self.assertEqual(blocked.returncode, 2)
        self.assertIn(b"package update is incomplete", blocked.stderr)
        self.assertFalse((self.store / self.release_one.name).exists())
        self.assertFalse((self.control / "selected-release").exists())

        pending.unlink()
        completed = self._publish(self.release_one)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("ascii"))

    def test_compare_and_swap_and_test_hooks_fail_closed(self) -> None:
        first = self._publish(self.release_one)
        self.assertEqual(first.returncode, 0, first.stderr.decode("ascii"))
        stale = self._run(
            "publish",
            "--signed-application",
            os.fspath(self.release_two),
            "--expected-current",
            "f" * 64,
        )
        self.assertEqual(stale.returncode, 2)
        self.assertIn(b"differs from expected", stale.stderr)
        self.assertEqual(self._selected(), self.release_one.name)
        self.assertTrue((self.store / self.release_two.name).is_dir())

        rejected_hook = subprocess.run(
            [
                sys.executable,
                "-B",
                os.fspath(PUBLISHER),
                "--test-fail-before-selector-rename",
                "select",
                "--release-id",
                self.release_one.name,
                "--expected-current",
                self.release_one.name,
                "--reason",
                "reselect",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                TEST_MODE_ENV: "1",
            },
            check=False,
            timeout=10,
        )
        self.assertEqual(rejected_hook.returncode, 2)
        self.assertIn(b"requires explicit test mode", rejected_hook.stderr)

    def test_static_launchers_clear_loader_environment_and_bound_arguments(
        self,
    ) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("a C compiler is required")
        inherited_path = self.test_root / "inherited-authority"
        inherited_path.write_bytes(b"must not reach Python\n")
        initial_descriptor = os.open(inherited_path, os.O_RDONLY)
        inherited_descriptor = fcntl.fcntl(initial_descriptor, fcntl.F_DUPFD, 200)
        os.close(initial_descriptor)
        self.assertGreaterEqual(inherited_descriptor, 200)
        os.set_inheritable(inherited_descriptor, True)
        self.addCleanup(os.close, inherited_descriptor)
        probe = self.test_root / "launcher-probe.py"
        probe.write_text(
            "import json, os, sys\n"
            "try:\n"
            f"    os.fstat({inherited_descriptor})\n"
            "except OSError:\n"
            "    inherited_fd_open = False\n"
            "else:\n"
            "    inherited_fd_open = True\n"
            "sys.stdout.write(json.dumps({'argv': sys.argv, "
            "'environment': dict(os.environ), "
            "'inherited_fd_open': inherited_fd_open}, sort_keys=True))\n",
            encoding="ascii",
        )
        sentinel = self.test_root / "loader-constructor-ran"
        injection_source = self.test_root / "loader-injection.c"
        injection_source.write_text(
            "#include <fcntl.h>\n"
            "#include <unistd.h>\n"
            "__attribute__((constructor)) static void injected(void) {\n"
            f"  int fd = open({json.dumps(os.fspath(sentinel))}, "
            "O_WRONLY | O_CREAT | O_TRUNC, 0600);\n"
            "  if (fd >= 0) { (void)write(fd, \"loaded\\n\", 7); "
            "(void)close(fd); }\n"
            "}\n",
            encoding="ascii",
        )
        injection = self.test_root / "loader-injection.so"
        self._checked(
            [
                compiler,
                "-shared",
                "-fPIC",
                os.fspath(injection_source),
                "-o",
                os.fspath(injection),
            ]
        )

        def build_launcher(
            name: str, forward: bool, *, close_range_syscall: int | None = None
        ) -> Path:
            launcher = self.test_root / name
            command = [
                compiler,
                "-std=c11",
                "-Os",
                "-g0",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-stack-protector",
                "-fno-pie",
                "-fno-asynchronous-unwind-tables",
                "-fno-unwind-tables",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wconversion",
                "-Wformat=2",
                "-Wshadow",
                "-Wundef",
                f'-DGROK_LAUNCHER_SCRIPT="{probe}"',
                f"-DGROK_LAUNCHER_FORWARD_ARGS={int(forward)}",
            ]
            if close_range_syscall is not None:
                command.append(
                    "-DGROK_LAUNCHER_TEST_CLOSE_RANGE_SYSCALL="
                    + str(close_range_syscall)
                )
            command.extend(
                [
                    os.fspath(LAUNCHER_SOURCE),
                    "-nostdlib",
                    "-static",
                    "-no-pie",
                    "-Wl,-e,_start",
                    "-Wl,--build-id=none",
                    "-Wl,-z,noexecstack",
                    "-Wl,--fatal-warnings",
                    "-Wl,-s",
                    "-o",
                    os.fspath(launcher),
                ]
            )
            self._checked(command)
            program_headers = self._checked(
                ["/usr/bin/readelf", "-lW", os.fspath(launcher)]
            ).stdout
            dynamic = self._checked(
                ["/usr/bin/readelf", "-dW", os.fspath(launcher)]
            ).stdout
            self.assertNotIn(b"INTERP", program_headers)
            self.assertNotIn(b"DYNAMIC", program_headers)
            self.assertNotIn(b"NEEDED", dynamic)
            return launcher

        package_launcher = build_launcher("package-launcher", False)
        publisher_launcher = build_launcher("publisher-launcher", True)
        unavailable_close_range = build_launcher(
            "unavailable-close-range-launcher",
            False,
            close_range_syscall=999999,
        )
        hostile_environment = {
            "LD_PRELOAD": os.fspath(injection),
            "LD_LIBRARY_PATH": os.fspath(self.test_root),
            "PATH": "/hostile",
            "LANG": "hostile",
            "LC_ALL": "hostile",
            "PYTHONPATH": "/hostile",
            "PYTHONINSPECT": "1",
        }
        exact_environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        package = subprocess.run(
            [os.fspath(package_launcher), *["ignored"] * 80],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=hostile_environment,
            pass_fds=(inherited_descriptor,),
            check=False,
            timeout=10,
        )
        self.assertEqual(package.returncode, 0, package.stderr.decode("ascii"))
        package_result = json.loads(package.stdout)
        self.assertEqual(package_result["argv"], [os.fspath(probe)])
        self.assertEqual(package_result["environment"], exact_environment)
        self.assertFalse(package_result["inherited_fd_open"])
        self.assertFalse(sentinel.exists())

        unavailable = subprocess.run(
            [os.fspath(unavailable_close_range)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=hostile_environment,
            pass_fds=(inherited_descriptor,),
            check=False,
            timeout=10,
        )
        self.assertEqual(unavailable.returncode, 126)
        self.assertEqual(unavailable.stdout, b"")
        self.assertEqual(unavailable.stderr, b"grok-python-launcher: EXEC\n")
        self.assertFalse(sentinel.exists())

        forwarded = ["publish", "--expected-current", "none"]
        publisher = subprocess.run(
            [os.fspath(publisher_launcher), *forwarded],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=hostile_environment,
            pass_fds=(inherited_descriptor,),
            check=False,
            timeout=10,
        )
        self.assertEqual(publisher.returncode, 0, publisher.stderr.decode("ascii"))
        publisher_result = json.loads(publisher.stdout)
        self.assertEqual(
            publisher_result["argv"], [os.fspath(probe), *forwarded]
        )
        self.assertEqual(publisher_result["environment"], exact_environment)
        self.assertFalse(publisher_result["inherited_fd_open"])
        self.assertFalse(sentinel.exists())

        oversized = subprocess.run(
            [os.fspath(publisher_launcher), *["excess"] * 65],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=hostile_environment,
            check=False,
            timeout=10,
        )
        self.assertEqual(oversized.returncode, 126)
        self.assertEqual(oversized.stdout, b"")
        self.assertEqual(oversized.stderr, b"grok-python-launcher: EXEC\n")
        self.assertFalse(sentinel.exists())

    def test_package_install_preserves_both_lock_inodes_and_installs_publisher(
        self,
    ) -> None:
        if shutil.which("cc") is None or shutil.which("pkg-config") is None:
            self.skipTest("compiler and pkg-config are required")
        destination = self.test_root / "package-root"
        destination.mkdir(mode=0o700)
        command = [
            "/usr/bin/make",
            "-C",
            os.fspath(self.package_source),
            "install-test",
            f"KEY_ID={KEY_ID}",
            f"PUBLIC_KEY_HEX={self.public_key_hex}",
            "TEST_MODE=1",
            f"TEST_DESTDIR={destination}",
        ]
        def restrictive_umask() -> None:
            os.umask(0o077)

        first = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=restrictive_umask,
            check=False,
            timeout=30,
        )
        self.assertEqual(first.returncode, 0, first.stderr.decode("ascii"))
        update = destination / CONTROL_ROOT.relative_to("/") / "update.lock"
        operation = (
            destination / "var/lib/grok-proxy/release-control/operation.lock"
        )
        for directory in (
            destination / "usr",
            destination / "usr/local/libexec/grok-proxy/bootstrap",
            destination / "usr/local/libexec/grok-proxy/bootstrap-releases",
            destination / "var/lib/grok-proxy/release-control",
        ):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
        first_identities = {
            "update": (update.stat().st_dev, update.stat().st_ino),
            "operation": (operation.stat().st_dev, operation.stat().st_ino),
        }
        self._checked(command)
        self.assertEqual(
            first_identities["update"], (update.stat().st_dev, update.stat().st_ino)
        )
        self.assertEqual(
            first_identities["operation"],
            (operation.stat().st_dev, operation.stat().st_ino),
        )
        operation_descriptor = os.open(operation, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(operation_descriptor, fcntl.LOCK_EX)
        blocked_install = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            update_probe = os.open(update, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        fcntl.flock(
                            update_probe, fcntl.LOCK_SH | fcntl.LOCK_NB
                        )
                    except BlockingIOError:
                        break
                    else:
                        fcntl.flock(update_probe, fcntl.LOCK_UN)
                    if blocked_install.poll() is not None:
                        self.fail("package install exited before taking update.lock")
                    if time.monotonic() >= deadline:
                        self.fail("package install did not take update.lock")
                    time.sleep(0.01)
            finally:
                os.close(update_probe)
            self.assertIsNone(blocked_install.poll())
            fcntl.flock(operation_descriptor, fcntl.LOCK_UN)
            blocked_stdout, blocked_stderr = blocked_install.communicate(timeout=30)
        finally:
            os.close(operation_descriptor)
            if blocked_install.poll() is None:
                blocked_install.kill()
                blocked_install.wait(timeout=5)
        self.assertEqual(
            blocked_install.returncode,
            0,
            (blocked_stdout + blocked_stderr).decode("ascii", errors="replace"),
        )
        for lock in (update, operation):
            information = lock.stat()
            self.assertEqual(stat.S_IMODE(information.st_mode), 0o600)
            self.assertEqual(information.st_nlink, 1)
            self.assertEqual(information.st_size, 0)
        installed_publisher = (
            destination
            / CONTROL_ROOT.relative_to("/")
            / "grok-bootstrap-publisher"
        )
        self.assertEqual(stat.S_IMODE(installed_publisher.stat().st_mode), 0o555)
        launcher = installed_publisher.read_bytes()
        self.assertTrue(launcher.startswith(b"\x7fELF\x02\x01\x01"))
        self.assertIn(b"/usr/bin/python3\x00", launcher)
        self.assertIn(
            b"/usr/local/libexec/grok-proxy/bootstrap/"
            b"grok-bootstrap-publisher.py\x00",
            launcher,
        )
        self.assertIn(
            b"grok-static-python-launcher-v1:forward-bounded-64\x00",
            launcher,
        )
        self.assertEqual(
            stat.S_IMODE(
                (
                    destination
                    / CONTROL_ROOT.relative_to("/")
                    / "grok-bootstrap-publisher.py"
                )
                .stat()
                .st_mode
            ),
            0o444,
        )
        activator_root = destination / "usr/libexec/grok-bootstrap-package"
        payload_root = destination / "usr/lib/grok-bootstrap-package"
        self.assertEqual(stat.S_IMODE(activator_root.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE(payload_root.stat().st_mode), 0o555)
        package_launcher = activator_root / "grok-bootstrap-package-activate"
        self.assertEqual(stat.S_IMODE(package_launcher.stat().st_mode), 0o555)
        launcher_bytes = package_launcher.read_bytes()
        self.assertTrue(launcher_bytes.startswith(b"\x7fELF\x02\x01\x01"))
        self.assertIn(
            b"/usr/libexec/grok-bootstrap-package/activate_package.py\x00",
            launcher_bytes,
        )
        self.assertIn(
            b"grok-static-python-launcher-v1:zero-arguments\x00",
            launcher_bytes,
        )
        self.assertEqual(
            stat.S_IMODE((activator_root / "activate_package.py").stat().st_mode),
            0o444,
        )
        for name, expected_mode in (
            ("grok-bootstrap", 0o555),
            ("grok-bootstrap-publisher.py", 0o444),
            ("grok-bootstrap-publisher", 0o555),
        ):
            information = (payload_root / name).stat()
            self.assertEqual(stat.S_IMODE(information.st_mode), expected_mode)
            self.assertEqual(information.st_nlink, 1)
        described = self._checked(
            [
                os.fspath(
                    destination
                    / CONTROL_ROOT.relative_to("/")
                    / "grok-bootstrap"
                ),
                "--describe-trust-anchor",
            ]
        )
        self.assertEqual(
            json.loads(described.stdout),
            {
                "key_id": KEY_ID,
                "public_key_hex": self.public_key_hex,
                "schema_version": "grok-bootstrap-trust-anchor-v1",
            },
        )

    def test_package_install_rejects_unsafe_existing_operation_lock(self) -> None:
        for attack in ("mode", "symlink", "hardlink", "nonempty"):
            with self.subTest(attack=attack):
                destination = self.test_root / f"unsafe-operation-root-{attack}"
                lock = (
                    destination
                    / "var/lib/grok-proxy/release-control/operation.lock"
                )
                lock.parent.mkdir(parents=True, mode=0o755)
                destination.chmod(0o700)
                current = lock.parent
                while current != destination:
                    current.chmod(0o755)
                    current = current.parent
                if attack == "mode":
                    lock.touch(mode=0o600)
                    lock.chmod(0o644)
                elif attack == "symlink":
                    outside = destination / "outside-operation-lock"
                    outside.touch(mode=0o600)
                    lock.symlink_to(outside)
                elif attack == "hardlink":
                    outside = destination / "outside-operation-lock"
                    outside.touch(mode=0o600)
                    os.link(outside, lock)
                else:
                    lock.write_bytes(b"unsafe")
                    lock.chmod(0o600)
                rejected = subprocess.run(
                    [
                        "/usr/bin/make",
                        "-C",
                        os.fspath(self.package_source),
                        "install-test",
                        f"KEY_ID={KEY_ID}",
                        f"PUBLIC_KEY_HEX={self.public_key_hex}",
                        "TEST_MODE=1",
                        f"TEST_DESTDIR={destination}",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=30,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(
                    b"package lock is unsafe: operation.lock",
                    rejected.stderr,
                )

    def test_package_partial_activation_is_fail_closed_and_rerunnable(self) -> None:
        destination = self.test_root / "partial-package-root"
        destination.mkdir(mode=0o700)
        command = [
            "/usr/bin/make",
            "-C",
            os.fspath(self.package_source),
            "install-test",
            f"KEY_ID={KEY_ID}",
            f"PUBLIC_KEY_HEX={self.public_key_hex}",
            "TEST_MODE=1",
            f"TEST_DESTDIR={destination}",
        ]
        self._checked(command)
        control = destination / CONTROL_ROOT.relative_to("/")
        native = control / "grok-bootstrap"
        pending = control / "package-update.pending"

        def injected(stage: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                [*command, f"TEST_FAIL_AT={stage}"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )

        before_support = native.stat()
        support_failure = injected("support")
        self.assertNotEqual(support_failure.returncode, 0)
        self.assertIn(b"injected support failure", support_failure.stderr)
        after_support = native.stat()
        self.assertEqual(
            (before_support.st_dev, before_support.st_ino),
            (after_support.st_dev, after_support.st_ino),
        )
        self.assertTrue(pending.is_file())

        alternate = self.test_root / "different-same-anchor-package"
        alternate.mkdir(mode=0o755)
        build_root = self.package_source / "build"
        for name in (
            "activate_package.py",
            "grok-bootstrap-package-activate",
            "grok-bootstrap",
            "grok-bootstrap-publisher.py",
            "grok-bootstrap-publisher",
        ):
            shutil.copy2(build_root / name, alternate / name)
        different_publisher = alternate / "grok-bootstrap-publisher.py"
        different_publisher.chmod(0o644)
        different_publisher.write_bytes(different_publisher.read_bytes() + b"\n")
        different_publisher.chmod(0o444)
        different_generation = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                "-S",
                os.fspath(build_root / "activate_package.py"),
                "--test-root",
                os.fspath(destination),
                "--test-stage-from",
                os.fspath(alternate),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
                "GROK_BOOTSTRAP_PACKAGE_ACTIVATOR_TEST_MODE": "1",
            },
            check=False,
            timeout=30,
        )
        self.assertNotEqual(different_generation.returncode, 0)
        self.assertIn(
            b"pending package generation differs from the fixed payload",
            different_generation.stderr,
        )
        self.assertTrue(pending.is_file())
        self._checked(command)
        self.assertFalse(pending.exists())

        before_native = native.stat()
        native_failure = injected("native")
        self.assertNotEqual(native_failure.returncode, 0)
        self.assertIn(b"injected native failure", native_failure.stderr)
        after_native = native.stat()
        self.assertNotEqual(
            (before_native.st_dev, before_native.st_ino),
            (after_native.st_dev, after_native.st_ino),
        )
        self.assertTrue(pending.is_file())
        described = self._checked([os.fspath(native), "--describe-trust-anchor"])
        self.assertEqual(json.loads(described.stdout)["key_id"], KEY_ID)
        self._checked(command)
        self.assertFalse(pending.exists())

        before_rotation = native.stat()
        rotated = subprocess.run(
            [
                *[
                    item
                    for item in command
                    if not item.startswith("PUBLIC_KEY_HEX=")
                ],
                "PUBLIC_KEY_HEX=" + "a" * 64,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(rotated.returncode, 0)
        self.assertIn(b"key rotation requires an explicit future migration", rotated.stderr)
        after_rotation = native.stat()
        self.assertEqual(
            (before_rotation.st_dev, before_rotation.st_ino),
            (after_rotation.st_dev, after_rotation.st_ino),
        )
        self.assertFalse(pending.exists())

    def test_package_failure_hooks_and_test_build_override_are_preflight_rejected(
        self,
    ) -> None:
        destination = self.test_root / "rejected-package-root"
        destination.mkdir(mode=0o700)
        install_test = [
            "/usr/bin/make",
            "-C",
            os.fspath(self.package_source),
            "install-test",
            f"KEY_ID={KEY_ID}",
            f"PUBLIC_KEY_HEX={self.public_key_hex}",
            "TEST_MODE=1",
            f"TEST_DESTDIR={destination}",
        ]

        invalid_hook = subprocess.run(
            [*install_test, "TEST_FAIL_AT=invalid"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(invalid_hook.returncode, 0)
        self.assertIn(b"invalid choice", invalid_hook.stderr)
        self.assertFalse((destination / "usr").exists())
        self.assertFalse((destination / "var").exists())

        ambient_environment = dict(os.environ)
        ambient_environment.update(
            {"TEST_MODE": "1", "TEST_DESTDIR": os.fspath(destination)}
        )
        ambient_only = subprocess.run(
            [
                "/usr/bin/make",
                "-C",
                os.fspath(self.package_source),
                "install-test",
                f"KEY_ID={KEY_ID}",
                f"PUBLIC_KEY_HEX={self.public_key_hex}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=ambient_environment,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(ambient_only.returncode, 0)
        self.assertIn(b"requires command-line TEST_MODE=1", ambient_only.stderr)
        self.assertFalse((destination / "usr").exists())
        self.assertFalse((destination / "var").exists())

        production_make = subprocess.run(
            [
                "/usr/bin/make",
                "-C",
                os.fspath(self.package_source),
                "install",
                "DESTDIR=/",
                "GROK_BOOTSTRAP_PACKAGE_ACTIVATOR_TEST_MODE=1",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertNotEqual(production_make.returncode, 0)
        self.assertIn(b"root Make install is forbidden", production_make.stderr)

        test_build = subprocess.run(
            [
                "make",
                "-C",
                os.fspath(self.package_source),
                "all",
                f"KEY_ID={KEY_ID}",
                f"PUBLIC_KEY_HEX={self.public_key_hex}",
                "CFLAGS=-DGROK_BOOTSTRAP_TEST_BUILD=1",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(test_build.returncode, 0)
        self.assertIn(b"controlled by this Makefile", test_build.stderr)

    def test_package_toolchain_and_destination_ancestry_are_closed(self) -> None:
        hostile = self.test_root / "hostile-tools"
        hostile.mkdir(mode=0o755)
        sentinel = self.test_root / "hostile-tool-executed"
        tool = (
            "#!/bin/sh\n"
            f"printf attacked > {shlex.quote(os.fspath(sentinel))}\n"
            "exit 97\n"
        )
        for name in (
            "cat",
            "cc",
            "chmod",
            "flock",
            "grep",
            "id",
            "install",
            "mkdir",
            "mv",
            "nm",
            "pkg-config",
            "python3",
            "readelf",
            "rm",
            "sh",
            "stat",
            "sync",
        ):
            executable = hostile / name
            executable.write_text(tool, encoding="ascii")
            executable.chmod(0o755)
        safe_destination = self.test_root / "closed-toolchain-root"
        safe_destination.mkdir(mode=0o700)
        environment = dict(os.environ)
        environment.update(
            {
                "PATH": os.fspath(hostile) + ":/usr/bin:/bin",
                "CC": os.fspath(hostile / "cc"),
                "PKG_CONFIG": os.fspath(hostile / "pkg-config"),
                "CPPFLAGS": "-include /definitely/missing-hostile-header",
                "CFLAGS": "-B/definitely/missing-hostile-toolchain",
                "LDFLAGS": "-Wl,--definitely-invalid-hostile-option",
                "SHELL": os.fspath(hostile / "sh"),
                "BUILD_DIR": os.fspath(self.test_root / "ambient-build-root"),
            }
        )
        closed = subprocess.run(
            [
                "/usr/bin/make",
                "-C",
                os.fspath(self.package_source),
                "install-test",
                f"KEY_ID={KEY_ID}",
                f"PUBLIC_KEY_HEX={self.public_key_hex}",
                "TEST_MODE=1",
                f"TEST_DESTDIR={safe_destination}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
            timeout=30,
        )
        self.assertEqual(closed.returncode, 0, closed.stderr.decode("ascii"))
        self.assertFalse(sentinel.exists())
        self.assertFalse((self.test_root / "ambient-build-root").exists())

        writable_parent = self.test_root / "writable-package-parent"
        writable_parent.mkdir(mode=0o777)
        writable_parent.chmod(0o777)
        writable_destination = writable_parent / "root"
        writable_destination.mkdir(mode=0o700)
        writable = subprocess.run(
            [
                "/usr/bin/make",
                "-C",
                os.fspath(self.package_source),
                "install-test",
                f"KEY_ID={KEY_ID}",
                f"PUBLIC_KEY_HEX={self.public_key_hex}",
                "TEST_MODE=1",
                f"TEST_DESTDIR={writable_destination}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(writable.returncode, 0)
        self.assertIn(b"test root ancestry is unsafe", writable.stderr)
        self.assertFalse((writable_destination / "usr").exists())

        real_destination = self.test_root / "real-package-root"
        real_destination.mkdir(mode=0o700)
        linked_destination = self.test_root / "linked-package-root"
        linked_destination.symlink_to(real_destination.name)
        linked = subprocess.run(
            [
                "/usr/bin/make",
                "-C",
                os.fspath(self.package_source),
                "install-test",
                f"KEY_ID={KEY_ID}",
                f"PUBLIC_KEY_HEX={self.public_key_hex}",
                "TEST_MODE=1",
                f"TEST_DESTDIR={linked_destination}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(linked.returncode, 0)
        self.assertIn(b"canonical", linked.stderr)
        self.assertFalse((real_destination / "usr").exists())

        nested_destination = self.test_root / "nested-link-package-root"
        nested_destination.mkdir(mode=0o700)
        outside = self.test_root / "nested-link-outside"
        outside.mkdir(mode=0o755)
        (nested_destination / "usr").symlink_to(outside)
        nested = subprocess.run(
            [
                "/usr/bin/make",
                "-C",
                os.fspath(self.package_source),
                "install-test",
                f"KEY_ID={KEY_ID}",
                f"PUBLIC_KEY_HEX={self.public_key_hex}",
                "TEST_MODE=1",
                f"TEST_DESTDIR={nested_destination}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(nested.returncode, 0)
        self.assertIn(b"fixed package directory authority is unsafe", nested.stderr)
        self.assertEqual(list(outside.iterdir()), [])

    def test_package_activator_rejects_unsafe_fixed_payload_and_self_files(
        self,
    ) -> None:
        for attack in (
            "payload-mode",
            "payload-symlink",
            "payload-hardlink",
            "payload-extra",
            "payload-ancestry",
            "payload-dynamic-launcher",
            "activator-mode",
            "activator-dynamic-launcher",
        ):
            with self.subTest(attack=attack):
                destination = self.test_root / f"fixed-package-attack-{attack}"
                destination.mkdir(mode=0o700)
                self._checked(
                    [
                        "/usr/bin/make",
                        "-C",
                        os.fspath(self.package_source),
                        "install-test",
                        f"KEY_ID={KEY_ID}",
                        f"PUBLIC_KEY_HEX={self.public_key_hex}",
                        "TEST_MODE=1",
                        f"TEST_DESTDIR={destination}",
                    ]
                )
                payload_root = destination / "usr/lib/grok-bootstrap-package"
                activator_root = (
                    destination / "usr/libexec/grok-bootstrap-package"
                )
                publisher = payload_root / "grok-bootstrap-publisher.py"
                if attack == "payload-mode":
                    publisher.chmod(0o644)
                elif attack == "payload-symlink":
                    payload_root.chmod(0o755)
                    publisher.unlink()
                    publisher.symlink_to("grok-bootstrap")
                    payload_root.chmod(0o555)
                elif attack == "payload-hardlink":
                    payload_root.chmod(0o755)
                    publisher.unlink()
                    outside = destination / "outside-package-artifact"
                    outside.write_bytes(b"unsafe\n")
                    outside.chmod(0o444)
                    os.link(outside, publisher)
                    payload_root.chmod(0o555)
                elif attack == "payload-extra":
                    payload_root.chmod(0o755)
                    extra = payload_root / "unexpected"
                    extra.write_bytes(b"unsafe\n")
                    extra.chmod(0o444)
                    payload_root.chmod(0o555)
                elif attack == "payload-ancestry":
                    (destination / "usr/lib").chmod(0o775)
                elif attack == "payload-dynamic-launcher":
                    payload_root.chmod(0o755)
                    dynamic_launcher = payload_root / "grok-bootstrap-publisher"
                    dynamic_launcher.unlink()
                    shutil.copy2("/usr/bin/true", dynamic_launcher)
                    dynamic_launcher.chmod(0o555)
                    payload_root.chmod(0o555)
                elif attack == "activator-mode":
                    (activator_root / "activate_package.py").chmod(0o644)
                else:
                    activator_root.chmod(0o755)
                    dynamic_launcher = (
                        activator_root / "grok-bootstrap-package-activate"
                    )
                    dynamic_launcher.unlink()
                    shutil.copy2("/usr/bin/true", dynamic_launcher)
                    dynamic_launcher.chmod(0o555)
                    activator_root.chmod(0o555)

                rejected = subprocess.run(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-B",
                        "-S",
                        os.fspath(self.package_source / "build/activate_package.py"),
                        "--test-root",
                        os.fspath(destination),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "GROK_BOOTSTRAP_PACKAGE_ACTIVATOR_TEST_MODE": "1",
                    },
                    check=False,
                    timeout=30,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(
                    (
                        destination
                        / CONTROL_ROOT.relative_to("/")
                        / "package-update.pending"
                    ).exists()
                )

    def test_package_metadata_installs_fixed_administrative_tool_and_locks(self) -> None:
        metadata = json.loads(
            (BOOTSTRAP_ROOT / "package/grok-bootstrap-package.json").read_text(
                encoding="utf-8"
            )
        )
        publisher = metadata["administrative_publisher"]
        self.assertEqual(
            publisher["path"],
            "/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap-publisher",
        )
        self.assertFalse(publisher["candidate_installer_invokes_publisher"])
        self.assertEqual(
            publisher["release_control_operation_lock"],
            "/var/lib/grok-proxy/release-control/operation.lock",
        )
        self.assertFalse(metadata["package_requirements"]["in_place_key_rotation_supported"])
        self.assertTrue(metadata["package_transaction"]["consumers_fail_closed_while_pending"])
        transaction = metadata["package_transaction"]
        self.assertTrue(transaction["make_is_never_invoked_as_root"])
        self.assertEqual(
            transaction["activation_command"],
            "/usr/libexec/grok-bootstrap-package/grok-bootstrap-package-activate",
        )
        self.assertEqual(transaction["activation_arguments"], [])
        self.assertFalse(transaction["production_launcher_forwards_arguments"])
        self.assertFalse(transaction["production_launcher_can_reach_test_controls"])
        self.assertTrue(
            transaction["different_same_key_generation_while_pending_fails_closed"]
        )
        artifacts = metadata["artifacts"]
        self.assertEqual(
            metadata["supported_launcher_architectures"],
            ["x86_64", "aarch64"],
        )
        self.assertEqual(artifacts["payload_root"], "/usr/lib/grok-bootstrap-package")
        self.assertEqual(
            artifacts["activator_root"], "/usr/libexec/grok-bootstrap-package"
        )
        for description in (
            *artifacts["closed_payload"].values(),
            *artifacts["closed_activator"].values(),
        ):
            self.assertEqual(description["link_count"], 1)
        self.assertIn(
            "freestanding static",
            artifacts["closed_payload"]["grok-bootstrap-publisher"]["format"],
        )
        self.assertTrue(transaction["launcher_has_no_libc_startup"])
        self.assertTrue(transaction["directory_modes_independent_of_inherited_umask"])
        self.assertIn("production private signing key", metadata["forbidden_inputs"])


if __name__ == "__main__":
    unittest.main()
