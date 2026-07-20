#!/usr/bin/env python3
"""Adversarial tests for the native pre-import Grok bootstrap."""

from __future__ import annotations

import ast
import fcntl
import hashlib
import json
import importlib.util
import os
from pathlib import Path
import pwd
import select
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile


PROXY_ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_ROOT = PROXY_ROOT / "bootstrap"
BUILDER = BOOTSTRAP_ROOT / "build_bundle.py"
STAGER = BOOTSTRAP_ROOT / "stage_dispatcher.py"
DISPATCHER_MAIN = BOOTSTRAP_ROOT / "dispatcher_main.py"
SOURCE = BOOTSTRAP_ROOT / "bootstrap.c"
PACKAGE_METADATA = BOOTSTRAP_ROOT / "package" / "grok-bootstrap-package.json"
DEBIAN_PACKAGE_BUILDER = BOOTSTRAP_ROOT / "build_debian_package.py"
DPKG_DEB = Path("/usr/bin/dpkg-deb")
OPENSSL = Path("/usr/bin/openssl")
KEY_ID = "test-key"
DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
ARTIFACTS = (
    "dispatcher.pyz",
    "release-manifest.sig",
    "release-manifest.txt",
)
PACKAGE_BUILD_INPUTS = (
    "Makefile",
    "activate_package.py",
    "bootstrap.c",
    "isolated_python_launcher.c",
    "publish_signed_application.py",
)


class BootstrapTests(unittest.TestCase):
    """Compile with an ephemeral key; never put a private key in the tree."""

    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc")
        pkg_config = shutil.which("pkg-config")
        if compiler is None or pkg_config is None or not OPENSSL.is_file():
            raise unittest.SkipTest("C compiler, pkg-config, and /usr/bin/openssl required")

        cls._temporary = tempfile.TemporaryDirectory(
            prefix="grok-bootstrap-tests-", dir=Path.home()
        )
        cls.root = Path(cls._temporary.name)
        cls.compiler = compiler
        cls.pkg_config = pkg_config
        accounts = [
            account
            for account in pwd.getpwall()
            if account.pw_uid > 0
            and account.pw_dir.startswith("/")
            and account.pw_dir != "/"
        ]
        if not accounts:
            raise unittest.SkipTest("bootstrap test needs a non-root passwd account")
        cls.sudo_target_uid = accounts[0].pw_uid
        cls.key_one = cls.root / "key-one.pem"
        cls.key_two = cls.root / "key-two.pem"
        cls.public_key_one = cls._generate_key(cls.key_one)
        cls._generate_key(cls.key_two)
        cls.test_binary = cls.root / "grok-bootstrap-test"
        cls.production_binary = cls.root / "grok-bootstrap-production-check"
        cls._compile_binary(cls.test_binary, test_build=True)
        cls._compile_binary(cls.production_binary, test_build=False)

        cls.package_source = cls.root / "package-source"
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

        cls.source_tree = cls.root / "application-source"
        (cls.source_tree / "pkg").mkdir(parents=True)
        (cls.source_tree / "__main__.py").write_text(
            "import fcntl\n"
            "import os\n"
            "import stat\n"
            "import sys\n"
            "\n"
            "authority_fd = int(os.environ['GROK_BOOTSTRAP_AUTHORITY_FD'])\n"
            "authority = os.fstat(authority_fd)\n"
            "expected_seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | "
            "fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)\n"
            "authority_valid = (\n"
            "    stat.S_ISREG(authority.st_mode)\n"
            "    and stat.S_IMODE(authority.st_mode) == 0o600\n"
            "    and authority.st_nlink == 0\n"
            "    and (fcntl.fcntl(authority_fd, fcntl.F_GET_SEALS) & expected_seals)\n"
            "        == expected_seals\n"
            "    and not (fcntl.fcntl(authority_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)\n"
            "    and os.readlink(f'/proc/self/fd/{authority_fd}').lstrip('/')\n"
            "        == 'memfd:grok-dispatcher (deleted)'\n"
            ")\n"
            "with open(sys.argv[1], 'w', encoding='ascii') as marker:\n"
            "    marker.write('executed\\n')\n"
            "    marker.write(os.getcwd() + '\\n')\n"
            "    marker.write(','.join(sorted(os.environ)) + '\\n')\n"
            "    marker.write(os.environ.get('SUDO_UID', '<absent>') + '\\n')\n"
            "    marker.write('authority-valid' if authority_valid else 'authority-invalid')\n",
            encoding="ascii",
        )
        (cls.source_tree / "pkg" / "value.py").write_text(
            "VALUE = 17\n", encoding="ascii"
        )
        (cls.source_tree / "tool.sh").write_text(
            "#!/bin/sh\nexit 0\n", encoding="ascii"
        )
        (cls.source_tree / "tool.sh").chmod(0o755)

        cls.base_output = cls.root / "base-output"
        cls.base_output.mkdir()
        cls.base_release = cls._build_bundle(cls.base_output, cls.key_one)

        cls.dispatcher_stage = cls.root / "dispatcher-stage"
        cls._stage_dispatcher(cls.dispatcher_stage)
        cls.dispatcher_output = cls.root / "dispatcher-output"
        cls.dispatcher_output.mkdir()
        cls.dispatcher_release = cls._build_bundle(
            cls.dispatcher_output, cls.key_one, source=cls.dispatcher_stage
        )

        module_spec = importlib.util.spec_from_file_location(
            "grok_bootstrap_dispatcher_main", DISPATCHER_MAIN
        )
        if module_spec is None or module_spec.loader is None:
            raise AssertionError("cannot load dispatcher extraction shim")
        cls.dispatcher_module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(cls.dispatcher_module)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "root"):
            cls._make_tree_removable(cls.root)
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()

    def setUp(self) -> None:
        self._case_counter = 0

    @classmethod
    def _run_checked(cls, command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        completed = subprocess.run(command, check=False, capture_output=True, **kwargs)
        if completed.returncode != 0:
            raise AssertionError(
                f"command failed ({completed.returncode}): {command!r}\n"
                f"stdout: {completed.stdout!r}\nstderr: {completed.stderr!r}"
            )
        return completed

    @classmethod
    def _generate_key(cls, path: Path) -> str:
        cls._run_checked(
            [
                os.fspath(OPENSSL),
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                os.fspath(path),
            ]
        )
        path.chmod(0o600)
        public = cls._run_checked(
            [
                os.fspath(OPENSSL),
                "pkey",
                "-in",
                os.fspath(path),
                "-pubout",
                "-outform",
                "DER",
            ]
        ).stdout
        if len(public) != len(DER_PREFIX) + 32 or not public.startswith(DER_PREFIX):
            raise AssertionError("unexpected OpenSSL Ed25519 public-key encoding")
        return public[len(DER_PREFIX) :].hex()

    @classmethod
    def _compile_binary(cls, output: Path, *, test_build: bool) -> None:
        cflags = shlex.split(
            cls._run_checked([cls.pkg_config, "--cflags", "openssl"], text=True).stdout
        )
        libraries = shlex.split(
            cls._run_checked([cls.pkg_config, "--libs", "openssl"], text=True).stdout
        )
        command = [
            cls.compiler,
            "-D_FORTIFY_SOURCE=3",
            "-std=c11",
            "-O2",
            "-g0",
            "-fPIE",
            "-fstack-protector-strong",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wconversion",
            "-Wformat=2",
            "-Wshadow",
            "-Wstrict-prototypes",
            "-Wundef",
            f'-DGROK_BOOTSTRAP_KEY_ID="{KEY_ID}"',
            f'-DGROK_BOOTSTRAP_PUBLIC_KEY_HEX="{cls.public_key_one}"',
        ]
        if test_build:
            command.append("-DGROK_BOOTSTRAP_TEST_BUILD=1")
        command.extend(
            [
                *cflags,
                os.fspath(SOURCE),
                "-o",
                os.fspath(output),
                "-Wl,-z,relro,-z,now",
                "-pie",
                *libraries,
            ]
        )
        cls._run_checked(command, text=True)

    @classmethod
    def _build_bundle(
        cls, output: Path, key: Path, *, source: Path | None = None
    ) -> Path:
        if source is None:
            source = cls.source_tree
        completed = cls._run_checked(
            [
                sys.executable,
                os.fspath(BUILDER),
                "--source",
                os.fspath(source),
                "--output",
                os.fspath(output),
                "--key-id",
                KEY_ID,
                "--signing-key",
                os.fspath(key),
                "--openssl",
                os.fspath(OPENSSL),
            ],
            text=True,
        )
        return Path(completed.stdout.strip())

    @classmethod
    def _stage_dispatcher(cls, output: Path, *, source: Path = PROXY_ROOT) -> Path:
        completed = cls._run_checked(
            [
                sys.executable,
                "-B",
                os.fspath(STAGER),
                "--source-root",
                os.fspath(source),
                "--output",
                os.fspath(output),
            ],
            text=True,
        )
        staged = Path(completed.stdout.strip())
        if staged != output:
            raise AssertionError("dispatcher stager returned an unexpected path")
        return staged

    def _dispatcher_authoring_fixture(self, label: str) -> Path:
        source = self.root / f"dispatcher-authoring-{self._testMethodName}-{label}"
        source.mkdir()
        for name in self.dispatcher_module.REQUIRED_TOP_LEVEL:
            shutil.copy2(PROXY_ROOT / name, source / name)
        brokers = [
            name
            for name in self.dispatcher_module.BROKER_CANDIDATES
            if (PROXY_ROOT / name).is_file()
        ]
        self.assertEqual(len(brokers), 1)
        shutil.copy2(PROXY_ROOT / brokers[0], source / brokers[0])
        shutil.copytree(PROXY_ROOT / "grok_ms", source / "grok_ms")
        (source / "bootstrap").mkdir()
        shutil.copy2(DISPATCHER_MAIN, source / "bootstrap" / "dispatcher_main.py")
        return source

    @staticmethod
    def _make_tree_removable(root: Path) -> None:
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            try:
                information = path.lstat()
                if stat.S_ISLNK(information.st_mode):
                    continue
                path.chmod(0o700 if stat.S_ISDIR(information.st_mode) else 0o600)
            except FileNotFoundError:
                pass

    def _copy_release(self, label: str) -> Path:
        self._case_counter += 1
        parent = self.root / "cases" / f"{self._testMethodName}-{self._case_counter}-{label}"
        parent.mkdir(parents=True)
        parent.chmod(0o755)
        release = parent / self.base_release.name
        shutil.copytree(self.base_release, release, copy_function=shutil.copy2)
        for artifact in ARTIFACTS:
            (release / artifact).chmod(0o444)
        release.chmod(0o555)
        selector = parent / "selected-release"
        selector.write_text(release.name + "\n", encoding="ascii")
        selector.chmod(0o444)
        update_lock = parent / "update.lock"
        update_lock.touch(mode=0o600)
        update_lock.chmod(0o600)
        return release

    def _run_bootstrap(
        self,
        release: Path,
        marker: Path,
        *,
        environment: dict[str, str] | None = None,
        supply_target_identity: bool = True,
    ) -> subprocess.CompletedProcess:
        if environment is None:
            environment = os.environ.copy()
        environment["GROK_BOOTSTRAP_TEST_SELECTOR_DIR"] = os.fspath(
            release.parent
        )
        if (
            supply_target_identity
            and os.geteuid() == 0
            and self.sudo_target_uid is not None
        ):
            environment["SUDO_UID"] = str(self.sudo_target_uid)
        return subprocess.run(
            [
                os.fspath(self.test_binary),
                "--release-dir",
                os.fspath(release),
                "--",
                os.fspath(marker),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=10,
            check=False,
        )

    def _assert_preimport_failure(
        self, completed: subprocess.CompletedProcess, marker: Path
    ) -> None:
        self.assertEqual(completed.returncode, 126)
        self.assertEqual(completed.stdout, b"")
        self.assertFalse(marker.exists(), "candidate Python executed on bootstrap failure")
        self.assertTrue(completed.stderr.startswith(b"grok-bootstrap: "))
        self.assertLessEqual(len(completed.stderr), 96)
        self.assertNotIn(os.fsencode(self.root), completed.stderr)
        self.assertTrue(completed.stderr.endswith(b"\n"))

    @staticmethod
    def _rewrite_artifact(path: Path, content: bytes) -> None:
        path.chmod(0o644)
        path.write_bytes(content)
        path.chmod(0o444)

    @classmethod
    def _resign_manifest(cls, release: Path, key: Path) -> None:
        signature = release / "release-manifest.sig"
        signature.chmod(0o644)
        cls._run_checked(
            [
                os.fspath(OPENSSL),
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                os.fspath(key),
                "-in",
                os.fspath(release / "release-manifest.txt"),
                "-out",
                os.fspath(signature),
            ]
        )
        signature.chmod(0o444)

    def test_valid_release_executes_sealed_bundle_with_closed_context(self) -> None:
        release = self._copy_release("valid")
        marker = release.parent / "marker.txt"
        environment = os.environ.copy()
        environment["PYTHONPATH"] = "/candidate/controlled/path"
        environment["GROK_SENTINEL"] = "must-not-cross-exec"
        environment["SUDO_USER"] = "must-not-cross-exec"
        environment["SUDO_GID"] = "999999"
        hostile_openssl = release.parent / "hostile-openssl.cnf"
        hostile_openssl.write_text(
            "config_diagnostics = 1\n"
            "openssl_conf = hostile_init\n"
            "[hostile_init]\n"
            "providers = hostile_providers\n"
            "[hostile_providers]\n"
            "hostile = hostile_provider\n"
            "[hostile_provider]\n"
            "module = /definitely/not/a/provider.so\n"
            "activate = 1\n",
            encoding="ascii",
        )
        environment["OPENSSL_CONF"] = os.fspath(hostile_openssl)
        environment["OPENSSL_MODULES"] = "/caller/controlled/providers"
        if os.geteuid() != 0:
            environment["SUDO_UID"] = "malformed-must-be-dropped"

        completed = self._run_bootstrap(release, marker, environment=environment)

        self.assertEqual(completed.returncode, 0, completed.stderr.decode("ascii"))
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")
        lines = marker.read_text(encoding="ascii").splitlines()
        self.assertEqual(lines[0], "executed")
        self.assertEqual(lines[1], "/")
        expected_environment = {
            "GROK_BOOTSTRAP_AUTHORITY_FD",
            "LANG",
            "LC_ALL",
            "PATH",
            "PYTHONDONTWRITEBYTECODE",
        }
        if os.geteuid() == 0:
            expected_environment.add("SUDO_UID")
            self.assertEqual(lines[3], str(self.sudo_target_uid))
        else:
            self.assertEqual(lines[3], "<absent>")
        self.assertEqual(set(lines[2].split(",")), expected_environment)
        self.assertEqual(lines[4], "authority-valid")

    def test_selector_rejects_downgrade_and_unsafe_metadata_before_import(self) -> None:
        attacks = ("mismatch", "uppercase", "missing", "mode", "symlink", "hardlink", "fifo")
        for attack in attacks:
            with self.subTest(attack=attack):
                release = self._copy_release(f"selector-{attack}")
                selector = release.parent / "selected-release"
                marker = release.parent / "marker.txt"
                if attack in {"mismatch", "uppercase"}:
                    selector.chmod(0o644)
                    value = "f" * 64 if attack == "mismatch" else "A" * 64
                    selector.write_text(value + "\n", encoding="ascii")
                    selector.chmod(0o444)
                elif attack == "missing":
                    selector.unlink()
                elif attack == "mode":
                    selector.chmod(0o644)
                elif attack == "symlink":
                    selector.unlink()
                    selector.symlink_to(release.name)
                elif attack == "hardlink":
                    outside = release.parent / "selector-outside"
                    outside.write_text(release.name + "\n", encoding="ascii")
                    outside.chmod(0o444)
                    selector.unlink()
                    os.link(outside, selector)
                else:
                    selector.unlink()
                    os.mkfifo(selector, 0o444)

                completed = self._run_bootstrap(release, marker)
                self._assert_preimport_failure(completed, marker)
                self.assertEqual(
                    completed.stderr, b"grok-bootstrap: SELECTOR_AUTHORITY\n"
                )

    def test_update_lock_rejects_unsafe_metadata_before_import(self) -> None:
        attacks = ("missing", "mode", "symlink", "hardlink", "fifo", "nonempty")
        for attack in attacks:
            with self.subTest(attack=attack):
                release = self._copy_release(f"update-lock-{attack}")
                update_lock = release.parent / "update.lock"
                marker = release.parent / "marker.txt"
                if attack == "missing":
                    update_lock.unlink()
                elif attack == "mode":
                    update_lock.chmod(0o644)
                elif attack == "symlink":
                    update_lock.unlink()
                    update_lock.symlink_to("selected-release")
                elif attack == "hardlink":
                    outside = release.parent / "update-lock-outside"
                    outside.touch(mode=0o600)
                    outside.chmod(0o600)
                    update_lock.unlink()
                    os.link(outside, update_lock)
                elif attack == "fifo":
                    update_lock.unlink()
                    os.mkfifo(update_lock, 0o600)
                else:
                    update_lock.write_bytes(b"not-empty")

                completed = self._run_bootstrap(release, marker)
                self._assert_preimport_failure(completed, marker)
                self.assertEqual(
                    completed.stderr, b"grok-bootstrap: SELECTOR_AUTHORITY\n"
                )

    def test_incomplete_package_update_is_rejected_before_import(self) -> None:
        release = self._copy_release("package-update-pending")
        marker = release.parent / "marker.txt"
        package_pending = release.parent / "package-update.pending"
        package_pending.write_bytes(b"package update in progress\n")
        package_pending.chmod(0o444)

        completed = self._run_bootstrap(release, marker)

        self._assert_preimport_failure(completed, marker)
        self.assertEqual(completed.stderr, b"grok-bootstrap: SELECTOR_AUTHORITY\n")

    def test_update_lock_is_root_only_and_package_install_preserves_inode(self) -> None:
        release = self._copy_release("update-lock-permissions")
        update_lock = release.parent / "update.lock"
        information = update_lock.stat()
        self.assertEqual(stat.S_IMODE(information.st_mode), 0o600)
        self.assertEqual(information.st_nlink, 1)
        self.assertEqual(information.st_size, 0)
        if os.geteuid() == 0:
            account = pwd.getpwuid(self.sudo_target_uid)

            def drop_privileges() -> None:
                os.setgroups([])
                os.setgid(account.pw_gid)
                os.setuid(account.pw_uid)

            denied = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os,sys; os.open(sys.argv[1], os.O_RDONLY)",
                    os.fspath(update_lock),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=drop_privileges,
                check=False,
                timeout=10,
            )
            self.assertNotEqual(denied.returncode, 0)

        destination = self.root / f"package-root-{self._testMethodName}"
        destination.mkdir(mode=0o700)
        command = [
            "/usr/bin/make",
            "-C",
            os.fspath(self.package_source),
            "install-test",
            f"KEY_ID={KEY_ID}",
            f"PUBLIC_KEY_HEX={self.public_key_one}",
            "TEST_MODE=1",
            f"TEST_DESTDIR={destination}",
        ]
        self._run_checked(command)
        installed_lock = (
            destination / "usr/local/libexec/grok-proxy/bootstrap/update.lock"
        )
        first = installed_lock.stat()
        self._run_checked(command)
        second = installed_lock.stat()
        self.assertEqual((first.st_dev, first.st_ino), (second.st_dev, second.st_ino))
        self.assertEqual(stat.S_IMODE(second.st_mode), 0o600)
        self.assertEqual(second.st_nlink, 1)
        self.assertEqual(second.st_size, 0)

    def test_package_install_rejects_unsafe_existing_update_lock(self) -> None:
        for attack in ("mode", "symlink", "hardlink", "nonempty"):
            with self.subTest(attack=attack):
                destination = self.root / f"unsafe-lock-root-{attack}"
                lock = destination / "usr/local/libexec/grok-proxy/bootstrap/update.lock"
                lock.parent.mkdir(parents=True)
                destination.chmod(0o700)
                current = lock.parent
                while current != destination:
                    current.chmod(0o755)
                    current = current.parent
                if attack == "mode":
                    lock.touch(mode=0o600)
                    lock.chmod(0o644)
                elif attack == "symlink":
                    outside = destination / "outside-lock"
                    outside.touch(mode=0o600)
                    lock.symlink_to(outside)
                elif attack == "hardlink":
                    outside = destination / "outside-lock"
                    outside.touch(mode=0o600)
                    os.link(outside, lock)
                else:
                    lock.write_bytes(b"unsafe")
                    lock.chmod(0o600)
                completed = subprocess.run(
                    [
                        "/usr/bin/make",
                        "-C",
                        os.fspath(self.package_source),
                        "install-test",
                        f"KEY_ID={KEY_ID}",
                        f"PUBLIC_KEY_HEX={self.public_key_one}",
                        "TEST_MODE=1",
                        f"TEST_DESTDIR={destination}",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=30,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    b"package lock is unsafe: update.lock",
                    completed.stderr,
                )

    def test_production_bootstrap_rejects_non_root_before_path_handling(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="grok-production-bootstrap-", dir="/tmp"
        ) as td:
            public_directory = Path(td)
            public_directory.chmod(0o755)
            executable = public_directory / "grok-bootstrap"
            shutil.copy2(self.production_binary, executable)
            executable.chmod(0o555)
            preexec = None
            if os.geteuid() == 0:
                account = pwd.getpwuid(self.sudo_target_uid)

                def drop_privileges() -> None:
                    os.setgroups([])
                    os.setgid(account.pw_gid)
                    os.setuid(account.pw_uid)

                preexec = drop_privileges
            completed = subprocess.run(
                [os.fspath(executable)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=preexec,
                check=False,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 126)
            self.assertEqual(
                completed.stderr, b"grok-bootstrap: TARGET_IDENTITY\n"
            )

    def test_legacy_memfd_fallback_removes_execute_mode(self) -> None:
        release = self._copy_release("legacy-memfd")
        marker = release.parent / "marker.txt"
        environment = os.environ.copy()
        environment["GROK_BOOTSTRAP_TEST_FORCE_MEMFD_FALLBACK"] = "1"
        completed = self._run_bootstrap(release, marker, environment=environment)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("ascii"))
        self.assertEqual(
            marker.read_text(encoding="ascii").splitlines()[4],
            "authority-valid",
        )

    def test_selector_replacement_is_rejected_at_final_exec_boundary(self) -> None:
        release = self._copy_release("selector-race")
        selector = release.parent / "selected-release"
        marker = release.parent / "marker.txt"
        ready_read, ready_write = os.pipe()
        continue_read, continue_write = os.pipe()
        environment = os.environ.copy()
        environment["GROK_BOOTSTRAP_TEST_READY_FD"] = str(ready_write)
        environment["GROK_BOOTSTRAP_TEST_CONTINUE_FD"] = str(continue_read)
        environment["GROK_BOOTSTRAP_TEST_SELECTOR_DIR"] = os.fspath(
            release.parent
        )
        process = subprocess.Popen(
            [
                os.fspath(self.test_binary),
                "--release-dir",
                os.fspath(release),
                "--",
                os.fspath(marker),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            pass_fds=(ready_write, continue_read),
        )
        os.close(ready_write)
        os.close(continue_read)
        try:
            readable, _, _ = select.select([ready_read], [], [], 5.0)
            self.assertEqual(readable, [ready_read])
            self.assertEqual(os.read(ready_read, 1), b"R")
            selector.unlink()
            selector.write_text(release.name + "\n", encoding="ascii")
            selector.chmod(0o444)
            os.write(continue_write, b"C")
            stdout, stderr = process.communicate(timeout=10)
        finally:
            os.close(ready_read)
            os.close(continue_write)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

        completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        self._assert_preimport_failure(completed, marker)
        self.assertEqual(completed.stderr, b"grok-bootstrap: SELECTOR_AUTHORITY\n")

    def test_update_lock_replacement_is_rejected_at_final_exec_boundary(self) -> None:
        release = self._copy_release("update-lock-race")
        update_lock = release.parent / "update.lock"
        marker = release.parent / "marker.txt"
        ready_read, ready_write = os.pipe()
        continue_read, continue_write = os.pipe()
        environment = os.environ.copy()
        environment["GROK_BOOTSTRAP_TEST_READY_FD"] = str(ready_write)
        environment["GROK_BOOTSTRAP_TEST_CONTINUE_FD"] = str(continue_read)
        environment["GROK_BOOTSTRAP_TEST_SELECTOR_DIR"] = os.fspath(
            release.parent
        )
        process = subprocess.Popen(
            [
                os.fspath(self.test_binary),
                "--release-dir",
                os.fspath(release),
                "--",
                os.fspath(marker),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            pass_fds=(ready_write, continue_read),
        )
        os.close(ready_write)
        os.close(continue_read)
        try:
            readable, _, _ = select.select([ready_read], [], [], 5.0)
            self.assertEqual(readable, [ready_read])
            self.assertEqual(os.read(ready_read, 1), b"R")
            update_lock.unlink()
            update_lock.touch(mode=0o600)
            update_lock.chmod(0o600)
            os.write(continue_write, b"C")
            stdout, stderr = process.communicate(timeout=10)
        finally:
            os.close(ready_read)
            os.close(continue_write)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

        completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        self._assert_preimport_failure(completed, marker)
        self.assertEqual(completed.stderr, b"grok-bootstrap: SELECTOR_AUTHORITY\n")

    def test_selector_update_lock_serializes_authorization(self) -> None:
        release = self._copy_release("selector-update-lock")
        marker = release.parent / "marker.txt"
        lock_fd = os.open(
            release.parent / "update.lock",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        environment = os.environ.copy()
        environment["GROK_BOOTSTRAP_TEST_SELECTOR_DIR"] = os.fspath(release.parent)
        if os.geteuid() == 0 and self.sudo_target_uid is not None:
            environment["SUDO_UID"] = str(self.sudo_target_uid)
        process = subprocess.Popen(
            [
                os.fspath(self.test_binary),
                "--release-dir",
                os.fspath(release),
                "--",
                os.fspath(marker),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        try:
            replacement = release.parent / "selected-release.next"
            replacement.write_text("f" * 64 + "\n", encoding="ascii")
            replacement.chmod(0o444)
            os.replace(replacement, release.parent / "selected-release")
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            stdout, stderr = process.communicate(timeout=10)
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

        completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        self._assert_preimport_failure(completed, marker)
        self.assertEqual(completed.stderr, b"grok-bootstrap: SELECTOR_AUTHORITY\n")

    def test_selector_shared_lock_is_held_through_exec_handoff(self) -> None:
        release = self._copy_release("selector-exec-lock")
        marker = release.parent / "marker.txt"
        ready_read, ready_write = os.pipe()
        continue_read, continue_write = os.pipe()
        environment = os.environ.copy()
        environment["GROK_BOOTSTRAP_TEST_EXEC_READY_FD"] = str(ready_write)
        environment["GROK_BOOTSTRAP_TEST_EXEC_CONTINUE_FD"] = str(continue_read)
        environment["GROK_BOOTSTRAP_TEST_SELECTOR_DIR"] = os.fspath(release.parent)
        if os.geteuid() == 0 and self.sudo_target_uid is not None:
            environment["SUDO_UID"] = str(self.sudo_target_uid)
        process = subprocess.Popen(
            [
                os.fspath(self.test_binary),
                "--release-dir",
                os.fspath(release),
                "--",
                os.fspath(marker),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            pass_fds=(ready_write, continue_read),
        )
        os.close(ready_write)
        os.close(continue_read)
        lock_fd = os.open(
            release.parent / "update.lock",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            readable, _, _ = select.select([ready_read], [], [], 5.0)
            self.assertEqual(readable, [ready_read])
            self.assertEqual(os.read(ready_read, 1), b"E")
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.write(continue_write, b"C")
            stdout, stderr = process.communicate(timeout=10)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(ready_read)
            os.close(continue_write)
            os.close(lock_fd)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

        self.assertEqual(process.returncode, 0, stderr.decode("ascii"))
        self.assertEqual(stdout, b"")
        self.assertTrue(marker.is_file())

    def test_root_bootstrap_rejects_missing_or_malformed_target_identity(self) -> None:
        invalid_values = (
            None,
            "0",
            f"0{self.sudo_target_uid}",
            f"+{self.sudo_target_uid}",
            "4294967295",
        )
        for value in invalid_values:
            with self.subTest(sudo_uid=value):
                release = self._copy_release("target-identity")
                marker = release.parent / "marker.txt"
                environment = os.environ.copy()
                environment["GROK_BOOTSTRAP_TEST_ASSUME_ROOT"] = "1"
                if value is None:
                    environment.pop("SUDO_UID", None)
                else:
                    environment["SUDO_UID"] = value
                completed = self._run_bootstrap(
                    release,
                    marker,
                    environment=environment,
                    supply_target_identity=False,
                )
                self._assert_preimport_failure(completed, marker)
                self.assertEqual(
                    completed.stderr, b"grok-bootstrap: TARGET_IDENTITY\n"
                )

        release = self._copy_release("target-identity-valid")
        marker = release.parent / "marker.txt"
        environment = os.environ.copy()
        environment["GROK_BOOTSTRAP_TEST_ASSUME_ROOT"] = "1"
        environment["SUDO_UID"] = str(self.sudo_target_uid)
        environment["SUDO_USER"] = "must-not-cross-exec"
        environment["SUDO_GID"] = "999999"
        completed = self._run_bootstrap(
            release,
            marker,
            environment=environment,
            supply_target_identity=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("ascii"))
        lines = marker.read_text(encoding="ascii").splitlines()
        self.assertEqual(
            set(lines[2].split(",")),
            {
                "GROK_BOOTSTRAP_AUTHORITY_FD",
                "LANG",
                "LC_ALL",
                "PATH",
                "PYTHONDONTWRITEBYTECODE",
                "SUDO_UID",
            },
        )
        self.assertEqual(lines[3], str(self.sudo_target_uid))
        self.assertEqual(lines[4], "authority-valid")

    def test_builder_is_byte_deterministic_and_normalizes_metadata(self) -> None:
        first_output = self.root / "deterministic-one"
        second_output = self.root / "deterministic-two"
        first_output.mkdir()
        second_output.mkdir()

        first = self._build_bundle(first_output, self.key_one)
        second = self._build_bundle(second_output, self.key_one)

        self.assertEqual(first.name, second.name)
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE(second.stat().st_mode), 0o555)
        for artifact in ARTIFACTS:
            first_path = first / artifact
            second_path = second / artifact
            self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
            self.assertEqual(stat.S_IMODE(first_path.stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE(second_path.stat().st_mode), 0o444)

    def test_missing_and_unsigned_manifests_fail_before_candidate_import(self) -> None:
        for label, mutation in ("missing", "missing"), ("zeroed", "zeroed"):
            with self.subTest(mutation=mutation):
                release = self._copy_release(label)
                marker = release.parent / "marker.txt"
                signature = release / "release-manifest.sig"
                if mutation == "missing":
                    release.chmod(0o755)
                    signature.unlink()
                    release.chmod(0o555)
                else:
                    self._rewrite_artifact(signature, bytes(64))

                completed = self._run_bootstrap(release, marker)
                self._assert_preimport_failure(completed, marker)

    def test_wrong_key_signature_fails_before_candidate_import(self) -> None:
        release = self._copy_release("wrong-key")
        marker = release.parent / "marker.txt"
        self._resign_manifest(release, self.key_two)

        completed = self._run_bootstrap(release, marker)

        self._assert_preimport_failure(completed, marker)
        self.assertEqual(completed.stderr, b"grok-bootstrap: SIGNATURE_INVALID\n")

    def test_manifest_and_bundle_tampering_fail_before_candidate_import(self) -> None:
        for target in ("manifest", "bundle"):
            with self.subTest(target=target):
                release = self._copy_release(target)
                marker = release.parent / "marker.txt"
                path = release / (
                    "release-manifest.txt" if target == "manifest" else "dispatcher.pyz"
                )
                content = bytearray(path.read_bytes())
                content[len(content) // 2] ^= 0x01
                self._rewrite_artifact(path, bytes(content))

                completed = self._run_bootstrap(release, marker)
                self._assert_preimport_failure(completed, marker)

    def test_correctly_signed_noncanonical_manifests_are_rejected(self) -> None:
        def uppercase_inventory_digest(content: bytes) -> bytes:
            position = content.index(b"file=") + 10
            mutable = bytearray(content)
            mutable[position] = ord("A")
            return bytes(mutable)

        mutations = {
            "extra-field": lambda content: content + b"extra=value\n",
            "missing-final-newline": lambda content: content[:-1],
            "path-traversal": lambda content: content.replace(
                b":__main__.py\n", b":../main.py\n", 1
            ),
            "uppercase-digest": uppercase_inventory_digest,
        }
        for label, mutation in mutations.items():
            with self.subTest(mutation=label):
                release = self._copy_release(label)
                marker = release.parent / "marker.txt"
                manifest = release / "release-manifest.txt"
                self._rewrite_artifact(manifest, mutation(manifest.read_bytes()))
                self._resign_manifest(release, self.key_one)

                completed = self._run_bootstrap(release, marker)
                self._assert_preimport_failure(completed, marker)
                self.assertEqual(completed.stderr, b"grok-bootstrap: MANIFEST_INVALID\n")

    def test_untrusted_metadata_links_special_files_and_extras_are_rejected(self) -> None:
        attacks = ("directory-mode", "file-mode", "symlink", "hardlink", "fifo", "extra")
        for attack in attacks:
            with self.subTest(attack=attack):
                release = self._copy_release(attack)
                marker = release.parent / "marker.txt"
                bundle = release / "dispatcher.pyz"
                if attack == "directory-mode":
                    release.chmod(0o755)
                elif attack == "file-mode":
                    bundle.chmod(0o644)
                elif attack == "symlink":
                    release.chmod(0o755)
                    bundle.unlink()
                    bundle.symlink_to(self.base_release / "dispatcher.pyz")
                    release.chmod(0o555)
                elif attack == "hardlink":
                    outside = release.parent / "outside.pyz"
                    outside.write_bytes((self.base_release / "dispatcher.pyz").read_bytes())
                    outside.chmod(0o444)
                    release.chmod(0o755)
                    bundle.unlink()
                    os.link(outside, bundle)
                    release.chmod(0o555)
                elif attack == "fifo":
                    release.chmod(0o755)
                    bundle.unlink()
                    os.mkfifo(bundle, 0o444)
                    bundle.chmod(0o444)
                    release.chmod(0o555)
                else:
                    release.chmod(0o755)
                    (release / "unexpected").write_bytes(b"not trusted")
                    (release / "unexpected").chmod(0o444)
                    release.chmod(0o555)

                completed = self._run_bootstrap(release, marker)
                self._assert_preimport_failure(completed, marker)

    def test_descriptor_relative_open_detects_bundle_path_replacement(self) -> None:
        release = self._copy_release("replacement-race")
        marker = release.parent / "marker.txt"
        bundle = release / "dispatcher.pyz"
        ready_read, ready_write = os.pipe()
        continue_read, continue_write = os.pipe()
        environment = os.environ.copy()
        environment["GROK_BOOTSTRAP_TEST_READY_FD"] = str(ready_write)
        environment["GROK_BOOTSTRAP_TEST_CONTINUE_FD"] = str(continue_read)
        environment["GROK_BOOTSTRAP_TEST_SELECTOR_DIR"] = os.fspath(
            release.parent
        )
        process = subprocess.Popen(
            [
                os.fspath(self.test_binary),
                "--release-dir",
                os.fspath(release),
                "--",
                os.fspath(marker),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            pass_fds=(ready_write, continue_read),
        )
        os.close(ready_write)
        os.close(continue_read)
        try:
            readable, _, _ = select.select([ready_read], [], [], 5.0)
            self.assertEqual(readable, [ready_read], "bootstrap did not reach race barrier")
            self.assertEqual(os.read(ready_read, 1), b"R")

            release.chmod(0o755)
            bundle.unlink()
            shutil.copyfile(self.base_release / "dispatcher.pyz", bundle)
            bundle.chmod(0o444)
            release.chmod(0o555)
            os.write(continue_write, b"C")
            stdout, stderr = process.communicate(timeout=10)
        finally:
            os.close(ready_read)
            os.close(continue_write)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

        completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        self._assert_preimport_failure(completed, marker)
        self.assertEqual(completed.stderr, b"grok-bootstrap: PATH_CHANGED\n")

    def test_builder_rejects_linked_source_members(self) -> None:
        source = self.root / "linked-source"
        output = self.root / "linked-output"
        source.mkdir()
        output.mkdir()
        (source / "__main__.py").write_bytes(b"raise SystemExit(0)\n")
        (source / "linked.py").symlink_to(source / "__main__.py")

        completed = subprocess.run(
            [
                sys.executable,
                os.fspath(BUILDER),
                "--source",
                os.fspath(source),
                "--output",
                os.fspath(output),
                "--key-id",
                KEY_ID,
                "--signing-key",
                os.fspath(self.key_one),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")
        self.assertIn(b"linked or special file", completed.stderr)
        self.assertEqual(list(output.iterdir()), [])

    def test_dispatcher_staging_is_closed_and_deterministic(self) -> None:
        second = self.root / "dispatcher-stage-second"
        self._stage_dispatcher(second)

        def inventory(root: Path) -> dict[str, tuple[int, bytes]]:
            return {
                path.relative_to(root).as_posix(): (
                    stat.S_IMODE(path.stat().st_mode),
                    path.read_bytes(),
                )
                for path in root.rglob("*")
                if path.is_file()
            }

        first_inventory = inventory(self.dispatcher_stage)
        second_inventory = inventory(second)
        self.assertEqual(first_inventory, second_inventory)
        self.assertEqual(first_inventory["__main__.py"][1], DISPATCHER_MAIN.read_bytes())
        self.assertEqual(stat.S_IMODE(self.dispatcher_stage.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE(second.stat().st_mode), 0o555)
        self.assertIn("install-release.py", first_inventory)
        self.assertIn("grok-remote", first_inventory)
        self.assertIn("grok_ms/release_admission.py", first_inventory)
        self.assertIn("grok_ms/managed_profile.py", first_inventory)
        self.assertIn("grok_ms/rung_admission.py", first_inventory)
        self.assertNotIn("README.md", first_inventory)
        self.assertFalse(
            any("__pycache__" in path.split("/") for path in first_inventory)
        )
        self.assertEqual(
            sum(name in first_inventory for name in ("vpn-broker", "vpn-broker.py")),
            1,
        )

    def test_dispatcher_stager_does_not_open_undeclared_private_or_runtime_files(
        self,
    ) -> None:
        source = self._dispatcher_authoring_fixture("closed-read-set")
        private_key = source / "id_grokproxy"
        private_key.write_bytes(b"sentinel-private-material-must-not-be-read\n")
        private_key.chmod(0o000)
        unrelated_fifo = source / "unrelated-runtime.pipe"
        os.mkfifo(unrelated_fifo, 0o000)
        output = self.root / "closed-read-set-output"

        staged = self._stage_dispatcher(output, source=source)

        self.assertEqual(staged, output)
        self.assertFalse((staged / private_key.name).exists())
        self.assertFalse((staged / unrelated_fifo.name).exists())
        self.assertEqual(stat.S_IMODE(private_key.lstat().st_mode), 0o000)

    def test_dispatcher_stager_rejects_missing_deferred_import_modules(self) -> None:
        for module in ("managed_profile.py", "rung_admission.py"):
            with self.subTest(module=module):
                source = self._dispatcher_authoring_fixture(f"missing-{module}")
                (source / "grok_ms" / module).unlink()
                output = self.root / f"missing-deferred-{module}"
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        os.fspath(STAGER),
                        "--source-root",
                        os.fspath(source),
                        "--output",
                        os.fspath(output),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                    timeout=20,
                    check=False,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stdout, b"")
                self.assertIn(b"mandatory module", completed.stderr)
                self.assertFalse(output.exists())

    def test_dispatcher_stager_rejects_links_and_special_selected_members(self) -> None:
        attacks = ("top-level-symlink", "package-fifo")
        for attack in attacks:
            with self.subTest(attack=attack):
                source = self._dispatcher_authoring_fixture(attack)
                if attack == "top-level-symlink":
                    selected = source / "egress.sh"
                    selected.unlink()
                    selected.symlink_to("/dev/null")
                else:
                    selected = source / "grok_ms" / "client.py"
                    selected.unlink()
                    os.mkfifo(selected, 0o600)
                output = self.root / f"selected-special-output-{attack}"
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        os.fspath(STAGER),
                        "--source-root",
                        os.fspath(source),
                        "--output",
                        os.fspath(output),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                    timeout=20,
                    check=False,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stdout, b"")
                self.assertIn(b"linked or special", completed.stderr)
                self.assertFalse(output.exists())

    def test_dispatcher_shim_extracts_only_the_signed_closed_runtime(self) -> None:
        run_parent = self.root / "dispatcher-run"
        run_parent.mkdir(mode=0o700)
        archive = self.dispatcher_release / "dispatcher.pyz"

        with self.dispatcher_module.extracted_dispatcher(
            archive,
            run_parent=run_parent,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        ) as extracted:
            self.assertEqual(stat.S_IMODE(extracted.stat().st_mode), 0o700)
            self.assertEqual(
                (extracted / "install-release.py").read_bytes(),
                (self.dispatcher_stage / "install-release.py").read_bytes(),
            )
            self.assertEqual(
                stat.S_IMODE((extracted / "install-release.py").stat().st_mode),
                0o644,
            )
            self.assertEqual(
                stat.S_IMODE((extracted / "grok-remote").stat().st_mode),
                0o755,
            )
            self.assertFalse((extracted / "README.md").exists())
            plan_environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
            if os.geteuid() == 0:
                plan_environment["SUDO_UID"] = str(self.sudo_target_uid)
            planned = subprocess.run(
                [sys.executable, "-I", os.fspath(extracted / "install-release.py"), "plan"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=plan_environment,
                timeout=20,
                check=False,
            )
            self.assertEqual(planned.returncode, 2)
            self.assertEqual(planned.stdout, b"")
            self.assertIn(b"native bootstrap authority", planned.stderr)
            extracted_path = extracted
        self.assertFalse(extracted_path.exists())

    def test_dispatcher_shim_rejects_unsafe_archive_member(self) -> None:
        valid = self.dispatcher_release / "dispatcher.pyz"
        unsafe = self.root / "unsafe-dispatcher.pyz"
        with zipfile.ZipFile(valid, "r") as source, zipfile.ZipFile(
            unsafe, "w", compression=zipfile.ZIP_STORED, allowZip64=False
        ) as destination:
            for information in source.infolist():
                destination.writestr(information, source.read(information))
            traversal = zipfile.ZipInfo("../escape.py", (1980, 1, 1, 0, 0, 0))
            traversal.create_system = 3
            traversal.compress_type = zipfile.ZIP_STORED
            traversal.external_attr = (stat.S_IFREG | 0o644) << 16
            destination.writestr(traversal, b"raise SystemExit(0)\n")
        run_parent = self.root / "unsafe-dispatcher-run"
        run_parent.mkdir(mode=0o700)

        with self.assertRaises(self.dispatcher_module.DispatcherExtractionError):
            with self.dispatcher_module.extracted_dispatcher(
                unsafe,
                run_parent=run_parent,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            ):
                self.fail("unsafe archive unexpectedly reached the dispatcher")
        self.assertEqual(list(run_parent.iterdir()), [])

    def test_production_build_excludes_hooks_and_package_forbids_test_keying(self) -> None:
        production = self.production_binary.read_bytes()
        test = self.test_binary.read_bytes()
        production_root = b"/usr/local/libexec/grok-proxy/bootstrap-releases/"
        colliding_root = b"/usr/local/libexec/grok-proxy/releases/"
        self.assertIn(production_root, production)
        self.assertNotIn(colliding_root, production)
        self.assertNotIn(b"GROK_BOOTSTRAP_TEST_READY_FD", production)
        self.assertNotIn(b"GROK_BOOTSTRAP_TEST_CONTINUE_FD", production)
        self.assertNotIn(b"GROK_BOOTSTRAP_TEST_EXEC_READY_FD", production)
        self.assertNotIn(b"GROK_BOOTSTRAP_TEST_EXEC_CONTINUE_FD", production)
        self.assertNotIn(b"GROK_BOOTSTRAP_TEST_ASSUME_ROOT", production)
        self.assertNotIn(b"GROK_BOOTSTRAP_TEST_FORCE_MEMFD_FALLBACK", production)
        self.assertNotIn(b"GROK_BOOTSTRAP_TEST_SELECTOR_DIR", production)
        self.assertIn(b"GROK_BOOTSTRAP_TEST_READY_FD", test)
        self.assertIn(b"GROK_BOOTSTRAP_TEST_EXEC_READY_FD", test)
        self.assertIn(b"GROK_BOOTSTRAP_TEST_ASSUME_ROOT", test)
        self.assertIn(b"GROK_BOOTSTRAP_TEST_FORCE_MEMFD_FALLBACK", test)
        self.assertIn(b"GROK_BOOTSTRAP_TEST_SELECTOR_DIR", test)

        metadata = json.loads(PACKAGE_METADATA.read_text(encoding="utf-8"))
        self.assertIn("production private signing key", metadata["forbidden_inputs"])
        self.assertIn("GROK_BOOTSTRAP_TEST_BUILD", metadata["forbidden_inputs"])
        self.assertEqual(
            metadata["signed_application_store"]["root"],
            "/usr/local/libexec/grok-proxy/bootstrap-releases",
        )
        self.assertTrue(
            metadata["signed_application_store"]["namespaces_must_remain_disjoint"]
        )
        self.assertEqual(
            metadata["selector"]["path"],
            "/usr/local/libexec/grok-proxy/bootstrap/selected-release",
        )
        self.assertEqual(metadata["selector"]["link_count"], 1)
        self.assertIn(
            "final exec boundary",
            metadata["selector"]["native_enforcement"],
        )
        self.assertTrue(
            metadata["selector"]["caller_validation_is_defense_in_depth"]
        )
        transaction_lock = metadata["selector"]["transaction_lock"]
        self.assertEqual(
            transaction_lock["anchor"],
            "/usr/local/libexec/grok-proxy/bootstrap/update.lock",
        )
        self.assertEqual(transaction_lock["mode"], "0600")
        self.assertEqual(transaction_lock["link_count"], 1)
        self.assertEqual(transaction_lock["size"], 0)
        self.assertTrue(
            transaction_lock["anchor_inode_must_never_be_replaced_or_truncated"]
        )
        self.assertIn(
            "LOCK_EX",
            metadata["selector"]["transaction_lock"][
                "administrative_publisher"
            ],
        )
        self.assertFalse(
            metadata["dispatcher_staging"]["mutable_authoring_source_fallback"]
        )
        self.assertTrue(
            metadata["package_requirements"]["administrative_signature_required"]
        )
        debian_package = metadata["debian_package"]
        self.assertEqual(debian_package["builder"], "build_debian_package.py")
        self.assertIn("/usr/bin/dpkg-deb", debian_package["fixed_tools"])
        self.assertEqual(
            debian_package["postinst"]["activation"].split()[0],
            "/usr/libexec/grok-bootstrap-package/"
            "grok-bootstrap-package-activate",
        )
        self.assertFalse(debian_package["postinst"]["test_mode_hook"])
        self.assertIn(
            "signed-by", debian_package["authentication_requirement"]
        )
        self.assertEqual(metadata["target_identity"]["native_invocation_uid"], 0)


class DebianPackageBuilderTests(unittest.TestCase):
    """Build and inspect the production package without acquiring root."""

    VERSION = "1.0.0+test1"
    SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"  # commit fixture
    SOURCE_DATE_EPOCH = 1_784_505_600
    SOURCE_FILES = (
        "Makefile",
        "activate_package.py",
        "bootstrap.c",
        "build_debian_package.py",
        "isolated_python_launcher.c",
        "publish_signed_application.py",
    )
    DATA_ROOTS = {
        "usr/lib/grok-bootstrap-package": {
            "grok-bootstrap": 0o555,
            "grok-bootstrap-publisher.py": 0o444,
            "grok-bootstrap-publisher": 0o555,
        },
        "usr/libexec/grok-bootstrap-package": {
            "activate_package.py": 0o444,
            "grok-bootstrap-package-activate": 0o555,
        },
    }

    @classmethod
    def setUpClass(cls) -> None:
        if os.geteuid() == 0 or os.getegid() == 0:
            raise unittest.SkipTest("Debian package construction must be non-root")
        required = (
            "/usr/bin/cc",
            "/usr/bin/dpkg-deb",
            "/usr/bin/make",
            "/usr/bin/nm",
            "/usr/bin/openssl",
            "/usr/bin/pkg-config",
            "/usr/bin/readelf",
        )
        if any(not Path(path).is_file() for path in required):
            raise unittest.SkipTest("Debian package build tools are required")
        architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(
            os.uname().machine
        )
        if architecture is None:
            raise unittest.SkipTest("Debian package test requires x86_64 or AArch64")
        cls.architecture = architecture
        cls._temporary = tempfile.TemporaryDirectory(
            prefix="grok-debian-package-tests-", dir=Path.home()
        )
        cls.root = Path(cls._temporary.name)
        cls.root.chmod(0o700)
        cls.source = cls.root / "source"
        cls.source.mkdir(mode=0o700)
        for name in cls.SOURCE_FILES:
            shutil.copy2(BOOTSTRAP_ROOT / name, cls.source / name)
        package_directory = cls.source / "package"
        package_directory.mkdir(mode=0o700)
        shutil.copy2(PACKAGE_METADATA, package_directory / PACKAGE_METADATA.name)

        key = cls.root / "ephemeral-test-key.pem"
        cls._run_checked(
            [
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                os.fspath(key),
            ]
        )
        key.chmod(0o600)
        public = cls._run_checked(
            [
                "/usr/bin/openssl",
                "pkey",
                "-in",
                os.fspath(key),
                "-pubout",
                "-outform",
                "DER",
            ]
        ).stdout
        if len(public) != len(DER_PREFIX) + 32 or not public.startswith(DER_PREFIX):
            raise AssertionError("unexpected Ed25519 public-key encoding")
        public_hex = public[len(DER_PREFIX) :].hex()
        cls._run_checked(
            [
                "/usr/bin/make",
                "-C",
                os.fspath(cls.source),
                "all",
                "KEY_ID=debian-package-test-key",
                f"PUBLIC_KEY_HEX={public_hex}",
            ],
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        cls.build_root = cls.source / "build"

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "root"):
            BootstrapTests._make_tree_removable(cls.root)
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()

    @classmethod
    def _run_checked(
        cls, command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=120,
            **kwargs,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"command failed ({completed.returncode}): {command!r}\n"
                f"stdout: {completed.stdout!r}\nstderr: {completed.stderr!r}"
            )
        return completed

    def _output_directory(self, label: str) -> Path:
        output = self.root / f"{self._testMethodName}-{label}"
        output.mkdir(mode=0o700)
        output.chmod(0o700)
        return output

    def _package_path(self, output_directory: Path) -> Path:
        return output_directory / (
            f"grok-bootstrap_{self.VERSION}_{self.architecture}.deb"
        )

    def _build_command(
        self,
        output: Path,
        *,
        build_root: Path | None = None,
        architecture: str | None = None,
    ) -> list[str]:
        if build_root is None:
            build_root = self.build_root
        if architecture is None:
            architecture = self.architecture
        return [
            sys.executable,
            "-I",
            "-B",
            os.fspath(self.source / "build_debian_package.py"),
            "--build-root",
            os.fspath(build_root),
            "--output",
            os.fspath(output),
            "--version",
            self.VERSION,
            "--source-commit",
            self.SOURCE_COMMIT,
            "--architecture",
            architecture,
            "--source-date-epoch",
            str(self.SOURCE_DATE_EPOCH),
        ]

    def test_debian_package_is_deterministic_closed_and_root_owned(self) -> None:
        first_output = self._output_directory("first")
        second_output = self._output_directory("second")
        first = self._package_path(first_output)
        second = self._package_path(second_output)
        self._run_checked(self._build_command(first))
        self._run_checked(self._build_command(second))

        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o644)
        fields = self._run_checked(
            [os.fspath(DPKG_DEB), "--field", os.fspath(first)]
        ).stdout.decode("utf-8")
        self.assertIn("Package: grok-bootstrap\n", fields)
        self.assertIn(f"Version: {self.VERSION}\n", fields)
        self.assertIn(f"Architecture: {self.architecture}\n", fields)
        self.assertIn(f"X-Grok-Source-Commit: {self.SOURCE_COMMIT}\n", fields)

        listing = self._run_checked(
            [os.fspath(DPKG_DEB), "--contents", os.fspath(first)]
        ).stdout.decode("utf-8")
        lines = listing.splitlines()
        self.assertTrue(lines)
        self.assertTrue(all(" root/root " in line for line in lines))
        listed_paths = {line.split()[-1] for line in lines}
        self.assertEqual(
            listed_paths,
            {
                "./",
                "./usr/",
                "./usr/lib/",
                "./usr/lib/grok-bootstrap-package/",
                "./usr/lib/grok-bootstrap-package/grok-bootstrap",
                "./usr/lib/grok-bootstrap-package/grok-bootstrap-publisher.py",
                "./usr/lib/grok-bootstrap-package/grok-bootstrap-publisher",
                "./usr/libexec/",
                "./usr/libexec/grok-bootstrap-package/",
                "./usr/libexec/grok-bootstrap-package/activate_package.py",
                "./usr/libexec/grok-bootstrap-package/grok-bootstrap-package-activate",
            },
        )

        extracted = self.root / f"{self._testMethodName}-extracted"
        control = self.root / f"{self._testMethodName}-control"
        self._run_checked(
            [os.fspath(DPKG_DEB), "--extract", os.fspath(first), os.fspath(extracted)]
        )
        self._run_checked(
            [os.fspath(DPKG_DEB), "--control", os.fspath(first), os.fspath(control)]
        )
        for relative_root, expected_files in self.DATA_ROOTS.items():
            root = extracted / relative_root
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o555)
            self.assertEqual(
                sorted(path.name for path in root.iterdir()), sorted(expected_files)
            )
            for name, mode in expected_files.items():
                installed = root / name
                built = self.build_root / name
                self.assertEqual(installed.read_bytes(), built.read_bytes())
                self.assertEqual(stat.S_IMODE(installed.stat().st_mode), mode)

        postinst = control / "postinst"
        postinst_raw = postinst.read_bytes()
        self.assertEqual(stat.S_IMODE(postinst.stat().st_mode), 0o755)
        self.assertTrue(postinst_raw.startswith(b"#!/usr/bin/python3 -IBS\n"))
        ast.parse(postinst_raw.decode("utf-8"), filename="postinst", mode="exec")
        self.assertIn(self.VERSION.encode("ascii"), postinst_raw)
        self.assertIn(self.SOURCE_COMMIT.encode("ascii"), postinst_raw)
        self.assertNotIn(b"GROK_BOOTSTRAP_PACKAGE_ACTIVATOR_TEST_MODE", postinst_raw)
        self.assertNotIn(b"--test-root", postinst_raw)
        for expected_files in self.DATA_ROOTS.values():
            for name in expected_files:
                raw = (self.build_root / name).read_bytes()
                self.assertIn(hashlib.sha256(raw).hexdigest().encode("ascii"), postinst_raw)
                self.assertIn(f"'size': {len(raw)}".encode("ascii"), postinst_raw)

    def test_debian_package_builder_rejects_unsafe_or_drifted_inputs(self) -> None:
        module_spec = importlib.util.spec_from_file_location(
            "grok_debian_package_builder_supplementary_group_test",
            self.source / "build_debian_package.py",
        )
        self.assertIsNotNone(module_spec)
        self.assertIsNotNone(module_spec.loader)
        builder_module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(builder_module)
        with mock.patch.object(builder_module.os, "getgroups", return_value=[0]):
            with self.assertRaisesRegex(
                builder_module.PackageBuildError, "must run as non-root"
            ):
                builder_module.build_package(types.SimpleNamespace())

        attacks = ("extra", "symlink", "mode", "python", "loader")
        for attack in attacks:
            with self.subTest(attack=attack):
                build_root = self.root / f"bad-build-{attack}"
                shutil.copytree(self.build_root, build_root, copy_function=shutil.copy2)
                build_root.chmod(0o755)
                if attack == "extra":
                    (build_root / "unexpected").write_bytes(b"not in the contract\n")
                elif attack == "symlink":
                    target = build_root / "activate_package.py"
                    target.unlink()
                    target.symlink_to("grok-bootstrap-publisher.py")
                elif attack == "mode":
                    (build_root / "grok-bootstrap-publisher.py").chmod(0o644)
                elif attack == "python":
                    target = build_root / "grok-bootstrap-publisher.py"
                    target.chmod(0o644)
                    target.write_bytes(b"if invalid python\n")
                    target.chmod(0o444)
                else:
                    target = build_root / "grok-bootstrap-publisher"
                    target.chmod(0o755)
                    with target.open("ab") as stream:
                        stream.write(b"LD_PRELOAD\x00")
                    target.chmod(0o555)
                output_directory = self._output_directory(f"bad-output-{attack}")
                output = self._package_path(output_directory)
                completed = subprocess.run(
                    self._build_command(output, build_root=build_root),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stdout, b"")
                self.assertTrue(
                    completed.stderr.startswith(b"grok-bootstrap package builder: ")
                )
                self.assertFalse(output.exists())

        other_architecture = "amd64" if self.architecture == "arm64" else "arm64"
        output_directory = self._output_directory("wrong-architecture")
        output = output_directory / (
            f"grok-bootstrap_{self.VERSION}_{other_architecture}.deb"
        )
        completed = subprocess.run(
            self._build_command(output, architecture=other_architecture),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"does not match the build host", completed.stderr)
        self.assertFalse(output.exists())

        existing_directory = self._output_directory("existing")
        existing = self._package_path(existing_directory)
        existing.write_bytes(b"sentinel\n")
        completed = subprocess.run(
            self._build_command(existing),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(existing.read_bytes(), b"sentinel\n")


if __name__ == "__main__":
    unittest.main()
