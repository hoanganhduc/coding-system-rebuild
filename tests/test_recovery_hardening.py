from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def listing_block(
    path: str,
    *,
    size: int = 8,
    packed: int = 8,
    folder: str = "-",
    attributes: str = " -rw-------",
    encrypted: str = "+",
) -> str:
    return "\n".join(
        (
            f"Path = {path}",
            f"Folder = {folder}",
            f"Size = {size}",
            f"Packed Size = {packed}",
            f"Attributes = {attributes}",
            f"Encrypted = {encrypted}",
        )
    )


class LegacyZipHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.helper = load_module(
            "csr_legacy_zip_tool_hardening", "bin/lib/legacy_zip_tool.py"
        )

    def parse(self, blocks: list[str]):
        return self.helper._parse_listing(("\n\n".join(blocks) + "\n").encode())

    def test_listing_rejects_size_ratio_count_type_and_path_conflicts(self) -> None:
        cases = (
            [listing_block("huge", size=self.helper.MAX_MEMBER_BYTES + 1)],
            [listing_block("ratio", size=201, packed=1)],
            [listing_block("link", attributes=" l---------")],
            [listing_block("plain", encrypted="-")],
            [listing_block("parent"), listing_block("parent/child")],
        )
        for blocks in cases:
            with self.subTest(blocks=blocks), self.assertRaises(
                self.helper.LegacyZipError
            ):
                self.parse(blocks)
        with mock.patch.object(self.helper, "MAX_MEMBERS", 1):
            with self.assertRaisesRegex(self.helper.LegacyZipError, "too many"):
                self.parse([listing_block("one"), listing_block("two")])
        with mock.patch.object(self.helper, "MAX_EXPANDED_BYTES", 10):
            with self.assertRaisesRegex(self.helper.LegacyZipError, "expanded size"):
                self.parse(
                    [
                        listing_block("one", size=6, packed=6),
                        listing_block("two", size=6, packed=6),
                    ]
                )

    def test_listing_capture_stops_at_byte_bound(self) -> None:
        with self.assertRaisesRegex(self.helper.LegacyZipError, "output bound"):
            self.helper._bounded_capture(
                [
                    sys.executable,
                    "-c",
                    "import os; os.write(1, b'x' * 4096)",
                ],
                pass_fds=(),
                max_bytes=128,
                timeout=2,
            )

    def test_seven_zip_ignores_a_hostile_path_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            hostile = Path(temporary) / "7zz"
            hostile.write_text("#!/usr/bin/env bash\nexit 99\n", encoding="utf-8")
            hostile.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": temporary}, clear=False):
                selected = Path(self.helper.seven_zip())
            self.assertIn(selected, (Path("/usr/bin/7zz"), Path("/usr/bin/7z")))
            self.assertNotEqual(selected, hostile)
            self.assertEqual(
                self.helper.SAFE_ENV,
                {"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )

    @unittest.skipUnless(
        shutil.which("7zz") or shutil.which("7z"), "7-Zip is required"
    )
    def test_encrypted_member_is_streamed_to_a_regular_bounded_file(self) -> None:
        seven_zip = shutil.which("7zz") or shutil.which("7z")
        assert seven_zip is not None
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source"
            secret = source / ".config/demo/secret.json"
            secret.parent.mkdir(parents=True)
            secret.write_bytes(b'{"fixture":"synthetic"}\n')
            archive = root / "legacy.zip"
            password_value = "synthetic-password-only"
            made = subprocess.run(
                [
                    seven_zip,
                    "a",
                    "-tzip",
                    "-mem=AES256",
                    f"-p{password_value}",
                    str(archive),
                    ".config/demo/secret.json",
                ],
                cwd=source,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(made.returncode, 0, made.stderr.decode(errors="replace"))
            password = root / "password.txt"
            password.write_text(password_value + "\n", encoding="utf-8")
            password.chmod(0o600)
            output = root / "output"
            output.mkdir(mode=0o700)
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "bin/lib/legacy_zip_tool.py"),
                    "extract",
                    "--archive",
                    str(archive),
                    "--password-file",
                    str(password),
                    "--output-dir",
                    str(output),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(
                result.returncode, 0, result.stderr.decode(errors="replace")
            )
            restored = output / ".config/demo/secret.json"
            self.assertEqual(restored.read_bytes(), secret.read_bytes())
            self.assertTrue(stat.S_ISREG(restored.lstat().st_mode))
            self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)


class SecureRecoveryTemporaryStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.helper = load_module("csr_secure_temp_hardening", "bin/lib/secure_temp.py")

    def test_default_directory_is_owner_only_and_on_tmpfs(self) -> None:
        with self.helper.secure_temporary_directory(prefix="csr-test-") as temporary:
            path = Path(temporary)
            self.assertEqual(path.stat().st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertEqual(self.helper._filesystem_type(path), "tmpfs")


    def test_persistent_root_requires_exact_explicit_override(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root.chmod(0o700)
            environment = {
                self.helper.TMPDIR_ENV: str(root),
                self.helper.PERSISTENT_OVERRIDE_ENV: "0",
            }
            with mock.patch.dict(os.environ, environment), mock.patch.object(
                self.helper, "_filesystem_type", return_value="ext4"
            ):
                with self.assertRaisesRegex(self.helper.SecureTempError, "not on tmpfs"):
                    self.helper.select_secure_temp_root()
            environment[self.helper.PERSISTENT_OVERRIDE_ENV] = "1"
            with mock.patch.dict(os.environ, environment), mock.patch.object(
                self.helper, "_filesystem_type", return_value="ext4"
            ):
                self.assertEqual(self.helper.select_secure_temp_root(), root.resolve())

    def test_group_or_world_accessible_root_is_always_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root.chmod(0o755)
            with mock.patch.dict(
                os.environ,
                {
                    self.helper.TMPDIR_ENV: str(root),
                    self.helper.PERSISTENT_OVERRIDE_ENV: "1",
                },
            ):
                with self.assertRaisesRegex(self.helper.SecureTempError, "owner-only"):
                    self.helper.select_secure_temp_root()

    def test_recovery_plaintext_tempdirs_use_the_secure_helper(self) -> None:
        source = (ROOT / "bin/lib/recovery_tool.py").read_text(encoding="utf-8")
        self.assertNotIn("tempfile.TemporaryDirectory", source)
        self.assertGreaterEqual(source.count("secure_temporary_directory("), 4)


class RecoveryPackShellBoundaryTests(unittest.TestCase):
    def test_help_is_secret_independent_and_side_effect_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            marker = home / "executed"
            bash_env = home / "bash-env"
            bash_env.write_text(f"/usr/bin/touch {marker}\n", encoding="utf-8")

            completed = subprocess.run(
                [str(ROOT / "bin/secrets-pack.sh"), "--help"],
                env={
                    "HOME": str(home),
                    "PATH": str(home),
                    "BASH_ENV": str(bash_env),
                    "BASH_FUNC_echo%%": (
                        f"() {{ /usr/bin/touch {marker}; return 99; }}"
                    ),
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertIn("usage: bin/secrets-pack.sh", completed.stdout.decode())
            self.assertFalse(marker.exists())
            self.assertFalse((home / ".config").exists())
            self.assertFalse((home / "secrets-out").exists())

    def test_early_failure_ignores_hostile_shell_startup_and_exported_functions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            marker = home / "executed"
            bash_env = home / "bash-env"
            bash_env.write_text(f"/usr/bin/touch {marker}\n", encoding="utf-8")
            environment = {
                "HOME": str(home),
                "PATH": str(home),
                "BASH_ENV": str(bash_env),
                "ENV": str(bash_env),
                "BASH_FUNC_mkdir%%": (
                    f"() {{ /usr/bin/touch {marker}; return 99; }}"
                ),
                "BASH_FUNC_stat%%": (
                    f"() {{ /usr/bin/touch {marker}; return 99; }}"
                ),
            }

            completed = subprocess.run(
                [str(ROOT / "bin/secrets-pack.sh")],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertFalse(marker.exists())

    def test_all_secret_bearing_shell_entrypoints_use_privileged_mode(self) -> None:
        entrypoints = (
            "bin/secrets-pack.sh",
            "bin/secrets-verify.sh",
            "bin/secrets-restore.sh",
            "bin/secret-restore-quiescence.sh",
            "bin/materialize-openclaw-runtime.sh",
            "bin/restore-openclaw-owner-data.sh",
            "bin/apply-tailscale-authority.sh",
            "bin/setup-tailscale-key.sh",
            "bin/restore.sh",
            "bin/install.sh",
            "restore-ubuntu.sh",
        )
        for relative in entrypoints:
            with self.subTest(relative=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertTrue(source.startswith("#!/usr/bin/bash -p\n"))

        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        for invocation in (
            "/usr/bin/bash -p bin/secrets-pack.sh",
            "/usr/bin/bash -p bin/secrets-verify.sh",
            "/usr/bin/bash -p bin/secrets-restore.sh",
            "/usr/bin/bash -p bin/restore-openclaw-owner-data.sh",
            "/usr/bin/bash -p bin/setup-tailscale-key.sh",
        ):
            self.assertIn(invocation, makefile)

        for relative in ("bin/restore.sh", "restore-ubuntu.sh"):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn('["/usr/bin/bash", "-p", f"/proc/self/fd/{sealed_fd}"],', source)
        self.assertIn(
            "exec /usr/bin/bash -p \"$CSR_REEXEC_INSTALL\"",
            (ROOT / "bin/install.sh").read_text(encoding="utf-8"),
        )

    def test_direct_secret_entrypoints_ignore_hostile_startup_hooks(self) -> None:
        cases = (
            ("bin/secrets-verify.sh", ("--degraded",), 0),
            ("bin/secrets-restore.sh", (), 2),
            (
                "bin/materialize-openclaw-runtime.sh",
                ("--allow-missing-classroom50", "--skip-secret-projections"),
                0,
            ),
        )
        for relative, arguments, expected in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                marker = home / "startup-hook-ran"
                startup = home / "bash-env"
                startup.write_text(
                    f"/usr/bin/touch {marker}\n", encoding="utf-8"
                )
                completed = subprocess.run(
                    [os.fspath(ROOT / relative), *arguments],
                    env={
                        "HOME": os.fspath(home),
                        "PATH": os.fspath(home),
                        "BASH_ENV": os.fspath(startup),
                        "ENV": os.fspath(startup),
                        "BASH_FUNC_python3%%": (
                            f"() {{ /usr/bin/touch {marker}; return 99; }}"
                        ),
                    },
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(completed.returncode, expected, completed.stderr.decode())
                self.assertFalse(marker.exists())


class RecoveryReleaseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release = load_module(
            "csr_recovery_release_hardening", "bin/verify-recovery-release.py"
        )

    def test_child_failures_are_redacted_and_run_in_a_closed_git_environment(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["synthetic"],
            returncode=9,
            stdout=b"",
            stderr=b"https://token-canary@example.invalid/private\n",
        )
        with mock.patch.object(
            self.release.subprocess, "run", return_value=completed
        ) as invoked:
            with self.assertRaises(self.release.ReleaseQualificationError) as caught:
                self.release._run(["/usr/bin/false"], "synthetic gate")
        self.assertNotIn("token-canary", str(caught.exception))
        environment = invoked.call_args.kwargs["env"]
        self.assertEqual(environment["HOME"], "/nonexistent")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertNotIn("PYTHONPATH", environment)

    def test_release_shell_boundaries_disable_git_hooks_and_global_config(self) -> None:
        published = (ROOT / "bin/verify-published-head.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("safe_git()", published)
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", published)
        self.assertIn("-c core.fsmonitor=false", published)
        self.assertIn("-c core.hooksPath=/dev/null", published)
        self.assertNotIn("authority: $remote_url", published)
        for relative in (
            "bin/secrets-pack.sh",
            "bin/secrets-import-legacy-zip.sh",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("safe_release_git()", source)
            self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", source)
            self.assertIn("GIT_NO_REPLACE_OBJECTS=1", source)
            self.assertIn("-c core.fsmonitor=false", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
