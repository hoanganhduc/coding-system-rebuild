import importlib.util
import fcntl
import hashlib
import os
from pathlib import Path
import py_compile
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class RestoreEntrypointTests(unittest.TestCase):
    def _write_script(self, path: Path, body: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/usr/bin/env bash\nset -eu\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def _remove_group_world_write(self, path: Path) -> None:
        path.chmod(stat.S_IMODE(path.lstat().st_mode) & ~0o022)
        for member in path.rglob("*"):
            if not member.is_symlink():
                member.chmod(stat.S_IMODE(member.lstat().st_mode) & ~0o022)

    def _run_sealed_install(
        self, repository: Path, environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        descriptor = os.memfd_create(
            "csr-test-installer",
            getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0),
        )
        try:
            os.write(descriptor, (repository / "bin/install.sh").read_bytes())
            os.lseek(descriptor, 0, os.SEEK_SET)
            fcntl.fcntl(
                descriptor,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_SEAL
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_WRITE,
            )
            return subprocess.run(
                ["/usr/bin/bash", f"/proc/self/fd/{descriptor}"],
                pass_fds=(descriptor,),
                env={
                    **environment,
                    "CSR_INSTALL_REPO_ROOT": str(repository),
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        finally:
            os.close(descriptor)

    def _exact_checkout_fixture(self, root: Path) -> tuple[Path, str]:
        repository = root / "repository"
        repository.mkdir()
        (repository / "tracked.txt").write_text("committed\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        subprocess.run(["git", "add", "."], cwd=repository, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Recovery Test",
                "-c",
                "user.email=recovery-test@example.invalid",
                "commit",
                "-qm",
                "synthetic fixture",
            ],
            cwd=repository,
            check=True,
        )
        self._remove_group_world_write(repository)
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        return repository, commit

    def _run_exact_checkout(self, repository: Path, commit: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/usr/bin/python3",
                str(ROOT / "bin/verify-exact-checkout.py"),
                "--repository",
                str(repository),
                "--commit",
                commit,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _recovery_auth_fixture(self, root: Path) -> tuple[Path, dict[str, str]]:
        repository = root / "repository"
        (repository / "bin/lib").mkdir(parents=True)
        shutil.copy2(ROOT / "Makefile", repository / "Makefile")
        shutil.copy2(
            ROOT / "bin/secrets-restore.sh", repository / "bin/secrets-restore.sh"
        )
        verifier_marker = root / "signature-verifier-ran"
        materializer_marker = root / "materializer-ran"
        self._write_script(
            repository / "bin/verify-recovery-signature.sh",
            ': > "$CSR_TEST_VERIFIER_MARKER"\nexit 43\n',
        )
        (repository / "bin/lib/recovery_tool.py").write_text(
            "from pathlib import Path\n"
            "import os\n"
            "Path(os.environ['CSR_TEST_VERIFIER_MARKER']).touch()\n"
            "raise SystemExit(43)\n",
            encoding="utf-8",
        )
        self._write_script(
            repository / "bin/materialize-openclaw-runtime.sh",
            ': > "$CSR_TEST_MATERIALIZER_MARKER"\n',
        )
        recovery_set = root / "recovery-set"
        recovery_set.mkdir()
        destination = root / "destination"
        destination.mkdir()
        sentinel = destination / "sentinel"
        sentinel.write_text("unchanged\n", encoding="utf-8")
        first_share = root / "share-01.txt"
        second_share = root / "share-02.txt"
        first_share.write_text("synthetic-one\n", encoding="utf-8")
        second_share.write_text("synthetic-two\n", encoding="utf-8")
        environment = os.environ.copy()
        environment.update(
            {
                "RECOVERY_SET": str(recovery_set),
                "CSR_ESCROW_SHARE_1_FILE": str(first_share),
                "CSR_ESCROW_SHARE_2_FILE": str(second_share),
                "HOME_OVERRIDE": str(destination),
                "CSR_TEST_VERIFIER_MARKER": str(verifier_marker),
                "CSR_TEST_MATERIALIZER_MARKER": str(materializer_marker),
            }
        )
        return repository, environment

    def test_makefile_exposes_complete_operator_surface(self) -> None:
        source = (ROOT / "Makefile").read_text(encoding="utf-8")
        for target in (
            "restore:",
            "verify-schedulers:",
            "scheduler-status:",
            "recovery-drill:",
            "refresh-lock:",
        ):
            self.assertIn(target, source)

    def test_install_orders_derived_state_before_scheduler_activation(self) -> None:
        source = (ROOT / "bin" / "install.sh").read_text(encoding="utf-8")
        completion = source.index("materialize-openclaw-completion.sh")
        unit_activation = source.index("reconcile-systemd-user-units.sh")
        gateway_health = source.index("openclaw_exact health --json", unit_activation)
        cron_import = source.index("openclaw-cron-v2.py", gateway_health)
        scheduler_canary = source.index("wait-scheduler-canaries.sh", cron_import)
        self.assertLess(completion, unit_activation)
        self.assertLess(unit_activation, gateway_health)
        self.assertLess(gateway_health, cron_import)
        self.assertLess(unit_activation, scheduler_canary)
        self.assertIn("CSR_SCHEDULER_NOT_BEFORE_UNIX", source)
        self.assertIn(
            '--not-before-unix "$CSR_SCHEDULER_NOT_BEFORE_UNIX"', source
        )
        self.assertIn("A direct PHASE=12 resume", source)

    def test_verifier_consumes_target_and_scheduler_contracts(self) -> None:
        source = (ROOT / "bin" / "verify.sh").read_text(encoding="utf-8")
        self.assertIn("verify-target-state.py", source)
        self.assertIn("verify-schedulers", source)
        self.assertIn("installed-runtime-smoke --require-complete-coverage", source)
        self.assertIn("--runtime-smoke-report", source)
        self.assertIn("--openclaw-runtime-passed", source)
        self.assertNotIn("crontab has $N jobs", source)
        self.assertIn("CSR_SCHEDULER_NOT_BEFORE_UNIX", source)
        self.assertIn("--not-before-unix", source)

    def test_restore_resolver_requires_one_recovery_set(self) -> None:
        script = ROOT / "bin" / "restore.sh"
        with tempfile.TemporaryDirectory() as temporary:
            inbox = Path(temporary)
            missing = subprocess.run(
                ["bash", str(script), "--resolve-only", "--inbox", str(inbox)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(missing.returncode, 0)

            first = inbox / "set-one"
            first.mkdir()
            (first / "recovery-set.json").write_text("{}\n", encoding="utf-8")
            selected = subprocess.run(
                ["bash", str(script), "--resolve-only", "--inbox", str(inbox)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(selected.returncode, 0, selected.stderr)
            self.assertEqual(Path(selected.stdout.strip()), first)

            second = inbox / "set-two"
            second.mkdir()
            (second / "recovery-set.json").write_text("{}\n", encoding="utf-8")
            ambiguous = subprocess.run(
                ["bash", str(script), "--resolve-only", "--inbox", str(inbox)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(ambiguous.returncode, 0)
            self.assertIn("ambiguous", ambiguous.stderr.lower())

    def test_signed_owner_member_replaces_ambient_and_latest_archive_selection(self) -> None:
        restore = (ROOT / "bin/restore.sh").read_text(encoding="utf-8")
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        stage_zero = (ROOT / "restore-ubuntu.sh").read_text(encoding="utf-8")
        self.assertIn(
            "unset OWNER_DATA REQUIRE_OWNER_DATA CSR_OWNER_DATA_REQUIREMENT",
            restore,
        )
        self.assertIn("inspect-set-owner", restore)
        self.assertIn('OWNER_DATA="$SET_DIR/$SIGNED_OWNER_FILE"', restore)
        self.assertNotIn('$INBOX/owner-data', restore)
        self.assertNotIn("OWNER_ARCHIVES", restore)
        self.assertIn("inspect-set-owner", install)
        self.assertIn('OWNER_DATA="$RECOVERY_SET/$SIGNED_OWNER_FILE"', install)
        self.assertNotIn("ls -1t", install)
        self.assertNotIn("openclaw-backups/openclaw-private-", install)
        handoff = stage_zero.split("RESTORE_ENV=(", 1)[1].split(
            "RESTORE_RUNTIME_DIR=", 1
        )[0]
        self.assertNotIn("OWNER_DATA", handoff)

    def test_production_signing_pin_is_consistent(self) -> None:
        public_digest = hashlib.sha256(
            (ROOT / "system/recovery/recovery-signing-public-key.pub").read_bytes()
        ).hexdigest()
        tool = (ROOT / "bin/lib/recovery_tool.py").read_text(encoding="utf-8")
        stage_zero = (ROOT / "restore-ubuntu.sh").read_text(encoding="utf-8")
        signer = (ROOT / "bin/sign-recovery-set.sh").read_text(encoding="utf-8")
        self.assertIn(f'"{public_digest}"', tool)
        self.assertIn(f'SIGNING_KEY_SHA256="{public_digest}"', stage_zero)
        self.assertIn(f'KEY_SHA256="{public_digest}"', signer)

    def test_pinned_signature_verifier_accepts_a_genuine_signature_and_rejects_tamper(
        self,
    ) -> None:
        """Run the unmodified verifier in a harness whose pinned trust root is a
        key made for this test, so no production key ever signs test data."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            harness = root / "repository"
            shutil.copytree(ROOT / "bin/lib", harness / "bin/lib",
                            ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copy2(ROOT / "bin/verify-recovery-signature.sh",
                         harness / "bin/verify-recovery-signature.sh")
            key = root / "test-only-signing-key"
            subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                           check=True)
            public = key.with_suffix(".pub").read_bytes()
            (harness / "system/recovery").mkdir(parents=True)
            (harness / "system/recovery/recovery-signing-public-key.pub").write_bytes(public)
            tool = harness / "bin/lib/recovery_tool.py"
            text, count = re.subn(
                r'^RECOVERY_SIGNING_KEY_SHA256 = \(\n    "[0-9a-f]{64}"\n\)$',
                f'RECOVERY_SIGNING_KEY_SHA256 = (\n    "{hashlib.sha256(public).hexdigest()}"\n)',
                tool.read_text(encoding="utf-8"),
                flags=re.MULTILINE,
            )
            self.assertEqual(count, 1)
            tool.write_text(text, encoding="utf-8")

            recovery_set = root / "recovery-set"
            recovery_set.mkdir()
            manifest = recovery_set / "recovery-set.json"
            manifest.write_text(
                '{"components":{"coding-system-rebuild":{"commit":"' + "a" * 40 + '"}}}\n',
                encoding="utf-8",
            )
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-Y", "sign", "-f", str(key),
                 "-n", "coding-system-recovery-set-v1", str(manifest)],
                check=True,
            )
            (recovery_set / "recovery-signing-public-key.pub").write_bytes(public)
            environment = {**os.environ, "RECOVERY_SET": str(recovery_set)}
            verifier = ["bash", str(harness / "bin/verify-recovery-signature.sh")]
            valid = subprocess.run(verifier, env=environment, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertIn("signature: valid", valid.stdout)

            manifest.write_text(
                '{"components":{"coding-system-rebuild":{"commit":"' + "b" * 40 + '"}}}\n',
                encoding="utf-8",
            )
            invalid = subprocess.run(verifier, env=environment, text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(invalid.returncode, 2)
            self.assertIn("detached signature is invalid", invalid.stderr)

            # A genuine signature by another key, shipped with that key, is not trusted.
            other = root / "other-test-only-key"
            subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other)],
                           check=True)
            manifest.write_text(
                '{"components":{"coding-system-rebuild":{"commit":"' + "a" * 40 + '"}}}\n',
                encoding="utf-8",
            )
            (recovery_set / "recovery-set.json.sig").unlink()
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-Y", "sign", "-f", str(other),
                 "-n", "coding-system-recovery-set-v1", str(manifest)],
                check=True,
            )
            (recovery_set / "recovery-signing-public-key.pub").write_bytes(
                other.with_suffix(".pub").read_bytes()
            )
            foreign = subprocess.run(verifier, env=environment, text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(foreign.returncode, 2)
            self.assertIn("trust root mismatch", foreign.stderr)

    def test_direct_and_make_secret_restore_authenticate_before_mutation(self) -> None:
        for entrypoint in ("direct", "make"):
            with self.subTest(entrypoint=entrypoint):
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    repository, environment = self._recovery_auth_fixture(root)
                    if entrypoint == "direct":
                        command = ["bash", str(repository / "bin/secrets-restore.sh")]
                        cwd = None
                    else:
                        command = ["make", "-s", "restore-secrets"]
                        cwd = repository
                    completed = subprocess.run(
                        command,
                        cwd=cwd,
                        env=environment,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertTrue(
                        Path(environment["CSR_TEST_VERIFIER_MARKER"]).is_file()
                    )
                    self.assertFalse(
                        Path(environment["CSR_TEST_MATERIALIZER_MARKER"]).exists()
                    )
                    destination = Path(environment["HOME_OVERRIDE"])
                    self.assertEqual(
                        {path.name for path in destination.iterdir()}, {"sentinel"}
                    )
                    self.assertEqual(
                        (destination / "sentinel").read_text(encoding="utf-8"),
                        "unchanged\n",
                    )

    def test_direct_install_authenticates_before_any_install_gate_or_phase(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repository = root / "repository"
            (repository / "bin/lib").mkdir(parents=True)
            shutil.copy2(ROOT / "bin/install.sh", repository / "bin/install.sh")
            shutil.copy2(
                ROOT / "bin/verify-exact-checkout.py",
                repository / "bin/verify-exact-checkout.py",
            )
            verifier_marker = root / "signature-verifier-ran"
            provision_marker = root / "grok-provision-ran"
            self._write_script(
                repository / "bin/verify-recovery-signature.sh",
                ': > "$CSR_TEST_VERIFIER_MARKER"\nexit 43\n',
            )
            (repository / "bin/provision-grok-bootstrap.py").write_text(
                "from pathlib import Path\n"
                "import os\n"
                "Path(os.environ['CSR_TEST_PROVISION_MARKER']).touch()\n",
                encoding="utf-8",
            )
            (repository / "bin/lib/recovery_tool.py").write_text(
                "import os\n"
                "from pathlib import Path\n"
                "import sys\n"
                "if sys.argv[1] == 'check-snapshot':\n"
                "    raise SystemExit(0)\n"
                "if sys.argv[1] == 'remove-snapshot':\n"
                "    Path(sys.argv[sys.argv.index('--snapshot-dir') + 1]).rmdir()\n",
                encoding="utf-8",
            )
            (repository / ".gitignore").write_text(
                "__pycache__/\n*.pyc\n", encoding="utf-8"
            )
            subprocess.run(
                ["git", "init", "-q"], cwd=repository, check=True
            )
            subprocess.run(
                ["git", "add", "."], cwd=repository, check=True
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Recovery Test",
                    "-c",
                    "user.email=recovery-test@example.invalid",
                    "commit",
                    "-qm",
                    "synthetic fixture",
                ],
                cwd=repository,
                check=True,
            )
            fsmonitor_marker = root / "hostile-fsmonitor-ran"
            fsmonitor = root / "hostile-fsmonitor"
            self._write_script(
                fsmonitor,
                f': > "{fsmonitor_marker}"\nprintf "\n"\n',
            )
            subprocess.run(
                ["git", "config", "core.fsmonitor", str(fsmonitor)],
                cwd=repository,
                check=True,
            )
            self._remove_group_world_write(repository)
            recovery_set = root / "recovery-set"
            recovery_set.mkdir()
            home = root / "home"
            home.mkdir()
            hostile_uname_marker = root / "hostile-uname-ran"
            self._write_script(
                home / ".local/bin/uname",
                f': > "{hostile_uname_marker}"\n/usr/bin/uname "$@"\n',
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "RECOVERY_SET": str(recovery_set),
                    "CSR_TEST_VERIFIER_MARKER": str(verifier_marker),
                    "CSR_TEST_PROVISION_MARKER": str(provision_marker),
                }
            )
            unauthenticated = subprocess.run(
                ["bash", str(repository / "bin/install.sh")],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(unauthenticated.returncode, 2)
            self.assertIn(
                "authenticated restore requires the sealed installer handoff",
                unauthenticated.stderr,
            )
            self.assertFalse(verifier_marker.exists())
            self.assertFalse(provision_marker.exists())
            self.assertFalse(fsmonitor_marker.exists())
            self.assertFalse(hostile_uname_marker.exists())
            shutil.rmtree(home / ".local")

            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            environment.update(
                {
                    "CSR_EXPECTED_RECOVERY_COMMIT": commit,
                    "CSR_RESTORE_RECOVERY_SNAPSHOT": str(recovery_set),
                    "CSR_STAGE0_VERIFIED_COMMIT": commit,
                }
            )
            completed = self._run_sealed_install(repository, environment)
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("repository-generation identity is invalid", completed.stderr)
            self.assertFalse(verifier_marker.exists())
            self.assertFalse(provision_marker.exists())
            self.assertFalse(fsmonitor_marker.exists())
            self.assertEqual(list(home.iterdir()), [])

    def test_exact_checkout_rejects_an_attacker_owned_sticky_ancestor(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_exact_checkout", ROOT / "bin/verify-exact-checkout.py"
        )
        assert spec is not None and spec.loader is not None
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        unsafe = os.stat_result(
            (
                stat.S_IFDIR | 0o1777,
                1,
                1,
                1,
                os.geteuid() + 1,
                os.getegid(),
                0,
                0,
                0,
                0,
            )
        )
        with mock.patch.object(Path, "lstat", return_value=unsafe):
            with self.assertRaises(verifier.CheckoutError):
                verifier.require_safe_ancestors(Path("/attacker-owned/repository"))

    def test_exact_checkout_rejects_local_fsck_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repository, commit = self._exact_checkout_fixture(Path(td))
            subprocess.run(
                ["git", "config", "fsck.badObjectSha1", "ignore"],
                cwd=repository,
                check=True,
            )
            self._remove_group_world_write(repository)
            completed = self._run_exact_checkout(repository, commit)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("fsck overrides", completed.stderr)

    def test_exact_checkout_rejects_group_writable_repository_or_metadata(self) -> None:
        for relative in (Path("."), Path(".git")):
            with self.subTest(relative=str(relative)):
                with tempfile.TemporaryDirectory() as td:
                    repository, commit = self._exact_checkout_fixture(Path(td))
                    target = repository / relative
                    target.chmod(stat.S_IMODE(target.stat().st_mode) | 0o020)
                    completed = self._run_exact_checkout(repository, commit)
                    self.assertEqual(completed.returncode, 2)
                    self.assertIn("writable", completed.stderr)

    def test_exact_checkout_rejects_untracked_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repository, commit = self._exact_checkout_fixture(Path(td))
            extra = repository / "untracked-empty"
            extra.mkdir(mode=0o700)
            completed = self._run_exact_checkout(repository, commit)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("uncommitted directory", completed.stderr)

    def test_exact_checkout_migration_exception_is_only_for_safe_external_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repository, commit = self._exact_checkout_fixture(Path(td))
            external = repository / "external/component"
            external.mkdir(parents=True, mode=0o700)
            (repository / "external").chmod(0o700)
            external.chmod(0o700)
            payload = external / "fixture.txt"
            payload.write_text("legacy component\n", encoding="utf-8")
            payload.chmod(0o600)
            rejected = self._run_exact_checkout(repository, commit)
            self.assertEqual(rejected.returncode, 2)
            accepted = subprocess.run(
                [
                    "/usr/bin/python3",
                    str(ROOT / "bin/verify-exact-checkout.py"),
                    "--repository",
                    str(repository),
                    "--commit",
                    commit,
                    "--allow-untracked-root",
                    "external",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            unrelated = repository / "still-untracked"
            unrelated.mkdir(mode=0o700)
            refused = subprocess.run(
                [
                    "/usr/bin/python3",
                    str(ROOT / "bin/verify-exact-checkout.py"),
                    "--repository",
                    str(repository),
                    "--commit",
                    commit,
                    "--allow-untracked-root",
                    "external",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(refused.returncode, 2)
            self.assertIn("uncommitted directory", refused.stderr)

    def test_exact_checkout_rejects_wrong_size_before_content_digest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repository, commit = self._exact_checkout_fixture(Path(td))
            tracked = repository / "tracked.txt"
            tracked.write_text("replacement with a different size\n", encoding="utf-8")
            tracked.chmod(0o600)
            completed = self._run_exact_checkout(repository, commit)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("file size differs", completed.stderr)

    def test_exact_checkout_rejects_special_permission_bits(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repository = Path(td) / "repository"
            repository.mkdir()
            executable = repository / "tool"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Recovery Test",
                    "-c",
                    "user.email=recovery-test@example.invalid",
                    "commit",
                    "-qm",
                    "executable fixture",
                ],
                cwd=repository,
                check=True,
            )
            self._remove_group_world_write(repository)
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout.strip()
            executable.chmod(0o4700)
            completed = self._run_exact_checkout(repository, commit)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("checkout file", completed.stderr)

    def test_storage_snapshot_rejects_nested_mount_records(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_exact_checkout_mounts", ROOT / "bin/verify-exact-checkout.py"
        )
        assert spec is not None and spec.loader is not None
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        mountinfo = (
            "20 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"
            "21 20 0:55 / /repo/nested rw,nosuid - tmpfs tmpfs rw\n"
        )
        with mock.patch.object(Path, "read_text", return_value=mountinfo):
            with self.assertRaisesRegex(verifier.CheckoutError, "nested or direct mount"):
                verifier.storage_snapshot(Path("/repo"))

    def test_stage0_handoff_uses_a_closed_environment_without_make(self) -> None:
        source = (ROOT / "restore-ubuntu.sh").read_text(encoding="utf-8")
        handoff = source.split(
            'note "handing off to the authenticated restore entry point"', 1
        )[1]
        self.assertIn('/usr/bin/env -i "${RESTORE_ENV[@]}"', handoff)
        self.assertIn('RESTORE_ENV+=(PHASE="$REQUESTED_PHASE")', handoff)
        self.assertIn("os.memfd_create", handoff)
        self.assertIn("F_ADD_SEALS", handoff)
        generation = source.split(
            'note "handing off to the authenticated restore entry point"', 1
        )[0]
        self.assertIn("cat-file blob", generation)
        self.assertIn("repository-generation-$GENERATION_HELPER_SHA256.py", generation)
        self.assertIn("CSR_STAGE0_REPOSITORY_GENERATION", handoff)
        self.assertIn("os.execve", handoff)
        self.assertIn('["/usr/bin/bash", "-p", f"/proc/self/fd/{sealed_fd}"]', handoff)
        self.assertNotIn("/usr/bin/make -C", handoff)
        self.assertIn("MAKEFILES", source.split("die()", 1)[0])
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        restore_recipe = makefile.split("restore:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("/usr/bin/bash -p bin/restore.sh", restore_recipe)

    def test_stage0_and_installer_reject_out_of_range_phase(self) -> None:
        for value in ("0", "13", "1x", "-1"):
            with self.subTest(value=value):
                stage0 = subprocess.run(
                    ["/usr/bin/bash", "-p", str(ROOT / "restore-ubuntu.sh"), "--check-only"],
                    env={**os.environ, "PHASE": value},
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(stage0.returncode, 2)
                self.assertIn("PHASE must be an integer", stage0.stderr)
                installer = subprocess.run(
                    ["/usr/bin/bash", str(ROOT / "bin/install.sh")],
                    env={**os.environ, "PHASE": value},
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(installer.returncode, 2)
                self.assertIn("PHASE must be an integer", installer.stderr)

    def test_docker_group_reentry_keeps_the_authenticated_memfd(self) -> None:
        source = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        branch = source.split("# `usermod -aG docker`", 1)[1].split("# 3 ─ secrets", 1)[0]
        self.assertIn('CSR_REEXEC_INSTALL="$INSTALL_SCRIPT_SOURCE"', branch)
        self.assertIn('CSR_INSTALL_REPO_ROOT="$REPO"', branch)
        self.assertNotIn('CSR_REEXEC_INSTALL="$REPO/bin/install.sh"\n    export', branch)

    def test_stage0_clone_is_private_hardened_and_no_replace(self) -> None:
        source = (ROOT / "restore-ubuntu.sh").read_text(encoding="utf-8")
        validation = source.index('validate_clone_parent "$REPO_TARGET"')
        staging = source.index("/usr/bin/mktemp -d", validation)
        network = source.index("fetch -q --depth 1", staging)
        activation = source.index("rename_clone_noreplace", network)
        self.assertLess(validation, staging)
        self.assertLess(staging, network)
        self.assertLess(network, activation)
        self.assertIn("protocol.ext.allow=never", source)
        self.assertIn("CLONE_STAGE_PREFIX", source)
        self.assertIn("/usr/bin/chmod 0700", source)
        self.assertIn("renameat2(-100, source, -100, destination, 1)", source)
        self.assertIn("2,  # RENAME_EXCHANGE", source)
        self.assertIn('"$CLONE_STAGE" "$RESTORE_COMMIT" external', source)
        self.assertIn('exchange_clone_atomically "$CLONE_STAGE" "$REPO_TARGET"', source)
        self.assertLess(
            source.index('"$REPO_TARGET" "$EXISTING_COMMIT" \\'),
            source.index('exchange_clone_atomically "$CLONE_STAGE" "$REPO_TARGET"'),
        )

    def test_install_repo_override_cannot_redirect_the_trusted_installer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            attacker = root / "attacker-repository"
            (attacker / "bin").mkdir(parents=True)
            marker = root / "attacker-verifier-ran"
            self._write_script(
                attacker / "bin/install.sh", "exit 0\n"
            )
            self._write_script(
                attacker / "bin/verify-recovery-signature.sh",
                f': > "{marker}"\n',
            )
            completed = subprocess.run(
                ["bash", str(ROOT / "bin/install.sh")],
                env={
                    **os.environ,
                    "CSR_INSTALL_REPO_ROOT": str(attacker),
                    "HOME": str(root / "home"),
                    "PHASE": "2147483647",
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn(
                "descriptor-bound install did not use a held installer",
                completed.stderr,
            )
            self.assertFalse(marker.exists())

            recovery_set = root / "recovery-set"
            recovery_set.mkdir()
            descriptor = os.open(ROOT / "bin/install.sh", os.O_RDONLY)
            try:
                authenticated_override = subprocess.run(
                    ["/usr/bin/bash", f"/proc/self/fd/{descriptor}"],
                    pass_fds=(descriptor,),
                    env={
                        **os.environ,
                        "CSR_INSTALL_REPO_ROOT": str(ROOT),
                        "HOME": str(root / "home"),
                        "RECOVERY_SET": str(recovery_set),
                        "PHASE": "2147483647",
                    },
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
            finally:
                os.close(descriptor)
            self.assertEqual(authenticated_override.returncode, 2)
            self.assertIn(
                "installer entry point is not immutable and sealed",
                authenticated_override.stderr,
            )

    def test_final_gate_does_not_resolve_bash_or_python_from_hostile_home(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repository = root / "repository"
            (repository / "bin").mkdir(parents=True)
            shutil.copy2(ROOT / "bin/install.sh", repository / "bin/install.sh")
            home = root / "home"
            hostile_bin = home / ".local/bin"
            marker = root / "hostile-final-gate-tool-ran"
            for name in ("bash", "python3"):
                self._write_script(hostile_bin / name, f': > "{marker}"\nexit 0\n')

            completed = subprocess.run(
                ["/usr/bin/bash", str(repository / "bin/install.sh")],
                env={
                    **os.environ,
                    "HOME": str(home),
                    "PATH": f"{hostile_bin}:/usr/bin:/bin",
                    "PHASE": "12",
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertFalse(
                (home / ".local/state/coding-system/restore-report.json").exists()
            )

    def test_recovery_python_invocations_ignore_repo_local_bytecode(self) -> None:
        for relative in (
            "bin/verify-recovery-signature.sh",
            "bin/secrets-verify.sh",
            "bin/secrets-restore.sh",
            "bin/restore.sh",
            "bin/install.sh",
        ):
            self.assertIn(
                "-X pycache_prefix=/dev/null",
                (ROOT / relative).read_text(encoding="utf-8"),
                relative,
            )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            library = root / "lib"
            library.mkdir()
            for name in (
                "recovery_tool.py",
                "secure_temp.py",
                "shamir.py",
                "restore_transaction.py",
            ):
                shutil.copy2(ROOT / "bin/lib" / name, library / name)
            marker = root / "ignored-bytecode-ran"
            secure_temp = library / "secure_temp.py"
            original = secure_temp.read_bytes()
            secure_temp.write_text(
                "from contextlib import contextmanager\n"
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).touch()\n"
                "class SecureTempError(RuntimeError):\n    pass\n"
                "@contextmanager\n"
                "def secure_temporary_directory(*, prefix):\n"
                "    yield '/tmp'\n",
                encoding="utf-8",
            )
            cache = Path(importlib.util.cache_from_source(str(secure_temp)))
            cache.parent.mkdir()
            py_compile.compile(
                str(secure_temp),
                cfile=str(cache),
                doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            )
            secure_temp.write_bytes(original)

            control = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(library / "recovery_tool.py"),
                    "--help",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(control.returncode, 0, control.stderr)
            self.assertTrue(marker.is_file(), "forged unchecked cache was not loadable")
            marker.unlink()
            protected = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    "-X",
                    "pycache_prefix=/dev/null",
                    str(library / "recovery_tool.py"),
                    "--help",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(protected.returncode, 0, protected.stderr)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
