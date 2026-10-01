#!/usr/bin/env python3
"""Focused hostile-path and private-file tests for source initialization."""

from __future__ import annotations

import importlib.util
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "bin/lib/init_private_state.py"


def load_helper():
    library = str(HELPER_PATH.parent)
    if library not in sys.path:
        sys.path.insert(0, library)
    spec = importlib.util.spec_from_file_location("init_private_state", HELPER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load init-private helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InitPrivateStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = load_helper()

    def test_signing_pin_matches_tracked_stage0_public_key(self) -> None:
        public_key = ROOT / "system/recovery/recovery-signing-public-key.pub"
        self.assertEqual(
            self.helper.RECOVERY_SIGNING_KEY_SHA256,
            hashlib.sha256(public_key.read_bytes()).hexdigest(),
        )

    @staticmethod
    def _home(root: Path) -> Path:
        home = root / "home"
        home.mkdir(mode=0o700)
        (home / ".config").mkdir(mode=0o700)
        (home / ".config/coding-system").mkdir(mode=0o700)
        return home

    def test_owner_passphrase_generation_is_private_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self._home(Path(td))
            owner = home / ".config/coding-system/openclaw-owner-backup-passphrase.txt"
            legacy = home / ".config/coding-system/zip-password.txt"

            self.assertEqual(
                self.helper.ensure_owner_passphrase(owner, legacy), "generated"
            )
            first = owner.read_bytes()
            self.assertGreaterEqual(len(first.rstrip(b"\n")), 32)
            self.assertEqual(stat.S_IMODE(owner.stat().st_mode), 0o600)
            self.assertEqual(owner.stat().st_nlink, 1)
            self.assertEqual(
                self.helper.ensure_owner_passphrase(owner, legacy), "existing"
            )
            self.assertEqual(owner.read_bytes(), first)

    def test_owner_passphrase_migrates_only_safe_legacy_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self._home(Path(td))
            owner = home / ".config/coding-system/openclaw-owner-backup-passphrase.txt"
            legacy = home / ".config/coding-system/zip-password.txt"
            legacy.write_bytes(b"L" * 48 + b"\n")
            legacy.chmod(0o600)

            self.assertEqual(
                self.helper.ensure_owner_passphrase(owner, legacy), "migrated"
            )
            self.assertEqual(owner.read_bytes(), legacy.read_bytes())

            owner.unlink()
            link = home / ".config/coding-system/legacy-link"
            link.symlink_to(legacy)
            with self.assertRaisesRegex(self.helper.InitPrivateError, "unsafe"):
                self.helper.ensure_owner_passphrase(owner, link)

            hardlink = home / ".config/coding-system/legacy-hardlink"
            os.link(legacy, hardlink)
            with self.assertRaisesRegex(self.helper.InitPrivateError, "unsafe"):
                self.helper.ensure_owner_passphrase(owner, hardlink)

            hardlink.unlink()
            legacy.chmod(0o640)
            with self.assertRaisesRegex(self.helper.InitPrivateError, "unsafe"):
                self.helper.ensure_owner_passphrase(owner, legacy)

    def test_ensure_directory_rejects_link_and_repairs_owner_mode(self) -> None:
        with self.assertRaisesRegex(self.helper.InitPrivateError, "invalid"):
            self.helper._ensure_private_directory(Path("/"))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir(mode=0o700)
            config = home / ".config"
            config.mkdir(mode=0o700)
            target = config / "coding-system"
            target.mkdir(mode=0o755)
            self.helper._ensure_private_directory(target)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)

            target.rmdir()
            elsewhere = root / "elsewhere"
            elsewhere.mkdir(mode=0o700)
            target.symlink_to(elsewhere, target_is_directory=True)
            with self.assertRaisesRegex(
                self.helper.InitPrivateError, "create|unsafe"
            ):
                self.helper._ensure_private_directory(target)

    def test_denylist_preserves_entries_without_disclosing_values(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self._home(Path(td))
            owner = home / ".secrets.env"
            owner.write_text(
                "# coding-system private owner settings; literal KEY=value data only\n"
                "TELEGRAM_CHAT_ID=123456789\n"
                "MOLBOOK_AGENT_ID=agent-123456\n",
                encoding="utf-8",
            )
            owner.chmod(0o600)

            zotero = home / ".codex/runtime/workspace/skills/zotero"
            zotero.mkdir(mode=0o700, parents=True)
            for parent in (
                home / ".codex",
                home / ".codex/runtime",
                home / ".codex/runtime/workspace",
                home / ".codex/runtime/workspace/skills",
            ):
                parent.chmod(0o700)
            config = zotero / "config.json"
            config.write_text('{"user_id":"987654321"}\n', encoding="utf-8")
            config.chmod(0o644)

            google = home / ".config/openclaw/google-chat"
            google.mkdir(mode=0o700, parents=True)
            (home / ".config/openclaw").chmod(0o700)
            (google / "sample-app-012345abcdef.json").write_text(
                "{}\n", encoding="utf-8"
            )

            denylist = home / ".config/coding-system/leak-denylist.txt"
            denylist.write_text("preserved-value\n", encoding="utf-8")
            denylist.chmod(0o600)
            count = self.helper.seed_denylist(home, denylist)

            values = set(denylist.read_text(encoding="utf-8").splitlines())
            self.assertEqual(count, len(values))
            self.assertEqual(
                values,
                {
                    "123456789",
                    "987654321",
                    "agent-123456",
                    "preserved-value",
                    "sample-app",
                },
            )
            self.assertEqual(stat.S_IMODE(denylist.stat().st_mode), 0o600)
            self.assertEqual(denylist.stat().st_nlink, 1)

    def test_denylist_seeds_the_owner_schedule_and_storage_locations(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self._home(Path(td))
            owner = home / ".secrets.env"
            owner.write_text(
                "CSR_OWNER_TIMEZONE=Etc/UTC\n"
                "CSR_RSS_DIGEST_ONCALENDAR=*-*-* 04:30:00 Etc/UTC\n"
                "CSR_RCLONE_DEST=remote-a:backup-path\n"
                "CSR_OWNER_RCLONE_DEST=remote-a:owner-path\n"
                "CSR_ESCROW_GDRIVE=remote-b:escrow-path\n"
                "CSR_ESCROW_GH_REPO=someone/escrow-store\n",
                encoding="utf-8",
            )
            owner.chmod(0o600)
            (home / ".config/openclaw").mkdir(mode=0o700)
            denylist = home / ".config/coding-system/leak-denylist.txt"
            self.helper.seed_denylist(home, denylist)
            values = set(denylist.read_text(encoding="utf-8").splitlines())
            # the timezone alone is country-level and stays out of the denylist
            self.assertEqual(
                values,
                {
                    "*-*-* 04:30:00 Etc/UTC",
                    "remote-a:backup-path",
                    "remote-a:owner-path",
                    "remote-b:escrow-path",
                    "someone/escrow-store",
                },
            )

    @unittest.skipUnless(
        Path("/usr/bin/ssh-keygen").is_file() and hasattr(os, "memfd_create"),
        "Linux ssh-keygen and memfd are required",
    )
    def test_signing_authority_matches_exact_public_identity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root.chmod(0o700)
            key = root / "recovery-signing"
            result = subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(key),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            public_digest = hashlib.sha256(
                key.with_suffix(".pub").read_bytes()
            ).hexdigest()
            self.helper.verify_signing_authority(
                key,
                key.with_suffix(".pub"),
                expected_public_sha256=public_digest,
            )
            isolated = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(HELPER_PATH),
                    "verify-signing",
                    "--key",
                    str(key),
                    "--trusted-public",
                    str(key.with_suffix(".pub")),
                ],
                env={
                    "HOME": str(root),
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(isolated.returncode, 2)
            self.assertIn(
                "public trust root is not pinned",
                isolated.stderr.decode(errors="replace"),
            )

            other = root / "other"
            result = subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(other),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            with self.assertRaisesRegex(
                self.helper.InitPrivateError, "differs from the pinned"
            ):
                self.helper.verify_signing_authority(
                    key,
                    other.with_suffix(".pub"),
                    expected_public_sha256=hashlib.sha256(
                        other.with_suffix(".pub").read_bytes()
                    ).hexdigest(),
                )


class InitPrivateShellBoundaryTests(unittest.TestCase):
    def test_help_ignores_hostile_path_bash_env_and_pythonpath(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temporary = Path(td)
            fake_bin = temporary / "bin"
            fake_bin.mkdir()
            marker = temporary / "executed"
            bash_env = temporary / "bash-env"
            bash_env.write_text(f"/usr/bin/touch {marker}\n", encoding="utf-8")
            for command in ("dirname", "sed", "python3", "ssh-keygen"):
                fake = fake_bin / command
                fake.write_text(
                    f"#!/usr/bin/bash\ntouch {marker}\nexit 99\n", encoding="utf-8"
                )
                fake.chmod(0o755)
            environment = {
                "HOME": str(temporary),
                "PATH": str(fake_bin),
                "BASH_ENV": str(bash_env),
                "PYTHONPATH": str(fake_bin),
                "LD_LIBRARY_PATH": str(fake_bin),
                "BASH_FUNC_sed%%": f"() {{ /usr/bin/touch {marker}; return 99; }}",
                "BASH_FUNC_python3%%": f"() {{ /usr/bin/touch {marker}; return 99; }}",
            }
            for script in ("init-private.sh", "escrow-passphrase.sh"):
                result = subprocess.run(
                    [str(ROOT / "bin" / script), "--help"],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    result.stderr.decode(errors="replace"),
                )
            self.assertFalse(marker.exists())

    def test_shells_pin_path_and_scrub_interpreter_injection(self) -> None:
        for script in ("init-private.sh", "escrow-passphrase.sh"):
            text = (ROOT / "bin" / script).read_text(encoding="utf-8")
            self.assertTrue(text.startswith("#!/usr/bin/bash -p\n"))
            self.assertIn("export PATH=/usr/bin:/bin", text)
            self.assertIn("unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME", text)
            self.assertIn("umask 077", text)

    def test_escrow_local_command_ignores_hostile_shell_environment(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root.chmod(0o700)
            fake_bin = root / "bin"
            fake_bin.mkdir(mode=0o700)
            marker = root / "executed"
            bash_env = root / "bash-env"
            bash_env.write_text(f"/usr/bin/touch {marker}\n", encoding="utf-8")
            fake_python = fake_bin / "python3"
            fake_python.write_text(
                f"#!/usr/bin/bash\n/usr/bin/touch {marker}\nexit 99\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o700)
            generation = root / "generation"
            master = root / "master.key"
            result = subprocess.run(
                [
                    str(ROOT / "bin/escrow-passphrase.sh"),
                    "create-generation",
                    str(generation),
                    str(master),
                ],
                env={
                    "HOME": str(root),
                    "PATH": str(fake_bin),
                    "BASH_ENV": str(bash_env),
                    "PYTHONPATH": str(fake_bin),
                    "BASH_FUNC_python3%%": (
                        f"() {{ /usr/bin/touch {marker}; return 99; }}"
                    ),
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                check=False,
            )
            self.assertEqual(
                result.returncode,
                0,
                result.stderr.decode(errors="replace"),
            )
            self.assertTrue((generation / "escrow-generation.json").is_file())
            self.assertTrue(master.is_file())
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
