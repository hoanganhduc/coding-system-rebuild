#!/usr/bin/env python3
"""Security regressions for the data-only private owner-settings boundary."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "bin/lib/owner_settings.py"
SPEC = importlib.util.spec_from_file_location("csr_owner_settings", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
owner_settings = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owner_settings)
MIGRATION_MODULE_PATH = ROOT / "bin/migrate-owner-settings.py"
MIGRATION_SPEC = importlib.util.spec_from_file_location(
    "csr_migrate_owner_settings", MIGRATION_MODULE_PATH
)
assert MIGRATION_SPEC is not None and MIGRATION_SPEC.loader is not None
migration = importlib.util.module_from_spec(MIGRATION_SPEC)
MIGRATION_SPEC.loader.exec_module(migration)


def private_file(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o600)


class OwnerSettingsTests(unittest.TestCase):
    def test_accepts_only_the_exact_owner_setting_names(self) -> None:
        payload = b"".join(
            f"{key}=value-{index}\n".encode()
            for index, key in enumerate(owner_settings.OWNER_SETTING_KEYS)
        )
        self.assertEqual(
            set(owner_settings.parse_owner_settings(payload)),
            set(owner_settings.OWNER_SETTING_KEYS),
        )
        for unsupported in (
            b"MOLTBOOK_API_KEY=secret\n",
            b"MOLTBOOK_FUTURE_SETTING=value\n",
            b"UNKNOWN=value\n",
            b"export TELEGRAM_CHAT_ID=123\n",
        ):
            with self.subTest(unsupported=unsupported):
                with self.assertRaises(owner_settings.OwnerSettingsError):
                    owner_settings.parse_owner_settings(unsupported)

    def test_owner_location_and_schedule_settings_are_accepted_everywhere(self) -> None:
        keys = ("CSR_OWNER_TIMEZONE", "CSR_RSS_DIGEST_ONCALENDAR", "CSR_RCLONE_DEST",
                "CSR_OWNER_RCLONE_DEST", "CSR_ESCROW_GDRIVE", "CSR_ESCROW_GH_REPO")
        payload = "".join(f"{key}=synthetic-{index}\n" for index, key in enumerate(keys)).encode()
        self.assertEqual(set(owner_settings.parse_owner_settings(payload)), set(keys))
        loader = (ROOT / "system/shell/bashrc.block.sh").read_text(encoding="utf-8")
        case_line = next(line.strip() for line in loader.splitlines()
                         if line.strip().startswith("CLASSROOM50_ORG_ALLOWLIST|"))
        self.assertEqual(case_line.removesuffix(") ;;").split("|"),
                         list(owner_settings.OWNER_SETTING_KEYS))

    def test_get_prints_one_allowlisted_value_as_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".secrets.env"
            private_file(path, b"CSR_RSS_DIGEST_ONCALENDAR=*-*-* 04:30:00 Etc/UTC\n")
            command = ["/usr/bin/python3", "-I", "-B", os.fspath(MODULE_PATH), "get", "--path", os.fspath(path)]
            present = subprocess.run(command + ["--key", "CSR_RSS_DIGEST_ONCALENDAR"],
                                     text=True, capture_output=True, check=False)
            self.assertEqual((present.returncode, present.stdout), (0, "*-*-* 04:30:00 Etc/UTC\n"))
            absent = subprocess.run(command + ["--key", "CSR_RCLONE_DEST"],
                                    text=True, capture_output=True, check=False)
            self.assertEqual((absent.returncode, absent.stdout), (0, "\n"))
            unknown = subprocess.run(command + ["--key", "HOME"], text=True, capture_output=True, check=False)
            self.assertEqual(unknown.returncode, 2)

    def test_rejects_shell_fragments_without_executing_them(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "executed"
            payload = f"TELEGRAM_CHAT_ID=$(touch {marker})\n".encode()
            with self.assertRaises(owner_settings.OwnerSettingsError):
                owner_settings.parse_owner_settings(payload)
            self.assertFalse(marker.exists())

    def test_rejects_symlinked_or_world_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            private_file(real / ".secrets.env", b"TELEGRAM_CHAT_ID=123\n")
            (root / "linked").symlink_to(real, target_is_directory=True)
            with self.assertRaises(owner_settings.OwnerSettingsError):
                owner_settings.read_owner_settings(root / "linked/.secrets.env")

            unsafe = root / "unsafe"
            private_file(unsafe / ".secrets.env", b"TELEGRAM_CHAT_ID=123\n")
            unsafe.chmod(0o777)
            with self.assertRaises(owner_settings.OwnerSettingsError):
                owner_settings.read_owner_settings(unsafe / ".secrets.env")

    def test_rejects_same_size_mutation_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".secrets.env"
            original = b"TELEGRAM_CHAT_ID=111\n"
            replacement = b"TELEGRAM_CHAT_ID=222\n"
            private_file(path, original)
            real_read = os.read
            mutated = False

            def mutating_read(descriptor: int, size: int) -> bytes:
                nonlocal mutated
                block = real_read(descriptor, size)
                if block and not mutated:
                    mutated = True
                    path.write_bytes(replacement)
                    path.chmod(0o600)
                return block

            with mock.patch.object(owner_settings.os, "read", side_effect=mutating_read):
                with self.assertRaises(owner_settings.OwnerSettingsError):
                    owner_settings.read_owner_settings(path)

    def _shell_home(self, root: Path, helper: bytes | None = None) -> tuple[Path, str]:
        home = root / "home"
        helper_path = home / ".local/share/coding-system/repository/bin/lib/owner_settings.py"
        private_file(
            helper_path,
            MODULE_PATH.read_bytes() if helper is None else helper,
        )
        source = (ROOT / "system/shell/bashrc.block.sh").read_text(encoding="utf-8")
        start = source.index(
            "# coding-system: private owner settings are data, never executable shell."
        )
        terminator = "export CSR_OWNER_SETTINGS_STATUS CSR_OWNER_SETTINGS_RC\n"
        end = source.index(terminator, start) + len(terminator)
        return home, source[start:end]

    def _run_loader(self, home: Path, block: str) -> subprocess.CompletedProcess[str]:
        block_path = home / "loader.sh"
        block_path.write_text(block, encoding="utf-8")
        return subprocess.run(
            [
                "bash",
                "--noprofile",
                "--norc",
                "-c",
                'source "$1"; printf "STATUS=%s RC=%s CHAT=%s\\n" '
                '"$CSR_OWNER_SETTINGS_STATUS" "$CSR_OWNER_SETTINGS_RC" '
                '"${TELEGRAM_CHAT_ID-}"',
                "bash",
                os.fspath(block_path),
            ],
            env={"HOME": os.fspath(home), "PATH": os.environ["PATH"]},
            text=True,
            capture_output=True,
            check=False,
        )

    def test_shell_loader_malformed_file_is_fail_visible_and_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home, block = self._shell_home(Path(temporary))
            private_file(
                home / ".secrets.env",
                b"TELEGRAM_CHAT_ID=123\nMOLTBOOK_API_KEY=must-not-load\n",
            )
            result = self._run_loader(home, block)
            self.assertEqual(result.returncode, 0)
            self.assertIn("STATUS=INVALID RC=2 CHAT=", result.stdout)
            self.assertIn("private owner settings are invalid", result.stderr)

    def test_shell_loader_helper_failure_is_fail_visible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home, block = self._shell_home(
                Path(temporary), b"raise SystemExit(7)\n"
            )
            private_file(home / ".secrets.env", b"TELEGRAM_CHAT_ID=123\n")
            result = self._run_loader(home, block)
            self.assertEqual(result.returncode, 0)
            self.assertIn("STATUS=INVALID RC=2 CHAT=", result.stdout)
            self.assertIn("private owner settings are invalid", result.stderr)

    def test_shell_loader_rechecks_helper_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            helper = b'import sys\nsys.stdout.buffer.write(b"PATH\\0attacker\\0")\n'
            home, block = self._shell_home(Path(temporary), helper)
            private_file(home / ".secrets.env", b"TELEGRAM_CHAT_ID=123\n")
            result = self._run_loader(home, block)
            self.assertIn("STATUS=INVALID RC=2 CHAT=", result.stdout)
            self.assertIn("private owner settings are invalid", result.stderr)


class OwnerSettingsMigrationTests(unittest.TestCase):
    def run_migration(self, home: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                os.fspath(ROOT / "bin/migrate-owner-settings.py"),
                "--home",
                os.fspath(home),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def run_materializer(self, home: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                os.fspath(ROOT / "bin/materialize-secret-projections.py"),
                "--home",
                os.fspath(home),
                "--migrate-vnu-legacy",
                "--migrate-remote-bridge-legacy",
                "--migrate-aas-legacy",
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_pre_files_promote_credentials_before_sanitized_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            (home / ".bashrc").write_text("# current bashrc\n", encoding="utf-8")
            (home / ".profile").write_text("# current profile\n", encoding="utf-8")
            bash_backup = home / ".bashrc.pre-coding-system"
            bash_backup.write_text(
                "export KIMI_API_KEY=kimi-pre-canary\n"
                "export KAGGLE_API_TOKEN=kaggle-pre-canary\n"
                "export ZULIP_ORG_URL=https://fixture.zulip.invalid\n"
                "export ZULIP_EMAIL=bot@fixture.invalid\n"
                "export ZULIP_API_KEY=zulip-pre-canary\n",
                encoding="utf-8",
            )
            bash_backup.chmod(0o664)
            profile_backup = home / ".profile.pre-coding-system"
            profile_backup.write_text(
                "export VNU_EOFFICE_USERNAME=fixture-user\n"
                "export VNU_EOFFICE_PASSWORD=vnu-pre-canary\n"
                "export VNU_STATE_HMAC_KEY=vnu-state-pre-canary\n",
                encoding="utf-8",
            )
            profile_backup.chmod(0o664)
            private_file(home / ".npmrc", b"//registry.example/:_authToken=npm-canary\n")
            private_file(
                home / ".npmrc.pre-coding-system",
                b"//registry.example/:_authToken=npm-canary\n",
            )

            migrated = self.run_migration(home)
            self.assertEqual(migrated.returncode, 0, migrated.stderr)
            for backup in (bash_backup, profile_backup):
                self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
                text = backup.read_text(encoding="utf-8")
                for name in (
                    "KIMI_API_KEY",
                    "KAGGLE_API_TOKEN",
                    "ZULIP_API_KEY",
                    "VNU_EOFFICE_PASSWORD",
                ):
                    self.assertNotIn(name, text)
            self.assertFalse((home / ".npmrc.pre-coding-system").exists())

            projected = self.run_materializer(home)
            self.assertEqual(projected.returncode, 0, projected.stderr)
            self.assertIn(
                "KIMI_API_KEY=kimi-pre-canary\n",
                (home / ".config/ai-agents-skills/providers.env").read_text(
                    encoding="utf-8"
                ),
            )
            self.assertIn(
                "KAGGLE_API_TOKEN=kaggle-pre-canary\n",
                (home / ".config/ai-agents-skills/compute.env").read_text(
                    encoding="utf-8"
                ),
            )
            remote = json.loads(
                (home / ".config/remote-bridge/secrets.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(remote["zulip"]["api_key"], "zulip-pre-canary")
            self.assertNotIn("telegram", remote)
            vnu = json.loads(
                (home / ".config/vnu-eoffice/secrets.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(vnu["VNU_EOFFICE_PASSWORD"], "vnu-pre-canary")
            self.assertNotIn("TELEGRAM_BOT_TOKEN", vnu)
            owner = (home / ".secrets.env").read_text(encoding="utf-8")
            for name in (
                "KIMI_API_KEY",
                "KAGGLE_API_TOKEN",
                "ZULIP_API_KEY",
                "VNU_EOFFICE_PASSWORD",
            ):
                self.assertNotIn(name, owner)

    def test_live_broad_credential_residue_converges_to_dedicated_authorities(self) -> None:
        """Preserve every known value before scrubbing either broad source."""

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            (home / ".bashrc").write_text("# clean\n", encoding="utf-8")
            private_file(
                home / ".secrets.env",
                b"TELEGRAM_CHAT_ID=12345\n"
                b"TELEGRAM_BOT_TOKEN=telegram-residue-canary\n"
                b"LEANEXPLORE_API_KEY=lean-residue-canary\n"
                b"OCRSPACE_API_KEY=ocr-residue-canary\n",
            )
            private_file(
                home / ".config/ai-agents-skills/providers.env",
                b"GH_TOKEN=github-residue-canary\n",
            )

            migrated = self.run_migration(home)
            self.assertEqual(migrated.returncode, 0, migrated.stderr)
            quarantined = (home / ".secrets.env").read_text(encoding="utf-8")
            for key in (
                "TELEGRAM_BOT_TOKEN",
                "LEANEXPLORE_API_KEY",
                "OCRSPACE_API_KEY",
            ):
                self.assertIn(f"{key}=", quarantined)

            projected = self.run_materializer(home)
            self.assertEqual(projected.returncode, 0, projected.stderr)

            shared = json.loads(
                (home / ".config/ai-agents-skills/secrets.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                shared["TELEGRAM_BOT_TOKEN"], "telegram-residue-canary"
            )
            skill = (
                home / ".config/ai-agents-skills/skill.env"
            ).read_text(encoding="utf-8")
            self.assertIn("LEANEXPLORE_API_KEY=lean-residue-canary\n", skill)
            self.assertIn("OCRSPACE_API_KEY=ocr-residue-canary\n", skill)
            copilot = (
                home / ".config/ai-agents-skills/providers/copilot.env"
            ).read_text(encoding="utf-8")
            self.assertIn("GH_TOKEN=github-residue-canary\n", copilot)

            owner = (home / ".secrets.env").read_text(encoding="utf-8")
            self.assertIn("TELEGRAM_CHAT_ID=12345\n", owner)
            for key in (
                "TELEGRAM_BOT_TOKEN",
                "LEANEXPLORE_API_KEY",
                "OCRSPACE_API_KEY",
            ):
                self.assertNotIn(key, owner)
            broad_provider = (
                home / ".config/ai-agents-skills/providers.env"
            ).read_text(encoding="utf-8")
            self.assertNotIn("GH_TOKEN", broad_provider)

            rerun = self.run_materializer(home)
            self.assertEqual(rerun.returncode, 0, rerun.stderr)
            self.assertEqual(
                shared,
                json.loads(
                    (home / ".config/ai-agents-skills/secrets.json").read_text(
                        encoding="utf-8"
                    )
                ),
            )
            self.assertIn(
                "GH_TOKEN=github-residue-canary\n",
                (
                    home / ".config/ai-agents-skills/providers/copilot.env"
                ).read_text(encoding="utf-8"),
            )

    def test_incomplete_zulip_shell_set_fails_before_source_scrub(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            (home / ".bashrc").write_text(
                "export ZULIP_API_KEY=incomplete-canary\n", encoding="utf-8"
            )
            migrated = self.run_migration(home)
            self.assertEqual(migrated.returncode, 0, migrated.stderr)
            before = (home / ".secrets.env").read_bytes()

            projected = self.run_materializer(home)

            self.assertEqual(projected.returncode, 2)
            self.assertEqual((home / ".secrets.env").read_bytes(), before)
            self.assertFalse((home / ".config/remote-bridge/secrets.json").exists())
            self.assertNotIn("incomplete-canary", projected.stdout + projected.stderr)

    def test_divergent_zulip_shell_set_fails_without_authority_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            (home / ".bashrc").write_text(
                "export ZULIP_ORG_URL=https://new.zulip.invalid\n"
                "export ZULIP_EMAIL=new@fixture.invalid\n"
                "export ZULIP_API_KEY=new-zulip-canary\n",
                encoding="utf-8",
            )
            authority = home / ".config/remote-bridge/secrets.json"
            private_file(
                authority,
                json.dumps(
                    {
                        "default_channel": "zulip",
                        "notify_channels": ["zulip"],
                        "allowed_user_ids": [],
                        "zulip": {
                            "site": "https://old.zulip.invalid",
                            "email": "old@fixture.invalid",
                            "api_key": "old-zulip-canary",
                            "control_stream": "aas-remote",
                            "topic_prefix": "job/",
                            "allowed_user_ids": [],
                        },
                    }
                ).encode()
                + b"\n",
            )
            before = authority.read_bytes()
            self.assertEqual(self.run_migration(home).returncode, 0)

            projected = self.run_materializer(home)

            self.assertEqual(projected.returncode, 2)
            self.assertEqual(authority.read_bytes(), before)
            self.assertIn(
                "ZULIP_API_KEY=new-zulip-canary",
                (home / ".secrets.env").read_text(encoding="utf-8"),
            )
            self.assertNotIn("new-zulip-canary", projected.stdout + projected.stderr)

    def test_zulip_shell_migration_preserves_existing_remote_bridge_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            (home / ".bashrc").write_text(
                "export ZULIP_ORG_URL=https://fixture.zulip.invalid\n"
                "export ZULIP_EMAIL=bot@fixture.invalid\n"
                "export ZULIP_API_KEY=zulip-canary\n",
                encoding="utf-8",
            )
            authority = home / ".config/remote-bridge/secrets.json"
            current = {
                "default_channel": "telegram",
                "notify_channels": ["telegram"],
                "allowed_user_ids": ["operator-1"],
                "telegram": {
                    "bot_token": "dedicated-telegram-canary",
                    "mode": "polling",
                    "allowed_chat_ids": ["chat-1"],
                    "allowed_user_ids": ["operator-1"],
                },
            }
            private_file(authority, json.dumps(current).encode() + b"\n")
            self.assertEqual(self.run_migration(home).returncode, 0)

            projected = self.run_materializer(home)

            self.assertEqual(projected.returncode, 0, projected.stderr)
            observed = json.loads(authority.read_text(encoding="utf-8"))
            for key, value in current.items():
                self.assertEqual(observed[key], value)
            self.assertEqual(observed["zulip"]["api_key"], "zulip-canary")
            self.assertNotEqual(
                observed["telegram"]["bot_token"], observed["zulip"]["api_key"]
            )

    def test_incomplete_or_divergent_vnu_shell_set_fails_closed(self) -> None:
        cases = (
            ("export VNU_EOFFICE_PASSWORD=missing-user-canary\n", None),
            (
                "export VNU_EOFFICE_USERNAME=new-user\n"
                "export VNU_EOFFICE_PASSWORD=new-vnu-canary\n",
                {
                    "VNU_EOFFICE_USERNAME": "old-user",
                    "VNU_EOFFICE_PASSWORD": "old-vnu-canary",
                },
            ),
        )
        for shell, current in cases:
            with self.subTest(current=current), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary) / "home"
                home.mkdir(mode=0o700)
                (home / ".bashrc").write_text(shell, encoding="utf-8")
                authority = home / ".config/vnu-eoffice/secrets.json"
                if current is not None:
                    private_file(authority, json.dumps(current).encode() + b"\n")
                before = authority.read_bytes() if authority.exists() else None
                self.assertEqual(self.run_migration(home).returncode, 0)

                projected = self.run_materializer(home)

                self.assertEqual(projected.returncode, 2)
                if before is None:
                    self.assertFalse(authority.exists())
                else:
                    self.assertEqual(authority.read_bytes(), before)
                self.assertNotIn("canary", projected.stdout + projected.stderr)

    def test_npmrc_duplicate_rejects_symlink_hardlink_and_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            authority = home / ".npmrc"
            private_file(authority, b"token=fixture\n")
            duplicate = home / ".npmrc.pre-coding-system"
            duplicate.symlink_to(authority)
            self.assertEqual(self.run_migration(home).returncode, 2)
            self.assertTrue(duplicate.is_symlink())

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            authority = home / ".npmrc"
            private_file(authority, b"token=fixture\n")
            duplicate = home / ".npmrc.pre-coding-system"
            os.link(authority, duplicate)
            self.assertEqual(self.run_migration(home).returncode, 2)
            self.assertTrue(duplicate.exists())

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            authority = home / ".npmrc"
            duplicate = home / ".npmrc.pre-coding-system"
            replacement = home / ".replacement-npmrc"
            private_file(authority, b"token=fixture\n")
            private_file(duplicate, b"token=fixture\n")
            private_file(replacement, b"token=replacement\n")
            approved = migration._preflight_npmrc_duplicate(home)
            self.assertIsNotNone(approved)
            real_stat = migration.os.stat
            swapped = False

            def replace_before_stat(path: object, *args: object, **kwargs: object):
                nonlocal swapped
                if path == ".npmrc.pre-coding-system" and not swapped:
                    swapped = True
                    os.replace(replacement, duplicate)
                return real_stat(path, *args, **kwargs)

            with mock.patch.object(migration.os, "stat", side_effect=replace_before_stat):
                with self.assertRaises(migration.MigrationError):
                    migration._retire_npmrc_duplicate(home, approved)
            self.assertEqual(duplicate.read_bytes(), b"token=replacement\n")

    def test_migrates_only_exact_owner_names_and_moltbook_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            (home / ".bashrc").write_text(
                "export TELEGRAM_CHAT_ID=12345\n"
                "export MOLTBOOK_PROFILE=quiet\n"
                "export MOLTBOOK_API_KEY=credential-canary\n",
                encoding="utf-8",
            )
            result = self.run_migration(home)
            self.assertEqual(result.returncode, 0, result.stderr)
            owner = (home / ".secrets.env").read_text(encoding="utf-8")
            self.assertIn("TELEGRAM_CHAT_ID=12345\n", owner)
            self.assertIn("MOLTBOOK_PROFILE=quiet\n", owner)
            self.assertNotIn("MOLTBOOK_API_KEY", owner)
            self.assertNotIn("export ", owner)
            self.assertEqual(
                (home / ".openclaw/moltbook.env").read_text(encoding="utf-8"),
                "# coding-system managed Moltbook gateway authority\n"
                "MOLTBOOK_API_KEY=credential-canary\n",
            )
            bashrc = (home / ".bashrc").read_text(encoding="utf-8")
            self.assertNotIn("credential-canary", bashrc)
            self.assertNotIn(".openclaw/moltbook.env", bashrc)
            self.assertIn("CSR_OWNER_SETTINGS_RC", bashrc)

    def test_legacy_shell_loaders_are_removed_outside_the_managed_block(self) -> None:
        # Owner values such as a calendar schedule contain spaces; sourcing the
        # data file as shell would run part of a value as a command.
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            (home / ".bashrc").write_text(
                "export PATH=/usr/bin:/bin\n"
                "[ -f ~/.secrets.env ] && . ~/.secrets.env\n"
                'if [ -f "$HOME/unrelated" ]; then :; fi\n'
                '[ -f "$HOME/.secrets.env" ] && . "$HOME/.secrets.env"\n'
                '[[ -f "$HOME/.secrets.env" ]] && . "$HOME/.secrets.env"\n'
                "export TELEGRAM_CHAT_ID=12345\n",
                encoding="utf-8",
            )
            result = self.run_migration(home)
            self.assertEqual(result.returncode, 0, result.stderr)
            bashrc = (home / ".bashrc").read_text(encoding="utf-8")
            self.assertNotIn(". ~/.secrets.env", bashrc)
            self.assertNotIn('. "$HOME/.secrets.env"', bashrc)
            self.assertIn("export PATH=/usr/bin:/bin\n", bashrc)
            self.assertIn('if [ -f "$HOME/unrelated" ]; then :; fi\n', bashrc)
            self.assertIn("CSR_OWNER_SETTINGS_RC", bashrc)
            self.assertEqual(self.run_migration(home).returncode, 0)
            self.assertEqual((home / ".bashrc").read_text(encoding="utf-8"), bashrc)

    def test_equal_moltbook_legacy_is_scrubbed_without_using_account_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            (home / ".bashrc").write_text("# clean\n", encoding="utf-8")
            private_file(
                home / ".secrets.env",
                b"MOLTBOOK_API_KEY=same-canary\nTELEGRAM_CHAT_ID=12345\n",
            )
            private_file(
                home / ".openclaw/moltbook.env",
                b"MOLTBOOK_API_KEY=same-canary\n",
            )
            account = home / ".config/moltbook/credentials.json"
            private_file(account, b'{"api_key":"different-account-canary"}\n')  # LEAKSCAN-EXEMPT: synthetic fixture
            result = self.run_migration(home)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(
                "MOLTBOOK_API_KEY",
                (home / ".secrets.env").read_text(encoding="utf-8"),
            )
            self.assertIn("different-account-canary", account.read_text(encoding="utf-8"))

    def test_divergent_moltbook_authority_fails_without_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            bashrc = home / ".bashrc"
            bashrc.write_text("# clean\n", encoding="utf-8")
            private_file(home / ".secrets.env", b"MOLTBOOK_API_KEY=legacy-canary\n")
            authority = home / ".openclaw/moltbook.env"
            private_file(authority, b"MOLTBOOK_API_KEY=current-canary\n")
            before = {
                "bashrc": bashrc.read_bytes(),
                "owner": (home / ".secrets.env").read_bytes(),
                "authority": authority.read_bytes(),
            }
            result = self.run_migration(home)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(bashrc.read_bytes(), before["bashrc"])
            self.assertEqual((home / ".secrets.env").read_bytes(), before["owner"])
            self.assertEqual(authority.read_bytes(), before["authority"])

    def test_hostile_or_unknown_legacy_input_is_rejected_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            marker = home / "executed"
            bashrc = home / ".bashrc"
            bashrc.write_text("# clean\n", encoding="utf-8")
            private_file(
                home / ".secrets.env",
                f"MOLTBOOK_PROFILE=$(touch {marker})\nMOLTBOOK_UNKNOWN=value\n".encode(),
            )
            result = self.run_migration(home)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(marker.exists())
            self.assertEqual(bashrc.read_text(encoding="utf-8"), "# clean\n")

    def test_unknown_command_inside_managed_block_is_not_silently_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            original = (
                "# >>> coding-system secrets >>>\n"
                "touch /tmp/must-not-run-or-delete\n"
                "# <<< coding-system secrets <<<\n"
            )
            (home / ".bashrc").write_text(original, encoding="utf-8")
            result = self.run_migration(home)
            self.assertEqual(result.returncode, 2)
            self.assertEqual((home / ".bashrc").read_text(encoding="utf-8"), original)


CAPTURE_SPEC = importlib.util.spec_from_file_location(
    "csr_owner_settings_manifest_sync", ROOT / "bin/lib/manifest_sync.py"
)
assert CAPTURE_SPEC is not None and CAPTURE_SPEC.loader is not None
capture = importlib.util.module_from_spec(CAPTURE_SPEC)
CAPTURE_SPEC.loader.exec_module(capture)


def previous_loader_block() -> list[str]:
    """The managed loader as installed before the CSR_* owner settings existed."""
    block = migration._safe_loader_block()
    case = [
        index
        for index, line in enumerate(block)
        if line.lstrip().startswith("CLASSROOM50_ORG_ALLOWLIST|")
    ]
    assert len(case) == 1
    block[case[0]] = (
        "        CLASSROOM50_ORG_ALLOWLIST|TELEGRAM_CHAT_ID|MOLBOOK_AGENT_ID|"
        "MOLTBOOK_ALLOWLIST|MOLTBOOK_AUTONOMOUS|MOLTBOOK_COLOR|MOLTBOOK_PROFILE|"
        "MOLTBOOK_URL|MOLTBOOK_WORKSPACE) ;;\n"
    )
    return block


class LoaderUpgradeTests(unittest.TestCase):
    def run_migration(self, home: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                os.fspath(ROOT / "bin/migrate-owner-settings.py"),
                "--home",
                os.fspath(home),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def migrate_text(self, text: str) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            (home / ".bashrc").write_text(text.replace("{{ HOME }}", str(home)), encoding="utf-8")
            result = self.run_migration(home)
            return result, (home / ".bashrc").read_text(encoding="utf-8")

    def test_previous_loader_is_upgraded_in_place(self) -> None:
        before = "export PATH=/usr/bin:/bin\n" + "".join(previous_loader_block())
        result, after = self.migrate_text(before + "alias ll='ls -l'\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            after,
            "export PATH=/usr/bin:/bin\n"
            + "".join(migration._safe_loader_block())
            + "alias ll='ls -l'\n",
        )

    def test_loader_shaped_block_with_an_extra_command_is_rejected(self) -> None:
        block = migration._safe_loader_block()
        block.insert(3, "touch /tmp/must-not-run-or-delete\n")
        original = "".join(block)
        result, after = self.migrate_text(original)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(after, original)

    def test_loader_with_a_changed_command_is_rejected(self) -> None:
        block = migration._safe_loader_block()
        changed = [index for index, line in enumerate(block) if "break" in line]
        self.assertEqual(len(changed), 1)
        block[changed[0]] = "        touch /tmp/must-not-run-or-delete\n"
        original = "".join(block)
        result, after = self.migrate_text(original)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(after, original)

    def test_rendered_template_migrates_twice_without_change(self) -> None:
        template = (ROOT / "system/shell/bashrc.block.sh").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            rendered = template.replace("{{ HOME }}", str(home))
            (home / ".bashrc").write_text(rendered, encoding="utf-8")
            first = self.run_migration(home)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual((home / ".bashrc").read_text(encoding="utf-8"), rendered)
            second = self.run_migration(home)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual((home / ".bashrc").read_text(encoding="utf-8"), rendered)

    def test_bashrc_without_final_newline_keeps_valid_syntax(self) -> None:
        result, after = self.migrate_text("alias ll='ls -l'")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(after.startswith("alias ll='ls -l'\n" + migration.MARK_BEGIN + "\n"))
        check = subprocess.run(["/usr/bin/bash", "-n"], input=after, text=True,
                               capture_output=True, check=False)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_other_shell_sources_of_owner_settings_are_rejected(self) -> None:
        for line in (
            "source ~/.secrets.env\n",
            '. "${HOME}/.secrets.env"\n',
            "set -a; . ~/.secrets.env; set +a\n",
            "[ -f ~/.secrets.env ] && . ~/.secrets.env  # load\n",
        ):
            with self.subTest(line=line):
                original = "export PATH=/usr/bin:/bin\n" + line
                result, after = self.migrate_text(original)
                self.assertEqual(result.returncode, 2)
                self.assertIn("secrets.env", result.stderr)
                self.assertEqual(after, original)

    def test_a_migration_that_would_break_bash_syntax_is_refused(self) -> None:
        original = "if true; then\n[ -f ~/.secrets.env ] && . ~/.secrets.env\nfi\n"
        result, after = self.migrate_text(original)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(after, original)

    def test_capture_keeps_the_markers_and_the_current_loader(self) -> None:
        errors: list[str] = []
        text = "export PATH=/usr/bin:/bin\n" + "".join(previous_loader_block())
        captured = capture.split_bashrc(text, errors)
        self.assertEqual(errors, [])
        self.assertEqual(
            captured, "export PATH=/usr/bin:/bin\n" + "".join(migration._safe_loader_block())
        )

    def test_capture_refuses_a_bashrc_that_sources_owner_settings_as_shell(self) -> None:
        errors: list[str] = []
        text = "[ -f ~/.secrets.env ] && . ~/.secrets.env\n" + "".join(
            migration._safe_loader_block()
        )
        self.assertIsNone(capture.split_bashrc(text, errors))
        self.assertTrue(any("migrate-owner-settings" in error for error in errors), errors)

    def test_template_never_sources_owner_settings_as_shell(self) -> None:
        template = (ROOT / "system/shell/bashrc.block.sh").read_text(encoding="utf-8")
        self.assertEqual(template.count(migration.MARK_BEGIN + "\n"), 1)
        before, rest = template.split(migration.MARK_BEGIN + "\n", 1)
        after = rest.split(migration.MARK_END + "\n", 1)[1]
        for line in (before + after).splitlines():
            if not line.lstrip().startswith("#"):
                self.assertNotIn(".secrets.env", line)


if __name__ == "__main__":
    unittest.main()
