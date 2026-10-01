#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/materialize-secret-projections.py"


def load_module():
    spec = importlib.util.spec_from_file_location("secret_projections", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SecretProjectionTests(unittest.TestCase):
    def test_installed_consumer_ancestors_converge_to_owner_private(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            relatives = (
                ".local/share/ai-agents-skills/runtime/workspace/research_compute",
                ".local/share/ai-agents-skills/runtime/workspace/skills/autonomous-research-loop-runtime",
                ".local/share/ai-agents-skills/runtime/workspace/skills/remote-bridge",
            )
            for relative in relatives:
                path = home / relative
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(0o775)

            module._converge_declared_private_directories(home)

            for relative in relatives:
                self.assertEqual(stat.S_IMODE((home / relative).stat().st_mode), 0o700)

    @staticmethod
    def file_delivery_authority(replay: str) -> dict[str, object]:
        return {
            "version": 1,
            "hmac_key_hex": "42" * 32,
            "allowed": {
                "signal": ["owner-device"],
                "whatsapp": ["owner-chat"],
            },
            "max_job_age_seconds": 60,
            "max_media_bytes": 4096,
            "replay_ledger_dir": replay,
            "replay_retention_seconds": 300,
            "max_replay_entries": 100,
        }

    @staticmethod
    def write_file_delivery_authority(home: Path, value: dict[str, object]) -> Path:
        authority = home / ".config/ai-agents-skills/file-delivery-queue.json"
        authority.parent.mkdir(parents=True)
        authority.write_text(json.dumps(value) + "\n", encoding="utf-8")
        authority.chmod(0o600)
        return authority

    @staticmethod
    def openclaw_file_delivery_policy(
        *, telegram: list[str] | None = None
    ) -> dict[str, object]:
        return {
            "schema": "openclaw.file-delivery-policy/v1",
            "delivery_policy": {
                "allowed_targets": {
                    "telegram": telegram or [],
                    "zulip": [],
                    "googlechat": [],
                    "whatsapp": [],
                    "zalo": [],
                }
            },
        }

    @staticmethod
    def write_openclaw_json(home: Path, relative: str, value: dict[str, object]) -> Path:
        path = home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_legacy_tailscale_env_is_bounded_and_migrated_to_raw_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            legacy = home / ".config/coding-system/tailscale.env"
            legacy.parent.mkdir(parents=True)
            legacy.write_text(
                "TS_AUTHKEY=tskey-auth-abcdefghijklmnopqrstuvwx\n"
                "TS_HOSTNAME=openclaw\n",
                encoding="utf-8",
            )
            legacy.chmod(0o600)
            result = self.run_projection(home)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(legacy.exists())
            self.assertEqual(
                (home / ".config/coding-system/tailscale-authkey").read_text(),
                "tskey-auth-abcdefghijklmnopqrstuvwx\n",
            )
            self.assertEqual(
                (home / ".config/coding-system/tailscale-hostname").read_text(),
                "openclaw\n",
            )
            self.assertNotIn(
                "tskey-auth-abcdefghijklmnopqrstuvwx",
                result.stdout + result.stderr,
            )

    def test_legacy_tailscale_conflict_or_shell_syntax_fails_without_scrub(self) -> None:
        cases = (
            (
                "TS_AUTHKEY=tskey-auth-abcdefghijklmnopqrstuvwx\n"
                "TS_HOSTNAME=$(touch {MARKER})\n",
                None,
            ),
            (
                "TS_AUTHKEY=tskey-auth-abcdefghijklmnopqrstuvwx\n"
                "TS_HOSTNAME=openclaw\n",
                "tskey-auth-zyxwvutsrqponmlkjihgfedc\n",
            ),
        )
        for legacy_text, current in cases:
            with self.subTest(current=current), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                legacy = home / ".config/coding-system/tailscale.env"
                legacy.parent.mkdir(parents=True)
                marker = home / "must-not-run"
                rendered_legacy = legacy_text.replace("{MARKER}", os.fspath(marker))
                legacy.write_text(rendered_legacy, encoding="utf-8")
                legacy.chmod(0o600)
                if current is not None:
                    authority = home / ".config/coding-system/tailscale-authkey"
                    authority.write_text(current, encoding="utf-8")
                    authority.chmod(0o600)
                result = self.run_projection(home)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(legacy.read_text(encoding="utf-8"), rendered_legacy)
                self.assertFalse(marker.exists())

    def test_file_delivery_legacy_default_migrates_without_changing_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            old_replay = home / ".local/state/ai-agents-skills/file-delivery-replay"
            expected = self.file_delivery_authority(str(old_replay))
            authority = self.write_file_delivery_authority(home, expected)

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads(authority.read_text(encoding="utf-8"))
            self.assertEqual(
                observed["replay_ledger_dir"],
                "aas-host-state:file-delivery-replay",
            )
            for key in set(expected) - {"replay_ledger_dir"}:
                self.assertEqual(observed[key], expected[key])
            self.assertEqual(authority.stat().st_mode & 0o777, 0o600)
            self.assertTrue(old_replay.is_dir())
            self.assertEqual(old_replay.stat().st_mode & 0o777, 0o700)
            self.assertNotIn("42" * 32, result.stdout + result.stderr)

    def test_file_delivery_token_survives_cross_home_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_home = root / "source-home"
            restored_home = root / "restored-home"
            source_home.mkdir(mode=0o700)
            restored_home.mkdir(mode=0o700)
            source_authority = self.write_file_delivery_authority(
                source_home,
                self.file_delivery_authority(
                    str(
                        source_home
                        / ".local/state/ai-agents-skills/file-delivery-replay"
                    )
                ),
            )
            first = self.run_projection(source_home)
            self.assertEqual(first.returncode, 0, first.stderr)

            restored_authority = self.write_file_delivery_authority(
                restored_home,
                json.loads(source_authority.read_text(encoding="utf-8")),
            )
            second = self.run_projection(restored_home)

            self.assertEqual(second.returncode, 0, second.stderr)
            restored = json.loads(restored_authority.read_text(encoding="utf-8"))
            self.assertEqual(
                restored["replay_ledger_dir"],
                "aas-host-state:file-delivery-replay",
            )
            self.assertNotIn(str(source_home), restored_authority.read_text())
            restored_replay = (
                restored_home
                / ".local/state/ai-agents-skills/file-delivery-replay"
            )
            self.assertTrue(restored_replay.is_dir())
            self.assertEqual(restored_replay.stat().st_mode & 0o777, 0o700)

    def test_file_delivery_rejects_arbitrary_legacy_replay_paths_transactionally(self) -> None:
        for replay in (
            "/tmp/custom-file-delivery-replay",
            "relative/file-delivery-replay",
            "aas-host-state:other",
        ):
            with self.subTest(replay=replay), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                authority = self.write_file_delivery_authority(
                    home, self.file_delivery_authority(replay)
                )
                before = authority.read_bytes()

                result = self.run_projection(home)

                self.assertEqual(result.returncode, 2)
                self.assertEqual(authority.read_bytes(), before)
                self.assertIn("replay ledger is invalid", result.stderr)
                self.assertNotIn("42" * 32, result.stdout + result.stderr)

    def test_file_delivery_replay_bounds_are_exact(self) -> None:
        mutations = (
            ("retention-too-short", {"replay_retention_seconds": 119}),
            ("retention-too-long", {"replay_retention_seconds": 604_801}),
            ("retention-bool", {"replay_retention_seconds": True}),
            ("entries-too-low", {"max_replay_entries": 99}),
            ("entries-too-high", {"max_replay_entries": 100_001}),
            ("entries-bool", {"max_replay_entries": True}),
        )
        for label, changed in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                value = self.file_delivery_authority(
                    "aas-host-state:file-delivery-replay"
                )
                value.update(changed)
                authority = self.write_file_delivery_authority(home, value)
                before = authority.read_bytes()

                result = self.run_projection(home)

                self.assertEqual(result.returncode, 2)
                self.assertEqual(authority.read_bytes(), before)

    def test_file_delivery_legacy_restore_rejects_divergent_destination(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            recovery = root / "recovery"
            virtual = root / "virtual"
            output = root / "output"
            for directory in (home, recovery, virtual, output):
                directory.mkdir(mode=0o700)

            current = self.file_delivery_authority(
                "aas-host-state:file-delivery-replay"
            )
            self.write_file_delivery_authority(home, current)
            restored = self.file_delivery_authority(
                "/old-owner/.local/state/ai-agents-skills/file-delivery-replay"
            )
            restored["hmac_key_hex"] = "31" * 32
            self.write_file_delivery_authority(recovery, restored)
            inputs, mutations = module.transaction_file_contract(home)
            module.snapshot_transaction_inputs(home, virtual, inputs)
            recovery_modes = {
                ".config/ai-agents-skills/file-delivery-queue.json": 0o600
            }
            module.overlay_transaction_stage(virtual, recovery, recovery_modes)
            module.materialize(
                virtual,
                migrate_vnu_legacy=False,
                migrate_remote_bridge_legacy=False,
                migrate_aas_legacy=False,
            )
            final_contract = dict(mutations)
            final_contract.update(recovery_modes)
            final_modes = module.export_transaction_files(
                virtual, output, final_contract
            )
            replace_paths = frozenset(set(mutations) - set(recovery_modes))

            with self.assertRaises(module.RestoreTransactionError):
                module.transactional_apply(
                    output,
                    home,
                    final_modes,
                    replace=False,
                    replace_paths=replace_paths,
                )
            observed = json.loads(
                (
                    home
                    / ".config/ai-agents-skills/file-delivery-queue.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(observed["hmac_key_hex"], "42" * 32)

    def test_file_delivery_absence_creates_only_private_continuity_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(
                (home / ".config/ai-agents-skills/file-delivery-queue.json").exists()
            )
            ledger = home / ".local/state/ai-agents-skills/file-delivery-replay"
            self.assertTrue(ledger.is_dir())
            self.assertEqual(ledger.stat().st_mode & 0o777, 0o700)

    def test_aas_queue_authority_is_never_mirrored_to_openclaw_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.write_file_delivery_authority(
                home,
                self.file_delivery_authority(
                    "aas-host-state:file-delivery-replay"
                ),
            )
            shared = home / ".config/ai-agents-skills/secrets.json"
            shared.write_text(
                json.dumps({"TELEGRAM_BOT_TOKEN": "telegram-only-canary"}) + "\n",
                encoding="utf-8",
            )
            shared.chmod(0o600)

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            openclaw = (
                home / ".openclaw/workspace/.config/file-delivery/secrets.json"
            )
            self.assertFalse(openclaw.exists())
            self.assertFalse(
                (home / ".openclaw/file-delivery-policy.json").exists()
            )
            self.assertNotIn(
                "telegram-only-canary", result.stdout + result.stderr
            )

    def test_openclaw_canonical_policy_is_preserved_and_legacy_projection_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            canonical = self.write_openclaw_json(
                home,
                ".openclaw/file-delivery-policy.json",
                self.openclaw_file_delivery_policy(),
            )
            canonical_before = canonical.read_bytes()
            legacy = self.openclaw_file_delivery_policy(
                telegram=["legacy-must-not-win"]
            )
            legacy["TELEGRAM_BOT_TOKEN"] = "legacy-token-must-not-win"
            self.write_openclaw_json(
                home,
                ".openclaw/workspace/.config/file-delivery/secrets.json",
                legacy,
            )
            self.write_openclaw_json(
                home,
                ".openclaw/secrets.json",
                {
                    "TELEGRAM_BOT_TOKEN": "host-token-canary",
                    "TELEGRAM_CHAT_ID": "host-chat-must-not-override",
                },
            )

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(canonical.read_bytes(), canonical_before)
            self.assertFalse(
                (
                    home
                    / ".openclaw/workspace/.config/file-delivery/secrets.json"
                ).exists()
            )
            self.assertEqual(canonical.stat().st_mode & 0o777, 0o600)

    def test_openclaw_legacy_projection_is_retired_without_creating_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.write_openclaw_json(
                home,
                ".openclaw/workspace/.config/file-delivery/secrets.json",
                {
                    "schema": "openclaw.file-delivery-policy/v1",
                    "TELEGRAM_BOT_TOKEN": "derived-token-is-not-authority",
                    "delivery_policy": {
                        "allowed_targets": {"zulip": ["Research:papers"]}
                    },
                },
            )
            self.write_openclaw_json(
                home,
                ".openclaw/secrets.json",
                {"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""},
            )

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            authority_path = home / ".openclaw/file-delivery-policy.json"
            self.assertFalse(authority_path.exists())
            self.assertFalse(
                (
                    home
                    / ".openclaw/workspace/.config/file-delivery/secrets.json"
                ).exists()
            )
            self.assertNotIn("derived-token-is-not-authority", result.stdout + result.stderr)

    def test_openclaw_chat_identity_does_not_create_recipient_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.write_openclaw_json(
                home,
                ".openclaw/secrets.json",
                {
                    "TELEGRAM_BOT_TOKEN": "host-token-canary",
                    "TELEGRAM_CHAT_ID": "approved-chat",
                    "ZULIP_API_KEY": "must-not-authorize",
                    "conversation_id": "must-not-authorize",
                },
            )

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(
                (home / ".openclaw/file-delivery-policy.json").exists()
            )
            self.assertFalse(
                (
                    home
                    / ".openclaw/workspace/.config/file-delivery/secrets.json"
                ).exists()
            )
            self.assertNotIn("host-token-canary", result.stdout + result.stderr)

    def test_openclaw_credentials_without_policy_do_not_authorize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            projection = self.write_openclaw_json(
                home,
                ".openclaw/workspace/.config/file-delivery/secrets.json",
                {"TELEGRAM_BOT_TOKEN": "historical-derived-token"},
            )
            self.write_openclaw_json(
                home,
                ".openclaw/secrets.json",
                {
                    "TELEGRAM_BOT_TOKEN": "host-token-alone",
                    "TELEGRAM_CHAT_ID": "",
                    "ZULIP_API_KEY": "zulip-identity-is-not-a-target",
                },
            )

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(projection.exists())
            self.assertFalse(
                (home / ".openclaw/file-delivery-policy.json").exists()
            )
            self.assertNotIn("host-token-alone", result.stdout + result.stderr)

    def test_openclaw_malformed_retired_projection_is_removed_without_migration(self) -> None:
        cases = {
            "unknown-field": {
                **self.openclaw_file_delivery_policy(),
                "ZULIP_API_KEY": "must-not-cross",
            },
            "unknown-channel": {
                "schema": "openclaw.file-delivery-policy/v1",
                "delivery_policy": {
                    "allowed_targets": {"matrix": ["room"]}
                },
            },
            "duplicate-target": self.openclaw_file_delivery_policy(
                telegram=["same-chat", "same-chat"]
            ),
            "empty-token": {
                **self.openclaw_file_delivery_policy(),
                "TELEGRAM_BOT_TOKEN": "",
            },
        }
        for label, candidate in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                projection = self.write_openclaw_json(
                    home,
                    ".openclaw/workspace/.config/file-delivery/secrets.json",
                    candidate,
                )

                result = self.run_projection(home)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(projection.exists())
                self.assertFalse(
                    (home / ".openclaw/file-delivery-policy.json").exists()
                )
                self.assertNotIn("must-not-cross", result.stdout + result.stderr)

    def test_openclaw_malformed_host_policy_fails_without_retiring_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            authority = self.write_openclaw_json(
                home,
                ".openclaw/file-delivery-policy.json",
                {
                    "schema": "openclaw.file-delivery-policy/v1",
                    "delivery_policy": {
                        "allowed_targets": {"matrix": ["must-not-cross"]}
                    },
                },
            )
            projection = self.write_openclaw_json(
                home,
                ".openclaw/workspace/.config/file-delivery/secrets.json",
                {"TELEGRAM_BOT_TOKEN": "legacy-canary"},
            )
            authority_before = authority.read_bytes()
            projection_before = projection.read_bytes()

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 2)
            self.assertEqual(authority.read_bytes(), authority_before)
            self.assertEqual(projection.read_bytes(), projection_before)
            self.assertNotIn("must-not-cross", result.stdout + result.stderr)
            self.assertNotIn("legacy-canary", result.stdout + result.stderr)

    def test_openclaw_policy_paths_are_bounded_transaction_files(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            inputs, mutations = module.transaction_file_contract(home)
            authority = ".openclaw/file-delivery-policy.json"
            retired = ".openclaw/workspace/.config/file-delivery/secrets.json"
            self.assertEqual(inputs[authority], 0o600)
            self.assertNotIn(authority, mutations)
            self.assertEqual(inputs[retired], 0o600)
            self.assertEqual(mutations[retired], 0o600)

    def test_host_queue_selectors_are_fixed_and_not_ambient(self) -> None:
        # The shell block is captured from the running host.  It may leave the
        # selector out (the queue is then simply not configured), but it never
        # points it anywhere except the fixed authority.
        shell = (ROOT / "system/shell/bashrc.block.sh").read_text(encoding="utf-8")
        fixed = 'export AAS_FILE_DELIVERY_SECRETS_FILE="$HOME/.config/ai-agents-skills/file-delivery-queue.json"'
        mentions = [
            line.strip() for line in shell.splitlines() if "AAS_FILE_DELIVERY_SECRETS_FILE" in line
        ]
        self.assertTrue(all(line == fixed for line in mentions), mentions)
        # A restore completes the Codex selectors through the phase-6 migration.
        spec = importlib.util.spec_from_file_location(
            "migrate_codex_config_for_queue", ROOT / "bin/migrate-codex-config.py"
        )
        assert spec is not None and spec.loader is not None
        migrate_codex = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migrate_codex)
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".codex").mkdir(mode=0o700)
            rendered = home / ".codex/config.toml"
            rendered.write_text(
                (ROOT / "agents/codex/config.toml.template")
                .read_text(encoding="utf-8")
                .replace("{{ HOME }}", str(home)),
                encoding="utf-8",
            )
            rendered.chmod(0o600)
            migrate_codex.migrate(rendered, home)
            codex = tomllib.loads(rendered.read_text(encoding="utf-8"))["shell_environment_policy"]
        self.assertIn("AAS_FILE_DELIVERY_SECRETS_FILE", codex["exclude"])
        self.assertEqual(
            codex["set"]["AAS_FILE_DELIVERY_SECRETS_FILE"],
            f"{home}/.config/ai-agents-skills/file-delivery-queue.json",
        )

    def setUp(self) -> None:
        self.previous_umask = os.umask(0o077)

    def tearDown(self) -> None:
        os.umask(self.previous_umask)

    def run_projection(self, home: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SCRIPT), "--home", str(home), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_opencode_sqlite_family_converges_to_owner_only_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            directory = home / ".local/share/opencode"
            directory.mkdir(parents=True)
            database = directory / "opencode.db"
            for suffix in ("", "-wal", "-shm", "-journal"):
                path = Path(os.fspath(database) + suffix)
                path.write_bytes(b"synthetic-sqlite-family-canary")
                path.chmod(0o644)
            directory.chmod(0o755)

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            for suffix in ("", "-wal", "-shm", "-journal"):
                path = Path(os.fspath(database) + suffix)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(
                "synthetic-sqlite-family-canary", result.stdout + result.stderr
            )

    def test_getscipapers_runtime_files_converge_to_owner_only_permissions(self) -> None:
        relatives = ("nexus/proxy.json", "getpapers/unpywall_cache")
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            for relative, payload in zip(
                relatives, ('{"type":"socks5"}\n', "synthetic-unpywall-canary\n")
            ):
                authority = home / ".config/getscipapers" / relative
                authority.parent.mkdir(parents=True, exist_ok=True)
                authority.write_text(payload, encoding="utf-8")
                authority.chmod(0o664)

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            for relative in relatives:
                authority = home / ".config/getscipapers" / relative
                projection = (
                    home / ".openclaw/workspace/.config/getscipapers" / relative
                )
                self.assertEqual(stat.S_IMODE(authority.stat().st_mode), 0o600)
                self.assertEqual(projection.read_bytes(), authority.read_bytes())
                self.assertEqual(stat.S_IMODE(projection.stat().st_mode), 0o600)
            self.assertNotIn(
                "synthetic-unpywall-canary", result.stdout + result.stderr
            )

    def test_opencode_sqlite_convergence_rejects_links_and_special_files(self) -> None:
        cases = ("directory-symlink", "database-symlink", "hardlink", "fifo")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home = root / "home"
                home.mkdir(mode=0o700)
                directory = home / ".local/share/opencode"
                outside = root / "outside"
                outside.mkdir(mode=0o700)
                victim = outside / "victim.sqlite"
                victim.write_bytes(b"outside-sqlite-canary")
                victim.chmod(0o600)
                if case == "directory-symlink":
                    directory.parent.mkdir(parents=True)
                    directory.symlink_to(outside, target_is_directory=True)
                else:
                    directory.mkdir(parents=True)
                    database = directory / "opencode.db"
                    if case == "database-symlink":
                        database.symlink_to(victim)
                    elif case == "hardlink":
                        os.link(victim, database)
                    else:
                        os.mkfifo(database, 0o600)

                result = subprocess.run(
                    ["python3", str(SCRIPT), "--home", str(home)],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5,
                )

                self.assertEqual(result.returncode, 2)
                self.assertEqual(victim.read_bytes(), b"outside-sqlite-canary")
                self.assertNotIn("outside-sqlite-canary", result.stdout + result.stderr)

    def test_every_manifest_projection_has_explicit_materializer(self) -> None:
        module = load_module()
        manifest = yaml.safe_load((ROOT / "secrets/secrets-manifest.yaml").read_text())
        projection_ids = {
            entry["id"]
            for entry in manifest["entries"]
            if entry.get("classification", manifest["entry_defaults"]["classification"])
            == "projection"
        }
        self.assertEqual(projection_ids, module.SUPPORTED_PROJECTION_IDS)

    def test_authorities_converge_and_stale_projections_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".config/ai-agents-skills").mkdir(parents=True)
            (home / ".config/ai-agents-skills/secrets.json").write_text(
                '{"ZOTERO_API_KEY":"fixture-zotero"}\n'
            )
            (home / ".config/send-email").mkdir(parents=True)
            (home / ".config/send-email/secrets.json").write_text(
                '{"accounts":{"fixture":{"host":"example"}},"default_account":"fixture"}\n'
            )
            (home / ".config/gh").mkdir(parents=True)
            (home / ".config/gh/hosts.yml").write_text(
                "github.com:\n  oauth_token: fixture-token\n", encoding="utf-8"
            )
            (home / ".config/gh/config.yml").write_text(
                "git_protocol: ssh\n", encoding="utf-8"
            )
            (home / ".openclaw").mkdir()
            (home / ".openclaw/secrets.json").write_text('{"TOKEN":"redacted-fixture"}\n')
            (home / ".openclaw/workspace").mkdir()
            (home / ".openclaw/workspace/.secrets.json").write_text(
                '{"TOKEN":"stale-broad-projection"}\n'  # LEAKSCAN-EXEMPT: synthetic fixture
            )
            (home / ".modal.toml").write_text('[profile]\ntoken_id="fixture"\n')
            research = home / ".local/share/ai-agents-skills/runtime/workspace/config/research-compute.toml"
            research.parent.mkdir(parents=True)
            research.write_text(
                'install_id = "fixture"\n'
                'broker_state_root = "../../private-state"\n'
                '[gha]\nenabled = false\n',
                encoding="utf-8",
            )
            research.chmod(0o644)
            (home / ".config/getscipapers/ablesci").mkdir(parents=True)
            (home / ".config/getscipapers/ablesci/credentials.json").write_text('{"key":"fixture"}\n')
            (home / ".openclaw/workspace/secrets/getscipapers/nexus").mkdir(
                parents=True
            )
            (home / ".openclaw/workspace/secrets/getscipapers/nexus/credentials.json").write_text(
                '{"token":"legacy-fixture"}\n', encoding="utf-8"
            )
            (home / ".openclaw/workspace/.config/getscipapers/wosonhj").mkdir(parents=True)
            (home / ".openclaw/workspace/.config/getscipapers/wosonhj/credentials.json").write_text('{}\n')
            (home / ".openclaw/secrets.json.bak.old").write_text('{}\n')
            (home / ".openclaw/agents/main/agent").mkdir(parents=True)
            (home / ".openclaw/agents/main/agent/auth-profiles.json.bak").write_text('{}\n')

            result = self.run_projection(home)
            self.assertEqual(result.returncode, 0, result.stderr)
            source = (home / ".config/ai-agents-skills/secrets.json").read_bytes()
            for relative in (
                ".codex/runtime/workspace/.secrets.json",
                ".local/share/ai-agents-skills/runtime/workspace/.secrets.json",
            ):
                target = home / relative
                self.assertEqual(target.read_bytes(), source)
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertFalse(
                (
                    home
                    / ".openclaw/workspace/.config/ai-agents-skills/secrets.json"
                ).exists()
            )
            self.assertFalse(
                (home / ".openclaw/workspace/.config/send-email/secrets.json").exists()
            )
            self.assertFalse((home / ".openclaw/workspace/.secrets.json").exists())
            for name in ("hosts.yml", "config.yml"):
                authority = home / ".config/gh" / name
                projection = home / ".openclaw/workspace/.config/gh" / name
                self.assertEqual(projection.read_bytes(), authority.read_bytes())
                self.assertEqual(projection.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("fixture-token", result.stdout + result.stderr)
            research_projection = home / ".openclaw/workspace/config/research-compute.toml"
            self.assertIn(
                'broker_state_root = "data/research/research-compute"',
                research_projection.read_text(encoding="utf-8"),
            )
            self.assertNotIn("../../private-state", research_projection.read_text(encoding="utf-8"))
            self.assertEqual(research_projection.stat().st_mode & 0o777, 0o600)
            self.assertFalse(
                (home / ".openclaw/workspace/.config/getscipapers/wosonhj/credentials.json").exists()
            )
            self.assertTrue(
                (home / ".openclaw/workspace/.config/getscipapers/ablesci/credentials.json").is_file()
            )
            self.assertEqual(
                (home / ".config/getscipapers/nexus/credentials.json").read_text(
                    encoding="utf-8"
                ),
                '{"token":"legacy-fixture"}\n',
            )
            self.assertEqual(
                (
                    home
                    / ".openclaw/workspace/.config/getscipapers/nexus/credentials.json"
                ).read_text(encoding="utf-8"),
                '{"token":"legacy-fixture"}\n',
            )
            self.assertFalse(
                (home / ".openclaw/workspace/secrets/getscipapers").exists()
            )
            self.assertFalse((home / ".openclaw/secrets.json.bak.old").exists())
            self.assertFalse(
                (home / ".openclaw/agents/main/agent/auth-profiles.json.bak").exists()
            )

    def test_declared_group_writable_projection_parents_converge_privately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            authority = home / ".config/ai-agents-skills/providers/copilot.env"
            authority.parent.mkdir(parents=True)
            authority.write_text("GH_TOKEN=fixture-token\n", encoding="utf-8")
            authority.chmod(0o600)
            (home / ".config").chmod(0o775)
            (home / ".config/ai-agents-skills").chmod(0o775)
            authority.parent.chmod(0o775)

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            for directory in (
                home / ".config",
                home / ".config/ai-agents-skills",
                authority.parent,
                home / ".openclaw",
                home / ".openclaw/workspace",
                home / ".openclaw/workspace/.config/ai-agents-skills/providers",
            ):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            projection = (
                home
                / ".openclaw/workspace/.config/ai-agents-skills/providers/copilot.env"
            )
            self.assertEqual(projection.read_bytes(), authority.read_bytes())

    def test_host_openclaw_skill_and_delivery_projections_are_exact_subsets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            shared = home / ".config/ai-agents-skills/secrets.json"
            shared.parent.mkdir(parents=True)
            shared.write_text(
                json.dumps(
                    {
                        "GDRIVE_CREDENTIALS": "drive-canary",
                        "TELEGRAM_BOT_TOKEN": "telegram-canary",
                        "WEBDAV_PASSWORD": "webdav-canary",
                        "ZOTERO_API_KEY": "zotero-canary",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            shared.chmod(0o600)
            skill = home / ".config/ai-agents-skills/skill.env"
            skill.write_text(
                "AXLE_API_KEY=axle-canary\n"
                "LEANEXPLORE_API_KEY=lean-canary\n"
                "OPENCLAW_S2_API_KEY=digest-canary\n"
                "ZENODO_TOKEN=unrelated-canary\n"
                "SEMANTIC_SCHOLAR_API_KEY=s2-canary\n"
                "UNPAYWALL_EMAIL=operator@example.invalid\n",
                encoding="utf-8",
            )
            skill.chmod(0o600)
            stale_broad = (
                home
                / ".openclaw/workspace/.config/ai-agents-skills/skill.env"
            )
            stale_broad.parent.mkdir(parents=True)
            stale_broad.write_text("ZENODO_TOKEN=stale-canary\n", encoding="utf-8")
            stale_broad.chmod(0o600)
            policy = self.openclaw_file_delivery_policy(
                telegram=["approved-chat"]
            )
            self.write_openclaw_json(
                home, ".openclaw/file-delivery-policy.json", policy
            )
            self.write_openclaw_json(
                home,
                ".openclaw/secrets.json",
                {"TELEGRAM_BOT_TOKEN": "host-telegram-canary"},
            )

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(stale_broad.exists())
            root = home / ".openclaw/workspace/.config/ai-agents-skills"
            expected_env = {
                "axiom-axle.env": {"AXLE_API_KEY": "axle-canary"},
                "lean-explore.env": {"LEANEXPLORE_API_KEY": "lean-canary"},
                "research-digest.env": {"OPENCLAW_S2_API_KEY": "digest-canary"},
                "submission-venue.env": {
                    "SEMANTIC_SCHOLAR_API_KEY": "s2-canary",
                    "UNPAYWALL_EMAIL": "operator@example.invalid",
                },
            }
            for name, expected in expected_env.items():
                projection = root / name
                observed = {
                    key: value
                    for line in projection.read_text(encoding="utf-8").splitlines()
                    if line and not line.startswith("#")
                    for key, value in (line.split("=", 1),)
                }
                self.assertEqual(observed, expected)
                self.assertEqual(projection.stat().st_mode & 0o777, 0o600)
            expected_zotero = {
                "GDRIVE_CREDENTIALS": "drive-canary",
                "SEMANTIC_SCHOLAR_API_KEY": "s2-canary",
                "WEBDAV_PASSWORD": "webdav-canary",
                "ZOTERO_API_KEY": "zotero-canary",
            }
            for projection in (
                home / ".config/ai-agents-skills/zotero-secrets.json",
                root / "zotero-secrets.json",
            ):
                self.assertEqual(
                    json.loads(projection.read_text(encoding="utf-8")),
                    expected_zotero,
                )
                self.assertEqual(projection.stat().st_mode & 0o777, 0o600)
            delivery = (
                home / ".openclaw/workspace/.config/file-delivery/secrets.json"
            )
            self.assertFalse(delivery.exists())
            self.assertEqual(
                json.loads(
                    (home / ".openclaw/file-delivery-policy.json").read_text(
                        encoding="utf-8"
                    )
                ),
                policy,
            )
            self.assertNotIn("unrelated-canary", result.stdout + result.stderr)

    def test_vnu_legacy_values_become_authority_then_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".claude").mkdir()
            (home / ".claude/secrets.json").write_text(
                json.dumps(
                    {
                        "VNU_EOFFICE_USERNAME": "fixture-user",
                        "UNRELATED": "must-not-project",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (home / ".openclaw").mkdir()
            (home / ".openclaw/secrets.json").write_text(
                json.dumps(
                    {
                        "VNU_EOFFICE_PASSWORD": "fixture-password",
                        "VNU_STATE_HMAC_KEY": "fixture-hmac",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = self.run_projection(home, "--migrate-vnu-legacy")
            self.assertEqual(result.returncode, 0, result.stderr)
            authority = json.loads((home / ".config/vnu-eoffice/secrets.json").read_text())
            projection = json.loads(
                (home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json").read_text()
            )
            self.assertEqual(
                set(authority),
                {
                    "VNU_EOFFICE_USERNAME",
                    "VNU_EOFFICE_PASSWORD",
                    "VNU_STATE_HMAC_KEY",
                },
            )
            self.assertEqual(projection, authority)

    def test_legacy_zulip_values_become_dedicated_remote_bridge_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".claude").mkdir()
            (home / ".claude/secrets.json").write_text(
                json.dumps(
                    {
                        "TELEGRAM_BOT_TOKEN": "legacy-shared-token-must-not-migrate",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (home / ".openclaw").mkdir()
            (home / ".openclaw/secrets.json").write_text(
                json.dumps(
                    {
                        "ZULIP_ORG_URL": "https://fixture.zulip.invalid",
                        "ZULIP_EMAIL": "bot@fixture.invalid",
                        "ZULIP_API_KEY": "fixture-zulip-key",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = self.run_projection(home, "--migrate-remote-bridge-legacy")
            self.assertEqual(result.returncode, 0, result.stderr)
            authority_path = home / ".config/remote-bridge/secrets.json"
            authority = json.loads(authority_path.read_text(encoding="utf-8"))
            self.assertEqual(authority["notify_channels"], ["zulip"])
            self.assertEqual(
                set(authority["zulip"]),
                {
                    "site",
                    "email",
                    "api_key",
                    "control_stream",
                    "topic_prefix",
                    "allowed_user_ids",
                },
            )
            self.assertNotIn("telegram", authority)
            self.assertNotIn("legacy-shared-token-must-not-migrate", result.stdout + result.stderr)
            self.assertEqual(authority_path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(
                (
                    home
                    / ".openclaw/workspace/.config/remote-bridge/secrets.json"
                ).exists()
            )

            remote_path = (
                Path.home()
                / "ai-agents-skills/canonical/runtime/skills"
                / "remote-bridge/remote_bridge.py"
            )
            if remote_path.is_file():
                spec = importlib.util.spec_from_file_location(
                    "csr_remote_bridge_projection_test", remote_path
                )
                assert spec is not None and spec.loader is not None
                remote = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = remote
                previous_dont_write_bytecode = sys.dont_write_bytecode
                sys.dont_write_bytecode = True
                try:
                    spec.loader.exec_module(remote)
                    config = remote.build_config(
                        str(authority_path), environ={"HOME": str(home)}
                    )
                finally:
                    sys.dont_write_bytecode = previous_dont_write_bytecode
                    sys.modules.pop(spec.name, None)
                self.assertEqual(config.notify_channels, ["zulip"])
                self.assertEqual(config.allowed_user_ids, [])
                self.assertEqual(config.zulip["allowed_user_ids"], [])
                self.assertEqual(config.secrets_path, str(authority_path))

    def test_aas_legacy_credentials_configs_and_compute_are_promoted_and_projected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".claude/skills/zotero").mkdir(parents=True)
            (home / ".claude/skills/calibre").mkdir(parents=True)
            (home / ".claude/skills/zotero/config.json").write_text(
                '{"library_id":"fixture","semantic_scholar_api_key":"fixture-s2-secret"}\n',
                encoding="utf-8",
            )
            (home / ".claude/skills/calibre/config.json").write_text(
                '{"folder_id":"fixture"}\n', encoding="utf-8"
            )
            (home / ".claude/skills/zotero/config.json").chmod(0o644)
            (home / ".claude/skills/calibre/config.json").chmod(0o644)
            (home / ".config/send-email").mkdir(parents=True)
            (home / ".config/send-email/secrets.json").write_text(
                '{"accounts":{"fixture":{"host":"smtp.invalid","user":"fixture-user",'
                '"password":"fixture-mail","from":"fixture@example.invalid"}},'
                '"default_account":"fixture"}\n',
                encoding="utf-8",
            )
            (home / ".config/course/google-classroom").mkdir(parents=True)
            (home / ".config/course/google-classroom/credentials.json").write_text(
                '{"installed":{"client_id":"fixture"}}\n', encoding="utf-8"
            )
            (home / ".config/course/demo101").mkdir(parents=True)
            (home / ".config/course/demo101/config.json").write_text(
                json.dumps(
                    {
                        "CANVAS_LMS_API_URL": "https://canvas.example.invalid",
                        "CANVAS_LMS_API_KEY": "fixture-canvas-secret",
                        "CANVAS_LMS_COURSE_ID": "fixture-course",
                        "UNRELATED_COURSE_SETTING": "must-not-project",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (home / ".claude/secrets.json").write_text(
                json.dumps(
                    {
                        "ZOTERO_API_KEY": "fixture-zotero",
                        "WEBDAV_PASSWORD": "fixture-webdav",
                        "TELEGRAM_BOT_TOKEN": "fixture-delivery",
                        "GH_TOKEN": "fixture-provider",
                        "VNU_EOFFICE_PASSWORD": "must-not-enter-aas",
                        "ZULIP_API_KEY": "must-remain-remote-bridge-only",
                        "UNRELATED": "must-not-migrate",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (home / ".openclaw").mkdir(parents=True)
            (home / ".openclaw/secrets.json").write_text(
                json.dumps(
                    {
                        "GDRIVE_CREDENTIALS": "fixture-drive",
                        "HCLOUD_TOKEN": "fixture-hetzner",
                        "KIMI_API_KEY": "fixture-kimi",
                        "LEANEXPLORE_API_KEY": "fixture-lean",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (home / ".secrets.env").write_text(
                "# retained owner settings\n"
                "CLASSROOM50_ORG_ALLOWLIST=fixture-org\n"
                "KAGGLE_API_TOKEN=fixture-kaggle\n"
                "OCRSPACE_API_KEY=fixture-ocr\n",
                encoding="utf-8",
            )

            result = self.run_projection(home, "--migrate-aas-legacy")
            self.assertEqual(result.returncode, 0, result.stderr)
            authority_path = home / ".config/ai-agents-skills/secrets.json"
            authority = json.loads(authority_path.read_text(encoding="utf-8"))
            self.assertEqual(
                set(authority),
                {
                    "ZOTERO_API_KEY",
                    "WEBDAV_PASSWORD",
                    "GDRIVE_CREDENTIALS",
                    "TELEGRAM_BOT_TOKEN",
                },
            )
            self.assertFalse(
                {"HCLOUD_TOKEN", "KAGGLE_API_TOKEN", "VNU_EOFFICE_PASSWORD", "ZULIP_API_KEY", "UNRELATED"}
                & set(authority)
            )
            compute_text = (home / ".config/ai-agents-skills/compute.env").read_text()
            self.assertIn("HCLOUD_TOKEN=", compute_text)
            self.assertIn("KAGGLE_API_TOKEN=", compute_text)
            self.assertIn(
                "LEANEXPLORE_API_KEY=",
                (home / ".config/ai-agents-skills/skill.env").read_text(),
            )
            self.assertIn(
                "OCRSPACE_API_KEY=",
                (home / ".config/ai-agents-skills/skill.env").read_text(),
            )
            self.assertIn(
                "SEMANTIC_SCHOLAR_API_KEY=",
                (home / ".config/ai-agents-skills/skill.env").read_text(),
            )
            self.assertIn(
                "GH_TOKEN=",
                (
                    home / ".config/ai-agents-skills/providers/copilot.env"
                ).read_text(),
            )
            self.assertIn(
                "KIMI_API_KEY=",
                (home / ".config/ai-agents-skills/providers.env").read_text(),
            )
            self.assertNotIn(
                "GH_TOKEN=",
                (home / ".config/ai-agents-skills/providers.env").read_text(),
            )
            self.assertEqual(
                (
                    home
                    / ".openclaw/workspace/.config/ai-agents-skills/providers/copilot.env"
                ).read_bytes(),
                (
                    home / ".config/ai-agents-skills/providers/copilot.env"
                ).read_bytes(),
            )
            self.assertNotIn("fixture-hetzner", result.stdout + result.stderr)
            self.assertNotIn("fixture-kaggle", result.stdout + result.stderr)
            self.assertNotIn("fixture-s2-secret", result.stdout + result.stderr)
            self.assertEqual(
                (home / ".secrets.env").read_text(encoding="utf-8"),
                "# retained owner settings\nCLASSROOM50_ORG_ALLOWLIST=fixture-org\n",
            )
            scrubbed = (home / ".secrets.env").read_bytes()
            rerun = self.run_projection(home, "--migrate-aas-legacy")
            self.assertEqual(rerun.returncode, 0, rerun.stderr)
            self.assertEqual((home / ".secrets.env").read_bytes(), scrubbed)
            self.assertEqual(
                (home / ".kaggle/access_token").read_text(encoding="utf-8"),
                "fixture-kaggle\n",
            )
            for relative in (
                ".codex/runtime/workspace/.secrets.json",
                ".local/share/ai-agents-skills/runtime/workspace/.secrets.json",
            ):
                self.assertEqual((home / relative).read_bytes(), authority_path.read_bytes())
            self.assertFalse(
                (home / ".openclaw/workspace/.config/send-email/secrets.json").exists()
            )
            for runtime_root in (
                ".codex/runtime/workspace",
                ".local/share/ai-agents-skills/runtime/workspace",
                ".openclaw/workspace",
            ):
                self.assertEqual(
                    (home / runtime_root / "skills/zotero/config.json").read_text(),
                    '{\n  "library_id": "fixture"\n}\n',
                )
                self.assertEqual(
                    (home / runtime_root / "skills/calibre/config.json").read_text(),
                    '{"folder_id":"fixture"}\n',
                )
            self.assertTrue(
                (home / ".config/course/google-classroom/credentials.json").is_file()
            )
            self.assertTrue(
                (
                    home
                    / ".openclaw/workspace/.config/course/google-classroom/credentials.json"
                ).is_file()
            )
            canvas_authority = home / ".config/course/canvas/config.json"
            self.assertEqual(
                set(json.loads(canvas_authority.read_text(encoding="utf-8"))),
                {
                    "CANVAS_LMS_API_URL",
                    "CANVAS_LMS_API_KEY",
                    "CANVAS_LMS_COURSE_ID",
                },
            )
            self.assertEqual(canvas_authority.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                (
                    home
                    / ".openclaw/workspace/.config/course/canvas/config.json"
                ).read_bytes(),
                canvas_authority.read_bytes(),
            )
            self.assertNotIn("fixture-canvas-secret", result.stdout + result.stderr)

    def test_legacy_unquoted_hash_is_preserved_exactly_before_source_scrub(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            dotenv = home / ".secrets.env"
            dotenv.write_text(
                "# retained\nKAGGLE_API_TOKEN=fixture#hash-never-truncate\n",
                encoding="utf-8",
            )
            dotenv.chmod(0o600)

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 0, result.stderr)
            compute = (home / ".config/ai-agents-skills/compute.env").read_text(
                encoding="utf-8"
            )
            self.assertIn("KAGGLE_API_TOKEN=fixture#hash-never-truncate\n", compute)
            self.assertEqual(
                (home / ".kaggle/access_token").read_text(encoding="utf-8"),
                "fixture#hash-never-truncate\n",
            )
            self.assertEqual(dotenv.read_text(encoding="utf-8"), "# retained\n")
            self.assertNotIn("fixture#hash-never-truncate", result.stdout + result.stderr)

    def test_legacy_trailing_comment_fails_without_scrubbing_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            dotenv = home / ".secrets.env"
            original = "KAGGLE_API_TOKEN=fixture-value # ambiguous comment\n"
            dotenv.write_text(original, encoding="utf-8")
            dotenv.chmod(0o600)

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertEqual(dotenv.read_text(encoding="utf-8"), original)
            self.assertFalse((home / ".config/ai-agents-skills/compute.env").exists())
            self.assertNotIn("fixture-value", result.stdout + result.stderr)

    def test_runtime_projection_only_aas_key_is_promoted_before_convergence(self) -> None:
        relatives = (
            ".codex/runtime/workspace/.secrets.json",
            ".local/share/ai-agents-skills/runtime/workspace/.secrets.json",
            ".openclaw/workspace/.config/ai-agents-skills/secrets.json",
            ".openclaw/workspace/.secrets.json",
        )
        for relative in relatives:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                source = home / relative
                source.parent.mkdir(parents=True)
                source.write_text(
                    '{"ZOTERO_API_KEY":"projection-only-zotero-canary",'
                    '"UNRELATED":"must-not-promote"}\n',
                    encoding="utf-8",
                )

                result = self.run_projection(home, "--migrate-aas-legacy")

                self.assertEqual(result.returncode, 0, result.stderr)
                authority = json.loads(
                    (home / ".config/ai-agents-skills/secrets.json").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(
                    authority, {"ZOTERO_API_KEY": "projection-only-zotero-canary"}
                )
                self.assertFalse((home / ".openclaw/workspace/.secrets.json").exists())
                self.assertNotIn(
                    "projection-only-zotero-canary", result.stdout + result.stderr
                )

    def test_divergent_runtime_projection_aas_keys_fail_before_convergence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            first = home / ".codex/runtime/workspace/.secrets.json"
            second = home / ".openclaw/workspace/.secrets.json"
            for path, value in (
                (first, "first-zotero-canary"),
                (second, "second-zotero-canary"),
            ):
                path.parent.mkdir(parents=True)
                path.write_text(
                    json.dumps({"ZOTERO_API_KEY": value}) + "\n",
                    encoding="utf-8",
                )

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("legacy AAS credential sources conflict", result.stderr)
            self.assertFalse((home / ".config/ai-agents-skills/secrets.json").exists())
            self.assertTrue(first.exists())
            self.assertTrue(second.exists())
            self.assertNotIn("first-zotero-canary", result.stdout + result.stderr)
            self.assertNotIn("second-zotero-canary", result.stdout + result.stderr)

    def test_divergent_legacy_aas_sources_fail_before_authority_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".claude").mkdir(parents=True)
            (home / ".openclaw").mkdir(parents=True)
            (home / ".claude/secrets.json").write_text(
                '{"LEANEXPLORE_API_KEY":"first-canary-secret"}\n',
                encoding="utf-8",
            )
            (home / ".openclaw/secrets.json").write_text(
                '{"LEANEXPLORE_API_KEY":"second-canary-secret"}\n',
                encoding="utf-8",
            )

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("legacy AAS credential sources conflict", result.stderr)
            self.assertNotIn("first-canary-secret", result.stdout + result.stderr)
            self.assertNotIn("second-canary-secret", result.stdout + result.stderr)
            self.assertFalse(
                (home / ".config/ai-agents-skills/skill.env").exists()
            )

    def test_conflicting_dotenv_and_canonical_authority_fail_before_scrub(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            skill_env = home / ".config/ai-agents-skills/skill.env"
            skill_env.parent.mkdir(parents=True)
            skill_env.write_text("LEANEXPLORE_API_KEY=canonical-canary\n", encoding="utf-8")
            skill_env.chmod(0o600)
            dotenv = home / ".secrets.env"
            dotenv.write_text(
                "CLASSROOM50_ORG_ALLOWLIST=fixture-org\n"
                "LEANEXPLORE_API_KEY=legacy-canary\n",
                encoding="utf-8",
            )
            before = dotenv.read_bytes()

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("conflicts with its authority", result.stderr)
            self.assertEqual(dotenv.read_bytes(), before)
            self.assertNotIn("canonical-canary", result.stdout + result.stderr)
            self.assertNotIn("legacy-canary", result.stdout + result.stderr)

    def test_dotenv_credential_migration_never_evaluates_shell_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            marker = home / "must-not-exist"
            dotenv = home / ".secrets.env"
            dotenv.write_text(
                f"LEANEXPLORE_API_KEY=$(touch {marker})\n",
                encoding="utf-8",
            )
            before = dotenv.read_bytes()

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("not a literal value", result.stderr)
            self.assertEqual(dotenv.read_bytes(), before)
            self.assertFalse(marker.exists())
            self.assertFalse(
                (home / ".config/ai-agents-skills/skill.env").exists()
            )

    def test_divergent_legacy_zotero_s2_secret_fails_before_scrub(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            legacy_config = home / ".claude/skills/zotero/config.json"
            legacy_config.parent.mkdir(parents=True)
            legacy_config.write_text(
                '{"semantic_scholar_api_key":"config-s2-canary"}\n',
                encoding="utf-8",
            )
            legacy_config.chmod(0o644)
            (home / ".secrets.env").write_text(
                "SEMANTIC_SCHOLAR_API_KEY=env-s2-canary\n",
                encoding="utf-8",
            )

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("legacy Zotero Semantic Scholar credentials conflict", result.stderr)
            self.assertNotIn("config-s2-canary", result.stdout + result.stderr)
            self.assertNotIn("env-s2-canary", result.stdout + result.stderr)
            self.assertFalse(
                (home / ".config/ai-agents-skills/skill.env").exists()
            )
            self.assertIn(
                "semantic_scholar_api_key",
                legacy_config.read_text(encoding="utf-8"),
            )

    def test_projection_only_zotero_s2_secret_is_promoted_before_convergence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            legacy_config = home / ".openclaw/workspace/skills/zotero/config.json"
            legacy_config.parent.mkdir(parents=True)
            legacy_config.write_text(
                '{"library_id":"fixture-library",'
                '"semantic_scholar_api_key":"projection-s2-canary"}\n',
                encoding="utf-8",
            )
            legacy_config.chmod(0o644)

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 0, result.stderr)
            skill_env = (home / ".config/ai-agents-skills/skill.env").read_text(
                encoding="utf-8"
            )
            self.assertIn("SEMANTIC_SCHOLAR_API_KEY=projection-s2-canary", skill_env)
            canonical = json.loads(
                (home / ".config/ai-agents-skills/zotero/config.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(canonical, {"library_id": "fixture-library"})
            self.assertEqual(json.loads(legacy_config.read_text(encoding="utf-8")), canonical)
            self.assertNotIn("projection-s2-canary", result.stdout + result.stderr)

    def test_divergent_zotero_projection_secrets_fail_before_scrub(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            paths = (
                home / ".openclaw/workspace/skills/zotero/config.json",
                home / ".codex/runtime/workspace/skills/zotero/config.json",
            )
            for path, value in zip(paths, ("first-s2-canary", "second-s2-canary")):
                path.parent.mkdir(parents=True)
                path.write_text(
                    json.dumps({"semantic_scholar_api_key": value}) + "\n",
                    encoding="utf-8",
                )
                path.chmod(0o644)

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("legacy Zotero Semantic Scholar credentials conflict", result.stderr)
            self.assertFalse((home / ".config/ai-agents-skills/skill.env").exists())
            for path in paths:
                self.assertIn(
                    "semantic_scholar_api_key", path.read_text(encoding="utf-8")
                )
            self.assertNotIn("first-s2-canary", result.stdout + result.stderr)
            self.assertNotIn("second-s2-canary", result.stdout + result.stderr)

    def test_legacy_zotero_s2_conflict_with_canonical_skill_env_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            legacy_config = home / ".claude/skills/zotero/config.json"
            legacy_config.parent.mkdir(parents=True)
            legacy_config.write_text(
                '{"semantic_scholar_api_key":"config-s2-canary"}\n',
                encoding="utf-8",
            )
            legacy_config.chmod(0o644)
            skill_env = home / ".config/ai-agents-skills/skill.env"
            skill_env.parent.mkdir(parents=True)
            skill_env.write_text(
                "SEMANTIC_SCHOLAR_API_KEY=canonical-s2-canary\n",
                encoding="utf-8",
            )
            skill_env.chmod(0o600)

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("legacy Zotero Semantic Scholar credentials conflict", result.stderr)
            self.assertNotIn("config-s2-canary", result.stdout + result.stderr)
            self.assertNotIn("canonical-s2-canary", result.stdout + result.stderr)
            self.assertIn(
                "semantic_scholar_api_key",
                legacy_config.read_text(encoding="utf-8"),
            )
            self.assertEqual(
                skill_env.read_text(encoding="utf-8"),
                "SEMANTIC_SCHOLAR_API_KEY=canonical-s2-canary\n",
            )

    def test_runtime_env_authorities_reject_padding_and_control_characters(self) -> None:
        for payload in (
            "LEANEXPLORE_API_KEY=value \n",
            "LEANEXPLORE_API_KEY=value\tinside\n",
            "LEANEXPLORE_API_KEY=value\x7finside\n",
        ):
            with self.subTest(payload=repr(payload)), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                authority = home / ".config/ai-agents-skills/skill.env"
                authority.parent.mkdir(parents=True)
                authority.write_text(payload, encoding="utf-8")
                authority.chmod(0o600)

                result = self.run_projection(home)

                self.assertEqual(result.returncode, 2)
                self.assertIn("skill credential authority contains an invalid", result.stderr)

    def test_divergent_legacy_canvas_configs_require_explicit_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            for course, key in (("one", "fixture-one"), ("two", "fixture-two")):
                directory = home / ".config/course" / course
                directory.mkdir(parents=True)
                (directory / "config.json").write_text(
                    json.dumps(
                        {
                            "CANVAS_LMS_API_URL": "https://canvas.example.invalid",
                            "CANVAS_LMS_API_KEY": key,
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("multiple divergent legacy Canvas configs", result.stderr)
            self.assertNotIn("fixture-one", result.stdout + result.stderr)
            self.assertNotIn("fixture-two", result.stdout + result.stderr)

    def test_symlinked_legacy_canvas_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            course_root = home / ".config/course"
            course_root.mkdir(parents=True)
            outside = home / "outside"
            outside.mkdir()
            (outside / "config.json").write_text(
                json.dumps(
                    {
                        "CANVAS_LMS_API_URL": "https://canvas.example.invalid",
                        "CANVAS_LMS_API_KEY": "outside-secret",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (course_root / "linked").symlink_to(outside, target_is_directory=True)

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("directory is unsafe", result.stderr)
            self.assertNotIn("outside-secret", result.stdout + result.stderr)

    def test_shared_authority_rejects_unrelated_or_dedicated_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            authority = home / ".config/ai-agents-skills/secrets.json"
            authority.parent.mkdir(parents=True)
            authority.write_text(
                '{"ZOTERO_API_KEY":"fixture","accounts":{}}\n', encoding="utf-8"
            )

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 2)
            self.assertIn("unsupported fields", result.stderr)

    def test_partial_legacy_zulip_values_do_not_create_an_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".claude").mkdir()
            (home / ".claude/secrets.json").write_text(
                json.dumps(
                    {
                        "ZULIP_ORG_URL": "https://fixture.zulip.invalid",
                        "ZULIP_EMAIL": "bot@fixture.invalid",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = self.run_projection(home, "--migrate-remote-bridge-legacy")
            self.assertEqual(result.returncode, 2)
            self.assertIn("legacy Remote Bridge Zulip credential source is incomplete", result.stderr)
            self.assertFalse((home / ".config/remote-bridge/secrets.json").exists())

    def test_divergent_legacy_zulip_sources_fail_before_authority_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            for relative, api_key in (
                (".claude/secrets.json", "first-zulip-canary"),
                (".openclaw/secrets.json", "second-zulip-canary"),
            ):
                path = home / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps(
                        {
                            "ZULIP_ORG_URL": "https://fixture.zulip.invalid",
                            "ZULIP_EMAIL": "bot@fixture.invalid",
                            "ZULIP_API_KEY": api_key,
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

            result = self.run_projection(home, "--migrate-remote-bridge-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("legacy Remote Bridge Zulip credential sources conflict", result.stderr)
            self.assertNotIn("first-zulip-canary", result.stdout + result.stderr)
            self.assertNotIn("second-zulip-canary", result.stdout + result.stderr)
            self.assertFalse((home / ".config/remote-bridge/secrets.json").exists())

    def test_symlink_projection_destination_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".openclaw/workspace").mkdir(parents=True)
            (home / ".openclaw/secrets.json").write_text('{"TOKEN":"fixture"}\n')
            victim = home / "victim"
            victim.write_text("unchanged\n")
            (home / ".openclaw/workspace/.secrets.json").symlink_to(victim)
            result = self.run_projection(home)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(victim.read_text(), "unchanged\n")

    def test_absent_research_authority_removes_stale_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            destination = home / ".openclaw/workspace/config/research-compute.toml"
            destination.parent.mkdir(parents=True)
            destination.write_text('broker_state_root = "stale"\n', encoding="utf-8")

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(destination.exists())

    def test_research_projection_rejects_symlinked_destination_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            source = home / ".local/share/ai-agents-skills/runtime/workspace/config/research-compute.toml"
            source.parent.mkdir(parents=True)
            source.write_text('install_id = "fixture"\n', encoding="utf-8")
            source.chmod(0o644)
            victim = home / "victim"
            victim.mkdir()
            (home / ".openclaw").mkdir()
            (home / ".openclaw/workspace").symlink_to(victim)

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 2)
            self.assertEqual(list(victim.iterdir()), [])

    def test_authority_read_rejects_symlinked_parent_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            outside = root / "outside"
            home.mkdir()
            outside.mkdir()
            (outside / "ai-agents-skills").mkdir()
            (outside / "ai-agents-skills/secrets.json").write_text(
                '{"ZOTERO_API_KEY":"outside-authority-canary"}\n',
                encoding="utf-8",
            )
            (home / ".config").symlink_to(outside, target_is_directory=True)

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 2)
            self.assertNotIn("outside-authority-canary", result.stdout + result.stderr)
            self.assertFalse((home / ".codex").exists())

    def test_group_writable_home_or_ancestor_is_rejected(self) -> None:
        for unsafe_home in (True, False):
            with self.subTest(unsafe_home=unsafe_home), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                authority = home / ".config/ai-agents-skills/secrets.json"
                authority.parent.mkdir(parents=True)
                authority.write_text(
                    '{"ZOTERO_API_KEY":"permission-canary"}\n', encoding="utf-8"
                )
                authority.chmod(0o600)
                if unsafe_home:
                    home.chmod(0o770)
                else:
                    (home / ".config").chmod(0o770)

                result = self.run_projection(home)

                self.assertNotIn("permission-canary", result.stdout + result.stderr)
                if unsafe_home:
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse((home / ".codex").exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((home / ".config").stat().st_mode & 0o777, 0o700)
                    self.assertTrue(
                        (home / ".codex/runtime/workspace/.secrets.json").is_file()
                    )

    def test_private_authority_requires_0600_and_redacts_its_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "sensitive-home-path-canary"
            authority = home / ".config/ai-agents-skills/secrets.json"
            authority.parent.mkdir(parents=True)
            authority.write_text(
                '{"ZOTERO_API_KEY":"private-mode-canary"}\n', encoding="utf-8"
            )
            authority.chmod(0o644)

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 2)
            self.assertIn("unsafe projection authority", result.stderr)
            self.assertNotIn("sensitive-home-path-canary", result.stderr)
            self.assertNotIn("private-mode-canary", result.stdout + result.stderr)
            self.assertFalse((home / ".codex").exists())

    def test_declared_public_authority_accepts_0644(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            authority = home / ".config/ai-agents-skills/zotero/config.json"
            authority.parent.mkdir(parents=True)
            authority.write_text('{"library_id":"fixture"}\n', encoding="utf-8")
            authority.chmod(0o644)

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            projection = home / ".codex/runtime/workspace/skills/zotero/config.json"
            self.assertEqual(projection.read_bytes(), authority.read_bytes())
            self.assertEqual(projection.stat().st_mode & 0o777, 0o644)

    def test_legacy_getscipapers_ancestor_symlink_never_deletes_external_root(self) -> None:
        cases = (
            (".openclaw", "workspace/secrets/getscipapers"),
            (".openclaw/workspace", "secrets/getscipapers"),
            (".openclaw/workspace/secrets", "getscipapers"),
        )
        for link_relative, victim_relative in cases:
            with self.subTest(link=link_relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home = root / "home"
                outside = root / "outside-path-canary"
                home.mkdir()
                victim = outside / victim_relative
                victim.mkdir(parents=True)
                victim_identity = (victim.stat().st_dev, victim.stat().st_ino)
                link = home / link_relative
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(outside, target_is_directory=True)

                result = self.run_projection(home)

                self.assertEqual(result.returncode, 2)
                self.assertTrue(victim.is_dir())
                self.assertEqual(
                    (victim.stat().st_dev, victim.stat().st_ino), victim_identity
                )
                self.assertNotIn("outside-path-canary", result.stderr)

    def test_atomic_write_detects_destination_ancestor_swap(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            destination = home / ".config/remote-bridge/secrets.json"
            destination.parent.mkdir(parents=True)
            displaced = home / ".config/remote-bridge.displaced"
            replacement_marker = b"replacement-must-survive\n"
            real_confirm = module._confirm_parent_identity
            swapped = False

            def swap_then_confirm(selected_home, selected_path, expected):
                nonlocal swapped
                if not swapped:
                    destination.parent.rename(displaced)
                    destination.parent.mkdir()
                    (destination.parent / destination.name).write_bytes(
                        replacement_marker
                    )
                    swapped = True
                return real_confirm(selected_home, selected_path, expected)

            token = module._ACTIVE_HOME.set(module._require_home(home))
            try:
                with mock.patch.object(
                    module, "_confirm_parent_identity", side_effect=swap_then_confirm
                ):
                    with self.assertRaisesRegex(
                        module.ProjectionError, "path changed during operation"
                    ):
                        module._atomic_write(
                            home, destination, b"new-secret-canary\n", 0o600
                        )
            finally:
                module._ACTIVE_HOME.reset(token)

            self.assertEqual(destination.read_bytes(), replacement_marker)
            self.assertFalse(any(displaced.glob(".projection-*.tmp")))

    def test_descriptor_cleanup_runs_on_inspection_and_temp_cleanup_errors(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            with (
                mock.patch.object(module.os, "open", return_value=123),
                mock.patch.object(module.os, "fstat", side_effect=OSError("fixture")),
                mock.patch.object(module.os, "close") as close,
            ):
                with self.assertRaises(OSError):
                    module._open_home_descriptor(home)
                close.assert_called_once_with(123)

        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            destination = home / ".config/remote-bridge/secrets.json"
            destination.parent.mkdir(parents=True)
            captured: dict[str, int] = {}
            real_open_parent = module._open_parent_descriptor
            real_close = module.os.close

            def capture_parent(*args, **kwargs):
                opened = real_open_parent(*args, **kwargs)
                assert opened is not None
                captured["descriptor"] = opened[0]
                return opened

            with (
                mock.patch.object(
                    module, "_open_parent_descriptor", side_effect=capture_parent
                ),
                mock.patch.object(
                    module,
                    "_confirm_parent_identity",
                    side_effect=module.ProjectionError("fixture"),
                ),
                mock.patch.object(module.os, "unlink", side_effect=OSError("fixture")),
                mock.patch.object(module.os, "close", wraps=real_close) as close,
            ):
                with self.assertRaises(OSError):
                    module._atomic_write(home, destination, b"cleanup-canary\n", 0o600)
                close.assert_any_call(captured["descriptor"])

    def test_authority_read_detects_same_size_concurrent_mutation(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            authority = home / ".config/ai-agents-skills/skill.env"
            authority.parent.mkdir(parents=True)
            authority.write_bytes(b"KEY=first-canary\n")
            replacement = b"KEY=other-canary\n"
            self.assertEqual(len(replacement), authority.stat().st_size)
            real_read = module.os.read
            mutated = False

            def read_then_mutate(descriptor, size):
                nonlocal mutated
                payload = real_read(descriptor, size)
                if payload and not mutated:
                    authority.write_bytes(replacement)
                    mutated = True
                return payload

            token = module._ACTIVE_HOME.set(module._require_home(home))
            try:
                with mock.patch.object(module.os, "read", side_effect=read_then_mutate):
                    with self.assertRaisesRegex(
                        module.ProjectionError, "authority changed during read"
                    ):
                        module._read_regular(authority, required_mode=0o600)
            finally:
                module._ACTIVE_HOME.reset(token)

    def test_missing_github_authorities_remove_stale_sandbox_projections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            destination = home / ".openclaw/workspace/.config/gh"
            destination.mkdir(parents=True)
            (destination / "hosts.yml").write_text("stale-host\n", encoding="utf-8")
            (destination / "config.yml").write_text("stale-config\n", encoding="utf-8")

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((destination / "hosts.yml").exists())
            self.assertFalse((destination / "config.yml").exists())

    def test_unknown_legacy_getscipapers_file_is_not_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            unknown = (
                home
                / ".openclaw/workspace/secrets/getscipapers/private/unknown.bin"
            )
            unknown.parent.mkdir(parents=True)
            unknown.write_bytes(b"owner-data-fixture")

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 2)
            self.assertIn("unsupported paths", result.stderr)
            self.assertEqual(unknown.read_bytes(), b"owner-data-fixture")

    def test_divergent_legacy_getscipapers_file_preserves_both_copies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            authority = home / ".config/getscipapers/ablesci/credentials.json"
            authority.parent.mkdir(parents=True)
            authority.write_text('{"key":"current"}\n', encoding="utf-8")
            legacy = (
                home
                / ".openclaw/workspace/secrets/getscipapers/ablesci/credentials.json"
            )
            legacy.parent.mkdir(parents=True)
            legacy.write_text('{"key":"legacy"}\n', encoding="utf-8")

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 2)
            self.assertIn("diverges from its authority", result.stderr)
            self.assertTrue(authority.is_file())
            self.assertTrue(legacy.is_file())

    def test_projection_only_vnu_credentials_are_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            projection = home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json"
            projection.parent.mkdir(parents=True)
            expected = {
                "VNU_EOFFICE_USERNAME": "projection-user",
                "VNU_EOFFICE_PASSWORD": "projection-password-canary",
                "VNU_STATE_HMAC_KEY": "projection-hmac-canary",
            }
            legacy_projection = {
                **expected,
                "TELEGRAM_BOT_TOKEN": "retired-vnu-delivery-canary",
                "TELEGRAM_CHAT_ID": "retired-vnu-chat-canary",
            }
            projection.write_text(
                json.dumps(legacy_projection) + "\n", encoding="utf-8"
            )

            result = self.run_projection(home, "--migrate-vnu-legacy")

            self.assertEqual(result.returncode, 0, result.stderr)
            authority = home / ".config/vnu-eoffice/secrets.json"
            self.assertEqual(json.loads(authority.read_text(encoding="utf-8")), expected)
            self.assertEqual(projection.read_bytes(), authority.read_bytes())
            self.assertNotIn("projection-password-canary", result.stdout + result.stderr)
            self.assertNotIn("retired-vnu-delivery-canary", result.stdout + result.stderr)

    def test_conflicting_vnu_projection_fails_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            projection = home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json"
            projection.parent.mkdir(parents=True)
            projection.write_text(
                json.dumps(
                    {
                        "VNU_EOFFICE_USERNAME": "projection-user",
                        "VNU_EOFFICE_PASSWORD": "projection-password-canary",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            legacy = home / ".claude/secrets.json"
            legacy.parent.mkdir(parents=True)
            legacy.write_text(
                json.dumps(
                    {
                        "VNU_EOFFICE_USERNAME": "different-user",
                        "VNU_EOFFICE_PASSWORD": "projection-password-canary",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            before_projection = projection.read_bytes()
            before_legacy = legacy.read_bytes()

            result = self.run_projection(home, "--migrate-vnu-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("VNU eOffice credential sources conflict", result.stderr)
            self.assertFalse((home / ".config/vnu-eoffice/secrets.json").exists())
            self.assertEqual(projection.read_bytes(), before_projection)
            self.assertEqual(legacy.read_bytes(), before_legacy)
            self.assertNotIn("projection-password-canary", result.stdout + result.stderr)

    def test_projection_only_remote_bridge_credentials_are_promoted(self) -> None:
        expected = {
            "default_channel": "zulip",
            "notify_channels": ["zulip"],
            "allowed_user_ids": [],
            "zulip": {
                "site": "https://projection.zulip.invalid",
                "email": "projection-bot@invalid.example",
                "api_key": "projection-zulip-canary",  # LEAKSCAN-EXEMPT: synthetic fixture
                "control_stream": "aas-remote",
                "topic_prefix": "job/",
                "allowed_user_ids": [],
            },
        }
        for relative in (
            ".openclaw/workspace/.config/remote-bridge/secrets.json",
            ".openclaw/workspace/secrets/remote-bridge/secrets.json",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                projection = home / relative
                projection.parent.mkdir(parents=True)
                projection.write_text(json.dumps(expected) + "\n", encoding="utf-8")

                result = self.run_projection(home, "--migrate-remote-bridge-legacy")

                self.assertEqual(result.returncode, 0, result.stderr)
                authority = home / ".config/remote-bridge/secrets.json"
                self.assertEqual(
                    json.loads(authority.read_text(encoding="utf-8")), expected
                )
                current_projection = (
                    home / ".openclaw/workspace/.config/remote-bridge/secrets.json"
                )
                self.assertFalse(current_projection.exists())
                self.assertFalse(
                    (home / ".openclaw/workspace/secrets/remote-bridge/secrets.json").exists()
                )
                self.assertNotIn("projection-zulip-canary", result.stdout + result.stderr)

    def test_retired_remote_bridge_projection_is_promoted_without_explicit_legacy_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            projection = self.write_openclaw_json(
                home,
                ".openclaw/workspace/.config/remote-bridge/secrets.json",
                {
                    "default_channel": "zulip",
                    "notify_channels": ["zulip"],
                    "allowed_user_ids": [],
                    "zulip": {
                        "site": "https://retired.zulip.invalid",
                        "email": "retired-bot@invalid.example",
                        "api_key": "retired-zulip-canary",  # LEAKSCAN-EXEMPT: synthetic fixture
                    },
                },
            )

            result = self.run_projection(home)

            self.assertEqual(result.returncode, 0, result.stderr)
            authority = home / ".config/remote-bridge/secrets.json"
            self.assertTrue(authority.is_file())
            self.assertFalse(projection.exists())
            self.assertEqual(authority.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("retired-zulip-canary", result.stdout + result.stderr)

    def test_retired_openclaw_workspace_zulip_projection_seeds_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            projection = home / ".openclaw/workspace/.secrets.json"
            projection.parent.mkdir(parents=True)
            projection.write_text(
                json.dumps(
                    {
                        "ZULIP_ORG_URL": "https://workspace.zulip.invalid",
                        "ZULIP_EMAIL": "workspace-bot@invalid.example",
                        "ZULIP_API_KEY": "workspace-zulip-canary",
                        "GATEWAY_AUTH_TOKEN": "unrelated-gateway-canary",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            result = self.run_projection(home, "--migrate-remote-bridge-legacy")

            self.assertEqual(result.returncode, 0, result.stderr)
            authority = json.loads(
                (home / ".config/remote-bridge/secrets.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                authority["zulip"]["site"], "https://workspace.zulip.invalid"
            )
            self.assertEqual(
                authority["zulip"]["email"], "workspace-bot@invalid.example"
            )
            self.assertNotIn("GATEWAY_AUTH_TOKEN", authority)
            self.assertFalse(projection.exists())
            self.assertNotIn("workspace-zulip-canary", result.stdout + result.stderr)
            self.assertNotIn("unrelated-gateway-canary", result.stdout + result.stderr)

    def test_conflicting_remote_bridge_projections_fail_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            paths = (
                home / ".openclaw/workspace/.config/remote-bridge/secrets.json",
                home / ".openclaw/workspace/secrets/remote-bridge/secrets.json",
            )
            for path, api_key in zip(paths, ("first-zulip-canary", "second-zulip-canary")):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps(
                        {
                            "default_channel": "zulip",
                            "notify_channels": ["zulip"],
                            "allowed_user_ids": [],
                            "zulip": {
                                "site": "https://projection.zulip.invalid",
                                "email": "projection-bot@invalid.example",
                                "api_key": api_key,
                            },
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
            before = [path.read_bytes() for path in paths]

            result = self.run_projection(home, "--migrate-remote-bridge-legacy")

            self.assertEqual(result.returncode, 2)
            self.assertIn("Remote Bridge projections conflict", result.stderr)
            self.assertFalse((home / ".config/remote-bridge/secrets.json").exists())
            self.assertEqual([path.read_bytes() for path in paths], before)
            self.assertNotIn("first-zulip-canary", result.stdout + result.stderr)
            self.assertNotIn("second-zulip-canary", result.stdout + result.stderr)

    def test_every_historical_send_email_projection_can_seed_the_authority(self) -> None:
        smtp = {
            "smtp": {
                "host": "smtp.projection.invalid",
                "user": "projection-user",
                "password": "projection-smtp-canary",  # LEAKSCAN-EXEMPT: synthetic fixture
                "from": "sender@projection.invalid",
            }
        }
        for relative in (
            ".openclaw/workspace/.config/send-email/secrets.json",
            ".codex/runtime/workspace/.secrets.json",
            ".local/share/ai-agents-skills/runtime/workspace/.secrets.json",
            ".openclaw/workspace/.secrets.json",
            ".claude/secrets.json",
            ".openclaw/secrets.json",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                source = home / relative
                source.parent.mkdir(parents=True)
                source.write_text(json.dumps(smtp) + "\n", encoding="utf-8")

                result = self.run_projection(home, "--migrate-aas-legacy")

                self.assertEqual(result.returncode, 0, result.stderr)
                authority = home / ".config/send-email/secrets.json"
                self.assertEqual(json.loads(authority.read_text(encoding="utf-8")), smtp)
                self.assertEqual(authority.stat().st_mode & 0o777, 0o600)
                if relative == ".openclaw/workspace/.config/send-email/secrets.json":
                    self.assertFalse(source.exists())
                self.assertNotIn("projection-smtp-canary", result.stdout + result.stderr)

    def test_generic_metadata_is_not_mistaken_for_send_email_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            legacy = home / ".claude/secrets.json"
            legacy.parent.mkdir(parents=True)
            legacy.write_text(
                json.dumps(
                    {
                        "_README": "metadata for an unrelated legacy bundle",
                        "default_account": "unrelated-account-label",
                        "ZOTERO_API_KEY": "zotero-canary",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            result = self.run_projection(home, "--migrate-aas-legacy")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((home / ".config/send-email/secrets.json").exists())
            self.assertNotIn("zotero-canary", result.stdout + result.stderr)

    def test_conflicting_smtp_sources_preflight_before_other_migrations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            vnu_projection = (
                home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json"
            )
            vnu_projection.parent.mkdir(parents=True)
            vnu_projection.write_text(
                json.dumps(
                    {
                        "VNU_EOFFICE_USERNAME": "projection-user",
                        "VNU_EOFFICE_PASSWORD": "vnu-password-canary",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            smtp_sources = (
                home / ".codex/runtime/workspace/.secrets.json",
                home / ".local/share/ai-agents-skills/runtime/workspace/.secrets.json",
            )
            for source, password in zip(
                smtp_sources, ("first-smtp-canary", "second-smtp-canary")
            ):
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(
                    json.dumps(
                        {
                            "smtp": {
                                "host": "smtp.projection.invalid",
                                "user": "projection-user",
                                "password": password,
                                "from": "sender@projection.invalid",
                            }
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
            before_vnu = vnu_projection.read_bytes()
            before_smtp = [source.read_bytes() for source in smtp_sources]

            result = self.run_projection(
                home, "--migrate-vnu-legacy", "--migrate-aas-legacy"
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("send-email credential sources conflict", result.stderr)
            self.assertFalse((home / ".config/vnu-eoffice/secrets.json").exists())
            self.assertFalse((home / ".config/send-email/secrets.json").exists())
            self.assertEqual(vnu_projection.read_bytes(), before_vnu)
            self.assertEqual([source.read_bytes() for source in smtp_sources], before_smtp)
            self.assertNotIn("first-smtp-canary", result.stdout + result.stderr)
            self.assertNotIn("second-smtp-canary", result.stdout + result.stderr)

    def test_incomplete_smtp_projection_fails_before_other_migrations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            vnu_projection = (
                home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json"
            )
            vnu_projection.parent.mkdir(parents=True)
            vnu_projection.write_text(
                json.dumps(
                    {
                        "VNU_EOFFICE_USERNAME": "projection-user",
                        "VNU_EOFFICE_PASSWORD": "vnu-password-canary",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            smtp_projection = (
                home / ".openclaw/workspace/.config/send-email/secrets.json"
            )
            smtp_projection.parent.mkdir(parents=True)
            smtp_projection.write_text(
                '{"smtp":{"host":"smtp.invalid","password":"smtp-canary"}}\n',
                encoding="utf-8",
            )
            before_vnu = vnu_projection.read_bytes()
            before_smtp = smtp_projection.read_bytes()

            result = self.run_projection(
                home, "--migrate-vnu-legacy", "--migrate-aas-legacy"
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("send-email profile is incomplete", result.stderr)
            self.assertFalse((home / ".config/vnu-eoffice/secrets.json").exists())
            self.assertFalse((home / ".config/send-email/secrets.json").exists())
            self.assertEqual(vnu_projection.read_bytes(), before_vnu)
            self.assertEqual(smtp_projection.read_bytes(), before_smtp)
            self.assertNotIn("smtp-canary", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
