#!/usr/bin/env python3
"""Synthetic regression tests for the recovery-set and escrow contracts."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "bin" / "lib" / "recovery_tool.py"
MANIFEST = ROOT / "secrets" / "secrets-manifest.yaml"


def load_helper():
    spec = importlib.util.spec_from_file_location("recovery_tool", HELPER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def fixture_manifest(path: Path) -> Path:
    value = {
        "schema": "coding-system.secrets-manifest.v2",
        "entry_defaults": {
            "classification": "authority",
            "portability": "portable",
            "backup": True,
        },
        "dir_perms": {
            ".config/demo": "0700",
            ".config/.wrangler": "0700",
            ".config/.wrangler/config": "0700",
            ".local/share/opencode": "0700",
            ".local/share/forms-private-keys": "0700",
            ".local/share/pki": "0700",
            ".local/share/pki/nssdb": "0700",
            ".agent": "0700",
            ".state/demo": "0700",
            ".openclaw/workspace": "0700",
            ".openclaw/devices": "0700",
            ".openclaw/state": "0700",
        },
        "entries": [
            {
                "id": "demo-authority",
                "path": ".config/demo/secret.json",
                "mode": "0600",
                "required": True,
                "classification": "authority",
                "authority": "demo-authority",
                "portability": "portable",
                "backup": True,
                "feature": "fixture authority",
                "obtain": "synthetic fixture",
            },
            {
                "id": "demo-projection",
                "path": ".agent/secret.json",
                "mode": "0600",
                "required": False,
                "classification": "projection",
                "authority": "demo-authority",
                "portability": "regenerated",
                "backup": False,
                "feature": "fixture projection",
                "obtain": "materialized from fixture authority",
            },
            {
                "id": "demo-session",
                "path": ".config/demo/session.json",
                "mode": "0600",
                "required": False,
                "classification": "session",
                "authority": "demo-session",
                "portability": "reauth-required",
                "backup": True,
                "feature": "fixture session",
                "obtain": "synthetic login",
            },
            {
                "id": "wrangler-oauth-session",
                "path": ".config/.wrangler/config/default.toml",
                "mode": "0600",
                "required": False,
                "classification": "session",
                "authority": "wrangler-oauth-session",
                "portability": "reauth-required",
                "backup": True,
                "feature": "fixture Wrangler OAuth session",
                "obtain": "synthetic Wrangler login",
            },
            {
                "id": "opencode-native-session-store",
                "path": ".local/share/opencode/opencode.db",
                "mode": "0600",
                "required": False,
                "classification": "session",
                "authority": "opencode-native-session-store",
                "portability": "reauth-required",
                "backup": True,
                "capture": "sqlite-backup",
                "feature": "fixture OpenCode native session store",
                "obtain": "synthetic OpenCode login",
            },
            {
                "id": "forms-backup-attestation-authority",
                "path": ".local/share/forms-private-keys/forms-backup-attestation-ed25519.pem",
                "mode": "0600",
                "required": False,
                "classification": "authority",
                "authority": "forms-backup-attestation-authority",
                "portability": "portable",
                "backup": True,
                "feature": "fixture Forms signing authority",
                "obtain": "synthetic Forms key",
            },
            {
                "id": "forms-classroom50-runner-local-authority",
                "path": "forms/apps/classroom50-runner/.env",
                "mode": "0600",
                "required": False,
                "classification": "authority",
                "authority": "forms-classroom50-runner-local-authority",
                "portability": "portable",
                "backup": True,
                "feature": "fixture Forms runner local authority",
                "obtain": "synthetic Forms runner configuration",
            },
            {
                "id": "forms-api-local-authority",
                "path": "forms/apps/api/.dev.vars",
                "mode": "0600",
                "required": False,
                "classification": "authority",
                "authority": "forms-api-local-authority",
                "portability": "portable",
                "backup": True,
                "feature": "fixture Forms API local authority",
                "obtain": "synthetic Forms API configuration",
            },
            {
                "id": "forms-web-local-private-settings",
                "path": "forms/apps/web/.env.local",
                "mode": "0600",
                "required": False,
                "classification": "private-state",
                "authority": "forms-web-local-private-settings",
                "portability": "portable",
                "backup": True,
                "feature": "fixture Forms web local settings",
                "obtain": "synthetic Forms web configuration",
            },
            {
                "id": "nss-private-key-database",
                "path": ".local/share/pki/nssdb/key4.db",
                "mode": "0600",
                "required": False,
                "classification": "private-state",
                "authority": "nss-private-key-database",
                "portability": "portable",
                "backup": True,
                "capture": "sqlite-backup",
                "feature": "fixture NSS key database",
                "obtain": "synthetic NSS state",
            },
            {
                "id": "nss-certificate-database",
                "path": ".local/share/pki/nssdb/cert9.db",
                "mode": "0600",
                "required": False,
                "classification": "private-state",
                "authority": "nss-certificate-database",
                "portability": "portable",
                "backup": True,
                "capture": "sqlite-backup",
                "feature": "fixture NSS certificate database",
                "obtain": "synthetic NSS state",
            },
            {
                "id": "nss-module-state",
                "path": ".local/share/pki/nssdb/pkcs11.txt",
                "mode": "0600",
                "required": False,
                "classification": "private-state",
                "authority": "nss-module-state",
                "portability": "portable",
                "backup": True,
                "feature": "fixture NSS module state",
                "obtain": "synthetic NSS state",
            },
            {
                "id": "claude-root-private-state",
                "path": ".claude.json",
                "mode": "0600",
                "required": False,
                "classification": "private-state",
                "authority": "claude-root-private-state",
                "portability": "portable",
                "backup": True,
                "feature": "fixture Claude root state",
                "obtain": "synthetic Claude state",
            },
            {
                "id": "demo-private-state",
                "path": ".state/demo/note.txt",
                "mode": "0600",
                "required": False,
                "classification": "private-state",
                "authority": "demo-private-state",
                "portability": "portable",
                "backup": True,
                "feature": "fixture private state",
                "obtain": "synthetic state",
            },
            {
                "id": "openclaw-address-book-state",
                "path": ".openclaw/workspace/.address-book.json",
                "mode": "0600",
                "required": False,
                "classification": "private-state",
                "authority": "openclaw-address-book-state",
                "portability": "portable",
                "backup": True,
                "feature": "fixture OpenClaw address book",
                "obtain": "synthetic contacts",
            },
            {
                "id": "openclaw-device-pairing-session",
                "path": ".openclaw/devices/",
                "mode": "0600",
                "required": False,
                "classification": "session",
                "authority": "openclaw-device-pairing-session",
                "portability": "machine-bound",
                "backup": True,
                "feature": "fixture OpenClaw device pairing state",
                "obtain": "synthetic pairing",
            },
            {
                "id": "openclaw-agent-models-owner-input",
                "path": ".openclaw/agents/*/agent/models.json",
                "mode": "0600",
                "required": False,
                "classification": "session",
                "authority": "openclaw-agent-models-owner-input",
                "portability": "portable",
                "backup": False,
                "feature": "fixture owner-only legacy provider input",
                "obtain": "synthetic owner archive",
            },
            {
                "id": "openclaw-global-state-owner-input",
                "path": ".openclaw/state/openclaw.sqlite",
                "mode": "0600",
                "required": False,
                "classification": "private-state",
                "authority": "openclaw-global-state-owner-input",
                "portability": "portable",
                "backup": False,
                "feature": "fixture owner-only global state",
                "obtain": "synthetic owner archive",
            },
        ],
    }
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    return path


def owner_private_directory(path: Path) -> Path:
    """Create a synthetic owner-only directory chain used by source detectors."""

    path.mkdir(parents=True, exist_ok=True)
    current = path
    while current != current.parent:
        current.chmod(0o700)
        if current.name == ".openclaw":
            break
        current = current.parent
    return path


def write_owner_private_json(path: Path, value: object) -> Path:
    owner_private_directory(path.parent)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


class ManifestContractTests(unittest.TestCase):
    def test_published_manifest_is_v2_and_covers_missing_agents(self) -> None:
        helper = load_helper()
        manifest = helper.load_secrets_manifest(MANIFEST)
        entries = {entry["path"]: entry for entry in manifest["entries"]}
        self.assertEqual(manifest["schema"], "coding-system.secrets-manifest.v2")
        for path in (
            ".config/vnu-eoffice/secrets.json",
            ".kimi-code/config.toml",
            ".local/share/opencode/auth.json",
            ".local/share/opencode/opencode.db",
            ".local/share/forms-private-keys/forms-backup-attestation-ed25519.pem",
            ".local/share/pki/nssdb/key4.db",
            ".local/share/pki/nssdb/cert9.db",
            ".local/share/pki/nssdb/pkcs11.txt",
            ".claude.json",
            ".gemini/oauth_creds.json",
            ".copilot/auth.json",
            ".docker/config.json",
            ".config/.wrangler/config/default.toml",
            ".openclaw/devices/",
            ".openclaw/file-delivery-policy.json",
            ".config/ai-agents-skills/file-delivery-queue.json",
            ".local/state/ai-agents-skills/file-delivery-replay/",
            ".openclaw/agents/*/agent/auth.json",
            ".openclaw/agents/*/agent/auth-state.json",
            ".openclaw/agents/*/agent/models.json",
            ".openclaw/state/openclaw.sqlite",
        ):
            self.assertIn(path, entries)
        self.assertEqual(
            entries[".openclaw/workspace/secrets/vnu-eoffice/secrets.json"]["classification"],
            "projection",
        )
        self.assertFalse(
            entries[".openclaw/workspace/secrets/vnu-eoffice/secrets.json"]["backup"]
        )
        self.assertEqual(entries[".config/openclaw/google-chat/*.json"]["mode"], "0600")
        address_book = entries[".openclaw/workspace/.address-book.json"]
        self.assertEqual(address_book["classification"], "private-state")
        self.assertTrue(address_book["backup"])
        self.assertEqual(address_book["portability"], "portable")
        wrangler = entries[".config/.wrangler/config/default.toml"]
        self.assertEqual(wrangler["classification"], "session")
        self.assertEqual(wrangler["portability"], "reauth-required")
        self.assertTrue(wrangler["backup"])
        self.assertEqual(manifest["dir_perms"][".config/.wrangler"], "0700")
        self.assertEqual(
            manifest["dir_perms"][".config/.wrangler/config"], "0700"
        )
        opencode = entries[".local/share/opencode/opencode.db"]
        self.assertEqual(opencode["classification"], "session")
        self.assertEqual(opencode["portability"], "reauth-required")
        self.assertTrue(opencode["backup"])
        self.assertEqual(opencode["capture"], "sqlite-backup")
        self.assertEqual(opencode["mode"], "0600")
        self.assertEqual(
            manifest["dir_perms"][".local/share/opencode"], "0700"
        )
        forms = entries[
            ".local/share/forms-private-keys/forms-backup-attestation-ed25519.pem"
        ]
        self.assertEqual(forms["classification"], "authority")
        self.assertEqual(forms["portability"], "portable")
        self.assertTrue(forms["backup"])
        self.assertEqual(
            entries[".claude.json"]["classification"], "private-state"
        )
        self.assertTrue(entries[".claude.json"]["backup"])
        for relative in (
            ".local/share/pki/nssdb/key4.db",
            ".local/share/pki/nssdb/cert9.db",
        ):
            self.assertEqual(entries[relative]["capture"], "sqlite-backup")
            self.assertEqual(entries[relative]["classification"], "private-state")
            self.assertTrue(entries[relative]["backup"])
        devices = entries[".openclaw/devices/"]
        self.assertEqual(devices["classification"], "session")
        self.assertEqual(devices["portability"], "machine-bound")
        self.assertTrue(devices["backup"])
        self.assertEqual(manifest["dir_perms"][".openclaw/devices"], "0700")
        global_state = entries[".openclaw/state/openclaw.sqlite"]
        self.assertEqual(global_state["classification"], "private-state")
        self.assertEqual(global_state["portability"], "portable")
        self.assertFalse(global_state["backup"])
        self.assertEqual(global_state["mode"], "0600")
        self.assertEqual(manifest["dir_perms"][".openclaw/state"], "0700")
        openclaw_policy = entries[".openclaw/file-delivery-policy.json"]
        self.assertEqual(openclaw_policy["classification"], "authority")
        self.assertEqual(openclaw_policy["portability"], "portable")
        self.assertFalse(openclaw_policy["backup"])
        self.assertEqual(manifest["dir_perms"][".openclaw"], "0700")
        queue = entries[".config/ai-agents-skills/file-delivery-queue.json"]
        self.assertEqual(queue["classification"], "authority")
        self.assertEqual(queue["portability"], "portable")
        self.assertTrue(queue["backup"])
        replay = entries[
            ".local/state/ai-agents-skills/file-delivery-replay/"
        ]
        self.assertEqual(replay["classification"], "private-state")
        self.assertEqual(replay["portability"], "portable")
        self.assertTrue(replay["backup"])
        self.assertEqual(
            manifest["dir_perms"][
                ".local/state/ai-agents-skills/file-delivery-replay"
            ],
            "0700",
        )

        source_contract = entries[
            ".config/coding-system/skill-credential-source-contract.json"
        ]
        signing_authority = entries[
            ".config/coding-system/recovery-signing"
        ]
        self.assertEqual(source_contract["legacy_import"], "generated")
        self.assertEqual(
            signing_authority["legacy_import"], "destination-authority"
        )
        self.assertTrue(source_contract["required"])
        self.assertTrue(signing_authority["required"])

        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(
            (ROOT / "secrets/secrets-manifest.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.validate(
            yaml.safe_load(MANIFEST.read_text(encoding="utf-8")), schema
        )

    def test_legacy_import_policy_is_bounded_to_required_backup_entries(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            path = fixture_manifest(Path(td) / "manifest.yaml")
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            entry = value["entries"][0]

            entry["legacy_import"] = "unknown-strategy"
            path.write_text(yaml.safe_dump(value), encoding="utf-8")
            with self.assertRaisesRegex(helper.RecoveryError, "legacy import policy"):
                helper.load_secrets_manifest(path)

            entry["legacy_import"] = "generated"
            entry["required"] = False
            path.write_text(yaml.safe_dump(value), encoding="utf-8")
            with self.assertRaisesRegex(helper.RecoveryError, "required backup entry"):
                helper.load_secrets_manifest(path)

            entry["required"] = True
            entry["legacy_import"] = "destination-authority"
            entry["classification"] = "private-state"
            entry["authority"] = entry["id"]
            path.write_text(yaml.safe_dump(value), encoding="utf-8")
            with self.assertRaisesRegex(helper.RecoveryError, "must be an authority"):
                helper.load_secrets_manifest(path)

    def test_sqlite_capture_policy_is_bounded_to_one_private_archived_database(self) -> None:
        helper = load_helper()
        mutations = (
            ("backup", False, "SQLite backup capture"),
            ("mode", "0644", "SQLite backup capture"),
            ("path", ".local/share/opencode/*.db", "SQLite backup capture"),
            ("capture", "raw-wal-copy", "capture policy"),
        )
        for field, changed, expected in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as td:
                path = fixture_manifest(Path(td) / "manifest.yaml")
                value = yaml.safe_load(path.read_text(encoding="utf-8"))
                entry = next(
                    item
                    for item in value["entries"]
                    if item["id"] == "opencode-native-session-store"
                )
                entry[field] = changed
                path.write_text(yaml.safe_dump(value), encoding="utf-8")
                with self.assertRaisesRegex(helper.RecoveryError, expected):
                    helper.load_secrets_manifest(path)

    def test_projection_must_reference_an_authority_and_is_not_archived(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            path = fixture_manifest(Path(td) / "manifest.yaml")
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            value["entries"][1]["backup"] = True
            path.write_text(yaml.safe_dump(value), encoding="utf-8")
            with self.assertRaisesRegex(helper.RecoveryError, "projection.*backup"):
                helper.load_secrets_manifest(path)

    def test_metadata_only_discovery_fails_on_unclassified_candidate(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            candidate = home / ".config/demo/new-token.json"
            candidate.parent.mkdir(parents=True)
            candidate.write_text("synthetic fixture", encoding="utf-8")
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )
            self.assertEqual(
                helper.discover_unclassified(home, manifest),
                [".config/demo/new-token.json"],
            )

    def test_structured_discovery_reports_only_generic_config_path_and_secret_field(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            codex = home / ".codex/config.toml"
            codex.parent.mkdir(parents=True)
            codex.write_text(
                '[provider]\napi_key = "literal-codex-canary"\n',
                encoding="utf-8",
            )
            skill_config = (
                home / ".openclaw/workspace/skills/user-provider/config.json"
            )
            skill_config.parent.mkdir(parents=True)
            skill_config.write_text(
                json.dumps(
                    {
                        "providers": {
                            "fixture": {"apiKey": "literal-model-canary"}  # LEAKSCAN-EXEMPT: synthetic fixture
                        }
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            observed = helper.discover_unclassified(home, manifest)

            self.assertEqual(
                observed,
                [
                    ".codex/config.toml#api_key",
                    ".openclaw/workspace/skills/user-provider/config.json#apikey",
                ],
            )
            rendered = "\n".join(observed)
            self.assertNotIn("literal-codex-canary", rendered)
            self.assertNotIn("literal-model-canary", rendered)

    def test_structured_discovery_ignores_placeholders_vendor_and_examples(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            values = {
                ".codex/config.toml": '[provider]\napi_key = "${OPENAI_API_KEY}"\n',
                ".openclaw/agents/main/agent/models.json": (
                    '{"providers":{"fixture":{"apiKey":"{{ secret_value }}"}}}\n'
                ),
                ".openclaw/workspace/vendor/provider/config.json": (
                    '{"api_key":"vendor-example-canary"}\n'  # LEAKSCAN-EXEMPT: synthetic fixture
                ),
                ".claude/plugins/demo/examples/settings.json": (
                    '{"token":"documentation-canary"}\n'  # LEAKSCAN-EXEMPT: synthetic fixture
                ),
            }
            for relative, payload in values.items():
                path = home / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(payload, encoding="utf-8")
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            self.assertEqual(helper.discover_unclassified(home, manifest), [])

    def test_structured_discovery_detects_camel_case_secret_fields(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            settings = home / ".codex/settings.json"
            settings.parent.mkdir(parents=True)
            settings.write_text(
                json.dumps(
                    {
                        "accessToken": "literal-access-canary",
                        "authToken": "literal-auth-canary",
                        "bearerToken": "literal-bearer-canary",
                        "clientSecret": "literal-client-canary",  # LEAKSCAN-EXEMPT: synthetic fixture
                        "privateKey": "literal-private-canary",
                        "refreshToken": "literal-refresh-canary",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            self.assertEqual(
                helper.discover_unclassified(home, manifest),
                [
                    ".codex/settings.json#accesstoken",
                    ".codex/settings.json#authtoken",
                    ".codex/settings.json#bearertoken",
                    ".codex/settings.json#clientsecret",
                    ".codex/settings.json#privatekey",
                    ".codex/settings.json#refreshtoken",
                ],
            )

    def test_structured_discovery_checks_nested_root_claude_mcp_fields(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            (home / ".claude.json").write_text(
                json.dumps(
                    {
                        "oauthAccount": {"email": "metadata@example.invalid"},
                        "projects": {
                            "/synthetic": {
                                "mcpServers": {
                                    "fixture": {
                                        "env": {
                                            "clientSecret": "nested-mcp-secret-canary"  # LEAKSCAN-EXEMPT: synthetic fixture
                                        }
                                    }
                                }
                            }
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )
            manifest["entries"] = [
                entry
                for entry in manifest["entries"]
                if entry["id"] != "claude-root-private-state"
            ]

            observed = helper.discover_unclassified(home, manifest)

            self.assertEqual(observed, [".claude.json#clientsecret"])
            self.assertNotIn("nested-mcp-secret-canary", "\n".join(observed))

    def test_discovery_covers_bounded_local_share_and_state_roots(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            nss = home / ".local/share/pki/nssdb"
            nss.mkdir(parents=True)
            database = nss / "key4.db"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE metadata (id INTEGER PRIMARY KEY)")
            connection.commit()
            connection.close()
            forms = (
                home
                / ".local/share/forms-private-keys/forms-backup-attestation-ed25519.pem"
            )
            forms.parent.mkdir(parents=True)
            forms.write_text("synthetic-private-key-canary\n", encoding="utf-8")
            local_token = home / ".local/state/example/token"
            local_token.parent.mkdir(parents=True)
            local_token.write_text("synthetic-local-token-canary\n", encoding="utf-8")
            skipped = (
                home
                / ".local/share/forms-private-backups/generation/private-key.pem"
            )
            skipped.parent.mkdir(parents=True)
            skipped.write_text("generated-backup-canary\n", encoding="utf-8")
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )
            manifest["entries"] = [
                entry
                for entry in manifest["entries"]
                if entry["id"]
                not in {
                    "forms-backup-attestation-authority",
                    "nss-private-key-database",
                }
            ]

            observed = helper.discover_unclassified(home, manifest)

            self.assertEqual(
                observed,
                [
                    ".local/share/forms-private-keys/forms-backup-attestation-ed25519.pem",
                    ".local/share/pki/nssdb/key4.db",
                    ".local/state/example/token",
                ],
            )
            rendered = "\n".join(observed)
            self.assertNotIn("synthetic-private-key-canary", rendered)
            self.assertNotIn("synthetic-local-token-canary", rendered)
            self.assertNotIn("generated-backup-canary", rendered)

    def test_structured_discovery_covers_wrangler_default_toml(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            config = home / ".config/.wrangler/config/default.toml"
            config.parent.mkdir(parents=True)
            config.write_text(
                'oauth_token = "literal-oauth-canary"\n'
                'refresh_token = "literal-refresh-canary"\n',
                encoding="utf-8",
            )
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )
            manifest["entries"] = [
                entry
                for entry in manifest["entries"]
                if entry["id"] != "wrangler-oauth-session"
            ]

            observed = helper.discover_unclassified(home, manifest)

            self.assertEqual(
                observed,
                [
                    ".config/.wrangler/config/default.toml#oauth_token",
                    ".config/.wrangler/config/default.toml#refresh_token",
                ],
            )
            self.assertNotIn("literal-oauth-canary", "\n".join(observed))
            self.assertNotIn("literal-refresh-canary", "\n".join(observed))

    def test_published_manifest_classifies_wrangler_default_toml(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "home"
            config = home / ".config/.wrangler/config/default.toml"
            config.parent.mkdir(parents=True)
            config.write_text(
                'oauth_token = "literal-oauth-canary"\n'
                'refresh_token = "literal-refresh-canary"\n',
                encoding="utf-8",
            )
            config.chmod(0o600)
            manifest = helper.load_secrets_manifest(MANIFEST)

            self.assertNotIn(
                ".config/.wrangler/config/default.toml#oauth_token",
                helper.discover_unclassified(home, manifest),
            )

    def test_sqlite_discovery_is_schema_only_and_fails_closed_when_undeclared(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            database = home / ".local/share/opencode/opencode.db"
            database.parent.mkdir(parents=True)
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE account (access_token TEXT, refresh_token TEXT, secret TEXT)"
            )
            connection.execute(
                "INSERT INTO account VALUES (?, ?, ?)",
                (
                    "row-access-canary-must-not-render",
                    "row-refresh-canary-must-not-render",
                    "row-secret-canary-must-not-render",
                ),
            )
            connection.commit()
            connection.close()
            database.chmod(0o600)
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )
            manifest["entries"] = [
                entry
                for entry in manifest["entries"]
                if entry["id"] != "opencode-native-session-store"
            ]

            observed = helper.discover_unclassified(home, manifest)

            self.assertEqual(
                observed,
                [
                    ".local/share/opencode/opencode.db#access_token",
                    ".local/share/opencode/opencode.db#refresh_token",
                    ".local/share/opencode/opencode.db#secret",
                ],
            )
            rendered = "\n".join(observed)
            self.assertNotIn("row-access-canary", rendered)
            self.assertNotIn("row-refresh-canary", rendered)
            self.assertNotIn("row-secret-canary", rendered)

    def test_published_manifest_classifies_opencode_sqlite_schema(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "home"
            database = home / ".local/share/opencode/opencode.db"
            database.parent.mkdir(parents=True)
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE account (access_token TEXT, refresh_token TEXT, secret TEXT)"
            )
            connection.commit()
            connection.close()
            database.chmod(0o600)

            observed = helper.discover_unclassified(
                home, helper.load_secrets_manifest(MANIFEST)
            )

            self.assertFalse(
                any(
                    item.startswith(".local/share/opencode/opencode.db")
                    for item in observed
                )
            )

    def test_openclaw_global_sqlite_discovery_is_schema_only_when_undeclared(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            database = home / ".openclaw/state/openclaw.sqlite"
            database.parent.mkdir(parents=True)
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE capability (private_key TEXT, private_key_pem TEXT)"
            )
            connection.execute(
                "INSERT INTO capability VALUES (?, ?)",
                (
                    "global-private-key-row-canary-must-not-render",
                    "global-private-pem-row-canary-must-not-render",
                ),
            )
            connection.commit()
            connection.close()
            database.chmod(0o600)
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )
            manifest["entries"] = [
                entry
                for entry in manifest["entries"]
                if entry["id"] != "openclaw-global-state-owner-input"
            ]

            observed = helper.discover_unclassified(home, manifest)

            self.assertEqual(
                observed,
                [
                    ".openclaw/state/openclaw.sqlite#private_key",
                    ".openclaw/state/openclaw.sqlite#private_key_pem",
                ],
            )
            rendered = "\n".join(observed)
            self.assertNotIn("global-private-key-row-canary", rendered)
            self.assertNotIn("global-private-pem-row-canary", rendered)

    def test_published_manifest_classifies_openclaw_global_sqlite_schema(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "home"
            database = home / ".openclaw/state/openclaw.sqlite"
            database.parent.mkdir(parents=True)
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE capability (private_key TEXT, private_key_pem TEXT)"
            )
            connection.commit()
            connection.close()
            database.chmod(0o600)

            observed = helper.discover_unclassified(
                home, helper.load_secrets_manifest(MANIFEST)
            )

            self.assertFalse(
                any(
                    item.startswith(".openclaw/state/openclaw.sqlite")
                    for item in observed
                )
            )

    def test_sqlite_discovery_ignores_codex_accounting_columns(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            database = home / ".codex/state.sqlite"
            database.parent.mkdir(parents=True)
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE usage (token_budget INTEGER, tokens_used INTEGER, ownership_token TEXT)"
            )
            connection.commit()
            connection.close()
            database.chmod(0o600)
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            self.assertEqual(helper.discover_unclassified(home, manifest), [])

    def test_sqlite_discovery_error_never_renders_database_bytes(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            database = home / ".local/share/opencode/broken.sqlite"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"malformed-row-secret-canary")
            database.chmod(0o600)
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            with self.assertRaises(helper.RecoveryError) as raised:
                helper.discover_unclassified(home, manifest)

            rendered = str(raised.exception)
            self.assertIn(".local/share/opencode/broken.sqlite", rendered)
            self.assertNotIn("malformed-row-secret-canary", rendered)

    def test_sqlite_discovery_skips_declared_databases_and_fails_closed_otherwise(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            declared = home / ".codex/logs_2.sqlite"
            declared.parent.mkdir(parents=True)
            connection = sqlite3.connect(declared)
            connection.execute("CREATE TABLE logs (access_token TEXT, message TEXT)")
            connection.commit()
            connection.close()
            path = fixture_manifest(root / "manifest.yaml")
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            value["entries"].append(
                {
                    "path": ".codex/logs_*.sqlite",
                    "mode": "0644",
                    "required": False,
                    "classification": "private-state",
                    "portability": "regenerated",
                    "backup": False,
                    "feature": "runtime log database",
                    "obtain": "recreated by the agent",
                }
            )
            path.write_text(yaml.safe_dump(value), encoding="utf-8")
            manifest = helper.load_secrets_manifest(path)

            with mock.patch.object(helper, "MAX_SECRET_FILE", 4096):
                self.assertGreater(declared.stat().st_size, 4096)
                self.assertEqual(helper.discover_unclassified(home, manifest), [])
                undeclared = home / ".codex/other.sqlite"
                undeclared.write_bytes(declared.read_bytes())
                with self.assertRaises(helper.RecoveryError) as raised:
                    helper.discover_unclassified(home, manifest)

            self.assertIn("cannot be inspected safely", str(raised.exception))

    def test_sqlite_discovery_reads_an_empty_database_as_schema_free(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            database = home / ".openclaw/workspace/data/calibre/metadata.db"
            database.parent.mkdir(parents=True)
            database.touch()
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            self.assertEqual(helper.discover_unclassified(home, manifest), [])

    def test_published_manifest_declares_codex_runtime_databases(self) -> None:
        helper = load_helper()
        manifest = helper.load_secrets_manifest(MANIFEST)
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "home"
            (home / ".codex").mkdir(parents=True)
            for name in ("logs_2.sqlite", "thread_history_1.sqlite"):
                connection = sqlite3.connect(home / ".codex" / name)
                connection.execute("CREATE TABLE items (secret TEXT)")
                connection.commit()
                connection.close()
                matching = [
                    entry
                    for entry in manifest["entries"]
                    if helper._entry_matches(entry, f".codex/{name}")
                ]
                self.assertEqual([entry["backup"] for entry in matching], [False])

            with mock.patch.object(helper, "MAX_SECRET_FILE", 4096):
                self.assertEqual(helper.discover_unclassified(home, manifest), [])

    def test_published_manifest_classifies_regenerated_and_kept_host_paths(self) -> None:
        helper = load_helper()
        manifest = helper.load_secrets_manifest(MANIFEST)
        component = "0" * 40
        regenerated_or_elsewhere = [
            f".local/share/coding-system/components/openclaw-bot/{component}/config/secrets.json.template",
            ".local/state/openclaw-bot/delivery-authorities/telegram/token",
            ".openclaw/workspace/data/projects/demo/.env",
            ".openclaw/workspace/data/research/zotero/staging/Token Sliding on Trees.pdf",
            ".openclaw/agents/host/qmd/xdg-cache/qmd/index.sqlite",
            ".openclaw/workspace/.openclaw/state/openclaw.sqlite",
            ".local/state/syncthing/key.pem",
            ".local/state/syncthing/index-v2/folder.0001-demo.db",
            ".config/go/telemetry/local/upload.token",
            ".claude/data/research/zotero/staging/Token Sliding on Trees.pdf",
            ".codex/runtime/workspace/data/research/zotero/staging/Token Sliding on Trees.pdf",
            ".codex/runtime/load_secret_env.py",
            ".codex/runtime/workspace/skills/demo/credential_client.py",
        ]
        kept = [
            ".config/course/google-classroom/tokens/demo.json",
            ".config/course/demo101/credentials.json",
            ".config/course/demo101/token.pickle",
            ".config/cursor/auth.json",
            ".config/chatgpt-local-coder/backup-secrets-20260101-000000.json",
            ".config/remote-bridge/secrets.json.bak-20260101",
            ".local/share/forms-private-keys/account-hard-delete-scope-secret-v1.txt.gpg",
            ".local/share/forms-private-keys/admin-local-deletion-secrets-v1.json.gpg",
        ]

        def capturing(relative: str) -> list[str]:
            return [
                entry["id"]
                for entry in manifest["entries"]
                if entry["backup"]
                and helper._entry_matches(entry, relative)
                and not helper._excluded(entry, relative)
            ]

        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "home"
            for relative in regenerated_or_elsewhere + kept + [".config/course/demo101/course.log"]:
                path = home / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                # Unreadable database bytes prove declared paths are never opened.
                path.write_bytes(b"not a database")
                path.chmod(0o600)

            self.assertEqual(helper.discover_unclassified(home, manifest), [])
        for relative in regenerated_or_elsewhere:
            self.assertEqual(capturing(relative), [], relative)
        for relative in kept:
            self.assertEqual(len(capturing(relative)), 1, relative)
        self.assertEqual(capturing(".config/course/demo101/course.log"), [])
        for relative in (
            ".config/course/google-classroom/credentials.json",
            ".config/course/canvas/config.json",
        ):
            self.assertEqual(len(capturing(relative)), 1, relative)

    def test_structured_discovery_ignores_only_exact_secret_refs(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            settings = home / ".codex/settings.json"
            settings.parent.mkdir(parents=True)
            settings.write_text(
                json.dumps(
                    {
                        "apiKey": {
                            "source": "env",
                            "provider": "default",
                            "id": "OPENAI_API_KEY",
                        },
                        "clientSecret": {
                            "source": "env",
                            "provider": "default",
                            "id": "CLIENT_SECRET",
                            "fallback": "literal-fallback-canary",
                        },
                        "refreshToken": {
                            "source": "env",
                            "id": "REFRESH_TOKEN",
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            observed = helper.discover_unclassified(home, manifest)

            self.assertEqual(
                observed,
                [
                    ".codex/settings.json#clientsecret",
                    ".codex/settings.json#refreshtoken",
                ],
            )
            self.assertNotIn("literal-fallback-canary", "\n".join(observed))

    def test_copilot_jsonc_discovery_is_comment_and_string_aware(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            config = home / ".copilot/config.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                """// leading comment
{
  "endpoint": "https://example.invalid/path//still-a-string",
  /* bounded block comment */
  "clientSecret": "literal-jsonc-canary" // trailing comment, LEAKSCAN-EXEMPT: synthetic fixture
}
""",
                encoding="utf-8",
            )
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            observed = helper.discover_unclassified(home, manifest)

            self.assertEqual(
                observed,
                [".copilot/config.json#clientsecret"],
            )
            self.assertNotIn("literal-jsonc-canary", "\n".join(observed))

    def test_copilot_jsonc_parse_error_names_only_the_relative_path(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            config = home / ".copilot/config.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                '// comment\n{"token":"first-canary","token":"second-canary"}\n',
                encoding="utf-8",
            )
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            with self.assertRaises(helper.RecoveryError) as raised:
                helper.discover_unclassified(home, manifest)

            rendered = str(raised.exception)
            self.assertIn(
                'cannot be inspected safely: ".copilot/config.json"', rendered
            )
            self.assertNotIn("first-canary", rendered)
            self.assertNotIn("second-canary", rendered)

    def test_published_owner_input_classifies_models_secret_fields(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            models = home / ".openclaw/agents/main/agent/models.json"
            models.parent.mkdir(parents=True)
            models.write_text(
                '{"providers":{"fixture":{"apiKey":"owner-only-canary"}}}\n',
                encoding="utf-8",
            )
            models.chmod(0o600)
            manifest = helper.load_secrets_manifest(MANIFEST)

            self.assertNotIn(
                ".openclaw/agents/main/agent/models.json#apikey",
                helper.discover_unclassified(home, manifest),
            )

    def test_discovery_covers_common_agent_credential_roots(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            for relative in (
                ".bashrc.pre-coding-system",
                ".cache/huggingface/token",
                ".codex/auth.json.bak.20260805",
                ".config/example/auth/session-state.json",
                ".config/example/api-key.txt",
                ".config/example/secrets/opaque.json",
                ".gauss/.env",
                ".git-credentials",
                ".huggingface/token",
                ".kaggle/kaggle.json",
                ".npmrc.pre-coding-system",
                ".pypirc",
                ".profile.pre-coding-system",
            ):
                candidate = home / relative
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_text("synthetic fixture", encoding="utf-8")
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            self.assertEqual(
                helper.discover_unclassified(home, manifest),
                [
                    ".bashrc.pre-coding-system",
                    ".cache/huggingface/token",
                    ".codex/auth.json.bak.20260805",
                    ".config/example/api-key.txt",
                    ".config/example/auth/session-state.json",
                    ".config/example/secrets/opaque.json",
                    ".gauss/.env",
                    ".git-credentials",
                    ".huggingface/token",
                    ".kaggle/kaggle.json",
                    ".npmrc.pre-coding-system",
                    ".profile.pre-coding-system",
                    ".pypirc",
                ],
            )

    def test_discovery_covers_forms_checkout_local_secret_files(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            candidates = (
                "forms/apps/classroom50-runner/.env",
                "forms/apps/api/.dev.vars",
                "forms/apps/web/.env.local",
            )
            for relative in candidates:
                candidate = home / relative
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_text("SYNTHETIC=value\n", encoding="utf-8")
            manifest_path = fixture_manifest(root / "manifest.yaml")
            manifest_value = yaml.safe_load(
                manifest_path.read_text(encoding="utf-8")
            )
            manifest_value["entries"] = [
                entry
                for entry in manifest_value["entries"]
                if entry["path"] not in candidates
            ]
            manifest_path.write_text(
                yaml.safe_dump(manifest_value), encoding="utf-8"
            )
            manifest = helper.load_secrets_manifest(manifest_path)

            self.assertEqual(
                helper.discover_unclassified(home, manifest),
                sorted(candidates),
            )

            published = helper.load_secrets_manifest(MANIFEST)
            self.assertEqual(helper.discover_unclassified(home, published), [])

    def test_backup_source_metadata_must_match_the_private_manifest_contract(self) -> None:
        helper = load_helper()
        entry = {"id": "fixture", "mode": "0600"}
        good = mock.Mock(
            st_uid=os.geteuid(),
            st_nlink=1,
            st_mode=stat.S_IFREG | 0o600,
        )
        helper._validate_manifest_source_metadata(good, entry)

        cases = (
            ("owned", {"st_uid": os.geteuid() + 1}),
            ("link", {"st_nlink": 2}),
            ("permissions", {"st_mode": stat.S_IFREG | 0o644}),
        )
        for label, replacement in cases:
            with self.subTest(label=label):
                bad = mock.Mock(
                    st_uid=replacement.get("st_uid", os.geteuid()),
                    st_nlink=replacement.get("st_nlink", 1),
                    st_mode=replacement.get("st_mode", stat.S_IFREG | 0o600),
                )
                with self.assertRaisesRegex(helper.RecoveryError, label):
                    helper._validate_manifest_source_metadata(bad, entry)

    def test_backup_source_permissions_compare_only_bits_other_users_reach(self) -> None:
        helper = load_helper()
        entry = {"id": "fixture", "mode": "0600"}

        def source(mode: int) -> mock.Mock:
            return mock.Mock(st_uid=os.geteuid(), st_nlink=1, st_mode=stat.S_IFREG | mode)

        # Owner bits and narrower modes never widen what other users can read.
        helper._validate_manifest_source_metadata(source(0o700), entry)
        helper._validate_manifest_source_metadata(source(0o400), entry)
        helper._validate_manifest_source_metadata(source(0o664), {"id": "notes", "mode": "0664"})
        with self.assertRaisesRegex(helper.RecoveryError, "permissions"):
            helper._validate_manifest_source_metadata(source(0o664), {"id": "notes", "mode": "0644"})
        # Bits that other users cannot reach through the home are not compared.
        helper._validate_manifest_source_metadata(source(0o664), entry, 0)
        with self.assertRaisesRegex(helper.RecoveryError, "permissions"):
            helper._validate_manifest_source_metadata(source(0o640), entry, 0o070)
        helper._validate_manifest_source_metadata(source(0o604), entry, 0o070)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            authority = home / ".config/demo/secret.json"
            authority.parent.mkdir(parents=True)
            authority.write_text("synthetic\n", encoding="utf-8")
            authority.chmod(0o664)
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            home.chmod(0o700)
            self.assertIn(
                ".config/demo/secret.json",
                helper.enumerate_manifest_files(home, manifest),
            )
            home.chmod(0o750)
            with self.assertRaisesRegex(helper.RecoveryError, "permissions"):
                helper.enumerate_manifest_files(home, manifest)
            home.chmod(0o711)
            with self.assertRaisesRegex(helper.RecoveryError, "permissions"):
                helper.enumerate_manifest_files(home, manifest)

    def test_manifest_enumeration_rejects_broad_or_hardlinked_backup_sources(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            authority = home / ".config/demo/secret.json"
            authority.parent.mkdir(parents=True)
            authority.write_text("synthetic\n", encoding="utf-8")
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )

            home.chmod(0o755)
            authority.chmod(0o644)
            with self.assertRaisesRegex(helper.RecoveryError, "permissions"):
                helper.enumerate_manifest_files(home, manifest)

            authority.chmod(0o600)
            os.link(authority, root / "second-link")
            with self.assertRaisesRegex(helper.RecoveryError, "exactly one link"):
                helper.enumerate_manifest_files(home, manifest)

    def test_skill_config_is_scanned_but_generated_sandbox_copy_is_skipped(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            live = home / ".openclaw/workspace/skills/new-provider/config.json"
            generated = (
                home
                / ".openclaw/sandbox/runtime/skills/new-provider/config.json"
            )
            live.parent.mkdir(parents=True)
            generated.parent.mkdir(parents=True)
            live.write_text("{}\n", encoding="utf-8")
            generated.write_text("{}\n", encoding="utf-8")
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )
            self.assertEqual(
                helper.discover_unclassified(home, manifest),
                [".openclaw/workspace/skills/new-provider/config.json"],
            )

    def test_generated_marketplace_is_skipped_but_user_npmrc_is_scanned(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            generated = (
                home
                / ".claude/plugins/marketplaces/vendor/external_plugins/demo/.npmrc"
            )
            live = home / ".claude/plugins/user-plugin/.npmrc"
            generated.parent.mkdir(parents=True)
            live.parent.mkdir(parents=True)
            generated.write_text("registry=https://registry.npmjs.org\n", encoding="utf-8")
            live.write_text("synthetic fixture\n", encoding="utf-8")
            manifest = helper.load_secrets_manifest(
                fixture_manifest(root / "manifest.yaml")
            )
            self.assertEqual(
                helper.discover_unclassified(home, manifest),
                [".claude/plugins/user-plugin/.npmrc"],
            )

    def test_available_commit_must_contain_the_exact_manifest_bytes(self) -> None:
        helper = load_helper()
        raw = b"synthetic immutable manifest bytes\n"
        digest = hashlib.sha256(raw).hexdigest()
        with mock.patch.object(helper, "_git_manifest_at_commit", return_value=raw):
            helper._bind_manifest_to_commit(raw, digest, "a" * 40)
        with mock.patch.object(
            helper, "_git_manifest_at_commit", return_value=b"different bytes\n"
        ):
            with self.assertRaisesRegex(helper.RecoveryError, "referenced.*commit"):
                helper._bind_manifest_to_commit(raw, digest, "a" * 40)


@unittest.skipUnless(Path("/usr/bin/ssh-keygen").is_file(), "ssh-keygen is required")
class LegacySigningAuthorityStageTests(unittest.TestCase):
    def _new_key(self, root: Path, name: str = "recovery-signing") -> tuple[Path, Path]:
        key = root / name
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
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return key, key.with_suffix(".pub")

    @staticmethod
    def _destination_home(root: Path) -> Path:
        home = root / "stage-home"
        target_parent = home / ".config/coding-system"
        target_parent.mkdir(mode=0o700, parents=True)
        home.chmod(0o700)
        (home / ".config").chmod(0o700)
        target_parent.chmod(0o700)
        return home

    @staticmethod
    def _trusted_digest(public_key: Path) -> str:
        return hashlib.sha256(public_key.read_bytes()).hexdigest()

    def test_stages_destination_authority_only_after_pinned_public_match(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key, public_key = self._new_key(root)
            home = self._destination_home(root)
            target = home / ".config/coding-system/recovery-signing"
            target.write_bytes(b"synthetic stale staging content\n")
            target.chmod(0o600)

            helper.stage_legacy_signing_authority(
                key,
                home,
                public_key,
                expected_public_key_sha256=self._trusted_digest(public_key),
            )

            self.assertEqual(target.read_bytes(), key.read_bytes())
            info = target.stat()
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)

    def test_public_key_mismatch_does_not_replace_existing_stage_file(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key, _public_key = self._new_key(root, "source")
            _other_key, other_public = self._new_key(root, "other")
            home = self._destination_home(root)
            target = home / ".config/coding-system/recovery-signing"
            original = b"synthetic preexisting stage file\n"
            target.write_bytes(original)
            target.chmod(0o600)

            with self.assertRaisesRegex(helper.RecoveryError, "trust root mismatch"):
                helper.stage_legacy_signing_authority(
                    key,
                    home,
                    other_public,
                    expected_public_key_sha256=self._trusted_digest(other_public),
                )

            self.assertEqual(target.read_bytes(), original)
            self.assertFalse(any(target.parent.glob(".recovery-signing.tmp-*")))

    def test_rejects_unsafe_source_metadata_and_path_components(self) -> None:
        helper = load_helper()
        cases = (
            "symlink",
            "broad-mode",
            "narrow-mode",
            "hardlink",
            "empty",
            "oversized",
            "parent-symlink",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                key, public_key = self._new_key(root, "source")
                source = key
                if case == "symlink":
                    source = root / "source-link"
                    source.symlink_to(key)
                elif case == "broad-mode":
                    key.chmod(0o640)
                elif case == "narrow-mode":
                    key.chmod(0o400)
                elif case == "hardlink":
                    os.link(key, root / "second-link")
                elif case == "empty":
                    key.write_bytes(b"")
                    key.chmod(0o600)
                elif case == "oversized":
                    key.write_bytes(b"x" * (helper.MAX_RECOVERY_SIGNING_KEY_BYTES + 1))
                    key.chmod(0o600)
                elif case == "parent-symlink":
                    real = root / "real"
                    real.mkdir(mode=0o700)
                    moved = real / "source"
                    key.rename(moved)
                    source_parent = root / "linked"
                    source_parent.symlink_to(real, target_is_directory=True)
                    source = source_parent / "source"

                with self.assertRaises(helper.RecoveryError):
                    helper.stage_legacy_signing_authority(
                        source,
                        self._destination_home(root),
                        public_key,
                        expected_public_key_sha256=self._trusted_digest(public_key),
                    )

    def test_rejects_non_owner_source(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key, public_key = self._new_key(root)
            real_fstat = os.fstat

            def foreign_regular(descriptor: int):
                info = real_fstat(descriptor)
                if stat.S_ISREG(info.st_mode):
                    return mock.Mock(
                        st_mode=info.st_mode,
                        st_uid=os.geteuid() + 1,
                        st_dev=info.st_dev,
                        st_ino=info.st_ino,
                        st_nlink=info.st_nlink,
                        st_size=info.st_size,
                        st_mtime_ns=info.st_mtime_ns,
                        st_ctime_ns=info.st_ctime_ns,
                    )
                return info

            with mock.patch.object(helper.os, "fstat", side_effect=foreign_regular):
                with self.assertRaisesRegex(helper.RecoveryError, "owned by the caller"):
                    helper.stage_legacy_signing_authority(
                        key,
                        self._destination_home(root),
                        public_key,
                        expected_public_key_sha256=self._trusted_digest(public_key),
                    )

    def test_rejects_source_path_swap_during_capture(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key, public_key = self._new_key(root, "source")
            replacement, _replacement_public = self._new_key(root, "replacement")
            original_read = helper._read_fd
            swapped = False

            def read_then_swap(descriptor: int, limit: int) -> bytes:
                nonlocal swapped
                raw = original_read(descriptor, limit)
                if not swapped:
                    key.rename(root / "captured-source")
                    replacement.rename(key)
                    swapped = True
                return raw

            with mock.patch.object(helper, "_read_fd", side_effect=read_then_swap):
                with self.assertRaisesRegex(helper.RecoveryError, "changed while reading"):
                    helper.stage_legacy_signing_authority(
                        key,
                        self._destination_home(root),
                        public_key,
                        expected_public_key_sha256=self._trusted_digest(public_key),
                    )


class EscrowContractTests(unittest.TestCase):
    def test_all_six_pairs_recover_one_immutable_2_of_4_generation(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            master = root / "master.key"
            generation_dir = root / "generation"
            manifest_path = helper.create_escrow_generation(generation_dir, master)
            manifest = helper.load_escrow_manifest(manifest_path)
            shares = sorted(generation_dir.glob("share-*.txt"))
            self.assertEqual(len(shares), 4)
            self.assertEqual(manifest["threshold"], 2)
            self.assertEqual(manifest["shares"], 4)
            expected = master.read_bytes().rstrip(b"\n")
            for pair in itertools.combinations(shares, 2):
                self.assertEqual(
                    helper.recover_master_from_share_files(manifest, list(pair)),
                    expected,
                )
            with self.assertRaisesRegex(helper.RecoveryError, "already exists"):
                helper.create_escrow_generation(generation_dir, root / "other.key")

            try:
                import jsonschema
            except ImportError:
                self.skipTest("jsonschema is not installed")
            schema = json.loads(
                (ROOT / "secrets/escrow-generation.schema.json").read_text(encoding="utf-8")
            )
            jsonschema.validate(manifest, schema)

    def test_recovery_writes_master_to_file_not_stdout(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            master = root / "master.key"
            generation = root / "generation"
            manifest_path = helper.create_escrow_generation(generation, master)
            recovered = root / "recovered.key"
            helper.recover_master_to_file(
                manifest_path,
                sorted(generation.glob("share-*.txt"))[:2],
                recovered,
            )
            self.assertEqual(recovered.read_bytes(), master.read_bytes())
            self.assertEqual(stat.S_IMODE(recovered.stat().st_mode), 0o600)

    def test_existing_master_is_never_altered_or_unlinked_on_refusal(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            master = root / "master.key"
            original = b"operator-owned-existing-master\n"
            master.write_bytes(original)
            master.chmod(0o600)
            original_inode = master.stat().st_ino
            generation = root / "generation"

            with self.assertRaisesRegex(helper.RecoveryError, "overwrite"):
                helper.create_escrow_generation(generation, master)

            self.assertEqual(master.read_bytes(), original)
            self.assertEqual(master.stat().st_ino, original_inode)
            self.assertFalse(generation.exists())

    def test_hardlinked_share_is_rejected(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            master = root / "master.key"
            generation = root / "generation"
            manifest_path = helper.create_escrow_generation(generation, master)
            manifest = helper.load_escrow_manifest(manifest_path)
            shares = sorted(generation.glob("share-*.txt"))[:2]
            alias = root / "share-alias.txt"
            os.link(shares[0], alias)
            with self.assertRaisesRegex(helper.RecoveryError, "exactly one link"):
                helper.recover_master_from_share_files(manifest, shares)


class ArchiveBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = load_helper()

    def make_tar(self, path: Path, members: list[tuple[str, bytes, str]]) -> None:
        with tarfile.open(path, "w") as archive:
            for name, payload, kind in members:
                info = tarfile.TarInfo(name)
                info.mode = 0o600
                if kind == "file":
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "target"
                    archive.addfile(info)
                else:
                    raise AssertionError(kind)

    def test_rejects_traversal_links_duplicates_and_unknown_members(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manifest_path = fixture_manifest(root / "manifest.yaml")
            manifest = self.helper.load_secrets_manifest(manifest_path)
            cases = [
                [("../escape", b"x", "file")],
                [(".config/demo/secret.json", b"", "symlink")],
                [
                    (".config/demo/secret.json", b"x", "file"),
                    (".config/demo/secret.json", b"y", "file"),
                ],
                [(".config/demo/not-declared", b"x", "file")],
            ]
            for index, members in enumerate(cases):
                archive = root / f"bad-{index}.tar"
                self.make_tar(archive, members)
                with self.subTest(index=index), self.assertRaises(self.helper.RecoveryError):
                    self.helper.validate_tar_archive(archive, manifest, "secrets")

    def test_restore_refuses_a_symlink_destination_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            stage.chmod(0o700)
            source = stage / ".config/demo/secret.json"
            source.parent.mkdir(parents=True)
            source.write_text("fixture", encoding="utf-8")
            source.chmod(0o600)
            destination = root / "home"
            destination.mkdir()
            destination.chmod(0o700)
            outside = root / "outside"
            outside.mkdir()
            (destination / ".config").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(self.helper.RecoveryError, "symlink|unsafe"):
                self.helper.apply_staged_tree(
                    stage,
                    destination,
                    {".config/demo/secret.json": 0o600},
                    replace=False,
                )

    def test_apply_rolls_back_every_prior_replacement_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            stage = root / "stage"
            destination = root / "home"
            stage.mkdir(mode=0o700)
            stage.chmod(0o700)
            (stage / ".config/demo").mkdir(parents=True)
            (destination / ".config/demo").mkdir(parents=True)
            destination.chmod(0o700)
            (destination / ".config").chmod(0o700)
            (destination / ".config/demo").chmod(0o700)
            modes = {}
            for name in ("a.json", "b.json"):
                relative = f".config/demo/{name}"
                (stage / relative).write_text(f"new-{name}\n", encoding="utf-8")
                (destination / relative).write_text(f"old-{name}\n", encoding="utf-8")
                (stage / relative).chmod(0o600)
                (destination / relative).chmod(0o600)
                modes[relative] = 0o600
            transaction_module = sys.modules["restore_transaction"]
            real_install = transaction_module._install_open_source
            calls = 0

            def fail_second(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise transaction_module.RestoreTransactionError(
                        "synthetic install failure"
                    )
                return real_install(*args, **kwargs)

            with mock.patch.object(
                transaction_module, "_install_open_source", side_effect=fail_second
            ):
                with self.assertRaisesRegex(
                    self.helper.RecoveryError, "synthetic install failure"
                ):
                    self.helper.apply_staged_tree(
                        stage, destination, modes, replace=True
                    )
            for name in ("a.json", "b.json"):
                self.assertEqual(
                    (destination / f".config/demo/{name}").read_text(encoding="utf-8"),
                    f"old-{name}\n",
                )
            self.assertEqual(
                list((destination / ".config/demo").glob(".csr-*")), []
            )


class OwnerDataSourceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = load_helper()

    def source_home(self, root: Path) -> Path:
        home = root / "home"
        home.mkdir(mode=0o700)
        return home

    def agent_directory(self, home: Path, agent_id: str = "main") -> Path:
        return owner_private_directory(
            home / f".openclaw/agents/{agent_id}/agent"
        )

    @staticmethod
    def global_wal_database(home: Path) -> tuple[Path, sqlite3.Connection]:
        state = owner_private_directory(home / ".openclaw/state")
        database = state / "openclaw.sqlite"
        connection = sqlite3.connect(database)
        if connection.execute("PRAGMA journal_mode = WAL").fetchone() != ("wal",):
            connection.close()
            raise AssertionError("fixture did not enter WAL mode")
        connection.executescript(
            """
            PRAGMA user_version = 1;
            CREATE TABLE schema_meta (
              meta_key TEXT PRIMARY KEY, role TEXT NOT NULL,
              schema_version INTEGER NOT NULL, agent_id TEXT,
              app_version TEXT, created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );
            CREATE TABLE global_capability (
              capability_key TEXT PRIMARY KEY, private_key TEXT,
              private_key_pem TEXT
            );
            INSERT INTO schema_meta VALUES
              ('primary', 'global', 1, NULL, 'fixture', 1, 1);
            INSERT INTO global_capability VALUES
              ('primary', 'global-private-key-canary-a', 'global-private-pem-canary-a');
            """
        )
        connection.commit()
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(os.fspath(database) + suffix)
            if candidate.exists():
                candidate.chmod(0o600)
        return database, connection

    def test_unconfigured_source_is_optional_and_state_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self.source_home(Path(td))
            first = self.helper.openclaw_private_source_state(home, b"x" * 32)
            second = self.helper.openclaw_private_source_state(home, b"x" * 32)
            self.assertEqual(first, second)
            self.assertFalse(first[0])

    def test_nonplaceholder_models_json_requires_owner_data(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self.source_home(Path(td))
            agent = self.agent_directory(home)
            models = write_owner_private_json(
                agent / "models.json",
                {"providers": {"fixture": {"apiKey": "configured-canary"}}},
            )
            configured, initial = self.helper.openclaw_private_source_state(
                home, b"x" * 32
            )
            self.assertTrue(configured)

            write_owner_private_json(
                models,
                {"providers": {"fixture": {"apiKey": "<redacted>"}}},
            )
            configured, replaced = self.helper.openclaw_private_source_state(
                home, b"x" * 32
            )
            self.assertFalse(configured)
            self.assertNotEqual(initial, replaced)

    def test_canonical_sqlite_auth_row_requires_owner_data(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self.source_home(Path(td))
            database = self.agent_directory(home) / "openclaw-agent.sqlite"
            connection = sqlite3.connect(database)
            try:
                connection.executescript(
                    """
                    PRAGMA user_version = 1;
                    CREATE TABLE schema_meta (
                      meta_key TEXT PRIMARY KEY, role TEXT NOT NULL,
                      schema_version INTEGER NOT NULL, agent_id TEXT,
                      app_version TEXT, created_at INTEGER NOT NULL,
                      updated_at INTEGER NOT NULL
                    );
                    CREATE TABLE auth_profile_store (
                      store_key TEXT PRIMARY KEY, store_json TEXT NOT NULL,
                      updated_at INTEGER NOT NULL
                    );
                    CREATE TABLE auth_profile_state (
                      state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL,
                      updated_at INTEGER NOT NULL
                    );
                    INSERT INTO schema_meta VALUES
                      ('primary', 'agent', 1, 'main', NULL, 1, 1);
                    INSERT INTO auth_profile_store VALUES
                      ('profiles', '{"fixture":{"key":"configured-canary"}}', 1);
                    """
                )
                connection.commit()
            finally:
                connection.close()
            database.chmod(0o600)
            configured, _state = self.helper.openclaw_private_source_state(
                home, b"x" * 32
            )
            self.assertTrue(configured)

    def test_global_wal_state_is_bound_transactionally_without_rendering_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self.source_home(Path(td))
            database, connection = self.global_wal_database(home)
            try:
                configured, initial = self.helper.openclaw_private_source_state(
                    home, b"x" * 32
                )
                configured_again, stable = self.helper.openclaw_private_source_state(
                    home, b"x" * 32
                )
                self.assertTrue(configured)
                self.assertTrue(configured_again)
                self.assertEqual(initial, stable)

                connection.execute(
                    "UPDATE global_capability SET private_key = ? WHERE capability_key = ?",
                    ("global-private-key-canary-b", "primary"),
                )
                connection.commit()
                for suffix in ("", "-wal", "-shm"):
                    candidate = Path(os.fspath(database) + suffix)
                    if candidate.exists():
                        candidate.chmod(0o600)
                configured_changed, changed = (
                    self.helper.openclaw_private_source_state(home, b"x" * 32)
                )
                self.assertTrue(configured_changed)
                self.assertNotEqual(initial, changed)
                self.assertNotIn("global-private-key-canary", changed)
                self.assertNotIn("global-private-pem-canary", changed)
            finally:
                connection.close()

    def test_global_state_rejects_wrong_owner_version_and_unsafe_sidecars(self) -> None:
        mutations = {
            "wrong-owner": "UPDATE schema_meta SET role = 'agent' WHERE meta_key = 'primary'",
            "wrong-version": "PRAGMA user_version = 2",
        }
        for label, statement in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as td:
                home = self.source_home(Path(td))
                database, connection = self.global_wal_database(home)
                try:
                    connection.execute(statement)
                    connection.commit()
                    for suffix in ("", "-wal", "-shm"):
                        candidate = Path(os.fspath(database) + suffix)
                        if candidate.exists():
                            candidate.chmod(0o600)
                    with self.assertRaisesRegex(
                        self.helper.RecoveryError,
                        "ownership is invalid|schema is unsupported",
                    ):
                        self.helper.openclaw_private_source_state(home, b"x" * 32)
                finally:
                    connection.close()

        with tempfile.TemporaryDirectory() as td:
            home = self.source_home(Path(td))
            database, connection = self.global_wal_database(home)
            try:
                wal = Path(os.fspath(database) + "-wal")
                self.assertTrue(wal.exists())
                wal.chmod(0o644)
                with self.assertRaisesRegex(
                    self.helper.RecoveryError, "global state database is unsafe"
                ):
                    self.helper.openclaw_private_source_state(home, b"x" * 32)
            finally:
                connection.close()

    def test_verified_extraction_state_matches_logically_and_rejects_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "live").mkdir(mode=0o700)
            home = self.source_home(root / "live")
            _live_database, live_connection = self.global_wal_database(home)
            extraction = root / "extracted"
            payload_state = (
                extraction
                / "recovery-quarantine/archive-authority/payload/state"
            )
            payload_state.mkdir(parents=True)
            current = payload_state
            while True:
                current.chmod(0o700)
                if current == extraction:
                    break
                current = current.parent
            extracted_database = payload_state / "openclaw.sqlite"
            (root / "archive-source").mkdir(mode=0o700)
            archive_home = self.source_home(root / "archive-source")
            archive_database, extracted = self.global_wal_database(archive_home)
            try:
                extracted.execute(
                    "INSERT INTO global_capability VALUES (?, ?, ?)",
                    ("transient", "discarded", "discarded"),
                )
                extracted.execute(
                    "DELETE FROM global_capability WHERE capability_key = ?",
                    ("transient",),
                )
                extracted.commit()
            finally:
                extracted.close()
            os.replace(archive_database, extracted_database)
            extracted_database.chmod(0o600)
            key = b"x" * 32
            try:
                live_configured, live_state = (
                    self.helper.openclaw_private_source_state(home, key)
                )
                archive_configured, archive_state = (
                    self.helper.openclaw_extracted_source_state(extraction, key)
                )
                self.assertTrue(live_configured)
                self.assertTrue(archive_configured)
                self.assertEqual(live_state, archive_state)

                extracted = sqlite3.connect(extracted_database)
                try:
                    extracted.execute(
                        "UPDATE global_capability SET private_key = ? "
                        "WHERE capability_key = 'primary'",
                        ("archive-mismatch-canary",),
                    )
                    extracted.commit()
                finally:
                    extracted.close()
                extracted_database.chmod(0o600)
                _configured, mismatched = (
                    self.helper.openclaw_extracted_source_state(extraction, key)
                )
                self.assertNotEqual(live_state, mismatched)
                self.assertNotIn("archive-mismatch-canary", mismatched)
            finally:
                live_connection.close()

    def test_host_file_delivery_authority_is_bound_even_when_deny_all(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self.source_home(Path(td))
            policy = write_owner_private_json(
                home / ".openclaw/file-delivery-policy.json",
                {
                    "schema": "openclaw.file-delivery-policy/v1",
                    "delivery_policy": {
                        "allowed_targets": {
                            "telegram": [],
                            "zulip": [],
                            "googlechat": [],
                            "whatsapp": [],
                            "zalo": [],
                        }
                    },
                },
            )
            configured, initial = self.helper.openclaw_private_source_state(
                home, b"x" * 32
            )
            self.assertTrue(configured)
            value = json.loads(policy.read_text(encoding="utf-8"))
            value["delivery_policy"]["allowed_targets"]["telegram"] = [
                "approved-fixture"
            ]
            write_owner_private_json(policy, value)
            configured, replaced = self.helper.openclaw_private_source_state(
                home, b"x" * 32
            )
            self.assertTrue(configured)
            self.assertNotEqual(initial, replaced)

    def test_malformed_file_delivery_authority_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self.source_home(Path(td))
            policy = home / ".openclaw/file-delivery-policy.json"
            owner_private_directory(policy.parent)
            policy.write_text(
                '{"schema":"openclaw.file-delivery-policy/v1",'
                '"schema":"openclaw.file-delivery-policy/v1",'
                '"delivery_policy":{"allowed_targets":{}}}\n',
                encoding="utf-8",
            )
            policy.chmod(0o600)
            with self.assertRaisesRegex(
                self.helper.RecoveryError, "duplicate JSON mapping key"
            ):
                self.helper.openclaw_private_source_state(home, b"x" * 32)


class SQLiteCaptureTests(unittest.TestCase):
    @staticmethod
    def make_wal_database(home: Path) -> tuple[Path, sqlite3.Connection]:
        database = home / ".local/share/opencode/opencode.db"
        database.parent.mkdir(parents=True)
        database.parent.chmod(0o700)
        connection = sqlite3.connect(database)
        self_journal = connection.execute("PRAGMA journal_mode = WAL").fetchone()
        if self_journal != ("wal",):
            connection.close()
            raise AssertionError("fixture did not enter WAL mode")
        connection.execute(
            "CREATE TABLE account (id INTEGER PRIMARY KEY, access_token TEXT, refresh_token TEXT)"
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute(
            "INSERT INTO account(access_token, refresh_token) VALUES (?, ?)",
            ("committed-access-canary", "committed-refresh-canary"),
        )
        connection.commit()
        for suffix in ("", "-wal", "-shm"):
            path = Path(os.fspath(database) + suffix)
            if path.exists():
                path.chmod(0o600)
        return database, connection

    @staticmethod
    def fixture_entry(helper, root: Path) -> tuple[dict, dict]:
        manifest = helper.load_secrets_manifest(
            fixture_manifest(root / "manifest.yaml")
        )
        entry = next(
            item
            for item in manifest["entries"]
            if item["id"] == "opencode-native-session-store"
        )
        return manifest, entry

    def test_transactional_snapshot_is_valid_during_active_wal_mutation(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir(mode=0o700)
            database, writer = self.make_wal_database(home)
            _manifest, entry = self.fixture_entry(helper, root)
            wal_path = Path(os.fspath(database) + "-wal")
            self.assertTrue(wal_path.is_file())
            self.assertGreater(wal_path.stat().st_size, 0)
            writer.execute("BEGIN IMMEDIATE")
            writer.execute(
                "INSERT INTO account(access_token, refresh_token) VALUES (?, ?)",
                ("uncommitted-access-canary", "uncommitted-refresh-canary"),
            )
            root_fd = helper._open_directory_path(home)
            try:
                payload = helper._snapshot_sqlite_capture(
                    home,
                    root_fd,
                    ".local/share/opencode/opencode.db",
                    entry,
                )
            finally:
                os.close(root_fd)
                writer.rollback()
                writer.close()

            snapshot = root / "snapshot.sqlite"
            snapshot.write_bytes(payload)
            snapshot.chmod(0o600)
            captured = sqlite3.connect(snapshot)
            try:
                self.assertEqual(captured.execute("PRAGMA quick_check").fetchone(), ("ok",))
                self.assertEqual(
                    captured.execute(
                        "SELECT access_token, refresh_token FROM account ORDER BY id"
                    ).fetchall(),
                    [("committed-access-canary", "committed-refresh-canary")],
                )
            finally:
                captured.close()
            self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o600)

    def test_sqlite_capture_rejects_unsafe_parent_symlink_hardlink_and_modes(self) -> None:
        helper = load_helper()
        cases = ("unsafe-parent", "symlink", "hardlink", "database-mode", "wal-mode")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                home = root / "home"
                home.mkdir(mode=0o700)
                database, connection = self.make_wal_database(home)
                manifest, _entry = self.fixture_entry(helper, root)
                if case == "unsafe-parent":
                    database.parent.chmod(0o755)
                elif case == "symlink":
                    connection.close()
                    outside = root / "outside.sqlite"
                    database.replace(outside)
                    database.symlink_to(outside)
                elif case == "hardlink":
                    os.link(database, root / "second-link.sqlite")
                elif case == "database-mode":
                    database.chmod(0o640)
                elif case == "wal-mode":
                    Path(os.fspath(database) + "-wal").chmod(0o640)
                try:
                    with self.assertRaises(helper.RecoveryError):
                        helper.enumerate_manifest_files(home, manifest)
                finally:
                    if case != "symlink":
                        connection.close()


@unittest.skipUnless(Path("/usr/bin/gpg").exists(), "gpg is required")
class RecoverySetRoundTripTests(unittest.TestCase):
    def make_creation_inputs(
        self, root: Path, helper, *, configured_owner: bool = False
    ) -> tuple[Path, Path, Path, Path, Path]:
        source_home = root / "source-home"
        source_home.mkdir(mode=0o700)
        authority = source_home / ".config/demo/secret.json"
        authority.parent.mkdir(parents=True)
        authority.write_text('{"token":"synthetic-only"}\n', encoding="utf-8")
        authority.chmod(0o600)
        if configured_owner:
            write_owner_private_json(
                source_home / ".openclaw/agents/main/agent/models.json",
                {"providers": {"fixture": {"apiKey": "configured-canary"}}},
            )
        manifest_path = fixture_manifest(root / "manifest.yaml")
        master = root / "master.key"
        generation = root / "generation"
        escrow_manifest = helper.create_escrow_generation(generation, master)
        return source_home, manifest_path, master, escrow_manifest, authority

    def make_cryptographically_signed_fixture(
        self, root: Path, helper
    ) -> tuple[Path, Path, Path, list[Path], Path]:
        source_home = root / "signed-source-home"
        authority = source_home / ".config/demo/secret.json"
        authority.parent.mkdir(parents=True)
        authority.write_text(
            '{"token":"signed-synthetic-only"}\n',  # LEAKSCAN-EXEMPT: synthetic fixture
            encoding="utf-8",
        )
        authority.chmod(0o600)
        manifest_path = fixture_manifest(root / "signed-manifest.yaml")
        master = root / "signed-master.key"
        generation = root / "signed-generation"
        escrow_manifest = helper.create_escrow_generation(generation, master)
        set_dir = root / "signed-recovery-set"
        helper.create_recovery_set(
            manifest_path=manifest_path,
            source_home=source_home,
            output_dir=set_dir,
            master_key_file=master,
            escrow_manifest_path=escrow_manifest,
            component_commit="a" * 40,
            set_id="csr-signed-fixture-0001",
        )
        signing_key = root / "ephemeral-recovery-signing"
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(signing_key),
            ],
            check=True,
        )
        public_key = signing_key.with_suffix(".pub")
        (set_dir / "recovery-signing-public-key.pub").write_bytes(
            public_key.read_bytes()
        )
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-q",
                "-f",
                str(signing_key),
                "-n",
                helper.RECOVERY_SIGNING_NAMESPACE,
                str(set_dir / "recovery-set.json"),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        shares = sorted(generation.glob("share-*.txt"))[:2]
        return set_dir, manifest_path, public_key, shares, authority

    def test_wal_visible_opencode_database_round_trips_as_one_private_snapshot(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, manifest, master, escrow, _authority = self.make_creation_inputs(
                root, helper
            )
            database, live_connection = SQLiteCaptureTests.make_wal_database(source)
            immutable = sqlite3.connect(
                f"{database.absolute().as_uri()}?mode=ro&immutable=1",
                uri=True,
            )
            try:
                self.assertEqual(
                    immutable.execute("SELECT count(*) FROM account").fetchone(),
                    (0,),
                )
            finally:
                immutable.close()

            set_dir = root / "recovery-set"
            try:
                helper.create_recovery_set(
                    manifest_path=manifest,
                    source_home=source,
                    output_dir=set_dir,
                    master_key_file=master,
                    escrow_manifest_path=escrow,
                    component_commit="a" * 40,
                    set_id="csr-opencode-sqlite-fixture",
                )
            finally:
                live_connection.close()

            destination = root / "destination"
            destination.mkdir(mode=0o700)
            shares = sorted((root / "generation").glob("share-*.txt"))[:2]
            helper.restore_recovery_set(
                set_dir=set_dir,
                manifest_path=manifest,
                escrow_manifest_path=escrow,
                share_files=shares,
                destination_home=destination,
                replace=False,
            )

            restored = destination / ".local/share/opencode/opencode.db"
            for suffix in ("-wal", "-shm", "-journal"):
                self.assertFalse(Path(os.fspath(restored) + suffix).exists())
            restored_connection = sqlite3.connect(restored)
            try:
                self.assertEqual(
                    restored_connection.execute("PRAGMA quick_check").fetchone(),
                    ("ok",),
                )
                self.assertEqual(
                    restored_connection.execute(
                        "SELECT access_token, refresh_token FROM account ORDER BY id"
                    ).fetchall(),
                    [("committed-access-canary", "committed-refresh-canary")],
                )
            finally:
                restored_connection.close()
            self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(restored.parent.stat().st_mode), 0o700)
            for suffix in ("-wal", "-shm", "-journal"):
                self.assertFalse(Path(os.fspath(restored) + suffix).exists())

    def test_forms_nss_and_claude_private_state_round_trip_exactly(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, manifest, master, escrow, _authority = self.make_creation_inputs(
                root, helper
            )
            forms = (
                source
                / ".local/share/forms-private-keys/forms-backup-attestation-ed25519.pem"
            )
            forms.parent.mkdir(parents=True)
            forms.parent.chmod(0o700)
            forms.write_bytes(b"synthetic-forms-signing-authority\n")
            forms.chmod(0o600)
            forms_local: dict[str, bytes] = {
                "forms/apps/classroom50-runner/.env": (
                    b"CLASSROOM50_GITHUB_TOKEN=synthetic-runner-token\n"
                ),
                "forms/apps/api/.dev.vars": b"JWT_SECRET=synthetic-jwt-secret\n",
                "forms/apps/web/.env.local": (
                    b"VITE_API_BASE=https://forms.example.invalid\n"
                ),
            }
            for relative, payload in forms_local.items():
                local_file = source / relative
                local_file.parent.mkdir(parents=True, exist_ok=True)
                local_file.write_bytes(payload)
                local_file.chmod(0o600)

            nss = source / ".local/share/pki/nssdb"
            nss.mkdir(parents=True)
            nss.parent.chmod(0o700)
            nss.chmod(0o700)
            for name, value in (("key4.db", "private-key-state"), ("cert9.db", "cert-state")):
                database = nss / name
                connection = sqlite3.connect(database)
                connection.execute("CREATE TABLE fixture (id INTEGER PRIMARY KEY, value TEXT)")
                connection.execute("INSERT INTO fixture(value) VALUES (?)", (value,))
                connection.commit()
                connection.close()
                database.chmod(0o600)
            pkcs11 = nss / "pkcs11.txt"
            pkcs11.write_text("synthetic-pkcs11-state\n", encoding="utf-8")
            pkcs11.chmod(0o600)

            claude = source / ".claude.json"
            claude_payload = {
                "oauthAccount": {"email": "metadata@example.invalid"},
                "projects": {"/synthetic": {"mcpServers": {}}},
            }
            claude.write_text(
                json.dumps(claude_payload, sort_keys=True) + "\n", encoding="utf-8"
            )
            claude.chmod(0o600)

            set_dir = root / "recovery-set"
            helper.create_recovery_set(
                manifest_path=manifest,
                source_home=source,
                output_dir=set_dir,
                master_key_file=master,
                escrow_manifest_path=escrow,
                component_commit="a" * 40,
                set_id="csr-forms-nss-claude-fixture",
            )
            destination = root / "destination"
            destination.mkdir(mode=0o700)
            shares = sorted((root / "generation").glob("share-*.txt"))[:2]
            helper.restore_recovery_set(
                set_dir=set_dir,
                manifest_path=manifest,
                escrow_manifest_path=escrow,
                share_files=shares,
                destination_home=destination,
                replace=False,
            )

            restored_forms = (
                destination
                / ".local/share/forms-private-keys/forms-backup-attestation-ed25519.pem"
            )
            self.assertEqual(restored_forms.read_bytes(), forms.read_bytes())
            self.assertEqual(stat.S_IMODE(restored_forms.stat().st_mode), 0o600)
            for relative, payload in forms_local.items():
                restored_local = destination / relative
                self.assertEqual(restored_local.read_bytes(), payload)
                self.assertEqual(
                    stat.S_IMODE(restored_local.stat().st_mode), 0o600
                )
            self.assertEqual(
                json.loads((destination / ".claude.json").read_text(encoding="utf-8")),
                claude_payload,
            )
            for name, expected in (("key4.db", "private-key-state"), ("cert9.db", "cert-state")):
                restored = destination / ".local/share/pki/nssdb" / name
                connection = sqlite3.connect(restored)
                try:
                    self.assertEqual(
                        connection.execute("SELECT value FROM fixture").fetchone(),
                        (expected,),
                    )
                    self.assertEqual(
                        connection.execute("PRAGMA quick_check").fetchone(), ("ok",)
                    )
                finally:
                    connection.close()
                self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)
                for suffix in ("-wal", "-shm", "-journal"):
                    self.assertFalse(Path(os.fspath(restored) + suffix).exists())
            self.assertEqual(
                (destination / ".local/share/pki/nssdb/pkcs11.txt").read_text(
                    encoding="utf-8"
                ),
                "synthetic-pkcs11-state\n",
            )

    def test_v2_unconfigured_source_has_explicit_null_owner_contract(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, manifest, master, escrow, _authority = self.make_creation_inputs(
                root, helper
            )
            output = root / "recovery-set"
            helper.create_recovery_set(
                manifest,
                source,
                output,
                master,
                escrow,
                "a" * 40,
                "csr-v2-unconfigured-fixture",
            )
            public = helper.load_recovery_manifest(output)
            self.assertEqual(public["schema"], helper.RECOVERY_SCHEMA)
            self.assertIn("owner_data", public)
            self.assertIsNone(public["owner_data"])

            configured, source_state = helper.openclaw_private_source_state(
                source, master.read_bytes().rstrip(b"\r\n")
            )
            self.assertFalse(configured)
            archive = root / "openclaw-private-20260805T010200Z.tar.gz.gpg"
            archive.write_bytes(b"synthetic encrypted history archive\n")
            archive.chmod(0o600)
            history_output = root / "history-recovery-set"
            helper.create_recovery_set(
                manifest,
                source,
                history_output,
                master,
                escrow,
                "a" * 40,
                "csr-v2-history-fixture",
                archive,
                source_state,
                "reviewed-prebuilt-override",
            )
            history_public = helper.load_recovery_manifest(history_output)
            self.assertEqual(
                history_public["owner_data"]["requirement"], "history-only"
            )

    def test_configured_source_without_owner_archive_fails_before_publish(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, manifest, master, escrow, _authority = self.make_creation_inputs(
                root, helper, configured_owner=True
            )
            output = root / "recovery-set"
            with self.assertRaisesRegex(
                helper.RecoveryError, "requires an owner-data archive"
            ):
                helper.create_recovery_set(
                    manifest,
                    source,
                    output,
                    master,
                    escrow,
                    "a" * 40,
                    "csr-v2-owner-required-fixture",
                )
            self.assertFalse(output.exists())

    def test_owner_capture_rejects_changed_source_state(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, manifest, master, escrow, _authority = self.make_creation_inputs(
                root, helper, configured_owner=True
            )
            configured, source_state = helper.openclaw_private_source_state(
                source, master.read_bytes().rstrip(b"\r\n")
            )
            self.assertTrue(configured)
            archive = root / "openclaw-private-20260805T010203Z.tar.gz.gpg"
            archive.write_bytes(b"synthetic encrypted owner archive\n")
            archive.chmod(0o600)
            write_owner_private_json(
                source / ".openclaw/agents/main/agent/models.json",
                {"providers": {"fixture": {"apiKey": "changed-canary"}}},
            )
            output = root / "recovery-set"
            with self.assertRaisesRegex(
                helper.RecoveryError, "changed during owner-data capture"
            ):
                helper.create_recovery_set(
                    manifest,
                    source,
                    output,
                    master,
                    escrow,
                    "a" * 40,
                    "csr-v2-owner-race-fixture",
                    archive,
                    source_state,
                    "fresh-native-snapshot",
                )
            self.assertFalse(output.exists())

    def test_v2_owner_archive_is_exact_signed_inventory(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, manifest, master, escrow, _authority = self.make_creation_inputs(
                root, helper, configured_owner=True
            )
            configured, source_state = helper.openclaw_private_source_state(
                source, master.read_bytes().rstrip(b"\r\n")
            )
            self.assertTrue(configured)
            archive = root / "openclaw-private-20260805T010203Z.tar.gz.gpg"
            archive_payload = b"synthetic encrypted owner archive\n"
            archive.write_bytes(archive_payload)
            archive.chmod(0o600)
            output = root / "recovery-set"
            helper.create_recovery_set(
                manifest,
                source,
                output,
                master,
                escrow,
                "a" * 40,
                "csr-v2-owner-fixture",
                archive,
                source_state,
                "fresh-native-snapshot",
            )
            public = helper.load_recovery_manifest(output)
            owner = public["owner_data"]
            self.assertEqual(owner["file"], archive.name)
            self.assertEqual(owner["requirement"], "agent-private-capability")
            self.assertEqual(owner["capture_policy"], "fresh-native-snapshot")
            self.assertEqual(owner["source_state_hmac_sha256"], source_state)
            self.assertEqual(
                owner["sha256"], hashlib.sha256(archive_payload).hexdigest()
            )
            self.assertEqual((output / archive.name).read_bytes(), archive_payload)

            manifest_path = output / "recovery-set.json"
            manifest_raw = manifest_path.read_bytes()
            embedded = output / archive.name

            embedded.write_bytes(b"swapped encrypted owner archive\n")
            embedded.chmod(0o600)
            with self.assertRaisesRegex(helper.RecoveryError, "digest/size mismatch"):
                helper.load_recovery_manifest(output)
            embedded.write_bytes(archive_payload)
            embedded.chmod(0o600)

            extra = output / "openclaw-private-20260805T010204Z.tar.gz.gpg"
            extra.write_bytes(b"undeclared owner archive\n")
            extra.chmod(0o600)
            with self.assertRaisesRegex(helper.RecoveryError, "undeclared files"):
                helper.load_recovery_manifest(output)
            extra.unlink()

            duplicate = manifest_raw.replace(
                b'  "owner_data":', b'  "owner_data": null,\n  "owner_data":', 1
            )
            manifest_path.write_bytes(duplicate)
            manifest_path.chmod(0o600)
            with self.assertRaisesRegex(
                helper.RecoveryError, "duplicate JSON mapping key"
            ):
                helper.load_recovery_manifest(output)
            manifest_path.write_bytes(manifest_raw)
            manifest_path.chmod(0o600)

            embedded.unlink()
            with self.assertRaisesRegex(helper.RecoveryError, "cannot open|required"):
                helper.load_recovery_manifest(output)

    def test_schema_v1_needs_explicit_degraded_gate(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, manifest, master, escrow, _authority = self.make_creation_inputs(
                root, helper
            )
            output = root / "recovery-set"
            helper.create_recovery_set(
                manifest,
                source,
                output,
                master,
                escrow,
                "a" * 40,
                "csr-v1-degraded-fixture",
            )
            manifest_path = output / "recovery-set.json"
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            value["schema"] = helper.LEGACY_RECOVERY_SCHEMA
            value.pop("owner_data")
            manifest_path.write_text(
                json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            manifest_path.chmod(0o600)
            with self.assertRaisesRegex(helper.RecoveryError, "explicit degraded"):
                helper.load_recovery_manifest(output)
            accepted = helper.load_recovery_manifest(output, allow_legacy=True)
            self.assertEqual(accepted["schema"], helper.LEGACY_RECOVERY_SCHEMA)

    def test_create_validate_restore_and_conflict_refusal(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_home = root / "source-home"
            destination = root / "destination"
            source_home.mkdir()
            destination.mkdir()
            destination.chmod(0o700)
            authority = source_home / ".config/demo/secret.json"
            authority.parent.mkdir(parents=True)
            authority.write_text('{"token":"synthetic-only"}\n', encoding="utf-8")
            authority.chmod(0o600)
            state = source_home / ".state/demo/note.txt"
            state.parent.mkdir(parents=True)
            state.write_text("private fixture\n", encoding="utf-8")
            state.chmod(0o600)
            address_book = source_home / ".openclaw/workspace/.address-book.json"
            owner_private_directory(address_book.parent)
            address_book.write_text(
                '{"contacts":{"reader@example.invalid":{"name":"Reader"}}}\n',
                encoding="utf-8",
            )
            address_book.chmod(0o600)
            devices = source_home / ".openclaw/devices"
            owner_private_directory(devices)
            paired = devices / "paired.json"
            paired.write_text(
                '{"device-fixture":{"tokens":{"operator":"pairing-canary"}}}\n',
                encoding="utf-8",
            )
            pending = devices / "pending.json"
            pending.write_text("{}\n", encoding="utf-8")
            paired.chmod(0o600)
            pending.chmod(0o600)
            wrangler = source_home / ".config/.wrangler/config/default.toml"
            wrangler.parent.mkdir(parents=True)
            wrangler.write_text(
                'oauth_token = "synthetic-oauth-only"\n'
                'refresh_token = "synthetic-refresh-only"\n',
                encoding="utf-8",
            )
            wrangler.chmod(0o600)
            manifest_path = fixture_manifest(root / "manifest.yaml")
            master = root / "master.key"
            generation = root / "generation"
            escrow_manifest = helper.create_escrow_generation(generation, master)
            set_dir = root / "recovery-set"
            helper.create_recovery_set(
                manifest_path=manifest_path,
                source_home=source_home,
                output_dir=set_dir,
                master_key_file=master,
                escrow_manifest_path=escrow_manifest,
                component_commit="a" * 40,
                set_id="csr-fixture-0001",
            )
            recovery_manifest = json.loads(
                (set_dir / "recovery-set.json").read_text(encoding="utf-8")
            )
            try:
                import jsonschema
            except ImportError:
                jsonschema = None
            if jsonschema is not None:
                schema = json.loads(
                    (ROOT / "secrets/recovery-set.schema.json").read_text(encoding="utf-8")
                )
                jsonschema.validate(recovery_manifest, schema)
            self.assertEqual(
                recovery_manifest["components"]["coding-system-rebuild"]["commit"],
                "a" * 40,
            )
            self.assertEqual(
                recovery_manifest["bootstrap"]["file"], "restore-ubuntu.sh"
            )
            self.assertEqual(
                recovery_manifest["bootstrap"]["sha256"],
                hashlib.sha256((set_dir / "restore-ubuntu.sh").read_bytes()).hexdigest(),
            )
            signature = set_dir / "recovery-set.json.sig"
            signing_key = set_dir / "recovery-signing-public-key.pub"
            signature.write_text("synthetic detached signature\n", encoding="utf-8")
            signing_key.write_text("synthetic public key\n", encoding="utf-8")
            helper.load_recovery_manifest(set_dir)
            signing_key.unlink()
            with self.assertRaisesRegex(helper.RecoveryError, "signature pair"):
                helper.load_recovery_manifest(set_dir)
            signing_key.write_text("synthetic public key\n", encoding="utf-8")
            shares = sorted(generation.glob("share-*.txt"))[:2]
            helper.validate_recovery_set(
                set_dir,
                manifest_path,
                escrow_manifest,
                shares,
            )
            helper.restore_recovery_set(
                set_dir=set_dir,
                manifest_path=manifest_path,
                escrow_manifest_path=escrow_manifest,
                share_files=shares,
                destination_home=destination,
                replace=False,
            )
            restored = destination / ".config/demo/secret.json"
            self.assertEqual(restored.read_bytes(), authority.read_bytes())
            self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)
            self.assertEqual(
                (destination / ".state/demo/note.txt").read_text(encoding="utf-8"),
                "private fixture\n",
            )
            restored_address_book = (
                destination / ".openclaw/workspace/.address-book.json"
            )
            self.assertEqual(restored_address_book.read_bytes(), address_book.read_bytes())
            self.assertEqual(
                stat.S_IMODE(restored_address_book.stat().st_mode), 0o600
            )
            restored_devices = destination / ".openclaw/devices"
            self.assertEqual(stat.S_IMODE(restored_devices.stat().st_mode), 0o700)
            for source in (paired, pending):
                restored_device_file = restored_devices / source.name
                self.assertEqual(restored_device_file.read_bytes(), source.read_bytes())
                self.assertEqual(
                    stat.S_IMODE(restored_device_file.stat().st_mode), 0o600
                )
            restored_wrangler = (
                destination / ".config/.wrangler/config/default.toml"
            )
            self.assertEqual(restored_wrangler.read_bytes(), wrangler.read_bytes())
            self.assertEqual(stat.S_IMODE(restored_wrangler.stat().st_mode), 0o600)
            self.assertFalse((destination / ".agent/secret.json").exists())

            # Identical content is idempotent; divergent content is a conflict.
            helper.restore_recovery_set(
                set_dir=set_dir,
                manifest_path=manifest_path,
                escrow_manifest_path=escrow_manifest,
                share_files=shares,
                destination_home=destination,
                replace=False,
            )
            restored.write_text("divergent\n", encoding="utf-8")
            with self.assertRaisesRegex(helper.RecoveryError, "divergent"):
                helper.restore_recovery_set(
                    set_dir=set_dir,
                    manifest_path=manifest_path,
                    escrow_manifest_path=escrow_manifest,
                    share_files=shares,
                    destination_home=destination,
                    replace=False,
                )

            recovery_manifest["components"]["coding-system-rebuild"]["commit"] = (
                "b" * 40
            )
            (set_dir / "recovery-set.json").write_text(
                json.dumps(recovery_manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(helper.RecoveryError, "another recovery set"):
                helper.validate_recovery_set(
                    set_dir,
                    manifest_path,
                    escrow_manifest,
                    shares,
                )

    @unittest.skipUnless(Path("/usr/bin/ssh-keygen").is_file(), "ssh-keygen is required")
    def test_authenticated_restore_uses_signed_snapshot_after_source_swap(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            set_dir, manifest_path, public_key, shares, authority = (
                self.make_cryptographically_signed_fixture(root, helper)
            )
            key_hash = hashlib.sha256(public_key.read_bytes()).hexdigest()
            evidence = helper.verify_recovery_signature(
                set_dir,
                trusted_public_key=public_key,
                expected_key_sha256=key_hash,
                expected_component_commit="a" * 40,
            )
            self.assertEqual(evidence["component_commit"], "a" * 40)

            destination = root / "signed-destination"
            destination.mkdir(mode=0o700)
            original_verify = helper.verify_recovery_signature
            swapped = False

            def verify_then_swap(snapshot, **kwargs):
                nonlocal swapped
                result = original_verify(snapshot, **kwargs)
                if not swapped:
                    retired = root / "signed-recovery-set-before-swap"
                    os.replace(set_dir, retired)
                    set_dir.mkdir()
                    (set_dir / "recovery-set.json").write_text(
                        '{"components":{"coding-system-rebuild":{"commit":"'
                        + "b" * 40
                        + '"}}}\n',
                        encoding="utf-8",
                    )
                    swapped = True
                return result

            with mock.patch.object(
                helper, "verify_recovery_signature", side_effect=verify_then_swap
            ):
                public = helper.authenticated_restore_recovery_set(
                    set_dir,
                    manifest_path,
                    shares,
                    destination,
                    trusted_public_key=public_key,
                    expected_key_sha256=key_hash,
                    expected_component_commit="a" * 40,
                )
            self.assertTrue(swapped)
            self.assertEqual(public["set_id"], "csr-signed-fixture-0001")
            self.assertEqual(
                (destination / ".config/demo/secret.json").read_bytes(),
                authority.read_bytes(),
            )

    def test_recovery_uses_system_gpg_and_terminates_scoped_agents(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_home = root / "source-home"
            authority = source_home / ".config/demo/secret.json"
            authority.parent.mkdir(parents=True)
            authority.write_text(
                '{"token":"gpg-boundary-fixture"}\n',  # LEAKSCAN-EXEMPT: synthetic fixture
                encoding="utf-8",
            )
            authority.chmod(0o600)
            manifest_path = fixture_manifest(root / "manifest.yaml")
            master = root / "master.key"
            generation = root / "generation"
            escrow = helper.create_escrow_generation(generation, master)
            hostile_bin = root / "hostile-bin"
            hostile_bin.mkdir()
            marker = root / "hostile-gpg-ran"
            hostile_gpg = hostile_bin / "gpg"
            hostile_gpg.write_text(
                f'#!/usr/bin/env bash\n: > "{marker}"\nexit 0\n', encoding="utf-8"
            )
            hostile_gpg.chmod(0o700)
            seen_homedirs: list[str] = []
            real_temporary = helper.secure_temporary_directory

            @contextmanager
            def tracked_temporary(*, prefix: str):
                with real_temporary(prefix=prefix) as path:
                    if prefix == "csr-gpg-":
                        seen_homedirs.append(path)
                    yield path

            with mock.patch.dict(
                os.environ, {"PATH": f"{hostile_bin}:{os.environ['PATH']}"}
            ), mock.patch.object(
                helper, "secure_temporary_directory", side_effect=tracked_temporary
            ):
                helper.create_recovery_set(
                    manifest_path,
                    source_home,
                    root / "recovery-set",
                    master,
                    escrow,
                    "a" * 40,
                    "csr-gpg-boundary-fixture",
                )
            self.assertFalse(marker.exists())
            self.assertGreaterEqual(len(seen_homedirs), 3)
            processes = subprocess.run(
                ["/usr/bin/ps", "-eo", "args="],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout
            for homedir in seen_homedirs:
                self.assertNotIn(homedir, processes)

    def test_set_identity_and_commit_are_strict_and_output_is_immutable(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_home = root / "home"
            secret = source_home / ".config/demo/secret.json"
            secret.parent.mkdir(parents=True)
            secret.write_text("synthetic", encoding="utf-8")
            secret.chmod(0o600)
            manifest_path = fixture_manifest(root / "manifest.yaml")
            master = root / "master.key"
            escrow = helper.create_escrow_generation(root / "generation", master)
            for bad_commit in ("main", "A" * 40, "a" * 39, "a" * 41):
                with self.subTest(commit=bad_commit), self.assertRaisesRegex(
                    helper.RecoveryError, "commit"
                ):
                    helper.create_recovery_set(
                        manifest_path,
                        source_home,
                        root / f"bad-{hashlib.sha256(bad_commit.encode()).hexdigest()[:8]}",
                        master,
                        escrow,
                        bad_commit,
                    )

    def test_manifest_is_one_bounded_snapshot_for_create_validate_and_restore(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_home = root / "source-home"
            secret = source_home / ".config/demo/secret.json"
            secret.parent.mkdir(parents=True)
            secret.write_text("synthetic\n", encoding="utf-8")
            secret.chmod(0o600)
            manifest_path = fixture_manifest(root / "manifest.yaml")
            original_raw = manifest_path.read_bytes()
            swapped_raw = original_raw + b"\n# synthetic concurrent replacement\n"
            master = root / "master.key"
            generation = root / "generation"
            escrow = helper.create_escrow_generation(generation, master)
            set_dir = root / "recovery-set"
            real_read = helper._read_regular_bytes

            def run_with_swap(operation):
                replacement = root / "manifest.replacement"
                replacement.write_bytes(original_raw)
                os.replace(replacement, manifest_path)
                manifest_reads = 0

                def read_once(path, *, max_bytes, secret=False):
                    nonlocal manifest_reads
                    raw = real_read(Path(path), max_bytes=max_bytes, secret=secret)
                    if Path(path) == manifest_path:
                        manifest_reads += 1
                        concurrent = root / f"manifest.concurrent-{manifest_reads}"
                        concurrent.write_bytes(swapped_raw)
                        os.replace(concurrent, manifest_path)
                    return raw

                with mock.patch.object(helper, "_read_regular_bytes", side_effect=read_once), mock.patch.object(
                    helper, "_git_manifest_at_commit", return_value=None
                ):
                    operation()
                self.assertEqual(manifest_reads, 1)

            run_with_swap(
                lambda: helper.create_recovery_set(
                    manifest_path,
                    source_home,
                    set_dir,
                    master,
                    escrow,
                    "a" * 40,
                    "csr-fixture-snapshot",
                )
            )
            public = json.loads(
                (set_dir / "recovery-set.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                public["secrets_manifest"]["sha256"],
                hashlib.sha256(original_raw).hexdigest(),
            )
            shares = sorted(generation.glob("share-*.txt"))[:2]
            run_with_swap(
                lambda: helper.validate_recovery_set(
                    set_dir, manifest_path, escrow, shares
                )
            )
            destination = root / "destination"
            destination.mkdir()
            destination.chmod(0o700)
            run_with_swap(
                lambda: helper.restore_recovery_set(
                    set_dir,
                    manifest_path,
                    escrow,
                    shares,
                    destination,
                )
            )
            self.assertEqual(
                (destination / ".config/demo/secret.json").read_text(encoding="utf-8"),
                "synthetic\n",
            )


class LegacyGithubEscrowBoundaryTests(unittest.TestCase):
    def run_ensure(
        self,
        *,
        private: str,
        exists: str = "1",
        content_exists: str = "0",
        allow_create: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        home = root / "home"
        config = home / ".config/coding-system"
        config.mkdir(parents=True)
        password = config / "zip-password.txt"
        password.write_text("synthetic-legacy-password-material\n", encoding="utf-8")
        password.chmod(0o600)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        gh_log = root / "gh.log"
        gh = fake_bin / "gh"
        gh.write_text(
            """#!/usr/bin/env bash
set -u
printf '%s\\n' "$*" >> "$GH_LOG"
if [[ "${1:-}" == api && "${2:-}" == repos/test/escrow-store ]]; then
  [[ "$GH_EXISTS" == 1 || -f "$GH_CREATED_FILE" ]] || exit 1
  printf 'test/escrow-store\\t%s\\n' "$GH_PRIVATE"
  exit 0
fi
if [[ "${1:-}" == api && "${2:-}" == repos/test/escrow-store/contents/* ]]; then
  [[ "$GH_CONTENT_EXISTS" == 1 ]] || exit 1
  printf 'synthetic-object-sha\\n'
  exit 0
fi
if [[ "${1:-}" == repo && "${2:-}" == create ]]; then
  : > "$GH_CREATED_FILE"
  exit 0
fi
exit 1
""",
            encoding="utf-8",
        )
        gh.chmod(0o755)
        rclone = fake_bin / "rclone"
        rclone.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        rclone.chmod(0o755)
        production_script = ROOT / "bin/escrow-passphrase.sh"
        harness_root = root / "harness"
        harness_bin = harness_root / "bin"
        harness_bin.mkdir(parents=True)
        (harness_bin / "lib").symlink_to(ROOT / "bin/lib", target_is_directory=True)
        harness_script = harness_bin / production_script.name
        harness_script.write_text(
            production_script.read_text(encoding="utf-8").replace(
                "export PATH=/usr/bin:/bin",
                'export PATH="$CSR_ESCROW_TEST_PATH:/usr/bin:/bin"',
                1,
            ),
            encoding="utf-8",
        )
        harness_script.chmod(0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home),
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "CSR_ESCROW_TEST_PATH": str(fake_bin),
                "GH_LOG": str(gh_log),
                "GH_EXISTS": exists,
                "GH_PRIVATE": private,
                "GH_CONTENT_EXISTS": content_exists,
                "GH_CREATED_FILE": str(root / "github-created"),
                "CSR_ESCROW_GH_REPO": "test/escrow-store",
                "CSR_RCLONE_DEST": "dropbox-test:backups",
                "CSR_ESCROW_GDRIVE": "gdrive-test:backups",
                "CSR_LEGACY_ESCROW_GENERATION_ID": "legacy-fixture-0001",
            }
        )
        if allow_create:
            environment["CSR_ESCROW_ALLOW_GITHUB_REPO_CREATE"] = "1"
        result = subprocess.run(
            [str(harness_script), "ensure"],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return result, (
            gh_log.read_text(encoding="utf-8") if gh_log.exists() else ""
        )

    def test_public_or_missing_repository_is_never_written_implicitly(self) -> None:
        for private, exists in (("false", "1"), ("true", "0")):
            with self.subTest(private=private, exists=exists):
                result, log = self.run_ensure(private=private, exists=exists)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("-X PUT", log)
                self.assertNotIn("repo create", log)

    def test_missing_repository_creation_requires_explicit_opt_in(self) -> None:
        result, log = self.run_ensure(
            private="true",
            exists="0",
            content_exists="1",
            allow_create=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("repo create test/escrow-store --private", log)
        self.assertIn("refusing to overwrite", result.stderr)

    def test_generation_scoped_existing_object_requires_overwrite_opt_in(self) -> None:
        result, log = self.run_ensure(
            private="true", exists="1", content_exists="1"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to overwrite", result.stderr)
        self.assertIn(
            "contents/generations/legacy-fixture-0001/passphrase-share-github.txt",
            log,
        )
        self.assertNotIn("-X PUT", log)


@unittest.skipUnless(
    any(Path(path).exists() for path in ("/usr/bin/7zz", "/usr/bin/7z")),
    "7-Zip is required",
)
class LegacyBoundaryTests(unittest.TestCase):
    def test_legacy_adapter_supplies_password_only_after_private_tty_prompt(self) -> None:
        seven_zip = "/usr/bin/7zz" if Path("/usr/bin/7zz").exists() else "/usr/bin/7z"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "synthetic.txt"
            archive = root / "synthetic.zip"
            source.write_text("synthetic fixture only\n", encoding="utf-8")
            password = "synthetic-password-only"
            password_file = root / "password.txt"
            password_file.write_text(password + "\n", encoding="utf-8")
            password_file.chmod(0o600)
            made = subprocess.run(
                [
                    seven_zip,
                    "a",
                    "-tzip",
                    "-mem=AES256",
                    f"-p{password}",
                    str(archive),
                    str(source),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(made.returncode, 0, made.stderr.decode(errors="replace"))
            checked = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "bin/lib/legacy_zip_tool.py"),
                    "test",
                    "--archive",
                    str(archive),
                    "--password-file",
                    str(password_file),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr.decode(errors="replace"))

    def test_restore_rejects_legacy_zip_and_points_to_explicit_importer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "legacy.zip"
            archive.write_bytes(b"not an archive")
            environment = os.environ.copy()
            environment.pop("RECOVERY_SET", None)
            environment["SECRETS"] = str(archive)
            result = subprocess.run(
                [str(ROOT / "bin/secrets-restore.sh")],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Legacy ZIPs", result.stderr)
            self.assertIn("secrets-import-legacy-zip.sh", result.stderr)

    def test_legacy_listing_allows_only_declared_synthesized_required_entries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manifest = root / "manifest.yaml"
            manifest.write_text(
                yaml.safe_dump(
                    {
                        "entries": [
                            {
                                "path": ".legacy/required.txt",
                                "mode": "0600",
                                "required": True,
                            },
                            {
                                "path": ".config/coding-system/skill-credential-source-contract.json",
                                "mode": "0600",
                                "required": True,
                                "legacy_import": "generated",
                            },
                            {
                                "path": ".config/coding-system/recovery-signing",
                                "mode": "0600",
                                "required": True,
                                "legacy_import": "destination-authority",
                            },
                        ]
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["CSR_SECRETS_HOME"] = str(root / "home")
            command = [
                sys.executable,
                str(ROOT / "bin/lib/secrets_tool.py"),
                "verify-legacy-zip",
                str(manifest),
            ]
            accepted = subprocess.run(
                command,
                input=".legacy/required.txt\n",
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn("MISSING(legacy-generated)", accepted.stdout)
            self.assertIn(
                "MISSING(legacy-destination-authority)", accepted.stdout
            )

            rejected = subprocess.run(
                command,
                input="",
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(rejected.returncode, 1)
            self.assertIn("MISSING(required)", rejected.stdout)

    def test_new_wrappers_do_not_accept_secret_values_in_environment(self) -> None:
        for name in ("secrets-pack.sh", "secrets-verify.sh", "secrets-restore.sh"):
            text = (ROOT / "bin" / name).read_text(encoding="utf-8")
            self.assertNotIn("CSR_SECRETS_PASSWORD", text)
            self.assertNotRegex(text, r"-p[\"$'{]")

    def test_legacy_secrets_helper_has_bounded_usage_errors(self) -> None:
        helper = ROOT / "bin/lib/secrets_tool.py"
        for argument in ("-h", "--help"):
            completed = subprocess.run(
                [sys.executable, str(helper), argument],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("usage: secrets_tool.py COMMAND MANIFEST", completed.stdout)
            self.assertNotIn("Traceback", completed.stdout + completed.stderr)

        for arguments in ([], ["expand"], ["not-a-command", "missing.yaml"]):
            completed = subprocess.run(
                [sys.executable, str(helper), *arguments],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("usage: secrets_tool.py COMMAND MANIFEST", completed.stderr)
            self.assertNotIn("Traceback", completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
