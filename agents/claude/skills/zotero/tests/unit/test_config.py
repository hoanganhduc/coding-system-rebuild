"""Tests for lib/config.py — validation, env var precedence, fallback."""

import json
import os
import pytest
import tempfile

from lib.config import load_config, _load_secrets, DEFAULT_CONFIG


class TestLoadSecrets:
    def test_env_var_takes_precedence(self, monkeypatch, tmp_path):
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps({"ZOTERO_API_KEY": "from_file"}))
        monkeypatch.setenv("ZOTERO_API_KEY", "from_env")
        monkeypatch.setenv("OPENCLAW_SECRETS_FILE", str(secrets_file))
        secrets = _load_secrets()
        assert secrets["ZOTERO_API_KEY"] == "from_env"

    def test_falls_back_to_file(self, monkeypatch, tmp_path):
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps({"ZOTERO_API_KEY": "from_file"}))
        monkeypatch.delenv("ZOTERO_API_KEY", raising=False)
        monkeypatch.setenv("OPENCLAW_SECRETS_FILE", str(secrets_file))
        secrets = _load_secrets()
        assert secrets["ZOTERO_API_KEY"] == "from_file"

    def test_missing_secret_not_in_result(self, monkeypatch, tmp_path):
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps({}))
        monkeypatch.delenv("ZOTERO_API_KEY", raising=False)
        monkeypatch.delenv("WEBDAV_PASSWORD", raising=False)
        monkeypatch.delenv("GDRIVE_CREDENTIALS", raising=False)
        monkeypatch.setenv("OPENCLAW_SECRETS_FILE", str(secrets_file))
        secrets = _load_secrets()
        assert "ZOTERO_API_KEY" not in secrets


class TestLoadConfig:
    def test_missing_config_file_exits(self, monkeypatch):
        monkeypatch.setenv("OPENCLAW_WORKSPACE", "/nonexistent/path")
        with pytest.raises(SystemExit):
            load_config()

    def test_defaults_applied(self, monkeypatch, tmp_path):
        config_file = tmp_path / "skills" / "zotero" / "config.json"
        config_file.parent.mkdir(parents=True)
        config_file.write_text(json.dumps({"zotero_user_id": "123"}))
        monkeypatch.setenv("OPENCLAW_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("ZOTERO_API_KEY", "test_key")
        monkeypatch.setenv("OPENCLAW_SECRETS_FILE", str(tmp_path / "empty_secrets.json"))
        (tmp_path / "empty_secrets.json").write_text("{}")

        config = load_config()
        assert config["translation_server"] == DEFAULT_CONFIG["translation_server"]
        assert config["auto_catalog_threshold"] == 80

    def test_missing_required_field_exits(self, monkeypatch, tmp_path):
        config_file = tmp_path / "skills" / "zotero" / "config.json"
        config_file.parent.mkdir(parents=True)
        config_file.write_text(json.dumps({"zotero_user_id": "123"}))
        monkeypatch.setenv("OPENCLAW_WORKSPACE", str(tmp_path))
        monkeypatch.delenv("ZOTERO_API_KEY", raising=False)
        monkeypatch.setenv("OPENCLAW_SECRETS_FILE", str(tmp_path / "empty_secrets.json"))
        (tmp_path / "empty_secrets.json").write_text("{}")

        with pytest.raises(SystemExit):
            load_config(require=["ZOTERO_API_KEY"])
