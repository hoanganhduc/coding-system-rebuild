"""Config loader for the zot CLI. SecretRef-aware with env var + file fallback."""

import json
import os
import sys

REQUIRED_FOR_SEARCH = ["zotero_user_id"]
SECRETS_KEYS = ["ZOTERO_API_KEY", "WEBDAV_PASSWORD", "GDRIVE_CREDENTIALS"]

DEFAULT_CONFIG = {
    "translation_server": "http://host.docker.internal:1969",
    "gdrive_share_permission": "anyone_with_link",
    "auto_catalog_threshold": 80,
    "cache_max_age_hours": 24,
    "zotfile_pattern": "{author}_{year}_{title}",
}


def _find_config_path():
    workspace = os.environ.get("OPENCLAW_WORKSPACE", "{{ HOME }}/.openclaw/workspace")
    return os.path.join(workspace, "skills", "zotero", "config.json")


def _find_secrets_path():
    return os.environ.get(
        "OPENCLAW_SECRETS_FILE",
        os.path.expanduser("~/.openclaw/secrets.json"),
    )


def _load_secrets():
    """Load secrets: env vars first, fall back to secrets.json file."""
    secrets = {}
    for key in SECRETS_KEYS:
        val = os.environ.get(key)
        if val:
            secrets[key] = val

    missing = [k for k in SECRETS_KEYS if k not in secrets]
    if missing:
        secrets_path = _find_secrets_path()
        if os.path.exists(secrets_path):
            with open(secrets_path) as f:
                file_secrets = json.load(f)
            for key in missing:
                if key in file_secrets and file_secrets[key]:
                    secrets[key] = file_secrets[key]

    return secrets


def load_config(require=None):
    """Load config + secrets. Returns merged dict.

    Args:
        require: list of required config keys (beyond REQUIRED_FOR_SEARCH).
                 Raises SystemExit if any are missing.
    """
    config_path = _find_config_path()
    if not os.path.exists(config_path):
        print(json.dumps({
            "status": "error",
            "action": "config",
            "message": f"Config file not found: {config_path}",
            "code": "CONFIG_MISSING",
        }))
        sys.exit(1)

    with open(config_path) as f:
        config = json.load(f)

    # Apply defaults for missing optional keys
    for key, default in DEFAULT_CONFIG.items():
        if key not in config or config[key] == "":
            config[key] = default

    # Merge secrets
    secrets = _load_secrets()
    config.update(secrets)

    # Validate required fields
    required = list(REQUIRED_FOR_SEARCH)
    if require:
        required.extend(require)

    missing = [k for k in required if not config.get(k)]
    if missing:
        print(json.dumps({
            "status": "error",
            "action": "config",
            "message": f"Missing required config: {', '.join(missing)}",
            "code": "CONFIG_MISSING",
        }))
        sys.exit(1)

    # Resolve workspace path
    config["workspace"] = os.environ.get(
        "OPENCLAW_WORKSPACE", "{{ HOME }}/.openclaw/workspace"
    )
    config["staging_dir"] = os.path.join(
        config["workspace"], "data", "research", "zotero", "staging"
    )

    return config
