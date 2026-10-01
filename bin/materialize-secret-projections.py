#!/usr/bin/env python3
"""Converge every declared secret/config projection from its authority.

Only authority files belong in a recovery set.  This command is the single
post-restore projection boundary: present authorities are copied atomically,
absent optional authorities remove their stale derived copy, and legacy backup
projections are pruned.  It never prints file contents.
"""

from __future__ import annotations

import argparse
import contextvars
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import sys


LIB = Path(__file__).resolve().parent / "lib"
if os.fspath(LIB) not in sys.path:
    sys.path.insert(0, os.fspath(LIB))
from restore_transaction import RestoreTransactionError, transactional_apply  # noqa: E402
from secure_temp import SecureTempError, secure_temporary_directory  # noqa: E402
from owner_settings import OwnerSettingsError, read_owner_settings  # noqa: E402
from tailscale_authority import (  # noqa: E402
    AUTHKEY_RELATIVE,
    HOSTNAME_RELATIVE,
    LEGACY_RELATIVE,
    TailscaleAuthorityError,
    parse_authkey,
    parse_hostname,
    parse_legacy,
)


MAX_PROJECTION_BYTES = 16 * 1024 * 1024
FILE_DELIVERY_AUTHORITY_MAX_BYTES = 65_536
FILE_DELIVERY_AUTHORITY_RELATIVE = (
    ".config/ai-agents-skills/file-delivery-queue.json"
)
FILE_DELIVERY_REPLAY_RELATIVE = (
    ".local/state/ai-agents-skills/file-delivery-replay"
)
FILE_DELIVERY_REPLAY_TOKEN = "aas-host-state:file-delivery-replay"
FILE_DELIVERY_AUTHORITY_KEYS = frozenset(
    {
        "version",
        "hmac_key_hex",
        "allowed",
        "max_job_age_seconds",
        "max_media_bytes",
        "replay_ledger_dir",
        "replay_retention_seconds",
        "max_replay_entries",
    }
)
FILE_DELIVERY_CHANNEL_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
FILE_DELIVERY_HMAC_RE = re.compile(r"[0-9a-f]{64}\Z")
FILE_DELIVERY_MAX_TARGET_BYTES = 1_024
OPENCLAW_FILE_DELIVERY_AUTHORITY_RELATIVE = (
    ".openclaw/file-delivery-policy.json"
)
OPENCLAW_FILE_DELIVERY_PROJECTION_RELATIVE = (
    ".openclaw/workspace/.config/file-delivery/secrets.json"
)
OPENCLAW_FILE_DELIVERY_SCHEMA = "openclaw.file-delivery-policy/v1"
OPENCLAW_FILE_DELIVERY_CHANNELS = (
    "telegram",
    "zulip",
    "googlechat",
    "whatsapp",
    "zalo",
)
OPENCLAW_FILE_DELIVERY_MAX_BYTES = 1_000_000
OPENCLAW_FILE_DELIVERY_MAX_TARGETS = 1_000
OPENCLAW_FILE_DELIVERY_MAX_TARGET_BYTES = 4_096
OPENCLAW_FILE_DELIVERY_MAX_TOKEN_BYTES = 16_384
OPENCODE_SQLITE_RELATIVE = ".local/share/opencode/opencode.db"
OPENCODE_SQLITE_SIDECARS = ("", "-wal", "-shm", "-journal")
MAX_OPENCODE_SQLITE_BYTES = 256 * 1024 * 1024
_ACTIVE_HOME: contextvars.ContextVar[Path | None] = contextvars.ContextVar(
    "projection_home", default=None
)
VNU_REQUIRED_KEYS = ("VNU_EOFFICE_USERNAME", "VNU_EOFFICE_PASSWORD")
VNU_OPTIONAL_KEYS = ("VNU_STATE_HMAC_KEY",)
VNU_RETIRED_DELIVERY_KEYS = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")
VNU_SOURCE_KEYS = (*VNU_REQUIRED_KEYS, *VNU_OPTIONAL_KEYS, *VNU_RETIRED_DELIVERY_KEYS)
VNU_DOTENV_KEYS = (*VNU_REQUIRED_KEYS, *VNU_OPTIONAL_KEYS)
CANVAS_CONFIG_KEYS = (
    "CANVAS_LMS_API_URL",
    "CANVAS_LMS_API_KEY",
    "CANVAS_LMS_COURSE_ID",
)
AAS_SHARED_JSON_KEYS = (
    "CALIBRE_GDRIVE_FOLDER_ID",
    "GDRIVE_CREDENTIALS",
    "TELEGRAM_BOT_TOKEN",
    "WEBDAV_PASSWORD",
    "ZOTERO_API_KEY",
)
SKILL_ENV_KEYS = (
    "AXLE_API_KEY",
    "LEANEXPLORE_API_KEY",
    "OCR_SPACE_API_KEY",
    "OCR_SPACE_KEY",
    "OCRSPACE_API_KEY",
    "OCRSPACE_KEY",
    "OPENCLAW_S2_API_KEY",
    "SEMANTIC_SCHOLAR_API_KEY",
    "UNPAYWALL_EMAIL",
    "ZENODO_TOKEN",
)
PROVIDER_ENV_KEYS = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "DEEPSEEK_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROK_API_KEY",
    "KIMI_API_KEY",
    "MOONSHOT_API_KEY",
    "OPENAI_API_KEY",
    "OPENCODE_API_KEY",
    "XAI_API_KEY",
)
COPILOT_ENV_KEYS = (
    "COPILOT_GITHUB_TOKEN",
    "COPILOT_PROVIDER_API_KEY",
    "COPILOT_PROVIDER_BEARER_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
)
COMPUTE_ENV_KEYS = (
    "HCLOUD_TOKEN",
    "HCLOUD_SSH_KEYS",
    "KAGGLE_API_TOKEN",
    "KAGGLE_CONFIG_DIR",
)
LEGACY_REMOTE_BRIDGE_ZULIP_KEYS = {
    "site": "ZULIP_ORG_URL",
    "email": "ZULIP_EMAIL",
    "api_key": "ZULIP_API_KEY",
}
SEND_EMAIL_PROFILE_KEYS = frozenset(
    {
        "host",
        "port",
        "user",
        "username",
        "password",
        "pass",
        "from",
        "sender",
        "security",
        "timeout",
        "from_name",
        "reply_to",
        "cc",
        "bcc",
        "signature",
        "signature_html",
        "reply_to_self",
        "bcc_self",
        "pgp_sign",
        "pgp_key",
        "pgp_passphrase",
        "gnupg_home",
    }
)
SEND_EMAIL_TOP_LEVEL_KEYS = frozenset(
    {"smtp", "accounts", "default_account", "_README"}
)
REMOTE_BRIDGE_TOP_LEVEL_KEYS = frozenset(
    {"default_channel", "notify_channels", "allowed_user_ids", "zulip", "telegram"}
)
REMOTE_BRIDGE_ZULIP_KEYS = frozenset(
    {"site", "email", "api_key", "control_stream", "topic_prefix", "allowed_user_ids"}
)
REMOTE_BRIDGE_TELEGRAM_KEYS = frozenset(
    {"bot_token", "mode", "allowed_chat_ids", "allowed_user_ids"}
)
GETSCIPAPERS_PRIVATE_FILES = {
    "ablesci/ablesci_cache.pkl": False,
    "ablesci/credentials.json": True,
    "facebook/credentials.json": True,
    "facebook/facebook_session_cache.pkl": False,
    "getpapers/config.json": True,
    "getpapers/proxy.json": True,
    "getpapers/proxy_list.json": True,
    "getpapers/unpywall_cache": False,
    "nexus/credentials.json": True,
    "nexus/proxy.json": True,
    "nexus/proxy_list.json": True,
    "nexus/telegram_session.session": False,
    "scinet/credentials.json": True,
    "scinet/scinet_cache.pkl": False,
    "wosonhj/credentials.json": True,
    "wosonhj/wosonhj_cache.pkl": False,
    "zlib/zlib_config.json": True,
}

DECLARED_PRIVATE_DIRECTORIES = frozenset(
    {
        ".claude",
        ".codex/runtime/workspace",
        ".config/ai-agents-skills",
        ".config/ai-agents-skills/providers",
        ".config/ai-agents-skills/zotero",
        ".config/ai-agents-skills/calibre",
        ".local/state/ai-agents-skills/file-delivery-replay",
        ".config/course/canvas",
        ".config/course/google-classroom",
        ".config/getscipapers",
        ".config/remote-bridge",
        ".config/send-email",
        ".config/vnu-eoffice",
        ".kaggle",
        ".local/share/ai-agents-skills/runtime/workspace",
        ".local/share/ai-agents-skills/runtime/workspace/research_compute",
        ".local/share/ai-agents-skills/runtime/workspace/skills/autonomous-research-loop-runtime",
        ".local/share/ai-agents-skills/runtime/workspace/skills/remote-bridge",
        ".local/share/opencode",
        ".openclaw",
        ".openclaw/workspace",
        ".openclaw/workspace/.config/ai-agents-skills",
        ".openclaw/workspace/.config/ai-agents-skills/providers",
        ".openclaw/workspace/.config/file-delivery",
        ".openclaw/workspace/.config/course/canvas",
        ".openclaw/workspace/.config/getscipapers",
        ".openclaw/workspace/.config/remote-bridge",
        ".openclaw/workspace/.config/send-email",
        ".openclaw/workspace/secrets",
        ".openclaw/workspace/secrets/getscipapers",
        ".openclaw/workspace/secrets/vnu-eoffice",
    }
)

# Kept explicit so a manifest test can prove that a new projection cannot be
# added without also defining its convergence behavior here.
SUPPORTED_PROJECTION_IDS = {
    "aas-secrets-codex-projection",
    "aas-secrets-shared-projection",
    "retired-aas-secrets-openclaw-projection",
    "retired-tailscale-env-projection",
    "retired-send-email-openclaw-projection",
    "aas-compute-openclaw-projection",
    "retired-aas-skill-secrets-openclaw-projection",
    "aas-axle-openclaw-projection",
    "aas-leanexplore-openclaw-projection",
    "aas-research-digest-openclaw-projection",
    "aas-submission-venue-openclaw-projection",
    "aas-zotero-host-projection",
    "aas-zotero-skill-openclaw-projection",
    "aas-calibre-host-projection",
    "aas-calibre-openclaw-projection",
    "retired-openclaw-file-delivery-projection",
    "aas-provider-secrets-openclaw-projection",
    "aas-copilot-provider-openclaw-projection",
    "retired-remote-bridge-openclaw-projection",
    "kaggle-access-token-projection",
    "course-google-credentials-openclaw-projection",
    "course-google-token-openclaw-projection",
    "course-canvas-openclaw-projection",
    "openclaw-secrets-backup-projection",
    "retired-openclaw-workspace-secrets-projection",
    "vnu-eoffice-openclaw-projection",
    "modal-openclaw-projection",
    "getscipapers-openclaw-projection",
    "openclaw-zotero-config-projection",
    "codex-zotero-config-projection",
    "aas-zotero-config-projection",
    "claude-zotero-config-projection",
    "openclaw-calibre-config-projection",
    "codex-calibre-config-projection",
    "aas-calibre-config-projection",
    "claude-calibre-config-projection",
    "openclaw-research-compute-projection",
    "openclaw-github-cli-hosts-projection",
    "openclaw-github-cli-config-projection",
}

# Exact regular-file surface read and/or mutated by the materializer. Recovery
# uses this metadata to build a private virtual HOME, run every migration there,
# and commit the resulting authorities, projections, scrubs, and deletions in
# one durable transaction. Dynamic bounded trees are added by
# ``transaction_file_contract`` below.
TRANSACTION_INPUT_FILE_MODES = {
    ".secrets.env": 0o600,
    AUTHKEY_RELATIVE: 0o600,
    HOSTNAME_RELATIVE: 0o600,
    LEGACY_RELATIVE: 0o600,
    ".claude/secrets.json": 0o600,
    ".openclaw/secrets.json": 0o600,
    ".config/send-email/secrets.json": 0o600,
    ".openclaw/workspace/.config/send-email/secrets.json": 0o600,
    ".codex/runtime/workspace/.secrets.json": 0o600,
    ".local/share/ai-agents-skills/runtime/workspace/.secrets.json": 0o600,
    ".openclaw/workspace/.secrets.json": 0o600,
    ".config/vnu-eoffice/secrets.json": 0o600,
    ".openclaw/workspace/secrets/vnu-eoffice/secrets.json": 0o600,
    ".config/remote-bridge/secrets.json": 0o600,
    ".openclaw/workspace/.config/remote-bridge/secrets.json": 0o600,
    ".openclaw/workspace/secrets/remote-bridge/secrets.json": 0o600,
    ".config/ai-agents-skills/secrets.json": 0o600,
    ".openclaw/workspace/.config/ai-agents-skills/secrets.json": 0o600,
    ".config/ai-agents-skills/calibre-secrets.json": 0o600,
    FILE_DELIVERY_AUTHORITY_RELATIVE: 0o600,
    OPENCLAW_FILE_DELIVERY_AUTHORITY_RELATIVE: 0o600,
    ".openclaw/workspace/.config/ai-agents-skills/calibre-secrets.json": 0o600,
    ".config/ai-agents-skills/compute.env": 0o600,
    ".openclaw/workspace/.config/ai-agents-skills/compute.env": 0o600,
    ".config/ai-agents-skills/skill.env": 0o600,
    ".openclaw/workspace/.config/ai-agents-skills/skill.env": 0o600,
    ".openclaw/workspace/.config/ai-agents-skills/axiom-axle.env": 0o600,
    ".openclaw/workspace/.config/ai-agents-skills/lean-explore.env": 0o600,
    ".openclaw/workspace/.config/ai-agents-skills/research-digest.env": 0o600,
    ".openclaw/workspace/.config/ai-agents-skills/submission-venue.env": 0o600,
    ".config/ai-agents-skills/zotero-secrets.json": 0o600,
    ".openclaw/workspace/.config/ai-agents-skills/zotero-secrets.json": 0o600,
    OPENCLAW_FILE_DELIVERY_PROJECTION_RELATIVE: 0o600,
    ".config/ai-agents-skills/providers.env": 0o600,
    ".openclaw/workspace/.config/ai-agents-skills/providers.env": 0o600,
    ".config/ai-agents-skills/providers/copilot.env": 0o600,
    ".openclaw/workspace/.config/ai-agents-skills/providers/copilot.env": 0o600,
    ".kaggle/access_token": 0o600,
    ".config/course/google-classroom/credentials.json": 0o600,
    ".config/course/google-classroom/token.pickle": 0o600,
    ".openclaw/workspace/.config/course/google-classroom/credentials.json": 0o600,
    ".openclaw/workspace/.config/course/google-classroom/token.pickle": 0o600,
    ".config/course/canvas/config.json": 0o600,
    ".openclaw/workspace/.config/course/canvas/config.json": 0o600,
    ".modal.toml": 0o600,
    ".openclaw/workspace/.modal.toml": 0o600,
    ".local/share/ai-agents-skills/runtime/workspace/config/research-compute.toml": 0o644,
    ".openclaw/workspace/config/research-compute.toml": 0o600,
    ".config/ai-agents-skills/zotero/config.json": 0o644,
    ".openclaw/workspace/skills/zotero/config.json": 0o644,
    ".codex/runtime/workspace/skills/zotero/config.json": 0o644,
    ".local/share/ai-agents-skills/runtime/workspace/skills/zotero/config.json": 0o644,
    ".claude/skills/zotero/config.json": 0o644,
    ".config/ai-agents-skills/calibre/config.json": 0o644,
    ".openclaw/workspace/skills/calibre/config.json": 0o644,
    ".codex/runtime/workspace/skills/calibre/config.json": 0o644,
    ".local/share/ai-agents-skills/runtime/workspace/skills/calibre/config.json": 0o644,
    ".claude/skills/calibre/config.json": 0o644,
    ".config/gh/hosts.yml": 0o600,
    ".config/gh/config.yml": 0o600,
    ".openclaw/workspace/.config/gh/hosts.yml": 0o600,
    ".openclaw/workspace/.config/gh/config.yml": 0o600,
}

TRANSACTION_MUTATION_FILE_MODES = {
    relative: mode
    for relative, mode in TRANSACTION_INPUT_FILE_MODES.items()
    if relative
    not in {
        ".claude/secrets.json",
        ".openclaw/secrets.json",
        OPENCLAW_FILE_DELIVERY_AUTHORITY_RELATIVE,
        ".local/share/ai-agents-skills/runtime/workspace/config/research-compute.toml",
        ".config/gh/hosts.yml",
        ".config/gh/config.yml",
    }
}


class ProjectionError(RuntimeError):
    """A redaction-safe projection failure."""


def transaction_file_contract(home: Path) -> tuple[dict[str, int], dict[str, int]]:
    """Return the exact bounded input and mutation file surfaces for HOME."""

    home = _require_home(home)
    # Parent-mode convergence is an explicit prerequisite for descriptor-safe
    # discovery.  It also prevents a legacy private tree from being inspected
    # through a group-writable ancestor.
    _converge_declared_private_directories(home)
    _converge_opencode_sqlite_permissions(home)
    _converge_getscipapers_permissions(home)
    _ensure_file_delivery_replay_directory(home)
    inputs = dict(TRANSACTION_INPUT_FILE_MODES)
    mutations = dict(TRANSACTION_MUTATION_FILE_MODES)
    for relative in GETSCIPAPERS_PRIVATE_FILES:
        for root in (
            ".config/getscipapers",
            ".openclaw/workspace/.config/getscipapers",
            ".openclaw/workspace/secrets/getscipapers",
        ):
            path = f"{root}/{relative}"
            inputs[path] = 0o600
            mutations[path] = 0o600

    # Validate the complete legacy tree before copying its allowlisted files.
    # Otherwise an undeclared file could stay live while the virtual HOME made
    # the migration appear complete.
    _inspect_legacy_getscipapers_tree(
        home, home / ".openclaw/workspace/secrets/getscipapers"
    )

    dynamic: list[tuple[Path, int, bool]] = []
    dynamic.extend(
        (path, 0o600, False) for path in _legacy_canvas_config_paths(home)
    )
    openclaw_root = home / ".openclaw"
    if openclaw_root.exists() and not openclaw_root.is_symlink():
        dynamic.extend(
            (path, 0o600, True)
            for path in openclaw_root.glob("secrets.json.bak.*")
        )
        agents = openclaw_root / "agents"
        if agents.exists() and not agents.is_symlink():
            dynamic.extend(
                (path, 0o600, True)
                for path in agents.glob("*/agent/auth-profiles.json.bak")
            )
    for path, mode, mutated in dynamic:
        try:
            relative = path.relative_to(home).as_posix()
        except ValueError as exc:  # pragma: no cover - bounded roots are under HOME
            raise ProjectionError("transaction path escaped projection home") from exc
        if not relative or any(part in {"", ".", ".."} for part in Path(relative).parts):
            raise ProjectionError("invalid materializer transaction path")
        inputs[relative] = mode
        if mutated:
            mutations[relative] = mode
    return inputs, mutations


def _validate_transaction_modes(modes: dict[str, int]) -> None:
    for relative, mode in modes.items():
        path = Path(relative)
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.as_posix() != relative
            or type(mode) is not int
            or not 0 <= mode <= 0o777
        ):
            raise ProjectionError("invalid materializer transaction contract")


def _copy_transaction_files(
    source_home: Path,
    destination_home: Path,
    modes: dict[str, int],
) -> None:
    _validate_transaction_modes(modes)
    source_home = _require_home(source_home)
    destination_home = _require_home(destination_home)
    for relative, mode in sorted(modes.items()):
        source_token = _ACTIVE_HOME.set(source_home)
        try:
            payload = _read_regular(source_home / relative, required_mode=mode)
        finally:
            _ACTIVE_HOME.reset(source_token)
        if payload is None:
            continue
        destination_token = _ACTIVE_HOME.set(destination_home)
        try:
            _atomic_write(
                destination_home,
                destination_home / relative,
                payload,
                mode,
            )
        finally:
            _ACTIVE_HOME.reset(destination_token)


def snapshot_transaction_inputs(
    source_home: Path,
    destination_home: Path,
    modes: dict[str, int],
) -> None:
    """Copy the bounded current input surface into a private virtual HOME."""

    source_home = _require_home(source_home)
    _converge_declared_private_directories(source_home)
    _copy_transaction_files(source_home, destination_home, modes)


def overlay_transaction_stage(
    virtual_home: Path,
    recovery_stage: Path,
    modes: dict[str, int],
) -> None:
    """Overlay authenticated archive members onto the virtual HOME."""

    _copy_transaction_files(recovery_stage, virtual_home, modes)


def export_transaction_files(
    virtual_home: Path,
    output_stage: Path,
    modes: dict[str, int],
) -> dict[str, int | None]:
    """Export final bytes and authenticated deletions for one transaction."""

    _validate_transaction_modes(modes)
    virtual_home = _require_home(virtual_home)
    output_stage = _require_home(output_stage)
    result: dict[str, int | None] = {}
    for relative, mode in sorted(modes.items()):
        virtual_token = _ACTIVE_HOME.set(virtual_home)
        try:
            payload = _read_regular(virtual_home / relative, required_mode=mode)
        finally:
            _ACTIVE_HOME.reset(virtual_token)
        if payload is None:
            result[relative] = None
            continue
        output_token = _ACTIVE_HOME.set(output_stage)
        try:
            _atomic_write(output_stage, output_stage / relative, payload, mode)
        finally:
            _ACTIVE_HOME.reset(output_token)
        result[relative] = mode
    return result


def _converge_declared_private_directories(home: Path) -> None:
    """Remove group/other access only from explicit projection parent chains."""

    declared = set(DECLARED_PRIVATE_DIRECTORIES)
    transaction_files = set(TRANSACTION_INPUT_FILE_MODES)
    for relative in GETSCIPAPERS_PRIVATE_FILES:
        transaction_files.update(
            {
                f".config/getscipapers/{relative}",
                f".openclaw/workspace/.config/getscipapers/{relative}",
                f".openclaw/workspace/secrets/getscipapers/{relative}",
            }
        )
    for relative in transaction_files:
        parts = Path(relative).parts[:-1]
        declared.update(
            Path(*parts[:index]).as_posix()
            for index in range(1, len(parts) + 1)
        )

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for relative in sorted(declared):
        parts = Path(relative).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise ProjectionError("declared private directory is invalid")
        descriptor = os.open(home, flags)
        try:
            for part in parts:
                try:
                    linked = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    break
                if (
                    not stat.S_ISDIR(linked.st_mode)
                    or linked.st_uid != os.getuid()
                ):
                    raise ProjectionError("unsafe declared private directory")
                child = os.open(part, flags, dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if (
                        not stat.S_ISDIR(opened.st_mode)
                        or opened.st_uid != os.getuid()
                        or (opened.st_dev, opened.st_ino)
                        != (linked.st_dev, linked.st_ino)
                    ):
                        raise ProjectionError("declared private directory changed")
                    if stat.S_IMODE(opened.st_mode) != 0o700:
                        os.fchmod(child, 0o700)
                        os.fsync(child)
                except BaseException:
                    os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child
        finally:
            os.close(descriptor)


def _converge_opencode_sqlite_permissions(home: Path) -> None:
    """Restrict the exact OpenCode DB/WAL family without following links."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(home, flags)
    try:
        for component in Path(OPENCODE_SQLITE_RELATIVE).parts[:-1]:
            try:
                linked = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return
            if not stat.S_ISDIR(linked.st_mode) or linked.st_uid != os.geteuid():
                raise ProjectionError("unsafe OpenCode SQLite directory")
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        base = Path(OPENCODE_SQLITE_RELATIVE).name
        for suffix in OPENCODE_SQLITE_SIDECARS:
            name = base + suffix
            try:
                linked = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(linked.st_mode)
                or linked.st_uid != os.geteuid()
                or linked.st_nlink != 1
                or linked.st_size > MAX_OPENCODE_SQLITE_BYTES
            ):
                raise ProjectionError("unsafe OpenCode SQLite state")
            file_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                file_descriptor = os.open(name, file_flags, dir_fd=descriptor)
            except OSError as exc:
                raise ProjectionError("unsafe OpenCode SQLite state") from exc
            try:
                opened = os.fstat(file_descriptor)
                if (
                    not stat.S_ISREG(linked.st_mode)
                    or not stat.S_ISREG(opened.st_mode)
                    or (linked.st_dev, linked.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or opened.st_uid != os.geteuid()
                    or opened.st_nlink != 1
                    or opened.st_size > MAX_OPENCODE_SQLITE_BYTES
                ):
                    raise ProjectionError("unsafe OpenCode SQLite state")
                if stat.S_IMODE(opened.st_mode) != 0o600:
                    os.fchmod(file_descriptor, 0o600)
                    os.fsync(file_descriptor)
                after = os.fstat(file_descriptor)
                named_after = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False
                )
                if (
                    _stable_file_identity(after)
                    != _stable_file_identity(named_after)
                    or (after.st_dev, after.st_ino)
                    != (opened.st_dev, opened.st_ino)
                ):
                    raise ProjectionError("OpenCode SQLite state changed")
            finally:
                os.close(file_descriptor)
    finally:
        os.close(descriptor)


def _converge_getscipapers_permissions(home: Path) -> None:
    """Restrict declared GetSciPapers authority files the skill rewrites at umask."""

    source_root = home / ".config/getscipapers"
    for relative in sorted(GETSCIPAPERS_PRIVATE_FILES):
        authority = source_root / relative
        opened = _open_parent_descriptor(home, authority, create=False)
        if opened is None:
            continue
        parent_descriptor, leaf, parent_identity = opened
        try:
            try:
                linked = os.stat(
                    leaf, dir_fd=parent_descriptor, follow_symlinks=False
                )
            except FileNotFoundError:
                continue
            if stat.S_IMODE(linked.st_mode) == 0o600:
                continue
            if (
                not stat.S_ISREG(linked.st_mode)
                or linked.st_uid != os.getuid()
                or linked.st_nlink != 1
            ):
                raise ProjectionError("unsafe GetSciPapers authority")
            file_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(leaf, file_flags, dir_fd=parent_descriptor)
            try:
                information = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(information.st_mode)
                    or _stable_file_identity(information)
                    != _stable_file_identity(linked)
                    or information.st_uid != os.getuid()
                    or information.st_nlink != 1
                ):
                    raise ProjectionError("unsafe GetSciPapers authority")
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                after = os.fstat(descriptor)
                named_after = os.stat(
                    leaf, dir_fd=parent_descriptor, follow_symlinks=False
                )
                if (
                    _stable_file_identity(after)
                    != _stable_file_identity(named_after)
                    or (after.st_dev, after.st_ino)
                    != (information.st_dev, information.st_ino)
                ):
                    raise ProjectionError("GetSciPapers authority changed")
            finally:
                os.close(descriptor)
        finally:
            os.close(parent_descriptor)
        _confirm_parent_identity(home, authority, parent_identity)


def _ensure_file_delivery_replay_directory(home: Path) -> None:
    """Create the fixed host replay ledger without following path links."""

    ledger = home / FILE_DELIVERY_REPLAY_RELATIVE
    opened = _open_parent_descriptor(home, ledger / ".state", create=True)
    if opened is None:  # pragma: no cover - create=True always returns a descriptor
        raise ProjectionError("file-delivery replay ledger is unavailable")
    descriptor, _leaf, identity = opened
    try:
        information = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(information.st_mode)
            or information.st_uid != os.getuid()
            or (information.st_dev, information.st_ino) != identity
        ):
            raise ProjectionError("unsafe file-delivery replay ledger")
        if stat.S_IMODE(information.st_mode) != 0o700:
            os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _confirm_parent_identity(home, ledger / ".state", identity)


def _require_home(home: Path) -> Path:
    home = home.expanduser().absolute()
    info = home.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ProjectionError("projection home is unsafe")
    return home


def _relative_parts(home: Path, path: Path) -> tuple[str, ...]:
    target = path.expanduser().absolute()
    try:
        relative = target.relative_to(home)
    except ValueError as exc:
        raise ProjectionError("projection path escapes the target home") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ProjectionError("projection path is invalid")
    return relative.parts


def _open_home_descriptor(home: Path) -> int:
    before = home.lstat()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(home, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            raise ProjectionError("projection home changed during inspection")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_parent_descriptor(
    home: Path, path: Path, *, create: bool
) -> tuple[int, str, tuple[int, int]] | None:
    parts = _relative_parts(home, path)
    descriptor = _open_home_descriptor(home)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for component in parts[:-1]:
            child = -1
            try:
                try:
                    child = os.open(component, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        os.close(descriptor)
                        return None
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    child = os.open(component, flags, dir_fd=descriptor)
                information = os.fstat(child)
                if (
                    not stat.S_ISDIR(information.st_mode)
                    or information.st_uid != os.getuid()
                    or stat.S_IMODE(information.st_mode) & 0o022
                ):
                    raise ProjectionError("unsafe projection path ancestor")
            except BaseException:
                if child >= 0:
                    os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        parent = os.fstat(descriptor)
        return descriptor, parts[-1], (parent.st_dev, parent.st_ino)
    except BaseException:
        os.close(descriptor)
        raise


def _confirm_parent_identity(
    home: Path, path: Path, expected: tuple[int, int]
) -> None:
    reopened = _open_parent_descriptor(home, path, create=False)
    if reopened is None:
        raise ProjectionError("projection path changed during operation")
    descriptor, _leaf, observed = reopened
    os.close(descriptor)
    if observed != expected:
        raise ProjectionError("projection path changed during operation")


def _stable_file_identity(information: os.stat_result) -> tuple[int, ...]:
    return (
        information.st_dev,
        information.st_ino,
        information.st_mode,
        information.st_uid,
        information.st_nlink,
        information.st_size,
        information.st_mtime_ns,
        information.st_ctime_ns,
    )


def _safe_directory(information: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(information.st_mode)
        and information.st_uid == os.getuid()
        and not stat.S_IMODE(information.st_mode) & 0o022
    )


def _open_directory_entry(
    parent_descriptor: int,
    name: str,
    *,
    missing_ok: bool,
    error: str,
) -> tuple[int, os.stat_result] | None:
    try:
        linked = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise ProjectionError(error) from None
    if not _safe_directory(linked):
        raise ProjectionError(error)

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        if (
            not _safe_directory(opened)
            or _stable_file_identity(opened) != _stable_file_identity(linked)
        ):
            raise ProjectionError(error)
        return descriptor, opened
    except ProjectionError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ProjectionError(error) from exc
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _read_regular(path: Path, *, required_mode: int) -> bytes | None:
    home = _ACTIVE_HOME.get()
    if home is None:
        raise ProjectionError("projection home is not active")
    opened_parent = _open_parent_descriptor(home, path, create=False)
    if opened_parent is None:
        return None
    parent_descriptor, leaf, parent_identity = opened_parent
    try:
        try:
            info = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or not 0 < info.st_size <= MAX_PROJECTION_BYTES
            or stat.S_IMODE(info.st_mode) != required_mode
        ):
            raise ProjectionError("unsafe projection authority")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(leaf, flags, dir_fd=parent_descriptor)
        try:
            opened = os.fstat(descriptor)
            if _stable_file_identity(opened) != _stable_file_identity(info):
                raise ProjectionError("projection authority changed during inspection")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise ProjectionError("projection authority was truncated during read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise ProjectionError("projection authority grew during read")
            after = os.fstat(descriptor)
            if _stable_file_identity(after) != _stable_file_identity(opened):
                raise ProjectionError("projection authority changed during read")
        finally:
            os.close(descriptor)
        _confirm_parent_identity(home, path, parent_identity)
        return b"".join(chunks)
    finally:
        os.close(parent_descriptor)


def _json_object(payload: bytes, label: str) -> dict:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectionError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ProjectionError(f"{label} must be a JSON object")
    return value


def _json_payload(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_string_list(value: object, label: str) -> None:
    if (
        not isinstance(value, list)
        or any(not _nonempty_string(item) for item in value)
        or len(value) != len(set(value))
    ):
        raise ProjectionError(f"{label} is invalid")


def _normalized_send_email_profile(value: dict) -> dict:
    normalized: dict[str, object] = {}
    for key, item in value.items():
        lowered = str(key).lower()
        if lowered.startswith("smtp_"):
            lowered = lowered[5:]
        if lowered in normalized and normalized[lowered] != item:
            raise ProjectionError("legacy send-email profile has conflicting aliases")
        normalized[lowered] = item
    return normalized


def _validate_send_email_profile(value: object) -> None:
    if not isinstance(value, dict):
        raise ProjectionError("legacy send-email profile is invalid")
    normalized = _normalized_send_email_profile(value)
    if set(normalized) - SEND_EMAIL_PROFILE_KEYS:
        raise ProjectionError("legacy send-email profile contains unsupported fields")
    if not all(
        (
            _nonempty_string(normalized.get("host")),
            _nonempty_string(normalized.get("user") or normalized.get("username")),
            _nonempty_string(
                normalized.get("password") or normalized.get("pass")
            ),
            _nonempty_string(normalized.get("from") or normalized.get("sender")),
        )
    ):
        raise ProjectionError("legacy send-email profile is incomplete")


def _validate_send_email_document(value: dict) -> None:
    allowed_top = set(SEND_EMAIL_TOP_LEVEL_KEYS) | set(SEND_EMAIL_PROFILE_KEYS) | {
        "SMTP_" + key.upper() for key in SEND_EMAIL_PROFILE_KEYS
    }
    if set(value) - allowed_top:
        raise ProjectionError("legacy send-email authority contains unrelated fields")
    metadata = value.get("_README")
    if metadata is not None and not _nonempty_string(metadata):
        raise ProjectionError("legacy send-email metadata is invalid")
    profiles = 0
    if "smtp" in value:
        _validate_send_email_profile(value["smtp"])
        profiles += 1
    accounts = value.get("accounts")
    if accounts is not None:
        if not isinstance(accounts, dict) or not accounts:
            raise ProjectionError("legacy send-email accounts are invalid")
        for account in accounts.values():
            _validate_send_email_profile(account)
            profiles += 1
        default = value.get("default_account")
        if default is not None and (
            not isinstance(default, str) or default not in accounts
        ):
            raise ProjectionError("legacy send-email default account is invalid")
    direct = {
        key: item for key, item in value.items() if key not in SEND_EMAIL_TOP_LEVEL_KEYS
    }
    if direct:
        _validate_send_email_profile(direct)
        profiles += 1
    if profiles == 0:
        raise ProjectionError("legacy send-email authority is incomplete")


def _extract_send_email_document(document: dict) -> dict | None:
    selected = {
        key: item
        for key, item in document.items()
        if key in SEND_EMAIL_TOP_LEVEL_KEYS
        or key in SEND_EMAIL_PROFILE_KEYS
        or (
            isinstance(key, str)
            and key.startswith("SMTP_")
            and key[5:].lower() in SEND_EMAIL_PROFILE_KEYS
        )
    }
    # Generic legacy bundles may carry their own metadata or account-selection
    # label.  Match the send-email reader's shape test: only an SMTP block,
    # accounts map, or direct SMTP profile field makes the bundle a candidate.
    if not (set(selected) - {"_README", "default_account"}):
        return None
    _validate_send_email_document(selected)
    return selected


def _send_email_semantic_value(value: dict) -> dict:
    return {key: item for key, item in value.items() if key != "_README"}


def _inspect_send_email_legacy(home: Path) -> dict | None:
    selected: dict | None = None
    selected_semantic: dict | None = None
    for path, label, dedicated in (
        (
            home / ".config/send-email/secrets.json",
            "send-email authority",
            True,
        ),
        (
            home / ".openclaw/workspace/.config/send-email/secrets.json",
            "legacy OpenClaw send-email projection",
            True,
        ),
        (home / ".codex/runtime/workspace/.secrets.json", "legacy Codex runtime", False),
        (
            home / ".local/share/ai-agents-skills/runtime/workspace/.secrets.json",
            "legacy shared runtime",
            False,
        ),
        (home / ".openclaw/workspace/.secrets.json", "legacy OpenClaw runtime", False),
        (home / ".claude/secrets.json", "legacy Claude secret bundle", False),
        (home / ".openclaw/secrets.json", "legacy OpenClaw secret bundle", False),
    ):
        payload = _read_regular(path, required_mode=0o600)
        if payload is None:
            continue
        document = _json_object(payload, label)
        candidate = document if dedicated else _extract_send_email_document(document)
        if candidate is None:
            continue
        _validate_send_email_document(candidate)
        semantic = _send_email_semantic_value(candidate)
        if selected_semantic is not None and semantic != selected_semantic:
            raise ProjectionError("legacy send-email credential sources conflict")
        if selected is None:
            selected = candidate
            selected_semantic = semantic
    return selected


def _migrate_send_email_legacy(home: Path, selected: dict | None = None) -> str:
    if selected is None:
        selected = _inspect_send_email_legacy(home)
    if selected is None:
        return "absent"
    authority = home / ".config/send-email/secrets.json"
    current_payload = _read_regular(authority, required_mode=0o600)
    desired = _json_payload(selected)
    if current_payload is not None:
        current = _json_object(current_payload, "send-email authority")
        if _send_email_semantic_value(current) == _send_email_semantic_value(selected):
            return "current"
        raise ProjectionError("legacy send-email credential sources conflict")
    _atomic_write(home, authority, desired, 0o600)
    return "migrated"


def _read_env_authority(
    path: Path, allowed_keys: tuple[str, ...], label: str
) -> dict[str, str]:
    payload = _read_regular(path, required_mode=0o600)
    if payload is None:
        return {}
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectionError(f"{label} is not valid UTF-8") from exc
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if raw != line:
            raise ProjectionError(f"{label} contains an invalid line")
        if "=" not in line:
            raise ProjectionError(f"{label} contains an invalid line")
        key, value = line.split("=", 1)
        if key not in allowed_keys or key in values or not value:
            raise ProjectionError(f"{label} contains an invalid key")
        if value != value.strip() or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        ):
            raise ProjectionError(f"{label} contains an invalid value")
        values[key] = value
    return values


def _env_payload(
    values: dict[str, str], allowed_keys: tuple[str, ...], label: str
) -> bytes:
    lines = [f"# coding-system managed {label}; strict KEY=value format\n"]
    lines.extend(f"{key}={values[key]}\n" for key in allowed_keys if key in values)
    return "".join(lines).encode()


def _literal_dotenv_values_and_scrubbed_payload(
    path: Path, allowed_keys: tuple[str, ...]
) -> tuple[dict[str, str], bytes | None]:
    """Parse migrated assignments without evaluation and prepare their removal."""

    payload = _read_regular(path, required_mode=0o600)
    if payload is None:
        return {}, None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectionError("legacy environment authority is not valid UTF-8") from exc
    values: dict[str, str] = {}
    retained: list[str] = []
    changed = False
    allowed = set(allowed_keys)
    assignment = re.compile(
        r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*\Z"
    )
    for original in text.splitlines(keepends=True):
        line = original.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            retained.append(original)
            continue
        match = assignment.fullmatch(line)
        if match is None or match.group(1) not in allowed:
            retained.append(original)
            continue
        key, raw = match.groups()
        if any(character in raw for character in ("$", "`", "\x00")):
            raise ProjectionError("legacy environment credential is not a literal value")
        try:
            # In a shell assignment word, an unquoted '#' after '=' is data,
            # not a comment (for example KEY=abc#def).  Disabling shlex comment
            # stripping preserves that value exactly.  A separate trailing
            # comment becomes additional tokens and therefore fails closed
            # instead of silently changing a credential before source scrub.
            tokens = shlex.split(raw, comments=False, posix=True)
        except ValueError as exc:
            raise ProjectionError("legacy environment credential is not a literal value") from exc
        if len(tokens) != 1 or not tokens[0]:
            raise ProjectionError("legacy environment credential is not a literal value")
        if key in values:
            raise ProjectionError("legacy environment credential is duplicated")
        values[key] = tokens[0]
        changed = True
    rendered = "".join(retained).encode("utf-8")
    return values, rendered if changed else None


def _literal_dotenv_subset(
    home: Path,
    keys: tuple[str, ...],
    label: str,
    *,
    required_keys: tuple[str, ...],
) -> dict[str, str]:
    values, _ = _literal_dotenv_values_and_scrubbed_payload(
        home / ".secrets.env", keys
    )
    if values and any(key not in values for key in required_keys):
        raise ProjectionError(f"legacy {label} source is incomplete")
    return values


def _scrub_literal_dotenv_subset(home: Path, keys: tuple[str, ...]) -> None:
    _values, scrubbed = _literal_dotenv_values_and_scrubbed_payload(
        home / ".secrets.env", keys
    )
    if scrubbed is not None:
        _atomic_write(home, home / ".secrets.env", scrubbed, 0o600)


def _remove_projection(home: Path, destination: Path) -> bool:
    opened_parent = _open_parent_descriptor(home, destination, create=False)
    if opened_parent is None:
        return False
    parent_descriptor, leaf, parent_identity = opened_parent
    try:
        try:
            info = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise ProjectionError("unsafe stale projection")
        os.unlink(leaf, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
        _confirm_parent_identity(home, destination, parent_identity)
        return True
    finally:
        os.close(parent_descriptor)


def _remove_empty_directory(
    home: Path, destination: Path, expected_identity: tuple[int, int]
) -> None:
    opened_parent = _open_parent_descriptor(home, destination, create=False)
    if opened_parent is None:
        raise ProjectionError("legacy GetSciPapers projection changed during removal")
    parent_descriptor, leaf, parent_identity = opened_parent
    try:
        try:
            information = os.stat(
                leaf, dir_fd=parent_descriptor, follow_symlinks=False
            )
        except FileNotFoundError:
            raise ProjectionError(
                "legacy GetSciPapers projection changed during removal"
            ) from None
        if (
            not _safe_directory(information)
            or (information.st_dev, information.st_ino) != expected_identity
        ):
            raise ProjectionError(
                "legacy GetSciPapers projection changed during removal"
            )
        try:
            os.rmdir(leaf, dir_fd=parent_descriptor)
        except OSError as exc:
            raise ProjectionError(
                "legacy GetSciPapers projection changed during removal"
            ) from exc
        os.fsync(parent_descriptor)
        _confirm_parent_identity(home, destination, parent_identity)
    finally:
        os.close(parent_descriptor)


def _atomic_write(home: Path, destination: Path, payload: bytes, mode: int) -> None:
    if len(payload) > MAX_PROJECTION_BYTES:
        raise ProjectionError("projection payload exceeds its bound")
    opened_parent = _open_parent_descriptor(home, destination, create=True)
    if opened_parent is None:  # pragma: no cover - create=True cannot return None
        raise ProjectionError("projection destination parent is unavailable")
    parent_descriptor, leaf, parent_identity = opened_parent
    temporary = ""
    try:
        try:
            existing = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != os.getuid()
            or existing.st_nlink != 1
        ):
            raise ProjectionError("unsafe projection destination")

        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = -1
        for _attempt in range(32):
            temporary = f".projection-{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    temporary, flags, mode, dir_fd=parent_descriptor
                )
                break
            except FileExistsError:
                continue
        if descriptor < 0:
            raise ProjectionError("could not allocate a projection temporary file")
        try:
            os.fchmod(descriptor, mode)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise ProjectionError("projection temporary write failed")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        _confirm_parent_identity(home, destination, parent_identity)
        os.replace(
            temporary,
            leaf,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary = ""
        os.fsync(parent_descriptor)
        _confirm_parent_identity(home, destination, parent_identity)
    finally:
        try:
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=parent_descriptor)
                except FileNotFoundError:
                    pass
        finally:
            os.close(parent_descriptor)


def _mirror(home: Path, source_relative: str, destination_relative: str, mode: int) -> str:
    source = home / source_relative
    destination = home / destination_relative
    payload = _read_regular(source, required_mode=mode)
    if payload is None:
        removed = _remove_projection(home, destination)
        return "removed" if removed else "absent"
    _atomic_write(home, destination, payload, mode)
    return "ready"


def _mirror_preserving_legacy(
    home: Path, source_relative: str, destination_relative: str, mode: int
) -> str:
    payload = _read_regular(home / source_relative, required_mode=mode)
    if payload is None:
        return "legacy-unmigrated"
    _atomic_write(home, home / destination_relative, payload, mode)
    return "ready"


def _materialize_openclaw_skill_subset(
    home: Path,
    *,
    destination_relative: str,
    keys: tuple[str, ...],
    label: str,
) -> str:
    """Project only one OpenClaw skill's keys from the broad host authority."""

    values = _read_env_authority(
        home / ".config/ai-agents-skills/skill.env",
        SKILL_ENV_KEYS,
        "skill credential authority",
    )
    selected = {key: values[key] for key in keys if key in values}
    destination = home / destination_relative
    if not selected:
        removed = _remove_projection(home, destination)
        return "removed" if removed else "absent"
    _atomic_write(home, destination, _env_payload(selected, keys, label), 0o600)
    return "ready"


def _materialize_zotero_secrets(home: Path, *, destination_relative: str) -> str:
    """Build Zotero's exact compound projection without copying broad vaults."""

    shared_payload = _read_regular(
        home / ".config/ai-agents-skills/secrets.json", required_mode=0o600
    )
    shared = (
        _json_object(shared_payload, "ai-agents-skills shared secret authority")
        if shared_payload is not None
        else {}
    )
    skill = _read_env_authority(
        home / ".config/ai-agents-skills/skill.env",
        SKILL_ENV_KEYS,
        "skill credential authority",
    )
    selected = {
        key: shared[key]
        for key in ("ZOTERO_API_KEY", "WEBDAV_PASSWORD", "GDRIVE_CREDENTIALS")
        if key in shared
    }
    if "SEMANTIC_SCHOLAR_API_KEY" in skill:
        selected["SEMANTIC_SCHOLAR_API_KEY"] = skill["SEMANTIC_SCHOLAR_API_KEY"]
    destination = home / destination_relative
    if not selected:
        removed = _remove_projection(home, destination)
        return "removed" if removed else "absent"
    _atomic_write(home, destination, _json_payload(selected), 0o600)
    return "ready"


def _materialize_calibre_secrets(home: Path, *, destination_relative: str) -> str:
    """Project only Calibre's two Drive-related shared-authority fields."""

    shared_payload = _read_regular(
        home / ".config/ai-agents-skills/secrets.json", required_mode=0o600
    )
    shared = (
        _json_object(shared_payload, "ai-agents-skills shared secret authority")
        if shared_payload is not None
        else {}
    )
    selected = {
        key: shared[key]
        for key in ("GDRIVE_CREDENTIALS", "CALIBRE_GDRIVE_FOLDER_ID")
        if key in shared
    }
    destination = home / destination_relative
    if not selected:
        removed = _remove_projection(home, destination)
        return "removed" if removed else "absent"
    _atomic_write(home, destination, _json_payload(selected), 0o600)
    return "ready"


def _validate_openclaw_delivery_string(
    value: object, *, maximum_bytes: int, label: str
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum_bytes
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProjectionError(f"OpenClaw file-delivery {label} is invalid")
    return value


def _validate_openclaw_allowed_targets(
    value: object, *, allow_missing_channels: bool
) -> dict[str, list[str]]:
    supported = set(OPENCLAW_FILE_DELIVERY_CHANNELS)
    if not isinstance(value, dict) or set(value) - supported:
        raise ProjectionError("OpenClaw file-delivery target allowlist is invalid")
    if not allow_missing_channels and set(value) != supported:
        raise ProjectionError("OpenClaw file-delivery target allowlist is invalid")

    normalized: dict[str, list[str]] = {}
    for channel in OPENCLAW_FILE_DELIVERY_CHANNELS:
        targets = value.get(channel, [])
        if not isinstance(targets, list) or len(targets) > OPENCLAW_FILE_DELIVERY_MAX_TARGETS:
            raise ProjectionError("OpenClaw file-delivery target allowlist is invalid")
        validated = [
            _validate_openclaw_delivery_string(
                target,
                maximum_bytes=OPENCLAW_FILE_DELIVERY_MAX_TARGET_BYTES,
                label="target",
            )
            for target in targets
        ]
        if len(validated) != len(set(validated)):
            raise ProjectionError("OpenClaw file-delivery target allowlist is invalid")
        normalized[channel] = validated
    return normalized


def _validate_openclaw_file_delivery_document(
    value: dict,
    *,
    allow_token: bool,
    allow_missing_channels: bool,
) -> dict[str, object]:
    required = {"schema", "delivery_policy"}
    allowed = required | ({"TELEGRAM_BOT_TOKEN"} if allow_token else set())
    if not required.issubset(value) or set(value) - allowed:
        raise ProjectionError("OpenClaw file-delivery document shape is invalid")
    if value.get("schema") != OPENCLAW_FILE_DELIVERY_SCHEMA:
        raise ProjectionError("OpenClaw file-delivery schema is unsupported")
    delivery_policy = value.get("delivery_policy")
    if not isinstance(delivery_policy, dict) or set(delivery_policy) != {
        "allowed_targets"
    }:
        raise ProjectionError("OpenClaw file-delivery policy shape is invalid")
    targets = _validate_openclaw_allowed_targets(
        delivery_policy.get("allowed_targets"),
        allow_missing_channels=allow_missing_channels,
    )
    normalized: dict[str, object] = {
        "schema": OPENCLAW_FILE_DELIVERY_SCHEMA,
        "delivery_policy": {"allowed_targets": targets},
    }
    if "TELEGRAM_BOT_TOKEN" in value:
        if not allow_token:
            raise ProjectionError("OpenClaw file-delivery authority contains a token")
        normalized["TELEGRAM_BOT_TOKEN"] = _validate_openclaw_delivery_string(
            value["TELEGRAM_BOT_TOKEN"],
            maximum_bytes=OPENCLAW_FILE_DELIVERY_MAX_TOKEN_BYTES,
            label="Telegram token",
        )
    return normalized


def _converge_openclaw_file_delivery(home: Path) -> dict[str, str]:
    """Validate the owner-archive authority and retire the old workspace view."""

    authority_path = home / OPENCLAW_FILE_DELIVERY_AUTHORITY_RELATIVE
    projection_path = home / OPENCLAW_FILE_DELIVERY_PROJECTION_RELATIVE
    authority_payload = _read_regular(authority_path, required_mode=0o600)

    if authority_payload is not None and len(authority_payload) > OPENCLAW_FILE_DELIVERY_MAX_BYTES:
        raise ProjectionError("OpenClaw file-delivery authority exceeds its size bound")
    if authority_payload is not None:
        authority_candidate = _strict_json_object(
            authority_payload, "OpenClaw file-delivery authority"
        )
        _validate_openclaw_file_delivery_document(
            authority_candidate,
            allow_token=False,
            allow_missing_channels=False,
        )
        migration = "current"
    else:
        migration = "NOT_CONFIGURED"

    removed = _remove_projection(home, projection_path)
    return {
        "migration": migration,
        "projection": "removed" if removed else "absent",
    }


def _materialize_research_config(home: Path) -> str:
    source = home / ".local/share/ai-agents-skills/runtime/workspace/config/research-compute.toml"
    destination = home / ".openclaw/workspace/config/research-compute.toml"
    payload = _read_regular(source, required_mode=0o644)
    if payload is None:
        removed = _remove_projection(home, destination)
        return "removed" if removed else "absent"
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectionError("research-compute authority is not valid UTF-8") from exc
    replacement = 'broker_state_root = "data/research/research-compute"'
    pattern = re.compile(r"^broker_state_root[ \t]*=.*$", re.MULTILINE)
    matches = pattern.findall(text)
    if len(matches) > 1:
        raise ProjectionError("research-compute authority has ambiguous broker_state_root entries")
    if matches:
        rendered = pattern.sub(replacement, text)
    else:
        lines = text.splitlines(keepends=True)
        insertion = next(
            (index for index, line in enumerate(lines) if line.lstrip().startswith("[")),
            len(lines),
        )
        prefix = "" if insertion == 0 else "\n"
        lines.insert(insertion, f"{prefix}{replacement}\n")
        rendered = "".join(lines)
        if not rendered.endswith("\n"):
            rendered += "\n"
    _atomic_write(home, destination, rendered.encode("utf-8"), 0o600)
    return "ready"


def _inspect_vnu_legacy(home: Path) -> dict | None:
    authority_keys = (*VNU_REQUIRED_KEYS, *VNU_OPTIONAL_KEYS)
    merged: dict[str, str] = {}
    triggered = False
    for path, label, dedicated in (
        (
            home / ".config/vnu-eoffice/secrets.json",
            "VNU eOffice authority",
            True,
        ),
        (
            home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json",
            "legacy OpenClaw VNU eOffice projection",
            True,
        ),
        (home / ".claude/secrets.json", "legacy Claude secret authority", False),
        (home / ".openclaw/secrets.json", "legacy OpenClaw secret authority", False),
    ):
        payload = _read_regular(path, required_mode=0o600)
        if payload is None:
            continue
        document = _json_object(payload, label)
        if dedicated:
            if set(document) - set(VNU_SOURCE_KEYS):
                raise ProjectionError("legacy VNU eOffice credential source is invalid")
            if any(not _nonempty_string(document.get(key)) for key in VNU_REQUIRED_KEYS):
                raise ProjectionError(
                    "legacy VNU eOffice credential source is incomplete"
                )
            triggered = True
        elif any(key in document for key in (*VNU_REQUIRED_KEYS, "VNU_STATE_HMAC_KEY")):
            triggered = True
            for key in VNU_RETIRED_DELIVERY_KEYS:
                if key in document and not _nonempty_string(document[key]):
                    raise ProjectionError(
                        "legacy VNU eOffice credential source is invalid"
                    )
        for key in authority_keys:
            if key not in document:
                continue
            value = document[key]
            if not _nonempty_string(value):
                raise ProjectionError("legacy VNU eOffice credential source is invalid")
            if key in merged and merged[key] != value:
                raise ProjectionError("legacy VNU eOffice credential sources conflict")
            merged[key] = value
    shell_values = _literal_dotenv_subset(
        home,
        VNU_DOTENV_KEYS,
        "VNU eOffice credential",
        required_keys=VNU_REQUIRED_KEYS,
    )
    if shell_values:
        triggered = True
        for key, value in shell_values.items():
            if key in merged and merged[key] != value:
                raise ProjectionError("legacy VNU eOffice credential sources conflict")
            merged[key] = value
    if not triggered:
        return None
    if any(key not in merged for key in VNU_REQUIRED_KEYS):
        raise ProjectionError("legacy VNU eOffice credential source is incomplete")
    return merged


def _migrate_vnu_legacy(home: Path, selected: dict | None = None) -> str:
    if selected is None:
        selected = _inspect_vnu_legacy(home)
    if selected is None:
        return "absent"
    authority = home / ".config/vnu-eoffice/secrets.json"
    current_payload = _read_regular(authority, required_mode=0o600)
    desired = _json_payload(selected)
    if current_payload == desired:
        status = "current"
    else:
        _atomic_write(home, authority, desired, 0o600)
        status = "updated" if current_payload is not None else "migrated"
    _scrub_literal_dotenv_subset(home, VNU_DOTENV_KEYS)
    return status


def _validate_vnu_authority(home: Path) -> None:
    payload = _read_regular(
        home / ".config/vnu-eoffice/secrets.json", required_mode=0o600
    )
    if payload is None:
        return
    value = _json_object(payload, "VNU eOffice authority")
    if any(
        not isinstance(value.get(key), str) or not value[key].strip()
        for key in VNU_REQUIRED_KEYS
    ):
        raise ProjectionError("VNU eOffice authority lacks required credential fields")
    allowed = {*VNU_REQUIRED_KEYS, *VNU_OPTIONAL_KEYS}
    if any(key not in allowed for key in value):
        raise ProjectionError("VNU eOffice authority contains an unsupported field")


def _validate_canvas_authority(home: Path) -> None:
    authority = home / ".config/course/canvas/config.json"
    payload = _read_regular(authority, required_mode=0o600)
    if payload is None:
        return
    value = _json_object(payload, "Canvas authority")
    if set(value) - set(CANVAS_CONFIG_KEYS):
        raise ProjectionError("Canvas authority contains an unsupported field")
    if any(
        not isinstance(value.get(key), str) or not value[key].strip()
        for key in CANVAS_CONFIG_KEYS[:2]
    ):
        raise ProjectionError("Canvas authority lacks required credential fields")
    course_id = value.get("CANVAS_LMS_COURSE_ID")
    if course_id is not None and (
        not isinstance(course_id, str) or not course_id.strip()
    ):
        raise ProjectionError("Canvas authority contains an invalid course id")


def _validate_remote_bridge_authority(home: Path) -> None:
    authority = home / ".config/remote-bridge/secrets.json"
    payload = _read_regular(authority, required_mode=0o600)
    if payload is None:
        return
    value = _json_object(payload, "Remote Bridge authority")
    zulip = value.get("zulip")
    telegram = value.get("telegram")
    usable_zulip = isinstance(zulip, dict) and all(
        isinstance(zulip.get(key), str) and bool(zulip[key].strip())
        for key in ("site", "email", "api_key")
    )
    usable_telegram = isinstance(telegram, dict) and isinstance(
        telegram.get("bot_token"), str
    ) and bool(telegram["bot_token"].strip())
    if not usable_zulip and not usable_telegram:
        raise ProjectionError("Remote Bridge authority has no complete notification channel")
    channels = value.get("notify_channels")
    if channels is not None and (
        not isinstance(channels, list)
        or any(channel not in {"zulip", "telegram"} for channel in channels)
        or ("zulip" in channels and not usable_zulip)
        or ("telegram" in channels and not usable_telegram)
    ):
        raise ProjectionError("Remote Bridge notification channel selection is invalid")


def _validate_aas_authorities(home: Path) -> None:
    shared_payload = _read_regular(
        home / ".config/ai-agents-skills/secrets.json", required_mode=0o600
    )
    if shared_payload is not None:
        shared = _json_object(shared_payload, "ai-agents-skills shared secret authority")
        if set(shared) - set(AAS_SHARED_JSON_KEYS) or any(
            not isinstance(value, str) or not value.strip() for value in shared.values()
        ):
            raise ProjectionError(
                "ai-agents-skills shared secret authority contains unsupported fields"
            )
    _read_env_authority(
        home / ".config/ai-agents-skills/compute.env",
        COMPUTE_ENV_KEYS,
        "compute credential authority",
    )
    _read_env_authority(
        home / ".config/ai-agents-skills/skill.env",
        SKILL_ENV_KEYS,
        "skill credential authority",
    )
    _read_env_authority(
        home / ".config/ai-agents-skills/providers.env",
        PROVIDER_ENV_KEYS,
        "provider credential authority",
    )
    _read_env_authority(
        home / ".config/ai-agents-skills/providers/copilot.env",
        COPILOT_ENV_KEYS,
        "Copilot provider credential authority",
    )
    send_email = _read_regular(
        home / ".config/send-email/secrets.json", required_mode=0o600
    )
    if send_email is not None:
        _json_object(send_email, "send-email authority")


def _strict_json_object(payload: bytes, label: str) -> dict:
    """Decode a JSON object while rejecting duplicate keys at every level."""

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ProjectionError(f"{label} contains duplicate fields")
            value[key] = item
        return value

    try:
        value = json.loads(payload, object_pairs_hook=unique_pairs)
    except ProjectionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectionError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ProjectionError(f"{label} must be a JSON object")
    return value


def _is_legacy_file_delivery_replay_default(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        candidate = Path(value)
    except (OSError, ValueError):
        return False
    suffix = Path(FILE_DELIVERY_REPLAY_RELATIVE).parts
    return bool(
        candidate.is_absolute()
        and os.fspath(candidate) == value
        and len(candidate.parts) > len(suffix)
        and candidate.parts[-len(suffix) :] == suffix
        and all(part not in {"", ".", ".."} for part in candidate.parts[1:])
    )


def _validate_file_delivery_queue_document(value: dict) -> bool:
    """Validate the AAS-native queue authority; return whether it is legacy."""

    if set(value) != FILE_DELIVERY_AUTHORITY_KEYS:
        raise ProjectionError("file-delivery queue authority schema is unsupported")
    if type(value.get("version")) is not int or value["version"] != 1:
        raise ProjectionError("file-delivery queue authority schema is unsupported")
    hmac_key = value.get("hmac_key_hex")
    if not isinstance(hmac_key, str) or not FILE_DELIVERY_HMAC_RE.fullmatch(hmac_key):
        raise ProjectionError("file-delivery queue authority HMAC key is invalid")

    allowed = value.get("allowed")
    if not isinstance(allowed, dict) or not allowed:
        raise ProjectionError("file-delivery queue authority allowlist is empty")
    for channel, targets in allowed.items():
        if not isinstance(channel, str) or not FILE_DELIVERY_CHANNEL_RE.fullmatch(channel):
            raise ProjectionError("file-delivery queue authority channel is invalid")
        if (
            not isinstance(targets, list)
            or not targets
            or any(
                not isinstance(target, str)
                or not target
                or target != target.strip()
                or len(target.encode("utf-8")) > FILE_DELIVERY_MAX_TARGET_BYTES
                or any(ord(character) < 32 or ord(character) == 127 for character in target)
                for target in targets
            )
            or len(targets) != len(set(targets))
        ):
            raise ProjectionError("file-delivery queue target allowlist is invalid")

    age = value.get("max_job_age_seconds")
    if type(age) is not int or not 5 <= age <= 300:
        raise ProjectionError("file-delivery queue job age limit is invalid")
    media_limit = value.get("max_media_bytes")
    if type(media_limit) is not int or not 1 <= media_limit <= 100 * 1024 * 1024:
        raise ProjectionError("file-delivery queue media limit is invalid")

    retention = value.get("replay_retention_seconds")
    if (
        type(retention) is not int
        or retention < age + 60
        or retention > 604_800
    ):
        raise ProjectionError("file-delivery queue retention limit is invalid")
    max_entries = value.get("max_replay_entries")
    if type(max_entries) is not int or not 100 <= max_entries <= 100_000:
        raise ProjectionError("file-delivery queue entry limit is invalid")

    replay = value.get("replay_ledger_dir")
    if replay == FILE_DELIVERY_REPLAY_TOKEN:
        return False
    if _is_legacy_file_delivery_replay_default(replay):
        return True
    raise ProjectionError("file-delivery queue replay ledger is invalid")


def _migrate_file_delivery_queue_authority(home: Path) -> str:
    """Rewrite only the historical canonical replay path to its portable token."""

    path = home / FILE_DELIVERY_AUTHORITY_RELATIVE
    payload = _read_regular(path, required_mode=0o600)
    if payload is None:
        return "absent"
    if len(payload) > FILE_DELIVERY_AUTHORITY_MAX_BYTES:
        raise ProjectionError("file-delivery queue authority exceeds its size bound")
    authority = _strict_json_object(payload, "file-delivery queue authority")
    legacy = _validate_file_delivery_queue_document(authority)
    if not legacy:
        return "current"
    migrated = dict(authority)
    migrated["replay_ledger_dir"] = FILE_DELIVERY_REPLAY_TOKEN
    _atomic_write(home, path, _json_payload(migrated), 0o600)
    return "migrated"


def _validate_remote_bridge_document(value: dict) -> None:
    if set(value) - REMOTE_BRIDGE_TOP_LEVEL_KEYS:
        raise ProjectionError("legacy Remote Bridge authority contains unrelated fields")
    default = value.get("default_channel")
    if default is not None and default not in {"zulip", "telegram"}:
        raise ProjectionError("legacy Remote Bridge default channel is invalid")
    channels = value.get("notify_channels")
    if channels is not None:
        _validate_string_list(channels, "legacy Remote Bridge notification channels")
        if any(channel not in {"zulip", "telegram"} for channel in channels):
            raise ProjectionError("legacy Remote Bridge notification channels are invalid")
    allowed_users = value.get("allowed_user_ids")
    if allowed_users is not None:
        _validate_string_list(allowed_users, "legacy Remote Bridge user allowlist")

    zulip = value.get("zulip")
    complete_zulip = False
    if zulip is not None:
        if not isinstance(zulip, dict) or set(zulip) - REMOTE_BRIDGE_ZULIP_KEYS:
            raise ProjectionError("legacy Remote Bridge Zulip config is invalid")
        if any(not _nonempty_string(zulip.get(key)) for key in ("site", "email", "api_key")):
            raise ProjectionError("legacy Remote Bridge Zulip config is incomplete")
        for key in ("control_stream", "topic_prefix"):
            if key in zulip and not _nonempty_string(zulip[key]):
                raise ProjectionError("legacy Remote Bridge Zulip config is invalid")
        if "allowed_user_ids" in zulip:
            _validate_string_list(
                zulip["allowed_user_ids"], "legacy Remote Bridge Zulip allowlist"
            )
        complete_zulip = True

    telegram = value.get("telegram")
    complete_telegram = False
    if telegram is not None:
        if not isinstance(telegram, dict) or set(telegram) - REMOTE_BRIDGE_TELEGRAM_KEYS:
            raise ProjectionError("legacy Remote Bridge Telegram config is invalid")
        if not _nonempty_string(telegram.get("bot_token")):
            raise ProjectionError("legacy Remote Bridge Telegram config is incomplete")
        if "mode" in telegram and not _nonempty_string(telegram["mode"]):
            raise ProjectionError("legacy Remote Bridge Telegram config is invalid")
        for key in ("allowed_chat_ids", "allowed_user_ids"):
            if key in telegram:
                _validate_string_list(
                    telegram[key], "legacy Remote Bridge Telegram allowlist"
                )
        complete_telegram = True

    if not complete_zulip and not complete_telegram:
        raise ProjectionError("legacy Remote Bridge authority has no complete channel")
    if channels is not None and (
        ("zulip" in channels and not complete_zulip)
        or ("telegram" in channels and not complete_telegram)
    ):
        raise ProjectionError("legacy Remote Bridge notification channels are invalid")


def _legacy_remote_bridge_document(value: dict[str, str]) -> dict:
    zulip = {
        key: value[legacy_key]
        for key, legacy_key in LEGACY_REMOTE_BRIDGE_ZULIP_KEYS.items()
    }
    zulip.update(
        {
            "control_stream": "aas-remote",
            "topic_prefix": "job/",
            "allowed_user_ids": [],
        }
    )
    return {
        "default_channel": "zulip",
        "notify_channels": ["zulip"],
        "allowed_user_ids": [],
        "zulip": zulip,
    }


def _inspect_remote_bridge_legacy(home: Path) -> dict | None:
    selected: dict | None = None
    for path, label in (
        (
            home / ".config/remote-bridge/secrets.json",
            "Remote Bridge authority",
        ),
        (
            home / ".openclaw/workspace/.config/remote-bridge/secrets.json",
            "legacy OpenClaw Remote Bridge projection",
        ),
        (
            home / ".openclaw/workspace/secrets/remote-bridge/secrets.json",
            "older OpenClaw Remote Bridge projection",
        ),
    ):
        payload = _read_regular(path, required_mode=0o600)
        if payload is None:
            continue
        document = _json_object(payload, label)
        _validate_remote_bridge_document(document)
        if selected is not None and document != selected:
            raise ProjectionError("legacy Remote Bridge projections conflict")
        if selected is None:
            selected = document

    legacy_keys = tuple(LEGACY_REMOTE_BRIDGE_ZULIP_KEYS.values())
    legacy = _merged_legacy_json_values(
        home,
        legacy_keys,
        "Remote Bridge Zulip credential",
        complete_per_source=True,
        extra_sources=(
            (
                ".openclaw/workspace/.secrets.json",
                "retired OpenClaw workspace secret projection",
            ),
        ),
    )
    shell_legacy = _literal_dotenv_subset(
        home,
        legacy_keys,
        "Remote Bridge Zulip credential",
        required_keys=legacy_keys,
    )
    for key, value in shell_legacy.items():
        if key in legacy and legacy[key] != value:
            raise ProjectionError("legacy Remote Bridge Zulip credential sources conflict")
        legacy[key] = value
    if not legacy:
        return selected
    if any(not _nonempty_string(legacy.get(key)) for key in legacy_keys):
        raise ProjectionError("legacy Remote Bridge Zulip credential source is incomplete")
    if selected is None:
        selected = _legacy_remote_bridge_document(legacy)
        _validate_remote_bridge_document(selected)
        return selected

    selected = json.loads(json.dumps(selected))
    zulip = selected.get("zulip")
    expected = {
        key: legacy[legacy_key]
        for key, legacy_key in LEGACY_REMOTE_BRIDGE_ZULIP_KEYS.items()
    }
    if zulip is None:
        selected["zulip"] = _legacy_remote_bridge_document(legacy)["zulip"]
    elif any(zulip.get(key) != expected[key] for key in expected):
        raise ProjectionError("legacy Remote Bridge Zulip credential sources conflict")
    _validate_remote_bridge_document(selected)
    return selected


def _migrate_remote_bridge_legacy(home: Path, selected: dict | None = None) -> str:
    """Promote historical dedicated or generic channels into one authority."""

    if selected is None:
        selected = _inspect_remote_bridge_legacy(home)
    if selected is None:
        return "absent"
    authority = home / ".config/remote-bridge/secrets.json"
    current_payload = _read_regular(authority, required_mode=0o600)
    desired = _json_payload(selected)
    if current_payload == desired:
        status = "current"
    else:
        _atomic_write(home, authority, desired, 0o600)
        status = "updated" if current_payload is not None else "migrated"
    _remove_projection(
        home, home / ".openclaw/workspace/secrets/remote-bridge/secrets.json"
    )
    _remove_projection(
        home, home / ".openclaw/workspace/.config/remote-bridge/secrets.json"
    )
    _scrub_literal_dotenv_subset(
        home, tuple(LEGACY_REMOTE_BRIDGE_ZULIP_KEYS.values())
    )
    return status


def _retire_remote_bridge_openclaw_projection(home: Path) -> str:
    """Preserve one legacy dedicated view as host authority, then remove it."""

    projection = home / ".openclaw/workspace/.config/remote-bridge/secrets.json"
    payload = _read_regular(projection, required_mode=0o600)
    if payload is None:
        return "absent"
    candidate = _json_object(payload, "retired OpenClaw Remote Bridge projection")
    _validate_remote_bridge_document(candidate)

    authority = home / ".config/remote-bridge/secrets.json"
    authority_payload = _read_regular(authority, required_mode=0o600)
    if authority_payload is None:
        _atomic_write(home, authority, _json_payload(candidate), 0o600)
        status = "promoted-and-removed"
    else:
        current = _json_object(authority_payload, "Remote Bridge authority")
        _validate_remote_bridge_document(current)
        if current != candidate:
            raise ProjectionError(
                "retired OpenClaw Remote Bridge projection conflicts with its authority"
            )
        status = "removed"
    _remove_projection(home, projection)
    return status


def _migrate_file_authority(
    home: Path,
    destination: Path,
    sources: list[Path],
    *,
    mode: int,
    require_json: bool,
) -> str:
    current_payload = _read_regular(destination, required_mode=mode)
    if current_payload is not None:
        if require_json:
            _json_object(current_payload, "ai-agents-skills config authority")
        return "current"
    for source in sources:
        payload = _read_regular(source, required_mode=mode)
        if payload is None:
            continue
        if require_json:
            _json_object(payload, "legacy ai-agents-skills config")
        _atomic_write(home, destination, payload, mode)
        return "migrated"
    return "absent"


def _migrate_json_authority(home: Path, destination: Path, sources: list[Path]) -> str:
    return _migrate_file_authority(
        home,
        destination,
        sources,
        mode=0o644,
        require_json=True,
    )


def _migrate_canvas_legacy(home: Path) -> str:
    """Extract one unambiguous legacy Canvas credential set into its authority."""

    authority = home / ".config/course/canvas/config.json"
    if _read_regular(authority, required_mode=0o600) is not None:
        _validate_canvas_authority(home)
        return "current"
    course_root = home / ".config/course"
    try:
        root_info = course_root.lstat()
    except FileNotFoundError:
        return "absent"
    if (
        course_root.is_symlink()
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != os.getuid()
    ):
        raise ProjectionError("legacy course config root is unsafe")

    candidates: dict[bytes, dict[str, str]] = {}
    for source in sorted(course_root.glob("*/config.json")):
        if source == authority:
            continue
        parent_info = source.parent.lstat()
        if (
            source.parent.is_symlink()
            or not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.getuid()
        ):
            raise ProjectionError("legacy course config directory is unsafe")
        payload = _read_regular(source, required_mode=0o600)
        if payload is None:
            continue
        value = _json_object(payload, "legacy course config")
        selected = {
            key: value[key].strip()
            for key in CANVAS_CONFIG_KEYS
            if isinstance(value.get(key), str) and value[key].strip()
        }
        if not all(key in selected for key in CANVAS_CONFIG_KEYS[:2]):
            continue
        rendered = _json_payload(selected)
        candidates[rendered] = selected
    if not candidates:
        return "absent"
    if len(candidates) != 1:
        raise ProjectionError(
            "multiple divergent legacy Canvas configs require explicit selection"
        )
    rendered, _selected = next(iter(candidates.items()))
    _atomic_write(home, authority, rendered, 0o600)
    return "migrated"


def _legacy_canvas_config_paths(home: Path) -> tuple[Path, ...]:
    """Discover legacy course configs without following directory symlinks."""

    course_root = home / ".config/course"
    try:
        root_info = course_root.lstat()
    except FileNotFoundError:
        return ()
    if (
        course_root.is_symlink()
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != os.getuid()
    ):
        raise ProjectionError("legacy course config root is unsafe")

    discovered: list[Path] = []
    try:
        children = sorted(course_root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise ProjectionError("legacy course config root is unsafe") from exc
    for child in children:
        try:
            child_info = child.lstat()
        except OSError as exc:
            raise ProjectionError("legacy course config directory is unsafe") from exc
        if child.is_symlink():
            raise ProjectionError("legacy course config directory is unsafe")
        if not stat.S_ISDIR(child_info.st_mode):
            continue
        if child_info.st_uid != os.getuid():
            raise ProjectionError("legacy course config directory is unsafe")
        candidate = child / "config.json"
        try:
            candidate_info = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ProjectionError("legacy course config file is unsafe") from exc
        if (
            candidate.is_symlink()
            or not stat.S_ISREG(candidate_info.st_mode)
            or candidate_info.st_uid != os.getuid()
            or candidate_info.st_nlink != 1
        ):
            raise ProjectionError("legacy course config file is unsafe")
        discovered.append(candidate)
    return tuple(discovered)


def _migrate_strict_env_authority(
    home: Path,
    destination: Path,
    allowed_keys: tuple[str, ...],
    legacy_values: dict[str, str],
    label: str,
) -> str:
    current_payload = _read_regular(destination, required_mode=0o600)
    current = _read_env_authority(destination, allowed_keys, label)
    existed = current_payload is not None
    changed = False
    for key in allowed_keys:
        value = legacy_values.get(key)
        if key not in current and isinstance(value, str) and value.strip():
            if value != value.strip() or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in value
            ):
                raise ProjectionError(f"legacy {label} value is not single-line")
            current[key] = value
            changed = True
    if changed or not existed:
        _atomic_write(
            home,
            destination,
            _env_payload(current, allowed_keys, label),
            0o600,
        )
    if not existed:
        return "migrated" if current else "initialized"
    return "updated" if changed else "current"


def _merged_legacy_json_values(
    home: Path,
    allowed_keys: tuple[str, ...],
    label: str,
    *,
    complete_per_source: bool = False,
    extra_sources: tuple[tuple[str, str], ...] = (),
) -> dict[str, str]:
    """Merge bounded values from historical Claude and OpenClaw authorities."""

    merged: dict[str, str] = {}
    sources = (
        (".claude/secrets.json", "legacy Claude secret authority"),
        (".openclaw/secrets.json", "legacy OpenClaw secret authority"),
        *extra_sources,
    )
    for relative, source_label in sources:
        payload = _read_regular(home / relative, required_mode=0o600)
        if payload is None:
            continue
        document = _json_object(payload, source_label)
        mentioned = [key for key in allowed_keys if key in document]
        if complete_per_source and mentioned and len(mentioned) != len(allowed_keys):
            raise ProjectionError(f"legacy {label} source is incomplete")
        for key in mentioned:
            value = document[key]
            if not isinstance(value, str) or not value.strip():
                raise ProjectionError(f"legacy {label} source is invalid")
            if key in merged and merged[key] != value:
                raise ProjectionError(f"legacy {label} sources conflict")
            merged[key] = value
    return merged


def _merged_legacy_aas_values(home: Path) -> tuple[dict[str, str], bytes | None]:
    """Merge only declared AAS keys from every historical authority.

    Old recovery generations may hold a key in either the Claude or OpenClaw
    JSON bundle, or as a literal assignment in ``.secrets.env``.  Divergent
    copies are ambiguous and must fail before any canonical authority is
    written.
    """

    allowed_keys = (
        *AAS_SHARED_JSON_KEYS,
        *COMPUTE_ENV_KEYS,
        *SKILL_ENV_KEYS,
        *PROVIDER_ENV_KEYS,
        *COPILOT_ENV_KEYS,
    )
    sources = [
        _merged_legacy_json_values(home, allowed_keys, "AAS credential")
    ]
    for relative, label in (
        (
            ".codex/runtime/workspace/.secrets.json",
            "legacy Codex runtime secret projection",
        ),
        (
            ".local/share/ai-agents-skills/runtime/workspace/.secrets.json",
            "legacy shared runtime secret projection",
        ),
        (
            ".openclaw/workspace/.config/ai-agents-skills/secrets.json",
            "legacy bounded OpenClaw secret projection",
        ),
        (
            ".openclaw/workspace/.secrets.json",
            "legacy broad OpenClaw secret projection",
        ),
    ):
        payload = _read_regular(home / relative, required_mode=0o600)
        if payload is None:
            continue
        document = _json_object(payload, label)
        selected: dict[str, str] = {}
        for key in allowed_keys:
            if key not in document:
                continue
            value = document[key]
            if not isinstance(value, str) or not value.strip():
                raise ProjectionError("legacy AAS credential source is invalid")
            selected[key] = value
        sources.append(selected)
    shell_values, scrubbed_dotenv = _literal_dotenv_values_and_scrubbed_payload(
        home / ".secrets.env", allowed_keys
    )
    sources.append(shell_values)

    merged: dict[str, str] = {}
    for source in sources:
        for key, value in source.items():
            if key in merged and merged[key] != value:
                raise ProjectionError("legacy AAS credential sources conflict")
            merged[key] = value
    return merged, scrubbed_dotenv


def _assert_legacy_aas_matches_authorities(home: Path, legacy: dict[str, str]) -> None:
    """Reject authority/legacy conflicts before the migration writes anything."""

    shared_payload = _read_regular(
        home / ".config/ai-agents-skills/secrets.json", required_mode=0o600
    )
    shared = (
        _json_object(shared_payload, "ai-agents-skills secret authority")
        if shared_payload is not None
        else {}
    )
    authorities = (
        shared,
        _read_env_authority(
            home / ".config/ai-agents-skills/compute.env",
            COMPUTE_ENV_KEYS,
            "compute credentials",
        ),
        _read_env_authority(
            home / ".config/ai-agents-skills/skill.env",
            SKILL_ENV_KEYS,
            "skill credentials",
        ),
        _read_env_authority(
            home / ".config/ai-agents-skills/providers.env",
            PROVIDER_ENV_KEYS,
            "provider credentials",
        ),
        _read_env_authority(
            home / ".config/ai-agents-skills/providers/copilot.env",
            COPILOT_ENV_KEYS,
            "Copilot provider credentials",
        ),
    )
    for authority in authorities:
        for key in set(authority).intersection(legacy):
            if authority[key] != legacy[key]:
                raise ProjectionError("legacy AAS credential conflicts with its authority")


def _split_legacy_provider_authority(
    home: Path, legacy: dict[str, str]
) -> None:
    """Promote Copilot keys out of the historical mixed provider vault.

    Older recovery generations stored broad ARL provider keys and native
    Copilot target keys in the same ``providers.env`` file.  Treat that shape
    only as bounded migration input: merge every declared value into the
    preflighted legacy set, reject ambiguity, then scrub Copilot keys from the
    broad authority before either strict authority is materialized.
    """

    path = home / ".config/ai-agents-skills/providers.env"
    payload = _read_regular(path, required_mode=0o600)
    if payload is None:
        return
    mixed_keys = (*PROVIDER_ENV_KEYS, *COPILOT_ENV_KEYS)
    mixed = _read_env_authority(path, mixed_keys, "legacy provider credentials")
    for key, value in mixed.items():
        previous = legacy.get(key)
        if previous is not None and previous != value:
            raise ProjectionError("legacy AAS credential sources conflict")
        legacy[key] = value
    if any(key in mixed for key in COPILOT_ENV_KEYS):
        broad = {key: mixed[key] for key in PROVIDER_ENV_KEYS if key in mixed}
        _atomic_write(
            home,
            path,
            _env_payload(broad, PROVIDER_ENV_KEYS, "provider credentials"),
            0o600,
        )


def _inspect_legacy_zotero_s2_secret(home: Path) -> tuple[str | None, list[tuple[Path, dict]]]:
    """Read the historical lowercase Zotero secret before public config scrub."""

    observed: str | None = None
    documents: list[tuple[Path, dict]] = []
    for path, label in (
        (
            home / ".config/ai-agents-skills/zotero/config.json",
            "Zotero config authority",
        ),
        (home / ".claude/skills/zotero/config.json", "legacy Zotero config"),
        (
            home / ".openclaw/workspace/skills/zotero/config.json",
            "legacy OpenClaw Zotero config projection",
        ),
        (
            home / ".codex/runtime/workspace/skills/zotero/config.json",
            "legacy Codex Zotero config projection",
        ),
        (
            home
            / ".local/share/ai-agents-skills/runtime/workspace/skills/zotero/config.json",
            "legacy shared-runtime Zotero config projection",
        ),
    ):
        payload = _read_regular(path, required_mode=0o644)
        if payload is None:
            continue
        document = _json_object(payload, label)
        documents.append((path, document))
        if "semantic_scholar_api_key" not in document:
            continue
        value = document["semantic_scholar_api_key"]
        if value in (None, ""):
            continue
        if not isinstance(value, str) or not value.strip():
            raise ProjectionError("legacy Zotero Semantic Scholar credential is invalid")
        if observed is not None and observed != value:
            raise ProjectionError("legacy Zotero Semantic Scholar credentials conflict")
        observed = value
    return observed, documents


def _scrub_legacy_zotero_s2_secret(
    home: Path, documents: list[tuple[Path, dict]]
) -> None:
    for path, document in documents:
        if "semantic_scholar_api_key" not in document:
            continue
        cleaned = dict(document)
        cleaned.pop("semantic_scholar_api_key")
        _atomic_write(home, path, _json_payload(cleaned), 0o644)


def _migrate_aas_legacy(home: Path) -> dict[str, str]:
    """Promote bounded legacy skill credentials/configs into neutral authorities."""
    send_email_candidate = _inspect_send_email_legacy(home)
    legacy, scrubbed_dotenv = _merged_legacy_aas_values(home)
    legacy_s2, zotero_documents = _inspect_legacy_zotero_s2_secret(home)
    if legacy_s2 is not None:
        current_s2 = legacy.get("SEMANTIC_SCHOLAR_API_KEY")
        if current_s2 is not None and current_s2 != legacy_s2:
            raise ProjectionError("legacy Zotero Semantic Scholar credentials conflict")
        canonical_skill = _read_env_authority(
            home / ".config/ai-agents-skills/skill.env",
            SKILL_ENV_KEYS,
            "skill credentials",
        )
        canonical_s2 = canonical_skill.get("SEMANTIC_SCHOLAR_API_KEY")
        if canonical_s2 is not None and canonical_s2 != legacy_s2:
            raise ProjectionError("legacy Zotero Semantic Scholar credentials conflict")
        legacy["SEMANTIC_SCHOLAR_API_KEY"] = legacy_s2
    _split_legacy_provider_authority(home, legacy)
    _assert_legacy_aas_matches_authorities(home, legacy)
    send_email_status = _migrate_send_email_legacy(home, send_email_candidate)
    authority_path = home / ".config/ai-agents-skills/secrets.json"
    authority_payload = _read_regular(authority_path, required_mode=0o600)
    authority = (
        _json_object(authority_payload, "ai-agents-skills secret authority")
        if authority_payload is not None
        else {}
    )
    unsupported = sorted(set(authority) - set(AAS_SHARED_JSON_KEYS))
    if unsupported:
        raise ProjectionError(
            "ai-agents-skills shared secret authority contains unsupported fields"
        )
    changed = False
    for key in AAS_SHARED_JSON_KEYS:
        value = legacy.get(key)
        if key not in authority and isinstance(value, str) and value.strip():
            authority[key] = value
            changed = True
    if authority and (authority_payload is None or changed):
        _atomic_write(home, authority_path, _json_payload(authority), 0o600)
    secrets_status = "migrated" if authority_payload is None and authority else (
        "updated" if changed else ("current" if authority else "absent")
    )

    compute_status = _migrate_strict_env_authority(
        home,
        home / ".config/ai-agents-skills/compute.env",
        COMPUTE_ENV_KEYS,
        legacy,
        "compute credentials",
    )
    skill_status = _migrate_strict_env_authority(
        home,
        home / ".config/ai-agents-skills/skill.env",
        SKILL_ENV_KEYS,
        legacy,
        "skill credentials",
    )
    provider_status = _migrate_strict_env_authority(
        home,
        home / ".config/ai-agents-skills/providers.env",
        PROVIDER_ENV_KEYS,
        legacy,
        "provider credentials",
    )
    copilot_status = _migrate_strict_env_authority(
        home,
        home / ".config/ai-agents-skills/providers/copilot.env",
        COPILOT_ENV_KEYS,
        legacy,
        "Copilot provider credentials",
    )

    _scrub_legacy_zotero_s2_secret(home, zotero_documents)
    zotero_status = _migrate_json_authority(
        home,
        home / ".config/ai-agents-skills/zotero/config.json",
        [
            home / ".claude/skills/zotero/config.json",
            home / ".openclaw/workspace/skills/zotero/config.json",
            home / ".codex/runtime/workspace/skills/zotero/config.json",
            home
            / ".local/share/ai-agents-skills/runtime/workspace/skills/zotero/config.json",
        ],
    )
    calibre_status = _migrate_json_authority(
        home,
        home / ".config/ai-agents-skills/calibre/config.json",
        [home / ".claude/skills/calibre/config.json"],
    )
    canvas_status = _migrate_canvas_legacy(home)
    if scrubbed_dotenv is not None:
        _atomic_write(home, home / ".secrets.env", scrubbed_dotenv, 0o600)
    return {
        "secrets": secrets_status,
        "compute": compute_status,
        "skill": skill_status,
        "providers": provider_status,
        "copilot": copilot_status,
        "sendEmail": send_email_status,
        "zotero": zotero_status,
        "calibre": calibre_status,
        "canvas": canvas_status,
    }


def _materialize_kaggle_token(home: Path) -> str:
    compute = _read_env_authority(
        home / ".config/ai-agents-skills/compute.env",
        COMPUTE_ENV_KEYS,
        "compute credential authority",
    )
    destination = home / ".kaggle/access_token"
    token = compute.get("KAGGLE_API_TOKEN")
    if token is None:
        removed = _remove_projection(home, destination)
        return "removed" if removed else "absent"
    _atomic_write(home, destination, (token + "\n").encode(), 0o600)
    return "ready"


def _inspect_legacy_getscipapers_tree(
    home: Path, legacy_root: Path
) -> tuple[set[str], list[tuple[tuple[str, ...], tuple[int, int]]]]:
    opened_parent = _open_parent_descriptor(home, legacy_root, create=False)
    if opened_parent is None:
        return set(), []
    parent_descriptor, leaf, parent_identity = opened_parent
    root_descriptor = -1
    try:
        opened_root = _open_directory_entry(
            parent_descriptor,
            leaf,
            missing_ok=True,
            error="legacy GetSciPapers projection root is unsafe",
        )
        if opened_root is None:
            return set(), []
        root_descriptor, _root_information = opened_root

        allowed_directories: set[tuple[str, ...]] = {()}
        for relative in GETSCIPAPERS_PRIVATE_FILES:
            parts = Path(relative).parts
            allowed_directories.update(
                parts[:length] for length in range(1, len(parts))
            )
        observed_files: set[str] = set()
        observed_directories: list[tuple[tuple[str, ...], tuple[int, int]]] = []

        def inspect(directory_descriptor: int, prefix: tuple[str, ...]) -> None:
            before = os.fstat(directory_descriptor)
            if not _safe_directory(before) or prefix not in allowed_directories:
                raise ProjectionError("legacy GetSciPapers projection tree is unsafe")
            observed_directories.append(
                (prefix, (before.st_dev, before.st_ino))
            )
            try:
                names = sorted(os.listdir(directory_descriptor))
            except OSError as exc:
                raise ProjectionError(
                    "legacy GetSciPapers projection changed during inspection"
                ) from exc
            for name in names:
                if not name or name in {".", ".."} or "/" in name:
                    raise ProjectionError(
                        "legacy GetSciPapers projection tree is unsafe"
                    )
                child_parts = (*prefix, name)
                try:
                    information = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise ProjectionError(
                        "legacy GetSciPapers projection changed during inspection"
                    ) from exc
                if stat.S_ISDIR(information.st_mode):
                    if child_parts not in allowed_directories:
                        raise ProjectionError(
                            "legacy GetSciPapers projection contains unsupported paths"
                        )
                    opened_child = _open_directory_entry(
                        directory_descriptor,
                        name,
                        missing_ok=False,
                        error="legacy GetSciPapers projection tree is unsafe",
                    )
                    if opened_child is None:  # pragma: no cover - missing_ok=False
                        raise ProjectionError(
                            "legacy GetSciPapers projection changed during inspection"
                        )
                    child_descriptor, _child_information = opened_child
                    try:
                        inspect(child_descriptor, child_parts)
                    finally:
                        os.close(child_descriptor)
                    continue

                relative = "/".join(child_parts)
                if relative not in GETSCIPAPERS_PRIVATE_FILES:
                    raise ProjectionError(
                        "legacy GetSciPapers projection contains unsupported paths"
                    )
                if (
                    not stat.S_ISREG(information.st_mode)
                    or information.st_uid != os.getuid()
                    or information.st_nlink != 1
                    or stat.S_IMODE(information.st_mode) != 0o600
                ):
                    raise ProjectionError(
                        "legacy GetSciPapers projection tree is unsafe"
                    )
                observed_files.add(relative)

            after = os.fstat(directory_descriptor)
            if _stable_file_identity(after) != _stable_file_identity(before):
                raise ProjectionError(
                    "legacy GetSciPapers projection changed during inspection"
                )

        inspect(root_descriptor, ())
        _confirm_parent_identity(home, legacy_root, parent_identity)
        return observed_files, observed_directories
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)
        os.close(parent_descriptor)


def _mirror_getscipapers(home: Path) -> tuple[int, int]:
    source_root = home / ".config/getscipapers"
    destination_root = home / ".openclaw/workspace/.config/getscipapers"
    wanted: dict[str, bytes] = {}
    for relative, require_json in GETSCIPAPERS_PRIVATE_FILES.items():
        payload = _read_regular(source_root / relative, required_mode=0o600)
        if payload is not None:
            if require_json:
                _json_object(payload, "GetSciPapers authority")
            wanted[relative] = payload
    copied = 0
    removed = 0
    for relative, require_json in sorted(GETSCIPAPERS_PRIVATE_FILES.items()):
        destination = destination_root / relative
        payload = wanted.get(relative)
        if payload is None:
            if _remove_projection(home, destination):
                removed += 1
        else:
            if require_json:
                _json_object(payload, "GetSciPapers authority")
            _atomic_write(home, destination, payload, 0o600)
            copied += 1
    return copied, removed


def _migrate_and_prune_legacy_getscipapers(home: Path) -> tuple[int, int]:
    """Promote the old sandbox-only tree, then remove that derived copy."""

    legacy_root = home / ".openclaw/workspace/secrets/getscipapers"
    observed_files, observed_directories = _inspect_legacy_getscipapers_tree(
        home, legacy_root
    )
    if not observed_directories:
        return 0, 0

    migrated = 0
    for relative in sorted(observed_files):
        source = legacy_root / relative
        payload = _read_regular(source, required_mode=0o600)
        if payload is None:
            raise ProjectionError("legacy GetSciPapers projection changed during migration")
        if GETSCIPAPERS_PRIVATE_FILES[relative]:
            _json_object(payload, "legacy GetSciPapers projection")
        destination = home / ".config/getscipapers" / relative
        current = _read_regular(destination, required_mode=0o600)
        if current is None:
            _atomic_write(home, destination, payload, 0o600)
            migrated += 1
        elif current != payload:
            raise ProjectionError(
                "legacy GetSciPapers projection diverges from its authority"
            )

    removed = 0
    for relative in sorted(observed_files):
        source = legacy_root / relative
        if not _remove_projection(home, source):
            raise ProjectionError("legacy GetSciPapers projection changed during removal")
        removed += 1
    for relative_parts, identity in sorted(
        observed_directories, key=lambda item: len(item[0]), reverse=True
    ):
        directory = legacy_root.joinpath(*relative_parts)
        _remove_empty_directory(home, directory, identity)
    return migrated, removed


def prune_empty_legacy_getscipapers_tree(home: Path) -> int:
    """Remove the now-empty legacy directory tree after the file commit."""

    home = _require_home(home)
    legacy_root = home / ".openclaw/workspace/secrets/getscipapers"
    observed_files, observed_directories = _inspect_legacy_getscipapers_tree(
        home, legacy_root
    )
    if observed_files:
        raise ProjectionError(
            "legacy GetSciPapers projection changed after transaction"
        )
    removed = 0
    for relative_parts, identity in sorted(
        observed_directories, key=lambda item: len(item[0]), reverse=True
    ):
        directory = legacy_root.joinpath(*relative_parts)
        _remove_empty_directory(home, directory, identity)
        removed += 1
    return removed


def _prune_legacy_backups(home: Path) -> int:
    candidates = list((home / ".openclaw").glob("secrets.json.bak.*"))
    agents = home / ".openclaw/agents"
    if agents.exists() and not agents.is_symlink():
        candidates.extend(agents.glob("*/agent/auth-profiles.json.bak"))
    removed = 0
    for candidate in candidates:
        if _remove_projection(home, candidate):
            removed += 1
    return removed


def _migrate_tailscale_authority(home: Path) -> str:
    """Promote the exact legacy TS fields and retire the executable env file."""

    legacy_path = home / LEGACY_RELATIVE
    legacy_payload = _read_regular(legacy_path, required_mode=0o600)
    try:
        legacy = parse_legacy(legacy_payload) if legacy_payload is not None else {}
    except TailscaleAuthorityError as exc:
        raise ProjectionError("legacy Tailscale authority is invalid") from exc

    authkey_path = home / AUTHKEY_RELATIVE
    hostname_path = home / HOSTNAME_RELATIVE
    authkey_payload = _read_regular(authkey_path, required_mode=0o600)
    hostname_payload = _read_regular(hostname_path, required_mode=0o600)
    try:
        current_authkey = parse_authkey(authkey_payload) if authkey_payload is not None else None
        current_hostname = parse_hostname(hostname_payload) if hostname_payload is not None else None
    except TailscaleAuthorityError as exc:
        raise ProjectionError("Tailscale authority is invalid") from exc

    legacy_authkey = legacy.get("TS_AUTHKEY")
    legacy_hostname = legacy.get("TS_HOSTNAME")
    if legacy_authkey is not None and current_authkey not in (None, legacy_authkey):
        raise ProjectionError("legacy Tailscale auth key conflicts with its authority")
    if legacy_hostname is not None and current_hostname not in (None, legacy_hostname):
        raise ProjectionError("legacy Tailscale hostname conflicts with its setting")
    if current_authkey is None and legacy_authkey is not None:
        _atomic_write(home, authkey_path, (legacy_authkey + "\n").encode("ascii"), 0o600)
        current_authkey = legacy_authkey
    if current_hostname is None:
        selected_hostname = legacy_hostname or ("openclaw" if current_authkey else None)
        if selected_hostname is not None:
            _atomic_write(
                home, hostname_path, (selected_hostname + "\n").encode("ascii"), 0o600
            )
            current_hostname = selected_hostname
    if current_authkey is not None and current_hostname is None:
        raise ProjectionError("Tailscale authority is incomplete")
    removed = _remove_projection(home, legacy_path)
    if legacy_payload is not None:
        return "migrated" if removed else "current"
    return "current" if current_authkey is not None else "absent"


def _materialize(
    home: Path,
    *,
    migrate_vnu_legacy: bool,
    migrate_remote_bridge_legacy: bool,
    migrate_aas_legacy: bool,
) -> dict[str, object]:
    tailscale_migration = _migrate_tailscale_authority(home)
    file_delivery_queue_migration = _migrate_file_delivery_queue_authority(home)
    openclaw_file_delivery = _converge_openclaw_file_delivery(home)
    vnu_candidate = _inspect_vnu_legacy(home) if migrate_vnu_legacy else None
    remote_bridge_candidate = (
        _inspect_remote_bridge_legacy(home) if migrate_remote_bridge_legacy else None
    )
    if migrate_aas_legacy:
        _inspect_send_email_legacy(home)
    migration = (
        _migrate_vnu_legacy(home, vnu_candidate)
        if migrate_vnu_legacy
        else "not-requested"
    )
    remote_bridge_migration = (
        _migrate_remote_bridge_legacy(home, remote_bridge_candidate)
        if migrate_remote_bridge_legacy
        else "not-requested"
    )
    retired_remote_bridge = _retire_remote_bridge_openclaw_projection(home)
    aas_migration = (
        _migrate_aas_legacy(home)
        if migrate_aas_legacy
        else {
            "secrets": "not-requested",
            "compute": "not-requested",
            "skill": "not-requested",
            "providers": "not-requested",
            "copilot": "not-requested",
            "sendEmail": "not-requested",
            "zotero": "not-requested",
            "calibre": "not-requested",
            "canvas": "not-requested",
        }
    )
    _validate_vnu_authority(home)
    _validate_canvas_authority(home)
    _validate_remote_bridge_authority(home)
    _validate_aas_authorities(home)
    getscipapers_migrated, getscipapers_legacy_removed = (
        _migrate_and_prune_legacy_getscipapers(home)
    )
    results = {
        "retired-tailscale-env-projection": (
            "removed" if tailscale_migration == "migrated" else "absent"
        ),
        "aas-secrets-codex-projection": _mirror(
            home, ".config/ai-agents-skills/secrets.json", ".codex/runtime/workspace/.secrets.json", 0o600
        ),
        "aas-secrets-shared-projection": _mirror(
            home,
            ".config/ai-agents-skills/secrets.json",
            ".local/share/ai-agents-skills/runtime/workspace/.secrets.json",
            0o600,
        ),
        "retired-aas-secrets-openclaw-projection": (
            "removed"
            if _remove_projection(
                home,
                home
                / ".openclaw/workspace/.config/ai-agents-skills/secrets.json",
            )
            else "absent"
        ),
        "retired-send-email-openclaw-projection": (
            "removed"
            if _remove_projection(
                home,
                home / ".openclaw/workspace/.config/send-email/secrets.json",
            )
            else "absent"
        ),
        "aas-compute-openclaw-projection": _mirror(
            home,
            ".config/ai-agents-skills/compute.env",
            ".openclaw/workspace/.config/ai-agents-skills/compute.env",
            0o600,
        ),
        "retired-aas-skill-secrets-openclaw-projection": (
            "removed"
            if _remove_projection(
                home,
                home / ".openclaw/workspace/.config/ai-agents-skills/skill.env",
            )
            else "absent"
        ),
        "aas-axle-openclaw-projection": _materialize_openclaw_skill_subset(
            home,
            destination_relative=(
                ".openclaw/workspace/.config/ai-agents-skills/axiom-axle.env"
            ),
            keys=("AXLE_API_KEY",),
            label="OpenClaw Axiom AXLE credentials",
        ),
        "aas-leanexplore-openclaw-projection": (
            _materialize_openclaw_skill_subset(
                home,
                destination_relative=(
                    ".openclaw/workspace/.config/ai-agents-skills/lean-explore.env"
                ),
                keys=("LEANEXPLORE_API_KEY",),
                label="OpenClaw LeanExplore credentials",
            )
        ),
        "aas-research-digest-openclaw-projection": (
            _materialize_openclaw_skill_subset(
                home,
                destination_relative=(
                    ".openclaw/workspace/.config/ai-agents-skills/research-digest.env"
                ),
                keys=("OPENCLAW_S2_API_KEY",),
                label="OpenClaw research digest credentials",
            )
        ),
        "aas-submission-venue-openclaw-projection": (
            _materialize_openclaw_skill_subset(
                home,
                destination_relative=(
                    ".openclaw/workspace/.config/ai-agents-skills/submission-venue.env"
                ),
                keys=("SEMANTIC_SCHOLAR_API_KEY", "UNPAYWALL_EMAIL"),
                label="OpenClaw submission venue credentials",
            )
        ),
        "aas-zotero-host-projection": _materialize_zotero_secrets(
            home,
            destination_relative=(
                ".config/ai-agents-skills/zotero-secrets.json"
            ),
        ),
        "aas-zotero-skill-openclaw-projection": (
            _materialize_zotero_secrets(
                home,
                destination_relative=(
                    ".openclaw/workspace/.config/ai-agents-skills/zotero-secrets.json"
                ),
            )
        ),
        "aas-calibre-host-projection": _materialize_calibre_secrets(
            home,
            destination_relative=(
                ".config/ai-agents-skills/calibre-secrets.json"
            ),
        ),
        "aas-calibre-openclaw-projection": _materialize_calibre_secrets(
            home,
            destination_relative=(
                ".openclaw/workspace/.config/ai-agents-skills/calibre-secrets.json"
            ),
        ),
        "retired-openclaw-file-delivery-projection": openclaw_file_delivery[
            "projection"
        ],
        "aas-provider-secrets-openclaw-projection": _mirror(
            home,
            ".config/ai-agents-skills/providers.env",
            ".openclaw/workspace/.config/ai-agents-skills/providers.env",
            0o600,
        ),
        "aas-copilot-provider-openclaw-projection": _mirror(
            home,
            ".config/ai-agents-skills/providers/copilot.env",
            ".openclaw/workspace/.config/ai-agents-skills/providers/copilot.env",
            0o600,
        ),
        "retired-remote-bridge-openclaw-projection": retired_remote_bridge,
        "kaggle-access-token-projection": _materialize_kaggle_token(home),
        "course-google-credentials-openclaw-projection": _mirror(
            home,
            ".config/course/google-classroom/credentials.json",
            ".openclaw/workspace/.config/course/google-classroom/credentials.json",
            0o600,
        ),
        "course-google-token-openclaw-projection": _mirror(
            home,
            ".config/course/google-classroom/token.pickle",
            ".openclaw/workspace/.config/course/google-classroom/token.pickle",
            0o600,
        ),
        "course-canvas-openclaw-projection": _mirror(
            home,
            ".config/course/canvas/config.json",
            ".openclaw/workspace/.config/course/canvas/config.json",
            0o600,
        ),
        "vnu-eoffice-openclaw-projection": _mirror(
            home,
            ".config/vnu-eoffice/secrets.json",
            ".openclaw/workspace/secrets/vnu-eoffice/secrets.json",
            0o600,
        ),
        "modal-openclaw-projection": _mirror(
            home, ".modal.toml", ".openclaw/workspace/.modal.toml", 0o600
        ),
        "openclaw-research-compute-projection": _materialize_research_config(home),
        "openclaw-zotero-config-projection": _mirror(
            home,
            ".config/ai-agents-skills/zotero/config.json",
            ".openclaw/workspace/skills/zotero/config.json",
            0o644,
        ),
        "codex-zotero-config-projection": _mirror(
            home,
            ".config/ai-agents-skills/zotero/config.json",
            ".codex/runtime/workspace/skills/zotero/config.json",
            0o644,
        ),
        "aas-zotero-config-projection": _mirror(
            home,
            ".config/ai-agents-skills/zotero/config.json",
            ".local/share/ai-agents-skills/runtime/workspace/skills/zotero/config.json",
            0o644,
        ),
        "claude-zotero-config-projection": _mirror_preserving_legacy(
            home,
            ".config/ai-agents-skills/zotero/config.json",
            ".claude/skills/zotero/config.json",
            0o644,
        ),
        "openclaw-calibre-config-projection": _mirror(
            home,
            ".config/ai-agents-skills/calibre/config.json",
            ".openclaw/workspace/skills/calibre/config.json",
            0o644,
        ),
        "codex-calibre-config-projection": _mirror(
            home,
            ".config/ai-agents-skills/calibre/config.json",
            ".codex/runtime/workspace/skills/calibre/config.json",
            0o644,
        ),
        "aas-calibre-config-projection": _mirror(
            home,
            ".config/ai-agents-skills/calibre/config.json",
            ".local/share/ai-agents-skills/runtime/workspace/skills/calibre/config.json",
            0o644,
        ),
        "claude-calibre-config-projection": _mirror_preserving_legacy(
            home,
            ".config/ai-agents-skills/calibre/config.json",
            ".claude/skills/calibre/config.json",
            0o644,
        ),
        "openclaw-github-cli-hosts-projection": _mirror(
            home,
            ".config/gh/hosts.yml",
            ".openclaw/workspace/.config/gh/hosts.yml",
            0o600,
        ),
        "openclaw-github-cli-config-projection": _mirror(
            home,
            ".config/gh/config.yml",
            ".openclaw/workspace/.config/gh/config.yml",
            0o600,
        ),
    }
    copied, removed = _mirror_getscipapers(home)
    results["getscipapers-openclaw-projection"] = {
        "ready": copied,
        "staleRemoved": removed,
        "legacyMigrated": getscipapers_migrated,
        "legacyRemoved": getscipapers_legacy_removed,
    }
    retired_workspace_secret_removed = _remove_projection(
        home, home / ".openclaw/workspace/.secrets.json"
    )
    results["retired-openclaw-workspace-secrets-projection"] = (
        "removed" if retired_workspace_secret_removed else "absent"
    )
    results["retiredOpenClawWorkspaceSecretsRemoved"] = int(
        retired_workspace_secret_removed
    )
    results["legacyBackupProjectionsRemoved"] = _prune_legacy_backups(home)
    results["vnuLegacyMigration"] = migration
    results["remoteBridgeLegacyMigration"] = remote_bridge_migration
    results["aasLegacyMigration"] = aas_migration
    results["tailscaleMigration"] = tailscale_migration
    results["fileDeliveryQueueMigration"] = file_delivery_queue_migration
    results["openClawFileDeliveryPolicyMigration"] = openclaw_file_delivery[
        "migration"
    ]
    try:
        read_owner_settings(home / ".secrets.env")
    except OwnerSettingsError as exc:
        raise ProjectionError("private owner settings violate the data-only contract") from exc
    return results


def materialize(
    home: Path,
    *,
    migrate_vnu_legacy: bool,
    migrate_remote_bridge_legacy: bool,
    migrate_aas_legacy: bool,
) -> dict[str, object]:
    home = _require_home(home)
    _converge_declared_private_directories(home)
    _converge_opencode_sqlite_permissions(home)
    _converge_getscipapers_permissions(home)
    _ensure_file_delivery_replay_directory(home)
    token = _ACTIVE_HOME.set(home)
    try:
        return _materialize(
            home,
            migrate_vnu_legacy=migrate_vnu_legacy,
            migrate_remote_bridge_legacy=migrate_remote_bridge_legacy,
            migrate_aas_legacy=migrate_aas_legacy,
        )
    finally:
        _ACTIVE_HOME.reset(token)


def materialize_transactionally(
    home: Path,
    *,
    migrate_vnu_legacy: bool,
    migrate_remote_bridge_legacy: bool,
    migrate_aas_legacy: bool,
) -> dict[str, object]:
    """Preflight then atomically commit the standalone materializer surface."""

    home = _require_home(home)
    with secure_temporary_directory(prefix="csr-projection-transaction-") as temporary:
        work = Path(temporary)
        virtual_home = work / "virtual-home"
        output_stage = work / "stage"
        virtual_home.mkdir(mode=0o700)
        output_stage.mkdir(mode=0o700)
        inputs, mutations = transaction_file_contract(home)
        snapshot_transaction_inputs(home, virtual_home, inputs)
        result = materialize(
            virtual_home,
            migrate_vnu_legacy=migrate_vnu_legacy,
            migrate_remote_bridge_legacy=migrate_remote_bridge_legacy,
            migrate_aas_legacy=migrate_aas_legacy,
        )
        modes = export_transaction_files(virtual_home, output_stage, mutations)
        transactional_apply(output_stage, home, modes, replace=True)
        prune_empty_legacy_getscipapers_tree(home)
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--migrate-vnu-legacy", action="store_true")
    parser.add_argument("--migrate-remote-bridge-legacy", action="store_true")
    parser.add_argument("--migrate-aas-legacy", action="store_true")
    args = parser.parse_args()
    result = materialize_transactionally(
        args.home,
        migrate_vnu_legacy=args.migrate_vnu_legacy,
        migrate_remote_bridge_legacy=args.migrate_remote_bridge_legacy,
        migrate_aas_legacy=args.migrate_aas_legacy,
    )
    getscipapers = result["getscipapers-openclaw-projection"]
    stale_count = (
        getscipapers["staleRemoved"]
        + getscipapers["legacyRemoved"]
        + result["retiredOpenClawWorkspaceSecretsRemoved"]
        + result["legacyBackupProjectionsRemoved"]
    )
    # Counts/status only; never include authority or destination paths because
    # service names and personal layouts can themselves be sensitive.
    print(
        "secret projections: converged; "
        f"getscipapers={getscipapers['ready']}; "
        f"stale={stale_count}; "
        f"vnu-migration={result['vnuLegacyMigration']}; "
        f"remote-bridge-migration={result['remoteBridgeLegacyMigration']}"
        f"; aas-migration={result['aasLegacyMigration']['secrets']}/"
        f"{result['aasLegacyMigration']['compute']}/"
        f"{result['aasLegacyMigration']['skill']}/"
        f"{result['aasLegacyMigration']['providers']}/"
        f"{result['aasLegacyMigration']['copilot']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProjectionError as exc:
        print(f"materialize-secret-projections: {exc}", file=os.sys.stderr)
        raise SystemExit(2)
    except OSError:
        print(
            "materialize-secret-projections: filesystem operation failed",
            file=os.sys.stderr,
        )
        raise SystemExit(2)
    except (RestoreTransactionError, SecureTempError):
        print(
            "materialize-secret-projections: transaction failed",
            file=os.sys.stderr,
        )
        raise SystemExit(2)
