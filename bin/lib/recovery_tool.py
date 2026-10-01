#!/usr/bin/env python3
"""Create, validate, and safely restore coding-system recovery sets.

Secret material is accepted only through regular files (or inherited file
descriptors in the GnuPG child).  No command prints a secret, share, or
decrypted archive member.  The public recovery-set manifest is written last,
which makes its presence the commit marker for an immutable generation.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from contextlib import contextmanager
import errno
import fnmatch
import hashlib
import hmac
import importlib.util
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import secrets
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from datetime import datetime, timezone
from typing import Iterable, Iterator

import yaml


LIB_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = LIB_DIR.parents[1]
if str(LIB_DIR) not in sys.path:
    sys.path.insert(0, str(LIB_DIR))
from shamir import combine as shamir_combine  # noqa: E402
from shamir import split as shamir_split  # noqa: E402
from secure_temp import SecureTempError, secure_temporary_directory  # noqa: E402
from restore_transaction import (  # noqa: E402
    RestoreTransactionError,
    recover_pending_transactions,
    transactional_apply,
)


SECRETS_SCHEMA = "coding-system.secrets-manifest.v2"
ESCROW_SCHEMA = "coding-system.escrow-generation.v1"
RECOVERY_SCHEMA = "coding-system.recovery-set.v2"
LEGACY_RECOVERY_SCHEMA = "coding-system.recovery-set.v1"
KEYS_SCHEMA = "coding-system.recovery-keys.v1"
CLASSIFICATIONS = {"authority", "projection", "session", "private-state"}
PORTABILITY = {"portable", "reauth-required", "machine-bound", "regenerated"}
CAPTURE_POLICIES = {"regular", "sqlite-backup"}
COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{7,127}\Z")
MAX_SECRET_FILE = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_OWNER_DATA_BYTES = 8 * 1024 * 1024 * 1024
MAX_OPENCLAW_AUTH_JSON_BYTES = 16 * 1024 * 1024
MAX_OPENCLAW_AGENT_DB_BYTES = 512 * 1024 * 1024
MAX_OPENCLAW_GLOBAL_DB_BYTES = 512 * 1024 * 1024
MAX_KEYS_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_RECOVERY_SIGNING_KEY_BYTES = 64 * 1024
RECOVERY_SIGNATURE_FILES = {
    "recovery-set.json.sig",
    "recovery-signing-public-key.pub",
}
RECOVERY_SIGNING_IDENTITY = "coding-system-recovery"
RECOVERY_SIGNING_NAMESPACE = "coding-system-recovery-set-v1"
RECOVERY_SIGNING_KEY_SHA256 = (
    "c869a7314609cc6a6c167a3dc7e4f8456b7c0ac11eeb9dd091db0d99b3b82898"
)
RECOVERY_SNAPSHOT_REQUIRED = frozenset(
    {
        "recovery-set.json",
        "recovery-set.json.sig",
        "recovery-signing-public-key.pub",
        "escrow-generation.json",
        "keys.json.gpg",
        "secrets.tar.gpg",
        "private-state.tar.gpg",
    }
)
RECOVERY_SNAPSHOT_ALLOWED = RECOVERY_SNAPSHOT_REQUIRED | {"restore-ubuntu.sh"}
OWNER_DATA_FILENAME_RE = re.compile(
    r"openclaw-private-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.gpg\Z"
)
OPENCLAW_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+~_-]{0,127}\Z")
OPENCLAW_AGENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
OWNER_DATA_REQUIREMENTS = frozenset(
    {"agent-private-capability", "history-only"}
)
OWNER_DATA_CAPTURE_POLICIES = frozenset(
    {"fresh-native-snapshot", "reviewed-prebuilt-override"}
)
OPENCLAW_FILE_DELIVERY_SCHEMA = "openclaw.file-delivery-policy/v1"
OPENCLAW_FILE_DELIVERY_CHANNELS = frozenset(
    {"telegram", "zulip", "googlechat", "whatsapp", "zalo"}
)
DISCOVERY_ROOTS = (
    ".bashrc.pre-coding-system",
    ".cache/huggingface/token",
    ".git-credentials",
    ".huggingface",
    ".kaggle",
    ".modal.toml",
    ".netrc",
    ".npmrc",
    ".npmrc.pre-coding-system",
    ".pypirc",
    ".profile.pre-coding-system",
    ".secrets.env",
    ".aws",
    ".claude.json",
    ".claude",
    ".codewhale",
    ".codex",
    ".config",
    ".copilot",
    ".deepseek",
    ".docker",
    ".gemini",
    ".gauss",
    ".gnupg",
    ".grok",
    ".kimi-code",
    ".local/share",
    ".local/state",
    ".openclaw",
    ".ssh",
    "forms/apps/api/.dev.vars",
    "forms/apps/classroom50-runner/.env",
    "forms/apps/web/.env.local",
)
DISCOVERY_SKIP_DIRS = {
    ".cache",
    ".git",
    ".local",
    ".tmp",
    ".venv",
    ".venvs",
    "__pycache__",
    "ai-agents-skills",
    "applications",
    "cache",
    "crashes",
    "docling-venv",
    "forms-private-backups",
    "history",
    "lib",
    "learnings",
    "log",
    "logs",
    # Generated third-party marketplace checkouts are immutable package-manager
    # inputs, not live credential authorities.  Keep user-owned skills/plugins
    # in scope while excluding only these known vendor/cache roots.
    "marketplace-cache",
    "marketplaces",
    "memory",
    "node_modules",
    "man",
    "nano",
    "pipx",
    "sandbox",
    "sessions",
    "tmp",
    "trash",
    "updates",
    "user-history",
}
STRUCTURED_DISCOVERY_SKIP_COMPONENTS = frozenset(
    {
        "build",
        "dist",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "test",
        "tests",
        "testdata",
        "vendor",
        "vendors",
    }
)
STRUCTURED_DISCOVERY_PREFIXES = (
    ".claude/",
    ".codewhale/",
    ".codex/",
    ".config/claude/",
    ".config/codex/",
    ".config/gemini/",
    ".config/opencode/",
    ".config/.wrangler/",
    ".copilot/",
    ".deepseek/",
    ".gemini/",
    ".kimi-code/",
    ".local/share/",
    ".local/state/",
    ".openclaw/",
)
STRUCTURED_DISCOVERY_NAMES = frozenset(
    {
        "config.json",
        "config.toml",
        "default.toml",
        "mcp-config.json",
        "mcp.json",
        "mcp.toml",
        "model.json",
        "models.json",
        "settings.json",
        "settings.toml",
    }
)
SQLITE_DISCOVERY_EXTENSIONS = (".db", ".sqlite", ".sqlite3")
SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
SQLITE_SECRET_COLUMN_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "auth_token",
        "bearer_token",
        "client_secret",
        "credential",
        "credentials",
        "password",
        "private_key",
        "private_key_pem",
        "refresh_token",
        "secret",
    }
)
MAX_SQLITE_SCHEMA_TABLES = 4096
MAX_SQLITE_SCHEMA_COLUMNS = 65_536
STRUCTURED_SECRET_FIELD_NAMES = frozenset(
    {
        "access_key",
        "access_token",
        "accesskey",
        "accesstoken",
        "api_key",
        "apikey",
        "auth_token",
        "authorization",
        "bearer_token",
        "bot_token",
        "client_secret",
        "credential",
        "credentials",
        "oauth_token",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "token",
    }
)
STRUCTURED_SECRET_FIELD_NAMES_COMPACT = frozenset(
    name.replace("_", "") for name in STRUCTURED_SECRET_FIELD_NAMES
)


class RecoveryError(RuntimeError):
    """A redaction-safe recovery contract failure."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise RecoveryError("duplicate YAML mapping key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _json_loads_unique(raw: bytes) -> object:
    def unique_pairs(pairs):
        mapping = {}
        for key, value in pairs:
            if key in mapping:
                raise RecoveryError("duplicate JSON mapping key")
            mapping[key] = value
        return mapping

    return json.loads(raw, object_pairs_hook=unique_pairs)


def _validate_timestamp(value: object, label: str) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RecoveryError(f"invalid {label} timestamp")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise RecoveryError(f"invalid {label} timestamp") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> str:
    digest = hashlib.sha256()
    descriptor = _open_regular(path, max_bytes=max_bytes)
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _safe_pattern(value: object, *, label: str = "path") -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise RecoveryError(f"invalid {label}")
    if value.startswith("/") or "\x00" in value:
        raise RecoveryError(f"unsafe {label}")
    parts = value.rstrip("/").split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise RecoveryError(f"unsafe {label}")
    return value


def _safe_member_name(value: str) -> str:
    _safe_pattern(value, label="archive member")
    if len(value.encode("utf-8")) > 4096 or any(
        len(part.encode("utf-8")) > 255 for part in value.split("/")
    ):
        raise RecoveryError("archive member path exceeds filesystem bounds")
    if any(character in value for character in ("*", "?", "[")):
        raise RecoveryError("archive member contains glob syntax")
    pure = PurePosixPath(value)
    normalized = pure.as_posix()
    if normalized != value or pure.is_absolute():
        raise RecoveryError("archive member is not canonical")
    return value


def _parse_mode(value: object, *, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0[0-7]{3}", value):
        raise RecoveryError(f"invalid mode for {label}")
    mode = int(value, 8)
    if mode & 0o7000:
        raise RecoveryError(f"privileged mode is forbidden for {label}")
    return mode


def _parse_secrets_manifest(raw: bytes, *, name: str) -> dict:
    try:
        value = yaml.load(raw, Loader=_UniqueKeyLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RecoveryError(f"invalid YAML: {name}") from exc
    if not isinstance(value, dict):
        raise RecoveryError(f"invalid mapping: {name}")
    return value


def _validate_secrets_manifest(manifest: dict) -> dict:
    if manifest.get("schema") != SECRETS_SCHEMA:
        raise RecoveryError(f"secrets manifest must use {SECRETS_SCHEMA}")
    if set(manifest) != {"schema", "entry_defaults", "dir_perms", "entries"}:
        raise RecoveryError("secrets manifest has unexpected fields")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise RecoveryError("secrets manifest entries are missing")
    dir_perms = manifest.get("dir_perms", {})
    if not isinstance(dir_perms, dict):
        raise RecoveryError("secrets manifest dir_perms must be a mapping")
    for directory, mode in dir_perms.items():
        _safe_pattern(directory, label="directory path")
        _parse_mode(mode, label=directory)

    defaults = manifest.get("entry_defaults")
    if not isinstance(defaults, dict) or set(defaults) != {
        "classification",
        "portability",
        "backup",
    }:
        raise RecoveryError("secrets manifest entry_defaults are invalid")
    if defaults["classification"] not in CLASSIFICATIONS:
        raise RecoveryError("invalid default secret classification")
    if defaults["portability"] not in PORTABILITY or type(defaults["backup"]) is not bool:
        raise RecoveryError("invalid default secret portability/backup policy")

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    authorities: set[str] = set()
    allowed_entry_fields = {
        "id",
        "path",
        "mode",
        "required",
        "classification",
        "authority",
        "portability",
        "backup",
        "feature",
        "obtain",
        "exclude",
        "legacy_import",
        "capture",
    }
    for entry in entries:
        if not isinstance(entry, dict):
            raise RecoveryError("secrets manifest entry is not a mapping")
        if not set(entry).issubset(allowed_entry_fields):
            raise RecoveryError("secrets manifest entry has unexpected fields")
        legacy_import = entry.get("legacy_import")
        if legacy_import not in (None, "generated", "destination-authority"):
            raise RecoveryError("secrets manifest entry has invalid legacy import policy")
        capture = entry.get("capture", "regular")
        if capture not in CAPTURE_POLICIES:
            raise RecoveryError("secrets manifest entry has invalid capture policy")
        for key, default in defaults.items():
            entry.setdefault(key, default)
        path_value = _safe_pattern(entry.get("path"), label="entry path")
        entry_id = entry.get("id")
        if entry_id is None:
            entry_id = "secret-" + hashlib.sha256(path_value.encode("utf-8")).hexdigest()[:16]
            entry["id"] = entry_id
        if not isinstance(entry_id, str) or not ID_RE.fullmatch(entry_id):
            raise RecoveryError("secrets manifest entry has an invalid id")
        if entry_id in seen_ids:
            raise RecoveryError(f"duplicate secrets manifest id: {entry_id}")
        seen_ids.add(entry_id)
        path_value = _safe_pattern(entry.get("path"), label=f"path for {entry_id}")
        if path_value in seen_paths:
            raise RecoveryError(f"duplicate secrets manifest path: {path_value}")
        seen_paths.add(path_value)
        classification = entry.get("classification")
        if classification not in CLASSIFICATIONS:
            raise RecoveryError(f"invalid classification for {entry_id}")
        authority = entry.get("authority")
        if authority is None and classification != "projection":
            authority = entry_id
            entry["authority"] = authority
        if not isinstance(authority, str) or not ID_RE.fullmatch(authority):
            raise RecoveryError(f"invalid authority for {entry_id}")
        portability = entry.get("portability")
        if portability not in PORTABILITY:
            raise RecoveryError(f"invalid portability for {entry_id}")
        if type(entry.get("required")) is not bool or type(entry.get("backup")) is not bool:
            raise RecoveryError(f"required/backup flags must be booleans for {entry_id}")
        if capture == "sqlite-backup" and (
            not entry["backup"]
            or any(character in path_value for character in ("*", "?", "["))
            or path_value.endswith("/")
            or not path_value.casefold().endswith(SQLITE_DISCOVERY_EXTENSIONS)
            or _parse_mode(entry.get("mode"), label=entry_id) != 0o600
        ):
            raise RecoveryError(
                f"SQLite backup capture must name one private database: {entry_id}"
            )
        if legacy_import is not None and (
            not entry["required"] or not entry["backup"]
        ):
            raise RecoveryError(
                f"legacy import policy is limited to a required backup entry: {entry_id}"
            )
        if legacy_import == "destination-authority" and classification != "authority":
            raise RecoveryError(
                f"legacy destination authority must be an authority: {entry_id}"
            )
        _parse_mode(entry.get("mode"), label=entry_id)
        if not isinstance(entry.get("feature"), str) or not isinstance(entry.get("obtain"), str):
            raise RecoveryError(f"feature/obtain metadata is missing for {entry_id}")
        excludes = entry.get("exclude", [])
        if not isinstance(excludes, list) or not all(isinstance(x, str) for x in excludes):
            raise RecoveryError(f"invalid excludes for {entry_id}")
        if classification == "authority":
            if authority != entry_id:
                raise RecoveryError(f"authority entry {entry_id} must self-identify")
            authorities.add(entry_id)
        elif classification == "projection":
            if entry["backup"]:
                raise RecoveryError(f"projection {entry_id} cannot enable backup")
            if portability != "regenerated":
                raise RecoveryError(f"projection {entry_id} must be regenerated")
    for entry in entries:
        if entry["classification"] == "projection" and entry["authority"] not in authorities:
            raise RecoveryError(
                f"projection {entry['id']} references unknown authority {entry['authority']}"
            )
    return manifest


def _read_secrets_manifest_snapshot(path: Path | str) -> tuple[dict, bytes, str]:
    """Read one immutable, bounded manifest snapshot for parsing and hashing."""
    path = Path(path)
    raw = _read_regular_bytes(path, max_bytes=MAX_MANIFEST_BYTES)
    manifest = _validate_secrets_manifest(
        _parse_secrets_manifest(raw, name=path.name)
    )
    return manifest, raw, _sha256_bytes(raw)


def load_secrets_manifest(path: Path | str) -> dict:
    manifest, _raw, _digest = _read_secrets_manifest_snapshot(path)
    return manifest


def _git_file_at_commit(
    component_commit: str, relative: str, *, maximum: int
) -> bytes | None:
    """Return one immutable blob when this repository has the referenced commit."""
    commit_object = f"{component_commit}^{{commit}}"
    blob_object = f"{component_commit}:{relative}"

    def run(*arguments: str) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                ["git", "-C", str(REPOSITORY_ROOT), *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )
        except FileNotFoundError as exc:
            raise RecoveryError("git is required to bind an available repository commit") from exc
        except subprocess.TimeoutExpired as exc:
            raise RecoveryError("git commit binding timed out") from exc

    available = run("cat-file", "-e", commit_object)
    if available.returncode != 0:
        return None
    size_result = run("cat-file", "-s", blob_object)
    if size_result.returncode != 0:
        raise RecoveryError(f"referenced commit lacks {relative}")
    try:
        size = int(size_result.stdout.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise RecoveryError(f"invalid committed file size: {relative}") from exc
    if not 0 < size <= maximum:
        raise RecoveryError(f"committed file exceeds the recovery bound: {relative}")
    blob_result = run("cat-file", "blob", blob_object)
    if blob_result.returncode != 0 or len(blob_result.stdout) != size:
        raise RecoveryError(f"cannot read committed file: {relative}")
    return bytes(blob_result.stdout)


def _git_manifest_at_commit(component_commit: str) -> bytes | None:
    return _git_file_at_commit(
        component_commit,
        "secrets/secrets-manifest.yaml",
        maximum=MAX_MANIFEST_BYTES,
    )


def _bind_manifest_to_commit(
    manifest_raw: bytes, manifest_digest: str, component_commit: str
) -> None:
    committed_raw = _git_manifest_at_commit(component_commit)
    if committed_raw is None:
        return
    if not secrets.compare_digest(_sha256_bytes(committed_raw), manifest_digest):
        raise RecoveryError(
            "secrets manifest does not match the referenced coding-system-rebuild commit"
        )


def _open_regular(path: Path, *, max_bytes: int, secret: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RecoveryError(f"cannot open required regular file: {path.name}") from exc
    try:
        info = os.fstat(descriptor)
        linked = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or not stat.S_ISREG(linked.st_mode):
            raise RecoveryError(f"not a regular file: {path.name}")
        if (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino):
            raise RecoveryError(f"file changed while opening: {path.name}")
        if info.st_size > max_bytes:
            raise RecoveryError(f"file exceeds the recovery bound: {path.name}")
        if secret and stat.S_IMODE(info.st_mode) & 0o077:
            raise RecoveryError(f"secret file permissions are too broad: {path.name}")
        if secret and info.st_nlink != 1:
            raise RecoveryError(f"secret file must have exactly one link: {path.name}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular_bytes(path: Path, *, max_bytes: int, secret: bool = False) -> bytes:
    descriptor = _open_regular(path, max_bytes=max_bytes, secret=secret)
    try:
        before = os.fstat(descriptor)
        raw = _read_fd(descriptor, max_bytes)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) != before.st_size
        or _stable_file_identity(before) != _stable_file_identity(after)
    ):
        raise RecoveryError(f"file changed while reading: {path.name}")
    return raw


def _open_optional_private_directory(parent_fd: int, name: str) -> int | None:
    """Open one owner-private directory entry without following a link."""

    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RecoveryError("OpenClaw private capability path is unsafe") from exc
    information = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_uid != os.geteuid()
        or stat.S_IMODE(information.st_mode) & 0o077
    ):
        os.close(descriptor)
        raise RecoveryError("OpenClaw private capability directory is unsafe")
    return descriptor


def _open_optional_private_dirfd_file(
    parent_fd: int, name: str, *, max_bytes: int
) -> tuple[int, os.stat_result] | None:
    """Open one owner-only regular file beneath an already-bound parent."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RecoveryError("OpenClaw private capability file is unsafe") from exc
    try:
        before = os.fstat(descriptor)
        named_before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(named_before.st_mode)
            or (before.st_dev, before.st_ino)
            != (named_before.st_dev, named_before.st_ino)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= max_bytes
        ):
            raise RecoveryError("OpenClaw private capability file is unsafe")
        return descriptor, before
    except BaseException:
        os.close(descriptor)
        raise


def _read_optional_private_dirfd_file(
    parent_fd: int, name: str, *, max_bytes: int
) -> bytes | None:
    """Read one stable owner-only regular file beneath an already-bound parent."""

    opened = _open_optional_private_dirfd_file(
        parent_fd, name, max_bytes=max_bytes
    )
    if opened is None:
        return None
    descriptor, before = opened
    try:
        payload = _read_fd(descriptor, max_bytes)
        after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            len(payload) != before.st_size
            or _stable_file_identity(before) != _stable_file_identity(after)
            or (after.st_dev, after.st_ino)
            != (named_after.st_dev, named_after.st_ino)
        ):
            raise RecoveryError(
                "OpenClaw private capability file changed during inspection"
            )
        return payload
    finally:
        os.close(descriptor)


def _credential_value_is_configured(value: object) -> bool:
    placeholders = {
        "",
        "<redacted>",
        "__redacted__",
        "{{ private_id }}",
        "{{ redacted }}",
        "{{ secret_value }}",
    }
    if isinstance(value, str):
        return value.strip().casefold() not in placeholders
    if isinstance(value, dict):
        # A file/env SecretRef is a configured private capability even though
        # the literal value lives elsewhere. Executable SecretRefs are rejected
        # later by the OpenClaw auth-closure gate.
        source = value.get("source")
        if isinstance(source, str) and source.casefold() in {"env", "file", "exec"}:
            return True
        return any(_credential_value_is_configured(item) for item in value.values())
    if isinstance(value, list):
        return any(_credential_value_is_configured(item) for item in value)
    return value is not None and value is not False


def _json_contains_openclaw_credential(value: object) -> bool:
    secret_names = {
        "apikey",
        "api_key",
        "accesskey",
        "access_key",
        "accesstoken",
        "access_token",
        "credential",
        "credentials",
        "key",
        "password",
        "secret",
        "token",
    }
    nodes = 0

    def visit(item: object, depth: int) -> bool:
        nonlocal nodes
        nodes += 1
        if nodes > 100_000 or depth > 12:
            raise RecoveryError("OpenClaw private capability JSON exceeds its bound")
        if isinstance(item, dict):
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise RecoveryError("OpenClaw private capability JSON is invalid")
                normalized = re.sub(r"[^a-z0-9_]", "", key.casefold())
                if normalized in secret_names and _credential_value_is_configured(nested):
                    return True
                if visit(nested, depth + 1):
                    return True
        elif isinstance(item, list):
            return any(visit(nested, depth + 1) for nested in item)
        return False

    return visit(value, 0)


def _configured_openclaw_json(payload: bytes) -> bool:
    try:
        value = _json_loads_unique(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("OpenClaw private capability JSON is invalid") from exc
    return _json_contains_openclaw_credential(value)


def _validate_openclaw_file_delivery_policy(payload: bytes) -> None:
    """Validate the portable host authority captured only by the owner archive."""

    try:
        value = _json_loads_unique(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("OpenClaw file-delivery policy is invalid") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "delivery_policy"}:
        raise RecoveryError("OpenClaw file-delivery policy is invalid")
    if value.get("schema") != OPENCLAW_FILE_DELIVERY_SCHEMA:
        raise RecoveryError("OpenClaw file-delivery policy is invalid")
    delivery_policy = value.get("delivery_policy")
    if not isinstance(delivery_policy, dict) or set(delivery_policy) != {
        "allowed_targets"
    }:
        raise RecoveryError("OpenClaw file-delivery policy is invalid")
    allowed_targets = delivery_policy.get("allowed_targets")
    if not isinstance(allowed_targets, dict) or set(allowed_targets) != set(
        OPENCLAW_FILE_DELIVERY_CHANNELS
    ):
        raise RecoveryError("OpenClaw file-delivery policy is invalid")
    for targets in allowed_targets.values():
        if (
            not isinstance(targets, list)
            or any(not isinstance(target, str) or not target for target in targets)
            or len(set(targets)) != len(targets)
        ):
            raise RecoveryError("OpenClaw file-delivery policy is invalid")


def _configured_openclaw_database(
    descriptor: int, before: os.stat_result, parent_fd: int, name: str
) -> bool:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"file:/proc/self/fd/{descriptor}?mode=ro&immutable=1",
            uri=True,
            timeout=5,
        )
        if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise RecoveryError("OpenClaw private capability database is invalid")
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        required = {"schema_meta", "auth_profile_store", "auth_profile_state"}
        if not required.issubset(tables):
            raise RecoveryError("OpenClaw private capability database is unsupported")
        configured = any(
            connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] > 0
            for table in ("auth_profile_store", "auth_profile_state")
        )
    except sqlite3.Error as exc:
        raise RecoveryError("OpenClaw private capability database is unreadable") from exc
    finally:
        if connection is not None:
            connection.close()
    after = os.fstat(descriptor)
    named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        _stable_file_identity(before) != _stable_file_identity(after)
        or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
    ):
        raise RecoveryError(
            "OpenClaw private capability database changed during inspection"
        )
    return configured


def _validate_openclaw_sqlite_family(
    parent_fd: int, name: str, *, max_bytes: int, label: str = "OpenClaw global state"
) -> None:
    """Validate one owner-private SQLite main file and every live sidecar."""

    for index, suffix in enumerate(("", *SQLITE_SIDECAR_SUFFIXES)):
        selected = name + suffix
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(selected, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            if index == 0:
                raise RecoveryError(f"{label} database is missing")
            continue
        except OSError as exc:
            raise RecoveryError(f"{label} database is unsafe") from exc
        try:
            opened = os.fstat(descriptor)
            named = os.stat(selected, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(named.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (index == 0 and opened.st_size == 0)
                or opened.st_size > max_bytes
            ):
                raise RecoveryError(f"{label} database is unsafe")
        finally:
            os.close(descriptor)


def _sqlite_logical_digest(connection: sqlite3.Connection) -> bytes:
    """Hash schema plus the typed row multiset without rendering application data."""

    digest = hashlib.sha256(b"coding-system/sqlite-logical-state/v1\0")
    schema_rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "ORDER BY type, name, tbl_name"
    ).fetchall()
    if len(schema_rows) > MAX_SQLITE_SCHEMA_TABLES * 4:
        raise RecoveryError("OpenClaw database schema exceeds its bound")

    def encode_value(value: object) -> bytes:
        if value is None:
            return b"n"
        if isinstance(value, bool):
            return b"i1" if value else b"i0"
        if isinstance(value, int):
            payload = str(value).encode("ascii")
            return b"i" + len(payload).to_bytes(8, "big") + payload
        if isinstance(value, float):
            payload = struct.pack(">d", value)
            return b"f" + payload
        if isinstance(value, str):
            payload = value.encode("utf-8")
            return b"t" + len(payload).to_bytes(8, "big") + payload
        if isinstance(value, bytes):
            return b"b" + len(value).to_bytes(8, "big") + value
        raise RecoveryError("OpenClaw database contains an unsupported value")

    tables: list[str] = []
    for row in schema_rows:
        if len(row) != 4 or not all(
            value is None or isinstance(value, str) for value in row
        ):
            raise RecoveryError("OpenClaw database schema is invalid")
        encoded = b"".join(encode_value(value) for value in row)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        if row[0] == "table":
            assert isinstance(row[1], str)
            tables.append(row[1])

    total_rows = 0
    total_bytes = 0
    for table in sorted(tables):
        if len(table.encode("utf-8")) > 1024:
            raise RecoveryError("OpenClaw database schema is invalid")
        quoted = table.replace('"', '""')
        cursor = connection.execute(f'SELECT * FROM "{quoted}"')
        row_digests: list[bytes] = []
        for row in cursor:
            total_rows += 1
            if total_rows > 2_000_000:
                raise RecoveryError("OpenClaw database row count exceeds its bound")
            encoded = b"".join(encode_value(value) for value in row)
            total_bytes += len(encoded)
            if total_bytes > MAX_OPENCLAW_GLOBAL_DB_BYTES:
                raise RecoveryError("OpenClaw database logical state exceeds its bound")
            row_digests.append(hashlib.sha256(encoded).digest())
        table_name = table.encode("utf-8")
        digest.update(len(table_name).to_bytes(4, "big"))
        digest.update(table_name)
        digest.update(len(row_digests).to_bytes(8, "big"))
        for row_digest in sorted(row_digests):
            digest.update(row_digest)
    return digest.digest()


def _openclaw_global_state_digest(parent_fd: int) -> bytes:
    """Bind one transactional global-state image without exposing row values."""

    name = "openclaw.sqlite"
    _validate_openclaw_sqlite_family(
        parent_fd, name, max_bytes=MAX_OPENCLAW_GLOBAL_DB_BYTES
    )
    opened = _open_optional_private_dirfd_file(
        parent_fd, name, max_bytes=MAX_OPENCLAW_GLOBAL_DB_BYTES
    )
    if opened is None:  # pragma: no cover - validated immediately above
        raise RecoveryError("OpenClaw global state database is missing")
    descriptor, before = opened
    source: sqlite3.Connection | None = None
    target: sqlite3.Connection | None = None
    deadline = time.monotonic() + 60
    try:
        with secure_temporary_directory(prefix="csr-openclaw-global-state-") as temporary:
            snapshot = Path(temporary) / "openclaw.sqlite"
            try:
                source_path = Path("/proc/self/fd") / str(parent_fd) / name
                source = sqlite3.connect(
                    f"{source_path.as_uri()}?mode=ro", uri=True, timeout=5
                )
                source.execute("PRAGMA query_only = ON")
                source.execute("PRAGMA trusted_schema = OFF")
                page_size = int(source.execute("PRAGMA page_size").fetchone()[0])
                if not 512 <= page_size <= 65_536:
                    raise RecoveryError("OpenClaw global state page size is invalid")
                target = sqlite3.connect(snapshot, timeout=5)

                def bounded_progress(
                    _status: int, remaining: int, total: int
                ) -> None:
                    if (
                        remaining < 0
                        or total < 0
                        or total * page_size > MAX_OPENCLAW_GLOBAL_DB_BYTES
                        or time.monotonic() > deadline
                    ):
                        raise RecoveryError(
                            "OpenClaw global state snapshot exceeds its bound"
                        )

                source.backup(
                    target, pages=256, progress=bounded_progress, sleep=0.01
                )
                if target.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise RecoveryError("OpenClaw global state snapshot is invalid")
                tables = {
                    row[0]
                    for row in target.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                if "schema_meta" not in tables:
                    raise RecoveryError("OpenClaw global state schema is unsupported")
                columns = {
                    row[1] for row in target.execute("PRAGMA table_info(schema_meta)")
                }
                if not {
                    "meta_key",
                    "role",
                    "schema_version",
                    "agent_id",
                }.issubset(columns):
                    raise RecoveryError("OpenClaw global state schema is unsupported")
                if target.execute("PRAGMA user_version").fetchone() != (1,):
                    raise RecoveryError("OpenClaw global state schema is unsupported")
                owner = target.execute(
                    "SELECT role, agent_id, schema_version FROM schema_meta "
                    "WHERE meta_key='primary'"
                ).fetchone()
                if owner != ("global", None, 1):
                    raise RecoveryError("OpenClaw global state ownership is invalid")
                digest = _sqlite_logical_digest(target)
                target.close()
                target = None
                source.close()
                source = None
            except sqlite3.Error as exc:
                raise RecoveryError("OpenClaw global state database is unreadable") from exc
            finally:
                if target is not None:
                    target.close()
                if source is not None:
                    source.close()
            snapshot.chmod(0o600)
        after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or (after.st_dev, after.st_ino)
            != (named_after.st_dev, named_after.st_ino)
        ):
            raise RecoveryError("OpenClaw global state changed during inspection")
        _validate_openclaw_sqlite_family(
            parent_fd, name, max_bytes=MAX_OPENCLAW_GLOBAL_DB_BYTES
        )
        return digest
    finally:
        os.close(descriptor)


def _openclaw_agent_state_digest(
    parent_fd: int, agent_id: str
) -> tuple[bytes, bool]:
    """Bind one transactional per-agent auth image by logical SQLite content."""

    name = "openclaw-agent.sqlite"
    label = "OpenClaw private capability"
    _validate_openclaw_sqlite_family(
        parent_fd,
        name,
        max_bytes=MAX_OPENCLAW_AGENT_DB_BYTES,
        label=label,
    )
    opened = _open_optional_private_dirfd_file(
        parent_fd, name, max_bytes=MAX_OPENCLAW_AGENT_DB_BYTES
    )
    if opened is None:  # pragma: no cover - validated immediately above
        raise RecoveryError("OpenClaw private capability database is missing")
    descriptor, before = opened
    source: sqlite3.Connection | None = None
    target: sqlite3.Connection | None = None
    deadline = time.monotonic() + 60
    try:
        with secure_temporary_directory(prefix="csr-openclaw-agent-state-") as temporary:
            snapshot = Path(temporary) / name
            try:
                source_path = Path("/proc/self/fd") / str(parent_fd) / name
                source = sqlite3.connect(
                    f"{source_path.as_uri()}?mode=ro", uri=True, timeout=5
                )
                source.execute("PRAGMA query_only = ON")
                source.execute("PRAGMA trusted_schema = OFF")
                page_size = int(source.execute("PRAGMA page_size").fetchone()[0])
                if not 512 <= page_size <= 65_536:
                    raise RecoveryError(
                        "OpenClaw private capability page size is invalid"
                    )
                target = sqlite3.connect(snapshot, timeout=5)

                def bounded_progress(
                    _status: int, remaining: int, total: int
                ) -> None:
                    if (
                        remaining < 0
                        or total < 0
                        or total * page_size > MAX_OPENCLAW_AGENT_DB_BYTES
                        or time.monotonic() > deadline
                    ):
                        raise RecoveryError(
                            "OpenClaw private capability snapshot exceeds its bound"
                        )

                source.backup(
                    target, pages=256, progress=bounded_progress, sleep=0.01
                )
                if target.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise RecoveryError(
                        "OpenClaw private capability snapshot is invalid"
                    )
                tables = {
                    row[0]
                    for row in target.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                required = {
                    "schema_meta",
                    "auth_profile_store",
                    "auth_profile_state",
                }
                if not required.issubset(tables):
                    raise RecoveryError(
                        "OpenClaw private capability database is unsupported"
                    )
                if target.execute("PRAGMA user_version").fetchone() != (1,):
                    raise RecoveryError(
                        "OpenClaw private capability database is unsupported"
                    )
                owner = target.execute(
                    "SELECT role, agent_id, schema_version FROM schema_meta "
                    "WHERE meta_key='primary'"
                ).fetchone()
                if owner != ("agent", agent_id, 1):
                    raise RecoveryError(
                        "OpenClaw private capability ownership is invalid"
                    )
                configured = any(
                    target.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    > 0
                    for table in ("auth_profile_store", "auth_profile_state")
                )
                digest = _sqlite_logical_digest(target)
                target.close()
                target = None
                source.close()
                source = None
            except sqlite3.Error as exc:
                raise RecoveryError(
                    "OpenClaw private capability database is unreadable"
                ) from exc
            finally:
                if target is not None:
                    target.close()
                if source is not None:
                    source.close()
            snapshot.chmod(0o600)
        after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or (after.st_dev, after.st_ino)
            != (named_after.st_dev, named_after.st_ino)
        ):
            raise RecoveryError(
                "OpenClaw private capability database changed during inspection"
            )
        _validate_openclaw_sqlite_family(
            parent_fd,
            name,
            max_bytes=MAX_OPENCLAW_AGENT_DB_BYTES,
            label=label,
        )
        return digest, configured
    finally:
        os.close(descriptor)


def _openclaw_agent_inventory(agents_fd: int | None) -> set[str]:
    if agents_fd is None:
        return set()
    try:
        entries = list(os.scandir(agents_fd))
    except OSError as exc:
        raise RecoveryError("OpenClaw agent inventory is unsafe") from exc
    names: set[str] = set()
    for entry in entries:
        if (
            OPENCLAW_AGENT_ID_RE.fullmatch(entry.name) is None
            or entry.name in names
            or entry.is_symlink()
            or not entry.is_dir(follow_symlinks=False)
        ):
            raise RecoveryError("OpenClaw agent inventory is unsafe")
        names.add(entry.name)
    return names


def _inspect_openclaw_agent_roots(
    json_agents_fd: int | None,
    database_agents_fd: int | None,
    state: hmac.HMAC,
) -> bool:
    """Bind split legacy-JSON and canonical-DB agent roots in live path order."""

    configured = False
    agent_ids = sorted(
        _openclaw_agent_inventory(json_agents_fd)
        | _openclaw_agent_inventory(database_agents_fd)
    )
    for agent_id in agent_ids:
        json_root_fd: int | None = None
        json_agent_fd: int | None = None
        database_root_fd: int | None = None
        database_agent_fd: int | None = None
        try:
            if json_agents_fd is not None:
                json_root_fd = _open_optional_private_directory(
                    json_agents_fd, agent_id
                )
                if json_root_fd is not None:
                    json_agent_fd = _open_optional_private_directory(
                        json_root_fd, "agent"
                    )
            if database_agents_fd is not None:
                database_root_fd = _open_optional_private_directory(
                    database_agents_fd, agent_id
                )
                if database_root_fd is not None:
                    database_agent_fd = _open_optional_private_directory(
                        database_root_fd, "agent"
                    )
            if json_agent_fd is not None:
                for filename in (
                    "auth-profiles.json",
                    "auth-state.json",
                    "auth.json",
                    "models.json",
                ):
                    payload = _read_optional_private_dirfd_file(
                        json_agent_fd,
                        filename,
                        max_bytes=MAX_OPENCLAW_AUTH_JSON_BYTES,
                    )
                    if payload is None:
                        continue
                    relative = f"agents/{agent_id}/agent/{filename}".encode(
                        "utf-8"
                    )
                    state.update(len(relative).to_bytes(4, "big"))
                    state.update(relative)
                    state.update(hashlib.sha256(payload).digest())
                    # Evaluate first: `or` would stop validating later agents
                    # once any earlier one is configured.
                    payload_configured = _configured_openclaw_json(payload)
                    configured = configured or payload_configured
            if database_agent_fd is not None:
                try:
                    os.stat(
                        "openclaw-agent.sqlite",
                        dir_fd=database_agent_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                else:
                    digest, database_configured = _openclaw_agent_state_digest(
                        database_agent_fd, agent_id
                    )
                    relative = (
                        f"agents/{agent_id}/agent/openclaw-agent.sqlite"
                    ).encode("utf-8")
                    state.update(len(relative).to_bytes(4, "big"))
                    state.update(relative)
                    state.update(digest)
                    configured = configured or database_configured
        finally:
            if database_agent_fd is not None:
                os.close(database_agent_fd)
            if database_root_fd is not None:
                os.close(database_root_fd)
            if json_agent_fd is not None:
                os.close(json_agent_fd)
            if json_root_fd is not None:
                os.close(json_root_fd)
    return configured


def _inspect_openclaw_private_capability(
    source_home: Path | str, hmac_key: bytes
) -> tuple[bool, str]:
    """Detect and bind source auth/model state without publishing raw digests."""

    state = hmac.new(
        hmac_key,
        b"coding-system/openclaw-owner-source/v1\0",
        hashlib.sha256,
    )
    configured = False
    home_fd = _open_directory_path(Path(source_home))
    openclaw_fd: int | None = None
    agents_fd: int | None = None
    state_fd: int | None = None
    try:
        openclaw_fd = _open_optional_private_directory(home_fd, ".openclaw")
        if openclaw_fd is None:
            return False, state.hexdigest()
        delivery_policy = _read_optional_private_dirfd_file(
            openclaw_fd,
            "file-delivery-policy.json",
            max_bytes=MAX_OPENCLAW_AUTH_JSON_BYTES,
        )
        if delivery_policy is not None:
            _validate_openclaw_file_delivery_policy(delivery_policy)
            relative = b"file-delivery-policy.json"
            state.update(len(relative).to_bytes(4, "big"))
            state.update(relative)
            state.update(hashlib.sha256(delivery_policy).digest())
            # Presence is meaningful even for an explicit deny-all policy: this
            # host authority is portable only through the owner archive.
            configured = True
        state_fd = _open_optional_private_directory(openclaw_fd, "state")
        if state_fd is not None:
            try:
                os.stat(
                    "openclaw.sqlite", dir_fd=state_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                pass
            else:
                relative = b"state/openclaw.sqlite"
                state.update(len(relative).to_bytes(4, "big"))
                state.update(relative)
                state.update(_openclaw_global_state_digest(state_fd))
                # The native global store is credential-capable owner state
                # even when its sensitive tables are currently empty.
                configured = True
        agents_fd = _open_optional_private_directory(openclaw_fd, "agents")
        # Evaluate first: `or` short-circuits once the global store or the
        # delivery policy has set `configured`, so no per-agent credential ever
        # reached `state` and replacing agents/*/auth.json left this digest --
        # the only integrity binding these backup:false artifacts have --
        # byte-identical.
        agents_configured = _inspect_openclaw_agent_roots(agents_fd, agents_fd, state)
        configured = configured or agents_configured
        return configured, state.hexdigest()
    finally:
        if state_fd is not None:
            os.close(state_fd)
        if agents_fd is not None:
            os.close(agents_fd)
        if openclaw_fd is not None:
            os.close(openclaw_fd)
        os.close(home_fd)


def openclaw_private_capability_configured(source_home: Path | str) -> bool:
    """Detect source auth/model capabilities that only the owner archive captures."""

    configured, _state = _inspect_openclaw_private_capability(
        source_home, b"classification-only"
    )
    return configured


def openclaw_private_source_state(
    source_home: Path | str, hmac_key: bytes
) -> tuple[bool, str]:
    if not hmac_key:
        raise RecoveryError("owner-data source-state HMAC key is empty")
    return _inspect_openclaw_private_capability(source_home, hmac_key)


def openclaw_extracted_source_state(
    extraction_root: Path | str, hmac_key: bytes
) -> tuple[bool, str]:
    """Bind the verified owner archive's split quarantine/canonical layout."""

    if not hmac_key:
        raise RecoveryError("owner-data source-state HMAC key is empty")
    state = hmac.new(
        hmac_key,
        b"coding-system/openclaw-owner-source/v1\0",
        hashlib.sha256,
    )
    configured = False
    root_fd = _open_directory_path(Path(extraction_root))
    quarantine_fd: int | None = None
    archive_authority_fd: int | None = None
    authority_fd: int | None = None
    state_fd: int | None = None
    json_agents_fd: int | None = None
    database_agents_fd: int | None = None
    try:
        root_information = os.fstat(root_fd)
        if (
            root_information.st_uid != os.geteuid()
            or stat.S_IMODE(root_information.st_mode) & 0o077
        ):
            raise RecoveryError("OpenClaw owner extraction root is unsafe")
        quarantine_fd = _open_optional_private_directory(
            root_fd, "recovery-quarantine"
        )
        if quarantine_fd is not None:
            archive_authority_fd = _open_optional_private_directory(
                quarantine_fd, "archive-authority"
            )
        if archive_authority_fd is not None:
            authority_fd = _open_optional_private_directory(
                archive_authority_fd, "payload"
            )
        if authority_fd is not None:
            delivery_policy = _read_optional_private_dirfd_file(
                authority_fd,
                "file-delivery-policy.json",
                max_bytes=MAX_OPENCLAW_AUTH_JSON_BYTES,
            )
            if delivery_policy is not None:
                _validate_openclaw_file_delivery_policy(delivery_policy)
                relative = b"file-delivery-policy.json"
                state.update(len(relative).to_bytes(4, "big"))
                state.update(relative)
                state.update(hashlib.sha256(delivery_policy).digest())
                configured = True
            state_fd = _open_optional_private_directory(authority_fd, "state")
            if state_fd is not None:
                try:
                    os.stat(
                        "openclaw.sqlite",
                        dir_fd=state_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                else:
                    relative = b"state/openclaw.sqlite"
                    state.update(len(relative).to_bytes(4, "big"))
                    state.update(relative)
                    state.update(_openclaw_global_state_digest(state_fd))
                    configured = True
            json_agents_fd = _open_optional_private_directory(
                authority_fd, "agents"
            )
        database_agents_fd = _open_optional_private_directory(root_fd, "agents")
        configured = configured or _inspect_openclaw_agent_roots(
            json_agents_fd, database_agents_fd, state
        )
        return configured, state.hexdigest()
    finally:
        if database_agents_fd is not None:
            os.close(database_agents_fd)
        if json_agents_fd is not None:
            os.close(json_agents_fd)
        if state_fd is not None:
            os.close(state_fd)
        if authority_fd is not None:
            os.close(authority_fd)
        if archive_authority_fd is not None:
            os.close(archive_authority_fd)
        if quarantine_fd is not None:
            os.close(quarantine_fd)
        os.close(root_fd)


def _open_directory_path(path: Path) -> int:
    """Open an existing directory without following any path-component link."""
    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    descriptor = os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise RecoveryError("unsafe or unavailable directory path") from exc


def _mkdir_exclusive(path: Path, mode: int, label: str) -> None:
    if "/" in path.name or path.name in ("", ".", ".."):
        raise RecoveryError(f"unsafe {label} name")
    parent_fd = _open_directory_path(path.parent)
    try:
        os.mkdir(path.name, mode, dir_fd=parent_fd)
        child_fd = _open_dir_component(parent_fd, path.name)
        os.close(child_fd)
    except FileExistsError as exc:
        raise RecoveryError(f"{label} already exists") from exc
    except OSError as exc:
        raise RecoveryError(f"cannot create {label} directory") from exc
    finally:
        os.close(parent_fd)


def _read_fd(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise RecoveryError("file exceeds the recovery bound")


def _read_secret_file(path: Path) -> bytes:
    descriptor = _open_regular(path, max_bytes=4096, secret=True)
    try:
        value = _read_fd(descriptor, 4096).rstrip(b"\r\n")
    finally:
        os.close(descriptor)
    if len(value) < 32:
        raise RecoveryError("master key must contain at least 32 bytes")
    return value


def _public_ed25519_identity(raw: bytes) -> bytes:
    if not raw or len(raw) > MAX_KEYS_BYTES:
        raise RecoveryError("recovery signing public key shape is invalid")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise RecoveryError("recovery signing public key is not ASCII") from exc
    if len(lines) != 1:
        raise RecoveryError("recovery signing public key shape is invalid")
    fields = lines[0].split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise RecoveryError("unsupported recovery signing public key")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RecoveryError("recovery signing public key shape is invalid") from exc
    if not decoded:
        raise RecoveryError("recovery signing public key shape is invalid")
    return f"{fields[0]} {fields[1]}".encode("ascii")


def _read_stable_owner_signing_authority(path: Path) -> bytes:
    if path.name in ("", ".", "..") or "/" in path.name:
        raise RecoveryError("unsafe recovery signing authority path")
    parent_fd = _open_directory_path(path.parent)
    descriptor = -1
    try:
        parent_info = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or stat.S_IMODE(parent_info.st_mode) & 0o022
        ):
            raise RecoveryError("recovery signing authority parent is unsafe")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise RecoveryError("cannot open destination recovery signing authority") from exc
        before = os.fstat(descriptor)
        linked_before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(linked_before.st_mode)
            or (before.st_dev, before.st_ino)
            != (linked_before.st_dev, linked_before.st_ino)
        ):
            raise RecoveryError("recovery signing authority is not a regular file")
        if before.st_uid != os.geteuid():
            raise RecoveryError("recovery signing authority is not owned by the caller")
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise RecoveryError("recovery signing authority must have mode 0600")
        if before.st_nlink != 1:
            raise RecoveryError("recovery signing authority must have exactly one link")
        if not 0 < before.st_size <= MAX_RECOVERY_SIGNING_KEY_BYTES:
            raise RecoveryError("recovery signing authority exceeds its bound")
        raw = _read_fd(descriptor, MAX_RECOVERY_SIGNING_KEY_BYTES)
        after = os.fstat(descriptor)
        linked_after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            len(raw) != before.st_size
            or _stable_file_identity(before) != _stable_file_identity(after)
            or _stable_file_identity(linked_before)
            != _stable_file_identity(linked_after)
            or (after.st_dev, after.st_ino)
            != (linked_after.st_dev, linked_after.st_ino)
        ):
            raise RecoveryError("recovery signing authority changed while reading")
        return raw
    except OSError as exc:
        raise RecoveryError("cannot inspect destination recovery signing authority") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _derive_ed25519_public_identity(descriptor: int) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        result = subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-y",
                "-f",
                f"/proc/self/fd/{descriptor}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(descriptor,),
            env={
                "HOME": "/",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            start_new_session=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RecoveryError("recovery signing public-key derivation could not run") from exc
    if result.returncode != 0 or len(result.stdout) > MAX_KEYS_BYTES:
        raise RecoveryError("destination recovery signing authority is not usable")
    return _public_ed25519_identity(result.stdout)


def stage_legacy_signing_authority(
    source_key: Path | str,
    destination_home: Path | str,
    trusted_public_key: Path | str,
    *,
    expected_public_key_sha256: str = RECOVERY_SIGNING_KEY_SHA256,
) -> Path:
    """Copy the destination signing authority into private legacy-import staging."""
    source_raw = _read_stable_owner_signing_authority(Path(source_key))
    trusted_raw = _read_regular_bytes(Path(trusted_public_key), max_bytes=MAX_KEYS_BYTES)
    if (
        re.fullmatch(r"[0-9a-f]{64}", expected_public_key_sha256) is None
        or not secrets.compare_digest(
            _sha256_bytes(trusted_raw), expected_public_key_sha256
        )
    ):
        raise RecoveryError("recovery signing trust root mismatch")
    trusted_identity = _public_ed25519_identity(trusted_raw)

    target_parent = Path(destination_home) / ".config/coding-system"
    target_name = "recovery-signing"
    parent_fd = _open_directory_path(target_parent)
    temporary = f".{target_name}.tmp-{secrets.token_hex(8)}"
    descriptor = -1
    replaced = False
    try:
        parent_info = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or stat.S_IMODE(parent_info.st_mode) != 0o700
        ):
            raise RecoveryError("legacy signing staging directory must be owner-only")
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        view = memoryview(source_raw)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        derived_identity = _derive_ed25519_public_identity(descriptor)
        if not secrets.compare_digest(derived_identity, trusted_identity):
            raise RecoveryError("recovery signing trust root mismatch")
        os.replace(
            temporary,
            target_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        replaced = True
        os.close(descriptor)
        descriptor = -1
        os.fsync(parent_fd)

        verify_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(target_name, verify_flags, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        linked_before = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        staged_raw = _read_fd(descriptor, MAX_RECOVERY_SIGNING_KEY_BYTES)
        after = os.fstat(descriptor)
        linked_after = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or len(staged_raw) != before.st_size
            or not secrets.compare_digest(staged_raw, source_raw)
            or _stable_file_identity(before) != _stable_file_identity(after)
            or _stable_file_identity(linked_before)
            != _stable_file_identity(linked_after)
            or (after.st_dev, after.st_ino)
            != (linked_after.st_dev, linked_after.st_ino)
        ):
            raise RecoveryError("staged recovery signing authority is unsafe")
    except RecoveryError:
        raise
    except OSError as exc:
        raise RecoveryError("cannot stage destination recovery signing authority") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not replaced:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)
    return target_parent / target_name


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    if "/" in path.name or path.name in ("", ".", ".."):
        raise RecoveryError("unsafe output filename")
    parent_fd = _open_directory_path(path.parent)
    temporary = f".{path.name}.tmp-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, mode, dir_fd=parent_fd)
    except BaseException:
        os.close(parent_fd)
        raise
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)
        raise
    else:
        os.close(descriptor)
    try:
        os.link(
            temporary,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileExistsError as exc:
        os.unlink(temporary, dir_fd=parent_fd)
        os.close(parent_fd)
        raise RecoveryError(f"refusing to overwrite immutable output: {path.name}") from exc
    except BaseException:
        os.unlink(temporary, dir_fd=parent_fd)
        os.close(parent_fd)
        raise
    os.unlink(temporary, dir_fd=parent_fd)
    os.close(parent_fd)


def _stable_file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _snapshot_member_limit(name: str) -> int:
    if name in {"keys.json.gpg", "secrets.tar.gpg", "private-state.tar.gpg"}:
        return MAX_ARCHIVE_BYTES
    if OWNER_DATA_FILENAME_RE.fullmatch(name) is not None:
        return MAX_OWNER_DATA_BYTES
    return MAX_KEYS_BYTES


def _open_dirfd_regular(directory_fd: int, name: str, *, max_bytes: int) -> int:
    if (
        name not in RECOVERY_SNAPSHOT_ALLOWED
        and OWNER_DATA_FILENAME_RE.fullmatch(name) is None
    ):
        raise RecoveryError("recovery snapshot member is not allowlisted")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise RecoveryError(f"cannot open recovery snapshot member: {name}") from exc
    try:
        info = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)
            or info.st_nlink != 1
            or not 0 < info.st_size <= max_bytes
        ):
            raise RecoveryError(f"unsafe recovery snapshot member: {name}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_dirfd_regular(directory_fd: int, name: str, *, max_bytes: int) -> bytes:
    descriptor = _open_dirfd_regular(directory_fd, name, max_bytes=max_bytes)
    try:
        before = os.fstat(descriptor)
        raw = _read_fd(descriptor, max_bytes)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) != before.st_size
        or _stable_file_identity(before) != _stable_file_identity(after)
    ):
        raise RecoveryError(f"recovery snapshot member changed while reading: {name}")
    return raw


def _snapshot_inventory_contract(
    directory_fd: int, *, allow_legacy: bool
) -> tuple[frozenset[str], frozenset[str]]:
    manifest_raw = _read_dirfd_regular(
        directory_fd, "recovery-set.json", max_bytes=MAX_KEYS_BYTES
    )
    try:
        value = _json_loads_unique(manifest_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("recovery snapshot manifest is invalid") from exc
    if not isinstance(value, dict):
        raise RecoveryError("recovery snapshot manifest is invalid")
    schema = value.get("schema")
    if schema == LEGACY_RECOVERY_SCHEMA:
        if not allow_legacy:
            raise RecoveryError(
                "legacy recovery set requires an explicit degraded compatibility gate"
            )
        owner_data = None
    elif schema == RECOVERY_SCHEMA:
        if "owner_data" not in value:
            raise RecoveryError("recovery-set v2 lacks its owner-data contract")
        owner_data = _validate_owner_data_record(value["owner_data"])
    else:
        raise RecoveryError("unsupported recovery set schema")
    required = set(RECOVERY_SNAPSHOT_REQUIRED)
    allowed = set(RECOVERY_SNAPSHOT_ALLOWED)
    if owner_data is not None:
        owner_name = str(owner_data["file"])
        required.add(owner_name)
        allowed.add(owner_name)
    return frozenset(required), frozenset(allowed)


def _copy_dirfd_regular(
    source_fd: int,
    destination_fd: int,
    name: str,
    *,
    max_bytes: int,
) -> None:
    source = _open_dirfd_regular(source_fd, name, max_bytes=max_bytes)
    destination = -1
    try:
        before = os.fstat(source)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        destination = os.open(name, flags, 0o400, dir_fd=destination_fd)
        copied = 0
        while True:
            chunk = os.read(source, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > max_bytes:
                raise RecoveryError(f"recovery snapshot member exceeds its bound: {name}")
            view = memoryview(chunk)
            while view:
                written = os.write(destination, view)
                view = view[written:]
        after = os.fstat(source)
        if (
            copied != before.st_size
            or _stable_file_identity(before) != _stable_file_identity(after)
        ):
            raise RecoveryError(f"recovery snapshot member changed while copying: {name}")
        os.fchmod(destination, 0o400)
        os.fsync(destination)
    except BaseException:
        if destination >= 0:
            os.close(destination)
            destination = -1
            try:
                os.unlink(name, dir_fd=destination_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(source)
        if destination >= 0:
            os.close(destination)


def snapshot_recovery_set(
    set_dir: Path | str,
    output_dir: Path | str,
    *,
    allow_legacy: bool = False,
) -> Path:
    """Copy one closed recovery inventory through held no-follow descriptors."""
    set_dir = Path(set_dir)
    output_dir = Path(output_dir)
    try:
        output_info = output_dir.lstat()
    except OSError as exc:
        raise RecoveryError("recovery snapshot destination is unavailable") from exc
    if (
        output_dir.is_symlink()
        or not stat.S_ISDIR(output_info.st_mode)
        or output_info.st_uid != os.geteuid()
        or stat.S_IMODE(output_info.st_mode) != 0o700
    ):
        raise RecoveryError("recovery snapshot destination must be owner-only")
    source_fd = _open_directory_path(set_dir)
    destination_fd = _open_directory_path(output_dir)
    try:
        if os.listdir(destination_fd):
            raise RecoveryError("recovery snapshot destination must be empty")
        required, allowed = _snapshot_inventory_contract(
            source_fd, allow_legacy=allow_legacy
        )
        before = frozenset(os.listdir(source_fd))
        if (
            not required.issubset(before)
            or not before.issubset(allowed)
        ):
            raise RecoveryError("recovery set inventory is not closed and complete")
        for name in sorted(before):
            _copy_dirfd_regular(
                source_fd,
                destination_fd,
                name,
                max_bytes=_snapshot_member_limit(name),
            )
        after = frozenset(os.listdir(source_fd))
        if after != before:
            raise RecoveryError("recovery set inventory changed while snapshotting")
        os.fchmod(destination_fd, 0o500)
        os.fsync(destination_fd)
    finally:
        os.close(source_fd)
        os.close(destination_fd)
    return output_dir


def validate_private_recovery_snapshot(
    path: Path | str, *, allow_legacy: bool = False
) -> Path:
    path = Path(path)
    expected = re.compile(
        rf"csr-recovery-snapshot\.{os.geteuid()}\."
        rf"(?:[0-9a-f]{{32}}\.)?[A-Za-z0-9_-]+\Z"
    )
    if path.parent != Path("/tmp") or expected.fullmatch(path.name) is None:
        raise RecoveryError("recovery snapshot path is not canonical")
    directory_fd = _open_directory_path(path)
    try:
        info = os.fstat(directory_fd)
        required, allowed = _snapshot_inventory_contract(
            directory_fd, allow_legacy=allow_legacy
        )
        names = frozenset(os.listdir(directory_fd))
        if (
            info.st_uid != os.geteuid()
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o500
            or not required.issubset(names)
            or not names.issubset(allowed)
        ):
            raise RecoveryError("recovery snapshot protection or inventory is invalid")
        for name in names:
            member = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(member.st_mode)
                or member.st_uid != os.geteuid()
                or member.st_nlink != 1
                or stat.S_IMODE(member.st_mode) != 0o400
                or not 0 < member.st_size <= _snapshot_member_limit(name)
            ):
                raise RecoveryError(f"recovery snapshot member is unsafe: {name}")
    finally:
        os.close(directory_fd)
    return path


def _signed_component_commit(manifest_raw: bytes) -> str:
    try:
        value = _json_loads_unique(manifest_raw)
        commit = value["components"]["coding-system-rebuild"]["commit"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RecoveryError("signed recovery set lacks a repository commit") from exc
    if not isinstance(commit, str) or COMMIT_RE.fullmatch(commit) is None:
        raise RecoveryError("signed recovery set repository commit is invalid")
    return commit


def verify_recovery_signature(
    set_dir: Path | str,
    *,
    trusted_public_key: Path | str | None = None,
    expected_key_sha256: str = RECOVERY_SIGNING_KEY_SHA256,
    expected_component_commit: str | None = None,
) -> dict[str, str]:
    """Verify exactly one descriptor-captured signature/key/manifest tuple."""
    set_dir = Path(set_dir)
    trusted_path = (
        Path(trusted_public_key)
        if trusted_public_key is not None
        else REPOSITORY_ROOT / "system/recovery/recovery-signing-public-key.pub"
    )
    trusted_raw = _read_regular_bytes(trusted_path, max_bytes=MAX_KEYS_BYTES)
    directory_fd = _open_directory_path(set_dir)
    try:
        set_key_raw = _read_dirfd_regular(
            directory_fd,
            "recovery-signing-public-key.pub",
            max_bytes=MAX_KEYS_BYTES,
        )
        signature_raw = _read_dirfd_regular(
            directory_fd,
            "recovery-set.json.sig",
            max_bytes=MAX_KEYS_BYTES,
        )
        manifest_raw = _read_dirfd_regular(
            directory_fd,
            "recovery-set.json",
            max_bytes=MAX_KEYS_BYTES,
        )
    finally:
        os.close(directory_fd)
    trusted_hash = _sha256_bytes(trusted_raw)
    set_key_hash = _sha256_bytes(set_key_raw)
    if (
        not re.fullmatch(r"[0-9a-f]{64}", expected_key_sha256)
        or not secrets.compare_digest(trusted_hash, expected_key_sha256)
        or not secrets.compare_digest(set_key_hash, expected_key_sha256)
        or not secrets.compare_digest(trusted_raw, set_key_raw)
    ):
        raise RecoveryError("recovery signing trust root mismatch")
    try:
        key_lines = set_key_raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise RecoveryError("recovery signing key is not ASCII") from exc
    if len(key_lines) != 1:
        raise RecoveryError("recovery signing key shape is invalid")
    key_fields = key_lines[0].split()
    if len(key_fields) < 2 or key_fields[0] != "ssh-ed25519":
        raise RecoveryError("unsupported recovery signing key")
    allowed_signer = (
        f"{RECOVERY_SIGNING_IDENTITY} {key_fields[0]} {key_fields[1]}\n".encode(
            "ascii"
        )
    )
    with secure_temporary_directory(prefix="csr-recovery-signature-") as temporary:
        work = Path(temporary)
        allowed_path = work / "allowed-signers"
        signature_path = work / "recovery-set.json.sig"
        _atomic_write(allowed_path, allowed_signer, 0o600)
        _atomic_write(signature_path, signature_raw, 0o600)
        try:
            result = subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-Y",
                    "verify",
                    "-q",
                    "-f",
                    os.fspath(allowed_path),
                    "-I",
                    RECOVERY_SIGNING_IDENTITY,
                    "-n",
                    RECOVERY_SIGNING_NAMESPACE,
                    "-s",
                    os.fspath(signature_path),
                ],
                input=manifest_raw,
                env={
                    "HOME": "/",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                },
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RecoveryError("recovery signature verification could not run") from exc
    if result.returncode != 0:
        raise RecoveryError("recovery detached signature is invalid")
    commit = _signed_component_commit(manifest_raw)
    if expected_component_commit is not None:
        if (
            COMMIT_RE.fullmatch(expected_component_commit) is None
            or not secrets.compare_digest(commit, expected_component_commit)
        ):
            raise RecoveryError("signed recovery set belongs to another repository commit")
    return {
        "component_commit": commit,
        "manifest_sha256": _sha256_bytes(manifest_raw),
        "signing_key_sha256": set_key_hash,
    }


def _discard_recovery_snapshot(path: Path) -> None:
    expected = re.compile(
        rf"csr-recovery-snapshot\.{os.geteuid()}\."
        rf"(?:[0-9a-f]{{32}}\.)?[A-Za-z0-9_-]+\Z"
    )
    if path.parent != Path("/tmp") or expected.fullmatch(path.name) is None:
        raise RecoveryError("refusing unsafe recovery snapshot cleanup")
    directory_fd = _open_directory_path(path)
    try:
        info = os.fstat(directory_fd)
        if info.st_uid != os.geteuid() or not stat.S_ISDIR(info.st_mode):
            raise RecoveryError("refusing recovery snapshot owned by another principal")
        names = frozenset(os.listdir(directory_fd))
        if any(
            name not in RECOVERY_SNAPSHOT_ALLOWED
            and OWNER_DATA_FILENAME_RE.fullmatch(name) is None
            for name in names
        ):
            raise RecoveryError("refusing recovery snapshot with an unsafe inventory")
        os.fchmod(directory_fd, 0o700)
        for name in names:
            member = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(member.st_mode):
                raise RecoveryError("refusing unsafe recovery snapshot member cleanup")
            os.unlink(name, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(path)


@contextmanager
def authenticated_recovery_snapshot(
    set_dir: Path | str,
    *,
    trusted_public_key: Path | str | None = None,
    expected_key_sha256: str = RECOVERY_SIGNING_KEY_SHA256,
    expected_component_commit: str | None = None,
    allow_legacy: bool = False,
) -> Iterator[Path]:
    snapshot = Path(
        tempfile.mkdtemp(
            prefix=f"csr-recovery-snapshot.{os.geteuid()}.", dir="/tmp"
        )
    )
    snapshot.chmod(0o700)
    try:
        snapshot_recovery_set(set_dir, snapshot, allow_legacy=allow_legacy)
        verify_recovery_signature(
            snapshot,
            trusted_public_key=trusted_public_key,
            expected_key_sha256=expected_key_sha256,
            expected_component_commit=expected_component_commit,
        )
        yield snapshot
    finally:
        _discard_recovery_snapshot(snapshot)


def create_escrow_generation(output_dir: Path | str, master_key_out: Path | str) -> Path:
    output_dir = Path(output_dir)
    master_key_out = Path(master_key_out)
    _mkdir_exclusive(output_dir, 0o700, "escrow generation")
    generation_id = f"escrow-{datetime.now(timezone.utc).strftime('%Y%m%dt%H%M%Sz')}-{secrets.token_hex(8)}"
    master = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=")
    try:
        lines = shamir_split(master, 2, 4)
        share_records = []
        for index, line in enumerate(lines, start=1):
            name = f"share-{index:02d}.txt"
            payload = line.encode("ascii") + b"\n"
            _atomic_write(output_dir / name, payload, 0o600)
            share_records.append(
                {"index": index, "file": name, "sha256": _sha256_bytes(payload)}
            )
        manifest = {
            "schema": ESCROW_SCHEMA,
            "generation_id": generation_id,
            "created_at": _utc_now(),
            "threshold": 2,
            "shares": 4,
            "master_key_sha256": _sha256_bytes(master),
            "share_records": share_records,
        }
        manifest_path = output_dir / "escrow-generation.json"
        _atomic_write(
            manifest_path,
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            0o600,
        )
        validate_all_share_pairs(manifest_path, output_dir)
    except BaseException:
        # This directory was created exclusively by this invocation.
        shutil.rmtree(output_dir, ignore_errors=True)
        raise
    try:
        # Publish the external master only after the complete generation has
        # validated.  _atomic_write refuses an existing path, so a refusal can
        # never alter or unlink an operator-owned master.
        _atomic_write(master_key_out, master + b"\n", 0o600)
    except BaseException:
        shutil.rmtree(output_dir, ignore_errors=True)
        raise
    return manifest_path


def _load_json_regular(path: Path, *, max_bytes: int, secret: bool = False) -> dict:
    descriptor = _open_regular(path, max_bytes=max_bytes, secret=secret)
    try:
        raw = _read_fd(descriptor, max_bytes)
    finally:
        os.close(descriptor)
    try:
        value = _json_loads_unique(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"invalid JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise RecoveryError(f"invalid JSON mapping: {path.name}")
    return value


def load_escrow_manifest(path: Path | str) -> dict:
    path = Path(path)
    value = _load_json_regular(path, max_bytes=MAX_KEYS_BYTES)
    if value.get("schema") != ESCROW_SCHEMA:
        raise RecoveryError("unsupported escrow generation schema")
    if set(value) != {
        "schema",
        "generation_id",
        "created_at",
        "threshold",
        "shares",
        "master_key_sha256",
        "share_records",
    }:
        raise RecoveryError("escrow generation has unexpected fields")
    _validate_timestamp(value.get("created_at"), "escrow creation")
    if not isinstance(value.get("generation_id"), str) or not ID_RE.fullmatch(
        value["generation_id"]
    ):
        raise RecoveryError("invalid escrow generation id")
    if value.get("threshold") != 2 or value.get("shares") != 4:
        raise RecoveryError("escrow generation must be exactly 2-of-4")
    master_hash = value.get("master_key_sha256")
    if not isinstance(master_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", master_hash):
        raise RecoveryError("invalid escrow master digest")
    records = value.get("share_records")
    if not isinstance(records, list) or len(records) != 4:
        raise RecoveryError("escrow generation requires four share records")
    indexes = set()
    files = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"index", "file", "sha256"}:
            raise RecoveryError("invalid escrow share record")
        index = record["index"]
        name = _safe_member_name(record["file"])
        digest = record["sha256"]
        if type(index) is not int or index not in range(1, 5):
            raise RecoveryError("invalid escrow share index")
        if "/" in name or not re.fullmatch(r"share-0[1-4]\.txt", name):
            raise RecoveryError("invalid escrow share filename")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RecoveryError("invalid escrow share digest")
        indexes.add(index)
        files.add(name)
    if indexes != {1, 2, 3, 4} or len(files) != 4:
        raise RecoveryError("escrow share records are not unique")
    return value


def _read_share(path: Path, records: list[dict]) -> str:
    raw = _read_regular_bytes(path, max_bytes=8192, secret=True)
    digest = _sha256_bytes(raw)
    matching = [record for record in records if record["sha256"] == digest]
    if len(matching) != 1:
        raise RecoveryError(f"share does not belong to this escrow generation: {path.name}")
    try:
        line = raw.decode("ascii").strip()
        tag, index_text, _ = line.split(":", 2)
        index = int(index_text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise RecoveryError(f"invalid share encoding: {path.name}") from exc
    if tag != "shamir-v1" or index != matching[0]["index"]:
        raise RecoveryError(f"share index does not match its record: {path.name}")
    return line


def recover_master_from_share_files(manifest: dict, share_files: list[Path | str]) -> bytes:
    if len(share_files) < 2:
        raise RecoveryError("two distinct share files are required")
    lines = [_read_share(Path(path), manifest["share_records"]) for path in share_files]
    indexes = [int(line.split(":", 2)[1]) for line in lines]
    if len(set(indexes)) != len(indexes):
        raise RecoveryError("duplicate escrow shares are not allowed")
    recovered_values = set()
    for pair in itertools.combinations(lines, 2):
        try:
            recovered_values.add(shamir_combine(list(pair)))
        except (ValueError, ZeroDivisionError) as exc:
            raise RecoveryError("escrow share reconstruction failed") from exc
    if len(recovered_values) != 1:
        raise RecoveryError("provided escrow shares disagree")
    master = recovered_values.pop()
    if _sha256_bytes(master) != manifest["master_key_sha256"]:
        raise RecoveryError("escrow shares reconstruct the wrong generation")
    return master


def validate_all_share_pairs(manifest_path: Path | str, share_dir: Path | str) -> None:
    manifest = load_escrow_manifest(manifest_path)
    share_dir = Path(share_dir)
    shares = [share_dir / record["file"] for record in manifest["share_records"]]
    for pair in itertools.combinations(shares, 2):
        recover_master_from_share_files(manifest, list(pair))


def recover_master_to_file(
    manifest_path: Path | str,
    share_files: list[Path | str],
    output_path: Path | str,
) -> None:
    manifest = load_escrow_manifest(manifest_path)
    master = recover_master_from_share_files(manifest, share_files)
    _atomic_write(Path(output_path), master + b"\n", 0o600)


def recover_legacy_shares_to_file(
    share_files: list[Path | str], output_path: Path | str
) -> None:
    if len(share_files) < 2:
        raise RecoveryError("two protected legacy share files are required")
    lines = []
    for value in share_files:
        raw = _read_regular_bytes(Path(value), max_bytes=8192, secret=True)
        try:
            lines.append(raw.decode("ascii").strip())
        except UnicodeDecodeError as exc:
            raise RecoveryError("invalid legacy share encoding") from exc
    try:
        recovered = shamir_combine(lines)
    except (ValueError, ZeroDivisionError) as exc:
        raise RecoveryError("legacy share reconstruction failed") from exc
    _atomic_write(Path(output_path), recovered + b"\n", 0o600)


def _entry_matches(entry: dict, relative: str) -> bool:
    pattern = entry["path"]
    base = pattern.rstrip("/")
    if pattern.endswith("/"):
        return relative.startswith(base + "/")
    if any(character in pattern for character in ("*", "?", "[")):
        return fnmatch.fnmatchcase(relative, pattern)
    return relative == pattern


def _excluded(entry: dict, relative: str) -> bool:
    return any(
        fnmatch.fnmatchcase(relative, pattern)
        or fnmatch.fnmatchcase(PurePosixPath(relative).name, pattern)
        for pattern in entry.get("exclude", [])
    )


def _credential_candidate(relative: str) -> bool:
    path = PurePosixPath(relative)
    name = path.name.lower()
    ancestor_names = {part.lower() for part in path.parts[:-1]}
    exact = {
        ".bashrc.pre-coding-system",
        ".credentials.json",
        ".dev.vars",
        ".env",
        ".env.local",
        ".modal.toml",
        ".netrc",
        ".npmrc",
        ".npmrc.pre-coding-system",
        ".pypirc",
        ".profile.pre-coding-system",
        "auth.json",
        "authorized_keys",
        "hosts.yml",
        "id_rsa",
        "known_hosts",
        "kaggle.json",
        "key4.db",
        "cert9.db",
        "pkcs11.txt",
        "forms-backup-attestation-ed25519.pem.gpg",
        "rclone.conf",
        "tailscaled.state",
    }
    backup_base = re.sub(r"\.(?:bak|backup|old)(?:\..*)?\Z", "", name)
    if name in exact or backup_base in exact:
        return True
    if ancestor_names & {
        "auth",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "token",
        "tokens",
    }:
        return True
    if name == "config.toml" and relative.startswith(
        (".kimi-code/", ".codewhale/", ".deepseek/")
    ):
        return True
    if name == "config.json" and any(
        marker in f"/{relative.lower()}" for marker in ("/skills/", "/plugins/")
    ):
        return True
    if name.endswith((".env", ".key", ".pem")):
        return True
    words = set(filter(None, re.split(r"[^a-z0-9]+", name)))
    if (
        "apikey" in words
        or "oauth" in words
        or "oauth2" in words
        or {"api", "key"}.issubset(words)
    ):
        return True
    return "auth-profile" in name or bool(
        words & {"credential", "credentials", "secret", "secrets", "token", "tokens"}
    )


def _structured_discovery_kind(relative: str) -> str | None:
    lowered = relative.casefold()
    path = PurePosixPath(lowered)
    name = path.name
    if lowered == ".claude.json":
        return "json"
    if not lowered.startswith(STRUCTURED_DISCOVERY_PREFIXES):
        return None
    if any(part in STRUCTURED_DISCOVERY_SKIP_COMPONENTS for part in path.parts[:-1]):
        return None
    if name not in STRUCTURED_DISCOVERY_NAMES:
        return None
    if lowered == ".copilot/config.json":
        return "jsonc"
    return "json" if name.endswith(".json") else "toml"


def _sqlite_discovery_candidate(relative: str) -> bool:
    lowered = relative.casefold()
    path = PurePosixPath(lowered)
    if not lowered.startswith(STRUCTURED_DISCOVERY_PREFIXES):
        return False
    if any(part in STRUCTURED_DISCOVERY_SKIP_COMPONENTS for part in path.parts[:-1]):
        return False
    if lowered.endswith(SQLITE_SIDECAR_SUFFIXES):
        return False
    return lowered.endswith(SQLITE_DISCOVERY_EXTENSIONS)


def _is_exact_structured_secret_ref(value: object) -> bool:
    """Recognize only OpenClaw's canonical, three-field SecretRef shape."""

    if not isinstance(value, dict) or set(value) != {"source", "provider", "id"}:
        return False
    source = value.get("source")
    provider = value.get("provider")
    identifier = value.get("id")
    return (
        isinstance(source, str)
        and source.casefold() in {"env", "file", "exec"}
        and isinstance(provider, str)
        and bool(provider.strip())
        and isinstance(identifier, str)
        and bool(identifier.strip())
    )


def _structured_value_contains_literal_secret(value: object) -> bool:
    if isinstance(value, str):
        stripped = value.strip()
        if not _credential_value_is_configured(stripped):
            return False
        if re.fullmatch(r"\$\{?[A-Z][A-Z0-9_]*\}?", stripped):
            return False
        if re.fullmatch(r"(?i:env):[A-Z][A-Z0-9_]*", stripped):
            return False
        if re.fullmatch(r"\{\{\s*[A-Za-z_][A-Za-z0-9_. -]*\s*\}\}", stripped):
            return False
        return True
    if isinstance(value, dict):
        if _is_exact_structured_secret_ref(value):
            return False
        return any(_structured_value_contains_literal_secret(item) for item in value.values())
    if isinstance(value, list):
        return any(_structured_value_contains_literal_secret(item) for item in value)
    return value is not None and value is not False


def _structured_secret_fields(value: object) -> set[str]:
    fields: set[str] = set()
    nodes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > 100_000 or depth > 12:
            raise RecoveryError("structured credential discovery exceeds its bound")
        if isinstance(item, dict):
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise RecoveryError("structured credential discovery mapping is invalid")
                normalized = re.sub(r"[^a-z0-9_]", "", key.casefold())
                compact = normalized.replace("_", "")
                if (
                    (
                        normalized in STRUCTURED_SECRET_FIELD_NAMES
                        or compact in STRUCTURED_SECRET_FIELD_NAMES_COMPACT
                    )
                    and _structured_value_contains_literal_secret(nested)
                ):
                    fields.add(normalized)
                visit(nested, depth + 1)
        elif isinstance(item, list):
            for nested in item:
                visit(nested, depth + 1)

    visit(value, 0)
    return fields


def _strip_jsonc_comments(raw: bytes) -> str:
    """Remove JSONC comments without treating comment markers in strings as syntax."""

    text = raw.decode("utf-8")
    output: list[str] = []
    index = 0
    in_string = False
    while index < len(text):
        character = text[index]
        if in_string:
            output.append(character)
            if character == "\\":
                index += 1
                if index < len(text):
                    output.append(text[index])
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            output.append(character)
            index += 1
            continue
        if character == "/" and index + 1 < len(text):
            marker = text[index + 1]
            if marker == "/":
                output.extend((" ", " "))
                index += 2
                while index < len(text) and text[index] not in {"\r", "\n"}:
                    output.append(" ")
                    index += 1
                continue
            if marker == "*":
                output.extend((" ", " "))
                index += 2
                while index < len(text):
                    if (
                        text[index] == "*"
                        and index + 1 < len(text)
                        and text[index + 1] == "/"
                    ):
                        output.extend((" ", " "))
                        index += 2
                        break
                    output.append(text[index] if text[index] in {"\r", "\n"} else " ")
                    index += 1
                else:
                    raise ValueError("unterminated JSONC block comment")
                continue
        output.append(character)
        index += 1
    return "".join(output)


def _inspect_structured_secret_fields(
    path: Path, kind: str, relative: str
) -> set[str]:
    raw = _read_regular_bytes(path, max_bytes=MAX_MANIFEST_BYTES)
    try:
        if kind == "json":
            value = _json_loads_unique(raw)
        elif kind == "jsonc":
            value = _json_loads_unique(_strip_jsonc_comments(raw))
        else:
            value = tomllib.loads(raw.decode("utf-8"))
    except (
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        RecoveryError,
    ) as exc:
        redacted_path = json.dumps(relative, ensure_ascii=True)
        raise RecoveryError(
            f"known agent configuration cannot be inspected safely: {redacted_path}"
        ) from exc
    return _structured_secret_fields(value)


def _inspect_sqlite_secret_fields(path: Path, relative: str) -> set[str]:
    """Inspect only bounded SQLite schema names; never read application rows."""

    parent_fd = _open_directory_path(path.parent)
    descriptor = -1
    connection: sqlite3.Connection | None = None
    before: os.stat_result | None = None
    after: os.stat_result | None = None
    linked_after: os.stat_result | None = None
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        linked_before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(linked_before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_size > MAX_SECRET_FILE
            or _stable_file_identity(before) != _stable_file_identity(linked_before)
        ):
            raise RecoveryError("known agent database cannot be inspected safely")
        if before.st_size == 0:
            # SQLite reads an empty file as an empty database, which has no schema.
            return set()
        sqlite_path = Path("/proc/self/fd") / str(parent_fd) / path.name
        connection = sqlite3.connect(
            f"{sqlite_path.as_uri()}?mode=ro",
            uri=True,
            timeout=5,
        )
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("BEGIN")
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
        if len(tables) > MAX_SQLITE_SCHEMA_TABLES:
            raise RecoveryError("known agent database schema exceeds its bound")
        fields: set[str] = set()
        column_count = 0
        for row in tables:
            if (
                len(row) != 1
                or not isinstance(row[0], str)
                or not row[0]
                or len(row[0].encode("utf-8")) > 1024
            ):
                raise RecoveryError("known agent database schema is invalid")
            quoted = row[0].replace('"', '""')
            columns = connection.execute(
                f'PRAGMA table_xinfo("{quoted}")'
            ).fetchall()
            column_count += len(columns)
            if column_count > MAX_SQLITE_SCHEMA_COLUMNS:
                raise RecoveryError("known agent database schema exceeds its bound")
            for column in columns:
                name = column[1] if len(column) > 1 else None
                if not isinstance(name, str) or len(name.encode("utf-8")) > 1024:
                    raise RecoveryError("known agent database schema is invalid")
                normalized = re.sub(r"[^a-z0-9_]+", "", name.casefold())
                if normalized in SQLITE_SECRET_COLUMN_NAMES:
                    fields.add(normalized)
        connection.rollback()
    except sqlite3.Error as exc:
        redacted_path = json.dumps(relative, ensure_ascii=True)
        raise RecoveryError(
            f"known agent database cannot be inspected safely: {redacted_path}"
        ) from exc
    finally:
        if connection is not None:
            connection.close()
        try:
            if descriptor >= 0:
                after = os.fstat(descriptor)
                linked_after = os.stat(
                    path.name, dir_fd=parent_fd, follow_symlinks=False
                )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent_fd)
    assert before is not None and after is not None and linked_after is not None
    if (
        _stable_file_identity(before) != _stable_file_identity(after)
        or _stable_file_identity(after) != _stable_file_identity(linked_after)
    ):
        raise RecoveryError("known agent database changed during schema inspection")
    return fields


def _declared(manifest: dict, relative: str) -> bool:
    return any(_entry_matches(entry, relative) for entry in manifest["entries"])


def discover_unclassified(home: Path, manifest: dict) -> list[str]:
    """Find undeclared credential paths and bounded structured secret fields."""
    root_fd = _open_directory_path(home)
    os.close(root_fd)
    candidates: set[str] = set()
    structured: dict[str, set[str]] = {}
    sqlite_structured: dict[str, set[str]] = {}
    for relative_root in DISCOVERY_ROOTS:
        root = home / relative_root
        if not os.path.lexists(root):
            continue
        try:
            root_info = root.lstat()
        except OSError as exc:
            raise RecoveryError("cannot inspect credential discovery root") from exc
        if root.is_symlink():
            raise RecoveryError("symlink credential discovery root")
        if stat.S_ISREG(root_info.st_mode):
            if _credential_candidate(relative_root):
                candidates.add(relative_root)
            if _declared(manifest, relative_root):
                continue
            kind = _structured_discovery_kind(relative_root)
            if kind is not None:
                fields = _inspect_structured_secret_fields(
                    root, kind, relative_root
                )
                if fields:
                    structured[relative_root] = fields
            if _sqlite_discovery_candidate(relative_root):
                fields = _inspect_sqlite_secret_fields(root, relative_root)
                if fields:
                    sqlite_structured[relative_root] = fields
            continue
        if not stat.S_ISDIR(root_info.st_mode):
            raise RecoveryError("special credential discovery root")
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            safe_dirs = []
            for dirname in dirnames:
                child = Path(directory) / dirname
                info = child.lstat()
                if stat.S_ISLNK(info.st_mode):
                    # A link that looks credential-bearing is itself unclassified;
                    # unrelated runtime links are not traversed.
                    relative = child.relative_to(home).as_posix()
                    if _credential_candidate(relative):
                        candidates.add(relative)
                    continue
                if dirname.lower() not in DISCOVERY_SKIP_DIRS:
                    safe_dirs.append(dirname)
            dirnames[:] = safe_dirs
            for filename in filenames:
                path = Path(directory) / filename
                relative = path.relative_to(home).as_posix()
                if _credential_candidate(relative):
                    candidates.add(relative)
                if _declared(manifest, relative):
                    # A declared file is classified whatever it holds, so only
                    # undeclared files are opened for inspection.
                    continue
                kind = _structured_discovery_kind(relative)
                if kind is not None:
                    fields = _inspect_structured_secret_fields(path, kind, relative)
                    if fields:
                        structured[relative] = fields
                if _sqlite_discovery_candidate(relative):
                    fields = _inspect_sqlite_secret_fields(path, relative)
                    if fields:
                        sqlite_structured[relative] = fields
    unclassified: list[str] = []
    for candidate in sorted(candidates | set(structured) | set(sqlite_structured)):
        if not _declared(manifest, candidate):
            fields = structured.get(candidate) or sqlite_structured.get(candidate)
            if fields:
                unclassified.extend(
                    f"{candidate}#{field}" for field in sorted(fields)
                )
            else:
                unclassified.append(candidate)
    return unclassified


def _walk_regular_tree(root: Path, home: Path, entry: dict) -> list[str]:
    output: list[str] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name, reverse=True)
        except OSError as exc:
            raise RecoveryError("cannot enumerate a declared secret directory") from exc
        for item in entries:
            try:
                info = item.stat(follow_symlinks=False)
            except OSError as exc:
                raise RecoveryError("cannot inspect a declared secret path") from exc
            relative = Path(item.path).relative_to(home).as_posix()
            if stat.S_ISLNK(info.st_mode):
                raise RecoveryError("symlink in declared secret tree")
            if _excluded(entry, relative):
                continue
            if stat.S_ISDIR(info.st_mode):
                stack.append(Path(item.path))
            elif stat.S_ISREG(info.st_mode):
                output.append(relative)
            else:
                raise RecoveryError("special file in declared secret tree")
    return sorted(output)


def _enumerate_entry(home: Path, entry: dict) -> list[str]:
    pattern = entry["path"]
    base = pattern.rstrip("/")
    hits: list[Path] = []
    if any(character in pattern for character in ("*", "?", "[")):
        import glob

        hits = [Path(value) for value in glob.glob(str(home / pattern))]
    else:
        candidate = home / base
        if os.path.lexists(candidate):
            hits = [candidate]
    output: list[str] = []
    for hit in sorted(hits):
        try:
            info = hit.lstat()
        except OSError as exc:
            raise RecoveryError("cannot inspect a declared secret path") from exc
        if stat.S_ISLNK(info.st_mode):
            raise RecoveryError("symlink in declared secret path")
        if stat.S_ISDIR(info.st_mode):
            output.extend(_walk_regular_tree(hit, home, entry))
        elif stat.S_ISREG(info.st_mode):
            output.append(hit.relative_to(home).as_posix())
        else:
            raise RecoveryError("special file in declared secret path")
    return sorted(path for path in output if not _excluded(entry, path))


def _reachable_permission_bits(home_info: os.stat_result) -> int:
    """Group and other permission bits that those users can reach through the home."""
    mode = stat.S_IMODE(home_info.st_mode)
    return (0o070 if mode & 0o010 else 0) | (0o007 if mode & 0o001 else 0)


def _validate_manifest_source_metadata(
    info: os.stat_result, entry: dict, reachable: int = 0o077
) -> None:
    """Refuse a live backup source that other users can use beyond its manifest mode.

    Archives always carry the manifest mode, so owner bits are not compared, and
    group or other bits count only where those users can traverse the home.
    """
    if info.st_uid != os.geteuid():
        raise RecoveryError("declared backup source is not owned by the current user")
    if info.st_nlink != 1:
        raise RecoveryError("declared backup source must have exactly one link")
    expected_mode = _parse_mode(entry["mode"], label=entry["id"])
    if stat.S_IMODE(info.st_mode) & reachable & ~expected_mode:
        raise RecoveryError(
            "declared backup source permissions are broader than the manifest"
        )


def _validate_sqlite_capture_source(
    root_fd: int, relative: str, entry: dict
) -> None:
    """Require a private database directory and private live SQLite sidecars."""

    _safe_member_name(relative)
    components = relative.split("/")
    parent_fd = os.dup(root_fd)
    try:
        for component in components[:-1]:
            child = _open_dir_component(parent_fd, component)
            os.close(parent_fd)
            parent_fd = child
        parent_info = os.fstat(parent_fd)
        if (
            parent_info.st_uid != os.geteuid()
            or stat.S_IMODE(parent_info.st_mode) != 0o700
        ):
            raise RecoveryError("SQLite backup source directory is not owner-private")
        for index, suffix in enumerate(("", *SQLITE_SIDECAR_SUFFIXES)):
            name = components[-1] + suffix
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(name, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                if index == 0:
                    raise RecoveryError("declared SQLite backup source is missing")
                continue
            except OSError as exc:
                raise RecoveryError("SQLite backup source is unsafe") from exc
            try:
                information = os.fstat(descriptor)
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(information.st_mode)
                    or not stat.S_ISREG(named.st_mode)
                    or (information.st_dev, information.st_ino)
                    != (named.st_dev, named.st_ino)
                    or information.st_uid != os.geteuid()
                    or information.st_nlink != 1
                    or stat.S_IMODE(information.st_mode) != 0o600
                    or information.st_size > MAX_SECRET_FILE
                ):
                    raise RecoveryError("SQLite backup source is not owner-private")
            finally:
                os.close(descriptor)
    finally:
        os.close(parent_fd)


def _snapshot_sqlite_capture(
    source_home: Path, root_fd: int, relative: str, entry: dict
) -> bytes:
    """Create one bounded, transactionally consistent SQLite backup image."""

    _validate_sqlite_capture_source(root_fd, relative, entry)
    components = relative.split("/")
    parent_fd = os.dup(root_fd)
    for component in components[:-1]:
        child = _open_dir_component(parent_fd, component)
        os.close(parent_fd)
        parent_fd = child
    descriptor = _open_relative_regular(root_fd, relative)
    source: sqlite3.Connection | None = None
    target: sqlite3.Connection | None = None
    before = os.fstat(descriptor)
    deadline = time.monotonic() + 60
    try:
        with secure_temporary_directory(prefix="csr-sqlite-backup-") as temporary:
            snapshot = Path(temporary) / "snapshot.sqlite"
            try:
                source_path = (
                    Path("/proc/self/fd") / str(parent_fd) / components[-1]
                )
                source = sqlite3.connect(
                    f"{source_path.as_uri()}?mode=ro",
                    uri=True,
                    timeout=5,
                )
                source.execute("PRAGMA query_only = ON")
                source.execute("PRAGMA trusted_schema = OFF")
                page_size = int(source.execute("PRAGMA page_size").fetchone()[0])
                if not 512 <= page_size <= 65_536:
                    raise RecoveryError("SQLite backup source page size is invalid")
                target = sqlite3.connect(snapshot, timeout=5)

                def bounded_progress(
                    _status: int, remaining: int, total: int
                ) -> None:
                    if (
                        remaining < 0
                        or total < 0
                        or total * page_size > MAX_SECRET_FILE
                        or time.monotonic() > deadline
                    ):
                        raise RecoveryError("SQLite backup capture exceeds its bound")

                source.backup(
                    target,
                    pages=256,
                    progress=bounded_progress,
                    sleep=0.01,
                )
                if target.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise RecoveryError("SQLite backup snapshot is invalid")
                target.close()
                target = None
                source.close()
                source = None
            except sqlite3.Error as exc:
                raise RecoveryError("SQLite backup capture failed") from exc
            finally:
                if target is not None:
                    target.close()
                if source is not None:
                    source.close()
            snapshot.chmod(0o600)
            data = _read_regular_bytes(snapshot, max_bytes=MAX_SECRET_FILE, secret=True)
        after = os.fstat(descriptor)
        named_after = os.stat(
            components[-1], dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or (after.st_dev, after.st_ino)
            != (named_after.st_dev, named_after.st_ino)
        ):
            raise RecoveryError("SQLite backup source changed identity during capture")
        _validate_manifest_source_metadata(
            after, entry, _reachable_permission_bits(os.fstat(root_fd))
        )
        _validate_sqlite_capture_source(root_fd, relative, entry)
        return data
    finally:
        os.close(descriptor)
        os.close(parent_fd)


def _open_relative_regular(root_fd: int, relative: str) -> int:
    _safe_member_name(relative)
    components = relative.split("/")
    descriptor = os.dup(root_fd)
    file_fd = -1
    try:
        for component in components[:-1]:
            child = _open_dir_component(descriptor, component)
            os.close(descriptor)
            descriptor = child
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(components[-1], flags, dir_fd=descriptor)
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SECRET_FILE:
            os.close(file_fd)
            file_fd = -1
            raise RecoveryError("declared secret is not a bounded regular file")
        return file_fd
    except OSError as exc:
        if file_fd >= 0:
            os.close(file_fd)
        raise RecoveryError("unsafe declared secret path") from exc
    finally:
        os.close(descriptor)


def enumerate_manifest_files(home: Path, manifest: dict) -> dict[str, dict]:
    try:
        home_info = home.lstat()
    except OSError as exc:
        raise RecoveryError("source home is unavailable") from exc
    if home.is_symlink() or not stat.S_ISDIR(home_info.st_mode):
        raise RecoveryError("source home must be a real directory")
    files: dict[str, dict] = {}
    missing: list[str] = []
    reachable = _reachable_permission_bits(home_info)
    root_fd = _open_directory_path(home)
    try:
        for entry in manifest["entries"]:
            if not entry["backup"]:
                continue
            found = _enumerate_entry(home, entry)
            if not found and entry["required"]:
                missing.append(entry["id"])
            for relative in found:
                # Re-open through no-follow directory descriptors so an exact
                # path whose ancestor is a symlink cannot enter the capture.
                descriptor = _open_relative_regular(root_fd, relative)
                try:
                    _validate_manifest_source_metadata(
                        os.fstat(descriptor), entry, reachable
                    )
                finally:
                    os.close(descriptor)
                if entry.get("capture", "regular") == "sqlite-backup":
                    _validate_sqlite_capture_source(root_fd, relative, entry)
                if relative in files:
                    raise RecoveryError("a source file matches multiple manifest entries")
                files[relative] = entry
    finally:
        os.close(root_fd)
    if missing:
        raise RecoveryError("required manifest entries are missing: " + ", ".join(missing))
    return files


def _read_source_regular(path: Path) -> tuple[bytes, os.stat_result]:
    descriptor = _open_regular(path, max_bytes=MAX_SECRET_FILE)
    try:
        before = os.fstat(descriptor)
        data = _read_fd(descriptor, MAX_SECRET_FILE)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    linked = path.lstat()
    identity = lambda info: (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )
    if identity(before) != identity(after) or identity(after) != identity(linked):
        raise RecoveryError("source file changed during capture")
    return data, after


def _write_tar(path: Path, source_home: Path, files: dict[str, dict], group: str) -> None:
    selected = {
        relative: entry
        for relative, entry in files.items()
        if ("private-state" if entry["classification"] == "private-state" else "secrets")
        == group
    }
    root_fd = _open_directory_path(source_home)
    try:
        reachable = _reachable_permission_bits(os.fstat(root_fd))
        with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
            for relative, entry in sorted(selected.items()):
                if entry.get("capture", "regular") == "sqlite-backup":
                    data = _snapshot_sqlite_capture(
                        source_home, root_fd, relative, entry
                    )
                    info = tarfile.TarInfo(relative)
                    info.size = len(data)
                    info.mode = _parse_mode(entry["mode"], label=entry["id"])
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    archive.addfile(info, fileobj=_BytesReader(data))
                    continue
                descriptor = _open_relative_regular(root_fd, relative)
                try:
                    before = os.fstat(descriptor)
                    _validate_manifest_source_metadata(before, entry, reachable)
                    data = _read_fd(descriptor, MAX_SECRET_FILE)
                    after = os.fstat(descriptor)
                    _validate_manifest_source_metadata(after, entry, reachable)
                finally:
                    os.close(descriptor)
                identity = lambda value: (
                    value.st_dev,
                    value.st_ino,
                    value.st_size,
                    value.st_mtime_ns,
                    value.st_ctime_ns,
                )
                if identity(before) != identity(after):
                    raise RecoveryError("source file changed during capture")
                info = tarfile.TarInfo(relative)
                info.size = len(data)
                info.mode = _parse_mode(entry["mode"], label=entry["id"])
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                archive.addfile(info, fileobj=_BytesReader(data))
    finally:
        os.close(root_fd)


class _BytesReader:
    def __init__(self, value: bytes):
        self.value = value
        self.position = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.value) - self.position
        chunk = self.value[self.position : self.position + size]
        self.position += len(chunk)
        return chunk


def _gpg(
    source: Path,
    output: Path,
    passphrase: bytes,
    *,
    decrypt: bool,
    max_output: int,
) -> None:
    # Recovery decryption is an authentication boundary: never resolve GnuPG
    # through an inherited, potentially user-writable PATH.  Ubuntu 24.04's
    # gnupg package owns both fixed paths below.
    gpg = "/usr/bin/gpg"
    gpgconf = "/usr/bin/gpgconf"
    crypto_environment = {
        "HOME": "/",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    if not os.path.isfile(gpg) or not os.access(gpg, os.X_OK):
        raise RecoveryError("the system gpg executable is required for recovery")
    if not os.path.isfile(gpgconf) or not os.access(gpgconf, os.X_OK):
        raise RecoveryError("the system gpgconf executable is required for recovery")
    source_fd = _open_regular(source, max_bytes=max_output)
    output_parent_fd = _open_directory_path(output.parent)
    output_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    output_fd = -1
    read_fd = -1
    write_fd = -1
    success = False

    def bounded_child() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_output, max_output))

    try:
        try:
            output_fd = os.open(
                output.name, output_flags, 0o600, dir_fd=output_parent_fd
            )
        except FileExistsError as exc:
            raise RecoveryError("refusing to overwrite cryptographic output") from exc
        read_fd, write_fd = os.pipe()
        os.set_inheritable(read_fd, True)
        with secure_temporary_directory(prefix="csr-gpg-") as homedir:
            os.chmod(homedir, 0o700)
            command = [
                gpg,
                "--no-options",
                "--homedir",
                homedir,
                "--batch",
                "--yes",
                "--no-symkey-cache",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                str(read_fd),
                "--output",
                f"/proc/self/fd/{output_fd}",
            ]
            if decrypt:
                command.extend(["--decrypt", f"/proc/self/fd/{source_fd}"])
            else:
                command.extend(
                    [
                        "--compress-algo",
                        "none",
                        "--cipher-algo",
                        "AES256",
                        "--symmetric",
                        f"/proc/self/fd/{source_fd}",
                    ]
                )
            try:
                process = subprocess.Popen(
                    command,
                    env=crypto_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    pass_fds=(read_fd, source_fd, output_fd),
                    preexec_fn=bounded_child,
                )
                os.close(read_fd)
                read_fd = -1
                try:
                    payload = memoryview(passphrase + b"\n")
                    while payload:
                        written = os.write(write_fd, payload)
                        payload = payload[written:]
                finally:
                    os.close(write_fd)
                    write_fd = -1
                try:
                    process.communicate(timeout=180)
                except subprocess.TimeoutExpired as exc:
                    process.kill()
                    process.communicate()
                    raise RecoveryError("gpg operation timed out") from exc
                if process.returncode != 0:
                    # Do not relay arbitrary GnuPG output into automation logs.
                    raise RecoveryError("gpg encryption/decryption failed")
            finally:
                # A dedicated homedir must not leave an agent (and potentially
                # cached symmetric material) alive after the operation.
                try:
                    agent_cleanup = subprocess.run(
                        [gpgconf, "--homedir", homedir, "--kill", "gpg-agent"],
                        env=crypto_environment,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                        check=False,
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise RecoveryError("could not terminate the scoped gpg agent") from exc
                if agent_cleanup.returncode != 0:
                    raise RecoveryError("could not terminate the scoped gpg agent")
        info = os.fstat(output_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_output:
            raise RecoveryError("gpg output violated the recovery bound")
        os.fchmod(output_fd, 0o600)
        os.fsync(output_fd)
        success = True
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        if output_fd >= 0:
            os.close(output_fd)
            if not success:
                try:
                    os.unlink(output.name, dir_fd=output_parent_fd)
                except FileNotFoundError:
                    pass
        os.close(output_parent_fd)
        os.close(source_fd)


def _artifact_record(path: Path) -> dict:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise RecoveryError("recovery artifact is not regular")
    return {"file": path.name, "sha256": _sha256_file(path), "size": info.st_size}


def _qualified_openclaw_version(component_commit: str) -> str:
    """Return the OpenClaw version from the commit-bound compatibility lock."""

    lock_path = REPOSITORY_ROOT / "system/openclaw/compatibility.lock.json"
    local_raw = _read_regular_bytes(lock_path, max_bytes=MAX_KEYS_BYTES)
    committed = _git_file_at_commit(
        component_commit,
        "system/openclaw/compatibility.lock.json",
        maximum=MAX_KEYS_BYTES,
    )
    raw = committed if committed is not None else local_raw
    try:
        value = _json_loads_unique(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("OpenClaw compatibility lock is invalid") from exc
    openclaw = value.get("openclaw") if isinstance(value, dict) else None
    version = openclaw.get("version") if isinstance(openclaw, dict) else None
    if (
        value.get("schema_version") != 1
        or not isinstance(version, str)
        or OPENCLAW_VERSION_RE.fullmatch(version) is None
    ):
        raise RecoveryError("OpenClaw compatibility lock has no qualified version")
    return version


def _validate_owner_data_record(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "file",
        "sha256",
        "size",
        "openclaw_version",
        "requirement",
        "created_at",
        "source_state_hmac_sha256",
        "capture_policy",
    }:
        raise RecoveryError("invalid owner-data recovery record")
    filename = value.get("file")
    digest = value.get("sha256")
    size = value.get("size")
    version = value.get("openclaw_version")
    requirement = value.get("requirement")
    created_at = value.get("created_at")
    source_state = value.get("source_state_hmac_sha256")
    capture_policy = value.get("capture_policy")
    if (
        not isinstance(filename, str)
        or OWNER_DATA_FILENAME_RE.fullmatch(filename) is None
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or type(size) is not int
        or not 0 < size <= MAX_OWNER_DATA_BYTES
        or not isinstance(version, str)
        or OPENCLAW_VERSION_RE.fullmatch(version) is None
        or requirement not in OWNER_DATA_REQUIREMENTS
        or not isinstance(created_at, str)
        or not created_at.endswith("Z")
        or not isinstance(source_state, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_state) is None
        or capture_policy not in OWNER_DATA_CAPTURE_POLICIES
    ):
        raise RecoveryError("invalid owner-data recovery record")
    _validate_timestamp(created_at, "owner-data capture")
    return dict(value)


def _copy_owner_data_archive(source: Path, destination: Path) -> dict[str, object]:
    if OWNER_DATA_FILENAME_RE.fullmatch(source.name) is None:
        raise RecoveryError("owner-data archive filename is not canonical")
    source_fd = _open_regular(source, max_bytes=MAX_OWNER_DATA_BYTES, secret=True)
    destination_parent_fd = _open_directory_path(destination.parent)
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        destination_fd = os.open(
            destination.name, flags, 0o600, dir_fd=destination_parent_fd
        )
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_OWNER_DATA_BYTES:
                raise RecoveryError("owner-data archive exceeds its bound")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise RecoveryError("owner-data archive copy was truncated")
                view = view[written:]
        after = os.fstat(source_fd)
        if (
            copied != before.st_size
            or _stable_file_identity(before) != _stable_file_identity(after)
        ):
            raise RecoveryError("owner-data archive changed while copying")
        os.fchmod(destination_fd, 0o600)
        os.fsync(destination_fd)
        os.fsync(destination_parent_fd)
        return {
            "file": destination.name,
            "sha256": digest.hexdigest(),
            "size": copied,
        }
    except BaseException:
        if destination_fd >= 0:
            os.close(destination_fd)
            destination_fd = -1
        try:
            os.unlink(destination.name, dir_fd=destination_parent_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(destination_parent_fd)


def create_recovery_set(
    manifest_path: Path | str,
    source_home: Path | str,
    output_dir: Path | str,
    master_key_file: Path | str,
    escrow_manifest_path: Path | str,
    component_commit: str,
    set_id: str | None = None,
    owner_data_archive: Path | str | None = None,
    expected_owner_source_state_hmac: str | None = None,
    owner_data_capture_policy: str | None = None,
) -> Path:
    manifest_path = Path(manifest_path)
    source_home = Path(source_home)
    output_dir = Path(output_dir)
    master_key_file = Path(master_key_file)
    escrow_manifest_path = Path(escrow_manifest_path)
    owner_data_path = Path(owner_data_archive) if owner_data_archive is not None else None
    if not COMMIT_RE.fullmatch(component_commit):
        raise RecoveryError("coding-system-rebuild commit must be lowercase 40- or 64-hex")
    if set_id is None:
        set_id = f"csr-{datetime.now(timezone.utc).strftime('%Y%m%dt%H%M%Sz')}-{secrets.token_hex(8)}"
    if not ID_RE.fullmatch(set_id):
        raise RecoveryError("invalid recovery set id")
    manifest, manifest_raw, manifest_digest = _read_secrets_manifest_snapshot(
        manifest_path
    )
    _bind_manifest_to_commit(manifest_raw, manifest_digest, component_commit)
    bootstrap_path = REPOSITORY_ROOT / "restore-ubuntu.sh"
    bootstrap_raw = _read_regular_bytes(bootstrap_path, max_bytes=MAX_KEYS_BYTES)
    committed_bootstrap = _git_file_at_commit(
        component_commit, "restore-ubuntu.sh", maximum=MAX_KEYS_BYTES
    )
    if committed_bootstrap is not None and not secrets.compare_digest(
        committed_bootstrap, bootstrap_raw
    ):
        raise RecoveryError(
            "Stage-0 bootstrap does not match the referenced coding-system-rebuild commit"
        )
    escrow = load_escrow_manifest(escrow_manifest_path)
    escrow_raw = _read_regular_bytes(escrow_manifest_path, max_bytes=MAX_KEYS_BYTES)
    try:
        if _json_loads_unique(escrow_raw) != escrow:
            raise RecoveryError("escrow manifest changed during validation")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("invalid escrow generation JSON") from exc
    master = _read_secret_file(master_key_file)
    if _sha256_bytes(master) != escrow["master_key_sha256"]:
        raise RecoveryError("master key does not match the escrow generation")
    unclassified = discover_unclassified(source_home, manifest)
    if unclassified:
        raise RecoveryError(
            "unclassified credential candidates: " + ", ".join(unclassified[:20])
        )
    files = enumerate_manifest_files(source_home, manifest)
    owner_data_required, owner_source_state = openclaw_private_source_state(
        source_home, master
    )
    if owner_data_required and owner_data_path is None:
        raise RecoveryError(
            "configured OpenClaw private capability requires an owner-data archive"
        )
    if owner_data_path is not None:
        if (
            expected_owner_source_state_hmac is None
            or not secrets.compare_digest(
                expected_owner_source_state_hmac, owner_source_state
            )
        ):
            raise RecoveryError(
                "OpenClaw private source state changed during owner-data capture"
            )
        if owner_data_capture_policy not in OWNER_DATA_CAPTURE_POLICIES:
            raise RecoveryError("owner-data capture policy is invalid")
    elif expected_owner_source_state_hmac is not None or owner_data_capture_policy is not None:
        raise RecoveryError("owner-data capture metadata has no archive")
    openclaw_version = _qualified_openclaw_version(component_commit)
    _mkdir_exclusive(output_dir, 0o700, "recovery set")
    try:
        escrow_copy = output_dir / "escrow-generation.json"
        _atomic_write(escrow_copy, escrow_raw, 0o600)
        bootstrap_copy = output_dir / "restore-ubuntu.sh"
        _atomic_write(bootstrap_copy, bootstrap_raw, 0o500)
        with secure_temporary_directory(prefix="csr-recovery-build-") as temporary:
            work = Path(temporary)
            plaintext_records: dict[str, dict] = {}
            artifact_keys: dict[str, bytes] = {}
            for group, filename in (
                ("secrets", "secrets.tar.gpg"),
                ("private-state", "private-state.tar.gpg"),
            ):
                plain = work / f"{group}.tar"
                _write_tar(plain, source_home, files, group)
                artifact_keys[filename] = base64.urlsafe_b64encode(
                    secrets.token_bytes(32)
                ).rstrip(b"=")
                plaintext_records[filename] = {
                    "sha256": _sha256_file(plain),
                    "size": plain.stat().st_size,
                }
                _gpg(
                    plain,
                    output_dir / filename,
                    artifact_keys[filename],
                    decrypt=False,
                    max_output=MAX_ARCHIVE_BYTES,
                )
            keys = {
                "schema": KEYS_SCHEMA,
                "set_id": set_id,
                "component_commit": component_commit,
                "artifacts": {
                    filename: {
                        "passphrase": artifact_keys[filename].decode("ascii"),
                        "plaintext_sha256": plaintext_records[filename]["sha256"],
                        "plaintext_size": plaintext_records[filename]["size"],
                    }
                    for filename in sorted(artifact_keys)
                },
            }
            keys_plain = work / "keys.json"
            keys_plain.write_text(
                json.dumps(keys, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            keys_plain.chmod(0o600)
            _gpg(
                keys_plain,
                output_dir / "keys.json.gpg",
                master,
                decrypt=False,
                max_output=MAX_KEYS_BYTES,
            )

        artifacts = {
            "keys": _artifact_record(output_dir / "keys.json.gpg"),
            "secrets": _artifact_record(output_dir / "secrets.tar.gpg"),
            "private_state": _artifact_record(output_dir / "private-state.tar.gpg"),
        }
        owner_data: dict[str, object] | None = None
        if owner_data_path is not None:
            owner_data = _copy_owner_data_archive(
                owner_data_path, output_dir / owner_data_path.name
            )
            owner_data.update(
                {
                    "openclaw_version": openclaw_version,
                    "requirement": (
                        "agent-private-capability"
                        if owner_data_required
                        else "history-only"
                    ),
                    "created_at": datetime.strptime(
                        owner_data_path.name[
                            len("openclaw-private-") : -len(".tar.gz.gpg")
                        ],
                        "%Y%m%dT%H%M%SZ",
                    )
                    .replace(tzinfo=timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "source_state_hmac_sha256": owner_source_state,
                    "capture_policy": owner_data_capture_policy,
                }
            )
        public = {
            "schema": RECOVERY_SCHEMA,
            "set_id": set_id,
            "created_at": _utc_now(),
            "components": {
                "coding-system-rebuild": {"commit": component_commit},
            },
            "escrow_generation": {
                "generation_id": escrow["generation_id"],
                "file": "escrow-generation.json",
                "manifest_sha256": _sha256_bytes(escrow_raw),
            },
            "secrets_manifest": {
                "schema": SECRETS_SCHEMA,
                "sha256": manifest_digest,
            },
            "bootstrap": _artifact_record(bootstrap_copy),
            "artifacts": artifacts,
            "owner_data": owner_data,
        }
        marker = output_dir / "recovery-set.json"
        _atomic_write(
            marker,
            (json.dumps(public, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            0o600,
        )
        return marker
    except BaseException:
        shutil.rmtree(output_dir, ignore_errors=True)
        raise


def load_recovery_manifest(
    set_dir: Path | str, *, allow_legacy: bool = False
) -> dict:
    set_dir = Path(set_dir)
    try:
        info = set_dir.lstat()
    except OSError as exc:
        raise RecoveryError("recovery set directory is unavailable") from exc
    if set_dir.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise RecoveryError("recovery set path is not a real directory")
    value = _load_json_regular(set_dir / "recovery-set.json", max_bytes=MAX_KEYS_BYTES)
    schema = value.get("schema")
    if schema == LEGACY_RECOVERY_SCHEMA:
        if not allow_legacy:
            raise RecoveryError(
                "legacy recovery set requires an explicit degraded compatibility gate"
            )
    elif schema != RECOVERY_SCHEMA:
        raise RecoveryError("unsupported recovery set schema")
    expected_fields = {
        "schema",
        "set_id",
        "created_at",
        "components",
        "escrow_generation",
        "secrets_manifest",
        "artifacts",
    }
    if schema == RECOVERY_SCHEMA:
        expected_fields.add("owner_data")
    if set(value) not in (expected_fields, expected_fields | {"bootstrap"}):
        raise RecoveryError("recovery set manifest has unexpected fields")
    _validate_timestamp(value.get("created_at"), "recovery-set creation")
    components = value.get("components")
    if not isinstance(components, dict) or set(components) != {"coding-system-rebuild"}:
        raise RecoveryError("recovery set component inventory is invalid")
    set_id = value.get("set_id")
    if not isinstance(set_id, str) or not ID_RE.fullmatch(set_id):
        raise RecoveryError("invalid recovery set id")
    try:
        commit = value["components"]["coding-system-rebuild"]["commit"]
    except (KeyError, TypeError) as exc:
        raise RecoveryError("recovery set lacks the coding-system-rebuild commit") from exc
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise RecoveryError("invalid coding-system-rebuild commit in recovery set")
    owner_data = (
        _validate_owner_data_record(value.get("owner_data"))
        if schema == RECOVERY_SCHEMA
        else None
    )
    if owner_data is not None:
        if owner_data["openclaw_version"] != _qualified_openclaw_version(commit):
            raise RecoveryError(
                "owner-data archive version differs from the qualified OpenClaw lock"
            )
    escrow = value.get("escrow_generation")
    if not isinstance(escrow, dict) or set(escrow) != {
        "generation_id",
        "file",
        "manifest_sha256",
    }:
        raise RecoveryError("invalid escrow generation reference")
    if not isinstance(escrow["generation_id"], str) or not ID_RE.fullmatch(
        escrow["generation_id"]
    ):
        raise RecoveryError("invalid escrow generation reference")
    if not re.fullmatch(r"[0-9a-f]{64}", str(escrow["manifest_sha256"])):
        raise RecoveryError("invalid escrow manifest digest")
    if escrow["file"] != "escrow-generation.json":
        raise RecoveryError("invalid escrow manifest filename")
    secrets_manifest = value.get("secrets_manifest")
    if (
        not isinstance(secrets_manifest, dict)
        or secrets_manifest.get("schema") != SECRETS_SCHEMA
        or not re.fullmatch(r"[0-9a-f]{64}", str(secrets_manifest.get("sha256")))
    ):
        raise RecoveryError("invalid secrets manifest reference")
    bootstrap = value.get("bootstrap")
    if bootstrap is not None:
        if (
            not isinstance(bootstrap, dict)
            or set(bootstrap) != {"file", "sha256", "size"}
            or bootstrap.get("file") != "restore-ubuntu.sh"
            or not re.fullmatch(r"[0-9a-f]{64}", str(bootstrap.get("sha256")))
            or type(bootstrap.get("size")) is not int
            or not 0 < bootstrap["size"] <= MAX_KEYS_BYTES
        ):
            raise RecoveryError("invalid Stage-0 bootstrap record")
        bootstrap_path = set_dir / "restore-ubuntu.sh"
        descriptor = _open_regular(bootstrap_path, max_bytes=MAX_KEYS_BYTES)
        try:
            bootstrap_size = os.fstat(descriptor).st_size
        finally:
            os.close(descriptor)
        if (
            bootstrap_size != bootstrap["size"]
            or _sha256_file(bootstrap_path) != bootstrap["sha256"]
        ):
            raise RecoveryError("Stage-0 bootstrap digest/size mismatch")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "keys",
        "secrets",
        "private_state",
    }:
        raise RecoveryError("recovery set artifact inventory is incomplete")
    expected_names = {
        "keys": "keys.json.gpg",
        "secrets": "secrets.tar.gpg",
        "private_state": "private-state.tar.gpg",
    }
    for key, expected_name in expected_names.items():
        record = artifacts[key]
        if not isinstance(record, dict) or set(record) != {"file", "sha256", "size"}:
            raise RecoveryError("invalid recovery artifact record")
        if record["file"] != expected_name:
            raise RecoveryError("unexpected recovery artifact filename")
        if not re.fullmatch(r"[0-9a-f]{64}", str(record["sha256"])):
            raise RecoveryError("invalid recovery artifact digest")
        if type(record["size"]) is not int or not 0 < record["size"] <= MAX_ARCHIVE_BYTES:
            raise RecoveryError("invalid recovery artifact size")
        path = set_dir / expected_name
        descriptor = _open_regular(path, max_bytes=MAX_ARCHIVE_BYTES)
        try:
            actual_size = os.fstat(descriptor).st_size
        finally:
            os.close(descriptor)
        if actual_size != record["size"] or _sha256_file(path) != record["sha256"]:
            raise RecoveryError("recovery artifact digest/size mismatch")
    escrow_path = set_dir / "escrow-generation.json"
    if _sha256_file(escrow_path) != escrow["manifest_sha256"]:
        raise RecoveryError("escrow manifest digest mismatch")
    allowed = {
        "recovery-set.json",
        "escrow-generation.json",
        *expected_names.values(),
        *RECOVERY_SIGNATURE_FILES,
    }
    if bootstrap is not None:
        allowed.add("restore-ubuntu.sh")
    if owner_data is not None:
        owner_name = str(owner_data["file"])
        owner_path = set_dir / owner_name
        descriptor = _open_regular(
            owner_path, max_bytes=MAX_OWNER_DATA_BYTES, secret=True
        )
        try:
            owner_size = os.fstat(descriptor).st_size
        finally:
            os.close(descriptor)
        if (
            owner_size != owner_data["size"]
            or _sha256_file(owner_path, max_bytes=MAX_OWNER_DATA_BYTES)
            != owner_data["sha256"]
        ):
            raise RecoveryError("owner-data archive digest/size mismatch")
        allowed.add(owner_name)
    actual = {entry.name for entry in os.scandir(set_dir)}
    required = {"recovery-set.json", "escrow-generation.json", *expected_names.values()}
    if bootstrap is not None:
        required.add("restore-ubuntu.sh")
    if owner_data is not None:
        required.add(str(owner_data["file"]))
    if not required.issubset(actual) or not actual.issubset(allowed):
        raise RecoveryError("recovery set contains undeclared files")
    present_signatures = actual.intersection(RECOVERY_SIGNATURE_FILES)
    if present_signatures and present_signatures != RECOVERY_SIGNATURE_FILES:
        raise RecoveryError("recovery set has an incomplete detached-signature pair")
    for name in present_signatures:
        descriptor = _open_regular(set_dir / name, max_bytes=MAX_KEYS_BYTES)
        try:
            if os.fstat(descriptor).st_size == 0:
                raise RecoveryError("recovery detached-signature file is empty")
        finally:
            os.close(descriptor)
    return value


def _load_keys(path: Path, set_id: str, component_commit: str) -> dict:
    value = _load_json_regular(path, max_bytes=MAX_KEYS_BYTES, secret=True)
    if set(value) != {"schema", "set_id", "component_commit", "artifacts"}:
        raise RecoveryError("invalid recovery key envelope fields")
    if (
        value.get("schema") != KEYS_SCHEMA
        or value.get("set_id") != set_id
        or value.get("component_commit") != component_commit
    ):
        raise RecoveryError("decrypted key envelope belongs to another recovery set")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "private-state.tar.gpg",
        "secrets.tar.gpg",
    }:
        raise RecoveryError("invalid recovery key envelope")
    for filename, record in artifacts.items():
        if not isinstance(record, dict) or set(record) != {
            "passphrase",
            "plaintext_sha256",
            "plaintext_size",
        }:
            raise RecoveryError("invalid recovery artifact key record")
        passphrase = record["passphrase"]
        if not isinstance(passphrase, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", passphrase):
            raise RecoveryError("invalid wrapped artifact key")
        if not re.fullmatch(r"[0-9a-f]{64}", str(record["plaintext_sha256"])):
            raise RecoveryError("invalid plaintext digest")
        if type(record["plaintext_size"]) is not int or not 0 < record["plaintext_size"] <= MAX_ARCHIVE_BYTES:
            raise RecoveryError("invalid plaintext size")
    return value


def _expected_entry_for_path(manifest: dict, relative: str, group: str) -> dict:
    matches = []
    for entry in manifest["entries"]:
        entry_group = (
            "private-state" if entry["classification"] == "private-state" else "secrets"
        )
        if entry["backup"] and entry_group == group and _entry_matches(entry, relative):
            matches.append(entry)
    if len(matches) != 1:
        raise RecoveryError("archive member is undeclared or ambiguously declared")
    if _excluded(matches[0], relative):
        raise RecoveryError("archive member matches an excluded path")
    return matches[0]


def validate_tar_archive(path: Path | str, manifest: dict, group: str) -> dict[str, int]:
    path = Path(path)
    if group not in {"secrets", "private-state"}:
        raise RecoveryError("invalid recovery archive group")
    descriptor = _open_regular(path, max_bytes=MAX_ARCHIVE_BYTES)
    seen: dict[str, int] = {}
    total = 0
    required_seen: set[str] = set()
    archive_file = None
    try:
        archive_file = os.fdopen(descriptor, "rb")
        descriptor = -1
        archive = tarfile.open(fileobj=archive_file, mode="r:")
    except (tarfile.TarError, OSError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if archive_file is not None:
            archive_file.close()
        raise RecoveryError("invalid recovery tar archive") from exc
    with archive_file, archive:
        count = 0
        for member in archive:
            count += 1
            if count > MAX_ARCHIVE_MEMBERS:
                raise RecoveryError("recovery archive has too many members")
            relative = _safe_member_name(member.name)
            if relative in seen:
                raise RecoveryError("duplicate recovery archive member")
            if not member.isfile() or member.issym() or member.islnk():
                raise RecoveryError("recovery archives may contain only regular files")
            if member.size < 0 or member.size > MAX_SECRET_FILE:
                raise RecoveryError("recovery archive member exceeds its bound")
            total += member.size
            if total > MAX_ARCHIVE_BYTES:
                raise RecoveryError("recovery archive expands beyond its bound")
            entry = _expected_entry_for_path(manifest, relative, group)
            expected_mode = _parse_mode(entry["mode"], label=entry["id"])
            if stat.S_IMODE(member.mode) != expected_mode:
                raise RecoveryError("recovery archive member mode disagrees with manifest")
            seen[relative] = expected_mode
            required_seen.add(entry["id"])
        missing = []
        for entry in manifest["entries"]:
            entry_group = (
                "private-state"
                if entry["classification"] == "private-state"
                else "secrets"
            )
            if entry["backup"] and entry["required"] and entry_group == group:
                if entry["id"] not in required_seen:
                    missing.append(entry["id"])
        if missing:
            raise RecoveryError("required recovery archive entries are missing")
    return seen


def _decrypt_set(
    set_dir: Path,
    public: dict,
    master: bytes,
    work: Path,
    manifest: dict,
) -> tuple[dict[str, Path], dict[str, int]]:
    keys_path = work / "keys.json"
    _gpg(
        set_dir / public["artifacts"]["keys"]["file"],
        keys_path,
        master,
        decrypt=True,
        max_output=MAX_KEYS_BYTES,
    )
    keys = _load_keys(
        keys_path,
        public["set_id"],
        public["components"]["coding-system-rebuild"]["commit"],
    )
    plaintext: dict[str, Path] = {}
    modes: dict[str, int] = {}
    for group, public_key, filename in (
        ("secrets", "secrets", "secrets.tar.gpg"),
        ("private-state", "private_state", "private-state.tar.gpg"),
    ):
        record = keys["artifacts"][filename]
        plain = work / filename.removesuffix(".gpg")
        _gpg(
            set_dir / public["artifacts"][public_key]["file"],
            plain,
            record["passphrase"].encode("ascii"),
            decrypt=True,
            max_output=MAX_ARCHIVE_BYTES,
        )
        if (
            plain.stat().st_size != record["plaintext_size"]
            or _sha256_file(plain) != record["plaintext_sha256"]
        ):
            raise RecoveryError("decrypted recovery artifact digest/size mismatch")
        modes.update(validate_tar_archive(plain, manifest, group))
        plaintext[group] = plain
    return plaintext, modes


def _validate_recovery_bindings(
    set_dir: Path,
    manifest_path: Path,
    escrow_manifest_path: Path,
    *,
    allow_legacy: bool = False,
) -> tuple[dict, dict, dict]:
    public = load_recovery_manifest(set_dir, allow_legacy=allow_legacy)
    manifest, manifest_raw, manifest_digest = _read_secrets_manifest_snapshot(
        manifest_path
    )
    escrow = load_escrow_manifest(escrow_manifest_path)
    if not secrets.compare_digest(
        manifest_digest, public["secrets_manifest"]["sha256"]
    ):
        raise RecoveryError("recovery set was created with another secrets manifest")
    component_commit = public["components"]["coding-system-rebuild"]["commit"]
    _bind_manifest_to_commit(manifest_raw, manifest_digest, component_commit)
    if _sha256_file(escrow_manifest_path) != public["escrow_generation"]["manifest_sha256"]:
        raise RecoveryError("recovery set was created with another escrow manifest")
    if escrow["generation_id"] != public["escrow_generation"]["generation_id"]:
        raise RecoveryError("recovery set references another escrow generation")
    return public, manifest, escrow


def validate_recovery_set(
    set_dir: Path | str,
    manifest_path: Path | str,
    escrow_manifest_path: Path | str,
    share_files: list[Path | str],
    *,
    allow_legacy: bool = False,
) -> dict:
    set_dir = Path(set_dir)
    manifest_path = Path(manifest_path)
    escrow_manifest_path = Path(escrow_manifest_path)
    public, manifest, escrow = _validate_recovery_bindings(
        set_dir,
        manifest_path,
        escrow_manifest_path,
        allow_legacy=allow_legacy,
    )
    master = recover_master_from_share_files(escrow, share_files)
    with secure_temporary_directory(prefix="csr-recovery-validate-") as temporary:
        _decrypt_set(set_dir, public, master, Path(temporary), manifest)
    return public


def authenticated_validate_recovery_set(
    set_dir: Path | str,
    manifest_path: Path | str,
    share_files: list[Path | str],
    *,
    trusted_public_key: Path | str | None = None,
    expected_key_sha256: str = RECOVERY_SIGNING_KEY_SHA256,
    expected_component_commit: str | None = None,
    allow_legacy: bool = False,
) -> dict:
    with authenticated_recovery_snapshot(
        set_dir,
        trusted_public_key=trusted_public_key,
        expected_key_sha256=expected_key_sha256,
        expected_component_commit=expected_component_commit,
        allow_legacy=allow_legacy,
    ) as snapshot:
        return validate_recovery_set(
            snapshot,
            manifest_path,
            snapshot / "escrow-generation.json",
            share_files,
            allow_legacy=allow_legacy,
        )


def _open_dir_component(parent_fd: int, component: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        return os.open(component, flags, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise RecoveryError("unsafe symlink or non-directory restore ancestor") from exc
        raise

def apply_staged_tree(
    stage: Path | str,
    destination: Path | str,
    modes: dict[str, int],
    *,
    replace: bool,
    replace_paths: frozenset[str] = frozenset(),
    _test_crash_at: str | None = None,
) -> None:
    try:
        transactional_apply(
            stage,
            destination,
            modes,
            replace=replace,
            replace_paths=replace_paths,
            _test_crash_at=_test_crash_at,
        )
    except RestoreTransactionError as exc:
        raise RecoveryError(str(exc)) from exc
    except OSError as exc:
        raise RecoveryError("restore transaction filesystem operation failed") from exc


def recover_incomplete_restore(
    destination: Path | str, *, _test_crash_at: str | None = None
) -> None:
    """Rollback an uncommitted restore or clean a committed transaction."""
    try:
        recover_pending_transactions(
            destination, _test_crash_at=_test_crash_at
        )
    except RestoreTransactionError as exc:
        raise RecoveryError(str(exc)) from exc
    except OSError as exc:
        raise RecoveryError("restore transaction filesystem operation failed") from exc


def _extract_regular_members(archive_path: Path, stage: Path, modes: dict[str, int]) -> None:
    with tarfile.open(archive_path, "r:") as archive:
        count = 0
        for member in archive:
            count += 1
            if count > MAX_ARCHIVE_MEMBERS:
                raise RecoveryError("recovery archive has too many members")
            relative = _safe_member_name(member.name)
            if relative not in modes or not member.isfile():
                raise RecoveryError("archive changed after validation")
            source = archive.extractfile(member)
            if source is None:
                raise RecoveryError("cannot read recovery archive member")
            data = source.read(MAX_SECRET_FILE + 1)
            if len(data) != member.size or len(data) > MAX_SECRET_FILE:
                raise RecoveryError("recovery archive member size changed")
            target = stage / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            current = target.parent
            while current != stage:
                info = current.lstat()
                if (
                    current.is_symlink()
                    or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.geteuid()
                ):
                    raise RecoveryError("unsafe staging directory")
                current.chmod(0o700)
                current = current.parent
            _atomic_write(target, data, modes[relative])


def _load_projection_materializer():
    path = REPOSITORY_ROOT / "bin/materialize-secret-projections.py"
    spec = importlib.util.spec_from_file_location(
        "coding_system_projection_transaction", path
    )
    if spec is None or spec.loader is None:
        raise RecoveryError("secret projection materializer is unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise RecoveryError("secret projection materializer is unavailable") from exc
    return module


def _prepare_materialized_restore(
    recovery_stage: Path,
    destination_home: Path,
    recovery_modes: dict[str, int],
    work: Path,
) -> tuple[Path, dict[str, int | None], frozenset[str]]:
    """Preflight every credential mutation in a private virtual HOME."""

    materializer = _load_projection_materializer()
    virtual_home = work / "virtual-home"
    output_stage = work / "transaction-stage"
    virtual_home.mkdir(mode=0o700)
    output_stage.mkdir(mode=0o700)
    try:
        input_modes, mutation_modes = materializer.transaction_file_contract(
            destination_home
        )
        materializer.snapshot_transaction_inputs(
            destination_home, virtual_home, input_modes
        )
        materializer.overlay_transaction_stage(
            virtual_home, recovery_stage, recovery_modes
        )
        materializer.materialize(
            virtual_home,
            migrate_vnu_legacy=True,
            migrate_remote_bridge_legacy=True,
            migrate_aas_legacy=True,
        )
        final_contract = dict(mutation_modes)
        for relative, mode in recovery_modes.items():
            previous = final_contract.get(relative)
            if previous is not None and previous != mode:
                raise RecoveryError("restore and projection modes disagree")
            final_contract[relative] = mode
        final_modes = materializer.export_transaction_files(
            virtual_home, output_stage, final_contract
        )
    except RecoveryError:
        raise
    except Exception as exc:
        # Materializer exceptions can contain parser details derived from
        # secret input. Keep the recovery boundary redaction-safe.
        raise RecoveryError("secret projection transaction preflight failed") from exc
    replace_paths = frozenset(set(mutation_modes) - set(recovery_modes))
    return output_stage, final_modes, replace_paths


def restore_recovery_set(
    set_dir: Path | str,
    manifest_path: Path | str,
    escrow_manifest_path: Path | str,
    share_files: list[Path | str],
    destination_home: Path | str,
    replace: bool = False,
    *,
    allow_legacy: bool = False,
) -> dict:
    set_dir = Path(set_dir)
    manifest_path = Path(manifest_path)
    escrow_manifest_path = Path(escrow_manifest_path)
    public, manifest, escrow = _validate_recovery_bindings(
        set_dir,
        manifest_path,
        escrow_manifest_path,
        allow_legacy=allow_legacy,
    )
    master = recover_master_from_share_files(escrow, share_files)
    with secure_temporary_directory(prefix="csr-recovery-restore-") as temporary:
        work = Path(temporary)
        decrypted, modes = _decrypt_set(set_dir, public, master, work, manifest)
        stage = work / "stage"
        stage.mkdir(mode=0o700)
        for group in ("secrets", "private-state"):
            _extract_regular_members(decrypted[group], stage, modes)
        destination = Path(destination_home)
        transaction_stage, transaction_modes, replace_paths = (
            _prepare_materialized_restore(stage, destination, modes, work)
        )
        apply_staged_tree(
            transaction_stage,
            destination,
            transaction_modes,
            replace=replace,
            replace_paths=replace_paths,
        )
    return public


def authenticated_restore_recovery_set(
    set_dir: Path | str,
    manifest_path: Path | str,
    share_files: list[Path | str],
    destination_home: Path | str,
    replace: bool = False,
    *,
    trusted_public_key: Path | str | None = None,
    expected_key_sha256: str = RECOVERY_SIGNING_KEY_SHA256,
    expected_component_commit: str | None = None,
    allow_legacy: bool = False,
) -> dict:
    with authenticated_recovery_snapshot(
        set_dir,
        trusted_public_key=trusted_public_key,
        expected_key_sha256=expected_key_sha256,
        expected_component_commit=expected_component_commit,
        allow_legacy=allow_legacy,
    ) as snapshot:
        return restore_recovery_set(
            set_dir=snapshot,
            manifest_path=manifest_path,
            escrow_manifest_path=snapshot / "escrow-generation.json",
            share_files=share_files,
            destination_home=destination_home,
            replace=replace,
            allow_legacy=allow_legacy,
        )


def _paths(values: Iterable[str]) -> list[Path]:
    return [Path(value) for value in values]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    manifest = sub.add_parser("manifest-check")
    manifest.add_argument("--manifest", type=Path, required=True)
    discover = sub.add_parser("discover")
    discover.add_argument("--manifest", type=Path, required=True)
    discover.add_argument("--home", type=Path, required=True)

    create_escrow = sub.add_parser("create-escrow")
    create_escrow.add_argument("--output-dir", type=Path, required=True)
    create_escrow.add_argument("--master-key-out", type=Path, required=True)
    validate_escrow = sub.add_parser("validate-escrow")
    validate_escrow.add_argument("--manifest", type=Path, required=True)
    validate_escrow.add_argument("--share-dir", type=Path, required=True)
    recover = sub.add_parser("recover-escrow")
    recover.add_argument("--manifest", type=Path, required=True)
    recover.add_argument("--share-file", action="append", required=True)
    recover.add_argument("--master-key-out", type=Path, required=True)
    legacy_recover = sub.add_parser("recover-legacy")
    legacy_recover.add_argument("--share-file", action="append", required=True)
    legacy_recover.add_argument("--output", type=Path, required=True)
    legacy_signing = sub.add_parser("stage-legacy-signing-authority")
    legacy_signing.add_argument("--source-key", type=Path, required=True)
    legacy_signing.add_argument("--destination-home", type=Path, required=True)
    legacy_signing.add_argument("--trusted-public-key", type=Path, required=True)

    create = sub.add_parser("create-set")
    create.add_argument("--manifest", type=Path, required=True)
    create.add_argument("--source-home", type=Path, required=True)
    create.add_argument("--output-dir", type=Path, required=True)
    create.add_argument("--master-key-file", type=Path, required=True)
    create.add_argument("--escrow-manifest", type=Path, required=True)
    create.add_argument("--component-commit", required=True)
    create.add_argument("--set-id")
    create.add_argument("--owner-data-archive", type=Path)
    create.add_argument("--expected-owner-source-state-hmac")
    create.add_argument(
        "--owner-data-capture-policy", choices=sorted(OWNER_DATA_CAPTURE_POLICIES)
    )
    owner_source = sub.add_parser("inspect-owner-source")
    owner_source.add_argument("--source-home", type=Path, required=True)
    owner_source.add_argument("--master-key-file", type=Path, required=True)
    extracted_owner = sub.add_parser("inspect-owner-extracted-source")
    extracted_owner.add_argument("--extraction-root", type=Path, required=True)
    extracted_owner.add_argument("--master-key-file", type=Path, required=True)
    owner_record = sub.add_parser("inspect-set-owner")
    owner_record.add_argument("--set-dir", type=Path, required=True)
    authenticate = sub.add_parser("authenticate-signature")
    authenticate.add_argument("--set-dir", type=Path, required=True)
    authenticate.add_argument("--expected-component-commit")
    snapshot = sub.add_parser("snapshot-set")
    snapshot.add_argument("--set-dir", type=Path, required=True)
    snapshot.add_argument("--output-dir", type=Path, required=True)
    snapshot.add_argument("--allow-legacy-recovery-set", action="store_true")
    check_snapshot = sub.add_parser("check-snapshot")
    check_snapshot.add_argument("--snapshot-dir", type=Path, required=True)
    check_snapshot.add_argument("--allow-legacy-recovery-set", action="store_true")
    discard = sub.add_parser("remove-snapshot")
    discard.add_argument("--snapshot-dir", type=Path, required=True)
    recover_transaction = sub.add_parser("recover-transaction")
    recover_transaction.add_argument("--destination-home", type=Path, required=True)
    for command in ("validate-set", "restore"):
        item = sub.add_parser(command)
        item.add_argument("--set-dir", type=Path, required=True)
        item.add_argument("--manifest", type=Path, required=True)
        item.add_argument("--share-file", action="append", required=True)
        item.add_argument("--expected-component-commit")
        item.add_argument("--allow-legacy-recovery-set", action="store_true")
        if command == "restore":
            item.add_argument("--destination-home", type=Path, required=True)
            item.add_argument("--replace", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "manifest-check":
            load_secrets_manifest(arguments.manifest)
            print("secrets manifest: valid v2 contract")
        elif arguments.command == "discover":
            manifest = load_secrets_manifest(arguments.manifest)
            unclassified = discover_unclassified(arguments.home, manifest)
            if unclassified:
                raise RecoveryError(
                    "unclassified credential candidates: " + ", ".join(unclassified[:20])
                )
            print("credential discovery: all candidates classified")
        elif arguments.command == "create-escrow":
            path = create_escrow_generation(arguments.output_dir, arguments.master_key_out)
            print(f"escrow generation created: {path}")
        elif arguments.command == "validate-escrow":
            validate_all_share_pairs(arguments.manifest, arguments.share_dir)
            print("escrow generation: all six 2-of-4 pairs valid")
        elif arguments.command == "recover-escrow":
            recover_master_to_file(
                arguments.manifest,
                _paths(arguments.share_file),
                arguments.master_key_out,
            )
            print(f"escrow master written to protected file: {arguments.master_key_out}")
        elif arguments.command == "recover-legacy":
            recover_legacy_shares_to_file(
                _paths(arguments.share_file), arguments.output
            )
            print(f"legacy passphrase written to protected file: {arguments.output}")
        elif arguments.command == "stage-legacy-signing-authority":
            stage_legacy_signing_authority(
                arguments.source_key,
                arguments.destination_home,
                arguments.trusted_public_key,
            )
            print("legacy destination recovery signing authority: staged and pinned")
        elif arguments.command == "create-set":
            marker = create_recovery_set(
                arguments.manifest,
                arguments.source_home,
                arguments.output_dir,
                arguments.master_key_file,
                arguments.escrow_manifest,
                arguments.component_commit,
                arguments.set_id,
                arguments.owner_data_archive,
                arguments.expected_owner_source_state_hmac,
                arguments.owner_data_capture_policy,
            )
            print(f"immutable recovery set created: {marker.parent}")
        elif arguments.command == "inspect-owner-source":
            configured, state_hmac = openclaw_private_source_state(
                arguments.source_home,
                _read_secret_file(arguments.master_key_file),
            )
            print(
                json.dumps(
                    {"configured": configured, "source_state_hmac_sha256": state_hmac},
                    sort_keys=True,
                )
            )
        elif arguments.command == "inspect-owner-extracted-source":
            configured, state_hmac = openclaw_extracted_source_state(
                arguments.extraction_root,
                _read_secret_file(arguments.master_key_file),
            )
            print(
                json.dumps(
                    {"configured": configured, "source_state_hmac_sha256": state_hmac},
                    sort_keys=True,
                )
            )
        elif arguments.command == "inspect-set-owner":
            public = load_recovery_manifest(arguments.set_dir)
            print(
                json.dumps(
                    {"owner_data": public["owner_data"]},
                    sort_keys=True,
                )
            )
        elif arguments.command == "authenticate-signature":
            evidence = verify_recovery_signature(
                arguments.set_dir,
                expected_component_commit=arguments.expected_component_commit,
            )
            print(
                "recovery-set signature: valid "
                f"(SHA256:{evidence['signing_key_sha256']})"
            )
        elif arguments.command == "snapshot-set":
            snapshot_recovery_set(
                arguments.set_dir,
                arguments.output_dir,
                allow_legacy=arguments.allow_legacy_recovery_set,
            )
            print(f"recovery set snapshot created: {arguments.output_dir}")
        elif arguments.command == "check-snapshot":
            validate_private_recovery_snapshot(
                arguments.snapshot_dir,
                allow_legacy=arguments.allow_legacy_recovery_set,
            )
            print("recovery set snapshot protection: valid")
        elif arguments.command == "remove-snapshot":
            _discard_recovery_snapshot(arguments.snapshot_dir)
            print("recovery set snapshot removed")
        elif arguments.command == "recover-transaction":
            recover_incomplete_restore(arguments.destination_home)
            print("restore transaction state recovered")
        elif arguments.command == "validate-set":
            public = authenticated_validate_recovery_set(
                arguments.set_dir,
                arguments.manifest,
                _paths(arguments.share_file),
                expected_component_commit=arguments.expected_component_commit,
                allow_legacy=arguments.allow_legacy_recovery_set,
            )
            print(f"recovery set valid: {public['set_id']}")
        elif arguments.command == "restore":
            public = authenticated_restore_recovery_set(
                arguments.set_dir,
                arguments.manifest,
                _paths(arguments.share_file),
                arguments.destination_home,
                replace=arguments.replace,
                expected_component_commit=arguments.expected_component_commit,
                allow_legacy=arguments.allow_legacy_recovery_set,
            )
            print(f"recovery set restored: {public['set_id']}")
        return 0
    except (RecoveryError, SecureTempError) as exc:
        print(f"recovery: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
