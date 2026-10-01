#!/usr/bin/env python3
"""Verify the pinned ai-agents-skills target-state contract without secrets."""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Any

import yaml


SCHEMA = "ai-agents-skills.target-state.v3"
MCP_REPORT_SCHEMA = "coding-system.mcp-verification.v1"
AAS_RUNTIME_SMOKE_SCHEMA = "ai-agents-skills.installed-runtime-smoke.v1"
STATUS_PRIORITY = {
    "PASS": 0,
    "NOT_APPLICABLE": 0,
    "NOT_CONFIGURED": 1,
    "CREDIT_BLOCKED": 1,
    "REAUTH_REQUIRED": 2,
    "AUTH_INVALID": 3,
    "TECHNICAL_FAIL": 4,
}
RUNTIME_PROBES: dict[str, tuple[list[str], list[str]]] = {
    "python-runtime": (["python3"], ["--version"]),
    "git-cli": (["git"], ["--version"]),
    "node-runtime": (["node"], ["--version"]),
    "github-cli": (["gh"], ["--version"]),
    "sagemath": (["sage"], ["--version"]),
}
SUPPORTED_READINESS = {
    "cli-version",
    "managed-skill-visibility",
    "runtime-smoke",
    "auth-structural",
    "auth-native",
    "credential-projection",
    "mcp-handshake",
    "scheduler-canary",
    "agent-auth-closure",
}
MAX_CREDENTIAL_BYTES = 16 * 1024 * 1024
MAX_GITHUB_HOSTS_BYTES = 1024 * 1024
MAX_STRICT_ENV_BYTES = 65_536
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
STRICT_ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
OPENCLAW_AGENT_STORE_GLOB = ".openclaw/agents/*/agent/openclaw-agent.sqlite"
REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_AGENT_AUTH_EVIDENCE_AGE_SECONDS = 300
AAS_INSTALL_STATE_SCHEMA_VERSION = 2
AAS_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
AAS_SKILL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
OPENCLAW_MANIFEST_ID_RE = re.compile(r"^target_manifest_[A-Za-z0-9_.-]+$")
OPENCLAW_ACTION_ID_RE = re.compile(r"^target_action_[A-Za-z0-9_.-]+$")
FILE_DELIVERY_QUEUE_CONTRACT: dict[str, Any] = {
    "kind": "strict-json-file",
    "path": ".config/ai-agents-skills/file-delivery-queue.json",
    "pointer_env": "AAS_FILE_DELIVERY_SECRETS_FILE",
    "schema_version": 1,
    "exact_keys": [
        "version",
        "hmac_key_hex",
        "allowed",
        "max_job_age_seconds",
        "max_media_bytes",
        "replay_ledger_dir",
        "replay_retention_seconds",
        "max_replay_entries",
    ],
    "restore_policy": "authority",
    "generation_policy": "explicit-allowlist-required",
    "replay_ledger_field": {
        "exact_value": "aas-host-state:file-delivery-replay",
        "resolution": (
            "authority-home/.local/state/ai-agents-skills/file-delivery-replay"
        ),
        "legacy_migration": (
            "rewrite-old-default-only-preserve-other-fields-reject-conflicts"
        ),
    },
    "replay_ledger": {
        "default_path": ".local/state/ai-agents-skills/file-delivery-replay",
        "must_be_outside_agent_workspace": True,
        "mode": "0700",
        "restore_policy": "state-continuity",
        "backup_required": True,
        "retention_contract": (
            "used_at+replay_retention_seconds-strictly-before-now"
        ),
        "retention_minimum": "max_job_age_seconds+60",
        "entry_bound_field": "max_replay_entries",
    },
    "distinct_from": ".openclaw/workspace/.config/file-delivery/secrets.json",
    "readiness_when_absent": "NOT_CONFIGURED",
}


class ContractError(RuntimeError):
    pass


def load_manifest(path: Path) -> dict[str, Any]:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ContractError("target-state manifest contains duplicate fields")
            value[key] = item
        return value

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs
        )
    except ContractError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read target-state manifest: {path}") from exc
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ContractError("target-state manifest is not schema v3")
    if (
        value.get("schema_version") != 3
        or not isinstance(value.get("targets"), dict)
        or not value.get("targets")
        or not isinstance(value.get("runtime_credential_authorities"), dict)
        or (
            "software_integrations" in value
            and not isinstance(value.get("software_integrations"), dict)
        )
    ):
        raise ContractError("target-state manifest shape is invalid")
    validate_runtime_credential_authorities(value["runtime_credential_authorities"])
    return value


def validate_runtime_credential_authorities(value: dict[str, Any]) -> None:
    """Require the exact pinned host-queue metadata contract, without reading it."""

    if set(value) != {"file-delivery-queue"}:
        raise ContractError("runtime credential authority inventory is invalid")
    queue = value.get("file-delivery-queue")
    if queue != FILE_DELIVERY_QUEUE_CONTRACT:
        raise ContractError("file-delivery queue target-state contract is invalid")
    for raw in (
        queue["path"],
        queue["replay_ledger"]["default_path"],
        queue["distinct_from"],
    ):
        safe_relative(raw)


def runtime_credential_authority_report(value: dict[str, Any]) -> dict[str, Any]:
    """Emit metadata-only evidence that the pinned host authority was declared."""

    queue = value["file-delivery-queue"]
    return {
        "file-delivery-queue": {
            "status": "PASS",
            "kind": queue["kind"],
            "path": queue["path"],
            "pointer_env": queue["pointer_env"],
            "schema_version": queue["schema_version"],
            "exact_keys": list(queue["exact_keys"]),
            "restore_policy": queue["restore_policy"],
            "generation_policy": queue["generation_policy"],
            "readiness_when_absent": queue["readiness_when_absent"],
            "distinct_from": queue["distinct_from"],
            "replay_ledger_field": dict(queue["replay_ledger_field"]),
            "replay_ledger": dict(queue["replay_ledger"]),
        }
    }


def safe_relative(raw: str) -> PurePosixPath:
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts or raw.startswith("~"):
        raise ContractError(f"unsafe target-state path: {raw!r}")
    return path


def worst_status(statuses: list[str], default: str = "PASS") -> str:
    status = default
    for candidate in statuses:
        if candidate not in STATUS_PRIORITY:
            raise ContractError(f"unknown target-state status: {candidate!r}")
        if STATUS_PRIORITY[candidate] > STATUS_PRIORITY[status]:
            status = candidate
    return status


def path_metadata(path: Path, expected_kind: str) -> dict[str, Any]:
    result: dict[str, Any] = {"present": False, "secure_mode": False, "nonempty": False}
    try:
        info = path.lstat()
    except FileNotFoundError:
        return result
    result["present"] = True
    result["mode"] = f"{stat.S_IMODE(info.st_mode):04o}"
    result["symlink"] = stat.S_ISLNK(info.st_mode)
    if result["symlink"]:
        return result
    if expected_kind in {"directory", "native-store"}:
        result["expected_type"] = stat.S_ISDIR(info.st_mode)
        if result["expected_type"]:
            try:
                result["nonempty"] = next(path.iterdir(), None) is not None
            except OSError:
                result["nonempty"] = False
    else:
        result["expected_type"] = stat.S_ISREG(info.st_mode)
        result["nonempty"] = bool(result["expected_type"] and 0 < info.st_size <= MAX_CREDENTIAL_BYTES)
        result["size_within_bound"] = bool(result["expected_type"] and info.st_size <= MAX_CREDENTIAL_BYTES)
    result["secure_mode"] = bool(result["expected_type"] and not (stat.S_IMODE(info.st_mode) & 0o077))
    return result


def _github_hosts_payload_is_valid(payload: bytes) -> bool:
    """Validate gh's YAML shape without constructing alias-expanded objects."""

    try:
        text = payload.decode("utf-8")
        document = yaml.compose(text, Loader=yaml.SafeLoader)
    except (UnicodeDecodeError, yaml.YAMLError):
        return False
    if document is None or document.tag != "tag:yaml.org,2002:map":
        return False
    hosts: set[str] = set()
    for host_node, profile_node in document.value:
        if (
            host_node.tag != "tag:yaml.org,2002:str"
            or not isinstance(host_node.value, str)
            or not host_node.value.strip()
            or host_node.value in hosts
            or profile_node.tag != "tag:yaml.org,2002:map"
        ):
            return False
        hosts.add(host_node.value)
        profile_keys: set[str] = set()
        has_token = False
        for key_node, value_node in profile_node.value:
            if (
                key_node.tag != "tag:yaml.org,2002:str"
                or not isinstance(key_node.value, str)
                or key_node.value in profile_keys
            ):
                return False
            profile_keys.add(key_node.value)
            if key_node.value == "oauth_token":
                if (
                    value_node.tag != "tag:yaml.org,2002:str"
                    or not isinstance(value_node.value, str)
                    or not value_node.value.strip()
                ):
                    return False
                has_token = True
        if not has_token:
            return False
    return bool(hosts)


def structurally_valid_credential_file(
    path: Path, *, structure: str | None = None
) -> bool:
    """Inspect shape only; never return or report credential content."""
    if structure not in {None, "github-hosts-v1"}:
        return False
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor = _open_directory_nofollow(path.parent)
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_descriptor,
        )
    except OSError:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        return False
    try:
        info = os.fstat(descriptor)
        path_info = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        max_bytes = (
            MAX_GITHUB_HOSTS_BYTES
            if structure == "github-hosts-v1"
            else MAX_CREDENTIAL_BYTES
        )
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > max_bytes
            or stat.S_IMODE(info.st_mode) & 0o077
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
        ):
            return False
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 65536))
            if not block:
                return False
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            return False
        after = os.fstat(descriptor)
        after_path = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        signature = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_gid,
            stat.S_IFMT(value.st_mode),
            stat.S_IMODE(value.st_mode),
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if signature(info) != signature(after) or signature(after) != signature(after_path):
            return False
    except OSError:
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    payload = b"".join(chunks)
    if structure == "github-hosts-v1":
        return _github_hosts_payload_is_valid(payload)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text.strip():
        return False
    try:
        if path.suffix == ".json":
            value = json.loads(text)
            return isinstance(value, (dict, list)) and bool(value)
        if path.suffix == ".toml":
            value = tomllib.loads(text)
            return isinstance(value, dict) and bool(value)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError):
        return False
    return True


def path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root)
        return True
    except (OSError, ValueError):
        return False


def _open_directory_nofollow(path: Path) -> int:
    """Open an absolute directory chain without traversing symlinks."""

    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute.anchor or os.sep, flags)
    try:
        for component in absolute.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _safe_regular_metadata(path: Path, root: Path) -> dict[str, Any]:
    """Inspect a protected regular file without following any path symlink."""

    absolute = Path(os.path.abspath(path))
    try:
        absolute.relative_to(root)
    except ValueError:
        return {"valid": False}
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor = _open_directory_nofollow(absolute.parent)
        path_info = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or path_info.st_uid != os.geteuid()
            or path_info.st_nlink != 1
            or path_info.st_size <= 0
            or path_info.st_size > MAX_CREDENTIAL_BYTES
            or stat.S_IMODE(path_info.st_mode) & 0o077
        ):
            return {"valid": False}
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        if (
            (path_info.st_dev, path_info.st_ino) != (opened.st_dev, opened.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or opened.st_size <= 0
            or opened.st_size > MAX_CREDENTIAL_BYTES
            or stat.S_IMODE(opened.st_mode) & 0o077
        ):
            return {"valid": False}
        return {
            "valid": True,
            "mode": f"{stat.S_IMODE(opened.st_mode):04o}",
            "size": opened.st_size,
            "device": opened.st_dev,
            "inode": opened.st_ino,
            "mtimeNs": opened.st_mtime_ns,
            "ctimeNs": opened.st_ctime_ns,
        }
    except OSError:
        return {"valid": False}
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _agent_auth_store_matches(
    root: Path, raw: str
) -> tuple[dict[str, dict[str, Any]], bool]:
    """Expand the one-segment agent DB glob without following symlinked directories."""

    relative = safe_relative(raw)
    parts = relative.parts
    if parts.count("*") != 1 or any(
        any(character in part for character in "*?[]") for part in parts if part != "*"
    ):
        raise ContractError("agent-auth authority must contain one path-segment wildcard")
    wildcard_index = parts.index("*")
    if wildcard_index == 0 or wildcard_index == len(parts) - 1:
        raise ContractError("agent-auth authority wildcard placement is invalid")
    parent = root.joinpath(*parts[:wildcard_index])
    try:
        parent_descriptor = _open_directory_nofollow(parent)
    except FileNotFoundError:
        return {}, False
    except OSError:
        return {}, True
    try:
        names = os.listdir(parent_descriptor)
    except OSError:
        os.close(parent_descriptor)
        return {}, True
    os.close(parent_descriptor)

    matched: dict[str, dict[str, Any]] = {}
    unsafe = False
    for name in names:
        candidate_root = parent / name
        candidate = candidate_root.joinpath(*parts[wildcard_index + 1 :])
        try:
            root_info = candidate_root.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(root_info.st_mode):
            unsafe = True
            continue
        if not stat.S_ISDIR(root_info.st_mode):
            continue
        if not os.path.lexists(candidate):
            continue
        if AGENT_ID_RE.fullmatch(name) is None:
            unsafe = True
            continue
        metadata = _safe_regular_metadata(candidate, root)
        if not metadata.get("valid"):
            unsafe = True
            continue
        matched[name] = metadata
    return matched, unsafe


def strict_env_file_keys(path: Path) -> set[str]:
    """Return key names using the AAS launcher's exact protected-file admission rules."""

    absolute = Path(os.path.abspath(path))
    parent_descriptor: int | None = None
    try:
        parent_descriptor = _open_directory_nofollow(absolute.parent)
        path_info = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or path_info.st_nlink != 1
            or path_info.st_size > MAX_STRICT_ENV_BYTES
        ):
            raise ContractError("strict env authority metadata is unsafe")
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size > MAX_STRICT_ENV_BYTES
            or (path_info.st_dev, path_info.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ContractError("strict env authority metadata is unsafe")
        chunks: list[bytes] = []
        remaining = MAX_STRICT_ENV_BYTES + 1
        while remaining > 0:
            block = os.read(descriptor, min(remaining, 65_536))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) > MAX_STRICT_ENV_BYTES:
            raise ContractError("strict env authority exceeded its admitted size")
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ContractError("strict env authority changed while reading")
    except OSError as exc:
        raise ContractError("strict env authority cannot be opened safely") from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("strict env authority is not UTF-8") from exc
    keys: set[str] = set()
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if raw != raw.strip() or "=" not in raw:
            raise ContractError(
                f"strict env authority has invalid assignment at line {line_number}"
            )
        key, value = raw.split("=", 1)
        if (
            STRICT_ENV_KEY_RE.fullmatch(key) is None
            or key in keys
            or not value
            or value != value.strip()
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise ContractError(
                f"strict env authority has invalid assignment at line {line_number}"
            )
        keys.add(key)
    return keys


def credential_observations(root: Path, entries: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    observations: list[dict[str, Any]] = []
    statuses: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ContractError("credential authority must be an object")
        kind = str(entry.get("kind", ""))
        raw = str(entry.get("path", ""))
        policy = str(entry.get("restore_policy", ""))
        if not policy:
            raise ContractError("credential authority restore policy is missing")
        observation: dict[str, Any] = {"kind": kind, "path": raw, "restore_policy": policy}
        if kind == "environment":
            if not raw or "/" in raw or "=" in raw:
                raise ContractError(f"unsafe environment authority name: {raw!r}")
            observation["present"] = bool(os.environ.get(raw, "").strip())
            observation["status"] = "PASS" if observation["present"] else "NOT_CONFIGURED"
        elif kind == "strict-env-file":
            relative = safe_relative(raw)
            authority_path = root / Path(*relative.parts)
            selected_keys = entry.get("keys")
            allowed_keys = entry.get("allowed_keys")
            if (
                not isinstance(selected_keys, list)
                or not selected_keys
                or not all(
                    isinstance(key, str)
                    and STRICT_ENV_KEY_RE.fullmatch(key) is not None
                    for key in selected_keys
                )
                or len(selected_keys) != len(set(selected_keys))
                or not isinstance(allowed_keys, list)
                or not allowed_keys
                or not all(
                    isinstance(key, str)
                    and STRICT_ENV_KEY_RE.fullmatch(key) is not None
                    for key in allowed_keys
                )
                or len(allowed_keys) != len(set(allowed_keys))
                or not set(selected_keys).issubset(set(allowed_keys))
            ):
                raise ContractError("strict env authority keys are invalid")
            metadata = path_metadata(authority_path, "file")
            observation.update(metadata)
            observation["selected_keys"] = list(selected_keys)
            if not metadata["present"]:
                observation["status"] = "NOT_CONFIGURED"
            elif (
                not path_is_within(authority_path, root)
                or metadata.get("symlink")
                or not metadata.get("expected_type")
            ):
                observation["status"] = "TECHNICAL_FAIL"
            else:
                try:
                    available_keys = strict_env_file_keys(authority_path)
                except ContractError:
                    observation["status"] = "TECHNICAL_FAIL"
                else:
                    if not available_keys.issubset(set(allowed_keys)):
                        observation["structurally_valid"] = False
                        observation["status"] = "TECHNICAL_FAIL"
                    else:
                        matched_keys = [key for key in selected_keys if key in available_keys]
                        observation["matched_keys"] = matched_keys
                        observation["structurally_valid"] = True
                        observation["status"] = "PASS" if matched_keys else "NOT_CONFIGURED"
        elif kind == "glob":
            evidence = entry.get("evidence")
            if evidence is not None and evidence != "agent-auth-closure":
                raise ContractError(f"unsupported credential authority evidence: {evidence!r}")
            if evidence == "agent-auth-closure":
                match_records, unsafe = _agent_auth_store_matches(root, raw)
                observation["evidence"] = evidence
                observation["matches"] = len(match_records)
                observation["present"] = bool(match_records)
                observation["secure_mode"] = bool(match_records) and not unsafe
                observation["structurally_valid"] = bool(match_records) and not unsafe
                if unsafe:
                    observation["status"] = "TECHNICAL_FAIL"
                else:
                    observation["status"] = "PASS" if match_records else "NOT_CONFIGURED"
            else:
                relative = safe_relative(raw)
                matches = sorted(Path(item) for item in glob.glob(str(root / str(relative))))
                metadata = [path_metadata(item, "file") for item in matches]
                structurally_valid = [
                    bool(
                        path_is_within(path, root)
                        and item["secure_mode"]
                        and item["nonempty"]
                        and structurally_valid_credential_file(path)
                    )
                    for item, path in zip(metadata, matches, strict=True)
                ]
                observation["matches"] = len(matches)
                observation["present"] = bool(matches)
                observation["secure_mode"] = bool(metadata) and all(item["secure_mode"] for item in metadata)
                observation["structurally_valid"] = bool(structurally_valid) and all(structurally_valid)
                if matches and not observation["structurally_valid"]:
                    observation["status"] = "TECHNICAL_FAIL"
                else:
                    observation["status"] = "PASS" if matches else "NOT_CONFIGURED"
        elif kind in {"file", "directory", "native-store"}:
            relative = safe_relative(raw)
            authority_path = root / Path(*relative.parts)
            metadata = path_metadata(authority_path, kind)
            observation.update(metadata)
            if metadata["present"] and not path_is_within(authority_path, root):
                observation["status"] = "TECHNICAL_FAIL"
            elif metadata["present"] and (metadata.get("symlink") or not metadata.get("expected_type")):
                observation["status"] = "TECHNICAL_FAIL"
            elif metadata["present"] and kind != "native-store" and not metadata["secure_mode"]:
                observation["status"] = "TECHNICAL_FAIL"
            elif kind == "file" and metadata["present"]:
                observation["structurally_valid"] = structurally_valid_credential_file(
                    authority_path, structure=entry.get("structure")
                )
                observation["status"] = "PASS" if observation["structurally_valid"] else "TECHNICAL_FAIL"
            elif kind == "directory" and metadata["present"]:
                observation["status"] = "PASS" if metadata["nonempty"] else "NOT_CONFIGURED"
            elif kind == "native-store":
                observation["status"] = "REAUTH_REQUIRED"
            elif policy in {"portable-session", "reauth-if-nonportable"}:
                observation["status"] = "REAUTH_REQUIRED"
            else:
                observation["status"] = "NOT_CONFIGURED"
        else:
            raise ContractError(f"unsupported credential authority kind: {kind!r}")
        observations.append(observation)
        statuses.append(str(observation["status"]))
    if not statuses:
        return "NOT_CONFIGURED", observations
    if "TECHNICAL_FAIL" in statuses:
        return "TECHNICAL_FAIL", observations
    if "PASS" in statuses:
        return "PASS", observations
    return worst_status(statuses, "NOT_CONFIGURED"), observations


def command_probe(candidates: list[str], version_argv: list[str], path: str) -> dict[str, Any]:
    command = next((located for item in candidates if (located := shutil.which(item, path=path))), None)
    if command is None:
        return {"status": "TECHNICAL_FAIL", "reason": "cli-missing", "candidates": candidates}
    try:
        completed = subprocess.run(
            [command, *version_argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
            env={**os.environ, "PATH": path},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "TECHNICAL_FAIL", "reason": type(exc).__name__}
    first_line = completed.stdout.splitlines()[0][:240] if completed.stdout.splitlines() else ""
    return {
        "status": "PASS" if completed.returncode == 0 else "TECHNICAL_FAIL",
        "command": command,
        "returncode": completed.returncode,
        "version": first_line,
    }


def credential_projection_observation(
    command: str | None,
    root: Path,
    path: str,
    auth_status: str,
    contract: object,
    authority_contracts: object,
) -> dict[str, Any]:
    if not isinstance(contract, dict):
        return {"status": "TECHNICAL_FAIL", "reason": "projection-contract-missing"}
    launcher_raw = contract.get("launcher")
    launcher_source_raw = contract.get("launcher_source")
    closure_loader_raw = contract.get("closure_loader")
    authority_raw = contract.get("authority")
    pointer_env = contract.get("pointer_env")
    argv = contract.get("argv")
    if (
        not isinstance(launcher_raw, str)
        or not isinstance(launcher_source_raw, str)
        or not isinstance(closure_loader_raw, str)
        or not isinstance(authority_raw, str)
        or not isinstance(pointer_env, str)
        or STRICT_ENV_KEY_RE.fullmatch(pointer_env) is None
        or not isinstance(argv, list)
        or not all(isinstance(item, str) and item for item in argv)
        or not isinstance(authority_contracts, list)
    ):
        return {"status": "TECHNICAL_FAIL", "reason": "projection-contract-invalid"}
    launcher = root / Path(*safe_relative(launcher_raw).parts)
    authority = root / Path(*safe_relative(authority_raw).parts)
    closure_loader_link = root / Path(*safe_relative(closure_loader_raw).parts)
    launcher_source = REPO_ROOT / Path(*safe_relative(launcher_source_raw).parts)
    try:
        info = launcher.lstat()
    except OSError:
        return {"status": "TECHNICAL_FAIL", "reason": "projection-launcher-missing"}
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o755
        or not path_is_within(launcher, root)
    ):
        return {"status": "TECHNICAL_FAIL", "reason": "projection-launcher-unsafe"}
    try:
        source_info = launcher_source.lstat()
        closure_loader = closure_loader_link.resolve(strict=True)
        closure_info = closure_loader.lstat()
        closure_relative = closure_loader.relative_to(
            root / ".local/share/coding-system/npm-closures"
        )
    except (OSError, ValueError):
        return {"status": "TECHNICAL_FAIL", "reason": "projection-launcher-source-invalid"}
    if (
        stat.S_ISLNK(source_info.st_mode)
        or not stat.S_ISREG(source_info.st_mode)
        or not path_is_within(launcher_source, REPO_ROOT)
        or stat.S_ISLNK(closure_info.st_mode)
        or not stat.S_ISREG(closure_info.st_mode)
        or len(closure_relative.parts) < 2
        or re.fullmatch(
            r"sha256-(?:amd64|arm64)-[0-9a-f]{64}-[0-9a-f]{64}", closure_relative.parts[0]
        ) is None
    ):
        return {"status": "TECHNICAL_FAIL", "reason": "projection-launcher-source-invalid"}
    try:
        expected_launcher = (
            launcher_source.read_text(encoding="utf-8")
            .replace("{{ HOME }}", str(root))
            .replace("{{ COPILOT_LOADER }}", str(closure_loader))
        )
        actual_launcher = launcher.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return {"status": "TECHNICAL_FAIL", "reason": "projection-launcher-unreadable"}
    if (
        "{{ HOME }}" in expected_launcher
        or "{{ COPILOT_LOADER }}" in expected_launcher
        or actual_launcher != expected_launcher
    ):
        return {"status": "TECHNICAL_FAIL", "reason": "projection-launcher-tampered"}
    if not command:
        return {"status": "TECHNICAL_FAIL", "reason": "projection-launcher-missing"}
    try:
        selected_matches = os.path.samefile(command, launcher)
    except OSError:
        selected_matches = False
    if not selected_matches:
        return {"status": "TECHNICAL_FAIL", "reason": "projection-launcher-not-selected"}
    if auth_status != "PASS":
        return {"status": auth_status, "reason": "credential-authority-not-ready"}
    matching_authorities = [
        entry
        for entry in authority_contracts
        if isinstance(entry, dict)
        and entry.get("kind") == "strict-env-file"
        and entry.get("path") == authority_raw
    ]
    if len(matching_authorities) != 1:
        return {"status": "TECHNICAL_FAIL", "reason": "projection-authority-ambiguous"}
    allowed_keys = matching_authorities[0].get("allowed_keys")
    if not isinstance(allowed_keys, list) or not all(
        isinstance(key, str) and STRICT_ENV_KEY_RE.fullmatch(key) is not None
        for key in allowed_keys
    ):
        return {"status": "TECHNICAL_FAIL", "reason": "projection-authority-invalid"}
    probe_env = os.environ.copy()
    for key in allowed_keys:
        probe_env.pop(key, None)
    probe_env.pop(pointer_env, None)
    probe_env[pointer_env] = str(authority)
    probe_env["PATH"] = path
    try:
        completed = subprocess.run(
            [str(launcher), *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
            env=probe_env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "TECHNICAL_FAIL", "reason": type(exc).__name__}
    passed = (
        completed.returncode == 0
        and completed.stdout.strip() == "PASS lane=provider"
    )
    return {
        "status": "PASS" if passed else "TECHNICAL_FAIL",
        "reason": "verified" if passed else "credential-projection-probe-failed",
        "returncode": completed.returncode,
    }


def runtime_observations(requirements: list[str], path: str) -> tuple[str, list[dict[str, Any]]]:
    observations = []
    for requirement in requirements:
        if requirement not in RUNTIME_PROBES:
            raise ContractError(f"unsupported runtime requirement: {requirement!r}")
        candidates, argv = RUNTIME_PROBES[requirement]
        probe = command_probe(candidates, argv, path)
        observations.append({"requirement": requirement, **probe})
    return worst_status([item["status"] for item in observations]), observations


def _load_owner_private_json(path: Path, root: Path, label: str) -> dict[str, Any]:
    """Read an installer receipt through one stable, owner-private descriptor."""

    absolute = Path(os.path.abspath(path))
    try:
        absolute.relative_to(root)
    except ValueError as exc:
        raise ContractError(f"{label} is outside the restored home") from exc
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor = _open_directory_nofollow(absolute.parent)
        path_info = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or path_info.st_uid != os.geteuid()
            or path_info.st_nlink != 1
            or stat.S_IMODE(path_info.st_mode) != 0o600
            or path_info.st_size <= 0
            or path_info.st_size > MAX_EVIDENCE_BYTES
        ):
            raise ContractError(f"{label} metadata is unsafe")
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        if (
            (path_info.st_dev, path_info.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > MAX_EVIDENCE_BYTES
        ):
            raise ContractError(f"{label} metadata is unsafe")
        payload = bytearray()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 65_536))
            if not block:
                raise ContractError(f"{label} was truncated")
            payload.extend(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise ContractError(f"{label} exceeded its admitted size")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ContractError(f"{label} changed while reading")
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ContractError(f"{label} cannot be opened safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    try:
        value = json.loads(bytes(payload).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{label} root is invalid")
    return value


def _stable_regular_sha256(
    path: Path,
    boundary: Path,
    *,
    allowed_uids: set[int],
) -> str | None:
    """Hash a bounded regular file without following any path symlink."""

    absolute = Path(os.path.abspath(path))
    try:
        absolute.relative_to(boundary)
    except ValueError:
        return None
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor = _open_directory_nofollow(absolute.parent)
        path_info = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or path_info.st_uid not in allowed_uids
            or path_info.st_nlink != 1
            or path_info.st_size <= 0
            or path_info.st_size > MAX_EVIDENCE_BYTES
            or stat.S_IMODE(path_info.st_mode) & 0o002
        ):
            return None
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        if (
            (path_info.st_dev, path_info.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid not in allowed_uids
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_EVIDENCE_BYTES
            or stat.S_IMODE(before.st_mode) & 0o002
        ):
            return None
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 65_536))
            if not block:
                return None
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            return None
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            return None
        return "sha256:" + digest.hexdigest()
    except OSError:
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _stable_regular_attestation(
    path: Path,
    boundary: Path,
    *,
    allowed_uids: set[int],
) -> dict[str, Any] | None:
    """Read the rich identity/content signature emitted by OpenClaw target apply."""

    absolute = Path(os.path.abspath(path))
    try:
        absolute.relative_to(boundary)
    except ValueError:
        return None
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor = _open_directory_nofollow(absolute.parent)
        path_info = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or path_info.st_uid not in allowed_uids
            or path_info.st_nlink != 1
            or path_info.st_size <= 0
            or path_info.st_size > MAX_EVIDENCE_BYTES
            or stat.S_IMODE(path_info.st_mode) & 0o002
        ):
            return None
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        if (
            (path_info.st_dev, path_info.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid not in allowed_uids
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_EVIDENCE_BYTES
            or stat.S_IMODE(before.st_mode) & 0o002
        ):
            return None
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 65_536))
            if not block:
                return None
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            return None
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            return None
        return {
            "exists": True,
            "kind": "file",
            "hash": "sha256:" + digest.hexdigest(),
            "device": int(after.st_dev),
            "inode": int(after.st_ino),
            "size": int(after.st_size),
            "mode": stat.S_IMODE(after.st_mode),
            "uid": int(after.st_uid),
            "nlink": int(after.st_nlink),
            "mtime_ns": int(after.st_mtime_ns),
            "ctime_ns": int(after.st_ctime_ns),
        }
    except OSError:
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _load_stable_source_json(path: Path, boundary: Path, label: str) -> dict[str, Any]:
    """Read a bounded AAS source manifest without following path symlinks."""

    absolute = Path(os.path.abspath(path))
    try:
        absolute.relative_to(boundary)
    except ValueError as exc:
        raise ContractError(f"{label} is outside the AAS source root") from exc
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor = _open_directory_nofollow(absolute.parent)
        path_info = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or path_info.st_uid not in {0, os.geteuid()}
            or path_info.st_nlink != 1
            or path_info.st_size <= 0
            or path_info.st_size > MAX_EVIDENCE_BYTES
            or stat.S_IMODE(path_info.st_mode) & 0o002
        ):
            raise ContractError(f"{label} metadata is unsafe")
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        if (
            (path_info.st_dev, path_info.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_EVIDENCE_BYTES
            or stat.S_IMODE(before.st_mode) & 0o002
        ):
            raise ContractError(f"{label} metadata is unsafe")
        payload = bytearray()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 65_536))
            if not block:
                raise ContractError(f"{label} was truncated")
            payload.extend(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise ContractError(f"{label} exceeded its admitted size")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ContractError(f"{label} changed while reading")
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ContractError(f"{label} cannot be opened safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    try:
        value = json.loads(bytes(payload).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{label} root is invalid")
    return value


def _complete_restore_skills(aas_source_root: Path, target_name: str) -> set[str]:
    profiles = _load_stable_source_json(
        aas_source_root / "manifest/profiles.yaml",
        aas_source_root,
        "AAS profiles manifest",
    )
    skills = _load_stable_source_json(
        aas_source_root / "manifest/skills.yaml",
        aas_source_root,
        "AAS skills manifest",
    )
    profile_table = profiles.get("profiles")
    skill_table = skills.get("skills")
    complete = profile_table.get("complete-restore") if isinstance(profile_table, dict) else None
    if (
        profiles.get("schema_version") != 1
        or skills.get("schema_version") != 1
        or not isinstance(complete, dict)
        or complete.get("skills") != ["*"]
        or not isinstance(skill_table, dict)
    ):
        raise ContractError("AAS complete-restore inventory is invalid")
    runtime_backed: set[str] = set()
    if target_name == "openclaw":
        runtime = _load_stable_source_json(
            aas_source_root / "manifest/runtime.yaml",
            aas_source_root,
            "AAS runtime manifest",
        )
        runtime_table = runtime.get("skills")
        if runtime.get("schema_version") != 1 or not isinstance(runtime_table, dict):
            raise ContractError("AAS runtime inventory is invalid")
        if any(not isinstance(skill, str) for skill in runtime_table):
            raise ContractError("AAS runtime inventory is invalid")
        runtime_backed = set(runtime_table)
    required: set[str] = set()
    for skill, spec in skill_table.items():
        if (
            not isinstance(skill, str)
            or AAS_SKILL_RE.fullmatch(skill) is None
            or not isinstance(spec, dict)
            or not isinstance(spec.get("supported_agents"), list)
            or any(not isinstance(agent, str) for agent in spec["supported_agents"])
        ):
            raise ContractError("AAS skills inventory is invalid")
        if target_name in spec["supported_agents"] and skill not in runtime_backed:
            required.add(skill)
    return required


def _stable_symlink_target(path: Path, boundary: Path) -> str | None:
    absolute = Path(os.path.abspath(path))
    try:
        absolute.relative_to(boundary)
    except ValueError:
        return None
    parent_descriptor: int | None = None
    try:
        parent_descriptor = _open_directory_nofollow(absolute.parent)
        info = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
        ):
            return None
        return os.readlink(absolute.name, dir_fd=parent_descriptor)
    except OSError:
        return None
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _installed_signature_matches(
    path: Path,
    root: Path,
    signature: object,
    expected_source: Path,
) -> bool:
    if not isinstance(signature, dict) or signature.get("exists") is not True:
        return False
    if signature.get("kind") == "file" and set(signature) == {"exists", "kind", "hash"}:
        expected_hash = signature.get("hash")
        return bool(
            isinstance(expected_hash, str)
            and SHA256_RE.fullmatch(expected_hash)
            and _stable_regular_sha256(path, root, allowed_uids={os.geteuid()})
            == expected_hash
        )
    if signature.get("kind") == "symlink" and set(signature) == {"exists", "kind", "target"}:
        expected_target = str(expected_source)
        return (
            signature.get("target") == expected_target
            and _stable_symlink_target(path, root) == expected_target
        )
    return False


def _run_receipt_action(
    root: Path,
    run_id: str,
    state_runs: list[dict[str, Any]],
    record: dict[str, Any],
    receipt_cache: dict[str, dict[str, Any] | None],
) -> dict[str, Any] | None:
    summaries = [item for item in state_runs if item.get("run_id") == run_id]
    if len(summaries) != 1:
        return None
    summary = summaries[0]
    action_count = summary.get("action_count")
    if isinstance(action_count, bool) or not isinstance(action_count, int) or action_count <= 0:
        return None
    if run_id not in receipt_cache:
        receipt_path = root / ".ai-agents-skills/runs" / f"{run_id}.json"
        try:
            receipt_cache[run_id] = _load_owner_private_json(
                receipt_path,
                root,
                "installer run receipt",
            )
        except (FileNotFoundError, ContractError):
            receipt_cache[run_id] = None
    receipt = receipt_cache[run_id]
    if receipt is None:
        return None
    if (
        set(receipt) != {"run_id", "actions"}
        or receipt.get("run_id") != run_id
        or not isinstance(receipt.get("actions"), list)
        or len(receipt["actions"]) != action_count
        or any(not isinstance(item, dict) for item in receipt["actions"])
    ):
        return None
    matches = [item for item in receipt["actions"] if item.get("key") == record.get("key")]
    if len(matches) != 1 or matches[0] != record:
        return None
    return matches[0]


def _main_installer_skill_observation(
    root: Path,
    aas_source_root: Path,
    target_name: str,
    home_raw: str,
) -> dict[str, Any]:
    source_root = Path(os.path.abspath(aas_source_root))
    state_path = root / ".ai-agents-skills/state.json"
    try:
        state = _load_owner_private_json(state_path, root, "installer state")
    except FileNotFoundError:
        return {"status": "TECHNICAL_FAIL", "reason": "installer-state-missing"}
    except ContractError:
        return {"status": "TECHNICAL_FAIL", "reason": "installer-state-invalid"}
    if (
        set(state) - {"schema_version", "artifacts", "runs", "uninstall_records", "provenance"}
        or isinstance(state.get("schema_version"), bool)
        or state.get("schema_version") != AAS_INSTALL_STATE_SCHEMA_VERSION
        or not isinstance(state.get("artifacts"), list)
        or not isinstance(state.get("runs"), list)
        or not isinstance(state.get("uninstall_records"), list)
        or any(not isinstance(item, dict) for item in state["artifacts"])
        or any(not isinstance(item, dict) for item in state["runs"])
    ):
        return {"status": "TECHNICAL_FAIL", "reason": "installer-state-invalid"}
    try:
        required_skills = _complete_restore_skills(source_root, target_name)
    except FileNotFoundError:
        return {"status": "TECHNICAL_FAIL", "reason": "complete-restore-inventory-missing"}
    except ContractError:
        return {"status": "TECHNICAL_FAIL", "reason": "complete-restore-inventory-invalid"}
    if not required_skills:
        return {"status": "TECHNICAL_FAIL", "reason": "complete-restore-inventory-empty"}
    records = [
        item
        for item in state["artifacts"]
        if item.get("agent") == target_name and item.get("artifact_type") == "skill-file"
    ]
    if not records:
        return {"status": "TECHNICAL_FAIL", "reason": "managed-skill-record-missing"}
    home = root / Path(*safe_relative(home_raw).parts)
    seen_keys: set[str] = set()
    seen_skills: set[str] = set()
    receipt_ids: set[str] = set()
    receipt_cache: dict[str, dict[str, Any] | None] = {}
    for record in records:
        skill = record.get("skill")
        run_id = record.get("run_id")
        if (
            not isinstance(skill, str)
            or AAS_SKILL_RE.fullmatch(skill) is None
            or not isinstance(run_id, str)
            or AAS_RUN_ID_RE.fullmatch(run_id) is None
            or record.get("managed") is not True
        ):
            return {"status": "TECHNICAL_FAIL", "reason": "managed-skill-record-invalid"}
        expected_artifact = (
            home / "skills" / f"{skill}.md"
            if target_name == "antigravity"
            else home / "skills" / skill / "SKILL.md"
        )
        expected_source = source_root / "canonical" / "skills" / skill / "SKILL.md"
        source_digest = _stable_regular_sha256(
            expected_source,
            source_root,
            allowed_uids={0, os.geteuid()},
        )
        expected_key = f"{target_name}:{skill}:{expected_artifact}"
        key = record.get("key")
        if (
            key != expected_key
            or key in seen_keys
            or skill in seen_skills
            or record.get("artifact") != str(expected_artifact)
            or record.get("source_path") != str(expected_source)
            or source_digest is None
            or record.get("canonical_source_sha256") != source_digest
            or not _installed_signature_matches(
                expected_artifact,
                root,
                record.get("installed_signature"),
                expected_source,
            )
            or _run_receipt_action(
                root,
                run_id,
                state["runs"],
                record,
                receipt_cache,
            )
            is None
        ):
            return {"status": "TECHNICAL_FAIL", "reason": "managed-skill-receipt-mismatch"}
        seen_keys.add(key)
        seen_skills.add(skill)
        receipt_ids.add(run_id)
    missing_skills = sorted(required_skills - seen_skills)
    if missing_skills:
        return {
            "status": "TECHNICAL_FAIL",
            "reason": "complete-restore-inventory-incomplete",
            "missing_skill_count": len(missing_skills),
            "missing_skills": missing_skills,
        }
    return {
        "status": "PASS",
        "reason": "installer-receipt-verified",
        "managed_skill_records": len(records),
        "required_skill_records": len(required_skills),
        "receipt_count": len(receipt_ids),
    }


def _openclaw_target_skill_observation(
    root: Path,
    aas_source_root: Path,
) -> dict[str, Any]:
    source_root = Path(os.path.abspath(aas_source_root))
    state_path = root / ".ai-agents-skills/openclaw-target-state.json"
    try:
        state = _load_owner_private_json(state_path, root, "OpenClaw target state")
    except FileNotFoundError:
        return {"status": "TECHNICAL_FAIL", "reason": "openclaw-target-state-missing"}
    except ContractError:
        return {"status": "TECHNICAL_FAIL", "reason": "openclaw-target-state-invalid"}
    if (
        set(state) != {"schema_version", "artifacts", "runs", "transactions"}
        or isinstance(state.get("schema_version"), bool)
        or state.get("schema_version") != 1
        or not isinstance(state.get("artifacts"), list)
        or not state["artifacts"]
        or not isinstance(state.get("runs"), list)
        or not isinstance(state.get("transactions"), list)
        or any(not isinstance(item, dict) for item in state["artifacts"])
        or any(not isinstance(item, dict) for item in state["runs"])
        or any(not isinstance(item, dict) for item in state["transactions"])
    ):
        return {"status": "TECHNICAL_FAIL", "reason": "openclaw-target-state-invalid"}
    try:
        required_skills = _complete_restore_skills(source_root, "openclaw")
    except FileNotFoundError:
        return {"status": "TECHNICAL_FAIL", "reason": "complete-restore-inventory-missing"}
    except ContractError:
        return {"status": "TECHNICAL_FAIL", "reason": "complete-restore-inventory-invalid"}
    if not required_skills:
        return {"status": "TECHNICAL_FAIL", "reason": "complete-restore-inventory-empty"}
    expected_record_fields = {
        "key",
        "manifest_id",
        "action_id",
        "action_class",
        "skill",
        "relative_path",
        "installed_hash",
        "installed_signature",
        "source_hash",
        "canonical_source_hash",
        "attestation",
        "created_parent_dirs",
        "run_id",
    }
    seen_keys: set[str] = set()
    seen_skills: set[str] = set()

    def safe_created_parent(value: object) -> bool:
        if not isinstance(value, str):
            return False
        try:
            return str(safe_relative(value)) == value
        except ContractError:
            return False

    for record in state["artifacts"]:
        skill = record.get("skill")
        run_id = record.get("run_id")
        manifest_id = record.get("manifest_id")
        action_id = record.get("action_id")
        installed_hash = record.get("installed_hash")
        canonical_source_hash = record.get("canonical_source_hash")
        if (
            set(record) != expected_record_fields
            or not isinstance(skill, str)
            or AAS_SKILL_RE.fullmatch(skill) is None
            or not isinstance(run_id, str)
            or AAS_RUN_ID_RE.fullmatch(run_id) is None
            or not isinstance(manifest_id, str)
            or OPENCLAW_MANIFEST_ID_RE.fullmatch(manifest_id) is None
            or not isinstance(action_id, str)
            or OPENCLAW_ACTION_ID_RE.fullmatch(action_id) is None
            or record.get("action_class") not in {"canary-skill-file", "managed-skill-file"}
            or not isinstance(installed_hash, str)
            or SHA256_RE.fullmatch(installed_hash) is None
            or record.get("source_hash") != installed_hash
            or not isinstance(canonical_source_hash, str)
            or SHA256_RE.fullmatch(canonical_source_hash) is None
            or record.get("attestation") not in {"created", "adopted-identical"}
            or record.get("relative_path") != f"skills/{skill}/SKILL.md"
            or not isinstance(record.get("created_parent_dirs"), list)
            or any(not safe_created_parent(item) for item in record["created_parent_dirs"])
        ):
            return {"status": "TECHNICAL_FAIL", "reason": "openclaw-target-record-invalid"}
        key = f"{manifest_id}:{action_id}"
        artifact = root / ".openclaw" / "skills" / skill / "SKILL.md"
        signature = record.get("installed_signature")
        current_signature = _stable_regular_attestation(
            artifact,
            root,
            allowed_uids={os.geteuid()},
        )
        expected_source = source_root / "canonical" / "skills" / skill / "SKILL.md"
        current_source_hash = _stable_regular_sha256(
            expected_source,
            source_root,
            allowed_uids={0, os.geteuid()},
        )
        if (
            record.get("key") != key
            or key in seen_keys
            or skill in seen_skills
            or not isinstance(signature, dict)
            or signature != current_signature
            or signature.get("hash") != installed_hash
            or current_source_hash is None
            or canonical_source_hash != current_source_hash
        ):
            return {"status": "TECHNICAL_FAIL", "reason": "openclaw-target-receipt-mismatch"}
        runs = [item for item in state["runs"] if item.get("run_id") == run_id]
        transactions = [
            item for item in state["transactions"] if item.get("run_id") == run_id
        ]
        if len(runs) != 1 or len(transactions) != 1:
            return {"status": "TECHNICAL_FAIL", "reason": "openclaw-target-transaction-missing"}
        run = runs[0]
        transaction = transactions[0]
        action_count = run.get("action_count")
        actions = transaction.get("actions")
        if (
            run.get("manifest_id") != manifest_id
            or isinstance(action_count, bool)
            or not isinstance(action_count, int)
            or action_count <= 0
            or transaction.get("manifest_id") != manifest_id
            or transaction.get("status") != "applied"
            or not isinstance(actions, list)
            or len(actions) != action_count
            or any(not isinstance(item, dict) for item in actions)
        ):
            return {"status": "TECHNICAL_FAIL", "reason": "openclaw-target-transaction-invalid"}
        matches = [item for item in actions if item.get("key") == key]
        if len(matches) != 1:
            return {"status": "TECHNICAL_FAIL", "reason": "openclaw-target-transaction-invalid"}
        action = matches[0]
        missing_signature = {"exists": False, "kind": "missing"}
        attestation = record["attestation"]
        expected_operation = "create" if attestation == "created" else "no-op"
        expected_pre_state = missing_signature if attestation == "created" else signature
        expected_reason = "ready" if attestation == "created" else "ready-to-adopt"
        if (
            action.get("manifest_id") != manifest_id
            or action.get("action_id") != action_id
            or action.get("action_class") != record.get("action_class")
            or action.get("skill") != skill
            or action.get("relative_path") != record.get("relative_path")
            or action.get("operation") != expected_operation
            or action.get("canonical_source_hash") != canonical_source_hash
            or action.get("expected_hash") != installed_hash
            or action.get("pre_state") != expected_pre_state
            or action.get("current_pre_state") != expected_pre_state
            or action.get("drift") is not False
            or action.get("blocked") is not False
            or action.get("reason") != expected_reason
            or (attestation == "adopted-identical" and record["created_parent_dirs"] != [])
        ):
            return {"status": "TECHNICAL_FAIL", "reason": "openclaw-target-transaction-mismatch"}
        seen_keys.add(key)
        seen_skills.add(skill)
    missing_skills = sorted(required_skills - seen_skills)
    if missing_skills:
        return {
            "status": "TECHNICAL_FAIL",
            "reason": "complete-restore-inventory-incomplete",
            "missing_skill_count": len(missing_skills),
            "missing_skills": missing_skills,
        }
    return {
        "status": "PASS",
        "reason": "openclaw-target-receipt-verified",
        "managed_skill_records": len(state["artifacts"]),
        "required_skill_records": len(required_skills),
        "receipt_count": len({item["run_id"] for item in state["artifacts"]}),
    }


def managed_skill_observation(
    root: Path,
    aas_source_root: Path,
    target_name: str,
    home_raw: str,
) -> dict[str, Any]:
    if target_name == "openclaw":
        return _openclaw_target_skill_observation(root, aas_source_root)
    return _main_installer_skill_observation(
        root,
        aas_source_root,
        target_name,
        home_raw,
    )


def load_mcp_evidence(path: Path | None, root: Path) -> dict[str, Any]:
    if path is None:
        return {"status": "TECHNICAL_FAIL", "reason": "mcp-report-missing"}
    try:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_size > MAX_EVIDENCE_BYTES
            or not path_is_within(path, root)
        ):
            raise ContractError("MCP evidence report is unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError("cannot read MCP evidence report") from exc
    if not isinstance(value, dict) or value.get("schema") != MCP_REPORT_SCHEMA:
        raise ContractError("MCP evidence report schema is invalid")
    return {"status": "PASS" if value.get("status") == "PASS" else "TECHNICAL_FAIL"}


def load_runtime_smoke_evidence(path: Path | None, root: Path) -> dict[str, Any]:
    if path is None:
        return {"status": "TECHNICAL_FAIL", "reason": "runtime-smoke-report-missing"}
    try:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_size <= 0
            or info.st_size > MAX_EVIDENCE_BYTES
            or not path_is_within(path, root)
        ):
            raise ContractError("installed runtime-smoke report is unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"status": "TECHNICAL_FAIL", "reason": "runtime-smoke-report-missing"}
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError("cannot read installed runtime-smoke report") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema") != AAS_RUNTIME_SMOKE_SCHEMA
        or value.get("schema_version") != 1
        or value.get("mode") != "installed"
        or isinstance(value.get("checked"), bool)
        or not isinstance(value.get("checked"), int)
        or not isinstance(value.get("unknown_coverage_count"), int)
        or isinstance(value.get("unknown_coverage_count"), bool)
        or not isinstance(value.get("missing_managed_runtime_count"), int)
        or isinstance(value.get("missing_managed_runtime_count"), bool)
        or not isinstance(value.get("declared_exclusions"), list)
        or not isinstance(value.get("results"), list)
    ):
        raise ContractError("installed runtime-smoke report schema is invalid")
    passed = (
        value.get("status") == "ok"
        and value["checked"] > 0
        and value["unknown_coverage_count"] == 0
        and value["missing_managed_runtime_count"] == 0
    )
    return {
        "status": "PASS" if passed else "TECHNICAL_FAIL",
        "reason": "verified" if passed else "runtime-smoke-not-passing",
        "checked": value["checked"],
        "declared_exclusion_count": len(value["declared_exclusions"]),
        "unknown_coverage_count": value["unknown_coverage_count"],
        "missing_managed_runtime_count": value["missing_managed_runtime_count"],
    }


def _load_fresh_protected_json(path: Path, root: Path) -> dict[str, Any]:
    """Read fresh 0600 evidence once through a stable, no-follow descriptor."""

    absolute = Path(os.path.abspath(path))
    try:
        absolute.relative_to(root)
    except ValueError as exc:
        raise ContractError("agent-auth evidence is outside the restored home") from exc
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor = _open_directory_nofollow(absolute.parent)
        path_info = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or path_info.st_uid != os.geteuid()
            or path_info.st_nlink != 1
            or stat.S_IMODE(path_info.st_mode) != 0o600
            or path_info.st_size <= 0
            or path_info.st_size > MAX_EVIDENCE_BYTES
        ):
            raise ContractError("agent-auth evidence metadata is unsafe")
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        if (
            (path_info.st_dev, path_info.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > MAX_EVIDENCE_BYTES
        ):
            raise ContractError("agent-auth evidence metadata is unsafe")
        age = time.time() - before.st_mtime
        if age < -30 or age > MAX_AGENT_AUTH_EVIDENCE_AGE_SECONDS:
            raise ContractError("agent-auth evidence is stale")
        payload = bytearray()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 65_536))
            if not block:
                raise ContractError("agent-auth evidence was truncated")
            payload.extend(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise ContractError("agent-auth evidence exceeded its admitted size")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ContractError("agent-auth evidence changed while reading")
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ContractError("agent-auth evidence cannot be opened safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    try:
        value = json.loads(bytes(payload).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("agent-auth evidence is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ContractError("agent-auth evidence root is invalid")
    return value


def _bounded_metadata_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 256
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def load_agent_auth_evidence(
    path: Path | None,
    root: Path,
    contract: object,
    authorities: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate metadata-only OpenClaw DB evidence without contacting providers."""

    if path is None:
        return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-report-missing"}
    if not isinstance(contract, dict):
        raise ContractError("agent-auth evidence contract is missing")
    required_contract = {
        "source": "openclaw-runtime-report",
        "source_schema_version": 1,
        "source_profile": "full",
        "source_status": "passed",
        "payload_key": "agent_auth",
        "report_fields": [
            "schema",
            "status",
            "runtimeVersion",
            "verificationMode",
            "openclawExecuted",
            "networkEnabled",
            "agents",
            "failureCount",
            "failures",
        ],
        "report_schema": "openclaw.agent-auth-closure/v2",
        "expected_runtime_version": contract.get("expected_runtime_version"),
        "report_status": "PASS",
        "verification_mode": "offline-structural-only",
        "openclaw_executed": False,
        "network_enabled": False,
        "agent_fields": ["agentId", "status", "canonicalStore", "reasons"],
        "canonical_store_fields": [
            "exists",
            "integrity",
            "schemaVersion",
            "appVersion",
            "authStoreRows",
            "profileCount",
            "configured",
            "authorityJsonValid",
            "executableSecretRefFree",
            "credentialSourceKinds",
            "redactionSentinelFree",
            "device",
            "inode",
            "size",
            "mtimeNs",
            "ctimeNs",
        ],
        "canonical_store_schema_version": 1,
        "canonical_store_app_version_policy": "null-or-exact-runtime-version",
        "credential_source_kinds_allowed": ["env", "file"],
        "provider_calls_allowed": False,
    }
    if (
        contract != required_contract
        or not _bounded_metadata_name(contract.get("expected_runtime_version"))
    ):
        raise ContractError("agent-auth evidence contract is invalid")
    evidence_authorities = [
        entry
        for entry in authorities
        if isinstance(entry, dict) and entry.get("evidence") == "agent-auth-closure"
    ]
    if len(evidence_authorities) != 1 or evidence_authorities[0].get("kind") != "glob":
        raise ContractError("agent-auth authority is missing or ambiguous")
    raw_glob = evidence_authorities[0].get("path")
    if raw_glob != OPENCLAW_AGENT_STORE_GLOB:
        raise ContractError("agent-auth authority path is invalid")
    store_records, unsafe_store = _agent_auth_store_matches(root, raw_glob)
    if unsafe_store:
        return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-store-unsafe"}
    try:
        outer = _load_fresh_protected_json(path, root)
    except FileNotFoundError:
        return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-report-missing"}
    except ContractError as exc:
        reason = (
            "agent-auth-report-stale"
            if "stale" in str(exc)
            else "agent-auth-report-invalid"
        )
        return {"status": "TECHNICAL_FAIL", "reason": reason}
    if (
        isinstance(outer.get("schema_version"), bool)
        or not isinstance(outer.get("schema_version"), int)
        or outer.get("schema_version") != contract["source_schema_version"]
        or outer.get("profile") != contract["source_profile"]
        or outer.get("status") != contract["source_status"]
        or outer.get("failures") != []
        or outer.get("skipped") != []
    ):
        return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-source-report-invalid"}
    payload = outer.get(contract["payload_key"])
    if (
        not isinstance(payload, dict)
        or set(payload) != set(contract["report_fields"])
        or payload.get("schema") != contract["report_schema"]
        or payload.get("runtimeVersion") != contract["expected_runtime_version"]
        or payload.get("status") != contract["report_status"]
        or payload.get("verificationMode") != contract["verification_mode"]
        or payload.get("openclawExecuted") is not contract["openclaw_executed"]
        or payload.get("networkEnabled") is not contract["network_enabled"]
        or payload.get("failureCount") != 0
        or isinstance(payload.get("failureCount"), bool)
        or payload.get("failures") != []
        or not isinstance(payload.get("agents"), list)
        or not payload["agents"]
    ):
        return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-payload-invalid"}
    agent_ids: set[str] = set()
    existing_store_ids: set[str] = set()
    for agent in payload["agents"]:
        if (
            not isinstance(agent, dict)
            or set(agent) != set(contract["agent_fields"])
        ):
            return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-agent-invalid"}
        agent_id = agent.get("agentId")
        if (
            not isinstance(agent_id, str)
            or AGENT_ID_RE.fullmatch(agent_id) is None
            or agent_id in agent_ids
            or agent.get("status") != "PASS"
            or agent.get("reasons") != []
        ):
            return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-agent-invalid"}
        agent_ids.add(agent_id)
        store = agent.get("canonicalStore")
        if (
            not isinstance(store, dict)
            or set(store) != set(contract["canonical_store_fields"])
        ):
            return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-store-metadata-invalid"}
        exists = store.get("exists")
        if not isinstance(exists, bool):
            return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-store-metadata-invalid"}
        if exists:
            rows = store.get("authStoreRows")
            profile_count = store.get("profileCount")
            source_kinds = store.get("credentialSourceKinds")
            if (
                store.get("integrity") is not True
                or isinstance(store.get("schemaVersion"), bool)
                or not isinstance(store.get("schemaVersion"), int)
                or store.get("schemaVersion")
                != contract["canonical_store_schema_version"]
                or (
                    store.get("appVersion") is not None
                    and store.get("appVersion")
                    != contract["expected_runtime_version"]
                )
                or isinstance(rows, bool)
                or not isinstance(rows, int)
                or rows < 0
                or isinstance(profile_count, bool)
                or not isinstance(profile_count, int)
                or profile_count <= 0
                or store.get("configured") is not True
                or store.get("authorityJsonValid") is not True
                or store.get("executableSecretRefFree") is not True
                or store.get("redactionSentinelFree") is not True
                or not isinstance(source_kinds, list)
                or not all(isinstance(kind, str) for kind in source_kinds)
                or source_kinds != sorted(set(source_kinds))
                or any(
                    kind not in set(contract["credential_source_kinds_allowed"])
                    for kind in source_kinds
                )
                or any(
                    isinstance(store.get(key), bool)
                    or not isinstance(store.get(key), int)
                    or store[key] < 0
                    for key in ("device", "inode", "size", "mtimeNs", "ctimeNs")
                )
            ):
                return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-store-metadata-invalid"}
            existing_store_ids.add(agent_id)
            observed_store = store_records.get(agent_id)
            if observed_store is None or any(
                store[key] != observed_store[key]
                for key in ("device", "inode", "size", "mtimeNs", "ctimeNs")
            ):
                return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-store-evidence-mismatch"}
        elif any(
            store.get(key) is not None
            for key in (
                "integrity",
                "schemaVersion",
                "appVersion",
                "authStoreRows",
                "profileCount",
                "configured",
                "authorityJsonValid",
                "executableSecretRefFree",
                "credentialSourceKinds",
                "redactionSentinelFree",
                "device",
                "inode",
                "size",
                "mtimeNs",
                "ctimeNs",
            )
        ):
            return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-store-metadata-invalid"}
    if existing_store_ids != set(store_records):
        return {"status": "TECHNICAL_FAIL", "reason": "agent-auth-store-evidence-mismatch"}
    return {
        "status": "PASS",
        "reason": "verified",
        "agent_count": len(agent_ids),
        "canonical_store_count": len(store_records),
        "provider_calls": 0,
    }


def validate_target_contract(name: str, target: dict[str, Any]) -> tuple[list[str], list[str]]:
    if not isinstance(target, dict):
        raise ContractError(f"target contract must be an object: {name}")
    safe_relative(str(target.get("home", "")))
    runtimes = target.get("runtime_requirements")
    readiness = target.get("readiness")
    if not isinstance(runtimes, list) or not runtimes or not all(isinstance(item, str) for item in runtimes):
        raise ContractError(f"runtime requirements are invalid for target {name}")
    if len(runtimes) != len(set(runtimes)):
        raise ContractError(f"runtime requirements contain duplicates for target {name}")
    unknown_runtimes = sorted(set(runtimes) - set(RUNTIME_PROBES))
    if unknown_runtimes:
        raise ContractError(f"unsupported runtime requirements for target {name}: {unknown_runtimes}")
    if not isinstance(readiness, list) or not readiness or not all(isinstance(item, str) for item in readiness):
        raise ContractError(f"readiness declarations are invalid for target {name}")
    if len(readiness) != len(set(readiness)):
        raise ContractError(f"readiness declarations contain duplicates for target {name}")
    unknown_readiness = sorted(set(readiness) - SUPPORTED_READINESS)
    if unknown_readiness:
        raise ContractError(f"unsupported readiness declarations for target {name}: {unknown_readiness}")
    inventory_only = target.get("inventory_only", False)
    if not isinstance(inventory_only, bool):
        raise ContractError(f"inventory-only marker is invalid for target {name}")
    if inventory_only:
        if (
            "cli-version" not in readiness
            or "auth-native" not in readiness
            or "managed-skill-visibility" in readiness
            or target.get("credential_state") != "native-unconfigured"
            or target.get("restore_policy") != "reauth-native-configuration"
            or target.get("readiness_when_authority_absent") != "NOT_CONFIGURED"
            or target.get("surfaces") is not None
            or target.get("credential_authorities") != []
        ):
            raise ContractError(f"inventory-only contract is invalid for target {name}")
    elif not {"cli-version", "managed-skill-visibility"}.issubset(readiness):
        raise ContractError(f"baseline readiness declarations are missing for target {name}")
    raw_surfaces = target.get("surfaces")
    contract_surfaces = raw_surfaces if isinstance(raw_surfaces, list) else [target]
    declared_authorities = [
        authority
        for surface in contract_surfaces
        if isinstance(surface, dict)
        for authority in surface.get("credential_authorities", [])
        if isinstance(authority, dict)
    ]
    agent_auth_authorities = [
        authority
        for authority in declared_authorities
        if authority.get("evidence") == "agent-auth-closure"
    ]
    if "agent-auth-closure" in readiness:
        contracts = target.get("evidence_contracts")
        contract = contracts.get("agent-auth-closure") if isinstance(contracts, dict) else None
        if (
            len(agent_auth_authorities) != 1
            or agent_auth_authorities[0].get("kind") != "glob"
            or agent_auth_authorities[0].get("path") != OPENCLAW_AGENT_STORE_GLOB
            or not isinstance(contract, dict)
            or set(contract) != {
                "source",
                "source_schema_version",
                "source_profile",
                "source_status",
                "payload_key",
                "report_fields",
                "report_schema",
                "expected_runtime_version",
                "report_status",
                "verification_mode",
                "openclaw_executed",
                "network_enabled",
                "agent_fields",
                "canonical_store_fields",
                "canonical_store_schema_version",
                "canonical_store_app_version_policy",
                "credential_source_kinds_allowed",
                "provider_calls_allowed",
            }
            or contract.get("source") != "openclaw-runtime-report"
            or isinstance(contract.get("source_schema_version"), bool)
            or not isinstance(contract.get("source_schema_version"), int)
            or contract.get("source_schema_version") != 1
            or contract.get("source_profile") != "full"
            or contract.get("source_status") != "passed"
            or contract.get("payload_key") != "agent_auth"
            or contract.get("report_fields")
            != [
                "schema",
                "status",
                "runtimeVersion",
                "verificationMode",
                "openclawExecuted",
                "networkEnabled",
                "agents",
                "failureCount",
                "failures",
            ]
            or contract.get("report_schema") != "openclaw.agent-auth-closure/v2"
            or not _bounded_metadata_name(contract.get("expected_runtime_version"))
            or contract.get("report_status") != "PASS"
            or contract.get("verification_mode") != "offline-structural-only"
            or contract.get("openclaw_executed") is not False
            or contract.get("network_enabled") is not False
            or contract.get("agent_fields")
            != ["agentId", "status", "canonicalStore", "reasons"]
            or contract.get("canonical_store_fields")
            != [
                "exists",
                "integrity",
                "schemaVersion",
                "appVersion",
                "authStoreRows",
                "profileCount",
                "configured",
                "authorityJsonValid",
                "executableSecretRefFree",
                "credentialSourceKinds",
                "redactionSentinelFree",
                "device",
                "inode",
                "size",
                "mtimeNs",
                "ctimeNs",
            ]
            or isinstance(contract.get("canonical_store_schema_version"), bool)
            or contract.get("canonical_store_schema_version") != 1
            or contract.get("canonical_store_app_version_policy")
            != "null-or-exact-runtime-version"
            or contract.get("credential_source_kinds_allowed") != ["env", "file"]
            or contract.get("provider_calls_allowed") is not False
        ):
            raise ContractError(f"agent-auth evidence contract is invalid for target {name}")
        authority_path = safe_relative(str(agent_auth_authorities[0].get("path", "")))
        authority_parts = authority_path.parts
        if (
            authority_parts.count("*") != 1
            or authority_parts.index("*") in {0, len(authority_parts) - 1}
            or any(
                any(character in part for character in "*?[]")
                for part in authority_parts
                if part != "*"
            )
        ):
            raise ContractError(f"agent-auth authority path is invalid for target {name}")
    elif agent_auth_authorities:
        raise ContractError(f"agent-auth authority lacks readiness declaration for target {name}")
    if "credential-projection" in readiness:
        projection = target.get("credential_projection")
        if (
            not isinstance(projection, dict)
            or not isinstance(projection.get("launcher"), str)
            or not isinstance(projection.get("launcher_source"), str)
            or not isinstance(projection.get("closure_loader"), str)
            or not isinstance(projection.get("authority"), str)
            or not isinstance(projection.get("pointer_env"), str)
            or STRICT_ENV_KEY_RE.fullmatch(projection.get("pointer_env", "")) is None
            or not isinstance(projection.get("argv"), list)
            or not projection["argv"]
            or not all(isinstance(item, str) and item for item in projection["argv"])
        ):
            raise ContractError(f"credential projection contract is invalid for target {name}")
        safe_relative(projection["launcher"])
        safe_relative(projection["launcher_source"])
        safe_relative(projection["closure_loader"])
        safe_relative(projection["authority"])
    return runtimes, readiness


def validate_integration_contract(
    name: str, integration: dict[str, Any]
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    """Validate a non-agent software surface without implying skill ownership."""

    if not isinstance(integration, dict):
        raise ContractError(f"software integration contract must be an object: {name}")
    candidates = integration.get("cli_candidates")
    version_argv = integration.get("version_argv")
    readiness = integration.get("readiness")
    authorities = integration.get("credential_authorities")
    if (
        integration.get("classification") != "non-agent-integration"
        or not isinstance(integration.get("declared_exclusion"), str)
        or not integration["declared_exclusion"].strip()
        or not isinstance(candidates, list)
        or not candidates
        or not all(isinstance(item, str) and item for item in candidates)
        or len(candidates) != len(set(candidates))
        or not isinstance(version_argv, list)
        or not version_argv
        or not all(isinstance(item, str) and item for item in version_argv)
        or not isinstance(readiness, list)
        or readiness != ["cli-version", "auth-structural"]
        or not isinstance(authorities, list)
        or not authorities
    ):
        raise ContractError(f"software integration contract is invalid: {name}")
    for authority in authorities:
        if (
            not isinstance(authority, dict)
            or authority.get("kind") not in {"file", "directory", "native-store"}
            or not isinstance(authority.get("path"), str)
            or not isinstance(authority.get("restore_policy"), str)
            or authority.get("fallback_policy") not in {None, "reauth-if-nonportable"}
            or authority.get("structure") != "github-hosts-v1"
        ):
            raise ContractError(
                f"software integration credential authority is invalid: {name}"
            )
        safe_relative(authority["path"])
    return candidates, version_argv, authorities


def verify(
    manifest: dict[str, Any],
    root: Path,
    aas_source_root: Path,
    path: str,
    allow_missing: set[str],
    readiness_phase: str,
    mcp_report: Path | None,
    runtime_smoke_report: Path | None,
    openclaw_runtime_report: Path | None,
    openclaw_runtime_passed: bool,
    scheduler_canary_passed: bool,
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    overall = "PASS"
    mcp_evidence = load_mcp_evidence(mcp_report, root) if readiness_phase == "full" else None
    runtime_smoke_evidence = (
        load_runtime_smoke_evidence(runtime_smoke_report, root)
        if readiness_phase == "full"
        else None
    )
    for name, target in manifest["targets"].items():
        if name in allow_missing:
            results[name] = {"status": "NOT_APPLICABLE", "reason": "explicitly-unsupported"}
            continue
        runtimes, readiness = validate_target_contract(name, target)
        runtime_status, runtime_results = runtime_observations(runtimes, path)
        declared_surfaces = target.get("surfaces")
        surfaces = declared_surfaces if isinstance(declared_surfaces, list) else [target]
        if not surfaces:
            raise ContractError(f"target has no CLI surfaces: {name}")
        surface_results: list[dict[str, Any]] = []
        for index, surface in enumerate(surfaces):
            if not isinstance(surface, dict):
                raise ContractError(f"invalid surface for target {name}")
            surface_id = str(surface.get("id", name))
            candidates = surface.get("cli_candidates")
            version_argv = surface.get("version_argv")
            authorities_raw = surface.get("credential_authorities")
            if (
                not surface_id
                or not isinstance(candidates, list)
                or not all(isinstance(item, str) and item for item in candidates)
                or not isinstance(version_argv, list)
                or not all(isinstance(item, str) for item in version_argv)
                or not isinstance(authorities_raw, list)
            ):
                raise ContractError(f"invalid surface contract for target {name} at index {index}")
            # A credential-projected target must prove the exact managed launcher directly;
            # global npm PATH ordering is not an executable-selection authority.
            if "credential-projection" in readiness and len(surfaces) == 1:
                projection = target["credential_projection"]
                candidates = [
                    str(root / Path(*safe_relative(projection["launcher"]).parts))
                ]
            cli = command_probe(candidates, version_argv, path)
            auth_status, authorities = credential_observations(root, authorities_raw)
            surface_status = worst_status([cli["status"], auth_status])
            surface_results.append(
                {
                    "id": surface_id,
                    "status": surface_status,
                    "cli": cli,
                    "auth_status": auth_status,
                    "credential_authorities": authorities,
                }
            )

        aggregate_cli = worst_status([item["cli"]["status"] for item in surface_results])
        aggregate_auth = worst_status([item["auth_status"] for item in surface_results])
        readiness_results: list[dict[str, Any]] = []
        for declaration in readiness:
            if declaration == "cli-version":
                observation = {"check": declaration, "status": aggregate_cli}
            elif declaration == "managed-skill-visibility":
                observation = {
                    "check": declaration,
                    **managed_skill_observation(
                        root,
                        aas_source_root,
                        name,
                        target["home"],
                    ),
                }
            elif declaration == "runtime-smoke" and readiness_phase == "pre-runtime":
                observation = {
                    "check": declaration,
                    "status": "NOT_CONFIGURED",
                    "reason": "deferred-pre-runtime",
                }
            elif declaration == "runtime-smoke" and name == "openclaw":
                observation = {
                    "check": declaration,
                    "status": "PASS" if openclaw_runtime_passed else "TECHNICAL_FAIL",
                    "reason": (
                        "openclaw-runtime-verified"
                        if openclaw_runtime_passed
                        else "openclaw-runtime-not-verified"
                    ),
                }
            elif declaration == "runtime-smoke":
                assert runtime_smoke_evidence is not None
                observation = {"check": declaration, **runtime_smoke_evidence}
            elif declaration in {"auth-structural", "auth-native"}:
                observation = {"check": declaration, "status": aggregate_auth}
            elif declaration == "credential-projection":
                projection_command = (
                    surface_results[0].get("cli", {}).get("command")
                    if len(surface_results) == 1
                    else None
                )
                observation = {
                    "check": declaration,
                    **credential_projection_observation(
                        projection_command,
                        root,
                        path,
                        aggregate_auth,
                        target.get("credential_projection"),
                        surfaces[0].get("credential_authorities")
                        if len(surfaces) == 1
                        else None,
                    ),
                }
            elif declaration == "agent-auth-closure" and readiness_phase == "pre-runtime":
                observation = {
                    "check": declaration,
                    "status": "NOT_CONFIGURED",
                    "reason": "deferred-pre-runtime",
                }
            elif declaration == "agent-auth-closure":
                all_authorities = [
                    authority
                    for surface in surfaces
                    for authority in surface.get("credential_authorities", [])
                    if isinstance(authority, dict)
                ]
                evidence_contracts = target.get("evidence_contracts")
                evidence_contract = (
                    evidence_contracts.get("agent-auth-closure")
                    if isinstance(evidence_contracts, dict)
                    else None
                )
                observation = {
                    "check": declaration,
                    **load_agent_auth_evidence(
                        openclaw_runtime_report,
                        root,
                        evidence_contract,
                        all_authorities,
                    ),
                }
            elif readiness_phase == "pre-runtime":
                observation = {"check": declaration, "status": "NOT_CONFIGURED", "reason": "deferred-pre-runtime"}
            elif declaration == "mcp-handshake":
                assert mcp_evidence is not None
                observation = {"check": declaration, **mcp_evidence}
            elif declaration == "scheduler-canary":
                observation = {
                    "check": declaration,
                    "status": "PASS" if scheduler_canary_passed else "TECHNICAL_FAIL",
                    "reason": "scheduler-canary-not-confirmed" if not scheduler_canary_passed else "confirmed",
                }
            else:  # validated above; retained as a fail-closed guard
                raise ContractError(f"unsupported readiness declaration: {declaration}")
            readiness_results.append(observation)

        status = worst_status(
            [runtime_status]
            + [item["status"] for item in surface_results]
            + [item["status"] for item in readiness_results]
        )
        result: dict[str, Any] = {
            "status": status,
            "runtime_status": runtime_status,
            "runtime_requirements": runtime_results,
            "readiness": readiness_results,
        }
        if isinstance(declared_surfaces, list):
            result["surfaces"] = surface_results
        else:
            surface_detail = dict(surface_results[0])
            surface_detail.pop("id", None)
            surface_detail.pop("status", None)
            result.update(surface_detail)
        results[name] = result
        overall = worst_status([overall, status])
    integration_results: dict[str, Any] = {}
    for name, integration in manifest.get("software_integrations", {}).items():
        candidates, version_argv, authorities_raw = validate_integration_contract(
            name, integration
        )
        cli = command_probe(candidates, version_argv, path)
        auth_status, authorities = credential_observations(root, authorities_raw)
        status = worst_status([str(cli["status"]), auth_status])
        integration_results[name] = {
            "status": status,
            "classification": "non-agent-integration",
            "cli": cli,
            "auth_status": auth_status,
            "credential_authorities": authorities,
            "readiness": [
                {"check": "cli-version", "status": cli["status"]},
                {"check": "auth-structural", "status": auth_status},
            ],
        }
        overall = worst_status([overall, status])

    report = {
        "schema": "coding-system.target-verification.v2",
        "status": overall,
        # bin/write-verification-evidence.py gates on this field.  Emitting it
        # here is what makes that gate able to fail; while it was absent the
        # consumer's default silently certified every target sidecar.
        "technicalStatus": "FAIL" if overall in {"TECHNICAL_FAIL", "AUTH_INVALID"} else "PASS",
        "readiness_phase": readiness_phase,
        "runtime_credential_authorities": runtime_credential_authority_report(
            manifest["runtime_credential_authorities"]
        ),
        "targets": results,
    }
    if integration_results:
        report["software_integrations"] = integration_results
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--aas-source-root", type=Path)
    parser.add_argument("--root", type=Path, default=Path.home())
    parser.add_argument("--path", default=os.environ.get("PATH", ""))
    parser.add_argument("--allow-missing-target", action="append", default=[])
    parser.add_argument("--readiness-phase", choices=("pre-runtime", "full"), default="full")
    parser.add_argument("--mcp-report", type=Path)
    parser.add_argument("--runtime-smoke-report", type=Path)
    parser.add_argument("--openclaw-runtime-report", type=Path)
    parser.add_argument("--openclaw-runtime-passed", action="store_true")
    parser.add_argument("--scheduler-canary-passed", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        if args.aas_source_root is None:
            manifest_path = Path(os.path.abspath(args.manifest))
            if manifest_path.parent.name != "manifest":
                raise ContractError(
                    "nonstandard target-state manifest requires --aas-source-root"
                )
            aas_source_root = manifest_path.parent.parent
        else:
            aas_source_root = Path(os.path.abspath(args.aas_source_root))
        report = verify(
            manifest,
            args.root.resolve(),
            aas_source_root,
            args.path,
            set(args.allow_missing_target),
            args.readiness_phase,
            args.mcp_report,
            args.runtime_smoke_report,
            args.openclaw_runtime_report,
            args.openclaw_runtime_passed,
            args.scheduler_canary_passed,
        )
    except ContractError as exc:
        print(f"verify-target-state: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # a verifier crash is a technical failure, not a status
        # Exit 1 is reserved for nontechnical statuses, and bin/verify.sh:590
        # reports it as ok.  Letting an unexpected exception reach the default
        # exit code would turn any crash in here into a green restore gate.
        print(f"verify-target-state: unexpected failure: {exc!r}", file=sys.stderr)
        return 2
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=args.output.parent, prefix=f".{args.output.name}."
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, args.output)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
    else:
        sys.stdout.write(payload)
    if report["status"] in {"PASS", "NOT_APPLICABLE"}:
        return 0
    if report["status"] in {"TECHNICAL_FAIL", "AUTH_INVALID"}:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
