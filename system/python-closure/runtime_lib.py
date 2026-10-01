#!/usr/bin/env python3
"""Shared, stdlib-only runtime contract for the locked Python wheelhouse."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any


EXTRACTION_SCHEMA = "coding-system.python-wheelhouse-extraction/v1"
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OCI_REFERENCE = re.compile(r"^([^\s@]+)@(sha256:[0-9a-f]{64})$")
MAX_JSON_BYTES = 4 * 1024 * 1024


class RuntimeContractError(RuntimeError):
    """A wheelhouse image selection or extraction receipt is invalid."""


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_regular(path: Path, *, max_bytes: int | None = None) -> str:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeContractError(f"file is not a single-link regular file: {path}")
        if max_bytes is not None and (info.st_size <= 0 or info.st_size > max_bytes):
            raise RuntimeContractError(f"file exceeds its size contract: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError as exc:
        raise RuntimeContractError(f"cannot hash {path}: {exc}") from exc


def _read_json(path: Path, *, canonical: bool) -> tuple[dict[str, Any], bytes]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeContractError(f"JSON authority is not a single-link regular file: {path}")
        if info.st_size <= 0 or info.st_size > MAX_JSON_BYTES:
            raise RuntimeContractError(f"JSON authority has an invalid size: {path}")
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeContractError(f"cannot read JSON authority {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeContractError(f"JSON authority is not an object: {path}")
    if canonical and canonical_json(value) != raw:
        raise RuntimeContractError(f"JSON authority is not canonical: {path}")
    return value, raw


def load_locked_image(lock_path: Path, architecture: str) -> dict[str, str]:
    """Select exactly one digest-only wheelhouse image for an architecture."""

    if architecture not in {"amd64", "arm64"}:
        raise RuntimeContractError(f"unsupported architecture: {architecture}")
    value, raw = _read_json(lock_path, canonical=False)
    if value.get("schema_version") != 1 or not isinstance(value.get("images"), list):
        raise RuntimeContractError("OCI image lock has an unsupported schema")
    wanted = f"linux/{architecture}"
    matches = []
    for image in value["images"]:
        if not isinstance(image, dict):
            continue
        roles = image.get("roles")
        platforms = image.get("platforms")
        if (
            isinstance(roles, list)
            and "python-wheelhouse" in roles
            and isinstance(platforms, dict)
            and wanted in platforms
        ):
            matches.append(image)
    if len(matches) != 1:
        raise RuntimeContractError(
            f"ARTIFACT_UNAVAILABLE: expected exactly one locked python-wheelhouse for {wanted}, "
            f"found {len(matches)}"
        )
    image = matches[0]
    required = {"id", "roles", "repository", "reference", "index_digest", "platforms", "evidence"}
    if set(image) != required:
        raise RuntimeContractError("locked python-wheelhouse image has unexpected fields")
    reference = image.get("reference")
    repository = image.get("repository")
    index_digest = image.get("index_digest")
    platform_digest = image["platforms"].get(wanted)
    match = OCI_REFERENCE.fullmatch(reference) if isinstance(reference, str) else None
    if (
        not match
        or match.group(1) != repository
        or match.group(2) != index_digest
        or not isinstance(platform_digest, str)
        or not OCI_DIGEST.fullmatch(platform_digest)
    ):
        raise RuntimeContractError("python-wheelhouse lock is not digest-only and internally consistent")
    return {
        "reference": reference,
        "repository": str(repository),
        "index_digest": str(index_digest),
        "platform_digest": platform_digest,
        "platform": wanted,
        "images_lock_sha256": hashlib.sha256(raw).hexdigest(),
    }


def provenance_path(destination: Path) -> Path:
    return destination.with_name(f"{destination.name}.provenance.json")


def expected_provenance(
    image: dict[str, str], wheelhouse: Path
) -> dict[str, object]:
    return {
        "schema": EXTRACTION_SCHEMA,
        "imagesLockSha256": image["images_lock_sha256"],
        "image": {
            "reference": image["reference"],
            "indexDigest": image["index_digest"],
            "platformDigest": image["platform_digest"],
            "platform": image["platform"],
        },
        "wheelhouseManifestSha256": sha256_regular(
            wheelhouse / "manifest.json", max_bytes=MAX_JSON_BYTES
        ),
    }


def write_provenance(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise RuntimeContractError(f"unsafe extraction receipt parent: {path.parent}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(canonical_json(value))
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o444)
        os.replace(temporary, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def verify_provenance(
    path: Path,
    *,
    wheelhouse: Path,
    images_lock: Path,
    architecture: str,
) -> dict[str, object]:
    value, _raw = _read_json(path, canonical=True)
    image = load_locked_image(images_lock, architecture)
    expected = expected_provenance(image, wheelhouse)
    if value != expected:
        raise RuntimeContractError(
            "wheelhouse extraction receipt differs from the image lock or canonical manifest"
        )
    return value
