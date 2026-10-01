#!/usr/bin/env python3
"""Canonical Python wheelhouse manifests and validation (stdlib only)."""

from __future__ import annotations

from email.parser import BytesParser
from email.policy import default
import hashlib
import itertools
import json
from pathlib import Path
import re
import stat
import zipfile


SCHEMA = "coding-system.python-wheelhouse/v1"
INDEX_SCHEMA = "coding-system.python-wheelhouse-index/v1"
ENVIRONMENTS = (
    "workspace",
    "shared",
    "docling-cpu",
    "lean-explore",
    "getscipapers",
    "aider",
    "modal",
    "course-management",
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
WHEEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+!-]*\.whl$")
TAG_PART = re.compile(r"^[A-Za-z0-9_]+$")
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_WHEEL_BYTES = 4 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
MAX_FILES = 4096
DOCLING_CPU_REQUIRED = {"torch", "torchvision"}


class WheelhouseError(RuntimeError):
    """A wheelhouse violated the immutable artifact contract."""


def canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _wheel_parts(filename: str) -> tuple[str, str, str, str, str]:
    if not WHEEL_NAME.fullmatch(filename):
        raise WheelhouseError(f"unsupported wheel filename: {filename!r}")
    parts = filename[:-4].split("-")
    if len(parts) == 5:
        distribution, version, python_tag, abi_tag, platform_tag = parts
    elif len(parts) == 6 and re.fullmatch(r"[0-9][A-Za-z0-9_.]*", parts[2]):
        distribution, version, _build, python_tag, abi_tag, platform_tag = parts
    else:
        raise WheelhouseError(f"wheel filename lacks PEP 427 fields: {filename!r}")
    return distribution, version, python_tag, abi_tag, platform_tag


def wheel_tags(filename: str) -> list[str]:
    _distribution, _version, python_tag, abi_tag, platform_tag = _wheel_parts(filename)
    groups: list[list[str]] = []
    for value in (python_tag, abi_tag, platform_tag):
        parts = value.split(".")
        if not parts or any(not TAG_PART.fullmatch(part) for part in parts):
            raise WheelhouseError(f"invalid compressed wheel tag in {filename!r}")
        groups.append(parts)
    return sorted("-".join(values) for values in itertools.product(*groups))


def _tag_is_compatible(tag: str, architecture: str) -> bool:
    python_tag, abi_tag, platform_tag = tag.split("-", 2)
    if python_tag in {"py3", "py312"}:
        python_ok = abi_tag == "none"
    elif python_tag == "cp312":
        python_ok = abi_tag in {"cp312", "abi3", "none"}
    else:
        match = re.fullmatch(r"cp3([0-9]{1,2})", python_tag)
        python_ok = bool(match and abi_tag == "abi3" and int(match.group(1)) <= 12)
    if not python_ok:
        return False
    if platform_tag == "any":
        return True
    suffix = "_x86_64" if architecture == "amd64" else "_aarch64"
    return platform_tag.startswith(("linux_", "manylinux", "musllinux")) and platform_tag.endswith(suffix)


def inspect_wheel(path: Path, architecture: str) -> dict[str, object]:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise WheelhouseError(f"wheel is not a single-link regular file: {path}")
    if info.st_size <= 0 or info.st_size > MAX_WHEEL_BYTES:
        raise WheelhouseError(f"wheel has an invalid size: {path.name}")
    distribution, filename_version, _py, _abi, _platform = _wheel_parts(path.name)
    tags = wheel_tags(path.name)
    if not any(_tag_is_compatible(tag, architecture) for tag in tags):
        raise WheelhouseError(f"wheel is incompatible with CPython 3.12/{architecture}: {path.name}")
    try:
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > 20000:
                raise WheelhouseError(f"wheel has too many members: {path.name}")
            metadata_members = [
                item
                for item in archive.infolist()
                if item.filename.count("/") == 1 and item.filename.endswith(".dist-info/METADATA")
            ]
            if len(metadata_members) != 1 or metadata_members[0].file_size > 1024 * 1024:
                raise WheelhouseError(f"wheel has no unique bounded METADATA: {path.name}")
            metadata = BytesParser(policy=default).parsebytes(archive.read(metadata_members[0]))
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise WheelhouseError(f"cannot inspect wheel {path.name}: {exc}") from exc
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
        raise WheelhouseError(f"wheel METADATA lacks Name/Version: {path.name}")
    if canonical_name(name) != canonical_name(distribution):
        raise WheelhouseError(f"wheel filename and METADATA names differ: {path.name}")
    if version.replace("-", "_") != filename_version:
        raise WheelhouseError(f"wheel filename and METADATA versions differ: {path.name}")
    return {
        "name": canonical_name(name),
        "version": version,
        "filename": path.name,
        "sha256": sha256_file(path),
        "tags": tags,
    }


def validate_docling_cpu(artifacts: list[dict[str, object]]) -> None:
    names = {str(artifact["name"]) for artifact in artifacts}
    missing = sorted(DOCLING_CPU_REQUIRED - names)
    if missing:
        raise WheelhouseError(f"docling-cpu is missing required CPU wheels: {missing}")
    for artifact in artifacts:
        name = str(artifact["name"])
        version = str(artifact["version"])
        if name == "triton" or name.startswith(("nvidia-", "cuda-", "triton-", "pytorch-triton", "rocm-")):
            raise WheelhouseError(f"docling-cpu contains accelerator package: {name}")
        if name in DOCLING_CPU_REQUIRED and "+cpu" not in version:
            raise WheelhouseError(f"docling-cpu contains non-CPU {name} wheel: {version}")


def build_manifests(root: Path, platform_name: str) -> dict[str, object]:
    if platform_name not in {"linux/amd64", "linux/arm64"}:
        raise WheelhouseError(f"unsupported platform: {platform_name}")
    architecture = platform_name.split("/", 1)[1]
    index_environments: list[dict[str, object]] = []
    for environment in ENVIRONMENTS:
        directory = root / environment
        if not directory.is_dir() or directory.is_symlink():
            raise WheelhouseError(f"missing wheel directory: {environment}")
        wheels = sorted(directory.glob("*.whl"), key=lambda item: item.name)
        if not wheels:
            raise WheelhouseError(f"wheel directory is empty: {environment}")
        artifacts = [inspect_wheel(wheel, architecture) for wheel in wheels]
        names = [str(item["name"]) for item in artifacts]
        filenames = [str(item["filename"]) for item in artifacts]
        if len(names) != len(set(names)):
            raise WheelhouseError(f"environment contains duplicate distributions: {environment}")
        if len(filenames) != len(set(filenames)):
            raise WheelhouseError(f"environment contains duplicate wheel filenames: {environment}")
        if environment == "docling-cpu":
            validate_docling_cpu(artifacts)
        manifest = {
            "schema": SCHEMA,
            "platform": platform_name,
            "python": {"implementation": "cpython", "version": "3.12"},
            "environment": environment,
            "artifacts": artifacts,
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_bytes(canonical_json(manifest))
        total = sum(wheel.stat().st_size for wheel in wheels)
        index_environments.append(
            {
                "name": environment,
                "manifest": f"{environment}/manifest.json",
                "sha256": sha256_file(manifest_path),
                "wheelCount": len(wheels),
                "wheelBytes": total,
            }
        )
    index = {
        "schema": INDEX_SCHEMA,
        "platform": platform_name,
        "python": {"implementation": "cpython", "version": "3.12"},
        "environments": index_environments,
    }
    (root / "manifest.json").write_bytes(canonical_json(index))
    return index


def _read_canonical_json(path: Path) -> dict[str, object]:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise WheelhouseError(f"manifest is not a single-link regular file: {path}")
    if info.st_size <= 0 or info.st_size > MAX_MANIFEST_BYTES:
        raise WheelhouseError(f"manifest has an invalid size: {path}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WheelhouseError(f"manifest is invalid JSON: {path}") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise WheelhouseError(f"manifest is not canonical JSON: {path}")
    return value


def validate_wheelhouse(root: Path, expected_platform: str) -> dict[str, object]:
    if expected_platform not in {"linux/amd64", "linux/arm64"}:
        raise WheelhouseError(f"unsupported platform: {expected_platform}")
    root_info = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(root_info.st_mode):
        raise WheelhouseError("wheelhouse root is not a directory")
    files = 0
    total_bytes = 0
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        info = path.lstat()
        if path.is_symlink() or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise WheelhouseError(f"unsupported wheelhouse node: {relative}")
        if stat.S_ISREG(info.st_mode):
            files += 1
            total_bytes += info.st_size
            if files > MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
                raise WheelhouseError("wheelhouse exceeds file or byte bounds")
        parts = relative.parts
        allowed = (
            parts == ("manifest.json",)
            or (len(parts) == 1 and parts[0] in ENVIRONMENTS and stat.S_ISDIR(info.st_mode))
            or (
                len(parts) == 2
                and parts[0] in ENVIRONMENTS
                and stat.S_ISREG(info.st_mode)
                and (parts[1] == "manifest.json" or WHEEL_NAME.fullmatch(parts[1]))
            )
        )
        if not allowed:
            raise WheelhouseError(f"unexpected wheelhouse path: {relative}")

    index = _read_canonical_json(root / "manifest.json")
    if set(index) != {"schema", "platform", "python", "environments"}:
        raise WheelhouseError("wheelhouse index has unexpected fields")
    if index.get("schema") != INDEX_SCHEMA or index.get("platform") != expected_platform:
        raise WheelhouseError("wheelhouse index schema/platform mismatch")
    if index.get("python") != {"implementation": "cpython", "version": "3.12"}:
        raise WheelhouseError("wheelhouse index Python mismatch")
    entries = index.get("environments")
    if not isinstance(entries, list) or [item.get("name") if isinstance(item, dict) else None for item in entries] != list(ENVIRONMENTS):
        raise WheelhouseError("wheelhouse index must list all environments in canonical order")

    architecture = expected_platform.split("/", 1)[1]
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"name", "manifest", "sha256", "wheelCount", "wheelBytes"}:
            raise WheelhouseError("wheelhouse index environment entry is invalid")
        environment = str(item["name"])
        expected_manifest = f"{environment}/manifest.json"
        if item["manifest"] != expected_manifest or not isinstance(item["sha256"], str) or not SHA256.fullmatch(item["sha256"]):
            raise WheelhouseError(f"invalid manifest binding for {environment}")
        manifest_path = root / expected_manifest
        if sha256_file(manifest_path) != item["sha256"]:
            raise WheelhouseError(f"manifest digest mismatch for {environment}")
        manifest = _read_canonical_json(manifest_path)
        if set(manifest) != {"schema", "platform", "python", "environment", "artifacts"}:
            raise WheelhouseError(f"environment manifest has unexpected fields: {environment}")
        if (
            manifest.get("schema") != SCHEMA
            or manifest.get("platform") != expected_platform
            or manifest.get("python") != {"implementation": "cpython", "version": "3.12"}
            or manifest.get("environment") != environment
        ):
            raise WheelhouseError(f"environment manifest header mismatch: {environment}")
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise WheelhouseError(f"environment manifest is empty: {environment}")
        expected_artifacts = [inspect_wheel(path, architecture) for path in sorted((root / environment).glob("*.whl"), key=lambda value: value.name)]
        if artifacts != expected_artifacts:
            raise WheelhouseError(f"wheel inventory or digest mismatch: {environment}")
        wheel_bytes = sum((root / environment / str(artifact["filename"])).stat().st_size for artifact in artifacts)
        if item["wheelCount"] != len(artifacts) or item["wheelBytes"] != wheel_bytes:
            raise WheelhouseError(f"wheel count/byte binding mismatch: {environment}")
        if environment == "docling-cpu":
            validate_docling_cpu(artifacts)
    return index
