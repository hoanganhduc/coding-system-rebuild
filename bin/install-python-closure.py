#!/usr/bin/env python3
"""Validate, install, and verify immutable Python wheel closures.

The installer intentionally does not resolve dependencies.  A qualified lock
names every wheel in one environment, and those exact artifacts are installed
into a new pip-less venv using host pip with ``--no-index --no-deps``.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import fcntl
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
import uuid
from typing import Callable, Iterator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "system/docker/python-wheelhouse"))
sys.path.insert(0, str(ROOT / "system/python-closure"))
from wheelhouse_lib import (  # noqa: E402
    WheelhouseError,
    sha256_file as wheelhouse_sha256_file,
    validate_wheelhouse,
)
from runtime_lib import (  # noqa: E402
    RuntimeContractError,
    verify_provenance,
)


SCHEMA = "coding-system.python-closure/v2"
MARKER_SCHEMA = "coding-system.python-closure-install/v3"
CONTENT_SCHEMA = "coding-system.python-closure-content/v2"
INSTALLER_VERSION = 3
PLATFORMS = {"ubuntu-24.04-amd64", "ubuntu-24.04-arm64"}
ENVIRONMENTS = {
    "workspace": ".openclaw/workspace/.python-closure/workspace",
    "shared": ".local/share/coding-system/python-closure/shared",
    "docling-cpu": ".local/share/coding-system/python-closure/docling-cpu",
    "lean-explore": ".local/share/coding-system/python-closure/lean-explore",
    "getscipapers": ".local/share/coding-system/python-closure/getscipapers",
    "aider": ".local/share/coding-system/python-closure/aider",
    "modal": ".local/share/coding-system/python-closure/modal",
    "course-management": ".course_venv",
}
QUALIFICATION_STATES = {"pending-artifacts", "partial", "qualified"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIST_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")
WHEEL_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+!-]*\.whl$")
TAG_PART = re.compile(r"^[A-Za-z0-9_]+$")
MARKER = ".coding-system-python-closure.json"


class ClosureError(RuntimeError):
    """A lock, artifact, or installed environment violated the contract."""


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ClosureError(f"{label} must be an object")
    return value


def _exact_keys(
    value: dict[str, object], required: set[str], label: str, optional: set[str] | None = None
) -> None:
    optional = optional or set()
    missing = required - set(value)
    extra = set(value) - required - optional
    if missing:
        raise ClosureError(f"{label} lacks required fields: {', '.join(sorted(missing))}")
    if extra:
        raise ClosureError(f"{label} has unexpected fields: {', '.join(sorted(extra))}")


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _qualification(value: object, label: str) -> tuple[str, list[str]]:
    item = _object(value, label)
    _exact_keys(item, {"state", "blockers"}, label)
    state = item["state"]
    blockers = item["blockers"]
    if state not in QUALIFICATION_STATES:
        raise ClosureError(f"{label}.state is unsupported: {state!r}")
    if not isinstance(blockers, list) or any(
        not isinstance(entry, str) or not entry.strip() for entry in blockers
    ):
        raise ClosureError(f"{label}.blockers must contain nonempty strings")
    if len(blockers) != len(set(blockers)):
        raise ClosureError(f"{label}.blockers contains duplicates")
    if state == "qualified" and blockers:
        raise ClosureError(f"{label} is qualified but still has blockers")
    if state != "qualified" and not blockers:
        raise ClosureError(f"{label} is not qualified but has no blocker evidence")
    return str(state), list(blockers)


def _wheel_parts(filename: str) -> tuple[str, str, str, str, str]:
    if not WHEEL_FILENAME.fullmatch(filename):
        raise ClosureError(f"artifact is not a supported wheel filename: {filename!r}")
    parts = filename[:-4].split("-")
    if len(parts) == 5:
        distribution, version, python_tag, abi_tag, platform_tag = parts
    elif len(parts) == 6 and re.fullmatch(r"[0-9][A-Za-z0-9_.]*", parts[2]):
        distribution, version, _build, python_tag, abi_tag, platform_tag = parts
    else:
        raise ClosureError(f"wheel filename does not have PEP 427 fields: {filename!r}")
    if not all((distribution, version, python_tag, abi_tag, platform_tag)):
        raise ClosureError(f"wheel filename contains an empty field: {filename!r}")
    return distribution, version, python_tag, abi_tag, platform_tag


def _expanded_tags(python_tag: str, abi_tag: str, platform_tag: str) -> set[str]:
    groups = []
    for value, label in (
        (python_tag, "python"),
        (abi_tag, "ABI"),
        (platform_tag, "platform"),
    ):
        parts = value.split(".")
        if not parts or any(not TAG_PART.fullmatch(part) for part in parts):
            raise ClosureError(f"wheel has an invalid compressed {label} tag: {value!r}")
        groups.append(parts)
    return {f"{python}-{abi}-{platform}" for python in groups[0] for abi in groups[1] for platform in groups[2]}


def _python_abi_compatible(python_tag: str, abi_tag: str) -> bool:
    if python_tag in {"py3", "py312"}:
        return abi_tag == "none"
    if python_tag == "cp312":
        return abi_tag in {"cp312", "abi3", "none"}
    match = re.fullmatch(r"cp3([0-9]{1,2})", python_tag)
    if match and abi_tag == "abi3":
        return int(match.group(1)) <= 12
    return False


def _platform_tag_compatible(tag: str, architecture: str) -> bool:
    if tag == "any":
        return True
    if not tag.startswith(("linux_", "manylinux", "musllinux")):
        return False
    if architecture == "amd64":
        return tag.endswith("_x86_64")
    return tag.endswith("_aarch64")


def _validate_artifact(
    value: object, *, label: str, architecture: str, cpu_only: bool
) -> dict[str, object]:
    item = _object(value, label)
    _exact_keys(
        item,
        {"name", "version", "filename", "tags", "sha256"},
        label,
    )
    name = item["name"]
    version = item["version"]
    filename = item["filename"]
    if not isinstance(name, str) or not DIST_NAME.fullmatch(name):
        raise ClosureError(f"{label}.name is not a valid distribution name")
    if name != _canonical_name(name):
        raise ClosureError(f"{label}.name must use its normalized distribution spelling")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ClosureError(f"{label}.version is not an exact supported version")
    if not isinstance(filename, str):
        raise ClosureError(f"{label}.filename must be a string")
    wheel_name, wheel_version, py_tag, abi_tag, platform_tag = _wheel_parts(filename)
    if _canonical_name(name) != _canonical_name(wheel_name):
        raise ClosureError(f"{label}.name does not match the wheel filename")
    if version.replace("-", "_") != wheel_version:
        raise ClosureError(f"{label}.version does not match the wheel filename")

    tags = item["tags"]
    expected_tags = _expanded_tags(py_tag, abi_tag, platform_tag)
    if (
        not isinstance(tags, list)
        or any(not isinstance(tag, str) for tag in tags)
        or len(tags) != len(set(tags))
        or set(tags) != expected_tags
    ):
        raise ClosureError(f"{label}.tags must exactly equal the tags encoded in the wheel filename")
    compatible_python_tag = False
    for tag in tags:
        python_value, abi_value, platform_value = tag.split("-", 2)
        compatible_python_tag = compatible_python_tag or _python_abi_compatible(
            python_value, abi_value
        )
        if not _platform_tag_compatible(platform_value, architecture):
            raise ClosureError(f"{label} is incompatible with {architecture}: {tag}")
    if not compatible_python_tag:
        raise ClosureError(f"{label} is incompatible with CPython 3.12")

    digest = item["sha256"]
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ClosureError(f"{label}.sha256 must be a lowercase SHA-256 digest")

    normalized = _canonical_name(name)
    if cpu_only:
        forbidden = (
            normalized in {"cuda", "nvidia", "triton"}
            or normalized.startswith("nvidia-")
            or normalized.startswith("cuda-")
            or normalized.startswith("cupy")
        )
        if forbidden:
            raise ClosureError(f"{label} violates the docling CPU-only profile: {name}")
        if normalized in {"torch", "torchvision", "torchaudio"} and "+cpu" not in version:
            raise ClosureError(f"{label} must use an explicitly CPU-qualified PyTorch version")

    return {
        "name": name,
        "canonical_name": normalized,
        "version": version,
        "filename": filename,
        "tags": list(tags),
        "sha256": digest,
    }


def validate_lock(data: object) -> dict[str, object]:
    lock = _object(data, "lock")
    _exact_keys(
        lock,
        {
            "schema",
            "platform",
            "python",
            "qualification",
            "wheelhouseManifestSha256",
            "environments",
        },
        "lock",
        {"$schema"},
    )
    if lock["schema"] != SCHEMA:
        raise ClosureError(f"unsupported Python closure schema: {lock['schema']!r}")
    platform_name = lock["platform"]
    if platform_name not in PLATFORMS:
        raise ClosureError(f"unsupported Python closure platform: {platform_name!r}")
    architecture = str(platform_name).rsplit("-", 1)[1]
    python = _object(lock["python"], "lock.python")
    _exact_keys(python, {"implementation", "version"}, "lock.python")
    if python != {"implementation": "cpython", "version": "3.12"}:
        raise ClosureError("Python closure must target CPython 3.12")
    overall_state, _ = _qualification(lock["qualification"], "lock.qualification")
    root_manifest_sha256 = lock["wheelhouseManifestSha256"]
    if root_manifest_sha256 is not None and (
        not isinstance(root_manifest_sha256, str) or not SHA256.fullmatch(root_manifest_sha256)
    ):
        raise ClosureError("lock.wheelhouseManifestSha256 must be null or a lowercase SHA-256 digest")

    environments = _object(lock["environments"], "lock.environments")
    if set(environments) != set(ENVIRONMENTS):
        missing = set(ENVIRONMENTS) - set(environments)
        extra = set(environments) - set(ENVIRONMENTS)
        detail = []
        if missing:
            detail.append(f"missing {', '.join(sorted(missing))}")
        if extra:
            detail.append(f"unexpected {', '.join(sorted(extra))}")
        raise ClosureError("lock.environments has the wrong closure: " + "; ".join(detail))

    normalized_environments: dict[str, object] = {}
    qualified_count = 0
    for environment_name in sorted(ENVIRONMENTS):
        label = f"lock.environments.{environment_name}"
        environment = _object(environments[environment_name], label)
        _exact_keys(
            environment,
            {"installPath", "profile", "qualification", "manifestSha256", "artifacts"},
            label,
        )
        install_path = environment["installPath"]
        if install_path != ENVIRONMENTS[environment_name]:
            raise ClosureError(f"{label}.installPath must be {ENVIRONMENTS[environment_name]!r}")
        relative = PurePosixPath(str(install_path))
        if relative.is_absolute() or ".." in relative.parts:
            raise ClosureError(f"{label}.installPath escapes the user's home")
        expected_profile = "cpu-only" if environment_name == "docling-cpu" else "default"
        if environment["profile"] != expected_profile:
            raise ClosureError(f"{label}.profile must be {expected_profile!r}")
        state, blockers = _qualification(environment["qualification"], f"{label}.qualification")
        manifest_sha256 = environment["manifestSha256"]
        if manifest_sha256 is not None and (
            not isinstance(manifest_sha256, str) or not SHA256.fullmatch(manifest_sha256)
        ):
            raise ClosureError(f"{label}.manifestSha256 must be null or a lowercase SHA-256 digest")
        artifacts = environment["artifacts"]
        if not isinstance(artifacts, list):
            raise ClosureError(f"{label}.artifacts must be an array")
        if state == "qualified" and not artifacts:
            raise ClosureError(f"{label} is qualified but contains no artifacts")
        if state == "qualified" and manifest_sha256 is None:
            raise ClosureError(f"{label} is qualified but has no canonical manifest digest")
        if state != "qualified" and (manifest_sha256 is not None or artifacts):
            raise ClosureError(
                f"{label} is not qualified but contains canonical manifest or artifact claims"
            )
        if state == "qualified":
            qualified_count += 1

        normalized_artifacts = []
        seen: dict[str, set[str]] = {
            "name": set(),
            "filename": set(),
            "sha256": set(),
        }
        for index, artifact in enumerate(artifacts):
            normalized = _validate_artifact(
                artifact,
                label=f"{label}.artifacts[{index}]",
                architecture=architecture,
                cpu_only=environment_name == "docling-cpu",
            )
            duplicate_values = {
                "name": str(normalized["canonical_name"]),
                "filename": str(normalized["filename"]),
                "sha256": str(normalized["sha256"]),
            }
            for kind, duplicate_value in duplicate_values.items():
                if duplicate_value in seen[kind]:
                    raise ClosureError(f"{label}.artifacts contains duplicate {kind}: {duplicate_value}")
                seen[kind].add(duplicate_value)
            normalized_artifacts.append(normalized)
        normalized_environments[environment_name] = {
            "installPath": install_path,
            "profile": expected_profile,
            "qualification": {"state": state, "blockers": blockers},
            "manifestSha256": manifest_sha256,
            "artifacts": normalized_artifacts,
        }

    if overall_state == "qualified" and qualified_count != len(ENVIRONMENTS):
        raise ClosureError("lock is qualified but one or more environments are not qualified")
    if overall_state == "qualified" and root_manifest_sha256 is None:
        raise ClosureError("qualified lock has no canonical wheelhouse manifest digest")
    if qualified_count and root_manifest_sha256 is None:
        raise ClosureError("lock with a qualified environment has no wheelhouse manifest digest")
    if overall_state == "pending-artifacts" and qualified_count:
        raise ClosureError("lock with a qualified environment must use partial or qualified state")
    if overall_state == "pending-artifacts" and root_manifest_sha256 is not None:
        raise ClosureError("pending-artifacts lock must not claim a wheelhouse manifest digest")
    if overall_state == "partial" and not 0 < qualified_count < len(ENVIRONMENTS):
        raise ClosureError("partial lock must contain some, but not all, qualified environments")

    return {
        "schema": SCHEMA,
        "platform": platform_name,
        "python": dict(python),
        "qualification": lock["qualification"],
        "wheelhouseManifestSha256": root_manifest_sha256,
        "environments": normalized_environments,
    }


def load_lock(path: Path) -> tuple[dict[str, object], str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ClosureError(f"cannot read Python closure lock {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ClosureError(f"invalid JSON in Python closure lock {path}: {exc}") from exc
    return validate_lock(data), hashlib.sha256(raw).hexdigest()


def _manifest_artifact(artifact: dict[str, object]) -> dict[str, object]:
    return {
        "name": artifact["canonical_name"],
        "version": artifact["version"],
        "filename": artifact["filename"],
        "sha256": artifact["sha256"],
        "tags": artifact["tags"],
    }


def _read_environment_manifest(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClosureError(f"cannot read canonical environment manifest {path}: {exc}") from exc
    return _object(value, f"canonical environment manifest {path}")


def validate_wheelhouse_against_lock(
    lock: dict[str, object],
    *,
    wheelhouse: Path,
    provenance: Path,
    images_lock: Path,
    environments: list[str],
) -> dict[str, object]:
    """Bind a validated extracted wheelhouse to the qualified Python lock."""

    architecture = str(lock["platform"]).rsplit("-", 1)[1]
    expected_platform = f"linux/{architecture}"
    for environment_name in environments:
        require_environment_qualified(lock, environment_name)
    try:
        index = validate_wheelhouse(wheelhouse, expected_platform)
        receipt = verify_provenance(
            provenance,
            wheelhouse=wheelhouse,
            images_lock=images_lock,
            architecture=architecture,
        )
    except (WheelhouseError, RuntimeContractError, OSError) as exc:
        raise ClosureError(f"wheelhouse authority validation failed: {exc}") from exc

    root_digest = wheelhouse_sha256_file(wheelhouse / "manifest.json")
    if root_digest != lock["wheelhouseManifestSha256"]:
        raise ClosureError(
            "canonical wheelhouse manifest digest differs from the qualified Python lock"
        )
    indexed = {
        str(item["name"]): item
        for item in index["environments"]  # type: ignore[index]
    }
    environment_sources: dict[str, object] = {}
    for environment_name in environments:
        environment = lock["environments"][environment_name]  # type: ignore[index]
        manifest_path = wheelhouse / environment_name / "manifest.json"
        manifest_digest = wheelhouse_sha256_file(manifest_path)
        if manifest_digest != environment["manifestSha256"]:  # type: ignore[index]
            raise ClosureError(
                f"canonical manifest digest differs from {environment_name} lock"
            )
        if indexed[environment_name]["sha256"] != manifest_digest:  # type: ignore[index]
            raise ClosureError(
                f"wheelhouse index does not bind the {environment_name} manifest"
            )
        manifest = _read_environment_manifest(manifest_path)
        expected_artifacts = [
            _manifest_artifact(artifact)
            for artifact in environment["artifacts"]  # type: ignore[index]
        ]
        if manifest.get("artifacts") != expected_artifacts:
            raise ClosureError(
                f"canonical artifact inventory differs from {environment_name} lock"
            )
        environment_sources[environment_name] = {
            "manifestSha256": manifest_digest,
            "wheels": [
                wheelhouse / environment_name / str(artifact["filename"])
                for artifact in environment["artifacts"]  # type: ignore[index]
            ],
        }
    return {
        "receipt": receipt,
        "rootManifestSha256": root_digest,
        "environments": environment_sources,
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ClosureError(f"wheelhouse artifact is not a regular file: {path}")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ClosureError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ClosureError(f"cannot inspect /etc/os-release: {exc}") from exc
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name] = value.strip().strip('"')
    return values


def _machine_architecture(machine: str) -> str:
    normalized = machine.lower()
    if normalized in {"x86_64", "amd64"}:
        return "amd64"
    if normalized in {"aarch64", "arm64"}:
        return "arm64"
    raise ClosureError(f"unsupported host architecture: {machine}")


def _interpreter_info(python: Path) -> dict[str, object]:
    script = (
        "import json,platform,sys;"
        "print(json.dumps({'implementation':sys.implementation.name,"
        "'version':[sys.version_info.major,sys.version_info.minor,sys.version_info.micro],"
        "'machine':platform.machine()}))"
    )
    result = subprocess.run(
        [str(python), "-I", "-c", script], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise ClosureError(f"cannot inspect Python interpreter {python}: {result.stderr.strip()}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ClosureError(f"Python interpreter returned invalid identity: {python}") from exc
    return _object(value, "Python interpreter identity")


def require_compatible_host(lock: dict[str, object], python: Path) -> None:
    os_release = _read_os_release()
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04":
        raise ClosureError("Python closure installation requires Ubuntu 24.04")
    info = _interpreter_info(python)
    version = info.get("version")
    if info.get("implementation") != "cpython" or not isinstance(version, list) or version[:2] != [3, 12]:
        raise ClosureError("Python closure installation requires CPython 3.12")
    architecture = _machine_architecture(str(info.get("machine", "")))
    expected = str(lock["platform"]).rsplit("-", 1)[1]
    if architecture != expected:
        raise ClosureError(f"lock targets {expected}, but the selected Python is {architecture}")


def _pip_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in list(environment):
        if name.startswith("PIP_") or name in {"PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"}:
            environment.pop(name, None)
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PIP_NO_INPUT"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _run(command: list[str], *, label: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        env=_pip_environment(),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        if len(detail) > 4000:
            detail = detail[-4000:]
        raise ClosureError(f"{label} failed ({result.returncode}): {detail}")
    return result


def _pip_prefix(python: Path, environment: Path) -> list[str]:
    return [str(python), "-m", "pip", "--isolated", "--python", str(environment)]


def installed_inventory(python: Path, environment: Path) -> dict[str, str]:
    result = _run(
        _pip_prefix(python, environment) + ["list", "--local", "--format=json"],
        label=f"pip inventory for {environment}",
    )
    try:
        records = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ClosureError(f"pip returned invalid inventory JSON for {environment}") from exc
    if not isinstance(records, list):
        raise ClosureError(f"pip returned a non-array inventory for {environment}")
    inventory: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict) or not {"name", "version"} <= set(record):
            raise ClosureError(f"pip returned an invalid distribution record for {environment}")
        name = record["name"]
        version = record["version"]
        if not isinstance(name, str) or not isinstance(version, str):
            raise ClosureError(f"pip returned a non-string distribution record for {environment}")
        canonical = _canonical_name(name)
        if canonical in inventory:
            raise ClosureError(f"pip returned duplicate distribution {canonical}")
        inventory[canonical] = version
    return inventory


def expected_inventory(environment: dict[str, object]) -> dict[str, str]:
    return {
        str(artifact["canonical_name"]): str(artifact["version"])
        for artifact in environment["artifacts"]  # type: ignore[index]
    }


def expected_marker(
    lock: dict[str, object],
    lock_sha256: str,
    environment_name: str,
    source: dict[str, object],
    installed_content: dict[str, object],
) -> dict[str, object]:
    environment = lock["environments"][environment_name]  # type: ignore[index]
    artifacts = environment["artifacts"]  # type: ignore[index]
    distributions = [
        {
            "name": artifact["canonical_name"],
            "version": artifact["version"],
            "filename": artifact["filename"],
            "sha256": artifact["sha256"],
        }
        for artifact in sorted(artifacts, key=lambda value: value["canonical_name"])
    ]
    return {
        "schema": MARKER_SCHEMA,
        "installerVersion": INSTALLER_VERSION,
        "lockSha256": lock_sha256,
        "platform": lock["platform"],
        "python": lock["python"],
        "environment": environment_name,
        "source": {
            "imagesLockSha256": source["receipt"]["imagesLockSha256"],  # type: ignore[index]
            "image": source["receipt"]["image"],  # type: ignore[index]
            "wheelhouseManifestSha256": source["rootManifestSha256"],
            "environmentManifestSha256": source["environments"][environment_name][  # type: ignore[index]
                "manifestSha256"
            ],
        },
        "distributions": distributions,
        "installedContent": installed_content,
    }


def _hash_installed_file(path: Path) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ClosureError(
            f"cannot open installed file without following links {path}: {exc}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ClosureError(f"installed content is not a regular file: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            raise ClosureError(f"installed file changed while it was being hashed: {path}")
        return digest.hexdigest(), before.st_size
    except OSError as exc:
        raise ClosureError(f"cannot hash installed file {path}: {exc}") from exc
    finally:
        os.close(descriptor)


def installed_content_manifest(environment: Path) -> dict[str, object]:
    """Hash every path and mode in the immutable venv tree."""

    requested = environment.absolute()
    try:
        root = requested.resolve(strict=True)
    except OSError as exc:
        raise ClosureError(f"cannot resolve Python closure generation {requested}: {exc}") from exc
    if not root.is_dir() or root.is_symlink():
        raise ClosureError(f"cannot inventory non-directory Python closure generation: {requested}")
    digest = hashlib.sha256()
    digest.update((CONTENT_SCHEMA + "\n").encode("utf-8"))
    entry_count = 0

    def add_record(record: dict[str, object]) -> None:
        nonlocal entry_count
        payload = json.dumps(
            record, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
        entry_count += 1

    def walk(directory: Path, relative_directory: PurePosixPath) -> None:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise ClosureError(f"cannot enumerate installed content {directory}: {exc}") from exc
        for entry in entries:
            relative = relative_directory / entry.name
            if relative == PurePosixPath(MARKER):
                continue
            path = Path(entry.path)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ClosureError(f"cannot inspect installed content {path}: {exc}") from exc
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                add_record({"mode": mode, "path": relative.as_posix(), "type": "directory"})
                walk(path, relative)
            elif stat.S_ISREG(metadata.st_mode):
                file_digest, size = _hash_installed_file(path)
                add_record(
                    {
                        "mode": mode,
                        "path": relative.as_posix(),
                        "sha256": file_digest,
                        "size": size,
                        "type": "file",
                    }
                )
            elif stat.S_ISLNK(metadata.st_mode):
                try:
                    link_value = os.readlink(path)
                except OSError as exc:
                    raise ClosureError(f"cannot read installed symlink {path}: {exc}") from exc
                add_record(
                    {
                        "mode": mode,
                        "path": relative.as_posix(),
                        "target": link_value,
                        "type": "symlink",
                    }
                )
            else:
                raise ClosureError(f"installed content contains an unsupported file type: {path}")

    add_record(
        {
            "mode": stat.S_IMODE(root.lstat().st_mode),
            "path": ".",
            "type": "directory",
        }
    )
    walk(root, PurePosixPath())
    return {
        "schema": CONTENT_SCHEMA,
        "entryCount": entry_count,
        "sha256": digest.hexdigest(),
    }


def freeze_generation_contents(environment: Path) -> None:
    """Make installed code read-only so normal imports cannot create cache authority."""
    root = environment.resolve(strict=True)
    for directory, directories, files in os.walk(root, topdown=False, followlinks=False):
        current = Path(directory)
        for name in files:
            path = current / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ClosureError(f"cannot freeze unsupported installed path: {path}")
            executable = bool(stat.S_IMODE(info.st_mode) & 0o111)
            path.chmod(0o555 if executable else 0o444, follow_symlinks=False)
        for name in directories:
            path = current / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise ClosureError(f"cannot freeze unsupported installed path: {path}")
            path.chmod(0o555, follow_symlinks=False)
    # The marker writer needs one atomic rename in the generation root.  The
    # root remains owner-writable; every executable/importable subtree is
    # read-only and every new root entry is covered by the content manifest.
    root.chmod(0o755)


def _installed_content_claim(value: object, target: Path) -> dict[str, object]:
    claim = _object(value, f"installed content claim for {target}")
    _exact_keys(
        claim,
        {"schema", "entryCount", "sha256"},
        f"installed content claim for {target}",
    )
    if claim["schema"] != CONTENT_SCHEMA:
        raise ClosureError(f"installed content claim uses an unsupported schema: {target}")
    count = claim["entryCount"]
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise ClosureError(f"installed content claim has an invalid entry count: {target}")
    digest = claim["sha256"]
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ClosureError(f"installed content claim has an invalid digest: {target}")
    return dict(claim)


def _read_marker(environment: Path) -> object:
    marker = environment / MARKER
    try:
        metadata = marker.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > 1024 * 1024
            or metadata.st_mode & 0o222
        ):
            raise ClosureError(f"invalid Python closure marker: {marker}")
        return json.loads(marker.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ClosureError(f"Python closure marker is missing: {marker}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ClosureError(f"cannot read Python closure marker {marker}: {exc}") from exc


def _write_marker(environment: Path, marker: dict[str, object]) -> None:
    destination = environment / MARKER
    data = (json.dumps(marker, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{MARKER}.", dir=environment)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.replace(temporary, destination)
        _fsync_directory(environment)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def verify_installed(
    lock: dict[str, object],
    lock_sha256: str,
    environment_name: str,
    target: Path,
    python: Path,
    source: dict[str, object],
) -> dict[str, str]:
    if not target.is_dir():
        raise ClosureError(f"Python closure target is not a directory: {target}")
    marker = _object(_read_marker(target), f"Python closure marker for {target}")
    installed_content = _installed_content_claim(marker.get("installedContent"), target)
    if marker != expected_marker(
        lock, lock_sha256, environment_name, source, installed_content
    ):
        raise ClosureError(f"Python closure marker differs from its lock: {target}")
    _run(_pip_prefix(python, target) + ["check"], label=f"pip check for {target}")
    actual = installed_inventory(python, target)
    expected = expected_inventory(lock["environments"][environment_name])  # type: ignore[index]
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        wrong = sorted(name for name in set(actual) & set(expected) if actual[name] != expected[name])
        details = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if extra:
            details.append(f"extra={','.join(extra)}")
        if wrong:
            details.append(f"wrong-version={','.join(wrong)}")
        raise ClosureError("installed distribution inventory differs from the lock: " + " ".join(details))
    observed_content = installed_content_manifest(target)
    if observed_content != installed_content:
        raise ClosureError(
            "installed package/module or entry-point bytes differ from the "
            f"closure marker: {target}"
        )
    return actual


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _target_lock(target: Path) -> Iterator[None]:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    lock_path = target.parent / f".{target.name}.python-closure.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ClosureError(f"Python closure lock is not a regular file: {lock_path}")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _remove_owned_tree(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ClosureError(f"refusing to remove non-directory Python closure generation: {path}")
    shutil.rmtree(path)


def _remove_replaced_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    else:
        raise ClosureError(f"unsupported replaced Python runtime path: {path}")


def _exchange_paths(left: Path, right: Path) -> None:
    """Atomically exchange two Linux paths without unlinking either one."""

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise ClosureError("renameat2 is unavailable on this supported Ubuntu host") from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    at_fdcwd = -100
    rename_exchange = 2
    result = renameat2(
        at_fdcwd,
        os.fsencode(left),
        at_fdcwd,
        os.fsencode(right),
        rename_exchange,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), f"{left} <-> {right}")


def _restore_replaced_path(backup: Path, target: Path) -> None:
    if os.path.lexists(target):
        # RENAME_EXCHANGE works across file types and restores a directory or
        # symlink over the activated link in one namespace operation.  The
        # displaced managed link then occupies backup and is safe to remove.
        _exchange_paths(backup, target)
        try:
            _remove_replaced_path(backup)
        except (OSError, ClosureError) as exc:
            print(
                f"python-closure: warning: displaced managed path retained at {backup}: {exc}",
                file=sys.stderr,
            )
    else:
        os.rename(backup, target)


def activate_generation(
    generation: Path,
    target: Path,
    post_activate: Callable[[], None],
) -> Path | None:
    """Switch target to generation and restore the old target on any failure."""

    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    next_link = target.parent / f".{target.name}.next-{uuid.uuid4().hex}"
    relative_generation = os.path.relpath(generation, target.parent)
    target_existed = os.path.lexists(target)
    if target_existed and not target.is_symlink() and not target.is_dir():
        raise ClosureError(f"refusing to replace a non-directory target: {target}")
    backup = (
        target.parent / f".{target.name}.rollback-{uuid.uuid4().hex}"
        if target_existed
        else None
    )
    os.symlink(relative_generation, next_link)
    try:
        if backup is not None:
            os.rename(target, backup)
            _fsync_directory(target.parent)
        os.replace(next_link, target)
        _fsync_directory(target.parent)
        post_activate()
        return backup
    except BaseException as activation_error:
        rollback_error: Exception | None = None
        try:
            if backup is not None and os.path.lexists(backup):
                _restore_replaced_path(backup, target)
                backup = None
            elif not target_existed and os.path.lexists(target):
                if not target.is_symlink() or os.readlink(target) != relative_generation:
                    raise ClosureError(
                        "refusing to remove an unexpected path during activation "
                        f"rollback: {target}"
                    )
                target.unlink()
            _fsync_directory(target.parent)
        except Exception as exc:
            rollback_error = exc
        if rollback_error is not None:
            retained = (
                f"; original state retained at {backup}"
                if backup is not None and os.path.lexists(backup)
                else ""
            )
            raise ClosureError(
                "Python closure activation failed and rollback could not complete for "
                f"{target}{retained}: "
                f"{rollback_error}"
            ) from activation_error
        raise
    finally:
        try:
            next_link.unlink()
        except FileNotFoundError:
            pass


def _resolve_python(value: str) -> Path:
    resolved = shutil.which(value)
    if resolved is None:
        raise ClosureError(f"Python interpreter is not executable: {value}")
    return Path(resolved).resolve()


def _target_path(
    lock: dict[str, object], environment_name: str, home: Path, override: Path | None
) -> Path:
    if override is not None:
        target = override.expanduser()
        if not target.is_absolute():
            target = Path.cwd() / target
        target = target.absolute()
    else:
        relative = lock["environments"][environment_name]["installPath"]  # type: ignore[index]
        target = home.expanduser().absolute() / str(relative)
    if target == Path("/") or target == home.expanduser().absolute():
        raise ClosureError(f"unsafe Python closure target: {target}")
    return target


def compatibility_links(home: Path) -> dict[Path, tuple[Path, str]]:
    home = home.expanduser().absolute()
    if home == Path("/"):
        raise ClosureError("refusing to materialize Python compatibility links under /")
    closure = home / ".local/share/coding-system/python-closure"
    return {
        home / ".openclaw/workspace/.local": (
            home
            / ".openclaw/workspace/.python-closure/workspace/lib/python3.12/site-packages",
            ".python-closure/workspace/lib/python3.12/site-packages",
        ),
        home / ".venvs": (closure / "shared", str(closure / "shared")),
        home / ".local/share/ai-agents-skills/runtime/workspace/.local": (
            closure / "shared",
            str(closure / "shared"),
        ),
        home / ".local/share/docling-venv": (
            closure / "docling-cpu",
            str(closure / "docling-cpu"),
        ),
        home / ".codex/runtime/workspace/.venvs/lean-explore": (
            closure / "lean-explore",
            str(closure / "lean-explore"),
        ),
        home / ".local/share/pipx/venvs/aider-chat": (
            closure / "aider",
            str(closure / "aider"),
        ),
        home / ".local/bin/aider": (
            home / ".local/share/pipx/venvs/aider-chat/bin/aider",
            str(home / ".local/share/pipx/venvs/aider-chat/bin/aider"),
        ),
        home / ".local/bin/modal": (
            closure / "modal/bin/modal",
            str(closure / "modal/bin/modal"),
        ),
    }


def verify_compatibility_links(home: Path) -> dict[str, str]:
    observed: dict[str, str] = {}
    for link, (target, link_value) in compatibility_links(home).items():
        if not link.is_symlink() or os.readlink(link) != link_value:
            raise ClosureError(f"Python runtime compatibility link differs: {link} -> {link_value}")
        if not target.exists():
            raise ClosureError(f"Python runtime compatibility target is missing: {target}")
        observed[str(link)] = str(target)
    return observed


def activate_compatibility_links(
    home: Path, *, replace_unmanaged: bool
) -> dict[str, str]:
    specifications = compatibility_links(home)

    def prospective_target_exists(target: Path) -> bool:
        if target.exists():
            return True
        for projected, (source, _link_value) in sorted(
            specifications.items(), key=lambda item: len(item[0].parts), reverse=True
        ):
            try:
                suffix = target.relative_to(projected)
            except ValueError:
                continue
            return (source / suffix).exists()
        return False

    pending: list[tuple[Path, Path, str, Path]] = []
    for link, (target, link_value) in specifications.items():
        if not prospective_target_exists(target):
            raise ClosureError(f"cannot link missing Python closure runtime: {target}")
        if link.is_symlink() and os.readlink(link) == link_value:
            continue
        if os.path.lexists(link) and not replace_unmanaged:
            raise ClosureError(
                f"Python compatibility path already exists; pass --replace-unmanaged: {link}"
            )
        link.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        next_link = link.parent / f".{link.name}.next-{uuid.uuid4().hex}"
        pending.append((link, target, link_value, next_link))

    prepared: list[Path] = []
    changes: list[tuple[Path, str, Path | None]] = []
    try:
        for _link, _target, link_value, next_link in pending:
            os.symlink(link_value, next_link)
            prepared.append(next_link)

        try:
            for link, _target, link_value, next_link in pending:
                backup: Path | None = None
                if os.path.lexists(link):
                    backup = link.parent / f".{link.name}.rollback-{uuid.uuid4().hex}"
                    changes.append((link, link_value, backup))
                    os.rename(link, backup)
                    _fsync_directory(link.parent)
                else:
                    changes.append((link, link_value, None))
                os.replace(next_link, link)
                _fsync_directory(link.parent)
            observed = verify_compatibility_links(home)
        except BaseException as activation_error:
            rollback_failures: list[str] = []
            for link, link_value, backup in reversed(changes):
                try:
                    if backup is not None and os.path.lexists(backup):
                        _restore_replaced_path(backup, link)
                    elif backup is not None:
                        if not os.path.lexists(link):
                            raise ClosureError(
                                f"original compatibility path disappeared: {link}"
                            )
                        if link.is_symlink() and os.readlink(link) == link_value:
                            raise ClosureError(
                                f"original compatibility path has no rollback copy: {link}"
                            )
                    elif backup is None and os.path.lexists(link):
                        if not link.is_symlink() or os.readlink(link) != link_value:
                            raise ClosureError(
                                f"refusing to remove an unexpected rollback path: {link}"
                            )
                        link.unlink()
                    _fsync_directory(link.parent)
                except Exception as exc:
                    retained = f" (original retained at {backup})" if backup is not None else ""
                    rollback_failures.append(f"{link}: {exc}{retained}")
            if rollback_failures:
                raise ClosureError(
                    "Python compatibility activation failed and rollback was incomplete: "
                    + "; ".join(rollback_failures)
                ) from activation_error
            raise

        for link, _link_value, backup in changes:
            if backup is None or not os.path.lexists(backup):
                continue
            if os.path.lexists(link):
                try:
                    _remove_replaced_path(backup)
                    _fsync_directory(link.parent)
                except (OSError, ClosureError) as exc:
                    print(
                        "python-closure: warning: replaced compatibility path retained "
                        f"at {backup}: {exc}",
                        file=sys.stderr,
                    )
        return observed
    finally:
        for next_link in prepared:
            try:
                next_link.unlink()
            except FileNotFoundError:
                pass


def _is_managed_target(target: Path) -> bool:
    try:
        return stat.S_ISREG((target / MARKER).lstat().st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


def require_environment_qualified(
    lock: dict[str, object], environment_name: str
) -> dict[str, object]:
    if environment_name not in ENVIRONMENTS:
        raise ClosureError(f"unknown Python closure environment: {environment_name}")
    environment = lock["environments"][environment_name]  # type: ignore[index]
    state = environment["qualification"]["state"]  # type: ignore[index]
    if state != "qualified":
        blockers = "; ".join(environment["qualification"]["blockers"])  # type: ignore[index]
        raise ClosureError(f"Python environment {environment_name} is not qualified: {blockers}")
    return environment


def require_lock_qualified(lock: dict[str, object]) -> None:
    if lock["qualification"]["state"] != "qualified":  # type: ignore[index]
        blockers = "; ".join(lock["qualification"]["blockers"])  # type: ignore[index]
        raise ClosureError(f"Python closure platform is not qualified: {blockers}")


def install_environment(
    lock: dict[str, object],
    lock_sha256: str,
    environment_name: str,
    *,
    target: Path,
    source: dict[str, object],
    python: Path,
    replace_unmanaged: bool,
) -> str:
    if environment_name not in ENVIRONMENTS:
        raise ClosureError(f"unknown Python closure environment: {environment_name}")
    environment = require_environment_qualified(lock, environment_name)
    require_compatible_host(lock, python)

    with _target_lock(target):
        if os.path.lexists(target):
            try:
                verify_installed(
                    lock, lock_sha256, environment_name, target, python, source
                )
                return "unchanged"
            except ClosureError:
                if not _is_managed_target(target) and not replace_unmanaged:
                    raise ClosureError(
                        f"target exists without a matching closure marker; pass --replace-unmanaged explicitly: {target}"
                    )

        wheels = source["environments"][environment_name]["wheels"]  # type: ignore[index]
        for wheel, artifact in zip(wheels, environment["artifacts"], strict=True):  # type: ignore[index]
            if _file_sha256(wheel) != artifact["sha256"]:  # type: ignore[index]
                raise ClosureError(f"wheel changed after manifest validation: {wheel}")
        generation_root = target.parent / f".{target.name}.generations"
        generation_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        generation_name = f"{environment_name}-{lock_sha256}"
        generation = generation_root / generation_name
        if os.path.lexists(generation):
            if generation.is_symlink() or not generation.is_dir():
                raise ClosureError(f"invalid Python closure generation path: {generation}")
            try:
                verify_installed(
                    lock, lock_sha256, environment_name, generation, python, source
                )
            except ClosureError:
                target_uses_generation = False
                if target.is_symlink():
                    try:
                        target_uses_generation = target.resolve() == generation.resolve()
                    except OSError:
                        target_uses_generation = False
                if target_uses_generation:
                    # Never expose a rebuild through an already-active symlink.
                    # A repair generation receives its final path before venv
                    # creation, preserving both staging isolation and shebangs.
                    generation = generation_root / (
                        f"{generation_name}-repair-{uuid.uuid4().hex[:12]}"
                    )
                else:
                    _remove_owned_tree(generation)

        built = False
        if not generation.exists():
            try:
                _run(
                    [str(python), "-I", "-m", "venv", "--without-pip", "--copies", str(generation)],
                    label=f"create Python environment {environment_name}",
                )
                _run(
                    _pip_prefix(python, generation)
                    + [
                        "install",
                        "--no-index",
                        "--no-deps",
                        "--no-compile",
                        "--no-warn-script-location",
                        *[str(wheel) for wheel in wheels],
                    ],
                    label=f"offline wheel installation for {environment_name}",
                )
                _run(_pip_prefix(python, generation) + ["check"], label=f"pip check for {environment_name}")
                actual = installed_inventory(python, generation)
                expected = expected_inventory(environment)
                if actual != expected:
                    raise ClosureError(
                        f"staged distribution inventory differs from {environment_name} lock: "
                        f"expected={json.dumps(expected, sort_keys=True)} actual={json.dumps(actual, sort_keys=True)}"
                    )
                freeze_generation_contents(generation)
                _write_marker(
                    generation,
                    expected_marker(
                        lock,
                        lock_sha256,
                        environment_name,
                        source,
                        installed_content_manifest(generation),
                    ),
                )
                verify_installed(
                    lock, lock_sha256, environment_name, generation, python, source
                )
                built = True
            except BaseException:
                if generation.exists() and not generation.is_symlink():
                    _remove_owned_tree(generation)
                raise

        activation_committed = False
        try:
            backup = activate_generation(
                generation,
                target,
                lambda: verify_installed(
                    lock, lock_sha256, environment_name, target, python, source
                ),
            )
            activation_committed = True
            if backup is not None:
                try:
                    _remove_replaced_path(backup)
                    _fsync_directory(target.parent)
                except (OSError, ClosureError) as exc:
                    # The new target is already verified and committed.  Do not
                    # turn old-state cleanup into a broken new activation; leave
                    # the bounded rollback path for inspection.
                    print(f"python-closure: warning: old target retained at {backup}: {exc}", file=sys.stderr)
        except BaseException:
            target_uses_generation = False
            if target.is_symlink():
                try:
                    target_uses_generation = target.resolve() == generation.resolve()
                except OSError:
                    target_uses_generation = False
            if (
                built
                and not activation_committed
                and not target_uses_generation
                and generation.exists()
                and not generation.is_symlink()
            ):
                _remove_owned_tree(generation)
            raise
        return "installed"


def _summary(lock: dict[str, object], lock_sha256: str) -> dict[str, object]:
    environments = lock["environments"]
    return {
        "schema": lock["schema"],
        "platform": lock["platform"],
        "qualification": lock["qualification"],
        "lockSha256": lock_sha256,
        "wheelhouseManifestSha256": lock["wheelhouseManifestSha256"],
        "environments": {
            name: {
                "qualification": environment["qualification"],
                "manifestSha256": environment["manifestSha256"],
                "artifactCount": len(environment["artifacts"]),
            }
            for name, environment in environments.items()
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate a wheel closure lock")
    validate.add_argument("--lock", required=True, type=Path)
    validate.add_argument("--require-qualified", action="store_true")

    for command in ("install", "verify", "install-all", "verify-all"):
        child = subparsers.add_parser(command, help=f"{command} from the locked wheelhouse")
        child.add_argument("--lock", required=True, type=Path)
        child.add_argument("--wheelhouse", required=True, type=Path)
        child.add_argument("--provenance", required=True, type=Path)
        child.add_argument(
            "--images-lock",
            type=Path,
            default=ROOT / "system/software/images.lock.json",
        )
        if command in {"install", "verify"}:
            child.add_argument("--environment", required=True, choices=sorted(ENVIRONMENTS))
        child.add_argument("--home", type=Path, default=Path.home())
        if command in {"install", "verify"}:
            child.add_argument("--target", type=Path)
        child.add_argument("--python", default="python3")
        if command in {"install", "install-all"}:
            child.add_argument("--replace-unmanaged", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        lock, lock_sha256 = load_lock(arguments.lock)
        if arguments.command == "validate":
            if arguments.require_qualified and lock["qualification"]["state"] != "qualified":
                blockers = "; ".join(lock["qualification"]["blockers"])
                raise ClosureError(f"Python closure platform is not qualified: {blockers}")
            print(json.dumps(_summary(lock, lock_sha256), indent=2, sort_keys=True))
            return 0

        all_environments = arguments.command.endswith("-all")
        environment_names = (
            list(ENVIRONMENTS) if all_environments else [arguments.environment]
        )
        if all_environments:
            require_lock_qualified(lock)
        python = _resolve_python(arguments.python)
        require_compatible_host(lock, python)
        source = validate_wheelhouse_against_lock(
            lock,
            wheelhouse=arguments.wheelhouse.expanduser().absolute(),
            provenance=arguments.provenance.expanduser().absolute(),
            images_lock=arguments.images_lock.expanduser().absolute(),
            environments=environment_names,
        )
        if arguments.command in {"verify", "verify-all"}:
            inventories: dict[str, object] = {}
            targets: dict[str, str] = {}
            for environment_name in environment_names:
                override = arguments.target if not all_environments else None
                target = _target_path(lock, environment_name, arguments.home, override)
                inventories[environment_name] = verify_installed(
                    lock, lock_sha256, environment_name, target, python, source
                )
                targets[environment_name] = str(target)
            links = verify_compatibility_links(arguments.home) if all_environments else {}
            print(
                json.dumps(
                    {
                        "status": "verified",
                        "environments": inventories,
                        "targets": targets,
                        "compatibilityLinks": links,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        statuses: dict[str, str] = {}
        targets = {}
        for environment_name in environment_names:
            override = arguments.target if not all_environments else None
            target = _target_path(lock, environment_name, arguments.home, override)
            statuses[environment_name] = install_environment(
                lock,
                lock_sha256,
                environment_name,
                target=target,
                source=source,
                python=python,
                replace_unmanaged=arguments.replace_unmanaged,
            )
            targets[environment_name] = str(target)
        links = (
            activate_compatibility_links(
                arguments.home, replace_unmanaged=arguments.replace_unmanaged
            )
            if all_environments
            else {}
        )
        print(
            json.dumps(
                {
                    "status": "installed",
                    "environments": statuses,
                    "targets": targets,
                    "compatibilityLinks": links,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except ClosureError as exc:
        print(f"python-closure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
