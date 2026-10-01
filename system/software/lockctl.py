#!/usr/bin/env python3
"""Validate and fetch the immutable Ubuntu software closure.

This helper intentionally uses only the Python standard library so it is usable
immediately after the Stage-0 bootstrap.  It never installs an artifact; callers
must choose an explicit, reviewable installation action after `fetch` verifies
the locked SHA-256 digest.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys
import urllib.parse
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
SOFTWARE = ROOT / "system" / "software"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OCI_REFERENCE = re.compile(r"^([^\s@]+)@(sha256:[0-9a-f]{64})$")
ARTIFACT_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class LockError(RuntimeError):
    """A checked-in lock is invalid or incomplete."""


def canonical_arch(value: str | None = None) -> str:
    raw = (value or platform.machine()).lower()
    if raw in {"aarch64", "arm64"}:
        return "arm64"
    if raw in {"x86_64", "amd64"}:
        return "amd64"
    raise LockError(f"unsupported architecture: {raw}")


def profile_path(arch: str) -> Path:
    return SOFTWARE / f"ubuntu-24.04-{canonical_arch(arch)}.lock.json"


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LockError(f"cannot read JSON lock {path}: {exc}") from exc


def load_profile(arch: str) -> dict[str, object]:
    path = profile_path(arch)
    value = load_json(path)
    if not isinstance(value, dict):
        raise LockError(f"platform lock must be an object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked_repo_path(relative: object) -> Path:
    if not isinstance(relative, str) or not relative or relative.startswith("/"):
        raise LockError(f"manifest path is not a nonempty relative path: {relative!r}")
    candidate = ROOT.joinpath(relative)
    try:
        candidate.resolve(strict=False).relative_to(ROOT.resolve())
    except ValueError as exc:
        raise LockError(f"manifest escapes repository root: {relative}") from exc
    if candidate.is_symlink() or not candidate.is_file():
        raise LockError(f"manifest is missing, nonregular, or a symlink: {relative}")
    return candidate


def artifact_map(profile: dict[str, object]) -> dict[str, dict[str, str]]:
    artifacts = profile.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise LockError("platform lock has no artifacts")
    result: dict[str, dict[str, str]] = {}
    required = {"id", "version", "url", "sha256", "format", "evidence"}
    allowed_formats = {"binary", "tar.gz", "tar.xz", "tar.zst", "zip", "deb", "apt-key", "apt-source"}
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != required:
            raise LockError("every artifact must contain exactly id/version/url/sha256/format/evidence")
        if not all(isinstance(item[key], str) for key in required):
            raise LockError("artifact fields must be strings")
        artifact = {key: str(item[key]) for key in required}
        identifier = artifact["id"]
        if not ARTIFACT_ID.fullmatch(identifier) or identifier in result:
            raise LockError(f"invalid or duplicate artifact id: {identifier!r}")
        parsed = urllib.parse.urlsplit(artifact["url"])
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise LockError(f"artifact URL must be credential-free HTTPS: {identifier}")
        if parsed.fragment:
            raise LockError(f"artifact URL must not contain a fragment: {identifier}")
        if not SHA256.fullmatch(artifact["sha256"]):
            raise LockError(f"artifact has invalid SHA-256: {identifier}")
        if artifact["format"] not in allowed_formats:
            raise LockError(f"artifact has unsupported format: {identifier}")
        if not artifact["version"] or not artifact["evidence"]:
            raise LockError(f"artifact lacks version/evidence: {identifier}")
        result[identifier] = artifact
    return result


def validate_npm_lock() -> list[str]:
    errors: list[str] = []
    lock_path = SOFTWARE / "npm-globals.lock.json"
    raw = load_json(lock_path)
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        return ["npm globals lock has unsupported schema"]
    packages = raw.get("packages")
    if not isinstance(packages, list) or not packages:
        return ["npm globals lock has no packages"]
    locked: dict[str, str] = {}
    for item in packages:
        if not isinstance(item, dict) or set(item) != {"name", "version", "integrity"}:
            errors.append("npm lock entries must contain exactly name/version/integrity")
            continue
        name, version, integrity = item["name"], item["version"], item["integrity"]
        if not all(isinstance(value, str) and value for value in (name, version, integrity)):
            errors.append("npm lock entry fields must be nonempty strings")
            continue
        spec = f"{name}@{version}"
        if spec in locked:
            errors.append(f"duplicate npm lock entry: {spec}")
        if not integrity.startswith("sha512-"):
            errors.append(f"npm lock entry lacks sha512 integrity: {spec}")
        locked[spec] = integrity
    requested = {
        line.strip()
        for line in (ROOT / "system/packages/npm-globals.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    if requested != set(locked):
        errors.append(
            "npm globals and integrity lock differ: "
            f"missing={sorted(requested - set(locked))}, extra={sorted(set(locked) - requested)}"
        )
    return errors


def validate_images() -> list[str]:
    errors: list[str] = []
    raw = load_json(SOFTWARE / "images.lock.json")
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        return ["OCI image lock has unsupported schema"]
    if raw.get("supported_platforms") != ["linux/amd64", "linux/arm64"]:
        errors.append("OCI lock must support exactly linux/amd64 and linux/arm64")
    images = raw.get("images")
    if not isinstance(images, list) or not images:
        return errors + ["OCI image lock has no images"]
    identifiers: set[str] = set()
    selected: dict[str, set[str]] = {"amd64": set(), "arm64": set()}
    roles: dict[str, dict[str, int]] = {
        "amd64": {"openclaw-sandbox": 0, "sagemath": 0, "zotero-translation-server": 0},
        "arm64": {"openclaw-sandbox": 0, "sagemath": 0, "zotero-translation-server": 0},
    }
    for image in images:
        if not isinstance(image, dict):
            errors.append("OCI image entries must be objects")
            continue
        required = {"id", "roles", "repository", "reference", "index_digest", "platforms", "evidence"}
        if set(image) != required:
            errors.append(f"OCI image entry has unexpected fields: {image.get('id', '?')}")
            continue
        identifier = image.get("id")
        reference = image.get("reference")
        repository = image.get("repository")
        index_digest = image.get("index_digest")
        platforms = image.get("platforms")
        image_roles = image.get("roles")
        if not isinstance(identifier, str) or not ARTIFACT_ID.fullmatch(identifier) or identifier in identifiers:
            errors.append(f"invalid or duplicate OCI image id: {identifier!r}")
            continue
        identifiers.add(identifier)
        match = OCI_REFERENCE.fullmatch(reference) if isinstance(reference, str) else None
        if not match or match.group(1) != repository or match.group(2) != index_digest:
            errors.append(f"OCI image is not pinned to its declared digest: {identifier}")
        if isinstance(reference, str) and ":latest" in reference:
            errors.append(f"mutable latest tag is forbidden: {identifier}")
        if not isinstance(index_digest, str) or not OCI_DIGEST.fullmatch(index_digest):
            errors.append(f"invalid OCI index digest: {identifier}")
        if not isinstance(platforms, dict) or not platforms:
            errors.append(f"OCI image has no platforms: {identifier}")
            continue
        if not isinstance(image_roles, list) or not image_roles or not all(isinstance(role, str) for role in image_roles):
            errors.append(f"OCI image has invalid roles: {identifier}")
            continue
        for platform_name, manifest_digest in platforms.items():
            if platform_name not in {"linux/amd64", "linux/arm64"}:
                errors.append(f"unsupported OCI platform {platform_name}: {identifier}")
                continue
            if not isinstance(manifest_digest, str) or not OCI_DIGEST.fullmatch(manifest_digest):
                errors.append(f"invalid platform manifest digest {platform_name}: {identifier}")
            arch = platform_name.split("/", 1)[1]
            selected[arch].add(str(reference))
            for role in image_roles:
                if role in roles[arch]:
                    roles[arch][role] += 1
    for arch, counts in roles.items():
        for role, count in counts.items():
            if count != 1:
                errors.append(f"{arch} must select exactly one {role} image (found {count})")

    text_entries: dict[str, set[str]] = {"amd64": set(), "arm64": set()}
    for line in (ROOT / "system/packages/docker-images.txt").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            reference, condition = stripped.split("|", 1)
        except ValueError:
            errors.append(f"invalid docker-images.txt line: {stripped}")
            continue
        if not OCI_REFERENCE.fullmatch(reference) or ":latest" in reference:
            errors.append(f"docker-images.txt contains a mutable/invalid reference: {reference}")
        if condition == "any":
            text_entries["amd64"].add(reference)
            text_entries["arm64"].add(reference)
        elif condition in text_entries:
            text_entries[condition].add(reference)
        else:
            errors.append(f"docker-images.txt contains unsupported architecture: {condition}")
    for arch in selected:
        if selected[arch] != text_entries[arch]:
            errors.append(f"docker-images.txt and OCI lock differ for {arch}")

    compatibility = load_json(ROOT / "system/openclaw/compatibility.lock.json")
    sandbox_reference = None
    if isinstance(compatibility, dict):
        sandbox = compatibility.get("sandbox")
        if isinstance(sandbox, dict):
            sandbox_reference = sandbox.get("image")
    locked_sandbox = next(
        (image["reference"] for image in images if isinstance(image, dict) and image.get("id") == "openclaw-sandbox"),
        None,
    )
    if sandbox_reference != locked_sandbox:
        errors.append("OpenClaw compatibility and OCI image locks disagree")
    return errors


# An unresolved artifact of a component that the operator turned off with its
# SKIP_* flag set to "1" does not block a complete release.
SKIPPABLE_ARTIFACTS = {"grok-artifact": "SKIP_GROK"}


def skipped_flags(environment: dict[str, str] | None = None) -> frozenset[str]:
    environment = os.environ if environment is None else environment
    return frozenset(
        flag for flag in SKIPPABLE_ARTIFACTS.values() if environment.get(flag) == "1"
    )


def validate_profile(
    arch: str, require_complete: bool = False, skipped: frozenset[str] = frozenset()
) -> list[str]:
    errors: list[str] = []
    profile_data = load_profile(arch)
    host = profile_data.get("host")
    canonical = canonical_arch(arch)
    expected_platform = f"linux/{canonical}"
    if profile_data.get("schema_version") != 1:
        errors.append("platform lock has unsupported schema")
    if not isinstance(host, dict) or host != {
        "id": "ubuntu",
        "version_id": "24.04",
        "architecture": canonical,
        "platform": expected_platform,
    }:
        errors.append(f"platform lock host does not exactly describe Ubuntu 24.04 {canonical}")
    qualification = profile_data.get("qualification")
    if (
        not isinstance(qualification, dict)
        or set(qualification) != {"state", "evidence"}
        or qualification.get("state") not in {"pending-clean-host", "qualified"}
        or not isinstance(qualification.get("evidence"), str)
        or not qualification.get("evidence")
    ):
        errors.append("platform lock has invalid qualification metadata")
    elif require_complete and qualification["state"] != "qualified":
        errors.append(
            f"platform has not passed the clean-host release gate: {qualification['state']}"
        )
    manifests = profile_data.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        errors.append("platform lock has no manifest digests")
    else:
        seen: set[str] = set()
        for item in manifests:
            if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
                errors.append("manifest entries must contain exactly path/sha256")
                continue
            relative, expected = item.get("path"), item.get("sha256")
            if not isinstance(relative, str) or relative in seen:
                errors.append(f"invalid or duplicate manifest path: {relative!r}")
                continue
            seen.add(relative)
            if not isinstance(expected, str) or not SHA256.fullmatch(expected):
                errors.append(f"invalid manifest digest: {relative}")
                continue
            try:
                actual = sha256_file(checked_repo_path(relative))
            except LockError as exc:
                errors.append(str(exc))
                continue
            if actual != expected:
                errors.append(f"manifest digest mismatch: {relative}: expected {expected}, got {actual}")
    try:
        artifact_map(profile_data)
    except LockError as exc:
        errors.append(str(exc))
    cli_versions = profile_data.get("cli_versions")
    if not isinstance(cli_versions, dict) or not cli_versions or not all(
        isinstance(key, str) and isinstance(value, str) and value
        for key, value in cli_versions.items()
    ):
        errors.append("platform lock has invalid CLI versions")
    unresolved = profile_data.get("unresolved")
    if not isinstance(unresolved, list):
        errors.append("platform lock unresolved field must be a list")
    else:
        for item in unresolved:
            if not isinstance(item, dict) or set(item) != {"id", "status", "reason"}:
                errors.append("unresolved entries must contain exactly id/status/reason")
                continue
            if item.get("status") not in {"not-applicable", "unverified-artifact"}:
                errors.append(f"invalid unresolved status: {item.get('id', '?')}")
            if (
                require_complete
                and item.get("status") == "unverified-artifact"
                and SKIPPABLE_ARTIFACTS.get(item.get("id")) not in skipped
            ):
                errors.append(f"unresolved required artifact: {item.get('id')}: {item.get('reason')}")
    errors.extend(validate_npm_lock())
    errors.extend(validate_images())
    return errors


def get_artifact(arch: str, identifier: str) -> dict[str, str]:
    artifacts = artifact_map(load_profile(arch))
    try:
        return artifacts[identifier]
    except KeyError as exc:
        raise LockError(f"artifact is not locked for {canonical_arch(arch)}: {identifier}") from exc


class HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise LockError(f"artifact redirect is not HTTPS: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_artifact(arch: str, identifier: str, output: Path) -> None:
    artifact = get_artifact(arch, identifier)
    if output.exists() or output.is_symlink():
        raise LockError(f"refusing to overwrite artifact output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = output.with_name(f".{output.name}.part-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise LockError(f"temporary artifact path already exists: {temporary}")
    request = urllib.request.Request(
        artifact["url"],
        headers={"User-Agent": "coding-system-rebuild-lockctl/1"},
    )
    opener = urllib.request.build_opener(HttpsOnlyRedirectHandler())
    digest = hashlib.sha256()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as target, opener.open(request, timeout=120) as source:
            final_url = source.geturl()
            if urllib.parse.urlsplit(final_url).scheme != "https":
                raise LockError(f"artifact final URL is not HTTPS: {final_url}")
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        actual = digest.hexdigest()
        if actual != artifact["sha256"]:
            raise LockError(
                f"artifact digest mismatch for {identifier}: expected {artifact['sha256']}, got {actual}"
            )
        os.replace(temporary, output)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


# Artifact-locked CLIs: the cli_versions name and the artifact that installs it.
CLI_ARTIFACTS = {
    "agy": "antigravity-agy",
    "bun": "bun",
    "elan": "elan",
    "gh-teacher": "gh-teacher",
    "gprolog": "gprolog",
    "grok": "grok",
    "kimi": "kimi",
    "node": "node",
    "ollama": "ollama",
    "rustup": "rustup-init",
    "veracrypt": "veracrypt-console",
}
NUMERIC_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+")
MAX_PROMOTED_ARTIFACT = 4 * 1024 * 1024 * 1024


def version_tuple(value: str) -> tuple[int, ...]:
    if not NUMERIC_VERSION.fullmatch(value):
        raise ValueError(f"not a dotted numeric version: {value!r}")
    return tuple(int(part) for part in value.split("."))


def download_sha256(url: str) -> str:
    """SHA-256 of one bounded HTTPS download, streamed without keeping it."""
    request = urllib.request.Request(url, headers={"User-Agent": "coding-system-rebuild-lockctl/1"})
    opener = urllib.request.build_opener(HttpsOnlyRedirectHandler())
    digest = hashlib.sha256()
    total = 0
    with opener.open(request, timeout=120) as source:
        if urllib.parse.urlsplit(source.geturl()).scheme != "https":
            raise LockError(f"artifact final URL is not HTTPS: {source.geturl()}")
        for block in iter(lambda: source.read(1024 * 1024), b""):
            total += len(block)
            if total > MAX_PROMOTED_ARTIFACT:
                raise LockError(f"artifact download exceeds its bound: {url}")
            digest.update(block)
    return digest.hexdigest()


def promote_artifact(identifier: str, version: str, *, sha256_of=None, today: str | None = None) -> None:
    """Point one artifact at a newer release on every platform lock.

    Every platform's download is hashed before any lock changes, and only the
    artifact's own entry and its CLI floor are rewritten, byte for byte.
    """
    sha256_of = sha256_of or download_sha256
    today = today or datetime.date.today().isoformat()
    if not NUMERIC_VERSION.fullmatch(version):
        raise LockError(f"promoted version must be dotted numeric: {version!r}")
    planned = []
    for arch in ("amd64", "arm64"):
        artifact = get_artifact(arch, identifier)
        old = artifact["version"]
        if not NUMERIC_VERSION.fullmatch(old) or version_tuple(version) <= version_tuple(old):
            raise LockError(f"{identifier} {version} is not newer than the locked {old}")
        if old not in artifact["url"]:
            raise LockError(f"{identifier} URL does not carry its version")
        url = artifact["url"].replace(old, version)
        planned.append((arch, artifact, url, sha256_of(url)))
    cli = next((name for name, artifact_id in CLI_ARTIFACTS.items() if artifact_id == identifier), None)
    for arch, artifact, url, digest in planned:
        path = profile_path(arch)
        text = path.read_text(encoding="utf-8")
        start = text.index(f'"id": {json.dumps(identifier)}')
        end = text.index("}", start)
        block = text[start:end]
        evidence = (
            f"{identifier} {version}: HTTPS download hashed on {today}, when a backup "
            "found this version installed on the reference host"
        )
        if artifact["evidence"].startswith("UNVERIFIED"):
            evidence = f"UNVERIFIED — {evidence}; the vendor publishes no independent checksum"
        for field, value in (("version", version), ("url", url), ("sha256", digest), ("evidence", evidence)):
            current = f'"{field}": {json.dumps(artifact[field], ensure_ascii=False)}'
            if block.count(current) != 1:
                raise LockError(f"{identifier} lock entry has an unexpected layout")
            block = block.replace(current, f'"{field}": {json.dumps(value, ensure_ascii=False)}')
        text = text[:start] + block + text[end:]
        floor = json.loads(text)["cli_versions"].get(cli) if cli else None
        if floor is not None:
            current = f"    {json.dumps(cli)}: {json.dumps(floor)}"
            if text.count(current) != 1:
                raise LockError(f"{cli} CLI floor has an unexpected layout")
            text = text.replace(current, f"    {json.dumps(cli)}: {json.dumps(version)}")
        temporary = path.with_name(f".{path.name}.promote-{os.getpid()}")
        temporary.write_text(text, encoding="utf-8")
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)


# openclaw moves only with the OpenClaw compatibility tuple, never on its own.
NPM_TUPLE_MANAGED = frozenset({"openclaw"})


def npm_registry_integrity(name: str, version: str) -> str:
    """The sha512 integrity that the npm registry publishes for one release."""
    url = (
        "https://registry.npmjs.org/"
        + urllib.parse.quote(name, safe="@/")
        + "/"
        + urllib.parse.quote(version, safe="")
    )
    request = urllib.request.Request(
        url, headers={"User-Agent": "coding-system-rebuild-lockctl/1", "Accept": "application/json"}
    )
    opener = urllib.request.build_opener(HttpsOnlyRedirectHandler())
    with opener.open(request, timeout=60) as response:
        document = json.loads(response.read(8 * 1024 * 1024))
    dist = document.get("dist") if isinstance(document, dict) else None
    integrity = dist.get("integrity") if isinstance(dist, dict) else None
    if (
        document.get("name") != name
        or document.get("version") != version
        or not isinstance(integrity, str)
        or not integrity.startswith("sha512-")
    ):
        raise LockError(f"npm registry gave no sha512 integrity for {name}@{version}")
    return integrity


def promote_npm(name: str, version: str, *, integrity_of=None, today: str | None = None) -> None:
    """Move one locked npm global to a newer release and rebind its digests.

    The request list, the integrity lock and both platform locks' manifest
    digests change together, only after the registry answered.
    """
    integrity_of = integrity_of or npm_registry_integrity
    today = today or datetime.date.today().isoformat()
    if name in NPM_TUPLE_MANAGED:
        raise LockError(f"{name} moves only with its compatibility tuple")
    lock_path = SOFTWARE / "npm-globals.lock.json"
    requested_path = ROOT / "system/packages/npm-globals.txt"
    lock_text = lock_path.read_text(encoding="utf-8")
    lock = json.loads(lock_text)
    if json.dumps(lock, indent=2) + "\n" != lock_text:
        raise LockError("npm globals lock has an unexpected layout")
    entry = next((item for item in lock["packages"] if item.get("name") == name), None)
    if entry is None:
        raise LockError(f"{name} is not a locked npm global")
    old = entry["version"]
    if (
        not NUMERIC_VERSION.fullmatch(version)
        or not NUMERIC_VERSION.fullmatch(old)
        or version_tuple(version) <= version_tuple(old)
    ):
        raise LockError(f"{name} {version} is not newer than the locked {old}")
    integrity = integrity_of(name, version)
    entry.update(version=version, integrity=integrity)
    lock["resolved_at"] = f"{today}T00:00:00Z"
    new_lock = json.dumps(lock, indent=2) + "\n"
    requested = requested_path.read_text(encoding="utf-8")
    if f"\n{name}@{old}\n" not in f"\n{requested}":
        raise LockError(f"{name}@{old} is not requested in npm-globals.txt")
    new_requested = f"\n{requested}".replace(f"\n{name}@{old}\n", f"\n{name}@{version}\n", 1)[1:]
    rewrites = {lock_path: new_lock, requested_path: new_requested}
    old_digests = {
        "system/software/npm-globals.lock.json": hashlib.sha256(lock_text.encode()).hexdigest(),
        "system/packages/npm-globals.txt": hashlib.sha256(requested.encode()).hexdigest(),
    }
    new_digests = {
        "system/software/npm-globals.lock.json": hashlib.sha256(new_lock.encode()).hexdigest(),
        "system/packages/npm-globals.txt": hashlib.sha256(new_requested.encode()).hexdigest(),
    }
    for arch in ("amd64", "arm64"):
        path = profile_path(arch)
        text = rewrites.get(path) or path.read_text(encoding="utf-8")
        for relative, digest in old_digests.items():
            current = f'{{"path": "{relative}", "sha256": "{digest}"}}'
            if text.count(current) != 1:
                raise LockError(f"{arch} platform lock does not bind {relative} as expected")
            text = text.replace(current, f'{{"path": "{relative}", "sha256": "{new_digests[relative]}"}}')
        rewrites[path] = text
    for path, text in rewrites.items():
        temporary = path.with_name(f".{path.name}.promote-{os.getpid()}")
        temporary.write_text(text, encoding="utf-8")
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)


def npm_integrity(spec: str) -> str:
    raw = load_json(SOFTWARE / "npm-globals.lock.json")
    if not isinstance(raw, dict) or not isinstance(raw.get("packages"), list):
        raise LockError("invalid npm globals lock")
    for package in raw["packages"]:
        if isinstance(package, dict) and f"{package.get('name')}@{package.get('version')}" == spec:
            integrity = package.get("integrity")
            if isinstance(integrity, str):
                return integrity
    raise LockError(f"npm package is not integrity-locked: {spec}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", default=platform.machine(), help="host architecture")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate", help="validate all checked-in locks")
    validate.add_argument("--require-complete", action="store_true")
    artifact = subparsers.add_parser("artifact", help="print one locked artifact field")
    artifact.add_argument("identifier")
    artifact.add_argument("field", choices=["id", "version", "url", "sha256", "format", "evidence"])
    fetch = subparsers.add_parser("fetch", help="download and SHA-256 verify one artifact")
    fetch.add_argument("identifier")
    fetch.add_argument("output", type=Path)
    promote = subparsers.add_parser(
        "promote", help="point an artifact at a newer release, hashing each platform download"
    )
    promote.add_argument("identifier")
    promote.add_argument("version")
    npm = subparsers.add_parser("npm-integrity", help="print the locked npm integrity")
    npm.add_argument("spec")
    subparsers.add_parser("platform", help="print canonical linux platform")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        arch = canonical_arch(args.arch)
        if args.command == "validate":
            skipped = skipped_flags()
            errors = validate_profile(
                arch, require_complete=args.require_complete, skipped=skipped
            )
            if errors:
                for error in errors:
                    prefix = (
                        "ARTIFACT_UNAVAILABLE"
                        if error.startswith(
                            (
                                "platform has not passed the clean-host release gate:",
                                "unresolved required artifact:",
                            )
                        )
                        else "LOCK FAIL"
                    )
                    print(f"{prefix}: {error}", file=sys.stderr)
                return 2
            profile_data = load_profile(arch)
            unresolved = profile_data.get("unresolved", [])
            print(f"software lock: valid for ubuntu-24.04/{arch}")
            for item in unresolved if isinstance(unresolved, list) else []:
                if isinstance(item, dict):
                    flag = SKIPPABLE_ARTIFACTS.get(item.get("id"))
                    note = f" (optional: {flag}=1)" if flag in skipped else ""
                    print(f"software lock: {item.get('status')}: {item.get('id')}{note}")
            return 0
        if args.command == "artifact":
            print(get_artifact(arch, args.identifier)[args.field])
            return 0
        if args.command == "fetch":
            fetch_artifact(arch, args.identifier, args.output)
            print(args.output)
            return 0
        if args.command == "promote":
            promote_artifact(args.identifier, args.version)
            print(f"promoted {args.identifier} to {args.version}")
            return 0
        if args.command == "npm-integrity":
            print(npm_integrity(args.spec))
            return 0
        if args.command == "platform":
            print(f"linux/{arch}")
            return 0
    except (LockError, OSError, urllib.error.URLError) as exc:
        print(f"lockctl: {exc}", file=sys.stderr)
        return 2
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
