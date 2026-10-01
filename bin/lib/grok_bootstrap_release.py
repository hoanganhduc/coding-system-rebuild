#!/usr/bin/env python3
"""Closed metadata and artifact validation for Grok bootstrap releases."""

from __future__ import annotations

import base64
import binascii
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
from typing import Any
from urllib.parse import quote, urlparse


SCHEMA = "grok-bootstrap-release-lock.v1"
REPOSITORY = "hoanganhduc/coding-system-rebuild"
RELEASE_URL_ROOT = f"https://github.com/{REPOSITORY}/releases/download"
MANIFEST_SCHEMA = "grok-bootstrap-manifest-v1"
AUTHORIZATION_SCHEMA = "grok-bootstrap-release-authorization-v1"
AUTHORIZATION_IDENTITY_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
AUTHORIZATION_NAMES = (
    "release-authorization.json",
    "release-authorization.sig",
)
BUILD_WORKFLOW = ".github/workflows/grok-bootstrap-build.yml"
DEFAULT_BRANCH_REF = "refs/heads/main"
DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
RELEASE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
TAG_RE = re.compile(r"^grok-bootstrap-v[0-9][0-9A-Za-z.+_-]{0,126}$")
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+~_-]{0,127}$")
FILE_LINE_RE = re.compile(
    r"^file=(?:0644|0755):[0-9a-f]{64}:([A-Za-z0-9._/-]+)$"
)
SHA256_RE = RELEASE_ID_RE
ARCHITECTURES = ("amd64", "arm64")
SIGNED_NAMES = (
    "dispatcher.pyz",
    "release-manifest.sig",
    "release-manifest.txt",
)
MAX_ARTIFACT_SIZE = 128 * 1024 * 1024
MAX_MANIFEST_SIZE = 1024 * 1024
MAX_DEBIAN_TAR_SIZE = 64 * 1024 * 1024
FIXED_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
}


class ReleaseError(RuntimeError):
    """A release cannot satisfy the closed Grok bootstrap contract."""


class ArtifactUnavailable(ReleaseError):
    """The release lock is valid but its immutable artifacts are not published."""


def core_artifact_names(version: str) -> tuple[str, ...]:
    return (
        *SIGNED_NAMES,
        *(f"grok-bootstrap_{version}_{architecture}.deb" for architecture in ARCHITECTURES),
    )


def release_artifact_names(version: str) -> tuple[str, ...]:
    return (*core_artifact_names(version), *AUTHORIZATION_NAMES)


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise ReleaseError(f"{label} has an invalid field set")
    return value


def _bounded_text(value: Any, label: str, maximum: int = 1024) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise ReleaseError(f"{label} is invalid")
    return value


def _validate_trust_anchor(value: Any) -> dict[str, str]:
    anchor = _exact_keys(value, {"key_id", "public_key_hex"}, "trust anchor")
    key_id = _bounded_text(anchor["key_id"], "trust-anchor key id", 64)
    public_key_hex = _bounded_text(
        anchor["public_key_hex"], "trust-anchor public key", 64
    )
    if KEY_ID_RE.fullmatch(key_id) is None or SHA256_RE.fullmatch(public_key_hex) is None:
        raise ReleaseError("trust anchor is invalid")
    return {"key_id": key_id, "public_key_hex": public_key_hex}


def _validate_authorization_anchor(value: Any) -> dict[str, str]:
    anchor = _exact_keys(
        value, {"identity", "namespace", "public_key"}, "release authorization anchor"
    )
    identity = _bounded_text(anchor["identity"], "authorization identity", 64)
    namespace = _bounded_text(anchor["namespace"], "authorization namespace", 64)
    public_key = _bounded_text(anchor["public_key"], "authorization public key", 256)
    parts = public_key.split(" ")
    if (
        AUTHORIZATION_IDENTITY_RE.fullmatch(identity) is None
        or AUTHORIZATION_IDENTITY_RE.fullmatch(namespace) is None
        or len(parts) != 2
        or parts[0] != "ssh-ed25519"
    ):
        raise ReleaseError("release authorization anchor is invalid")
    try:
        wire = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ReleaseError("release authorization anchor is invalid") from exc
    expected_prefix = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
    if len(wire) != len(expected_prefix) + 32 or not wire.startswith(expected_prefix):
        raise ReleaseError("release authorization anchor is invalid")
    return {"identity": identity, "namespace": namespace, "public_key": public_key}


def _release_url(tag: str, name: str) -> str:
    return f"{RELEASE_URL_ROOT}/{quote(tag, safe='._+-')}/{quote(name, safe='._+-')}"


def _validate_artifact_spec(value: Any, *, tag: str, name: str) -> dict[str, Any]:
    artifact = _exact_keys(value, {"name", "sha256", "size", "url"}, name)
    if artifact["name"] != name:
        raise ReleaseError(f"artifact name differs from its lock key: {name}")
    digest = _bounded_text(artifact["sha256"], f"{name} SHA-256", 64)
    if SHA256_RE.fullmatch(digest) is None:
        raise ReleaseError(f"{name} SHA-256 is invalid")
    size = artifact["size"]
    if type(size) is not int or not 0 < size <= MAX_ARTIFACT_SIZE:
        raise ReleaseError(f"{name} size is invalid")
    url = _bounded_text(artifact["url"], f"{name} URL", 2048)
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
        raise ReleaseError(f"{name} URL is invalid")
    if url != _release_url(tag, name):
        raise ReleaseError(f"{name} URL is not the repository-controlled release asset")
    return {"name": name, "sha256": digest, "size": size, "url": url}


def _validate_pending_intent(value: Any) -> dict[str, Any]:
    intent = _exact_keys(
        value,
        {
            "authorization_schema",
            "minimum_package_version",
            "operation",
            "required_architectures",
            "signed_application_id",
            "workflow_ref",
        },
        "pending release intent",
    )
    minimum = _bounded_text(
        intent["minimum_package_version"], "pending minimum package version", 128
    )
    release_id = _bounded_text(
        intent["signed_application_id"], "pending signed application id", 64
    )
    if (
        intent["operation"] != "initial-qualification"
        or intent["authorization_schema"] != AUTHORIZATION_SCHEMA
        or intent["workflow_ref"] != DEFAULT_BRANCH_REF
        or intent["required_architectures"] != list(ARCHITECTURES)
        or VERSION_RE.fullmatch(minimum) is None
        or RELEASE_ID_RE.fullmatch(release_id) is None
    ):
        raise ReleaseError("pending release intent is invalid")
    return {
        "authorization_schema": AUTHORIZATION_SCHEMA,
        "minimum_package_version": minimum,
        "operation": "initial-qualification",
        "required_architectures": list(ARCHITECTURES),
        "signed_application_id": release_id,
        "workflow_ref": DEFAULT_BRANCH_REF,
    }


def validate_lock(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReleaseError("release lock must be a JSON object")
    common = {
        "$schema",
        "release_authorization_anchor",
        "schema_version",
        "state",
        "trust_anchor",
    }
    state = value.get("state")
    if state == "pending-publication":
        lock = _exact_keys(
            value, common | {"pending_intent", "pending_reason"}, "pending release lock"
        )
    elif state == "qualified":
        lock = _exact_keys(value, common | {"release"}, "qualified release lock")
    else:
        raise ReleaseError("release-lock state is invalid")
    if lock["$schema"] != "release-lock.schema.json" or lock["schema_version"] != SCHEMA:
        raise ReleaseError("release-lock schema identity is invalid")
    anchor = _validate_trust_anchor(lock["trust_anchor"])
    authorization_anchor = _validate_authorization_anchor(
        lock["release_authorization_anchor"]
    )
    if state == "pending-publication":
        reason = _bounded_text(lock["pending_reason"], "pending reason", 2048)
        intent = _validate_pending_intent(lock["pending_intent"])
        return {
            "$schema": lock["$schema"],
            "schema_version": SCHEMA,
            "state": state,
            "release_authorization_anchor": authorization_anchor,
            "trust_anchor": anchor,
            "pending_intent": intent,
            "pending_reason": reason,
        }

    release = _exact_keys(
        lock["release"],
        {
            "artifacts",
            "authorization_id",
            "package_version",
            "signed_application_id",
            "source_commit",
            "tag",
        },
        "qualified release",
    )
    tag = _bounded_text(release["tag"], "release tag", 128)
    version = _bounded_text(release["package_version"], "package version", 128)
    source_commit = _bounded_text(release["source_commit"], "source commit", 40)
    release_id = _bounded_text(
        release["signed_application_id"], "signed application id", 64
    )
    authorization_id = _bounded_text(
        release["authorization_id"], "release authorization id", 64
    )
    if TAG_RE.fullmatch(tag) is None:
        raise ReleaseError("release tag is invalid")
    if VERSION_RE.fullmatch(version) is None:
        raise ReleaseError("package version is invalid")
    if COMMIT_RE.fullmatch(source_commit) is None:
        raise ReleaseError("source commit is invalid")
    if (
        RELEASE_ID_RE.fullmatch(release_id) is None
        or SHA256_RE.fullmatch(authorization_id) is None
    ):
        raise ReleaseError("signed application id is invalid")
    expected_names = set(release_artifact_names(version))
    artifacts = _exact_keys(release["artifacts"], expected_names, "release artifacts")
    normalized_artifacts = {
        name: _validate_artifact_spec(artifacts[name], tag=tag, name=name)
        for name in sorted(expected_names)
    }
    return {
        "$schema": lock["$schema"],
        "schema_version": SCHEMA,
        "state": state,
        "release_authorization_anchor": authorization_anchor,
        "trust_anchor": anchor,
        "release": {
            "artifacts": normalized_artifacts,
            "authorization_id": authorization_id,
            "package_version": version,
            "signed_application_id": release_id,
            "source_commit": source_commit,
            "tag": tag,
        },
    }


def load_lock(path: Path, *, require_qualified: bool = False) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if len(raw) > 1024 * 1024:
            raise ReleaseError("release lock is too large")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("release lock is unavailable or invalid") from exc
    lock = validate_lock(value)
    if require_qualified and lock["state"] != "qualified":
        raise ArtifactUnavailable(lock["pending_reason"])
    return lock


SNAPSHOT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _same_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return all(getattr(left, field) == getattr(right, field) for field in SNAPSHOT_FIELDS)


def _descriptor_bytes(descriptor: int, *, maximum: int, label: str) -> bytes:
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or not 0 < opened.st_size <= maximum
    ):
        raise ReleaseError(f"{label} metadata is unsafe")
    chunks: list[bytes] = []
    offset = 0
    while offset < opened.st_size:
        try:
            chunk = os.pread(descriptor, min(64 * 1024, opened.st_size - offset), offset)
        except InterruptedError:
            continue
        if not chunk:
            raise ReleaseError(f"{label} changed while read")
        chunks.append(chunk)
        offset += len(chunk)
    if not _same_snapshot(opened, os.fstat(descriptor)):
        raise ReleaseError(f"{label} changed while read")
    return b"".join(chunks)


def sha256_descriptor(descriptor: int, *, label: str = "artifact") -> tuple[int, str]:
    raw = _descriptor_bytes(descriptor, maximum=MAX_ARTIFACT_SIZE, label=label)
    return len(raw), hashlib.sha256(raw).hexdigest()


def open_verified_artifact(
    path: Path, specification: dict[str, Any] | None = None
) -> int:
    try:
        information = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as exc:
        raise ReleaseError(f"artifact cannot be opened safely: {path.name}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or not _same_snapshot(information, opened)
            or opened.st_nlink != 1
            or not 0 < opened.st_size <= MAX_ARTIFACT_SIZE
        ):
            raise ReleaseError(f"artifact metadata is unsafe: {path.name}")
        if specification is not None:
            verify_artifact_descriptor(descriptor, specification, label=path.name)
        named_after = path.stat(follow_symlinks=False)
        if not _same_snapshot(opened, os.fstat(descriptor)) or not _same_snapshot(
            opened, named_after
        ):
            raise ReleaseError(f"artifact changed while opened: {path.name}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_artifact_set(
    directory: Path,
    names: set[str] | tuple[str, ...],
    specifications: dict[str, dict[str, Any]] | None = None,
) -> tuple[int, dict[str, int]]:
    expected = set(names)
    try:
        named = directory.lstat()
        directory_fd = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as exc:
        raise ReleaseError("artifact directory cannot be opened safely") from exc
    descriptors: dict[str, int] = {}
    try:
        opened = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(named.st_mode)
            or not _same_snapshot(named, opened)
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            raise ReleaseError("artifact directory metadata is unsafe")
        with os.scandir(directory_fd) as iterator:
            actual = {entry.name for entry in iterator}
        if actual != expected:
            raise ReleaseError("artifact directory inventory is not closed")
        for name in sorted(expected):
            if not name or "/" in name or name in {".", ".."}:
                raise ReleaseError("artifact name is unsafe")
            try:
                child_named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise ReleaseError(f"artifact cannot be opened safely: {name}") from exc
            child_opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(child_named.st_mode)
                or not _same_snapshot(child_named, child_opened)
                or child_opened.st_nlink != 1
                or not 0 < child_opened.st_size <= MAX_ARTIFACT_SIZE
            ):
                os.close(descriptor)
                raise ReleaseError(f"artifact metadata is unsafe: {name}")
            descriptors[name] = descriptor
            if specifications is not None:
                verify_artifact_descriptor(
                    descriptor, specifications[name], label=name
                )
        if not _same_snapshot(opened, os.fstat(directory_fd)):
            raise ReleaseError("artifact directory changed while opened")
        return directory_fd, descriptors
    except BaseException:
        for descriptor in descriptors.values():
            os.close(descriptor)
        os.close(directory_fd)
        raise


def sha256_file(path: Path) -> tuple[int, str]:
    descriptor = open_verified_artifact(path)
    try:
        return sha256_descriptor(descriptor, label=path.name)
    finally:
        os.close(descriptor)


def verify_artifact(path: Path, specification: dict[str, Any]) -> None:
    size, digest = sha256_file(path)
    if size != specification["size"] or digest != specification["sha256"]:
        raise ReleaseError(f"artifact differs from its release lock: {path.name}")


def verify_artifact_descriptor(
    descriptor: int, specification: dict[str, Any], *, label: str
) -> None:
    size, digest = sha256_descriptor(descriptor, label=label)
    if size != specification["size"] or digest != specification["sha256"]:
        raise ReleaseError(f"artifact differs from its release lock: {label}")


def _manifest_values(raw: bytes) -> tuple[dict[str, str], list[str]]:
    if not raw or len(raw) > MAX_MANIFEST_SIZE or not raw.endswith(b"\n"):
        raise ReleaseError("signed dispatcher manifest is invalid")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ReleaseError("signed dispatcher manifest is invalid") from exc
    fixed_names = (
        "schema",
        "key_id",
        "release_id",
        "bundle_name",
        "bundle_size",
        "bundle_sha256",
        "file_count",
    )
    if len(lines) < len(fixed_names):
        raise ReleaseError("signed dispatcher manifest is incomplete")
    values: dict[str, str] = {}
    for index, name in enumerate(fixed_names):
        prefix = name + "="
        if not lines[index].startswith(prefix):
            raise ReleaseError("signed dispatcher manifest order is invalid")
        values[name] = lines[index][len(prefix) :]
    file_lines = lines[len(fixed_names) :]
    try:
        file_count = int(values["file_count"])
        bundle_size = int(values["bundle_size"])
    except ValueError as exc:
        raise ReleaseError("signed dispatcher manifest count is invalid") from exc
    if str(file_count) != values["file_count"] or str(bundle_size) != values["bundle_size"]:
        raise ReleaseError("signed dispatcher manifest number is noncanonical")
    if file_count != len(file_lines) or not 1 <= len(file_lines) <= 4096:
        raise ReleaseError("signed dispatcher file inventory is invalid")
    paths: list[str] = []
    for line in file_lines:
        match = FILE_LINE_RE.fullmatch(line)
        if match is None:
            raise ReleaseError("signed dispatcher file inventory is invalid")
        path = match.group(1)
        parts = path.split("/")
        if path.startswith("/") or path.endswith("/") or any(
            part in {"", ".", ".."} for part in parts
        ):
            raise ReleaseError("signed dispatcher file inventory is invalid")
        paths.append(path)
    if paths != sorted(paths) or len(paths) != len(set(paths)) or paths.count("__main__.py") != 1:
        raise ReleaseError("signed dispatcher file inventory is invalid")
    inventory = ("\n".join(file_lines) + "\n").encode("ascii")
    if hashlib.sha256(inventory).hexdigest() != values["release_id"]:
        raise ReleaseError("signed dispatcher release id is invalid")
    return values, file_lines


def _sealed_memfd(name: str, raw: bytes) -> int:
    try:
        descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise ReleaseError("signature-verification memory file write stalled")
            offset += written
        os.fsync(descriptor)
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except (AttributeError, OSError) as exc:
        if "descriptor" in locals():
            os.close(descriptor)
        raise ReleaseError("sealed signature-verification memory is unavailable") from exc


def _verify_ed25519(
    message: bytes,
    signature: bytes,
    public_key_hex: str,
    *,
    label: str,
    openssl: Path,
) -> None:
    if len(signature) != 64 or not openssl.is_absolute() or not openssl.is_file():
        raise ReleaseError(f"{label} signature material is invalid")
    descriptors = [
        _sealed_memfd("grok-public-key", DER_PREFIX + bytes.fromhex(public_key_hex)),
        _sealed_memfd("grok-signed-message", message),
        _sealed_memfd("grok-signature", signature),
    ]
    key_fd, message_fd, signature_fd = descriptors
    try:
        try:
            completed = subprocess.run(
                [
                    os.fspath(openssl),
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    f"/proc/self/fd/{key_fd}",
                    "-sigfile",
                    f"/proc/self/fd/{signature_fd}",
                    "-in",
                    f"/proc/self/fd/{message_fd}",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=tuple(descriptors),
                close_fds=True,
                env=FIXED_ENVIRONMENT,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ReleaseError(f"{label} signature verification failed") from exc
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    if (
        completed.returncode != 0
        or len(completed.stdout) > 4096
        or len(completed.stderr) > 4096
    ):
        raise ReleaseError(f"{label} signature is invalid")


def _verify_ssh_signature(
    message: bytes,
    signature: bytes,
    authorization_anchor: dict[str, str],
    *,
    ssh_keygen: Path = Path("/usr/bin/ssh-keygen"),
) -> None:
    if (
        not signature.startswith(b"-----BEGIN SSH SIGNATURE-----\n")
        or not signature.endswith(b"-----END SSH SIGNATURE-----\n")
        or len(signature) > 16 * 1024
        or not ssh_keygen.is_absolute()
        or not ssh_keygen.is_file()
    ):
        raise ReleaseError("release authorization signature material is invalid")
    allowed_signers = (
        f"{authorization_anchor['identity']} {authorization_anchor['public_key']}\n"
    ).encode("ascii")
    descriptors = [
        _sealed_memfd("grok-authorization-signers", allowed_signers),
        _sealed_memfd("grok-authorization-message", message),
        _sealed_memfd("grok-authorization-signature", signature),
    ]
    signers_fd, message_fd, signature_fd = descriptors
    try:
        try:
            completed = subprocess.run(
                [
                    os.fspath(ssh_keygen),
                    "-Y",
                    "verify",
                    "-f",
                    f"/proc/self/fd/{signers_fd}",
                    "-I",
                    authorization_anchor["identity"],
                    "-n",
                    authorization_anchor["namespace"],
                    "-s",
                    f"/proc/self/fd/{signature_fd}",
                ],
                stdin=message_fd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=tuple(descriptors),
                close_fds=True,
                env=FIXED_ENVIRONMENT,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ReleaseError("release authorization signature verification failed") from exc
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    if (
        completed.returncode != 0
        or len(completed.stdout) > 4096
        or len(completed.stderr) > 4096
    ):
        raise ReleaseError("release authorization signature is invalid")


def verify_signed_dispatcher_descriptors(
    descriptors: dict[str, int],
    *,
    key_id: str,
    public_key_hex: str,
    expected_release_id: str | None = None,
    openssl: Path = Path("/usr/bin/openssl"),
) -> str:
    if set(descriptors) != set(SIGNED_NAMES):
        raise ReleaseError("signed dispatcher descriptor inventory is not closed")
    manifest_raw = _descriptor_bytes(
        descriptors["release-manifest.txt"],
        maximum=MAX_MANIFEST_SIZE,
        label="signed dispatcher manifest",
    )
    bundle_raw = _descriptor_bytes(
        descriptors["dispatcher.pyz"],
        maximum=MAX_ARTIFACT_SIZE,
        label="signed dispatcher bundle",
    )
    signature_raw = _descriptor_bytes(
        descriptors["release-manifest.sig"],
        maximum=64,
        label="signed dispatcher signature",
    )
    values, _file_lines = _manifest_values(manifest_raw)
    if (
        values["schema"] != MANIFEST_SCHEMA
        or values["key_id"] != key_id
        or values["bundle_name"] != "dispatcher.pyz"
        or values["bundle_size"] != str(len(bundle_raw))
        or values["bundle_sha256"] != hashlib.sha256(bundle_raw).hexdigest()
        or RELEASE_ID_RE.fullmatch(values["release_id"]) is None
        or (expected_release_id is not None and values["release_id"] != expected_release_id)
    ):
        raise ReleaseError("signed dispatcher manifest identity is invalid")
    _verify_ed25519(
        manifest_raw,
        signature_raw,
        public_key_hex,
        label="signed dispatcher",
        openssl=openssl,
    )
    return values["release_id"]


def verify_signed_dispatcher(
    directory: Path,
    *,
    key_id: str,
    public_key_hex: str,
    expected_release_id: str | None = None,
    require_exact_inventory: bool = True,
    openssl: Path = Path("/usr/bin/openssl"),
) -> str:
    if require_exact_inventory:
        names = set(SIGNED_NAMES)
    else:
        try:
            names = {entry.name for entry in directory.iterdir()}
        except OSError as exc:
            raise ReleaseError("signed dispatcher directory is unavailable") from exc
        if not set(SIGNED_NAMES).issubset(names):
            raise ReleaseError("signed dispatcher directory inventory is not closed")
    directory_fd, all_descriptors = open_artifact_set(directory, names)
    try:
        signed = {name: all_descriptors[name] for name in SIGNED_NAMES}
        return verify_signed_dispatcher_descriptors(
            signed,
            key_id=key_id,
            public_key_hex=public_key_hex,
            expected_release_id=expected_release_id,
            openssl=openssl,
        )
    finally:
        for descriptor in all_descriptors.values():
            os.close(descriptor)
        os.close(directory_fd)


def _ar_members(raw: bytes) -> dict[str, bytes]:
    if not raw.startswith(b"!<arch>\n"):
        raise ReleaseError("Debian package ar header is invalid")
    offset = 8
    members: dict[str, bytes] = {}
    while offset < len(raw):
        if offset + 60 > len(raw):
            raise ReleaseError("Debian package ar inventory is invalid")
        header = raw[offset : offset + 60]
        offset += 60
        if header[58:60] != b"`\n":
            raise ReleaseError("Debian package ar inventory is invalid")
        try:
            raw_name = header[:16].decode("ascii").rstrip()
            name = raw_name[:-1] if raw_name.endswith("/") else raw_name
            member_size = int(header[48:58].decode("ascii").strip())
            owner = int(header[28:34].decode("ascii").strip() or "0")
            group = int(header[34:40].decode("ascii").strip() or "0")
            mode = int(header[40:48].decode("ascii").strip(), 8)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseError("Debian package ar inventory is invalid") from exc
        if (
            name not in {"debian-binary", "control.tar.gz", "data.tar.gz"}
            or name in members
            or member_size < 0
            or owner != 0
            or group != 0
            or mode != 0o100644
            or offset + member_size > len(raw)
        ):
            raise ReleaseError("Debian package ar inventory is invalid")
        members[name] = raw[offset : offset + member_size]
        offset += member_size
        if member_size % 2:
            if offset >= len(raw) or raw[offset : offset + 1] != b"\n":
                raise ReleaseError("Debian package ar alignment is invalid")
            offset += 1
    if list(members) != ["debian-binary", "control.tar.gz", "data.tar.gz"]:
        raise ReleaseError("Debian package ar inventory is not closed")
    if members["debian-binary"] != b"2.0\n":
        raise ReleaseError("Debian package format version is invalid")
    return members


def _bounded_gzip(raw: bytes, *, label: str) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
            result = stream.read(MAX_DEBIAN_TAR_SIZE + 1)
            extra = stream.read(1)
    except (OSError, EOFError) as exc:
        raise ReleaseError(f"{label} compression is invalid") from exc
    if len(result) > MAX_DEBIAN_TAR_SIZE or extra:
        raise ReleaseError(f"{label} exceeds its expanded-size bound")
    return result


def _normalized_tar_inventory(
    raw: bytes, *, label: str
) -> dict[str, tuple[tarfile.TarInfo, bytes | None]]:
    result: dict[str, tuple[tarfile.TarInfo, bytes | None]] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive.getmembers():
                name = member.name
                while name.startswith("./"):
                    name = name[2:]
                name = name.rstrip("/")
                if name == ".":
                    name = ""
                parts = name.split("/") if name else []
                if (
                    name in result
                    or any(part in {"", ".", ".."} for part in parts)
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname not in {"", "root"}
                    or member.gname not in {"", "root"}
                    or member.pax_headers
                    or not (member.isdir() or member.isreg())
                ):
                    raise ReleaseError(f"{label} inventory is unsafe")
                content: bytes | None = None
                if member.isreg():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ReleaseError(f"{label} file is unreadable")
                    content = stream.read(member.size + 1)
                    if len(content) != member.size:
                        raise ReleaseError(f"{label} file changed while read")
                result[name] = (member, content)
    except (tarfile.TarError, OSError) as exc:
        raise ReleaseError(f"{label} archive is invalid") from exc
    return result


def _expected_control(version: str, architecture: str, source_commit: str) -> bytes:
    return (
        f"Package: grok-bootstrap\n"
        f"Version: {version}\n"
        f"Architecture: {architecture}\n"
        "Section: admin\n"
        "Priority: optional\n"
        "Maintainer: Grok Bootstrap Maintainers <root@localhost>\n"
        "Depends: python3 (>= 3.10), binutils, libssl3t64 | libssl3\n"
        f"X-Grok-Source-Commit: {source_commit}\n"
        "Description: authenticated pre-import Grok release bootstrap\n"
        " Installs one closed package-owned bootstrap generation.\n"
    ).encode("ascii")


DEBIAN_PAYLOAD_SPEC = {
    "": ("directory", 0o755, 0),
    "usr": ("directory", 0o755, 0),
    "usr/lib": ("directory", 0o755, 0),
    "usr/lib/grok-bootstrap-package": ("directory", 0o555, 0),
    "usr/lib/grok-bootstrap-package/grok-bootstrap": (
        "file",
        0o555,
        16 * 1024 * 1024,
    ),
    "usr/lib/grok-bootstrap-package/grok-bootstrap-publisher.py": (
        "file",
        0o444,
        4 * 1024 * 1024,
    ),
    "usr/lib/grok-bootstrap-package/grok-bootstrap-publisher": (
        "file",
        0o555,
        16 * 1024,
    ),
    "usr/libexec": ("directory", 0o755, 0),
    "usr/libexec/grok-bootstrap-package": ("directory", 0o555, 0),
    "usr/libexec/grok-bootstrap-package/activate_package.py": (
        "file",
        0o444,
        4 * 1024 * 1024,
    ),
    "usr/libexec/grok-bootstrap-package/grok-bootstrap-package-activate": (
        "file",
        0o555,
        16 * 1024,
    ),
}


def validate_debian_package_descriptor(
    descriptor: int,
    *,
    version: str,
    architecture: str,
    source_commit: str,
    key_id: str,
    public_key_hex: str,
) -> None:
    raw = _descriptor_bytes(
        descriptor, maximum=MAX_ARTIFACT_SIZE, label="Debian package"
    )
    members = _ar_members(raw)
    control = _normalized_tar_inventory(
        _bounded_gzip(members["control.tar.gz"], label="Debian control archive"),
        label="Debian control archive",
    )
    if set(control) != {"", "control"}:
        raise ReleaseError(
            "Debian control inventory contains a maintainer script or unknown file"
        )
    root_info, _ = control[""]
    control_info, control_raw = control["control"]
    if (
        not root_info.isdir()
        or stat.S_IMODE(root_info.mode) != 0o755
        or not control_info.isreg()
        or stat.S_IMODE(control_info.mode) != 0o644
        or control_raw != _expected_control(version, architecture, source_commit)
    ):
        raise ReleaseError("Debian control metadata differs from the release identity")

    payload = _normalized_tar_inventory(
        _bounded_gzip(members["data.tar.gz"], label="Debian payload archive"),
        label="Debian payload archive",
    )
    if set(payload) != set(DEBIAN_PAYLOAD_SPEC):
        raise ReleaseError("Debian payload inventory is not closed")
    for name, (kind, mode, maximum) in DEBIAN_PAYLOAD_SPEC.items():
        information, content = payload[name]
        if (
            stat.S_IMODE(information.mode) != mode
            or (kind == "directory" and not information.isdir())
            or (kind == "directory" and information.size != 0)
            or (kind == "file" and not information.isreg())
            or (kind == "file" and (content is None or not 0 < len(content) <= maximum))
            or (kind == "file" and information.size != len(content or b""))
        ):
            raise ReleaseError(f"Debian payload metadata is invalid: {name or '/'}")
    native = payload["usr/lib/grok-bootstrap-package/grok-bootstrap"][1]
    assert native is not None
    if (
        native.count(key_id.encode("ascii")) != 1
        or native.count(public_key_hex.encode("ascii")) != 1
    ):
        raise ReleaseError("Debian native verifier does not embed the locked trust anchor")


def validate_debian_package(
    path: Path,
    *,
    version: str,
    architecture: str,
    source_commit: str,
    key_id: str,
    public_key_hex: str,
) -> None:
    descriptor = open_verified_artifact(path)
    try:
        validate_debian_package_descriptor(
            descriptor,
            version=version,
            architecture=architecture,
            source_commit=source_commit,
            key_id=key_id,
            public_key_hex=public_key_hex,
        )
    finally:
        os.close(descriptor)


def _core_authorization_records(
    artifacts: dict[str, dict[str, Any]], version: str
) -> dict[str, dict[str, Any]]:
    expected = set(core_artifact_names(version))
    if set(artifacts) != expected:
        raise ReleaseError("release authorization core artifact inventory is invalid")
    return {
        name: {
            "sha256": artifacts[name]["sha256"],
            "size": artifacts[name]["size"],
        }
        for name in sorted(expected)
    }


def release_authorization_payload(
    *,
    artifacts: dict[str, dict[str, Any]],
    package_version: str,
    signed_application_id: str,
    source_commit: str,
    tag: str,
    trust_anchor: dict[str, str],
    authorization_anchor: dict[str, str],
) -> dict[str, Any]:
    return {
        "architectures": list(ARCHITECTURES),
        "artifacts": _core_authorization_records(artifacts, package_version),
        "authorization_anchor": authorization_anchor,
        "build_workflow": BUILD_WORKFLOW,
        "package_version": package_version,
        "repository": REPOSITORY,
        "schema_version": AUTHORIZATION_SCHEMA,
        "signed_application_id": signed_application_id,
        "source_commit": source_commit,
        "tag": tag,
        "trust_anchor": trust_anchor,
        "workflow_ref": DEFAULT_BRANCH_REF,
    }


def verify_release_authorization_descriptors(
    descriptors: dict[str, int],
    *,
    artifacts: dict[str, dict[str, Any]],
    package_version: str,
    signed_application_id: str,
    source_commit: str,
    tag: str,
    trust_anchor: dict[str, str],
    authorization_anchor: dict[str, str],
    expected_authorization_id: str | None = None,
) -> str:
    if set(descriptors) != set(AUTHORIZATION_NAMES):
        raise ReleaseError("release authorization descriptor inventory is not closed")
    raw = _descriptor_bytes(
        descriptors["release-authorization.json"],
        maximum=MAX_MANIFEST_SIZE,
        label="release authorization",
    )
    signature = _descriptor_bytes(
        descriptors["release-authorization.sig"],
        maximum=16 * 1024,
        label="release authorization signature",
    )
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("release authorization is invalid") from exc
    expected = release_authorization_payload(
        artifacts=artifacts,
        package_version=package_version,
        signed_application_id=signed_application_id,
        source_commit=source_commit,
        tag=tag,
        trust_anchor=trust_anchor,
        authorization_anchor=authorization_anchor,
    )
    if value != expected or raw != canonical_json(expected):
        raise ReleaseError("release authorization does not bind the exact release")
    authorization_id = hashlib.sha256(raw).hexdigest()
    if (
        expected_authorization_id is not None
        and authorization_id != expected_authorization_id
    ):
        raise ReleaseError("release authorization identity differs from its lock")
    _verify_ssh_signature(raw, signature, authorization_anchor)
    return authorization_id


def artifact_record_descriptor(
    descriptor: int, *, tag: str, name: str
) -> dict[str, Any]:
    size, digest = sha256_descriptor(descriptor, label=name)
    return {
        "name": name,
        "sha256": digest,
        "size": size,
        "url": _release_url(tag, name),
    }


def artifact_record(path: Path, *, tag: str) -> dict[str, Any]:
    descriptor = open_verified_artifact(path)
    try:
        return artifact_record_descriptor(descriptor, tag=tag, name=path.name)
    finally:
        os.close(descriptor)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode(
        "ascii"
    )
