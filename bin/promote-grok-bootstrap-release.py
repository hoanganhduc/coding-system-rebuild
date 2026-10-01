#!/usr/bin/env python3
"""Prepare or validate an administratively authorized Grok bootstrap release."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))

from lib.grok_bootstrap_release import (
    ARCHITECTURES,
    AUTHORIZATION_NAMES,
    FIXED_ENVIRONMENT,
    SIGNED_NAMES,
    ReleaseError,
    artifact_record_descriptor,
    canonical_json,
    core_artifact_names,
    load_lock,
    open_artifact_set,
    release_artifact_names,
    release_authorization_payload,
    validate_debian_package_descriptor,
    validate_lock,
    verify_release_authorization_descriptors,
    verify_signed_dispatcher_descriptors,
)


TAG_RE = re.compile(r"^grok-bootstrap-v[0-9][0-9A-Za-z.+_-]{0,126}$")
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+~_-]{0,127}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--package-version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--emit-authorization-request",
        action="store_true",
        help="emit the canonical five-artifact authorization document for offline signing",
    )
    parser.add_argument(
        "--base-lock",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "system/grok-proxy/bootstrap/release.lock.json",
    )
    return parser.parse_args(argv)


def _validate_output(path: Path) -> None:
    if not path.is_absolute():
        raise ReleaseError("output must be absolute")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError("output parent is unavailable") from exc
    if parent != path.parent or path.exists() or path.is_symlink():
        raise ReleaseError("output path is unsafe or already exists")


def _validate_artifact_root(path: Path) -> Path:
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
        opened = resolved.lstat()
    except OSError as exc:
        raise ReleaseError("artifact directory is unavailable") from exc
    if (
        not path.is_absolute()
        or resolved != path
        or stat.S_ISLNK(named.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) & 0o022
    ):
        raise ReleaseError("artifact directory is unsafe")
    return resolved


def _require_initial_pending_intent(
    lock: dict[str, object], package_version: str
) -> dict[str, object]:
    if lock["state"] != "pending-publication":
        raise ReleaseError(
            "qualified-to-qualified promotion is forbidden; create and review an explicit pending transition"
        )
    intent = lock["pending_intent"]
    completed = subprocess.run(
        [
            "/usr/bin/dpkg",
            "--compare-versions",
            package_version,
            "ge",
            intent["minimum_package_version"],
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=FIXED_ENVIRONMENT,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0:
        raise ReleaseError("package version is below the pending intent minimum")
    return intent


def _release_material(
    arguments: argparse.Namespace,
) -> tuple[dict[str, object], dict[str, dict[str, object]], str]:
    if TAG_RE.fullmatch(arguments.tag) is None:
        raise ReleaseError("release tag is invalid")
    if VERSION_RE.fullmatch(arguments.package_version) is None:
        raise ReleaseError("package version is invalid")
    if COMMIT_RE.fullmatch(arguments.source_commit) is None:
        raise ReleaseError("source commit is invalid")
    root = _validate_artifact_root(arguments.artifact_dir)
    base_lock = load_lock(arguments.base_lock)
    intent = _require_initial_pending_intent(base_lock, arguments.package_version)
    anchor = base_lock["trust_anchor"]
    expected_names = (
        set(core_artifact_names(arguments.package_version))
        if arguments.emit_authorization_request
        else set(release_artifact_names(arguments.package_version))
    )
    directory_fd, descriptors = open_artifact_set(root, expected_names)
    try:
        signed_application_id = verify_signed_dispatcher_descriptors(
            {name: descriptors[name] for name in SIGNED_NAMES},
            key_id=anchor["key_id"],
            public_key_hex=anchor["public_key_hex"],
        )
        if signed_application_id != intent["signed_application_id"]:
            raise ReleaseError("signed dispatcher differs from the pending intent")
        for architecture in ARCHITECTURES:
            package_name = (
                f"grok-bootstrap_{arguments.package_version}_{architecture}.deb"
            )
            validate_debian_package_descriptor(
                descriptors[package_name],
                version=arguments.package_version,
                architecture=architecture,
                source_commit=arguments.source_commit,
                key_id=anchor["key_id"],
                public_key_hex=anchor["public_key_hex"],
            )
        records = {
            name: artifact_record_descriptor(
                descriptors[name], tag=arguments.tag, name=name
            )
            for name in sorted(expected_names)
        }
        core_records = {
            name: records[name]
            for name in core_artifact_names(arguments.package_version)
        }
        if arguments.emit_authorization_request:
            return base_lock, core_records, signed_application_id
        authorization_id = verify_release_authorization_descriptors(
            {name: descriptors[name] for name in AUTHORIZATION_NAMES},
            artifacts=core_records,
            package_version=arguments.package_version,
            signed_application_id=signed_application_id,
            source_commit=arguments.source_commit,
            tag=arguments.tag,
            trust_anchor=anchor,
            authorization_anchor=base_lock["release_authorization_anchor"],
        )
        return base_lock, records, authorization_id
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)
        os.close(directory_fd)


def generate(arguments: argparse.Namespace) -> tuple[dict[str, object] | bytes, dict[str, str]]:
    base_lock, records, identity = _release_material(arguments)
    anchor = base_lock["trust_anchor"]
    if arguments.emit_authorization_request:
        request = release_authorization_payload(
            artifacts=records,
            package_version=arguments.package_version,
            signed_application_id=identity,
            source_commit=arguments.source_commit,
            tag=arguments.tag,
            trust_anchor=anchor,
            authorization_anchor=base_lock["release_authorization_anchor"],
        )
        return canonical_json(request), {
            "signed_application_id": identity,
            "state": "authorization-request",
        }

    candidate: dict[str, object] = {
        "$schema": "release-lock.schema.json",
        "schema_version": "grok-bootstrap-release-lock.v1",
        "state": "qualified",
        "release_authorization_anchor": base_lock["release_authorization_anchor"],
        "trust_anchor": anchor,
        "release": {
            "artifacts": records,
            "authorization_id": identity,
            "package_version": arguments.package_version,
            "signed_application_id": base_lock["pending_intent"][
                "signed_application_id"
            ],
            "source_commit": arguments.source_commit,
            "tag": arguments.tag,
        },
    }
    validate_lock(candidate)
    return candidate, {
        "authorization_id": identity,
        "signed_application_id": candidate["release"]["signed_application_id"],
        "state": "qualified-candidate",
    }


def _write_transactional(path: Path, raw: bytes) -> None:
    temporary = path.parent / f".{path.name}.stage-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = -1
    linked = False
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise ReleaseError("transactional output write did not progress")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path, follow_symlinks=False)
        linked = True
        directory_fd = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        readback_fd = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            readback = bytearray()
            while len(readback) < len(raw):
                chunk = os.read(readback_fd, len(raw) - len(readback))
                if not chunk:
                    break
                readback.extend(chunk)
            if bytes(readback) != raw or os.read(readback_fd, 1):
                raise ReleaseError("transactional output readback failed")
        finally:
            os.close(readback_fd)
    except FileExistsError as exc:
        raise ReleaseError("output path appeared during transactional publication") from exc
    except BaseException:
        if linked:
            try:
                staged_info = temporary.lstat()
                output_info = path.lstat()
                if (staged_info.st_dev, staged_info.st_ino) == (
                    output_info.st_dev,
                    output_info.st_ino,
                ):
                    path.unlink()
            except OSError:
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
        _validate_output(arguments.output)
        value, result = generate(arguments)
        raw = value if isinstance(value, bytes) else canonical_json(value)
        _write_transactional(arguments.output, raw)
        result.update(
            {
                "output": os.fspath(arguments.output),
                "source_commit": arguments.source_commit,
                "tag": arguments.tag,
            }
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ReleaseError, subprocess.SubprocessError) as exc:
        print(f"promote-grok-bootstrap-release: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
