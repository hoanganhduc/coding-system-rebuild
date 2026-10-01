#!/usr/bin/env python3
"""Extract a locked Python wheelhouse OCI image without executing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "system/docker/python-wheelhouse"))
sys.path.insert(0, str(ROOT / "system/python-closure"))
from wheelhouse_lib import (  # noqa: E402
    ENVIRONMENTS,
    MAX_FILES,
    MAX_MANIFEST_BYTES,
    MAX_TOTAL_BYTES,
    MAX_WHEEL_BYTES,
    WHEEL_NAME,
    WheelhouseError,
    sha256_file,
    validate_wheelhouse,
)
from runtime_lib import (  # noqa: E402
    RuntimeContractError,
    expected_provenance,
    load_locked_image as _load_locked_image,
    provenance_path,
    verify_provenance,
    write_provenance,
)


DEFAULT_LOCK = ROOT / "system/software/images.lock.json"
MAX_REGISTRY_MANIFEST_BYTES = 4 * 1024 * 1024


class ExtractError(RuntimeError):
    """Image selection, registry proof, or bounded extraction failed."""


def canonical_arch(value: str | None = None) -> str:
    raw = (value or platform.machine()).lower()
    if raw in {"x86_64", "amd64"}:
        return "amd64"
    if raw in {"aarch64", "arm64"}:
        return "arm64"
    raise ExtractError(f"unsupported architecture: {raw}")


def load_locked_image(lock_path: Path, architecture: str) -> dict[str, str]:
    try:
        return _load_locked_image(lock_path, architecture)
    except RuntimeContractError as exc:
        raise ExtractError(str(exc)) from exc


def docker_prefix() -> list[str]:
    direct = subprocess.run(
        ["docker", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return ["docker"] if direct.returncode == 0 else ["sudo", "-n", "docker"]


def run_bounded(command: list[str], limit: int) -> bytes:
    with tempfile.TemporaryFile() as error_file:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=error_file)
        assert process.stdout is not None
        output = process.stdout.read(limit + 1)
        if len(output) > limit:
            process.kill()
            process.wait()
            raise ExtractError(f"command output exceeds {limit} bytes: {command[0]}")
        returncode = process.wait()
        if returncode != 0:
            error_file.seek(0)
            detail = error_file.read(MAX_MANIFEST_BYTES).decode("utf-8", "replace").strip()
            raise ExtractError(f"command failed ({returncode}): {' '.join(command)}: {detail}")
        return output


def verify_registry_manifest(prefix: list[str], image: dict[str, str]) -> None:
    raw = run_bounded(
        prefix + ["buildx", "imagetools", "inspect", "--raw", image["reference"]],
        MAX_REGISTRY_MANIFEST_BYTES,
    )
    observed = "sha256:" + hashlib.sha256(raw).hexdigest()
    if observed != image["index_digest"]:
        raise ExtractError(
            f"registry manifest digest mismatch: expected {image['index_digest']}, got {observed}"
        )
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExtractError("registry returned invalid manifest JSON") from exc
    if not isinstance(manifest, dict):
        raise ExtractError("registry manifest is not an object")
    media_type = manifest.get("mediaType")
    if media_type in {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }:
        descriptors = manifest.get("manifests")
        if not isinstance(descriptors, list):
            raise ExtractError("registry index has no manifest descriptors")
        os_name, architecture = image["platform"].split("/", 1)
        matches = [
            descriptor
            for descriptor in descriptors
            if isinstance(descriptor, dict)
            and isinstance(descriptor.get("platform"), dict)
            and descriptor["platform"].get("os") == os_name
            and descriptor["platform"].get("architecture") == architecture
        ]
        if len(matches) != 1 or matches[0].get("digest") != image["platform_digest"]:
            raise ExtractError("locked platform manifest is absent or ambiguous in the registry index")
    elif media_type in {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }:
        if image["platform_digest"] != image["index_digest"]:
            raise ExtractError("single-platform image lock uses different index/platform digests")
    else:
        raise ExtractError(f"unsupported registry manifest media type: {media_type!r}")


def verify_local_image(prefix: list[str], image: dict[str, str], architecture: str) -> None:
    observed_arch = run_bounded(
        prefix + ["image", "inspect", "--format", "{{.Architecture}}", image["reference"]],
        128,
    ).decode().strip()
    if observed_arch != architecture:
        raise ExtractError(f"local image architecture mismatch: expected {architecture}, got {observed_arch}")
    repo_digests_raw = run_bounded(
        prefix + ["image", "inspect", "--format", "{{json .RepoDigests}}", image["reference"]],
        MAX_MANIFEST_BYTES,
    )
    try:
        repo_digests = json.loads(repo_digests_raw)
    except json.JSONDecodeError as exc:
        raise ExtractError("Docker returned invalid RepoDigests") from exc
    if not isinstance(repo_digests, list) or image["reference"] not in repo_digests:
        raise ExtractError("Docker did not retain the locked repository digest")


def _relative_member(name: str) -> PurePosixPath | None:
    raw = name
    while raw.startswith("./"):
        raw = raw[2:]
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ExtractError(f"unsafe archive path: {name!r}")
    if not path.parts or path.parts[0] != "wheelhouse":
        raise ExtractError(f"archive member is outside wheelhouse: {name!r}")
    if len(path.parts) == 1:
        return None
    return PurePosixPath(*path.parts[1:])


def _allowed_relative(path: PurePosixPath, is_directory: bool) -> bool:
    parts = path.parts
    if parts == ("manifest.json",):
        return not is_directory
    if len(parts) == 1 and parts[0] in ENVIRONMENTS:
        return is_directory
    if len(parts) == 2 and parts[0] in ENVIRONMENTS and not is_directory:
        return parts[1] == "manifest.json" or bool(WHEEL_NAME.fullmatch(parts[1]))
    return False


def extract_bounded_tar(stream, destination: Path) -> None:
    members = 0
    total = 0
    seen: set[PurePosixPath] = set()
    try:
        archive = tarfile.open(fileobj=stream, mode="r|*")
        for member in archive:
            members += 1
            if members > MAX_FILES + len(ENVIRONMENTS) + 1:
                raise ExtractError("wheelhouse archive exceeds the member-count bound")
            relative = _relative_member(member.name)
            if relative is None:
                if not member.isdir():
                    raise ExtractError("wheelhouse archive root is not a directory")
                continue
            if relative in seen:
                raise ExtractError(f"duplicate archive member: {relative}")
            seen.add(relative)
            if not (member.isdir() or member.isreg()):
                raise ExtractError(f"archive member is not a regular file/directory: {relative}")
            if not _allowed_relative(relative, member.isdir()):
                raise ExtractError(f"unexpected archive member: {relative}")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=False, exist_ok=False)
                continue
            limit = MAX_MANIFEST_BYTES if relative.name == "manifest.json" else MAX_WHEEL_BYTES
            if member.size <= 0 or member.size > limit:
                raise ExtractError(f"archive member has invalid size: {relative}")
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise ExtractError("wheelhouse archive exceeds the byte bound")
            if not target.parent.is_dir() or target.parent.is_symlink():
                raise ExtractError(f"archive member parent was not declared safely: {relative}")
            source = archive.extractfile(member)
            if source is None:
                raise ExtractError(f"cannot read archive member: {relative}")
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o400,
            )
            remaining = member.size
            try:
                while remaining:
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ExtractError(f"truncated archive member: {relative}")
                    pending = memoryview(block)
                    while pending:
                        written = os.write(descriptor, pending)
                        if written <= 0:
                            raise ExtractError(f"cannot write archive member: {relative}")
                        pending = pending[written:]
                    remaining -= len(block)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
                source.close()
    except (tarfile.TarError, OSError) as exc:
        if isinstance(exc, ExtractError):
            raise
        raise ExtractError(f"cannot extract wheelhouse archive: {exc}") from exc


def copy_from_container(prefix: list[str], reference: str, destination: Path) -> None:
    container = f"csr-python-wheelhouse-{uuid.uuid4().hex}"
    subprocess.run(
        prefix + ["create", "--name", container, reference, "/__coding_system_artifact_image_never_runs__"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    primary_error: BaseException | None = None
    try:
        with tempfile.TemporaryFile() as error_file:
            process = subprocess.Popen(
                prefix + ["cp", f"{container}:/wheelhouse", "-"],
                stdout=subprocess.PIPE,
                stderr=error_file,
            )
            assert process.stdout is not None
            try:
                extract_bounded_tar(process.stdout, destination)
            except BaseException as exc:
                primary_error = exc
                process.kill()
            finally:
                process.stdout.close()
            returncode = process.wait()
            if primary_error is not None:
                raise primary_error
            if returncode != 0:
                error_file.seek(0)
                detail = error_file.read(MAX_MANIFEST_BYTES).decode("utf-8", "replace").strip()
                raise ExtractError(f"docker cp failed ({returncode}): {detail}")
    finally:
        cleanup = subprocess.run(prefix + ["rm", container], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if cleanup.returncode != 0 and primary_error is None:
            raise ExtractError("failed to remove never-started extraction container")


def _fsync_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_file():
            os.chmod(path, 0o444)
        elif path.is_dir():
            os.chmod(path, 0o555)
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    os.chmod(root, 0o555)
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_tree(path: Path) -> None:
    if not path.exists():
        return
    for directory, subdirectories, _files in os.walk(path, topdown=False):
        for name in subdirectories:
            os.chmod(Path(directory) / name, 0o700)
        os.chmod(directory, 0o700)
    shutil.rmtree(path)


def activate(stage: Path, destination: Path, expected_platform: str, *, replace: bool) -> str:
    if destination.is_symlink():
        raise ExtractError(f"destination must not be a symlink: {destination}")
    if destination.exists():
        if not destination.is_dir():
            raise ExtractError(f"destination is not a directory: {destination}")
        current = destination / "manifest.json"
        incoming = stage / "manifest.json"
        if current.is_file() and not current.is_symlink() and sha256_file(current) == sha256_file(incoming):
            validate_wheelhouse(destination, expected_platform)
            _remove_tree(stage)
            return "unchanged"
        if not replace:
            raise ExtractError(f"destination exists with different content; pass --replace: {destination}")
        backup = destination.with_name(f".{destination.name}.backup.{uuid.uuid4().hex}")
        os.replace(destination, backup)
        try:
            os.replace(stage, destination)
        except BaseException:
            os.replace(backup, destination)
            raise
        _remove_tree(backup)
        return "replaced"
    os.replace(stage, destination)
    return "installed"


def extract_locked(
    lock: Path,
    architecture: str,
    destination: Path,
    *,
    receipt: Path | None,
    replace: bool,
) -> str:
    image = load_locked_image(lock, architecture)
    prefix = docker_prefix()
    verify_registry_manifest(prefix, image)
    subprocess.run(prefix + ["pull", "--platform", image["platform"], image["reference"]], check=True)
    verify_local_image(prefix, image, architecture)
    destination = destination.absolute()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        raise ExtractError("destination parent is unsafe")
    stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}.stage.", dir=destination.parent))
    try:
        copy_from_container(prefix, image["reference"], stage)
        validate_wheelhouse(stage, image["platform"])
        _fsync_tree(stage)
        status = activate(stage, destination, image["platform"], replace=replace)
        stage = Path()
        receipt_path = receipt.absolute() if receipt is not None else provenance_path(destination)
        write_provenance(receipt_path, expected_provenance(image, destination))
        verify_provenance(
            receipt_path,
            wheelhouse=destination,
            images_lock=lock,
            architecture=architecture,
        )
        return status
    finally:
        if stage != Path() and stage.exists():
            try:
                _remove_tree(stage)
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    extract_parser = subparsers.add_parser("extract", help="pull and atomically extract a locked OCI wheelhouse")
    extract_parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    extract_parser.add_argument("--arch", default=platform.machine())
    extract_parser.add_argument("--destination", type=Path, required=True)
    extract_parser.add_argument("--provenance", type=Path)
    extract_parser.add_argument("--replace", action="store_true")
    verify_parser = subparsers.add_parser("verify-directory", help="validate an already copied candidate directory")
    verify_parser.add_argument("--directory", type=Path, required=True)
    verify_parser.add_argument("--platform", required=True, choices=("linux/amd64", "linux/arm64"))
    verify_parser.add_argument("--lock", type=Path)
    verify_parser.add_argument("--provenance", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-directory":
            validate_wheelhouse(args.directory, args.platform)
            if (args.lock is None) != (args.provenance is None):
                raise ExtractError("--lock and --provenance must be supplied together")
            if args.lock is not None:
                verify_provenance(
                    args.provenance,
                    wheelhouse=args.directory,
                    images_lock=args.lock,
                    architecture=args.platform.split("/", 1)[1],
                )
            print(f"wheelhouse verified: {args.directory} ({args.platform})")
        else:
            architecture = canonical_arch(args.arch)
            status = extract_locked(
                args.lock,
                architecture,
                args.destination,
                receipt=args.provenance,
                replace=args.replace,
            )
            print(json.dumps({"status": status, "destination": str(args.destination), "platform": f"linux/{architecture}"}, sort_keys=True))
        return 0
    except (
        ExtractError,
        RuntimeContractError,
        WheelhouseError,
        OSError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"extract-python-wheelhouse: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
