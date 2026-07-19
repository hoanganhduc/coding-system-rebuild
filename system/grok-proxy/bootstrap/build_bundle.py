#!/usr/bin/env python3
"""Build and sign one deterministic Grok bootstrap application bundle."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile


SCHEMA = "grok-bootstrap-manifest-v1"
BUNDLE_NAME = "dispatcher.pyz"
MANIFEST_NAME = "release-manifest.txt"
SIGNATURE_NAME = "release-manifest.sig"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_FILES = 4096
MAX_DIRECTORIES = 4096
MAX_DEPTH = 64
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
SAFE_KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class BuildError(RuntimeError):
    """The candidate cannot be represented by the closed bundle format."""


def safe_relative_path(value: str) -> bool:
    if not value or len(value) > 512 or not SAFE_PATH_RE.fullmatch(value):
        return False
    if value.startswith("/") or value.endswith("/"):
        return False
    parts = value.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def normalized_mode(info: os.stat_result) -> int:
    return 0o755 if stat.S_IMODE(info.st_mode) & 0o111 else 0o644


def same_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    fields = (
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
    return all(getattr(left, field) == getattr(right, field) for field in fields)


def read_open_file(file_descriptor: int, expected: os.stat_result) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = os.read(file_descriptor, 64 * 1024)
        except InterruptedError:
            continue
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_FILE_BYTES or total > expected.st_size:
            raise BuildError("source file changed or exceeds its size bound")
        chunks.append(chunk)
    current = os.fstat(file_descriptor)
    if total != expected.st_size or not same_snapshot(expected, current):
        raise BuildError("source file changed while it was read")
    return b"".join(chunks)


def collect_source(
    source: Path, *, require_main: bool = True
) -> list[tuple[str, int, bytes, str]]:
    try:
        root_info = source.lstat()
    except OSError as exc:
        raise BuildError("source root is unavailable") from exc
    if not stat.S_ISDIR(root_info.st_mode) or source.is_symlink():
        raise BuildError("source root must be a real directory")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        root_descriptor = os.open(source, flags)
    except OSError as exc:
        raise BuildError("source root cannot be opened safely") from exc

    records: list[tuple[str, int, bytes, str]] = []
    directory_count = 0
    source_bytes = 0

    def visit(directory_descriptor: int, prefix: str, depth: int) -> None:
        nonlocal directory_count, source_bytes
        if depth > MAX_DEPTH:
            raise BuildError("source exceeds its directory-depth bound")
        directory_count += 1
        if directory_count > MAX_DIRECTORIES:
            raise BuildError("source exceeds its directory-count bound")

        before = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise BuildError("source contains a special directory")
        with os.scandir(directory_descriptor) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)

        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            if not safe_relative_path(relative):
                raise BuildError("source contains an unsafe relative path")
            entry_info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(entry_info.st_mode):
                try:
                    child_descriptor = os.open(
                        entry.name, flags, dir_fd=directory_descriptor
                    )
                except OSError as exc:
                    raise BuildError("source directory changed while it was opened") from exc
                try:
                    opened_info = os.fstat(child_descriptor)
                    if not same_snapshot(entry_info, opened_info):
                        raise BuildError("source directory changed while it was opened")
                    visit(child_descriptor, relative, depth + 1)
                finally:
                    os.close(child_descriptor)
            elif stat.S_ISREG(entry_info.st_mode):
                if entry_info.st_nlink != 1:
                    raise BuildError("source contains a multiply linked file")
                if entry_info.st_size < 0 or entry_info.st_size > MAX_FILE_BYTES:
                    raise BuildError("source file exceeds its size bound")
                try:
                    file_descriptor = os.open(
                        entry.name,
                        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory_descriptor,
                    )
                except OSError as exc:
                    raise BuildError("source file changed while it was opened") from exc
                try:
                    opened_info = os.fstat(file_descriptor)
                    if not same_snapshot(entry_info, opened_info):
                        raise BuildError("source file changed while it was opened")
                    data = read_open_file(file_descriptor, opened_info)
                finally:
                    os.close(file_descriptor)
                source_bytes += len(data)
                if source_bytes > MAX_BUNDLE_BYTES:
                    raise BuildError("source exceeds its aggregate size bound")
                records.append(
                    (
                        relative,
                        normalized_mode(opened_info),
                        data,
                        hashlib.sha256(data).hexdigest(),
                    )
                )
                if len(records) > MAX_FILES:
                    raise BuildError("source exceeds its file-count bound")
            else:
                kind = "directory" if entry.is_dir(follow_symlinks=False) else "file"
                raise BuildError(f"source contains a linked or special {kind}")

        after = os.fstat(directory_descriptor)
        if not same_snapshot(before, after):
            raise BuildError("source directory changed while it was read")

    try:
        opened_root_info = os.fstat(root_descriptor)
        if not same_snapshot(root_info, opened_root_info):
            raise BuildError("source root changed while it was opened")
        visit(root_descriptor, "", 0)
        if not same_snapshot(opened_root_info, source.lstat()):
            raise BuildError("source root path changed while it was read")
    finally:
        os.close(root_descriptor)

    records.sort(key=lambda item: item[0])
    if not records:
        raise BuildError("source must contain at least one file")
    if require_main and sum(record[0] == "__main__.py" for record in records) != 1:
        raise BuildError("source must contain exactly one __main__.py")
    return records


def inventory_lines(records: list[tuple[str, int, bytes, str]]) -> list[str]:
    return [f"file={mode:04o}:{digest}:{path}" for path, mode, _data, digest in records]


def build_zip(path: Path, records: list[tuple[str, int, bytes, str]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for relative, mode, data, _digest in records:
            entry = zipfile.ZipInfo(relative, FIXED_ZIP_TIME)
            entry.create_system = 3
            entry.compress_type = zipfile.ZIP_STORED
            entry.external_attr = (stat.S_IFREG | mode) << 16
            entry.flag_bits |= 0x800
            archive.writestr(entry, data)
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise BuildError("bundle exceeds its size bound")


def canonical_manifest(
    key_id: str,
    release_id: str,
    bundle_size: int,
    bundle_sha256: str,
    file_lines: list[str],
) -> bytes:
    lines = [
        f"schema={SCHEMA}",
        f"key_id={key_id}",
        f"release_id={release_id}",
        f"bundle_name={BUNDLE_NAME}",
        f"bundle_size={bundle_size}",
        f"bundle_sha256={bundle_sha256}",
        f"file_count={len(file_lines)}",
        *file_lines,
    ]
    return ("\n".join(lines) + "\n").encode("ascii")


def sign_manifest(openssl: Path, key: Path, manifest: Path, signature: Path) -> None:
    if not openssl.is_absolute() or not openssl.is_file():
        raise BuildError("openssl must be an absolute regular-file path")
    if not key.is_absolute() or not key.is_file() or key.is_symlink():
        raise BuildError("signing key must be an external absolute regular file")
    completed = subprocess.run(
        [
            os.fspath(openssl),
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            os.fspath(key),
            "-in",
            os.fspath(manifest),
            "-out",
            os.fspath(signature),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        timeout=30,
    )
    if completed.returncode != 0:
        raise BuildError("openssl refused to sign the manifest")
    if signature.stat().st_size != 64:
        raise BuildError("Ed25519 signature has the wrong size")


def make_bundle(source: Path, output: Path, key_id: str, key: Path, openssl: Path) -> Path:
    if not SAFE_KEY_ID_RE.fullmatch(key_id):
        raise BuildError("key id is invalid")
    try:
        source_argument_info = source.lstat()
        output_argument_info = output.lstat()
    except OSError as exc:
        raise BuildError("source and output roots must already exist") from exc
    if stat.S_ISLNK(source_argument_info.st_mode) or not stat.S_ISDIR(
        source_argument_info.st_mode
    ):
        raise BuildError("source root must be a real directory")
    if stat.S_ISLNK(output_argument_info.st_mode) or not stat.S_ISDIR(
        output_argument_info.st_mode
    ):
        raise BuildError("output root must be a real directory")
    source = source.resolve(strict=True)
    output = output.resolve(strict=True)
    if source == output or source in output.parents or output in source.parents:
        raise BuildError("source and output trees must be disjoint")

    records = collect_source(source)
    file_lines = inventory_lines(records)
    inventory = ("\n".join(file_lines) + "\n").encode("ascii")
    release_id = hashlib.sha256(inventory).hexdigest()
    final = output / release_id
    if final.exists() or final.is_symlink():
        raise BuildError("release output already exists")

    temporary = Path(tempfile.mkdtemp(prefix=".grok-bootstrap-", dir=output))
    stage = temporary / release_id
    renamed = False
    completed = False
    try:
        stage.mkdir(mode=0o700)
        bundle = stage / BUNDLE_NAME
        build_zip(bundle, records)
        bundle_data = bundle.read_bytes()
        manifest_data = canonical_manifest(
            key_id,
            release_id,
            len(bundle_data),
            hashlib.sha256(bundle_data).hexdigest(),
            file_lines,
        )
        if len(manifest_data) > MAX_MANIFEST_BYTES:
            raise BuildError("manifest exceeds its size bound")
        manifest = stage / MANIFEST_NAME
        signature = stage / SIGNATURE_NAME
        manifest.write_bytes(manifest_data)
        sign_manifest(openssl, key, manifest, signature)

        for artifact in (bundle, manifest, signature):
            artifact.chmod(0o444)
        os.rename(stage, final)
        renamed = True
        final.chmod(0o555)
        completed = True
        return final
    finally:
        if renamed and not completed and final.exists() and not final.is_symlink():
            for path in sorted(final.rglob("*"), reverse=True):
                try:
                    path.chmod(0o700 if path.is_dir() else 0o600)
                except OSError:
                    pass
            final.chmod(0o700)
            shutil.rmtree(final, ignore_errors=True)
        if temporary.exists():
            for path in sorted(temporary.rglob("*"), reverse=True):
                try:
                    path.chmod(0o700 if path.is_dir() else 0o600)
                except OSError:
                    pass
            shutil.rmtree(temporary, ignore_errors=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--signing-key", required=True, type=Path)
    parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        release = make_bundle(
            args.source,
            args.output,
            args.key_id,
            args.signing_key,
            args.openssl,
        )
    except (BuildError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        print(f"build-bundle: {exc}", file=os.sys.stderr)
        return 2
    print(release)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
