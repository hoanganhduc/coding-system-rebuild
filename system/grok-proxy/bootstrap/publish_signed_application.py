#!/usr/bin/python3
"""Publish and select an already-signed Grok bootstrap application."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import zipfile


CONTROL_ROOT = Path("/usr/local/libexec/grok-proxy/bootstrap")
STORE_ROOT = Path("/usr/local/libexec/grok-proxy/bootstrap-releases")
RELEASE_CONTROL_ROOT = Path("/var/lib/grok-proxy/release-control")
UPDATE_LOCK = "update.lock"
OPERATION_LOCK = "operation.lock"
SELECTOR = "selected-release"
NATIVE_VERIFIER = "grok-bootstrap"
AUDIT_ROOT = "selector-audit"
AUDIT_PENDING = "pending.json"
AUDIT_STAGE = "pending.tmp"
PACKAGE_PENDING = "package-update.pending"
ARTIFACTS = (
    "dispatcher.pyz",
    "release-manifest.sig",
    "release-manifest.txt",
)
INTERLOCK_FILES = (
    "rollback-deny.json",
    "canary-terminal.json",
    "rung-canary.json",
)
RELEASE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]*)$")
FILE_RE = re.compile(r"^file=(0644|0755):([0-9a-f]{64}):(.+)$")
TRUST_SCHEMA = "grok-bootstrap-trust-anchor-v1"
MANIFEST_SCHEMA = "grok-bootstrap-manifest-v1"
BUNDLE_NAME = "dispatcher.pyz"
MAX_FILES = 4096
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
TEST_MODE_ENV = "GROK_BOOTSTRAP_PUBLISHER_TEST_MODE"


class PublisherError(RuntimeError):
    """The requested administrative transaction is unsafe."""


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _same_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
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


def _safe_relative_path(value: str) -> bool:
    if not value or len(value) > 512 or SAFE_PATH_RE.fullmatch(value) is None:
        return False
    if value.startswith("/") or value.endswith("/"):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _directory_names_bounded(directory_fd: int, maximum: int) -> list[str]:
    names: list[str] = []
    with os.scandir(directory_fd) as iterator:
        for entry in iterator:
            names.append(entry.name)
            if len(names) > maximum:
                raise PublisherError("directory inventory exceeds its bound")
    names.sort()
    return names


def _open_relative_directory(
    root_fd: int, relative: Path, uid: int, gid: int, mode: int
) -> int:
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} or "/" in part for part in relative.parts)
    ):
        raise PublisherError("test path authority is unsafe")
    descriptor = os.dup(root_fd)
    try:
        parts = relative.parts
        for index, part in enumerate(parts):
            named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            opened = os.fstat(child)
            final = index == len(parts) - 1
            if (
                not stat.S_ISDIR(named.st_mode)
                or not stat.S_ISDIR(opened.st_mode)
                or not _same_identity(named, opened)
                or opened.st_uid != uid
                or opened.st_gid != gid
                or stat.S_IMODE(opened.st_mode) & 0o022
                or (final and stat.S_IMODE(opened.st_mode) != mode)
            ):
                os.close(child)
                raise PublisherError("test path authority is unsafe")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise PublisherError("test path authority is unsafe") from exc
    except BaseException:
        os.close(descriptor)
        raise


def _open_production_directory(path: Path, mode: int) -> int:
    if not path.is_absolute():
        raise PublisherError("production path is not absolute")
    components = path.parts[1:]
    if (
        not components
        or any(part in {"", ".", ".."} or "/" in part for part in components)
    ):
        raise PublisherError("production path authority is unsafe")
    descriptor = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        root = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(root.st_mode)
            or root.st_uid != 0
            or root.st_gid != 0
            or stat.S_IMODE(root.st_mode) & 0o022
        ):
            raise PublisherError("root filesystem authority is unsafe")
        for index, part in enumerate(components):
            named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            opened = os.fstat(child)
            final = index == len(components) - 1
            if (
                not stat.S_ISDIR(named.st_mode)
                or not stat.S_ISDIR(opened.st_mode)
                or not _same_identity(named, opened)
                or opened.st_uid != 0
                or opened.st_gid != 0
                or stat.S_IMODE(opened.st_mode) & 0o022
                or (final and stat.S_IMODE(opened.st_mode) != mode)
            ):
                os.close(child)
                raise PublisherError("production path authority is unsafe")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise PublisherError("production path authority is unsafe") from exc
    except BaseException:
        os.close(descriptor)
        raise


class Layout:
    def __init__(self, test_root: Path | None) -> None:
        self.test_root_fd = -1
        self.test_mode = test_root is not None
        self.test_root = test_root
        if self.test_mode:
            if os.environ.get(TEST_MODE_ENV) != "1":
                raise PublisherError("test path override requires explicit test mode")
            assert test_root is not None
            if not test_root.is_absolute() or test_root.resolve(strict=True) != test_root:
                raise PublisherError("test root must be an existing canonical path")
            info = test_root.lstat()
            descriptor = os.open(
                test_root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or not _same_identity(info, opened)
                or info.st_uid != os.geteuid()
                or info.st_gid != os.getegid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                os.close(descriptor)
                raise PublisherError("test root authority is unsafe")
            self.test_root_fd = descriptor
            self.uid = os.geteuid()
            self.gid = os.getegid()
            self.control = test_root / CONTROL_ROOT.relative_to("/")
            self.store = test_root / STORE_ROOT.relative_to("/")
            self.release_control = test_root / RELEASE_CONTROL_ROOT.relative_to("/")
        else:
            if os.geteuid() != 0:
                raise PublisherError("production publisher is root-only")
            self.uid = 0
            self.gid = 0
            self.control = CONTROL_ROOT
            self.store = STORE_ROOT
            self.release_control = RELEASE_CONTROL_ROOT

    def open_control(self) -> int:
        if self.test_mode:
            return _open_relative_directory(
                self.test_root_fd, CONTROL_ROOT.relative_to("/"), self.uid, self.gid, 0o755
            )
        return _open_production_directory(self.control, 0o755)

    def open_store(self) -> int:
        if self.test_mode:
            return _open_relative_directory(
                self.test_root_fd, STORE_ROOT.relative_to("/"), self.uid, self.gid, 0o755
            )
        return _open_production_directory(self.store, 0o755)

    def open_release_control(self) -> int:
        if self.test_mode:
            return _open_relative_directory(
                self.test_root_fd,
                RELEASE_CONTROL_ROOT.relative_to("/"),
                self.uid,
                self.gid,
                0o755,
            )
        return _open_production_directory(self.release_control, 0o755)

    def open_source(self, source: Path) -> int:
        if not source.is_absolute() or RELEASE_ID_RE.fullmatch(source.name) is None:
            raise PublisherError("signed application source path is invalid")
        if self.test_mode:
            try:
                relative = source.relative_to(self.test_root)
            except ValueError as exc:
                raise PublisherError("test signed source is outside its anchored root") from exc
            return _open_relative_directory(
                self.test_root_fd, relative, self.uid, self.gid, 0o555
            )
        return _open_production_directory(source, 0o555)

    def close(self) -> None:
        if self.test_root_fd >= 0:
            os.close(self.test_root_fd)
            self.test_root_fd = -1


def _read_fd(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = os.read(descriptor, 64 * 1024)
        except InterruptedError:
            continue
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > maximum:
            raise PublisherError("signed artifact exceeds its size bound")
        chunks.append(chunk)


def _read_named_regular(
    directory_fd: int,
    name: str,
    *,
    uid: int,
    gid: int,
    mode: int,
    maximum: int,
) -> bytes:
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise PublisherError("signed artifact cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(named.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or not _same_identity(named, opened)
            or opened.st_uid != uid
            or opened.st_gid != gid
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_nlink != 1
            or opened.st_size < 0
            or opened.st_size > maximum
        ):
            raise PublisherError("signed artifact metadata is unsafe")
        data = _read_fd(descriptor, maximum)
        current = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            len(data) != opened.st_size
            or not _same_snapshot(opened, current)
            or not _same_snapshot(opened, named_after)
        ):
            raise PublisherError("signed artifact changed while it was read")
        return data
    finally:
        os.close(descriptor)


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _load_trust_anchor(control_fd: int, uid: int, gid: int) -> tuple[str, bytes]:
    try:
        named = os.stat(NATIVE_VERIFIER, dir_fd=control_fd, follow_symlinks=False)
        descriptor = os.open(
            NATIVE_VERIFIER,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=control_fd,
        )
    except OSError as exc:
        raise PublisherError("native bootstrap trust anchor cannot be opened") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(named.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or not _same_identity(named, opened)
            or opened.st_uid != uid
            or opened.st_gid != gid
            or stat.S_IMODE(opened.st_mode) != 0o555
            or opened.st_nlink != 1
            or not 0 < opened.st_size <= 16 * 1024 * 1024
        ):
            raise PublisherError("native bootstrap trust anchor is unsafe")
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}", "--describe-trust-anchor"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(descriptor,),
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
            },
            timeout=10,
            check=False,
        )
        if completed.returncode != 0 or len(completed.stdout) > 1024:
            raise PublisherError("native bootstrap trust-anchor report failed")
        current = os.stat(
            NATIVE_VERIFIER, dir_fd=control_fd, follow_symlinks=False
        )
        if (
            not _same_snapshot(opened, os.fstat(descriptor))
            or not _same_snapshot(opened, current)
        ):
            raise PublisherError("native bootstrap trust anchor changed during report")
        raw = completed.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise PublisherError("native bootstrap trust-anchor report failed") from exc
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublisherError("bootstrap trust anchor is invalid") from exc
    if (
        type(value) is not dict
        or set(value) != {"schema_version", "key_id", "public_key_hex"}
        or value.get("schema_version") != TRUST_SCHEMA
        or type(value.get("key_id")) is not str
        or KEY_ID_RE.fullmatch(value["key_id"]) is None
        or type(value.get("public_key_hex")) is not str
        or RELEASE_ID_RE.fullmatch(value["public_key_hex"]) is None
        or raw != _canonical_json(value)
    ):
        raise PublisherError("bootstrap trust anchor is invalid")
    return value["key_id"], bytes.fromhex(value["public_key_hex"])


def _parse_manifest(raw: bytes, release_id: str, key_id: str) -> dict[str, object]:
    if len(raw) > MAX_MANIFEST_BYTES or not raw.endswith(b"\n") or b"\r" in raw:
        raise PublisherError("signed manifest is not canonical")
    try:
        lines = [line.decode("ascii") for line in raw[:-1].split(b"\n")]
    except UnicodeDecodeError as exc:
        raise PublisherError("signed manifest is not ASCII") from exc
    if len(lines) < 8:
        raise PublisherError("signed manifest is incomplete")
    expected = (
        ("schema", MANIFEST_SCHEMA),
        ("key_id", key_id),
        ("release_id", release_id),
        ("bundle_name", BUNDLE_NAME),
    )
    for line, (field, value) in zip(lines[:4], expected):
        if line != f"{field}={value}":
            raise PublisherError("signed manifest header is invalid")
    numeric: dict[str, int] = {}
    for index, field in ((4, "bundle_size"), (6, "file_count")):
        prefix = field + "="
        value = lines[index][len(prefix) :] if lines[index].startswith(prefix) else ""
        if DECIMAL_RE.fullmatch(value) is None:
            raise PublisherError("signed manifest decimal is not canonical")
        numeric[field] = int(value)
    digest_prefix = "bundle_sha256="
    bundle_digest = (
        lines[5][len(digest_prefix) :] if lines[5].startswith(digest_prefix) else ""
    )
    if RELEASE_ID_RE.fullmatch(bundle_digest) is None:
        raise PublisherError("signed manifest bundle digest is invalid")
    file_lines = lines[7:]
    if not 1 <= numeric["file_count"] <= MAX_FILES or len(file_lines) != numeric["file_count"]:
        raise PublisherError("signed manifest file count is invalid")
    records: list[tuple[str, int, str]] = []
    for line in file_lines:
        match = FILE_RE.fullmatch(line)
        if match is None or not _safe_relative_path(match.group(3)):
            raise PublisherError("signed manifest inventory is invalid")
        records.append((match.group(3), int(match.group(1), 8), match.group(2)))
    paths = [record[0] for record in records]
    if paths != sorted(paths) or len(paths) != len(set(paths)) or paths.count("__main__.py") != 1:
        raise PublisherError("signed manifest inventory is not closed")
    inventory = ("\n".join(file_lines) + "\n").encode("ascii")
    if hashlib.sha256(inventory).hexdigest() != release_id:
        raise PublisherError("signed manifest release id is inconsistent")
    if not 0 < numeric["bundle_size"] <= MAX_BUNDLE_BYTES:
        raise PublisherError("signed bundle size is invalid")
    return {
        "bundle_size": numeric["bundle_size"],
        "bundle_sha256": bundle_digest,
        "records": records,
    }


def _validate_bundle(raw: bytes, manifest: dict[str, object]) -> None:
    records = manifest["records"]
    assert isinstance(records, list)
    if (
        len(raw) != manifest["bundle_size"]
        or hashlib.sha256(raw).hexdigest() != manifest["bundle_sha256"]
        or len(raw) < 22
        or raw[:4] != b"PK\x03\x04"
        or raw[-22:-18] != b"PK\x05\x06"
        or raw[-2:] != b"\x00\x00"
    ):
        raise PublisherError("signed bundle digest or shape is invalid")
    end = raw[-22:]
    if (
        int.from_bytes(end[4:6], "little") != 0
        or int.from_bytes(end[6:8], "little") != 0
        or int.from_bytes(end[8:10], "little") != len(records)
        or int.from_bytes(end[10:12], "little") != len(records)
        or int.from_bytes(end[20:22], "little") != 0
        or int.from_bytes(end[12:16], "little")
        + int.from_bytes(end[16:20], "little")
        != len(raw) - 22
    ):
        raise PublisherError("signed bundle central inventory is not canonical")
    try:
        with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
            entries = archive.infolist()
            if archive.comment or len(entries) != len(records):
                raise PublisherError("signed bundle inventory is not closed")
            total = 0
            expected_offset = 0
            for information, record in zip(entries, records):
                path, mode, digest = record
                unix_mode = (information.external_attr >> 16) & 0xFFFF
                if (
                    information.filename != path
                    or information.orig_filename != path
                    or information.date_time != FIXED_ZIP_TIME
                    or information.create_system != 3
                    or information.compress_type != zipfile.ZIP_STORED
                    or information.flag_bits & ~0x800
                    or information.extra
                    or information.comment
                    or unix_mode != stat.S_IFREG | mode
                    or information.file_size < 0
                    or information.file_size > MAX_FILE_BYTES
                    or information.compress_size != information.file_size
                    or information.header_offset != expected_offset
                ):
                    raise PublisherError("signed bundle member is not canonical")
                data = archive.read(information)
                total += len(data)
                expected_offset += (
                    30
                    + len(path.encode("ascii"))
                    + len(information.extra)
                    + information.compress_size
                )
                if total > MAX_BUNDLE_BYTES or hashlib.sha256(data).hexdigest() != digest:
                    raise PublisherError("signed bundle member digest is invalid")
            if archive.start_dir != expected_offset:
                raise PublisherError("signed bundle has noncanonical local records")
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        if isinstance(exc, PublisherError):
            raise
        raise PublisherError("signed bundle cannot be parsed") from exc


def _sealed_memfd(name: str, data: bytes) -> int:
    if not hasattr(os, "memfd_create"):
        raise PublisherError("sealed signature verification input is unsupported")
    descriptor = os.memfd_create(
        name,
        getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0),
    )
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.lseek(descriptor, 0, os.SEEK_SET)
        seals = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _verify_signature(public_key: bytes, manifest: bytes, signature: bytes) -> None:
    if len(signature) != 64:
        raise PublisherError("signed manifest signature size is invalid")
    descriptors = [
        _sealed_memfd("grok-bootstrap-public-key", DER_PREFIX + public_key),
        _sealed_memfd("grok-bootstrap-manifest", manifest),
        _sealed_memfd("grok-bootstrap-signature", signature),
    ]
    try:
        command = [
            "/usr/bin/openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-keyform",
            "DER",
            "-rawin",
            "-inkey",
            f"/proc/self/fd/{descriptors[0]}",
            "-in",
            f"/proc/self/fd/{descriptors[1]}",
            "-sigfile",
            f"/proc/self/fd/{descriptors[2]}",
        ]
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=tuple(descriptors),
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "OPENSSL_CONF": "/dev/null",
            },
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise PublisherError("signed manifest signature is invalid")
    except (OSError, subprocess.SubprocessError) as exc:
        raise PublisherError("cannot verify signed manifest signature") from exc
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _validated_release(
    parent_fd: int,
    name: str,
    *,
    expected_release_id: str | None = None,
    uid: int,
    gid: int,
    key_id: str,
    public_key: bytes,
) -> tuple[dict[str, bytes], str]:
    release_id = name if expected_release_id is None else expected_release_id
    if RELEASE_ID_RE.fullmatch(release_id) is None:
        raise PublisherError("signed application id is invalid")
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        release_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise PublisherError("signed application directory cannot be opened safely") from exc
    try:
        opened = os.fstat(release_fd)
        if (
            not stat.S_ISDIR(named.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or not _same_identity(named, opened)
            or opened.st_uid != uid
            or opened.st_gid != gid
            or stat.S_IMODE(opened.st_mode) != 0o555
            or opened.st_nlink < 2
        ):
            raise PublisherError("signed application directory metadata is unsafe")
        names = _directory_names_bounded(release_fd, len(ARTIFACTS))
        if names != list(ARTIFACTS):
            raise PublisherError("signed application artifact set is not closed")
        values = {
            artifact: _read_named_regular(
                release_fd,
                artifact,
                uid=uid,
                gid=gid,
                mode=0o444,
                maximum=(
                    MAX_BUNDLE_BYTES
                    if artifact == BUNDLE_NAME
                    else MAX_MANIFEST_BYTES
                    if artifact == "release-manifest.txt"
                    else 64
                ),
            )
            for artifact in ARTIFACTS
        }
        manifest = _parse_manifest(
            values["release-manifest.txt"], release_id, key_id
        )
        _verify_signature(
            public_key,
            values["release-manifest.txt"],
            values["release-manifest.sig"],
        )
        _validate_bundle(values[BUNDLE_NAME], manifest)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_snapshot(opened, os.fstat(release_fd)) or not _same_snapshot(opened, current):
            raise PublisherError("signed application directory changed during validation")
        return values, hashlib.sha256(values["release-manifest.txt"]).hexdigest()
    finally:
        os.close(release_fd)


def _source_directory(source_fd: int) -> os.stat_result:
    opened = os.fstat(source_fd)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o555
        or opened.st_nlink < 2
    ):
        raise PublisherError("signed application source metadata is unsafe")
    return opened


def _copy_source_to_stage(
    source_fd: int,
    source_info: os.stat_result,
    store_fd: int,
    stage_name: str,
    uid: int,
    gid: int,
) -> int:
    stage_fd = -1
    stage_created = False
    try:
        names = _directory_names_bounded(source_fd, len(ARTIFACTS))
        if names != list(ARTIFACTS):
            raise PublisherError("signed application source artifact set is not closed")
        os.mkdir(stage_name, 0o700, dir_fd=store_fd)
        stage_created = True
        stage_fd = os.open(
            stage_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=store_fd,
        )
        os.fchown(stage_fd, uid, gid)
        for artifact in ARTIFACTS:
            maximum = (
                MAX_BUNDLE_BYTES
                if artifact == BUNDLE_NAME
                else MAX_MANIFEST_BYTES
                if artifact == "release-manifest.txt"
                else 64
            )
            data = _read_named_regular(
                source_fd,
                artifact,
                uid=source_info.st_uid,
                gid=source_info.st_gid,
                mode=0o444,
                maximum=maximum,
            )
            destination = os.open(
                artifact,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
                dir_fd=stage_fd,
            )
            try:
                os.fchown(destination, uid, gid)
                offset = 0
                while offset < len(data):
                    offset += os.write(destination, data[offset:])
                os.fsync(destination)
                os.fchmod(destination, 0o444)
                os.fsync(destination)
            finally:
                os.close(destination)
        if not _same_snapshot(source_info, os.fstat(source_fd)):
            raise PublisherError("signed application source changed during import")
        os.fchmod(stage_fd, 0o555)
        os.fsync(stage_fd)
        return stage_fd
    except BaseException:
        if stage_fd >= 0:
            _remove_stage(store_fd, stage_name, stage_fd)
            os.close(stage_fd)
        elif stage_created:
            try:
                os.rmdir(stage_name, dir_fd=store_fd)
                os.fsync(store_fd)
            except OSError:
                pass
        raise


_libc = ctypes.CDLL(None, use_errno=True)
_renameat2 = getattr(_libc, "renameat2", None)
if _renameat2 is not None:
    _renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    _renameat2.restype = ctypes.c_int


def _rename_noreplace(source_fd: int, source: str, target_fd: int, target: str) -> None:
    if _renameat2 is None:
        raise PublisherError("atomic no-replace publication is unsupported")
    result = _renameat2(
        source_fd,
        os.fsencode(source),
        target_fd,
        os.fsencode(target),
        1,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, os.strerror(error), target)
        raise PublisherError("atomic no-replace publication failed") from OSError(
            error, os.strerror(error)
        )


def _remove_stage(store_fd: int, stage_name: str, stage_fd: int) -> None:
    try:
        os.fchmod(stage_fd, 0o700)
        with os.scandir(stage_fd) as iterator:
            names = [entry.name for entry in iterator]
        for name in names:
            try:
                descriptor = os.open(
                    name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=stage_fd
                )
                try:
                    os.fchmod(descriptor, 0o600)
                finally:
                    os.close(descriptor)
                os.unlink(name, dir_fd=stage_fd)
            except OSError:
                return
        os.rmdir(stage_name, dir_fd=store_fd)
        os.fsync(store_fd)
    except OSError:
        return


@contextmanager
def _bootstrap_locked(control_fd: int, uid: int, gid: int):
    try:
        named = os.stat(UPDATE_LOCK, dir_fd=control_fd, follow_symlinks=False)
        descriptor = os.open(
            UPDATE_LOCK,
            os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=control_fd,
        )
    except OSError as exc:
        raise PublisherError("bootstrap update lock cannot be opened safely") from exc
    locked = False
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(named.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or not _same_identity(named, opened)
            or opened.st_uid != uid
            or opened.st_gid != gid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size != 0
        ):
            raise PublisherError("bootstrap update lock authority is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        current = os.stat(UPDATE_LOCK, dir_fd=control_fd, follow_symlinks=False)
        if not _same_snapshot(opened, os.fstat(descriptor)) or not _same_snapshot(opened, current):
            raise PublisherError("bootstrap update lock changed while held")
        try:
            os.stat(PACKAGE_PENDING, dir_fd=control_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise PublisherError("bootstrap package update state is unsafe") from exc
        else:
            raise PublisherError("bootstrap package update is incomplete")
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _read_selector(control_fd: int, uid: int, gid: int) -> str | None:
    try:
        raw = _read_named_regular(
            control_fd,
            SELECTOR,
            uid=uid,
            gid=gid,
            mode=0o444,
            maximum=65,
        )
    except PublisherError as exc:
        try:
            os.stat(SELECTOR, dir_fd=control_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError:
            pass
        raise PublisherError("bootstrap selector authority is unsafe") from exc
    if len(raw) != 65 or raw[-1:] != b"\n":
        raise PublisherError("bootstrap selector content is invalid")
    try:
        value = raw[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise PublisherError("bootstrap selector content is invalid") from exc
    if RELEASE_ID_RE.fullmatch(value) is None:
        raise PublisherError("bootstrap selector content is invalid")
    return value


@contextmanager
def _release_control_guard(layout: Layout):
    control_fd = layout.open_release_control()
    operation_fd = -1
    locked = False
    try:
        try:
            named = os.stat(OPERATION_LOCK, dir_fd=control_fd, follow_symlinks=False)
            operation_fd = os.open(
                OPERATION_LOCK,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=control_fd,
            )
        except OSError as exc:
            raise PublisherError("release-control operation lock is unsafe") from exc
        opened = os.fstat(operation_fd)
        if (
            not stat.S_ISREG(named.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or not _same_identity(named, opened)
            or opened.st_uid != layout.uid
            or opened.st_gid != layout.gid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size != 0
        ):
            raise PublisherError("release-control operation lock is unsafe")
        fcntl.flock(operation_fd, fcntl.LOCK_SH)
        locked = True
        current_lock = os.stat(
            OPERATION_LOCK, dir_fd=control_fd, follow_symlinks=False
        )
        if (
            not _same_snapshot(opened, os.fstat(operation_fd))
            or not _same_snapshot(opened, current_lock)
        ):
            raise PublisherError("release-control operation lock changed while held")
        yield control_fd
    finally:
        if locked:
            fcntl.flock(operation_fd, fcntl.LOCK_UN)
        if operation_fd >= 0:
            os.close(operation_fd)
        os.close(control_fd)


def _assert_release_control_quiescent(layout: Layout, control_fd: int) -> None:
    for name in INTERLOCK_FILES:
        try:
            os.stat(name, dir_fd=control_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise PublisherError("release-control interlock cannot be inspected") from exc
        raise PublisherError("release-control recovery interlock is active")
    try:
        scopes = os.stat("runner-scopes", dir_fd=control_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise PublisherError("runner-scope interlock authority is absent") from exc
    except OSError as exc:
        raise PublisherError("runner-scope interlock cannot be inspected") from exc
    if (
        not stat.S_ISDIR(scopes.st_mode)
        or scopes.st_uid != layout.uid
        or scopes.st_gid != layout.gid
        or stat.S_IMODE(scopes.st_mode) != 0o700
    ):
        raise PublisherError("runner-scope interlock authority is unsafe")
    scopes_fd = os.open(
        "runner-scopes",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=control_fd,
    )
    try:
        if not _same_identity(scopes, os.fstat(scopes_fd)):
            raise PublisherError("runner-scope interlock changed during open")
        with os.scandir(scopes_fd) as iterator:
            if next(iterator, None) is not None:
                raise PublisherError("runner-scope recovery journal is active")
    finally:
        os.close(scopes_fd)


def _audit_directory(control_fd: int, uid: int, gid: int) -> int:
    try:
        os.mkdir(AUDIT_ROOT, 0o755, dir_fd=control_fd)
        created = True
    except FileExistsError:
        created = False
    except OSError as exc:
        raise PublisherError("selector audit directory cannot be created") from exc
    descriptor = os.open(
        AUDIT_ROOT,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=control_fd,
    )
    if created:
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o755)
        os.fsync(descriptor)
        os.fsync(control_fd)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != 0o755
    ):
        os.close(descriptor)
        raise PublisherError("selector audit directory authority is unsafe")
    return descriptor


def _open_audit_directory_optional(
    control_fd: int, uid: int, gid: int
) -> int | None:
    try:
        named = os.stat(AUDIT_ROOT, dir_fd=control_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PublisherError("selector audit directory cannot be inspected") from exc
    try:
        descriptor = os.open(
            AUDIT_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=control_fd,
        )
    except OSError as exc:
        raise PublisherError("selector audit directory cannot be opened") from exc
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(named.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or not _same_identity(named, opened)
        or opened.st_uid != uid
        or opened.st_gid != gid
        or stat.S_IMODE(opened.st_mode) != 0o755
    ):
        os.close(descriptor)
        raise PublisherError("selector audit directory authority is unsafe")
    return descriptor


def _read_audit_record(
    audit_fd: int, name: str, uid: int, gid: int
) -> dict[str, object]:
    raw = _read_named_regular(
        audit_fd, name, uid=uid, gid=gid, mode=0o444, maximum=4096
    )
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublisherError("selector audit record is invalid") from exc
    expected_fields = {
        "audit_id",
        "from_release",
        "manifest_sha256",
        "operation",
        "prepared_unix_ns",
        "schema_version",
        "selector_stage",
        "to_release",
    }
    if (
        type(value) is not dict
        or set(value) != expected_fields
        or type(value.get("audit_id")) is not str
        or re.fullmatch(
            r"[1-9][0-9]*-[1-9][0-9]*-[0-9a-f]{16}", value["audit_id"]
        )
        is None
        or value.get("schema_version") != "grok-bootstrap-selector-audit-v1"
        or value.get("operation") not in {"publish", "reselect", "rollback"}
        or (
            value.get("from_release") is not None
            and (
                type(value.get("from_release")) is not str
                or RELEASE_ID_RE.fullmatch(value["from_release"]) is None
            )
        )
        or type(value.get("to_release")) is not str
        or RELEASE_ID_RE.fullmatch(value["to_release"]) is None
        or type(value.get("manifest_sha256")) is not str
        or RELEASE_ID_RE.fullmatch(value["manifest_sha256"]) is None
        or type(value.get("prepared_unix_ns")) is not int
        or not 1 <= value["prepared_unix_ns"] <= 2**63 - 1
        or type(value.get("selector_stage")) is not str
        or re.fullmatch(
            r"\.selected-release-[1-9][0-9]*-[0-9a-f]{16}",
            value["selector_stage"],
        )
        is None
        or raw != _canonical_json(value)
    ):
        raise PublisherError("selector audit record is invalid")
    return value


def _discard_incomplete_audit_stage(
    audit_fd: int, uid: int, gid: int
) -> None:
    try:
        named = os.stat(AUDIT_STAGE, dir_fd=audit_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PublisherError("incomplete selector audit cannot be inspected") from exc
    if (
        not stat.S_ISREG(named.st_mode)
        or named.st_uid != uid
        or named.st_gid != gid
        or stat.S_IMODE(named.st_mode) not in {0o600, 0o444}
        or named.st_nlink != 1
        or not 0 <= named.st_size <= 4096
    ):
        raise PublisherError("incomplete selector audit stage is unsafe")
    os.unlink(AUDIT_STAGE, dir_fd=audit_fd)
    os.fsync(audit_fd)


def _remove_recovered_selector_stage(
    control_fd: int,
    name: str,
    target: str,
    uid: int,
    gid: int,
) -> None:
    del target
    try:
        named = os.stat(name, dir_fd=control_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PublisherError("recovered selector stage cannot be inspected") from exc
    if (
        not stat.S_ISREG(named.st_mode)
        or named.st_uid != uid
        or named.st_gid != gid
        or stat.S_IMODE(named.st_mode) not in {0o600, 0o444}
        or named.st_nlink != 1
        or not 0 <= named.st_size <= 65
    ):
        raise PublisherError("recovered selector stage is unsafe")
    os.unlink(name, dir_fd=control_fd)
    os.fsync(control_fd)


def _reconcile_selector_audits(
    control_fd: int,
    store_fd: int,
    *,
    uid: int,
    gid: int,
    key_id: str,
    public_key: bytes,
) -> None:
    audit_fd = _open_audit_directory_optional(control_fd, uid, gid)
    if audit_fd is None:
        return
    try:
        _discard_incomplete_audit_stage(audit_fd, uid, gid)
        try:
            value = _read_audit_record(
                audit_fd, AUDIT_PENDING, uid, gid
            )
        except PublisherError as exc:
            try:
                os.stat(AUDIT_PENDING, dir_fd=audit_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise PublisherError("pending selector audit is unsafe") from exc
        current = _read_selector(control_fd, uid, gid)
        source = value["from_release"]
        target = str(value["to_release"])
        stage = str(value["selector_stage"])
        if current == source:
            _remove_recovered_selector_stage(
                control_fd, stage, target, uid, gid
            )
            destination = str(value["audit_id"]) + ".aborted.json"
            _rename_noreplace(audit_fd, AUDIT_PENDING, audit_fd, destination)
            os.fsync(audit_fd)
            return
        if current == target:
            try:
                os.stat(stage, dir_fd=control_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise PublisherError(
                    "committed selector stage cannot be inspected"
                ) from exc
            else:
                raise PublisherError(
                    "committed selector still has a publication stage"
                )
            _values, manifest_sha = _validated_release(
                store_fd,
                target,
                uid=uid,
                gid=gid,
                key_id=key_id,
                public_key=public_key,
            )
            if manifest_sha != value["manifest_sha256"]:
                raise PublisherError("pending selector audit target has changed")
            os.fsync(store_fd)
            os.fsync(control_fd)
            destination = str(value["audit_id"]) + ".committed.json"
            _rename_noreplace(audit_fd, AUDIT_PENDING, audit_fd, destination)
            os.fsync(audit_fd)
            return
        raise PublisherError("pending selector audit contradicts current selection")
    finally:
        os.close(audit_fd)


def _write_regular(
    directory_fd: int, name: str, data: bytes, uid: int, gid: int, mode: int
) -> int:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        os.fchown(descriptor, uid, gid)
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != mode
            or info.st_nlink != 1
            or info.st_size != len(data)
        ):
            raise PublisherError("atomic publication stage metadata is unsafe")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _rotate_selector(
    control_fd: int,
    *,
    uid: int,
    gid: int,
    current: str | None,
    target: str,
    operation: str,
    manifest_sha256: str,
    fail_before_rename: bool,
    fail_after_rename: bool,
) -> None:
    audit_fd = _audit_directory(control_fd, uid, gid)
    audit_id = f"{time.time_ns()}-{os.getpid()}-{secrets.token_hex(8)}"
    committed = audit_id + ".committed.json"
    temporary = f".selected-release-{os.getpid()}-{secrets.token_hex(8)}"
    audit_value = {
        "audit_id": audit_id,
        "from_release": current,
        "manifest_sha256": manifest_sha256,
        "operation": operation,
        "prepared_unix_ns": time.time_ns(),
        "schema_version": "grok-bootstrap-selector-audit-v1",
        "selector_stage": temporary,
        "to_release": target,
    }
    audit_file = _write_regular(
        audit_fd, AUDIT_STAGE, _canonical_json(audit_value), uid, gid, 0o444
    )
    os.close(audit_file)
    try:
        _rename_noreplace(audit_fd, AUDIT_STAGE, audit_fd, AUDIT_PENDING)
    except FileExistsError as exc:
        raise PublisherError("an unresolved selector audit is already pending") from exc
    os.fsync(audit_fd)
    selector_fd = -1
    present = True
    try:
        selector_fd = _write_regular(
            control_fd,
            temporary,
            (target + "\n").encode("ascii"),
            uid,
            gid,
            0o444,
        )
        os.close(selector_fd)
        selector_fd = -1
        if fail_before_rename:
            raise PublisherError("injected failure before selector rename")
        os.rename(
            temporary,
            SELECTOR,
            src_dir_fd=control_fd,
            dst_dir_fd=control_fd,
        )
        present = False
        os.fsync(control_fd)
        if _read_selector(control_fd, uid, gid) != target:
            raise PublisherError("selector publication did not bind the requested release")
        if fail_after_rename:
            raise PublisherError("injected failure after selector rename")
        _rename_noreplace(audit_fd, AUDIT_PENDING, audit_fd, committed)
        os.fsync(audit_fd)
    finally:
        if selector_fd >= 0:
            os.close(selector_fd)
        if present:
            try:
                os.unlink(temporary, dir_fd=control_fd)
                os.fsync(control_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        os.close(audit_fd)


def _publish(
    layout: Layout,
    source: Path,
    expected_current: str | None,
    *,
    fail_before_selector_rename: bool,
    fail_after_selector_rename: bool,
) -> dict[str, object]:
    source_fd = -1
    control_fd = -1
    store_fd = -1
    try:
        source_fd = layout.open_source(source)
        source_info = _source_directory(source_fd)
        control_fd = layout.open_control()
        store_fd = layout.open_store()
        with _bootstrap_locked(control_fd, layout.uid, layout.gid):
            key_id, public_key = _load_trust_anchor(
                control_fd, layout.uid, layout.gid
            )
            release_id = source.name
            if RELEASE_ID_RE.fullmatch(release_id) is None:
                raise PublisherError("signed application directory name is invalid")
            stage_name = f".publish-{release_id}-{secrets.token_hex(8)}"
            stage_fd = -1
            stage_present = False
            published = False
            try:
                stage_fd = _copy_source_to_stage(
                    source_fd,
                    source_info,
                    store_fd,
                    stage_name,
                    layout.uid,
                    layout.gid,
                )
                stage_present = True
                stage_values, stage_manifest_sha = _validated_release(
                    store_fd,
                    stage_name,
                    expected_release_id=release_id,
                    uid=layout.uid,
                    gid=layout.gid,
                    key_id=key_id,
                    public_key=public_key,
                )
                try:
                    _rename_noreplace(store_fd, stage_name, store_fd, release_id)
                    stage_present = False
                    published = True
                    published_info = os.stat(
                        release_id, dir_fd=store_fd, follow_symlinks=False
                    )
                    if not _same_snapshot(os.fstat(stage_fd), published_info):
                        raise PublisherError(
                            "published signed application identity changed"
                        )
                    os.fsync(store_fd)
                except FileExistsError:
                    try:
                        existing_values, existing_manifest_sha = _validated_release(
                            store_fd,
                            release_id,
                            uid=layout.uid,
                            gid=layout.gid,
                            key_id=key_id,
                            public_key=public_key,
                        )
                    except PublisherError as exc:
                        raise PublisherError(
                            "conflicting signed application already exists"
                        ) from exc
                    if (
                        existing_values != stage_values
                        or existing_manifest_sha != stage_manifest_sha
                    ):
                        raise PublisherError(
                            "conflicting signed application already exists"
                        )
                with _release_control_guard(layout) as release_control_fd:
                    _reconcile_selector_audits(
                        control_fd,
                        store_fd,
                        uid=layout.uid,
                        gid=layout.gid,
                        key_id=key_id,
                        public_key=public_key,
                    )
                    current = _read_selector(control_fd, layout.uid, layout.gid)
                    if current != expected_current:
                        raise PublisherError(
                            "bootstrap selector differs from expected current release"
                        )
                    changed = current != release_id
                    if changed:
                        _assert_release_control_quiescent(
                            layout, release_control_fd
                        )
                        _values, final_manifest_sha = _validated_release(
                            store_fd,
                            release_id,
                            uid=layout.uid,
                            gid=layout.gid,
                            key_id=key_id,
                            public_key=public_key,
                        )
                        if final_manifest_sha != stage_manifest_sha:
                            raise PublisherError(
                                "published signed application changed before selection"
                            )
                        _rotate_selector(
                            control_fd,
                            uid=layout.uid,
                            gid=layout.gid,
                            current=current,
                            target=release_id,
                            operation="publish",
                            manifest_sha256=stage_manifest_sha,
                            fail_before_rename=fail_before_selector_rename,
                            fail_after_rename=fail_after_selector_rename,
                        )
                return {
                    "changed": changed,
                    "operation": "publish",
                    "published": published,
                    "release_id": release_id,
                    "selected_release_id": release_id,
                }
            finally:
                if stage_fd >= 0:
                    if stage_present:
                        _remove_stage(store_fd, stage_name, stage_fd)
                    os.close(stage_fd)
    finally:
        if store_fd >= 0:
            os.close(store_fd)
        if control_fd >= 0:
            os.close(control_fd)
        if source_fd >= 0:
            os.close(source_fd)


def _select(
    layout: Layout,
    release_id: str,
    reason: str,
    expected_current: str | None,
    *,
    fail_before_selector_rename: bool,
    fail_after_selector_rename: bool,
) -> dict[str, object]:
    if RELEASE_ID_RE.fullmatch(release_id) is None:
        raise PublisherError("signed application id is invalid")
    control_fd = layout.open_control()
    store_fd = layout.open_store()
    try:
        with _bootstrap_locked(control_fd, layout.uid, layout.gid):
            key_id, public_key = _load_trust_anchor(
                control_fd, layout.uid, layout.gid
            )
            with _release_control_guard(layout) as release_control_fd:
                _reconcile_selector_audits(
                    control_fd,
                    store_fd,
                    uid=layout.uid,
                    gid=layout.gid,
                    key_id=key_id,
                    public_key=public_key,
                )
                current = _read_selector(control_fd, layout.uid, layout.gid)
                if current != expected_current:
                    raise PublisherError(
                        "bootstrap selector differs from expected current release"
                    )
                changed = current != release_id
                if changed:
                    _assert_release_control_quiescent(
                        layout, release_control_fd
                    )
                _values, manifest_sha = _validated_release(
                    store_fd,
                    release_id,
                    uid=layout.uid,
                    gid=layout.gid,
                    key_id=key_id,
                    public_key=public_key,
                )
                if changed:
                    _rotate_selector(
                        control_fd,
                        uid=layout.uid,
                        gid=layout.gid,
                        current=current,
                        target=release_id,
                        operation=reason,
                        manifest_sha256=manifest_sha,
                        fail_before_rename=fail_before_selector_rename,
                        fail_after_rename=fail_after_selector_rename,
                    )
            return {
                "changed": changed,
                "operation": reason,
                "published": False,
                "release_id": release_id,
                "selected_release_id": release_id,
            }
    finally:
        os.close(store_fd)
        os.close(control_fd)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument(
        "--test-fail-before-selector-rename",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--test-fail-after-selector-rename",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    publish = commands.add_parser("publish")
    publish.add_argument("--signed-application", required=True, type=Path)
    publish.add_argument("--expected-current", required=True)
    select_parser = commands.add_parser("select")
    select_parser.add_argument("--release-id", required=True)
    select_parser.add_argument("--expected-current", required=True)
    select_parser.add_argument("--reason", required=True, choices=("reselect", "rollback"))
    return parser.parse_args(argv)


def _expected_current(value: str) -> str | None:
    if value == "none":
        return None
    if RELEASE_ID_RE.fullmatch(value) is None:
        raise PublisherError("expected current release must be 'none' or 64 lowercase hex")
    return value


def main(argv: list[str] | None = None) -> int:
    layout: Layout | None = None
    try:
        args = _parse_args(argv)
        test_hook = (
            args.test_fail_before_selector_rename
            or args.test_fail_after_selector_rename
        )
        if test_hook and (
            args.test_root is None or os.environ.get(TEST_MODE_ENV) != "1"
        ):
            raise PublisherError("failure injection requires explicit test mode")
        layout = Layout(args.test_root)
        expected = _expected_current(args.expected_current)
        if args.command == "publish":
            result = _publish(
                layout,
                args.signed_application,
                expected,
                fail_before_selector_rename=args.test_fail_before_selector_rename,
                fail_after_selector_rename=args.test_fail_after_selector_rename,
            )
        else:
            result = _select(
                layout,
                args.release_id,
                args.reason,
                expected,
                fail_before_selector_rename=args.test_fail_before_selector_rename,
                fail_after_selector_rename=args.test_fail_after_selector_rename,
            )
        sys.stdout.buffer.write(_canonical_json(result))
        return 0
    except (PublisherError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"grok-bootstrap-publisher: {exc}", file=sys.stderr)
        return 2
    finally:
        if layout is not None:
            layout.close()


if __name__ == "__main__":
    raise SystemExit(main())
