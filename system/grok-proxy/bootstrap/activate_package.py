#!/usr/bin/python3
"""Activate one fixed Grok bootstrap package payload.

The production entry point accepts no path or source overrides.  A package
manager installs the reviewed payload and this activator at their fixed roots,
then invokes the closed launcher.  The test-only path stages those same build
artifacts beneath a private, descriptor-anchored non-root prefix.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


ACTIVATOR_ROOT = Path("/usr/libexec/grok-bootstrap-package")
ACTIVATOR_SCRIPT = ACTIVATOR_ROOT / "activate_package.py"
PAYLOAD_ROOT = Path("/usr/lib/grok-bootstrap-package")
CONTROL_ROOT = Path("/usr/local/libexec/grok-proxy/bootstrap")
STORE_ROOT = Path("/usr/local/libexec/grok-proxy/bootstrap-releases")
RELEASE_CONTROL_ROOT = Path("/var/lib/grok-proxy/release-control")
RUNNER_SCOPES = "runner-scopes"
UPDATE_LOCK = "update.lock"
OPERATION_LOCK = "operation.lock"
PACKAGE_PENDING = "package-update.pending"
MARKER_STAGE = ".package-update.pending.stage"
TEST_MODE_ENV = "GROK_BOOTSTRAP_PACKAGE_ACTIVATOR_TEST_MODE"
TRUST_SCHEMA = "grok-bootstrap-trust-anchor-v1"
GENERATION_SCHEMA = "grok-bootstrap-package-generation-v1"
MARKER_SCHEMA = "grok-bootstrap-package-update-v1"
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")

PAYLOAD_SPEC = {
    "grok-bootstrap": (0o555, 16 * 1024 * 1024),
    "grok-bootstrap-publisher.py": (0o444, 4 * 1024 * 1024),
    "grok-bootstrap-publisher": (0o555, 16 * 1024),
}
ACTIVATOR_SPEC = {
    "activate_package.py": (0o444, 4 * 1024 * 1024),
    "grok-bootstrap-package-activate": (0o555, 16 * 1024),
}

STATIC_LAUNCHER_COMMON_TOKENS = (
    b"/usr/bin/python3\x00",
    b"-I\x00",
    b"-B\x00",
    b"-S\x00",
    b"PATH=/usr/bin:/bin\x00",
    b"LANG=C\x00",
    b"LC_ALL=C\x00",
    b"PYTHONDONTWRITEBYTECODE=1\x00",
)
ACTIVATOR_LAUNCHER_CONTRACT = (
    b"grok-static-python-launcher-v1:zero-arguments\x00"
)
PUBLISHER_LAUNCHER_CONTRACT = (
    b"grok-static-python-launcher-v1:forward-bounded-64\x00"
)


class ActivationError(RuntimeError):
    """The package cannot be activated without weakening an authority."""


class InjectedFailure(RuntimeError):
    """A test-only crash point was reached."""

    def __init__(self, code: int, stage: str) -> None:
        super().__init__(stage)
        self.code = code
        self.stage = stage


class OpenedFile:
    def __init__(
        self, name: str, descriptor: int, information: os.stat_result, data: bytes
    ) -> None:
        self.name = name
        self.descriptor = descriptor
        self.information = information
        self.data = data

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


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


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(descriptor, data[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise ActivationError("package artifact write did not progress")
        offset += written


def _set_owner(descriptor: int, uid: int, gid: int) -> None:
    information = os.fstat(descriptor)
    if information.st_uid != uid or information.st_gid != gid:
        os.fchown(descriptor, uid, gid)


def _read_all(descriptor: int, maximum: int) -> bytes:
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
            raise ActivationError("package artifact exceeds its size bound")
        chunks.append(chunk)


def _bounded_names(directory_fd: int, maximum: int) -> list[str]:
    names: list[str] = []
    with os.scandir(directory_fd) as iterator:
        for entry in iterator:
            names.append(entry.name)
            if len(names) > maximum:
                raise ActivationError("package directory inventory is not closed")
    names.sort()
    return names


def _components(path: Path) -> tuple[str, ...]:
    if not path.is_absolute():
        raise ActivationError("fixed package path is not absolute")
    result = path.parts[1:]
    if not result or any(part in {"", ".", ".."} or "/" in part for part in result):
        raise ActivationError("fixed package path is invalid")
    return result


class Layout:
    def __init__(self, test_root: Path | None, test_mode_admitted: bool) -> None:
        self.root_fd = -1
        self.test_mode = test_root is not None
        self.uid = os.geteuid()
        self.gid = os.getegid()
        if self.test_mode:
            if (
                not test_mode_admitted
                or self.uid == 0
                or test_root is None
                or not test_root.is_absolute()
            ):
                raise ActivationError(
                    "test root requires explicit nonprivileged package-activator test mode"
                )
            try:
                if test_root.resolve(strict=True) != test_root:
                    raise ActivationError("test root must be an existing canonical path")
            except OSError as exc:
                raise ActivationError("test root must be an existing canonical path") from exc
            self.root_fd = self._open_test_root(test_root)
        else:
            if test_mode_admitted:
                raise ActivationError("package-activator test controls require a test root")
            if self.uid != 0 or self.gid != 0:
                raise ActivationError("production package activation is root-only")
            self.uid = 0
            self.gid = 0
            self.root_fd = os.open(
                "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            root = os.fstat(self.root_fd)
            if (
                not stat.S_ISDIR(root.st_mode)
                or root.st_uid != 0
                or root.st_gid != 0
                or stat.S_IMODE(root.st_mode) & 0o022
            ):
                self.close()
                raise ActivationError("root filesystem authority is unsafe")

    def _open_test_root(self, path: Path) -> int:
        descriptor = os.open(
            "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            root = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(root.st_mode)
                or (root.st_uid, root.st_gid)
                not in {(0, 0), (self.uid, self.gid)}
                or stat.S_IMODE(root.st_mode) & 0o022
            ):
                raise ActivationError("test root ancestry is unsafe")
            parts = _components(path)
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
                    or opened.st_uid not in {0, self.uid}
                    or stat.S_IMODE(opened.st_mode) & 0o022
                    or (
                        final
                        and (
                            opened.st_uid != self.uid
                            or opened.st_gid != self.gid
                            or stat.S_IMODE(opened.st_mode) != 0o700
                        )
                    )
                ):
                    os.close(child)
                    raise ActivationError("test root ancestry is unsafe")
                os.close(descriptor)
                descriptor = child
            return descriptor
        except OSError as exc:
            os.close(descriptor)
            raise ActivationError("test root ancestry is unsafe") from exc
        except BaseException:
            os.close(descriptor)
            raise

    def _open_path(
        self,
        path: Path,
        final_mode: int,
        *,
        create: bool,
        writable_leaf_for_test_staging: bool = False,
    ) -> int:
        descriptor = os.dup(self.root_fd)
        try:
            parts = _components(path)
            for index, part in enumerate(parts):
                final = index == len(parts) - 1
                desired = final_mode if final else 0o755
                created = False
                try:
                    named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    created = True
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
                try:
                    opened = os.fstat(child)
                    if created:
                        _set_owner(child, self.uid, self.gid)
                        os.fchmod(child, desired)
                        os.fsync(child)
                        named = os.stat(
                            part, dir_fd=descriptor, follow_symlinks=False
                        )
                        opened = os.fstat(child)
                        os.fsync(descriptor)
                except BaseException:
                    os.close(child)
                    raise
                allowed_final_modes = {final_mode}
                if final and writable_leaf_for_test_staging and self.test_mode:
                    allowed_final_modes.add(0o755)
                if (
                    not stat.S_ISDIR(named.st_mode)
                    or not stat.S_ISDIR(opened.st_mode)
                    or not _same_identity(named, opened)
                    or opened.st_uid != self.uid
                    or opened.st_gid != self.gid
                    or stat.S_IMODE(opened.st_mode) & 0o022
                    or (
                        final
                        and stat.S_IMODE(opened.st_mode) not in allowed_final_modes
                    )
                ):
                    os.close(child)
                    raise ActivationError("fixed package directory authority is unsafe")
                os.close(descriptor)
                descriptor = child
            return descriptor
        except OSError as exc:
            os.close(descriptor)
            raise ActivationError("fixed package directory authority is unsafe") from exc
        except BaseException:
            os.close(descriptor)
            raise

    def open_existing(self, path: Path, mode: int) -> int:
        return self._open_path(path, mode, create=False)

    def ensure(self, path: Path, mode: int) -> int:
        return self._open_path(path, mode, create=True)

    def open_test_staging_directory(self, path: Path) -> int:
        if not self.test_mode:
            raise ActivationError("package payload staging is test-only")
        descriptor = self._open_path(
            path, 0o555, create=True, writable_leaf_for_test_staging=True
        )
        os.fchmod(descriptor, 0o755)
        os.fsync(descriptor)
        return descriptor

    def check_identity(self, path: Path, mode: int, held_fd: int) -> None:
        current = self.open_existing(path, mode)
        try:
            if not _same_identity(os.fstat(current), os.fstat(held_fd)):
                raise ActivationError("fixed package directory identity changed")
        finally:
            os.close(current)

    def close(self) -> None:
        if self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1


def _open_external_test_source(path: Path, uid: int, gid: int) -> int:
    if not path.is_absolute():
        raise ActivationError("test package source must be absolute")
    try:
        if path.resolve(strict=True) != path:
            raise ActivationError("test package source must be canonical")
    except OSError as exc:
        raise ActivationError("test package source must be canonical") from exc
    descriptor = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        for index, part in enumerate(_components(path)):
            named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            opened = os.fstat(child)
            final = index == len(_components(path)) - 1
            if (
                not stat.S_ISDIR(named.st_mode)
                or not stat.S_ISDIR(opened.st_mode)
                or not _same_identity(named, opened)
                or opened.st_uid not in {0, uid}
                or stat.S_IMODE(opened.st_mode) & 0o002
                or (
                    final
                    and (
                        opened.st_uid != uid
                        or opened.st_gid != gid
                        or stat.S_IMODE(opened.st_mode) & 0o022
                    )
                )
            ):
                os.close(child)
                raise ActivationError("test package source ancestry is unsafe")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise ActivationError("test package source ancestry is unsafe") from exc
    except BaseException:
        os.close(descriptor)
        raise


def _open_verified_file(
    directory_fd: int,
    name: str,
    *,
    uid: int,
    gid: int,
    mode: int,
    maximum: int,
) -> OpenedFile:
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise ActivationError(f"package artifact is unsafe: {name}") from exc
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
            or not 0 < opened.st_size <= maximum
        ):
            raise ActivationError(f"package artifact is unsafe: {name}")
        data = _read_all(descriptor, maximum)
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            len(data) != opened.st_size
            or not _same_snapshot(opened, os.fstat(descriptor))
            or not _same_snapshot(opened, named_after)
        ):
            raise ActivationError(f"package artifact changed while read: {name}")
        return OpenedFile(name, descriptor, opened, data)
    except BaseException:
        os.close(descriptor)
        raise


def _check_opened_file(
    directory_fd: int, opened_file: OpenedFile, *, uid: int, gid: int, mode: int
) -> None:
    try:
        named = os.stat(opened_file.name, dir_fd=directory_fd, follow_symlinks=False)
        opened = os.fstat(opened_file.descriptor)
    except OSError as exc:
        raise ActivationError("package artifact identity changed") from exc
    if (
        not _same_snapshot(opened_file.information, opened)
        or not _same_snapshot(opened_file.information, named)
        or opened.st_uid != uid
        or opened.st_gid != gid
        or stat.S_IMODE(opened.st_mode) != mode
    ):
        raise ActivationError("package artifact identity changed")


def _close_files(files: dict[str, OpenedFile]) -> None:
    for opened_file in files.values():
        opened_file.close()


def _open_closed_files(
    directory_fd: int,
    spec: dict[str, tuple[int, int]],
    *,
    uid: int,
    gid: int,
) -> dict[str, OpenedFile]:
    if _bounded_names(directory_fd, len(spec)) != sorted(spec):
        raise ActivationError("package artifact set is not closed")
    files: dict[str, OpenedFile] = {}
    try:
        for name, (mode, maximum) in spec.items():
            files[name] = _open_verified_file(
                directory_fd,
                name,
                uid=uid,
                gid=gid,
                mode=mode,
                maximum=maximum,
            )
        return files
    except BaseException:
        _close_files(files)
        raise


def _remove_safe_stage(
    directory_fd: int,
    name: str,
    *,
    uid: int,
    gid: int,
    maximum: int,
    allowed_modes: set[int],
) -> None:
    try:
        information = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ActivationError("reserved package stage is unsafe") from exc
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_uid != uid
        or information.st_gid != gid
        or information.st_nlink != 1
        or information.st_size < 0
        or information.st_size > maximum
        or stat.S_IMODE(information.st_mode) not in allowed_modes
    ):
        raise ActivationError("reserved package stage is unsafe")
    os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def _replace_from_bytes(
    directory_fd: int,
    name: str,
    data: bytes,
    *,
    uid: int,
    gid: int,
    mode: int,
    maximum: int,
    stage_prefix: str,
) -> None:
    stage = f".{stage_prefix}-{name}.stage"
    _remove_safe_stage(
        directory_fd,
        stage,
        uid=uid,
        gid=gid,
        maximum=maximum,
        allowed_modes={0o600, mode},
    )
    descriptor = os.open(
        stage,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        _set_owner(descriptor, uid, gid)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(stage, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)


def _stage_test_payload(layout: Layout, source: Path) -> None:
    source_fd = _open_external_test_source(source, layout.uid, layout.gid)
    payload_fd = -1
    activator_fd = -1
    source_files: dict[str, OpenedFile] = {}
    try:
        combined = {**PAYLOAD_SPEC, **ACTIVATOR_SPEC}
        for name, (mode, maximum) in combined.items():
            source_files[name] = _open_verified_file(
                source_fd,
                name,
                uid=layout.uid,
                gid=layout.gid,
                mode=mode,
                maximum=maximum,
            )
        payload_fd = layout.open_test_staging_directory(PAYLOAD_ROOT)
        activator_fd = layout.open_test_staging_directory(ACTIVATOR_ROOT)
        for name, (mode, maximum) in PAYLOAD_SPEC.items():
            _replace_from_bytes(
                payload_fd,
                name,
                source_files[name].data,
                uid=layout.uid,
                gid=layout.gid,
                mode=mode,
                maximum=maximum,
                stage_prefix="test-package",
            )
        for name, (mode, maximum) in ACTIVATOR_SPEC.items():
            _replace_from_bytes(
                activator_fd,
                name,
                source_files[name].data,
                uid=layout.uid,
                gid=layout.gid,
                mode=mode,
                maximum=maximum,
                stage_prefix="test-package",
            )
        os.fchmod(payload_fd, 0o555)
        os.fchmod(activator_fd, 0o555)
        os.fsync(payload_fd)
        os.fsync(activator_fd)
    finally:
        _close_files(source_files)
        if payload_fd >= 0:
            os.close(payload_fd)
        if activator_fd >= 0:
            os.close(activator_fd)
        os.close(source_fd)


def _parse_anchor(raw: bytes) -> dict[str, str]:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActivationError("native bootstrap trust anchor is invalid") from exc
    if (
        type(value) is not dict
        or set(value) != {"schema_version", "key_id", "public_key_hex"}
        or value.get("schema_version") != TRUST_SCHEMA
        or type(value.get("key_id")) is not str
        or KEY_ID_RE.fullmatch(value["key_id"]) is None
        or type(value.get("public_key_hex")) is not str
        or HEX_RE.fullmatch(value["public_key_hex"]) is None
        or raw != _canonical_json(value)
    ):
        raise ActivationError("native bootstrap trust anchor is invalid")
    return value


def _describe_native(opened_file: OpenedFile) -> dict[str, str]:
    try:
        completed = subprocess.run(
            [f"/proc/self/fd/{opened_file.descriptor}", "--describe-trust-anchor"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(opened_file.descriptor,),
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ActivationError("native bootstrap trust-anchor report failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > 1024:
        raise ActivationError("native bootstrap trust-anchor report failed")
    if not _same_snapshot(opened_file.information, os.fstat(opened_file.descriptor)):
        raise ActivationError("native bootstrap changed during trust-anchor report")
    return _parse_anchor(completed.stdout)


def _validate_static_launcher(raw: bytes, *, script: bytes, contract: bytes) -> None:
    expected_machine = {"x86_64": 62, "aarch64": 183}.get(os.uname().machine)
    if (
        expected_machine is None
        or len(raw) < 64
        or raw[:7] != b"\x7fELF\x02\x01\x01"
        or int.from_bytes(raw[16:18], "little") != 2
        or int.from_bytes(raw[18:20], "little") != expected_machine
        or int.from_bytes(raw[20:24], "little") != 1
        or int.from_bytes(raw[52:54], "little") != 64
    ):
        raise ActivationError("static Python launcher ELF header is invalid")
    program_offset = int.from_bytes(raw[32:40], "little")
    program_size = int.from_bytes(raw[54:56], "little")
    program_count = int.from_bytes(raw[56:58], "little")
    if (
        program_size != 56
        or not 1 <= program_count <= 64
        or program_offset < 64
        or program_offset + program_size * program_count > len(raw)
    ):
        raise ActivationError("static Python launcher program headers are invalid")
    program_types = {
        int.from_bytes(
            raw[
                program_offset + index * program_size :
                program_offset + index * program_size + 4
            ],
            "little",
        )
        for index in range(program_count)
    }
    if 1 not in program_types or 2 in program_types or 3 in program_types:
        raise ActivationError("Python launcher is not a static no-interpreter ELF")
    required = (*STATIC_LAUNCHER_COMMON_TOKENS, script, contract)
    if any(raw.count(token) != 1 for token in required):
        raise ActivationError("static Python launcher contract is invalid")
    if b"LD_PRELOAD" in raw or b"LD_LIBRARY_PATH" in raw:
        raise ActivationError("static Python launcher contains a loader input")


def _validate_support(payload: dict[str, OpenedFile]) -> None:
    try:
        compile(
            payload["grok-bootstrap-publisher.py"].data,
            "grok-bootstrap-publisher.py",
            "exec",
        )
    except (SyntaxError, ValueError) as exc:
        raise ActivationError("publisher implementation is not valid Python") from exc
    _validate_static_launcher(
        payload["grok-bootstrap-publisher"].data,
        script=(
            b"/usr/local/libexec/grok-proxy/bootstrap/"
            b"grok-bootstrap-publisher.py\x00"
        ),
        contract=PUBLISHER_LAUNCHER_CONTRACT,
    )


def _generation(
    payload: dict[str, OpenedFile], anchor: dict[str, str]
) -> tuple[dict[str, object], bytes]:
    artifacts: dict[str, object] = {}
    for name, (mode, _maximum) in PAYLOAD_SPEC.items():
        data = payload[name].data
        artifacts[name] = {
            "mode": f"{mode:04o}",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
    generation: dict[str, object] = {
        "anchor": anchor,
        "artifacts": artifacts,
        "schema_version": GENERATION_SCHEMA,
    }
    generation_id = hashlib.sha256(_canonical_json(generation)).hexdigest()
    marker = {
        "generation": generation,
        "generation_id": generation_id,
        "schema_version": MARKER_SCHEMA,
    }
    return generation, _canonical_json(marker)


def _open_or_create_lock(
    directory_fd: int, name: str, *, uid: int, gid: int
) -> tuple[int, os.stat_result]:
    created = False
    try:
        descriptor = os.open(
            name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        created = True
        _set_owner(descriptor, uid, gid)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.fsync(directory_fd)
    except FileExistsError:
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise ActivationError(f"package lock is unsafe: {name}") from exc
    except OSError as exc:
        raise ActivationError(f"package lock is unsafe: {name}") from exc
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
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
            raise ActivationError(f"package lock is unsafe: {name}")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        if created:
            # The inode is intentionally left in place.  Lock anchors are never
            # unlinked by this activator, including on failed first activation.
            pass
        raise


def _lock_and_recheck(
    directory_fd: int,
    name: str,
    descriptor: int,
    original: os.stat_result,
    operation: int,
) -> None:
    fcntl.flock(descriptor, operation)
    _recheck_lock(directory_fd, name, descriptor, original)


def _recheck_lock(
    directory_fd: int,
    name: str,
    descriptor: int,
    original: os.stat_result,
) -> None:
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise ActivationError("package lock identity changed while held") from exc
    if not _same_snapshot(original, named) or not _same_snapshot(original, opened):
        raise ActivationError("package lock identity changed while held")


def _open_optional_installed(
    directory_fd: int,
    name: str,
    *,
    uid: int,
    gid: int,
    mode: int,
    maximum: int,
) -> OpenedFile | None:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ActivationError(f"installed package artifact is unsafe: {name}") from exc
    try:
        return _open_verified_file(
            directory_fd,
            name,
            uid=uid,
            gid=gid,
            mode=mode,
            maximum=maximum,
        )
    except ActivationError as exc:
        raise ActivationError(f"installed package artifact is unsafe: {name}") from exc


def _read_pending(
    control_fd: int, *, uid: int, gid: int
) -> tuple[OpenedFile, bytes] | None:
    pending = _open_optional_installed(
        control_fd,
        PACKAGE_PENDING,
        uid=uid,
        gid=gid,
        mode=0o444,
        maximum=16 * 1024,
    )
    if pending is None:
        return None
    try:
        value = json.loads(pending.data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        pending.close()
        raise ActivationError("package update marker is invalid") from exc
    if type(value) is not dict or pending.data != _canonical_json(value):
        pending.close()
        raise ActivationError("package update marker is invalid")
    return pending, pending.data


def _write_pending(
    control_fd: int, marker: bytes, *, uid: int, gid: int
) -> OpenedFile:
    _remove_safe_stage(
        control_fd,
        MARKER_STAGE,
        uid=uid,
        gid=gid,
        maximum=16 * 1024,
        allowed_modes={0o600, 0o444},
    )
    descriptor = os.open(
        MARKER_STAGE,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC,
        0o600,
        dir_fd=control_fd,
    )
    try:
        _set_owner(descriptor, uid, gid)
        _write_all(descriptor, marker)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.rename(
        MARKER_STAGE,
        PACKAGE_PENDING,
        src_dir_fd=control_fd,
        dst_dir_fd=control_fd,
    )
    os.fsync(control_fd)
    result = _read_pending(control_fd, uid=uid, gid=gid)
    if result is None:
        raise ActivationError("package update marker publication failed")
    return result[0]


def _validate_existing_components(
    control_fd: int,
    *,
    uid: int,
    gid: int,
    anchor: dict[str, str],
    pending_exists: bool,
) -> None:
    opened: dict[str, OpenedFile] = {}
    try:
        for name, (mode, maximum) in PAYLOAD_SPEC.items():
            value = _open_optional_installed(
                control_fd,
                name,
                uid=uid,
                gid=gid,
                mode=mode,
                maximum=maximum,
            )
            if value is not None:
                opened[name] = value
        native = opened.get("grok-bootstrap")
        if native is not None and _describe_native(native) != anchor:
            raise ActivationError(
                "Grok bootstrap key rotation requires an explicit future migration"
            )
        if native is None and not pending_exists and any(
            name in opened for name in PAYLOAD_SPEC if name != "grok-bootstrap"
        ):
            raise ActivationError("unmarked partial Grok package state is unsafe")
    finally:
        _close_files(opened)


def _stage_active_components(
    control_fd: int,
    payload: dict[str, OpenedFile],
    *,
    uid: int,
    gid: int,
) -> dict[str, str]:
    stages: dict[str, str] = {}
    for name, (mode, maximum) in PAYLOAD_SPEC.items():
        stage = f".package-activate-{name}.stage"
        _remove_safe_stage(
            control_fd,
            stage,
            uid=uid,
            gid=gid,
            maximum=maximum,
            allowed_modes={0o600, mode},
        )
        descriptor = os.open(
            stage,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=control_fd,
        )
        try:
            _set_owner(descriptor, uid, gid)
            _write_all(descriptor, payload[name].data)
            os.fsync(descriptor)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        staged = _open_verified_file(
            control_fd,
            stage,
            uid=uid,
            gid=gid,
            mode=mode,
            maximum=maximum,
        )
        try:
            if staged.data != payload[name].data:
                raise ActivationError("staged package artifact differs from payload")
        finally:
            staged.close()
        stages[name] = stage
    os.fsync(control_fd)
    return stages


def _cleanup_active_stages(
    control_fd: int,
    *,
    uid: int,
    gid: int,
) -> None:
    for name, (mode, maximum) in PAYLOAD_SPEC.items():
        _remove_safe_stage(
            control_fd,
            f".package-activate-{name}.stage",
            uid=uid,
            gid=gid,
            maximum=maximum,
            allowed_modes={0o600, mode},
        )


def _activate_components(
    control_fd: int,
    stages: dict[str, str],
    *,
    test_fail_at: str | None,
) -> None:
    for name in ("grok-bootstrap-publisher.py", "grok-bootstrap-publisher"):
        os.replace(
            stages[name], name, src_dir_fd=control_fd, dst_dir_fd=control_fd
        )
    os.fsync(control_fd)
    if test_fail_at == "support":
        raise InjectedFailure(99, "support")
    os.replace(
        stages["grok-bootstrap"],
        "grok-bootstrap",
        src_dir_fd=control_fd,
        dst_dir_fd=control_fd,
    )
    os.fsync(control_fd)
    if test_fail_at == "native":
        raise InjectedFailure(98, "native")


def _verify_installed_generation(
    control_fd: int,
    payload: dict[str, OpenedFile],
    anchor: dict[str, str],
    *,
    uid: int,
    gid: int,
) -> None:
    installed: dict[str, OpenedFile] = {}
    try:
        for name, (mode, maximum) in PAYLOAD_SPEC.items():
            installed[name] = _open_verified_file(
                control_fd,
                name,
                uid=uid,
                gid=gid,
                mode=mode,
                maximum=maximum,
            )
            if installed[name].data != payload[name].data:
                raise ActivationError("installed package generation is mixed")
        if _describe_native(installed["grok-bootstrap"]) != anchor:
            raise ActivationError("installed native bootstrap anchor is inconsistent")
    finally:
        _close_files(installed)


def _verify_runtime_script(
    activator_files: dict[str, OpenedFile], *, test_mode: bool, uid: int, gid: int
) -> None:
    _validate_static_launcher(
        activator_files["grok-bootstrap-package-activate"].data,
        script=b"/usr/libexec/grok-bootstrap-package/activate_package.py\x00",
        contract=ACTIVATOR_LAUNCHER_CONTRACT,
    )
    if not test_mode:
        if Path(__file__) != ACTIVATOR_SCRIPT:
            raise ActivationError("production activator was not loaded from its fixed path")
        return
    try:
        runtime = Path(__file__)
        named = runtime.lstat()
        descriptor = os.open(
            runtime, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as exc:
        raise ActivationError("test activator runtime is unsafe") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(named.st_mode)
            or not _same_identity(named, opened)
            or opened.st_uid != uid
            or opened.st_gid != gid
            or stat.S_IMODE(opened.st_mode) != 0o444
            or opened.st_nlink != 1
            or opened.st_size > ACTIVATOR_SPEC["activate_package.py"][1]
            or _read_all(descriptor, ACTIVATOR_SPEC["activate_package.py"][1])
            != activator_files["activate_package.py"].data
            or not _same_snapshot(opened, os.fstat(descriptor))
        ):
            raise ActivationError("test activator runtime differs from staged package")
    finally:
        os.close(descriptor)


def _activate(layout: Layout, test_fail_at: str | None) -> dict[str, object]:
    activator_fd = layout.open_existing(ACTIVATOR_ROOT, 0o555)
    payload_fd = layout.open_existing(PAYLOAD_ROOT, 0o555)
    activator_files: dict[str, OpenedFile] = {}
    payload: dict[str, OpenedFile] = {}
    control_fd = -1
    store_fd = -1
    release_control_fd = -1
    runner_scopes_fd = -1
    update_fd = -1
    operation_fd = -1
    pending_file: OpenedFile | None = None
    stages_created = False
    try:
        activator_files = _open_closed_files(
            activator_fd,
            ACTIVATOR_SPEC,
            uid=layout.uid,
            gid=layout.gid,
        )
        payload = _open_closed_files(
            payload_fd, PAYLOAD_SPEC, uid=layout.uid, gid=layout.gid
        )
        _verify_runtime_script(
            activator_files,
            test_mode=layout.test_mode,
            uid=layout.uid,
            gid=layout.gid,
        )
        _validate_support(payload)
        anchor = _describe_native(payload["grok-bootstrap"])
        generation, marker = _generation(payload, anchor)
        generation_id = hashlib.sha256(_canonical_json(generation)).hexdigest()

        control_fd = layout.ensure(CONTROL_ROOT, 0o755)
        update_fd, update_info = _open_or_create_lock(
            control_fd, UPDATE_LOCK, uid=layout.uid, gid=layout.gid
        )
        _lock_and_recheck(
            control_fd, UPDATE_LOCK, update_fd, update_info, fcntl.LOCK_EX
        )

        store_fd = layout.ensure(STORE_ROOT, 0o755)
        release_control_fd = layout.ensure(RELEASE_CONTROL_ROOT, 0o755)
        operation_fd, operation_info = _open_or_create_lock(
            release_control_fd,
            OPERATION_LOCK,
            uid=layout.uid,
            gid=layout.gid,
        )
        _lock_and_recheck(
            release_control_fd,
            OPERATION_LOCK,
            operation_fd,
            operation_info,
            fcntl.LOCK_SH,
        )
        runner_scopes_fd = layout.ensure(
            RELEASE_CONTROL_ROOT / RUNNER_SCOPES, 0o700
        )

        pending = _read_pending(control_fd, uid=layout.uid, gid=layout.gid)
        if pending is not None:
            pending_file, pending_bytes = pending
            if pending_bytes != marker:
                raise ActivationError(
                    "pending package generation differs from the fixed payload"
                )
        _validate_existing_components(
            control_fd,
            uid=layout.uid,
            gid=layout.gid,
            anchor=anchor,
            pending_exists=pending_file is not None,
        )
        stages_created = True
        stages = _stage_active_components(
            control_fd, payload, uid=layout.uid, gid=layout.gid
        )
        if pending_file is None:
            pending_file = _write_pending(
                control_fd, marker, uid=layout.uid, gid=layout.gid
            )
        _activate_components(control_fd, stages, test_fail_at=test_fail_at)
        _verify_installed_generation(
            control_fd,
            payload,
            anchor,
            uid=layout.uid,
            gid=layout.gid,
        )

        layout.check_identity(ACTIVATOR_ROOT, 0o555, activator_fd)
        layout.check_identity(PAYLOAD_ROOT, 0o555, payload_fd)
        layout.check_identity(CONTROL_ROOT, 0o755, control_fd)
        layout.check_identity(STORE_ROOT, 0o755, store_fd)
        layout.check_identity(RELEASE_CONTROL_ROOT, 0o755, release_control_fd)
        layout.check_identity(
            RELEASE_CONTROL_ROOT / RUNNER_SCOPES, 0o700, runner_scopes_fd
        )
        _recheck_lock(control_fd, UPDATE_LOCK, update_fd, update_info)
        _recheck_lock(
            release_control_fd,
            OPERATION_LOCK,
            operation_fd,
            operation_info,
        )
        for name, (mode, _maximum) in ACTIVATOR_SPEC.items():
            _check_opened_file(
                activator_fd,
                activator_files[name],
                uid=layout.uid,
                gid=layout.gid,
                mode=mode,
            )
        for name, (mode, _maximum) in PAYLOAD_SPEC.items():
            _check_opened_file(
                payload_fd,
                payload[name],
                uid=layout.uid,
                gid=layout.gid,
                mode=mode,
            )
        assert pending_file is not None
        _check_opened_file(
            control_fd,
            pending_file,
            uid=layout.uid,
            gid=layout.gid,
            mode=0o444,
        )
        os.unlink(PACKAGE_PENDING, dir_fd=control_fd)
        os.fsync(control_fd)
        pending_file.close()
        pending_file = None
        stages_created = False
        return {"activated": True, "generation_id": generation_id}
    finally:
        if stages_created and control_fd >= 0:
            try:
                _cleanup_active_stages(
                    control_fd, uid=layout.uid, gid=layout.gid
                )
            except ActivationError:
                pass
        if pending_file is not None:
            pending_file.close()
        if operation_fd >= 0:
            os.close(operation_fd)
        if update_fd >= 0:
            os.close(update_fd)
        for descriptor in (
            runner_scopes_fd,
            release_control_fd,
            store_fd,
            control_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)
        _close_files(payload)
        _close_files(activator_files)
        os.close(payload_fd)
        os.close(activator_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="activate the fixed Grok bootstrap package payload"
    )
    parser.add_argument("--test-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--test-stage-from", type=Path, help=argparse.SUPPRESS)
    parser.add_argument(
        "--test-fail-at", choices=("support", "native"), help=argparse.SUPPRESS
    )
    return parser


def main(arguments: list[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    test_mode_admitted = os.environ.get(TEST_MODE_ENV) == "1"
    os.umask(0o077)
    os.environ.clear()
    os.environ.update(
        {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    layout: Layout | None = None
    try:
        if (
            parsed.test_root is None
            and (parsed.test_stage_from is not None or parsed.test_fail_at is not None)
        ):
            raise ActivationError("package-activator test controls require a test root")
        layout = Layout(parsed.test_root, test_mode_admitted)
        if parsed.test_stage_from is not None:
            _stage_test_payload(layout, parsed.test_stage_from)
        result = _activate(layout, parsed.test_fail_at)
        sys.stdout.buffer.write(_canonical_json(result))
        return 0
    except InjectedFailure as exc:
        sys.stderr.write(f"grok-package-activate: injected {exc.stage} failure\n")
        return exc.code
    except (ActivationError, OSError, subprocess.SubprocessError) as exc:
        sys.stderr.write(f"grok-package-activate: {exc}\n")
        return 2
    finally:
        if layout is not None:
            layout.close()


if __name__ == "__main__":
    raise SystemExit(main())
