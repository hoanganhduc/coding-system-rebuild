#!/usr/bin/python3
"""Build the closed Grok bootstrap Debian package as a non-root user."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


DPKG_DEB = "/usr/bin/dpkg-deb"
READELF = "/usr/bin/readelf"
NM = "/usr/bin/nm"
PACKAGE_NAME = "grok-bootstrap"
PACKAGE_METADATA = Path(__file__).resolve().parent / "package" / "grok-bootstrap-package.json"
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+~_-]{0,127}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ARCHITECTURES = {
    "amd64": ("x86_64", 62),
    "arm64": ("aarch64", 183),
}
MAX_SOURCE_DATE_EPOCH = 4_102_444_800
FIXED_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
}

COMMON_LAUNCHER_TOKENS = (
    b"/usr/bin/python3\x00",
    b"-I\x00",
    b"-B\x00",
    b"-S\x00",
    b"PATH=/usr/bin:/bin\x00",
    b"LANG=C\x00",
    b"LC_ALL=C\x00",
    b"PYTHONDONTWRITEBYTECODE=1\x00",
)

ROOT_SPEC = {
    "/usr/lib/grok-bootstrap-package": {
        "mode": 0o555,
        "files": {
            "grok-bootstrap": {
                "build": "build/grok-bootstrap",
                "mode": 0o555,
                "maximum": 16 * 1024 * 1024,
                "kind": "native-elf",
            },
            "grok-bootstrap-publisher.py": {
                "build": "build/grok-bootstrap-publisher.py",
                "mode": 0o444,
                "maximum": 4 * 1024 * 1024,
                "kind": "python",
            },
            "grok-bootstrap-publisher": {
                "build": "build/grok-bootstrap-publisher",
                "mode": 0o555,
                "maximum": 16 * 1024,
                "kind": "publisher-launcher",
            },
        },
    },
    "/usr/libexec/grok-bootstrap-package": {
        "mode": 0o555,
        "files": {
            "activate_package.py": {
                "build": "build/activate_package.py",
                "mode": 0o444,
                "maximum": 4 * 1024 * 1024,
                "kind": "python",
            },
            "grok-bootstrap-package-activate": {
                "build": "build/grok-bootstrap-package-activate",
                "mode": 0o555,
                "maximum": 16 * 1024,
                "kind": "activator-launcher",
            },
        },
    },
}

LAUNCHER_CONTRACTS = {
    "publisher-launcher": (
        b"/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap-publisher.py\x00",
        b"grok-static-python-launcher-v1:forward-bounded-64\x00",
    ),
    "activator-launcher": (
        b"/usr/libexec/grok-bootstrap-package/activate_package.py\x00",
        b"grok-static-python-launcher-v1:zero-arguments\x00",
    ),
}


class PackageBuildError(RuntimeError):
    """The package cannot be built without weakening the package contract."""


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


def _read_exact(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
        except InterruptedError:
            continue
        if not chunk:
            raise PackageBuildError("build artifact changed while read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise PackageBuildError("build artifact changed while read")
    return b"".join(chunks)


def _run_tool(command: list[str], descriptor: int) -> bytes:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(descriptor,),
            close_fds=True,
            env=FIXED_ENVIRONMENT,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PackageBuildError("static-launcher inspection tool failed") from exc
    if (
        completed.returncode != 0
        or len(completed.stdout) > 64 * 1024
        or len(completed.stderr) > 16 * 1024
    ):
        raise PackageBuildError("static-launcher inspection tool failed")
    return completed.stdout


def _elf_program_types(raw: bytes, expected_machine: int) -> set[int]:
    if (
        len(raw) < 64
        or raw[:7] != b"\x7fELF\x02\x01\x01"
        or int.from_bytes(raw[18:20], "little") != expected_machine
        or int.from_bytes(raw[20:24], "little") != 1
        or int.from_bytes(raw[52:54], "little") != 64
    ):
        raise PackageBuildError("package ELF architecture is invalid")
    program_offset = int.from_bytes(raw[32:40], "little")
    program_size = int.from_bytes(raw[54:56], "little")
    program_count = int.from_bytes(raw[56:58], "little")
    if (
        program_size != 56
        or not 1 <= program_count <= 64
        or program_offset < 64
        or program_offset + program_size * program_count > len(raw)
    ):
        raise PackageBuildError("package ELF program headers are invalid")
    return {
        int.from_bytes(
            raw[
                program_offset + index * program_size :
                program_offset + index * program_size + 4
            ],
            "little",
        )
        for index in range(program_count)
    }


def _validate_artifact(
    name: str,
    kind: str,
    raw: bytes,
    descriptor: int,
    expected_machine: int,
) -> None:
    if kind == "python":
        try:
            ast.parse(raw.decode("utf-8"), filename=name, mode="exec")
        except (SyntaxError, UnicodeDecodeError, ValueError) as exc:
            raise PackageBuildError(f"build artifact is not valid Python: {name}") from exc
        return

    program_types = _elf_program_types(raw, expected_machine)
    if kind == "native-elf":
        if 1 not in program_types:
            raise PackageBuildError("native verifier has no loadable segment")
        return

    if kind not in LAUNCHER_CONTRACTS:
        raise PackageBuildError("package artifact kind is invalid")
    if (
        int.from_bytes(raw[16:18], "little") != 2
        or 1 not in program_types
        or 2 in program_types
        or 3 in program_types
    ):
        raise PackageBuildError("static launcher is not a static no-interpreter ELF")
    script, contract = LAUNCHER_CONTRACTS[kind]
    required = (*COMMON_LAUNCHER_TOKENS, script, contract)
    if any(raw.count(token) != 1 for token in required):
        raise PackageBuildError("static launcher fixed-string contract is invalid")
    if b"LD_PRELOAD" in raw or b"LD_LIBRARY_PATH" in raw:
        raise PackageBuildError("static launcher contains a loader input")
    descriptor_path = f"/proc/self/fd/{descriptor}"
    dynamic = _run_tool([READELF, "-dW", "--", descriptor_path], descriptor)
    if b"(NEEDED)" in dynamic:
        raise PackageBuildError("static launcher has a needed library")
    undefined = _run_tool([NM, "-u", "--", descriptor_path], descriptor)
    if undefined.strip():
        raise PackageBuildError("static launcher has an undefined symbol")


def _validate_metadata() -> None:
    try:
        raw = PACKAGE_METADATA.read_bytes()
        metadata = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageBuildError("package metadata is invalid") from exc
    if (
        type(metadata) is not dict
        or metadata.get("schema_version") != "grok-bootstrap-package.v1"
        or metadata.get("package_name") != PACKAGE_NAME
    ):
        raise PackageBuildError("package metadata is invalid")
    artifacts = metadata.get("artifacts")
    if type(artifacts) is not dict:
        raise PackageBuildError("package metadata is invalid")
    metadata_roots = {
        artifacts.get("payload_root"): artifacts.get("closed_payload"),
        artifacts.get("activator_root"): artifacts.get("closed_activator"),
    }
    if set(metadata_roots) != set(ROOT_SPEC):
        raise PackageBuildError("package metadata root inventory drifted")
    for root, root_spec in ROOT_SPEC.items():
        entries = metadata_roots[root]
        if type(entries) is not dict or set(entries) != set(root_spec["files"]):
            raise PackageBuildError("package metadata file inventory drifted")
        for name, file_spec in root_spec["files"].items():
            entry = entries[name]
            if (
                type(entry) is not dict
                or entry.get("build") != file_spec["build"]
                or entry.get("mode") != f"{file_spec['mode']:04o}"
                or entry.get("link_count") != 1
            ):
                raise PackageBuildError("package metadata file contract drifted")


def _open_build_root(path: Path) -> int:
    if not path.is_absolute():
        raise PackageBuildError("build root must be absolute")
    try:
        if path.resolve(strict=True) != path:
            raise PackageBuildError("build root must be canonical")
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as exc:
        raise PackageBuildError("build root is unsafe") from exc
    information = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_uid != os.geteuid()
        or information.st_gid != os.getegid()
        or stat.S_IMODE(information.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise PackageBuildError("build root is unsafe")
    return descriptor


def _load_artifacts(build_root: Path, expected_machine: int) -> dict[str, dict[str, object]]:
    directory_fd = _open_build_root(build_root)
    expected_names = {
        Path(file_spec["build"]).name
        for root_spec in ROOT_SPEC.values()
        for file_spec in root_spec["files"].values()
    }
    try:
        with os.scandir(directory_fd) as iterator:
            names = sorted(entry.name for entry in iterator)
        if names != sorted(expected_names):
            raise PackageBuildError("build root does not contain the exact five-file inventory")
        result: dict[str, dict[str, object]] = {}
        for root, root_spec in ROOT_SPEC.items():
            for name, file_spec in root_spec["files"].items():
                try:
                    named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory_fd,
                    )
                except OSError as exc:
                    raise PackageBuildError(f"build artifact is unsafe: {name}") from exc
                try:
                    opened = os.fstat(descriptor)
                    maximum = file_spec["maximum"]
                    if (
                        not stat.S_ISREG(named.st_mode)
                        or not stat.S_ISREG(opened.st_mode)
                        or not _same_identity(named, opened)
                        or opened.st_uid != os.geteuid()
                        or opened.st_gid != os.getegid()
                        or stat.S_IMODE(opened.st_mode) != file_spec["mode"]
                        or opened.st_nlink != 1
                        or not 0 < opened.st_size <= maximum
                    ):
                        raise PackageBuildError(f"build artifact is unsafe: {name}")
                    raw = _read_exact(descriptor, opened.st_size)
                    named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (
                        not _same_snapshot(opened, os.fstat(descriptor))
                        or not _same_snapshot(opened, named_after)
                    ):
                        raise PackageBuildError(f"build artifact changed while read: {name}")
                    _validate_artifact(
                        name,
                        file_spec["kind"],
                        raw,
                        descriptor,
                        expected_machine,
                    )
                    if not _same_snapshot(opened, os.fstat(descriptor)):
                        raise PackageBuildError(f"build artifact changed during validation: {name}")
                    result[f"{root}/{name}"] = {
                        "data": raw,
                        "kind": file_spec["kind"],
                        "mode": file_spec["mode"],
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "size": len(raw),
                    }
                finally:
                    os.close(descriptor)
        return result
    finally:
        os.close(directory_fd)


POSTINST_TEMPLATE = r'''#!/usr/bin/python3 -IBS
"""Authenticated pre-execution gate for one Grok bootstrap package generation."""

import ast
import hashlib
import os
import stat
import subprocess
import sys


PACKAGE_VERSION = @@PACKAGE_VERSION@@
SOURCE_COMMIT = @@SOURCE_COMMIT@@
PACKAGE_ARCHITECTURE = @@PACKAGE_ARCHITECTURE@@
EXPECTED_MACHINE_NAME = @@EXPECTED_MACHINE_NAME@@
EXPECTED_MACHINE = @@EXPECTED_MACHINE@@
EXPECTED_ROOTS = @@EXPECTED_ROOTS@@
ACTIVATOR_PATH = "/usr/libexec/grok-bootstrap-package/grok-bootstrap-package-activate"
FIXED_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONDONTWRITEBYTECODE": "1",
}
COMMON_LAUNCHER_TOKENS = (
    b"/usr/bin/python3\x00",
    b"-I\x00",
    b"-B\x00",
    b"-S\x00",
    b"PATH=/usr/bin:/bin\x00",
    b"LANG=C\x00",
    b"LC_ALL=C\x00",
    b"PYTHONDONTWRITEBYTECODE=1\x00",
)
LAUNCHER_CONTRACTS = {
    "publisher-launcher": (
        b"/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap-publisher.py\x00",
        b"grok-static-python-launcher-v1:forward-bounded-64\x00",
    ),
    "activator-launcher": (
        b"/usr/libexec/grok-bootstrap-package/activate_package.py\x00",
        b"grok-static-python-launcher-v1:zero-arguments\x00",
    ),
}


class VerificationError(RuntimeError):
    pass


def same_identity(left, right):
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def same_snapshot(left, right):
    fields = (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
        "st_size", "st_mtime_ns", "st_ctime_ns",
    )
    return all(getattr(left, field) == getattr(right, field) for field in fields)


def validate_directory(information, exact_mode=None):
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_uid != 0
        or information.st_gid != 0
        or stat.S_IMODE(information.st_mode) & 0o022
        or (exact_mode is not None and stat.S_IMODE(information.st_mode) != exact_mode)
    ):
        raise VerificationError("package directory authority is unsafe")


def open_fixed_root(path, exact_mode):
    parts = path.split("/")[1:]
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise VerificationError("package directory path is invalid")
    try:
        descriptor = os.open(
            "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        validate_directory(os.fstat(descriptor))
        for index, part in enumerate(parts):
            named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            opened = os.fstat(child)
            if not same_snapshot(named, opened):
                os.close(child)
                raise VerificationError("package directory identity changed")
            validate_directory(opened, exact_mode if index == len(parts) - 1 else None)
            os.close(descriptor)
            descriptor = child
        return descriptor, os.fstat(descriptor)
    except VerificationError:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise
    except OSError as exc:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise VerificationError("package directory authority is unsafe") from exc


def bounded_names(descriptor, maximum):
    names = []
    try:
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                names.append(entry.name)
                if len(names) > maximum:
                    raise VerificationError("package directory inventory is not closed")
    except OSError as exc:
        raise VerificationError("package directory inventory is unsafe") from exc
    names.sort()
    return names


def read_exact(descriptor, size):
    chunks = []
    remaining = size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
        except InterruptedError:
            continue
        if not chunk:
            raise VerificationError("package artifact changed while read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise VerificationError("package artifact changed while read")
    return b"".join(chunks)


def open_file(directory_fd, name, specification):
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise VerificationError("package artifact authority is unsafe") from exc
    try:
        if (
            not stat.S_ISREG(named.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or not same_identity(named, opened)
            or opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != specification["mode"]
            or opened.st_nlink != 1
            or opened.st_size != specification["size"]
        ):
            raise VerificationError("package artifact authority is unsafe")
        raw = read_exact(descriptor, specification["size"])
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            hashlib.sha256(raw).hexdigest() != specification["sha256"]
            or not same_snapshot(opened, os.fstat(descriptor))
            or not same_snapshot(opened, named_after)
        ):
            raise VerificationError("package artifact content or snapshot is invalid")
        return {"descriptor": descriptor, "snapshot": opened, "data": raw}
    except BaseException:
        os.close(descriptor)
        raise


def elf_program_types(raw):
    if (
        len(raw) < 64
        or raw[:7] != b"\x7fELF\x02\x01\x01"
        or int.from_bytes(raw[18:20], "little") != EXPECTED_MACHINE
        or int.from_bytes(raw[20:24], "little") != 1
        or int.from_bytes(raw[52:54], "little") != 64
    ):
        raise VerificationError("package ELF architecture is invalid")
    offset = int.from_bytes(raw[32:40], "little")
    size = int.from_bytes(raw[54:56], "little")
    count = int.from_bytes(raw[56:58], "little")
    if (
        size != 56
        or not 1 <= count <= 64
        or offset < 64
        or offset + size * count > len(raw)
    ):
        raise VerificationError("package ELF program headers are invalid")
    return {
        int.from_bytes(raw[offset + index * size:offset + index * size + 4], "little")
        for index in range(count)
    }


def run_tool(command, descriptor):
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(descriptor,),
            close_fds=True,
            env=FIXED_ENVIRONMENT,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VerificationError("static-launcher inspection tool failed") from exc
    if (
        completed.returncode != 0
        or len(completed.stdout) > 64 * 1024
        or len(completed.stderr) > 16 * 1024
    ):
        raise VerificationError("static-launcher inspection tool failed")
    return completed.stdout


def validate_file(name, specification, opened):
    raw = opened["data"]
    kind = specification["kind"]
    if kind == "python":
        try:
            ast.parse(raw.decode("utf-8"), filename=name, mode="exec")
        except (SyntaxError, UnicodeDecodeError, ValueError) as exc:
            raise VerificationError("package Python source is invalid") from exc
        return
    program_types = elf_program_types(raw)
    if kind == "native-elf":
        if 1 not in program_types:
            raise VerificationError("native verifier has no loadable segment")
        return
    if kind not in LAUNCHER_CONTRACTS:
        raise VerificationError("package artifact kind is invalid")
    if (
        int.from_bytes(raw[16:18], "little") != 2
        or 1 not in program_types
        or 2 in program_types
        or 3 in program_types
    ):
        raise VerificationError("static launcher is not a static no-interpreter ELF")
    script, contract = LAUNCHER_CONTRACTS[kind]
    required = (*COMMON_LAUNCHER_TOKENS, script, contract)
    if any(raw.count(token) != 1 for token in required):
        raise VerificationError("static launcher fixed-string contract is invalid")
    if b"LD_PRELOAD" in raw or b"LD_LIBRARY_PATH" in raw:
        raise VerificationError("static launcher contains a loader input")
    descriptor = opened["descriptor"]
    descriptor_path = f"/proc/self/fd/{descriptor}"
    dynamic = run_tool(["/usr/bin/readelf", "-dW", "--", descriptor_path], descriptor)
    if b"(NEEDED)" in dynamic:
        raise VerificationError("static launcher has a needed library")
    undefined = run_tool(["/usr/bin/nm", "-u", "--", descriptor_path], descriptor)
    if undefined.strip():
        raise VerificationError("static launcher has an undefined symbol")


def recheck_file(directory_fd, name, specification, opened):
    descriptor = opened["descriptor"]
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = read_exact(descriptor, specification["size"])
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        current = os.fstat(descriptor)
    except OSError as exc:
        raise VerificationError("package artifact identity changed") from exc
    if (
        not same_snapshot(opened["snapshot"], named)
        or not same_snapshot(opened["snapshot"], current)
        or hashlib.sha256(raw).hexdigest() != specification["sha256"]
    ):
        raise VerificationError("package artifact identity changed")


def verify_and_activate():
    if (
        os.geteuid() != 0
        or os.getegid() != 0
        or os.uname().machine != EXPECTED_MACHINE_NAME
        or os.execve not in os.supports_fd
    ):
        raise VerificationError("package host authority or architecture is invalid")
    if len(sys.argv) not in {2, 3} or sys.argv[1] != "configure":
        raise VerificationError("package post-install invocation is invalid")
    roots = {}
    files = {}
    try:
        for root_path, root_specification in EXPECTED_ROOTS.items():
            directory_fd, snapshot = open_fixed_root(root_path, root_specification["mode"])
            roots[root_path] = {"descriptor": directory_fd, "snapshot": snapshot}
            expected_names = sorted(root_specification["files"])
            if bounded_names(directory_fd, len(expected_names)) != expected_names:
                raise VerificationError("package directory inventory is not closed")
            for name, specification in root_specification["files"].items():
                opened = open_file(directory_fd, name, specification)
                files[f"{root_path}/{name}"] = opened
                validate_file(name, specification, opened)

        for root_path, root_specification in EXPECTED_ROOTS.items():
            held = roots[root_path]
            current_fd, current_snapshot = open_fixed_root(
                root_path, root_specification["mode"]
            )
            try:
                if (
                    not same_snapshot(held["snapshot"], os.fstat(held["descriptor"]))
                    or not same_snapshot(held["snapshot"], current_snapshot)
                    or bounded_names(held["descriptor"], len(root_specification["files"]))
                    != sorted(root_specification["files"])
                ):
                    raise VerificationError("package directory identity changed")
            finally:
                os.close(current_fd)
            for name, specification in root_specification["files"].items():
                recheck_file(
                    held["descriptor"],
                    name,
                    specification,
                    files[f"{root_path}/{name}"],
                )

        activator = files[ACTIVATOR_PATH]["descriptor"]
        for path, opened in files.items():
            if path != ACTIVATOR_PATH:
                os.close(opened["descriptor"])
                opened["descriptor"] = -1
        for held in roots.values():
            os.close(held["descriptor"])
            held["descriptor"] = -1
        os.environ.clear()
        os.environ.update(FIXED_ENVIRONMENT)
        try:
            os.execve(activator, [ACTIVATOR_PATH], FIXED_ENVIRONMENT)
        except OSError as exc:
            raise VerificationError("zero-argument package activator exec failed") from exc
    finally:
        for opened in files.values():
            descriptor = opened.get("descriptor", -1)
            if descriptor >= 0:
                os.close(descriptor)
                opened["descriptor"] = -1
        for held in roots.values():
            descriptor = held.get("descriptor", -1)
            if descriptor >= 0:
                os.close(descriptor)
                held["descriptor"] = -1


if __name__ == "__main__":
    try:
        verify_and_activate()
    except VerificationError as exc:
        print(f"grok-bootstrap postinst: {exc}", file=sys.stderr)
        raise SystemExit(2)
'''


def _render_postinst(
    artifacts: dict[str, dict[str, object]],
    *,
    version: str,
    source_commit: str,
    architecture: str,
    machine_name: str,
    machine: int,
) -> bytes:
    expected_roots: dict[str, dict[str, object]] = {}
    for root, root_spec in ROOT_SPEC.items():
        files: dict[str, dict[str, object]] = {}
        for name in sorted(root_spec["files"]):
            artifact = artifacts[f"{root}/{name}"]
            files[name] = {
                "kind": artifact["kind"],
                "mode": artifact["mode"],
                "sha256": artifact["sha256"],
                "size": artifact["size"],
            }
        expected_roots[root] = {"files": files, "mode": root_spec["mode"]}
    replacements = {
        "@@PACKAGE_VERSION@@": repr(version),
        "@@SOURCE_COMMIT@@": repr(source_commit),
        "@@PACKAGE_ARCHITECTURE@@": repr(architecture),
        "@@EXPECTED_MACHINE_NAME@@": repr(machine_name),
        "@@EXPECTED_MACHINE@@": repr(machine),
        "@@EXPECTED_ROOTS@@": repr(expected_roots),
    }
    rendered = POSTINST_TEMPLATE
    for marker, value in replacements.items():
        if rendered.count(marker) != 1:
            raise PackageBuildError("postinst template marker contract drifted")
        rendered = rendered.replace(marker, value)
    raw = rendered.encode("utf-8")
    try:
        ast.parse(rendered, filename="postinst", mode="exec")
    except (SyntaxError, ValueError) as exc:
        raise PackageBuildError("generated postinst is not valid Python") from exc
    return raw


def _write_file(path: Path, raw: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise PackageBuildError("package staging write did not progress")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _control_bytes(version: str, architecture: str, source_commit: str) -> bytes:
    content = (
        f"Package: {PACKAGE_NAME}\n"
        f"Version: {version}\n"
        f"Architecture: {architecture}\n"
        "Section: admin\n"
        "Priority: optional\n"
        "Maintainer: Grok Bootstrap Maintainers <root@localhost>\n"
        "Depends: python3 (>= 3.10), binutils, libssl3t64 | libssl3\n"
        f"X-Grok-Source-Commit: {source_commit}\n"
        "Description: authenticated pre-import Grok release bootstrap\n"
        " Installs one closed package-owned bootstrap generation.\n"
    )
    return content.encode("ascii")


def _set_tree_time(root: Path, epoch: int) -> None:
    paths = sorted(root.rglob("*"), key=lambda path: len(path.parts), reverse=True)
    for path in paths:
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    os.utime(root, (epoch, epoch), follow_symlinks=False)


def _stage_package(
    stage: Path,
    artifacts: dict[str, dict[str, object]],
    postinst: bytes,
    control: bytes,
    epoch: int,
) -> None:
    stage.chmod(0o755)
    control_root = stage / "DEBIAN"
    control_root.mkdir(mode=0o755)
    control_root.chmod(0o755)
    _write_file(control_root / "control", control, 0o644)
    _write_file(control_root / "postinst", postinst, 0o755)
    for root, root_spec in ROOT_SPEC.items():
        destination = stage
        for component in root.split("/")[1:]:
            destination = destination / component
            destination.mkdir(mode=0o755, exist_ok=True)
            destination.chmod(0o755)
        for name in sorted(root_spec["files"]):
            artifact = artifacts[f"{root}/{name}"]
            _write_file(destination / name, artifact["data"], artifact["mode"])
        destination.chmod(root_spec["mode"])
    _set_tree_time(stage, epoch)


def _validate_output(path: Path, version: str, architecture: str) -> None:
    expected_name = f"{PACKAGE_NAME}_{version}_{architecture}.deb"
    if not path.is_absolute() or path.name != expected_name:
        raise PackageBuildError(f"output must be an absolute path named {expected_name}")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise PackageBuildError("output parent is unsafe") from exc
    if parent != path.parent:
        raise PackageBuildError("output parent must be canonical")
    information = parent.stat()
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_uid != os.geteuid()
        or information.st_gid != os.getegid()
        or stat.S_IMODE(information.st_mode) & 0o022
        or path.exists()
        or path.is_symlink()
    ):
        raise PackageBuildError("output path is unsafe or already exists")


def build_package(arguments: argparse.Namespace) -> Path:
    if os.geteuid() == 0 or os.getegid() == 0 or 0 in os.getgroups():
        raise PackageBuildError("Debian package construction must run as non-root")
    if VERSION_RE.fullmatch(arguments.version) is None:
        raise PackageBuildError("package version is invalid")
    if COMMIT_RE.fullmatch(arguments.source_commit) is None:
        raise PackageBuildError("source commit must be 40 lowercase hexadecimal characters")
    if arguments.architecture not in ARCHITECTURES:
        raise PackageBuildError("package architecture must be amd64 or arm64")
    machine_name, machine = ARCHITECTURES[arguments.architecture]
    if os.uname().machine != machine_name:
        raise PackageBuildError("package architecture does not match the build host")
    if not 0 <= arguments.source_date_epoch <= MAX_SOURCE_DATE_EPOCH:
        raise PackageBuildError("source date epoch is invalid")
    output = Path(arguments.output)
    build_root = Path(arguments.build_root)
    _validate_output(output, arguments.version, arguments.architecture)
    _validate_metadata()
    artifacts = _load_artifacts(build_root, machine)
    postinst = _render_postinst(
        artifacts,
        version=arguments.version,
        source_commit=arguments.source_commit,
        architecture=arguments.architecture,
        machine_name=machine_name,
        machine=machine,
    )
    control = _control_bytes(arguments.version, arguments.architecture, arguments.source_commit)
    temporary_root = Path(
        tempfile.mkdtemp(prefix=".grok-bootstrap-deb-", dir=output.parent)
    )
    temporary_deb = temporary_root / "package.deb"
    try:
        stage = temporary_root / "root"
        stage.mkdir(mode=0o700)
        try:
            _stage_package(
                stage,
                artifacts,
                postinst,
                control,
                arguments.source_date_epoch,
            )
        except OSError as exc:
            raise PackageBuildError("Debian package staging failed") from exc
        environment = dict(FIXED_ENVIRONMENT)
        environment["SOURCE_DATE_EPOCH"] = str(arguments.source_date_epoch)
        try:
            completed = subprocess.run(
                [
                    DPKG_DEB,
                    "--build",
                    "--root-owner-group",
                    "--uniform-compression",
                    "--threads-max=1",
                    "-Zgzip",
                    "-z9",
                    "-Snone",
                    os.fspath(stage),
                    os.fspath(temporary_deb),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                env=environment,
                check=False,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise PackageBuildError("dpkg-deb package construction failed") from exc
        if (
            completed.returncode != 0
            or len(completed.stdout) > 16 * 1024
            or len(completed.stderr) > 16 * 1024
            or not temporary_deb.is_file()
        ):
            raise PackageBuildError("dpkg-deb package construction failed")
        temporary_deb.chmod(0o644)
        descriptor = os.open(temporary_deb, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary_deb, output, follow_symlinks=False)
        except FileExistsError as exc:
            raise PackageBuildError("output path appeared during package construction") from exc
        directory_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return output
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="build one closed authenticated Grok bootstrap Debian package"
    )
    parser.add_argument("--build-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--architecture", required=True, choices=sorted(ARCHITECTURES))
    parser.add_argument("--source-date-epoch", required=True, type=int)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        output = build_package(parse_arguments(argv))
    except PackageBuildError as exc:
        print(f"grok-bootstrap package builder: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
