#!/usr/bin/env python3
"""Provision the locked Grok native trust anchor and signed dispatcher."""

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
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))

from lib.grok_bootstrap_release import (
    AUTHORIZATION_NAMES,
    ArtifactUnavailable,
    FIXED_ENVIRONMENT,
    RELEASE_ID_RE,
    SIGNED_NAMES,
    ReleaseError,
    load_lock,
    open_artifact_set,
    validate_debian_package_descriptor,
    verify_artifact,
    verify_release_authorization_descriptors,
    verify_signed_dispatcher,
    verify_signed_dispatcher_descriptors,
)


REPO = Path(__file__).resolve().parents[1]
LOCK_PATH = REPO / "system/grok-proxy/bootstrap/release.lock.json"
BOOTSTRAP_ROOT = Path("/usr/local/libexec/grok-proxy/bootstrap")
BOOTSTRAP_BINARY = BOOTSTRAP_ROOT / "grok-bootstrap"
PUBLISHER = BOOTSTRAP_ROOT / "grok-bootstrap-publisher"
SELECTOR = BOOTSTRAP_ROOT / "selected-release"
STORE = Path("/usr/local/libexec/grok-proxy/bootstrap-releases")
IMPORT_ROOT = Path("/var/lib/coding-system-rebuild")
PACKAGE_NAME = "grok-bootstrap"
PACKAGE_ACTIVATOR = Path(
    "/usr/libexec/grok-bootstrap-package/grok-bootstrap-package-activate"
)
MAX_DOWNLOAD_SIZE = 128 * 1024 * 1024
USER_AGENT = "coding-system-rebuild-grok-bootstrap/1"


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check-lock",
        action="store_true",
        help="validate the fixed lock without requiring publication",
    )
    mode.add_argument(
        "--verify-installed",
        action="store_true",
        help="verify the exact locked package and dispatcher without changing them",
    )
    mode.add_argument(
        "--require-qualified-lock",
        action="store_true",
        help="fail unless the fixed lock is qualified; do not use network or sudo",
    )
    return parser.parse_args(argv)


def host_architecture() -> str:
    machine = os.uname().machine
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    raise ReleaseError(f"unsupported Grok bootstrap architecture: {machine}")


def _run(
    command: list[str],
    *,
    sudo: bool = False,
    timeout: int = 120,
    capture: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    if sudo:
        command = ["/usr/bin/sudo", "-n", "--", *command]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            env=FIXED_ENVIRONMENT,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseError("Grok bootstrap system command could not run") from exc
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if len(stdout) > 64 * 1024 or len(stderr) > 64 * 1024:
        raise ReleaseError("Grok bootstrap system command produced excessive output")
    if completed.returncode != 0:
        diagnostic = stderr.decode("utf-8", errors="replace").strip().splitlines()
        suffix = f": {diagnostic[-1][:512]}" if diagnostic else ""
        raise ReleaseError(f"Grok bootstrap system command failed{suffix}")
    return completed


def _download(specification: dict[str, object], destination: Path) -> None:
    request = urllib.request.Request(
        str(specification["url"]), headers={"User-Agent": USER_AGENT}
    )
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    total = 0
    try:
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > int(specification["size"]) or total > MAX_DOWNLOAD_SIZE:
                        raise ReleaseError("downloaded artifact exceeds its locked size")
                    offset = 0
                    while offset < len(chunk):
                        written = os.write(descriptor, chunk[offset:])
                        if written <= 0:
                            raise ReleaseError("artifact download write did not progress")
                        offset += written
        except (OSError, urllib.error.URLError) as exc:
            raise ArtifactUnavailable(
                f"immutable release asset is unavailable: {specification['name']}"
            ) from exc
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    verify_artifact(destination, specification)


def _require_directory(path: Path, mode: int) -> None:
    try:
        information = path.lstat()
    except OSError as exc:
        raise ReleaseError(f"required root directory is unavailable: {path}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(information.st_mode)
        or (information.st_uid, information.st_gid) != (0, 0)
        or stat.S_IMODE(information.st_mode) != mode
    ):
        raise ReleaseError(f"required root directory is unsafe: {path}")


def _require_file(path: Path, mode: int, *, size: int | None = None) -> None:
    try:
        information = path.lstat()
    except OSError as exc:
        raise ReleaseError(f"required root file is unavailable: {path}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(information.st_mode)
        or (information.st_uid, information.st_gid) != (0, 0)
        or stat.S_IMODE(information.st_mode) != mode
        or information.st_nlink != 1
        or (size is not None and information.st_size != size)
    ):
        raise ReleaseError(f"required root file is unsafe: {path}")


def _installed_package_fields() -> dict[str, str]:
    completed = _run(
        [
            "/usr/bin/dpkg-query",
            "--show",
            "--showformat=${Status}\\n${Version}\\n${Architecture}\\n${X-Grok-Source-Commit}\\n",
            PACKAGE_NAME,
        ]
    )
    try:
        lines = completed.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ReleaseError("installed Grok package metadata is invalid") from exc
    if len(lines) != 4:
        raise ReleaseError("installed Grok package metadata is incomplete")
    return {
        "Status": lines[0],
        "Version": lines[1],
        "Architecture": lines[2],
        "X-Grok-Source-Commit": lines[3],
    }


def _describe_anchor() -> dict[str, str]:
    _require_file(BOOTSTRAP_BINARY, 0o555)
    completed = _run([os.fspath(BOOTSTRAP_BINARY), "--describe-trust-anchor"])
    try:
        value = json.loads(completed.stdout.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("installed Grok trust-anchor report is invalid") from exc
    if (
        type(value) is not dict
        or set(value) != {"key_id", "public_key_hex", "schema_version"}
        or value.get("schema_version") != "grok-bootstrap-trust-anchor-v1"
        or type(value.get("key_id")) is not str
        or type(value.get("public_key_hex")) is not str
    ):
        raise ReleaseError("installed Grok trust-anchor report is invalid")
    return {"key_id": value["key_id"], "public_key_hex": value["public_key_hex"]}


def _selected_release() -> str | None:
    try:
        information = SELECTOR.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ReleaseError("Grok bootstrap selector is unavailable") from exc
    try:
        raw = SELECTOR.read_bytes()
    except OSError as exc:
        raise ReleaseError("Grok bootstrap selector is unreadable") from exc
    if (
        SELECTOR.is_symlink()
        or not stat.S_ISREG(information.st_mode)
        or (information.st_uid, information.st_gid) != (0, 0)
        or stat.S_IMODE(information.st_mode) != 0o444
        or information.st_nlink != 1
        or re.fullmatch(rb"[0-9a-f]{64}\n", raw) is None
    ):
        raise ReleaseError("Grok bootstrap selector is unsafe")
    return raw[:-1].decode("ascii")


def verify_installed(lock: dict[str, object], architecture: str) -> None:
    release = lock["release"]
    anchor = lock["trust_anchor"]
    expected_package = {
        "Status": "install ok installed",
        "Version": release["package_version"],
        "Architecture": architecture,
        "X-Grok-Source-Commit": release["source_commit"],
    }
    if _installed_package_fields() != expected_package:
        raise ReleaseError("installed Grok bootstrap package differs from the release lock")
    verification = _run(["/usr/bin/dpkg", "--verify", PACKAGE_NAME])
    if verification.stdout or verification.stderr:
        raise ReleaseError("installed Grok bootstrap package files failed dpkg verification")
    _require_directory(BOOTSTRAP_ROOT, 0o755)
    _require_directory(STORE, 0o755)
    _require_file(BOOTSTRAP_ROOT / "update.lock", 0o600, size=0)
    _require_file(PUBLISHER, 0o555)
    if (BOOTSTRAP_ROOT / "package-update.pending").exists():
        raise ReleaseError("Grok bootstrap package activation is still pending")
    if _describe_anchor() != anchor:
        raise ReleaseError("installed Grok trust anchor differs from the release lock")
    release_id = release["signed_application_id"]
    if _selected_release() != release_id:
        raise ReleaseError("installed Grok signed dispatcher differs from the release lock")
    signed_root = STORE / release_id
    _require_directory(signed_root, 0o555)
    for name in SIGNED_NAMES:
        artifact = signed_root / name
        _require_file(artifact, 0o444)
        verify_artifact(artifact, release["artifacts"][name])
    verified_id = verify_signed_dispatcher(
        signed_root,
        key_id=anchor["key_id"],
        public_key_hex=anchor["public_key_hex"],
        expected_release_id=release_id,
    )
    if verified_id != release_id:
        raise ReleaseError("installed Grok signed dispatcher identity is invalid")


def _ensure_import_root() -> None:
    if IMPORT_ROOT.exists() or IMPORT_ROOT.is_symlink():
        _require_directory(IMPORT_ROOT, 0o755)
        return
    _run(
        [
            "/usr/bin/install",
            "-d",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0755",
            os.fspath(IMPORT_ROOT),
        ],
        sudo=True,
    )
    _require_directory(IMPORT_ROOT, 0o755)


def _copy_descriptor_to_root(descriptor: int, target: Path) -> None:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        completed = subprocess.run(
            [
                "/usr/bin/sudo",
                "-n",
                "--",
                "/usr/bin/dd",
                "bs=65536",
                "conv=fsync,excl",
                "status=none",
                f"of={target}",
            ],
            stdin=descriptor,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env=FIXED_ENVIRONMENT,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseError("held-descriptor root import could not run") from exc
    if (
        completed.returncode != 0
        or completed.stdout
        or len(completed.stderr) > 16 * 1024
    ):
        raise ReleaseError("held-descriptor root import failed")


def _verify_root_staged_artifact(
    path: Path, specification: dict[str, object], *, mode: int
) -> None:
    metadata = _run(
        ["/usr/bin/stat", "--format=%u:%g:%a:%h:%s", "--", os.fspath(path)],
        sudo=True,
    ).stdout.decode("ascii", errors="strict").strip()
    expected = f"0:0:{mode:o}:1:{specification['size']}"
    if metadata != expected:
        raise ReleaseError("root-staged artifact metadata is unsafe")
    digest_output = _run(
        ["/usr/bin/sha256sum", "--binary", "--", os.fspath(path)], sudo=True
    ).stdout
    if (
        len(digest_output) < 66
        or digest_output[:64].decode("ascii", errors="strict")
        != specification["sha256"]
        or digest_output[64:66] != b" *"
    ):
        raise ReleaseError("root-staged artifact differs from its release lock")


def _stage_signed_application(
    descriptors: dict[str, int], release: dict[str, object]
) -> tuple[Path, Path]:
    _ensure_import_root()
    parent = IMPORT_ROOT / f"grok-bootstrap-import-{os.getpid()}-{secrets.token_hex(8)}"
    release_id = release["signed_application_id"]
    signed_root = parent / release_id
    if parent.exists() or parent.is_symlink():
        raise ReleaseError("Grok bootstrap staging path unexpectedly exists")
    stage_started = False
    try:
        _run(
            [
                "/usr/bin/install",
                "-d",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0700",
                os.fspath(parent),
            ],
            sudo=True,
        )
        stage_started = True
        _run(
            [
                "/usr/bin/install",
                "-d",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0700",
                os.fspath(signed_root),
            ],
            sudo=True,
        )
        for name in SIGNED_NAMES:
            target = signed_root / name
            _copy_descriptor_to_root(descriptors[name], target)
            _run(
                ["/usr/bin/chown", "root:root", "--", os.fspath(target)], sudo=True
            )
            _run(["/usr/bin/chmod", "0600", "--", os.fspath(target)], sudo=True)
            _verify_root_staged_artifact(
                target, release["artifacts"][name], mode=0o600
            )
        for name in SIGNED_NAMES:
            _run(
                ["/usr/bin/chmod", "0444", "--", os.fspath(signed_root / name)],
                sudo=True,
            )
        _run(["/usr/bin/chmod", "0555", os.fspath(signed_root)], sudo=True)
        _require_directory(parent, 0o700)
        for name in SIGNED_NAMES:
            _verify_root_staged_artifact(
                signed_root / name, release["artifacts"][name], mode=0o444
            )
        return parent, signed_root
    except BaseException:
        if stage_started:
            _discard_stage(parent, signed_root, strict=False)
        raise


def _stage_package(
    descriptor: int,
    package_name: str,
    specification: dict[str, object],
) -> tuple[Path, Path]:
    _ensure_import_root()
    parent = IMPORT_ROOT / f"grok-bootstrap-package-{os.getpid()}-{secrets.token_hex(8)}"
    staged = parent / package_name
    if parent.exists() or parent.is_symlink():
        raise ReleaseError("Grok package staging path unexpectedly exists")
    stage_started = False
    try:
        _run(
            [
                "/usr/bin/install",
                "-d",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0700",
                os.fspath(parent),
            ],
            sudo=True,
        )
        stage_started = True
        _copy_descriptor_to_root(descriptor, staged)
        _run(["/usr/bin/chown", "root:root", "--", os.fspath(staged)], sudo=True)
        _run(["/usr/bin/chmod", "0600", "--", os.fspath(staged)], sudo=True)
        _require_directory(parent, 0o700)
        _verify_root_staged_artifact(staged, specification, mode=0o600)
        return parent, staged
    except BaseException:
        if stage_started:
            _discard_package_stage(parent, staged, strict=False)
        raise


def _discard_package_stage(parent: Path, staged: Path, *, strict: bool = True) -> None:
    if (
        parent.parent != IMPORT_ROOT
        or staged.parent != parent
        or not staged.name.startswith("grok-bootstrap_")
        or not staged.name.endswith(".deb")
    ):
        raise ReleaseError("refusing unsafe Grok package staging cleanup")
    for command in (
        ["/usr/bin/rm", "-f", "--", os.fspath(staged)],
        ["/usr/bin/rmdir", "--", os.fspath(parent)],
    ):
        try:
            _run(command, sudo=True)
        except ReleaseError:
            if strict:
                raise


def _discard_stage(parent: Path, signed_root: Path, *, strict: bool = True) -> None:
    if parent.parent != IMPORT_ROOT or signed_root.parent != parent or RELEASE_ID_RE.fullmatch(signed_root.name) is None:
        raise ReleaseError("refusing unsafe Grok bootstrap staging cleanup")
    commands = [
        *(
            ["/usr/bin/rm", "-f", "--", os.fspath(signed_root / name)]
            for name in SIGNED_NAMES
        ),
        ["/usr/bin/rmdir", "--", os.fspath(signed_root)],
        ["/usr/bin/rmdir", "--", os.fspath(parent)],
    ]
    for command in commands:
        try:
            _run(command, sudo=True)
        except ReleaseError:
            if strict:
                raise


def provision(lock: dict[str, object], architecture: str) -> None:
    release = lock["release"]
    anchor = lock["trust_anchor"]
    package_name = f"grok-bootstrap_{release['package_version']}_{architecture}.deb"
    artifacts = release["artifacts"]
    with tempfile.TemporaryDirectory(prefix="csr-grok-bootstrap-") as temporary:
        downloads = Path(temporary)
        selected_names = {*SIGNED_NAMES, *AUTHORIZATION_NAMES, package_name}
        for name in sorted(selected_names):
            _download(artifacts[name], downloads / name)
        directory_fd, descriptors = open_artifact_set(
            downloads,
            selected_names,
            {name: artifacts[name] for name in selected_names},
        )
        try:
            validate_debian_package_descriptor(
                descriptors[package_name],
                version=release["package_version"],
                architecture=architecture,
                source_commit=release["source_commit"],
                key_id=anchor["key_id"],
                public_key_hex=anchor["public_key_hex"],
            )
            verify_signed_dispatcher_descriptors(
                {name: descriptors[name] for name in SIGNED_NAMES},
                key_id=anchor["key_id"],
                public_key_hex=anchor["public_key_hex"],
                expected_release_id=release["signed_application_id"],
            )
            verify_release_authorization_descriptors(
                {name: descriptors[name] for name in AUTHORIZATION_NAMES},
                artifacts={
                    name: artifacts[name]
                    for name in (
                        *SIGNED_NAMES,
                        *(f"grok-bootstrap_{release['package_version']}_{item}.deb" for item in ("amd64", "arm64")),
                    )
                },
                package_version=release["package_version"],
                signed_application_id=release["signed_application_id"],
                source_commit=release["source_commit"],
                tag=release["tag"],
                trust_anchor=anchor,
                authorization_anchor=lock["release_authorization_anchor"],
                expected_authorization_id=release["authorization_id"],
            )

            package_parent: Path | None = None
            staged_package: Path | None = None
            try:
                package_parent, staged_package = _stage_package(
                    descriptors[package_name],
                    package_name,
                    artifacts[package_name],
                )
                _run(
                    ["/usr/bin/dpkg", "--install", os.fspath(staged_package)],
                    sudo=True,
                    timeout=300,
                )
            finally:
                if package_parent is not None and staged_package is not None:
                    _discard_package_stage(package_parent, staged_package)
            _run([os.fspath(PACKAGE_ACTIVATOR)], sudo=True, timeout=300)
            if _describe_anchor() != anchor:
                raise ReleaseError(
                    "installed Grok trust anchor differs from the release lock"
                )

            parent: Path | None = None
            signed_root: Path | None = None
            try:
                parent, signed_root = _stage_signed_application(
                    {name: descriptors[name] for name in SIGNED_NAMES}, release
                )
                expected = _selected_release() or "none"
                completed = _run(
                    [
                        os.fspath(PUBLISHER),
                        "publish",
                        "--signed-application",
                        os.fspath(signed_root),
                        "--expected-current",
                        expected,
                    ],
                    sudo=True,
                    timeout=300,
                )
                try:
                    result = json.loads(completed.stdout.decode("ascii"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ReleaseError("Grok publisher result is invalid") from exc
                if (
                    type(result) is not dict
                    or result.get("release_id") != release["signed_application_id"]
                    or result.get("selected_release_id")
                    != release["signed_application_id"]
                    or result.get("operation") != "publish"
                    or type(result.get("changed")) is not bool
                    or type(result.get("published")) is not bool
                ):
                    raise ReleaseError("Grok publisher result is invalid")
            finally:
                if parent is not None and signed_root is not None:
                    _discard_stage(parent, signed_root)
        finally:
            for descriptor in descriptors.values():
                os.close(descriptor)
            os.close(directory_fd)
    verify_installed(lock, architecture)


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
        lock = load_lock(
            LOCK_PATH,
            require_qualified=(
                not arguments.check_lock or arguments.require_qualified_lock
            ),
        )
        if arguments.check_lock:
            print(
                json.dumps(
                    {
                        "schema_version": lock["schema_version"],
                        "state": lock["state"],
                        "trust_anchor_key_id": lock["trust_anchor"]["key_id"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if arguments.require_qualified_lock:
            print(
                json.dumps(
                    {
                        "schema_version": lock["schema_version"],
                        "state": lock["state"],
                        "status": "qualified-lock-required",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        architecture = host_architecture()
        if arguments.verify_installed:
            verify_installed(lock, architecture)
        else:
            provision(lock, architecture)
        print(
            json.dumps(
                {
                    "architecture": architecture,
                    "package_version": lock["release"]["package_version"],
                    "signed_application_id": lock["release"]["signed_application_id"],
                    "status": "verified-installed",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except ArtifactUnavailable as exc:
        print(f"provision-grok-bootstrap: ARTIFACT_UNAVAILABLE: {exc}", file=sys.stderr)
        return 3
    except ReleaseError as exc:
        print(f"provision-grok-bootstrap: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
