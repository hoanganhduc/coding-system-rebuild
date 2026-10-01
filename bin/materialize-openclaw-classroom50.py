#!/usr/bin/env python3
"""Install the locked Classroom50 teacher extension into OpenClaw's workspace.

The host installation is the content-addressed authority.  The OpenClaw
workspace is mounted as ``/workspace`` in the sandbox.  Its GitHub CLI data
root deliberately lives outside ``/workspace/.local`` because that path is
owned by the transactional Python compatibility closure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import tempfile


ARCHITECTURES = {
    "aarch64": "arm64",
    "arm64": "arm64",
    "x86_64": "amd64",
    "amd64": "amd64",
}
MAX_BINARY_BYTES = 64 * 1024 * 1024


class MaterializationError(RuntimeError):
    """A redaction-safe Classroom50 runtime projection failure."""


def _require_home(home: Path) -> Path:
    home = home.expanduser().absolute()
    information = home.lstat()
    if (
        home.is_symlink()
        or not stat.S_ISDIR(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) & 0o022
    ):
        raise MaterializationError("Classroom50 projection home is unsafe")
    return home


def _read_locked_binary(path: Path) -> bytes:
    try:
        information = path.lstat()
    except OSError as exc:
        raise MaterializationError("locked host teacher extension is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(information.st_mode)
        or information.st_uid != os.getuid()
        or information.st_nlink != 1
        or not 0 < information.st_size <= MAX_BINARY_BYTES
        or stat.S_IMODE(information.st_mode) & 0o022
        or not stat.S_IMODE(information.st_mode) & 0o111
    ):
        raise MaterializationError("locked host teacher extension is unsafe")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (information.st_dev, information.st_ino):
            raise MaterializationError("host teacher extension changed during inspection")
        chunks: list[bytes] = []
        remaining = information.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise MaterializationError("host teacher extension was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise MaterializationError("host teacher extension grew during inspection")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _locked_artifact(repository: Path, architecture: str) -> tuple[str, str]:
    lock = json.loads(
        (repository / f"system/software/ubuntu-24.04-{architecture}.lock.json").read_text(
            encoding="utf-8"
        )
    )
    matches = [item for item in lock.get("artifacts", []) if item.get("id") == "gh-teacher"]
    if len(matches) != 1:
        raise MaterializationError("platform lock does not select one teacher extension")
    artifact = matches[0]
    digest = artifact.get("sha256")
    version = artifact.get("version")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or not isinstance(version, str)
        or not version
    ):
        raise MaterializationError("teacher extension platform lock is invalid")
    return digest, version


def _safe_parent(home: Path, destination: Path) -> None:
    try:
        relative = destination.relative_to(home)
    except ValueError as exc:
        raise MaterializationError("Classroom50 projection escapes the target home") from exc
    current = home
    for component in relative.parts[:-1]:
        current = current / component
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        information = current.lstat()
        if (
            current.is_symlink()
            or not stat.S_ISDIR(information.st_mode)
            or information.st_uid != os.getuid()
        ):
            raise MaterializationError("Classroom50 projection destination is unsafe")


def _atomic_install(home: Path, destination: Path, payload: bytes) -> None:
    _safe_parent(home, destination)
    try:
        current = destination.lstat()
    except FileNotFoundError:
        current = None
    if current is not None and (
        destination.is_symlink()
        or not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.getuid()
        or current.st_nlink != 1
    ):
        raise MaterializationError("existing Classroom50 projection is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}."
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o755)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _probe(command: list[str], environment: dict[str, str]) -> str:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=20,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MaterializationError("Classroom50 extension probe could not run") from exc
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise MaterializationError("Classroom50 extension probe failed")
    return result.stdout.strip()


def materialize(repository: Path, home: Path, architecture: str) -> Path:
    home = _require_home(home)
    expected_digest, expected_version = _locked_artifact(repository, architecture)
    source = home / ".local/share/gh/extensions/gh-teacher/gh-teacher"
    payload = _read_locked_binary(source)
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        raise MaterializationError("host teacher extension differs from the platform lock")
    workspace = home / ".openclaw/workspace"
    destination = workspace / ".local-data/gh/extensions/gh-teacher/gh-teacher"
    _atomic_install(home, destination, payload)
    if hashlib.sha256(_read_locked_binary(destination)).hexdigest() != expected_digest:
        raise MaterializationError("projected teacher extension differs from the platform lock")
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(workspace),
        "GH_CONFIG_DIR": str(workspace / ".config/gh"),
        "XDG_DATA_HOME": str(workspace / ".local-data"),
        "GH_PROMPT_DISABLED": "1",
        "NO_COLOR": "1",
        "TERM": "dumb",
    }
    version = _probe([str(destination), "--version"], environment)
    if not version.startswith(f"gh-teacher version v{expected_version} "):
        raise MaterializationError("projected teacher extension version differs from the lock")
    gh = shutil.which("gh", path=environment["PATH"])
    if gh is None:
        raise MaterializationError("GitHub CLI is unavailable for the Classroom50 probe")
    _probe([gh, "teacher", "--help"], environment)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--architecture", choices=("amd64", "arm64"))
    args = parser.parse_args()
    architecture = args.architecture or ARCHITECTURES.get(platform.machine().lower())
    if architecture is None:
        raise MaterializationError("unsupported Classroom50 platform")
    materialize(args.repository.resolve(), args.home, architecture)
    print("OpenClaw Classroom50 runtime: converged")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (MaterializationError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"materialize-openclaw-classroom50: {exc}", file=os.sys.stderr)
        raise SystemExit(2)
