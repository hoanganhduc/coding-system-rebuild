#!/usr/bin/env python3
"""Construct and publish the locked Node/npm closure as sealed generations owned by the user.

Nothing here runs as root: the builder refuses root, and every generation lives
under the owner's home.  The repository it reads may still be the root-owned
Stage-0 generation; it is only read.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import BinaryIO


OWNER_UID, OWNER_GID = os.geteuid(), os.getegid()
CODING_ROOT = Path(pwd.getpwuid(OWNER_UID).pw_dir) / ".local/share/coding-system"
NODE_ROOT = CODING_ROOT / "node-generations"
CLOSURE_ROOT = CODING_ROOT / "npm-closures"
LAUNCHER_ROOT = CODING_ROOT / "openclaw-launchers"
TREE_SCHEMA = "coding-system.immutable-tree/v1"
TREE_MARKER_SCHEMA = "coding-system.immutable-tree-complete/v1"
MANIFEST_NAME = ".csr-tree-manifest.json"
MARKER_NAME = ".csr-tree-complete"
ARTIFACT_MAGIC = b"CSR-OPENCLAW-ARTIFACTS-v1\n"
ARTIFACT_IDS = ("codewhale-codew", "codewhale-cli", "codewhale-tui")
ARTIFACT_TARGETS = ("codew", "codewhale", "codewhale-tui")
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_NODE_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_TREE_ENTRIES = 100_000
MAX_TREE_BYTES = 4 * 1024 * 1024 * 1024
AT_FDCWD = -100
RENAME_NOREPLACE = 1


class ClosureError(RuntimeError):
    pass


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _require_directory(path: Path, mode: int = 0o755) -> None:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) \
            or (info.st_uid, info.st_gid) != (OWNER_UID, OWNER_GID) \
            or stat.S_IMODE(info.st_mode) != mode:
        raise ClosureError(f"closure directory is unsafe: {path}")


def _require_owned(path: Path) -> None:
    """A real directory of the owner that no group or other can write."""

    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) \
            or info.st_uid != OWNER_UID or stat.S_IMODE(info.st_mode) & 0o022:
        raise ClosureError(f"closure parent directory is unsafe: {path}")


def _ensure_root(path: Path) -> Path:
    home = CODING_ROOT.parents[2]
    _require_owned(home)
    current = home
    for part in path.relative_to(home).parts:
        current = current / part
        managed = CODING_ROOT in current.parents
        created = False
        try:
            os.mkdir(current, 0o755 if managed else 0o700)
            created = True
        except FileExistsError:
            pass
        if created:
            if managed:
                os.chmod(current, 0o755)
            _fsync(current.parent)
        if managed:
            _require_directory(current)
        else:
            _require_owned(current)
    return current


def _require_repository(repository: Path) -> Path:
    repository = Path(repository)
    if not repository.is_absolute() or repository.is_symlink() or not repository.is_dir():
        raise ClosureError("OpenClaw builder requires one real repository directory")
    return repository


def _platform_lock(repository: Path, arch: str) -> tuple[dict[str, object], dict[str, dict[str, str]]]:
    if arch not in {"amd64", "arm64"}:
        raise ClosureError("unsupported OpenClaw closure architecture")
    path = repository / f"system/software/ubuntu-24.04-{arch}.lock.json"
    try:
        profile = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ClosureError("platform lock is unavailable or invalid") from exc
    if not isinstance(profile, dict) or not isinstance(profile.get("artifacts"), list):
        raise ClosureError("platform lock is invalid")
    artifacts: dict[str, dict[str, str]] = {}
    for raw in profile["artifacts"]:
        if not isinstance(raw, dict) or not all(isinstance(value, str) for value in raw.values()):
            raise ClosureError("platform artifact lock is invalid")
        identifier = raw.get("id")
        if isinstance(identifier, str):
            artifacts[identifier] = {str(key): str(value) for key, value in raw.items()}
    for identifier in ("node", *ARTIFACT_IDS):
        artifact = artifacts.get(identifier)
        if artifact is None or re.fullmatch(r"[0-9a-f]{64}", artifact.get("sha256", "")) is None:
            raise ClosureError(f"platform lock lacks exact artifact: {identifier}")
    return profile, artifacts


def _safe_relative(value: str) -> PurePosixPath:
    pure = PurePosixPath(value)
    if not value or pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ClosureError("immutable closure contains an unsafe path")
    return pure


def _safe_link(relative: str, target: str) -> None:
    pure = PurePosixPath(target)
    if not target or pure.is_absolute() or "\0" in target:
        raise ClosureError("immutable closure contains an unsafe symbolic link")
    depth = 0
    for part in PurePosixPath(relative).parent.joinpath(pure).parts:
        if part == "..":
            depth -= 1
        elif part not in {"", "."}:
            depth += 1
        if depth < 0:
            raise ClosureError("immutable closure contains an escaping symbolic link")


def _fsync(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _walk(root: Path) -> tuple[list[Path], list[Path], list[Path]]:
    directories: list[Path] = []
    files: list[Path] = []
    links: list[Path] = []
    device = root.lstat().st_dev
    total = 0
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        parent = Path(directory)
        for name in list(dirnames):
            child = parent / name
            info = child.lstat()
            if info.st_dev != device or (info.st_uid, info.st_gid) != (OWNER_UID, OWNER_GID):
                raise ClosureError("immutable closure entry authority changed")
            if stat.S_ISLNK(info.st_mode):
                links.append(child)
                dirnames.remove(name)
            elif stat.S_ISDIR(info.st_mode):
                directories.append(child)
            else:
                raise ClosureError("immutable closure contains an unsupported entry")
        for name in filenames:
            child = parent / name
            info = child.lstat()
            if info.st_dev != device or (info.st_uid, info.st_gid) != (OWNER_UID, OWNER_GID):
                raise ClosureError("immutable closure entry authority changed")
            if stat.S_ISLNK(info.st_mode):
                links.append(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                files.append(child)
                total += info.st_size
            else:
                raise ClosureError("immutable closure contains an unsupported or linked entry")
        if len(directories) + len(files) + len(links) > MAX_TREE_ENTRIES or total > MAX_TREE_BYTES:
            raise ClosureError("immutable closure exceeds its tree bounds")
    return directories, files, links


def _seal_payload(stage: Path) -> None:
    directories, files, links = _walk(stage)
    for path in files:
        mode = stat.S_IMODE(path.lstat().st_mode)
        if mode & 0o7000:
            raise ClosureError("closure file has special permission bits")
        os.chmod(path, 0o555 if mode & 0o111 else 0o444)
    for path in links:
        _safe_link(path.relative_to(stage).as_posix(), os.readlink(path))
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        os.chmod(path, 0o555)
        _fsync(path)


def _tree_entries(stage: Path) -> list[dict[str, object]]:
    directories, files, links = _walk(stage)
    entries: list[dict[str, object]] = []
    for path in directories:
        if stat.S_IMODE(path.lstat().st_mode) != 0o555:
            raise ClosureError("sealed closure directory is writable")
        entries.append({"mode": "0555", "path": path.relative_to(stage).as_posix(), "type": "directory"})
    for path in files:
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if mode not in {0o444, 0o555}:
            raise ClosureError("sealed closure file is writable")
        entries.append(
            {
                "mode": f"{mode:04o}",
                "path": path.relative_to(stage).as_posix(),
                "sha256": _sha256(path),
                "size": info.st_size,
                "type": "file",
            }
        )
    for path in links:
        relative = path.relative_to(stage).as_posix()
        target = os.readlink(path)
        _safe_link(relative, target)
        entries.append({"path": relative, "target": target, "type": "symlink"})
    entries.sort(key=lambda entry: str(entry["path"]))
    return entries


def _verify_tree(target: Path, expected_manifest_sha256: str | None = None) -> tuple[dict[str, object], str]:
    _require_directory(target, 0o555)
    manifest_path = target / MANIFEST_NAME
    marker_path = target / MARKER_NAME
    for path in (manifest_path, marker_path):
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 \
                or (info.st_uid, info.st_gid) != (OWNER_UID, OWNER_GID) or stat.S_IMODE(info.st_mode) != 0o444:
            raise ClosureError("immutable closure metadata file is unsafe")
    manifest_payload = manifest_path.read_bytes()
    manifest_sha = hashlib.sha256(manifest_payload).hexdigest()
    if expected_manifest_sha256 is not None and manifest_sha != expected_manifest_sha256:
        raise ClosureError("immutable closure manifest digest changed")
    try:
        manifest = json.loads(manifest_payload)
        marker = json.loads(marker_path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClosureError("immutable closure metadata is invalid") from exc
    if _canonical_json(manifest) != manifest_payload or marker != {
        "manifest_sha256": manifest_sha,
        "schema": TREE_MARKER_SCHEMA,
    }:
        raise ClosureError("immutable closure metadata changed")
    expected_entries = manifest.get("entries") if isinstance(manifest, dict) else None
    if not isinstance(expected_entries, list):
        raise ClosureError("immutable closure manifest entries are invalid")
    actual_entries = _tree_entries(target)
    actual_entries = [
        entry for entry in actual_entries if entry["path"] not in {MANIFEST_NAME, MARKER_NAME}
    ]
    if actual_entries != expected_entries:
        raise ClosureError("immutable closure tree differs from its complete manifest")
    return manifest, manifest_sha


def _rename_noreplace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise ClosureError("renameat2(RENAME_NOREPLACE) is unavailable")
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    if renameat2(AT_FDCWD, os.fsencode(source), AT_FDCWD, os.fsencode(target), RENAME_NOREPLACE) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(code, os.strerror(code), target)
        raise ClosureError(f"cannot publish immutable closure: {os.strerror(code)}")


def _remove_stage(base: Path, stage: Path) -> None:
    if not os.path.lexists(stage):
        return
    if stage.parent != base or not stage.name.startswith(".stage-") or stage.is_symlink():
        raise ClosureError("refusing unsafe closure stage cleanup")
    for directory, dirnames, _filenames in os.walk(stage, topdown=True, followlinks=False):
        os.chmod(directory, 0o700)
        for name in dirnames:
            child = Path(directory) / name
            if child.is_dir() and not child.is_symlink():
                os.chmod(child, 0o700)
    shutil.rmtree(stage)
    _fsync(base)


def _publish_tree(
    stage: Path,
    base: Path,
    name: str,
    *,
    arch: str,
    identity: str,
    kind: str,
) -> tuple[Path, str]:
    if stage.parent != base or not stage.name.startswith(".stage-"):
        raise ClosureError("closure stage is outside its fixed root")
    _seal_payload(stage)
    entries = _tree_entries(stage)
    manifest = {
        "arch": arch,
        "entries": entries,
        "identity": identity,
        "kind": kind,
        "schema": TREE_SCHEMA,
    }
    manifest_payload = _canonical_json(manifest)
    manifest_sha = hashlib.sha256(manifest_payload).hexdigest()
    _write_owned_file(stage / MANIFEST_NAME, manifest_payload, 0o444)
    # Completion marker is the final stage member, before atomic publication.
    _write_owned_file(
        stage / MARKER_NAME,
        _canonical_json({"manifest_sha256": manifest_sha, "schema": TREE_MARKER_SCHEMA}),
        0o444,
    )
    os.chmod(stage, 0o555)
    _fsync(stage)
    _verify_tree(stage, manifest_sha)
    target = base / name
    if os.path.lexists(target):
        existing, existing_sha = _verify_tree(target, manifest_sha)
        if existing != manifest:
            raise ClosureError("published closure differs from its locked reconstruction")
        _remove_stage(base, stage)
        return target, existing_sha
    try:
        _rename_noreplace(stage, target)
    except FileExistsError:
        existing, existing_sha = _verify_tree(target, manifest_sha)
        if existing != manifest:
            raise ClosureError("concurrent closure publication disagreed")
        _remove_stage(base, stage)
        return target, existing_sha
    _fsync(base)
    _verify_tree(target, manifest_sha)
    return target, manifest_sha


def _write_owned_file(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _new_stage(base: Path, label: str) -> Path:
    for _attempt in range(128):
        stage = base / f".stage-{label}-{secrets.token_hex(12)}"
        try:
            os.mkdir(stage, 0o700)
        except FileExistsError:
            continue
        return stage
    raise ClosureError("cannot allocate a closure stage")


def _read_bounded(stream: BinaryIO, maximum: int) -> bytes:
    payload = stream.read(maximum + 1)
    if not payload or len(payload) > maximum:
        raise ClosureError("locked artifact stream is empty or oversized")
    return payload


def publish_node(repository: Path, arch: str, stream: BinaryIO) -> tuple[Path, str]:
    repository = _require_repository(repository)
    _profile, artifacts = _platform_lock(repository, arch)
    node = artifacts["node"]
    payload = _read_bounded(stream, MAX_NODE_ARCHIVE_BYTES)
    if hashlib.sha256(payload).hexdigest() != node["sha256"]:
        raise ClosureError("Node archive differs from the platform lock")
    base = _ensure_root(NODE_ROOT)
    name = f"sha256-{arch}-{node['sha256']}"
    if os.path.lexists(base / name):
        manifest, manifest_sha = _verify_tree(base / name)
        if manifest.get("arch") != arch or manifest.get("kind") != "node-runtime" \
                or manifest.get("identity") != node["sha256"]:
            raise ClosureError("published Node generation differs from its platform lock")
        return base / name, manifest_sha
    stage = _new_stage(base, f"node-{arch}")
    archive = base / f".node-archive-{secrets.token_hex(12)}"
    try:
        _write_owned_file(archive, payload, 0o400)
        unpack = stage / ".unpack"
        os.mkdir(unpack, 0o700)
        with tarfile.open(archive, mode="r:xz") as bundle:
            members = bundle.getmembers()
            expected_top = f"node-v{node['version']}-linux-{'x64' if arch == 'amd64' else 'arm64'}"
            for member in members:
                pure = PurePosixPath(member.name)
                if not pure.parts or pure.is_absolute() or pure.parts[0] != expected_top \
                        or any(part in {"", ".", ".."} for part in pure.parts) \
                        or not (member.isdir() or member.isreg() or member.issym()):
                    raise ClosureError("Node archive contains an unsafe member")
                if member.issym():
                    _safe_link(member.name, member.linkname)
            bundle.extractall(unpack, filter="data")
        source = unpack / expected_top
        if source.is_symlink() or not source.is_dir():
            raise ClosureError("Node archive lacks its exact distribution root")
        for child in source.iterdir():
            os.rename(child, stage / child.name)
        os.rmdir(source)
        os.rmdir(unpack)
        probe = subprocess.run(
            [os.fspath(stage / "bin/node"), "--version"],
            env={"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
            check=False,
        )
        if probe.returncode != 0 or probe.stdout.strip() != f"v{node['version']}":
            raise ClosureError("locked Node generation reports the wrong version")
        return _publish_tree(
            stage,
            base,
            name,
            arch=arch,
            identity=node["sha256"],
            kind="node-runtime",
        )
    except BaseException:
        _remove_stage(base, stage)
        raise
    finally:
        if os.path.lexists(archive):
            os.unlink(archive)


def emit_artifacts(repository: Path, arch: str, directory: Path, output: BinaryIO) -> None:
    repository = Path(repository)
    _profile, artifacts = _platform_lock(repository, arch)
    output.write(ARTIFACT_MAGIC)
    output.write(_canonical_json({"arch": arch, "count": len(ARTIFACT_IDS)}))
    for identifier in ARTIFACT_IDS:
        path = directory / identifier
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 \
                or info.st_uid != os.geteuid() or not 0 < info.st_size <= MAX_ARTIFACT_BYTES:
            raise ClosureError("CodeWhale artifact input is unsafe")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != artifacts[identifier]["sha256"]:
            raise ClosureError("CodeWhale artifact differs from its platform lock")
        output.write(_canonical_json({"id": identifier, "size": len(payload)}))
        output.write(payload + b"\n")
    output.write(b"END\n")
    output.flush()


def _read_artifacts(repository: Path, arch: str, stream: BinaryIO) -> dict[str, bytes]:
    _profile, artifacts = _platform_lock(repository, arch)
    if stream.read(len(ARTIFACT_MAGIC)) != ARTIFACT_MAGIC:
        raise ClosureError("CodeWhale artifact stream has the wrong magic")
    try:
        header = json.loads(stream.readline(4097))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClosureError("CodeWhale artifact stream header is invalid") from exc
    if header != {"arch": arch, "count": len(ARTIFACT_IDS)}:
        raise ClosureError("CodeWhale artifact stream identity is invalid")
    result: dict[str, bytes] = {}
    for expected in ARTIFACT_IDS:
        try:
            record = json.loads(stream.readline(4097))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ClosureError("CodeWhale artifact record is invalid") from exc
        size = record.get("size") if isinstance(record, dict) else None
        if record.get("id") != expected or not isinstance(size, int) or not 0 < size <= MAX_ARTIFACT_BYTES:
            raise ClosureError("CodeWhale artifact record is invalid")
        payload = stream.read(size)
        if len(payload) != size or stream.read(1) != b"\n" \
                or hashlib.sha256(payload).hexdigest() != artifacts[expected]["sha256"]:
            raise ClosureError("CodeWhale artifact payload differs from the platform lock")
        result[expected] = payload
    if stream.read(4) != b"END\n" or stream.read(1):
        raise ClosureError("CodeWhale artifact stream has trailing data")
    return result


def _run_checked(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, timeout: int = 120) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise ClosureError("locked closure construction command failed")
    return completed.stdout.strip()


def _install_launcher(
    repository: Path,
    arch: str,
    node_root: Path,
    node_manifest_sha: str,
    closure_root: Path,
    closure_manifest_sha: str,
) -> dict[str, object]:
    helper_source = repository / "bin/converge-openclaw-executable.py"
    loader_source = repository / "bin/openclaw-launcher.py"
    for source in (helper_source, loader_source):
        info = source.lstat()
        if source.is_symlink() or not stat.S_ISREG(info.st_mode) \
                or info.st_uid not in {0, OWNER_UID} or stat.S_IMODE(info.st_mode) & 0o022:
            raise ClosureError("OpenClaw launcher source is not owner-controlled")
    package = json.loads((closure_root / "node_modules/openclaw/package.json").read_bytes())
    version = package.get("version") if isinstance(package, dict) else None
    if not isinstance(version, str) or not version:
        raise ClosureError("locked OpenClaw package version is unavailable")
    entry = closure_root / "node_modules/openclaw/openclaw.mjs"
    node = node_root / "bin/node"
    contract = {
        "arch": arch,
        "closure_manifest_sha256": closure_manifest_sha,
        "closure_root": os.fspath(closure_root),
        "entry": "node_modules/openclaw/openclaw.mjs",
        "entry_sha256": _sha256(entry),
        "node": "bin/node",
        "node_manifest_sha256": node_manifest_sha,
        "node_root": os.fspath(node_root),
        "node_sha256": _sha256(node),
        "package": "openclaw",
        "schema": "coding-system.openclaw-executable/v2",
        "version": version,
    }
    contract_payload = _canonical_json(contract)
    helper_payload = helper_source.read_bytes()
    helper_sha = hashlib.sha256(helper_payload).hexdigest()
    contract_sha = hashlib.sha256(contract_payload).hexdigest()
    marker_payload = _canonical_json(
        {"contract_sha256": contract_sha, "helper_sha256": helper_sha, "schema": "coding-system.openclaw-launcher/v1"}
    )
    marker_sha = hashlib.sha256(marker_payload).hexdigest()
    generation_sha = hashlib.sha256(helper_payload + contract_payload + marker_payload).hexdigest()
    base = _ensure_root(LAUNCHER_ROOT)
    generations = _ensure_root(base / "generations")
    selectors = _ensure_root(base / "selectors")
    target = generations / f"sha256-{generation_sha}"
    if not os.path.lexists(target):
        stage = _new_stage(generations, "launcher")
        try:
            _write_owned_file(stage / "converge-openclaw-executable.py", helper_payload, 0o444)
            _write_owned_file(stage / "contract.json", contract_payload, 0o444)
            _write_owned_file(stage / ".csr-launcher-complete", marker_payload, 0o444)
            os.chmod(stage, 0o555)
            _fsync(stage)
            _rename_noreplace(stage, target)
            _fsync(generations)
        except BaseException:
            _remove_stage(generations, stage)
            raise
    _require_directory(target, 0o555)
    if set(os.listdir(target)) != {"converge-openclaw-executable.py", "contract.json", ".csr-launcher-complete"} \
            or _sha256(target / "converge-openclaw-executable.py") != helper_sha \
            or _sha256(target / "contract.json") != contract_sha \
            or _sha256(target / ".csr-launcher-complete") != marker_sha:
        raise ClosureError("OpenClaw launcher generation changed")
    loader_target = base / "loader.py"
    loader_payload = loader_source.read_bytes()
    loader_sha = hashlib.sha256(loader_payload).hexdigest()
    _replace_owned_file(loader_target, loader_payload, 0o444)
    if _sha256(loader_target) != loader_sha:
        raise ClosureError("OpenClaw selector loader changed")
    selector_payload = _canonical_json(
        {
            "arch": arch,
            "contract_sha256": contract_sha,
            "helper_sha256": helper_sha,
            "launcher_root": os.fspath(target),
            "marker_sha256": marker_sha,
            "schema": "coding-system.openclaw-launcher-selector/v1",
        }
    )
    _replace_owned_file(selectors / f"{arch}.json", selector_payload, 0o444)
    return {"contract": os.fspath(target / "contract.json"), "launcher": os.fspath(target), "loader": os.fspath(loader_target)}


def _replace_owned_file(target: Path, payload: bytes, mode: int) -> None:
    stage = target.parent / f".{target.name}.stage-{secrets.token_hex(12)}"
    try:
        _write_owned_file(stage, payload, mode)
        if os.path.lexists(target):
            info = target.lstat()
            if target.is_symlink() or not stat.S_ISREG(info.st_mode) \
                    or (info.st_uid, info.st_gid) != (OWNER_UID, OWNER_GID):
                raise ClosureError("refusing to replace an unsafe launcher file")
        os.replace(stage, target)
        _fsync(target.parent)
    finally:
        if os.path.lexists(stage):
            os.unlink(stage)


def build_closure(repository: Path, arch: str, node_root: Path, stream: BinaryIO) -> dict[str, object]:
    repository = _require_repository(repository)
    _profile, artifacts = _platform_lock(repository, arch)
    expected_node = NODE_ROOT / f"sha256-{arch}-{artifacts['node']['sha256']}"
    if node_root != expected_node:
        raise ClosureError("Node generation path differs from the platform lock")
    node_manifest, node_manifest_sha = _verify_tree(node_root)
    if node_manifest.get("kind") != "node-runtime" or node_manifest.get("arch") != arch:
        raise ClosureError("Node generation identity is invalid")
    injected = _read_artifacts(repository, arch, stream)
    closure_source = repository / "system/software/npm-closure"
    closurectl = closure_source / "closurectl.py"
    _run_checked(["/usr/bin/python3", "-I", "-B", os.fspath(closurectl), "validate"])
    source_hash = _run_checked(["/usr/bin/python3", "-I", "-B", os.fspath(closurectl), "source-digest"])
    if re.fullmatch(r"[0-9a-f]{64}", source_hash) is None:
        raise ClosureError("npm closure source digest is invalid")
    base = _ensure_root(CLOSURE_ROOT)
    stage = _new_stage(base, f"npm-{arch}-{source_hash}")
    work = Path(tempfile.mkdtemp(prefix=".npm-work-", dir=base))
    try:
        shutil.copyfile(closure_source / "package.json", stage / "package.json")
        shutil.copyfile(closure_source / "package-lock.json", stage / "package-lock.json")
        npm_cli = node_root / "lib/node_modules/npm/bin/npm-cli.js"
        environment = {
            "HOME": os.fspath(work / "home"),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": f"{node_root / 'bin'}:/usr/bin:/bin",
            "npm_config_cache": os.fspath(work / "cache"),
        }
        os.mkdir(work / "home", 0o700)
        _run_checked(
            [
                os.fspath(node_root / "bin/node"),
                os.fspath(npm_cli),
                "ci",
                "--ignore-scripts",
                "--include=optional",
                "--install-strategy=hoisted",
                "--no-audit",
                "--no-fund",
            ],
            cwd=stage,
            env=environment,
            timeout=1800,
        )
        codewhale = stage / "node_modules/codewhale"
        manifest = json.loads((codewhale / "package.json").read_bytes())
        if not isinstance(manifest, dict) or manifest.get("name") != "codewhale" or manifest.get("version") != "0.9.2":
            raise ClosureError("locked CodeWhale package identity is invalid")
        downloads = codewhale / "bin/downloads"
        downloads.mkdir(mode=0o755, exist_ok=True)
        for identifier, target_name in zip(ARTIFACT_IDS, ARTIFACT_TARGETS, strict=True):
            if artifacts[identifier]["version"] != "0.9.2":
                raise ClosureError("CodeWhale artifact version differs from its npm wrapper")
            _write_owned_file(downloads / target_name, injected[identifier], 0o755)
            _write_owned_file(downloads / f"{target_name}.version", b"0.9.2", 0o644)
        _run_checked(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                os.fspath(closurectl),
                "verify-install",
                os.fspath(stage),
                "--arch",
                arch,
            ],
            timeout=180,
        )
        # The tree hash is computed by the builder after npm and all
        # locked native artifacts have been installed.  It is an identity, not
        # a trust-on-first-use replacement for the package lock/integrities.
        tree_hash = _run_checked(
            ["/usr/bin/python3", "-I", "-B", os.fspath(closurectl), "tree-digest", os.fspath(stage)],
            timeout=300,
        )
        if re.fullmatch(r"[0-9a-f]{64}", tree_hash) is None:
            raise ClosureError("npm closure tree digest is invalid")
        target, closure_manifest_sha = _publish_tree(
            stage,
            base,
            f"sha256-{arch}-{source_hash}-{tree_hash}",
            arch=arch,
            identity=f"{source_hash}:{tree_hash}",
            kind="npm-closure",
        )
        launcher = _install_launcher(
            repository,
            arch,
            node_root,
            node_manifest_sha,
            target,
            closure_manifest_sha,
        )
        return {
            "arch": arch,
            "closure_manifest_sha256": closure_manifest_sha,
            "closure_root": os.fspath(target),
            "node_manifest_sha256": node_manifest_sha,
            "node_root": os.fspath(node_root),
            **launcher,
        }
    except BaseException:
        _remove_stage(base, stage)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("publish-node", "emit-artifacts", "build-closure"):
        command = commands.add_parser(name)
        command.add_argument("--repository", type=Path, required=True)
        command.add_argument("--arch", choices=("amd64", "arm64"), required=True)
        if name == "emit-artifacts":
            command.add_argument("--directory", type=Path, required=True)
        if name == "build-closure":
            command.add_argument("--node-root", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if OWNER_UID == 0:
        raise ClosureError("the OpenClaw closure is built by its owner, never by root")
    if arguments.command == "emit-artifacts":
        emit_artifacts(arguments.repository, arguments.arch, arguments.directory, sys.stdout.buffer)
        return 0
    if arguments.command == "publish-node":
        target, manifest_sha = publish_node(arguments.repository, arguments.arch, sys.stdin.buffer)
        print(_canonical_json({"manifest_sha256": manifest_sha, "node_root": os.fspath(target)}).decode("ascii"), end="")
    else:
        print(_canonical_json(build_closure(arguments.repository, arguments.arch, arguments.node_root, sys.stdin.buffer)).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ClosureError, OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f"openclaw-closure: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
