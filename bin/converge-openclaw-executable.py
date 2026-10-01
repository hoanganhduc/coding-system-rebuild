#!/usr/bin/env python3
"""Verify and execute OpenClaw only from sealed, locked generations owned by the user.

OpenClaw never runs as root and never from a root-owned tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_ENTRIES = 100_000
EXPECTED_SCHEMA = "coding-system.openclaw-executable/v2"
TREE_SCHEMA = "coding-system.immutable-tree/v1"
TREE_MARKER_SCHEMA = "coding-system.immutable-tree-complete/v1"
MANIFEST_NAME = ".csr-tree-manifest.json"
MARKER_NAME = ".csr-tree-complete"
EXECUTION_PATH = "/usr/bin:/bin"
EXECUTION_LOCALE = "C.UTF-8"


class ContractError(RuntimeError):
    """A redaction-safe executable-contract failure."""


def _execution_environment(home: Path) -> dict[str, str]:
    return {
        "HOME": os.fspath(home),
        "LANG": EXECUTION_LOCALE,
        "LC_ALL": EXECUTION_LOCALE,
        "PATH": EXECUTION_PATH,
    }


def _stable_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_regular(
    path: Path,
    limit: int,
    *,
    uid: int,
    gid: int,
    modes: frozenset[int],
) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        linked = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or _stable_identity(before) != _stable_identity(linked)
            or before.st_uid != uid
            or before.st_gid != gid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in modes
            or before.st_size < 0
            or before.st_size > limit
        ):
            raise ContractError("OpenClaw trusted input has unsafe metadata")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 64 * 1024))
            if not block:
                raise ContractError("OpenClaw trusted input changed")
            chunks.append(block)
            remaining -= len(block)
        if _stable_identity(before) != _stable_identity(os.fstat(descriptor)):
            raise ContractError("OpenClaw trusted input changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_json_regular(
    path: Path, *, uid: int, gid: int, limit: int = MAX_JSON_BYTES
) -> tuple[dict[str, object], bytes]:
    payload = _read_regular(
        path, limit, uid=uid, gid=gid, modes=frozenset({0o444})
    )
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("OpenClaw trusted JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ContractError("OpenClaw trusted JSON is invalid")
    canonical = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    if canonical != payload:
        raise ContractError("OpenClaw trusted JSON is not canonical")
    return value, payload


def _safe_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise ContractError(f"invalid {label}")
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ContractError(f"invalid {label}")
    return value


def _safe_absolute(value: object, prefix: Path, label: str) -> Path:
    if not isinstance(value, str):
        raise ContractError(f"invalid {label}")
    path = Path(value)
    if not path.is_absolute() or path == Path("/") or Path(os.path.normpath(path)) != path:
        raise ContractError(f"invalid {label}")
    try:
        path.relative_to(prefix)
    except ValueError as exc:
        raise ContractError(f"invalid {label}") from exc
    return path


def _load_contract(
    path: Path,
    *,
    uid: int,
    gid: int,
    coding_prefix: Path,
) -> dict[str, object]:
    value, _payload = _load_json_regular(
        path, uid=uid, gid=gid, limit=256 * 1024
    )
    required = {
        "arch",
        "closure_manifest_sha256",
        "closure_root",
        "entry",
        "entry_sha256",
        "node",
        "node_manifest_sha256",
        "node_root",
        "node_sha256",
        "package",
        "schema",
        "version",
    }
    if set(value) != required or (
        value.get("schema") != EXPECTED_SCHEMA
        or value.get("package") != "openclaw"
        or value.get("arch") not in {"amd64", "arm64"}
        or not isinstance(value.get("version"), str)
        or re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}", str(value.get("version"))) is None
    ):
        raise ContractError("OpenClaw executable contract is invalid")
    for field in (
        "closure_manifest_sha256",
        "entry_sha256",
        "node_manifest_sha256",
        "node_sha256",
    ):
        if not isinstance(value.get(field), str) or re.fullmatch(r"[0-9a-f]{64}", str(value[field])) is None:
            raise ContractError("OpenClaw executable contract is invalid")
    _safe_absolute(value["closure_root"], coding_prefix / "npm-closures", "closure root")
    _safe_absolute(value["node_root"], coding_prefix / "node-generations", "Node root")
    if _safe_relative(value["entry"], "OpenClaw entry") != "node_modules/openclaw/openclaw.mjs":
        raise ContractError("OpenClaw executable contract is invalid")
    if _safe_relative(value["node"], "Node executable") != "bin/node":
        raise ContractError("OpenClaw executable contract is invalid")
    return value


def _safe_link(relative: str, target: str) -> None:
    pure = PurePosixPath(target)
    if not target or pure.is_absolute() or "\x00" in target:
        raise ContractError("immutable OpenClaw tree contains an unsafe symbolic link")
    depth = 0
    for part in PurePosixPath(relative).parent.joinpath(pure).parts:
        if part == "..":
            depth -= 1
        elif part not in {"", "."}:
            depth += 1
        if depth < 0:
            raise ContractError("immutable OpenClaw tree contains an escaping symbolic link")


def _scan_tree(root: Path) -> dict[str, os.stat_result]:
    result: dict[str, os.stat_result] = {}
    device = root.lstat().st_dev
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        parent = Path(directory)
        for name in list(dirnames):
            path = parent / name
            info = path.lstat()
            if info.st_dev != device:
                raise ContractError("immutable OpenClaw tree crosses a device boundary")
            result[path.relative_to(root).as_posix()] = info
            if stat.S_ISLNK(info.st_mode):
                dirnames.remove(name)
        for name in filenames:
            path = parent / name
            info = path.lstat()
            if info.st_dev != device:
                raise ContractError("immutable OpenClaw tree crosses a device boundary")
            result[path.relative_to(root).as_posix()] = info
        if len(result) > MAX_ENTRIES:
            raise ContractError("immutable OpenClaw tree exceeds its entry bound")
    return result


def _verify_sealed_tree(
    root: Path,
    expected_manifest_sha256: str,
    *,
    uid: int,
    gid: int,
) -> dict[str, dict[str, object]]:
    root_info = root.lstat()
    if (
        root.is_symlink()
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != uid
        or root_info.st_gid != gid
        or stat.S_IMODE(root_info.st_mode) != 0o555
    ):
        raise ContractError("immutable OpenClaw tree root is unsafe")
    manifest, payload = _load_json_regular(
        root / MANIFEST_NAME, uid=uid, gid=gid
    )
    if hashlib.sha256(payload).hexdigest() != expected_manifest_sha256 or (
        set(manifest) != {"arch", "entries", "identity", "kind", "schema"}
        or manifest.get("schema") != TREE_SCHEMA
        or manifest.get("arch") not in {"amd64", "arm64"}
        or manifest.get("kind") not in {"node-runtime", "npm-closure"}
        or not isinstance(manifest.get("identity"), str)
        or not isinstance(manifest.get("entries"), list)
    ):
        raise ContractError("immutable OpenClaw tree manifest is invalid")
    marker, _marker_payload = _load_json_regular(
        root / MARKER_NAME, uid=uid, gid=gid, limit=64 * 1024
    )
    if marker != {
        "manifest_sha256": expected_manifest_sha256,
        "schema": TREE_MARKER_SCHEMA,
    }:
        raise ContractError("immutable OpenClaw tree completion marker is invalid")
    expected: dict[str, dict[str, object]] = {}
    for raw in manifest["entries"]:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
            raise ContractError("immutable OpenClaw tree manifest entry is invalid")
        relative = _safe_relative(raw["path"], "immutable tree path")
        if relative in expected or relative in {MANIFEST_NAME, MARKER_NAME}:
            raise ContractError("immutable OpenClaw tree manifest entry is duplicate")
        expected[relative] = raw
    actual = _scan_tree(root)
    if set(actual) != set(expected) | {MANIFEST_NAME, MARKER_NAME}:
        raise ContractError("immutable OpenClaw tree has missing or extra entries")
    for relative, record in expected.items():
        path = root / relative
        info = actual[relative]
        if info.st_uid != uid or info.st_gid != gid or info.st_dev != root_info.st_dev:
            raise ContractError("immutable OpenClaw tree entry authority changed")
        kind = record.get("type")
        if kind == "directory":
            if set(record) != {"mode", "path", "type"} or not stat.S_ISDIR(info.st_mode) \
                    or stat.S_IMODE(info.st_mode) != 0o555:
                raise ContractError("immutable OpenClaw directory changed")
        elif kind == "symlink":
            target = record.get("target")
            if set(record) != {"path", "target", "type"} or not isinstance(target, str) \
                    or not stat.S_ISLNK(info.st_mode) or info.st_nlink != 1 \
                    or os.readlink(path) != target:
                raise ContractError("immutable OpenClaw symbolic link changed")
            _safe_link(relative, target)
        elif kind == "file":
            if set(record) != {"mode", "path", "sha256", "size", "type"}:
                raise ContractError("immutable OpenClaw file record is invalid")
            mode = record.get("mode")
            expected_mode = 0o555 if mode == "0555" else 0o444 if mode == "0444" else -1
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 \
                    or stat.S_IMODE(info.st_mode) != expected_mode \
                    or info.st_size != record.get("size") \
                    or not isinstance(record.get("sha256"), str):
                raise ContractError("immutable OpenClaw file metadata changed")
            if info.st_size < 0 or info.st_size > MAX_FILE_BYTES:
                raise ContractError("immutable OpenClaw file exceeds its bound")
            data = _read_regular(
                path,
                max(1, info.st_size),
                uid=uid,
                gid=gid,
                modes=frozenset({expected_mode}),
            )
            if hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ContractError("immutable OpenClaw file bytes changed")
        else:
            raise ContractError("immutable OpenClaw tree entry type is invalid")
    return expected


def _open_executable(
    path: Path, expected_sha256: str, *, uid: int, gid: int
) -> int:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        linked = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or _stable_identity(info) != _stable_identity(linked)
            or info.st_uid != uid
            or info.st_gid != gid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o555
        ):
            raise ContractError("OpenClaw executable has unsafe metadata")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            digest.update(block)
        if digest.hexdigest() != expected_sha256:
            raise ContractError("OpenClaw executable digest differs from its contract")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def converge(
    home: Path,
    contract_path: Path,
    *,
    apply: bool,
    exec_arguments: list[str] | None = None,
    trusted_uid: int,
    trusted_gid: int,
    trusted_prefix: Path,
) -> dict[str, object]:
    contract = _load_contract(
        contract_path,
        uid=trusted_uid,
        gid=trusted_gid,
        coding_prefix=trusted_prefix,
    )
    home = Path(os.path.abspath(home))
    home_info = home.lstat()
    if home == Path("/") or home.is_symlink() or not stat.S_ISDIR(home_info.st_mode) \
            or home_info.st_uid != os.geteuid() or stat.S_IMODE(home_info.st_mode) & 0o022:
        raise ContractError("OpenClaw executable HOME is unsafe")
    closure_root = Path(str(contract["closure_root"]))
    node_root = Path(str(contract["node_root"]))
    closure_entries = _verify_sealed_tree(
        closure_root,
        str(contract["closure_manifest_sha256"]),
        uid=trusted_uid,
        gid=trusted_gid,
    )
    node_entries = _verify_sealed_tree(
        node_root,
        str(contract["node_manifest_sha256"]),
        uid=trusted_uid,
        gid=trusted_gid,
    )
    entry_relative = str(contract["entry"])
    node_relative = str(contract["node"])
    if entry_relative not in closure_entries or node_relative not in node_entries:
        raise ContractError("OpenClaw contract executable is absent from its full manifest")
    entry_path = closure_root / entry_relative
    node_path = node_root / node_relative
    entry_fd = _open_executable(
        entry_path,
        str(contract["entry_sha256"]),
        uid=trusted_uid,
        gid=trusted_gid,
    )
    node_fd = _open_executable(
        node_path,
        str(contract["node_sha256"]),
        uid=trusted_uid,
        gid=trusted_gid,
    )
    try:
        if exec_arguments is not None:
            if apply or not exec_arguments:
                raise ContractError("OpenClaw exact execution arguments are invalid")
            os.set_inheritable(node_fd, True)
            os.execve(
                f"/proc/self/fd/{node_fd}",
                ["openclaw", os.fspath(entry_path), *exec_arguments],
                _execution_environment(home),
            )
        return {
            "arch": contract["arch"],
            "closureManifestSha256": contract["closure_manifest_sha256"],
            "closureRoot": os.fspath(closure_root),
            "entry": entry_relative,
            "nodeRoot": os.fspath(node_root),
            "schema": EXPECTED_SCHEMA,
            "status": "converged" if apply else "verified",
            "version": contract["version"],
        }
    finally:
        os.close(node_fd)
        os.close(entry_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--home", required=True)
    parser.add_argument("--contract", required=True)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--apply", action="store_true")
    action.add_argument("--exec", dest="execute", action="store_true")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    try:
        if os.geteuid() == 0:
            raise ContractError("OpenClaw runs as its owner, never as root")
        home = Path(arguments.home)
        report = converge(
            home,
            Path(arguments.contract),
            apply=arguments.apply,
            exec_arguments=(
                arguments.arguments[1:]
                if arguments.execute and arguments.arguments[:1] == ["--"]
                else arguments.arguments if arguments.execute else None
            ),
            trusted_uid=os.geteuid(),
            trusted_gid=os.getegid(),
            trusted_prefix=home / ".local/share/coding-system",
        )
    except (ContractError, OSError) as exc:
        print(f"OpenClaw executable contract: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
