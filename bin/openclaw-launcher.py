#!/usr/bin/env python3
"""Resolve one sealed OpenClaw launcher generation owned by the user and delegate to it.

OpenClaw never runs from a root-owned tree: the launcher refuses root, and the
generations live under the owner's home.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys


# Relative to the owner's home directory.
ROOT_RELATIVE = Path(".local/share/coding-system/openclaw-launchers")
SCHEMA = "coding-system.openclaw-launcher-selector/v1"
MAX_BYTES = 256 * 1024


class LauncherError(RuntimeError):
    pass


def canonical_arch(value: str | None = None) -> str:
    machine = (value or platform.machine()).lower()
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    raise LauncherError("unsupported OpenClaw launcher architecture")


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_ctime_ns,
    )


def _require_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or (info.st_uid, info.st_gid) != (uid, gid)
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise LauncherError("OpenClaw launcher directory is unsafe")


def _read(
    path: Path,
    expected_sha256: str | None = None,
    *,
    uid: int,
    gid: int,
) -> tuple[bytes, int]:
    # O_NOFOLLOW makes a symlinked input fail with ELOOP, and an unreadable or
    # absent one fails with its own errno.  Those are launcher-contract
    # violations, so they must reach callers as LauncherError rather than as a
    # bare OSError that `except LauncherError` does not catch.
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise LauncherError("OpenClaw launcher input is unreadable") from exc
    try:
        before = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or _identity(before) != _identity(named)
            or before.st_uid != uid
            or before.st_gid != gid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o444
            or not 0 < before.st_size <= MAX_BYTES
        ):
            raise LauncherError("OpenClaw launcher input has unsafe metadata")
        payload = bytearray()
        while len(payload) < before.st_size:
            block = os.read(descriptor, before.st_size - len(payload))
            if not block:
                raise LauncherError("OpenClaw launcher input changed")
            payload.extend(block)
        if _identity(before) != _identity(os.fstat(descriptor)):
            raise LauncherError("OpenClaw launcher input changed")
        if expected_sha256 is not None and hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise LauncherError("OpenClaw launcher input digest changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return bytes(payload), descriptor
    except BaseException:
        os.close(descriptor)
        raise


def resolve(
    arch: str,
    *,
    root: Path,
    trusted_uid: int,
    trusted_gid: int,
) -> tuple[Path, Path, int]:
    arch = canonical_arch(arch)
    root = Path(root)
    _require_directory(root, uid=trusted_uid, gid=trusted_gid, mode=0o755)
    _require_directory(
        root / "selectors", uid=trusted_uid, gid=trusted_gid, mode=0o755
    )
    _require_directory(
        root / "generations", uid=trusted_uid, gid=trusted_gid, mode=0o755
    )
    selector_path = root / "selectors" / f"{arch}.json"
    selector_payload, selector_fd = _read(
        selector_path, uid=trusted_uid, gid=trusted_gid
    )
    os.close(selector_fd)
    try:
        selector = json.loads(selector_payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LauncherError("OpenClaw launcher selector is invalid") from exc
    canonical = (
        json.dumps(selector, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    if not isinstance(selector, dict) or canonical != selector_payload or (
        set(selector) != {"arch", "contract_sha256", "helper_sha256", "launcher_root", "marker_sha256", "schema"}
        or selector.get("schema") != SCHEMA
        or selector.get("arch") != arch
    ):
        raise LauncherError("OpenClaw launcher selector is invalid")
    for field in ("contract_sha256", "helper_sha256", "marker_sha256"):
        if not isinstance(selector.get(field), str) or re.fullmatch(r"[0-9a-f]{64}", selector[field]) is None:
            raise LauncherError("OpenClaw launcher selector digest is invalid")
    launcher_root = Path(str(selector.get("launcher_root", "")))
    expected_parent = root / "generations"
    if not launcher_root.is_absolute() or launcher_root.parent != expected_parent \
            or re.fullmatch(r"sha256-[0-9a-f]{64}", launcher_root.name) is None:
        raise LauncherError("OpenClaw launcher selector path is invalid")
    root_info = launcher_root.lstat()
    if launcher_root.is_symlink() or not stat.S_ISDIR(root_info.st_mode) \
            or (root_info.st_uid, root_info.st_gid) != (trusted_uid, trusted_gid) \
            or stat.S_IMODE(root_info.st_mode) != 0o555:
        raise LauncherError("OpenClaw launcher generation is unsafe")
    helper = launcher_root / "converge-openclaw-executable.py"
    contract = launcher_root / "contract.json"
    marker = launcher_root / ".csr-launcher-complete"
    if set(os.listdir(launcher_root)) != {
        "converge-openclaw-executable.py",
        "contract.json",
        ".csr-launcher-complete",
    }:
        raise LauncherError("OpenClaw launcher generation has missing or extra entries")
    _marker_payload, marker_fd = _read(
        marker,
        str(selector["marker_sha256"]),
        uid=trusted_uid,
        gid=trusted_gid,
    )
    os.close(marker_fd)
    _contract_payload, contract_fd = _read(
        contract,
        str(selector["contract_sha256"]),
        uid=trusted_uid,
        gid=trusted_gid,
    )
    os.close(contract_fd)
    _helper_payload, helper_fd = _read(
        helper,
        str(selector["helper_sha256"]),
        uid=trusted_uid,
        gid=trusted_gid,
    )
    return helper, contract, helper_fd


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--home", required=True)
    parser.add_argument("--arch")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--apply", action="store_true")
    action.add_argument("--exec", dest="execute", action="store_true")
    action.add_argument("--resolve-json", action="store_true")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    try:
        if os.geteuid() == 0:
            raise LauncherError("OpenClaw runs as its owner, never as root")
        home = Path(arguments.home)
        if not home.is_absolute():
            raise LauncherError("OpenClaw launcher HOME is not absolute")
        _helper, contract, helper_fd = resolve(
            arguments.arch or canonical_arch(),
            root=home / ROOT_RELATIVE,
            trusted_uid=os.geteuid(),
            trusted_gid=os.getegid(),
        )
        if arguments.resolve_json:
            print(
                json.dumps(
                    {
                        "contract": os.fspath(contract),
                        "helper": os.fspath(_helper),
                        "schema": SCHEMA,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        os.set_inheritable(helper_fd, True)
        delegated = [
            "/usr/bin/python3",
            "-I",
            "-B",
            f"/proc/self/fd/{helper_fd}",
            "--home",
            arguments.home,
            "--contract",
            os.fspath(contract),
        ]
        if arguments.apply:
            delegated.append("--apply")
        elif arguments.execute:
            delegated.extend(["--exec", "--", *(
                arguments.arguments[1:]
                if arguments.arguments[:1] == ["--"]
                else arguments.arguments
            )])
        os.execve("/usr/bin/python3", delegated, {
            "HOME": "/",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        })
    except (LauncherError, OSError) as exc:
        print(f"openclaw launcher: {exc}", file=sys.stderr)
        return 2
    finally:
        if "helper_fd" in locals():
            os.close(helper_fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
