#!/usr/bin/env python3
"""Verify a checkout directly against one commit tree without trusting its index."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


class CheckoutError(RuntimeError):
    """A fail-closed checkout identity error."""


LOCAL_FILESYSTEM_TYPES = frozenset(
    {
        "bcachefs",
        "btrfs",
        "ext2",
        "ext2/ext3",
        "ext3",
        "ext4",
        "f2fs",
        "jfs",
        "nilfs2",
        "overlay",
        "overlayfs",
        "reiserfs",
        "tmpfs",
        "xfs",
        "zfs",
    }
)


def run_git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_CONFIG_HOME": "/dev/null",
    }
    try:
        completed = subprocess.run(
            [
                "/usr/bin/git",
                "--no-optional-locks",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.commitGraph=false",
                "-c",
                "core.multiPackIndex=false",
                "-c",
                "core.alternateRefsCommand=",
                "-c",
                "fsck.skipList=/dev/null",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.file.allow=never",
                "-c",
                "credential.helper=",
                "-c",
                "core.sshCommand=/bin/false",
                "-C",
                os.fspath(repository),
                *arguments,
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckoutError("Git checkout inspection could not run") from exc
    return completed


def safe_git(repository: Path, *arguments: str) -> bytes:
    completed = run_git(repository, *arguments)
    if completed.returncode != 0:
        raise CheckoutError("Git checkout inspection failed")
    return completed.stdout


def require_private_owner(info: os.stat_result, *, label: str) -> None:
    owner = os.geteuid()
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != owner or mode & 0o022 or mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise CheckoutError(f"{label} is writable by another principal")


def _decode_mount_field(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def storage_snapshot(root: Path) -> tuple[str, str, str]:
    """Admit one local backing mount and reject mounts at/below the checkout."""

    try:
        lines = Path("/proc/self/mountinfo").read_text(
            encoding="utf-8", errors="surrogateescape"
        ).splitlines()
    except OSError as exc:
        raise CheckoutError("mount table is unavailable") from exc
    ancestors: list[tuple[Path, str, str]] = []
    nested: list[Path] = []
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
            device = fields[2]
            mountpoint = Path(_decode_mount_field(fields[4]))
            filesystem_type = fields[separator + 1].lower()
        except (IndexError, ValueError) as exc:
            raise CheckoutError("mount table contains an invalid record") from exc
        if mountpoint == root or mountpoint.is_relative_to(root):
            nested.append(mountpoint)
        if root == mountpoint or root.is_relative_to(mountpoint):
            ancestors.append((mountpoint, filesystem_type, device))
    if nested:
        raise CheckoutError("checkout contains a nested or direct mount")
    if not ancestors:
        raise CheckoutError("checkout backing mount could not be identified")
    mountpoint, filesystem_type, device = max(
        ancestors, key=lambda item: len(item[0].parts)
    )
    if filesystem_type not in LOCAL_FILESYSTEM_TYPES:
        raise CheckoutError("checkout backing filesystem is not an admitted local type")
    return os.fspath(mountpoint), filesystem_type, device


def require_safe_ancestors(path: Path) -> None:
    owner = os.geteuid()
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if ancestor.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise CheckoutError("checkout has an unsafe path ancestor")
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid not in {0, owner}:
            raise CheckoutError("checkout ancestor is owned by another principal")
        if mode & stat.S_ISVTX:
            continue
        if mode & 0o022:
            raise CheckoutError("checkout ancestor is group/world-writable without sticky protection")


def stable_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def object_digest(algorithm: str, payload: bytes) -> str:
    digest = hashlib.new(algorithm)
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def regular_digest(
    path: Path, algorithm: str, expected_size: int, expected_device: int
) -> tuple[str, os.stat_result]:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_dev != expected_device
        ):
            raise CheckoutError("checkout contains a linked or non-regular file")
        if before.st_size != expected_size:
            raise CheckoutError("checkout file size differs from the commit")
        require_private_owner(before, label="checkout file")
        digest = hashlib.new(algorithm)
        digest.update(f"blob {before.st_size}\0".encode("ascii"))
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if total != before.st_size or stable_identity(before) != stable_identity(after):
        raise CheckoutError("checkout file changed while hashing")
    return digest.hexdigest(), before


def committed_inventory(
    repository: Path, commit: str
) -> tuple[str, dict[str, tuple[str, str, int]]]:
    algorithm = safe_git(repository, "rev-parse", "--show-object-format").decode(
        "ascii"
    ).strip()
    if algorithm not in {"sha1", "sha256"}:
        raise CheckoutError("unsupported Git object format")
    raw = safe_git(repository, "ls-tree", "-lrz", "--full-tree", commit)
    inventory: dict[str, tuple[str, str, int]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, encoded_path = record.split(b"\t", 1)
            mode, kind, object_id, encoded_size = header.decode("ascii").split()
            relative = os.fsdecode(encoded_path)
        except (UnicodeDecodeError, ValueError) as exc:
            raise CheckoutError("invalid committed tree record") from exc
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise CheckoutError("submodules or unsupported Git tree entries are forbidden")
        if not encoded_size.isdigit():
            raise CheckoutError("committed blob has an invalid size")
        size = int(encoded_size)
        parts = Path(relative).parts
        if not parts or relative.startswith("/") or any(part in {"", ".", ".."} for part in parts):
            raise CheckoutError("unsafe committed tree path")
        if relative in inventory:
            raise CheckoutError("duplicate committed tree path")
        inventory[relative] = (mode, object_id, size)
    if not inventory:
        raise CheckoutError("committed tree is empty")
    return algorithm, inventory


def verify_metadata_tree(path: Path, expected_device: int) -> None:
    for current, directories, files in os.walk(path, topdown=True, followlinks=False):
        current_path = Path(current)
        info = current_path.lstat()
        if (
            current_path.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_dev != expected_device
        ):
            raise CheckoutError("Git metadata contains an unsafe directory")
        require_private_owner(info, label="Git metadata directory")
        for name in directories + files:
            candidate = current_path / name
            member = candidate.lstat()
            if member.st_dev != expected_device:
                raise CheckoutError("Git metadata crosses a filesystem boundary")
            if stat.S_ISLNK(member.st_mode) or not (
                stat.S_ISDIR(member.st_mode) or stat.S_ISREG(member.st_mode)
            ):
                raise CheckoutError("Git metadata contains an unsafe entry")
            require_private_owner(member, label="Git metadata entry")
            if stat.S_ISREG(member.st_mode) and member.st_nlink != 1:
                raise CheckoutError("Git metadata contains a linked file")


def reject_external_object_storage(repository: Path, git_directory: Path) -> None:
    forbidden = (
        git_directory / "commondir",
        git_directory / "config.worktree",
        git_directory / "objects/info/alternates",
        git_directory / "objects/info/http-alternates",
    )
    if any(os.path.lexists(path) for path in forbidden):
        raise CheckoutError("external Git object storage is forbidden")
    if any(path.name.endswith(".promisor") for path in git_directory.rglob("*")):
        raise CheckoutError("partial-clone Git object storage is forbidden")
    config = run_git(
        repository,
        "config",
        "--local",
        "--no-includes",
        "--null",
        "--name-only",
        "--list",
    )
    if config.returncode != 0:
        raise CheckoutError("local Git configuration could not be inspected")
    keys = {
        value.decode("utf-8", "surrogateescape").casefold()
        for value in config.stdout.split(b"\0")
        if value
    }
    if any(
        key.startswith(("include.", "includeif."))
        or key.startswith("fsck.")
        or key in {"extensions.partialclone", "extensions.worktreeconfig"}
        or (key.startswith("remote.") and key.endswith(".promisor"))
        for key in keys
    ):
        raise CheckoutError(
            "Git includes, fsck overrides, and partial-clone configuration are forbidden"
        )


def verify_untracked_migration_root(path: Path, expected_device: int) -> None:
    """Validate, but never interpret, the one legacy external/ migration root."""
    for current, directories, files in os.walk(path, topdown=True, followlinks=False):
        current_path = Path(current)
        current_info = current_path.lstat()
        if (
            current_path.is_symlink()
            or not stat.S_ISDIR(current_info.st_mode)
            or current_info.st_dev != expected_device
        ):
            raise CheckoutError("legacy external migration root is unsafe")
        require_private_owner(current_info, label="legacy external directory")
        for name in directories + files:
            member = (current_path / name).lstat()
            if member.st_dev != expected_device or stat.S_ISLNK(member.st_mode):
                raise CheckoutError("legacy external migration root is unsafe")
            if not (stat.S_ISDIR(member.st_mode) or stat.S_ISREG(member.st_mode)):
                raise CheckoutError("legacy external migration root contains a special file")
            require_private_owner(member, label="legacy external entry")
            if stat.S_ISREG(member.st_mode) and member.st_nlink != 1:
                raise CheckoutError("legacy external migration root contains a linked file")


def verify_checkout(
    repository: Path,
    commit: str,
    *,
    allowed_untracked_roots: frozenset[str] = frozenset(),
) -> None:
    absolute = Path(os.path.abspath(repository))
    if absolute != Path(os.path.realpath(repository)) or not absolute.is_dir():
        raise CheckoutError("checkout path is non-canonical or unsafe")
    require_safe_ancestors(absolute)
    storage_before = storage_snapshot(absolute)
    checkout_device = absolute.lstat().st_dev
    filesystem = subprocess.run(
        ["/usr/bin/stat", "-f", "-c", "%T", os.fspath(absolute)],
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
        check=False,
    )
    if filesystem.returncode != 0:
        raise CheckoutError("checkout filesystem could not be identified")
    fs_type = filesystem.stdout.strip().lower()
    if fs_type not in LOCAL_FILESYSTEM_TYPES:
        raise CheckoutError("authenticated restore requires an admitted local filesystem")

    git_path = safe_git(absolute, "rev-parse", "--absolute-git-dir")
    git_directory = Path(os.fsdecode(git_path).strip())
    if git_directory != absolute / ".git":
        raise CheckoutError("authenticated restore requires a self-contained Git checkout")
    verify_metadata_tree(git_directory, checkout_device)
    reject_external_object_storage(absolute, git_directory)
    safe_git(
        absolute,
        "fsck",
        "--strict",
        "--no-reflogs",
        "--no-cache",
        "--full",
        commit,
    )
    algorithm, expected = committed_inventory(absolute, commit)
    if any(
        relative == root or relative.startswith(root + "/")
        for root in allowed_untracked_roots
        for relative in expected
    ):
        raise CheckoutError("migration exception overlaps the committed tree")
    expected_directories = {
        parent.as_posix()
        for relative in expected
        for parent in Path(relative).parents
        if parent.as_posix() != "."
    }
    observed: set[str] = set()

    def walk(directory: Path, prefix: str = "") -> None:
        directory_info = directory.lstat()
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_dev != checkout_device
        ):
            raise CheckoutError("checkout contains an unsafe directory")
        require_private_owner(directory_info, label="checkout directory")
        with os.scandir(directory) as entries:
            for entry in entries:
                if not prefix and entry.name == ".git":
                    continue
                relative = f"{prefix}/{entry.name}" if prefix else entry.name
                path = directory / entry.name
                info = entry.stat(follow_symlinks=False)
                if info.st_dev != checkout_device:
                    raise CheckoutError("checkout crosses a filesystem boundary")
                if stat.S_ISDIR(info.st_mode):
                    if not prefix and relative in allowed_untracked_roots:
                        verify_untracked_migration_root(path, checkout_device)
                        continue
                    if relative not in expected_directories:
                        raise CheckoutError("checkout contains an uncommitted directory")
                    walk(path, relative)
                    continue
                observed.add(relative)
                record = expected.get(relative)
                if record is None:
                    raise CheckoutError("checkout contains an uncommitted path")
                expected_mode, expected_digest, expected_size = record
                if stat.S_ISLNK(info.st_mode):
                    if expected_mode != "120000":
                        raise CheckoutError("checkout file type differs from the commit")
                    target = os.fsencode(os.readlink(path))
                    if len(target) != expected_size:
                        raise CheckoutError("checkout symlink size differs from the commit")
                    actual_digest = object_digest(algorithm, target)
                    after = path.lstat()
                    if stable_identity(info) != stable_identity(after):
                        raise CheckoutError("checkout symlink changed while hashing")
                elif stat.S_ISREG(info.st_mode):
                    if expected_mode == "120000":
                        raise CheckoutError("checkout file type differs from the commit")
                    actual_digest, opened = regular_digest(
                        path, algorithm, expected_size, checkout_device
                    )
                    actual_mode = "100755" if stat.S_IMODE(opened.st_mode) & 0o111 else "100644"
                    if actual_mode != expected_mode:
                        raise CheckoutError("checkout executable mode differs from the commit")
                else:
                    raise CheckoutError("checkout contains a special file")
                if actual_digest != expected_digest:
                    raise CheckoutError("checkout content differs from the commit")

    walk(absolute)
    if observed != set(expected):
        raise CheckoutError("checkout is missing a committed path")
    if storage_snapshot(absolute) != storage_before:
        raise CheckoutError("checkout mount identity changed during verification")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument(
        "--allow-untracked-root",
        action="append",
        default=[],
        choices=("external",),
        help="one-time Stage-0 migration exception; only external is admitted",
    )
    arguments = parser.parse_args()
    try:
        verify_checkout(
            arguments.repository,
            arguments.commit,
            allowed_untracked_roots=frozenset(arguments.allow_untracked_root),
        )
    except (CheckoutError, OSError, subprocess.SubprocessError) as exc:
        print(f"verify-exact-checkout: {exc}", file=sys.stderr)
        return 2
    print("exact checkout: commit tree, ownership, and storage verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
