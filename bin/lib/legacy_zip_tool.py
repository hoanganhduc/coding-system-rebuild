#!/usr/bin/env python3
"""Bounded 7-Zip adapter for legacy migration without password-on-argv.

7-Zip has no passphrase-fd option. This helper gives it a private pseudo-TTY,
waits until the password prompt is visible, then sends the value read from a
protected regular file. Archive metadata and member content are consumed with
hard byte, count, ratio, and time limits. 7-Zip never writes archive paths to
the filesystem: regular members are streamed into no-follow files created by
this process.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import pty
import re
import select
import stat
import subprocess
import sys
import time


MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_LISTING_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 20_000
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_PATH_BYTES = 4096
MAX_COMPONENT_BYTES = 255
LIST_TIMEOUT_SECONDS = 60
TEST_TIMEOUT_SECONDS = 180
EXTRACT_TIMEOUT_SECONDS = 600
SAFE_ENV = {"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}


class LegacyZipError(RuntimeError):
    pass


@dataclass(frozen=True)
class LegacyMember:
    path: str
    is_directory: bool
    size: int
    packed_size: int


def read_password(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LegacyZipError("cannot open protected legacy password file") from exc
    try:
        info = os.fstat(descriptor)
        linked = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > 4096
        ):
            raise LegacyZipError("unsafe legacy password file")
        value = os.read(descriptor, 4097).rstrip(b"\r\n")
    finally:
        os.close(descriptor)
    if not value or len(value) > 4096 or b"\n" in value or b"\r" in value:
        raise LegacyZipError("invalid legacy password file")
    return value


def seven_zip() -> str:
    for candidate in (Path("/usr/bin/7zz"), Path("/usr/bin/7z")):
        try:
            # The lexical entry and every directory used to reach it are fixed
            # system paths; the final symlink target, if any, is checked too.
            for ancestor in (Path("/"), Path("/usr"), Path("/usr/bin")):
                info = ancestor.stat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022
                ):
                    raise LegacyZipError("7-Zip system path is not trusted")
            lexical = candidate.lstat()
            if lexical.st_uid != 0:
                raise LegacyZipError("7-Zip system entry is not root-owned")
            resolved = candidate.resolve(strict=True)
            parent = resolved.parent
            while True:
                info = parent.stat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022
                ):
                    raise LegacyZipError("7-Zip target path is not trusted")
                if parent == Path("/"):
                    break
                parent = parent.parent
            info = resolved.stat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or not stat.S_IMODE(info.st_mode) & 0o111
                or stat.S_IMODE(info.st_mode) & 0o6022
            ):
                raise LegacyZipError("7-Zip executable is not a trusted system binary")
            return os.fspath(resolved)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise LegacyZipError("cannot inspect fixed 7-Zip executable") from exc
    raise LegacyZipError("fixed /usr/bin/7zz or /usr/bin/7z is required")


def open_archive(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LegacyZipError("cannot open legacy ZIP") from exc
    try:
        info = os.fstat(descriptor)
        linked = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)
            or info.st_size > MAX_ARCHIVE_BYTES
        ):
            raise LegacyZipError("legacy ZIP is not a bounded regular file")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _kill_and_wait(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    process.wait()


def _bounded_capture(
    arguments: list[str],
    *,
    pass_fds: tuple[int, ...],
    max_bytes: int,
    timeout: int,
) -> bytes:
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        pass_fds=pass_fds,
        env=SAFE_ENV,
    )
    assert process.stdout is not None
    output_fd = process.stdout.fileno()
    deadline = time.monotonic() + timeout
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            if time.monotonic() >= deadline:
                _kill_and_wait(process)
                raise LegacyZipError("legacy ZIP listing timed out")
            readable, _, _ = select.select([output_fd], [], [], 0.25)
            if readable:
                chunk = os.read(output_fd, min(65536, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    _kill_and_wait(process)
                    raise LegacyZipError("legacy ZIP listing exceeds the output bound")
            elif process.poll() is not None:
                chunk = os.read(output_fd, min(65536, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise LegacyZipError("legacy ZIP listing exceeds the output bound")
        status = process.wait()
        if status != 0:
            raise LegacyZipError("cannot enumerate legacy ZIP")
        return b"".join(chunks)
    finally:
        process.stdout.close()
        if process.poll() is None:
            _kill_and_wait(process)


def run_with_private_tty(
    arguments: list[str], password: bytes, *, pass_fds: tuple[int, ...] = ()
) -> None:
    master_fd, slave_fd = pty.openpty()
    try:
        process = subprocess.Popen(
            arguments,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            pass_fds=pass_fds,
            env=SAFE_ENV,
        )
    finally:
        os.close(slave_fd)
    deadline = time.monotonic() + TEST_TIMEOUT_SECONDS
    pending = b""
    prompts = 0
    sent = False
    try:
        while True:
            if time.monotonic() >= deadline:
                _kill_and_wait(process)
                raise LegacyZipError("legacy ZIP operation timed out")
            readable, _, _ = select.select([master_fd], [], [], 0.25)
            if readable:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    chunk = b""
                if chunk:
                    pending = (pending + chunk)[-16384:]
                    if b"password" in pending.lower():
                        prompts += 1
                        pending = b""
                        if sent or prompts > 1:
                            _kill_and_wait(process)
                            raise LegacyZipError("legacy ZIP password was rejected")
                        os.write(master_fd, password + b"\n")
                        sent = True
            status = process.poll()
            if status is not None:
                if status != 0:
                    raise LegacyZipError("legacy ZIP operation failed")
                return
    finally:
        os.close(master_fd)
        if process.poll() is None:
            _kill_and_wait(process)


def safe_member_name(value: str) -> str:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise LegacyZipError("unsafe legacy ZIP member path")
    directory_form = value.endswith("/")
    trimmed = value[:-1] if directory_form else value
    try:
        encoded = trimmed.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise LegacyZipError("legacy ZIP member path is not UTF-8") from exc
    pure = PurePosixPath(trimmed)
    if (
        len(encoded) > MAX_PATH_BYTES
        or any(
            len(part.encode("utf-8")) > MAX_COMPONENT_BYTES
            or part in ("", ".", "..")
            for part in pure.parts
        )
    ):
        raise LegacyZipError("unsafe legacy ZIP member path")
    normalized = pure.as_posix()
    if normalized != trimmed:
        raise LegacyZipError("noncanonical legacy ZIP member path")
    return normalized


def _bounded_integer(value: str, *, label: str, maximum: int) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise LegacyZipError(f"invalid legacy ZIP {label}")
    number = int(value)
    if number > maximum:
        raise LegacyZipError(f"legacy ZIP {label} exceeds the bound")
    return number


def _parse_listing(raw: bytes) -> list[LegacyMember]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegacyZipError("legacy ZIP listing is not UTF-8") from exc
    text = text.replace("\r\n", "\n")
    blocks = [block for block in text.split("\n\n") if block.strip()]
    members: list[LegacyMember] = []
    for block in blocks:
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if not line or " = " not in line:
                raise LegacyZipError("ambiguous legacy ZIP listing")
            key, value = line.split(" = ", 1)
            if not key or key in fields:
                raise LegacyZipError("ambiguous legacy ZIP listing")
            fields[key] = value
        if not {"Path", "Folder", "Size", "Packed Size"}.issubset(fields):
            raise LegacyZipError("incomplete legacy ZIP member metadata")
        path = safe_member_name(fields["Path"])
        if fields["Folder"] not in {"+", "-"}:
            raise LegacyZipError("invalid legacy ZIP member type")
        is_directory = fields["Folder"] == "+"
        size = _bounded_integer(
            fields["Size"], label="member size", maximum=MAX_MEMBER_BYTES
        )
        packed = _bounded_integer(
            fields["Packed Size"],
            label="packed member size",
            maximum=MAX_ARCHIVE_BYTES,
        )
        attributes = fields.get("Attributes", "")
        unix_types = [
            token[0]
            for token in attributes.split()
            if len(token) >= 10 and token[0] in "-dlcbps"
        ]
        if any(
            value
            for key, value in fields.items()
            if "link" in key.lower()
        ):
            raise LegacyZipError("links are forbidden in a legacy ZIP")
        if any(kind in "lcbps" for kind in unix_types):
            raise LegacyZipError("special files are forbidden in a legacy ZIP")
        if is_directory:
            if size != 0 or (unix_types and any(kind != "d" for kind in unix_types)):
                raise LegacyZipError("invalid legacy ZIP directory metadata")
        else:
            if unix_types and any(kind != "-" for kind in unix_types):
                raise LegacyZipError("invalid legacy ZIP regular-file metadata")
            if fields.get("Encrypted") != "+":
                raise LegacyZipError("legacy ZIP contains an unencrypted regular file")
            if size and (packed == 0 or size > packed * MAX_COMPRESSION_RATIO):
                raise LegacyZipError("legacy ZIP compression ratio exceeds the bound")
        members.append(LegacyMember(path, is_directory, size, packed))

    if not members:
        raise LegacyZipError("legacy ZIP is empty")
    if len(members) > MAX_MEMBERS:
        raise LegacyZipError("legacy ZIP contains too many members")
    by_path: dict[str, bool] = {}
    total = 0
    total_packed = 0
    for member in members:
        if member.path in by_path:
            raise LegacyZipError("legacy ZIP contains duplicate members")
        by_path[member.path] = member.is_directory
        if not member.is_directory:
            total += member.size
            total_packed += member.packed_size
            if total > MAX_EXPANDED_BYTES:
                raise LegacyZipError("legacy ZIP expanded size exceeds the bound")
        parts = member.path.split("/")
        for index in range(1, len(parts)):
            ancestor = "/".join(parts[:index])
            if ancestor in by_path and not by_path[ancestor]:
                raise LegacyZipError("legacy ZIP has a file/directory path conflict")
    for path, is_directory in by_path.items():
        if is_directory:
            continue
        prefix = path + "/"
        if any(candidate.startswith(prefix) for candidate in by_path):
            raise LegacyZipError("legacy ZIP has a file/directory path conflict")
    if total and total > max(total_packed, 1) * MAX_COMPRESSION_RATIO:
        raise LegacyZipError("legacy ZIP total compression ratio exceeds the bound")
    return members


def list_members(archive_fd: int) -> list[LegacyMember]:
    os.lseek(archive_fd, 0, os.SEEK_SET)
    raw = _bounded_capture(
        [seven_zip(), "l", "-ba", "-slt", f"/proc/self/fd/{archive_fd}"],
        pass_fds=(archive_fd,),
        max_bytes=MAX_LISTING_BYTES,
        timeout=LIST_TIMEOUT_SECONDS,
    )
    return _parse_listing(raw)


def _open_output_root(path: Path) -> int:
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LegacyZipError("legacy extraction directory is unsafe") from exc
    try:
        opened = os.fstat(descriptor)
        linked = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(linked.st_mode)
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & 0o077
        ):
            raise LegacyZipError(
                "legacy extraction directory must be owner-only, new, and empty"
            )
        with os.scandir(path) as entries:
            if next(entries, None) is not None:
                raise LegacyZipError(
                    "legacy extraction directory must be owner-only, new, and empty"
                )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_member_parent(root_fd: int, relative: str) -> tuple[int, str]:
    components = relative.split("/")
    descriptor = os.dup(root_fd)
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for component in components[:-1]:
            try:
                os.mkdir(component, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, components[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _ensure_directory(root_fd: int, relative: str) -> None:
    parent_fd, name = _open_member_parent(root_fd, relative)
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            child_flags = (
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            child_fd = os.open(name, child_flags, dir_fd=parent_fd)
            os.close(child_fd)
    finally:
        os.close(parent_fd)


def _stream_member(
    archive_fd: int,
    member: LegacyMember,
    password: bytes,
    output_fd: int,
    *,
    deadline: float,
) -> None:
    archive_ref = f"/proc/self/fd/{archive_fd}"
    os.lseek(archive_fd, 0, os.SEEK_SET)
    process = subprocess.Popen(
        [seven_zip(), "x", "-bd", "-so", "-spd", archive_ref, member.path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        pass_fds=(archive_fd,),
        env=SAFE_ENV,
    )
    assert process.stdin is not None and process.stdout is not None
    try:
        process.stdin.write(password + b"\n")
        process.stdin.flush()
    except BrokenPipeError as exc:
        process.stdin.close()
        process.stdout.close()
        _kill_and_wait(process)
        raise LegacyZipError("legacy ZIP member extraction failed") from exc
    finally:
        if not process.stdin.closed:
            process.stdin.close()
    content_fd = process.stdout.fileno()
    written = 0
    content_open = True
    try:
        while content_open or process.poll() is None:
            if time.monotonic() >= deadline:
                _kill_and_wait(process)
                raise LegacyZipError("legacy ZIP extraction timed out")
            watched = [content_fd] if content_open else []
            readable, _, _ = select.select(watched, [], [], 0.25) if watched else ([], [], [])
            for descriptor in readable:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    content_open = False
                    continue
                written += len(chunk)
                if written > member.size or written > MAX_MEMBER_BYTES:
                    _kill_and_wait(process)
                    raise LegacyZipError("legacy ZIP member exceeded its declared size")
                view = memoryview(chunk)
                while view:
                    count = os.write(output_fd, view)
                    view = view[count:]
            if process.poll() is not None and not readable:
                if content_open:
                    chunk = os.read(content_fd, 65536)
                    if chunk:
                        written += len(chunk)
                        if written > member.size or written > MAX_MEMBER_BYTES:
                            raise LegacyZipError(
                                "legacy ZIP member exceeded its declared size"
                            )
                        view = memoryview(chunk)
                        while view:
                            count = os.write(output_fd, view)
                            view = view[count:]
                    else:
                        content_open = False
                else:
                    break
        status = process.wait()
        if status != 0:
            raise LegacyZipError("legacy ZIP member extraction failed")
        if written != member.size:
            raise LegacyZipError("legacy ZIP member size changed during extraction")
    finally:
        process.stdout.close()
        if process.poll() is None:
            _kill_and_wait(process)


def extract_members(
    archive_fd: int,
    members: list[LegacyMember],
    password: bytes,
    output: Path,
) -> None:
    root_fd = _open_output_root(output)
    deadline = time.monotonic() + EXTRACT_TIMEOUT_SECONDS
    try:
        for member in members:
            if member.is_directory:
                _ensure_directory(root_fd, member.path)
                continue
            parent_fd, name = _open_member_parent(root_fd, member.path)
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            file_fd = -1
            try:
                file_fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
                _stream_member(
                    archive_fd, member, password, file_fd, deadline=deadline
                )
                os.fchmod(file_fd, 0o600)
                os.fsync(file_fd)
            except BaseException:
                if file_fd >= 0:
                    os.close(file_fd)
                    file_fd = -1
                try:
                    os.unlink(name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                raise
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
                os.close(parent_fd)
    finally:
        os.close(root_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("list")
    listing.add_argument("--archive", type=Path, required=True)
    for command in ("test", "extract"):
        item = sub.add_parser(command)
        item.add_argument("--archive", type=Path, required=True)
        item.add_argument("--password-file", type=Path, required=True)
        if command == "extract":
            item.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        archive_fd = open_archive(arguments.archive)
        try:
            members = list_members(archive_fd)
            if arguments.command == "list":
                for member in members:
                    print(member.path)
                return 0
            password = read_password(arguments.password_file)
            archive_ref = f"/proc/self/fd/{archive_fd}"
            os.lseek(archive_fd, 0, os.SEEK_SET)
            if arguments.command == "test":
                run_with_private_tty(
                    [seven_zip(), "t", archive_ref],
                    password,
                    pass_fds=(archive_fd,),
                )
            else:
                extract_members(archive_fd, members, password, arguments.output_dir)
            return 0
        finally:
            os.close(archive_fd)
    except (LegacyZipError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"legacy ZIP: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
