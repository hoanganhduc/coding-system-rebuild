#!/usr/bin/env python3
"""Interactively write the raw Tailscale auth-key and nonsecret hostname files."""

from __future__ import annotations

import getpass
import os
from pathlib import Path
import secrets
import stat
import sys


LIB = Path(__file__).resolve().parent / "lib"
if os.fspath(LIB) not in sys.path:
    sys.path.insert(0, os.fspath(LIB))
from tailscale_authority import (  # noqa: E402
    AUTHKEY_RELATIVE,
    HOSTNAME_RELATIVE,
    TailscaleAuthorityError,
    parse_authkey,
    parse_hostname,
)


def _preflight(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise TailscaleAuthorityError("existing Tailscale authority is unsafe")


def _stage(path: Path, payload: bytes) -> Path:
    temporary = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return temporary


def main() -> int:
    home = Path.home().absolute()
    directory = home / ".config/coding-system"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    info = directory.lstat()
    if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        print("Tailscale authority setup: unsafe destination", file=sys.stderr)
        return 2
    try:
        authkey = parse_authkey((getpass.getpass("Paste the auth key (tskey-...): ") + "\n").encode("ascii"))
        hostname_text = input("Node hostname for restored machines [openclaw]: ").strip() or "openclaw"
        hostname = parse_hostname((hostname_text + "\n").encode("ascii"))
        authkey_path = home / AUTHKEY_RELATIVE
        hostname_path = home / HOSTNAME_RELATIVE
        _preflight(authkey_path)
        _preflight(hostname_path)
        staged_authkey = _stage(authkey_path, (authkey + "\n").encode("ascii"))
        try:
            staged_hostname = _stage(hostname_path, (hostname + "\n").encode("ascii"))
        except Exception:
            staged_authkey.unlink(missing_ok=True)
            raise
        os.replace(staged_authkey, authkey_path)
        os.replace(staged_hostname, hostname_path)
    except (EOFError, OSError, UnicodeError, TailscaleAuthorityError):
        print("Tailscale authority setup: invalid or unsafe input", file=sys.stderr)
        return 2
    print("Tailscale authority setup: raw key and hostname stored separately")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
