#!/usr/bin/env python3
"""Copy the host's private system configuration into the owner's recovery-set folder.

system/host/services.v1.json names each private file. A readable file is copied
directly; a root-only file is read with `sudo -n`, so a backup without
passwordless sudo reports it instead of prompting. Copies are owner-private
(0600) under ~/.config/coding-system/system-private/, which the encrypted
recovery set carries.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


REPO = Path(__file__).resolve().parents[1]
PRIVATE_DIRECTORY = Path(".config/coding-system/system-private")


def read_private(source: Path, sudo: str) -> bytes | None:
    try:
        return source.read_bytes()
    except PermissionError:
        pass
    except FileNotFoundError:
        return None
    completed = subprocess.run(
        [sudo, "-n", "/bin/cat", "--", str(source)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    return completed.stdout if completed.returncode == 0 else None


def write_private(destination: Path, data: bytes) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.is_file() and destination.read_bytes() == data:
        return
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    os.replace(temporary, destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", type=Path, default=REPO)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--sudo", default="/usr/bin/sudo")
    parser.add_argument("--strict", action="store_true", help="exit 1 when a private file is not exported")
    arguments = parser.parse_args(argv)
    declaration = json.loads(
        (arguments.repository / "system/host/services.v1.json").read_text(encoding="utf-8")
    )
    missing = []
    for item in declaration["private_files"]:
        relative = item["path"].lstrip("/")
        data = read_private(arguments.root / relative, arguments.sudo)
        if data is None:
            missing.append(item["path"])
            continue
        write_private(arguments.home / PRIVATE_DIRECTORY / relative, data)
    for path in missing:
        print(
            f"WARN: {path} was not exported; run `sudo -v` first or export it by hand",
            file=sys.stderr,
        )
    return 1 if missing and arguments.strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
