#!/usr/bin/env python3
"""Install the system services declared in system/host/services.v1.json.

Run as root during a restore. Public unit templates are rendered for the owner
account; private configuration comes from the owner's recovery-set copy under
~/.config/coding-system/system-private/ and is restored with its declared owner
and mode. A service whose unit is not installed, or a private file without a
copy, is reported and skipped rather than invented.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys


REPO = Path(__file__).resolve().parents[1]
PRIVATE_DIRECTORY = Path(".config/coding-system/system-private")


def install_bytes(destination: Path, data: bytes, mode: int, owner: tuple[int, int] | None) -> None:
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    if owner is not None:
        os.chown(temporary, *owner)
    os.chmod(temporary, mode)
    os.replace(temporary, destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", type=Path, default=REPO)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--group", required=True)
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--systemctl", default="/usr/bin/systemctl")
    parser.add_argument("--no-chown", action="store_true", help="keep the caller as owner (tests)")
    arguments = parser.parse_args(argv)
    declaration = json.loads(
        (arguments.repository / "system/host/services.v1.json").read_text(encoding="utf-8")
    )
    root_owner = None if arguments.no_chown else (0, 0)

    for unit, template in sorted(declaration["units"].items()):
        text = (arguments.repository / template).read_text(encoding="utf-8")
        text = (
            text.replace("{{ HOME }}", str(arguments.home))
            .replace("{{ USER }}", arguments.user)
            .replace("{{ GROUP }}", arguments.group)
        )
        if "{{" in text:
            print(f"ERROR: unresolved placeholder in {template}", file=sys.stderr)
            return 2
        install_bytes(arguments.root / "etc/systemd/system" / unit, text.encode("utf-8"), 0o644, root_owner)

    for item in declaration["private_files"]:
        relative = item["path"].lstrip("/")
        source = arguments.home / PRIVATE_DIRECTORY / relative
        if not source.is_file():
            print(f"WARN: no private copy of {item['path']}; that service keeps its package default", file=sys.stderr)
            continue
        owner = None
        if not arguments.no_chown:
            owner = (pwd.getpwnam(item["owner"]).pw_uid, grp.getgrnam(item["group"]).gr_gid)
        install_bytes(arguments.root / relative, source.read_bytes(), int(item["mode"], 8), owner)

    subprocess.run([arguments.systemctl, "daemon-reload"], check=True)
    for unit in declaration["enable"]:
        known = subprocess.run(
            [arguments.systemctl, "cat", unit], capture_output=True, check=False
        ).returncode == 0
        if not known:
            print(f"WARN: {unit} is not installed; it stays disabled", file=sys.stderr)
            continue
        started = subprocess.run([arguments.systemctl, "enable", "--now", unit], check=False)
        if started.returncode != 0:
            print(f"WARN: {unit} is enabled but did not start; see journalctl -u {unit}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
