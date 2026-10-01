#!/usr/bin/env python3
"""Report redacted local Tailscale recovery readiness without network access."""

from __future__ import annotations

import argparse
import json
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
    LEGACY_RELATIVE,
    TailscaleAuthorityError,
    local_backend_state,
    read_authkey,
    read_hostname,
)


def readiness(
    home: Path, *, tailscale: str = "tailscale", auth_attempt_failed: bool = False
) -> dict[str, object]:
    try:
        (home / LEGACY_RELATIVE).lstat()
    except FileNotFoundError:
        pass
    except OSError:
        return _report("TECHNICAL_FAIL", "legacy-authority-unsafe")
    else:
        return _report("TECHNICAL_FAIL", "legacy-authority-present")
    try:
        authkey = read_authkey(home)
        hostname = read_hostname(home)
    except TailscaleAuthorityError:
        return _report("TECHNICAL_FAIL", "authority-invalid")
    capabilities = [
        name
        for name, present in (("auth-key", authkey is not None), ("hostname", hostname is not None))
        if present
    ]
    if authkey is not None and hostname is None:
        return _report(
            "TECHNICAL_FAIL", "authority-incomplete", configured=True, capabilities=capabilities
        )
    state = local_backend_state(tailscale)
    if state == "Running":
        return _report(
            "PASS",
            "daemon-authenticated",
            configured=authkey is not None,
            capabilities=capabilities,
            daemon_authenticated=True,
        )
    if authkey is None:
        return _report("NOT_CONFIGURED", "authority-absent")
    if state in {"NeedsLogin", "NoState", "Stopped"}:
        return _report(
            "REAUTH_REQUIRED",
            "AUTH_INVALID" if auth_attempt_failed else "daemon-reauth-required",
            configured=True,
            capabilities=capabilities,
        )
    return _report(
        "TECHNICAL_FAIL",
        "local-status-unavailable",
        configured=True,
        capabilities=capabilities,
    )


def _report(
    status: str,
    reason: str,
    *,
    configured: bool = False,
    capabilities: list[str] | None = None,
    daemon_authenticated: bool = False,
) -> dict[str, object]:
    return {
        "capabilities": capabilities or [],
        "configured": configured,
        "daemonAuthenticated": daemon_authenticated,
        "reason": reason,
        "schema": "coding-system.tailscale-readiness/v1",
        "schemaVersion": 1,
        "status": status,
    }


def _write_private(path: Path, document: dict[str, object]) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.parent.lstat()
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise OSError("unsafe report parent")
    temporary = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        payload = (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short report write")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, path)
    parent = os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--tailscale-command", default="tailscale")
    parser.add_argument("--auth-attempt-failed", action="store_true")
    parser.add_argument("--emit-hostname", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    home = args.home.expanduser().absolute()
    if args.emit_hostname:
        try:
            authkey = read_authkey(home)
            hostname = read_hostname(home)
        except TailscaleAuthorityError:
            return 2
        if authkey is None or hostname is None:
            return 1
        print(hostname)
        return 0
    report = readiness(
        home,
        tailscale=args.tailscale_command,
        auth_attempt_failed=args.auth_attempt_failed,
    )
    if args.output is not None:
        try:
            _write_private(args.output, report)
        except OSError:
            print("tailscale readiness: TECHNICAL_FAIL", file=sys.stderr)
            return 2
    else:
        json.dump(report, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    print(f"tailscale readiness: {report['status']}", file=sys.stderr)
    return 2 if report["status"] == "TECHNICAL_FAIL" else (0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    raise SystemExit(main())
