#!/usr/bin/env python3
"""Create OpenClaw's VNU-only secret view without exposing secret values."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path

VNU_KEYS = ("VNU_EOFFICE_USERNAME", "VNU_EOFFICE_PASSWORD")


def bridge(home: Path) -> str:
    source = home / ".claude" / "secrets.json"
    target = home / ".openclaw" / "workspace" / "secrets" / "vnu-eoffice" / "secrets.json"

    if not source.exists():
        return "VNU eOffice secret bridge: source absent; skipped"
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("VNU eOffice secret bridge: unsafe source file")

    source_data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(source_data, dict):
        raise RuntimeError("VNU eOffice secret bridge: source must be a JSON object")
    missing = [
        key for key in VNU_KEYS
        if not isinstance(source_data.get(key), str) or not source_data[key].strip()
    ]
    if missing:
        return "VNU eOffice secret bridge: credentials absent; skipped"

    workspace = home / ".openclaw" / "workspace"
    if workspace.is_symlink():
        raise RuntimeError("VNU eOffice secret bridge: refusing symlink workspace")
    for directory in (workspace / "secrets", target.parent):
        if directory.is_symlink():
            raise RuntimeError("VNU eOffice secret bridge: refusing symlink secret directory")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    if target.is_symlink():
        raise RuntimeError("VNU eOffice secret bridge: refusing symlink target")
    if target.exists() and not target.is_file():
        raise RuntimeError("VNU eOffice secret bridge: target is not a regular file")

    payload = {key: source_data[key] for key in VNU_KEYS}

    descriptor, temporary_name = tempfile.mkstemp(prefix=".secrets.", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        target.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)

    mode = stat.S_IMODE(target.stat().st_mode)
    return f"VNU eOffice secret bridge: ready; mode={mode:04o}; VNU keys={len(VNU_KEYS)}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--home",
        type=Path,
        default=Path(os.environ.get("CSR_SECRETS_HOME", str(Path.home()))),
    )
    args = parser.parse_args()
    print(bridge(args.home.expanduser().resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
