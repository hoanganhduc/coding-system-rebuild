#!/usr/bin/env python3
"""Resolve exactly two protected, generation-bound escrow shares from the inbox."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys


LIB = Path(__file__).resolve().parent / "lib"
sys.path.insert(0, str(LIB))
from recovery_tool import (  # noqa: E402
    RecoveryError,
    _read_share,
    load_escrow_manifest,
    load_recovery_manifest,
)


class ResolutionError(RuntimeError):
    """Automatic share discovery was ambiguous or unsafe."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_private_directory(path: Path, label: str) -> None:
    try:
        information = path.lstat()
    except OSError as exc:
        raise ResolutionError(f"{label} is unavailable: {path}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) & 0o077
    ):
        raise ResolutionError(f"{label} must be an owner-only real directory: {path}")


def discover_share_files(
    inbox: Path, generation_id: str, records: list[dict[str, object]]
) -> list[Path]:
    require_private_directory(inbox, "recovery inbox")
    escrow_root = inbox / "escrow"
    generation_root = escrow_root / generation_id
    require_private_directory(escrow_root, "escrow inbox")
    require_private_directory(generation_root, "escrow generation inbox")
    expected_names = {str(record["file"]) for record in records}
    actual_names = {entry.name for entry in os.scandir(generation_root)}
    unexpected = actual_names - expected_names
    if unexpected:
        raise ResolutionError(
            "escrow generation inbox contains undeclared entries: " + ", ".join(sorted(unexpected))
        )
    selected: list[Path] = []
    for record in sorted(records, key=lambda value: int(value["index"])):
        candidate = generation_root / str(record["file"])
        if not os.path.lexists(candidate):
            continue
        # _read_share enforces owner, regular-file, no-follow, link-count,
        # permission, size, digest, ASCII encoding, and record/index binding.
        _read_share(candidate, records)
        selected.append(candidate.absolute())
    if len(selected) != 2:
        raise ResolutionError(
            f"expected exactly two matching shares in {generation_root}; found {len(selected)}"
        )
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set-dir", type=Path, required=True)
    parser.add_argument("--inbox", type=Path, required=True)
    parser.add_argument("--null", action="store_true", help="terminate output paths with NUL")
    args = parser.parse_args(argv)
    try:
        public = load_recovery_manifest(args.set_dir)
        escrow_path = args.set_dir / "escrow-generation.json"
        escrow = load_escrow_manifest(escrow_path)
        reference = public["escrow_generation"]
        if (
            escrow["generation_id"] != reference["generation_id"]
            or sha256_file(escrow_path) != reference["manifest_sha256"]
        ):
            raise ResolutionError("recovery set and embedded escrow generation do not agree")
        selected = discover_share_files(
            args.inbox.absolute(), escrow["generation_id"], escrow["share_records"]
        )
        separator = b"\0" if args.null else b"\n"
        sys.stdout.buffer.write(separator.join(os.fsencode(path) for path in selected) + separator)
        return 0
    except (OSError, RecoveryError, ResolutionError) as exc:
        print(f"resolve-escrow-shares: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
