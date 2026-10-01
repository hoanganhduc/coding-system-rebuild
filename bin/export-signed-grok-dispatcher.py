#!/usr/bin/env python3
"""Export one already signed Grok dispatcher without exposing a signing key."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import sys

sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))

from lib.grok_bootstrap_release import (
    RELEASE_ID_RE,
    SIGNED_NAMES,
    ReleaseError,
    load_lock,
    sha256_file,
    verify_signed_dispatcher,
)


REPO = Path(__file__).resolve().parents[1]
LOCK_PATH = REPO / "system/grok-proxy/bootstrap/release.lock.json"


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args(argv)


def _canonical_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise ReleaseError(f"{label} must be absolute")
    try:
        information = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"{label} is unavailable") from exc
    if (
        resolved != path
        or stat.S_ISLNK(information.st_mode)
        or not stat.S_ISDIR(information.st_mode)
    ):
        raise ReleaseError(f"{label} is unsafe")
    return resolved


def export_signed_dispatcher(
    source_root: Path,
    output_dir: Path,
    expected_release_id: str,
    *,
    lock_path: Path = LOCK_PATH,
) -> None:
    if RELEASE_ID_RE.fullmatch(expected_release_id) is None:
        raise ReleaseError("expected release id is invalid")
    source = _canonical_directory(source_root, "signed dispatcher source")
    if not output_dir.is_absolute():
        raise ReleaseError("export directory must be absolute")
    try:
        parent = output_dir.parent.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError("export directory parent is unavailable") from exc
    if parent != output_dir.parent or output_dir.exists() or output_dir.is_symlink():
        raise ReleaseError("export directory is unsafe or already exists")

    lock = load_lock(lock_path)
    anchor = lock["trust_anchor"]
    verify_signed_dispatcher(
        source,
        key_id=anchor["key_id"],
        public_key_hex=anchor["public_key_hex"],
        expected_release_id=expected_release_id,
    )
    expected = {name: sha256_file(source / name) for name in SIGNED_NAMES}

    created = False
    try:
        os.mkdir(output_dir, mode=0o700)
        created = True
        os.chmod(output_dir, 0o700, follow_symlinks=False)
        for name in SIGNED_NAMES:
            destination = output_dir / name
            source_descriptor = os.open(
                source / name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            destination_descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o400,
            )
            try:
                with os.fdopen(source_descriptor, "rb", closefd=True) as source_file:
                    source_descriptor = -1
                    with os.fdopen(destination_descriptor, "wb", closefd=True) as destination_file:
                        destination_descriptor = -1
                        shutil.copyfileobj(source_file, destination_file, length=64 * 1024)
                        destination_file.flush()
                        os.fsync(destination_file.fileno())
            finally:
                if source_descriptor >= 0:
                    os.close(source_descriptor)
                if destination_descriptor >= 0:
                    os.close(destination_descriptor)
            os.chmod(destination, 0o444, follow_symlinks=False)
            if sha256_file(destination) != expected[name]:
                raise ReleaseError(f"exported dispatcher artifact changed: {name}")
        directory_descriptor = os.open(
            output_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        verify_signed_dispatcher(
            output_dir,
            key_id=anchor["key_id"],
            public_key_hex=anchor["public_key_hex"],
            expected_release_id=expected_release_id,
        )
    except BaseException:
        if created:
            for name in SIGNED_NAMES:
                try:
                    (output_dir / name).unlink()
                except FileNotFoundError:
                    pass
            try:
                output_dir.rmdir()
            except FileNotFoundError:
                pass
        raise


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
        export_signed_dispatcher(
            arguments.source_root,
            arguments.output_dir,
            arguments.expected_release_id,
        )
        print(
            json.dumps(
                {
                    "export_dir": os.fspath(arguments.output_dir),
                    "private_key_exported": False,
                    "signed_application_id": arguments.expected_release_id,
                    "status": "verified-export",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except ReleaseError as exc:
        print(f"export-signed-grok-dispatcher: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
