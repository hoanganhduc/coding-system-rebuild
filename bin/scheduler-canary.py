#!/usr/bin/env python3
"""Record and verify provider-free scheduler execution evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import uuid
from typing import Any


SCHEMA = "coding-system.scheduler-canary/v1"


class CanaryError(ValueError):
    """Unsafe path or invalid canary evidence."""


def evidence_path(state_dir: Path, scheduler: str) -> Path:
    if not state_dir.is_absolute():
        raise CanaryError("state directory must be absolute")
    if scheduler not in {"cron", "systemd", "openclaw"}:
        raise CanaryError("scheduler must be cron, systemd, or openclaw")
    return state_dir / f"{scheduler}.json"


def build_evidence(scheduler: str, now: float, run_id: str | None = None) -> dict[str, Any]:
    identifier = run_id or str(uuid.uuid4())
    if not identifier or "\n" in identifier or len(identifier) > 128:
        raise CanaryError("run id must be a non-empty single line <= 128 characters")
    return {
        "schema": SCHEMA,
        "scheduler": scheduler,
        "observedAt": datetime.fromtimestamp(now, timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "observedAtUnix": int(now),
        "runId": identifier,
    }


def write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    if path.parent.is_symlink():
        raise CanaryError(f"refusing symlink state directory: {path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise CanaryError(f"unsafe state directory: {path.parent}")
    os.chmod(path.parent, 0o700)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise CanaryError(f"refusing non-regular evidence destination: {path}")
    payload = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_evidence(path: Path, scheduler: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CanaryError(f"missing regular canary evidence: {path}")
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CanaryError(f"cannot read canary evidence {path}: {error}") from error
    if not isinstance(evidence, dict):
        raise CanaryError("canary evidence root must be an object")
    if set(evidence) != {"schema", "scheduler", "observedAt", "observedAtUnix", "runId"}:
        raise CanaryError("canary evidence fields do not match v1")
    if evidence.get("schema") != SCHEMA or evidence.get("scheduler") != scheduler:
        raise CanaryError("canary evidence identity mismatch")
    timestamp = evidence.get("observedAtUnix")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise CanaryError("canary evidence timestamp is invalid")
    if not isinstance(evidence.get("observedAt"), str) or not isinstance(evidence.get("runId"), str):
        raise CanaryError("canary evidence text fields are invalid")
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="Record one scheduler execution")
    record.add_argument(
        "--scheduler", required=True, choices=("cron", "systemd", "openclaw")
    )
    record.add_argument("--state-dir", type=Path, required=True)
    record.add_argument("--dry-run", action="store_true")
    record.add_argument("--test-now", type=float, help=argparse.SUPPRESS)
    record.add_argument("--test-run-id", help=argparse.SUPPRESS)

    verify = subparsers.add_parser("verify", help="Verify scheduler evidence")
    verify.add_argument(
        "--scheduler", required=True, choices=("cron", "systemd", "openclaw")
    )
    verify.add_argument("--state-dir", type=Path, required=True)
    verify.add_argument("--max-age-seconds", type=int, default=900)
    verify.add_argument(
        "--not-before-unix",
        type=int,
        help="Require evidence emitted at or after this Unix timestamp",
    )
    verify.add_argument("--test-now", type=float, help=argparse.SUPPRESS)

    args = parser.parse_args(argv)
    try:
        path = evidence_path(args.state_dir.expanduser(), args.scheduler)
        now = args.test_now if args.test_now is not None else time.time()
        if args.command == "record":
            evidence = build_evidence(args.scheduler, now, args.test_run_id)
            if args.dry_run:
                print(f"scheduler canary: would record {args.scheduler}: {path}")
                return 0
            write_evidence(path, evidence)
            print(f"scheduler canary: recorded {args.scheduler}: {path}")
            return 0

        if args.max_age_seconds <= 0:
            raise CanaryError("max age must be positive")
        if args.not_before_unix is not None and args.not_before_unix < 0:
            raise CanaryError("not-before Unix timestamp must be non-negative")
        evidence = read_evidence(path, args.scheduler)
        age = int(now) - evidence["observedAtUnix"]
        if age < -300:
            raise CanaryError("canary evidence timestamp is in the future")
        if args.not_before_unix is not None and age < 0:
            raise CanaryError(
                "run-bound canary evidence timestamp is in the future"
            )
        if (
            args.not_before_unix is not None
            and evidence["observedAtUnix"] < args.not_before_unix
        ):
            print(
                f"scheduler canary: pre-boundary {args.scheduler}: "
                f"observed={evidence['observedAtUnix']} "
                f"required={args.not_before_unix}",
                file=sys.stderr,
            )
            return 1
        if age > args.max_age_seconds:
            print(
                f"scheduler canary: stale {args.scheduler}: age={age}s "
                f"max={args.max_age_seconds}s",
                file=sys.stderr,
            )
            return 1
        print(f"scheduler canary: PASS {args.scheduler}: age={max(age, 0)}s")
        return 0
    except CanaryError as error:
        print(f"scheduler canary: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
