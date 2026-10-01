#!/usr/bin/env python3
"""Atomically record the exact gate outcomes emitted by bin/verify.sh."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time

sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))

from lib.restore_evidence import (  # noqa: E402
    EVIDENCE_SCHEMA,
    GATE_CONTRACT,
    MAX_EVIDENCE_BYTES,
    SIDECAR_SCHEMAS,
    EvidenceContractError,
    closed_repository_commit,
    utc_timestamp,
    validate_commit,
    validate_gate_data,
    validate_run_id,
    validate_sidecar_bindings,
)


def _snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def read_private_sidecar(path: Path) -> tuple[dict, os.stat_result, bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceContractError(f"cannot open verification sidecar: {path.name}") from exc
    try:
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > MAX_EVIDENCE_BYTES
            ):
                raise EvidenceContractError(
                    f"verification sidecar ownership, mode, link count, or size is unsafe: {path.name}"
                )
            remaining = before.st_size
            chunks: list[bytes] = []
            while remaining:
                block = os.read(descriptor, min(remaining, 65536))
                if not block:
                    raise EvidenceContractError(f"verification sidecar is truncated: {path.name}")
                chunks.append(block)
                remaining -= len(block)
            if os.read(descriptor, 1):
                raise EvidenceContractError(f"verification sidecar grew while reading: {path.name}")
            after = os.fstat(descriptor)
            if _snapshot(before) != _snapshot(after):
                raise EvidenceContractError(f"verification sidecar changed while reading: {path.name}")
        except OSError as exc:
            raise EvidenceContractError(f"cannot read verification sidecar: {path.name}") from exc
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceContractError(f"verification sidecar is not valid JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise EvidenceContractError(f"verification sidecar root is invalid: {path.name}")
    return value, before, raw


def matching_gate(gates: list[dict[str, str]], name: str) -> dict[str, str]:
    prefixes = {
        "classroom50": ("Classroom50 ",),
        "target": ("agent target ", "target-state manifest unavailable in CI"),
    }[name]
    matches = [item for item in gates if item["label"].startswith(prefixes)]
    if len(matches) != 1:
        raise EvidenceContractError(f"cannot bind {name} sidecar to one verification gate")
    return matches[0]


def capture_sidecar(
    name: str,
    path: Path,
    *,
    gates: list[dict[str, str]],
    repository_commit: str,
    restore_run_id: str,
    run_started_at_unix: int,
    observed_at_unix: int,
) -> dict[str, object]:
    gate = matching_gate(gates, name)
    identity: dict[str, object] = {
        "repositoryCommit": repository_commit,
        "restoreRunId": restore_run_id,
        "capturedAtUnix": observed_at_unix,
    }
    if name == "target" and gate["label"] == "target-state manifest unavailable in CI":
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise EvidenceContractError("target sidecar exists despite an unavailable target gate")
        return {
            "present": False,
            **identity,
            "status": "NOT_CONFIGURED",
            "technicalStatus": "PASS",
            "gateLabel": gate["label"],
        }

    value, information, raw = read_private_sidecar(path)
    if information.st_mtime_ns < run_started_at_unix * 1_000_000_000:
        raise EvidenceContractError(f"{name} sidecar predates this verification run")
    if information.st_mtime_ns > (observed_at_unix + 5) * 1_000_000_000:
        raise EvidenceContractError(f"{name} sidecar timestamp is in the future")
    expected_schema = SIDECAR_SCHEMAS[name]
    if value.get("schema") != expected_schema:
        raise EvidenceContractError(f"{name} sidecar schema is invalid")
    status = value.get("status")
    technical_status = value.get("technicalStatus")
    if not isinstance(status, str) or technical_status != "PASS":
        raise EvidenceContractError(f"{name} sidecar does not report technical success")
    return {
        "present": True,
        "schema": expected_schema,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sizeBytes": information.st_size,
        "ownerUid": information.st_uid,
        "mode": f"{stat.S_IMODE(information.st_mode):04o}",
        "mtimeNs": information.st_mtime_ns,
        **identity,
        "status": status,
        "technicalStatus": technical_status,
        "gateLabel": gate["label"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("full", "ci"), required=True)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--restore-run-id", required=True)
    parser.add_argument("--run-started-at-unix", type=int, required=True)
    parser.add_argument("--target-report", type=Path, required=True)
    parser.add_argument("--classroom50-report", type=Path, required=True)
    parser.add_argument("--expected-commit")
    parser.add_argument("--pass-label", action="append", default=[])
    parser.add_argument("--fail-label", action="append", default=[])
    parser.add_argument("--skip-label", action="append", default=[])
    args = parser.parse_args()

    try:
        commit = closed_repository_commit(args.repository)
        expected_commit = (
            validate_commit(args.expected_commit)
            if args.expected_commit is not None
            else None
        )
        if args.profile == "full" and expected_commit is None:
            raise EvidenceContractError("full verification requires the authenticated commit")
        if expected_commit is not None and commit != expected_commit:
            raise EvidenceContractError(
                "repository HEAD differs from the authenticated expected commit"
            )
    except EvidenceContractError as exc:
        raise SystemExit(f"verification evidence repository commit is invalid: {exc}") from exc
    gates = [
        {"label": label, "status": status}
        for status, labels in (
            ("PASS", args.pass_label),
            ("FAIL", args.fail_label),
            ("NOT_CONFIGURED", args.skip_label),
        )
        for label in labels
    ]
    counts = {
        "pass": len(args.pass_label),
        "fail": len(args.fail_label),
        "notConfigured": len(args.skip_label),
    }
    status = "PASS" if not args.fail_label else "TECHNICAL_FAIL"
    try:
        gate_inventory = validate_gate_data(gates, counts, status, args.profile)
        restore_run_id = validate_run_id(args.restore_run_id)
    except EvidenceContractError as exc:
        raise SystemExit(f"verification evidence contract failed: {exc}") from exc
    observed_at_unix = int(time.time())
    if args.run_started_at_unix < 0 or args.run_started_at_unix > observed_at_unix:
        raise SystemExit("verification evidence run boundary is invalid")
    sidecars: dict[str, object] = {}
    if status == "PASS":
        try:
            sidecars = {
                "classroom50": capture_sidecar(
                    "classroom50",
                    args.classroom50_report,
                    gates=gates,
                    repository_commit=commit,
                    restore_run_id=restore_run_id,
                    run_started_at_unix=args.run_started_at_unix,
                    observed_at_unix=observed_at_unix,
                ),
                "target": capture_sidecar(
                    "target",
                    args.target_report,
                    gates=gates,
                    repository_commit=commit,
                    restore_run_id=restore_run_id,
                    run_started_at_unix=args.run_started_at_unix,
                    observed_at_unix=observed_at_unix,
                ),
            }
            validate_sidecar_bindings(
                sidecars,
                gates=gates,
                profile=args.profile,
                repository_commit=commit,
                restore_run_id=restore_run_id,
                run_started_at_unix=args.run_started_at_unix,
                observed_at_unix=observed_at_unix,
            )
        except EvidenceContractError as exc:
            raise SystemExit(f"verification sidecar contract failed: {exc}") from exc
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "gateContract": GATE_CONTRACT,
        "observedAt": utc_timestamp(observed_at_unix),
        "observedAtUnix": observed_at_unix,
        "repositoryCommit": commit,
        "profile": args.profile,
        "architecture": args.architecture,
        "restoreRunId": restore_run_id,
        "runStartedAtUnix": args.run_started_at_unix,
        "status": status,
        "counts": counts,
        "gates": gates,
        "gateInventory": gate_inventory,
        "sidecars": sidecars,
    }

    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise SystemExit("verification evidence parent is unsafe")
    os.chmod(output.parent, 0o700)
    if output.is_symlink() or (output.exists() and not output.is_file()):
        raise SystemExit("verification evidence destination is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent, prefix=f".{output.name}."
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(evidence, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, output)
        parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    print(f"verification evidence: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
