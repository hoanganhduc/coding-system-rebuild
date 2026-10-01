#!/usr/bin/env python3
"""Write a non-secret restore-report v1 after all technical gates pass."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import sys
import tempfile
import time

sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))

from lib.restore_evidence import (  # noqa: E402
    MAX_EVIDENCE_BYTES,
    EvidenceContractError,
    closed_repository_commit,
    expected_gate_ids,
    utc_timestamp,
    validate_commit,
    validate_evidence,
    validate_run_id,
)


ARCHITECTURES = {
    "aarch64": "arm64",
    "arm64": "arm64",
    "x86_64": "amd64",
    "amd64": "amd64",
}
TARGET_STATUSES = {
    "PASS",
    "AUTH_INVALID",
    "REAUTH_REQUIRED",
    "CREDIT_BLOCKED",
    "NOT_CONFIGURED",
    "NOT_APPLICABLE",
}


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return value


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


def read_private_json(
    path: Path, description: str
) -> tuple[dict, os.stat_result, str]:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as exc:
        raise EvidenceContractError(f"restore report requires regular {description}") from exc
    try:
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > MAX_EVIDENCE_BYTES
            ):
                raise EvidenceContractError(
                    f"{description} ownership, mode, link count, or size is unsafe"
                )
            remaining = before.st_size
            chunks: list[bytes] = []
            while remaining:
                block = os.read(descriptor, min(remaining, 65536))
                if not block:
                    raise EvidenceContractError(f"{description} is truncated")
                chunks.append(block)
                remaining -= len(block)
            if os.read(descriptor, 1):
                raise EvidenceContractError(f"{description} grew while reading")
            after = os.fstat(descriptor)
            if _snapshot(before) != _snapshot(after):
                raise EvidenceContractError(f"{description} changed while reading")
        except OSError as exc:
            raise EvidenceContractError(f"cannot read {description}") from exc
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceContractError(f"cannot parse {description}") from exc
    if not isinstance(value, dict):
        raise EvidenceContractError(f"{description} root must be an object")
    return value, before, hashlib.sha256(raw).hexdigest()


def read_private_evidence(path: Path) -> dict:
    value, _information, _digest = read_private_json(path, "verification evidence")
    return value


def read_bound_sidecar(path: Path, binding: dict, name: str) -> dict | None:
    if binding.get("present") is False:
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        raise EvidenceContractError(f"unbound {name} sidecar is present")
    value, information, digest = read_private_json(path, f"{name} sidecar")
    actual = {
        "sha256": digest,
        "sizeBytes": information.st_size,
        "ownerUid": information.st_uid,
        "mode": f"{stat.S_IMODE(information.st_mode):04o}",
        "mtimeNs": information.st_mtime_ns,
    }
    if any(binding.get(key) != expected for key, expected in actual.items()):
        raise EvidenceContractError(f"{name} sidecar differs from accepted evidence")
    if (
        value.get("schema") != binding.get("schema")
        or value.get("status") != binding.get("status")
        or value.get("technicalStatus", "PASS") != binding.get("technicalStatus")
    ):
        raise EvidenceContractError(f"{name} sidecar content disagrees with its binding")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("full", "ci"), required=True)
    parser.add_argument("--target-report", type=Path, required=True)
    parser.add_argument("--classroom50-report", type=Path, required=True)
    parser.add_argument("--verification-evidence", type=Path, required=True)
    parser.add_argument("--restore-run-id", required=True)
    parser.add_argument("--expected-commit")
    parser.add_argument(
        "--owner-data-status",
        choices=("restored", "fresh-baseline", "NOT_CONFIGURED"),
        required=True,
    )
    args = parser.parse_args()

    repository = args.repository.resolve()
    try:
        commit = closed_repository_commit(repository)
        expected_commit = (
            validate_commit(args.expected_commit)
            if args.expected_commit is not None
            else None
        )
        if args.profile == "full" and expected_commit is None:
            raise EvidenceContractError("full restore report requires the authenticated commit")
        if expected_commit is not None and commit != expected_commit:
            raise EvidenceContractError(
                "repository HEAD differs from the authenticated expected commit"
            )
    except EvidenceContractError as exc:
        raise SystemExit(f"restore report repository commit is invalid: {exc}") from exc
    machine = platform.machine().lower()
    if machine not in ARCHITECTURES:
        raise SystemExit(f"unsupported restore-report architecture: {machine}")
    architecture = ARCHITECTURES[machine]
    try:
        restore_run_id = validate_run_id(args.restore_run_id)
    except EvidenceContractError as exc:
        raise SystemExit(f"invalid restore run ID: {exc}") from exc
    lock = read_json(repository / f"system/software/ubuntu-24.04-{architecture}.lock.json")
    python_lock = read_json(repository / f"system/python-closure/ubuntu-24.04-{architecture}.lock.json")
    evidence_path = args.verification_evidence
    now_unix = int(time.time())
    try:
        evidence = read_private_evidence(evidence_path)
        evidence_age = validate_evidence(
            evidence,
            repository_commit=commit,
            profile=args.profile,
            architecture=architecture,
            restore_run_id=restore_run_id,
            now_unix=now_unix,
        )
    except EvidenceContractError as exc:
        raise SystemExit(f"verification evidence does not prove this restore: {exc}") from exc
    counts = evidence["counts"]
    gates = evidence["gates"]
    sidecars = evidence["sidecars"]
    try:
        target = read_bound_sidecar(args.target_report, sidecars["target"], "target")
        classroom50 = read_bound_sidecar(
            args.classroom50_report,
            sidecars["classroom50"],
            "Classroom50",
        )
    except EvidenceContractError as exc:
        raise SystemExit(f"verification sidecars do not prove this restore: {exc}") from exc
    target_status = str(sidecars["target"]["status"])
    if target_status not in TARGET_STATUSES:
        raise SystemExit("restore report received an invalid target status")
    if target is not None and target.get("status") != target_status:
        raise SystemExit("restore report target status disagrees with accepted evidence")
    if classroom50 is None or classroom50.get("technicalStatus") != "PASS":
        raise SystemExit("restore report refuses missing Classroom50 technical evidence")
    classroom50_status = str(sidecars["classroom50"]["status"])
    if classroom50_status not in {"PASS", "REAUTH_REQUIRED", "NOT_CONFIGURED"}:
        raise SystemExit("restore report received an invalid Classroom50 status")

    qualification = lock.get("qualification", {})
    python_qualification = python_lock.get("qualification", {})
    platform_qualified = qualification.get("state") == "qualified"
    python_qualified = python_qualification.get("state") == "qualified"
    report = {
        "schema": "coding-system.restore-report/v1",
        "completedAt": utc_timestamp(now_unix),
        "profile": args.profile,
        "repositoryCommit": commit,
        "restoreRunId": restore_run_id,
        "host": {"os": "ubuntu", "version": "24.04", "architecture": architecture},
        "technicalStatus": evidence["status"],
        "targetStatus": target_status,
        "classroom50Status": classroom50_status,
        "platformQualification": qualification.get("state", "unknown"),
        "pythonClosureQualification": python_qualification.get("state", "unknown"),
        "releaseReady": (
            args.profile == "full"
            and evidence["status"] == "PASS"
            and counts["notConfigured"] == 0
            and platform_qualified
            and python_qualified
        ),
        "ownerDataStatus": args.owner_data_status,
        "verificationEvidence": {
            "observedAt": evidence["observedAt"],
            "ageSeconds": evidence_age,
            "gateContract": evidence["gateContract"],
            "gateInventory": evidence["gateInventory"],
            "counts": counts,
            "gates": gates,
            "sidecars": sidecars,
        },
        "verification": {
            "technicalGateRun": evidence["status"],
            "pythonClosureQualification": (
                "PASS" if python_qualified else "ARTIFACT_UNAVAILABLE"
            ),
            "targets": target_status,
            "classroom50": classroom50_status,
        },
    }

    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise SystemExit("restore report parent is unsafe")
    os.chmod(output.parent, 0o700)
    if output.is_symlink() or (output.exists() and not output.is_file()):
        raise SystemExit("restore report destination is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(dir=output.parent, prefix=f".{output.name}.")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, output)
        directory_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    print(f"restore report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
