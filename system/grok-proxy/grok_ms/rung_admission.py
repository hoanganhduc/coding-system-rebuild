"""Final runtime admission for externally promoted route rungs.

The installer proves the full qualification transcript before publishing one
content-addressed terminal evidence record.  Runtime admission treats that
root-owned record as the revocable rung authority: selection metadata must be
globally exact, while a missing or invalid evidence object removes only its
own rung.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable, Mapping


RUNG_EVIDENCE_SCHEMA_VERSION = 9
RUNG_RECORD_FIELDS = frozenset(
    {"contract_sha256", "evidence_sha256", "grok_release_id", "rung"}
)
RUNG_MEASUREMENT_FIELDS = frozenset(
    {
        "duration_ms",
        "fault_load_canary_verified",
        "host_limits_verified",
        "post_repair_reconnect_cache_execution_units_verified",
        "result_sha256",
        "shared_route",
        "teardown_clean",
        "transport_timing_verified",
        "two_sessions",
    }
)

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RUNG = re.compile(
    r"^(?:direct|vpn|home:[A-Za-z0-9._:+@-]{1,120}|"
    r"ios:[a-z0-9][a-z0-9._-]{0,63})$"
)
_ROUTE_PROFILE = re.compile(
    r"^(?:direct|iphone|vpn|auto|auto-no-direct|"
    r"home:[A-Za-z0-9._:+@-]{1,120}|"
    r"ios:[a-z0-9][a-z0-9._-]{0,63})$"
)
_GROK_RELEASE = re.compile(r"^[A-Za-z0-9._:+@-]{1,128}$")
_MODEL = re.compile(r"^[A-Za-z0-9._:+/@-]{1,128}$")
_MAX_EVIDENCE_BYTES = 1_048_576


class RungAdmissionError(ValueError):
    """Selected rung metadata is not a safe global authorization set."""


class RungEvidenceInvalid(ValueError):
    """One terminal evidence object is absent, unsafe, or nonpassing."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _safe_directory(path: Path, uid: int, gid: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RungEvidenceInvalid("rung evidence directory is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != 0o755
    ):
        raise RungEvidenceInvalid("rung evidence directory is unsafe")


def _read_evidence(path: Path, uid: int, gid: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RungEvidenceInvalid("rung evidence is unavailable") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != 0o444
            or not 1 <= info.st_size <= _MAX_EVIDENCE_BYTES
        ):
            raise RungEvidenceInvalid("rung evidence has unsafe metadata")
        chunks: list[bytes] = []
        remaining = _MAX_EVIDENCE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_EVIDENCE_BYTES:
            raise RungEvidenceInvalid("rung evidence is oversized")
        return raw
    finally:
        os.close(descriptor)


def _route_matches(route_profile: Any, rung: str) -> bool:
    return bool(
        type(route_profile) is str
        and _ROUTE_PROFILE.fullmatch(route_profile) is not None
        and (
            route_profile == rung
            or route_profile == "auto"
            or (route_profile == "auto-no-direct" and rung != "direct")
            or (route_profile == "iphone" and rung.startswith("ios:"))
        )
    )


def normalize_selected_rungs(
    records: Iterable[Mapping[str, object]],
) -> tuple[dict[str, str], ...]:
    """Validate the root-selected record set as one canonical authority."""

    if isinstance(records, (str, bytes)) or not isinstance(records, list):
        raise RungAdmissionError("selected qualified rung set is not an array")
    if len(records) > 64:
        raise RungAdmissionError("selected qualified rung set exceeds its bound")
    normalized: list[dict[str, str]] = []
    identities: set[tuple[str, str, str]] = set()
    for record in records:
        if not isinstance(record, Mapping) or set(record) != RUNG_RECORD_FIELDS:
            raise RungAdmissionError(
                "selected qualified rung record has an unexpected shape"
            )
        rung = record.get("rung")
        contract = record.get("contract_sha256")
        evidence = record.get("evidence_sha256")
        grok_release = record.get("grok_release_id")
        if (
            type(rung) is not str
            or _RUNG.fullmatch(rung) is None
            or type(contract) is not str
            or _DIGEST.fullmatch(contract) is None
            or type(evidence) is not str
            or _DIGEST.fullmatch(evidence) is None
            or type(grok_release) is not str
            or _GROK_RELEASE.fullmatch(grok_release) is None
        ):
            raise RungAdmissionError("selected qualified rung identity is invalid")
        identity = (rung, contract, grok_release)
        if identity in identities:
            raise RungAdmissionError("selected qualified rung identity is duplicated")
        identities.add(identity)
        normalized.append(
            {
                "contract_sha256": contract,
                "evidence_sha256": evidence,
                "grok_release_id": grok_release,
                "rung": rung,
            }
        )
    ordered = sorted(
        normalized,
        key=lambda value: (
            value["rung"],
            value["contract_sha256"],
            value["grok_release_id"],
        ),
    )
    if normalized != ordered:
        raise RungAdmissionError("selected qualified rung set is not canonical")
    return tuple(normalized)


def _validate_terminal_evidence(
    record: Mapping[str, str],
    *,
    evidence_root: Path,
    release_id: str,
    host_id: str,
    root_uid: int,
    root_gid: int,
) -> None:
    _safe_directory(evidence_root, root_uid, root_gid)
    release_root = evidence_root / release_id
    _safe_directory(release_root, root_uid, root_gid)
    raw = _read_evidence(
        release_root / f"{record['evidence_sha256']}.json",
        root_uid,
        root_gid,
    )
    if hashlib.sha256(raw).hexdigest() != record["evidence_sha256"]:
        raise RungEvidenceInvalid("rung evidence digest changed")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RungEvidenceInvalid("rung evidence is not JSON") from exc
    if type(value) is not dict or raw != _canonical_json(value) + b"\n":
        raise RungEvidenceInvalid("rung evidence is not canonical")
    fields = {
        "schema_version",
        "release_id",
        "host_id",
        "rung",
        "route_profile",
        "contract_sha256",
        "rung_qualification_sha256",
        "grok_release_id",
        "model_id",
        "qualification_profile_sha256",
        "measured_unix_ns",
        "canary_nonce",
        "release_qualification_sha256",
        "real_pair_result_sha256",
        "measurements",
        "overall_pass",
    }
    rung = record["rung"]
    measurements = value.get("measurements")
    profile_sha256 = value.get("qualification_profile_sha256")
    release_qualification = value.get("release_qualification_sha256")
    real_pair = value.get("real_pair_result_sha256")
    if (
        set(value) != fields
        or value.get("schema_version") != RUNG_EVIDENCE_SCHEMA_VERSION
        or value.get("release_id") != release_id
        or value.get("host_id") != host_id
        or value.get("rung") != rung
        or not _route_matches(value.get("route_profile"), rung)
        or type(value.get("contract_sha256")) is not str
        or _DIGEST.fullmatch(value["contract_sha256"]) is None
        or value.get("rung_qualification_sha256")
        != record["contract_sha256"]
        or value.get("grok_release_id") != record["grok_release_id"]
        or type(value.get("model_id")) is not str
        or _MODEL.fullmatch(value["model_id"]) is None
        or not (
            profile_sha256 is None
            or (
                type(profile_sha256) is str
                and _DIGEST.fullmatch(profile_sha256) is not None
            )
        )
        or type(value.get("measured_unix_ns")) is not int
        or value.get("measured_unix_ns", 0) <= 0
        or type(value.get("canary_nonce")) is not str
        or _DIGEST.fullmatch(value["canary_nonce"]) is None
        or type(release_qualification) is not str
        or _DIGEST.fullmatch(release_qualification) is None
        or type(real_pair) is not str
        or _DIGEST.fullmatch(real_pair) is None
        or type(measurements) is not dict
        or set(measurements) != RUNG_MEASUREMENT_FIELDS
        or any(
            measurements.get(name) is not True
            for name in RUNG_MEASUREMENT_FIELDS
            if name not in {"duration_ms", "result_sha256"}
        )
        or type(measurements.get("duration_ms")) is not int
        or not 1 <= measurements.get("duration_ms", 0) <= 86_400_000
        or type(measurements.get("result_sha256")) is not str
        or _DIGEST.fullmatch(measurements["result_sha256"]) is None
        or value.get("overall_pass") is not True
    ):
        raise RungEvidenceInvalid("rung evidence is failed or mismatched")
    derived = hashlib.sha256(
        _canonical_json(
            {
                "real_pair_result_sha256": real_pair,
                "release_qualification_sha256": release_qualification,
            }
        )
        + b"\n"
    ).hexdigest()
    if measurements["result_sha256"] != derived:
        raise RungEvidenceInvalid("rung evidence result binding is invalid")


def eligible_selected_rungs(
    records: Iterable[Mapping[str, object]],
    *,
    control_root: Path,
    release_id: str,
    host_id: str,
    root_uid: int,
    root_gid: int,
) -> tuple[dict[str, str], ...]:
    """Return only records whose terminal evidence remains exactly valid."""

    normalized = normalize_selected_rungs(records)
    admitted: list[dict[str, str]] = []
    evidence_root = control_root / "rung-evidence"
    for record in normalized:
        try:
            _validate_terminal_evidence(
                record,
                evidence_root=evidence_root,
                release_id=release_id,
                host_id=host_id,
                root_uid=root_uid,
                root_gid=root_gid,
            )
        except (OSError, RungEvidenceInvalid, ValueError):
            continue
        admitted.append(record)
    return tuple(admitted)


__all__ = [
    "RUNG_EVIDENCE_SCHEMA_VERSION",
    "RungAdmissionError",
    "eligible_selected_rungs",
    "normalize_selected_rungs",
]
