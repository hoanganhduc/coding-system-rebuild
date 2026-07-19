"""Strict managed profiles for the default multi-session execution path.

The private profile freezes a complete :class:`RouteContract` and a resolved,
content-verified Grok executable.  A separate root-owned activation record
contains only the public bindings needed to select that private profile.
Neither record is an authority by itself: loading an active profile checks the
content address, both records, the nested contract, and the current executable
bytes before returning it to a caller.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import AbstractSet, Any, Iterable, Mapping

from .contract import RouteContract, canonical_json_bytes
from .grok_exec import GrokExecutableError, VerifiedGrokExecutable


MANAGED_PROFILE_SCHEMA_VERSION = 1
ACTIVATION_RECORD_SCHEMA_VERSION = 1
PROFILE_STATUS_SCHEMA = "grok-remote.profile-status.v1"
DEFAULT_PROFILE_NAME = "default"
PROFILE_FILE_MODE = 0o600
ACTIVATION_FILE_MODE = 0o444
PROFILE_DIRECTORY_MODE = 0o700
ACTIVATION_DIRECTORY_MODE = 0o755
PROFILE_MAXIMUM_BYTES = 1_048_576
ACTIVATION_MAXIMUM_BYTES = 16_384

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_GROK_RELEASE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PINNED_GROK_BASENAME_RE = re.compile(
    r"^grok-[A-Za-z0-9][A-Za-z0-9._-]{0,255}$"
)
_RUNG_RE = re.compile(r"^(?:direct|vpn|home:[A-Za-z0-9._:+@-]+|ios:[a-z0-9][a-z0-9._-]{0,63})$")
_RELEASE_RE = re.compile(r"^[A-Za-z0-9._:+/@-]{1,128}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9._:+/@-]{1,128}$")

_PROFILE_STATUS_REASONS = {
    "ready": frozenset(("ready",)),
    "degraded": frozenset(("ready_with_missing_optional_rungs",)),
    "blocked": frozenset(
        (
            "active_profile_invalid",
            "minimum_eligible_rungs_not_met",
            "release_evidence_invalid",
            "required_rungs_missing",
        )
    ),
    "unconfigured": frozenset(("no_active_profile",)),
}
_PROFILE_BOUND_BLOCKED_REASONS = frozenset(
    ("minimum_eligible_rungs_not_met", "required_rungs_missing")
)
_REDACTED_BLOCKED_REASONS = frozenset(
    ("active_profile_invalid", "release_evidence_invalid")
)


class ManagedProfileError(ValueError):
    """A managed profile, activation record, or storage path is unsafe."""


class ActivationCommitUncertain(ManagedProfileError):
    """The activation rename committed but parent-directory fsync failed."""


def _exact_mapping(
    value: Any, expected: set[str], path: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise ManagedProfileError(f"{path}: expected an object with string keys")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing {missing!r}")
        if extra:
            details.append(f"unexpected {extra!r}")
        raise ManagedProfileError(f"{path}: {'; '.join(details)}")
    return value


def _text(
    value: Any,
    path: str,
    *,
    pattern: re.Pattern[str],
    maximum: int,
) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise ManagedProfileError(f"{path}: expected a bounded string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ManagedProfileError(f"{path}: control characters are forbidden")
    if pattern.fullmatch(value) is None:
        raise ManagedProfileError(f"{path}: contains unsupported characters")
    return value


def _digest(value: Any, path: str) -> str:
    return _text(value, path, pattern=_DIGEST_RE, maximum=64)


def _grok_release(value: Any, path: str) -> str:
    return _text(value, path, pattern=_GROK_RELEASE_RE, maximum=71)


def _rung(value: Any, path: str) -> str:
    return _text(value, path, pattern=_RUNG_RE, maximum=128)


def _pinned_grok_path(value: Any, path: str) -> Path:
    if type(value) is not str or not 1 <= len(value) <= 4_096:
        raise ManagedProfileError(f"{path}: expected a bounded absolute path")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ManagedProfileError(f"{path}: control characters are forbidden")
    candidate = Path(value)
    if (
        not candidate.is_absolute()
        or str(candidate) != value
        or _PINNED_GROK_BASENAME_RE.fullmatch(candidate.name) is None
    ):
        raise ManagedProfileError(
            f"{path}: expected a normalized absolute versioned Grok path"
        )
    return candidate


def _canonical_record_bytes(value: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(value) + b"\n"


@dataclass(frozen=True, slots=True)
class ReadinessPolicy:
    """The minimum closed set of qualified rungs needed for activation."""

    minimum_eligible_rungs: int
    required_rungs: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.minimum_eligible_rungs) is not int
            or not 1 <= self.minimum_eligible_rungs <= 64
        ):
            raise ManagedProfileError(
                "readiness_policy.minimum_eligible_rungs: must be in [1, 64]"
            )
        if type(self.required_rungs) is not tuple:
            raise ManagedProfileError(
                "readiness_policy.required_rungs: expected an immutable tuple"
            )
        checked = tuple(
            _rung(item, f"readiness_policy.required_rungs[{index}]")
            for index, item in enumerate(self.required_rungs)
        )
        if len(set(checked)) != len(checked):
            raise ManagedProfileError(
                "readiness_policy.required_rungs: duplicates are forbidden"
            )
        if len(checked) > 64:
            raise ManagedProfileError(
                "readiness_policy.required_rungs: at most 64 rungs are supported"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "minimum_eligible_rungs": self.minimum_eligible_rungs,
            "required_rungs": list(self.required_rungs),
        }

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "readiness_policy"
    ) -> "ReadinessPolicy":
        value = _exact_mapping(
            value, {"minimum_eligible_rungs", "required_rungs"}, path
        )
        minimum = value["minimum_eligible_rungs"]
        required = value["required_rungs"]
        if type(minimum) is not int:
            raise ManagedProfileError(
                f"{path}.minimum_eligible_rungs: expected an integer"
            )
        if type(required) is not list:
            raise ManagedProfileError(f"{path}.required_rungs: expected an array")
        return cls(minimum, tuple(required))


@dataclass(frozen=True, slots=True)
class ProfileStatus:
    """The redacted, stable output shape consumed by ``doctor --json``."""

    schema_version: str
    status: str
    profile_name: str | None
    profile_sha256: str | None
    release_id: str | None
    grok_release_id: str | None
    model_id: str | None
    eligible_rungs: tuple[str, ...]
    missing_rungs: tuple[str, ...]
    reason_code: str

    def __post_init__(self) -> None:
        if self.schema_version != PROFILE_STATUS_SCHEMA:
            raise ManagedProfileError("status.schema_version: unsupported value")
        if type(self.status) is not str or self.status not in {
            "ready",
            "degraded",
            "blocked",
            "unconfigured",
        }:
            raise ManagedProfileError("status.status: unsupported value")
        if (
            type(self.reason_code) is not str
            or self.reason_code not in _PROFILE_STATUS_REASONS[self.status]
        ):
            raise ManagedProfileError(
                "status.reason_code: unsupported value for status"
            )
        identities = (
            self.profile_name,
            self.profile_sha256,
            self.release_id,
            self.grok_release_id,
            self.model_id,
        )
        present = tuple(item is not None for item in identities)
        if self.status in {"ready", "degraded"} and not all(present):
            raise ManagedProfileError(
                "status: ready and degraded records require every identity binding"
            )
        if self.status == "unconfigured" and any(present):
            raise ManagedProfileError(
                "status: unconfigured records cannot contain identity bindings"
            )
        if self.status == "blocked" and any(present) and not all(present):
            raise ManagedProfileError(
                "status: blocked identity bindings must be all present or all absent"
            )
        if self.status == "blocked":
            allowed = (
                _PROFILE_BOUND_BLOCKED_REASONS
                if all(present)
                else _REDACTED_BLOCKED_REASONS
            )
            if self.reason_code not in allowed:
                raise ManagedProfileError(
                    "status.reason_code: inconsistent blocked record"
                )
        if self.profile_name is not None and self.profile_name != DEFAULT_PROFILE_NAME:
            raise ManagedProfileError("status.profile_name: unsupported value")
        if self.profile_sha256 is not None:
            _digest(self.profile_sha256, "status.profile_sha256")
        if self.release_id is not None:
            _text(
                self.release_id,
                "status.release_id",
                pattern=_RELEASE_RE,
                maximum=128,
            )
        if self.grok_release_id is not None:
            _grok_release(self.grok_release_id, "status.grok_release_id")
        if self.model_id is not None:
            _text(self.model_id, "status.model_id", pattern=_MODEL_RE, maximum=128)
        if type(self.eligible_rungs) is not tuple or type(self.missing_rungs) is not tuple:
            raise ManagedProfileError("status rung collections must be immutable tuples")
        eligible = tuple(
            _rung(item, f"status.eligible_rungs[{index}]")
            for index, item in enumerate(self.eligible_rungs)
        )
        missing = tuple(
            _rung(item, f"status.missing_rungs[{index}]")
            for index, item in enumerate(self.missing_rungs)
        )
        if len(set(eligible)) != len(eligible) or len(set(missing)) != len(missing):
            raise ManagedProfileError("status rung collections cannot contain duplicates")
        if set(eligible) & set(missing):
            raise ManagedProfileError("status eligible and missing rungs must be disjoint")
        if self.status == "ready" and missing:
            raise ManagedProfileError("status: ready records cannot have missing rungs")
        if self.status == "degraded" and not missing:
            raise ManagedProfileError("status: degraded records require missing rungs")
        if self.status == "unconfigured" and (eligible or missing):
            raise ManagedProfileError("status: unconfigured records cannot contain rungs")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "profile_name": self.profile_name,
            "profile_sha256": self.profile_sha256,
            "release_id": self.release_id,
            "grok_release_id": self.grok_release_id,
            "model_id": self.model_id,
            "eligible_rungs": list(self.eligible_rungs),
            "missing_rungs": list(self.missing_rungs),
            "reason_code": self.reason_code,
        }

    @classmethod
    def from_dict(cls, value: Any, path: str = "status") -> "ProfileStatus":
        fields = {
            "schema_version",
            "status",
            "profile_name",
            "profile_sha256",
            "release_id",
            "grok_release_id",
            "model_id",
            "eligible_rungs",
            "missing_rungs",
            "reason_code",
        }
        value = _exact_mapping(value, fields, path)
        eligible = value["eligible_rungs"]
        missing = value["missing_rungs"]
        if type(eligible) is not list or type(missing) is not list:
            raise ManagedProfileError(f"{path}: rung fields must be arrays")
        return cls(
            schema_version=value["schema_version"],
            status=value["status"],
            profile_name=value["profile_name"],
            profile_sha256=value["profile_sha256"],
            release_id=value["release_id"],
            grok_release_id=value["grok_release_id"],
            model_id=value["model_id"],
            eligible_rungs=tuple(eligible),
            missing_rungs=tuple(missing),
            reason_code=value["reason_code"],
        )


def unconfigured_status() -> ProfileStatus:
    return ProfileStatus(
        PROFILE_STATUS_SCHEMA,
        "unconfigured",
        None,
        None,
        None,
        None,
        None,
        (),
        (),
        "no_active_profile",
    )


def blocked_status(reason_code: str) -> ProfileStatus:
    """Return a status for an untrusted record without leaking partial data."""

    return ProfileStatus(
        PROFILE_STATUS_SCHEMA,
        "blocked",
        None,
        None,
        None,
        None,
        None,
        (),
        (),
        reason_code,
    )


@dataclass(frozen=True, slots=True)
class ManagedProfile:
    schema_version: int
    profile_name: str
    contract: RouteContract
    contract_sha256: str
    grok_path: Path
    grok_release_id: str
    readiness_policy: ReadinessPolicy

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != MANAGED_PROFILE_SCHEMA_VERSION
        ):
            raise ManagedProfileError("profile.schema_version: unsupported value")
        if self.profile_name != DEFAULT_PROFILE_NAME:
            raise ManagedProfileError("profile.profile_name: unsupported value")
        if not isinstance(self.contract, RouteContract):
            raise ManagedProfileError("profile.contract: expected a RouteContract")
        if _digest(self.contract_sha256, "profile.contract_sha256") != self.contract.digest():
            raise ManagedProfileError("profile.contract_sha256: contract digest mismatch")
        pinned = _pinned_grok_path(str(self.grok_path), "profile.grok_path")
        if pinned != self.grok_path:
            raise ManagedProfileError("profile.grok_path: expected a normalized Path")
        if _grok_release(self.grok_release_id, "profile.grok_release_id") != self.contract.grok_release_id:
            raise ManagedProfileError(
                "profile.grok_release_id: does not match the frozen contract"
            )
        if not isinstance(self.readiness_policy, ReadinessPolicy):
            raise ManagedProfileError(
                "profile.readiness_policy: expected a ReadinessPolicy"
            )
        ladder = self.contract.ladder
        if self.readiness_policy.minimum_eligible_rungs > len(ladder):
            raise ManagedProfileError(
                "profile.readiness_policy.minimum_eligible_rungs: exceeds the frozen ladder"
            )
        unknown_required = set(self.readiness_policy.required_rungs) - set(ladder)
        if unknown_required:
            raise ManagedProfileError(
                "profile.readiness_policy.required_rungs: contains a rung outside the frozen ladder"
            )
        ordered_required = tuple(
            rung for rung in ladder if rung in self.readiness_policy.required_rungs
        )
        if ordered_required != self.readiness_policy.required_rungs:
            raise ManagedProfileError(
                "profile.readiness_policy.required_rungs: must preserve frozen ladder order"
            )

    @classmethod
    def create(
        cls,
        contract: RouteContract,
        grok_path: Path,
        readiness_policy: ReadinessPolicy,
        *,
        profile_name: str = DEFAULT_PROFILE_NAME,
    ) -> "ManagedProfile":
        try:
            with VerifiedGrokExecutable.open(grok_path) as executable:
                if executable.release_id != contract.grok_release_id:
                    raise ManagedProfileError(
                        "profile.grok_release_id: executable bytes do not match the contract"
                    )
                pinned_path = executable.path
        except GrokExecutableError as exc:
            raise ManagedProfileError(f"profile.grok_path: {exc}") from exc
        _pinned_grok_path(str(pinned_path), "profile.grok_path")
        return cls(
            MANAGED_PROFILE_SCHEMA_VERSION,
            profile_name,
            contract,
            contract.digest(),
            pinned_path,
            contract.grok_release_id,
            readiness_policy,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_name": self.profile_name,
            "contract": self.contract.to_dict(),
            "contract_sha256": self.contract_sha256,
            "grok_path": str(self.grok_path),
            "grok_release_id": self.grok_release_id,
            "readiness_policy": self.readiness_policy.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Any, path: str = "profile") -> "ManagedProfile":
        fields = {
            "schema_version",
            "profile_name",
            "contract",
            "contract_sha256",
            "grok_path",
            "grok_release_id",
            "readiness_policy",
        }
        value = _exact_mapping(value, fields, path)
        schema_version = value["schema_version"]
        if type(schema_version) is not int:
            raise ManagedProfileError(f"{path}.schema_version: expected an integer")
        try:
            contract = RouteContract.from_dict(value["contract"], f"{path}.contract")
        except ValueError as exc:
            raise ManagedProfileError(str(exc)) from exc
        return cls(
            schema_version,
            value["profile_name"],
            contract,
            value["contract_sha256"],
            _pinned_grok_path(value["grok_path"], f"{path}.grok_path"),
            value["grok_release_id"],
            ReadinessPolicy.from_dict(
                value["readiness_policy"], f"{path}.readiness_policy"
            ),
        )

    def canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def filename(self) -> str:
        return f"{self.digest()}.json"

    def readiness(self, eligible_rungs: Iterable[str]) -> ProfileStatus:
        if isinstance(eligible_rungs, (str, bytes)):
            raise ManagedProfileError("eligible_rungs: expected a collection of rungs")
        supplied = tuple(eligible_rungs)
        checked = tuple(
            _rung(item, f"eligible_rungs[{index}]")
            for index, item in enumerate(supplied)
        )
        if len(set(checked)) != len(checked):
            raise ManagedProfileError("eligible_rungs: duplicates are forbidden")
        unknown = set(checked) - set(self.contract.ladder)
        if unknown:
            raise ManagedProfileError(
                "eligible_rungs: contains a rung outside the frozen ladder"
            )
        eligible_set = set(checked)
        eligible = tuple(rung for rung in self.contract.ladder if rung in eligible_set)
        missing = tuple(rung for rung in self.contract.ladder if rung not in eligible_set)
        required_missing = set(self.readiness_policy.required_rungs) - eligible_set
        if required_missing:
            state = "blocked"
            reason = "required_rungs_missing"
        elif len(eligible) < self.readiness_policy.minimum_eligible_rungs:
            state = "blocked"
            reason = "minimum_eligible_rungs_not_met"
        elif missing:
            state = "degraded"
            reason = "ready_with_missing_optional_rungs"
        else:
            state = "ready"
            reason = "ready"
        return ProfileStatus(
            PROFILE_STATUS_SCHEMA,
            state,
            self.profile_name,
            self.digest(),
            self.contract.release_id,
            self.grok_release_id,
            self.contract.model_id,
            eligible,
            missing,
            reason,
        )


@dataclass(frozen=True, slots=True)
class ActivationRecord:
    schema_version: int
    profile_name: str
    profile_sha256: str
    release_id: str
    contract_sha256: str
    grok_release_id: str
    model_id: str
    activated_unix_ns: int

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != ACTIVATION_RECORD_SCHEMA_VERSION
        ):
            raise ManagedProfileError("activation.schema_version: unsupported value")
        if self.profile_name != DEFAULT_PROFILE_NAME:
            raise ManagedProfileError("activation.profile_name: unsupported value")
        _digest(self.profile_sha256, "activation.profile_sha256")
        _text(self.release_id, "activation.release_id", pattern=_RELEASE_RE, maximum=128)
        _digest(self.contract_sha256, "activation.contract_sha256")
        _grok_release(self.grok_release_id, "activation.grok_release_id")
        _text(self.model_id, "activation.model_id", pattern=_MODEL_RE, maximum=128)
        if (
            type(self.activated_unix_ns) is not int
            or not 1 <= self.activated_unix_ns <= 2**63 - 1
        ):
            raise ManagedProfileError(
                "activation.activated_unix_ns: expected a positive bounded integer"
            )

    @classmethod
    def from_profile(
        cls, profile: ManagedProfile, *, activated_unix_ns: int | None = None
    ) -> "ActivationRecord":
        if activated_unix_ns is None:
            activated_unix_ns = time.time_ns()
        return cls(
            ACTIVATION_RECORD_SCHEMA_VERSION,
            profile.profile_name,
            profile.digest(),
            profile.contract.release_id,
            profile.contract_sha256,
            profile.grok_release_id,
            profile.contract.model_id,
            activated_unix_ns,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_name": self.profile_name,
            "profile_sha256": self.profile_sha256,
            "release_id": self.release_id,
            "contract_sha256": self.contract_sha256,
            "grok_release_id": self.grok_release_id,
            "model_id": self.model_id,
            "activated_unix_ns": self.activated_unix_ns,
        }

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "activation"
    ) -> "ActivationRecord":
        fields = {
            "schema_version",
            "profile_name",
            "profile_sha256",
            "release_id",
            "contract_sha256",
            "grok_release_id",
            "model_id",
            "activated_unix_ns",
        }
        value = _exact_mapping(value, fields, path)
        return cls(
            value["schema_version"],
            value["profile_name"],
            value["profile_sha256"],
            value["release_id"],
            value["contract_sha256"],
            value["grok_release_id"],
            value["model_id"],
            value["activated_unix_ns"],
        )

    def canonical_bytes(self) -> bytes:
        return _canonical_record_bytes(self.to_dict())

    def validate_profile(self, profile: ManagedProfile) -> None:
        expected = {
            "profile_name": profile.profile_name,
            "profile_sha256": profile.digest(),
            "release_id": profile.contract.release_id,
            "contract_sha256": profile.contract_sha256,
            "grok_release_id": profile.grok_release_id,
            "model_id": profile.contract.model_id,
        }
        actual = {
            "profile_name": self.profile_name,
            "profile_sha256": self.profile_sha256,
            "release_id": self.release_id,
            "contract_sha256": self.contract_sha256,
            "grok_release_id": self.grok_release_id,
            "model_id": self.model_id,
        }
        differences = sorted(key for key in expected if expected[key] != actual[key])
        if differences:
            raise ManagedProfileError(
                f"activation/profile binding mismatch: {differences!r}"
            )


@dataclass(frozen=True, slots=True)
class ActiveManagedProfile:
    activation: ActivationRecord
    profile: ManagedProfile


def _open_secure_directory(
    path: Path, *, expected_uid: int, expected_gid: int, expected_mode: int
) -> int:
    if not path.is_absolute():
        raise ManagedProfileError(f"storage directory is not absolute: {path}")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ManagedProfileError(f"cannot open secure storage directory {path}: {exc}") from exc
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_uid
        or info.st_gid != expected_gid
        or stat.S_IMODE(info.st_mode) != expected_mode
    ):
        os.close(descriptor)
        raise ManagedProfileError(f"unsafe owner/type/mode for storage directory: {path}")
    return descriptor


def _read_exact_file(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
    directory_uid: int,
    directory_gid: int,
    directory_mode: int,
    maximum: int,
) -> bytes:
    if type(maximum) is not int or maximum < 2:
        raise ManagedProfileError("maximum read size is invalid")
    directory_fd = _open_secure_directory(
        path.parent,
        expected_uid=directory_uid,
        expected_gid=directory_gid,
        expected_mode=directory_mode,
    )
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise ManagedProfileError(f"cannot open managed metadata {path}: {exc}") from exc
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_gid != expected_gid
            or stat.S_IMODE(info.st_mode) != expected_mode
        ):
            raise ManagedProfileError(f"unsafe owner/type/mode for managed metadata: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ManagedProfileError(f"oversized managed metadata: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _decode_object(raw: bytes, path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManagedProfileError(f"invalid JSON managed metadata {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ManagedProfileError(f"managed metadata is not an object: {path}")
    return value


def load_managed_profile(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    directory_mode: int = PROFILE_DIRECTORY_MODE,
    expected_sha256: str | None = None,
) -> ManagedProfile:
    raw = _read_exact_file(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=PROFILE_FILE_MODE,
        directory_uid=expected_uid,
        directory_gid=expected_gid,
        directory_mode=directory_mode,
        maximum=PROFILE_MAXIMUM_BYTES,
    )
    profile = ManagedProfile.from_dict(_decode_object(raw, path))
    if raw != profile.canonical_bytes():
        raise ManagedProfileError(f"managed profile is not canonical: {path}")
    digest = profile.digest()
    if expected_sha256 is not None and digest != _digest(expected_sha256, "expected_sha256"):
        raise ManagedProfileError("managed profile content address mismatch")
    if path.name != f"{digest}.json":
        raise ManagedProfileError("managed profile filename is not its content address")
    return profile


def load_activation_record(
    path: Path,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
    directory_mode: int = ACTIVATION_DIRECTORY_MODE,
) -> ActivationRecord:
    raw = _read_exact_file(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=ACTIVATION_FILE_MODE,
        directory_uid=expected_uid,
        directory_gid=expected_gid,
        directory_mode=directory_mode,
        maximum=ACTIVATION_MAXIMUM_BYTES,
    )
    activation = ActivationRecord.from_dict(_decode_object(raw, path))
    if raw != activation.canonical_bytes():
        raise ManagedProfileError(f"activation record is not canonical: {path}")
    return activation


def open_profile_grok(
    profile: ManagedProfile,
    *,
    allowed_owner_uids: AbstractSet[int] | None = None,
) -> VerifiedGrokExecutable:
    """Open and bind the executable named by a previously validated profile."""

    try:
        executable = VerifiedGrokExecutable.open(
            profile.grok_path,
            allowed_owner_uids=allowed_owner_uids,
        )
    except GrokExecutableError as exc:
        raise ManagedProfileError(f"managed Grok executable is unsafe: {exc}") from exc
    if executable.path != profile.grok_path or executable.release_id != profile.grok_release_id:
        executable.close()
        raise ManagedProfileError("managed Grok executable identity mismatch")
    return executable


def load_active_profile(
    profile_root: Path,
    activation_path: Path,
    *,
    profile_uid: int,
    profile_gid: int,
    activation_uid: int = 0,
    activation_gid: int = 0,
    profile_directory_mode: int = PROFILE_DIRECTORY_MODE,
    activation_directory_mode: int = ACTIVATION_DIRECTORY_MODE,
    expected_release_id: str | None = None,
    verify_executable: bool = True,
) -> ActiveManagedProfile:
    activation = load_activation_record(
        activation_path,
        expected_uid=activation_uid,
        expected_gid=activation_gid,
        directory_mode=activation_directory_mode,
    )
    if expected_release_id is not None and activation.release_id != _text(
        expected_release_id,
        "expected_release_id",
        pattern=_RELEASE_RE,
        maximum=128,
    ):
        raise ManagedProfileError("active profile release does not match the selected release")
    profile = load_managed_profile(
        profile_root / f"{activation.profile_sha256}.json",
        expected_uid=profile_uid,
        expected_gid=profile_gid,
        directory_mode=profile_directory_mode,
        expected_sha256=activation.profile_sha256,
    )
    activation.validate_profile(profile)
    if verify_executable:
        with open_profile_grok(profile):
            pass
    return ActiveManagedProfile(activation, profile)


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        count = os.write(descriptor, data[offset:])
        if count <= 0:
            raise OSError(errno.EIO, "short write")
        offset += count


def _stage_file(
    directory_fd: int,
    temporary: str,
    data: bytes,
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int,
) -> None:
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=directory_fd,
    )
    primary_error: BaseException | None = None
    try:
        try:
            os.fchown(descriptor, owner_uid, owner_gid)
            os.fchmod(descriptor, mode)
            _write_all(descriptor, data)
            os.fsync(descriptor)
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            try:
                os.close(descriptor)
            except OSError as exc:
                if primary_error is None:
                    raise
                primary_error.add_note(
                    f"staged-record descriptor cleanup also failed: {exc}"
                )
    except BaseException as exc:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError as cleanup_exc:
            exc.add_note(f"staged-record unlink also failed: {cleanup_exc}")
        raise


def _validate_existing_bytes(
    directory_fd: int,
    name: str,
    expected: bytes,
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int,
) -> None:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_gid != owner_gid
            or stat.S_IMODE(info.st_mode) != mode
            or info.st_size != len(expected)
            or os.pread(descriptor, len(expected), 0) != expected
        ):
            raise ManagedProfileError(f"existing managed record is unsafe: {name}")
    finally:
        os.close(descriptor)


def write_content_addressed_profile(
    profile_root: Path,
    profile: ManagedProfile,
    *,
    owner_uid: int,
    owner_gid: int,
    directory_mode: int = PROFILE_DIRECTORY_MODE,
) -> Path:
    """Publish one immutable profile without replacing an existing address."""

    directory_fd = _open_secure_directory(
        profile_root,
        expected_uid=owner_uid,
        expected_gid=owner_gid,
        expected_mode=directory_mode,
    )
    name = profile.filename()
    data = profile.canonical_bytes()
    temporary = f".profile-{secrets.token_hex(16)}.tmp"
    staged = False
    primary_error: BaseException | None = None
    try:
        try:
            try:
                _validate_existing_bytes(
                    directory_fd,
                    name,
                    data,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                    mode=PROFILE_FILE_MODE,
                )
                return profile_root / name
            except FileNotFoundError:
                pass
            _stage_file(
                directory_fd,
                temporary,
                data,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                mode=PROFILE_FILE_MODE,
            )
            staged = True
            try:
                os.link(
                    temporary,
                    name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                _validate_existing_bytes(
                    directory_fd,
                    name,
                    data,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                    mode=PROFILE_FILE_MODE,
                )
            os.fsync(directory_fd)
            return profile_root / name
        except OSError as exc:
            raise ManagedProfileError(
                f"cannot publish managed profile: {exc}"
            ) from exc
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_error: OSError | None = None
        if staged:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = exc
        try:
            os.close(directory_fd)
        except OSError as exc:
            if cleanup_error is None:
                cleanup_error = exc
        if cleanup_error is not None:
            if primary_error is not None:
                primary_error.add_note(
                    f"managed-profile publication cleanup also failed: {cleanup_error}"
                )
            else:
                raise ManagedProfileError(
                    "cannot clean managed-profile publication state: "
                    f"{cleanup_error}"
                ) from cleanup_error


def write_activation_record(
    path: Path,
    activation: ActivationRecord,
    *,
    owner_uid: int,
    owner_gid: int,
    directory_mode: int = ACTIVATION_DIRECTORY_MODE,
) -> None:
    """Atomically replace the mutable activation pointer after strict checks."""

    directory_fd = _open_secure_directory(
        path.parent,
        expected_uid=owner_uid,
        expected_gid=owner_gid,
        expected_mode=directory_mode,
    )
    data = activation.canonical_bytes()
    temporary = f".activation-{secrets.token_hex(16)}.tmp"
    staged = False
    committed = False
    primary_error: BaseException | None = None
    try:
        try:
            try:
                _validate_existing_bytes(
                    directory_fd,
                    path.name,
                    data,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                    mode=ACTIVATION_FILE_MODE,
                )
            except FileNotFoundError:
                pass
            except ManagedProfileError:
                # A mutable pointer may contain a different valid record, but an
                # unsafe object (link/device/wrong owner/mode) must never be replaced.
                descriptor = os.open(
                    path.name,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    info = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_uid != owner_uid
                        or info.st_gid != owner_gid
                        or stat.S_IMODE(info.st_mode) != ACTIVATION_FILE_MODE
                    ):
                        raise ManagedProfileError(
                            f"existing activation record is unsafe: {path}"
                        )
                finally:
                    os.close(descriptor)
            _stage_file(
                directory_fd,
                temporary,
                data,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                mode=ACTIVATION_FILE_MODE,
            )
            staged = True
            os.replace(
                temporary,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            staged = False
            committed = True
            os.fsync(directory_fd)
        except OSError as exc:
            if committed:
                raise ActivationCommitUncertain(
                    "activation record rename committed but directory durability "
                    f"is uncertain: {exc}"
                ) from exc
            raise ManagedProfileError(
                f"cannot publish activation record: {exc}"
            ) from exc
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_error: OSError | None = None
        if staged:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = exc
        try:
            os.close(directory_fd)
        except OSError as exc:
            if cleanup_error is None:
                cleanup_error = exc
        if cleanup_error is not None and primary_error is None:
            if committed:
                raise ActivationCommitUncertain(
                    "activation record rename committed but descriptor cleanup "
                    f"is uncertain: {cleanup_error}"
                ) from cleanup_error
            raise ManagedProfileError(
                f"cannot clean activation publication state: {cleanup_error}"
            ) from cleanup_error
        if cleanup_error is not None and primary_error is not None:
            primary_error.add_note(
                f"activation publication cleanup also failed: {cleanup_error}"
            )


__all__ = [
    "ACTIVATION_DIRECTORY_MODE",
    "ACTIVATION_FILE_MODE",
    "ACTIVATION_RECORD_SCHEMA_VERSION",
    "ActiveManagedProfile",
    "ActivationCommitUncertain",
    "ActivationRecord",
    "DEFAULT_PROFILE_NAME",
    "MANAGED_PROFILE_SCHEMA_VERSION",
    "ManagedProfile",
    "ManagedProfileError",
    "PROFILE_DIRECTORY_MODE",
    "PROFILE_FILE_MODE",
    "PROFILE_STATUS_SCHEMA",
    "ProfileStatus",
    "ReadinessPolicy",
    "blocked_status",
    "load_activation_record",
    "load_active_profile",
    "load_managed_profile",
    "open_profile_grok",
    "unconfigured_status",
    "write_activation_record",
    "write_content_addressed_profile",
]
