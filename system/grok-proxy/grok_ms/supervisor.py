"""Per-user multi-session supervisor and lease state machine.

The supervisor is the sole writer for provider generations.  It holds the
stable compatibility lock, publishes a crash-persistent fence before any
provider effect, authenticates packet peers with ``SO_PEERCRED``, and exposes
only a qualified immutable backend through :class:`CommittedFrontend`.

This module intentionally keeps the control protocol small.  Every mutating
request is exact-shape, versioned, connection-bound, and replayable.  Provider
adapters remain responsible for returning and synchronously removing their
complete generation resource graph.
"""

from __future__ import annotations

import argparse
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass, field, replace
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Mapping, Sequence

from .config import _release_id
from .contract import (
    PROTOCOL_VERSION,
    SCHEMA_VERSION,
    Endpoint,
    RouteContract,
    canonical_json_bytes,
    qualification_route_profile_matches,
    reconstruct_original_contract,
)
from .frontend import CommittedFrontend, CommittedGeneration, FrontendDrainTimeout
from .grok_exec import GrokExecutableError, VerifiedGrokExecutable
from .ipc import ProtocolError, SeqPacketConnection, SeqPacketMessage, bind_seqpacket_listener
from .detached_scope import (
    DetachedScopeRecord,
    DetachedScopeStore,
    same_detached_authority,
)
from .parent_guard import clear_parent_death_signal
from .process_scope import (
    LinuxCgroupV2Scope,
    ProcessScopeBackend,
    ScopeError,
    ScopeHandle,
    ScopeIdentity,
    ScopeResidueError,
)
from .secure_files import SecureFileError, read_secure_json
from .providers import (
    DirectProvider,
    LegacyShellProvider,
    ProviderAdapter,
    ProviderCancelled,
    ProviderError,
    ProviderRequest,
    ProviderResourceGraph,
    ProviderResidueError,
    ProviderResult,
    ProviderScopeRecord,
    ProviderScopeStore,
    ProviderTimeout,
    QualificationEvidence,
    TransitionDeadline,
)
from .runtime import (
    EffectIntent,
    FenceBusyError,
    FenceRecord,
    FenceStore,
    IntentStore,
    ProcessIdentity,
    RuntimeSecurityError,
    SecureRuntime,
    _atomic_create_json,
    _atomic_replace_json,
    _create_secure_directory,
    _discard_staged_json,
    _durable_unlink,
    _open_secure_directory,
    _read_secure_json,
    current_process_identity,
    process_can_still_execute,
    process_matches,
    read_boot_id,
    read_pid_start_ticks,
)


def _diagnostic_text(value: object, limit: int) -> str:
    """Return bounded printable ASCII without terminal-control interpretation."""

    if type(limit) is not int or limit < 1:
        raise ValueError("diagnostic limit must be positive")
    escaped = json.dumps(str(value), ensure_ascii=True)[1:-1]
    return escaped[:limit]


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:+@/-]{1,256}$")
_HOME_RUNG_RE = re.compile(r"^home:[A-Za-z0-9._:+@-]{1,120}$")
_IOS_RUNG_RE = re.compile(r"^ios:[a-z0-9][a-z0-9._-]{0,63}$")
_RUNG_CANARY_SCHEMA_VERSION = 6
_IOS_DEVICE_TRANSITION_NS = 30_000_000_000
_IOS_FAMILY_TRANSITION_NS = 120_000_000_000
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_CANARY_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
_GROK_RELEASE_RE = re.compile(r"^[A-Za-z0-9._:+@-]{1,128}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9._:+/@-]{1,128}$")
_MAX_REPLAYS = 4_096
_MAX_DIAGNOSTICS = 48
_MAX_PROBE_OUTPUT = 1_048_576
_EXIT_IDENTITY_URL = "https://www.cloudflare.com/cdn-cgi/trace"
_RECOVERY_RECORD_VERSION = 1
_CHILD_RECOVERY_RECORD_VERSION = 2
_PROBE_RECOVERY_RECORD_VERSION = 1
_PROVIDER_RECOVERY_PHASES = {"PREPARED", "APPLIED", "FAILED", "CLEANED"}
_CHILD_RECOVERY_PHASES = {"PREPARED", "SCOPE_CREATED", "ATTACHED"}
_PROBE_RECOVERY_PHASES = _CHILD_RECOVERY_PHASES
_QUALIFICATION_HOLD_MIN_MS = 1_000
_QUALIFICATION_HOLD_MAX_MS = 900_000
_QUALIFICATION_POLL_SECONDS = 0.2
_JSON_RECORD_TARGET_RE = re.compile(r"^[A-Za-z0-9._:+@-]{1,296}\.json$")
_CONTROL_TARGET_RE = re.compile(r"^(?:recovery\.fence|supervisor\.ready)$")


class SupervisorError(RuntimeError):
    """Base class for deterministic supervisor failures."""


class AdmissionError(SupervisorError):
    """A complete authenticated request was rejected before mutation."""


class RecoveryRequired(SupervisorError):
    """Stale durable state cannot be safely cleared without explicit recovery."""


class EpochDraining(SupervisorError):
    """The epoch crossed the last-interest linearization point."""


def _identity_to_dict(identity: ProcessIdentity) -> dict[str, Any]:
    return {
        "boot_id": identity.boot_id,
        "pid": identity.pid,
        "pid_start_ticks": identity.start_ticks,
    }


def _identity_from_record(value: Any, name: str) -> ProcessIdentity:
    if type(value) is not dict or set(value) != {
        "boot_id",
        "pid",
        "pid_start_ticks",
    }:
        raise ValueError(f"{name}: missing or unexpected fields")
    return ProcessIdentity(
        pid=value["pid"],
        start_ticks=value["pid_start_ticks"],
        boot_id=value["boot_id"],
    )


@dataclass(frozen=True, slots=True)
class ProviderRecoveryRecord:
    schema_version: int
    record_version: int
    release_id: str
    owner_epoch: str
    effect_id: str
    phase: str
    request: ProviderRequest
    resources: ProviderResourceGraph | None

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("provider_recovery.schema_version: unsupported value")
        if self.record_version != _RECOVERY_RECORD_VERSION:
            raise ValueError("provider_recovery.record_version: unsupported value")
        _token(self.release_id, "provider_recovery.release_id")
        _token(self.owner_epoch, "provider_recovery.owner_epoch")
        _token(self.effect_id, "provider_recovery.effect_id")
        if self.phase not in _PROVIDER_RECOVERY_PHASES:
            raise ValueError("provider_recovery.phase: unsupported value")
        if self.request.owner_epoch != self.owner_epoch:
            raise ValueError("provider recovery request owner differs from the record")
        if self.request.contract.release_id != self.release_id:
            raise ValueError("provider recovery request release differs from the record")
        if self.resources is not None and (
            self.resources.owner_epoch,
            self.resources.transition_id,
            self.resources.generation,
            self.resources.rung,
        ) != (
            self.request.owner_epoch,
            self.request.transition_id,
            self.request.generation,
            self.request.rung,
        ):
            raise ValueError("provider recovery graph differs from the frozen request")
        if self.phase == "APPLIED" and self.resources is None:
            raise ValueError("APPLIED provider recovery record requires a resource graph")

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "kind": "provider-recovery",
            "owner_epoch": self.owner_epoch,
            "phase": self.phase,
            "record_version": self.record_version,
            "release_id": self.release_id,
            "request": self.request.to_dict(),
            "resources": self.resources.to_dict() if self.resources is not None else None,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ProviderRecoveryRecord":
        fields = {
            "effect_id",
            "kind",
            "owner_epoch",
            "phase",
            "record_version",
            "release_id",
            "request",
            "resources",
            "schema_version",
        }
        if type(value) is not dict or set(value) != fields:
            raise ValueError("provider recovery record has missing or unexpected fields")
        if value["kind"] != "provider-recovery":
            raise ValueError("provider recovery kind mismatch")
        request = ProviderRequest.from_dict(value["request"])
        resources = (
            None
            if value["resources"] is None
            else ProviderResourceGraph.from_dict(value["resources"])
        )
        return cls(
            schema_version=value["schema_version"],
            record_version=value["record_version"],
            release_id=value["release_id"],
            owner_epoch=value["owner_epoch"],
            effect_id=value["effect_id"],
            phase=value["phase"],
            request=request,
            resources=resources,
        )


@dataclass(frozen=True, slots=True)
class ChildRecoveryRecord:
    schema_version: int
    record_version: int
    release_id: str
    owner_epoch: str
    lease_id: str
    phase: str
    child: ProcessIdentity
    leader_path: str
    scope: ScopeIdentity

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("child_recovery.schema_version: unsupported value")
        if self.record_version != _CHILD_RECOVERY_RECORD_VERSION:
            raise ValueError("child_recovery.record_version: unsupported value")
        _token(self.release_id, "child_recovery.release_id")
        _token(self.owner_epoch, "child_recovery.owner_epoch")
        _token(self.lease_id, "child_recovery.lease_id")
        if self.phase not in _CHILD_RECOVERY_PHASES:
            raise ValueError("child_recovery.phase: unsupported value")
        if (self.phase == "PREPARED") == self.scope.created:
            raise ValueError("child recovery phase and cgroup inode state disagree")
        if type(self.leader_path) is not str or not Path(self.leader_path).is_absolute():
            raise ValueError("child_recovery.leader_path: expected an absolute path")

    def to_dict(self) -> dict[str, Any]:
        return {
            "child": _identity_to_dict(self.child),
            "kind": "child-recovery",
            "leader_path": self.leader_path,
            "lease_id": self.lease_id,
            "owner_epoch": self.owner_epoch,
            "phase": self.phase,
            "record_version": self.record_version,
            "release_id": self.release_id,
            "schema_version": self.schema_version,
            "scope": self.scope.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ChildRecoveryRecord":
        fields = {
            "child",
            "kind",
            "leader_path",
            "lease_id",
            "owner_epoch",
            "phase",
            "record_version",
            "release_id",
            "schema_version",
            "scope",
        }
        if type(value) is not dict or set(value) != fields:
            raise ValueError("child recovery record has missing or unexpected fields")
        if value["kind"] != "child-recovery":
            raise ValueError("child recovery kind mismatch")
        return cls(
            schema_version=value["schema_version"],
            record_version=value["record_version"],
            release_id=value["release_id"],
            owner_epoch=value["owner_epoch"],
            lease_id=value["lease_id"],
            phase=value["phase"],
            child=_identity_from_record(value["child"], "child_recovery.child"),
            leader_path=value["leader_path"],
            scope=ScopeIdentity.from_dict(value["scope"]),
        )


@dataclass(frozen=True, slots=True)
class ProbeRecoveryRecord:
    """Durable identity for one externally executing qualifier/health probe."""

    schema_version: int
    record_version: int
    release_id: str
    owner_epoch: str
    probe_id: str
    phase: str
    child: ProcessIdentity
    scope: ScopeIdentity

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("probe_recovery.schema_version: unsupported value")
        if self.record_version != _PROBE_RECOVERY_RECORD_VERSION:
            raise ValueError("probe_recovery.record_version: unsupported value")
        _token(self.release_id, "probe_recovery.release_id")
        _token(self.owner_epoch, "probe_recovery.owner_epoch")
        _token(self.probe_id, "probe_recovery.probe_id", _NONCE_RE)
        if self.phase not in _PROBE_RECOVERY_PHASES:
            raise ValueError("probe_recovery.phase: unsupported value")
        if (self.phase == "PREPARED") == self.scope.created:
            raise ValueError("probe recovery phase and cgroup inode state disagree")

    def to_dict(self) -> dict[str, Any]:
        return {
            "child": _identity_to_dict(self.child),
            "kind": "probe-recovery",
            "owner_epoch": self.owner_epoch,
            "phase": self.phase,
            "probe_id": self.probe_id,
            "record_version": self.record_version,
            "release_id": self.release_id,
            "schema_version": self.schema_version,
            "scope": self.scope.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ProbeRecoveryRecord":
        fields = {
            "child",
            "kind",
            "owner_epoch",
            "phase",
            "probe_id",
            "record_version",
            "release_id",
            "schema_version",
            "scope",
        }
        if type(value) is not dict or set(value) != fields:
            raise ValueError("probe recovery record has missing or unexpected fields")
        if value["kind"] != "probe-recovery":
            raise ValueError("probe recovery kind mismatch")
        return cls(
            schema_version=value["schema_version"],
            record_version=value["record_version"],
            release_id=value["release_id"],
            owner_epoch=value["owner_epoch"],
            probe_id=value["probe_id"],
            phase=value["phase"],
            child=_identity_from_record(value["child"], "probe_recovery.child"),
            scope=ScopeIdentity.from_dict(value["scope"]),
        )


def _same_probe_authority(
    persisted: ProbeRecoveryRecord,
    expected: ProbeRecoveryRecord,
) -> bool:
    """Accept an older conservative phase only for the same exact scope plan."""

    if (
        persisted.schema_version,
        persisted.record_version,
        persisted.release_id,
        persisted.owner_epoch,
        persisted.probe_id,
        persisted.child,
    ) != (
        expected.schema_version,
        expected.record_version,
        expected.release_id,
        expected.owner_epoch,
        expected.probe_id,
        expected.child,
    ):
        return False
    left = persisted.scope
    right = expected.scope
    if (
        left.backend,
        left.parent_path,
        left.parent_device,
        left.parent_inode,
        left.scope_path,
    ) != (
        right.backend,
        right.parent_path,
        right.parent_device,
        right.parent_inode,
        right.scope_path,
    ):
        return False
    if left.created and right.created:
        return (
            left.scope_device,
            left.scope_inode,
        ) == (
            right.scope_device,
            right.scope_inode,
        )
    return True


class RecoveryStore:
    """Strict durable records needed to replay a dead owner epoch."""

    def __init__(self, runtime: SecureRuntime) -> None:
        runtime.verify()
        self.root = runtime.root / "recovery"
        self.providers = self.root / "providers"
        self.children = self.root / "children"
        self.probes = self.root / "probes"
        self.provider_scopes = self.root / "provider-scopes"
        for directory in (
            self.root,
            self.providers,
            self.children,
            self.probes,
            self.provider_scopes,
        ):
            _create_secure_directory(directory)
        self.provider_scope_store = ProviderScopeStore(runtime.root)

    @staticmethod
    def _records(directory: Path, suffix: str) -> tuple[Path, ...]:
        records: list[Path] = []
        for entry in directory.iterdir():
            if entry.is_symlink() or not entry.name.endswith(suffix):
                raise RuntimeSecurityError(f"unexpected recovery record entry: {entry}")
            records.append(entry)
        return tuple(sorted(records, key=lambda item: item.name))

    def provider_path(self, effect_id: str) -> Path:
        _token(effect_id, "effect_id")
        return self.providers / f"{effect_id}.json"

    def child_path(self, lease_id: str) -> Path:
        _token(lease_id, "lease_id")
        return self.children / f"{lease_id}.json"

    def probe_path(self, probe_id: str) -> Path:
        _token(probe_id, "probe_id", _NONCE_RE)
        return self.probes / f"{probe_id}.json"

    def put_provider(self, record: ProviderRecoveryRecord) -> bool:
        path = self.provider_path(record.effect_id)
        if _atomic_create_json(path, record.to_dict()):
            return True
        existing = self.load_provider(record.effect_id)
        if existing == record:
            return False
        raise RuntimeSecurityError("provider recovery record conflicts with its replay")

    def load_provider(self, effect_id: str) -> ProviderRecoveryRecord | None:
        value = _read_secure_json(self.provider_path(effect_id))
        if value is None:
            return None
        try:
            record = ProviderRecoveryRecord.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeSecurityError(f"invalid provider recovery record: {exc}") from exc
        if record.effect_id != effect_id:
            raise RuntimeSecurityError("provider recovery filename and effect ID disagree")
        return record

    def replace_provider(self, record: ProviderRecoveryRecord) -> None:
        _atomic_replace_json(self.provider_path(record.effect_id), record.to_dict())

    def list_providers(self) -> tuple[ProviderRecoveryRecord, ...]:
        result: list[ProviderRecoveryRecord] = []
        for path in self._records(self.providers, ".json"):
            record = self.load_provider(path.name.removesuffix(".json"))
            if record is None:
                raise RuntimeSecurityError(f"recovery record disappeared: {path}")
            result.append(record)
        return tuple(result)

    def delete_provider(self, effect_id: str) -> bool:
        return _durable_unlink(self.provider_path(effect_id))

    def put_child(self, record: ChildRecoveryRecord) -> bool:
        path = self.child_path(record.lease_id)
        if _atomic_create_json(path, record.to_dict()):
            return True
        existing = self.load_child(record.lease_id)
        if existing == record:
            return False
        raise RuntimeSecurityError("child recovery record conflicts with its replay")

    def load_child(self, lease_id: str) -> ChildRecoveryRecord | None:
        value = _read_secure_json(self.child_path(lease_id))
        if value is None:
            return None
        try:
            record = ChildRecoveryRecord.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeSecurityError(f"invalid child recovery record: {exc}") from exc
        if record.lease_id != lease_id:
            raise RuntimeSecurityError("child recovery filename and lease ID disagree")
        return record

    def replace_child(self, record: ChildRecoveryRecord) -> None:
        _atomic_replace_json(self.child_path(record.lease_id), record.to_dict())

    def list_children(self) -> tuple[ChildRecoveryRecord, ...]:
        result: list[ChildRecoveryRecord] = []
        for path in self._records(self.children, ".json"):
            record = self.load_child(path.name.removesuffix(".json"))
            if record is None:
                raise RuntimeSecurityError(f"recovery record disappeared: {path}")
            result.append(record)
        return tuple(result)

    def delete_child(self, lease_id: str) -> bool:
        return _durable_unlink(self.child_path(lease_id))

    def put_probe(self, record: ProbeRecoveryRecord) -> bool:
        path = self.probe_path(record.probe_id)
        if _atomic_create_json(path, record.to_dict()):
            return True
        existing = self.load_probe(record.probe_id)
        if existing == record:
            return False
        raise RuntimeSecurityError("probe recovery record conflicts with its replay")

    def load_probe(self, probe_id: str) -> ProbeRecoveryRecord | None:
        value = _read_secure_json(self.probe_path(probe_id))
        if value is None:
            return None
        try:
            record = ProbeRecoveryRecord.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeSecurityError(f"invalid probe recovery record: {exc}") from exc
        if record.probe_id != probe_id:
            raise RuntimeSecurityError("probe recovery filename and probe ID disagree")
        return record

    def replace_probe(self, record: ProbeRecoveryRecord) -> None:
        _atomic_replace_json(self.probe_path(record.probe_id), record.to_dict())

    def list_probes(self) -> tuple[ProbeRecoveryRecord, ...]:
        result: list[ProbeRecoveryRecord] = []
        for path in self._records(self.probes, ".json"):
            record = self.load_probe(path.name.removesuffix(".json"))
            if record is None:
                raise RuntimeSecurityError(f"recovery record disappeared: {path}")
            result.append(record)
        return tuple(result)

    def delete_probe(self, probe_id: str) -> bool:
        return _durable_unlink(self.probe_path(probe_id))

    def list_provider_scopes(
        self,
    ) -> tuple[tuple[str, ProviderScopeRecord], ...]:
        return self.provider_scope_store.list_records()


def _token(value: Any, name: str, pattern: re.Pattern[str] = _TOKEN_RE) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise AdmissionError(f"{name}: invalid token")
    return value


def _exact(value: Mapping[str, Any], fields: set[str], name: str) -> None:
    actual = set(value)
    if actual != fields:
        raise AdmissionError(
            f"{name}: keys differ; missing={sorted(fields - actual)!r}, "
            f"unexpected={sorted(actual - fields)!r}"
        )


def _identity(value: Any, name: str) -> ProcessIdentity:
    if type(value) is not dict:
        raise AdmissionError(f"{name}: expected an object")
    _exact(value, {"pid", "pid_start_ticks", "boot_id"}, name)
    try:
        return ProcessIdentity(
            pid=value["pid"],
            start_ticks=value["pid_start_ticks"],
            boot_id=value["boot_id"],
        )
    except (TypeError, ValueError) as exc:
        raise AdmissionError(f"{name}: {exc}") from exc


def _process_parent(pid: int) -> int:
    record = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
    closing = record.rfind(")")
    fields = record[closing + 2 :].split() if closing >= 0 else []
    if len(fields) < 2 or not fields[1].isdecimal():
        raise AdmissionError(f"cannot validate parent for child pid {pid}")
    return int(fields[1])


def _pidfd_matches(pidfd: int, identity: ProcessIdentity) -> bool:
    if not hasattr(os, "pidfd_open") or not process_matches(identity):
        return False
    duplicate = os.pidfd_open(identity.pid, 0)
    try:
        return os.fstat(pidfd) == os.fstat(duplicate)
    finally:
        os.close(duplicate)


def _secure_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise RuntimeSecurityError(f"runtime path is not a real directory: {path}")
    if info.st_uid != os.getuid():
        raise RuntimeSecurityError(f"runtime directory has the wrong owner: {path}")
    os.chmod(path, 0o700, follow_symlinks=False)
    if stat.S_IMODE(path.lstat().st_mode) != 0o700:
        raise RuntimeSecurityError(f"runtime directory mode is not 0700: {path}")


def _publish_json_exclusive(path: Path, payload: Mapping[str, Any]) -> None:
    if not _atomic_create_json(path, payload):
        raise FileExistsError(f"readiness record already exists: {path}")


def _unlink_owned(path: Path, *, allowed: tuple[int, ...]) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if path.is_symlink() or info.st_uid != os.getuid() or stat.S_IFMT(info.st_mode) not in allowed:
        raise RuntimeSecurityError(f"refusing to unlink unowned runtime object: {path}")
    path.unlink()
    return True


@dataclass(slots=True)
class _Lease:
    lease_id: str
    lease_nonce: str
    register_request_id: str
    connection_id: str
    wrapper: ProcessIdentity
    contract_digest: str
    leader_path: Path
    state: str = "PROVISIONAL"
    child: ProcessIdentity | None = None
    child_pidfd: int | None = None
    child_scope: ScopeIdentity | None = None
    child_scope_handle: ScopeHandle | None = None


@dataclass(slots=True)
class _Connection:
    connection_id: str
    peer_pid: int
    peer_uid: int
    socket: socket.socket
    leases: set[str] = field(default_factory=set)
    qualification_pause_id: str | None = None
    qualification_nonce: str | None = None
    qualification_lease_ids: tuple[str, ...] = ()
    qualification_frozen: set[str] = field(default_factory=set)
    qualification_freeze_uncertain: bool = False
    qualification_cleanup_uncertain: bool = False
    qualification_frontend_armed: bool = False
    qualification_fault_in_progress: bool = False
    qualification_deadline_ns: int | None = None
    qualification_forbidden_socket_inodes: dict[str, frozenset[int]] = field(
        default_factory=dict
    )


@dataclass(frozen=True, slots=True)
class _Replay:
    connection_id: str
    fingerprint: str
    response: dict[str, Any]


Qualifier = Callable[
    [Endpoint, ProviderRequest, TransitionDeadline, threading.Event | None],
    QualificationEvidence,
]
HealthCheck = Callable[[ProviderResult], bool]


class Supervisor:
    """One per-user owner epoch with bounded control and provider state."""

    def __init__(
        self,
        control_root: str | os.PathLike[str],
        release_dir: str | os.PathLike[str],
        expected_contract_digest: str,
        *,
        expected_control_cap: int = 32,
        release_id: str | None = None,
        providers: Mapping[str, ProviderAdapter] | None = None,
        qualifier: Qualifier | None = None,
        health_check: HealthCheck | None = None,
        start_watchdog: bool = True,
        watchdog_interval: float = 10.0,
        watchdog_failures: int = 2,
        watchdog_probe_ms: int = 5_000,
        warm_legacy_handoff: bool = False,
        scoped_bootstrap: bool = False,
        process_scopes: ProcessScopeBackend | None = None,
        provider_canary_fd: int | None = None,
    ) -> None:
        self.control_root = Path(control_root)
        self.release_dir = Path(release_dir).resolve(strict=True)
        if _DIGEST_RE.fullmatch(expected_contract_digest) is None:
            raise ValueError("expected_contract_digest must be a lowercase SHA-256 digest")
        self.expected_contract_digest = expected_contract_digest
        if type(expected_control_cap) is not int or not 3 <= expected_control_cap <= 4_096:
            raise ValueError("expected_control_cap must be an integer in [3, 4096]")
        self.expected_control_cap = expected_control_cap
        self.release_id = release_id or _release_id(self.release_dir, os.environ)
        _token(self.release_id, "release_id")
        self._provider_canary_fd: int | None = None
        self._provider_canary_record: dict[str, Any] | None = None
        if type(watchdog_interval) not in (int, float) or watchdog_interval <= 0:
            raise ValueError("watchdog_interval must be positive")
        if type(watchdog_failures) is not int or not 1 <= watchdog_failures <= 100:
            raise ValueError("watchdog_failures must be an integer in [1, 100]")
        if type(watchdog_probe_ms) is not int or not 100 <= watchdog_probe_ms <= 60_000:
            raise ValueError("watchdog_probe_ms must be an integer in [100, 60000]")

        self.runtime = SecureRuntime(self.control_root)
        self.fences: FenceStore | None = None
        self.intents: IntentStore | None = None
        self.recovery: RecoveryStore | None = None
        self.owner = current_process_identity()
        self.owner_epoch = secrets.token_hex(16)
        self.phase = "BOOTSTRAPPING"
        self.contract: RouteContract | None = None
        self.contract_digest: str | None = None
        self.generation = 0
        self.active_result: ProviderResult | None = None
        self.active_adapter: ProviderAdapter | None = None
        self.transition: dict[str, Any] | None = None

        self._provided = dict(providers or {})
        # Production has no pidfd-only fallback.  Tests inject an explicit fake
        # backend through this constructor seam; no environment value selects it.
        self._process_scopes = process_scopes or LinuxCgroupV2Scope()
        self._direct_provider = DirectProvider(
            self.control_root,
            self.release_dir,
            process_scopes=self._process_scopes,
        )
        self._requires_grok_executable = qualifier is None
        self._qualifier = qualifier or self._default_qualifier
        self._health_check = health_check or self._default_health_check
        self._start_watchdog = start_watchdog
        self._watchdog_interval = float(watchdog_interval)
        self._watchdog_failures = watchdog_failures
        self._watchdog_probe_ms = watchdog_probe_ms
        self._warm_legacy_handoff = warm_legacy_handoff
        self._scoped_bootstrap = scoped_bootstrap
        self._detached_scopes: DetachedScopeStore | None = None
        self.frontend: CommittedFrontend | None = None
        self._compatibility_fd: int | None = None
        self._grok_executable: VerifiedGrokExecutable | None = None
        self._listener: socket.socket | None = None
        self._ready_path = self.control_root / "supervisor.ready"
        self._socket_path = self.control_root / "supervisor.sock"
        self._leader_dir = self.control_root / "leaders"
        self._fence_record: FenceRecord | None = None

        self._state_lock = threading.RLock()
        self._transition_lock = threading.Lock()
        self._generation_condition = threading.Condition(self._state_lock)
        self._probe_condition = threading.Condition(self._state_lock)
        self._generation_worker: threading.Thread | None = None
        self._generation_error: BaseException | None = None
        self._stop = threading.Event()
        self._cancel_transition = threading.Event()
        self._leases: dict[str, _Lease] = {}
        self._connections: dict[str, _Connection] = {}
        self._connection_slots = 0
        self._threads: set[threading.Thread] = set()
        self._active_probes: set[str] = set()
        self._watchdog_check_owners: set[int] = set()
        self._replays: OrderedDict[tuple[str, ...], _Replay] = OrderedDict()
        self._diagnostics: deque[dict[str, Any]] = deque(maxlen=_MAX_DIAGNOSTICS)
        self._sequence = 0
        self._authority_activity_sequence = 0
        self._cleanup_proved = False
        self._cleanup_error: str | None = None
        self._lease_cleanup_errors: list[str] = []
        self._bootstrapped = False
        self._bootstrap_attempted = False
        self._finalized = False
        self._preserve_fence_on_abort = False
        self._same_rung_repairs: set[str] = set()
        self._qualification_fault_nonces: set[str] = set()
        self._qualification_connection_id: str | None = None
        self._last_repair: dict[str, Any] | None = None
        try:
            if provider_canary_fd is not None:
                if type(provider_canary_fd) is not int or provider_canary_fd < 3:
                    raise ValueError("provider canary descriptor is unsafe")
                try:
                    self._provider_canary_fd = fcntl.fcntl(
                        provider_canary_fd,
                        fcntl.F_DUPFD_CLOEXEC,
                        3,
                    )
                except OSError as exc:
                    raise ValueError(
                        "provider canary descriptor is not open"
                    ) from exc
                self._provider_canary_record = (
                    self._read_provider_canary_authorization()
                )
            self._legacy_provider = LegacyShellProvider(
                self.control_root,
                self.release_dir,
                process_scopes=self._process_scopes,
                provider_canary_fd=self._provider_canary_fd,
            )
        except BaseException:
            self._close_provider_canary()
            raise

    # ------------------------------------------------------------------ bootstrap

    def bootstrap(self) -> None:
        """Acquire exclusion, recover only provably effect-free state, then listen."""

        if self._bootstrapped:
            raise SupervisorError("supervisor is already bootstrapped")
        if self._bootstrap_attempted:
            raise SupervisorError("a failed supervisor bootstrap is terminal")
        self._bootstrap_attempted = True
        try:
            epoch_scope = self._prepare_bootstrap()
        except Exception:
            self._bootstrap_abort()
            raise
        try:
            existing = self.fences.load()
            if existing is not None:
                if process_can_still_execute(
                    ProcessIdentity(existing.pid, existing.pid_start_ticks, existing.boot_id)
                ):
                    raise FenceBusyError(
                        f"live supervisor epoch {existing.owner_epoch!r} owns the recovery fence"
                    )
                if not self._stale_state_is_effect_free():
                    raise RecoveryRequired(
                        "dead supervisor left uncertain provider or intent state; recovery remains fenced"
                    )
                self._remove_clean_recovery_records()
                self.fences.clear(existing.owner_epoch)
                self._record("recover-stale", result="effect-free")

            self._fence_record = FenceRecord(
                schema_version=SCHEMA_VERSION,
                release_id=self.release_id,
                owner_epoch=self.owner_epoch,
                pid=self.owner.pid,
                pid_start_ticks=self.owner.start_ticks,
                boot_id=self.owner.boot_id,
                phase="BOOTSTRAPPING",
            )
            self.fences.publish(self._fence_record)
            if self._scoped_bootstrap:
                assert epoch_scope is not None
                owned_scope = epoch_scope.with_phase(
                    "OWNED",
                    owner_epoch=self.owner_epoch,
                )
                self._detached_scopes.replace(epoch_scope, owned_scope)
                epoch_scope = owned_scope
                clear_parent_death_signal()
            if self._warm_legacy_handoff:
                try:
                    _run_compatibility_handoff(
                        self.control_root,
                        self.release_dir,
                        self.owner_epoch,
                        self.release_id,
                        process_scopes=self._process_scopes,
                        detached_scopes=self._detached_scopes,
                    )
                except Exception:
                    self._preserve_fence_on_abort = True
                    raise
            self._listener = bind_seqpacket_listener(self._socket_path, backlog=32)
            self._listener.settimeout(0.2)
            ready_record = {
                "schema_version": SCHEMA_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "release_id": self.release_id,
                "owner_epoch": self.owner_epoch,
                "pid": self.owner.pid,
                "pid_start_ticks": self.owner.start_ticks,
                "boot_id": self.owner.boot_id,
                "socket": str(self._socket_path),
            }
            if self._provider_canary_record is not None:
                ready_record["provider_canary_nonce"] = str(
                    self._provider_canary_record["canary_nonce"]
                )
            _publish_json_exclusive(
                self._ready_path,
                ready_record,
            )
            self._bootstrapped = True
            self._record("bootstrap", result="ready")
            if self._start_watchdog:
                thread = threading.Thread(
                    target=self._watchdog_loop,
                    name="grok-supervisor-watchdog",
                    daemon=True,
                )
                with self._state_lock:
                    self._threads.add(thread)
                thread.start()
        except Exception:
            self._bootstrap_abort()
            raise

    def _prepare_bootstrap(self) -> DetachedScopeRecord | None:
        self.runtime.initialize()
        self.runtime.verify()
        _secure_directory(self._leader_dir)
        self.intents = IntentStore(self.runtime)
        self.recovery = RecoveryStore(self.runtime)
        self._detached_scopes = DetachedScopeStore(self.control_root)
        self._direct_provider.bind_scope_store(
            self.recovery.provider_scope_store
        )
        self._legacy_provider.bind_scope_store(
            self.recovery.provider_scope_store
        )
        self.fences = FenceStore(self.runtime)
        epoch_scope: DetachedScopeRecord | None = None
        if self._scoped_bootstrap:
            epoch_scope = self._detached_scopes.load("supervisor-epoch")
            if (
                epoch_scope is None
                or epoch_scope.phase != "ATTACHED"
                or epoch_scope.owner_epoch is not None
                or epoch_scope.release_id != self.release_id
                or epoch_scope.child != self.owner
            ):
                raise RuntimeSecurityError(
                    "scoped supervisor bootstrap authority is absent or mismatched"
                )
        self._acquire_compatibility_lock()
        return epoch_scope

    def _acquire_compatibility_lock(self) -> None:
        path = self.control_root / "compatibility.lock"
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise RuntimeSecurityError("compatibility lock has an unsafe type or owner")
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise FenceBusyError("the stable compatibility lock is already held") from exc
        except Exception:
            os.close(descriptor)
            raise
        self._compatibility_fd = descriptor

    def _stale_state_is_effect_free(self) -> bool:
        assert self.intents is not None and self.recovery is not None
        provider_root = self.control_root / "p"
        if provider_root.exists() or provider_root.is_symlink():
            try:
                if provider_root.is_symlink() or any(provider_root.iterdir()):
                    return False
            except OSError:
                return False
        try:
            entries = tuple(self.intents.directory.iterdir())
        except OSError:
            return False
        for entry in entries:
            if entry.is_symlink() or not entry.name.endswith(".json"):
                return False
            try:
                intent = self.intents.load(entry.name.removesuffix(".json"))
            except (RuntimeSecurityError, ValueError):
                return False
            if intent is None or intent.phase != "CLEANED":
                return False
        try:
            if self.recovery.list_children():
                return False
            if self.recovery.list_probes():
                return False
            if self.recovery.list_provider_scopes():
                return False
            if any(
                record.phase != "CLEANED"
                for record in self.recovery.list_providers()
            ):
                return False
        except (RuntimeSecurityError, OSError, ValueError):
            return False
        if self._detached_scopes is None:
            return False
        try:
            detached = self._detached_scopes.list_records()
        except (RuntimeSecurityError, OSError, ValueError):
            return False
        for record in detached:
            if not (
                self._scoped_bootstrap
                and record.kind == "supervisor-epoch"
                and record.phase == "ATTACHED"
                and record.owner_epoch is None
                and record.release_id == self.release_id
                and record.child == self.owner
            ):
                return False
        for directory in (self.control_root / "qualify", self._leader_dir):
            if not directory.exists() and not directory.is_symlink():
                continue
            try:
                _secure_directory(directory)
                if any(directory.iterdir()):
                    return False
            except (RuntimeSecurityError, OSError):
                return False
        return True

    def _remove_clean_recovery_records(self) -> None:
        assert self.recovery is not None
        if self.recovery.list_children():
            raise RecoveryRequired("attached child records require explicit recovery")
        if self.recovery.list_probes():
            raise RecoveryRequired("probe records require explicit recovery")
        if self.recovery.list_provider_scopes():
            raise RecoveryRequired("provider command scopes require explicit recovery")
        assert self.intents is not None
        for intent in _intent_records(self.intents):
            if intent.phase != "CLEANED" or intent.operation != "provider-start":
                raise RecoveryRequired("provider intents require explicit recovery")
            self.intents.delete(intent.effect_id)
        for record in self.recovery.list_providers():
            if record.phase != "CLEANED":
                raise RecoveryRequired("provider records require explicit recovery")
            self.recovery.delete_provider(record.effect_id)

    def _bootstrap_abort(self) -> None:
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        for path, allowed in (
            (self._ready_path, (stat.S_IFREG,)),
            (self._socket_path, (stat.S_IFSOCK,)),
        ):
            try:
                _unlink_owned(path, allowed=allowed)
            except (RuntimeSecurityError, OSError):
                pass
        if (
            not self._preserve_fence_on_abort
            and self._fence_record is not None
            and self.fences is not None
        ):
            try:
                self.fences.clear(self.owner_epoch)
            except (FenceBusyError, RuntimeSecurityError, OSError):
                pass
        self._release_compatibility_lock()
        try:
            self._close_provider_canary()
        except OSError:
            pass

    # ------------------------------------------------------------------ serving

    def serve_forever(self) -> None:
        if not self._bootstrapped or self._listener is None:
            raise SupervisorError("bootstrap must finish before serve_forever")
        try:
            while not self._stop.is_set():
                try:
                    client, _address = self._listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                client.set_inheritable(False)
                with self._state_lock:
                    cap = (
                        self.contract.limits.max_control_connections
                        if self.contract is not None
                        else self.expected_control_cap
                    )
                    if self._connection_slots >= cap:
                        reject = True
                    else:
                        reject = False
                        self._connection_slots += 1
                if reject:
                    rejected = SeqPacketConnection(client)
                    try:
                        rejected.send(
                            {
                                "ok": False,
                                "error": "control connection capacity exceeded",
                            }
                        )
                    except (ProtocolError, OSError):
                        pass
                    finally:
                        rejected.close()
                    continue
                thread = threading.Thread(
                    target=self._connection_loop,
                    args=(client,),
                    name="grok-supervisor-control",
                    daemon=True,
                )
                with self._state_lock:
                    self._threads.add(thread)
                try:
                    thread.start()
                except Exception:
                    with self._state_lock:
                        self._threads.discard(thread)
                        self._connection_slots -= 1
                    client.close()
                    raise
        finally:
            self._stop.set()
            if self._listener is not None:
                self._listener.close()
            if not self._cleanup_proved and self._leases:
                self._force_shutdown("serve-loop-exit")
            self._join_threads()
            self.finalize()

    def _connection_loop(self, sock: socket.socket) -> None:
        connection = SeqPacketConnection(sock)
        context: _Connection | None = None
        current = threading.current_thread()
        try:
            # An authenticated peer that never sends its first packet cannot
            # reserve a control slot indefinitely.  Lease-bearing connections
            # become blocking only after successful registration.
            sock.settimeout(2.0)
            peer = connection.verify_peer(expected_uid=os.getuid())
            context = _Connection(
                connection_id=secrets.token_hex(12),
                peer_pid=peer.pid,
                peer_uid=peer.uid,
                socket=sock,
            )
            with self._state_lock:
                cap = (
                    self.contract.limits.max_control_connections
                    if self.contract is not None
                    else self.expected_control_cap
                )
                if len(self._connections) >= cap:
                    connection.send(
                        {"ok": False, "error": "control connection capacity exceeded"}
                    )
                    return
                self._connections[context.connection_id] = context

            while not self._stop.is_set():
                if (
                    context.qualification_pause_id is not None
                    and self._qualification_pause_expired(context)
                ):
                    break
                with self._state_lock:
                    if self.contract is not None:
                        connection.max_packet_bytes = self.contract.limits.max_packet_bytes
                try:
                    message = connection.recv()
                except socket.timeout:
                    if context.qualification_pause_id is None:
                        break
                    if self._qualification_pause_expired(context):
                        break
                    continue
                except (ProtocolError, OSError):
                    break
                response = self._handle_message(context, message)
                try:
                    connection.send(response)
                except (ProtocolError, OSError):
                    break
                if context.qualification_pause_id is not None:
                    sock.settimeout(_QUALIFICATION_POLL_SECONDS)
                elif context.leases:
                    sock.settimeout(None)
                if response.get("shutdown") is True:
                    self._stop.set()
                    break
        finally:
            if context is not None:
                self._connection_lost(context)
                with self._state_lock:
                    self._connections.pop(context.connection_id, None)
            connection.close()
            with self._state_lock:
                self._threads.discard(current)
                self._connection_slots -= 1

    def _handle_message(
        self, context: _Connection, message: SeqPacketMessage
    ) -> dict[str, Any]:
        descriptors = list(message.fds)
        payload = message.payload
        replay_key: tuple[str, ...] | None = None
        fingerprint = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        try:
            kind = _token(payload.get("type"), "type")
            if payload.get("schema_version") != SCHEMA_VERSION:
                raise AdmissionError("schema_version mismatch")
            if payload.get("protocol_version") != PROTOCOL_VERSION:
                raise AdmissionError("protocol_version mismatch")
            if kind in {"register", "attach-child", "release"}:
                request_id = _token(payload.get("request_id"), "request_id")
                if kind == "register":
                    replay_key = (kind, request_id)
                else:
                    replay_key = (
                        kind,
                        _token(payload.get("owner_epoch"), "owner_epoch"),
                        _token(payload.get("lease_id"), "lease_id"),
                        request_id,
                    )
                replay = self._lookup_replay(replay_key, context, fingerprint)
                if replay is not None:
                    return replay

            if kind == "register":
                response = self._register(context, payload, descriptors)
            elif kind == "attach-child":
                response = self._attach_child(context, payload, descriptors)
            elif kind == "release":
                response = self._release(context, payload, descriptors)
            elif kind == "status":
                response = self._status(payload, descriptors)
            elif kind == "ip":
                response = self._ip(payload, descriptors)
            elif kind == "qualification-pause":
                response = self._qualification_pause(context, payload, descriptors)
            elif kind == "qualification-set-frozen":
                response = self._qualification_set_frozen(
                    context, payload, descriptors
                )
            elif kind == "qualification-quiesce":
                response = self._qualification_quiesce(
                    context, payload, descriptors
                )
            elif kind == "qualification-disarm":
                response = self._qualification_disarm(
                    context, payload, descriptors
                )
            elif kind == "qualification-provider-fault":
                response = self._qualification_provider_fault(
                    context, payload, descriptors
                )
            else:
                raise AdmissionError(f"unsupported request type {kind!r}")
        except (
            AdmissionError,
            EpochDraining,
            ProviderError,
            FrontendDrainTimeout,
            RuntimeSecurityError,
            OSError,
            ValueError,
        ) as exc:
            safe_error = _diagnostic_text(exc, 512)
            response = {
                "ok": False,
                "error": safe_error,
            }
            if type(payload.get("request_id")) is str:
                response["request_id"] = payload["request_id"]
            self._record(
                "request",
                result="rejected",
                reason=safe_error,
                kind=payload.get("type", ""),
            )
        finally:
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        with self._state_lock:
            if self.phase == "DRAINING":
                response["shutdown"] = True
        if replay_key is not None:
            self._save_replay(replay_key, context, fingerprint, response)
        return response

    def _lookup_replay(
        self,
        key: tuple[str, ...],
        context: _Connection,
        fingerprint: str,
    ) -> dict[str, Any] | None:
        with self._state_lock:
            replay = self._replays.get(key)
            if replay is None:
                return None
            if replay.connection_id != context.connection_id:
                raise AdmissionError("mutating request replay crossed its control connection")
            if replay.fingerprint != fingerprint:
                raise AdmissionError("request_id replay payload differs from the original")
            self._replays.move_to_end(key)
            return dict(replay.response)

    def _save_replay(
        self,
        key: tuple[str, ...],
        context: _Connection,
        fingerprint: str,
        response: dict[str, Any],
    ) -> None:
        with self._state_lock:
            existing = self._replays.get(key)
            record = _Replay(context.connection_id, fingerprint, dict(response))
            if existing is not None and existing != record:
                # Preserve the authoritative first outcome.  A conflicting
                # replay has already received an error and must not replace it.
                return
            self._replays[key] = record
            self._replays.move_to_end(key)
            while len(self._replays) > _MAX_REPLAYS:
                self._replays.popitem(last=False)

    # ------------------------------------------------------------------ protocol

    def _register(
        self,
        context: _Connection,
        payload: dict[str, Any],
        descriptors: list[int],
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "type",
                "schema_version",
                "protocol_version",
                "request_id",
                "lease_nonce",
                "wrapper",
                "contract",
            },
            "register",
        )
        if self._requires_grok_executable:
            if len(descriptors) != 1:
                raise AdmissionError("register requires exactly one Grok executable descriptor")
        elif descriptors:
            raise AdmissionError("register does not accept descriptors with an injected qualifier")
        request_id = _token(payload["request_id"], "request_id")
        nonce = _token(payload["lease_nonce"], "lease_nonce", _NONCE_RE)
        wrapper = _identity(payload["wrapper"], "wrapper")
        if wrapper.pid != context.peer_pid or not process_matches(wrapper):
            raise AdmissionError("wrapper identity does not match the authenticated peer")
        try:
            incoming = RouteContract.from_dict(payload["contract"])
        except (TypeError, ValueError) as exc:
            raise AdmissionError(f"contract: {exc}") from exc
        digest = incoming.digest()
        self._validate_provider_canary_contract(incoming)
        with self._state_lock:
            established = self.contract
        if established is not None:
            differences = established.semantic_differences(incoming)
            if differences:
                raise AdmissionError("contract mismatch: " + ", ".join(differences))
        else:
            if digest != self.expected_contract_digest:
                raise AdmissionError(
                    f"contract mismatch: expected digest {self.expected_contract_digest}, received {digest}"
                )
            if incoming.release_id != self.release_id:
                raise AdmissionError(
                    f"contract mismatch: release_id expected {self.release_id!r}, received {incoming.release_id!r}"
                )
            if incoming.limits.max_control_connections != self.expected_control_cap:
                raise AdmissionError(
                    "contract mismatch: bootstrap control cap differs from the canonical contract"
                )

        candidate: VerifiedGrokExecutable | None = None
        if self._requires_grok_executable:
            duplicate = os.dup(descriptors[0])
            try:
                candidate = VerifiedGrokExecutable.adopt(
                    duplicate,
                    incoming.grok_release_id,
                )
            except (GrokExecutableError, OSError) as exc:
                os.close(duplicate)
                raise AdmissionError(f"Grok executable descriptor: {exc}") from exc

        try:
            with self._state_lock:
                if self.phase == "DRAINING":
                    raise EpochDraining("supervisor epoch is draining")
                if self._qualification_connection_id is not None:
                    raise AdmissionError(
                        "qualification has closed lease admission for this epoch"
                    )
                if context.leases:
                    raise AdmissionError("one control connection may own only one lease")
                if self.contract is not None:
                    differences = self.contract.semantic_differences(incoming)
                    if differences:
                        raise AdmissionError("contract mismatch: " + ", ".join(differences))
                    contract = self.contract
                else:
                    if self._requires_grok_executable and candidate is None:
                        raise AdmissionError("first contract has no verified Grok executable")
                    contract = incoming
                    self.contract = incoming
                    self.contract_digest = digest
                    self._grok_executable = candidate
                    candidate = None
                if len(self._leases) >= contract.limits.max_leases:
                    raise AdmissionError("lease capacity exceeded")
                lease_id = secrets.token_hex(16)
                while lease_id in self._leases:
                    lease_id = secrets.token_hex(16)
                leader = self._new_leader_path()
                lease = _Lease(
                    lease_id=lease_id,
                    lease_nonce=nonce,
                    register_request_id=request_id,
                    connection_id=context.connection_id,
                    wrapper=wrapper,
                    contract_digest=digest,
                    leader_path=leader,
                )
                self._leases[lease_id] = lease
                context.leases.add(lease_id)
                self._record_locked("lease-register", result="provisional", lease_id=lease_id)
        finally:
            if candidate is not None:
                candidate.close()

        try:
            self._ensure_generation(lease_id)
        except Exception as primary:
            last = self._drop_lease(
                lease_id,
                terminate=False,
                linearize_reason="register-failed",
            )
            with self._state_lock:
                last = last or not self._leases
            try:
                self._drain_if_idle("register-failed")
            except ProviderError as drain_error:
                # Draining is still mandatory, but its aggregate residue must
                # not hide the transition failure that explains why exact
                # cleanup could not be proved in the first place.
                raise ProviderResidueError(
                    f"{primary}; drain residue: {drain_error}"
                ) from primary
            if last:
                self._stop.set()
            raise

        with self._state_lock:
            lease = self._leases.get(lease_id)
            if lease is None or self.phase == "DRAINING" or self.active_result is None:
                raise EpochDraining("lease lost interest before provider commit")
            assert self.contract is not None
            return {
                "ok": True,
                "type": "registered",
                "request_id": request_id,
                "owner_epoch": self.owner_epoch,
                "lease_id": lease_id,
                "leader_path": str(lease.leader_path),
                "public_endpoint": self.contract.public_endpoint.to_dict(),
                "contract_digest": lease.contract_digest,
                "state": "provisional",
            }

    def _attach_child(
        self,
        context: _Connection,
        payload: dict[str, Any],
        descriptors: list[int],
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "type",
                "schema_version",
                "protocol_version",
                "owner_epoch",
                "lease_id",
                "request_id",
                "child",
            },
            "attach-child",
        )
        if len(descriptors) != 1:
            raise AdmissionError("attach-child requires exactly one pidfd")
        owner_epoch = _token(payload["owner_epoch"], "owner_epoch")
        lease_id = _token(payload["lease_id"], "lease_id")
        request_id = _token(payload["request_id"], "request_id")
        child = _identity(payload["child"], "child")
        if owner_epoch != self.owner_epoch:
            raise AdmissionError("stale owner epoch")
        with self._state_lock:
            lease = self._leases.get(lease_id)
            if lease is None or lease.connection_id != context.connection_id:
                raise AdmissionError("lease does not belong to this control connection")
            if lease.state != "PROVISIONAL":
                raise AdmissionError("lease is not provisional")
            wrapper_pid = lease.wrapper.pid
        if not process_matches(child):
            raise AdmissionError("child identity is not live")
        if _process_parent(child.pid) != wrapper_pid:
            raise AdmissionError("child parent does not match the registered wrapper")
        pidfd = descriptors[0]
        if not _pidfd_matches(pidfd, child):
            raise AdmissionError("transferred pidfd does not match the child identity")
        if self.recovery is None:
            raise RuntimeSecurityError("child recovery store is unavailable")
        planned_scope = self._process_scopes.plan()
        child_record = ChildRecoveryRecord(
            schema_version=SCHEMA_VERSION,
            record_version=_CHILD_RECOVERY_RECORD_VERSION,
            release_id=self.release_id,
            owner_epoch=self.owner_epoch,
            lease_id=lease_id,
            phase="PREPARED",
            child=child,
            leader_path=str(lease.leader_path),
            scope=planned_scope,
        )
        # Durable intent precedes mkdir, PID migration, and the ACK which
        # releases the child barrier.  Each later record is fsync+rename durable.
        self.recovery.put_child(child_record)
        scope_handle: ScopeHandle | None = None
        try:
            scope_handle = self._process_scopes.create(planned_scope)
            child_record = replace(
                child_record,
                phase="SCOPE_CREATED",
                scope=scope_handle.identity,
            )
            self.recovery.replace_child(child_record)
            self._process_scopes.attach(scope_handle, child)
            child_record = replace(child_record, phase="ATTACHED")
            self.recovery.replace_child(child_record)
            with self._state_lock:
                lease = self._leases.get(lease_id)
                if lease is None or lease.connection_id != context.connection_id:
                    raise AdmissionError("lease disappeared during child attachment")
                if self.phase == "DRAINING" or self.active_result is None:
                    raise EpochDraining("provider is not committed")
                # Diagnostics are written while the lock still hides the state
                # transition.  Once this returns, the remaining assignments and
                # descriptor transfer are deliberately non-throwing.
                self._record_locked("child-attach", result="acknowledged", lease_id=lease_id)
                descriptors.pop(0)
                lease.child = child
                lease.child_pidfd = pidfd
                lease.child_scope = child_record.scope
                lease.child_scope_handle = scope_handle
                lease.state = "LIVE"
                scope_handle = None  # the lease now owns this descriptor
        except BaseException as exc:
            cleanup_error: BaseException | None = None
            try:
                self._process_scopes.reconcile(
                    child_record.scope,
                    child_record.phase,
                    child,
                    pidfd,
                    self._child_stop_seconds(),
                    handle=scope_handle,
                )
            except BaseException as cleanup:
                cleanup_error = cleanup
            finally:
                if scope_handle is not None:
                    scope_handle.close()
            if cleanup_error is None:
                try:
                    self.recovery.delete_child(lease_id)
                except BaseException as cleanup:
                    cleanup_error = cleanup
            if cleanup_error is not None:
                detail = f"child scope attachment cleanup is uncertain: {cleanup_error}"
                with self._state_lock:
                    self._lease_cleanup_errors.append(detail)
                    self._record_locked(
                        "child-attach",
                        result="residue",
                        reason=detail,
                        lease_id=lease_id,
                    )
                self._preserve_fence_on_abort = True
                raise ScopeError(detail) from exc
            raise
        return {
            "ok": True,
            "type": "attached",
            "request_id": request_id,
            "owner_epoch": self.owner_epoch,
            "lease_id": lease_id,
            "state": "live",
        }

    def _release(
        self,
        context: _Connection,
        payload: dict[str, Any],
        descriptors: list[int],
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "type",
                "schema_version",
                "protocol_version",
                "owner_epoch",
                "lease_id",
                "request_id",
                "child_status",
            },
            "release",
        )
        if descriptors:
            raise AdmissionError("release does not accept file descriptors")
        if payload["owner_epoch"] != self.owner_epoch:
            raise AdmissionError("stale owner epoch")
        lease_id = _token(payload["lease_id"], "lease_id")
        request_id = _token(payload["request_id"], "request_id")
        status_value = payload["child_status"]
        if type(status_value) is not int or not 0 <= status_value <= 255:
            raise AdmissionError("child_status must be an integer in [0, 255]")
        with self._state_lock:
            lease = self._leases.get(lease_id)
            if lease is None or lease.connection_id != context.connection_id:
                raise AdmissionError("lease does not belong to this control connection")
            if lease.child is not None and process_matches(lease.child):
                raise AdmissionError("cannot release a still-live child")
        last = self._drop_lease(
            lease_id,
            terminate=False,
            linearize_reason="last-release",
        )
        shutdown = False
        if last:
            self._drain_epoch()
            shutdown = self._cleanup_proved
        return {
            "ok": True,
            "type": "released",
            "request_id": request_id,
            "owner_epoch": self.owner_epoch,
            "lease_id": lease_id,
            "child_status": status_value,
            "shutdown": shutdown,
        }

    def _status(self, payload: dict[str, Any], descriptors: list[int]) -> dict[str, Any]:
        _exact(
            payload,
            {"type", "schema_version", "protocol_version", "request_id"},
            "status",
        )
        if descriptors:
            raise AdmissionError("status does not accept file descriptors")
        request_id = _token(payload["request_id"], "request_id")
        return {
            "ok": True,
            "type": "status",
            "request_id": request_id,
            "status": self.status_snapshot(),
        }

    def _ip(self, payload: dict[str, Any], descriptors: list[int]) -> dict[str, Any]:
        _exact(
            payload,
            {"type", "schema_version", "protocol_version", "request_id"},
            "ip",
        )
        if descriptors:
            raise AdmissionError("ip does not accept file descriptors")
        request_id = _token(payload["request_id"], "request_id")
        with self._state_lock:
            egress = (
                self.active_result.qualification.exit_identity
                if self.active_result is not None
                else ""
            )
        return {
            "ok": True,
            "type": "ip",
            "request_id": request_id,
            "egress_ip": egress,
        }

    @staticmethod
    def _release_control_root() -> tuple[Path, int]:
        if os.environ.get("GROK_TESTING") == "1":
            raw = os.environ.get("GROK_TEST_ROOT_RELEASE_CONTROL")
            if raw is not None:
                candidate = Path(raw)
                if not candidate.is_absolute():
                    raise AdmissionError("test release-control root is not absolute")
                return candidate, os.getuid()
        return Path("/var/lib/grok-proxy/release-control"), 0

    @staticmethod
    def _host_id() -> str:
        try:
            raw = Path("/etc/machine-id").read_text(encoding="ascii").strip()
        except OSError as exc:
            raise AdmissionError("cannot read the host qualification identity") from exc
        if re.fullmatch(r"[0-9a-f]{32}", raw) is None:
            raise AdmissionError("host qualification identity is invalid")
        return hashlib.sha256(raw.encode("ascii")).hexdigest()

    def _read_provider_canary_authorization(self) -> dict[str, Any]:
        descriptor = self._provider_canary_fd
        if descriptor is None:
            raise AdmissionError("provider canary descriptor is absent")
        root, expected_uid = self._release_control_root()
        try:
            actual = os.fstat(descriptor)
            expected = (root / "canary-auth.lock").lstat()
            deny = read_secure_json(
                root / "rollback-deny.json",
                expected_uid=expected_uid,
                expected_mode=0o444,
                maximum=65_536,
            )
            record = read_secure_json(
                root / "rung-canary.json",
                expected_uid=expected_uid,
                expected_mode=0o444,
                maximum=65_536,
            )
        except (OSError, SecureFileError) as exc:
            raise AdmissionError(
                "cannot inspect provider canary authorization"
            ) from exc
        if (
            not stat.S_ISREG(actual.st_mode)
            or not stat.S_ISREG(expected.st_mode)
            or actual.st_uid != expected_uid
            or expected.st_uid != expected_uid
            or stat.S_IMODE(actual.st_mode) != 0o600
            or stat.S_IMODE(expected.st_mode) != 0o600
            or (actual.st_dev, actual.st_ino)
            != (expected.st_dev, expected.st_ino)
        ):
            raise AdmissionError(
                "provider canary descriptor is not the fixed authorization"
            )
        if (
            set(deny)
            != {"schema_version", "operation", "from_release", "to_release"}
            or deny.get("schema_version") != 1
            or deny.get("operation") != "canary"
            or deny.get("from_release") != self.release_id
            or deny.get("to_release") != self.release_id
        ):
            raise AdmissionError("provider canary deny ledger is not exact")
        fields = {
            "schema_version", "release_id", "host_id", "canary_kind", "rung",
            "contract_sha256", "grok_release_id", "model_id", "canary_nonce",
            "created_unix_ns", "route_profile", "profile_sha256",
        }
        rung = record.get("rung")
        route_profile = record.get("route_profile")
        if (
            set(record) != fields
            or record.get("schema_version") != _RUNG_CANARY_SCHEMA_VERSION
            or record.get("release_id") != self.release_id
            or record.get("host_id") != self._host_id()
            or record.get("canary_kind") != "rung"
            or type(rung) is not str
            or rung == "direct"
            or not (
                rung == "vpn"
                or _HOME_RUNG_RE.fullmatch(rung) is not None
                or _IOS_RUNG_RE.fullmatch(rung) is not None
            )
            or type(route_profile) is not str
            or not (
                route_profile in {rung, "auto", "auto-no-direct"}
                or (_IOS_RUNG_RE.fullmatch(rung) is not None and route_profile == "iphone")
            )
            or type(record.get("contract_sha256")) is not str
            or _DIGEST_RE.fullmatch(record["contract_sha256"]) is None
            or type(record.get("grok_release_id")) is not str
            or _GROK_RELEASE_RE.fullmatch(record["grok_release_id"]) is None
            or type(record.get("model_id")) is not str
            or _MODEL_RE.fullmatch(record["model_id"]) is None
            or type(record.get("canary_nonce")) is not str
            or _CANARY_NONCE_RE.fullmatch(record["canary_nonce"]) is None
            or type(record.get("created_unix_ns")) is not int
            or record.get("created_unix_ns", 0) <= 0
            or not (
                record.get("profile_sha256") is None
                or _DIGEST_RE.fullmatch(str(record.get("profile_sha256")))
                is not None
            )
        ):
            raise AdmissionError("provider canary authorization record is invalid")
        return dict(record)

    def _validate_provider_canary_contract(
        self,
        contract: RouteContract,
    ) -> None:
        if self._provider_canary_fd is None:
            return
        current = self._read_provider_canary_authorization()
        if current != self._provider_canary_record:
            raise AdmissionError("provider canary authorization changed")
        try:
            original = reconstruct_original_contract(contract)
        except ValueError as exc:
            raise AdmissionError(
                "provider canary contract cannot reconstruct its original"
            ) from exc
        rung = str(current["rung"])
        if (
            contract.ladder != (rung,)
            or rung not in original.ladder
            or current["contract_sha256"] != original.digest()
            or current["grok_release_id"] != original.grok_release_id
            or current["model_id"] != original.model_id
            or current["release_id"] != original.release_id
            or not qualification_route_profile_matches(
                original,
                str(current["route_profile"]),
                rung,
            )
        ):
            raise AdmissionError(
                "provider canary is not bound to the first contract"
            )

    def _close_provider_canary(self) -> None:
        descriptor = self._provider_canary_fd
        self._provider_canary_fd = None
        self._provider_canary_record = None
        legacy = getattr(self, "_legacy_provider", None)
        if legacy is not None:
            legacy.revoke_provider_canary()
        if descriptor is not None:
            os.close(descriptor)

    def _qualification_authorization(
        self,
        descriptor: int,
        nonce: str,
    ) -> tuple[dict[str, Any], RouteContract, ProviderResult]:
        root, expected_uid = self._release_control_root()
        try:
            actual = os.fstat(descriptor)
            expected = (root / "canary-auth.lock").lstat()
        except OSError as exc:
            raise AdmissionError("cannot inspect the fixed canary authorization") from exc
        if (
            not stat.S_ISREG(actual.st_mode)
            or not stat.S_ISREG(expected.st_mode)
            or actual.st_uid != expected_uid
            or expected.st_uid != expected_uid
            or stat.S_IMODE(actual.st_mode) != 0o600
            or stat.S_IMODE(expected.st_mode) != 0o600
            or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            raise AdmissionError("qualification descriptor is not the fixed authorization")
        try:
            record = read_secure_json(
                root / "rung-canary.json",
                expected_uid=expected_uid,
                expected_mode=0o444,
                maximum=65_536,
            )
        except (OSError, SecureFileError) as exc:
            raise AdmissionError("cannot read the exact rung-canary authorization") from exc
        fields = {
            "schema_version", "release_id", "host_id", "canary_kind", "rung",
            "contract_sha256", "grok_release_id", "model_id", "canary_nonce",
            "created_unix_ns", "route_profile", "profile_sha256",
        }
        with self._state_lock:
            contract = self.contract
            active = self.active_result
            phase = self.phase
        try:
            original = (
                reconstruct_original_contract(contract)
                if contract is not None
                else None
            )
        except ValueError as exc:
            raise AdmissionError(
                "active runtime contract cannot reconstruct its authorized original"
            ) from exc
        if (
            set(record) != fields
            or record.get("schema_version") != _RUNG_CANARY_SCHEMA_VERSION
            or record.get("release_id") != self.release_id
            or record.get("host_id") != self._host_id()
            or record.get("canary_kind") != "rung"
            or record.get("canary_nonce") != nonce
            or type(record.get("created_unix_ns")) is not int
            or record.get("created_unix_ns", 0) <= 0
            or not (
                record.get("profile_sha256") is None
                or _DIGEST_RE.fullmatch(str(record.get("profile_sha256")))
                is not None
            )
            or contract is None
            or active is None
            or phase != "READY"
            or record.get("rung") != active.request.rung
            or contract.ladder != (record.get("rung"),)
            or original is None
            or record.get("rung") not in original.ladder
            or record.get("contract_sha256") != original.digest()
            or not qualification_route_profile_matches(
                original,
                str(record.get("route_profile")),
                str(record.get("rung")),
            )
            or record.get("grok_release_id") != original.grok_release_id
            or record.get("model_id") != original.model_id
            or _GROK_RELEASE_RE.fullmatch(str(record.get("grok_release_id"))) is None
            or _MODEL_RE.fullmatch(str(record.get("model_id"))) is None
        ):
            raise AdmissionError("qualification authorization is not exact for the active rung")
        return record, contract, active

    @staticmethod
    def _qualification_frontend_snapshot(
        frontend: CommittedFrontend | None,
    ) -> dict[str, int | None]:
        if frontend is None:
            raise AdmissionError("qualification has no committed frontend")
        gauges = frontend.gauges()
        values = {
            "committed_generation": gauges.committed_generation,
            "active_streams": gauges.active_streams,
            "accepted_streams": gauges.accepted_streams,
            "backend_connected_streams": gauges.backend_connected_streams,
            "client_to_backend_bytes": gauges.client_to_backend_bytes,
            "backend_to_client_bytes": gauges.backend_to_client_bytes,
        }
        if (
            values["committed_generation"] is not None
            and (
                type(values["committed_generation"]) is not int
                or values["committed_generation"] < 1
            )
        ) or any(
            type(value) is not int or value < 0
            for name, value in values.items()
            if name != "committed_generation"
        ):
            raise AdmissionError("qualification frontend counters are invalid")
        return values

    @staticmethod
    def _qualification_stream_state(
        frontend: CommittedFrontend | None,
    ) -> dict[str, Any]:
        if frontend is None:
            raise AdmissionError("qualification has no committed frontend")
        value = frontend.qualification_state()
        if type(value) is not dict or set(value) != {
            "response_hold", "accept_cursor", "quiesce_epoch", "streams",
        }:
            raise AdmissionError("qualification stream state is not exact")
        if (
            type(value["response_hold"]) is not bool
            or type(value["accept_cursor"]) is not int
            or value["accept_cursor"] < 0
            or type(value["quiesce_epoch"]) is not int
            or value["quiesce_epoch"] < 0
            or type(value["streams"]) is not list
            or len(value["streams"]) > 2
        ):
            raise AdmissionError("qualification stream state is invalid")
        fields = {
            "stream_id", "generation", "socks_state",
            "client_to_backend_bytes", "backend_to_client_bytes",
            "application_client_to_backend_bytes",
            "application_backend_to_client_bytes",
        }
        stream_ids: set[int] = set()
        for stream in value["streams"]:
            if type(stream) is not dict or set(stream) != fields:
                raise AdmissionError("qualification stream transcript is not exact")
            if (
                type(stream["stream_id"]) is not int
                or stream["stream_id"] < 1
                or stream["stream_id"] in stream_ids
                or type(stream["generation"]) is not int
                or stream["generation"] < 1
                or stream["socks_state"] not in {
                    "client-greeting", "server-method", "client-request",
                    "server-reply", "complete", "invalid",
                }
                or any(
                    type(stream[name]) is not int or stream[name] < 0
                    for name in fields - {
                        "stream_id", "generation", "socks_state"
                    }
                )
                or stream["application_client_to_backend_bytes"]
                > stream["client_to_backend_bytes"]
                or stream["application_backend_to_client_bytes"]
                > stream["backend_to_client_bytes"]
            ):
                raise AdmissionError("qualification stream transcript is invalid")
            stream_ids.add(stream["stream_id"])
        return value

    @staticmethod
    def _qualification_receipts_ready(
        state: Mapping[str, Any], generation: int, count: int
    ) -> bool:
        streams = state.get("streams")
        return (
            state.get("response_hold") is True
            and type(streams) is list
            and len(streams) == count
            and all(
                stream.get("generation") == generation
                and stream.get("socks_state") == "complete"
                and stream.get("application_client_to_backend_bytes", 0) > 0
                and stream.get("application_backend_to_client_bytes") == 0
                for stream in streams
            )
        )

    def _qualification_stream_bindings(
        self,
        context: _Connection,
        state: Mapping[str, Any],
    ) -> tuple[
        dict[int, tuple[str, int]],
        dict[str, frozenset[int]],
    ]:
        if self.frontend is None:
            raise AdmissionError("qualification has no committed frontend")
        deadline = context.qualification_deadline_ns
        if deadline is None or time.monotonic_ns() >= deadline:
            raise AdmissionError("qualification TCP ownership deadline expired")
        peers = self.frontend.qualification_peers()
        streams = state.get("streams")
        if (
            type(streams) is not list
            or set(peers)
            != {stream.get("stream_id") for stream in streams}
        ):
            raise AdmissionError(
                "qualification TCP identities differ from active streams"
            )
        scope_inodes: dict[str, frozenset[int]] = {}
        for lease_id in context.qualification_lease_ids:
            lease = self._leases.get(lease_id)
            if lease is None or lease.child_scope_handle is None:
                raise AdmissionError(
                    "qualification TCP ownership lost a lease scope"
                )
            scope_inodes[lease_id] = self._process_scopes.frozen_socket_inodes(
                lease.child_scope_handle, deadline
            )
        bindings: dict[int, tuple[str, int]] = {}
        for stream_id, endpoint in peers.items():
            inode = self._process_scopes.tcp_connection_inode(
                *endpoint, deadline
            )
            if inode is None:
                raise AdmissionError(
                    "qualification stream has no exact established TCP identity"
                )
            claims: list[str] = []
            for lease_id, owned_inodes in scope_inodes.items():
                if inode in owned_inodes:
                    claims.append(lease_id)
            if len(claims) != 1:
                raise AdmissionError(
                    "qualification stream is not owned by one exact lease scope"
                )
            bindings[stream_id] = (claims[0], inode)
        if time.monotonic_ns() >= deadline:
            raise AdmissionError("qualification TCP ownership deadline expired")
        return bindings, scope_inodes

    def _clear_qualification_context_locked(self, context: _Connection) -> None:
        if self._qualification_connection_id == context.connection_id:
            self._qualification_connection_id = None
        context.qualification_pause_id = None
        context.qualification_nonce = None
        context.qualification_lease_ids = ()
        context.qualification_frozen.clear()
        context.qualification_freeze_uncertain = False
        context.qualification_cleanup_uncertain = False
        context.qualification_frontend_armed = False
        context.qualification_fault_in_progress = False
        context.qualification_deadline_ns = None
        context.qualification_forbidden_socket_inodes.clear()

    def _qualification_operation_timeout(self, context: _Connection) -> float:
        deadline = context.qualification_deadline_ns
        if deadline is None:
            raise ScopeResidueError("qualification operation lost its deadline")
        remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise ScopeResidueError("qualification operation exceeded its deadline")
        return min(self._child_stop_seconds(), remaining)

    def _release_qualification_pause(
        self,
        context: _Connection,
        *,
        reason: str,
    ) -> None:
        errors: list[str] = (
            ["a qualification freeze rollback was uncertain"]
            if context.qualification_freeze_uncertain
            else []
        )
        if context.qualification_cleanup_uncertain:
            errors.append("a guarded qualification lease cleanup was uncertain")
        if context.qualification_fault_in_progress:
            errors.append("qualification lost its guard during provider repair")
        with self._state_lock:
            if self._qualification_connection_id != context.connection_id:
                self._clear_qualification_context_locked(context)
                return
            for lease_id in tuple(context.qualification_frozen):
                lease = self._leases.get(lease_id)
                if lease is None:
                    context.qualification_frozen.discard(lease_id)
                    continue
                handle = lease.child_scope_handle
                if handle is None:
                    errors.append("a frozen qualification lease lost its scope handle")
                    continue
                try:
                    self._process_scopes.thaw(
                        handle,
                        self._child_stop_seconds(),
                    )
                except BaseException as exc:
                    errors.append(_diagnostic_text(exc, 256))
                else:
                    context.qualification_frozen.discard(lease_id)
            if errors:
                self._preserve_fence_on_abort = True
            if self.phase != "DRAINING":
                self.phase = "DRAINING"
                self.generation += 1
                self._cancel_transition.set()
                try:
                    self._set_fence_phase("DRAINING")
                except BaseException as exc:
                    errors.append(
                        "cannot durably mark the terminal qualification "
                        f"drain: {_diagnostic_text(exc, 256)}"
                    )
                    self._preserve_fence_on_abort = True
            if errors:
                self._record_locked(
                    "qualification-pause",
                    result="thaw-uncertain",
                    reason=reason,
                )
            else:
                self._record_locked(
                    "qualification-pause",
                    result="terminal-drain",
                    reason=reason,
                )
            self._clear_qualification_context_locked(context)
        try:
            self._force_shutdown(
                "qualification-thaw-uncertain"
                if errors
                else "qualification-guard-released"
            )
        finally:
            self._stop.set()
        if errors:
            raise ScopeError("qualification thaw was uncertain; epoch forced to drain")

    def _qualification_pause_expired(self, context: _Connection) -> bool:
        with self._state_lock:
            deadline = context.qualification_deadline_ns
            expired = deadline is not None and time.monotonic_ns() >= deadline
        if not expired:
            return False
        try:
            self._release_qualification_pause(context, reason="deadline")
        except ScopeError:
            pass
        return True

    def _qualification_pause(
        self,
        context: _Connection,
        payload: dict[str, Any],
        descriptors: list[int],
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "type", "schema_version", "protocol_version", "request_id",
                "owner_epoch", "canary_nonce", "deadline_monotonic_ns",
                "wrappers",
            },
            "qualification-pause",
        )
        if len(descriptors) != 1:
            raise AdmissionError(
                "qualification-pause requires one authorization descriptor"
            )
        request_id = _token(payload["request_id"], "request_id")
        if payload["owner_epoch"] != self.owner_epoch:
            raise AdmissionError("stale qualification owner epoch")
        nonce = _token(
            payload["canary_nonce"], "canary_nonce", _CANARY_NONCE_RE
        )
        deadline_monotonic_ns = payload["deadline_monotonic_ns"]
        now_monotonic_ns = time.monotonic_ns()
        if (
            type(deadline_monotonic_ns) is not int
            or deadline_monotonic_ns
            < now_monotonic_ns + _QUALIFICATION_HOLD_MIN_MS * 1_000_000
            or deadline_monotonic_ns
            > now_monotonic_ns + _QUALIFICATION_HOLD_MAX_MS * 1_000_000
        ):
            raise AdmissionError("qualification hold deadline is outside its fixed bound")
        raw_wrappers = payload["wrappers"]
        if type(raw_wrappers) is not list or len(raw_wrappers) != 2:
            raise AdmissionError("qualification-pause requires exactly two wrappers")
        wrappers = tuple(
            _identity(value, f"wrappers[{index}]")
            for index, value in enumerate(raw_wrappers)
        )
        if len(set(wrappers)) != 2:
            raise AdmissionError("qualification wrappers are not unique")
        _record, contract, authorized_active = self._qualification_authorization(
            descriptors[0], nonce
        )
        installed = False
        try:
            with self._probe_condition:
                while self._active_probes or self._watchdog_check_owners:
                    remaining = (
                        deadline_monotonic_ns - time.monotonic_ns()
                    ) / 1_000_000_000
                    if remaining <= 0:
                        raise AdmissionError(
                            "qualification-pause could not quiesce live probes"
                        )
                    self._probe_condition.wait(min(0.1, remaining))
                if context.leases or context.qualification_pause_id is not None:
                    raise AdmissionError(
                        "qualification-pause requires a dedicated control connection"
                    )
                if self._qualification_connection_id is not None:
                    raise AdmissionError("a qualification admission fence already exists")
                if (
                    self.phase != "READY"
                    or self.transition is not None
                    or self.active_result is not authorized_active
                    or self.contract is not contract
                    or len(self._leases) != 2
                ):
                    raise AdmissionError(
                        "qualification-pause requires one exact two-lease READY epoch"
                    )
                by_wrapper = {lease.wrapper: lease for lease in self._leases.values()}
                if len(by_wrapper) != 2 or set(by_wrapper) != set(wrappers):
                    raise AdmissionError(
                        "qualification wrappers do not equal the complete live lease set"
                    )
                ordered = tuple(by_wrapper[wrapper] for wrapper in wrappers)
                for lease in ordered:
                    if (
                        lease.state != "LIVE"
                        or lease.child is None
                        or lease.child_pidfd is None
                        or lease.child_scope is None
                        or lease.child_scope_handle is None
                        or not process_matches(lease.wrapper)
                        or not process_matches(lease.child)
                        or _process_parent(lease.wrapper.pid) != context.peer_pid
                        or _process_parent(lease.child.pid) != lease.wrapper.pid
                        or not _pidfd_matches(lease.child_pidfd, lease.child)
                    ):
                        raise AdmissionError(
                            "qualification lease is not bound to its exact verifier child"
                        )
                frontend_before = self._qualification_frontend_snapshot(self.frontend)
                if (
                    frontend_before["committed_generation"]
                    != authorized_active.request.generation
                    or frontend_before["active_streams"] != 0
                ):
                    raise AdmissionError(
                        "qualification children did not remain at their pre-exec holds"
                    )
                stream_before = self._qualification_stream_state(self.frontend)
                if stream_before != {
                    "response_hold": False,
                    "accept_cursor": 0,
                    "quiesce_epoch": 0,
                    "streams": [],
                }:
                    raise AdmissionError(
                        "qualification frontend is not one untouched empty generation"
                    )
                pause_id = secrets.token_hex(16)
                context.qualification_pause_id = pause_id
                context.qualification_nonce = nonce
                context.qualification_lease_ids = tuple(
                    lease.lease_id for lease in ordered
                )
                context.qualification_deadline_ns = deadline_monotonic_ns
                self._qualification_connection_id = context.connection_id
                installed = True
                assert self.frontend is not None
                armed_generation = self.frontend.qualification_arm()
                if armed_generation.generation != authorized_active.request.generation:
                    raise AdmissionError(
                        "qualification response hold armed the wrong generation"
                    )
                context.qualification_frontend_armed = True
                for lease in ordered:
                    assert lease.child_scope_handle is not None
                    try:
                        self._process_scopes.freeze(
                            lease.child_scope_handle,
                            self._qualification_operation_timeout(context),
                        )
                    except ScopeResidueError:
                        context.qualification_freeze_uncertain = True
                        raise
                    context.qualification_frozen.add(lease.lease_id)
                bindings = [
                    {
                        "lease_id": lease.lease_id,
                        "wrapper": _identity_to_dict(lease.wrapper),
                        "child": _identity_to_dict(lease.child),
                        "leader_path": str(lease.leader_path),
                        "scope": lease.child_scope.to_dict(),
                    }
                    for lease in ordered
                    if lease.child is not None and lease.child_scope is not None
                ]
                self._record_locked(
                    "qualification-pause",
                    result="frozen",
                    generation=authorized_active.request.generation,
                )
                return {
                    "ok": True,
                    "type": "qualification-pause",
                    "request_id": request_id,
                    "owner_epoch": self.owner_epoch,
                    "pause_id": pause_id,
                    "generation": authorized_active.request.generation,
                    "deadline_monotonic_ns": context.qualification_deadline_ns,
                    "bindings": bindings,
                    "frontend": frontend_before,
                    "qualification": self._qualification_stream_state(
                        self.frontend
                    ),
                }
        except BaseException as primary:
            if installed:
                try:
                    self._release_qualification_pause(
                        context, reason="pause-failed"
                    )
                except BaseException as cleanup:
                    raise ScopeError(
                        "qualification pause failed and thaw was uncertain"
                    ) from cleanup
            raise primary

    def _qualification_set_frozen(
        self,
        context: _Connection,
        payload: dict[str, Any],
        descriptors: list[int],
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "type", "schema_version", "protocol_version", "request_id",
                "owner_epoch", "canary_nonce", "pause_id", "wrapper",
                "frozen", "expected_generation",
            },
            "qualification-set-frozen",
        )
        if descriptors:
            raise AdmissionError(
                "qualification-set-frozen does not accept descriptors"
            )
        request_id = _token(payload["request_id"], "request_id")
        if payload["owner_epoch"] != self.owner_epoch:
            raise AdmissionError("stale qualification owner epoch")
        nonce = _token(
            payload["canary_nonce"], "canary_nonce", _CANARY_NONCE_RE
        )
        pause_id = _token(payload["pause_id"], "pause_id", _NONCE_RE)
        wrapper = _identity(payload["wrapper"], "wrapper")
        frozen = payload["frozen"]
        expected_generation = payload["expected_generation"]
        if type(frozen) is not bool or type(expected_generation) is not int:
            raise AdmissionError("qualification freeze request has invalid state")
        try:
            with self._state_lock:
                if (
                    self._qualification_connection_id != context.connection_id
                    or context.qualification_pause_id != pause_id
                    or context.qualification_nonce != nonce
                    or context.qualification_deadline_ns is None
                    or time.monotonic_ns() >= context.qualification_deadline_ns
                    or self.phase != "READY"
                    or self.transition is not None
                    or self.active_result is None
                    or self.active_result.request.generation != expected_generation
                    or self.generation != expected_generation
                ):
                    raise AdmissionError(
                        "qualification freeze request is not bound to the active guard"
                    )
                candidates = [
                    self._leases[lease_id]
                    for lease_id in context.qualification_lease_ids
                    if lease_id in self._leases
                    and self._leases[lease_id].wrapper == wrapper
                ]
                if len(candidates) != 1:
                    raise AdmissionError(
                        "qualification freeze target is not one exact guarded lease"
                    )
                lease = candidates[0]
                if (
                    lease.state != "LIVE"
                    or lease.child is None
                    or lease.child_scope_handle is None
                    or not process_matches(lease.wrapper)
                    or not process_matches(lease.child)
                ):
                    raise AdmissionError(
                        "qualification freeze target is no longer exact-live"
                    )
                currently_frozen = lease.lease_id in context.qualification_frozen
                if currently_frozen == frozen:
                    raise AdmissionError(
                        "qualification freeze target is already in the requested state"
                    )
                if frozen:
                    try:
                        self._process_scopes.freeze(
                            lease.child_scope_handle,
                            self._qualification_operation_timeout(context),
                        )
                    except ScopeResidueError:
                        context.qualification_freeze_uncertain = True
                        raise
                    context.qualification_frozen.add(lease.lease_id)
                else:
                    assert self.frontend is not None
                    self.frontend.qualification_reopen(
                        expected_generation,
                        self._qualification_operation_timeout(context),
                    )
                    self._process_scopes.thaw(
                        lease.child_scope_handle,
                        self._qualification_operation_timeout(context),
                    )
                    context.qualification_frozen.discard(lease.lease_id)
                frontend = self._qualification_frontend_snapshot(self.frontend)
                self._record_locked(
                    "qualification-pause",
                    result="frozen" if frozen else "thawed",
                    generation=expected_generation,
                )
                return {
                    "ok": True,
                    "type": "qualification-set-frozen",
                    "request_id": request_id,
                    "owner_epoch": self.owner_epoch,
                    "pause_id": pause_id,
                    "wrapper": _identity_to_dict(wrapper),
                    "child": _identity_to_dict(lease.child),
                    "frozen": frozen,
                    "generation": expected_generation,
                    "frozen_scopes": len(context.qualification_frozen),
                    "frontend": frontend,
                    "qualification": self._qualification_stream_state(
                        self.frontend
                    ),
                }
        except BaseException as primary:
            if not isinstance(primary, AdmissionError):
                try:
                    self._release_qualification_pause(
                        context, reason="freeze-change-failed"
                    )
                except BaseException as cleanup:
                    raise ScopeError(
                        "qualification freeze change and cleanup both failed"
                    ) from cleanup
            raise primary

    def _qualification_quiesce(
        self,
        context: _Connection,
        payload: dict[str, Any],
        descriptors: list[int],
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "type", "schema_version", "protocol_version", "request_id",
                "owner_epoch", "canary_nonce", "pause_id",
                "expected_generation", "wrapper", "stream_ids",
            },
            "qualification-quiesce",
        )
        if descriptors:
            raise AdmissionError("qualification-quiesce does not accept descriptors")
        request_id = _token(payload["request_id"], "request_id")
        nonce = _token(
            payload["canary_nonce"], "canary_nonce", _CANARY_NONCE_RE
        )
        pause_id = _token(payload["pause_id"], "pause_id", _NONCE_RE)
        generation = payload["expected_generation"]
        raw_wrapper = payload["wrapper"]
        raw_stream_ids = payload["stream_ids"]
        if (
            payload["owner_epoch"] != self.owner_epoch
            or type(generation) is not int
            or generation < 1
            or type(raw_stream_ids) is not list
            or len(raw_stream_ids) > 1
            or any(type(value) is not int or value < 1 for value in raw_stream_ids)
            or len(set(raw_stream_ids)) != len(raw_stream_ids)
        ):
            raise AdmissionError("qualification quiesce request is invalid")
        wrapper = (
            _identity(raw_wrapper, "wrapper")
            if raw_stream_ids
            else None
        )
        if (not raw_stream_ids and raw_wrapper is not None) or (
            raw_stream_ids and wrapper is None
        ):
            raise AdmissionError("qualification quiesce wrapper is invalid")
        with self._state_lock:
            if (
                self._qualification_connection_id != context.connection_id
                or context.qualification_pause_id != pause_id
                or context.qualification_nonce != nonce
                or context.qualification_deadline_ns is None
                or time.monotonic_ns() >= context.qualification_deadline_ns
                or not context.qualification_frontend_armed
                or context.qualification_fault_in_progress
                or set(context.qualification_lease_ids)
                != context.qualification_frozen
                or self.phase != "READY"
                or self.transition is not None
                or self.active_result is None
                or self.active_result.request.generation != generation
                or self.generation != generation
            ):
                raise AdmissionError(
                    "qualification quiesce is not bound to its frozen guard"
                )
            state = self._qualification_stream_state(self.frontend)
            actual_stream_ids = {
                stream["stream_id"] for stream in state["streams"]
            }
            if (
                state["response_hold"] is not True
                or (raw_stream_ids and actual_stream_ids != set(raw_stream_ids))
            ):
                raise AdmissionError(
                    "qualification quiesce lacks exact repaired stream receipts"
                )
            if raw_stream_ids:
                if not self._qualification_receipts_ready(state, generation, 1):
                    raise AdmissionError(
                        "qualification quiesce receipt is incomplete"
                    )
                candidates = [
                    self._leases[lease_id]
                    for lease_id in context.qualification_lease_ids
                    if lease_id in self._leases
                    and self._leases[lease_id].wrapper == wrapper
                ]
                if len(candidates) != 1:
                    raise AdmissionError(
                        "qualification quiesce wrapper is not one guarded lease"
                    )
                bindings, _scope_inodes = self._qualification_stream_bindings(
                    context, state
                )
                binding = bindings.get(raw_stream_ids[0])
                if binding is None or binding[0] != candidates[0].lease_id:
                    raise AdmissionError(
                        "qualification reconnect stream belongs to another scope"
                    )
                if binding[1] in context.qualification_forbidden_socket_inodes.get(
                    binding[0], frozenset()
                ):
                    raise AdmissionError(
                        "qualification reconnect reused a pre-fault socket"
                    )
            elif state["streams"]:
                bindings, _scope_inodes = self._qualification_stream_bindings(
                    context, state
                )
                if any(
                    inode
                    not in context.qualification_forbidden_socket_inodes.get(
                        lease_id, frozenset()
                    )
                    for lease_id, inode in bindings.values()
                ):
                    raise AdmissionError(
                        "qualification initial quiesce observed a foreign socket"
                    )
            assert self.frontend is not None
            quiesced = self.frontend.qualification_quiesce(
                generation,
                self._qualification_operation_timeout(context),
            )
            after = self._qualification_stream_state(self.frontend)
            if (
                after["response_hold"] is not True
                or after["streams"]
                or after["accept_cursor"] != quiesced["accept_cursor"]
                or after["quiesce_epoch"] != quiesced["quiesce_epoch"]
                or quiesced["accept_cursor"] < max(raw_stream_ids, default=0)
                or quiesced["generation"] != generation
                or context.qualification_deadline_ns is None
                or time.monotonic_ns() >= context.qualification_deadline_ns
            ):
                raise ScopeResidueError(
                    "qualification frontend did not reach exact quiescence"
                )
            return {
                "ok": True,
                "type": "qualification-quiesce",
                "request_id": request_id,
                "owner_epoch": self.owner_epoch,
                "pause_id": pause_id,
                "wrapper": (
                    _identity_to_dict(wrapper) if wrapper is not None else None
                ),
                **quiesced,
                "qualification": after,
            }

    def _qualification_disarm(
        self,
        context: _Connection,
        payload: dict[str, Any],
        descriptors: list[int],
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "type", "schema_version", "protocol_version", "request_id",
                "owner_epoch", "canary_nonce", "pause_id",
                "expected_generation",
            },
            "qualification-disarm",
        )
        if descriptors:
            raise AdmissionError("qualification-disarm does not accept descriptors")
        request_id = _token(payload["request_id"], "request_id")
        nonce = _token(
            payload["canary_nonce"], "canary_nonce", _CANARY_NONCE_RE
        )
        pause_id = _token(payload["pause_id"], "pause_id", _NONCE_RE)
        generation = payload["expected_generation"]
        with self._state_lock:
            if (
                payload["owner_epoch"] != self.owner_epoch
                or type(generation) is not int
                or self._qualification_connection_id != context.connection_id
                or context.qualification_pause_id != pause_id
                or context.qualification_nonce != nonce
                or context.qualification_deadline_ns is None
                or time.monotonic_ns() >= context.qualification_deadline_ns
                or not context.qualification_frontend_armed
                or context.qualification_fault_in_progress
                or set(context.qualification_lease_ids)
                != context.qualification_frozen
                or self.phase != "READY"
                or self.transition is not None
                or self.active_result is None
                or self.active_result.request.generation != generation
                or self.generation != generation
            ):
                raise AdmissionError(
                    "qualification disarm is not bound to its frozen guard"
                )
            before = self._qualification_stream_state(self.frontend)
            if before["response_hold"] is not True or before["streams"]:
                raise AdmissionError(
                    "qualification disarm requires an empty held frontend"
                )
            assert self.frontend is not None
            self.frontend.qualification_disarm()
            if (
                context.qualification_deadline_ns is None
                or time.monotonic_ns() >= context.qualification_deadline_ns
            ):
                raise ScopeResidueError(
                    "qualification deadline expired while disarming responses"
                )
            context.qualification_frontend_armed = False
            after = self._qualification_stream_state(self.frontend)
            if after["response_hold"] is not False or after["streams"]:
                raise ScopeResidueError(
                    "qualification response hold did not disarm exactly"
                )
            return {
                "ok": True,
                "type": "qualification-disarm",
                "request_id": request_id,
                "owner_epoch": self.owner_epoch,
                "pause_id": pause_id,
                "generation": generation,
                "qualification": after,
            }

    def _qualification_fault_guard(
        self,
        fault_context: _Connection,
        nonce: str,
        pause_id: str,
        generation: int,
        *,
        active_streams: int,
        begin: bool = False,
        require_in_progress: bool = False,
    ) -> _Connection:
        with self._state_lock:
            guard = (
                self._connections.get(self._qualification_connection_id)
                if self._qualification_connection_id is not None
                else None
            )
            if (
                guard is None
                or guard.qualification_pause_id != pause_id
                or guard.qualification_nonce != nonce
                or guard.qualification_deadline_ns is None
                or time.monotonic_ns() >= guard.qualification_deadline_ns
                or len(guard.qualification_lease_ids) != 2
                or guard.qualification_frozen
                != set(guard.qualification_lease_ids)
                or guard.qualification_freeze_uncertain
                or guard.qualification_cleanup_uncertain
                or not guard.qualification_frontend_armed
                or fault_context.connection_id == guard.connection_id
                or fault_context.peer_pid != guard.peer_pid
                or fault_context.peer_uid != guard.peer_uid
                or self.phase != "READY"
                or self.transition is not None
                or self.active_result is None
                or self.active_result.request.generation != generation
                or self.generation != generation
                or len(self._leases) != 2
                or set(self._leases) != set(guard.qualification_lease_ids)
            ):
                raise AdmissionError(
                    "qualification provider fault lacks its exact frozen pair guard"
                )
            for lease_id in guard.qualification_lease_ids:
                lease = self._leases[lease_id]
                if (
                    lease.state != "LIVE"
                    or lease.child is None
                    or lease.child_pidfd is None
                    or lease.child_scope_handle is None
                    or not process_matches(lease.wrapper)
                    or not process_matches(lease.child)
                    or not _pidfd_matches(lease.child_pidfd, lease.child)
                ):
                    raise AdmissionError(
                        "qualification provider fault pair is no longer exact-live"
                    )
            frontend = self._qualification_frontend_snapshot(self.frontend)
            streams = self._qualification_stream_state(self.frontend)
            if (
                frontend["committed_generation"] != generation
                or frontend["active_streams"] != active_streams
                or (
                    active_streams == 2
                    and not self._qualification_receipts_ready(
                        streams, generation, 2
                    )
                )
                or (
                    active_streams == 0
                    and (
                        streams["response_hold"] is not True
                        or streams["streams"]
                    )
                )
                or (begin and guard.qualification_fault_in_progress)
                or (
                    require_in_progress
                    and not guard.qualification_fault_in_progress
                )
            ):
                raise AdmissionError(
                    "qualification provider fault frontend is not guard-bound"
                )
            if active_streams == 2:
                bindings, scope_inodes = self._qualification_stream_bindings(
                    guard, streams
                )
                if {
                    lease_id for lease_id, _inode in bindings.values()
                } != set(guard.qualification_lease_ids):
                    raise AdmissionError(
                        "qualification old streams are not a scope-exact pair"
                    )
                if begin:
                    if guard.qualification_forbidden_socket_inodes:
                        raise AdmissionError(
                            "qualification pre-fault socket inventory already exists"
                        )
                    guard.qualification_forbidden_socket_inodes = scope_inodes
            elif set(guard.qualification_forbidden_socket_inodes) != set(
                guard.qualification_lease_ids
            ):
                raise AdmissionError(
                    "qualification repaired guard lost its pre-fault sockets"
                )
            if (
                guard.qualification_deadline_ns is None
                or time.monotonic_ns() >= guard.qualification_deadline_ns
            ):
                raise AdmissionError("qualification provider fault guard expired")
            if begin:
                guard.qualification_fault_in_progress = True
            return guard

    def _qualification_provider_fault(
        self,
        context: _Connection,
        payload: dict[str, Any],
        descriptors: list[int],
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "type", "schema_version", "protocol_version", "request_id",
                "owner_epoch", "canary_nonce", "pause_id",
                "expected_generation", "expected_old_streams_sha256",
            },
            "qualification-provider-fault",
        )
        if len(descriptors) != 1:
            raise AdmissionError(
                "qualification-provider-fault requires one authorization descriptor"
            )
        request_id = _token(payload["request_id"], "request_id")
        if payload["owner_epoch"] != self.owner_epoch:
            raise AdmissionError("stale qualification owner epoch")
        nonce = _token(
            payload["canary_nonce"], "canary_nonce", _CANARY_NONCE_RE
        )
        pause_id = _token(payload["pause_id"], "pause_id", _NONCE_RE)
        expected_generation = payload["expected_generation"]
        expected_old_streams_sha256 = payload["expected_old_streams_sha256"]
        if (
            type(expected_generation) is not int
            or expected_generation < 1
            or type(expected_old_streams_sha256) is not str
            or _DIGEST_RE.fullmatch(expected_old_streams_sha256) is None
        ):
            raise AdmissionError("qualification expected generation is invalid")
        if context.leases or context.qualification_pause_id is not None:
            raise AdmissionError(
                "qualification provider fault requires a dedicated connection"
            )
        record, contract, failed = self._qualification_authorization(
            descriptors[0], nonce
        )
        marker = self.control_root / f"qualification-fault-{nonce}.json"
        existing = _read_secure_json(marker)
        if existing is not None:
            if (
                existing.get("schema_version") == SCHEMA_VERSION
                and existing.get("release_id") == self.release_id
                and existing.get("owner_epoch") == self.owner_epoch
                and existing.get("canary_nonce") == nonce
                and existing.get("pause_id") == pause_id
                and existing.get("old_streams_sha256")
                == expected_old_streams_sha256
                and existing.get("phase") == "COMPLETED"
                and existing.get("repair_succeeded") is True
            ):
                self._qualification_fault_guard(
                    context,
                    nonce,
                    pause_id,
                    existing["generation_after"],
                    active_streams=0,
                )
                return {
                    "ok": True,
                    "type": "qualification-provider-fault",
                    "request_id": request_id,
                    "owner_epoch": self.owner_epoch,
                    "pause_id": pause_id,
                    "rung": existing["rung"],
                    "generation_before": existing["generation_before"],
                    "generation_after": existing["generation_after"],
                    "duration_ms": existing["duration_ms"],
                    "repair_succeeded": True,
                    "old_streams_sha256": existing["old_streams_sha256"],
                    "replayed": True,
                }
            raise AdmissionError("qualification provider fault was already consumed")
        if failed.request.generation != expected_generation:
            raise AdmissionError(
                "qualification provider fault generation differs from its pause"
            )
        guard = self._qualification_fault_guard(
            context,
            nonce,
            pause_id,
            expected_generation,
            active_streams=2,
            begin=True,
        )
        with self._state_lock:
            if nonce in self._qualification_fault_nonces:
                raise AdmissionError("qualification provider fault is already in progress")
            self._qualification_fault_nonces.add(nonce)
        assert self.frontend is not None
        stream_state = self._qualification_stream_state(self.frontend)
        if hashlib.sha256(
            canonical_json_bytes(stream_state["streams"])
        ).hexdigest() != expected_old_streams_sha256:
            raise AdmissionError(
                "qualification old stream transcript differs from verifier evidence"
            )
        expected_stream_ids = {
            stream["stream_id"] for stream in stream_state["streams"]
        }
        final_streams = [
            item.to_dict()
            for item in self.frontend.qualification_revoke(
                expected_stream_ids,
                self._qualification_operation_timeout(guard),
            )
        ]
        if (
            {item["stream_id"] for item in final_streams}
            != expected_stream_ids
            or any(
                item["generation"] != expected_generation
                or item["socks_state"] != "complete"
                or item["application_client_to_backend_bytes"] <= 0
                or item["application_backend_to_client_bytes"] != 0
                for item in final_streams
            )
        ):
            raise ScopeResidueError(
                "qualification old-generation streams were not revoked cleanly"
            )
        old_streams_sha256 = hashlib.sha256(
            canonical_json_bytes(final_streams)
        ).hexdigest()
        if old_streams_sha256 != expected_old_streams_sha256:
            raise ScopeResidueError(
                "qualification old stream transcript changed during revoke"
            )
        started_unix_ns = time.time_ns()
        prepared = {
            "schema_version": SCHEMA_VERSION,
            "release_id": self.release_id,
            "owner_epoch": self.owner_epoch,
            "canary_nonce": nonce,
            "pause_id": pause_id,
            "old_streams_sha256": old_streams_sha256,
            "rung": str(record["rung"]),
            "contract_sha256": record["contract_sha256"],
            "grok_release_id": contract.grok_release_id,
            "model_id": contract.model_id,
            "phase": "PREPARED",
            "started_unix_ns": started_unix_ns,
            "completed_unix_ns": None,
            "duration_ms": None,
            "generation_before": failed.request.generation,
            "generation_after": None,
            "repair_succeeded": False,
        }
        if not _atomic_create_json(marker, prepared):
            raise AdmissionError("qualification provider fault marker raced")
        outcome = self._repair_active(
            failed,
            reason="qualification-fault",
            require_same_rung=True,
        )
        if self._qualification_fault_guard(
            context,
            nonce,
            pause_id,
            outcome["generation_after"],
            active_streams=0,
            require_in_progress=True,
        ) is not guard:
            raise AdmissionError(
                "qualification provider fault guard changed during repair"
            )
        completed_unix_ns = time.time_ns()
        completed = {
            **prepared,
            "phase": "COMPLETED",
            "completed_unix_ns": completed_unix_ns,
            "duration_ms": outcome["duration_ms"],
            "generation_after": outcome["generation_after"],
            "repair_succeeded": True,
        }
        with self._state_lock:
            if self._qualification_fault_guard(
                context,
                nonce,
                pause_id,
                outcome["generation_after"],
                active_streams=0,
                require_in_progress=True,
            ) is not guard:
                raise AdmissionError(
                    "qualification provider fault guard changed before commit"
                )
            _atomic_replace_json(marker, completed)
            guard.qualification_fault_in_progress = False
        return {
            "ok": True,
            "type": "qualification-provider-fault",
            "request_id": request_id,
            "owner_epoch": self.owner_epoch,
            "pause_id": pause_id,
            "rung": str(record["rung"]),
            "generation_before": failed.request.generation,
            "generation_after": outcome["generation_after"],
            "duration_ms": outcome["duration_ms"],
            "repair_succeeded": True,
            "old_streams_sha256": old_streams_sha256,
            "replayed": False,
        }

    # ------------------------------------------------------------------ providers

    @staticmethod
    def _peer_closed(sock: socket.socket) -> bool:
        try:
            readable, _, _ = select.select([sock], [], [], 0)
            if not readable:
                return False
            return sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) == b""
        except BlockingIOError:
            return False
        except OSError:
            return True

    def _generation_worker_main(self) -> None:
        current = threading.current_thread()
        error: BaseException | None = None
        try:
            with self._transition_lock:
                with self._state_lock:
                    if self.phase == "DRAINING" or not self._leases:
                        raise EpochDraining("provider transition lost its live interest")
                    contract = None if self.active_result is not None else self.contract
                if contract is not None:
                    self._ensure_frontend(contract)
                    self._transition_candidates(contract.ladder, reason="initial")
        except BaseException as exc:
            error = exc
        with self._generation_condition:
            self._generation_error = error
            self._generation_condition.notify_all()
        # Linux PR_SET_PDEATHSIG is tied to the *creating thread* in a
        # multithreaded parent. Providers launched during the initial
        # transition therefore require this owner thread to live for the whole
        # epoch; otherwise returning here kills an otherwise committed backend.
        if error is None:
            self._stop.wait()
        with self._generation_condition:
            if self._generation_worker is current:
                self._generation_worker = None
            self._threads.discard(current)
            self._generation_condition.notify_all()

    def _ensure_generation(self, lease_id: str) -> None:
        while True:
            peer_socket: socket.socket | None = None
            with self._generation_condition:
                lease = self._leases.get(lease_id)
                if lease is None or self.phase == "DRAINING":
                    raise EpochDraining("lease no longer has live interest")
                if self.active_result is not None:
                    return
                if self._generation_error is not None:
                    raise self._generation_error
                worker = self._generation_worker
                if worker is None:
                    worker = threading.Thread(
                        target=self._generation_worker_main,
                        name="grok-supervisor-transition",
                        daemon=True,
                    )
                    self._generation_worker = worker
                    self._threads.add(worker)
                    try:
                        worker.start()
                    except BaseException:
                        self._threads.discard(worker)
                        self._generation_worker = None
                        raise
                context = self._connections.get(lease.connection_id)
                if context is not None:
                    peer_socket = context.socket
                self._generation_condition.wait(timeout=0.05)
            if peer_socket is not None and self._peer_closed(peer_socket):
                self._drop_lease(
                    lease_id,
                    terminate=False,
                    linearize_reason="register-control-eof",
                )
                raise EpochDraining("registration peer closed during provider transition")

    def _ensure_frontend(self, contract: RouteContract) -> None:
        if self.frontend is not None:
            return
        effective_streams = min(
            contract.limits.max_frontend_streams,
            contract.limits.total_buffer_bytes // contract.limits.per_stream_buffer_bytes,
        )
        if effective_streams < 1:
            raise AdmissionError("frontend buffer contract admits no stream")
        frontend = CommittedFrontend(
            listen_host=contract.public_endpoint.host,
            listen_port=contract.public_endpoint.port,
            backlog=min(4_096, max(1, contract.limits.max_control_connections * 4)),
            max_streams=effective_streams,
            per_stream_buffer_bytes=contract.limits.per_stream_buffer_bytes,
            total_buffer_bytes=contract.limits.total_buffer_bytes,
            connect_timeout=contract.timeout_policy.connect_ms / 1_000,
        )
        frontend.start()
        self.frontend = frontend

    def _transition_candidates(
        self,
        rungs: Sequence[str],
        *,
        reason: str,
        deadline: TransitionDeadline | None = None,
    ) -> None:
        contract = self.contract
        if contract is None or self.intents is None or self.recovery is None:
            raise SupervisorError("provider transition has no contract or intent store")
        if deadline is None:
            deadline = TransitionDeadline.after_ms(contract.timeout_policy.transition_ms)
        errors: list[str] = []
        ios_family_expires_ns: int | None = None
        for rung in rungs:
            rung_deadline = deadline
            if rung.startswith("ios:"):
                now_ns = time.monotonic_ns()
                if ios_family_expires_ns is None:
                    ios_family_expires_ns = min(
                        deadline.expires_ns,
                        now_ns + _IOS_FAMILY_TRANSITION_NS,
                    )
                rung_expires_ns = min(
                    deadline.expires_ns,
                    ios_family_expires_ns,
                    now_ns + _IOS_DEVICE_TRANSITION_NS,
                )
                if rung_expires_ns <= now_ns:
                    errors.append(f"{rung}: iOS family deadline expired")
                    continue
                rung_deadline = TransitionDeadline(rung_expires_ns)
            with self._state_lock:
                if self.phase == "DRAINING" or not self._leases:
                    raise EpochDraining("provider transition lost its live interest")
                self.generation += 1
                generation = self.generation
                transition_id = secrets.token_hex(12)
                port = contract.private_ports[(generation - 1) % len(contract.private_ports)]
                self.transition = {
                    "id": transition_id,
                    "generation": generation,
                    "rung": rung,
                    "reason": reason,
                    "phase": "PROBING",
                }
                self._record_locked("transition", result="probing", rung=rung, generation=generation)
            request = ProviderRequest(
                owner_epoch=self.owner_epoch,
                transition_id=transition_id,
                generation=generation,
                rung=rung,
                model_id=contract.model_id,
                private_endpoint=Endpoint("127.0.0.1", port),
                contract=contract,
            )
            adapter = self._provider_for(rung)
            effect_id = self._effect_id(generation)
            parameters = request.to_dict()
            intent = EffectIntent(
                schema_version=SCHEMA_VERSION,
                owner_epoch=self.owner_epoch,
                generation=generation,
                effect_id=effect_id,
                operation="provider-start",
                parameters_digest=hashlib.sha256(canonical_json_bytes(parameters)).hexdigest(),
                phase="PREPARED",
            )
            recovery_record = ProviderRecoveryRecord(
                schema_version=SCHEMA_VERSION,
                record_version=_RECOVERY_RECORD_VERSION,
                release_id=self.release_id,
                owner_epoch=self.owner_epoch,
                effect_id=effect_id,
                phase="PREPARED",
                request=request,
                resources=None,
            )
            # The complete frozen request is durable before the first provider
            # effect.  A crash after this point is either provably effect-free
            # or remains fenced until exact recovery can identify its graph.
            self.recovery.put_provider(recovery_record)
            self.intents.put(intent)
            result: ProviderResult | None = None
            started_ns = time.monotonic_ns()
            try:
                result = adapter.start(
                    request,
                    rung_deadline,
                    self._qualifier,
                    self._cancel_transition,
                )
                recovery_record = replace(
                    recovery_record,
                    phase="APPLIED",
                    resources=result.resources,
                )
                self.recovery.replace_provider(recovery_record)
                self.intents.advance(effect_id, "PREPARED", "APPLIED")
                assert self.frontend is not None
                committed = CommittedGeneration(
                    generation=generation,
                    backend_id=transition_id,
                    backend_host=request.private_endpoint.host,
                    backend_port=request.private_endpoint.port,
                    contract_digest=contract.digest(),
                )
                published = False
                with self._state_lock:
                    # Last-interest removal takes this same authority lock. Keep
                    # it across durable READY and frontend publication so a
                    # DRAINING transition cannot interleave between validation
                    # and admission opening.
                    if (
                        self.phase == "DRAINING"
                        or not self._leases
                        or self.contract_digest != contract.digest()
                        or self.transition is None
                        or self.transition["id"] != transition_id
                    ):
                        raise EpochDraining("candidate became stale before publication")
                    try:
                        # Persist recovery authority before public accept opens.
                        # A crash in this interval leaves a fenced APPLIED
                        # provider, never an adoptable live frontend.
                        self._set_fence_phase("READY")
                        self.frontend.commit_generation(
                            committed,
                            revoke_timeout=contract.timeout_policy.stop_ms / 1_000,
                        )
                        published = True
                        self.active_result = result
                        self.active_adapter = adapter
                        self.phase = "READY"
                        self.transition = None
                        self._record_locked(
                            "transition",
                            result="committed",
                            rung=rung,
                            generation=generation,
                            duration_ms=(time.monotonic_ns() - started_ns) // 1_000_000,
                        )
                    except BaseException:
                        if published:
                            try:
                                self.frontend.revoke(
                                    contract.timeout_policy.stop_ms / 1_000
                                )
                            except (FrontendDrainTimeout, OSError) as revoke_error:
                                self._lease_cleanup_errors.append(str(revoke_error))
                        self.active_result = None
                        self.active_adapter = None
                        self.phase = "BOOTSTRAPPING"
                        try:
                            self._set_fence_phase("BOOTSTRAPPING")
                        except BaseException as fence_error:
                            self._lease_cleanup_errors.append(str(fence_error))
                        raise
                return
            except ProviderResidueError as residue:
                with self._state_lock:
                    self._lease_cleanup_errors.append(str(residue))
                try:
                    self.intents.advance(effect_id, "PREPARED", "FAILED")
                except Exception:
                    pass
                try:
                    current = self.recovery.load_provider(effect_id)
                    if current is not None and current.phase == "PREPARED":
                        self.recovery.replace_provider(replace(current, phase="FAILED"))
                except Exception:
                    pass
                raise
            except Exception as exc:
                errors.append(f"{rung}: {exc}")
                if result is not None:
                    try:
                        # Cleanup owns an independent stop budget; the cumulative
                        # transition deadline may have expired in qualification.
                        self._stop_result(
                            adapter,
                            result,
                            TransitionDeadline.after_ms(
                                contract.timeout_policy.stop_ms
                            ),
                            effect_id,
                        )
                    except (ProviderError, RuntimeSecurityError) as cleanup:
                        with self._state_lock:
                            self._lease_cleanup_errors.append(str(cleanup))
                        raise ProviderResidueError(str(cleanup)) from exc
                else:
                    try:
                        report = adapter.recover(
                            request,
                            None,
                            TransitionDeadline.after_ms(
                                contract.timeout_policy.stop_ms
                            ),
                        )
                        if not report.clean:
                            raise ProviderResidueError("; ".join(report.issues))
                        self.intents.advance(effect_id, "PREPARED", "FAILED")
                        self.intents.advance(effect_id, "FAILED", "CLEANED")
                        current = self.recovery.load_provider(effect_id)
                        if current is not None:
                            self.recovery.replace_provider(
                                replace(current, phase="CLEANED")
                            )
                        self.intents.delete(effect_id)
                        if current is not None:
                            self.recovery.delete_provider(effect_id)
                    except Exception as cleanup:
                        with self._state_lock:
                            self._lease_cleanup_errors.append(str(cleanup))
                        raise ProviderResidueError(
                            f"failed start could not prove empty: {cleanup}"
                        ) from exc
                self._record(
                    "transition",
                    result="rejected",
                    reason=str(exc),
                    rung=rung,
                    generation=generation,
                    duration_ms=(time.monotonic_ns() - started_ns) // 1_000_000,
                )
                if isinstance(exc, (EpochDraining, ProviderCancelled)):
                    raise
        with self._state_lock:
            self.transition = None
        raise ProviderError("no provider rung qualified: " + "; ".join(errors))

    def _provider_for(self, rung: str) -> ProviderAdapter:
        if rung in self._provided:
            return self._provided[rung]
        if "*" in self._provided:
            return self._provided["*"]
        return self._direct_provider if rung == "direct" else self._legacy_provider

    def _stop_result(
        self,
        adapter: ProviderAdapter,
        result: ProviderResult,
        deadline: TransitionDeadline,
        effect_id: str,
    ) -> None:
        adapter.stop(result, deadline, None)
        residue = adapter.prove_empty(result)
        if not residue.clean:
            raise ProviderResidueError("; ".join(residue.issues))
        assert self.intents is not None
        intent = self.intents.load(effect_id)
        if intent is not None:
            if intent.phase == "PREPARED":
                self.intents.advance(effect_id, "PREPARED", "FAILED")
                self.intents.advance(effect_id, "FAILED", "CLEANED")
            elif intent.phase == "APPLIED":
                self.intents.advance(effect_id, "APPLIED", "CLEANED")
            elif intent.phase == "FAILED":
                self.intents.advance(effect_id, "FAILED", "CLEANED")
        if self.recovery is None:
            raise RuntimeSecurityError("provider recovery store is unavailable")
        record = self.recovery.load_provider(effect_id)
        if record is not None:
            if record.phase not in {"APPLIED", "FAILED", "CLEANED"}:
                raise RuntimeSecurityError(
                    f"provider recovery record is unexpectedly {record.phase}"
                )
            if record.phase != "CLEANED":
                self.recovery.replace_provider(replace(record, phase="CLEANED"))
        if intent is not None:
            self.intents.delete(effect_id)
        if record is not None:
            self.recovery.delete_provider(effect_id)

    def _repair_active(
        self,
        failed: ProviderResult,
        *,
        reason: str = "watchdog-failure",
        require_same_rung: bool = False,
    ) -> dict[str, Any]:
        if not self._transition_lock.acquire(blocking=False):
            if require_same_rung:
                raise AdmissionError("another provider transition is already active")
            return {
                "duration_ms": 0,
                "generation_after": failed.request.generation,
                "repaired": False,
            }
        fatal = False
        repaired = False
        started_ns = time.monotonic_ns()
        generation_after = failed.request.generation
        try:
            with self._state_lock:
                if self.active_result is not failed or self.phase == "DRAINING" or not self._leases:
                    if require_same_rung:
                        raise AdmissionError(
                            "qualification provider is no longer the active leased generation"
                        )
                    return {
                        "duration_ms": (time.monotonic_ns() - started_ns) // 1_000_000,
                        "generation_after": failed.request.generation,
                        "repaired": False,
                    }
                contract = self.contract
                assert contract is not None
                try:
                    index = contract.ladder.index(failed.request.rung)
                except ValueError:
                    index = len(contract.ladder) - 1
                remaining = contract.ladder[index + 1 :]
                same_rung = failed.request.rung not in self._same_rung_repairs
                if same_rung:
                    # Consume the one same-rung repair before mutation.  A
                    # crash or failed restart must never grant a second attempt.
                    self._same_rung_repairs.add(failed.request.rung)
                self.transition = {
                    "id": secrets.token_hex(12),
                    "generation": self.generation + 1,
                    "rung": failed.request.rung,
                    "reason": reason,
                    "phase": "REVOKING",
                }
            assert self.frontend is not None
            self.frontend.revoke(contract.timeout_policy.stop_ms / 1_000)
            deadline = TransitionDeadline.after_ms(contract.timeout_policy.transition_ms)
            adapter = self.active_adapter
            assert adapter is not None
            self._stop_result(
                adapter,
                failed,
                deadline,
                self._effect_id(failed.request.generation),
            )
            with self._state_lock:
                self.active_result = None
                self.active_adapter = None
            if same_rung:
                try:
                    self._transition_candidates(
                        (failed.request.rung,),
                        reason="same-rung-repair",
                        deadline=deadline,
                    )
                    repaired = True
                except (ProviderError, ProviderCancelled, EpochDraining):
                    if require_same_rung:
                        raise
            if not repaired and remaining and not require_same_rung:
                self._transition_candidates(
                    remaining,
                    reason="demotion",
                    deadline=deadline,
                )
                repaired = True
            elif not repaired:
                with self._state_lock:
                    self.transition = None
                    self._record_locked("watchdog", result="exhausted", rung=failed.request.rung)
                fatal = True
            with self._state_lock:
                if self.active_result is not None:
                    generation_after = self.active_result.request.generation
                self._last_repair = {
                    "reason": reason,
                    "rung": failed.request.rung,
                    "generation_before": failed.request.generation,
                    "generation_after": generation_after,
                    "same_rung": generation_after > failed.request.generation
                    and self.active_result is not None
                    and self.active_result.request.rung == failed.request.rung,
                    "duration_ms": (time.monotonic_ns() - started_ns) // 1_000_000,
                    "succeeded": repaired,
                }
        except Exception as exc:
            fatal = True
            with self._state_lock:
                self.transition = None
                self._record_locked("watchdog", result="failed", reason=str(exc))
        finally:
            self._transition_lock.release()
        if fatal:
            self._force_shutdown("watchdog-repair-failed")
            self._stop.set()
            if require_same_rung:
                raise ProviderError("qualification same-rung repair failed")
        return {
            "duration_ms": (time.monotonic_ns() - started_ns) // 1_000_000,
            "generation_after": generation_after,
            "repaired": repaired,
        }

    # ------------------------------------------------------------------ lease lifecycle

    def _new_leader_path(self) -> Path:
        for _ in range(64):
            path = self._leader_dir / f"l-{secrets.token_hex(6)}.sock"
            if len(os.fsencode(path)) >= 100:
                raise AdmissionError("leader socket path exceeds the short Unix-path budget")
            if not path.exists() and not path.is_symlink():
                return path
        raise SupervisorError("cannot allocate a unique leader path")

    def _child_stop_seconds(self) -> float:
        return (
            self.contract.timeout_policy.stop_ms / 1_000
            if self.contract is not None
            else 2.0
        )

    @staticmethod
    def _child_has_exited(lease: _Lease) -> bool:
        if lease.child is None:
            return True
        if lease.child_pidfd is not None:
            try:
                readable, _, _ = select.select([lease.child_pidfd], [], [], 0)
                if readable:
                    return True
            except (OSError, ValueError):
                pass
        return not process_matches(lease.child)

    def _drop_lease(
        self,
        lease_id: str,
        *,
        terminate: bool,
        linearize_reason: str | None = None,
    ) -> bool:
        with self._state_lock:
            lease = self._leases.get(lease_id)
        if lease is None:
            return False
        scope_clean = lease.child is None
        scope_error: BaseException | None = None
        guarded_cleanup_uncertain = False
        if lease.child is not None:
            if lease.child_scope is None:
                scope_error = ScopeError("attached child has no exact lease cgroup record")
            else:
                try:
                    # Normal child exit must also reconcile late descendants;
                    # control EOF additionally terminates the direct child.
                    self._process_scopes.reconcile(
                        lease.child_scope,
                        "ATTACHED",
                        lease.child,
                        lease.child_pidfd,
                        self._child_stop_seconds(),
                        handle=lease.child_scope_handle,
                    )
                    scope_clean = True
                except BaseException as exc:
                    scope_error = exc
        child_exited = self._child_has_exited(lease)
        child_residue = lease.child is not None and not child_exited
        with self._state_lock:
            lease = self._leases.pop(lease_id, None)
            if lease is None:
                return not self._leases
            context = self._connections.get(lease.connection_id)
            if context is not None:
                context.leases.discard(lease_id)
            if lease.child_pidfd is not None:
                try:
                    os.close(lease.child_pidfd)
                except OSError:
                    pass
                lease.child_pidfd = None
            if lease.child_scope_handle is not None:
                try:
                    lease.child_scope_handle.close()
                except OSError:
                    pass
                lease.child_scope_handle = None
            leader_clean = True
            try:
                self._cleanup_leader(lease.leader_path)
            except (RuntimeSecurityError, OSError) as exc:
                leader_clean = False
                self._lease_cleanup_errors.append(str(exc))
                self._record_locked(
                    "lease-release",
                    result="residue",
                    reason=str(exc),
                    lease_id=lease_id,
                )
            else:
                self._record_locked("lease-release", result="removed", lease_id=lease_id)
            if child_residue:
                guarded_cleanup_uncertain = True
                self._lease_cleanup_errors.append(
                    f"attached child remains alive: pid={lease.child.pid}"
                )
                self._record_locked(
                    "lease-release",
                    result="residue",
                    reason="attached child remains alive",
                    lease_id=lease_id,
                )
            if scope_error is not None:
                guarded_cleanup_uncertain = True
                detail = f"lease cgroup residue: {scope_error}"
                self._lease_cleanup_errors.append(detail)
                self._record_locked(
                    "lease-release",
                    result="residue",
                    reason=detail,
                    lease_id=lease_id,
                )
            if (
                lease.child is not None
                and not child_residue
                and scope_clean
                and leader_clean
            ):
                try:
                    if self.recovery is None:
                        raise RuntimeSecurityError("child recovery store is unavailable")
                    self.recovery.delete_child(lease_id)
                except (RuntimeSecurityError, OSError) as exc:
                    guarded_cleanup_uncertain = True
                    self._lease_cleanup_errors.append(str(exc))
                    self._record_locked(
                        "lease-release",
                        result="residue",
                        reason=str(exc),
                        lease_id=lease_id,
                    )
            qualification_context = (
                self._connections.get(self._qualification_connection_id)
                if self._qualification_connection_id is not None
                else None
            )
            if (
                qualification_context is not None
                and lease_id in qualification_context.qualification_lease_ids
                and (guarded_cleanup_uncertain or not leader_clean)
            ):
                qualification_context.qualification_cleanup_uncertain = True
            last = not self._leases
            if last and linearize_reason is not None and self.phase != "DRAINING":
                self.phase = "DRAINING"
                self.generation += 1
                self._cancel_transition.set()
                try:
                    self._set_fence_phase("DRAINING")
                except BaseException as exc:
                    detail = (
                        "cannot durably linearize last-lease drain: "
                        + _diagnostic_text(exc, 256)
                    )
                    self._preserve_fence_on_abort = True
                    self._lease_cleanup_errors.append(detail)
                    self._record_locked(
                        "epoch",
                        result="fence-error",
                        reason=detail,
                        generation=self.generation,
                    )
                else:
                    self._record_locked(
                        "epoch",
                        result="draining",
                        reason=linearize_reason,
                        generation=self.generation,
                    )
            return last

    def _cleanup_leader(self, path: Path) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if path.is_symlink() or info.st_uid != os.getuid() or not stat.S_ISSOCK(info.st_mode):
            raise RuntimeSecurityError(f"leader path has unexpected ownership or type: {path}")
        path.unlink()

    def _connection_lost(self, context: _Connection) -> None:
        if context.qualification_pause_id is not None:
            try:
                self._release_qualification_pause(context, reason="control-eof")
            except ScopeError:
                pass
        with self._state_lock:
            owned = tuple(context.leases)
        last = False
        for lease_id in owned:
            last = self._drop_lease(
                lease_id,
                terminate=True,
                linearize_reason="control-eof",
            )
        if owned and last:
            try:
                self._drain_epoch()
            except ProviderError:
                pass
            self._stop.set()

    def _linearize_draining(self, reason: str) -> None:
        with self._state_lock:
            if self.phase == "DRAINING":
                return
            if self._leases:
                return
            self.phase = "DRAINING"
            self.generation += 1
            self._cancel_transition.set()
            self._set_fence_phase("DRAINING")
            self._record_locked("epoch", result="draining", reason=reason, generation=self.generation)

    def _drain_if_idle(self, reason: str) -> None:
        with self._state_lock:
            idle = not self._leases
        if idle:
            self._linearize_draining(reason)
            self._drain_epoch()

    def _drain_epoch(self) -> None:
        # DRAINING is terminal for this epoch. Wake a watchdog probe before
        # waiting for exact scope cleanup; qualification uses the transition
        # cancellation event set at the linearization point.  A foreign
        # watchdog decision must quiesce before this thread takes the
        # transition lock: a fatal watchdog repair can itself need that lock
        # to force the same epoch down.
        self._stop.set()
        contract = self.contract
        stop_ms = contract.timeout_policy.stop_ms if contract is not None else 5_000
        probe_deadline = time.monotonic() + stop_ms / 1_000
        current = threading.get_ident()
        watchdog_error: str | None = None
        with self._probe_condition:
            while any(
                owner != current for owner in self._watchdog_check_owners
            ):
                remaining = probe_deadline - time.monotonic()
                if remaining <= 0:
                    watchdog_error = (
                        "watchdog health-check cleanup exceeded the stop deadline"
                    )
                    break
                self._probe_condition.wait(min(0.1, remaining))
        with self._transition_lock:
            with self._state_lock:
                errors = list(self._lease_cleanup_errors)
            if watchdog_error is not None:
                errors.append(watchdog_error)
            if self.frontend is not None:
                try:
                    self.frontend.revoke(stop_ms / 1_000)
                    self.frontend.close(stop_ms / 1_000)
                except (FrontendDrainTimeout, OSError) as exc:
                    errors.append(str(exc))
            with self._state_lock:
                active = self.active_result
                adapter = self.active_adapter
                self.active_result = None
                self.active_adapter = None
            if active is not None and adapter is not None:
                try:
                    self._stop_result(
                        adapter,
                        active,
                        TransitionDeadline.after_ms(stop_ms),
                        self._effect_id(active.request.generation),
                    )
                except ProviderError as exc:
                    errors.append(str(exc))
            with self._probe_condition:
                while self._active_probes:
                    remaining = probe_deadline - time.monotonic()
                    if remaining <= 0:
                        errors.append("probe cleanup exceeded the stop deadline")
                        break
                    self._probe_condition.wait(min(0.1, remaining))
                if watchdog_error is None and any(
                    owner != current for owner in self._watchdog_check_owners
                ):
                    errors.append(
                        "watchdog health-check ownership reopened during drain"
                    )
            if self.recovery is not None:
                try:
                    if self.recovery.list_probes():
                        errors.append("durable probe recovery records remain after drain")
                except (RuntimeSecurityError, OSError, ValueError) as exc:
                    errors.append(f"cannot prove probe recovery empty: {exc}")
            with self._state_lock:
                if self._leases:
                    errors.append("leases remain after drain")
                self._cleanup_proved = not errors
                self._cleanup_error = "; ".join(errors) if errors else None
                self._record_locked(
                    "epoch",
                    result="empty" if not errors else "fenced",
                    reason=self._cleanup_error or "",
                )
            if errors:
                raise ProviderResidueError("; ".join(errors))

    def _force_shutdown(self, reason: str) -> None:
        errors: list[str] = []
        with self._state_lock:
            if self.phase != "DRAINING":
                self.phase = "DRAINING"
                self.generation += 1
                self._cancel_transition.set()
                try:
                    self._set_fence_phase("DRAINING")
                except BaseException as exc:
                    errors.append(
                        "cannot durably mark forced shutdown: "
                        + _diagnostic_text(exc, 256)
                    )
                    self._preserve_fence_on_abort = True
                self._record_locked(
                    "epoch",
                    result="draining",
                    reason=reason,
                    generation=self.generation,
                )
        with self._state_lock:
            leases = tuple(self._leases)
        self._stop.set()
        for lease_id in leases:
            try:
                self._drop_lease(lease_id, terminate=True)
            except BaseException as exc:
                errors.append(
                    "forced lease cleanup failed: "
                    + _diagnostic_text(exc, 256)
                )
        try:
            self._drain_epoch()
        except BaseException as exc:
            errors.append(
                "forced epoch cleanup failed: " + _diagnostic_text(exc, 256)
            )
        frontend = self.frontend
        if frontend is not None:
            try:
                frontend.qualification_disarm()
            except BaseException as exc:
                errors.append(
                    "forced qualification disarm failed: "
                    + _diagnostic_text(exc, 256)
                )
        if errors:
            with self._state_lock:
                self._preserve_fence_on_abort = True
                self._lease_cleanup_errors.extend(errors)
                self._cleanup_proved = False
                self._cleanup_error = "; ".join(errors)
                self._record_locked(
                    "epoch",
                    result="fenced",
                    reason=self._cleanup_error,
                )

    def _effect_id(self, generation: int) -> str:
        return f"{self.owner_epoch}-g{generation}-start"

    # ------------------------------------------------------------------ watchdog/status

    def _default_health_check(self, result: ProviderResult) -> bool:
        """Bounded semantic liveness through the committed private SOCKS path."""

        if not all(process_matches(item) for item in result.resources.processes):
            return False
        contract = self.contract
        if contract is None:
            return False
        endpoint = result.request.private_endpoint
        deadline = TransitionDeadline.after_ms(
            min(self._watchdog_probe_ms, contract.timeout_policy.probe_ms)
        )
        environment = self._proxy_environment(endpoint)
        try:
            trace = self._run_probe(
                [
                    self._curl_binary(),
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--socks5-hostname",
                    f"{endpoint.host}:{endpoint.port}",
                    _EXIT_IDENTITY_URL,
                ],
                environment,
                deadline,
                "watchdog exit identity",
                max_seconds=self._watchdog_probe_ms / 1_000,
                cancellation=self._stop,
            )
            fields: dict[str, str] = {}
            for line in trace.splitlines():
                if "=" in line:
                    name, value = line.split("=", 1)
                    fields[name] = value.strip()
            identity = fields.get("ip", "")
            country = fields.get("loc", "")
            try:
                ipaddress.ip_address(identity)
            except ValueError:
                return False
            if identity != result.qualification.exit_identity:
                return False
            if country and country in contract.vpn_policy.blocked_countries:
                return False
            if (
                result.request.rung == "vpn"
                and (
                    not country
                    or country not in contract.vpn_policy.countries
                )
            ):
                return False
            return True
        except (ProviderError, RuntimeSecurityError) as exc:
            self._record("watchdog-probe", result="failed", reason=str(exc))
            return False

    def _begin_watchdog_health_check(self) -> bool:
        """Reserve one watchdog check unless qualification owns the epoch."""

        with self._probe_condition:
            if (
                self._stop.is_set()
                or self.phase == "DRAINING"
                or self._qualification_connection_id is not None
            ):
                return False
            owner = threading.get_ident()
            if owner in self._watchdog_check_owners:
                raise RuntimeSecurityError(
                    "watchdog health-check ownership is recursive"
                )
            self._watchdog_check_owners.add(owner)
            self._authority_activity_sequence += 1
            return True

    def _finish_watchdog_health_check(self) -> None:
        with self._probe_condition:
            owner = threading.get_ident()
            if owner not in self._watchdog_check_owners:
                raise RuntimeSecurityError(
                    "watchdog health-check ownership is missing"
                )
            self._watchdog_check_owners.remove(owner)
            self._authority_activity_sequence += 1
            self._probe_condition.notify_all()

    def _watchdog_loop(self) -> None:
        current = threading.current_thread()
        failed_generation: int | None = None
        consecutive_failures = 0
        try:
            while not self._stop.wait(self._watchdog_interval):
                with self._state_lock:
                    if self.phase == "DRAINING":
                        return
                    active = self.active_result
                    leases = tuple(self._leases.values())
                for lease in leases:
                    if not process_matches(lease.wrapper):
                        self._drop_lease(
                            lease.lease_id,
                            terminate=True,
                            linearize_reason="watchdog-wrapper-death",
                        )
                with self._state_lock:
                    no_interest = not self._leases
                if no_interest:
                    self._linearize_draining("watchdog-no-interest")
                    try:
                        self._drain_epoch()
                    except ProviderError:
                        pass
                    self._stop.set()
                    return
                if active is not None:
                    if not self._begin_watchdog_health_check():
                        failed_generation = None
                        consecutive_failures = 0
                        continue
                    try:
                        healthy = self._health_check(active)
                        if healthy:
                            failed_generation = None
                            consecutive_failures = 0
                            continue
                        if failed_generation != active.request.generation:
                            failed_generation = active.request.generation
                            consecutive_failures = 0
                        consecutive_failures += 1
                        self._record(
                            "watchdog",
                            result="unhealthy",
                            rung=active.request.rung,
                            generation=active.request.generation,
                            consecutive_failures=consecutive_failures,
                            failure_threshold=self._watchdog_failures,
                        )
                        if consecutive_failures >= self._watchdog_failures:
                            self._repair_active(active)
                            failed_generation = None
                            consecutive_failures = 0
                    finally:
                        self._finish_watchdog_health_check()
        finally:
            with self._state_lock:
                self._threads.discard(current)

    def status_snapshot(self) -> dict[str, Any]:
        with self._state_lock:
            provisional = sum(item.state == "PROVISIONAL" for item in self._leases.values())
            live = sum(item.state == "LIVE" for item in self._leases.values())
            active = self.active_result
            contract = self.contract
            frontend = self.frontend
            qualification_context = (
                self._connections.get(self._qualification_connection_id)
                if self._qualification_connection_id is not None
                else None
            )
            snapshot: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "release_id": self.release_id,
                "owner_epoch": self.owner_epoch,
                "phase": self.phase,
                "contract_digest": self.contract_digest,
                "generation": self.generation,
                "active_rung": active.request.rung if active is not None else None,
                "egress_ip": active.qualification.exit_identity if active is not None else "",
                "provisional_leases": provisional,
                "live_leases": live,
                "live_interest": len(self._leases),
                "transition": dict(self.transition) if self.transition is not None else None,
                "resources": {
                    "control_connections": len(self._connections),
                    "reserved_control_slots": self._connection_slots,
                    "max_control_connections": (
                        contract.limits.max_control_connections
                        if contract is not None
                        else self.expected_control_cap
                    ),
                    "leases": len(self._leases),
                    "max_leases": contract.limits.max_leases if contract is not None else None,
                    "active_probes": len(self._active_probes),
                    "watchdog_checks": len(self._watchdog_check_owners),
                    "authority_activity_sequence": (
                        self._authority_activity_sequence
                    ),
                    "provider_processes": (
                        len(active.resources.processes) if active is not None else 0
                    ),
                    "provider_paths": len(active.resources.paths) if active is not None else 0,
                    "provider_privileged": (
                        len(active.resources.privileged) if active is not None else 0
                    ),
                    "qualification": {
                        "active": qualification_context is not None,
                        "pause_id": (
                            qualification_context.qualification_pause_id
                            if qualification_context is not None
                            else None
                        ),
                        "lease_count": (
                            len(qualification_context.qualification_lease_ids)
                            if qualification_context is not None
                            else 0
                        ),
                        "frozen_scopes": (
                            len(qualification_context.qualification_frozen)
                            if qualification_context is not None
                            else 0
                        ),
                        "fault_in_progress": (
                            qualification_context.qualification_fault_in_progress
                            if qualification_context is not None
                            else False
                        ),
                    },
                },
                "cleanup_error": self._cleanup_error,
                "watchdog": {
                    "interval_ms": int(self._watchdog_interval * 1_000),
                    "failure_threshold": self._watchdog_failures,
                    "probe_timeout_ms": self._watchdog_probe_ms,
                    "model_requalification": "admission-only",
                    "same_rung_repair_limit": 1,
                    "same_rung_repaired": sorted(self._same_rung_repairs),
                    "last_repair": (
                        dict(self._last_repair)
                        if self._last_repair is not None
                        else None
                    ),
                },
                "diagnostics": list(self._diagnostics),
            }
        if frontend is not None:
            snapshot["resources"]["frontend"] = asdict(frontend.gauges())
            snapshot["resources"]["qualification"]["frontend"] = (
                self._qualification_stream_state(frontend)
                if qualification_context is not None
                else None
            )
        else:
            snapshot["resources"]["frontend"] = None
            snapshot["resources"]["qualification"]["frontend"] = None
        return snapshot

    def _record(self, event: str, *, result: str, **fields: Any) -> None:
        with self._state_lock:
            self._record_locked(event, result=result, **fields)

    def _record_locked(self, event: str, *, result: str, **fields: Any) -> None:
        self._sequence += 1
        record: dict[str, Any] = {
            "sequence": self._sequence,
            "monotonic_ms": time.monotonic_ns() // 1_000_000,
            "event": _diagnostic_text(event, 64),
            "result": _diagnostic_text(result, 128),
        }
        for name, value in fields.items():
            if value is None or type(value) in (bool, int):
                record[name] = value
            else:
                record[name] = _diagnostic_text(value, 512)
        self._diagnostics.append(record)

    # ------------------------------------------------------------------ live qualifier

    def _default_qualifier(
        self,
        endpoint: Endpoint,
        request: ProviderRequest,
        deadline: TransitionDeadline,
        cancellation: threading.Event | None,
    ) -> QualificationEvidence:
        """Probe model and exit identity through the exact private SOCKS path."""

        contract = self.contract
        if contract is None:
            raise ProviderError("qualification has no immutable contract")
        clean = self._proxy_environment(endpoint)
        samples: list[str] = []
        countries: list[str] = []
        country: str | None = None
        for index in range(contract.stability_policy.sample_count):
            if cancellation is not None and cancellation.is_set():
                raise ProviderCancelled("qualification was cancelled")
            trace = self._run_probe(
                [
                    self._curl_binary(),
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--socks5-hostname",
                    f"{endpoint.host}:{endpoint.port}",
                    _EXIT_IDENTITY_URL,
                ],
                clean,
                deadline,
                "exit identity",
                max_seconds=contract.timeout_policy.probe_ms / 1_000,
                cancellation=cancellation,
            )
            fields = {}
            for line in trace.splitlines():
                if "=" in line:
                    name, value = line.split("=", 1)
                    fields[name] = value.strip()
            identity = fields.get("ip", "")
            try:
                ipaddress.ip_address(identity)
            except ValueError:
                raise ProviderError("exit identity probe returned no valid IP")
            samples.append(identity)
            observed_country = fields.get("loc", "")
            if observed_country and re.fullmatch(r"[A-Z]{2}", observed_country):
                country = observed_country
                countries.append(observed_country)
            if country in contract.vpn_policy.blocked_countries:
                raise ProviderError(f"exit country {country} is blocked by the contract")
            if (
                request.rung == "vpn"
                and (
                    country is None
                    or country not in contract.vpn_policy.countries
                )
            ):
                raise ProviderError(
                    f"VPN exit country {country} is outside the contract allowlist"
                )
            if index + 1 < contract.stability_policy.sample_count:
                wait = contract.stability_policy.sample_interval_ms / 1_000
                remaining = deadline.remaining_seconds("stability interval")
                duration = min(wait, remaining)
                if cancellation is not None:
                    if cancellation.wait(duration):
                        raise ProviderCancelled("qualification was cancelled")
                else:
                    time.sleep(duration)
                if wait > remaining:
                    deadline.check("stability interval")
                deadline.check("stability interval")
        if contract.stability_policy.require_same_exit and len(set(samples)) != 1:
            raise ProviderError("exit identity changed during qualification")
        if request.rung == "vpn" and len(countries) != len(samples):
            raise ProviderError("VPN qualification did not return a country for every sample")
        if request.rung == "vpn" and len(set(countries)) != 1:
            raise ProviderError("VPN exit country changed during qualification")

        model_output = self._models_through_proxy(
            request,
            clean,
            deadline,
            cancellation,
        )
        models = {
            match.group(1)
            for line in model_output.splitlines()
            if (match := re.match(r"^\s+[-*]\s+(\S+)", line)) is not None
        }
        if request.model_id not in models:
            raise ProviderError(
                f"private route does not offer concrete model {request.model_id!r}"
            )
        return QualificationEvidence(
            endpoint=endpoint,
            model_id=request.model_id,
            exit_identity=samples[0],
            country_code=country,
            dns_path_verified=True,
            byte_path_verified=bool(model_output),
            stability_samples=tuple(samples),
        )

    @staticmethod
    def _curl_binary() -> str:
        """Return fixed production curl, with one explicit test-only seam."""

        if os.environ.get("GROK_TESTING") == "1":
            candidate = os.environ.get("GROK_TEST_CURL_BIN")
            if candidate is not None:
                path = Path(candidate)
                if not path.is_absolute():
                    raise ProviderError("GROK_TEST_CURL_BIN must be absolute")
                try:
                    info = path.lstat()
                except OSError as exc:
                    raise ProviderError(f"test curl executable is unavailable: {path}") from exc
                if path.is_symlink() or not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
                    raise ProviderError(f"test curl executable is unsafe: {path}")
                return str(path)
        return "/usr/bin/curl"

    @staticmethod
    def _proxy_environment(endpoint: Endpoint) -> dict[str, str]:
        proxy = f"socks5h://{endpoint.host}:{endpoint.port}"
        clean = {
            key: value
            for key, value in os.environ.items()
            if key
            not in {
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "NO_PROXY",
                "FTP_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
                "no_proxy",
                "ftp_proxy",
            }
        }
        clean.update(
            {
                "ALL_PROXY": proxy,
                "NO_PROXY": "localhost,127.0.0.1,::1,100.64.0.0/10,.ts.net",
                "no_proxy": "localhost,127.0.0.1,::1,100.64.0.0/10,.ts.net",
            }
        )
        return clean

    def _models_through_proxy(
        self,
        request: ProviderRequest,
        environment: Mapping[str, str],
        deadline: TransitionDeadline,
        cancellation: threading.Event | None = None,
    ) -> str:
        source_home = Path(os.environ.get("GROK_HOME", str(Path.home() / ".grok")))
        qualifier_root = self.control_root / "qualify"
        _secure_directory(qualifier_root)
        temporary = Path(tempfile.mkdtemp(prefix="models-", dir=qualifier_root))
        os.chmod(temporary, 0o700)
        try:
            for name in ("auth.json", "config.toml", "managed_config.toml"):
                source = source_home / name
                try:
                    info = source.lstat()
                except FileNotFoundError:
                    continue
                if source.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                    raise ProviderError(f"unsafe Grok qualification input: {source}")
                data = source.read_bytes()
                if len(data) > _MAX_PROBE_OUTPUT:
                    raise ProviderError(f"oversized Grok qualification input: {source}")
                destination = temporary / name
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                    0o600,
                )
                try:
                    view = memoryview(data)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise OSError("short Grok qualification file write")
                        view = view[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            env = dict(environment)
            env["GROK_HOME"] = str(temporary)
            grok = self._grok_executable
            if grok is None:
                raise ProviderError("qualification has no verified Grok executable")
            try:
                grok.verify()
            except (GrokExecutableError, OSError) as exc:
                raise ProviderError(f"Grok executable changed before qualification: {exc}") from exc
            leader = temporary / "probe-leader.sock"
            return self._run_probe(
                [
                    sys.executable,
                    "-I",
                    str(self.release_dir / "grok_ms" / "fd_exec.py"),
                    str(grok.descriptor),
                    str(grok.path),
                    "models",
                    "--leader-socket",
                    str(leader),
                ],
                env,
                deadline,
                f"model {request.model_id}",
                max_seconds=self.contract.timeout_policy.probe_ms / 1_000
                if self.contract is not None
                else None,
                pass_fds=(grok.descriptor,),
                cancellation=cancellation,
            )
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def _run_probe(
        self,
        argv: Sequence[str],
        environment: Mapping[str, str],
        deadline: TransitionDeadline,
        operation: str,
        *,
        max_seconds: float | None = None,
        pass_fds: Sequence[int] = (),
        cancellation: threading.Event | None = None,
    ) -> str:
        """Run one probe behind a parent-death barrier in an exact cgroup."""

        if cancellation is not None and cancellation.is_set():
            raise ProviderCancelled(f"{operation} probe was cancelled")
        if self.recovery is None:
            raise RuntimeSecurityError("probe recovery store is unavailable")
        timeout = deadline.remaining_seconds(operation)
        if max_seconds is not None:
            timeout = min(timeout, max_seconds)
        probe_expires = time.monotonic() + timeout
        cleanup_seconds = (
            self.contract.timeout_policy.stop_ms / 1_000
            if self.contract is not None
            else 5.0
        )
        parent = current_process_identity()
        planned_scope = self._process_scopes.plan()
        probe_id = secrets.token_hex(16)
        with self._probe_condition:
            self._active_probes.add(probe_id)
            self._authority_activity_sequence += 1
        barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
        process: subprocess.Popen[bytes] | None = None
        child: ProcessIdentity | None = None
        pidfd: int | None = None
        scope_handle: ScopeHandle | None = None
        record: ProbeRecoveryRecord | None = None
        record_attempted = False
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        primary_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        try:
            inherited = tuple(sorted(set(pass_fds) | {barrier_read}))
            process = subprocess.Popen(
                [
                    "/usr/bin/python3",
                    "-I",
                    str(self.release_dir / "grok_ms" / "parent_guard.py"),
                    "--parent-pid",
                    str(parent.pid),
                    "--parent-start-ticks",
                    str(parent.start_ticks),
                    "--parent-boot-id",
                    parent.boot_id,
                    "--barrier-fd",
                    str(barrier_read),
                    "--",
                    *list(argv),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(environment),
                close_fds=True,
                pass_fds=inherited,
                start_new_session=True,
            )
            os.close(barrier_read)
            barrier_read = -1
            child = ProcessIdentity(
                process.pid,
                read_pid_start_ticks(process.pid),
                parent.boot_id,
            )
            if not hasattr(os, "pidfd_open"):
                raise ScopeError("pidfd probe ownership is unavailable")
            pidfd = os.pidfd_open(child.pid, 0)
            if not _pidfd_matches(pidfd, child):
                raise ScopeError("probe pidfd does not match the barriered child")
            record = ProbeRecoveryRecord(
                schema_version=SCHEMA_VERSION,
                record_version=_PROBE_RECOVERY_RECORD_VERSION,
                release_id=self.release_id,
                owner_epoch=self.owner_epoch,
                probe_id=probe_id,
                phase="PREPARED",
                child=child,
                scope=planned_scope,
            )
            record_attempted = True
            self.recovery.put_probe(record)
            if cancellation is not None and cancellation.is_set():
                raise ProviderCancelled(f"{operation} probe was cancelled")
            scope_handle = self._process_scopes.create(planned_scope)
            record = replace(
                record,
                phase="SCOPE_CREATED",
                scope=scope_handle.identity,
            )
            self.recovery.replace_probe(record)
            self._process_scopes.attach(scope_handle, child)
            record = replace(record, phase="ATTACHED")
            self.recovery.replace_probe(record)
            if cancellation is not None and cancellation.is_set():
                raise ProviderCancelled(f"{operation} probe was cancelled")
            if os.write(barrier_write, b"\x01") != 1:
                raise ScopeError("short probe barrier release")
            os.close(barrier_write)
            barrier_write = -1

            assert process.stdout is not None and process.stderr is not None
            streams = {
                process.stdout.fileno(): stdout_buffer,
                process.stderr.fileno(): stderr_buffer,
            }
            for descriptor in streams:
                os.set_blocking(descriptor, False)
            while streams or process.poll() is None:
                if cancellation is not None and cancellation.is_set():
                    raise ProviderCancelled(f"{operation} probe was cancelled")
                remaining = probe_expires - time.monotonic()
                if remaining <= 0:
                    raise ProviderError(f"{operation} probe timed out after {timeout:.3f}s")
                readable, _writable, _exceptional = select.select(
                    tuple(streams), (), (), min(0.05, remaining)
                )
                for descriptor in readable:
                    buffer = streams[descriptor]
                    allowance = _MAX_PROBE_OUTPUT - len(buffer)
                    try:
                        chunk = os.read(descriptor, min(65_536, allowance + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        streams.pop(descriptor, None)
                        continue
                    buffer.extend(chunk)
                    if len(buffer) > _MAX_PROBE_OUTPUT:
                        raise ProviderError(f"{operation} probe output exceeded its bound")
        except BaseException as exc:
            primary_error = exc
        finally:
            for descriptor in (barrier_read, barrier_write):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            if process is not None:
                if record is not None and child is not None:
                    try:
                        self._process_scopes.reconcile(
                            record.scope,
                            record.phase,
                            child,
                            pidfd,
                            cleanup_seconds,
                            handle=scope_handle,
                        )
                    except BaseException as exc:
                        cleanup_error = exc
                else:
                    try:
                        process.kill()
                    except (OSError, ProcessLookupError):
                        pass
                if scope_handle is not None:
                    try:
                        scope_handle.close()
                    except OSError as exc:
                        cleanup_error = cleanup_error or exc
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError as exc:
                            cleanup_error = cleanup_error or exc
                try:
                    process.wait(timeout=cleanup_seconds)
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
                if cleanup_error is None and record_attempted:
                    try:
                        persisted = self.recovery.load_probe(probe_id)
                        if persisted is not None:
                            if record is None or not _same_probe_authority(
                                persisted,
                                record,
                            ):
                                raise RuntimeSecurityError(
                                    "persisted probe record conflicts with its cleanup authority"
                                )
                            self.recovery.delete_probe(probe_id)
                    except BaseException as exc:
                        cleanup_error = exc
            if pidfd is not None:
                try:
                    os.close(pidfd)
                except OSError as exc:
                    cleanup_error = cleanup_error or exc
            with self._probe_condition:
                self._active_probes.discard(probe_id)
                self._authority_activity_sequence += 1
                self._probe_condition.notify_all()

        if cleanup_error is not None:
            detail = f"probe scope cleanup is uncertain: {cleanup_error}"
            with self._state_lock:
                self._lease_cleanup_errors.append(detail)
                self._record_locked("probe", result="residue", reason=detail)
            self._preserve_fence_on_abort = True
            raise ScopeError(detail) from primary_error
        if primary_error is not None:
            if isinstance(primary_error, (ProviderError, RuntimeSecurityError)):
                raise primary_error
            raise ProviderError(f"{operation} probe failed: {primary_error}") from primary_error
        assert process is not None
        if process.returncode != 0:
            stderr = bytes(stderr_buffer)
            detail = (
                f"stderr_bytes={len(stderr)} "
                f"stderr_sha256={hashlib.sha256(stderr).hexdigest()}"
            )
            raise ProviderError(f"{operation} probe exited {process.returncode}: {detail}")
        try:
            return bytes(stdout_buffer).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ProviderError(f"{operation} probe returned non-UTF-8 output") from exc

    # ------------------------------------------------------------------ fence/finalization

    def _set_fence_phase(self, phase: str) -> None:
        if self._fence_record is None or self.fences is None:
            raise RuntimeSecurityError("recovery fence is not published")
        if self._fence_record.phase == phase:
            return
        existing = self.fences.load()
        if existing is None or existing.owner_epoch != self.owner_epoch:
            raise RuntimeSecurityError("recovery fence ownership changed")
        updated = replace(existing, phase=phase)
        _atomic_replace_json(self.fences.path, updated.to_dict())
        self._fence_record = updated

    def _release_compatibility_lock(self) -> None:
        descriptor = self._compatibility_fd
        self._compatibility_fd = None
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _join_threads(self) -> bool:
        stop_seconds = (
            self.contract.timeout_policy.stop_ms / 1_000
            if self.contract is not None
            else 5.0
        )
        deadline = time.monotonic() + max(5.0, min(60.0, stop_seconds + 1.0))
        current = threading.current_thread()
        # A draining request sets _stop before its handler sends the terminal
        # release/error packet. Give ordinary handlers a short grace period;
        # only then break control reads that would otherwise reserve a slot.
        grace_deadline = min(deadline, time.monotonic() + 0.5)
        while time.monotonic() < grace_deadline:
            with self._state_lock:
                threads = tuple(
                    thread
                    for thread in self._threads
                    if thread is not current and thread.is_alive()
                )
            if not threads:
                return True
            for thread in threads:
                thread.join(max(0.0, min(0.05, grace_deadline - time.monotonic())))
        with self._state_lock:
            connections = tuple(self._connections.values())
        for connection in connections:
            try:
                connection.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        while True:
            with self._state_lock:
                threads = tuple(
                    thread
                    for thread in self._threads
                    if thread is not current and thread.is_alive()
                )
            if not threads or time.monotonic() >= deadline:
                return not threads
            for thread in threads:
                thread.join(max(0.0, min(0.2, deadline - time.monotonic())))

    def _release_epoch_scope(self) -> None:
        if not self._scoped_bootstrap:
            return
        if self._detached_scopes is None:
            raise RuntimeSecurityError("supervisor epoch scope store is unavailable")
        record = self._detached_scopes.load("supervisor-epoch")
        if (
            record is None
            or record.phase != "OWNED"
            or record.release_id != self.release_id
            or record.owner_epoch != self.owner_epoch
            or record.child != self.owner
        ):
            raise RuntimeSecurityError("supervisor epoch scope authority changed")
        stop_seconds = (
            self.contract.timeout_policy.stop_ms / 1_000
            if self.contract is not None
            else 5.0
        )
        self._process_scopes.release_current(
            record.scope,
            max(1.0, min(60.0, stop_seconds)),
        )
        self._detached_scopes.delete(record)

    def finalize(self) -> None:
        if self._finalized:
            return
        self._finalized = True
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        errors: list[str] = []
        with self._state_lock:
            active_probes = tuple(self._active_probes)
            qualification_guard_active = self._qualification_connection_id is not None
            live_threads = tuple(
                thread
                for thread in self._threads
                if thread is not threading.current_thread() and thread.is_alive()
            )
        if self._preserve_fence_on_abort:
            errors.append("an earlier cleanup failure requires durable recovery")
        if active_probes:
            errors.append("active probe scopes remain during finalization")
        if qualification_guard_active:
            errors.append("qualification admission fence remains during finalization")
        if live_threads:
            errors.append("supervisor worker threads remain during finalization")
        if self.recovery is not None:
            try:
                if (
                    self.recovery.list_probes()
                    or self.recovery.list_children()
                    or self.recovery.list_providers()
                    or self.recovery.list_provider_scopes()
                ):
                    errors.append("durable recovery records remain during finalization")
            except (RuntimeSecurityError, OSError, ValueError) as exc:
                errors.append(f"cannot prove durable recovery state empty: {exc}")
        if self.intents is not None:
            try:
                if _intent_records(self.intents):
                    errors.append("durable effect intents remain during finalization")
            except (RuntimeSecurityError, OSError, ValueError) as exc:
                errors.append(f"cannot prove durable intent state empty: {exc}")
        if self._detached_scopes is not None:
            try:
                detached = self._detached_scopes.list_records()
                if self._scoped_bootstrap:
                    if len(detached) != 1 or detached[0].kind != "supervisor-epoch":
                        errors.append(
                            "unexpected detached scope records remain during finalization"
                        )
                elif detached:
                    errors.append(
                        "detached scope records remain during unscoped finalization"
                    )
            except (RuntimeSecurityError, OSError, ValueError) as exc:
                errors.append(f"cannot prove detached scope state empty: {exc}")
        for path, allowed in (
            (self._ready_path, (stat.S_IFREG,)),
            (self._socket_path, (stat.S_IFSOCK,)),
        ):
            try:
                _unlink_owned(path, allowed=allowed)
            except (RuntimeSecurityError, OSError) as exc:
                errors.append(str(exc))
        if self._cleanup_proved and not errors:
            try:
                self._release_epoch_scope()
            except (RuntimeSecurityError, ScopeError, OSError, ValueError) as exc:
                errors.append(str(exc))
        if self._cleanup_proved and not errors and self.fences is not None:
            try:
                self.fences.clear(self.owner_epoch)
                self._fence_record = None
            except (FenceBusyError, RuntimeSecurityError, OSError) as exc:
                errors.append(str(exc))
        self._release_compatibility_lock()
        try:
            self._close_provider_canary()
        except OSError as exc:
            errors.append(str(exc))
        grok = self._grok_executable
        self._grok_executable = None
        if grok is not None:
            try:
                grok.close()
            except OSError as exc:
                errors.append(str(exc))
        if errors:
            self._cleanup_proved = False
            self._cleanup_error = "; ".join(errors)


@dataclass(frozen=True, slots=True)
class RecoveryOutcome:
    recovered: bool
    owner_epoch: str | None
    provider_records: int
    child_records: int
    probe_records: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _run_compatibility_handoff(
    control_root: Path,
    release_dir: Path,
    owner_epoch: str,
    release_id: str,
    *,
    timeout_seconds: float = 20.0,
    cleanup_timeout_seconds: float = 20.0,
    process_scopes: ProcessScopeBackend | None = None,
    detached_scopes: DetachedScopeStore | None = None,
    recovery_deadline: TransitionDeadline | None = None,
) -> None:
    """Stop/prove old singleton resources in a durable transitive scope."""

    _token(owner_epoch, "handoff.owner_epoch")
    if _DIGEST_RE.fullmatch(release_id) is None:
        raise RecoveryRequired("compatibility handoff requires an installed SHA-256 release")
    if (
        type(timeout_seconds) not in (int, float)
        or timeout_seconds <= 0
        or type(cleanup_timeout_seconds) not in (int, float)
        or cleanup_timeout_seconds <= 0
    ):
        raise ValueError("compatibility handoff timeouts must be positive")
    if recovery_deadline is not None and not isinstance(
        recovery_deadline, TransitionDeadline
    ):
        raise ValueError("compatibility handoff recovery deadline is invalid")

    def bounded_remaining(cap: float, operation: str) -> float:
        if recovery_deadline is None:
            return float(cap)
        return min(float(cap), recovery_deadline.remaining_seconds(operation))

    if recovery_deadline is not None:
        recovery_deadline.check("offline compatibility handoff admission")
    runtime = SecureRuntime(control_root)
    runtime.verify()
    fence = FenceStore(runtime).load()
    if (
        fence is None
        or fence.owner_epoch != owner_epoch
        or fence.release_id != release_id
        or fence.phase not in {"BOOTSTRAPPING", "RECOVERING"}
    ):
        raise RecoveryRequired(
            "compatibility handoff lacks its exact bootstrapping or recovery fence"
        )
    backend = process_scopes or LinuxCgroupV2Scope()
    scope_store = detached_scopes or DetachedScopeStore(control_root)
    if scope_store.load("compatibility-handoff") is not None:
        raise RecoveryRequired("a previous compatibility handoff scope remains")
    account = pwd.getpwuid(os.getuid())
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "XDG_STATE_HOME": str(Path(account.pw_dir) / ".local/state"),
        "GROK_HANDOFF_MODE": "1",
        "GROK_HANDOFF_OWNER_EPOCH": owner_epoch,
        "GROK_HANDOFF_RELEASE_ID": release_id,
        "GROK_PROXY_PORT": "1080",
    }
    if os.environ.get("GROK_TESTING") == "1":
        environment["GROK_TESTING"] = "1"
        environment["GROK_TEST_CONTROL_DIR"] = str(control_root)
        for name in (
            "GROK_TEST_VPN_BROKER",
            "GROK_TAILSCALE_BIN",
            "GROK_TAILSCALED_BIN",
            "GROK_PRIMARY_TAILSCALE_BIN",
        ):
            if name in os.environ:
                environment[name] = os.environ[name]
    parent = current_process_identity()
    guard = release_dir / "grok_ms" / "parent_guard.py"
    script = release_dir / "egress.sh"
    planned = backend.plan()
    barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
    process: subprocess.Popen[bytes] | None = None
    child: ProcessIdentity | None = None
    pidfd: int | None = None
    handle: ScopeHandle | None = None
    record: DetachedScopeRecord | None = None
    record_persisted = False
    primary_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    try:
        if recovery_deadline is not None:
            recovery_deadline.check("offline compatibility handoff spawn")
        process = subprocess.Popen(
            [
                sys.executable,
                str(guard),
                "--parent-pid",
                str(parent.pid),
                "--parent-start-ticks",
                str(parent.start_ticks),
                "--parent-boot-id",
                parent.boot_id,
                "--barrier-fd",
                str(barrier_read),
                "--",
                "/bin/bash",
                str(script),
                "compatibility-handoff",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=(barrier_read,),
            start_new_session=True,
            env=environment,
        )
        os.close(barrier_read)
        barrier_read = -1
        child = ProcessIdentity(
            process.pid,
            read_pid_start_ticks(process.pid),
            parent.boot_id,
        )
        if not hasattr(os, "pidfd_open"):
            raise ScopeError("pidfd handoff ownership is unavailable")
        pidfd = os.pidfd_open(child.pid, 0)
        if not _pidfd_matches(pidfd, child):
            raise ScopeError("handoff pidfd does not match the barriered child")
        record = DetachedScopeRecord(
            schema_version=SCHEMA_VERSION,
            record_version=1,
            release_id=release_id,
            kind="compatibility-handoff",
            phase="PREPARED",
            owner_epoch=owner_epoch,
            child=child,
            scope=planned,
        )
        if not scope_store.put(record):
            raise RuntimeSecurityError("compatibility handoff record was replayed unexpectedly")
        record_persisted = True
        handle = backend.create(planned)
        created = replace(record, phase="SCOPE_CREATED", scope=handle.identity)
        scope_store.replace(record, created)
        record = created
        backend.attach(handle, child)
        attached = replace(record, phase="ATTACHED")
        scope_store.replace(record, attached)
        record = attached
        if recovery_deadline is not None:
            recovery_deadline.check("offline compatibility handoff release")
        if os.write(barrier_write, b"\x01") != 1:
            raise ScopeError("short compatibility handoff barrier release")
        os.close(barrier_write)
        barrier_write = -1
        try:
            wait_seconds = bounded_remaining(
                float(timeout_seconds),
                "offline compatibility handoff",
            )
            if recovery_deadline is not None:
                # Keep part of the one offline budget available for exact
                # cgroup reconciliation when the compatibility command stalls.
                cleanup_reserve = min(1.0, max(0.02, wait_seconds / 5))
                if wait_seconds <= cleanup_reserve:
                    raise ProviderTimeout(
                        "cumulative deadline expired before compatibility handoff"
                    )
                wait_seconds -= cleanup_reserve
            returncode = process.wait(timeout=wait_seconds)
        except subprocess.TimeoutExpired as exc:
            raise RecoveryRequired("compatibility handoff timed out") from exc
        if returncode != 0:
            raise RecoveryRequired(
                f"compatibility handoff did not prove empty (status {returncode})"
            )
    except BaseException as exc:
        primary_error = exc
    finally:
        for descriptor in (barrier_read, barrier_write):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        persisted: DetachedScopeRecord | None = None
        if record is not None and child is not None:
            journal_error: BaseException | None = None
            try:
                persisted = scope_store.load("compatibility-handoff")
                if persisted is not None and not same_detached_authority(
                    persisted, record
                ):
                    journal_error = RuntimeSecurityError(
                        "compatibility handoff scope authority changed"
                    )
                    persisted = None
            except BaseException as exc:
                journal_error = exc
                persisted = None
            try:
                phases = {"PREPARED": 0, "SCOPE_CREATED": 1, "ATTACHED": 2}
                authority = record
                if persisted is not None and phases[persisted.phase] >= phases[record.phase]:
                    authority = persisted
                # Containment is unconditional and non-waiting.  It precedes
                # all budget checks so an exhausted recovery deadline cannot
                # return while the handoff or a forked descendant still runs.
                if pidfd is not None:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    except (AttributeError, OSError, ProcessLookupError):
                        pass
                if authority.scope.created:
                    backend.force_kill(
                        authority.scope,
                        handle=handle,
                    )
                cleanup_seconds = bounded_remaining(
                    float(cleanup_timeout_seconds),
                    "offline compatibility handoff reconciliation",
                )
                backend.reconcile(
                    authority.scope,
                    authority.phase,
                    authority.child,
                    pidfd,
                    cleanup_seconds,
                    handle=handle,
                )
                if record_persisted and journal_error is None:
                    if persisted is None or not scope_store.delete(persisted):
                        raise RuntimeSecurityError(
                            "compatibility handoff record disappeared before cleanup"
                        )
                if journal_error is not None:
                    raise journal_error
            except BaseException as exc:
                cleanup_error = exc
        elif process is not None:
            try:
                if pidfd is not None:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                else:
                    process.kill()
            except (AttributeError, OSError, ProcessLookupError):
                pass
        if handle is not None:
            try:
                handle.close()
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        if process is not None:
            try:
                process.wait(
                    timeout=min(
                        1.0,
                        bounded_remaining(
                            float(cleanup_timeout_seconds),
                            "offline compatibility handoff reap",
                        ),
                    )
                )
            except subprocess.TimeoutExpired as exc:
                cleanup_error = cleanup_error or exc
            except ProviderTimeout as exc:
                cleanup_error = cleanup_error or exc
        if pidfd is not None:
            try:
                os.close(pidfd)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
    if cleanup_error is not None:
        raise RecoveryRequired(
            f"compatibility handoff scope cleanup is uncertain: {cleanup_error}"
        ) from primary_error
    if primary_error is not None:
        if isinstance(primary_error, RecoveryRequired):
            raise primary_error
        raise RecoveryRequired("compatibility handoff failed before completion") from primary_error
    if recovery_deadline is not None:
        recovery_deadline.check("offline compatibility handoff completion")


def _open_recovery_lock(path: Path, *, create: bool = True) -> int:
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise RuntimeSecurityError(f"recovery lock is unavailable: {path}") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or (not create and stat.S_IMODE(info.st_mode) != 0o600)
        ):
            raise RuntimeSecurityError(f"unsafe recovery lock: {path}")
        if create:
            os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise FenceBusyError(f"recovery lock is already held: {path}") from exc
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _close_recovery_lock(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _recover_child(
    record: ChildRecoveryRecord,
    store: RecoveryStore,
    control_root: Path,
    deadline: TransitionDeadline,
    process_scopes: ProcessScopeBackend,
) -> None:
    deadline.check("offline child recovery")
    leaders = control_root / "leaders"
    _secure_directory(leaders)
    leader = Path(record.leader_path)
    if leader.parent != leaders or not re.fullmatch(r"l-[0-9a-f]{12}\.sock", leader.name):
        raise RuntimeSecurityError("child recovery leader path escapes the leader directory")
    pidfd: int | None = None
    if process_matches(record.child):
        if not hasattr(os, "pidfd_open"):
            raise RecoveryRequired("pidfd recovery is unavailable")
        pidfd = os.pidfd_open(record.child.pid, 0)
        try:
            if not _pidfd_matches(pidfd, record.child):
                raise RecoveryRequired("attached child identity changed during recovery")
        except Exception:
            os.close(pidfd)
            raise
    try:
        process_scopes.reconcile(
            record.scope,
            record.phase,
            record.child,
            pidfd,
            deadline.remaining_seconds("offline child scope reconciliation"),
        )
    finally:
        if pidfd is not None:
            os.close(pidfd)
    deadline.check("offline child leader cleanup")
    try:
        info = leader.lstat()
    except FileNotFoundError:
        pass
    else:
        if leader.is_symlink() or info.st_uid != os.getuid() or not stat.S_ISSOCK(info.st_mode):
            raise RuntimeSecurityError(f"unsafe recovered leader path: {leader}")
        leader.unlink()
    deadline.check("offline child record deletion")
    store.delete_child(record.lease_id)


def _recover_probe(
    record: ProbeRecoveryRecord,
    store: RecoveryStore,
    deadline: TransitionDeadline,
    process_scopes: ProcessScopeBackend,
) -> None:
    """Reconcile a dead epoch's exact probe cgroup before workspace cleanup."""

    deadline.check("offline probe recovery")
    pidfd: int | None = None
    if process_matches(record.child):
        if not hasattr(os, "pidfd_open"):
            raise RecoveryRequired("pidfd probe recovery is unavailable")
        pidfd = os.pidfd_open(record.child.pid, 0)
        try:
            if not _pidfd_matches(pidfd, record.child):
                raise RecoveryRequired("probe identity changed during recovery")
        except Exception:
            os.close(pidfd)
            raise
    try:
        process_scopes.reconcile(
            record.scope,
            record.phase,
            record.child,
            pidfd,
            deadline.remaining_seconds("offline probe scope reconciliation"),
        )
    finally:
        if pidfd is not None:
            os.close(pidfd)
    deadline.check("offline probe record deletion")
    store.delete_probe(record.probe_id)


def _recover_detached_scope(
    record: DetachedScopeRecord,
    store: DetachedScopeStore,
    deadline: TransitionDeadline,
    process_scopes: ProcessScopeBackend,
    *,
    delete_record: bool = True,
) -> None:
    deadline.check(f"offline {record.kind} recovery")
    pidfd: int | None = None
    if process_matches(record.child):
        if not hasattr(os, "pidfd_open"):
            raise RecoveryRequired("pidfd detached-scope recovery is unavailable")
        pidfd = os.pidfd_open(record.child.pid, 0)
        try:
            if not _pidfd_matches(pidfd, record.child):
                raise RecoveryRequired(
                    "detached scope child identity changed during recovery"
                )
        except Exception:
            os.close(pidfd)
            raise
    try:
        process_scopes.reconcile(
            record.scope,
            "ATTACHED" if record.phase == "OWNED" else record.phase,
            record.child,
            pidfd,
            deadline.remaining_seconds(
                f"offline {record.kind} scope reconciliation"
            ),
        )
    finally:
        if pidfd is not None:
            os.close(pidfd)
    if delete_record:
        deadline.check(f"offline {record.kind} record deletion")
        store.delete(record)


def _cleanup_qualification_residue(control_root: Path) -> None:
    root = control_root / "qualify"
    if not root.exists() and not root.is_symlink():
        return
    _secure_directory(root)
    for temporary in tuple(root.iterdir()):
        info = temporary.lstat()
        if (
            temporary.is_symlink()
            or not temporary.name.startswith("models-")
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise RuntimeSecurityError(f"unsafe qualification residue: {temporary}")
        for entry in tuple(temporary.iterdir()):
            child_info = entry.lstat()
            if entry.is_symlink() or child_info.st_uid != os.getuid():
                raise RuntimeSecurityError(f"unsafe qualification entry: {entry}")
            if stat.S_ISREG(child_info.st_mode):
                if stat.S_IMODE(child_info.st_mode) != 0o600:
                    raise RuntimeSecurityError(
                        f"qualification file has unsafe mode: {entry}"
                    )
            elif not stat.S_ISSOCK(child_info.st_mode):
                raise RuntimeSecurityError(
                    f"qualification entry has an unsafe type: {entry}"
                )
            entry.unlink()
        temporary.rmdir()
    root.rmdir()


def _assert_directory_empty(path: Path, label: str) -> None:
    if not path.exists() and not path.is_symlink():
        return
    descriptor = _open_secure_directory(path)
    try:
        entries: list[str] = []
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                entries.append(entry.name)
                if len(entries) == 8:
                    break
    finally:
        os.close(descriptor)
    if entries:
        raise RecoveryRequired(
            f"{label} residue remains: " + ", ".join(entries)
        )


def _cleanup_dead_control_endpoints(
    control_root: Path, fence: FenceRecord | None
) -> None:
    ready = control_root / "supervisor.ready"
    control_socket = control_root / "supervisor.sock"
    try:
        value = _read_secure_json(ready)
    except RuntimeSecurityError as exc:
        # Older direct-final publishers could be killed after creating the
        # secure file but before completing its JSON. Readiness is derived
        # state, so a dead owner may discard only that exact parse-failure
        # shape after all recovery locks are held.
        if not isinstance(exc.__cause__, ProtocolError):
            raise
        info = ready.lstat()
        if (
            ready.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise
        _durable_unlink(ready)
        value = None
    if value is not None:
        expected = {
            "schema_version",
            "protocol_version",
            "release_id",
            "owner_epoch",
            "pid",
            "pid_start_ticks",
            "boot_id",
            "socket",
        }
        actual_fields = frozenset(value)
        if actual_fields not in {
            frozenset(expected),
            frozenset({*expected, "provider_canary_nonce"}),
        }:
            raise RuntimeSecurityError("stale readiness record has an unexpected shape")
        if (
            "provider_canary_nonce" in value
            and (
                type(value["provider_canary_nonce"]) is not str
                or _CANARY_NONCE_RE.fullmatch(
                    value["provider_canary_nonce"]
                )
                is None
            )
        ):
            raise RuntimeSecurityError(
                "stale readiness provider canary identity is invalid"
            )
        if fence is None or (
            value["release_id"],
            value["owner_epoch"],
            value["pid"],
            value["pid_start_ticks"],
            value["boot_id"],
            value["socket"],
        ) != (
            fence.release_id,
            fence.owner_epoch,
            fence.pid,
            fence.pid_start_ticks,
            fence.boot_id,
            str(control_socket),
        ):
            raise RuntimeSecurityError("stale readiness record differs from the recovery fence")
        _durable_unlink(ready)
    if control_socket.exists() or control_socket.is_symlink():
        _unlink_owned(control_socket, allowed=(stat.S_IFSOCK,))


def _intent_records(intents: IntentStore) -> tuple[EffectIntent, ...]:
    result: list[EffectIntent] = []
    for entry in intents.directory.iterdir():
        if entry.is_symlink() or not entry.name.endswith(".json"):
            raise RuntimeSecurityError(f"unexpected intent entry: {entry}")
        record = intents.load(entry.name.removesuffix(".json"))
        if record is None:
            raise RuntimeSecurityError(f"intent disappeared during recovery: {entry}")
        result.append(record)
    return tuple(result)


def _discard_offline_staging(
    root: Path,
    intents: IntentStore,
    store: RecoveryStore,
    detached_scopes: DetachedScopeStore,
) -> int:
    """Remove only recognized atomic-write temps after the owner is dead."""

    removed = _discard_staged_json(root, allowed_target=_CONTROL_TARGET_RE)
    for directory in (
        intents.directory,
        store.providers,
        store.children,
        store.probes,
        store.provider_scopes,
        detached_scopes.directory,
    ):
        removed += _discard_staged_json(
            directory,
            allowed_target=_JSON_RECORD_TARGET_RE,
        )
    return removed


def recover_offline(
    control_root: str | os.PathLike[str],
    release_dir: str | os.PathLike[str],
    *,
    providers: Mapping[str, ProviderAdapter] | None = None,
    process_scopes: ProcessScopeBackend | None = None,
    stop_ms: int = 15_000,
    recover_compatibility: bool = True,
    forbid_compatibility_handoff: bool = False,
    expected_fence: tuple[str, str, ProcessIdentity] | None = None,
    require_fence_absent: bool = False,
) -> RecoveryOutcome:
    """Replay a dead epoch to proven empty under both stable exclusion locks."""

    if type(stop_ms) is not int or not 100 <= stop_ms <= 300_000:
        raise ValueError("stop_ms must be an integer in [100, 300000]")
    if type(forbid_compatibility_handoff) is not bool:
        raise ValueError("forbid_compatibility_handoff must be a boolean")
    if forbid_compatibility_handoff and recover_compatibility:
        raise ValueError(
            "strict direct recovery cannot enable compatibility handoff"
        )
    if expected_fence is not None and require_fence_absent:
        raise ValueError("recovery cannot expect both an owner and an absent fence")
    if expected_fence is not None:
        if (
            type(expected_fence) is not tuple
            or len(expected_fence) != 3
            or type(expected_fence[0]) is not str
            or _DIGEST_RE.fullmatch(expected_fence[0]) is None
            or type(expected_fence[1]) is not str
            or not isinstance(expected_fence[2], ProcessIdentity)
        ):
            raise ValueError("expected recovery fence authority is invalid")
        _token(expected_fence[1], "expected recovery owner epoch")
    recovery_deadline = TransitionDeadline.after_ms(stop_ms)
    root = Path(control_root)
    release = Path(release_dir).resolve(strict=True)
    runtime = SecureRuntime(root)
    scoped_expectation = expected_fence is not None or require_fence_absent
    if not scoped_expectation:
        runtime.initialize()
    runtime.verify()
    bootstrap_fd: int | None = None
    compatibility_fd: int | None = None
    try:
        bootstrap_fd = _open_recovery_lock(
            root / "bootstrap.lock", create=not scoped_expectation
        )
        compatibility_fd = _open_recovery_lock(
            root / "compatibility.lock", create=not scoped_expectation
        )
        fences = FenceStore(runtime)
        fence = fences.load()
        if require_fence_absent and fence is not None:
            raise FenceBusyError("recovery expected no fence but another epoch is present")
        if expected_fence is not None:
            expected_release, expected_owner, expected_identity = expected_fence
            if fence is None or (
                fence.release_id,
                fence.owner_epoch,
                fence.pid,
                fence.pid_start_ticks,
                fence.boot_id,
            ) != (
                expected_release,
                expected_owner,
                expected_identity.pid,
                expected_identity.start_ticks,
                expected_identity.boot_id,
            ):
                raise FenceBusyError(
                    "recovery fence differs from the exact expected supervisor epoch"
                )
        # Scoped verifier admission must reject both a replacement epoch and a
        # matched live epoch before any store constructor can create/chmod
        # recovery directories.  Only a proven-dead owner may initialize the
        # stores needed to reconcile its durable records.
        if fence is not None:
            identity = ProcessIdentity(fence.pid, fence.pid_start_ticks, fence.boot_id)
            if process_can_still_execute(identity):
                raise FenceBusyError("the fenced supervisor is still alive")
        intents = IntentStore(runtime)
        store = RecoveryStore(runtime)
        detached_scopes = DetachedScopeStore(root)
        _discard_offline_staging(root, intents, store, detached_scopes)
        provider_records = store.list_providers()
        child_records = store.list_children()
        probe_records = store.list_probes()
        provider_scope_records = store.list_provider_scopes()
        detached_records = detached_scopes.list_records()
        scope_backend = process_scopes or LinuxCgroupV2Scope()
        epoch_scope = detached_scopes.load("supervisor-epoch")
        handoff_scope = detached_scopes.load("compatibility-handoff")
        if forbid_compatibility_handoff:
            if handoff_scope is not None:
                raise RecoveryRequired(
                    "strict direct recovery found a compatibility handoff scope"
                )
            if any(record.request.rung != "direct" for record in provider_records):
                raise RecoveryRequired(
                    "strict direct recovery found a non-direct provider record"
                )
            if any(
                record.request.rung != "direct"
                for _role, record in provider_scope_records
            ):
                raise RecoveryRequired(
                    "strict direct recovery found a non-direct provider scope"
                )
        if fence is None:
            if (
                child_records
                or provider_records
                or probe_records
                or provider_scope_records
            ):
                raise RecoveryRequired("recovery records exist without an owning fence")
            orphan_intents = _intent_records(intents)
            if any(
                item.phase != "CLEANED" or item.operation != "provider-start"
                for item in orphan_intents
            ):
                raise RecoveryRequired("non-clean intent exists without an owning fence")
            if handoff_scope is not None:
                _recover_detached_scope(
                    handoff_scope,
                    detached_scopes,
                    recovery_deadline,
                    scope_backend,
                    delete_record=False,
                )
                raise RecoveryRequired(
                    "contained compatibility handoff lacks an owning fence"
                )
            if any(record.kind != "supervisor-epoch" for record in detached_records):
                raise RecoveryRequired(
                    "non-epoch detached scope exists without an owning fence"
                )
            for intent in orphan_intents:
                recovery_deadline.check("offline clean intent deletion")
                intents.delete(intent.effect_id)
            reconciled_epoch = epoch_scope is not None
            if epoch_scope is not None:
                _recover_detached_scope(
                    epoch_scope,
                    detached_scopes,
                    recovery_deadline,
                    scope_backend,
                )
            recovery_deadline.check("offline empty-epoch residue cleanup")
            _assert_directory_empty(root / "p", "provider")
            _assert_directory_empty(root / "leaders", "leader")
            _assert_directory_empty(root / "qualify", "qualification")
            _cleanup_dead_control_endpoints(root, None)
            return RecoveryOutcome(reconciled_epoch, None, 0, 0, 0)

        selected_release = _release_id(release, os.environ)
        if fence.release_id != selected_release:
            raise RecoveryRequired(
                "selected release differs from the dead epoch; exact recovery is unavailable"
            )
        resume_requires_handoff = (
            fence.phase == "RECOVERING"
            and not forbid_compatibility_handoff
        )
        if fence.phase != "RECOVERING":
            fence = replace(fence, phase="RECOVERING")
            _atomic_replace_json(fences.path, fence.to_dict())

        if epoch_scope is not None and (
            epoch_scope.release_id != fence.release_id
            or epoch_scope.child
            != ProcessIdentity(fence.pid, fence.pid_start_ticks, fence.boot_id)
            or (
                epoch_scope.phase == "OWNED"
                and epoch_scope.owner_epoch != fence.owner_epoch
            )
            or (
                epoch_scope.phase != "OWNED"
                and epoch_scope.owner_epoch is not None
            )
        ):
            raise RecoveryRequired("supervisor epoch scope differs from its fence")
        if handoff_scope is not None:
            if (
                handoff_scope.release_id != fence.release_id
                or handoff_scope.owner_epoch != fence.owner_epoch
            ):
                raise RecoveryRequired(
                    "compatibility handoff scope differs from its fence"
                )
            # A handoff created by the supervisor can be nested beneath the
            # epoch scope.  Remove the nested exact child before attempting the
            # enclosing epoch rmdir, and force external handoff replay later.
            _recover_detached_scope(
                handoff_scope,
                detached_scopes,
                recovery_deadline,
                scope_backend,
            )
            resume_requires_handoff = True
        provider_requests = {record.request for record in provider_records}
        for _role, record in provider_scope_records:
            recovery_deadline.check("offline provider-scope validation")
            if (
                record.request.owner_epoch != fence.owner_epoch
                or record.release_id != fence.release_id
            ):
                raise RecoveryRequired(
                    "provider command scope belongs to another epoch"
                )
            if record.request not in provider_requests:
                raise RecoveryRequired(
                    "provider command scope has no complete provider recovery record"
                )
        for record in probe_records:
            recovery_deadline.check("offline probe record iteration")
            if (
                record.owner_epoch != fence.owner_epoch
                or record.release_id != fence.release_id
            ):
                raise RecoveryRequired("probe recovery record belongs to another epoch")
            _recover_probe(record, store, recovery_deadline, scope_backend)

        for record in child_records:
            recovery_deadline.check("offline child record iteration")
            if (
                record.owner_epoch != fence.owner_epoch
                or record.release_id != fence.release_id
            ):
                raise RecoveryRequired("child recovery record belongs to another epoch")
            _recover_child(record, store, root, recovery_deadline, scope_backend)

        supplied = dict(providers or {})
        direct = DirectProvider(
            root,
            release,
            process_scopes=scope_backend,
            scope_store=store.provider_scope_store,
        )
        legacy = LegacyShellProvider(
            root,
            release,
            process_scopes=scope_backend,
            scope_store=store.provider_scope_store,
        )
        recovered_effects: set[str] = set()
        for record in sorted(
            provider_records,
            key=lambda item: item.request.generation,
            reverse=True,
        ):
            recovery_deadline.check("offline provider record iteration")
            if (
                record.owner_epoch != fence.owner_epoch
                or record.release_id != fence.release_id
            ):
                raise RecoveryRequired("provider recovery record belongs to another epoch")
            digest = hashlib.sha256(
                canonical_json_bytes(record.request.to_dict())
            ).hexdigest()
            intent = intents.load(record.effect_id)
            if intent is not None and (
                intent.owner_epoch != record.owner_epoch
                or intent.generation != record.request.generation
                or intent.operation != "provider-start"
                or intent.parameters_digest != digest
            ):
                raise RecoveryRequired("provider intent differs from its recovery record")
            adapter = supplied.get(
                record.request.rung,
                supplied.get(
                    "*",
                    direct if record.request.rung == "direct" else legacy,
                ),
            )
            report = adapter.recover(
                record.request,
                record.resources,
                recovery_deadline,
            )
            if not report.clean:
                raise ProviderResidueError("; ".join(report.issues))
            if intent is not None:
                if intent.phase == "PREPARED":
                    intents.advance(record.effect_id, "PREPARED", "FAILED")
                    intents.advance(record.effect_id, "FAILED", "CLEANED")
                elif intent.phase == "APPLIED":
                    intents.advance(record.effect_id, "APPLIED", "CLEANED")
                elif intent.phase == "FAILED":
                    intents.advance(record.effect_id, "FAILED", "CLEANED")
                elif intent.phase != "CLEANED":
                    raise RecoveryRequired("provider intent has an unsupported recovery phase")
            if record.phase != "CLEANED":
                store.replace_provider(replace(record, phase="CLEANED"))
            if intent is not None:
                intents.delete(record.effect_id)
            store.delete_provider(record.effect_id)
            recovered_effects.add(record.effect_id)

        for intent in _intent_records(intents):
            recovery_deadline.check("offline intent record validation")
            if (
                intent.phase != "CLEANED"
                or intent.operation != "provider-start"
                or intent.effect_id in recovered_effects
            ):
                raise RecoveryRequired(
                    "provider intent has no complete recovery record"
                )
            intents.delete(intent.effect_id)
        if recover_compatibility or resume_requires_handoff:
            _run_compatibility_handoff(
                root,
                release,
                fence.owner_epoch,
                fence.release_id,
                process_scopes=scope_backend,
                detached_scopes=detached_scopes,
                recovery_deadline=recovery_deadline,
            )
        if epoch_scope is not None:
            _recover_detached_scope(
                epoch_scope,
                detached_scopes,
                recovery_deadline,
                scope_backend,
            )
        recovery_deadline.check("offline recovery final residue cleanup")
        _cleanup_qualification_residue(root)
        _assert_directory_empty(root / "p", "provider")
        _assert_directory_empty(root / "leaders", "leader")
        if (
            store.list_children()
            or store.list_providers()
            or store.list_probes()
            or store.list_provider_scopes()
            or detached_scopes.list_records()
            or _intent_records(intents)
        ):
            raise RecoveryRequired("durable recovery records remain")
        _cleanup_dead_control_endpoints(root, fence)
        recovery_deadline.check("offline recovery fence clearance")
        fences.clear(fence.owner_epoch)
        return RecoveryOutcome(
            True,
            fence.owner_epoch,
            len(provider_records),
            len(child_records),
            len(probe_records),
        )
    finally:
        _close_recovery_lock(compatibility_fd)
        _close_recovery_lock(bootstrap_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="grok-remote multi-session supervisor")
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--control-root", required=True, type=Path)
    parser.add_argument("--expected-contract", required=True)
    parser.add_argument("--expected-control-cap", required=True, type=int)
    parser.add_argument("--warm-legacy-handoff", action="store_true")
    parser.add_argument("--scoped-bootstrap", action="store_true")
    parser.add_argument("--provider-canary-fd", type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        supervisor = Supervisor(
            args.control_root,
            args.release_dir,
            args.expected_contract,
            expected_control_cap=args.expected_control_cap,
            warm_legacy_handoff=args.warm_legacy_handoff,
            scoped_bootstrap=args.scoped_bootstrap,
            provider_canary_fd=args.provider_canary_fd,
        )
    finally:
        if args.provider_canary_fd is not None:
            try:
                os.close(args.provider_canary_fd)
            except OSError:
                pass
    supervisor.bootstrap()

    def stop(_signum: int, _frame: Any) -> None:
        supervisor._force_shutdown("signal")
        supervisor._stop.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    supervisor.serve_forever()
    return 0 if supervisor._cleanup_proved else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        AdmissionError,
        FenceBusyError,
        ProtocolError,
        RecoveryRequired,
        RuntimeSecurityError,
        SupervisorError,
        OSError,
    ) as exc:
        print(f"[egress] multi-session supervisor: {exc}", file=sys.stderr)
        raise SystemExit(2)


__all__ = [
    "AdmissionError",
    "EpochDraining",
    "RecoveryRequired",
    "Supervisor",
    "SupervisorError",
    "main",
]
