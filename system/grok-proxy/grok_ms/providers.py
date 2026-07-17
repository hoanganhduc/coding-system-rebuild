"""Generation-scoped egress provider adapters for multi-session mode.

Providers never publish the public frontend.  They create and qualify one
private SOCKS endpoint, return an immutable ownership graph, and synchronously
remove that graph when stopped.  The supervisor remains the only component
allowed to commit a qualified result.

The legacy shell adapter intentionally exposes a narrow, fixed protocol to
``egress.sh``.  See :class:`LegacyShellProvider` for the exact commands and
environment required from the compatibility implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import os
from pathlib import Path
import pwd
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Mapping, Protocol, Sequence

from .contract import SCHEMA_VERSION, Endpoint, RouteContract
from .ipc import DEFAULT_MAX_PACKET_BYTES, ProtocolError, strict_json_loads
from .process_scope import (
    LinuxCgroupV2Scope,
    ProcessScopeBackend,
    ScopeHandle,
    ScopeIdentity,
)
from .runtime import (
    ProcessIdentity,
    RuntimeSecurityError,
    SecureRuntime,
    _atomic_create_json,
    _atomic_replace_json,
    _create_secure_directory,
    _durable_unlink,
    _open_secure_directory,
    _read_secure_json,
    _validate_regular_file,
    current_process_identity,
    pidfd_for_identity,
    process_can_still_execute,
    process_matches,
    read_boot_id,
    read_pid_start_ticks,
)


_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:+@/-]{1,256}$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9._:+@-]{1,128}$")
_HOME_RUNG_RE = re.compile(r"^home:[A-Za-z0-9._:+@-]{1,120}$")
_PATH_KINDS = {"control", "inventory", "log", "pid", "socket", "state"}
_PRIVILEGED_KINDS = {"namespace", "tun", "vpn_daemon"}
_FIXED_VPN_RESOURCES = {
    ("namespace", "grokvpn"),
    ("tun", "tun-grok"),
    ("vpn_daemon", "openvpn"),
}
_MINIMAL_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Shell-owned provider-up stages are preserved; every failure outside that
# reached-stage protocol is collapsed before it can cross the adapter boundary.
_PROVIDER_UP_STAGE_CODES = frozenset(range(20, 29))
_VPN_PROVIDER_UP_STAGE_CODES = frozenset(range(31, 35))
_PROVIDER_INFRASTRUCTURE_FAILURE = 29
_PROVIDER_SCOPE_RECORD_VERSION = 1
_PROVIDER_SCOPE_PHASES = frozenset({"PREPARED", "SCOPE_CREATED", "ATTACHED"})


class ProviderError(RuntimeError):
    """Base class for a provider lifecycle failure."""


class ProviderCancelled(ProviderError):
    """The transition was explicitly cancelled."""


class ProviderTimeout(ProviderError):
    """The one cumulative transition deadline expired."""


class ProviderProtocolError(ProviderError):
    """A provider returned malformed or inconsistent ownership data."""


class ProviderResidueError(ProviderError):
    """Synchronous teardown could not prove an empty generation."""


def _require_token(value: str, name: str, pattern: re.Pattern[str] = _TOKEN_RE) -> None:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValueError(f"{name}: invalid token")


def _require_positive_int(value: int, name: str, maximum: int = 2**31 - 1) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{name}: expected an integer in [1, {maximum}]")


def _valid_rung(rung: str) -> bool:
    return rung in {"direct", "iphone", "vpn"} or _HOME_RUNG_RE.fullmatch(rung) is not None


def _process_identity_to_dict(identity: ProcessIdentity) -> dict[str, Any]:
    return {
        "boot_id": identity.boot_id,
        "pid": identity.pid,
        "pid_start_ticks": identity.start_ticks,
    }


def _process_identity_from_dict(value: Any, name: str) -> ProcessIdentity:
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
class TransitionDeadline:
    """One absolute monotonic deadline shared by all nested provider work."""

    expires_ns: int
    clock_ns: Callable[[], int] = field(
        default=time.monotonic_ns, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        _require_positive_int(self.expires_ns, "deadline.expires_ns", 2**63 - 1)

    @classmethod
    def after_ms(
        cls, timeout_ms: int, *, clock_ns: Callable[[], int] = time.monotonic_ns
    ) -> "TransitionDeadline":
        _require_positive_int(timeout_ms, "timeout_ms", 3_600_000)
        return cls(clock_ns() + timeout_ms * 1_000_000, clock_ns)

    def remaining_seconds(self, operation: str = "provider operation") -> float:
        remaining = (self.expires_ns - self.clock_ns()) / 1_000_000_000
        if remaining <= 0:
            raise ProviderTimeout(f"cumulative deadline expired during {operation}")
        return remaining

    def check(self, operation: str = "provider operation") -> None:
        self.remaining_seconds(operation)


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    owner_epoch: str
    transition_id: str
    generation: int
    rung: str
    model_id: str
    private_endpoint: Endpoint
    contract: RouteContract

    def __post_init__(self) -> None:
        _require_token(self.owner_epoch, "request.owner_epoch", _OWNER_RE)
        _require_token(self.transition_id, "request.transition_id", _OWNER_RE)
        _require_positive_int(self.generation, "request.generation", 2**63 - 1)
        if not _valid_rung(self.rung):
            raise ValueError(f"request.rung: unsupported value {self.rung!r}")
        _require_token(self.model_id, "request.model_id")
        if not isinstance(self.private_endpoint, Endpoint):
            raise ValueError("request.private_endpoint: expected Endpoint")
        if self.private_endpoint.host != "127.0.0.1":
            raise ValueError("request.private_endpoint.host: v1 requires 127.0.0.1")
        if not isinstance(self.contract, RouteContract):
            raise ValueError("request.contract: expected RouteContract")
        if self.model_id != self.contract.model_id:
            raise ValueError("request.model_id: differs from the frozen contract")
        if self.rung not in self.contract.ladder:
            raise ValueError("request.rung: absent from the frozen contract ladder")
        if self.private_endpoint.port not in self.contract.private_ports:
            raise ValueError(
                "request.private_endpoint.port: absent from the frozen private ports"
            )
        if self.rung.startswith("home:"):
            endpoint = self.contract.home_endpoint(self.rung.removeprefix("home:"))
            if endpoint is None:
                raise ValueError("request.rung: has no frozen home endpoint")
            if endpoint.host.startswith("-") or endpoint.user.startswith("-"):
                raise ValueError(
                    "request.rung: frozen home host and user must not be option-shaped"
                )

    def to_dict(self) -> dict[str, Any]:
        """Return the strict recovery record, including the full frozen contract."""

        return {
            "contract": self.contract.to_dict(),
            "generation": self.generation,
            "model_id": self.model_id,
            "owner_epoch": self.owner_epoch,
            "private_endpoint": self.private_endpoint.to_dict(),
            "rung": self.rung,
            "transition_id": self.transition_id,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ProviderRequest":
        if type(value) is not dict:
            raise ValueError("request: expected an object")
        fields = {
            "contract",
            "generation",
            "model_id",
            "owner_epoch",
            "private_endpoint",
            "rung",
            "transition_id",
        }
        if set(value) != fields or any(type(key) is not str for key in value):
            raise ValueError("request: missing or unexpected fields")
        return cls(
            owner_epoch=value["owner_epoch"],
            transition_id=value["transition_id"],
            generation=value["generation"],
            rung=value["rung"],
            model_id=value["model_id"],
            private_endpoint=Endpoint.from_dict(
                value["private_endpoint"], "request.private_endpoint"
            ),
            contract=RouteContract.from_dict(value["contract"], "request.contract"),
        )


@dataclass(frozen=True, slots=True)
class ProviderScopeRecord:
    """Durable exact authority for one barriered provider process scope.

    The filename supplies the temporary ``command`` or retained ``provider``
    role.  Keeping the role out of the payload lets a successful provider-up
    promote the same record and cgroup with one atomic same-directory rename.
    """

    schema_version: int
    record_version: int
    release_id: str
    verb: str
    phase: str
    request: ProviderRequest
    child: ProcessIdentity
    scope: ScopeIdentity

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("provider_scope.schema_version: unsupported value")
        if self.record_version != _PROVIDER_SCOPE_RECORD_VERSION:
            raise ValueError("provider_scope.record_version: unsupported value")
        _require_token(self.release_id, "provider_scope.release_id")
        if not isinstance(self.request, ProviderRequest):
            raise ValueError("provider_scope.request: expected ProviderRequest")
        if self.release_id != self.request.contract.release_id:
            raise ValueError("provider_scope.release_id: differs from frozen request")
        if self.verb not in {
            "direct-up",
            "provider-up",
            "provider-next",
            "provider-recover",
            "provider-stop",
            "provider-prove-empty",
        }:
            raise ValueError("provider_scope.verb: unsupported value")
        if self.phase not in _PROVIDER_SCOPE_PHASES:
            raise ValueError("provider_scope.phase: unsupported value")
        if not isinstance(self.child, ProcessIdentity):
            raise ValueError("provider_scope.child: expected ProcessIdentity")
        if not isinstance(self.scope, ScopeIdentity):
            raise ValueError("provider_scope.scope: expected ScopeIdentity")
        if self.phase == "PREPARED" and self.scope.created:
            raise ValueError("provider_scope.scope: PREPARED scope cannot be created")
        if self.phase != "PREPARED" and not self.scope.created:
            raise ValueError("provider_scope.scope: created phase requires an inode identity")
        if (self.request.rung == "direct") != (self.verb == "direct-up"):
            raise ValueError(
                "provider_scope.verb: direct-up must match exactly the direct rung"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "child": _process_identity_to_dict(self.child),
            "phase": self.phase,
            "record_version": self.record_version,
            "release_id": self.release_id,
            "request": self.request.to_dict(),
            "schema_version": self.schema_version,
            "scope": self.scope.to_dict(),
            "verb": self.verb,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ProviderScopeRecord":
        fields = {
            "child",
            "phase",
            "record_version",
            "release_id",
            "request",
            "schema_version",
            "scope",
            "verb",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ValueError("provider_scope: missing or unexpected fields")
        return cls(
            schema_version=value["schema_version"],
            record_version=value["record_version"],
            release_id=value["release_id"],
            verb=value["verb"],
            phase=value["phase"],
            request=ProviderRequest.from_dict(value["request"]),
            child=_process_identity_from_dict(value["child"], "provider_scope.child"),
            scope=ScopeIdentity.from_dict(value["scope"]),
        )


def _same_provider_scope_authority(
    left: ProviderScopeRecord, right: ProviderScopeRecord
) -> bool:
    if (
        left.schema_version,
        left.record_version,
        left.release_id,
        left.verb,
        left.request,
        left.child,
    ) != (
        right.schema_version,
        right.record_version,
        right.release_id,
        right.verb,
        right.request,
        right.child,
    ):
        return False
    a = left.scope
    b = right.scope
    if (
        a.backend,
        a.parent_path,
        a.parent_device,
        a.parent_inode,
        a.scope_path,
    ) != (
        b.backend,
        b.parent_path,
        b.parent_device,
        b.parent_inode,
        b.scope_path,
    ):
        return False
    return not (a.created and b.created) or (
        a.scope_device,
        a.scope_inode,
    ) == (
        b.scope_device,
        b.scope_inode,
    )


class ProviderScopeStore:
    """Central recovery journal for barriered provider process cgroups."""

    _ENTRY_RE = re.compile(r"^(?P<tag>[0-9a-f]{24})\.(?P<role>command|provider)\.json$")

    def __init__(self, runtime_root: str | os.PathLike[str]) -> None:
        self.runtime = SecureRuntime(runtime_root)
        self.runtime.initialize()
        self.runtime.verify()
        recovery = self.runtime.root / "recovery"
        _create_secure_directory(recovery)
        self.directory = recovery / "provider-scopes"
        _create_secure_directory(self.directory)

    def path(self, request: ProviderRequest, role: str) -> Path:
        if role not in {"command", "provider"}:
            raise ValueError("provider scope role must be command or provider")
        return self.directory / f"{_workspace_tag(request)}.{role}.json"

    def load(self, request: ProviderRequest, role: str) -> ProviderScopeRecord | None:
        path = self.path(request, role)
        value = _read_secure_json(path)
        if value is None:
            return None
        try:
            record = ProviderScopeRecord.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeSecurityError(f"invalid provider scope record: {exc}") from exc
        if record.request != request:
            raise RuntimeSecurityError(
                "provider scope filename and frozen request disagree"
            )
        expected_start = (
            "direct-up" if request.rung == "direct" else "provider-up"
        )
        if role == "provider" and record.verb != expected_start:
            raise RuntimeSecurityError(
                "retained provider scope was not created by its expected provider start"
            )
        return record

    def put(self, request: ProviderRequest, record: ProviderScopeRecord) -> None:
        if record.request != request:
            raise RuntimeSecurityError("provider scope record request mismatch")
        path = self.path(request, "command")
        if _atomic_create_json(path, record.to_dict()):
            return
        existing = self.load(request, "command")
        if existing == record:
            return
        raise RuntimeSecurityError("provider command scope conflicts with its replay")

    def replace(self, request: ProviderRequest, record: ProviderScopeRecord) -> None:
        existing = self.load(request, "command")
        if existing is None or not _same_provider_scope_authority(existing, record):
            raise RuntimeSecurityError("provider command scope authority changed")
        phases = {"PREPARED": 0, "SCOPE_CREATED": 1, "ATTACHED": 2}
        if phases[record.phase] < phases[existing.phase]:
            raise RuntimeSecurityError("provider command scope phase regressed")
        _atomic_replace_json(self.path(request, "command"), record.to_dict())

    def promote(self, request: ProviderRequest, record: ProviderScopeRecord) -> None:
        existing = self.load(request, "command")
        if (
            existing is None
            or existing.phase != "ATTACHED"
            or record.phase != "ATTACHED"
            or record.verb
            != ("direct-up" if request.rung == "direct" else "provider-up")
            or not _same_provider_scope_authority(existing, record)
        ):
            raise RuntimeSecurityError("provider scope promotion authority is incomplete")
        source = self.path(request, "command")
        target = self.path(request, "provider")
        directory_fd = _open_secure_directory(self.directory)
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(source.name, flags, dir_fd=directory_fd)
            try:
                _validate_regular_file(descriptor, source)
            finally:
                os.close(descriptor)
            try:
                os.stat(target.name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeSecurityError("provider scope already exists")
            os.rename(
                source.name,
                target.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def delete(
        self,
        request: ProviderRequest,
        role: str,
        expected: ProviderScopeRecord,
    ) -> bool:
        existing = self.load(request, role)
        if existing is None:
            return False
        if not _same_provider_scope_authority(existing, expected):
            raise RuntimeSecurityError("provider scope authority changed before deletion")
        return _durable_unlink(self.path(request, role))

    def list_records(self) -> tuple[tuple[str, ProviderScopeRecord], ...]:
        result: list[tuple[str, ProviderScopeRecord]] = []
        for entry in self.directory.iterdir():
            match = self._ENTRY_RE.fullmatch(entry.name)
            if entry.is_symlink() or match is None:
                raise RuntimeSecurityError(
                    f"unexpected provider scope recovery entry: {entry}"
                )
            value = _read_secure_json(entry)
            if value is None:
                raise RuntimeSecurityError(f"provider scope record disappeared: {entry}")
            try:
                record = ProviderScopeRecord.from_dict(value)
            except (TypeError, ValueError) as exc:
                raise RuntimeSecurityError(
                    f"invalid provider scope recovery record: {exc}"
                ) from exc
            if match.group("tag") != _workspace_tag(record.request):
                raise RuntimeSecurityError(
                    "provider scope recovery filename and request disagree"
                )
            result.append((match.group("role"), record))
        return tuple(sorted(result, key=lambda item: self.path(item[1].request, item[0]).name))


@dataclass(frozen=True, slots=True)
class QualificationEvidence:
    endpoint: Endpoint
    model_id: str
    exit_identity: str
    country_code: str | None
    dns_path_verified: bool
    byte_path_verified: bool
    stability_samples: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, Endpoint):
            raise ValueError("qualification.endpoint: expected Endpoint")
        _require_token(self.model_id, "qualification.model_id")
        _require_token(self.exit_identity, "qualification.exit_identity")
        if self.country_code is not None:
            if type(self.country_code) is not str or re.fullmatch(
                r"[A-Z]{2}", self.country_code
            ) is None:
                raise ValueError("qualification.country_code: expected an uppercase ISO code")
        if type(self.dns_path_verified) is not bool or not self.dns_path_verified:
            raise ValueError("qualification.dns_path_verified: must be true")
        if type(self.byte_path_verified) is not bool or not self.byte_path_verified:
            raise ValueError("qualification.byte_path_verified: must be true")
        if type(self.stability_samples) is not tuple or not self.stability_samples:
            raise ValueError("qualification.stability_samples: expected a nonempty tuple")
        for sample in self.stability_samples:
            _require_token(sample, "qualification.stability_samples")
        if any(sample != self.exit_identity for sample in self.stability_samples):
            raise ValueError(
                "qualification.stability_samples: exit identity changed during qualification"
            )


@dataclass(frozen=True, slots=True)
class ListenerIdentity:
    endpoint: Endpoint
    socket_inode: int
    owner: ProcessIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, Endpoint):
            raise ValueError("listener.endpoint: expected Endpoint")
        _require_positive_int(self.socket_inode, "listener.socket_inode", 2**63 - 1)
        if not isinstance(self.owner, ProcessIdentity):
            raise ValueError("listener.owner: expected ProcessIdentity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint.to_dict(),
            "owner": _process_identity_to_dict(self.owner),
            "socket_inode": self.socket_inode,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ListenerIdentity":
        if type(value) is not dict or set(value) != {
            "endpoint",
            "owner",
            "socket_inode",
        }:
            raise ValueError("listener: missing or unexpected fields")
        return cls(
            endpoint=Endpoint.from_dict(value["endpoint"], "listener.endpoint"),
            socket_inode=value["socket_inode"],
            owner=_process_identity_from_dict(value["owner"], "listener.owner"),
        )


@dataclass(frozen=True, slots=True)
class PathIdentity:
    path: str
    kind: str
    device: int
    inode: int
    uid: int
    mode: int

    def __post_init__(self) -> None:
        path = Path(self.path)
        if type(self.path) is not str or not path.is_absolute():
            raise ValueError("path_identity.path: expected an absolute path")
        if self.kind not in _PATH_KINDS:
            raise ValueError(f"path_identity.kind: unsupported value {self.kind!r}")
        for name, value in (
            ("device", self.device),
            ("inode", self.inode),
            ("uid", self.uid),
            ("mode", self.mode),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"path_identity.{name}: expected a non-negative integer")

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "inode": self.inode,
            "kind": self.kind,
            "mode": self.mode,
            "path": self.path,
            "uid": self.uid,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "PathIdentity":
        if type(value) is not dict or set(value) != {
            "device",
            "inode",
            "kind",
            "mode",
            "path",
            "uid",
        }:
            raise ValueError("path_identity: missing or unexpected fields")
        return cls(
            path=value["path"],
            kind=value["kind"],
            device=value["device"],
            inode=value["inode"],
            uid=value["uid"],
            mode=value["mode"],
        )


@dataclass(frozen=True, slots=True)
class PrivilegedResourceIdentity:
    kind: str
    name: str
    broker_instance: str

    def __post_init__(self) -> None:
        if self.kind not in _PRIVILEGED_KINDS:
            raise ValueError(f"privileged.kind: unsupported value {self.kind!r}")
        if (self.kind, self.name) not in _FIXED_VPN_RESOURCES:
            raise ValueError("privileged resource is not in the fixed VPN resource set")
        _require_token(self.broker_instance, "privileged.broker_instance", _OWNER_RE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "broker_instance": self.broker_instance,
            "kind": self.kind,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "PrivilegedResourceIdentity":
        if type(value) is not dict or set(value) != {
            "broker_instance",
            "kind",
            "name",
        }:
            raise ValueError("privileged: missing or unexpected fields")
        return cls(
            kind=value["kind"],
            name=value["name"],
            broker_instance=value["broker_instance"],
        )


@dataclass(frozen=True, slots=True)
class ProviderResourceGraph:
    owner_epoch: str
    transition_id: str
    generation: int
    rung: str
    runtime_dir: str
    processes: tuple[ProcessIdentity, ...]
    listeners: tuple[ListenerIdentity, ...]
    paths: tuple[PathIdentity, ...]
    privileged: tuple[PrivilegedResourceIdentity, ...] = ()

    def __post_init__(self) -> None:
        _require_token(self.owner_epoch, "resources.owner_epoch", _OWNER_RE)
        _require_token(self.transition_id, "resources.transition_id", _OWNER_RE)
        _require_positive_int(self.generation, "resources.generation", 2**63 - 1)
        if not _valid_rung(self.rung):
            raise ValueError("resources.rung: invalid rung")
        runtime = Path(self.runtime_dir)
        if type(self.runtime_dir) is not str or not runtime.is_absolute():
            raise ValueError("resources.runtime_dir: expected an absolute path")
        if type(self.processes) is not tuple or not self.processes:
            raise ValueError("resources.processes: expected a nonempty immutable tuple")
        if len(set(self.processes)) != len(self.processes):
            raise ValueError("resources.processes: duplicates are forbidden")
        if type(self.listeners) is not tuple or len(self.listeners) != 1:
            raise ValueError("resources.listeners: exactly one private listener is required")
        if self.listeners[0].owner not in self.processes:
            raise ValueError("resources.listeners: listener owner is absent from process graph")
        if type(self.paths) is not tuple or type(self.privileged) is not tuple:
            raise ValueError("resources paths must be immutable tuples")
        for path in self.paths:
            try:
                Path(path.path).relative_to(runtime)
            except ValueError as exc:
                raise ValueError("resource path escapes its generation runtime") from exc
        actual_privileged = {(item.kind, item.name) for item in self.privileged}
        if self.rung == "vpn":
            if actual_privileged != _FIXED_VPN_RESOURCES:
                raise ValueError("vpn resources must name the fixed namespace, tun, and daemon")
            if len({item.broker_instance for item in self.privileged}) != 1:
                raise ValueError("vpn resources must share one broker instance")
        elif self.privileged:
            raise ValueError("only the vpn provider may return privileged resources")

    def to_dict(self) -> dict[str, Any]:
        """Return the complete strict graph used by offline recovery."""

        return {
            "generation": self.generation,
            "listeners": [item.to_dict() for item in self.listeners],
            "owner_epoch": self.owner_epoch,
            "paths": [item.to_dict() for item in self.paths],
            "privileged": [item.to_dict() for item in self.privileged],
            "processes": [_process_identity_to_dict(item) for item in self.processes],
            "rung": self.rung,
            "runtime_dir": self.runtime_dir,
            "transition_id": self.transition_id,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ProviderResourceGraph":
        fields = {
            "generation",
            "listeners",
            "owner_epoch",
            "paths",
            "privileged",
            "processes",
            "rung",
            "runtime_dir",
            "transition_id",
        }
        if type(value) is not dict or set(value) != fields:
            raise ValueError("resources: missing or unexpected fields")
        for name in ("listeners", "paths", "privileged", "processes"):
            if type(value[name]) is not list:
                raise ValueError(f"resources.{name}: expected an array")
        return cls(
            owner_epoch=value["owner_epoch"],
            transition_id=value["transition_id"],
            generation=value["generation"],
            rung=value["rung"],
            runtime_dir=value["runtime_dir"],
            processes=tuple(
                _process_identity_from_dict(item, f"resources.processes[{index}]")
                for index, item in enumerate(value["processes"])
            ),
            listeners=tuple(
                ListenerIdentity.from_dict(item) for item in value["listeners"]
            ),
            paths=tuple(PathIdentity.from_dict(item) for item in value["paths"]),
            privileged=tuple(
                PrivilegedResourceIdentity.from_dict(item)
                for item in value["privileged"]
            ),
        )


@dataclass(frozen=True, slots=True)
class ProviderResult:
    request: ProviderRequest
    qualification: QualificationEvidence
    resources: ProviderResourceGraph

    def __post_init__(self) -> None:
        if self.qualification.endpoint != self.request.private_endpoint:
            raise ValueError("qualification endpoint differs from the requested private endpoint")
        if self.qualification.model_id != self.request.model_id:
            raise ValueError("qualification model differs from the concrete requested model")
        graph = self.resources
        if (
            graph.owner_epoch,
            graph.transition_id,
            graph.generation,
            graph.rung,
        ) != (
            self.request.owner_epoch,
            self.request.transition_id,
            self.request.generation,
            self.request.rung,
        ):
            raise ValueError("resource graph does not belong to the provider request")
        if graph.listeners[0].endpoint != self.request.private_endpoint:
            raise ValueError("resource graph listener differs from the requested endpoint")


@dataclass(frozen=True, slots=True)
class ResidueReport:
    clean: bool
    issues: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.clean != (not self.issues):
            raise ValueError("residue report clean flag disagrees with its issues")


Qualifier = Callable[
    [Endpoint, ProviderRequest, TransitionDeadline, threading.Event | None],
    QualificationEvidence,
]


class ProviderAdapter(Protocol):
    def start(
        self,
        request: ProviderRequest,
        deadline: TransitionDeadline,
        qualifier: Qualifier,
        cancellation: threading.Event | None = None,
    ) -> ProviderResult: ...

    def stop(
        self,
        result: ProviderResult,
        deadline: TransitionDeadline,
        cancellation: threading.Event | None = None,
    ) -> None: ...

    def prove_empty(self, result: ProviderResult) -> ResidueReport: ...

    def recover(
        self,
        request: ProviderRequest,
        resources: ProviderResourceGraph | None,
        deadline: TransitionDeadline,
    ) -> ResidueReport: ...


def _check_cancel(cancellation: threading.Event | None) -> None:
    if cancellation is not None and cancellation.is_set():
        raise ProviderCancelled("provider operation was cancelled")


def _secure_directory(path: Path, *, create: bool = False) -> None:
    if create:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        os.chmod(path, 0o700, follow_symlinks=False)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise ProviderProtocolError(f"runtime path is not a real directory: {path}")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ProviderProtocolError(f"runtime directory has unsafe owner or mode: {path}")


@dataclass(frozen=True, slots=True)
class _GenerationWorkspace:
    root: Path
    path: Path
    inventory: Path
    pidfile: Path


def _workspace_tag(request: ProviderRequest) -> str:
    """Return the fixed-width collision-resistant generation directory tag."""

    material = b"\0".join(
        (
            request.owner_epoch.encode("ascii"),
            str(request.generation).encode("ascii"),
            str(request.private_endpoint.port).encode("ascii"),
        )
    )
    return hashlib.sha256(material).hexdigest()[:24]


def _create_workspace(root: Path, request: ProviderRequest) -> _GenerationWorkspace:
    SecureRuntime(root).initialize()
    _secure_directory(root)
    providers = root / "p"
    _secure_directory(providers, create=True)
    path = providers / _workspace_tag(request)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ProviderResidueError(f"generation runtime already exists: {path}") from exc
    _secure_directory(path)
    return _GenerationWorkspace(
        root=root,
        path=path,
        inventory=path / "inventory.json",
        pidfile=path / "backend.pid",
    )


def _workspace_for_request(root: Path, request: ProviderRequest) -> _GenerationWorkspace:
    path = root / "p" / _workspace_tag(request)
    return _GenerationWorkspace(
        root=root,
        path=path,
        inventory=path / "inventory.json",
        pidfile=path / "backend.pid",
    )


def _validate_recovery_graph(
    request: ProviderRequest, resources: ProviderResourceGraph
) -> None:
    if (
        resources.owner_epoch,
        resources.transition_id,
        resources.generation,
        resources.rung,
        resources.listeners[0].endpoint,
    ) != (
        request.owner_epoch,
        request.transition_id,
        request.generation,
        request.rung,
        request.private_endpoint,
    ):
        raise ProviderProtocolError("recovery graph does not belong to its frozen request")


def _remove_empty_workspace(workspace: _GenerationWorkspace) -> None:
    # The durable control root also contains locks, recovery records, and other
    # sessions.  A provider may remove only its exact tag and the now-empty
    # shared ``p`` directory, never the control root itself.
    for path in (workspace.path, workspace.path.parent):
        try:
            path.rmdir()
        except FileNotFoundError:
            continue
        except OSError:
            break


def _remove_effect_free_prepared_workspace(
    workspace: _GenerationWorkspace,
    *,
    exactly_exited_pids: frozenset[int] = frozenset(),
) -> tuple[str, ...]:
    """Remove only an empty workspace or one safely stale provider pidfile.

    Without a durable process-scope record, the numeric PID must be absent.
    A successfully reconciled exact scope also proves its recorded direct child
    exited, even while a non-reaping init temporarily leaves that PID visible as
    a zombie.
    """

    path = workspace.path
    if not path.exists() and not path.is_symlink():
        return ()
    try:
        _secure_directory(path)
        entries = tuple(path.iterdir())
    except (OSError, ProviderError) as exc:
        return (str(exc),)
    if not entries:
        _remove_empty_workspace(workspace)
        return () if not path.exists() else ("empty prepared workspace could not be removed",)
    if len(entries) != 1 or entries[0] != workspace.pidfile:
        return ("prepared workspace contains unknown effects without an exact graph",)
    try:
        info = workspace.pidfile.lstat()
        if (
            workspace.pidfile.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 32
        ):
            return ("prepared pidfile has unsafe identity",)
        raw = _read_bounded_secure_file(workspace.pidfile).decode("ascii").strip()
        if not raw.isdecimal() or not 1 <= int(raw) <= 2**31 - 1:
            return ("prepared pidfile is malformed",)
        # The pidfile predates the full stable graph.  Never signal this PID;
        # remove it only when the kernel proves there is no process to confuse
        # with the parent-death-guarded backend.
        if int(raw) not in exactly_exited_pids and (Path("/proc") / raw).exists():
            return ("prepared pidfile PID is still present without a stable identity",)
        identity = _snapshot_path(workspace.pidfile, "pid", workspace.path)
        _unlink_exact(identity)
        _remove_empty_workspace(workspace)
    except (UnicodeDecodeError, OSError, ProviderError) as exc:
        return (str(exc),)
    return () if not path.exists() else ("prepared workspace remains after safe cleanup",)


def _identity_for_pid(pid: int) -> ProcessIdentity:
    _require_positive_int(pid, "inventory.pid")
    try:
        owner = (Path("/proc") / str(pid)).stat().st_uid
    except OSError as exc:
        raise ProviderProtocolError(f"cannot inspect provider pid {pid}: {exc}") from exc
    if owner != os.getuid():
        raise ProviderProtocolError(
            f"provider pid {pid} is owned by uid {owner}, expected {os.getuid()}"
        )
    try:
        return ProcessIdentity(pid, read_pid_start_ticks(pid), read_boot_id())
    except (OSError, ValueError) as exc:
        raise ProviderProtocolError(
            f"cannot capture stable identity for provider pid {pid}: {exc}"
        ) from exc


def _snapshot_path(path: Path, kind: str, runtime_dir: Path) -> PathIdentity:
    if kind not in _PATH_KINDS:
        raise ProviderProtocolError(f"unsupported inventory path kind {kind!r}")
    try:
        path.relative_to(runtime_dir)
    except ValueError as exc:
        raise ProviderProtocolError(f"inventory path escapes generation runtime: {path}") from exc
    try:
        info = path.lstat()
    except OSError as exc:
        raise ProviderProtocolError(f"cannot inspect inventory path {path}: {exc}") from exc
    if path.is_symlink() or info.st_uid != os.getuid():
        raise ProviderProtocolError(f"inventory path has unsafe type or owner: {path}")
    return PathIdentity(
        path=str(path),
        kind=kind,
        device=info.st_dev,
        inode=info.st_ino,
        uid=info.st_uid,
        mode=stat.S_IMODE(info.st_mode),
    )


def _read_bounded_secure_file(path: Path) -> bytes:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ProviderProtocolError("provider inventory is not a regular file")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ProviderProtocolError("provider inventory has unsafe owner or mode")
    if info.st_size > DEFAULT_MAX_PACKET_BYTES:
        raise ProviderProtocolError("provider inventory exceeds the bounded record size")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ProviderProtocolError("provider inventory changed during open")
        data = b""
        while True:
            chunk = os.read(descriptor, 16_384)
            if not chunk:
                break
            data += chunk
            if len(data) > DEFAULT_MAX_PACKET_BYTES:
                raise ProviderProtocolError("provider inventory exceeds the bounded record size")
        return data
    finally:
        os.close(descriptor)


def _ipv4_listen_inodes(endpoint: Endpoint) -> tuple[int, ...]:
    if endpoint.host != "127.0.0.1":
        raise ProviderProtocolError("only the fixed IPv4 loopback endpoint is supported")
    expected_address = "0100007F"
    expected_port = f"{endpoint.port:04X}"
    found: list[int] = []
    try:
        lines = Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
    except OSError as exc:
        raise ProviderProtocolError(f"cannot inspect TCP listener table: {exc}") from exc
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or fields[3] != "0A":
            continue
        address, separator, port = fields[1].partition(":")
        if separator and address == expected_address and port == expected_port:
            try:
                inode = int(fields[9])
            except ValueError as exc:
                raise ProviderProtocolError("malformed listener inode") from exc
            if inode > 0:
                found.append(inode)
    return tuple(sorted(set(found)))


def _listener_identity(
    endpoint: Endpoint, processes: Sequence[ProcessIdentity]
) -> ListenerIdentity:
    inodes = _ipv4_listen_inodes(endpoint)
    if len(inodes) != 1:
        raise ProviderProtocolError(
            f"expected exactly one listener at {endpoint.host}:{endpoint.port}, found {len(inodes)}"
        )
    inode = inodes[0]
    owners: list[ProcessIdentity] = []
    expected_link = f"socket:[{inode}]"
    for identity in processes:
        if not process_matches(identity):
            raise ProviderProtocolError(f"provider process identity became stale: {identity.pid}")
        fd_dir = Path("/proc") / str(identity.pid) / "fd"
        try:
            descriptors = tuple(fd_dir.iterdir())
        except OSError:
            continue
        if any(
            _safe_readlink(descriptor) == expected_link for descriptor in descriptors
        ):
            owners.append(identity)
    if len(owners) != 1:
        raise ProviderProtocolError(
            f"private listener inode {inode} has {len(owners)} owners in the declared process graph"
        )
    return ListenerIdentity(endpoint, inode, owners[0])


def _safe_readlink(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


def _wait_for_listener(
    endpoint: Endpoint,
    processes: Sequence[ProcessIdentity],
    deadline: TransitionDeadline,
    cancellation: threading.Event | None,
) -> ListenerIdentity:
    last_error = "listener not ready"
    while True:
        _check_cancel(cancellation)
        try:
            return _listener_identity(endpoint, processes)
        except ProviderProtocolError as exc:
            last_error = str(exc)
        remaining = deadline.remaining_seconds("private listener readiness")
        if remaining <= 0.01:
            raise ProviderTimeout(last_error)
        time.sleep(min(0.02, remaining))


def _path_still_matches(identity: PathIdentity) -> bool:
    try:
        info = Path(identity.path).lstat()
    except FileNotFoundError:
        return False
    return (
        not Path(identity.path).is_symlink()
        and (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))
        == (identity.device, identity.inode, identity.uid, identity.mode)
    )


def _unlink_exact(identity: PathIdentity) -> None:
    path = Path(identity.path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    actual = (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))
    expected = (identity.device, identity.inode, identity.uid, identity.mode)
    if path.is_symlink() or actual != expected:
        raise ProviderResidueError(f"refusing to unlink replaced provider path: {path}")
    try:
        path.unlink()
    except OSError as exc:
        raise ProviderResidueError(f"cannot unlink exact provider path {path}: {exc}") from exc


def prove_empty_resources(
    resources: ProviderResourceGraph,
    *,
    exactly_exited: frozenset[ProcessIdentity] = frozenset(),
) -> ResidueReport:
    issues: list[str] = []
    for identity in resources.processes:
        if identity not in exactly_exited and process_can_still_execute(identity):
            issues.append(f"process still alive: pid={identity.pid}")
    try:
        if _ipv4_listen_inodes(resources.listeners[0].endpoint):
            endpoint = resources.listeners[0].endpoint
            issues.append(f"listener still present: {endpoint.host}:{endpoint.port}")
    except ProviderProtocolError as exc:
        issues.append(str(exc))
    for identity in resources.paths:
        if _path_still_matches(identity):
            issues.append(f"path still present: {identity.path}")
        elif Path(identity.path).exists() or Path(identity.path).is_symlink():
            issues.append(f"resource path was replaced: {identity.path}")
    runtime = Path(resources.runtime_dir)
    if runtime.exists() or runtime.is_symlink():
        try:
            entries = tuple(runtime.iterdir()) if runtime.is_dir() else ()
        except OSError:
            entries = ()
        issues.append(
            f"generation runtime still present: {runtime}"
            + (f" ({len(entries)} entries)" if entries else "")
        )
    # Privileged identities require the adapter's fixed provider-prove-empty
    # command; local inspection cannot prove a broker-owned namespace or daemon.
    return ResidueReport(clean=not issues, issues=tuple(issues))


def _terminate_exact_processes(
    processes: Sequence[ProcessIdentity],
    deadline: TransitionDeadline,
    children: Mapping[int, subprocess.Popen[bytes]] | None = None,
) -> frozenset[ProcessIdentity]:
    signal_issues: list[str] = []
    handles: dict[ProcessIdentity, int] = {}
    exact_exited: set[ProcessIdentity] = set()
    inspection_failed: set[ProcessIdentity] = set()

    def refresh_alive(
        candidates: Sequence[ProcessIdentity],
    ) -> list[ProcessIdentity]:
        if children is not None:
            for identity in candidates:
                child = children.get(identity.pid)
                if child is not None:
                    child.poll()
        alive: list[ProcessIdentity] = []
        for identity in candidates:
            descriptor = handles.get(identity)
            if descriptor is not None:
                if identity in inspection_failed:
                    alive.append(identity)
                    continue
                try:
                    readable, _, _ = select.select([descriptor], [], [], 0)
                except (OSError, ValueError) as exc:
                    inspection_failed.add(identity)
                    signal_issues.append(
                        f"cannot inspect stable handle for pid {identity.pid}: {exc}"
                    )
                    alive.append(identity)
                    continue
                if readable:
                    exact_exited.add(identity)
                    continue
            if not process_matches(identity):
                exact_exited.add(identity)
                continue
            alive.append(identity)
        return alive

    try:
        for identity in processes:
            try:
                handles[identity] = pidfd_for_identity(identity)
            except ProcessLookupError:
                exact_exited.add(identity)
            except (OSError, RuntimeError) as exc:
                signal_issues.append(
                    f"cannot acquire stable handle for pid {identity.pid}: {exc}"
                )
        alive = refresh_alive(tuple(handles))
        for identity in alive:
            descriptor = handles[identity]
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except (AttributeError, OSError) as exc:
                signal_issues.append(f"cannot terminate pid {identity.pid}: {exc}")
        try:
            remaining = deadline.remaining_seconds("provider process termination")
        except ProviderTimeout:
            remaining = 0.0
        grace_deadline = time.monotonic() + min(0.5, remaining / 2)
        while alive and time.monotonic() < grace_deadline:
            alive = refresh_alive(alive)
            if alive:
                time.sleep(min(0.02, max(0.0, grace_deadline - time.monotonic())))
        for identity in alive:
            descriptor = handles[identity]
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except (AttributeError, OSError) as exc:
                signal_issues.append(f"cannot kill pid {identity.pid}: {exc}")
        while alive:
            alive = refresh_alive(alive)
            if not alive:
                break
            try:
                remaining = deadline.remaining_seconds(
                    "provider process kill containment"
                )
            except ProviderTimeout:
                break
            time.sleep(min(0.02, remaining))
        for identity in processes:
            child = children.get(identity.pid) if children is not None else None
            if child is None:
                continue
            try:
                child.wait(
                    timeout=max(
                        0.01,
                        deadline.remaining_seconds("provider child reap"),
                    )
                )
            except (subprocess.TimeoutExpired, ProviderTimeout):
                # SIGKILL has already been sent through the stable handle.
                # Give waitpid one short bounded reap opportunity even when the
                # externally supplied stop budget expired at that boundary.
                try:
                    child.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
            if child.poll() is not None:
                exact_exited.add(identity)
        refresh_alive(processes)
    finally:
        for descriptor in handles.values():
            os.close(descriptor)
    if any(
        identity not in exact_exited and process_matches(identity)
        for identity in processes
    ):
        signal_issues.append("provider process did not exit before the stop deadline")
    if signal_issues:
        raise ProviderResidueError("; ".join(signal_issues))
    return frozenset(exact_exited)


class DirectProvider:
    """Run ``socks-netns.py`` without ``--netns`` on a private loopback port."""

    def __init__(
        self,
        runtime_root: str | os.PathLike[str],
        release_dir: str | os.PathLike[str],
        *,
        process_scopes: ProcessScopeBackend | None = None,
        scope_store: ProviderScopeStore | None = None,
    ) -> None:
        self.runtime_root = Path(runtime_root)
        release = Path(release_dir)
        if not release.is_absolute():
            raise ValueError("release_dir must be absolute")
        resolved = release.resolve(strict=True)
        script = resolved / "socks-netns.py"
        info = script.lstat()
        if script.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise ValueError("socks-netns.py must be a real file in the selected release")
        self.script = script
        guard = resolved / "grok_ms" / "parent_guard.py"
        guard_info = guard.lstat()
        if guard.is_symlink() or not stat.S_ISREG(guard_info.st_mode):
            raise ValueError("grok_ms/parent_guard.py must be a real release file")
        self.guard = guard
        self._process_scopes = process_scopes or LinuxCgroupV2Scope()
        self._scope_store = scope_store
        self._children: dict[tuple[str, int], subprocess.Popen[bytes]] = {}
        self._lock = threading.Lock()

    def _scopes(self) -> ProviderScopeStore:
        with self._lock:
            if self._scope_store is None:
                self._scope_store = ProviderScopeStore(self.runtime_root)
            return self._scope_store

    def bind_scope_store(self, store: ProviderScopeStore) -> None:
        if not isinstance(store, ProviderScopeStore):
            raise TypeError("scope store must be a ProviderScopeStore")
        with self._lock:
            if (
                self._scope_store is not None
                and self._scope_store.directory != store.directory
            ):
                raise RuntimeSecurityError("direct provider scope store root changed")
            self._scope_store = store

    def _reconcile_scope_role(
        self,
        request: ProviderRequest,
        role: str,
        *,
        record: ProviderScopeRecord | None = None,
        handle: ScopeHandle | None = None,
        pidfd: int | None = None,
        deadline: TransitionDeadline | None = None,
    ) -> None:
        store = self._scopes()
        journal_error: BaseException | None = None
        try:
            persisted = store.load(request, role)
        except (RuntimeSecurityError, OSError, ValueError) as exc:
            if record is None:
                if handle is not None:
                    handle.close()
                raise ProviderResidueError(
                    f"cannot inspect {role} direct provider scope: {exc}"
                ) from exc
            persisted = None
            journal_error = exc
        if persisted is None:
            if record is None:
                if handle is not None:
                    handle.close()
                return
            authority = record
            delete_after = False
        else:
            if record is not None and not _same_provider_scope_authority(
                persisted, record
            ):
                raise ProviderResidueError(
                    "direct provider scope authority changed before cleanup"
                )
            authority = persisted
            delete_after = True
        owned_pidfd = False
        if pidfd is None and process_matches(authority.child):
            try:
                pidfd = pidfd_for_identity(authority.child)
                owned_pidfd = True
            except (OSError, ProcessLookupError, RuntimeError):
                pidfd = None
        try:
            try:
                timeout_seconds = (
                    request.contract.timeout_policy.stop_ms / 1_000
                    if deadline is None
                    else deadline.remaining_seconds(
                        f"{role} direct provider scope reconciliation"
                    )
                )
            except ProviderTimeout:
                if pidfd is not None:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    except (AttributeError, OSError, ProcessLookupError):
                        pass
                if authority.scope.created:
                    self._process_scopes.force_kill(
                        authority.scope,
                        handle=handle,
                    )
                raise
            self._process_scopes.reconcile(
                authority.scope,
                authority.phase,
                authority.child,
                pidfd,
                timeout_seconds,
                handle=handle,
            )
            if delete_after:
                store.delete(request, role, authority)
            if journal_error is not None:
                raise ProviderResidueError(
                    f"{role} direct provider scope journal is uncertain after exact cleanup: "
                    f"{journal_error}"
                )
        except Exception as exc:
            raise ProviderResidueError(
                f"cannot reconcile direct provider scope: {exc}"
            ) from exc
        finally:
            if handle is not None:
                handle.close()
            if owned_pidfd and pidfd is not None:
                os.close(pidfd)

    def _promote_scope(self, request: ProviderRequest) -> None:
        store = self._scopes()
        record = store.load(request, "command")
        if record is None:
            raise ProviderResidueError("direct provider scope disappeared")
        try:
            store.promote(request, record)
        except Exception as exc:
            raise ProviderResidueError(
                f"cannot promote direct provider scope: {exc}"
            ) from exc

    def _scope_residue(self, request: ProviderRequest) -> tuple[str, ...]:
        issues: list[str] = []
        for role in ("command", "provider"):
            try:
                if self._scopes().load(request, role) is not None:
                    issues.append(f"{role} direct provider scope remains")
            except (RuntimeSecurityError, OSError, ValueError) as exc:
                issues.append(f"cannot inspect {role} direct provider scope: {exc}")
        return tuple(issues)

    def start(
        self,
        request: ProviderRequest,
        deadline: TransitionDeadline,
        qualifier: Qualifier,
        cancellation: threading.Event | None = None,
    ) -> ProviderResult:
        if request.rung != "direct":
            raise ProviderProtocolError("DirectProvider accepts only rung=direct")
        _check_cancel(cancellation)
        deadline.check("direct provider start")
        workspace = _create_workspace(self.runtime_root, request)
        child: subprocess.Popen[bytes] | None = None
        identity: ProcessIdentity | None = None
        resources: ProviderResourceGraph | None = None
        pidfd: int | None = None
        scope_handle: ScopeHandle | None = None
        scope_record: ProviderScopeRecord | None = None
        barrier_read = -1
        barrier_write = -1
        key = (request.owner_epoch, request.generation)
        try:
            environment = {
                "PATH": _MINIMAL_PATH,
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            }
            parent = current_process_identity()
            planned_scope = self._process_scopes.plan()
            barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
            child = subprocess.Popen(
                [
                    sys.executable,
                    str(self.guard),
                    "--parent-pid",
                    str(parent.pid),
                    "--parent-start-ticks",
                    str(parent.start_ticks),
                    "--parent-boot-id",
                    parent.boot_id,
                    "--barrier-fd",
                    str(barrier_read),
                    "--",
                    sys.executable,
                    str(self.script),
                    "--listen",
                    f"127.0.0.1:{request.private_endpoint.port}",
                    "--pidfile",
                    str(workspace.pidfile),
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
            identity = _identity_for_pid(child.pid)
            pidfd = pidfd_for_identity(identity)
            scope_record = ProviderScopeRecord(
                schema_version=SCHEMA_VERSION,
                record_version=_PROVIDER_SCOPE_RECORD_VERSION,
                release_id=request.contract.release_id,
                verb="direct-up",
                phase="PREPARED",
                request=request,
                child=identity,
                scope=planned_scope,
            )
            self._scopes().put(request, scope_record)
            scope_handle = self._process_scopes.create(planned_scope)
            created = replace(
                scope_record,
                phase="SCOPE_CREATED",
                scope=scope_handle.identity,
            )
            self._scopes().replace(request, created)
            scope_record = created
            self._process_scopes.attach(scope_handle, identity)
            attached = replace(scope_record, phase="ATTACHED")
            self._scopes().replace(request, attached)
            scope_record = attached
            with self._lock:
                if key in self._children:
                    raise ProviderResidueError("direct generation already has a tracked child")
                self._children[key] = child
            _check_cancel(cancellation)
            deadline.check("direct provider barrier release")
            if os.write(barrier_write, b"\x01") != 1:
                raise ProviderError("short direct provider barrier release")
            os.close(barrier_write)
            barrier_write = -1
            listener = _wait_for_listener(
                request.private_endpoint, (identity,), deadline, cancellation
            )
            pid_path = _snapshot_path(workspace.pidfile, "pid", workspace.path)
            resources = ProviderResourceGraph(
                owner_epoch=request.owner_epoch,
                transition_id=request.transition_id,
                generation=request.generation,
                rung=request.rung,
                runtime_dir=str(workspace.path),
                processes=(identity,),
                listeners=(listener,),
                paths=(pid_path,),
            )
            evidence = qualifier(
                request.private_endpoint, request, deadline, cancellation
            )
            _check_cancel(cancellation)
            deadline.check("direct provider qualification")
            self._promote_scope(request)
            if scope_handle is not None:
                scope_handle.close()
                scope_handle = None
            if pidfd is not None:
                os.close(pidfd)
                pidfd = None
            return ProviderResult(request, evidence, resources)
        except Exception as original:
            cleanup_deadline = TransitionDeadline.after_ms(10_000)
            cleanup_issues: list[str] = []
            if barrier_write >= 0:
                os.close(barrier_write)
                barrier_write = -1
            reconciled_scope = False
            if scope_record is not None:
                persisted_roles: list[str] = []
                for role in ("provider", "command"):
                    try:
                        if self._scopes().load(request, role) is not None:
                            persisted_roles.append(role)
                    except (RuntimeSecurityError, OSError, ValueError) as exc:
                        cleanup_issues.append(
                            f"cannot inspect {role} direct provider scope: {exc}"
                        )
                roles = persisted_roles or ["command"]
                for role in roles:
                    try:
                        active_handle = scope_handle
                        scope_handle = None
                        try:
                            self._reconcile_scope_role(
                                request,
                                role,
                                record=scope_record,
                                handle=active_handle,
                                pidfd=pidfd,
                                deadline=cleanup_deadline,
                            )
                        finally:
                            if active_handle is not None:
                                active_handle.close()
                        if not reconciled_scope:
                            reconciled_scope = True
                    except (
                        ProviderError,
                        RuntimeSecurityError,
                        OSError,
                        ValueError,
                    ) as exc:
                        cleanup_issues.append(str(exc))
            if resources is not None and not reconciled_scope:
                try:
                    self._stop_resources(
                        request, resources, workspace, cleanup_deadline
                    )
                except ProviderError as exc:
                    cleanup_issues.append(str(exc))
            elif child is not None and not reconciled_scope:
                if identity is None:
                    try:
                        identity = _identity_for_pid(child.pid)
                    except (OSError, ValueError, ProviderError):
                        # poll() both determines whether the child already died
                        # and reaps it when it did.
                        child.poll()
                if identity is not None:
                    try:
                        _terminate_exact_processes(
                            (identity,), cleanup_deadline, {child.pid: child}
                        )
                    except ProviderError as exc:
                        cleanup_issues.append(str(exc))
                else:
                    try:
                        child.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        cleanup_issues.append("unidentified direct child did not exit")
            if child is not None:
                try:
                    child.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
                if child.poll() is not None:
                    try:
                        path_record = _snapshot_path(
                            workspace.pidfile, "pid", workspace.path
                        )
                    except FileNotFoundError:
                        path_record = None
                    except ProviderError as exc:
                        cleanup_issues.append(str(exc))
                        path_record = None
                    if path_record is not None:
                        try:
                            _unlink_exact(path_record)
                        except ProviderError as exc:
                            cleanup_issues.append(str(exc))
            if scope_handle is not None:
                scope_handle.close()
                scope_handle = None
            if pidfd is not None:
                os.close(pidfd)
                pidfd = None
            if barrier_read >= 0:
                os.close(barrier_read)
                barrier_read = -1
            _remove_empty_workspace(workspace)
            with self._lock:
                self._children.pop(key, None)
            try:
                if _ipv4_listen_inodes(request.private_endpoint):
                    cleanup_issues.append("direct candidate listener remains after failed start")
            except ProviderError as exc:
                cleanup_issues.append(str(exc))
            if workspace.path.exists() or workspace.path.is_symlink():
                cleanup_issues.append("direct candidate runtime remains after failed start")
            cleanup_issues.extend(self._scope_residue(request))
            if cleanup_issues:
                raise ProviderResidueError("; ".join(cleanup_issues)) from original
            raise

    def _stop_resources(
        self,
        request: ProviderRequest,
        resources: ProviderResourceGraph,
        workspace: _GenerationWorkspace,
        deadline: TransitionDeadline,
    ) -> frozenset[ProcessIdentity]:
        _validate_recovery_graph(request, resources)
        issues: list[str] = []
        with self._lock:
            child = self._children.pop(
                (resources.owner_epoch, resources.generation), None
            )
        children = {child.pid: child} if child is not None else {}
        exact_exited: set[ProcessIdentity] = set()
        scope_records: list[tuple[str, ProviderScopeRecord]] = []
        for role in ("command", "provider"):
            try:
                record = self._scopes().load(request, role)
            except (RuntimeSecurityError, OSError, ValueError) as exc:
                issues.append(f"cannot inspect {role} direct provider scope: {exc}")
                continue
            if record is not None:
                scope_records.append((role, record))

        if not scope_records:
            # A successful direct start always promotes one exact scope.  Still
            # contain the known leader, but preserve a fail-closed error because
            # a missing scope cannot prove that setsid descendants are absent.
            try:
                exact_exited.update(
                    _terminate_exact_processes(
                        resources.processes, deadline, children
                    )
                )
            except ProviderError as exc:
                issues.append(str(exc))
            issues.append("direct provider scope authority is absent")
        else:
            for role, record in scope_records:
                authority_matches = (
                    len(resources.processes) == 1
                    and record.child == resources.processes[0]
                )
                if not authority_matches:
                    issues.append(
                        f"{role} direct provider scope child differs from its resource graph"
                    )
                try:
                    self._reconcile_scope_role(
                        request,
                        role,
                        record=record,
                        deadline=deadline,
                    )
                    if authority_matches:
                        exact_exited.add(record.child)
                except ProviderError as exc:
                    issues.append(str(exc))
            if len(exact_exited) != len(resources.processes):
                try:
                    exact_exited.update(
                        _terminate_exact_processes(
                            resources.processes, deadline, children
                        )
                    )
                except ProviderError as exc:
                    issues.append(str(exc))

        if child is not None:
            try:
                child.wait(
                    timeout=max(
                        0.01,
                        deadline.remaining_seconds("direct provider child reap"),
                    )
                )
            except (subprocess.TimeoutExpired, ProviderTimeout):
                try:
                    child.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    issues.append("direct provider child could not be reaped")
            if child.poll() is not None:
                exact_exited.update(
                    identity
                    for identity in resources.processes
                    if identity.pid == child.pid
                )

        if all(
            identity in exact_exited or not process_matches(identity)
            for identity in resources.processes
        ):
            for path in resources.paths:
                try:
                    _unlink_exact(path)
                except ProviderError as exc:
                    issues.append(str(exc))
        _remove_empty_workspace(workspace)
        report = prove_empty_resources(
            resources,
            exactly_exited=frozenset(exact_exited),
        )
        issues.extend(report.issues)
        issues.extend(self._scope_residue(request))
        if issues:
            raise ProviderResidueError("; ".join(dict.fromkeys(issues)))
        return frozenset(exact_exited)

    def stop(
        self,
        result: ProviderResult,
        deadline: TransitionDeadline,
        cancellation: threading.Event | None = None,
    ) -> None:
        del cancellation  # teardown is deliberately non-cancellable once begun
        workspace = _workspace_from_result(self.runtime_root, result)
        self._stop_resources(result.request, result.resources, workspace, deadline)

    def prove_empty(self, result: ProviderResult) -> ResidueReport:
        report = prove_empty_resources(result.resources)
        issues = list(report.issues)
        issues.extend(self._scope_residue(result.request))
        return ResidueReport(clean=not issues, issues=tuple(issues))

    def recover(
        self,
        request: ProviderRequest,
        resources: ProviderResourceGraph | None,
        deadline: TransitionDeadline,
    ) -> ResidueReport:
        """Replay teardown using only durable exact identities.

        A PREPARED request without a graph is clean only when neither its
        deterministic runtime nor private listener exists.  Observable effects
        without an identity graph remain fenced; recovery never guesses a PID.
        """

        if request.rung != "direct":
            raise ProviderProtocolError("DirectProvider accepts only rung=direct")
        workspace = _workspace_for_request(self.runtime_root, request)
        if resources is None:
            issues: list[str] = []
            exactly_exited_pids: set[int] = set()
            for role in ("command", "provider"):
                try:
                    record = self._scopes().load(request, role)
                except (RuntimeSecurityError, OSError, ValueError) as exc:
                    issues.append(
                        f"cannot inspect {role} direct provider scope: {exc}"
                    )
                    continue
                if record is None:
                    continue
                try:
                    self._reconcile_scope_role(
                        request,
                        role,
                        record=record,
                        deadline=deadline,
                    )
                    exactly_exited_pids.add(record.child.pid)
                except ProviderError as exc:
                    issues.append(str(exc))
            try:
                if _ipv4_listen_inodes(request.private_endpoint):
                    issues.append("prepared direct listener exists without an exact resource graph")
            except ProviderError as exc:
                issues.append(str(exc))
            if not issues:
                issues.extend(
                    _remove_effect_free_prepared_workspace(
                        workspace,
                        exactly_exited_pids=frozenset(exactly_exited_pids),
                    )
                )
            issues.extend(self._scope_residue(request))
            if issues:
                raise ProviderResidueError("; ".join(issues))
            return ResidueReport(True, ())
        _validate_recovery_graph(request, resources)
        if Path(resources.runtime_dir) != workspace.path:
            raise ProviderProtocolError("direct recovery runtime differs from the frozen request")
        exactly_exited = self._stop_resources(
            request, resources, workspace, deadline
        )
        report = prove_empty_resources(
            resources,
            exactly_exited=exactly_exited,
        )
        if not report.clean:
            raise ProviderResidueError("; ".join(report.issues))
        return report


def _workspace_from_result(root: Path, result: ProviderResult) -> _GenerationWorkspace:
    runtime = Path(result.resources.runtime_dir)
    workspace = _workspace_for_request(root, result.request)
    if runtime != workspace.path:
        raise ProviderProtocolError("result runtime differs from its frozen request")
    return workspace


class LegacyShellProvider:
    """Strict adapter for generation-aware home, iPhone, and VPN shell providers.

    ``egress.sh`` must implement exactly these feature-on commands:

    * ``provider-up RUNG`` -- synchronously create only ``RUNG`` on the supplied
      private port and atomically write the inventory record described by
      :meth:`_load_inventory`; it must not start its legacy watchdog.
    * ``provider-next vpn`` -- advance only the already-owned VPN broker cursor,
      preserve the exact relay/listener, and atomically republish inventory.
    * ``provider-stop RUNG`` -- synchronously remove that generation's user and
      broker-owned resources, including its inventory file.
    * ``provider-prove-empty RUNG`` -- exit zero only after independently proving
      that owner/generation has no user or privileged residue.

    The command receives only :meth:`_environment`; caller ``GROK_*`` variables
    and executable paths are never inherited.  The selected release script is
    unprivileged and any VPN work must go through the separately fixed broker.
    """

    def __init__(
        self,
        runtime_root: str | os.PathLike[str],
        release_dir: str | os.PathLike[str],
        *,
        process_scopes: ProcessScopeBackend | None = None,
        scope_store: ProviderScopeStore | None = None,
        provider_canary_fd: int | None = None,
    ) -> None:
        self.runtime_root = Path(runtime_root)
        release = Path(release_dir)
        if not release.is_absolute():
            raise ValueError("release_dir must be absolute")
        resolved = release.resolve(strict=True)
        script = resolved / "egress.sh"
        info = script.lstat()
        if script.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise ValueError("egress.sh must be a real file in the selected release")
        self.script = script
        guard = resolved / "grok_ms" / "parent_guard.py"
        guard_info = guard.lstat()
        if guard.is_symlink() or not stat.S_ISREG(guard_info.st_mode):
            raise ValueError("grok_ms/parent_guard.py must be a real release file")
        self.guard = guard
        self._process_scopes = process_scopes or LinuxCgroupV2Scope()
        self._scope_store = scope_store
        if provider_canary_fd is not None:
            if type(provider_canary_fd) is not int or provider_canary_fd < 3:
                raise ValueError("provider canary descriptor is unsafe")
            try:
                os.fstat(provider_canary_fd)
                os.set_inheritable(provider_canary_fd, False)
            except OSError as exc:
                raise ValueError("provider canary descriptor is not open") from exc
        self._provider_canary_fd = provider_canary_fd
        self._empty_proofs: set[tuple[str, int]] = set()
        self._lock = threading.Lock()

    def _scopes(self) -> ProviderScopeStore:
        with self._lock:
            if self._scope_store is None:
                self._scope_store = ProviderScopeStore(self.runtime_root)
            return self._scope_store

    def bind_scope_store(self, store: ProviderScopeStore) -> None:
        """Bind the supervisor-created journal before any provider command."""

        if not isinstance(store, ProviderScopeStore):
            raise TypeError("scope store must be a ProviderScopeStore")
        with self._lock:
            if (
                self._scope_store is not None
                and self._scope_store.directory != store.directory
            ):
                raise RuntimeSecurityError("provider scope store root changed")
            self._scope_store = store

    def revoke_provider_canary(self) -> None:
        """Forget the borrowed capability after terminal supervisor cleanup."""

        with self._lock:
            self._provider_canary_fd = None

    def _reconcile_scope_role(
        self,
        request: ProviderRequest,
        role: str,
        *,
        record: ProviderScopeRecord | None = None,
        handle: ScopeHandle | None = None,
        pidfd: int | None = None,
        deadline: TransitionDeadline | None = None,
    ) -> None:
        store = self._scopes()
        persisted = store.load(request, role)
        if persisted is None:
            if record is None:
                if handle is not None:
                    handle.close()
                return
            authority = record
            delete_after = False
        else:
            if record is not None and not _same_provider_scope_authority(
                persisted, record
            ):
                raise ProviderResidueError(
                    "provider command scope authority changed before cleanup"
                )
            authority = persisted
            delete_after = True
        owned_pidfd = False
        if pidfd is None and process_matches(authority.child):
            try:
                pidfd = pidfd_for_identity(authority.child)
                owned_pidfd = True
            except (OSError, ProcessLookupError, RuntimeError):
                pidfd = None
        try:
            try:
                timeout_seconds = (
                    request.contract.timeout_policy.stop_ms / 1_000
                    if deadline is None
                    else deadline.remaining_seconds(
                        f"{role} provider command scope reconciliation"
                    )
                )
            except ProviderTimeout:
                if pidfd is not None:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    except (AttributeError, OSError, ProcessLookupError):
                        pass
                if authority.scope.created:
                    self._process_scopes.force_kill(
                        authority.scope,
                        handle=handle,
                    )
                raise
            self._process_scopes.reconcile(
                authority.scope,
                authority.phase,
                authority.child,
                pidfd,
                timeout_seconds,
                handle=handle,
            )
            if delete_after:
                store.delete(request, role, authority)
        except Exception as exc:
            raise ProviderResidueError(
                f"cannot reconcile {role} provider command scope: {exc}"
            ) from exc
        finally:
            if handle is not None:
                handle.close()
            if owned_pidfd and pidfd is not None:
                os.close(pidfd)

    def _promote_provider_scope(self, request: ProviderRequest) -> None:
        store = self._scopes()
        record = store.load(request, "command")
        if record is None:
            raise ProviderResidueError("provider-up command scope disappeared")
        try:
            store.promote(request, record)
        except Exception as exc:
            raise ProviderResidueError(
                f"cannot promote provider command scope: {exc}"
            ) from exc

    def _scope_residue(self, request: ProviderRequest) -> tuple[str, ...]:
        issues: list[str] = []
        store = self._scopes()
        for role in ("command", "provider"):
            try:
                if store.load(request, role) is not None:
                    issues.append(f"{role} provider command scope remains")
            except (RuntimeSecurityError, OSError, ValueError) as exc:
                issues.append(f"cannot inspect {role} provider command scope: {exc}")
        return tuple(issues)

    @staticmethod
    def _environment(
        request: ProviderRequest,
        workspace: _GenerationWorkspace,
        deadline: TransitionDeadline | None = None,
    ) -> dict[str, str]:
        account = pwd.getpwuid(os.getuid())
        contract = request.contract
        environment = {
            "PATH": _MINIMAL_PATH,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": account.pw_dir,
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "GROK_PROVIDER_MODE": "1",
            "GROK_PROVIDER_OWNER_EPOCH": request.owner_epoch,
            "GROK_INTERLOCK_OWNER_EPOCH": request.owner_epoch,
            "GROK_PROVIDER_TRANSITION_ID": request.transition_id,
            "GROK_PROVIDER_GENERATION": str(request.generation),
            "GROK_PROVIDER_CONTRACT_DIGEST": contract.digest(),
            "GROK_EGRESS_RUNTIME_DIR": str(workspace.path),
            "GROK_PROVIDER_INVENTORY": str(workspace.inventory),
            "GROK_PROXY_PORT": str(request.private_endpoint.port),
            "GROK_REQUIRE_MODEL": request.model_id,
            "GROK_ACTIVE_RELEASE_ID": contract.release_id,
        }
        if deadline is not None:
            environment["GROK_PROVIDER_DEADLINE_NS"] = str(deadline.expires_ns)
        if request.rung.startswith("home:"):
            label = request.rung.removeprefix("home:")
            endpoint = contract.home_endpoint(label)
            if endpoint is None:  # ProviderRequest validation makes this unreachable.
                raise ProviderProtocolError("home rung has no frozen endpoint")
            environment.update(
                {
                    "GROK_PROVIDER_HOME_LABEL": endpoint.label,
                    "GROK_PROVIDER_HOME_HOST": endpoint.host,
                    "GROK_PROVIDER_HOME_USER": endpoint.user,
                    "GROK_PROVIDER_HOME_PORT": str(endpoint.port),
                }
            )
        elif request.rung == "iphone":
            if contract.phone_node_id is None:  # RouteContract validation rejects this.
                raise ProviderProtocolError("iPhone rung has no frozen node identity")
            environment["GROK_PROVIDER_IPHONE_NODE_ID"] = contract.phone_node_id
        elif request.rung == "vpn":
            policy = contract.vpn_policy
            countries = " ".join(policy.countries)
            blocked = " ".join(policy.blocked_countries)
            environment.update(
                {
                    "GROK_PROVIDER_VPN_NAMESPACE": policy.namespace,
                    "GROK_PROVIDER_VPN_MAX_TRIES": str(policy.max_tries),
                    "GROK_PROVIDER_VPN_RANKING_VERSION": policy.ranking_version,
                    "GROK_PROVIDER_VPN_COUNTRIES": countries,
                    "GROK_PROVIDER_VPN_BLOCKED_COUNTRIES": blocked,
                    # These compatibility names are still consumed by egress.sh;
                    # every value comes from the already-validated contract.
                    "GROK_VPN_NETNS": policy.namespace,
                    "GROK_VPN_MAX_TRIES": str(policy.max_tries),
                    "VPNGATE_COUNTRIES": countries,
                    "GROK_BLOCKED_CC": blocked,
                    "GROK_VPN_STABILITY_CHECKS": str(
                        contract.stability_policy.sample_count
                    ),
                    "GROK_STABILITY_INTERVAL_MS": str(
                        contract.stability_policy.sample_interval_ms
                    ),
                }
            )
        return environment

    def _command(
        self,
        verb: str,
        request: ProviderRequest,
        workspace: _GenerationWorkspace,
        deadline: TransitionDeadline,
        cancellation: threading.Event | None,
        *,
        retain_scope_on_success: bool = False,
    ) -> int:
        if verb not in {
            "provider-up",
            "provider-next",
            "provider-recover",
            "provider-stop",
            "provider-prove-empty",
        }:
            raise ValueError("unsupported provider shell verb")
        _check_cancel(cancellation)
        deadline.check(verb)
        try:
            parent = current_process_identity()
            planned_scope = self._process_scopes.plan()
        except Exception as exc:
            raise ProviderError(f"cannot plan {verb} command scope") from exc
        barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
        process: subprocess.Popen[bytes] | None = None
        child: ProcessIdentity | None = None
        pidfd: int | None = None
        scope_handle: ScopeHandle | None = None
        record: ProviderScopeRecord | None = None
        primary_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        retained = False
        rc: int | None = None
        try:
            environment = self._environment(request, workspace, deadline)
            pass_fds = (barrier_read,)
            if self._provider_canary_fd is not None:
                environment.update(
                    {
                        "GROK_RELEASE_CANARY_FD": str(
                            self._provider_canary_fd
                        ),
                        "GROK_RELEASE_CANARY_RELEASE_ID": (
                            request.contract.release_id
                        ),
                    }
                )
                pass_fds = (barrier_read, self._provider_canary_fd)
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(self.guard),
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
                    str(self.script),
                    verb,
                    request.rung,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=pass_fds,
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
            pidfd = pidfd_for_identity(child)
            record = ProviderScopeRecord(
                schema_version=SCHEMA_VERSION,
                record_version=_PROVIDER_SCOPE_RECORD_VERSION,
                release_id=request.contract.release_id,
                verb=verb,
                phase="PREPARED",
                request=request,
                child=child,
                scope=planned_scope,
            )
            self._scopes().put(request, record)
            scope_handle = self._process_scopes.create(planned_scope)
            record = ProviderScopeRecord(
                schema_version=record.schema_version,
                record_version=record.record_version,
                release_id=record.release_id,
                verb=record.verb,
                phase="SCOPE_CREATED",
                request=record.request,
                child=record.child,
                scope=scope_handle.identity,
            )
            self._scopes().replace(request, record)
            self._process_scopes.attach(scope_handle, child)
            record = ProviderScopeRecord(
                schema_version=record.schema_version,
                record_version=record.record_version,
                release_id=record.release_id,
                verb=record.verb,
                phase="ATTACHED",
                request=record.request,
                child=record.child,
                scope=record.scope,
            )
            self._scopes().replace(request, record)
            _check_cancel(cancellation)
            deadline.check(verb)
            if os.write(barrier_write, b"\x01") != 1:
                raise ProviderError(f"short {verb} command barrier release")
            os.close(barrier_write)
            barrier_write = -1
            while process.poll() is None:
                _check_cancel(cancellation)
                remaining = deadline.remaining_seconds(verb)
                cleanup_reserve = min(
                    0.5,
                    max(
                        0.02,
                        request.contract.timeout_policy.stop_ms / 5_000,
                    ),
                )
                if remaining <= cleanup_reserve:
                    raise ProviderTimeout(
                        f"cumulative deadline reserved for {verb} containment"
                    )
                time.sleep(min(0.02, remaining - cleanup_reserve))
            rc = process.returncode
            retained = retain_scope_on_success and rc == 0
        except OSError as exc:
            # A spawn failure is effect-free because no barriered child exists.
            if process is None:
                primary_error = exc
            else:
                primary_error = exc
        except BaseException as exc:
            primary_error = exc
        finally:
            for descriptor in (barrier_read, barrier_write):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            if process is not None and not retained:
                try:
                    if record is not None:
                        self._reconcile_scope_role(
                            request,
                            "command",
                            record=record,
                            handle=scope_handle,
                            pidfd=pidfd,
                            deadline=deadline,
                        )
                        scope_handle = None
                    else:
                        try:
                            process.kill()
                        except (OSError, ProcessLookupError):
                            pass
                    if process.poll() is None:
                        try:
                            process.wait(
                                timeout=deadline.remaining_seconds(
                                    f"{verb} command reap"
                                )
                            )
                        except (subprocess.TimeoutExpired, ProviderTimeout) as exc:
                            raise ProviderResidueError(
                                f"barriered {verb} command did not exit"
                            ) from exc
                except BaseException as exc:
                    cleanup_error = exc
            if scope_handle is not None:
                try:
                    scope_handle.close()
                except OSError as exc:
                    cleanup_error = cleanup_error or exc
            if pidfd is not None:
                try:
                    os.close(pidfd)
                except OSError as exc:
                    cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise ProviderResidueError(
                f"{verb} command scope cleanup is uncertain: {cleanup_error}"
            ) from primary_error
        if primary_error is not None:
            if process is None and isinstance(primary_error, OSError):
                return _PROVIDER_INFRASTRUCTURE_FAILURE
            if isinstance(primary_error, (ProviderCancelled, ProviderTimeout)):
                raise primary_error
            if isinstance(primary_error, ProviderError):
                raise primary_error
            raise ProviderError(f"{verb} command failed before completion") from primary_error
        assert rc is not None
        if rc == 0:
            return 0
        if verb == "provider-up" and rc in _PROVIDER_UP_STAGE_CODES:
            return rc
        if (
            verb == "provider-up"
            and request.rung == "vpn"
            and rc in _VPN_PROVIDER_UP_STAGE_CODES
        ):
            return rc
        return _PROVIDER_INFRASTRUCTURE_FAILURE

    def _load_inventory(
        self, request: ProviderRequest, workspace: _GenerationWorkspace
    ) -> ProviderResourceGraph:
        try:
            value = strict_json_loads(
                _read_bounded_secure_file(workspace.inventory),
                DEFAULT_MAX_PACKET_BYTES,
            )
        except (OSError, ProtocolError) as exc:
            raise ProviderProtocolError(f"cannot read provider inventory: {exc}") from exc
        fields = {
            "schema_version",
            "owner_epoch",
            "transition_id",
            "generation",
            "rung",
            "pids",
            "paths",
            "privileged",
        }
        if set(value) != fields:
            raise ProviderProtocolError("provider inventory has missing or unexpected fields")
        expected = {
            "schema_version": 1,
            "owner_epoch": request.owner_epoch,
            "transition_id": request.transition_id,
            "generation": request.generation,
            "rung": request.rung,
        }
        for name, wanted in expected.items():
            if value[name] != wanted or type(value[name]) is not type(wanted):
                raise ProviderProtocolError(f"provider inventory {name} mismatch")
        pids = value["pids"]
        paths = value["paths"]
        privileged = value["privileged"]
        if type(pids) is not list or not pids or any(type(pid) is not int for pid in pids):
            raise ProviderProtocolError("provider inventory requires a nonempty integer pid list")
        if len(set(pids)) != len(pids):
            raise ProviderProtocolError("provider inventory contains duplicate pids")
        if type(paths) is not list or type(privileged) is not list:
            raise ProviderProtocolError("provider inventory resource fields must be arrays")
        processes = tuple(_identity_for_pid(pid) for pid in pids)
        listener = _listener_identity(request.private_endpoint, processes)
        path_records: list[PathIdentity] = [
            _snapshot_path(workspace.inventory, "inventory", workspace.path)
        ]
        for index, item in enumerate(paths):
            if type(item) is not dict or set(item) != {"path", "kind"}:
                raise ProviderProtocolError(f"invalid inventory path at index {index}")
            if type(item["path"]) is not str or type(item["kind"]) is not str:
                raise ProviderProtocolError(f"invalid inventory path types at index {index}")
            path_records.append(
                _snapshot_path(Path(item["path"]), item["kind"], workspace.path)
            )
        privileged_records: list[PrivilegedResourceIdentity] = []
        for index, item in enumerate(privileged):
            if type(item) is not dict or set(item) != {"kind", "name", "broker_instance"}:
                raise ProviderProtocolError(f"invalid privileged record at index {index}")
            try:
                privileged_records.append(
                    PrivilegedResourceIdentity(
                        kind=item["kind"],
                        name=item["name"],
                        broker_instance=item["broker_instance"],
                    )
                )
            except (TypeError, ValueError) as exc:
                raise ProviderProtocolError(str(exc)) from exc
        return ProviderResourceGraph(
            owner_epoch=request.owner_epoch,
            transition_id=request.transition_id,
            generation=request.generation,
            rung=request.rung,
            runtime_dir=str(workspace.path),
            processes=processes,
            listeners=(listener,),
            paths=tuple(path_records),
            privileged=tuple(privileged_records),
        )

    @staticmethod
    def _validate_vpn_next_graph(
        previous: ProviderResourceGraph, current: ProviderResourceGraph
    ) -> None:
        """Prove broker ``next`` changed no user relay ownership boundary."""

        if (
            current.owner_epoch,
            current.transition_id,
            current.generation,
            current.rung,
            current.runtime_dir,
        ) != (
            previous.owner_epoch,
            previous.transition_id,
            previous.generation,
            previous.rung,
            previous.runtime_dir,
        ):
            raise ProviderProtocolError("VPN next changed the provider ownership scope")
        if current.processes != previous.processes:
            raise ProviderProtocolError("VPN next replaced the owned relay process")
        if current.listeners != previous.listeners:
            raise ProviderProtocolError("VPN next replaced the owned relay listener")
        if current.privileged != previous.privileged:
            raise ProviderProtocolError("VPN next changed the privileged resource names")
        previous_paths = {(item.path, item.kind): item for item in previous.paths}
        current_paths = {(item.path, item.kind): item for item in current.paths}
        if set(previous_paths) != set(current_paths):
            raise ProviderProtocolError("VPN next changed the provider path graph")
        for key, old_identity in previous_paths.items():
            new_identity = current_paths[key]
            if old_identity != new_identity and _path_still_matches(old_identity):
                raise ProviderProtocolError(
                    "VPN next left an old path identity reachable after replacement"
                )

    def start(
        self,
        request: ProviderRequest,
        deadline: TransitionDeadline,
        qualifier: Qualifier,
        cancellation: threading.Event | None = None,
    ) -> ProviderResult:
        if request.rung == "direct":
            raise ProviderProtocolError("LegacyShellProvider does not implement direct")
        _check_cancel(cancellation)
        workspace = _create_workspace(self.runtime_root, request)
        resources: ProviderResourceGraph | None = None
        key = (request.owner_epoch, request.generation)
        with self._lock:
            self._empty_proofs.discard(key)
        try:
            rc = self._command(
                "provider-up",
                request,
                workspace,
                deadline,
                cancellation,
                retain_scope_on_success=True,
            )
            if rc != 0:
                raise ProviderError(f"provider-up exited with status {rc}")
            deadline.check("provider inventory")
            resources = self._load_inventory(request, workspace)
            self._promote_provider_scope(request)
            attempts = request.contract.vpn_policy.max_tries if request.rung == "vpn" else 1
            for attempt in range(attempts):
                try:
                    evidence = qualifier(
                        request.private_endpoint, request, deadline, cancellation
                    )
                    _check_cancel(cancellation)
                    deadline.check("legacy provider qualification")
                    return ProviderResult(request, evidence, resources)
                except (ProviderCancelled, ProviderTimeout):
                    raise
                except ProviderError as candidate_error:
                    if request.rung != "vpn" or attempt + 1 >= attempts:
                        raise
                    _check_cancel(cancellation)
                    deadline.check("VPN candidate advance")
                    previous = resources
                    rc = self._command(
                        "provider-next", request, workspace, deadline, cancellation
                    )
                    if rc != 0:
                        raise ProviderError(
                            f"provider-next exited with status {rc}"
                        ) from candidate_error
                    deadline.check("VPN replacement inventory")
                    resources = self._load_inventory(request, workspace)
                    self._validate_vpn_next_graph(previous, resources)
            raise ProviderError("VPN candidate loop ended without a result")
        except Exception as original:
            cleanup = TransitionDeadline.after_ms(15_000)
            cleanup_issues: list[str] = []
            exact_exited: set[ProcessIdentity] = set()
            # An inventory/protocol failure occurs before provider-up's scope
            # can be promoted.  Reconcile that retained command authority
            # before starting the independently scoped cleanup command.
            try:
                self._reconcile_scope_role(
                    request,
                    "command",
                    deadline=cleanup,
                )
            except ProviderError as exc:
                cleanup_issues.append(str(exc))
            try:
                if self._command("provider-stop", request, workspace, cleanup, None) != 0:
                    cleanup_issues.append("provider-stop rejected failed-start cleanup")
            except ProviderError as exc:
                cleanup_issues.append(str(exc))
            if resources is not None:
                try:
                    exact_exited.update(
                        _terminate_exact_processes(resources.processes, cleanup)
                    )
                except ProviderError as exc:
                    cleanup_issues.append(str(exc))
                if all(
                    item in exact_exited or not process_matches(item)
                    for item in resources.processes
                ):
                    for path in resources.paths:
                        try:
                            _unlink_exact(path)
                        except ProviderError as exc:
                            cleanup_issues.append(str(exc))
            for role in ("command", "provider"):
                try:
                    self._reconcile_scope_role(
                        request,
                        role,
                        deadline=cleanup,
                    )
                except ProviderError as exc:
                    cleanup_issues.append(str(exc))
            _remove_empty_workspace(workspace)
            try:
                if self._command(
                    "provider-prove-empty", request, workspace, cleanup, None
                ) != 0:
                    cleanup_issues.append("provider-prove-empty rejected failed-start cleanup")
            except ProviderError as exc:
                cleanup_issues.append(str(exc))
            try:
                if _ipv4_listen_inodes(request.private_endpoint):
                    cleanup_issues.append("legacy candidate listener remains after failed start")
            except ProviderError as exc:
                cleanup_issues.append(str(exc))
            if workspace.path.exists() or workspace.path.is_symlink():
                cleanup_issues.append("legacy candidate runtime remains after failed start")
            if cleanup_issues:
                raise ProviderResidueError("; ".join(dict.fromkeys(cleanup_issues))) from original
            raise

    def stop(
        self,
        result: ProviderResult,
        deadline: TransitionDeadline,
        cancellation: threading.Event | None = None,
    ) -> None:
        del cancellation  # stop becomes non-cancellable after the drain linearization point
        workspace = _workspace_from_result(self.runtime_root, result)
        request = result.request
        key = (request.owner_epoch, request.generation)
        issues: list[str] = []
        exact_exited: set[ProcessIdentity] = set()
        try:
            rc = self._command("provider-stop", request, workspace, deadline, None)
            if rc != 0:
                issues.append(f"provider-stop exited with status {rc}")
        except ProviderError as exc:
            issues.append(str(exc))
        try:
            exact_exited.update(
                _terminate_exact_processes(result.resources.processes, deadline)
            )
        except ProviderError as exc:
            issues.append(str(exc))
        for role in ("command", "provider"):
            try:
                self._reconcile_scope_role(
                    request,
                    role,
                    deadline=deadline,
                )
            except ProviderError as exc:
                issues.append(str(exc))
        if all(
            item in exact_exited or not process_matches(item)
            for item in result.resources.processes
        ):
            for path in result.resources.paths:
                try:
                    _unlink_exact(path)
                except ProviderError as exc:
                    issues.append(str(exc))
        _remove_empty_workspace(workspace)
        try:
            rc = self._command(
                "provider-prove-empty", request, workspace, deadline, None
            )
            if rc != 0:
                issues.append("provider-prove-empty rejected the teardown")
        except ProviderError as exc:
            issues.append(str(exc))
        report = prove_empty_resources(
            result.resources,
            exactly_exited=frozenset(exact_exited),
        )
        issues.extend(report.issues)
        issues.extend(self._scope_residue(request))
        if issues:
            raise ProviderResidueError("; ".join(dict.fromkeys(issues)))
        with self._lock:
            self._empty_proofs.add(key)

    def prove_empty(self, result: ProviderResult) -> ResidueReport:
        report = prove_empty_resources(result.resources)
        issues = list(report.issues)
        issues.extend(self._scope_residue(result.request))
        key = (result.request.owner_epoch, result.request.generation)
        if result.resources.privileged:
            with self._lock:
                broker_proved = key in self._empty_proofs
            if not broker_proved:
                issues.append("privileged empty proof has not completed")
        return ResidueReport(clean=not issues, issues=tuple(issues))

    def recover(
        self,
        request: ProviderRequest,
        resources: ProviderResourceGraph | None,
        deadline: TransitionDeadline,
    ) -> ResidueReport:
        """Recover a dead generation through the closed provider protocol."""

        if request.rung == "direct":
            raise ProviderProtocolError("LegacyShellProvider does not implement direct")
        workspace = _workspace_for_request(self.runtime_root, request)
        issues: list[str] = []
        exact_exited: set[ProcessIdentity] = set()
        try:
            self._reconcile_scope_role(
                request,
                "command",
                deadline=deadline,
            )
        except ProviderError as exc:
            issues.append(str(exc))
        if resources is not None:
            _validate_recovery_graph(request, resources)
            if Path(resources.runtime_dir) != workspace.path:
                raise ProviderProtocolError(
                    "legacy recovery runtime differs from the frozen request"
                )
            try:
                exact_exited.update(
                    _terminate_exact_processes(resources.processes, deadline)
                )
            except ProviderError as exc:
                issues.append(str(exc))

        # For VPN this invokes broker `recover`, which replays the root ledger's
        # exact identities.  For other rungs it removes only the generation
        # paths after Python has terminated the durable process graph.
        try:
            rc = self._command(
                "provider-recover", request, workspace, deadline, None
            )
            if rc != 0:
                issues.append(f"provider-recover exited with status {rc}")
        except ProviderError as exc:
            issues.append(str(exc))

        try:
            self._reconcile_scope_role(
                request,
                "provider",
                deadline=deadline,
            )
        except ProviderError as exc:
            issues.append(str(exc))

        if resources is not None and all(
            item in exact_exited or not process_matches(item)
            for item in resources.processes
        ):
            for path in resources.paths:
                try:
                    _unlink_exact(path)
                except ProviderError as exc:
                    issues.append(str(exc))
        _remove_empty_workspace(workspace)
        try:
            rc = self._command(
                "provider-prove-empty", request, workspace, deadline, None
            )
            if rc != 0:
                issues.append("provider-prove-empty rejected recovery")
        except ProviderError as exc:
            issues.append(str(exc))
        if resources is not None:
            issues.extend(
                prove_empty_resources(
                    resources,
                    exactly_exited=frozenset(exact_exited),
                ).issues
            )
        else:
            try:
                if _ipv4_listen_inodes(request.private_endpoint):
                    issues.append("private listener remains after VPN recovery")
            except ProviderError as exc:
                issues.append(str(exc))
            if workspace.path.exists() or workspace.path.is_symlink():
                issues.append("generation runtime remains after VPN recovery")
        issues.extend(self._scope_residue(request))
        if issues:
            raise ProviderResidueError("; ".join(dict.fromkeys(issues)))
        with self._lock:
            self._empty_proofs.add((request.owner_epoch, request.generation))
        return ResidueReport(True, ())


@dataclass(frozen=True, slots=True)
class ScriptedStep:
    operation: str
    delay_ms: int = 0
    error: str | None = None

    def __post_init__(self) -> None:
        if self.operation not in {"start", "stop", "recover"}:
            raise ValueError("scripted operation must be start, stop, or recover")
        if type(self.delay_ms) is not int or not 0 <= self.delay_ms <= 3_600_000:
            raise ValueError("scripted delay_ms is out of range")
        if self.error is not None:
            _require_token(self.error, "scripted.error")


class ScriptedProvider:
    """Deterministic, mutation-free provider used by state-machine/fault tests."""

    def __init__(
        self,
        steps: Sequence[ScriptedStep],
        *,
        advance_ms: Callable[[int], None] | None = None,
    ) -> None:
        self._steps = list(steps)
        self._advance_ms = advance_ms or (lambda ms: time.sleep(ms / 1_000))
        self._calls: list[tuple[str, str, int]] = []
        self._active: dict[tuple[str, int], ProviderResult] = {}

    @property
    def calls(self) -> tuple[tuple[str, str, int], ...]:
        return tuple(self._calls)

    def _step(
        self,
        operation: str,
        request: ProviderRequest,
        deadline: TransitionDeadline,
        cancellation: threading.Event | None,
    ) -> None:
        if not self._steps:
            raise ProviderProtocolError(f"no scripted step remains for {operation}")
        step = self._steps.pop(0)
        if step.operation != operation:
            raise ProviderProtocolError(
                f"expected scripted {step.operation}, received {operation}"
            )
        self._calls.append((operation, request.rung, request.generation))
        _check_cancel(cancellation)
        deadline.check(f"scripted {operation}")
        self._advance_ms(step.delay_ms)
        _check_cancel(cancellation)
        deadline.check(f"scripted {operation}")
        if step.error is not None:
            raise ProviderError(step.error)

    @staticmethod
    def _resources(request: ProviderRequest) -> ProviderResourceGraph:
        process = ProcessIdentity(
            pid=10_000 + request.generation,
            start_ticks=request.generation,
            boot_id="00000000-0000-0000-0000-000000000000",
        )
        privileged: tuple[PrivilegedResourceIdentity, ...] = ()
        if request.rung == "vpn":
            privileged = tuple(
                PrivilegedResourceIdentity(kind, name, request.transition_id)
                for kind, name in sorted(_FIXED_VPN_RESOURCES)
            )
        return ProviderResourceGraph(
            owner_epoch=request.owner_epoch,
            transition_id=request.transition_id,
            generation=request.generation,
            rung=request.rung,
            runtime_dir=f"/scripted/{request.owner_epoch}/g{request.generation}",
            processes=(process,),
            listeners=(ListenerIdentity(request.private_endpoint, 50_000 + request.generation, process),),
            paths=(),
            privileged=privileged,
        )

    def start(
        self,
        request: ProviderRequest,
        deadline: TransitionDeadline,
        qualifier: Qualifier,
        cancellation: threading.Event | None = None,
    ) -> ProviderResult:
        self._step("start", request, deadline, cancellation)
        evidence = qualifier(request.private_endpoint, request, deadline, cancellation)
        _check_cancel(cancellation)
        deadline.check("scripted qualification")
        result = ProviderResult(request, evidence, self._resources(request))
        key = (request.owner_epoch, request.generation)
        if key in self._active:
            raise ProviderResidueError("scripted generation is already active")
        self._active[key] = result
        return result

    def stop(
        self,
        result: ProviderResult,
        deadline: TransitionDeadline,
        cancellation: threading.Event | None = None,
    ) -> None:
        self._step("stop", result.request, deadline, cancellation)
        self._active.pop((result.request.owner_epoch, result.request.generation), None)

    def prove_empty(self, result: ProviderResult) -> ResidueReport:
        key = (result.request.owner_epoch, result.request.generation)
        issues = () if key not in self._active else ("scripted generation remains active",)
        return ResidueReport(clean=not issues, issues=issues)

    def recover(
        self,
        request: ProviderRequest,
        resources: ProviderResourceGraph | None,
        deadline: TransitionDeadline,
    ) -> ResidueReport:
        if (
            resources is None
            and (request.owner_epoch, request.generation) not in self._active
        ):
            return ResidueReport(True, ())
        del resources
        self._step("recover", request, deadline, None)
        self._active.pop((request.owner_epoch, request.generation), None)
        return ResidueReport(True, ())
