"""Durable cgroup authority for intentional detached process lifetimes."""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import re
from typing import Any, Mapping

from .contract import SCHEMA_VERSION
from .process_scope import ScopeIdentity
from .runtime import (
    ProcessIdentity,
    RuntimeSecurityError,
    SecureRuntime,
    _atomic_create_json,
    _atomic_replace_json,
    _create_secure_directory,
    _durable_unlink,
    _read_secure_json,
)


_RECORD_VERSION = 1
_PHASES = frozenset({"PREPARED", "SCOPE_CREATED", "ATTACHED", "OWNED"})
_KINDS = frozenset({"supervisor-epoch", "compatibility-handoff"})
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:+@-]{1,128}$")


def _identity_to_dict(identity: ProcessIdentity) -> dict[str, Any]:
    return {
        "boot_id": identity.boot_id,
        "pid": identity.pid,
        "pid_start_ticks": identity.start_ticks,
    }


def _identity_from_dict(value: Any) -> ProcessIdentity:
    if type(value) is not dict or set(value) != {
        "boot_id",
        "pid",
        "pid_start_ticks",
    }:
        raise ValueError("detached_scope.child: missing or unexpected fields")
    return ProcessIdentity(
        pid=value["pid"],
        start_ticks=value["pid_start_ticks"],
        boot_id=value["boot_id"],
    )


@dataclass(frozen=True, slots=True)
class DetachedScopeRecord:
    schema_version: int
    record_version: int
    release_id: str
    kind: str
    phase: str
    owner_epoch: str | None
    child: ProcessIdentity
    scope: ScopeIdentity

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("detached_scope.schema_version: unsupported value")
        if self.record_version != _RECORD_VERSION:
            raise ValueError("detached_scope.record_version: unsupported value")
        if (
            type(self.release_id) is not str
            or _TOKEN_RE.fullmatch(self.release_id) is None
        ):
            raise ValueError("detached_scope.release_id: invalid token")
        if self.kind not in _KINDS:
            raise ValueError("detached_scope.kind: unsupported value")
        if self.phase not in _PHASES:
            raise ValueError("detached_scope.phase: unsupported value")
        if self.owner_epoch is not None and (
            type(self.owner_epoch) is not str
            or _TOKEN_RE.fullmatch(self.owner_epoch) is None
        ):
            raise ValueError("detached_scope.owner_epoch: invalid token")
        if not isinstance(self.child, ProcessIdentity):
            raise ValueError("detached_scope.child: expected ProcessIdentity")
        if not isinstance(self.scope, ScopeIdentity):
            raise ValueError("detached_scope.scope: expected ScopeIdentity")
        if (self.phase == "PREPARED") == self.scope.created:
            raise ValueError("detached scope phase and cgroup inode state disagree")
        if self.kind == "supervisor-epoch":
            if (self.phase == "OWNED") != (self.owner_epoch is not None):
                raise ValueError(
                    "only an owned supervisor epoch can name its owner epoch"
                )
        elif self.phase == "OWNED" or self.owner_epoch is None:
            raise ValueError(
                "compatibility handoff scopes require an owner and cannot use OWNED"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "child": _identity_to_dict(self.child),
            "kind": self.kind,
            "owner_epoch": self.owner_epoch,
            "phase": self.phase,
            "record_version": self.record_version,
            "release_id": self.release_id,
            "schema_version": self.schema_version,
            "scope": self.scope.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "DetachedScopeRecord":
        fields = {
            "child",
            "kind",
            "owner_epoch",
            "phase",
            "record_version",
            "release_id",
            "schema_version",
            "scope",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ValueError("detached_scope: missing or unexpected fields")
        return cls(
            schema_version=value["schema_version"],
            record_version=value["record_version"],
            release_id=value["release_id"],
            kind=value["kind"],
            phase=value["phase"],
            owner_epoch=value["owner_epoch"],
            child=_identity_from_dict(value["child"]),
            scope=ScopeIdentity.from_dict(value["scope"]),
        )

    def with_phase(
        self,
        phase: str,
        *,
        scope: ScopeIdentity | None = None,
        owner_epoch: str | None = None,
    ) -> "DetachedScopeRecord":
        return replace(
            self,
            phase=phase,
            scope=self.scope if scope is None else scope,
            owner_epoch=owner_epoch,
        )


def same_detached_authority(
    left: DetachedScopeRecord,
    right: DetachedScopeRecord,
) -> bool:
    if (
        left.schema_version,
        left.record_version,
        left.release_id,
        left.kind,
        left.child,
    ) != (
        right.schema_version,
        right.record_version,
        right.release_id,
        right.kind,
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


class DetachedScopeStore:
    """Strict one-record-per-kind journal beneath the secure runtime."""

    def __init__(self, runtime_root: str | os.PathLike[str]) -> None:
        self.runtime = SecureRuntime(runtime_root)
        self.runtime.initialize()
        self.runtime.verify()
        recovery = self.runtime.root / "recovery"
        _create_secure_directory(recovery)
        self.directory = recovery / "detached-scopes"
        _create_secure_directory(self.directory)

    def path(self, kind: str) -> Path:
        if kind not in _KINDS:
            raise ValueError("detached scope kind is unsupported")
        return self.directory / f"{kind}.json"

    def load(self, kind: str) -> DetachedScopeRecord | None:
        value = _read_secure_json(self.path(kind))
        if value is None:
            return None
        try:
            record = DetachedScopeRecord.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeSecurityError(f"invalid detached scope record: {exc}") from exc
        if record.kind != kind:
            raise RuntimeSecurityError("detached scope filename and kind disagree")
        return record

    def put(self, record: DetachedScopeRecord) -> bool:
        if _atomic_create_json(self.path(record.kind), record.to_dict()):
            return True
        existing = self.load(record.kind)
        if existing == record:
            return False
        raise RuntimeSecurityError("detached scope record conflicts with its replay")

    def replace(
        self,
        expected: DetachedScopeRecord,
        updated: DetachedScopeRecord,
    ) -> None:
        existing = self.load(expected.kind)
        if (
            existing is None
            or not same_detached_authority(existing, expected)
            or existing.phase != expected.phase
            or existing.owner_epoch != expected.owner_epoch
            or not same_detached_authority(expected, updated)
        ):
            raise RuntimeSecurityError("detached scope authority changed before replace")
        allowed = {
            ("PREPARED", "SCOPE_CREATED"),
            ("SCOPE_CREATED", "ATTACHED"),
        }
        if expected.kind == "supervisor-epoch":
            allowed.add(("ATTACHED", "OWNED"))
        if (expected.phase, updated.phase) not in allowed:
            raise RuntimeSecurityError("detached scope phase transition is invalid")
        if expected.kind == "compatibility-handoff" and (
            updated.owner_epoch != expected.owner_epoch
        ):
            raise RuntimeSecurityError("handoff scope owner changed during transition")
        _atomic_replace_json(self.path(expected.kind), updated.to_dict())

    def delete(self, expected: DetachedScopeRecord) -> bool:
        existing = self.load(expected.kind)
        if existing is None:
            return False
        if (
            not same_detached_authority(existing, expected)
            or existing.phase != expected.phase
            or existing.owner_epoch != expected.owner_epoch
        ):
            raise RuntimeSecurityError("detached scope authority changed before delete")
        return _durable_unlink(self.path(expected.kind))

    def list_records(self) -> tuple[DetachedScopeRecord, ...]:
        records: list[DetachedScopeRecord] = []
        for entry in self.directory.iterdir():
            if entry.is_symlink() or not entry.name.endswith(".json"):
                raise RuntimeSecurityError(
                    f"unexpected detached scope journal entry: {entry}"
                )
            kind = entry.name.removesuffix(".json")
            record = self.load(kind)
            if record is None:
                raise RuntimeSecurityError(f"detached scope disappeared: {entry}")
            records.append(record)
        return tuple(sorted(records, key=lambda item: item.kind))


__all__ = [
    "DetachedScopeRecord",
    "DetachedScopeStore",
    "same_detached_authority",
]
