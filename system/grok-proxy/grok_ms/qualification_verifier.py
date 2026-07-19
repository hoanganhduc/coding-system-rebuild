#!/usr/bin/env python3
"""Immutable fail-closed release and rung qualification verifier.

The installed release gate, real direct provider, real curl qualification,
cgroup-v2 containment, public SOCKS frontend, and fixed privileged broker
status interface are exercised.  Only the Grok workload is deterministic so a
32-client resource gate does not create paid model traffic.

No helper in this module deletes privileged state.  Root/VPN evidence comes
only from the fixed root-owned broker's read-only ``status`` operation.  An
unavailable or unverifiable inventory is a blocked verification, never a pass.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import resource
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from typing import Any, Callable, Iterable, Mapping, Sequence

from .config import build_contract, classify
from .grok_exec import grok_release_id
from .ipc import SeqPacketConnection
from .managed_profile import (
    ManagedProfileError,
    load_managed_profile,
    open_profile_grok,
)
from .contract import (
    PROTOCOL_VERSION,
    SCHEMA_VERSION,
    RouteContract,
    qualification_route_profile_matches,
)
from .providers import ProviderRequest, ProviderResourceGraph
from .detached_scope import DetachedScopeRecord


ROOT = Path(__file__).resolve().parents[1]
FAKE_GROK = ROOT / "grok_ms/qualification_fake_grok.py"
FIXED_BROKER = Path("/usr/local/libexec/grok-proxy/vpn-broker")
FIXED_SUDO = Path("/usr/bin/sudo")
CGROUP_MOUNT = Path("/sys/fs/cgroup")
CGROUP_RESOURCE_VALUE_NAMES = (
    "cgroup.max.depth",
    "cgroup.max.descendants",
    "memory.current",
    "memory.peak",
    "memory.high",
    "memory.max",
    "memory.swap.high",
    "memory.swap.max",
    "memory.zswap.max",
    "memory.events",
    "pids.current",
    "pids.peak",
    "pids.max",
    "pids.events",
    "cpu.idle",
    "cpu.max",
    "cpu.max.burst",
    "cpu.uclamp.max",
    "cpu.uclamp.min",
    "cpu.weight",
    "cpu.stat",
)
PUBLIC_PORT = 1080
PRIVATE_PORTS = (11080, 11081)
EVIDENCE_SCHEMA_VERSION = 5
QUALIFICATION_KIND = "grok-multi-session-qualification"
PROVIDER_RECOVERY_RECORD_VERSION = 1
CHILD_RECOVERY_RECORD_VERSION = 2
PROBE_RECOVERY_RECORD_VERSION = 1
PROVIDER_SCOPE_RECORD_VERSION = 1
MAX_RUNTIME_RECORD = 1_048_576
MAX_RUNTIME_INVENTORY_ENTRIES = 4_096
PAYLOAD_BYTES = 65_536
CLEANUP_SUPERVISOR_EXIT_SECONDS = 5
CLEANUP_WRAPPER_TERM_SECONDS = 3
CLEANUP_WRAPPER_KILL_SECONDS = 3
CLEANUP_RECOVER_SECONDS = 30
CLEANUP_PROOF_SECONDS = 30
CLEANUP_ECHO_SECONDS = 2
QUALIFICATION_HARD_SECONDS = 900
QUALIFICATION_CLEANUP_RESERVE_SECONDS = 120
_BOOT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PROBE_ID = re.compile(r"^[0-9a-f]{32}$")
_SCOPE_NAME = re.compile(r"^grok-ms-[0-9a-f]{24}$")
_RUNNER_SCOPE_NAME = re.compile(r"^grok-installer-[0-9a-f]{24}$")
_TOKEN = re.compile(r"^[A-Za-z0-9._:+@-]{1,256}$")
_RUNG_TOKEN = re.compile(
    r"^(?:direct|vpn|home:[A-Za-z0-9._:+@-]{1,120}|ios:[a-z0-9][a-z0-9._-]{0,63})$"
)
_ROUTE_PROFILE_TOKEN = re.compile(
    r"^(?:direct|iphone|vpn|auto|auto-no-direct|home:[A-Za-z0-9._:+@-]{1,120}|ios:[a-z0-9][a-z0-9._-]{0,63})$"
)
_GROK_RELEASE_TOKEN = re.compile(r"^[A-Za-z0-9._:+@-]{1,128}$")
_MODEL_TOKEN = re.compile(r"^[A-Za-z0-9._:+/@-]{1,128}$")
_BLOCKED_DEFAULT = (
    "AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT "
    "RO SK SI ES SE CN IR KP TM VE"
)
_CANARY_ENV = (
    "GROK_RELEASE_CANARY_MODE",
    "GROK_RELEASE_CANARY_FD",
    "GROK_RELEASE_CANARY_RELEASE_ID",
    "GROK_RELEASE_RUNG_CANARY",
    "GROK_RELEASE_CANARY_RUNG",
    "GROK_RELEASE_CANARY_CONTRACT",
    "GROK_RELEASE_CANARY_GROK_RELEASE",
    "GROK_RELEASE_CANARY_NONCE",
    "GROK_RELEASE_CANARY_KIND",
    "GROK_RELEASE_CANARY_MODEL",
    "GROK_RELEASE_CANARY_ROUTE_PROFILE",
    "GROK_RELEASE_CANARY_PROFILE_SHA256",
    "GROK_QUALIFICATION_DEADLINE_MONOTONIC_NS",
    "GROK_QUALIFICATION_CLEANUP_DEADLINE_MONOTONIC_NS",
)

QUALIFICATION_FAILURE_CODES = {
    "load32": frozenset(
        {
            "load32-authorization",
            "load32-provenance",
            "load32-contract",
            "load32-baseline",
            "load32-spawn",
            "load32-ready",
            "load32-runtime-proof",
            "load32-overload",
            "load32-completion",
            "load32-resource",
            "load32-resource-cgroup-pids-peak",
            "load32-resource-cgroup-pids-highwater",
            "load32-resource-memory",
            "load32-resource-sampler",
            "load32-cleanup",
            "load32-internal",
        }
    ),
    "fault-recovery": frozenset(
        {
            "fault-recovery-authorization",
            "fault-recovery-provenance",
            "fault-recovery-contract",
            "fault-recovery-baseline",
            "fault-recovery-spawn",
            "fault-recovery-ready",
            "fault-recovery-runtime-proof",
            "fault-recovery-supervisor-loss",
            "fault-recovery-recovery",
            "fault-recovery-resource",
            "fault-recovery-resource-cgroup-pids-peak",
            "fault-recovery-resource-cgroup-pids-highwater",
            "fault-recovery-resource-memory",
            "fault-recovery-resource-sampler",
            "fault-recovery-cleanup",
            "fault-recovery-internal",
        }
    ),
    "real-pair": frozenset(
        {
            "real-pair-authorization",
            "real-pair-provenance",
            "real-pair-contract",
            "real-pair-baseline",
            "real-pair-spawn",
            "real-pair-ready",
            "real-pair-authority",
            "real-pair-pause",
            "real-pair-model-refresh",
            "real-pair-old-generation",
            "real-pair-provider-fault",
            "real-pair-repair",
            "real-pair-reconnect",
            "real-pair-resume",
            "real-pair-completion",
            "real-pair-runtime",
            "real-pair-cleanup",
            "real-pair-internal",
        }
    ),
}
QUALIFICATION_BLOCKED_CODES = {
    step: frozenset({f"{step}-blocked"}) for step in QUALIFICATION_FAILURE_CODES
}

_INVENTORY_TARGETS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("recovery_children", ("recovery", "children")),
    ("recovery_probes", ("recovery", "probes")),
    ("recovery_providers", ("recovery", "providers")),
    ("recovery_provider_scopes", ("recovery", "provider-scopes")),
    ("recovery_detached_scopes", ("recovery", "detached-scopes")),
    ("intents", ("intents",)),
    ("leaders", ("leaders",)),
    ("provider_workspaces", ("p",)),
    # A literal providers/ directory is not used by this release.  Inventory it
    # anyway so a skewed release cannot hide residue behind the human-facing
    # name used in review and acceptance documents.
    ("providers", ("providers",)),
    ("qualify", ("qualify",)),
)
_CONTROL_ENDPOINTS = ("supervisor.sock", "supervisor.ready", "recovery.fence")


class VerificationError(RuntimeError):
    """A required live assertion failed."""


class VerificationBlocked(VerificationError):
    """A required read-only evidence channel was unavailable."""


class QualificationStageError(VerificationError):
    """A failure whose public diagnostic is a closed, verifier-owned code."""

    def __init__(self, error_code: str, detail: str) -> None:
        if not any(
            error_code in codes for codes in QUALIFICATION_FAILURE_CODES.values()
        ):
            raise ValueError("qualification failure code is not closed")
        super().__init__(detail)
        self.error_code = error_code


class QualificationStage:
    """Track a closed failure checkpoint without exposing dynamic detail."""

    def __init__(self, mode: str) -> None:
        if mode not in QUALIFICATION_FAILURE_CODES:
            raise ValueError("qualification mode has no failure codebook")
        self.mode = mode
        self.error_code = f"{mode}-authorization"

    def set(self, error_code: str) -> None:
        if error_code not in QUALIFICATION_FAILURE_CODES[self.mode]:
            raise ValueError("qualification stage is not in the mode codebook")
        self.error_code = error_code


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def account_control() -> Path:
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local/state/grok-proxy/control"


def _read_bounded(path: Path, maximum: int = MAX_RUNTIME_RECORD) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise VerificationError(f"not a regular evidence record: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise VerificationError(f"oversized evidence record: {path}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise VerificationError(f"evidence record identity changed: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_ascii(path: Path, maximum: int = MAX_RUNTIME_RECORD) -> str:
    try:
        return _read_bounded(path, maximum).decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"non-ASCII evidence record: {path}") from exc


def _read_json(path: Path, maximum: int = MAX_RUNTIME_RECORD) -> dict[str, Any]:
    try:
        value = json.loads(_read_bounded(path, maximum))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid JSON evidence record: {path}") from exc
    if type(value) is not dict:
        raise VerificationError(f"JSON evidence is not an object: {path}")
    return value


def _sha256_file(path: Path, maximum: int = 512 * 1024 * 1024) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    total = 0
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise VerificationError(f"digest target is not a regular file: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise VerificationError(f"digest target exceeds verifier bound: {path}")
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _json_digest(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    pid_start_ticks: int
    boot_id: str

    def __post_init__(self) -> None:
        if type(self.pid) is not int or not 1 <= self.pid <= 2**31 - 1:
            raise VerificationError("process identity has an invalid PID")
        if (
            type(self.pid_start_ticks) is not int
            or not 1 <= self.pid_start_ticks <= 2**63 - 1
        ):
            raise VerificationError("process identity has invalid start ticks")
        if type(self.boot_id) is not str or _BOOT_ID.fullmatch(self.boot_id) is None:
            raise VerificationError("process identity has an invalid boot ID")

    @classmethod
    def from_mapping(cls, value: Any, label: str) -> "ProcessIdentity":
        if type(value) is not dict or set(value) != {
            "pid",
            "pid_start_ticks",
            "boot_id",
        }:
            raise VerificationError(f"{label} has a non-exact process identity schema")
        return cls(value["pid"], value["pid_start_ticks"], value["boot_id"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "boot_id": self.boot_id,
            "pid": self.pid,
            "pid_start_ticks": self.pid_start_ticks,
        }


@dataclass(frozen=True, slots=True)
class CleanupAuthority:
    """The exact supervisor epoch this verifier is allowed to reconcile."""

    release_id: str
    owner_epoch: str
    supervisor: ProcessIdentity

    def __post_init__(self) -> None:
        if _DIGEST.fullmatch(self.release_id) is None:
            raise VerificationError("cleanup authority has an invalid release ID")
        if _TOKEN.fullmatch(self.owner_epoch) is None:
            raise VerificationError("cleanup authority has an invalid owner epoch")

    def to_dict(self) -> dict[str, Any]:
        return {
            "release_id": self.release_id,
            "owner_epoch": self.owner_epoch,
            "supervisor": self.supervisor.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ExclusiveCleanupAuthority:
    """A READY epoch proved to contain only this verifier's live children."""

    epoch: CleanupAuthority
    generation: int
    contract_digest: str
    children: tuple[ProcessIdentity, ...]
    leader_policy: str = "exact-sockets"

    def __post_init__(self) -> None:
        if type(self.generation) is not int or self.generation < 1:
            raise VerificationError("exclusive cleanup authority has an invalid generation")
        if _DIGEST.fullmatch(self.contract_digest) is None:
            raise VerificationError("exclusive cleanup authority has an invalid contract digest")
        if not self.children or len(self.children) != len(set(self.children)):
            raise VerificationError(
                "exclusive cleanup authority requires unique verifier children"
            )
        if self.leader_policy not in {"exact-sockets", "disabled-empty"}:
            raise VerificationError(
                "exclusive cleanup authority has an invalid leader policy"
            )


def read_boot_id(proc_root: Path = Path("/proc")) -> str:
    value = _read_ascii(proc_root / "sys/kernel/random/boot_id", 128).strip()
    if _BOOT_ID.fullmatch(value) is None:
        raise VerificationError("Linux boot identity has an invalid shape")
    return value


def process_start_ticks(pid: int, proc_root: Path = Path("/proc")) -> int:
    record = _read_ascii(proc_root / str(pid) / "stat", 16_384)
    fields = record[record.rfind(")") + 2 :].split()
    if len(fields) <= 19 or not fields[19].isdecimal():
        raise VerificationError(f"cannot parse start identity for PID {pid}")
    return int(fields[19])


def current_process_identity(
    pid: int, proc_root: Path = Path("/proc")
) -> ProcessIdentity:
    return ProcessIdentity(pid, process_start_ticks(pid, proc_root), read_boot_id(proc_root))


def process_matches(identity: ProcessIdentity, proc_root: Path = Path("/proc")) -> bool:
    try:
        return (
            read_boot_id(proc_root) == identity.boot_id
            and process_start_ticks(identity.pid, proc_root) == identity.pid_start_ticks
        )
    except (FileNotFoundError, ProcessLookupError, OSError, VerificationError):
        return False


def open_exact_pidfd(identity: ProcessIdentity) -> int:
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise VerificationBlocked("pidfd signalling is required for exact live fault control")
    try:
        descriptor = os.pidfd_open(identity.pid, 0)
    except OSError as exc:
        raise VerificationError(f"cannot open exact pidfd for PID {identity.pid}") from exc
    if not process_matches(identity):
        os.close(descriptor)
        raise VerificationError(f"PID identity changed while opening pidfd: {identity.pid}")
    return descriptor


def exact_signal(identity: ProcessIdentity, signum: int, pidfd: int | None = None) -> None:
    owned = pidfd is None
    descriptor = open_exact_pidfd(identity) if owned else pidfd
    assert descriptor is not None
    try:
        signal.pidfd_send_signal(descriptor, signum)
    except ProcessLookupError:
        if process_matches(identity):
            raise VerificationError(f"exact process {identity.pid} could not be signalled")
    finally:
        if owned:
            os.close(descriptor)


def wait_exact_pidfd_exit(
    identity: ProcessIdentity,
    pidfd: int,
    timeout: float,
) -> None:
    """Wait for one retained exact process identity to reach kernel exit."""

    if type(pidfd) is not int or pidfd < 0:
        raise VerificationError("exact process exit requires a valid pidfd")
    if type(timeout) not in (int, float) or isinstance(timeout, bool):
        raise VerificationError("exact process exit timeout is invalid")
    seconds = float(timeout)
    if not math.isfinite(seconds) or seconds < 0:
        raise VerificationError("exact process exit timeout is invalid")
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(pidfd, selectors.EVENT_READ)
            ready = selector.select(seconds)
    except OSError as exc:
        raise VerificationError(
            f"cannot wait for exact process exit: {identity.pid}"
        ) from exc
    if not ready:
        raise VerificationError(
            f"exact process did not exit before deadline: {identity.pid}"
        )


def close_pidfd_anchors(anchors: list[tuple[ProcessIdentity, int]]) -> None:
    errors: list[str] = []
    while anchors:
        identity, pidfd = anchors.pop()
        try:
            os.close(pidfd)
        except OSError as exc:
            errors.append(f"{identity.pid}: {exc}")
    if errors:
        raise VerificationError("cannot close exact process pidfds: " + "; ".join(errors))


def process_metrics(identity: ProcessIdentity, proc_root: Path = Path("/proc")) -> dict[str, Any]:
    anchor = open_exact_pidfd(identity) if proc_root == Path("/proc") else -1
    try:
        if not process_matches(identity, proc_root):
            raise VerificationError(f"recorded process is not exact-live: {identity.pid}")
        fields: dict[str, str] = {}
        for line in _read_ascii(
            proc_root / str(identity.pid) / "status", 1_048_576
        ).splitlines():
            if ":" in line:
                name, value = line.split(":", 1)
                fields[name] = value.strip()
        descriptor_dir = proc_root / str(identity.pid) / "fd"
        try:
            fd_count = len(tuple(descriptor_dir.iterdir()))
        except OSError as exc:
            raise VerificationError(
                f"cannot inventory descriptors for PID {identity.pid}"
            ) from exc
        result = {
            "identity": identity.to_dict(),
            "fd_count": fd_count,
            "threads": int(fields["Threads"]),
            "vmrss_kib": int(fields.get("VmRSS", "0 kB").split()[0]),
            "vmsize_kib": int(fields.get("VmSize", "0 kB").split()[0]),
            "cgroup": _read_ascii(
                proc_root / str(identity.pid) / "cgroup", 16_384
            ).strip(),
        }
        if not process_matches(identity, proc_root):
            raise VerificationError(
                f"process identity changed during metrics inventory: {identity.pid}"
            )
        if anchor >= 0:
            try:
                signal.pidfd_send_signal(anchor, 0)
            except ProcessLookupError as exc:
                raise VerificationError(
                    f"process exited during metrics inventory: {identity.pid}"
                ) from exc
        return result
    finally:
        if anchor >= 0:
            os.close(anchor)


def aggregate_process_metrics(
    identities: Iterable[ProcessIdentity], proc_root: Path = Path("/proc")
) -> dict[str, Any]:
    unique = sorted(set(identities), key=lambda item: item.pid)
    records = [process_metrics(item, proc_root) for item in unique]
    return {
        "processes": records,
        "process_count": len(records),
        "fd_count": sum(item["fd_count"] for item in records),
        "threads": sum(item["threads"] for item in records),
        "vmrss_kib": sum(item["vmrss_kib"] for item in records),
        "vmsize_kib": sum(item["vmsize_kib"] for item in records),
    }


def _aggregate_process_record(
    aggregate: Mapping[str, Any], identity: ProcessIdentity
) -> dict[str, Any]:
    """Return one previously captured exact process record without re-reading /proc."""

    records = aggregate.get("processes")
    target = identity.to_dict()
    matches = (
        [
            record
            for record in records
            if type(record) is dict and record.get("identity") == target
        ]
        if type(records) is list
        else []
    )
    if len(matches) != 1:
        raise VerificationError(
            "exact process aggregate lacks one matching identity record"
        )
    return dict(matches[0])


def ready_identity(control: Path) -> ProcessIdentity:
    value = _read_json(control / "supervisor.ready")
    return ProcessIdentity.from_mapping(
        {name: value.get(name) for name in ("pid", "pid_start_ticks", "boot_id")},
        "supervisor.ready",
    )


def capture_cleanup_authority(
    control: Path,
    snapshot: Mapping[str, Any],
    provenance: Mapping[str, Any],
    *,
    provider_canary_nonce: str | None = None,
) -> CleanupAuthority:
    """Bind cleanup to the READY epoch observed by this verification run."""

    ready = _read_json(control / "supervisor.ready")
    expected_ready_fields = {
        "schema_version",
        "protocol_version",
        "release_id",
        "owner_epoch",
        "pid",
        "pid_start_ticks",
        "boot_id",
        "socket",
    }
    if provider_canary_nonce is not None:
        expected_ready_fields.add("provider_canary_nonce")
    if set(ready) != expected_ready_fields:
        raise VerificationError("supervisor.ready has a non-exact authority schema")
    release_id = snapshot.get("release_id")
    owner_epoch = snapshot.get("owner_epoch")
    if (
        type(release_id) is not str
        or type(owner_epoch) is not str
        or ready.get("schema_version") != 1
        or ready.get("protocol_version") != PROTOCOL_VERSION
        or snapshot.get("phase") != "READY"
        or release_id != provenance.get("release_id")
        or ready.get("release_id") != release_id
        or ready.get("owner_epoch") != owner_epoch
        or ready.get("socket") != str(control / "supervisor.sock")
        or (
            provider_canary_nonce is not None
            and (
                _DIGEST.fullmatch(provider_canary_nonce) is None
                or ready.get("provider_canary_nonce")
                != provider_canary_nonce
            )
        )
    ):
        raise VerificationError("READY status, provenance, and supervisor identity disagree")
    authority = CleanupAuthority(
        release_id,
        owner_epoch,
        ProcessIdentity.from_mapping(
            {name: ready[name] for name in ("pid", "pid_start_ticks", "boot_id")},
            "supervisor.ready",
        ),
    )
    if not process_matches(authority.supervisor):
        raise VerificationError("captured cleanup supervisor is not exact-live")
    if not _assert_cleanup_fence_owner(cleanup_fence(control), authority):
        raise VerificationError("captured READY epoch has no durable recovery fence")
    return authority


def cleanup_fence(control: Path) -> tuple[CleanupAuthority, str] | None:
    path = control / "recovery.fence"
    try:
        value = _read_json(path)
    except FileNotFoundError:
        return None
    expected = {
        "schema_version",
        "release_id",
        "owner_epoch",
        "pid",
        "pid_start_ticks",
        "boot_id",
        "phase",
    }
    if (
        set(value) != expected
        or value.get("schema_version") != 1
        or value.get("phase") not in {
            "BOOTSTRAPPING",
            "RECOVERING",
            "READY",
            "DRAINING",
        }
    ):
        raise VerificationError("recovery fence has a non-exact cleanup schema")
    return (
        CleanupAuthority(
            value["release_id"],
            value["owner_epoch"],
            ProcessIdentity.from_mapping(
                {name: value[name] for name in ("pid", "pid_start_ticks", "boot_id")},
                "recovery fence",
            ),
        ),
        value["phase"],
    )


def _assert_cleanup_fence_owner(
    current: tuple[CleanupAuthority, str] | None,
    expected: CleanupAuthority,
) -> bool:
    if current is None:
        return False
    actual, _phase = current
    if actual != expected:
        raise VerificationError(
            "cleanup refused because the recovery fence belongs to a replacement epoch"
        )
    return True


def recovery_environment(
    env: Mapping[str, str], authority: CleanupAuthority | None
) -> dict[str, str]:
    selected = dict(env)
    for name in (
        "GROK_RECOVERY_EXPECT_RELEASE_ID",
        "GROK_RECOVERY_EXPECT_OWNER_EPOCH",
        "GROK_RECOVERY_EXPECT_PID",
        "GROK_RECOVERY_EXPECT_PID_START_TICKS",
        "GROK_RECOVERY_EXPECT_BOOT_ID",
        "GROK_RECOVERY_EXPECT_ABSENT",
        "GROK_QUALIFICATION_DIRECT_RECOVERY",
    ):
        selected.pop(name, None)
    # Only fixed release qualification is authorized to bypass compatibility
    # handoff during recovery.  Keeping this marker off the base environment is
    # essential: status/control calls share that environment and must not be
    # misclassified as strict recovery requests.
    if (
        selected.get("GROK_RELEASE_CANARY_KIND") == "release"
        and selected.get("GROK_RELEASE_CANARY_RUNG") == "direct"
        and selected.get("GROK_RELEASE_CANARY_ROUTE_PROFILE") == "direct"
    ):
        selected["GROK_QUALIFICATION_DIRECT_RECOVERY"] = "1"
    if authority is None:
        selected["GROK_RECOVERY_EXPECT_ABSENT"] = "1"
    else:
        selected.update(
            {
                "GROK_RECOVERY_EXPECT_RELEASE_ID": authority.release_id,
                "GROK_RECOVERY_EXPECT_OWNER_EPOCH": authority.owner_epoch,
                "GROK_RECOVERY_EXPECT_PID": str(authority.supervisor.pid),
                "GROK_RECOVERY_EXPECT_PID_START_TICKS": str(
                    authority.supervisor.pid_start_ticks
                ),
                "GROK_RECOVERY_EXPECT_BOOT_ID": authority.supervisor.boot_id,
            }
        )
    return selected


def _entry_kind(info: os.stat_result) -> str:
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISREG(info.st_mode):
        return "regular"
    if stat.S_ISSOCK(info.st_mode):
        return "socket"
    raise VerificationError("runtime inventory contains an unsupported object type")


def _check_deadline(
    deadline_monotonic_ns: int | None,
    label: str,
) -> None:
    if (
        deadline_monotonic_ns is not None
        and time.monotonic_ns() >= deadline_monotonic_ns
    ):
        raise VerificationError(f"qualification deadline expired during {label}")


def _inventory_tree(
    path: Path,
    *,
    deadline_monotonic_ns: int | None = None,
    remaining_entries: list[int] | None = None,
) -> dict[str, Any]:
    _check_deadline(deadline_monotonic_ns, "runtime inventory")
    try:
        root_info = path.lstat()
    except FileNotFoundError:
        return {"exists": False, "entries": []}
    if path.is_symlink() or not stat.S_ISDIR(root_info.st_mode):
        raise VerificationError(f"inventory root is not a real directory: {path}")
    if root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o700:
        raise VerificationError(f"inventory root has unsafe owner/mode: {path}")
    records: list[dict[str, Any]] = []
    entry_budget = (
        remaining_entries
        if remaining_entries is not None
        else [MAX_RUNTIME_INVENTORY_ENTRIES]
    )

    def bounded_children(current: Path) -> list[Path]:
        _check_deadline(deadline_monotonic_ns, "runtime inventory")
        children: list[Path] = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    _check_deadline(
                        deadline_monotonic_ns, "runtime inventory"
                    )
                    if entry_budget[0] <= 0:
                        raise VerificationError(
                            "runtime inventory exceeds its entry bound"
                        )
                    entry_budget[0] -= 1
                    children.append(Path(entry.path))
        except OSError as exc:
            raise VerificationError(f"cannot enumerate runtime inventory: {current}") from exc
        children.sort(key=lambda item: item.name)
        return children

    pending = [
        (child, Path(child.name))
        for child in reversed(bounded_children(path))
    ]
    while pending:
        child, relative = pending.pop()
        _check_deadline(deadline_monotonic_ns, "runtime inventory")
        info = child.lstat()
        if child.is_symlink() or info.st_uid != os.getuid():
            raise VerificationError(f"unsafe runtime inventory entry: {child}")
        kind = _entry_kind(info)
        record: dict[str, Any] = {
            "path": str(relative),
            "kind": kind,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "device": info.st_dev,
            "inode": info.st_ino,
            "size": info.st_size,
        }
        if kind == "regular":
            record["sha256"] = hashlib.sha256(_read_bounded(child)).hexdigest()
        records.append(record)
        if kind == "directory":
            pending.extend(
                (descendant, relative / descendant.name)
                for descendant in reversed(bounded_children(child))
            )
    return {
        "exists": True,
        "mode": stat.S_IMODE(root_info.st_mode),
        "uid": root_info.st_uid,
        "gid": root_info.st_gid,
        "device": root_info.st_dev,
        "inode": root_info.st_ino,
        "entries": records,
    }


def user_inventory(
    control: Path,
    *,
    deadline_monotonic_ns: int | None = None,
) -> dict[str, Any]:
    endpoints: dict[str, Any] = {}
    for name in _CONTROL_ENDPOINTS:
        _check_deadline(deadline_monotonic_ns, "user inventory")
        path = control / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            endpoints[name] = {"exists": False}
            continue
        if path.is_symlink() or info.st_uid != os.getuid():
            raise VerificationError(f"unsafe control endpoint: {path}")
        kind = _entry_kind(info)
        expected_kind = "socket" if name == "supervisor.sock" else "regular"
        if kind != expected_kind or stat.S_IMODE(info.st_mode) != 0o600:
            raise VerificationError(f"control endpoint has an unsafe type/mode: {path}")
        endpoints[name] = {
            "exists": True,
            "kind": kind,
            "mode": stat.S_IMODE(info.st_mode),
            "device": info.st_dev,
            "inode": info.st_ino,
        }
    remaining_entries = [MAX_RUNTIME_INVENTORY_ENTRIES]
    targets: dict[str, Any] = {}
    for label, parts in _INVENTORY_TARGETS:
        targets[label] = _inventory_tree(
            control.joinpath(*parts),
            deadline_monotonic_ns=deadline_monotonic_ns,
            remaining_entries=remaining_entries,
        )
    return {
        "captured_at": utc_timestamp(),
        "control": str(control),
        "endpoints": endpoints,
        "targets": targets,
    }


def assert_user_inventory_clean(inventory: Mapping[str, Any]) -> None:
    residue: list[str] = []
    endpoints = inventory.get("endpoints")
    targets = inventory.get("targets")
    if type(endpoints) is not dict or type(targets) is not dict:
        raise VerificationError("user inventory has an invalid schema")
    for name in _CONTROL_ENDPOINTS:
        value = endpoints.get(name)
        if type(value) is not dict or type(value.get("exists")) is not bool:
            raise VerificationError(f"user inventory omitted endpoint {name}")
        if value["exists"]:
            residue.append(name)
    for label, _parts in _INVENTORY_TARGETS:
        value = targets.get(label)
        if type(value) is not dict or type(value.get("entries")) is not list:
            raise VerificationError(f"user inventory omitted target {label}")
        if value["entries"]:
            residue.append(label)
    if residue:
        raise VerificationError(f"user cleanup residue remains: {', '.join(residue)}")


def _record_files(
    directory: Path,
    *,
    deadline_monotonic_ns: int | None = None,
) -> tuple[Path, ...]:
    _check_deadline(deadline_monotonic_ns, "recovery record inventory")
    if not directory.exists():
        return ()
    result: list[Path] = []
    try:
        with os.scandir(directory) as entries:
            paths: list[Path] = []
            for entry in entries:
                _check_deadline(
                    deadline_monotonic_ns, "recovery record inventory"
                )
                if len(paths) >= MAX_RUNTIME_INVENTORY_ENTRIES:
                    raise VerificationError(
                        "recovery record inventory exceeds its entry bound"
                    )
                paths.append(Path(entry.path))
    except OSError as exc:
        raise VerificationError(
            f"cannot enumerate recovery records: {directory}"
        ) from exc
    for path in sorted(paths, key=lambda item: item.name):
        _check_deadline(deadline_monotonic_ns, "recovery record inventory")
        info = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or not path.name.endswith(".json")
        ):
            raise VerificationError(f"unexpected recovery record entry: {path}")
        result.append(path)
    return tuple(result)


def _scope_evidence(
    value: Any,
    child: ProcessIdentity,
    *,
    proc_root: Path = Path("/proc"),
    cgroup_mount: Path = CGROUP_MOUNT,
) -> dict[str, Any]:
    fields = {
        "backend",
        "parent_path",
        "parent_device",
        "parent_inode",
        "scope_path",
        "scope_device",
        "scope_inode",
    }
    if type(value) is not dict or set(value) != fields:
        raise VerificationError("cgroup scope record has a non-exact schema")
    parent = Path(value["parent_path"])
    scope = Path(value["scope_path"])
    if (
        value["backend"] != "cgroup-v2-v1"
        or not parent.is_absolute()
        or not scope.is_absolute()
        or scope.parent != parent
        or _SCOPE_NAME.fullmatch(scope.name) is None
    ):
        raise VerificationError("cgroup scope record has unsafe paths or backend")
    try:
        relative = scope.relative_to(cgroup_mount)
    except ValueError as exc:
        raise VerificationError("cgroup scope is outside the fixed cgroup-v2 mount") from exc
    parent_info = parent.lstat()
    scope_info = scope.lstat()
    if (
        parent.is_symlink()
        or scope.is_symlink()
        or not stat.S_ISDIR(parent_info.st_mode)
        or not stat.S_ISDIR(scope_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or scope_info.st_uid != os.getuid()
    ):
        raise VerificationError("cgroup scope identity has an unsafe type or owner")
    if (parent_info.st_dev, parent_info.st_ino) != (
        value["parent_device"],
        value["parent_inode"],
    ):
        raise VerificationError("cgroup parent identity changed")
    if (scope_info.st_dev, scope_info.st_ino) != (
        value["scope_device"],
        value["scope_inode"],
    ):
        raise VerificationError("cgroup child identity changed")
    membership = _read_ascii(proc_root / str(child.pid) / "cgroup", 16_384).strip()
    if membership != f"0::/{relative}":
        raise VerificationError("recorded child escaped its exact cgroup scope")
    events: dict[str, str] = {}
    for line in _read_ascii(scope / "cgroup.events", 4_096).splitlines():
        pieces = line.split(" ", 1)
        if len(pieces) != 2 or pieces[0] in events:
            raise VerificationError("malformed cgroup.events evidence")
        events[pieces[0]] = pieces[1]
    if events.get("populated") != "1":
        raise VerificationError("live child cgroup is not populated")
    return {
        "backend": value["backend"],
        "parent_path": str(parent),
        "parent_device": parent_info.st_dev,
        "parent_inode": parent_info.st_ino,
        "scope_path": str(scope),
        "scope_device": scope_info.st_dev,
        "scope_inode": scope_info.st_ino,
        "populated": True,
        "membership": membership,
    }


def _retained_scope_evidence(
    value: Any,
    *,
    cgroup_mount: Path = CGROUP_MOUNT,
) -> dict[str, Any]:
    """Verify a retained provider cgroup after its direct shell has exited."""

    fields = {
        "backend",
        "parent_path",
        "parent_device",
        "parent_inode",
        "scope_path",
        "scope_device",
        "scope_inode",
    }
    if type(value) is not dict or set(value) != fields:
        raise VerificationError("provider cgroup scope has a non-exact schema")
    parent = Path(value["parent_path"])
    scope = Path(value["scope_path"])
    if (
        value["backend"] != "cgroup-v2-v1"
        or not parent.is_absolute()
        or not scope.is_absolute()
        or scope.parent != parent
        or _SCOPE_NAME.fullmatch(scope.name) is None
    ):
        raise VerificationError("provider cgroup scope has unsafe paths or backend")
    try:
        scope.relative_to(cgroup_mount)
    except ValueError as exc:
        raise VerificationError(
            "provider cgroup scope is outside the fixed cgroup-v2 mount"
        ) from exc
    parent_info = parent.lstat()
    scope_info = scope.lstat()
    if (
        parent.is_symlink()
        or scope.is_symlink()
        or not stat.S_ISDIR(parent_info.st_mode)
        or not stat.S_ISDIR(scope_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or scope_info.st_uid != os.getuid()
        or (parent_info.st_dev, parent_info.st_ino)
        != (value["parent_device"], value["parent_inode"])
        or (scope_info.st_dev, scope_info.st_ino)
        != (value["scope_device"], value["scope_inode"])
    ):
        raise VerificationError("provider cgroup scope identity changed")
    events: dict[str, str] = {}
    for line in _read_ascii(scope / "cgroup.events", 4_096).splitlines():
        pieces = line.split(" ", 1)
        if len(pieces) != 2 or pieces[0] in events:
            raise VerificationError("malformed provider cgroup.events evidence")
        events[pieces[0]] = pieces[1]
    if events.get("populated") not in {"0", "1"}:
        raise VerificationError("provider cgroup has no valid populated state")
    process_text = _read_ascii(scope / "cgroup.procs", 65_536).strip()
    processes: list[int] = []
    if process_text:
        for line in process_text.splitlines():
            if not line.isdecimal() or int(line) < 1:
                raise VerificationError("malformed provider cgroup.procs evidence")
            processes.append(int(line))
    if len(processes) != len(set(processes)) or (
        events["populated"] == "1"
    ) is not bool(processes):
        raise VerificationError("provider cgroup population evidence is inconsistent")
    return {
        "backend": value["backend"],
        "parent_path": str(parent),
        "parent_device": parent_info.st_dev,
        "parent_inode": parent_info.st_ino,
        "scope_path": str(scope),
        "scope_device": scope_info.st_dev,
        "scope_inode": scope_info.st_ino,
        "populated": events["populated"] == "1",
        "processes": sorted(processes),
    }


def _provider_scope_tag(request: ProviderRequest) -> str:
    material = b"\0".join(
        (
            request.owner_epoch.encode("ascii"),
            str(request.generation).encode("ascii"),
            str(request.private_endpoint.port).encode("ascii"),
        )
    )
    return hashlib.sha256(material).hexdigest()[:24]


def _provider_authority_graph(
    record: Mapping[str, Any],
    *,
    expected_rung: str,
) -> tuple[ProviderRequest, ProviderResourceGraph]:
    """Decode and bind one route-specific provider recovery authority."""

    try:
        request = ProviderRequest.from_dict(record.get("request"))
        graph = ProviderResourceGraph.from_dict(record.get("resources"))
    except (TypeError, ValueError) as exc:
        raise VerificationError(
            "provider recovery record lacks a valid route resource graph"
        ) from exc
    if (
        graph.owner_epoch != record.get("owner_epoch")
        or graph.owner_epoch != request.owner_epoch
        or graph.generation != request.generation
        or graph.transition_id != request.transition_id
        or graph.rung != request.rung
        or graph.rung != expected_rung
        or graph.listeners[0].endpoint != request.private_endpoint
    ):
        raise VerificationError(
            "provider resource graph differs from its frozen route request"
        )
    return request, graph


def recovery_authorities(
    control: Path,
    *,
    expected_rung: str,
    deadline_monotonic_ns: int | None = None,
) -> dict[str, Any]:
    children: list[dict[str, Any]] = []
    probes: list[dict[str, Any]] = []
    providers: list[dict[str, Any]] = []
    identities: list[ProcessIdentity] = []
    provider_identities: list[ProcessIdentity] = []
    provider_listeners: list[dict[str, Any]] = []
    provider_requests: list[ProviderRequest] = []
    provider_scope_requests: list[ProviderRequest] = []
    provider_scopes: list[dict[str, Any]] = []
    detached_scopes: list[dict[str, Any]] = []

    for path in _record_files(
        control / "recovery/detached-scopes",
        deadline_monotonic_ns=deadline_monotonic_ns,
    ):
        _check_deadline(
            deadline_monotonic_ns, "detached scope recovery authority"
        )
        value = _read_json(path)
        try:
            record = DetachedScopeRecord.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise VerificationError(
                "detached scope recovery authority is invalid"
            ) from exc
        if (
            path.name != f"{record.kind}.json"
            or record.kind != "supervisor-epoch"
            or record.phase != "OWNED"
            or record.owner_epoch is None
        ):
            raise VerificationError(
                "READY state has a handoff or unowned detached scope"
            )
        child = ProcessIdentity(
            record.child.pid,
            record.child.start_ticks,
            record.child.boot_id,
        )
        detached_scopes.append(
            {
                "record_sha256": _sha256_file(path),
                "release_id": record.release_id,
                "owner_epoch": record.owner_epoch,
                "kind": record.kind,
                "phase": record.phase,
                "process": process_metrics(child),
                "scope": _scope_evidence(record.scope.to_dict(), child),
            }
        )

    for path in _record_files(
        control / "recovery/children",
        deadline_monotonic_ns=deadline_monotonic_ns,
    ):
        _check_deadline(deadline_monotonic_ns, "child recovery authority")
        value = _read_json(path)
        lease_id = value.get("lease_id")
        if set(value) != {
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
        } or (
            value.get("kind") != "child-recovery"
            or value.get("phase") != "ATTACHED"
            or value.get("schema_version") != SCHEMA_VERSION
            or value.get("record_version") != CHILD_RECOVERY_RECORD_VERSION
            or type(lease_id) is not str
            or _TOKEN.fullmatch(lease_id) is None
            or path.name != f"{lease_id}.json"
        ):
            raise VerificationError(f"child record is not exactly attached: {path}")
        identity = ProcessIdentity.from_mapping(value.get("child"), "child recovery")
        scope = _scope_evidence(value.get("scope"), identity)
        leader_path = Path(value["leader_path"])
        if not leader_path.is_absolute() or leader_path.parent != control / "leaders":
            raise VerificationError("child recovery leader path escapes the fixed leader root")
        identities.append(identity)
        children.append(
            {
                "record_sha256": _sha256_file(path),
                "release_id": value.get("release_id"),
                "owner_epoch": value.get("owner_epoch"),
                "lease_id": value.get("lease_id"),
                "leader_path": value.get("leader_path"),
                "process": process_metrics(identity),
                "scope": scope,
            }
        )

    for path in _record_files(
        control / "recovery/probes",
        deadline_monotonic_ns=deadline_monotonic_ns,
    ):
        _check_deadline(deadline_monotonic_ns, "probe recovery authority")
        value = _read_json(path)
        probe_id = value.get("probe_id")
        if set(value) != {
            "child",
            "kind",
            "owner_epoch",
            "phase",
            "probe_id",
            "record_version",
            "release_id",
            "schema_version",
            "scope",
        } or (
            value.get("kind") != "probe-recovery"
            or value.get("phase") != "ATTACHED"
            or value.get("schema_version") != SCHEMA_VERSION
            or value.get("record_version") != PROBE_RECOVERY_RECORD_VERSION
            or type(probe_id) is not str
            or _PROBE_ID.fullmatch(probe_id) is None
            or path.name != f"{probe_id}.json"
        ):
            raise VerificationError(f"probe record is not exactly attached: {path}")
        identity = ProcessIdentity.from_mapping(value.get("child"), "probe recovery")
        identities.append(identity)
        probes.append(
            {
                "record_sha256": _sha256_file(path),
                "release_id": value.get("release_id"),
                "owner_epoch": value.get("owner_epoch"),
                "probe_id": value.get("probe_id"),
                "process": process_metrics(identity),
                "scope": _scope_evidence(value.get("scope"), identity),
            }
        )

    for path in _record_files(
        control / "recovery/providers",
        deadline_monotonic_ns=deadline_monotonic_ns,
    ):
        _check_deadline(deadline_monotonic_ns, "provider recovery authority")
        value = _read_json(path)
        effect_id = value.get("effect_id")
        if set(value) != {
            "effect_id",
            "kind",
            "owner_epoch",
            "phase",
            "record_version",
            "release_id",
            "request",
            "resources",
            "schema_version",
        } or (
            value.get("kind") != "provider-recovery"
            or value.get("phase") != "APPLIED"
            or value.get("schema_version") != SCHEMA_VERSION
            or value.get("record_version") != PROVIDER_RECOVERY_RECORD_VERSION
            or type(effect_id) is not str
            or _TOKEN.fullmatch(effect_id) is None
            or path.name != f"{effect_id}.json"
        ):
            raise VerificationError(f"provider record is not exactly applied: {path}")
        request, graph = _provider_authority_graph(
            value,
            expected_rung=expected_rung,
        )
        if value.get("release_id") != request.contract.release_id:
            raise VerificationError(
                "provider recovery record release differs from its frozen request"
            )
        provider_requests.append(request)
        resources = graph.to_dict()
        runtime_dir = Path(graph.runtime_dir)
        try:
            runtime_dir.relative_to(control / "p")
        except (TypeError, ValueError) as exc:
            raise VerificationError("provider runtime escapes the fixed provider root") from exc
        raw_processes = resources.get("processes")
        raw_listeners = resources.get("listeners")
        if (
            type(raw_processes) is not list
            or type(raw_listeners) is not list
            or len(raw_listeners) != 1
            or type(raw_listeners[0]) is not dict
        ):
            raise VerificationError(
                "provider resource graph omitted canonical process identities"
            )
        processes = [
            ProcessIdentity.from_mapping(item, "provider recovery process")
            for item in raw_processes
        ]
        if not processes or len(processes) != len(set(processes)):
            raise VerificationError("provider process authority is empty or duplicated")
        identities.extend(processes)
        provider_identities.extend(processes)
        listener = graph.listeners[0]
        listener_owner = ProcessIdentity.from_mapping(
            raw_listeners[0].get("owner"), "provider recovery listener owner"
        )
        if listener_owner not in processes:
            raise VerificationError(
                "provider listener owner differs from normalized process authority"
            )
        provider_listeners.append(
            {
                "host": listener.endpoint.host,
                "port": listener.endpoint.port,
                "socket_inode": listener.socket_inode,
                "owner": listener_owner.to_dict(),
            }
        )
        path_evidence: list[dict[str, Any]] = []
        if type(resources["paths"]) is not list:
            raise VerificationError("provider path graph is not a list")
        for path_record in resources["paths"]:
            if type(path_record) is not dict or set(path_record) != {
                "device",
                "inode",
                "kind",
                "mode",
                "path",
                "uid",
            }:
                raise VerificationError("provider path identity has a non-exact schema")
            actual_path = Path(path_record["path"])
            try:
                actual_path.relative_to(runtime_dir)
            except (TypeError, ValueError) as exc:
                raise VerificationError("provider path escapes its exact runtime") from exc
            actual_info = actual_path.lstat()
            if (
                actual_path.is_symlink()
                or actual_info.st_uid != path_record["uid"]
                or actual_info.st_dev != path_record["device"]
                or actual_info.st_ino != path_record["inode"]
                or stat.S_IMODE(actual_info.st_mode) != path_record["mode"]
            ):
                raise VerificationError("provider path identity changed")
            path_evidence.append(
                {
                    "kind": path_record["kind"],
                    "path": str(actual_path),
                    "uid": actual_info.st_uid,
                    "mode": stat.S_IMODE(actual_info.st_mode),
                    "device": actual_info.st_dev,
                    "inode": actual_info.st_ino,
                }
            )
        providers.append(
            {
                "record_sha256": _sha256_file(path),
                "release_id": value.get("release_id"),
                "owner_epoch": value.get("owner_epoch"),
                "generation": resources["generation"],
                "rung": graph.rung,
                "effect_id": value.get("effect_id"),
                "processes": [process_metrics(item) for item in processes],
                "listener": provider_listeners[-1],
                "runtime_dir": str(runtime_dir),
                "paths": path_evidence,
                "privileged": [item.to_dict() for item in graph.privileged],
            }
        )

    for path in _record_files(
        control / "recovery/provider-scopes",
        deadline_monotonic_ns=deadline_monotonic_ns,
    ):
        _check_deadline(
            deadline_monotonic_ns, "provider scope recovery authority"
        )
        value = _read_json(path)
        if set(value) != {
            "child",
            "phase",
            "record_version",
            "release_id",
            "request",
            "schema_version",
            "scope",
            "verb",
        } or (
            value.get("phase") != "ATTACHED"
            or value.get("schema_version") != SCHEMA_VERSION
            or value.get("record_version") != PROVIDER_SCOPE_RECORD_VERSION
        ):
            raise VerificationError(
                f"provider scope record is not exactly retained: {path}"
            )
        try:
            request = ProviderRequest.from_dict(value.get("request"))
            child = ProcessIdentity.from_mapping(
                value.get("child"), "provider scope command child"
            )
        except (TypeError, ValueError) as exc:
            raise VerificationError("provider scope record has invalid authority") from exc
        expected_verb = "direct-up" if request.rung == "direct" else "provider-up"
        child_is_live = process_matches(child)
        if (
            path.name != f"{_provider_scope_tag(request)}.provider.json"
            or value.get("release_id") != request.contract.release_id
            or value.get("verb") != expected_verb
            or child_is_live != (request.rung == "direct")
        ):
            raise VerificationError(
                "provider scope filename, release, verb, or child liveness is invalid"
            )
        scope = _retained_scope_evidence(value.get("scope"))
        provider_scope_requests.append(request)
        provider_scopes.append(
            {
                "record_sha256": _sha256_file(path),
                "release_id": value.get("release_id"),
                "owner_epoch": request.owner_epoch,
                "generation": request.generation,
                "rung": request.rung,
                "transition_id": request.transition_id,
                "request_sha256": _json_digest(request.to_dict()),
                "command": child.to_dict(),
                "verb": value.get("verb"),
                "scope": scope,
            }
        )

    if len(provider_requests) != 1 or len(provider_scopes) != 1:
        raise VerificationError(
            "provider lacks one exact retained process cgroup authority"
        )
    else:
        scope_record = provider_scopes[0]
        request = provider_requests[0]
        if provider_scope_requests[0] != request:
            raise VerificationError(
                "retained provider scope differs from the applied provider request"
            )
        if (
            scope_record["release_id"] != request.contract.release_id
            or scope_record["owner_epoch"] != request.owner_epoch
            or scope_record["generation"] != request.generation
            or scope_record["rung"] != request.rung
            or scope_record["transition_id"] != request.transition_id
        ):
            raise VerificationError(
                "retained provider scope differs from the applied provider request"
            )
        scope_pids = set(scope_record["scope"]["processes"])
        provider_pids = {item.pid for item in provider_identities}
        if expected_rung == "direct" and (
            len(provider_identities) != 1
            or scope_record["command"] != provider_identities[0].to_dict()
        ):
            raise VerificationError(
                "direct provider scope child differs from its resource graph"
            )
        if not scope_pids <= provider_pids:
            raise VerificationError(
                "retained provider scope contains a process outside its resource graph"
            )
        if expected_rung != "vpn" and scope_pids != provider_pids:
            raise VerificationError(
                "unprivileged provider processes are not exhaustively cgroup-contained"
            )
    if len(identities) != len(set(identities)):
        raise VerificationError("durable recovery authorities duplicate a process identity")
    return {
        "children": children,
        "probes": probes,
        "providers": providers,
        "provider_scopes": provider_scopes,
        "detached_scopes": detached_scopes,
        "identities": identities,
        "provider_identities": provider_identities,
        "provider_listeners": provider_listeners,
    }


def prove_exclusive_epoch_authority(
    control: Path,
    snapshot: Mapping[str, Any],
    authority: CleanupAuthority,
    authorities: Mapping[str, Any],
    expected_children: Sequence[ProcessIdentity],
    *,
    expected_contract_digest: str,
    expected_rung: str = "direct",
    require_capacity: bool = True,
    require_qualification_guard: bool = False,
    leader_policy: str = "exact-sockets",
    deadline_monotonic_ns: int | None = None,
) -> ExclusiveCleanupAuthority:
    """Issue destructive authority only for a capacity-filled verifier epoch."""

    children = tuple(expected_children)
    if not children or len(children) != len(set(children)):
        raise VerificationError("exclusive epoch proof has invalid expected children")
    count = len(children)
    resources = snapshot.get("resources")
    durable_children = authorities.get("children")
    durable_probes = authorities.get("probes")
    durable_providers = authorities.get("providers")
    durable_provider_scopes = authorities.get("provider_scopes")
    durable_detached_scopes = authorities.get("detached_scopes")
    provider_identities = authorities.get("provider_identities")
    qualification = resources.get("qualification") if type(resources) is dict else None
    qualification_valid = True
    if require_qualification_guard:
        try:
            qualification_frontend = _qualification_stream_state(
                qualification.get("frontend")
                if type(qualification) is dict
                else None
            )
        except VerificationError:
            qualification_valid = False
        else:
            qualification_valid = (
                set(qualification) == {
                    "active", "pause_id", "lease_count", "frozen_scopes",
                    "fault_in_progress", "frontend",
                }
                and qualification.get("active") is True
                and type(qualification.get("pause_id")) is str
                and _PROBE_ID.fullmatch(qualification["pause_id"]) is not None
                and qualification.get("lease_count") == count
                and type(qualification.get("frozen_scopes")) is int
                and 0 <= qualification.get("frozen_scopes", -1) <= count
                and qualification.get("fault_in_progress") is False
                and type(qualification_frontend["response_hold"]) is bool
            )
    if (
        type(resources) is not dict
        or type(durable_children) is not list
        or type(durable_probes) is not list
        or type(durable_providers) is not list
        or type(durable_provider_scopes) is not list
        or type(durable_detached_scopes) is not list
        or type(provider_identities) is not list
    ):
        raise VerificationError("exclusive epoch proof lacks closed runtime evidence")
    generation = snapshot.get("generation")
    contract_digest = snapshot.get("contract_digest")
    if (
        snapshot.get("release_id") != authority.release_id
        or snapshot.get("owner_epoch") != authority.owner_epoch
        or snapshot.get("phase") != "READY"
        or snapshot.get("active_rung") != expected_rung
        or snapshot.get("transition") is not None
        or snapshot.get("cleanup_error") is not None
        or snapshot.get("live_leases") != count
        or snapshot.get("provisional_leases") != 0
        or snapshot.get("live_interest") != count
        or resources.get("leases") != count
        or (
            require_capacity
            and resources.get("max_leases") != count
        )
        or (
            not require_capacity
            and (
                type(resources.get("max_leases")) is not int
                or resources.get("max_leases", 0) < count
            )
        )
        or resources.get("provider_processes") != len(provider_identities)
        or (
            require_qualification_guard
            and not qualification_valid
        )
        or type(generation) is not int
        or generation < 1
        or type(expected_contract_digest) is not str
        or _DIGEST.fullmatch(expected_contract_digest) is None
        or contract_digest != expected_contract_digest
    ):
        raise VerificationError("epoch is not an exact capacity-filled verifier epoch")
    if (
        durable_probes
        or len(durable_children) != count
        or len(durable_providers) != 1
        or len(durable_provider_scopes) != 1
        or len(durable_detached_scopes) != 1
    ):
        raise VerificationError("exclusive epoch has foreign or incomplete recovery records")
    expected_set = set(children)
    recorded_set = {
        ProcessIdentity.from_mapping(item["process"]["identity"], "exclusive child")
        for item in durable_children
    }
    if recorded_set != expected_set:
        raise VerificationError("exclusive epoch contains a child not owned by this verifier")
    epoch_records = [
        *durable_children,
        *durable_probes,
        *durable_providers,
        *durable_provider_scopes,
        *durable_detached_scopes,
    ]
    if any(
        item.get("release_id") != authority.release_id
        or item.get("owner_epoch") != authority.owner_epoch
        for item in epoch_records
    ) or durable_providers[0].get("generation") != generation:
        raise VerificationError("durable recovery records belong to another epoch")
    detached_identity = ProcessIdentity.from_mapping(
        durable_detached_scopes[0].get("process", {}).get("identity"),
        "detached supervisor epoch",
    )
    if (
        durable_detached_scopes[0].get("kind") != "supervisor-epoch"
        or durable_detached_scopes[0].get("phase") != "OWNED"
        or detached_identity != authority.supervisor
    ):
        raise VerificationError(
            "detached supervisor epoch differs from the cleanup authority"
        )
    if leader_policy not in {"exact-sockets", "disabled-empty"}:
        raise VerificationError("exclusive epoch proof has an invalid leader policy")
    expected_leaders = {item["leader_path"] for item in durable_children}
    if len(expected_leaders) != count:
        raise VerificationError("exclusive epoch durable leader paths are not unique")
    inventory = user_inventory(
        control, deadline_monotonic_ns=deadline_monotonic_ns
    )
    leader_entries = inventory["targets"]["leaders"]["entries"]
    if leader_policy == "exact-sockets":
        actual_leaders = {
            str(control / "leaders" / item["path"])
            for item in leader_entries
            if item.get("kind") == "socket"
        }
        if (
            len(leader_entries) != count
            or len(actual_leaders) != count
            or actual_leaders != expected_leaders
        ):
            raise VerificationError("exclusive epoch leader sockets are not exact")
    elif leader_entries:
        raise VerificationError(
            "exclusive epoch requires an empty disabled leader directory"
        )
    if not _assert_cleanup_fence_owner(cleanup_fence(control), authority):
        raise VerificationError("exclusive epoch lacks its exact recovery fence")
    if not process_matches(authority.supervisor) or not all(
        process_matches(item) for item in (*children, *provider_identities)
    ):
        raise VerificationError("exclusive epoch contains a stale process identity")
    return ExclusiveCleanupAuthority(
        epoch=authority,
        generation=generation,
        contract_digest=contract_digest,
        children=tuple(sorted(children, key=lambda item: item.pid)),
        leader_policy=leader_policy,
    )


def _tcp_listener_rows(proc_root: Path = Path("/proc")) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for name in ("tcp", "tcp6"):
        path = proc_root / "net" / name
        for line in _read_ascii(path, 4 * 1024 * 1024).splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            local = fields[1].split(":", 1)
            if len(local) != 2:
                raise VerificationError(f"malformed {name} listener row")
            try:
                raw_address = bytes.fromhex(local[0])
                port = int(local[1], 16)
                if name == "tcp":
                    if len(raw_address) != 4:
                        raise ValueError("wrong IPv4 address width")
                    packed_address = raw_address[::-1]
                    family = socket.AF_INET
                else:
                    if len(raw_address) != 16:
                        raise ValueError("wrong IPv6 address width")
                    packed_address = b"".join(
                        raw_address[index : index + 4][::-1]
                        for index in range(0, 16, 4)
                    )
                    family = socket.AF_INET6
                host = socket.inet_ntop(family, packed_address)
                inode = int(fields[9])
            except (OSError, ValueError) as exc:
                raise VerificationError(f"malformed {name} listener row") from exc
            rows.append(
                {
                    "family": 4 if name == "tcp" else 6,
                    "host": host,
                    "port": port,
                    "inode": inode,
                }
            )
    return tuple(rows)


def _listener_row_is_exact(
    row: Mapping[str, Any],
    *,
    host: str,
    port: int,
    owners: Sequence[Mapping[str, Any]],
) -> bool:
    return (
        row.get("host") == host
        and row.get("port") == port
        and row.get("owners") == list(owners)
    )


def _process_socket_inodes(
    owner: ProcessIdentity,
    proc_root: Path,
    *,
    deadline_monotonic_ns: int | None = None,
) -> set[int]:
    _check_deadline(deadline_monotonic_ns, "listener FD inventory")
    try:
        with os.scandir(proc_root / str(owner.pid) / "fd") as iterator:
            entries: list[Path] = []
            for entry in iterator:
                _check_deadline(
                    deadline_monotonic_ns, "listener FD inventory"
                )
                if len(entries) >= MAX_RUNTIME_INVENTORY_ENTRIES:
                    raise VerificationError(
                        "listener FD inventory exceeds its entry bound"
                    )
                entries.append(Path(entry.path))
    except OSError as exc:
        raise VerificationError(
            f"cannot inspect listener owner PID {owner.pid}"
        ) from exc
    result: set[int] = set()
    for entry in entries:
        _check_deadline(deadline_monotonic_ns, "listener FD inventory")
        try:
            target = os.readlink(entry)
        except (FileNotFoundError, OSError):
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match is not None:
            result.add(int(match.group(1)))
    return result


def listener_inventory(
    ports: Sequence[int],
    owners: Iterable[ProcessIdentity],
    proc_root: Path = Path("/proc"),
    *,
    deadline_monotonic_ns: int | None = None,
) -> dict[str, list[dict[str, Any]]]:
    _check_deadline(deadline_monotonic_ns, "listener inventory")
    owner_by_inode: dict[int, list[ProcessIdentity]] = {}
    exact_owners = tuple(sorted(set(owners), key=lambda item: item.pid))
    anchors: list[tuple[ProcessIdentity, int]] = []
    attributed: dict[ProcessIdentity, set[int]] = {
        owner: set() for owner in exact_owners
    }
    try:
        for owner in exact_owners:
            _check_deadline(deadline_monotonic_ns, "listener inventory")
            if proc_root == Path("/proc"):
                anchors.append((owner, open_exact_pidfd(owner)))
            if not process_matches(owner, proc_root):
                raise VerificationError(
                    f"listener owner is not exact-live: {owner.pid}"
                )
            for inode in _process_socket_inodes(
                owner,
                proc_root,
                deadline_monotonic_ns=deadline_monotonic_ns,
            ):
                owner_by_inode.setdefault(inode, []).append(owner)
        wanted = set(ports)
        result = {str(port): [] for port in ports}
        initial_rows = _tcp_listener_rows(proc_root)
        _check_deadline(deadline_monotonic_ns, "listener inventory")
        for row in initial_rows:
            if row["port"] not in wanted:
                continue
            matched = owner_by_inode.get(row["inode"], [])
            for owner in matched:
                attributed[owner].add(row["inode"])
            result[str(row["port"])].append(
                {
                    **row,
                    "owners": [
                        item.to_dict()
                        for item in sorted(matched, key=lambda item: item.pid)
                    ],
                }
            )
        for owner in exact_owners:
            if not attributed[owner].issubset(
                _process_socket_inodes(
                    owner,
                    proc_root,
                    deadline_monotonic_ns=deadline_monotonic_ns,
                )
            ):
                raise VerificationError(
                    "listener socket ownership changed during inventory"
                )
        final_rows = _tcp_listener_rows(proc_root)
        _check_deadline(deadline_monotonic_ns, "listener inventory")
        initial_wanted = {
            (row["family"], row["host"], row["port"], row["inode"])
            for row in initial_rows
            if row["port"] in wanted
        }
        final_wanted = {
            (row["family"], row["host"], row["port"], row["inode"])
            for row in final_rows
            if row["port"] in wanted
        }
        if initial_wanted != final_wanted:
            raise VerificationError("listener table changed during inventory")
        if not all(process_matches(owner, proc_root) for owner in exact_owners):
            raise VerificationError("listener owner identity changed during inventory")
        for owner, anchor in anchors:
            try:
                signal.pidfd_send_signal(anchor, 0)
            except ProcessLookupError as exc:
                raise VerificationError(
                    f"listener owner exited during inventory: {owner.pid}"
                ) from exc
        return result
    finally:
        for _owner, anchor in anchors:
            os.close(anchor)


def ports_are_bindable(ports: Sequence[int]) -> bool:
    sockets: list[socket.socket] = []
    try:
        for port in ports:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(probe)
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", port))
            probe.listen(1)
        return True
    except OSError:
        return False
    finally:
        for probe in sockets:
            probe.close()


def assert_ports_clean(inventory: Mapping[str, list[dict[str, Any]]], ports: Sequence[int]) -> None:
    occupied = [str(port) for port in ports if inventory.get(str(port))]
    if occupied or not ports_are_bindable(ports):
        raise VerificationError(f"listener residue remains on ports: {', '.join(occupied)}")


def current_cgroup_path(
    proc_root: Path = Path("/proc"), cgroup_mount: Path = CGROUP_MOUNT
) -> Path:
    lines = _read_ascii(proc_root / "self/cgroup", 16_384).splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise VerificationBlocked("one unified cgroup-v2 hierarchy is required")
    relative = lines[0][3:]
    if ".." in Path(relative).parts:
        raise VerificationBlocked("current cgroup path is not canonical")
    path = cgroup_mount / relative.lstrip("/")
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise VerificationBlocked("current cgroup-v2 directory is unsafe")
    return path


def resource_cgroup_path(
    proc_root: Path = Path("/proc"), cgroup_mount: Path = CGROUP_MOUNT
) -> Path:
    """Return the exact fresh runner whose counters isolate and bound this run."""

    names = (
        "GROK_QUALIFICATION_RESOURCE_CGROUP_PATH",
        "GROK_QUALIFICATION_RESOURCE_CGROUP_DEVICE",
        "GROK_QUALIFICATION_RESOURCE_CGROUP_INODE",
    )
    supplied = tuple(name in os.environ for name in names)
    current = current_cgroup_path(proc_root, cgroup_mount)
    if not any(supplied):
        return current
    if not all(supplied):
        raise VerificationBlocked(
            "qualification resource cgroup authority is incomplete"
        )
    raw_path, raw_device, raw_inode = (os.environ[name] for name in names)
    if (
        not raw_device.isascii()
        or not raw_device.isdecimal()
        or not raw_inode.isascii()
        or not raw_inode.isdecimal()
        or len(raw_path.encode("utf-8", "strict")) > 4096
    ):
        raise VerificationBlocked(
            "qualification resource cgroup authority is invalid"
        )
    authority = Path(raw_path)
    try:
        authority.relative_to(cgroup_mount)
    except ValueError as exc:
        raise VerificationBlocked(
            "qualification resource cgroup authority escapes cgroup-v2"
        ) from exc
    current_info = current.lstat()
    authority_info = authority.lstat()
    if (
        not authority.is_absolute()
        or authority.is_symlink()
        or current.is_symlink()
        or not stat.S_ISDIR(authority_info.st_mode)
        or not stat.S_ISDIR(current_info.st_mode)
        or current != authority
        or _RUNNER_SCOPE_NAME.fullmatch(current.name) is None
        or current_info.st_uid != os.getuid()
        or authority_info.st_uid != os.getuid()
        or current_info.st_dev != authority_info.st_dev
        or current_info.st_ino != authority_info.st_ino
        or (authority_info.st_dev, authority_info.st_ino)
        != (int(raw_device), int(raw_inode))
    ):
        raise VerificationBlocked(
            "qualification resource cgroup authority changed identity"
        )
    return authority


def cgroup_scope_inventory(
    proc_root: Path = Path("/proc"),
    cgroup_mount: Path = CGROUP_MOUNT,
    *,
    deadline_monotonic_ns: int | None = None,
) -> dict[str, Any]:
    """Recursively inventory the owned epoch and all nested runtime scopes."""

    parent = current_cgroup_path(proc_root, cgroup_mount)
    parent_info = parent.lstat()
    scopes: list[dict[str, Any]] = []
    remaining_entries = [MAX_RUNTIME_INVENTORY_ENTRIES]

    def child_cgroups(directory: Path) -> list[Path]:
        _check_deadline(deadline_monotonic_ns, "cgroup scope inventory")
        children: list[Path] = []
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    _check_deadline(
                        deadline_monotonic_ns, "cgroup scope inventory"
                    )
                    if remaining_entries[0] <= 0:
                        raise VerificationError(
                            "cgroup scope inventory exceeds its entry bound"
                        )
                    remaining_entries[0] -= 1
                    if entry.is_symlink():
                        raise VerificationError(
                            "delegated cgroup tree contains a symlink"
                        )
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    if not entry.name.startswith("grok-ms-"):
                        raise VerificationError(
                            f"unexpected child cgroup in qualification scope: {entry.name}"
                        )
                    if _SCOPE_NAME.fullmatch(entry.name) is None:
                        raise VerificationError(
                            f"invalid reserved cgroup scope name: {entry.name}"
                        )
                    children.append(Path(entry.path))
        except OSError as exc:
            raise VerificationBlocked(
                "cannot enumerate the delegated cgroup tree"
            ) from exc
        return sorted(children, key=lambda item: item.name)

    pending = [
        (entry, parent, 1)
        for entry in reversed(child_cgroups(parent))
    ]
    while pending:
        entry, scope_parent, depth = pending.pop()
        if depth > 64:
            raise VerificationError("reserved cgroup nesting depth exceeds its bound")
        _check_deadline(deadline_monotonic_ns, "cgroup scope inventory")
        info = entry.lstat()
        if (
            entry.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_dev != parent_info.st_dev
        ):
            raise VerificationError(
                f"reserved cgroup scope has an unsafe identity: {entry}"
            )
        events: dict[str, str] = {}
        for line in _read_ascii(entry / "cgroup.events", 4_096).splitlines():
            fields = line.split(" ", 1)
            if len(fields) != 2 or fields[0] in events:
                raise VerificationError(
                    f"malformed cgroup.events for scope: {entry}"
                )
            events[fields[0]] = fields[1]
        if events.get("populated") not in {"0", "1"}:
            raise VerificationError(
                f"reserved cgroup scope lacks populated state: {entry}"
            )
        process_text = _read_ascii(entry / "cgroup.procs", 65_536).strip()
        processes: list[int] = []
        if process_text:
            for line in process_text.splitlines():
                if not line.isdecimal() or int(line) < 1:
                    raise VerificationError(
                        f"malformed cgroup.procs for scope: {entry}"
                    )
                processes.append(int(line))
        if len(processes) != len(set(processes)):
            raise VerificationError(
                f"duplicate PID in cgroup.procs for scope: {entry}"
            )
        scopes.append(
            {
                "scope_path": str(entry),
                "scope_device": info.st_dev,
                "scope_inode": info.st_ino,
                "parent_path": str(scope_parent),
                "depth": depth,
                "populated": events["populated"] == "1",
                "processes": sorted(processes),
            }
        )
        pending.extend(
            (child, entry, depth + 1)
            for child in reversed(child_cgroups(entry))
        )
    return {
        "captured_at": utc_timestamp(),
        "parent_path": str(parent),
        "parent_device": parent_info.st_dev,
        "parent_inode": parent_info.st_ino,
        "scopes": scopes,
    }


def assert_cgroup_scopes_clean(inventory: Mapping[str, Any]) -> None:
    scopes = inventory.get("scopes")
    if type(scopes) is not list:
        raise VerificationError("lease cgroup inventory has an invalid schema")
    if scopes:
        raise VerificationError(
            "unrecorded or stale grok-ms cgroup scopes remain: "
            + ", ".join(str(item.get("scope_path")) for item in scopes)
        )


def assert_cgroup_scopes_match(
    inventory: Mapping[str, Any],
    authorities: Mapping[str, Any],
    *,
    allowed_descendant_pids: Iterable[int] = (),
) -> None:
    scopes = inventory.get("scopes")
    children = authorities.get("children")
    probes = authorities.get("probes")
    provider_scopes = authorities.get("provider_scopes")
    detached_scopes = authorities.get("detached_scopes")
    if (
        type(scopes) is not list
        or type(children) is not list
        or type(probes) is not list
        or type(provider_scopes) is not list
        or type(detached_scopes) is not list
        or len(detached_scopes) != 1
    ):
        raise VerificationError("cgroup/authority inventory has an invalid schema")
    detached = detached_scopes[0]
    if type(detached) is not dict:
        raise VerificationError("detached epoch authority is not an object")
    epoch_scope = detached.get("scope")
    epoch_process = detached.get("process")
    epoch_identity = (
        epoch_process.get("identity") if type(epoch_process) is dict else None
    )
    if (
        detached.get("kind") != "supervisor-epoch"
        or detached.get("phase") != "OWNED"
        or type(epoch_scope) is not dict
        or type(epoch_identity) is not dict
        or type(epoch_identity.get("pid")) is not int
    ):
        raise VerificationError("detached epoch authority is invalid")
    epoch_key = (
        epoch_scope.get("scope_path"),
        epoch_scope.get("scope_device"),
        epoch_scope.get("scope_inode"),
    )
    if (
        type(epoch_key[0]) is not str
        or type(epoch_key[1]) is not int
        or type(epoch_key[2]) is not int
        or epoch_scope.get("parent_path") != inventory.get("parent_path")
    ):
        raise VerificationError("detached epoch scope is not rooted in this verifier")
    epoch_pid = epoch_identity["pid"]
    expected_direct: dict[tuple[str, int, int], int] = {}
    for record in (*children, *probes):
        scope = record.get("scope")
        process = record.get("process")
        if type(scope) is not dict or type(process) is not dict:
            raise VerificationError("durable authority omitted scope/process evidence")
        identity = process.get("identity")
        if type(identity) is not dict or type(identity.get("pid")) is not int:
            raise VerificationError("durable authority omitted its direct process PID")
        key = (
            scope.get("scope_path"),
            scope.get("scope_device"),
            scope.get("scope_inode"),
        )
        if (
            type(key[0]) is not str
            or type(key[1]) is not int
            or type(key[2]) is not int
            or key == epoch_key
            or key in expected_direct
        ):
            raise VerificationError("durable authority has a duplicated/invalid scope identity")
        expected_direct[key] = identity["pid"]
    expected_provider: dict[tuple[str, int, int], tuple[int, ...]] = {}
    for record in provider_scopes:
        scope = record.get("scope") if type(record) is dict else None
        if type(scope) is not dict:
            raise VerificationError("provider authority omitted exact scope evidence")
        key = (
            scope.get("scope_path"),
            scope.get("scope_device"),
            scope.get("scope_inode"),
        )
        processes = scope.get("processes")
        if (
            type(key[0]) is not str
            or type(key[1]) is not int
            or type(key[2]) is not int
            or key == epoch_key
            or key in expected_direct
            or key in expected_provider
            or type(processes) is not list
            or any(type(pid) is not int or pid < 1 for pid in processes)
            or len(processes) != len(set(processes))
            or scope.get("populated") is not bool(processes)
        ):
            raise VerificationError("provider authority has an invalid exact scope")
        expected_provider[key] = tuple(processes)
    actual: dict[tuple[str, int, int], Mapping[str, Any]] = {}
    actual_pids: list[int] = []
    for scope in scopes:
        if type(scope) is not dict:
            raise VerificationError("lease cgroup inventory entry is not an object")
        key = (
            scope.get("scope_path"),
            scope.get("scope_device"),
            scope.get("scope_inode"),
        )
        if key in actual:
            raise VerificationError("lease cgroup inventory duplicated an exact scope")
        processes = scope.get("processes")
        if (
            type(processes) is not list
            or any(type(pid) is not int or pid < 1 for pid in processes)
            or len(processes) != len(set(processes))
            or scope.get("populated") is not bool(processes)
        ):
            raise VerificationError("lease cgroup process inventory is inconsistent")
        actual_pids.extend(processes)
        actual[key] = scope
    if set(actual) != {epoch_key} | set(expected_direct) | set(expected_provider):
        raise VerificationError(
            "live grok-ms cgroup set differs from durable recovery authorities"
        )
    epoch_actual = actual[epoch_key]
    if (
        epoch_actual.get("parent_path") != inventory.get("parent_path")
        or epoch_actual.get("depth") != 1
        or epoch_actual.get("populated") is not True
        or epoch_actual.get("processes") != [epoch_pid]
    ):
        raise VerificationError(
            "owned supervisor epoch has an invalid outer membership"
        )
    for key in set(expected_direct) | set(expected_provider):
        scope = actual[key]
        if (
            scope.get("parent_path") != epoch_key[0]
            or scope.get("depth") != 2
        ):
            raise VerificationError(
                "runtime scope is not an exact child of the owned epoch"
            )
    for key, pid in expected_direct.items():
        scope = actual[key]
        if scope.get("populated") is not True or pid not in scope.get("processes", []):
            raise VerificationError(
                "durable direct process is absent from its populated exact cgroup"
            )
    for key, processes in expected_provider.items():
        scope = actual[key]
        if tuple(scope.get("processes", ())) != processes or scope.get(
            "populated"
        ) is not bool(processes):
            raise VerificationError(
                "retained provider cgroup differs from its durable process evidence"
            )
    descendants = tuple(allowed_descendant_pids)
    provider_pids = {
        pid for processes in expected_provider.values() for pid in processes
    }
    if (
        any(type(pid) is not int or pid < 1 for pid in descendants)
        or len(descendants) != len(set(descendants))
        or len(actual_pids) != len(set(actual_pids))
        or set(actual_pids)
        != {epoch_pid}
        | set(expected_direct.values())
        | set(descendants)
        | provider_pids
    ):
        raise VerificationError(
            "reserved cgroup process set differs from exact authorities and descendants"
        )


def _cgroup_value(path: Path) -> str | dict[str, int] | None:
    try:
        text = _read_ascii(path, 65_536).strip()
    except FileNotFoundError:
        return None
    if path.name in {"cpu.stat", "memory.events", "pids.events"}:
        result: dict[str, int] = {}
        for line in text.splitlines():
            fields = line.split()
            if len(fields) != 2 or not fields[1].isdecimal() or fields[0] in result:
                raise VerificationError(f"malformed cgroup counter record: {path}")
            result[fields[0]] = int(fields[1])
        return result
    return text


def cgroup_resource_snapshot() -> dict[str, Any]:
    root = resource_cgroup_path()
    info = root.lstat()
    return {
        "captured_at": utc_timestamp(),
        "monotonic_ns": time.monotonic_ns(),
        "cgroup_path": str(root),
        "cgroup_device": info.st_dev,
        "cgroup_inode": info.st_ino,
        "values": {
            name: _cgroup_value(root / name)
            for name in CGROUP_RESOURCE_VALUE_NAMES
        },
    }


def _cgroup_identity(snapshot: Mapping[str, Any]) -> tuple[str, int, int]:
    identity = (
        snapshot.get("cgroup_path"),
        snapshot.get("cgroup_device"),
        snapshot.get("cgroup_inode"),
    )
    if (
        type(identity[0]) is not str
        or type(identity[1]) is not int
        or type(identity[2]) is not int
        or identity[1] < 1
        or identity[2] < 1
    ):
        raise VerificationError("cgroup resource snapshot has no exact identity")
    return identity


def _cgroup_counter(snapshot: Mapping[str, Any], name: str) -> int:
    values = snapshot.get("values")
    if type(values) is not dict:
        raise VerificationError("cgroup resource snapshot omitted values")
    value = values.get(name)
    if type(value) is not str or not value.isdecimal():
        raise VerificationError(f"required cgroup counter is absent/non-numeric: {name}")
    return int(value)


def _cgroup_events(snapshot: Mapping[str, Any], name: str) -> dict[str, int]:
    values = snapshot.get("values")
    if type(values) is not dict or type(values.get(name)) is not dict:
        raise VerificationError(f"required cgroup event record is absent: {name}")
    events = values[name]
    if not events or any(
        type(key) is not str or not key or type(value) is not int or value < 0
        for key, value in events.items()
    ):
        raise VerificationError(f"required cgroup event record is malformed: {name}")
    return dict(events)


def _cgroup_event_deltas(
    baseline: Mapping[str, Any],
    peak: Mapping[str, Any],
    post: Mapping[str, Any],
    name: str,
) -> dict[str, int]:
    before = _cgroup_events(baseline, name)
    during = _cgroup_events(peak, name)
    after = _cgroup_events(post, name)
    if set(before) != set(during) or set(before) != set(after):
        raise VerificationError(f"cgroup event schema changed during verification: {name}")
    if any(not before[key] <= during[key] <= after[key] for key in before):
        raise VerificationError(f"cgroup event counters regressed during verification: {name}")
    deltas = {key: after[key] - before[key] for key in before}
    if any(deltas.values()):
        raise VerificationError(f"cgroup controller reported a resource event: {name}")
    return deltas


def _resource_contract(count: int, *, mode: str) -> dict[str, int]:
    if mode not in {"load", "fault"} or not 1 <= count <= 32:
        raise VerificationError("resource contract request is invalid")
    expected_processes = 2 * count + 2 if mode == "load" else 5
    return {
        "expected_owned_processes": expected_processes,
        "max_owned_fds": 256 + 40 * count,
        "max_owned_threads": 96 + 12 * count,
        "max_owned_vmrss_kib": 768 * 1024 + count * 96 * 1024,
        "max_owned_vmsize_kib": 4 * 1024 * 1024 + count * 512 * 1024,
        # cgroup pids.current counts threads.  At held load each lease owns a
        # wrapper, Grok child, supervisor control thread, frontend stream
        # worker, provider stream worker, and verifier echo worker.  The fixed
        # allowance covers supervisor/provider/echo accept, watchdog, status,
        # overload, and cleanup transients.
        "max_cgroup_pids_delta": 48 + 6 * count,
        "max_cgroup_memory_delta_bytes": 768 * 1024 * 1024
        + count * 96 * 1024 * 1024,
        "post_pids_tolerance": 16,
        "post_memory_tolerance_bytes": 512 * 1024 * 1024,
    }


_RESOURCE_CONTRACT_KEYS = frozenset(
    {
        "expected_owned_processes",
        "max_owned_fds",
        "max_owned_threads",
        "max_owned_vmrss_kib",
        "max_owned_vmsize_kib",
        "max_cgroup_pids_delta",
        "max_cgroup_memory_delta_bytes",
        "post_pids_tolerance",
        "post_memory_tolerance_bytes",
    }
)
_RESOURCE_OBSERVED_KEYS = frozenset(
    {
        "peak_owned_processes",
        "peak_owned_fds",
        "peak_owned_threads",
        "peak_owned_vmrss_kib",
        "peak_owned_vmsize_kib",
        "cgroup_pids_delta",
        "cgroup_memory_delta_bytes",
        "cgroup_pids_highwater_delta",
        "cgroup_memory_highwater_delta_bytes",
        "memory_event_delta_total",
        "pids_event_delta_total",
        "post_owned_processes",
        "post_owned_fds",
        "post_owned_threads",
        "post_owned_vmrss_kib",
        "post_owned_vmsize_kib",
        "post_pids_delta",
        "post_memory_delta_bytes",
    }
)


def _host_numeric_limit(snapshot: Mapping[str, Any], name: str) -> int | None:
    values = snapshot.get("values")
    if type(values) is not dict:
        raise VerificationError("cgroup resource snapshot omitted host limits")
    value = values.get(name)
    if value == "max":
        return None
    if type(value) is not str or not value.isdecimal():
        raise VerificationError(f"required cgroup host limit is invalid: {name}")
    return int(value)


def assert_process_identities_absent(
    identities: Iterable[ProcessIdentity],
    *,
    timeout: float = 10.0,
    matcher: Callable[[ProcessIdentity], bool] = process_matches,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    if timeout < 0:
        raise VerificationError("process return timeout must be non-negative")
    unique = tuple(sorted(set(identities), key=lambda item: item.pid))
    deadline = time.monotonic() + timeout
    while True:
        live = tuple(item.pid for item in unique if matcher(item))
        if not live:
            return
        if time.monotonic() >= deadline:
            raise VerificationError(
                "exact owned processes did not return after the run: "
                + ",".join(str(pid) for pid in live)
            )
        sleeper(0.02)


def assert_resource_gate(
    *,
    mode: str,
    count: int,
    baseline: Mapping[str, Any],
    peak: Mapping[str, Any],
    post: Mapping[str, Any],
    peak_processes: Mapping[str, Any],
    post_processes: Mapping[str, Any],
) -> dict[str, Any]:
    """Fail unless process and cgroup peaks stay inside explicit host/contract bounds."""

    contract = _resource_contract(count, mode=mode)
    identities = {_cgroup_identity(item) for item in (baseline, peak, post)}
    if len(identities) != 1:
        raise VerificationError("host cgroup identity changed during verification")
    baseline_memory = _cgroup_counter(baseline, "memory.current")
    peak_memory = _cgroup_counter(peak, "memory.current")
    post_memory = _cgroup_counter(post, "memory.current")
    baseline_pids = _cgroup_counter(baseline, "pids.current")
    peak_pids = _cgroup_counter(peak, "pids.current")
    post_pids = _cgroup_counter(post, "pids.current")
    baseline_memory_highwater = _cgroup_counter(baseline, "memory.peak")
    during_memory_highwater = _cgroup_counter(peak, "memory.peak")
    peak_memory_highwater = _cgroup_counter(post, "memory.peak")
    baseline_pids_highwater = _cgroup_counter(baseline, "pids.peak")
    during_pids_highwater = _cgroup_counter(peak, "pids.peak")
    peak_pids_highwater = _cgroup_counter(post, "pids.peak")
    if (
        not baseline_memory_highwater
        <= during_memory_highwater
        <= peak_memory_highwater
        or not baseline_pids_highwater
        <= during_pids_highwater
        <= peak_pids_highwater
    ):
        raise VerificationError("cgroup high-water counter regressed during verification")
    memory_event_deltas = _cgroup_event_deltas(
        baseline, peak, post, "memory.events"
    )
    pids_event_deltas = _cgroup_event_deltas(baseline, peak, post, "pids.events")
    if type(peak_processes) is not dict or type(post_processes) is not dict:
        raise VerificationError("exact process aggregates are absent")
    numeric_process_fields = (
        "process_count",
        "fd_count",
        "threads",
        "vmrss_kib",
        "vmsize_kib",
    )
    for aggregate in (peak_processes, post_processes):
        if any(
            type(aggregate.get(name)) is not int or aggregate[name] < 0
            for name in numeric_process_fields
        ):
            raise VerificationError("exact process aggregate has invalid counters")
    if peak_processes["process_count"] != contract["expected_owned_processes"]:
        raise VerificationError("exact peak process inventory differs from the contract")
    for field, limit_name in (
        ("fd_count", "max_owned_fds"),
        ("threads", "max_owned_threads"),
        ("vmrss_kib", "max_owned_vmrss_kib"),
        ("vmsize_kib", "max_owned_vmsize_kib"),
    ):
        if peak_processes[field] > contract[limit_name]:
            raise VerificationError(f"exact peak {field} exceeds the resource contract")
    if any(post_processes[name] != 0 for name in numeric_process_fields):
        raise VerificationError("exact owned process resources did not return to zero")
    pids_delta = max(0, peak_pids - baseline_pids)
    memory_delta = max(0, peak_memory - baseline_memory)
    pids_highwater_delta = peak_pids_highwater - baseline_pids_highwater
    memory_highwater_delta = peak_memory_highwater - baseline_memory_highwater
    step = "load32" if mode == "load" else "fault-recovery"
    if pids_delta > contract["max_cgroup_pids_delta"]:
        raise QualificationStageError(
            f"{step}-resource-cgroup-pids-peak",
            "host cgroup PID peak exceeds the resource contract",
        )
    if memory_delta > contract["max_cgroup_memory_delta_bytes"]:
        raise QualificationStageError(
            f"{step}-resource-memory",
            "host cgroup memory peak exceeds the resource contract",
        )
    if pids_highwater_delta > contract["max_cgroup_pids_delta"]:
        raise QualificationStageError(
            f"{step}-resource-cgroup-pids-highwater",
            "host cgroup PID high-water exceeds the resource contract",
        )
    if memory_highwater_delta > contract["max_cgroup_memory_delta_bytes"]:
        raise QualificationStageError(
            f"{step}-resource-memory",
            "host cgroup memory high-water exceeds the resource contract",
        )
    if post_pids > baseline_pids + contract["post_pids_tolerance"]:
        raise VerificationError("host cgroup PIDs did not return within tolerance")
    if post_memory > baseline_memory + contract["post_memory_tolerance_bytes"]:
        raise VerificationError("host cgroup memory did not return within tolerance")
    pids_max = _host_numeric_limit(baseline, "pids.max")
    memory_max = _host_numeric_limit(baseline, "memory.max")
    if pids_max is not None and peak_pids > pids_max:
        raise VerificationError("observed PID use exceeds the host cgroup limit")
    if memory_max is not None and peak_memory > memory_max:
        raise VerificationError("observed memory use exceeds the host cgroup limit")
    records = peak_processes.get("processes")
    if type(records) is not list or len(records) != peak_processes["process_count"]:
        raise VerificationError("exact peak process records are incomplete")
    nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    nproc = resource.getrlimit(resource.RLIMIT_NPROC)[0]
    if nproc != resource.RLIM_INFINITY and peak_processes["threads"] > nproc:
        raise VerificationError("exact process/thread use exceeds the host RLIMIT_NPROC")
    record_identities: list[ProcessIdentity] = []
    computed = {name: 0 for name in ("fd_count", "threads", "vmrss_kib", "vmsize_kib")}
    for record in records:
        if (
            type(record) is not dict
            or set(record)
            != {
                "identity",
                "fd_count",
                "threads",
                "vmrss_kib",
                "vmsize_kib",
                "cgroup",
            }
            or type(record.get("fd_count")) is not int
            or type(record.get("threads")) is not int
            or type(record.get("vmrss_kib")) is not int
            or type(record.get("vmsize_kib")) is not int
            or type(record.get("cgroup")) is not str
            or not record["cgroup"]
            or (nofile != resource.RLIM_INFINITY and record["fd_count"] > nofile)
        ):
            raise VerificationError("process FD/thread evidence exceeds the host contract")
        record_identities.append(
            ProcessIdentity.from_mapping(record["identity"], "resource process")
        )
        for name in computed:
            if record[name] < 0:
                raise VerificationError("process resource evidence has a negative counter")
            computed[name] += record[name]
    if len(record_identities) != len(set(record_identities)) or any(
        computed[name] != peak_processes[name] for name in computed
    ):
        raise VerificationError("exact process records disagree with their aggregate")
    return {
        "contract": contract,
        "observed": {
            "peak_owned_processes": peak_processes["process_count"],
            "peak_owned_fds": peak_processes["fd_count"],
            "peak_owned_threads": peak_processes["threads"],
            "peak_owned_vmrss_kib": peak_processes["vmrss_kib"],
            "peak_owned_vmsize_kib": peak_processes["vmsize_kib"],
            "cgroup_pids_delta": pids_delta,
            "cgroup_memory_delta_bytes": memory_delta,
            "cgroup_pids_highwater_delta": pids_highwater_delta,
            "cgroup_memory_highwater_delta_bytes": memory_highwater_delta,
            "memory_event_delta_total": sum(memory_event_deltas.values()),
            "pids_event_delta_total": sum(pids_event_deltas.values()),
            "post_owned_processes": post_processes["process_count"],
            "post_owned_fds": post_processes["fd_count"],
            "post_owned_threads": post_processes["threads"],
            "post_owned_vmrss_kib": post_processes["vmrss_kib"],
            "post_owned_vmsize_kib": post_processes["vmsize_kib"],
            "post_pids_delta": post_pids - baseline_pids,
            "post_memory_delta_bytes": post_memory - baseline_memory,
        },
    }


class ResourceSampler:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._samples = 0
        self._maxima: dict[str, int] = {}
        self._cgroup_identity: tuple[str, int, int] | None = None
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                complete = cgroup_resource_snapshot()
                identity = _cgroup_identity(complete)
                snapshot = complete["values"]
                with self._lock:
                    if self._cgroup_identity is None:
                        self._cgroup_identity = identity
                    elif self._cgroup_identity != identity:
                        raise VerificationError(
                            "resource sampler observed a changed cgroup identity"
                        )
                    self._samples += 1
                    for name in ("memory.current", "memory.peak", "pids.current", "pids.peak"):
                        value = snapshot.get(name)
                        if type(value) is not str or not value.isdecimal():
                            raise VerificationError(
                                f"resource sampler lacks numeric counter {name}"
                            )
                        self._maxima[name] = max(self._maxima.get(name, 0), int(value))
                self._stop.wait(0.05)
        except BaseException as exc:
            self._error = exc

    def stop(
        self, deadline_monotonic_ns: int | None = None
    ) -> dict[str, Any]:
        self._stop.set()
        deadline = time.monotonic() + 3
        if deadline_monotonic_ns is not None:
            deadline = min(deadline, deadline_monotonic_ns / 1_000_000_000)
        self._thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if self._thread.is_alive():
            raise VerificationError("resource sampler did not stop")
        if self._error is not None:
            raise VerificationError(f"resource sampler failed: {self._error}") from self._error
        with self._lock:
            return {
                "samples": self._samples,
                "cgroup_identity": (
                    list(self._cgroup_identity)
                    if self._cgroup_identity is not None
                    else None
                ),
                "observed_maxima": dict(self._maxima),
            }


def assert_resource_sampler(
    evidence: Mapping[str, Any],
    *,
    expected_cgroup: Mapping[str, Any],
    contract_gate: Mapping[str, Any],
) -> dict[str, Any]:
    if type(evidence.get("samples")) is not int or evidence["samples"] < 1:
        raise VerificationError("resource sampler returned zero samples")
    expected_identity = list(_cgroup_identity(expected_cgroup))
    if evidence.get("cgroup_identity") != expected_identity:
        raise VerificationError("resource sampler cgroup identity changed")
    maxima = evidence.get("observed_maxima")
    required = {"memory.current", "memory.peak", "pids.current", "pids.peak"}
    if (
        type(maxima) is not dict
        or set(maxima) != required
        or any(type(maxima[name]) is not int or maxima[name] < 0 for name in required)
    ):
        raise VerificationError("resource sampler maxima are absent or non-numeric")
    contract = contract_gate.get("contract")
    if type(contract) is not dict:
        raise VerificationError("resource sampler has no contract gate")
    baseline_memory = _cgroup_counter(expected_cgroup, "memory.current")
    baseline_pids = _cgroup_counter(expected_cgroup, "pids.current")
    baseline_memory_highwater = _cgroup_counter(expected_cgroup, "memory.peak")
    baseline_pids_highwater = _cgroup_counter(expected_cgroup, "pids.peak")
    if maxima["memory.current"] > (
        baseline_memory + contract["max_cgroup_memory_delta_bytes"]
    ):
        raise VerificationError("sampled memory peak exceeds the resource contract")
    if maxima["pids.current"] > baseline_pids + contract["max_cgroup_pids_delta"]:
        raise VerificationError("sampled PID peak exceeds the resource contract")
    if maxima["memory.peak"] > (
        baseline_memory_highwater + contract["max_cgroup_memory_delta_bytes"]
    ):
        raise VerificationError("sampled memory high-water exceeds the resource contract")
    if maxima["pids.peak"] > (
        baseline_pids_highwater + contract["max_cgroup_pids_delta"]
    ):
        raise VerificationError("sampled PID high-water exceeds the resource contract")
    memory_max = _host_numeric_limit(expected_cgroup, "memory.max")
    pids_max = _host_numeric_limit(expected_cgroup, "pids.max")
    if memory_max is not None and maxima["memory.current"] > memory_max:
        raise VerificationError("sampled memory exceeds the host cgroup limit")
    if pids_max is not None and maxima["pids.current"] > pids_max:
        raise VerificationError("sampled PIDs exceed the host cgroup limit")
    return {
        "samples": evidence["samples"],
        "cgroup_identity_stable": True,
        "numeric_required_counters": True,
        "highwater_counters_checked": True,
        "sample_interval_ms": 50,
        "within_host_and_contract_bounds": True,
    }


def host_limits() -> dict[str, Any]:
    disk = os.statvfs(str(Path(pwd.getpwuid(os.getuid()).pw_dir)))

    def limit(name: int) -> list[int | str]:
        values = resource.getrlimit(name)
        return ["infinity" if item == resource.RLIM_INFINITY else item for item in values]

    return {
        "captured_at": utc_timestamp(),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "cpu_count": os.cpu_count(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "page_size": os.sysconf("SC_PAGE_SIZE"),
        "rlimit_nofile": limit(resource.RLIMIT_NOFILE),
        "rlimit_nproc": limit(resource.RLIMIT_NPROC),
        "disk_available_bytes": disk.f_bavail * disk.f_frsize,
        "uname": {
            "sysname": os.uname().sysname,
            "release": os.uname().release,
            "machine": os.uname().machine,
        },
        "cgroup_limits": cgroup_resource_snapshot(),
    }


def release_provenance(entrypoint: Path) -> dict[str, Any]:
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    selection_path = home / ".local/state/grok-proxy/release-control/selected-release.json"
    info = selection_path.lstat()
    if (
        selection_path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o444
    ):
        raise VerificationBlocked("installed user release selector has an unsafe identity")
    raw = _read_bounded(selection_path)
    try:
        selected = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationBlocked("installed user release selector is invalid") from exc
    release_id = selected.get("release_id") if type(selected) is dict else None
    if type(release_id) is not str or _DIGEST.fullmatch(release_id) is None:
        raise VerificationBlocked("installed user release selector has no valid release ID")
    if (
        selected.get("user_release_id") != release_id
        or selected.get("root_release_id") != release_id
        or selected.get("selection_phase") != "READY"
        or type(selected.get("evidence_sha256")) is not str
        or _DIGEST.fullmatch(selected["evidence_sha256"]) is None
        or selected["evidence_sha256"] == "0" * 64
        or selected.get("target_uid") != os.getuid()
        or selected.get("target_gid") != os.getgid()
    ):
        raise VerificationBlocked("installed release is not a coherent READY selection")
    expected_user_root = home / ".local/lib/grok-proxy"
    if selected.get("user_root") != str(expected_user_root):
        raise VerificationBlocked("installed user release selector has an unexpected user root")
    current = expected_user_root / "current"
    current_info = current.lstat()
    if (
        not stat.S_ISLNK(current_info.st_mode)
        or current_info.st_uid != 0
        or stat.S_IMODE(current_info.st_mode) != 0o777
        or os.readlink(current) != f"releases/{release_id}"
    ):
        raise VerificationBlocked("installed current selector is not exact and root-owned")
    manifest = expected_user_root / "releases" / release_id / "release.json"
    manifest_info = manifest.lstat()
    entrypoint_info = entrypoint.lstat()
    if (
        manifest.is_symlink()
        or not stat.S_ISREG(manifest_info.st_mode)
        or manifest_info.st_uid != 0
        or stat.S_IMODE(manifest_info.st_mode) != 0o444
        or entrypoint.is_symlink()
        or not stat.S_ISREG(entrypoint_info.st_mode)
        or entrypoint_info.st_uid != 0
        or stat.S_IMODE(entrypoint_info.st_mode) != 0o555
    ):
        raise VerificationBlocked("installed manifest or entrypoint has an unsafe identity")
    actual_manifest = _sha256_file(manifest)
    actual_entrypoint = _sha256_file(entrypoint)
    if (
        selected.get("user_manifest_sha256") != actual_manifest
        or selected.get("entrypoint_sha256") != actual_entrypoint
    ):
        raise VerificationBlocked("installed release provenance digests disagree")
    return {
        "release_id": release_id,
        "selection_sha256": hashlib.sha256(raw).hexdigest(),
        "selection_schema_version": selected.get("schema_version"),
        "release_schema_version": selected.get("release_schema_version"),
        "handshake_protocol": selected.get("handshake_protocol"),
        "operation": selected.get("operation"),
        "selection_phase": selected.get("selection_phase"),
        "promotion_evidence_sha256": selected.get("evidence_sha256"),
        "current_selector_target": os.readlink(current),
        "current_selector_device": current_info.st_dev,
        "current_selector_inode": current_info.st_ino,
        "user_manifest_sha256": actual_manifest,
        "root_manifest_sha256": selected.get("root_manifest_sha256"),
        "entrypoint_sha256": actual_entrypoint,
        "broker_gate_sha256": selected.get("broker_gate_sha256"),
        "workload_grok_sha256": _sha256_file(FAKE_GROK),
        "verifier_sha256": _sha256_file(Path(__file__).resolve()),
    }


def _canary_environment() -> dict[str, str]:
    selected = {name: os.environ[name] for name in _CANARY_ENV if name in os.environ}
    raw_fd = selected.get("GROK_RELEASE_CANARY_FD", "")
    if not selected:
        return {}
    if not raw_fd.isascii() or not raw_fd.isdecimal() or int(raw_fd) < 3:
        raise VerificationBlocked("qualification has no inherited canary capability")
    try:
        os.fstat(int(raw_fd))
    except OSError as exc:
        raise VerificationBlocked("qualification canary capability is not open") from exc
    return selected


def _pass_fds(env: Mapping[str, str]) -> tuple[int, ...]:
    raw = env.get("GROK_RELEASE_CANARY_FD", "")
    return (int(raw),) if raw.isascii() and raw.isdecimal() and int(raw) >= 3 else ()


def environment(count: int) -> dict[str, str]:
    account = pwd.getpwuid(os.getuid())
    # The verifier defines the whole routing contract.  Ambient provider,
    # binary, proxy, test, and policy selectors are intentionally not inherited.
    selected = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        # Release load/fault qualification uses a deterministic fake Grok and
        # exists to prove the direct transport, concurrency, recovery, and
        # resource bounds.  Geography is qualified separately by the real-pair
        # rung gate, so a production-blocked host country must not make this
        # policy-neutral release gate impossible.
        "GROK_BLOCKED_CC": "",
    }
    selected.update(_canary_environment())
    selected.update(
        {
            "GROK_MULTI_SESSION": "1",
            "GROK_PROXY_PORT": str(PUBLIC_PORT),
            "GROK_PRIVATE_PORTS": " ".join(str(item) for item in PRIVATE_PORTS),
            "GROK_MAX_LEASES": str(count),
            "GROK_MAX_CONTROL_CONNECTIONS": str(count + 2),
            "GROK_MAX_FRONTEND_STREAMS": str(max(64, count * 2)),
            "GROK_VPN_STABILITY_CHECKS": "1",
            "GROK_STABILITY_INTERVAL_MS": "0",
            "GROK_TRANSITION_TIMEOUT_MS": "120000",
            "GROK_PROBE_TIMEOUT_MS": "30000",
            "GROK_STOP_TIMEOUT_MS": "15000",
            "GROK_WATCHDOG_INTERVAL_MS": "60000",
        }
    )
    selected["GROK_BIN"] = str(FAKE_GROK)
    return selected


def _country_policy(env: Mapping[str, str]) -> tuple[int, str, str, str, str]:
    blocked = tuple(env.get("GROK_BLOCKED_CC", _BLOCKED_DEFAULT).split())
    preferred = tuple(
        env.get("VPNGATE_COUNTRIES", env.get("VPNGATE_PREFER", "VN JP KR TH ID")).split()
    )
    allowed = tuple(item for item in preferred if item not in set(blocked))
    if not allowed:
        raise VerificationBlocked("VPN policy has no allowed country for broker inventory")
    raw_tries = env.get("GROK_VPN_MAX_TRIES", "6")
    if not raw_tries.isdecimal() or not 1 <= int(raw_tries) <= 8:
        raise VerificationBlocked("VPN max tries is invalid for broker inventory")
    return (
        int(raw_tries),
        "vpngate-score-uptime-v1",
        ",".join(allowed),
        ",".join(allowed),
        ",".join(blocked),
    )


def broker_status_command(
    provenance: Mapping[str, Any],
    env: Mapping[str, str],
    snapshot: Mapping[str, Any] | None,
    *,
    broker: Path = FIXED_BROKER,
    sudo: Path = FIXED_SUDO,
    timeout_seconds: float = 25.0,
) -> list[str]:
    release_id = provenance.get("release_id")
    if type(release_id) is not str or _DIGEST.fullmatch(release_id) is None:
        raise VerificationBlocked("release provenance cannot authorize broker status")
    max_tries, ranking, countries, preferred, blocked = _country_policy(env)
    if snapshot is None:
        mode = "compatibility"
        owner = f"compat-{os.getuid()}"
        generation = 0
        digest = "0" * 64
    else:
        mode = "supervisor"
        owner = snapshot.get("owner_epoch")
        generation = snapshot.get("generation")
        digest = snapshot.get("contract_digest")
        if (
            type(owner) is not str
            or not owner
            or type(generation) is not int
            or generation < 1
            or type(digest) is not str
            or _DIGEST.fullmatch(digest) is None
            or snapshot.get("release_id") != release_id
        ):
            raise VerificationBlocked("supervisor snapshot cannot authorize broker status")
    if (
        type(timeout_seconds) not in {int, float}
        or not 0 < float(timeout_seconds) <= 30
    ):
        raise VerificationBlocked("broker status timeout is invalid")
    caller = current_process_identity(os.getpid())
    deadline_ns = time.monotonic_ns() + max(
        1, int(min(25.0, float(timeout_seconds)) * 1_000_000_000)
    )
    return [
        str(sudo),
        "-n",
        str(broker),
        "--operation",
        "status",
        "--mode",
        mode,
        "--release-id",
        release_id,
        "--owner-epoch",
        owner,
        "--generation",
        str(generation),
        "--listen-port",
        str(PRIVATE_PORTS[0]),
        "--contract-digest",
        digest,
        "--vpn-max-tries",
        str(max_tries),
        "--vpn-ranking-version",
        ranking,
        "--vpn-countries",
        countries,
        "--vpn-prefer-countries",
        preferred,
        "--vpn-blocked-countries",
        blocked,
        "--caller-pid",
        str(caller.pid),
        "--caller-start-ticks",
        str(caller.pid_start_ticks),
        "--caller-boot-id",
        caller.boot_id,
        "--deadline-monotonic-ns",
        str(deadline_ns),
    ]


def broker_inventory(
    provenance: Mapping[str, Any],
    env: Mapping[str, str],
    snapshot: Mapping[str, Any] | None,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    timeout: float = 30.0,
) -> dict[str, Any]:
    if type(timeout) not in {int, float} or not 0 < float(timeout) <= 30:
        raise VerificationBlocked("fixed broker inventory timeout is invalid")
    for path, mode in ((FIXED_BROKER, 0o555), (FIXED_SUDO, None)):
        try:
            info = path.lstat()
        except OSError as exc:
            raise VerificationBlocked(f"fixed root inventory executable is unavailable: {path}") from exc
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise VerificationBlocked(f"fixed root inventory executable is unsafe: {path}")
    command = broker_status_command(
        provenance,
        env,
        snapshot,
        timeout_seconds=float(timeout),
    )
    helper_env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GROK_TEST_")
    }
    try:
        if runner is subprocess.run:
            result = _bounded_text_command(
                command,
                env=helper_env,
                timeout=float(timeout),
            )
        else:
            result = runner(
                command,
                text=True,
                capture_output=True,
                timeout=float(timeout),
                check=False,
                env=helper_env,
            )
    except UnicodeError as exc:
        raise VerificationBlocked(
            "fixed broker status returned invalid text encoding"
        ) from exc
    if result.returncode != 0:
        raise VerificationBlocked(
            "fixed broker status inventory failed "
            f"(rc={result.returncode}, stderr_sha256={hashlib.sha256(result.stderr.encode()).hexdigest()})"
        )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise VerificationBlocked("fixed broker status returned invalid JSON") from exc
    fields = {
        "ok",
        "active",
        "namespace_alive",
        "tun_alive",
        "host_tun_alive",
        "vpn_alive",
        "relay_alive",
        "relay_pid",
        "root_artifact_residue",
        "ledger",
    }
    if type(value) is not dict or set(value) != fields or value.get("ok") is not True:
        raise VerificationBlocked("fixed broker status returned a non-exact schema")
    ledger = value["ledger"]
    summary: dict[str, Any] | None = None
    if ledger is not None:
        if type(ledger) is not dict:
            raise VerificationBlocked("fixed broker ledger is not an object")
        summary = {
            "sha256": _json_digest(ledger),
            "phase": ledger.get("phase"),
            "release_id": ledger.get("release_id"),
            "owner_epoch": ledger.get("owner_epoch"),
            "generation": ledger.get("generation"),
            "listen_port": ledger.get("listen_port"),
            "vpn_process": (
                {name: ledger["vpn"].get(name) for name in ("pid", "start_ticks", "boot_id")}
                if type(ledger.get("vpn")) is dict
                else None
            ),
            "relay_process": (
                {name: ledger["relay"].get(name) for name in ("pid", "start_ticks", "boot_id")}
                if type(ledger.get("relay")) is dict
                else None
            ),
            "operation_present": ledger.get("operation") is not None,
        }
    return {
        "captured_at": utc_timestamp(),
        "active": value["active"],
        "namespace_alive": value["namespace_alive"],
        "tun_alive": value["tun_alive"],
        "host_tun_alive": value["host_tun_alive"],
        "vpn_alive": value["vpn_alive"],
        "relay_alive": value["relay_alive"],
        "relay_pid": value["relay_pid"],
        "root_artifact_residue": value["root_artifact_residue"],
        "ledger": summary,
    }


def assert_root_inventory_clean(inventory: Mapping[str, Any]) -> None:
    dirty = [
        name
        for name in (
            "active",
            "namespace_alive",
            "tun_alive",
            "host_tun_alive",
            "vpn_alive",
            "relay_alive",
            "root_artifact_residue",
        )
        if inventory.get(name) is not False
    ]
    if inventory.get("relay_pid") is not None or inventory.get("ledger") is not None:
        dirty.append("ledger_or_relay_pid")
    if dirty:
        raise VerificationError(f"root/VPN cleanup residue remains: {', '.join(dirty)}")


def _bounded_text_command(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    pass_fds: Sequence[int] = (),
    timeout: float,
    maximum: int = MAX_RUNTIME_RECORD,
) -> subprocess.CompletedProcess[str]:
    """Run one helper with bounded time and combined captured output."""

    if timeout <= 0 or maximum < 1:
        raise VerificationError("bounded helper limits are invalid")
    process = subprocess.Popen(
        list(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        pass_fds=tuple(pass_fds),
        env=dict(env),
    )
    assert process.stdout is not None and process.stderr is not None
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    streams = {
        stdout_fd: bytearray(),
        stderr_fd: bytearray(),
    }
    selector = selectors.DefaultSelector()
    for descriptor in streams:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout

    def abort() -> None:
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        # This is our direct child and SIGKILL is not catchable. Reap it
        # synchronously even when the work deadline is already exhausted;
        # returning a live or zombie helper would violate containment.
        process.wait()

    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                abort()
                raise subprocess.TimeoutExpired(list(command), timeout)
            for key, _events in selector.select(min(0.1, remaining)):
                try:
                    chunk = os.read(key.fd, 65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                streams[key.fd].extend(chunk)
                if sum(len(value) for value in streams.values()) > maximum:
                    abort()
                    raise VerificationError(
                        "bounded helper output exceeded its fixed limit"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            abort()
            raise subprocess.TimeoutExpired(list(command), timeout)
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            abort()
            raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    stdout = bytes(streams[stdout_fd]).decode("utf-8")
    stderr = bytes(streams[stderr_fd]).decode("utf-8")
    return subprocess.CompletedProcess(
        list(command), returncode, stdout, stderr
    )


def invoke(
    entrypoint: Path,
    env: Mapping[str, str],
    *arguments: str,
    timeout: float = 10,
) -> subprocess.CompletedProcess[str]:
    return _bounded_text_command(
        [str(entrypoint), *arguments],
        env=env,
        pass_fds=_pass_fds(env),
        timeout=timeout,
    )


def status(
    entrypoint: Path,
    env: Mapping[str, str],
    *,
    timeout: float = 5,
) -> dict[str, Any] | None:
    try:
        result = invoke(entrypoint, env, "status", timeout=timeout)
    except (subprocess.TimeoutExpired, UnicodeError):
        return None
    if result.returncode == 0 and result.stdout.strip().startswith("{"):
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        if type(value) is dict:
            return value
    return None


def wait_status(
    entrypoint: Path,
    env: Mapping[str, str],
    predicate: Callable[[dict[str, Any]], bool],
    timeout: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] | None = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        current = status(
            entrypoint,
            env,
            timeout=min(5.0, remaining),
        )
        if current is not None:
            last = current
            if predicate(current):
                return current
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.05, remaining))
    raise VerificationError(f"status condition timed out; last_digest={_json_digest(last)}")


class EchoServer:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(128)
        self.listener.settimeout(0.1)
        self.port = int(self.listener.getsockname()[1])
        self._accepted = 0
        self._active = 0
        self._completed = 0
        self._received_bytes = 0
        self._sent_bytes = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._accepted += 1
                self._active += 1
            worker = threading.Thread(target=self._echo, args=(connection,), daemon=True)
            self._workers.append(worker)
            worker.start()

    def _echo(self, connection: socket.socket) -> None:
        try:
            with connection:
                while True:
                    data = connection.recv(64 * 1024)
                    if not data:
                        return
                    with self._lock:
                        self._received_bytes += len(data)
                    connection.sendall(data)
                    with self._lock:
                        self._sent_bytes += len(data)
        finally:
            with self._lock:
                self._active -= 1
                self._completed += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "accepted_connections": self._accepted,
                "active_connections": self._active,
                "completed_connections": self._completed,
                "received_bytes": self._received_bytes,
                "sent_bytes": self._sent_bytes,
            }

    def close(self, deadline_monotonic_ns: int | None = None) -> None:
        self._stop.set()
        self.listener.close()
        deadline = time.monotonic() + CLEANUP_ECHO_SECONDS
        if deadline_monotonic_ns is not None:
            deadline = min(deadline, deadline_monotonic_ns / 1_000_000_000)
        self._thread.join(timeout=max(0.0, deadline - time.monotonic()))
        errors: list[str] = []
        if self._thread.is_alive():
            errors.append("echo accept thread remained alive")
        for worker in self._workers:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
            if worker.is_alive():
                errors.append("echo worker remained alive")
        if errors:
            raise VerificationError("; ".join(errors))


@dataclass(slots=True)
class ManagedWrapper:
    process: subprocess.Popen[str]
    identity: ProcessIdentity
    pidfd: int
    qualification_release_fd: int = -1

    def release_qualification_child(self) -> None:
        if self.qualification_release_fd < 0:
            raise VerificationError("qualification child hold is not available")
        descriptor = self.qualification_release_fd
        self.qualification_release_fd = -1
        try:
            if os.write(descriptor, b"1") != 1:
                raise VerificationError("qualification child release was short")
        finally:
            os.close(descriptor)

    def close_pidfd(self) -> None:
        if self.qualification_release_fd >= 0:
            os.close(self.qualification_release_fd)
            self.qualification_release_fd = -1
        if self.pidfd >= 0:
            os.close(self.pidfd)
            self.pidfd = -1


def spawn_wrapper(
    entrypoint: Path,
    env: Mapping[str, str],
    echo: EchoServer,
    index: int,
    hold: float,
    *,
    descendant: Path | None = None,
    identity_file: Path | None = None,
    ready_file: Path | None = None,
    release_file: Path | None = None,
) -> ManagedWrapper:
    command = [
        str(entrypoint),
        "--direct",
        "-m",
        "grok-4.5",
        "--fake-connect",
        f"127.0.0.1:{echo.port}",
        "--fake-payload-bytes",
        str(PAYLOAD_BYTES),
        "--fake-slow-read-ms",
        "25",
        "--fake-hold",
        str(hold),
    ]
    if descendant is not None:
        command.extend(("--fake-descendant-file", str(descendant)))
    if identity_file is not None:
        command.extend(("--fake-identity-file", str(identity_file)))
    if ready_file is not None or release_file is not None:
        if ready_file is None or release_file is None:
            raise VerificationError("wrapper barrier paths must be supplied together")
        command.extend(
            (
                "--fake-ready-file",
                str(ready_file),
                "--fake-release-file",
                str(release_file),
                "--fake-barrier-timeout",
                "90",
            )
        )
    process = subprocess.Popen(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env),
        pass_fds=_pass_fds(env),
    )
    try:
        identity = current_process_identity(process.pid)
        pidfd = open_exact_pidfd(identity)
        return ManagedWrapper(process, identity, pidfd)
    except BaseException:
        process.kill()
        process.wait(timeout=3)
        raise


def _publish_release(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, b"release\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _wait_barrier_ready(paths: Sequence[Path], timeout: float) -> list[ProcessIdentity]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(path.exists() for path in paths):
            break
        time.sleep(0.02)
    else:
        raise VerificationError("not all deterministic data paths reached the barrier")
    identities: list[ProcessIdentity] = []
    for path in paths:
        value = _read_json(path, 4_096)
        if set(value) != {"boot_id", "payload_bytes", "pid", "pid_start_ticks"}:
            raise VerificationError("fixture barrier marker has a non-exact schema")
        if value["payload_bytes"] != PAYLOAD_BYTES:
            raise VerificationError("fixture barrier marker reports the wrong payload size")
        identity = ProcessIdentity.from_mapping(
            {name: value[name] for name in ("pid", "pid_start_ticks", "boot_id")},
            "fixture barrier",
        )
        if not process_matches(identity):
            raise VerificationError("fixture barrier process is no longer exact-live")
        identities.append(identity)
    if len(identities) != len(set(identities)):
        raise VerificationError("fixture barrier process identities are not unique")
    return identities


def _validate_frontend(snapshot: Mapping[str, Any], count: int) -> dict[str, Any]:
    resources = snapshot.get("resources")
    if type(resources) is not dict:
        raise VerificationError("status omitted resources")
    frontend = resources.get("frontend")
    if type(frontend) is not dict:
        raise VerificationError("status omitted frontend gauges")
    expected_exact = {
        "listener_alive": True,
        "accepting": True,
        "closing": False,
        "committed_generation": snapshot.get("generation"),
        "active_streams": count,
        "accepted_streams": count,
        "completed_streams": 0,
        "revoked_streams": 0,
        "rejected_uncommitted": 0,
        "rejected_overload": 0,
        "backend_connect_failures": 0,
    }
    mismatch = {
        name: (frontend.get(name), expected)
        for name, expected in expected_exact.items()
        if frontend.get(name) != expected
    }
    if mismatch:
        raise VerificationError(f"frontend contract gauges disagree: {mismatch!r}")
    integer_fields = (
        "peak_active_streams",
        "buffered_bytes",
        "peak_buffered_bytes",
        "stream_limit",
        "backlog_limit",
        "per_stream_buffer_limit",
        "total_buffer_limit",
        "backend_connected_streams",
        "client_to_backend_bytes",
        "backend_to_client_bytes",
    )
    if any(type(frontend.get(name)) is not int or frontend[name] < 0 for name in integer_fields):
        raise VerificationError("frontend contract contains invalid bounded gauges")
    if (
        frontend["peak_active_streams"] < count
        or frontend["backend_connected_streams"] != count
        or frontend["client_to_backend_bytes"] < count * PAYLOAD_BYTES
        or frontend["backend_to_client_bytes"] < count * PAYLOAD_BYTES
        or frontend["stream_limit"] < count
        or frontend["buffered_bytes"] > frontend["total_buffer_limit"]
        or frontend["peak_buffered_bytes"] > frontend["total_buffer_limit"]
        or frontend["per_stream_buffer_limit"] > frontend["total_buffer_limit"]
    ):
        raise VerificationError("frontend resource gauges escaped their contract limits")
    if (
        resources.get("leases") != count
        or resources.get("max_leases") != count
        or type(resources.get("control_connections")) is not int
        or not count <= resources["control_connections"] <= count + 2
        or type(resources.get("reserved_control_slots")) is not int
        or not 0 <= resources["reserved_control_slots"] <= count + 2
        or resources.get("max_control_connections") != count + 2
        or resources.get("provider_processes") != 1
        or snapshot.get("live_leases") != count
        or snapshot.get("provisional_leases") != 0
        or snapshot.get("live_interest") != count
        or snapshot.get("phase") != "READY"
        or snapshot.get("active_rung") != "direct"
        or snapshot.get("transition") is not None
        or snapshot.get("cleanup_error") is not None
    ):
        raise VerificationError("supervisor contract/resource gauges disagree")
    return dict(frontend)


def _validate_recovery_pair(
    first: Any, second: Any, expected_owner: str
) -> None:
    fields = {
        "recovered",
        "owner_epoch",
        "provider_records",
        "child_records",
        "probe_records",
    }
    if type(first) is not dict or set(first) != fields:
        raise VerificationError("first recovery response has a non-exact schema")
    if type(second) is not dict or set(second) != fields:
        raise VerificationError("second recovery response has a non-exact schema")
    if (
        first["recovered"] is not True
        or first["owner_epoch"] != expected_owner
        or type(first["provider_records"]) is not int
        or first["provider_records"] < 1
        or type(first["child_records"]) is not int
        or first["child_records"] < 1
        or type(first["probe_records"]) is not int
        or first["probe_records"] < 0
    ):
        raise VerificationError("first recovery did not reconcile the dead exact epoch")
    if second != {
        "recovered": False,
        "owner_epoch": None,
        "provider_records": 0,
        "child_records": 0,
        "probe_records": 0,
    }:
        raise VerificationError("second recovery was not an exact idempotent no-op")


def _cleanup_remaining_seconds(
    deadline_monotonic_ns: int,
    maximum: float,
) -> float:
    return max(
        0.0,
        min(
            float(maximum),
            deadline_monotonic_ns / 1_000_000_000 - time.monotonic(),
        ),
    )


def _cleanup_deadline_ns(deadline_monotonic_ns: int | None) -> int:
    if deadline_monotonic_ns is None:
        return (
            time.monotonic_ns()
            + QUALIFICATION_CLEANUP_RESERVE_SECONDS * 1_000_000_000
        )
    if type(deadline_monotonic_ns) is not int or deadline_monotonic_ns <= 0:
        raise VerificationError("cleanup deadline is invalid")
    return deadline_monotonic_ns


def _root_and_user_clean_checkpoint(
    provenance: Mapping[str, Any],
    env: Mapping[str, str],
    *,
    deadline_monotonic_ns: int | None = None,
) -> dict[str, Any]:
    user = user_inventory(
        account_control(), deadline_monotonic_ns=deadline_monotonic_ns
    )
    _check_deadline(deadline_monotonic_ns, "clean user inventory")
    listeners = listener_inventory(
        (PUBLIC_PORT, *PRIVATE_PORTS),
        (),
        deadline_monotonic_ns=deadline_monotonic_ns,
    )
    _check_deadline(deadline_monotonic_ns, "clean listener inventory")
    lease_scopes = cgroup_scope_inventory(
        deadline_monotonic_ns=deadline_monotonic_ns
    )
    _check_deadline(deadline_monotonic_ns, "clean cgroup inventory")
    assert_user_inventory_clean(user)
    assert_ports_clean(listeners, (PUBLIC_PORT, *PRIVATE_PORTS))
    assert_cgroup_scopes_clean(lease_scopes)
    broker_timeout = 30.0
    if deadline_monotonic_ns is not None:
        broker_timeout = _cleanup_remaining_seconds(
            deadline_monotonic_ns, 30.0
        )
        if broker_timeout <= 0:
            raise VerificationError(
                "cleanup deadline expired before root inventory"
            )
    root = broker_inventory(
        provenance, env, None, timeout=broker_timeout
    )
    _check_deadline(deadline_monotonic_ns, "clean root inventory")
    assert_root_inventory_clean(root)
    cgroup = cgroup_resource_snapshot()
    _check_deadline(deadline_monotonic_ns, "clean resource snapshot")
    process_aggregate = aggregate_process_metrics(())
    _check_deadline(deadline_monotonic_ns, "clean process aggregate")
    return {
        "captured_at": utc_timestamp(),
        "user": user,
        "listeners": listeners,
        "lease_cgroup_scopes": lease_scopes,
        "root_vpn": root,
        "cgroup": cgroup,
        "exact_owned_process_aggregate": process_aggregate,
    }


def wait_clean(
    provenance: Mapping[str, Any],
    env: Mapping[str, str],
    timeout: float = CLEANUP_PROOF_SECONDS,
    *,
    deadline_monotonic_ns: int | None = None,
) -> dict[str, Any]:
    deadline_ns = time.monotonic_ns() + max(0, int(timeout * 1_000_000_000))
    if deadline_monotonic_ns is not None:
        deadline_ns = min(deadline_ns, deadline_monotonic_ns)
    last_error = "not inspected"
    while time.monotonic_ns() < deadline_ns:
        try:
            return _root_and_user_clean_checkpoint(
                provenance,
                env,
                deadline_monotonic_ns=deadline_ns,
            )
        except VerificationBlocked:
            raise
        except (OSError, subprocess.SubprocessError, VerificationError) as exc:
            last_error = str(exc)
        time.sleep(
            max(
                0.0,
                min(
                    0.05,
                    (deadline_ns - time.monotonic_ns()) / 1_000_000_000,
                ),
            )
        )
    raise VerificationError(f"cleanup proof timed out: {last_error}")


def _stop_wrappers_bounded(
    wrappers: Sequence[ManagedWrapper],
    deadline_monotonic_ns: int | None = None,
) -> list[str]:
    hard_deadline_monotonic_ns = _cleanup_deadline_ns(
        deadline_monotonic_ns
    )
    errors: list[str] = []
    candidates = [wrapper for wrapper in wrappers if wrapper.process.returncode is None]
    for wrapper in candidates:
        try:
            exact_signal(wrapper.identity, signal.SIGTERM, wrapper.pidfd)
        except (OSError, VerificationError) as exc:
            errors.append(f"wrapper TERM failed: {exc}")

    term_deadline = min(
        time.monotonic() + CLEANUP_WRAPPER_TERM_SECONDS,
        hard_deadline_monotonic_ns / 1_000_000_000,
    )
    for wrapper in candidates:
        if wrapper.process.returncode is not None:
            continue
        try:
            wrapper.process.wait(timeout=max(0.0, term_deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass
        except OSError as exc:
            errors.append(f"wrapper TERM wait failed: {exc}")

    survivors = [
        wrapper for wrapper in candidates if wrapper.process.returncode is None
    ]
    for wrapper in survivors:
        try:
            exact_signal(wrapper.identity, signal.SIGKILL, wrapper.pidfd)
        except (OSError, VerificationError) as exc:
            errors.append(f"wrapper KILL failed: {exc}")

    kill_deadline = min(
        time.monotonic() + CLEANUP_WRAPPER_KILL_SECONDS,
        hard_deadline_monotonic_ns / 1_000_000_000,
    )
    for wrapper in survivors:
        if wrapper.process.returncode is not None:
            continue
        try:
            wrapper.process.wait(timeout=max(0.0, kill_deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"wrapper KILL wait failed: {exc}")
    for wrapper in wrappers:
        wrapper.close_pidfd()
    return errors


def cleanup(
    entrypoint: Path,
    env: Mapping[str, str],
    wrappers: Sequence[ManagedWrapper],
    provenance: Mapping[str, Any],
    authority: ExclusiveCleanupAuthority | None,
    *,
    expected_rung: str = "direct",
    expected_contract_digest: str | None = None,
    require_capacity: bool = True,
    require_qualification_guard: bool = False,
    deadline_monotonic_ns: int | None = None,
) -> dict[str, Any]:
    hard_deadline_monotonic_ns = _cleanup_deadline_ns(
        deadline_monotonic_ns
    )
    errors: list[str] = []
    epoch = authority.epoch if authority is not None else None
    global_mutation_allowed = False
    control = account_control()
    try:
        if epoch is not None:
            _assert_cleanup_fence_owner(cleanup_fence(control), epoch)
            if process_matches(epoch.supervisor):
                status_timeout = _cleanup_remaining_seconds(
                    hard_deadline_monotonic_ns, 5.0
                )
                if status_timeout <= 0:
                    raise VerificationError(
                        "cleanup deadline expired before authority revalidation"
                    )
                current = status(
                    entrypoint, env, timeout=status_timeout
                )
                if current is None:
                    raise VerificationError("cleanup cannot re-read its live supervisor")
                current_authorities = recovery_authorities(
                    control,
                    expected_rung=expected_rung,
                    deadline_monotonic_ns=hard_deadline_monotonic_ns,
                )
                renewed = prove_exclusive_epoch_authority(
                    control,
                    current,
                    epoch,
                    current_authorities,
                    authority.children,
                    expected_contract_digest=(
                        authority.contract_digest
                        if expected_contract_digest is None
                        else expected_contract_digest
                    ),
                    expected_rung=expected_rung,
                    require_capacity=require_capacity,
                    require_qualification_guard=require_qualification_guard,
                    leader_policy=authority.leader_policy,
                    deadline_monotonic_ns=hard_deadline_monotonic_ns,
                )
                if renewed != authority:
                    raise VerificationError("cleanup exclusivity proof changed")
                supervisor_pidfd = open_exact_pidfd(epoch.supervisor)
                try:
                    exact_signal(epoch.supervisor, signal.SIGKILL, supervisor_pidfd)
                    supervisor_timeout = _cleanup_remaining_seconds(
                        hard_deadline_monotonic_ns,
                        CLEANUP_SUPERVISOR_EXIT_SECONDS,
                    )
                    wait_exact_pidfd_exit(
                        epoch.supervisor,
                        supervisor_pidfd,
                        supervisor_timeout,
                    )
                finally:
                    os.close(supervisor_pidfd)
            global_mutation_allowed = True
    except (OSError, subprocess.SubprocessError, UnicodeError, VerificationError) as exc:
        errors.append(f"cleanup destructive authority refused: {exc}")
    finally:
        errors.extend(
            _stop_wrappers_bounded(
                wrappers, hard_deadline_monotonic_ns
            )
        )
    if authority is not None and not global_mutation_allowed:
        raise VerificationError("cleanup errors: " + "; ".join(errors))
    if authority is None:
        try:
            checkpoint = wait_clean(
                provenance,
                env,
                deadline_monotonic_ns=hard_deadline_monotonic_ns,
            )
        except (OSError, subprocess.SubprocessError, VerificationError) as exc:
            errors.append(
                "cleanup acquired no exact epoch authority; global state was not mutated: "
                + str(exc)
            )
            checkpoint = None
        if errors:
            raise VerificationError("cleanup errors: " + "; ".join(errors))
        assert checkpoint is not None
        return checkpoint

    try:
        owns_fence = _assert_cleanup_fence_owner(cleanup_fence(control), epoch)
    except (OSError, VerificationError) as exc:
        raise VerificationError(f"cleanup ownership check failed: {exc}") from exc
    if owns_fence and process_matches(epoch.supervisor):
        errors.append("cleanup refused a live supervisor after exclusivity revalidation")
    try:
        owns_fence = _assert_cleanup_fence_owner(cleanup_fence(control), epoch)
    except (OSError, VerificationError) as exc:
        errors.append(f"cleanup recovery ownership check failed: {exc}")
        owns_fence = False
    if owns_fence and global_mutation_allowed and not errors:
        try:
            recover_timeout = _cleanup_remaining_seconds(
                hard_deadline_monotonic_ns, CLEANUP_RECOVER_SECONDS
            )
            if recover_timeout <= 0:
                raise subprocess.TimeoutExpired(
                    [str(entrypoint), "recover"], 0
                )
            result = invoke(
                entrypoint,
                recovery_environment(env, epoch),
                "recover",
                timeout=recover_timeout,
            )
            if result.returncode != 0:
                errors.append(
                    f"cleanup exact recover failed rc={result.returncode} "
                    f"stderr_sha256={hashlib.sha256(result.stderr.encode()).hexdigest()}"
                )
            else:
                try:
                    recovered = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    errors.append(f"cleanup exact recover returned invalid JSON: {exc}")
                else:
                    if (
                        type(recovered) is not dict
                        or set(recovered)
                        != {
                            "recovered",
                            "owner_epoch",
                            "provider_records",
                            "child_records",
                            "probe_records",
                        }
                        or recovered.get("recovered") is not True
                        or recovered.get("owner_epoch") != epoch.owner_epoch
                        or any(
                            type(recovered.get(name)) is not int
                            or recovered[name] < 0
                            for name in (
                                "provider_records",
                                "child_records",
                                "probe_records",
                            )
                        )
                    ):
                        errors.append("cleanup exact recover did not reconcile its owned epoch")
        except subprocess.TimeoutExpired:
            errors.append("cleanup exact recover timed out")
    checkpoint: dict[str, Any] | None = None
    try:
        checkpoint = wait_clean(
            provenance,
            env,
            deadline_monotonic_ns=hard_deadline_monotonic_ns,
        )
    except (OSError, subprocess.SubprocessError, VerificationError) as exc:
        errors.append(str(exc))
    if errors:
        raise VerificationError("cleanup errors: " + "; ".join(errors))
    assert checkpoint is not None
    return checkpoint


def _finalize_run(
    primary: BaseException | None,
    cleanup_actions: Sequence[Callable[[], Any]],
    *,
    cleanup_error_code: str,
) -> None:
    cleanup_errors: list[str] = []
    for action in cleanup_actions:
        try:
            action()
        except BaseException as exc:
            cleanup_errors.append(f"{type(exc).__name__}: {exc}")
    if primary is not None:
        if cleanup_errors:
            raise QualificationStageError(
                cleanup_error_code,
                f"primary failure: {type(primary).__name__}: {primary}; "
                f"cleanup failures: {'; '.join(cleanup_errors)}",
            ) from primary
        raise primary
    if cleanup_errors:
        raise QualificationStageError(
            cleanup_error_code,
            "cleanup failures: " + "; ".join(cleanup_errors),
        )


def run_load(
    entrypoint: Path,
    count: int,
    provenance: Mapping[str, Any],
    expected_contract_digest: str,
    stage: QualificationStage | None = None,
) -> dict[str, Any]:
    stage = stage or QualificationStage("load32")
    stage.set("load32-contract")
    if _DIGEST.fullmatch(expected_contract_digest) is None:
        raise VerificationError("load qualification expected contract digest is invalid")
    control = account_control()
    env = environment(count)
    (
        work_deadline_monotonic_ns,
        cleanup_deadline_monotonic_ns,
    ) = _qualification_deadlines_ns(env)
    stage.set("load32-baseline")
    baseline = _root_and_user_clean_checkpoint(
        provenance,
        env,
        deadline_monotonic_ns=work_deadline_monotonic_ns,
    )
    limits = host_limits()
    stage.set("load32-spawn")
    echo = EchoServer()
    echo.start()
    wrappers: list[ManagedWrapper] = []
    cleanup_authority: ExclusiveCleanupAuthority | None = None
    primary: BaseException | None = None
    result: dict[str, Any] | None = None
    temporary = tempfile.TemporaryDirectory(prefix="grok-live-load-")
    barrier = Path(temporary.name)
    os.chmod(barrier, 0o700)
    release_file = barrier / "release"
    ready_files = [barrier / f"ready-{index}.json" for index in range(count)]
    started = time.monotonic()
    try:
        wrappers = [
            spawn_wrapper(
                entrypoint,
                env,
                echo,
                index,
                0.2,
                ready_file=ready_files[index],
                release_file=release_file,
            )
            for index in range(count)
        ]
        stage.set("load32-ready")
        snapshot = wait_status(
            entrypoint,
            env,
            lambda value: (
                value.get("live_leases") == count
                and value.get("contract_digest") == expected_contract_digest
            ),
            _remaining_seconds(
                work_deadline_monotonic_ns, 60, "load readiness"
            ),
        )
        candidate_authority = capture_cleanup_authority(control, snapshot, provenance)
        barrier_identities = _wait_barrier_ready(
            ready_files,
            _remaining_seconds(
                work_deadline_monotonic_ns, 60, "load barrier"
            ),
        )
        snapshot = wait_status(
            entrypoint,
            env,
            lambda value: (
                value.get("live_leases") == count
                and value.get("contract_digest") == expected_contract_digest
                and type(value.get("resources")) is dict
                and type(value["resources"].get("frontend")) is dict
                and value["resources"]["frontend"].get("active_streams") == count
            ),
            _remaining_seconds(
                work_deadline_monotonic_ns, 10, "load byte paths"
            ),
        )
        ready_seconds = time.monotonic() - started
        stage.set("load32-runtime-proof")
        frontend = _validate_frontend(snapshot, count)
        supervisor = candidate_authority.supervisor
        if not process_matches(supervisor):
            raise VerificationError("supervisor readiness identity is not exact-live")
        authorities = recovery_authorities(
            control,
            expected_rung="direct",
            deadline_monotonic_ns=work_deadline_monotonic_ns,
        )
        if len(authorities["children"]) != count:
            raise VerificationError("durable child record count differs from client count")
        if len(authorities["providers"]) != 1 or authorities["probes"]:
            raise VerificationError("direct READY generation has unexpected durable authorities")
        child_identities = [
            ProcessIdentity.from_mapping(item["process"]["identity"], "child evidence")
            for item in authorities["children"]
        ]
        if set(barrier_identities) != set(child_identities):
            raise VerificationError("barrier clients differ from durable child authorities")
        cleanup_authority = prove_exclusive_epoch_authority(
            control,
            snapshot,
            candidate_authority,
            authorities,
            barrier_identities,
            expected_contract_digest=expected_contract_digest,
            deadline_monotonic_ns=work_deadline_monotonic_ns,
        )
        peak_user = user_inventory(
            control,
            deadline_monotonic_ns=work_deadline_monotonic_ns,
        )
        leader_entries = peak_user["targets"]["leaders"]["entries"]
        live_leaders = [item for item in leader_entries if item["kind"] == "socket"]
        if len(leader_entries) != count or len(live_leaders) != count:
            raise VerificationError("live leader socket inventory differs from client count")
        scopes = [item["scope"]["scope_path"] for item in authorities["children"]]
        if len(scopes) != count or len(set(scopes)) != count:
            raise VerificationError("child cgroup scopes are not unique and exhaustive")
        scope_inventory = cgroup_scope_inventory(
            deadline_monotonic_ns=work_deadline_monotonic_ns
        )
        assert_cgroup_scopes_match(scope_inventory, authorities)
        known_owners = [supervisor, *authorities["provider_identities"]]
        listeners = listener_inventory(
            (PUBLIC_PORT, *PRIVATE_PORTS),
            known_owners,
            deadline_monotonic_ns=work_deadline_monotonic_ns,
        )
        public_rows = listeners[str(PUBLIC_PORT)]
        private_rows = [row for port in PRIVATE_PORTS for row in listeners[str(port)]]
        if len(public_rows) != 1 or not _listener_row_is_exact(
            public_rows[0],
            host="127.0.0.1",
            port=PUBLIC_PORT,
            owners=(supervisor.to_dict(),),
        ):
            raise VerificationError("public listener lacks the exact supervisor owner")
        if len(private_rows) != 1:
            raise VerificationError("direct provider does not own exactly one private listener")
        provider_listener = authorities["provider_listeners"][0]
        if (
            private_rows[0]["inode"] != provider_listener["socket_inode"]
            or not _listener_row_is_exact(
                private_rows[0],
                host=provider_listener["host"],
                port=provider_listener["port"],
                owners=(provider_listener["owner"],),
            )
        ):
            raise VerificationError("private listener differs from its durable exact authority")
        echo_peak = echo.snapshot()
        expected_bytes = count * PAYLOAD_BYTES
        if echo_peak != {
            "accepted_connections": count,
            "active_connections": count,
            "completed_connections": 0,
            "received_bytes": expected_bytes,
            "sent_bytes": expected_bytes,
        }:
            raise VerificationError(f"held echo byte-path counts disagree: {echo_peak!r}")
        root_peak = broker_inventory(
            provenance,
            env,
            snapshot,
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns, 30, "load root inventory"
            ),
        )
        assert_root_inventory_clean(root_peak)
        peak_processes = aggregate_process_metrics(
            [
                supervisor,
                *(wrapper.identity for wrapper in wrappers),
                *authorities["identities"],
            ]
        )
        peak_cgroup = cgroup_resource_snapshot()
        stage.set("load32-overload")
        overload = invoke(
            entrypoint,
            env,
            "--direct",
            "-m",
            "grok-4.5",
            "--fake-hold",
            "0.1",
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns, 10, "load overload"
            ),
        )
        if overload.returncode == 0 or "lease capacity exceeded" not in overload.stderr:
            raise VerificationError(
                "overload was not rejected exactly "
                f"(rc={overload.returncode}, stderr_sha256={hashlib.sha256(overload.stderr.encode()).hexdigest()})"
            )
        stage.set("load32-completion")
        _publish_release(release_file)
        outputs = [
            wrapper.process.communicate(
                timeout=_remaining_seconds(
                    work_deadline_monotonic_ns,
                    20,
                    "load client completion",
                )
            )
            for wrapper in wrappers
        ]
        failed = [wrapper.process.returncode for wrapper in wrappers if wrapper.process.returncode != 0]
        if failed:
            raise VerificationError(f"load wrapper return codes failed: {failed!r}")
        reported_leaders = {
            line.split("leader=", 1)[1].strip()
            for stdout, _stderr in outputs
            for line in stdout.splitlines()
            if "leader=" in line
        }
        if len(outputs) != count or len(reported_leaders) != count:
            raise VerificationError("completed client or reported leader count differs from load")
        expected_leaders = {
            item["leader_path"] for item in authorities["children"]
        }
        if reported_leaders != expected_leaders:
            raise VerificationError("reported leaders differ from durable child authorities")
        post = wait_clean(
            provenance,
            env,
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns, 30, "load cleanup proof"
            ),
            deadline_monotonic_ns=work_deadline_monotonic_ns,
        )
        owned_identities = (
            supervisor,
            *(wrapper.identity for wrapper in wrappers),
            *authorities["identities"],
        )
        assert_process_identities_absent(
            owned_identities,
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns,
                10,
                "load process return proof",
            ),
        )
        stage.set("load32-resource")
        resource_gate = assert_resource_gate(
            mode="load",
            count=count,
            baseline=baseline["cgroup"],
            peak=peak_cgroup,
            post=post["cgroup"],
            peak_processes=peak_processes,
            post_processes=post["exact_owned_process_aggregate"],
        )
        echo_post = echo.snapshot()
        if echo_post["completed_connections"] != count or echo_post["active_connections"] != 0:
            raise VerificationError("held byte paths did not all complete after barrier release")
        result = {
            "mode": "load",
            "clients_requested": count,
            "clients_completed": len(outputs),
            "ready_seconds": round(ready_seconds, 3),
            "release_id": snapshot.get("release_id"),
            "owner_epoch": snapshot.get("owner_epoch"),
            "generation": snapshot.get("generation"),
            "active_rung": snapshot.get("active_rung"),
            "contract_digest": snapshot.get("contract_digest"),
            "host_limits": limits,
            "contract_gauges": {
                "resources": snapshot["resources"],
                "frontend": frontend,
            },
            "authorities": {
                "supervisor": _aggregate_process_record(peak_processes, supervisor),
                "durable_children": authorities["children"],
                "durable_providers": authorities["providers"],
                "unique_child_scopes": len(set(scopes)),
                "unique_reported_leaders": len(reported_leaders),
                "lease_cgroup_scopes": scope_inventory,
            },
            "listener_inventory": listeners,
            "echo_peak": echo_peak,
            "echo_post": echo_post,
            "overload_returncode": overload.returncode,
            "overload_stderr_sha256": hashlib.sha256(overload.stderr.encode()).hexdigest(),
            "resources": {
                "baseline": {
                    "cgroup": baseline["cgroup"],
                    "exact_owned_process_aggregate": baseline[
                        "exact_owned_process_aggregate"
                    ],
                },
                "peak": {
                    "cgroup": peak_cgroup,
                    "exact_owned_process_aggregate": peak_processes,
                },
                "post": {
                    "cgroup": post["cgroup"],
                    "exact_owned_process_aggregate": post[
                        "exact_owned_process_aggregate"
                    ],
                },
                "gate": resource_gate,
            },
            "root_vpn_peak": root_peak,
            "post_cleanup": post,
            "cleanup_proved": True,
        }
    except BaseException as exc:
        primary = exc
    finally:
        _finalize_run(
            primary,
            (
                lambda: cleanup(
                    entrypoint,
                    env,
                    wrappers,
                    provenance,
                    cleanup_authority,
                    expected_contract_digest=expected_contract_digest,
                    deadline_monotonic_ns=cleanup_deadline_monotonic_ns,
                ),
                lambda: echo.close(cleanup_deadline_monotonic_ns),
                temporary.cleanup,
            ),
            cleanup_error_code="load32-cleanup",
        )
    assert result is not None
    return result


def run_fault(
    entrypoint: Path,
    marker: Path,
    provenance: Mapping[str, Any],
    expected_contract_digest: str,
    stage: QualificationStage | None = None,
) -> dict[str, Any]:
    stage = stage or QualificationStage("fault-recovery")
    stage.set("fault-recovery-contract")
    if _DIGEST.fullmatch(expected_contract_digest) is None:
        raise VerificationError("fault qualification expected contract digest is invalid")
    control = account_control()
    # Release qualification uses one immutable direct/fake contract for both
    # fixed steps.  The fault workload needs one lease but retains load32's
    # contract limits so the two observed contract digests are identical.
    env = environment(32)
    (
        work_deadline_monotonic_ns,
        cleanup_deadline_monotonic_ns,
    ) = _qualification_deadlines_ns(env)
    stage.set("fault-recovery-baseline")
    baseline = _root_and_user_clean_checkpoint(
        provenance,
        env,
        deadline_monotonic_ns=work_deadline_monotonic_ns,
    )
    limits = host_limits()
    if marker.exists() or marker.is_symlink():
        raise VerificationError("fault marker must be absent before the O_EXCL publication")
    marker_parent = marker.parent
    parent_info = marker_parent.lstat()
    if (
        marker_parent.is_symlink()
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or stat.S_IMODE(parent_info.st_mode) != 0o700
    ):
        raise VerificationError("fault marker parent must be a current-user mode-0700 directory")
    stage.set("fault-recovery-spawn")
    echo = EchoServer()
    echo.start()
    wrappers: list[ManagedWrapper] = []
    exit_anchors: list[tuple[ProcessIdentity, int]] = []
    cleanup_authority: ExclusiveCleanupAuthority | None = None
    primary: BaseException | None = None
    result: dict[str, Any] | None = None
    temporary = tempfile.TemporaryDirectory(prefix="grok-live-fault-")
    identity_root = Path(temporary.name)
    os.chmod(identity_root, 0o700)
    identity_file = identity_root / "child.json"
    try:
        wrapper = spawn_wrapper(
            entrypoint,
            env,
            echo,
            0,
            60,
            descendant=marker,
            identity_file=identity_file,
        )
        wrappers.append(wrapper)
        stage.set("fault-recovery-ready")
        snapshot = wait_status(
            entrypoint,
            env,
            lambda value: (
                value.get("live_leases") == 1
                and value.get("contract_digest") == expected_contract_digest
            ),
            _remaining_seconds(
                work_deadline_monotonic_ns, 60, "fault readiness"
            ),
        )
        candidate_authority = capture_cleanup_authority(control, snapshot, provenance)
        stage.set("fault-recovery-runtime-proof")
        deadline = min(
            time.monotonic() + 10,
            work_deadline_monotonic_ns / 1_000_000_000,
        )
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.02)
        if not marker.exists():
            raise VerificationError("escaped descendant identity marker was not published")
        marker_value = _read_json(marker, 4_096)
        descendant = ProcessIdentity.from_mapping(marker_value, "escaped descendant marker")
        if not process_matches(descendant):
            raise VerificationError("escaped descendant was not exact-live before the fault")
        authorities = recovery_authorities(
            control,
            expected_rung="direct",
            deadline_monotonic_ns=work_deadline_monotonic_ns,
        )
        if len(authorities["children"]) != 1 or len(authorities["providers"]) != 1:
            raise VerificationError("fault setup lacks exact child/provider recovery authority")
        child_value = _read_json(identity_file, 4_096)
        if set(child_value) != {
            "boot_id",
            "leader_path",
            "pid",
            "pid_start_ticks",
        }:
            raise VerificationError("fault child identity marker has a non-exact schema")
        child_identity = ProcessIdentity.from_mapping(
            {
                name: child_value[name]
                for name in ("pid", "pid_start_ticks", "boot_id")
            },
            "fault child identity marker",
        )
        recorded_child = ProcessIdentity.from_mapping(
            authorities["children"][0]["process"]["identity"],
            "fault durable child",
        )
        if (
            child_identity != recorded_child
            or child_value["leader_path"]
            != authorities["children"][0]["leader_path"]
        ):
            raise VerificationError("fault child marker differs from durable authority")
        scopes = [item["scope"]["scope_path"] for item in authorities["children"]]
        scope_inventory = cgroup_scope_inventory(
            deadline_monotonic_ns=work_deadline_monotonic_ns
        )
        assert_cgroup_scopes_match(
            scope_inventory,
            authorities,
            allowed_descendant_pids=(descendant.pid,),
        )
        cleanup_authority = prove_exclusive_epoch_authority(
            control,
            snapshot,
            candidate_authority,
            authorities,
            (child_identity,),
            expected_contract_digest=expected_contract_digest,
            require_capacity=False,
            deadline_monotonic_ns=work_deadline_monotonic_ns,
        )
        supervisor = cleanup_authority.epoch.supervisor
        root_before_fault = broker_inventory(
            provenance,
            env,
            snapshot,
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns,
                30,
                "fault root inventory",
            ),
        )
        assert_root_inventory_clean(root_before_fault)
        listeners_before_fault = listener_inventory(
            (PUBLIC_PORT, *PRIVATE_PORTS),
            (supervisor, *authorities["provider_identities"]),
            deadline_monotonic_ns=work_deadline_monotonic_ns,
        )
        public_rows = listeners_before_fault[str(PUBLIC_PORT)]
        private_rows = [
            row
            for port in PRIVATE_PORTS
            for row in listeners_before_fault[str(port)]
        ]
        provider_listener = authorities["provider_listeners"][0]
        if len(public_rows) != 1 or not _listener_row_is_exact(
            public_rows[0],
            host="127.0.0.1",
            port=PUBLIC_PORT,
            owners=(supervisor.to_dict(),),
        ):
            raise VerificationError("fault setup lacks the exact public listener owner")
        if (
            len(private_rows) != 1
            or private_rows[0]["inode"] != provider_listener["socket_inode"]
            or not _listener_row_is_exact(
                private_rows[0],
                host=provider_listener["host"],
                port=provider_listener["port"],
                owners=(provider_listener["owner"],),
            )
        ):
            raise VerificationError("fault setup lacks one exact private listener owner")
        echo_deadline = min(
            time.monotonic() + 2,
            work_deadline_monotonic_ns / 1_000_000_000,
        )
        echo_before_fault = echo.snapshot()
        while (
            time.monotonic() < echo_deadline
            and echo_before_fault["completed_connections"] != 1
        ):
            time.sleep(0.01)
            echo_before_fault = echo.snapshot()
        if echo_before_fault != {
            "accepted_connections": 1,
            "active_connections": 0,
            "completed_connections": 1,
            "received_bytes": PAYLOAD_BYTES,
            "sent_bytes": PAYLOAD_BYTES,
        }:
            raise VerificationError(
                f"fault setup byte-path counts disagree: {echo_before_fault!r}"
            )
        fault_peak_processes = aggregate_process_metrics(
            (
                supervisor,
                wrapper.identity,
                descendant,
                *authorities["identities"],
            )
        )
        fault_peak_cgroup = cgroup_resource_snapshot()
        final_snapshot = status(
            entrypoint,
            env,
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns,
                5,
                "fault final authority status",
            ),
        )
        if final_snapshot is None:
            raise VerificationError("fault setup lost its exact READY status")
        final_authorities = recovery_authorities(
            control,
            expected_rung="direct",
            deadline_monotonic_ns=work_deadline_monotonic_ns,
        )
        if prove_exclusive_epoch_authority(
            control,
            final_snapshot,
            cleanup_authority.epoch,
            final_authorities,
            cleanup_authority.children,
            expected_contract_digest=expected_contract_digest,
            require_capacity=False,
            deadline_monotonic_ns=work_deadline_monotonic_ns,
        ) != cleanup_authority:
            raise VerificationError("fault exclusivity changed before supervisor loss")
        exit_identities = tuple(
            sorted(
                {
                    supervisor,
                    wrapper.identity,
                    descendant,
                    *authorities["identities"],
                },
                key=lambda item: item.pid,
            )
        )
        for identity in exit_identities:
            exit_anchors.append((identity, open_exact_pidfd(identity)))
        stage.set("fault-recovery-supervisor-loss")
        supervisor_pidfd = next(
            pidfd for identity, pidfd in exit_anchors if identity == supervisor
        )
        killed = time.monotonic()
        exact_signal(supervisor, signal.SIGKILL, supervisor_pidfd)
        wrapper.process.wait(
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns,
                10,
                "fault wrapper exit",
            )
        )
        wrapper_exit_seconds = time.monotonic() - killed
        if wrapper.process.returncode == 0:
            raise VerificationError("wrapper reported success after exact supervisor loss")
        if not process_matches(descendant):
            raise VerificationError(
                "escaped descendant was not exact-live before offline recovery"
            )
        stage.set("fault-recovery-recovery")
        dirty_status = invoke(
            entrypoint,
            env,
            "status",
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns,
                5,
                "fault dirty status",
            ),
        )
        if dirty_status.returncode != 2:
            raise VerificationError(
                f"dead-epoch status did not require recovery: {dirty_status.returncode}"
            )
        first = invoke(
            entrypoint,
            recovery_environment(env, cleanup_authority.epoch),
            "recover",
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns,
                30,
                "fault first recovery",
            ),
        )
        second = invoke(
            entrypoint,
            recovery_environment(env, None),
            "recover",
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns,
                30,
                "fault idempotent recovery",
            ),
        )
        if first.returncode != 0 or second.returncode != 0:
            raise VerificationError(
                "recovery command failed "
                f"(first={first.returncode}, second={second.returncode}, "
                f"stderr_sha256={hashlib.sha256((first.stderr + second.stderr).encode()).hexdigest()})"
            )
        first_value = json.loads(first.stdout)
        second_value = json.loads(second.stdout)
        _validate_recovery_pair(first_value, second_value, str(snapshot.get("owner_epoch")))
        for identity, pidfd in exit_anchors:
            wait_exact_pidfd_exit(
                identity,
                pidfd,
                _remaining_seconds(
                    work_deadline_monotonic_ns,
                    10,
                    "fault exact exit proof",
                ),
            )
        stdout, stderr = wrapper.process.communicate(
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns,
                10,
                "fault output collection",
            )
        )
        post = wait_clean(
            provenance,
            env,
            timeout=_remaining_seconds(
                work_deadline_monotonic_ns,
                30,
                "fault cleanup proof",
            ),
            deadline_monotonic_ns=work_deadline_monotonic_ns,
        )
        stage.set("fault-recovery-resource")
        resource_gate = assert_resource_gate(
            mode="fault",
            count=1,
            baseline=baseline["cgroup"],
            peak=fault_peak_cgroup,
            post=post["cgroup"],
            peak_processes=fault_peak_processes,
            post_processes=post["exact_owned_process_aggregate"],
        )
        result = {
            "mode": "fault",
            "release_id": snapshot.get("release_id"),
            "owner_epoch": snapshot.get("owner_epoch"),
            "contract_digest": snapshot.get("contract_digest"),
            "host_limits": limits,
            "supervisor_identity": supervisor.to_dict(),
            "supervisor_kill_to_wrapper_exit_seconds": round(wrapper_exit_seconds, 3),
            "wrapper_returncode": wrapper.process.returncode,
            "wrapper_stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
            "wrapper_stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
            "descendant_identity": descendant.to_dict(),
            "child_identity": child_identity.to_dict(),
            "descendant_exact_live_before_fault": True,
            "descendant_exact_live_before_recovery": True,
            "descendant_exact_live_after_recovery": False,
            "descendant_exact_exit_ready_after_recovery": True,
            "exact_owned_pidfds_exit_ready_after_recovery": True,
            "recorded_child_scopes": scopes,
            "lease_cgroup_scopes_before_fault": scope_inventory,
            "listener_inventory_before_fault": listeners_before_fault,
            "echo_before_fault": echo_before_fault,
            "root_vpn_before_fault": root_before_fault,
            "dirty_status_returncode": dirty_status.returncode,
            "first_recovery": first_value,
            "second_recovery": second_value,
            "recovery_idempotent": True,
            "resources": {
                "baseline": {
                    "cgroup": baseline["cgroup"],
                    "exact_owned_process_aggregate": baseline[
                        "exact_owned_process_aggregate"
                    ],
                },
                "fault_peak": {
                    "cgroup": fault_peak_cgroup,
                    "exact_owned_process_aggregate": fault_peak_processes,
                },
                "post": {
                    "cgroup": post["cgroup"],
                    "exact_owned_process_aggregate": post[
                        "exact_owned_process_aggregate"
                    ],
                },
                "gate": resource_gate,
            },
            "post_cleanup": post,
            "cleanup_proved": True,
        }
    except BaseException as exc:
        primary = exc
    finally:
        _finalize_run(
            primary,
            (
                lambda: cleanup(
                    entrypoint,
                    env,
                    wrappers,
                    provenance,
                    cleanup_authority,
                    expected_contract_digest=expected_contract_digest,
                    require_capacity=False,
                    deadline_monotonic_ns=cleanup_deadline_monotonic_ns,
                ),
                lambda: close_pidfd_anchors(exit_anchors),
                lambda: echo.close(cleanup_deadline_monotonic_ns),
                temporary.cleanup,
            ),
            cleanup_error_code="fault-recovery-cleanup",
        )
    assert result is not None
    return result


@dataclass(frozen=True, slots=True)
class QualificationContext:
    release_id: str
    nonce: str
    canary_kind: str
    rung: str
    route_profile: str
    contract_sha256: str | None
    grok_release_id: str
    model_id: str
    auth_fd: int
    profile_sha256: str | None = None

    @classmethod
    def from_environment(cls) -> "QualificationContext":
        values = _canary_environment()
        required = {
            "GROK_RELEASE_CANARY_MODE",
            "GROK_RELEASE_CANARY_FD",
            "GROK_RELEASE_CANARY_RELEASE_ID",
            "GROK_RELEASE_RUNG_CANARY",
            "GROK_RELEASE_CANARY_RUNG",
            "GROK_RELEASE_CANARY_GROK_RELEASE",
            "GROK_RELEASE_CANARY_NONCE",
            "GROK_RELEASE_CANARY_KIND",
            "GROK_RELEASE_CANARY_MODEL",
            "GROK_RELEASE_CANARY_ROUTE_PROFILE",
        }
        if not required.issubset(values):
            raise VerificationBlocked("qualification authorization is incomplete")
        release_id = values["GROK_RELEASE_CANARY_RELEASE_ID"]
        nonce = values["GROK_RELEASE_CANARY_NONCE"]
        kind = values["GROK_RELEASE_CANARY_KIND"]
        rung = values["GROK_RELEASE_CANARY_RUNG"]
        route_profile = values["GROK_RELEASE_CANARY_ROUTE_PROFILE"]
        contract = values.get("GROK_RELEASE_CANARY_CONTRACT")
        profile_sha256 = values.get(
            "GROK_RELEASE_CANARY_PROFILE_SHA256"
        )
        grok_release = values["GROK_RELEASE_CANARY_GROK_RELEASE"]
        model = values["GROK_RELEASE_CANARY_MODEL"]
        if (
            values["GROK_RELEASE_CANARY_MODE"] != "1"
            or values["GROK_RELEASE_RUNG_CANARY"] != "1"
            or _DIGEST.fullmatch(release_id) is None
            or _DIGEST.fullmatch(nonce) is None
            or kind not in {"release", "rung"}
            or _RUNG_TOKEN.fullmatch(rung) is None
            or _ROUTE_PROFILE_TOKEN.fullmatch(route_profile) is None
            or _GROK_RELEASE_TOKEN.fullmatch(grok_release) is None
            or _MODEL_TOKEN.fullmatch(model) is None
            or (kind == "release" and contract is not None)
            or (kind == "release" and profile_sha256 is not None)
            or (kind == "release" and (rung != "direct" or route_profile != "direct"))
            or (kind == "rung" and (contract is None or _DIGEST.fullmatch(contract) is None))
            or (
                profile_sha256 is not None
                and _DIGEST.fullmatch(profile_sha256) is None
            )
        ):
            raise VerificationBlocked("qualification authorization values are invalid")
        return cls(
            release_id,
            nonce,
            kind,
            rung,
            route_profile,
            contract,
            grok_release,
            model,
            int(values["GROK_RELEASE_CANARY_FD"]),
            profile_sha256,
        )


def _release_contract(context: QualificationContext) -> str:
    selected = environment(32)
    identity = grok_release_id(FAKE_GROK)
    contract = build_contract(
        classify(("--direct", "-m", context.model_id)),
        context.model_id,
        release_dir=ROOT,
        grok_bin=FAKE_GROK,
        env=selected,
        grok_release_id=identity,
    )
    if (
        context.canary_kind != "release"
        or context.rung != "direct"
        or context.route_profile != "direct"
        or context.grok_release_id != identity
        or contract.release_id != context.release_id
        or not qualification_route_profile_matches(
            contract, context.route_profile, context.rung
        )
    ):
        raise VerificationBlocked("release qualification identity is mismatched")
    return contract.digest()


def _host_limits_valid(value: Any) -> bool:
    fields = {
        "captured_at",
        "uid",
        "gid",
        "cpu_count",
        "cpu_affinity",
        "page_size",
        "rlimit_nofile",
        "rlimit_nproc",
        "disk_available_bytes",
        "uname",
        "cgroup_limits",
    }
    if type(value) is not dict or set(value) != fields:
        return False
    if any(
        type(value.get(name)) is not int or value[name] < 0
        for name in ("uid", "gid", "page_size", "disk_available_bytes")
    ):
        return False
    if type(value.get("cpu_count")) is not int or value["cpu_count"] < 1:
        return False
    if (
        type(value.get("cpu_affinity")) is not list
        or not value["cpu_affinity"]
        or any(type(item) is not int or item < 0 for item in value["cpu_affinity"])
        or len(value["cpu_affinity"]) != len(set(value["cpu_affinity"]))
    ):
        return False
    if any(
        type(value.get(name)) is not list or len(value[name]) != 2
        for name in ("rlimit_nofile", "rlimit_nproc")
    ):
        return False
    uname = value.get("uname")
    cgroup = value.get("cgroup_limits")
    if type(cgroup) is not dict or set(cgroup) != {
        "captured_at",
        "monotonic_ns",
        "cgroup_path",
        "cgroup_device",
        "cgroup_inode",
        "values",
    }:
        return False
    values = cgroup.get("values")
    if type(values) is not dict or set(values) != set(CGROUP_RESOURCE_VALUE_NAMES):
        return False
    try:
        authority = resource_cgroup_path()
        authority_info = authority.lstat()
    except (OSError, VerificationBlocked):
        return False
    if (
        cgroup.get("cgroup_path") != str(authority)
        or cgroup.get("cgroup_device") != authority_info.st_dev
        or cgroup.get("cgroup_inode") != authority_info.st_ino
        or type(cgroup.get("captured_at")) is not str
        or not cgroup["captured_at"]
        or type(cgroup.get("monotonic_ns")) is not int
        or cgroup["monotonic_ns"] <= 0
    ):
        return False
    for name in ("memory.current", "memory.peak", "pids.current", "pids.peak"):
        if type(values.get(name)) is not str or not values[name].isdecimal():
            return False
    for name in ("memory.events", "pids.events", "cpu.stat"):
        record = values.get(name)
        if (
            type(record) is not dict
            or not record
            or any(
                type(key) is not str
                or not key
                or type(item) is not int
                or item < 0
                for key, item in record.items()
            )
        ):
            return False
    for name in (
        "cgroup.max.depth",
        "cgroup.max.descendants",
        "memory.high",
        "memory.max",
        "memory.swap.max",
        "pids.max",
        "cpu.max",
    ):
        if type(values.get(name)) is not str or not values[name]:
            return False
    return (
        type(value.get("captured_at")) is str
        and bool(value["captured_at"])
        and type(uname) is dict
        and set(uname) == {"sysname", "release", "machine"}
        and all(type(item) is str and item for item in uname.values())
        and type(cgroup) is dict
    )


def _compact_resource_evidence(
    gate: Mapping[str, Any],
) -> tuple[dict[str, int], dict[str, int]]:
    contract = gate.get("contract")
    observed = gate.get("observed")
    if (
        type(contract) is not dict
        or set(contract) != _RESOURCE_CONTRACT_KEYS
        or any(type(value) is not int or value < 0 for value in contract.values())
        or type(observed) is not dict
        or set(observed) != _RESOURCE_OBSERVED_KEYS
        or any(type(value) is not int for value in observed.values())
        or any(
            observed[name] < 0
            for name in _RESOURCE_OBSERVED_KEYS
            if name not in {"post_pids_delta", "post_memory_delta_bytes"}
        )
    ):
        raise VerificationError("resource gate has a non-exact compact schema")
    return dict(contract), dict(observed)


def _empty_compact_resources() -> tuple[dict[str, int], dict[str, int]]:
    return (
        {name: 0 for name in sorted(_RESOURCE_CONTRACT_KEYS)},
        {name: 0 for name in sorted(_RESOURCE_OBSERVED_KEYS)},
    )


def _compact_load(
    result: Mapping[str, Any], expected_contract_digest: str
) -> dict[str, Any]:
    authorities = result.get("authorities")
    frontend = result.get("contract_gauges", {}).get("frontend")
    echo_peak = result.get("echo_peak")
    gate = result.get("resources", {}).get("gate")
    if not all(type(item) is dict for item in (authorities, frontend, echo_peak, gate)):
        raise VerificationError("load32 result omitted required evidence")
    resource_contract, resource_observed = _compact_resource_evidence(gate)
    unique = authorities.get("unique_reported_leaders")
    observations = {
        "clients_requested": 32,
        "clients_completed": result.get("clients_completed"),
        "active_rung": result.get("active_rung"),
        "shared_owner_epoch": type(result.get("owner_epoch")) is str,
        "shared_generation": type(result.get("generation")) is int,
        "shared_contract": result.get("contract_digest") == expected_contract_digest,
        "unique_leaders": unique,
        "overload_rejected": result.get("overload_returncode") != 0,
        "byte_path_verified": (
            echo_peak.get("accepted_connections") == 32
            and echo_peak.get("received_bytes") == 32 * PAYLOAD_BYTES
            and echo_peak.get("sent_bytes") == 32 * PAYLOAD_BYTES
        ),
        "host_limits_captured": _host_limits_valid(result.get("host_limits")),
        "host_limits_sha256": _json_digest(result.get("host_limits")),
        "resource_contract": resource_contract,
        "resource_observed": resource_observed,
        "resource_gate_passed": "contract" in gate and "observed" in gate,
        "cleanup_proved": result.get("cleanup_proved") is True,
        "ready_duration_ms": int(float(result.get("ready_seconds", 0)) * 1_000),
        "detail_sha256": _json_digest(result),
    }
    expected = {
        **observations,
        "clients_completed": 32,
        "active_rung": "direct",
        "shared_owner_epoch": True,
        "shared_generation": True,
        "shared_contract": True,
        "unique_leaders": 32,
        "overload_rejected": True,
        "byte_path_verified": True,
        "host_limits_captured": True,
        "resource_gate_passed": True,
        "cleanup_proved": True,
    }
    if observations != expected:
        raise VerificationError("load32 compact acceptance criteria failed")
    return observations


def _compact_fault(
    result: Mapping[str, Any],
    duration_ms: int,
    expected_contract_digest: str,
) -> dict[str, Any]:
    gate = result.get("resources", {}).get("gate")
    first = result.get("first_recovery")
    second = result.get("second_recovery")
    if not all(type(item) is dict for item in (gate, first, second)):
        raise VerificationError("fault-recovery result omitted required evidence")
    resource_contract, resource_observed = _compact_resource_evidence(gate)
    if (
        result.get("contract_digest") != expected_contract_digest
        or not _host_limits_valid(result.get("host_limits"))
    ):
        raise VerificationError("fault-recovery contract or host limits are mismatched")
    observations = {
        "active_rung": "direct",
        "supervisor_loss_exact": type(result.get("supervisor_identity")) is dict,
        "wrapper_failed_closed": (
            type(result.get("wrapper_returncode")) is int
            and result.get("wrapper_returncode") != 0
        ),
        "descendant_contained": (
            result.get("descendant_exact_live_before_fault") is True
            and result.get("descendant_exact_live_before_recovery") is True
            and result.get("descendant_exact_live_after_recovery") is False
            and result.get("descendant_exact_exit_ready_after_recovery") is True
            and result.get("exact_owned_pidfds_exit_ready_after_recovery") is True
        ),
        "first_recovery_applied": first.get("recovered") is True,
        "second_recovery_noop": second.get("recovered") is False,
        "recovery_duration_ms": duration_ms,
        "resource_gate_passed": "contract" in gate and "observed" in gate,
        "host_limits_sha256": _json_digest(result.get("host_limits")),
        "resource_contract": resource_contract,
        "resource_observed": resource_observed,
        "cleanup_proved": result.get("cleanup_proved") is True,
        "detail_sha256": _json_digest(result),
    }
    if any(
        observations[name] is not True
        for name in (
            "supervisor_loss_exact", "wrapper_failed_closed", "descendant_contained",
            "first_recovery_applied", "second_recovery_noop", "resource_gate_passed",
            "cleanup_proved",
        )
    ):
        raise VerificationError("fault-recovery compact acceptance criteria failed")
    return observations


def _qualification_home(profile_sha256: str | None) -> Path:
    """Return the fixed account home, with one isolated profile-test seam."""

    try:
        account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError) as exc:
        raise VerificationBlocked(
            "qualification cannot resolve the target account home"
        ) from exc
    if not account_home.is_absolute():
        raise VerificationBlocked(
            "qualification target account home is not absolute"
        )
    if (
        profile_sha256 is None
        or os.environ.get("GROK_TESTING") != "1"
    ):
        return account_home
    candidate = Path(os.environ.get("HOME", str(account_home)))
    if not candidate.is_absolute():
        raise VerificationBlocked(
            "profile qualification test home is not absolute"
        )
    return candidate


def _qualification_profile_root(profile_sha256: str) -> Path:
    home = _qualification_home(profile_sha256)
    if os.environ.get("GROK_TESTING") == "1":
        state_value = os.environ.get("XDG_STATE_HOME")
        if state_value is not None:
            state_root = Path(state_value)
            if not state_root.is_absolute():
                raise VerificationBlocked(
                    "profile qualification XDG_STATE_HOME is not absolute"
                )
            return state_root / "grok-proxy/profiles"
    return home / ".local/state/grok-proxy/profiles"


def _real_environment() -> dict[str, str]:
    account = pwd.getpwuid(os.getuid())
    canary = _canary_environment()
    profile_sha256 = canary.get(
        "GROK_RELEASE_CANARY_PROFILE_SHA256"
    )
    selected_home = _qualification_home(profile_sha256)
    selected = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(selected_home),
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        "GROK_MULTI_SESSION": "1",
    }
    selected.update(canary)
    if (
        profile_sha256 is not None
        and os.environ.get("GROK_TESTING") == "1"
    ):
        # Prefix-layout tests use the same explicit test-only state seams as
        # the installed client.  These selectors are never copied for an
        # ordinary or legacy qualification context.
        selected["GROK_TESTING"] = "1"
        selected["HOME"] = str(selected_home)
        for name in (
            "XDG_STATE_HOME",
            "GROK_TEST_ROOT_RELEASE_CONTROL",
        ):
            value = os.environ.get(name)
            if value is not None:
                candidate = Path(value)
                if not candidate.is_absolute():
                    raise VerificationBlocked(
                        f"profile qualification {name} is not absolute"
                    )
                selected[name] = str(candidate)
    return selected


def _qualification_deadline_ns(env: Mapping[str, str]) -> int:
    raw = env.get("GROK_QUALIFICATION_DEADLINE_MONOTONIC_NS", "")
    now = time.monotonic_ns()
    if (
        not raw.isascii()
        or not raw.isdecimal()
        or int(raw) <= now
        or int(raw) > now + QUALIFICATION_HARD_SECONDS * 1_000_000_000
    ):
        raise VerificationBlocked(
            "qualification lacks one valid installer work deadline"
        )
    return int(raw)


def _qualification_cleanup_deadline_ns(
    env: Mapping[str, str], work_deadline_monotonic_ns: int
) -> int:
    raw = env.get(
        "GROK_QUALIFICATION_CLEANUP_DEADLINE_MONOTONIC_NS", ""
    )
    now = time.monotonic_ns()
    if (
        not raw.isascii()
        or not raw.isdecimal()
        or int(raw) <= now
        or int(raw)
        > now + QUALIFICATION_HARD_SECONDS * 1_000_000_000
        or int(raw) - work_deadline_monotonic_ns
        != QUALIFICATION_CLEANUP_RESERVE_SECONDS * 1_000_000_000
    ):
        raise VerificationBlocked(
            "qualification lacks one valid installer cleanup deadline"
        )
    return int(raw)


def _qualification_deadlines_ns(
    env: Mapping[str, str],
) -> tuple[int, int]:
    work_deadline_monotonic_ns = _qualification_deadline_ns(env)
    return (
        work_deadline_monotonic_ns,
        _qualification_cleanup_deadline_ns(
            env, work_deadline_monotonic_ns
        ),
    )


def _remaining_seconds(
    deadline_monotonic_ns: int,
    maximum: float,
    label: str,
) -> float:
    remaining = (
        deadline_monotonic_ns - time.monotonic_ns()
    ) / 1_000_000_000
    if remaining <= 0:
        raise VerificationError(f"qualification deadline expired during {label}")
    return max(0.001, min(float(maximum), remaining))


def _cache_snapshot(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        try:
            path.lstat()
        except FileNotFoundError:
            return {"state": "absent"}
        raise VerificationError("Grok model cache changed during one snapshot")
    except OSError as exc:
        raise VerificationError("Grok model cache has an unsafe identity") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 0 <= before.st_size <= MAX_RUNTIME_RECORD
        ):
            raise VerificationError("Grok model cache has an unsafe identity")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, MAX_RUNTIME_RECORD + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RUNTIME_RECORD:
                raise VerificationError("Grok model cache has an unsafe identity")
            chunks.append(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            current = path.lstat()
        except FileNotFoundError as exc:
            raise VerificationError(
                "Grok model cache changed during one snapshot"
            ) from exc
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_size,
            value.st_mtime_ns,
        )
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise VerificationError("Grok model cache changed during one snapshot")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("Grok model cache is not complete JSON") from exc
    if type(value) not in {dict, list}:
        raise VerificationError("Grok model cache has an unsupported JSON root")
    return {
        "state": "regular",
        "device": before.st_dev,
        "inode": before.st_ino,
        "mode": stat.S_IMODE(before.st_mode),
        "size": before.st_size,
        "mtime_ns": before.st_mtime_ns,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class CacheSampler:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.before = _cache_snapshot(path)
        self.samples: list[dict[str, Any]] = []
        self.error: BaseException | None = None
        self._seen_regular = self.before.get("state") == "regular"
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                sample = _cache_snapshot(self.path)
                state = sample.get("state")
                if self._seen_regular and state != "regular":
                    raise VerificationError(
                        "Grok cache disappeared after becoming regular"
                    )
                if state == "regular":
                    self._seen_regular = True
                if not self.samples or sample != self.samples[-1]:
                    if len(self.samples) >= 4_096:
                        raise VerificationError(
                            "Grok cache transition evidence exceeded its bound"
                        )
                    self.samples.append(sample)
                if self._stop.wait(0.02):
                    break
        except BaseException as exc:
            self.error = exc

    def stop(
        self, deadline_monotonic_ns: int | None = None
    ) -> tuple[dict[str, Any], tuple[dict[str, Any], ...], dict[str, Any]]:
        self._stop.set()
        deadline = time.monotonic() + 2
        if deadline_monotonic_ns is not None:
            deadline = min(deadline, deadline_monotonic_ns / 1_000_000_000)
        self._thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if self._thread.is_alive():
            raise VerificationError("Grok cache sampler did not stop")
        if self.error is not None:
            raise VerificationError("Grok cache sampler observed an invalid state") from self.error
        after = _cache_snapshot(self.path)
        return self.before, tuple(self.samples), after


def _cache_refresh_valid(
    before: Mapping[str, Any],
    during: Sequence[Mapping[str, Any]],
    after: Mapping[str, Any],
) -> bool:
    states = (before, *during, after)
    if (
        not during
        or not all(item.get("state") in {"absent", "regular"} for item in states)
        or after.get("state") != "regular"
    ):
        return False
    if before.get("state") == "absent":
        return any(item.get("state") == "regular" for item in during)
    if before.get("state") != "regular":
        return False

    def fingerprint(item: Mapping[str, Any]) -> tuple[Any, ...]:
        return tuple(
            item.get(name)
            for name in ("device", "inode", "size", "mtime_ns", "sha256")
        )

    original = fingerprint(before)
    return any(
        item.get("state") == "regular" and fingerprint(item) != original
        for item in (*during, after)
    )


def _cache_window_valid(
    before: Mapping[str, Any],
    during: Sequence[Mapping[str, Any]],
    after: Mapping[str, Any],
    *,
    allow_initial_absent: bool,
) -> bool:
    """Prove a sampled cache window never exposed an unsafe replacement gap."""

    if not during or after.get("state") != "regular":
        return False
    states = (before, *during, after)
    allowed = {"regular", "absent"} if allow_initial_absent else {"regular"}
    if not all(item.get("state") in allowed for item in states):
        return False
    if before.get("state") == "regular" and any(
        item.get("state") != "regular" for item in states
    ):
        return False
    seen_regular = before.get("state") == "regular"
    for item in states[1:]:
        if item.get("state") == "regular":
            seen_regular = True
        elif seen_regular:
            return False
    return True


def _bounded_collect(
    process: subprocess.Popen[bytes],
    *,
    timeout: float,
    maximum: int = MAX_RUNTIME_RECORD,
    deadline_monotonic_ns: int | None = None,
    termination_deadline_monotonic_ns: int | None = None,
) -> tuple[bytes, bytes]:
    assert process.stdout is not None and process.stderr is not None
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    streams = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    selector = selectors.DefaultSelector()
    for descriptor in streams:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    if deadline_monotonic_ns is not None:
        deadline = min(deadline, deadline_monotonic_ns / 1_000_000_000)
    termination_deadline = deadline + 10
    if termination_deadline_monotonic_ns is not None:
        termination_deadline = min(
            termination_deadline,
            termination_deadline_monotonic_ns / 1_000_000_000,
        )

    def terminate() -> None:
        if process.poll() is not None:
            return
        process.terminate()
        remaining = max(0.0, termination_deadline - time.monotonic())
        if remaining > 0:
            try:
                process.wait(timeout=min(5.0, remaining))
            except subprocess.TimeoutExpired:
                pass
        if process.returncode is None:
            process.kill()
            remaining = max(0.0, termination_deadline - time.monotonic())
            if remaining > 0:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    pass

    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate()
                raise VerificationError("real Grok qualification exceeded its fixed deadline")
            for key, _events in selector.select(min(0.1, remaining)):
                chunk = os.read(key.fd, 65_536)
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                target = streams[key.fd]
                target.extend(chunk)
                if len(target) > maximum:
                    terminate()
                    raise VerificationError("real Grok output exceeded its fixed bound")
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, 0)
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            terminate()
            raise VerificationError(
                "real Grok qualification exceeded its fixed deadline"
            ) from exc
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return bytes(streams[stdout_fd]), bytes(streams[stderr_fd])


def _bounded_collect_pair(
    wrappers: Sequence[ManagedWrapper],
    *,
    timeout: float,
    deadline_monotonic_ns: int | None = None,
    termination_deadline_monotonic_ns: int | None = None,
) -> list[tuple[bytes, bytes]]:
    if len(wrappers) != 2:
        raise VerificationError("real Grok qualification requires exactly two wrappers")
    outputs: list[tuple[bytes, bytes] | None] = [None, None]
    errors: list[BaseException] = []
    lock = threading.Lock()

    def collect(index: int, wrapper: ManagedWrapper) -> None:
        try:
            outputs[index] = _bounded_collect(
                wrapper.process,
                timeout=timeout,
                deadline_monotonic_ns=deadline_monotonic_ns,
                termination_deadline_monotonic_ns=(
                    termination_deadline_monotonic_ns
                ),
            )
        except BaseException as exc:
            with lock:
                errors.append(exc)

    threads = [
        threading.Thread(target=collect, args=(index, wrapper), daemon=True)
        for index, wrapper in enumerate(wrappers)
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout + 10
    if termination_deadline_monotonic_ns is not None:
        deadline = min(
            deadline,
            termination_deadline_monotonic_ns / 1_000_000_000,
        )
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    if any(thread.is_alive() for thread in threads):
        for wrapper in wrappers:
            if wrapper.process.poll() is None:
                wrapper.process.kill()
        raise VerificationError("real Grok collectors exceeded their fixed deadline")
    if errors:
        raise errors[0]
    if any(output is None for output in outputs):
        raise VerificationError("real Grok collector omitted an output")
    return [output for output in outputs if output is not None]


def _real_route_arguments(route_profile: str) -> list[str]:
    if route_profile == "direct":
        return ["--direct"]
    if route_profile == "iphone":
        return ["--iphone"]
    if route_profile.startswith("ios:") and re.fullmatch(
        r"[a-z0-9][a-z0-9._-]{0,63}", route_profile[4:]
    ):
        return ["--ios", route_profile[4:]]
    if route_profile == "vpn":
        return ["--vpn"]
    if route_profile == "auto":
        return []
    if route_profile == "auto-no-direct":
        return ["--no-direct"]
    if (
        route_profile.startswith("home:")
        and re.fullmatch(r"[A-Za-z0-9._:+@-]{1,120}", route_profile[5:])
        is not None
    ):
        return ["--host", route_profile[5:]]
    raise VerificationBlocked("real-pair route profile is not supported")


def _profile_bound_contract(
    context: QualificationContext,
) -> RouteContract:
    """Load the exact private profile selected by root-owned canary authority."""

    profile_sha256 = context.profile_sha256
    if profile_sha256 is None or _DIGEST.fullmatch(profile_sha256) is None:
        raise VerificationBlocked(
            "profile-bound qualification lacks an exact profile identity"
        )
    profile_root = _qualification_profile_root(profile_sha256)
    try:
        profile = load_managed_profile(
            profile_root / f"{profile_sha256}.json",
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
            expected_sha256=profile_sha256,
        )
        with open_profile_grok(profile):
            pass
    except (ManagedProfileError, OSError) as exc:
        # Do not expose an owner-only profile path or nested endpoint detail in
        # the verifier's closed failure surface.
        raise VerificationBlocked(
            "profile-bound qualification profile is invalid"
        ) from exc
    original = profile.contract
    if (
        context.canary_kind != "rung"
        or context.contract_sha256 is None
        or original.release_id != context.release_id
        or original.digest() != context.contract_sha256
        or profile.grok_release_id != context.grok_release_id
        or original.grok_release_id != context.grok_release_id
        or original.model_id != context.model_id
        or context.rung not in original.ladder
        or not qualification_route_profile_matches(
            original, context.route_profile, context.rung
        )
    ):
        raise VerificationBlocked(
            "profile-bound qualification identity is mismatched"
        )
    return original


def _real_contracts(
    context: QualificationContext,
    env: Mapping[str, str],
) -> tuple[RouteContract, RouteContract]:
    if context.profile_sha256 is None:
        route_arguments = _real_route_arguments(context.route_profile)
        original = build_contract(
            classify((*route_arguments, "-m", context.model_id)),
            context.model_id,
            release_dir=ROOT,
            grok_bin=(
                Path(pwd.getpwuid(os.getuid()).pw_dir)
                / ".local/bin/grok"
            ),
            env=env,
            grok_release_id=context.grok_release_id,
        )
    else:
        # The content-addressed profile, not ambient GROK/VPNGATE selectors,
        # is the complete contract source for profile-bound qualification.
        original = _profile_bound_contract(context)
    if (
        original.release_id != context.release_id
        or original.grok_release_id != context.grok_release_id
        or original.model_id != context.model_id
        or original.digest() != context.contract_sha256
        or not qualification_route_profile_matches(
            original, context.route_profile, context.rung
        )
    ):
        raise VerificationBlocked(
            "real-pair route profile does not reproduce the authorized original contract"
        )
    runtime = replace(original, ladder=(context.rung,))
    return original, runtime


def _spawn_real_wrapper(
    entrypoint: Path,
    env: Mapping[str, str],
    context: QualificationContext,
    session_id: str,
    cwd: Path,
) -> ManagedWrapper:
    response_schema = json.dumps(
        {
            "type": "object",
            "properties": {"token": {"const": "GROK_REMOTE_QUALIFICATION_OK"}},
            "required": ["token"],
            "additionalProperties": False,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    command = [
        str(entrypoint),
        *_real_route_arguments(context.route_profile),
        "-m", context.model_id,
        "--session-id", session_id,
        "--cwd", str(cwd),
        "--single", "Return the required qualification token object only.",
        "--json-schema", response_schema,
        "--output-format", "json",
        "--max-turns", "1",
        "--no-plan",
        "--no-subagents",
        "--disable-web-search",
        "--no-memory",
    ]
    hold_read, hold_write = os.pipe2(os.O_CLOEXEC)
    child_env = dict(env)
    child_env["GROK_QUALIFICATION_CHILD_HOLD_FD"] = str(hold_read)
    inherited = tuple(sorted({*_pass_fds(env), hold_read}))
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
            pass_fds=inherited,
        )
    except BaseException:
        os.close(hold_read)
        os.close(hold_write)
        raise
    os.close(hold_read)
    try:
        identity = current_process_identity(process.pid)
        return ManagedWrapper(
            process,
            identity,
            open_exact_pidfd(identity),
            hold_write,
        )
    except BaseException:
        os.close(hold_write)
        process.kill()
        process.wait(timeout=5)
        raise


def _spawn_models_wrapper(
    entrypoint: Path,
    env: Mapping[str, str],
    context: QualificationContext,
) -> ManagedWrapper:
    command = [
        str(entrypoint),
        *_real_route_arguments(context.route_profile),
        "-m",
        context.model_id,
        "models",
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env),
        pass_fds=_pass_fds(env),
    )
    try:
        identity = current_process_identity(process.pid)
        return ManagedWrapper(process, identity, open_exact_pidfd(identity))
    except BaseException:
        process.kill()
        process.wait(timeout=5)
        raise


def _models_output_contains(stdout: bytes, model_id: str) -> bool:
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError:
        return False
    models = {
        match.group(1)
        for line in text.splitlines()
        if (
            match := re.fullmatch(
                r"\s+[-*]\s+([A-Za-z0-9._:+/@-]{1,128})(?:\s+.*)?",
                line,
            )
        )
        is not None
    }
    return model_id in models


_QUALIFICATION_FRONTEND_FIELDS = {
    "committed_generation",
    "active_streams",
    "accepted_streams",
    "backend_connected_streams",
    "client_to_backend_bytes",
    "backend_to_client_bytes",
}

_QUALIFICATION_STREAM_FIELDS = {
    "stream_id", "generation", "socks_state",
    "client_to_backend_bytes", "backend_to_client_bytes",
    "application_client_to_backend_bytes",
    "application_backend_to_client_bytes",
}


def _qualification_frontend(value: Any) -> dict[str, int]:
    if type(value) is not dict or set(value) != _QUALIFICATION_FRONTEND_FIELDS:
        raise VerificationError("qualification frontend evidence is not exact")
    if any(type(item) is not int or item < 0 for item in value.values()):
        raise VerificationError("qualification frontend evidence is invalid")
    return dict(value)


def _qualification_stream_state(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "response_hold", "accept_cursor", "quiesce_epoch", "streams",
    }:
        raise VerificationError("qualification stream evidence is not exact")
    if (
        type(value["response_hold"]) is not bool
        or type(value["accept_cursor"]) is not int
        or value["accept_cursor"] < 0
        or type(value["quiesce_epoch"]) is not int
        or value["quiesce_epoch"] < 0
        or type(value["streams"]) is not list
        or len(value["streams"]) > 2
    ):
        raise VerificationError("qualification stream evidence is invalid")
    stream_ids: set[int] = set()
    streams: list[dict[str, Any]] = []
    for stream in value["streams"]:
        if type(stream) is not dict or set(stream) != _QUALIFICATION_STREAM_FIELDS:
            raise VerificationError("qualification stream receipt is not exact")
        counters = _QUALIFICATION_STREAM_FIELDS - {
            "stream_id", "generation", "socks_state"
        }
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
            or any(type(stream[name]) is not int or stream[name] < 0 for name in counters)
            or stream["application_client_to_backend_bytes"]
            > stream["client_to_backend_bytes"]
            or stream["application_backend_to_client_bytes"]
            > stream["backend_to_client_bytes"]
        ):
            raise VerificationError("qualification stream receipt is invalid")
        stream_ids.add(stream["stream_id"])
        streams.append(dict(stream))
    return {
        "response_hold": value["response_hold"],
        "accept_cursor": value["accept_cursor"],
        "quiesce_epoch": value["quiesce_epoch"],
        "streams": streams,
    }


def _recv_without_descriptors(
    connection: SeqPacketConnection, label: str
) -> dict[str, Any]:
    message = connection.recv()
    if message.fds:
        for descriptor in message.fds:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise VerificationError(f"{label} returned unexpected descriptors")
    if type(message.payload) is not dict:
        raise VerificationError(f"{label} returned a non-object response")
    return message.payload


@dataclass(slots=True)
class QualificationPause:
    connection: SeqPacketConnection
    owner_epoch: str
    canary_nonce: str
    pause_id: str
    generation: int
    deadline_monotonic_ns: int
    bindings: tuple[dict[str, Any], ...]
    frontend: dict[str, int]
    qualification: dict[str, Any]

    @classmethod
    def open(
        cls,
        context: QualificationContext,
        snapshot: Mapping[str, Any],
        wrappers: Sequence[ManagedWrapper],
        overall_deadline_monotonic_ns: int,
    ) -> "QualificationPause":
        if len(wrappers) != 2 or len({item.identity for item in wrappers}) != 2:
            raise VerificationError("qualification pause requires two unique wrappers")
        request_id = str(uuid.uuid4())
        remaining = _remaining_seconds(
            overall_deadline_monotonic_ns, 900, "qualification pause setup"
        )
        if remaining < 1:
            raise VerificationError(
                "qualification deadline has no bounded pause interval remaining"
            )
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        sock.settimeout(remaining)
        sock.connect(str(account_control() / "supervisor.sock"))
        connection = SeqPacketConnection(sock)
        try:
            connection.verify_peer(expected_uid=os.getuid())
            connection.send(
                {
                    "type": "qualification-pause",
                    "schema_version": SCHEMA_VERSION,
                    "protocol_version": PROTOCOL_VERSION,
                    "request_id": request_id,
                    "owner_epoch": snapshot.get("owner_epoch"),
                    "canary_nonce": context.nonce,
                    "deadline_monotonic_ns": overall_deadline_monotonic_ns,
                    "wrappers": [item.identity.to_dict() for item in wrappers],
                },
                (context.auth_fd,),
            )
            response = _recv_without_descriptors(
                connection, "qualification pause"
            )
            fields = {
                "ok", "type", "request_id", "owner_epoch", "pause_id",
                "generation", "deadline_monotonic_ns", "bindings", "frontend",
                "qualification",
            }
            if (
                type(response) is not dict
                or set(response) != fields
                or response.get("ok") is not True
                or response.get("type") != "qualification-pause"
                or response.get("request_id") != request_id
                or response.get("owner_epoch") != snapshot.get("owner_epoch")
                or type(response.get("pause_id")) is not str
                or _PROBE_ID.fullmatch(response["pause_id"]) is None
                or type(response.get("generation")) is not int
                or response.get("generation") != snapshot.get("generation")
                or type(response.get("deadline_monotonic_ns")) is not int
                or response.get("deadline_monotonic_ns") <= time.monotonic_ns()
                or response.get("deadline_monotonic_ns")
                != overall_deadline_monotonic_ns
                or type(response.get("bindings")) is not list
                or len(response["bindings"]) != 2
            ):
                raise VerificationError("qualification pause response is not exact")
            bindings: list[dict[str, Any]] = []
            for index, value in enumerate(response["bindings"]):
                if type(value) is not dict or set(value) != {
                    "lease_id", "wrapper", "child", "leader_path", "scope",
                }:
                    raise VerificationError(
                        "qualification pause binding is not exact"
                    )
                wrapper = ProcessIdentity.from_mapping(
                    value["wrapper"], f"qualification binding wrapper {index}"
                )
                child = ProcessIdentity.from_mapping(
                    value["child"], f"qualification binding child {index}"
                )
                if (
                    wrapper != wrappers[index].identity
                    or type(value["lease_id"]) is not str
                    or _TOKEN.fullmatch(value["lease_id"]) is None
                    or type(value["leader_path"]) is not str
                    or not Path(value["leader_path"]).is_absolute()
                    or type(value["scope"]) is not dict
                ):
                    raise VerificationError(
                        "qualification pause binding differs from its wrapper"
                    )
                bindings.append(
                    {
                        **value,
                        "wrapper_identity": wrapper,
                        "child_identity": child,
                    }
                )
            frontend = _qualification_frontend(response["frontend"])
            qualification = _qualification_stream_state(
                response["qualification"]
            )
            if (
                frontend["committed_generation"] != response["generation"]
                or frontend["active_streams"] != 0
                or qualification != {
                    "response_hold": True,
                    "accept_cursor": 0,
                    "quiesce_epoch": 0,
                    "streams": [],
                }
            ):
                raise VerificationError(
                    "qualification pause did not arm one empty held generation"
                )
            pause = cls(
                connection=connection,
                owner_epoch=str(response["owner_epoch"]),
                canary_nonce=context.nonce,
                pause_id=str(response["pause_id"]),
                generation=int(response["generation"]),
                deadline_monotonic_ns=int(response["deadline_monotonic_ns"]),
                bindings=tuple(bindings),
                frontend=frontend,
                qualification=qualification,
            )
            remaining = (
                pause.deadline_monotonic_ns - time.monotonic_ns()
            ) / 1_000_000_000
            if remaining <= 0:
                raise VerificationError("qualification pause expired during setup")
            sock.settimeout(max(1.0, remaining))
            return pause
        except BaseException:
            connection.close()
            raise

    def _arm_socket_deadline(self, label: str) -> None:
        self.connection.socket.settimeout(
            _remaining_seconds(self.deadline_monotonic_ns, 900, label)
        )

    def set_frozen(
        self,
        wrapper: ProcessIdentity,
        frozen: bool,
        expected_generation: int,
    ) -> dict[str, Any]:
        self._arm_socket_deadline("qualification freeze change")
        request_id = str(uuid.uuid4())
        self.connection.send(
            {
                "type": "qualification-set-frozen",
                "schema_version": SCHEMA_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "request_id": request_id,
                "owner_epoch": self.owner_epoch,
                "canary_nonce": self.canary_nonce,
                "pause_id": self.pause_id,
                "wrapper": wrapper.to_dict(),
                "frozen": frozen,
                "expected_generation": expected_generation,
            }
        )
        response = _recv_without_descriptors(
            self.connection, "qualification freeze"
        )
        fields = {
            "ok", "type", "request_id", "owner_epoch", "pause_id",
            "wrapper", "child", "frozen", "generation", "frozen_scopes",
            "frontend", "qualification",
        }
        if (
            type(response) is not dict
            or set(response) != fields
            or response.get("ok") is not True
            or response.get("type") != "qualification-set-frozen"
            or response.get("request_id") != request_id
            or response.get("owner_epoch") != self.owner_epoch
            or response.get("pause_id") != self.pause_id
            or ProcessIdentity.from_mapping(
                response.get("wrapper"), "qualification freeze wrapper"
            )
            != wrapper
            or response.get("frozen") is not frozen
            or response.get("generation") != expected_generation
            or type(response.get("frozen_scopes")) is not int
            or not 0 <= response["frozen_scopes"] <= 2
        ):
            raise VerificationError("qualification freeze response is not exact")
        child = ProcessIdentity.from_mapping(
            response["child"], "qualification freeze child"
        )
        binding = [
            item for item in self.bindings if item["wrapper_identity"] == wrapper
        ]
        if len(binding) != 1 or binding[0]["child_identity"] != child:
            raise VerificationError("qualification freeze child binding changed")
        return {
            "frozen_scopes": response["frozen_scopes"],
            "frontend": _qualification_frontend(response["frontend"]),
            "qualification": _qualification_stream_state(
                response["qualification"]
            ),
        }

    def quiesce(
        self,
        expected_generation: int,
        wrapper: ProcessIdentity | None,
        stream_ids: Sequence[int],
    ) -> dict[str, Any]:
        self._arm_socket_deadline("qualification quiesce")
        request_id = str(uuid.uuid4())
        selected = list(stream_ids)
        self.connection.send(
            {
                "type": "qualification-quiesce",
                "schema_version": SCHEMA_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "request_id": request_id,
                "owner_epoch": self.owner_epoch,
                "canary_nonce": self.canary_nonce,
                "pause_id": self.pause_id,
                "expected_generation": expected_generation,
                "wrapper": (
                    wrapper.to_dict() if wrapper is not None else None
                ),
                "stream_ids": selected,
            }
        )
        response = _recv_without_descriptors(
            self.connection, "qualification quiesce"
        )
        fields = {
            "ok", "type", "request_id", "owner_epoch", "pause_id",
            "wrapper", "accept_cursor", "quiesce_epoch", "generation",
            "qualification",
        }
        qualification = _qualification_stream_state(
            response.get("qualification")
        )
        if (
            set(response) != fields
            or response.get("ok") is not True
            or response.get("type") != "qualification-quiesce"
            or response.get("request_id") != request_id
            or response.get("owner_epoch") != self.owner_epoch
            or response.get("pause_id") != self.pause_id
            or response.get("generation") != expected_generation
            or (
                ProcessIdentity.from_mapping(
                    response.get("wrapper"), "qualification quiesce wrapper"
                )
                != wrapper
                if wrapper is not None
                else response.get("wrapper") is not None
            )
            or type(response.get("accept_cursor")) is not int
            or type(response.get("quiesce_epoch")) is not int
            or response["accept_cursor"] < max(selected, default=0)
            or qualification["response_hold"] is not True
            or qualification["streams"]
            or qualification["accept_cursor"] != response["accept_cursor"]
            or qualification["quiesce_epoch"] != response["quiesce_epoch"]
        ):
            raise VerificationError("qualification quiesce response is not exact")
        return {
            "accept_cursor": response["accept_cursor"],
            "quiesce_epoch": response["quiesce_epoch"],
            "qualification": qualification,
        }

    def disarm(self, expected_generation: int) -> dict[str, Any]:
        self._arm_socket_deadline("qualification disarm")
        request_id = str(uuid.uuid4())
        self.connection.send(
            {
                "type": "qualification-disarm",
                "schema_version": SCHEMA_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "request_id": request_id,
                "owner_epoch": self.owner_epoch,
                "canary_nonce": self.canary_nonce,
                "pause_id": self.pause_id,
                "expected_generation": expected_generation,
            }
        )
        response = _recv_without_descriptors(
            self.connection, "qualification disarm"
        )
        fields = {
            "ok", "type", "request_id", "owner_epoch", "pause_id",
            "generation", "qualification",
        }
        qualification = _qualification_stream_state(
            response.get("qualification")
        )
        if (
            set(response) != fields
            or response.get("ok") is not True
            or response.get("type") != "qualification-disarm"
            or response.get("request_id") != request_id
            or response.get("owner_epoch") != self.owner_epoch
            or response.get("pause_id") != self.pause_id
            or response.get("generation") != expected_generation
            or qualification["response_hold"] is not False
            or qualification["streams"]
        ):
            raise VerificationError("qualification disarm response is not exact")
        return qualification

    def close(self) -> None:
        self.connection.close()


def _bound_pause_children(
    pause: QualificationPause,
    authorities: Mapping[str, Any],
) -> tuple[ProcessIdentity, ...]:
    records = authorities.get("children")
    if type(records) is not list or len(records) != 2:
        raise VerificationError("qualification pause lacks two durable children")
    by_lease = {item.get("lease_id"): item for item in records}
    if len(by_lease) != 2:
        raise VerificationError("qualification durable lease bindings are not unique")
    scope_fields = {
        "backend", "parent_path", "parent_device", "parent_inode",
        "scope_path", "scope_device", "scope_inode",
    }
    children: list[ProcessIdentity] = []
    for binding in pause.bindings:
        record = by_lease.get(binding["lease_id"])
        if type(record) is not dict:
            raise VerificationError("qualification binding has no durable lease record")
        child = ProcessIdentity.from_mapping(
            record.get("process", {}).get("identity"),
            "qualification durable child",
        )
        scope = record.get("scope")
        if (
            child != binding["child_identity"]
            or record.get("leader_path") != binding["leader_path"]
            or type(scope) is not dict
            or {name: scope.get(name) for name in scope_fields} != binding["scope"]
        ):
            raise VerificationError(
                "qualification supervisor binding differs from durable recovery"
            )
        children.append(child)
    if len(set(children)) != 2:
        raise VerificationError("qualification bound children are not unique")
    return tuple(children)


def _child_execution_unit_evidence(
    authorities: Mapping[str, Any],
    expected_children: Sequence[ProcessIdentity],
) -> tuple[dict[str, Any], ...]:
    """Bind each exact Grok child identity to one distinct cgroup identity."""

    records = authorities.get("children")
    expected = tuple(expected_children)
    if (
        type(records) is not list
        or len(records) != len(expected)
        or not expected
        or len(set(expected)) != len(expected)
    ):
        raise VerificationError("execution-unit evidence has invalid child cardinality")
    evidence: list[dict[str, Any]] = []
    observed_children: set[ProcessIdentity] = set()
    observed_scopes: set[tuple[str, int, int]] = set()
    for record in records:
        if type(record) is not dict:
            raise VerificationError("execution-unit evidence has a malformed child")
        child = ProcessIdentity.from_mapping(
            record.get("process", {}).get("identity"),
            "execution-unit child",
        )
        scope = record.get("scope")
        if type(scope) is not dict:
            raise VerificationError("execution-unit evidence omits its cgroup scope")
        scope_identity = (
            scope.get("scope_path"),
            scope.get("scope_device"),
            scope.get("scope_inode"),
        )
        if (
            type(scope_identity[0]) is not str
            or not Path(scope_identity[0]).is_absolute()
            or type(scope_identity[1]) is not int
            or type(scope_identity[2]) is not int
            or child in observed_children
            or scope_identity in observed_scopes
        ):
            raise VerificationError(
                "execution-unit evidence has a duplicate or invalid identity"
            )
        observed_children.add(child)
        observed_scopes.add(scope_identity)
        evidence.append(
            {
                "child": child.to_dict(),
                "scope": {
                    "scope_path": scope_identity[0],
                    "scope_device": scope_identity[1],
                    "scope_inode": scope_identity[2],
                },
            }
        )
    if observed_children != set(expected):
        raise VerificationError(
            "execution-unit evidence differs from the guarded Grok children"
        )
    return tuple(
        sorted(
            evidence,
            key=lambda item: (
                item["child"]["pid"],
                item["child"]["pid_start_ticks"],
                item["child"]["boot_id"],
            ),
        )
    )


def _request_provider_fault(
    env: Mapping[str, str],
    context: QualificationContext,
    snapshot: Mapping[str, Any],
    pause: QualificationPause,
    expected_old_streams_sha256: str,
) -> dict[str, Any]:
    if _DIGEST.fullmatch(expected_old_streams_sha256) is None:
        raise VerificationError("old stream transcript digest is invalid")
    request_id = str(uuid.uuid4())

    def exchange() -> dict[str, Any]:
        remaining = (
            pause.deadline_monotonic_ns - time.monotonic_ns()
        ) / 1_000_000_000
        if remaining <= 0:
            raise VerificationError(
                "qualification pause expired before provider repair completed"
            )
        connection_socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        connection_socket.settimeout(max(0.001, remaining))
        connection_socket.connect(str(account_control() / "supervisor.sock"))
        connection = SeqPacketConnection(connection_socket)
        try:
            connection.verify_peer(expected_uid=os.getuid())
            connection.send(
                {
                    "type": "qualification-provider-fault",
                    "schema_version": SCHEMA_VERSION,
                    "protocol_version": PROTOCOL_VERSION,
                    "request_id": request_id,
                    "owner_epoch": snapshot.get("owner_epoch"),
                    "canary_nonce": context.nonce,
                    "pause_id": pause.pause_id,
                    "expected_generation": pause.generation,
                    "expected_old_streams_sha256": expected_old_streams_sha256,
                },
                (context.auth_fd,),
            )
            return _recv_without_descriptors(
                connection, "qualification provider fault"
            )
        finally:
            connection.close()

    response = exchange()
    fields = {
        "ok", "type", "request_id", "owner_epoch", "rung",
        "generation_before", "generation_after", "duration_ms",
        "repair_succeeded", "old_streams_sha256", "replayed", "pause_id",
    }
    if (
        set(response) != fields
        or response.get("ok") is not True
        or response.get("type") != "qualification-provider-fault"
        or response.get("request_id") != request_id
        or response.get("owner_epoch") != snapshot.get("owner_epoch")
        or response.get("pause_id") != pause.pause_id
        or response.get("rung") != context.rung
        or response.get("generation_before") != snapshot.get("generation")
        or type(response.get("generation_after")) is not int
        or response.get("generation_after") != response.get("generation_before", 0) + 1
        or type(response.get("duration_ms")) is not int
        or not 0 <= response.get("duration_ms", -1) <= 900_000
        or response.get("repair_succeeded") is not True
        or type(response.get("old_streams_sha256")) is not str
        or _DIGEST.fullmatch(response["old_streams_sha256"]) is None
        or response.get("old_streams_sha256")
        != expected_old_streams_sha256
        or response.get("replayed") is not False
    ):
        raise VerificationError("authenticated provider-fault result is not exact")
    replay = exchange()
    if (
        set(replay) != fields
        or replay.get("request_id") != request_id
        or replay.get("replayed") is not True
        or any(
            replay.get(name) != response.get(name)
            for name in fields - {"replayed"}
        )
    ):
        raise VerificationError("authenticated provider-fault replay was not idempotent")
    return {**response, "replay_verified": True}


def _guard_status_matches(
    value: Mapping[str, Any],
    *,
    contract_digest: str,
    rung: str,
    generation: int,
    pause_id: str,
    frozen_scopes: int,
    response_hold: bool = True,
    fault_in_progress: bool = False,
) -> bool:
    resources = value.get("resources")
    if type(resources) is not dict:
        return False
    qualification = resources.get("qualification")
    frontend = resources.get("frontend")
    if type(qualification) is not dict or set(qualification) != {
        "active", "pause_id", "lease_count", "frozen_scopes",
        "fault_in_progress", "frontend",
    }:
        return False
    try:
        stream_state = _qualification_stream_state(qualification["frontend"])
    except VerificationError:
        return False
    return (
        value.get("live_leases") == 2
        and value.get("active_rung") == rung
        and value.get("contract_digest") == contract_digest
        and value.get("generation") == generation
        and value.get("transition") is None
        and qualification["active"] is True
        and qualification["pause_id"] == pause_id
        and qualification["lease_count"] == 2
        and qualification["frozen_scopes"] == frozen_scopes
        and qualification["fault_in_progress"] is fault_in_progress
        and stream_state["response_hold"] is response_hold
        and type(frontend) is dict
        and frontend.get("committed_generation") == generation
    )


def _status_frontend(value: Mapping[str, Any]) -> dict[str, int]:
    resources = value.get("resources")
    frontend = resources.get("frontend") if type(resources) is dict else None
    if type(frontend) is not dict:
        raise VerificationError("qualification status omitted frontend counters")
    selected = {name: frontend.get(name) for name in _QUALIFICATION_FRONTEND_FIELDS}
    return _qualification_frontend(selected)


def _status_qualification(value: Mapping[str, Any]) -> dict[str, Any]:
    resources = value.get("resources")
    qualification = (
        resources.get("qualification") if type(resources) is dict else None
    )
    if type(qualification) is not dict or set(qualification) != {
        "active", "pause_id", "lease_count", "frozen_scopes",
        "fault_in_progress", "frontend",
    }:
        raise VerificationError("qualification status guard is not exact")
    return _qualification_stream_state(qualification["frontend"])


def _qualification_receipts_ready(
    state: Mapping[str, Any],
    generation: int,
    count: int,
    *,
    after_stream_id: int = 0,
) -> bool:
    streams = state.get("streams")
    return (
        state.get("response_hold") is True
        and type(streams) is list
        and len(streams) == count
        and all(
            stream.get("stream_id", 0) > after_stream_id
            and stream.get("generation") == generation
            and stream.get("socks_state") == "complete"
            and stream.get("application_client_to_backend_bytes", 0) > 0
            and stream.get("application_backend_to_client_bytes") == 0
            for stream in streams
        )
    )


def _wait_stable_frozen_receipts(
    entrypoint: Path,
    env: Mapping[str, str],
    *,
    contract_digest: str,
    rung: str,
    generation: int,
    pause_id: str,
    deadline_monotonic_ns: int,
) -> dict[str, Any]:
    """Require five identical exact transcript samples while both scopes freeze."""

    prior: list[dict[str, Any]] | None = None
    stable_samples = 0
    last: dict[str, Any] | None = None
    while time.monotonic_ns() < deadline_monotonic_ns:
        remaining = _remaining_seconds(
            deadline_monotonic_ns, 5, "old stream stabilization"
        )
        current = status(entrypoint, env, timeout=remaining)
        if current is not None and _guard_status_matches(
            current,
            contract_digest=contract_digest,
            rung=rung,
            generation=generation,
            pause_id=pause_id,
            frozen_scopes=2,
        ):
            state = _status_qualification(current)
            if _qualification_receipts_ready(state, generation, 2):
                streams = state["streams"]
                if streams == prior:
                    stable_samples += 1
                else:
                    prior = streams
                    stable_samples = 1
                last = current
                if stable_samples >= 5:
                    return current
            else:
                prior = None
                stable_samples = 0
        else:
            prior = None
            stable_samples = 0
        time.sleep(
            min(
                0.05,
                _remaining_seconds(
                    deadline_monotonic_ns, 0.05, "old stream stabilization"
                ),
            )
        )
    raise VerificationError(
        "old stream transcripts did not stabilize while frozen; "
        f"last_digest={_json_digest(last)}"
    )


def run_real_pair(
    entrypoint: Path,
    context: QualificationContext,
    provenance: Mapping[str, Any],
    stage: QualificationStage | None = None,
) -> dict[str, Any]:
    """Run the guarded two-session canary with per-scope reconnect proof."""

    stage = stage or QualificationStage("real-pair")
    stage.set("real-pair-contract")
    if context.canary_kind != "rung" or context.contract_sha256 is None:
        raise VerificationBlocked("real-pair requires an exact rung canary")
    env = _real_environment()
    (
        overall_deadline_monotonic_ns,
        cleanup_deadline_monotonic_ns,
    ) = _qualification_deadlines_ns(env)
    original_contract, runtime_contract = _real_contracts(context, env)
    runtime_contract_digest = runtime_contract.digest()
    stage.set("real-pair-baseline")
    _root_and_user_clean_checkpoint(
        provenance,
        env,
        deadline_monotonic_ns=overall_deadline_monotonic_ns,
    )
    wrappers: list[ManagedWrapper] = []
    pair_wrappers: list[ManagedWrapper] = []
    cleanup_authority: ExclusiveCleanupAuthority | None = None
    pause: QualificationPause | None = None
    temporary = tempfile.TemporaryDirectory(prefix="grok-real-pair-")
    cwd = Path(temporary.name)
    os.chmod(cwd, 0o700)
    cache_path = (
        Path(pwd.getpwuid(os.getuid()).pw_dir) / ".grok/models_cache.json"
    )
    preflight_cache = CacheSampler(cache_path)
    pair_cache: CacheSampler | None = None
    preflight_cache.start()
    preflight_cache_window: tuple[
        dict[str, Any], tuple[dict[str, Any], ...], dict[str, Any]
    ] | None = None
    pair_cache_window: tuple[
        dict[str, Any], tuple[dict[str, Any], ...], dict[str, Any]
    ] | None = None
    outputs: list[tuple[bytes, bytes]] = []
    models_stdout = b""
    models_stderr = b""
    models_lease_observed = False
    model_preflight_cleanup = False
    reconnect_proofs: list[dict[str, Any]] = []
    reconnect_duration_ms = 0
    started = time.monotonic_ns()
    primary: BaseException | None = None
    result: dict[str, Any] | None = None
    initial_scope_inventory: dict[str, Any] = {}
    repaired_scope_inventory: dict[str, Any] = {}
    repaired: Mapping[str, Any] = {}
    fault: Mapping[str, Any] = {}
    initial_execution_units: tuple[dict[str, Any], ...] = ()
    repaired_execution_units: tuple[dict[str, Any], ...] = ()
    try:
        # Refresh the real shared cache/catalog in a complete preflight epoch.
        # The two-session epoch starts only after this supervisor and every
        # scope/listener have returned to baseline.
        stage.set("real-pair-model-refresh")
        models_wrapper = _spawn_models_wrapper(entrypoint, env, context)
        wrappers.append(models_wrapper)
        models_lease_observed = process_matches(models_wrapper.identity)
        models_stdout, models_stderr = _bounded_collect(
            models_wrapper.process,
            timeout=_remaining_seconds(
                overall_deadline_monotonic_ns, 180, "model preflight"
            ),
            deadline_monotonic_ns=overall_deadline_monotonic_ns,
            termination_deadline_monotonic_ns=(
                cleanup_deadline_monotonic_ns
            ),
        )
        models_wrapper.close_pidfd()
        if (
            not models_lease_observed
            or models_wrapper.process.returncode != 0
            or not _models_output_contains(models_stdout, context.model_id)
        ):
            raise VerificationError(
                "bounded model preflight did not list the authorized model"
            )
        preflight_cache_window = preflight_cache.stop(
            overall_deadline_monotonic_ns
        )
        if not _cache_window_valid(
            *preflight_cache_window,
            allow_initial_absent=True,
        ):
            raise VerificationError(
                "model preflight exposed an unsafe cache state"
            )
        wait_clean(
            provenance,
            env,
            timeout=_remaining_seconds(
                overall_deadline_monotonic_ns, 60, "model preflight cleanup"
            ),
            deadline_monotonic_ns=overall_deadline_monotonic_ns,
        )
        model_preflight_cleanup = True
        pair_cache = CacheSampler(cache_path)
        pair_cache.start()

        stage.set("real-pair-spawn")
        session_ids = (str(uuid.uuid4()), str(uuid.uuid4()))
        pair_wrappers = [
            _spawn_real_wrapper(entrypoint, env, context, session_id, cwd)
            for session_id in session_ids
        ]
        wrappers.extend(pair_wrappers)
        stage.set("real-pair-ready")
        snapshot = wait_status(
            entrypoint,
            env,
            lambda value: (
                value.get("live_leases") == 2
                and value.get("active_rung") == context.rung
                and value.get("contract_digest") == runtime_contract_digest
                and type(value.get("resources")) is dict
                and type(value["resources"].get("frontend")) is dict
                and value["resources"]["frontend"].get("active_streams") == 0
            ),
            _remaining_seconds(
                overall_deadline_monotonic_ns, 180, "pair readiness"
            ),
        )
        stage.set("real-pair-authority")
        candidate = capture_cleanup_authority(
            account_control(),
            snapshot,
            provenance,
            provider_canary_nonce=context.nonce,
        )

        stage.set("real-pair-pause")
        pause = QualificationPause.open(
            context,
            snapshot,
            pair_wrappers,
            overall_deadline_monotonic_ns,
        )
        guarded = wait_status(
            entrypoint,
            env,
            lambda value: _guard_status_matches(
                value,
                contract_digest=runtime_contract_digest,
                rung=context.rung,
                generation=pause.generation,
                pause_id=pause.pause_id,
                frozen_scopes=2,
            ),
            _remaining_seconds(
                pause.deadline_monotonic_ns, 10, "guard acknowledgement"
            ),
        )

        stage.set("real-pair-old-generation")
        for wrapper in pair_wrappers:
            wrapper.release_qualification_child()
        for index, wrapper in enumerate(pair_wrappers):
            thaw = pause.set_frozen(
                wrapper.identity, False, pause.generation
            )
            if thaw["frozen_scopes"] != 1 - index:
                raise VerificationError(
                    "qualification did not release the exact held child scope"
                )
        old_ready = wait_status(
            entrypoint,
            env,
            lambda value: (
                _guard_status_matches(
                    value,
                    contract_digest=runtime_contract_digest,
                    rung=context.rung,
                    generation=pause.generation,
                    pause_id=pause.pause_id,
                    frozen_scopes=0,
                )
                and _qualification_receipts_ready(
                    _status_qualification(value), pause.generation, 2
                )
            ),
            _remaining_seconds(
                pause.deadline_monotonic_ns, 180, "old-generation receipts"
            ),
        )
        old_state = _status_qualification(old_ready)
        old_stream_ids = tuple(
            stream["stream_id"] for stream in old_state["streams"]
        )
        if len(set(old_stream_ids)) != 2:
            raise VerificationError(
                "old-generation qualification streams are not unique"
            )
        for index, wrapper in enumerate(pair_wrappers):
            frozen = pause.set_frozen(
                wrapper.identity, True, pause.generation
            )
            state = frozen["qualification"]
            if (
                frozen["frozen_scopes"] != index + 1
                or {item["stream_id"] for item in state["streams"]}
                != set(old_stream_ids)
                or not _qualification_receipts_ready(
                    state, pause.generation, 2
                )
            ):
                raise VerificationError(
                    "qualification old-generation receipts changed while freezing"
                )
        old_frozen = _wait_stable_frozen_receipts(
            entrypoint,
            env,
            contract_digest=runtime_contract_digest,
            rung=context.rung,
            generation=pause.generation,
            pause_id=pause.pause_id,
            deadline_monotonic_ns=min(
                pause.deadline_monotonic_ns,
                time.monotonic_ns() + 10_000_000_000,
            ),
        )
        old_frozen_state = _status_qualification(old_frozen)
        if {
            item["stream_id"] for item in old_frozen_state["streams"]
        } != set(old_stream_ids):
            raise VerificationError(
                "stable old-generation receipts changed stream identity"
            )
        expected_old_streams_sha256 = _json_digest(
            old_frozen_state["streams"]
        )

        # The children now reached exec in their exact cgroup scopes with
        # shared-leader use disabled, and are frozen with stable old-generation
        # receipts.  Only at this point can the narrow pre-exec candidate be
        # upgraded to cleanup authority.
        authorities = recovery_authorities(
            account_control(),
            expected_rung=context.rung,
            deadline_monotonic_ns=overall_deadline_monotonic_ns,
        )
        children = _bound_pause_children(pause, authorities)
        initial_scope_inventory = cgroup_scope_inventory(
            deadline_monotonic_ns=overall_deadline_monotonic_ns
        )
        assert_cgroup_scopes_match(initial_scope_inventory, authorities)
        cleanup_authority = prove_exclusive_epoch_authority(
            account_control(),
            old_frozen,
            candidate,
            authorities,
            children,
            expected_contract_digest=runtime_contract_digest,
            expected_rung=context.rung,
            require_capacity=False,
            require_qualification_guard=True,
            leader_policy="disabled-empty",
            deadline_monotonic_ns=overall_deadline_monotonic_ns,
        )
        initial_execution_units = _child_execution_unit_evidence(
            authorities, children
        )
        if len(initial_execution_units) != 2:
            raise VerificationError(
                "real-pair did not establish two independent Grok units"
            )

        stage.set("real-pair-provider-fault")
        fault = _request_provider_fault(
            env,
            context,
            old_frozen,
            pause,
            expected_old_streams_sha256,
        )
        stage.set("real-pair-repair")
        repaired = wait_status(
            entrypoint,
            env,
            lambda value: (
                _guard_status_matches(
                    value,
                    contract_digest=runtime_contract_digest,
                    rung=context.rung,
                    generation=fault["generation_after"],
                    pause_id=pause.pause_id,
                    frozen_scopes=2,
                )
                and value["resources"]["frontend"].get("active_streams") == 0
                and _status_qualification(value)["streams"] == []
            ),
            _remaining_seconds(
                pause.deadline_monotonic_ns,
                900,
                "same-rung provider repair",
            ),
        )
        repaired_authorities = recovery_authorities(
            account_control(),
            expected_rung=context.rung,
            deadline_monotonic_ns=overall_deadline_monotonic_ns,
        )
        if _bound_pause_children(pause, repaired_authorities) != children:
            raise VerificationError("qualification child bindings changed after repair")
        repaired_scope_inventory = cgroup_scope_inventory(
            deadline_monotonic_ns=overall_deadline_monotonic_ns
        )
        assert_cgroup_scopes_match(
            repaired_scope_inventory, repaired_authorities
        )
        cleanup_authority = prove_exclusive_epoch_authority(
            account_control(),
            repaired,
            candidate,
            repaired_authorities,
            children,
            expected_contract_digest=runtime_contract_digest,
            expected_rung=context.rung,
            require_capacity=False,
            require_qualification_guard=True,
            leader_policy="disabled-empty",
            deadline_monotonic_ns=overall_deadline_monotonic_ns,
        )
        repaired_execution_units = _child_execution_unit_evidence(
            repaired_authorities, children
        )
        if repaired_execution_units != initial_execution_units:
            raise VerificationError(
                "real-pair Grok execution-unit identities changed after repair"
            )

        stage.set("real-pair-reconnect")
        reconnect_started = time.monotonic_ns()
        repaired_state = _status_qualification(repaired)
        initial_quiesced = pause.quiesce(
            fault["generation_after"], None, []
        )
        if (
            initial_quiesced["accept_cursor"] < repaired_state["accept_cursor"]
            or initial_quiesced["quiesce_epoch"]
            != repaired_state["quiesce_epoch"] + 1
        ):
            raise VerificationError(
                "qualification repaired generation did not drain its accept backlog"
            )
        accept_cursor = initial_quiesced["accept_cursor"]
        quiesce_epoch = initial_quiesced["quiesce_epoch"]
        initial_quiesce_epoch = quiesce_epoch
        for index, wrapper in enumerate(pair_wrappers):
            binding = pause.bindings[index]
            child = binding["child_identity"]
            if not process_matches(wrapper.identity) or not process_matches(child):
                raise VerificationError(
                    "guarded real session exited before its reconnect proof"
                )
            thaw = pause.set_frozen(
                wrapper.identity, False, fault["generation_after"]
            )
            if thaw["frozen_scopes"] != 1:
                raise VerificationError("qualification thaw did not isolate one scope")
            remaining = (
                pause.deadline_monotonic_ns - time.monotonic_ns()
            ) / 1_000_000_000
            if remaining <= 0:
                raise VerificationError(
                    "qualification guard expired before reconnect proof"
                )
            observed = wait_status(
                entrypoint,
                env,
                lambda value, cursor=accept_cursor: (
                    _guard_status_matches(
                        value,
                        contract_digest=runtime_contract_digest,
                        rung=context.rung,
                        generation=fault["generation_after"],
                        pause_id=pause.pause_id,
                        frozen_scopes=1,
                    )
                    and _qualification_receipts_ready(
                        _status_qualification(value),
                        fault["generation_after"],
                        1,
                        after_stream_id=cursor,
                    )
                ),
                min(180.0, remaining),
            )
            observed_state = _status_qualification(observed)
            receipt = dict(observed_state["streams"][0])
            frozen = pause.set_frozen(
                wrapper.identity, True, fault["generation_after"]
            )
            frozen_state = frozen["qualification"]
            if (
                frozen["frozen_scopes"] != 2
                or not _qualification_receipts_ready(
                    frozen_state,
                    fault["generation_after"],
                    1,
                    after_stream_id=accept_cursor,
                )
                or frozen_state["streams"][0]["stream_id"]
                != receipt["stream_id"]
            ):
                raise VerificationError(
                    "qualification repaired stream changed while refreezing"
                )
            quiesced = pause.quiesce(
                fault["generation_after"],
                wrapper.identity,
                [receipt["stream_id"]],
            )
            if (
                quiesced["accept_cursor"] < receipt["stream_id"]
                or quiesced["accept_cursor"] < accept_cursor
                or quiesced["quiesce_epoch"] != quiesce_epoch + 1
            ):
                raise VerificationError(
                    "qualification reconnect quiescence did not advance exactly"
                )
            reconnect_proofs.append(
                {
                    "index": index,
                    "stream_id": receipt["stream_id"],
                    "generation": receipt["generation"],
                    "accept_cursor_before": accept_cursor,
                    "accept_cursor_after": quiesced["accept_cursor"],
                    "quiesce_epoch": quiesced["quiesce_epoch"],
                    "receipt_sha256": _json_digest(receipt),
                }
            )
            accept_cursor = quiesced["accept_cursor"]
            quiesce_epoch = quiesced["quiesce_epoch"]
        reconnect_duration_ms = (
            time.monotonic_ns() - reconnect_started
        ) // 1_000_000

        stage.set("real-pair-resume")
        disarmed = pause.disarm(fault["generation_after"])
        if (
            disarmed["response_hold"] is not False
            or disarmed["streams"]
            or disarmed["quiesce_epoch"] != quiesce_epoch
            or disarmed["accept_cursor"] != accept_cursor
        ):
            raise VerificationError(
                "qualification response hold did not disarm from quiescence"
            )
        for index, wrapper in enumerate(pair_wrappers):
            resumed = pause.set_frozen(
                wrapper.identity,
                False,
                fault["generation_after"],
            )
            if resumed["frozen_scopes"] != 1 - index:
                raise VerificationError(
                    "qualification did not thaw every exact scope"
                )

        stage.set("real-pair-completion")
        outputs = _bounded_collect_pair(
            pair_wrappers,
            timeout=_remaining_seconds(
                overall_deadline_monotonic_ns, 600, "pair completion"
            ),
            deadline_monotonic_ns=overall_deadline_monotonic_ns,
            termination_deadline_monotonic_ns=(
                cleanup_deadline_monotonic_ns
            ),
        )
        parsed: list[dict[str, Any]] = []
        for index, (stdout, _stderr) in enumerate(outputs):
            try:
                value = json.loads(stdout)
                text_value = json.loads(value["text"])
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
                raise VerificationError(
                    "real Grok output is not the fixed JSON result"
                ) from exc
            if (
                type(value) is not dict
                or value.get("sessionId") != session_ids[index]
                or text_value
                != {"token": "GROK_REMOTE_QUALIFICATION_OK"}  # LEAKSCAN-EXEMPT: public fixed canary
                or type(value.get("requestId")) is not str
                or not value.get("requestId")
            ):
                raise VerificationError("real Grok output failed its fixed schema")
            parsed.append(value)
        post = wait_clean(
            provenance,
            env,
            timeout=_remaining_seconds(
                overall_deadline_monotonic_ns, 60, "pair cleanup proof"
            ),
            deadline_monotonic_ns=overall_deadline_monotonic_ns,
        )
        for wrapper in wrappers:
            wrapper.close_pidfd()
        if pair_cache is None:
            raise VerificationError("pair cache sampler was not started")
        pair_cache_window = pair_cache.stop(
            overall_deadline_monotonic_ns
        )
        before_cache, during_cache, after_cache = pair_cache_window
        cache_valid = _cache_window_valid(
            before_cache,
            during_cache,
            after_cache,
            allow_initial_absent=False,
        )
        transport_ms = (time.monotonic_ns() - started) // 1_000_000
        watchdog = repaired.get("watchdog")
        last_repair = (
            watchdog.get("last_repair") if type(watchdog) is dict else None
        )
        single_repair = (
            fault["generation_after"] == fault["generation_before"] + 1
            and repaired.get("generation") == fault["generation_after"]
            and type(watchdog) is dict
            and watchdog.get("same_rung_repaired") == [context.rung]
            and type(last_repair) is dict
            and last_repair.get("reason") == "qualification-fault"
            and last_repair.get("rung") == context.rung
            and last_repair.get("generation_before")
            == fault["generation_before"]
            and last_repair.get("generation_after") == fault["generation_after"]
            and last_repair.get("same_rung") is True
            and last_repair.get("succeeded") is True
        )
        clients_reconnected = (
            len(reconnect_proofs) == 2
            and [item["index"] for item in reconnect_proofs] == [0, 1]
            and len({item["stream_id"] for item in reconnect_proofs}) == 2
            and all(
                item["generation"] == fault["generation_after"]
                and item["stream_id"] > item["accept_cursor_before"]
                and item["accept_cursor_after"] >= item["stream_id"]
                and type(item["receipt_sha256"]) is str
                and _DIGEST.fullmatch(item["receipt_sha256"]) is not None
                for item in reconnect_proofs
            )
            and [item["quiesce_epoch"] for item in reconnect_proofs]
            == [initial_quiesce_epoch + 1, initial_quiesce_epoch + 2]
        )
        result = {
            "sessions_requested": 2,
            "sessions_completed": len(outputs),
            "active_rung": context.rung,
            "rung_qualification_sha256": (
                original_contract.rung_qualification_digest(context.rung)
            ),
            "model_id": context.model_id,
            "shared_owner_epoch": guarded.get("owner_epoch")
            == repaired.get("owner_epoch"),
            "shared_generation": single_repair,
            "shared_contract": (
                guarded.get("contract_digest") == runtime_contract_digest
                and repaired.get("contract_digest") == runtime_contract_digest
            ),
            "independent_grok_units": len(initial_execution_units),
            "shared_leader_disabled": (
                cleanup_authority.leader_policy == "disabled-empty"
            ),
            "leader_socket_count": 0,
            "unique_session_ids": len({value["sessionId"] for value in parsed}),
            "outputs_valid": len(parsed) == 2,
            "exit_codes_zero": all(
                wrapper.process.returncode == 0 for wrapper in wrappers
            ),
            "cache_before_valid": before_cache.get("state") == "regular",
            "cache_during_valid": cache_valid,
            "cache_after_valid": after_cache.get("state") == "regular",
            "cache_identity_safe": cache_valid,
            "provider_fault_authenticated": (
                fault["replayed"] is False and fault["replay_verified"] is True
            ),
            "single_repair_observed": single_repair,
            "clients_survived_repair": clients_reconnected,
            "reconnect_duration_ms": reconnect_duration_ms,
            "transport_duration_ms": transport_ms,
            "cleanup_proved": post is not None,
            "detail_sha256": _json_digest(
                {
                    "before_cache": before_cache,
                    "during_cache_sha256": _json_digest(during_cache),
                    "after_cache": after_cache,
                    "preflight_cache": preflight_cache_window,
                    "preflight_cache_changed": (
                        _cache_refresh_valid(*preflight_cache_window)
                        if preflight_cache_window is not None
                        else False
                    ),
                    "fault": fault,
                    "old_stream_ids": list(old_stream_ids),
                    "old_streams_sha256": expected_old_streams_sha256,
                    "models_lease_observed": models_lease_observed,
                    "model_preflight_cleanup": model_preflight_cleanup,
                    "models_stdout_sha256": hashlib.sha256(
                        models_stdout
                    ).hexdigest(),
                    "models_stderr_sha256": hashlib.sha256(
                        models_stderr
                    ).hexdigest(),
                    "original_contract_sha256": original_contract.digest(),
                    "runtime_contract_sha256": runtime_contract_digest,
                    "leader_policy": cleanup_authority.leader_policy,
                    "execution_units_sha256": _json_digest(
                        list(initial_execution_units)
                    ),
                    "execution_units_stable": (
                        initial_execution_units == repaired_execution_units
                    ),
                    "initial_scope_inventory_sha256": _json_digest(
                        initial_scope_inventory
                    ),
                    "repaired_scope_inventory_sha256": _json_digest(
                        repaired_scope_inventory
                    ),
                    "reconnect_proofs": reconnect_proofs,
                    "initial_quiesce": initial_quiesced,
                    "output_sha256s": [
                        hashlib.sha256(item[0]).hexdigest() for item in outputs
                    ],
                    "stderr_sha256s": [
                        hashlib.sha256(item[1]).hexdigest() for item in outputs
                    ],
                }
            ),
            "blocked_reason": None,
        }
        boolean_fields = (
            "shared_owner_epoch", "shared_generation", "shared_contract",
            "shared_leader_disabled",
            "outputs_valid", "exit_codes_zero", "cache_before_valid",
            "cache_during_valid", "cache_after_valid", "cache_identity_safe",
            "provider_fault_authenticated", "single_repair_observed",
            "clients_survived_repair", "cleanup_proved",
        )
        if (
            result["sessions_completed"] != 2
            or result["active_rung"] != context.rung
            or result["model_id"] != context.model_id
            or result["independent_grok_units"] != 2
            or result["leader_socket_count"] != 0
            or result["unique_session_ids"] != 2
            or not model_preflight_cleanup
            or any(result[name] is not True for name in boolean_fields)
            or not 0 <= result["reconnect_duration_ms"] <= 900_000
            or not 0 <= result["transport_duration_ms"] <= 900_000
        ):
            raise VerificationError("real-pair acceptance criteria failed")
    except BaseException as exc:
        primary = exc
    finally:
        cleanup_errors: list[str] = []
        if preflight_cache._thread.is_alive():
            try:
                preflight_cache.stop(cleanup_deadline_monotonic_ns)
            except BaseException as exc:
                cleanup_errors.append(f"{type(exc).__name__}: {exc}")
        if pair_cache is not None and pair_cache._thread.is_alive():
            try:
                pair_cache.stop(cleanup_deadline_monotonic_ns)
            except BaseException as exc:
                cleanup_errors.append(f"{type(exc).__name__}: {exc}")
        try:
            cleanup(
                entrypoint,
                env,
                wrappers,
                provenance,
                cleanup_authority,
                expected_rung=context.rung,
                expected_contract_digest=runtime_contract_digest,
                require_capacity=False,
                require_qualification_guard=True,
                deadline_monotonic_ns=cleanup_deadline_monotonic_ns,
            )
        except BaseException as cleanup_error:
            cleanup_errors.append(
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
        if pause is not None:
            try:
                pause.close()
            except BaseException as exc:
                cleanup_errors.append(f"{type(exc).__name__}: {exc}")
        try:
            temporary.cleanup()
        except BaseException as exc:
            cleanup_errors.append(f"{type(exc).__name__}: {exc}")
        if cleanup_errors:
            detail = "cleanup failures: " + "; ".join(cleanup_errors)
            if primary is not None:
                detail = (
                    f"primary failure: {type(primary).__name__}: {primary}; "
                    + detail
                )
            primary = QualificationStageError("real-pair-cleanup", detail)
    if primary is not None:
        raise primary
    assert result is not None
    return result


def _default_observations(step: str) -> dict[str, Any]:
    digest = "0" * 64
    resource_contract, resource_observed = _empty_compact_resources()
    if step == "load32":
        return {
            "clients_requested": 32, "clients_completed": 0,
            "active_rung": "direct", "shared_owner_epoch": False,
            "shared_generation": False, "shared_contract": False,
            "unique_leaders": 0, "overload_rejected": False,
            "byte_path_verified": False, "host_limits_captured": False,
            "host_limits_sha256": digest,
            "resource_contract": resource_contract,
            "resource_observed": resource_observed,
            "resource_gate_passed": False, "cleanup_proved": False,
            "ready_duration_ms": 0, "detail_sha256": digest,
        }
    if step == "fault-recovery":
        return {
            "active_rung": "direct", "supervisor_loss_exact": False,
            "wrapper_failed_closed": False, "descendant_contained": False,
            "first_recovery_applied": False, "second_recovery_noop": False,
            "recovery_duration_ms": 0, "resource_gate_passed": False,
            "host_limits_sha256": digest,
            "resource_contract": resource_contract,
            "resource_observed": resource_observed,
            "cleanup_proved": False, "detail_sha256": digest,
        }
    return {
        "sessions_requested": 2, "sessions_completed": 0,
        "active_rung": "direct", "model_id": "unknown",
        "rung_qualification_sha256": digest,
        "shared_owner_epoch": False, "shared_generation": False,
        "shared_contract": False, "independent_grok_units": 0,
        "shared_leader_disabled": False, "leader_socket_count": 0,
        "unique_session_ids": 0, "outputs_valid": False,
        "exit_codes_zero": False, "cache_before_valid": False,
        "cache_during_valid": False, "cache_after_valid": False,
        "cache_identity_safe": False, "provider_fault_authenticated": False,
        "single_repair_observed": False, "clients_survived_repair": False,
        "reconnect_duration_ms": None, "transport_duration_ms": 0,
        "cleanup_proved": False, "detail_sha256": digest,
        "blocked_reason": "verification-not-run",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument(
        "--mode",
        required=True,
        choices=("load32", "fault-recovery", "real-pair"),
    )
    return result


def main() -> int:
    args = parser().parse_args()
    stage = QualificationStage(args.mode)
    started_unix_ns = time.time_ns()
    started_ns = time.monotonic_ns()
    context: QualificationContext | None = None
    contract_sha256 = "0" * 64
    observations = _default_observations(args.mode)
    status_name = "failed"
    error_code: str | None = None
    error_sha256: str | None = None
    returncode = 2
    sampler: ResourceSampler | None = None
    resource_evidence: Mapping[str, Any] | None = None
    cleanup_deadline_monotonic_ns: int | None = None
    try:
        if Path.cwd().resolve(strict=True) != ROOT.resolve(strict=True):
            raise VerificationBlocked("qualification cwd is not the exact release")
        context = QualificationContext.from_environment()
        _, cleanup_deadline_monotonic_ns = _qualification_deadlines_ns(
            os.environ
        )
        # Grok creates/atomically replaces its shared model cache.  The
        # authenticated verifier fixes a private umask before any workload so
        # a host-wide cooperative umask cannot make that cache group-writable.
        os.umask(0o077)
        if context.contract_sha256 is not None:
            contract_sha256 = context.contract_sha256
        # Exercise the installed admission gate, not the release payload it
        # eventually execs.  The selector's entrypoint digest binds this fixed
        # gate, which in turn revalidates the selected payload against the
        # immutable release manifest before every workload launch.
        stage.set(f"{args.mode}-provenance")
        entrypoint = (
            _qualification_home(context.profile_sha256)
            / ".local/bin/grok-remote"
        )
        provenance = release_provenance(entrypoint)
        if provenance.get("release_id") != context.release_id:
            raise VerificationBlocked("qualification release provenance is mismatched")
        if args.mode in {"load32", "fault-recovery"}:
            stage.set(f"{args.mode}-contract")
            contract_sha256 = _release_contract(context)
            stage.set(f"{args.mode}-resource-sampler")
            sampler = ResourceSampler()
            sampler.start()
            if args.mode == "load32":
                full_result = run_load(
                    entrypoint, 32, provenance, contract_sha256, stage
                )
                resource_evidence = full_result.get("resources")
                observations = _compact_load(full_result, contract_sha256)
            else:
                with tempfile.TemporaryDirectory(prefix="grok-fault-marker-") as directory:
                    marker_root = Path(directory)
                    os.chmod(marker_root, 0o700)
                    result = run_fault(
                        entrypoint,
                        marker_root / "descendant.json",
                        provenance,
                        contract_sha256,
                        stage,
                    )
                resource_evidence = result.get("resources")
                observations = _compact_fault(
                    result,
                    (time.monotonic_ns() - started_ns) // 1_000_000,
                    contract_sha256,
                )
        else:
            assert context.contract_sha256 is not None
            contract_sha256 = context.contract_sha256
            observations = run_real_pair(entrypoint, context, provenance, stage)
        if sampler is not None:
            stage.set(f"{args.mode}-resource-sampler")
            sampled = sampler.stop(cleanup_deadline_monotonic_ns)
            sampler = None
            if (
                type(resource_evidence) is not dict
                or type(resource_evidence.get("baseline")) is not dict
                or type(resource_evidence.get("gate")) is not dict
            ):
                raise VerificationError("qualification omitted resource gate evidence")
            assert_resource_sampler(
                sampled,
                expected_cgroup=resource_evidence["baseline"]["cgroup"],
                contract_gate=resource_evidence["gate"],
            )
        if args.mode == "real-pair" and observations["blocked_reason"] is not None:
            status_name = "blocked"
            error_code = "real-pair-blocked"
            error_sha256 = hashlib.sha256(
                str(observations["blocked_reason"]).encode("utf-8", "replace")
            ).hexdigest()
            returncode = 3
        else:
            status_name = "passed"
            returncode = 0
    except QualificationStageError as exc:
        status_name = "failed"
        error_code = exc.error_code
        error_sha256 = hashlib.sha256(
            str(exc).encode("utf-8", "replace")
        ).hexdigest()
        returncode = 2
    except VerificationBlocked as exc:
        status_name = "blocked"
        error_code = f"{args.mode}-blocked"
        error_sha256 = hashlib.sha256(str(exc).encode("utf-8", "replace")).hexdigest()
        returncode = 3
    except Exception as exc:
        status_name = "failed"
        error_code = stage.error_code
        error_sha256 = hashlib.sha256(str(exc).encode("utf-8", "replace")).hexdigest()
        returncode = 2
    finally:
        if sampler is not None:
            try:
                sampler.stop(cleanup_deadline_monotonic_ns)
            except BaseException as exc:
                status_name = "failed"
                error_code = f"{args.mode}-resource-sampler"
                error_sha256 = hashlib.sha256(
                    str(exc).encode("utf-8", "replace")
                ).hexdigest()
                returncode = 2
    completed_unix_ns = time.time_ns()
    duration_ms = min(900_000, (time.monotonic_ns() - started_ns) // 1_000_000)
    if context is None:
        release_id = os.environ.get("GROK_RELEASE_CANARY_RELEASE_ID", "0" * 64)
        nonce = os.environ.get("GROK_RELEASE_CANARY_NONCE", "0" * 64)
        canary_kind = os.environ.get("GROK_RELEASE_CANARY_KIND", "release")
        rung = os.environ.get("GROK_RELEASE_CANARY_RUNG", "direct")
        route_profile = os.environ.get(
            "GROK_RELEASE_CANARY_ROUTE_PROFILE", "direct"
        )
        grok_release_id = os.environ.get("GROK_RELEASE_CANARY_GROK_RELEASE", "unknown")
        model_id = os.environ.get("GROK_RELEASE_CANARY_MODEL", "unknown")
        profile_sha256 = os.environ.get(
            "GROK_RELEASE_CANARY_PROFILE_SHA256"
        )
    else:
        release_id = context.release_id
        nonce = context.nonce
        canary_kind = context.canary_kind
        rung = context.rung
        route_profile = context.route_profile
        grok_release_id = context.grok_release_id
        model_id = context.model_id
        profile_sha256 = context.profile_sha256
    record = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "kind": QUALIFICATION_KIND,
        "step": args.mode,
        "release_id": release_id,
        "canary_nonce": nonce,
        "canary_kind": canary_kind,
        "rung": rung,
        "route_profile": route_profile,
        "contract_sha256": contract_sha256,
        "grok_release_id": grok_release_id,
        "model_id": model_id,
        "profile_sha256": profile_sha256,
        "status": status_name,
        "started_unix_ns": started_unix_ns,
        "completed_unix_ns": completed_unix_ns,
        "duration_ms": duration_ms,
        "observations": observations,
        "error_code": error_code,
        "error_sha256": error_sha256,
    }
    encoded = json.dumps(
        record, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii") + b"\n"
    if len(encoded) > MAX_RUNTIME_RECORD:
        raise SystemExit(2)
    os.write(sys.stdout.fileno(), encoded)
    if returncode != 0:
        print("qualification_verifier: nonpassing result", file=sys.stderr)
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
