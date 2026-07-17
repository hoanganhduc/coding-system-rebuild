#!/usr/bin/env python3
"""Loopback/scripted tests for the multi-session supervisor state machine."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path
import random
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from grok_ms.contract import (
    Endpoint,
    ResourceLimits,
    RouteContract,
    RouteMode,
    StabilityPolicy,
    TimeoutPolicy,
    VpnPolicy,
)
from grok_ms.ipc import SeqPacketConnection
from grok_ms.frontend import FrontendGauges, FrontendQualificationStream
from grok_ms.grok_exec import VerifiedGrokExecutable
from grok_ms.detached_scope import DetachedScopeStore
from grok_ms.process_scope import (
    LinuxCgroupV2Scope,
    ScopeError,
    ScopeHandle,
    ScopeIdentity,
    ScopeResidueError,
)
from grok_ms.providers import (
    ListenerIdentity,
    PathIdentity,
    PrivilegedResourceIdentity,
    ProviderError,
    ProviderCancelled,
    ProviderResidueError,
    ProviderTimeout,
    ProviderRequest,
    ProviderResourceGraph,
    ProviderScopeRecord,
    QualificationEvidence,
    ResidueReport,
    ScriptedProvider,
    ScriptedStep,
    TransitionDeadline,
)
from grok_ms.runtime import (
    _atomic_create_json,
    EffectIntent,
    FenceRecord,
    FenceStore,
    IntentStore,
    ProcessIdentity,
    SecureRuntime,
    RuntimeSecurityError,
    current_process_identity,
    process_can_still_execute,
    process_matches,
    read_boot_id,
    read_pid_start_ticks,
)
import grok_ms.supervisor as supervisor_module
from grok_ms.supervisor import RecoveryRequired, Supervisor
from grok_ms.supervisor import (
    ChildRecoveryRecord,
    ProbeRecoveryRecord,
    ProviderRecoveryRecord,
    RecoveryStore,
    recover_offline,
)
from grok_ms.config import _release_id
from grok_ms.contract import canonical_json_bytes


def unused_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def contract(
    *,
    ladder: tuple[str, ...] = ("direct",),
    max_leases: int = 4,
    max_control_connections: int = 8,
    public_port: int | None = None,
    model_id: str = "grok-4.5",
) -> RouteContract:
    chosen_public = public_port or unused_port()
    chosen_private: list[int] = []
    while len(chosen_private) < 3:
        candidate = unused_port()
        if candidate != chosen_public and candidate not in chosen_private:
            chosen_private.append(candidate)
    return RouteContract(
        schema_version=1,
        protocol_version=1,
        release_id="test-release-1",
        model_id=model_id,
        route_mode=RouteMode.AUTO,
        forced_host=None,
        home_endpoints=(),
        phone_node_id=None,
        allow_direct="direct" in ladder,
        ladder=ladder,
        routing_config_digest="a" * 64,
        probe_policy_version="probe-test-v1",
        timeout_policy=TimeoutPolicy(
            connect_ms=1_000,
            probe_ms=1_000,
            transition_ms=200_000 if "vpn" in ladder else 2_000,
            stop_ms=1_000,
        ),
        stability_policy=StabilityPolicy(
            version="same-exit-test-v1",
            sample_count=1,
            sample_interval_ms=0,
            require_same_exit=True,
        ),
        vpn_policy=VpnPolicy(
            namespace="grokvpn",
            max_tries=2,
            ranking_version="rank-test-v1",
            countries=("JP",),
            blocked_countries=("CN",),
        ),
        helper_release_ids=(
            ("relay", "test-release-1"),
            ("vpn-broker", "test-release-1"),
        ),
        grok_release_id="grok-test-1",
        public_endpoint=Endpoint("127.0.0.1", chosen_public),
        private_ports=tuple(chosen_private),
        limits=ResourceLimits(
            max_leases=max_leases,
            max_control_connections=max_control_connections,
            max_frontend_streams=4,
            max_packet_bytes=65_536,
            per_stream_buffer_bytes=4_096,
            total_buffer_bytes=16_384,
        ),
    )


def evidence(
    endpoint: Endpoint,
    wanted: ProviderRequest,
    _deadline=None,
    _cancellation=None,
) -> QualificationEvidence:
    identity = "203.0.113.20" if wanted.rung == "direct" else "198.51.100.40"
    return QualificationEvidence(
        endpoint=endpoint,
        model_id=wanted.model_id,
        exit_identity=identity,
        country_code="JP",
        dns_path_verified=True,
        byte_path_verified=True,
        stability_samples=(identity,),
    )


def wrapper_record() -> dict[str, object]:
    identity = current_process_identity()
    return {
        "pid": identity.pid,
        "pid_start_ticks": identity.start_ticks,
        "boot_id": identity.boot_id,
    }


def dead_identity() -> ProcessIdentity:
    process = subprocess.Popen(["sleep", "10"])
    identity = ProcessIdentity(
        process.pid,
        read_pid_start_ticks(process.pid),
        read_boot_id(),
    )
    process.terminate()
    process.wait(timeout=2)
    return identity


def barriered_zombie() -> tuple[int, ProcessIdentity]:
    """Return an unreaped child whose exact identity is still in ``/proc``."""

    barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        os.close(barrier_write)
        try:
            os.read(barrier_read, 1)
        finally:
            os.close(barrier_read)
        os._exit(0)
    os.close(barrier_read)
    identity = ProcessIdentity(
        child,
        read_pid_start_ticks(child),
        read_boot_id(),
    )
    os.write(barrier_write, b"1")
    os.close(barrier_write)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        record = (Path("/proc") / str(child) / "stat").read_text(encoding="ascii")
        closing = record.rfind(")")
        fields = record[closing + 2 :].split() if closing >= 0 else []
        if fields and fields[0] == "Z":
            return child, identity
        time.sleep(0.005)
    os.waitpid(child, 0)
    raise AssertionError("child did not enter zombie state")


def recovery_workspace(root: Path, request_value: ProviderRequest) -> Path:
    material = b"\0".join(
        (
            request_value.owner_epoch.encode("ascii"),
            str(request_value.generation).encode("ascii"),
            str(request_value.private_endpoint.port).encode("ascii"),
        )
    )
    return root / "p" / hashlib.sha256(material).hexdigest()[:24]


class ExactRecoveryProvider:
    def __init__(self, provider_root: Path, marker: Path | None = None) -> None:
        self.provider_root = provider_root
        self.marker = marker
        self.calls: list[tuple[str, int, bool]] = []

    def recover(self, request, resources, _deadline):
        self.calls.append((request.rung, request.generation, resources is not None))
        if self.marker is not None:
            self.marker.unlink(missing_ok=True)
        if resources is not None:
            for identity in resources.paths:
                path = Path(identity.path)
                if path.exists():
                    info = path.lstat()
                    self.assert_identity = (
                        info.st_dev,
                        info.st_ino,
                        info.st_uid,
                        info.st_mode & 0o7777,
                    )
                    expected = (
                        identity.device,
                        identity.inode,
                        identity.uid,
                        identity.mode,
                    )
                    if self.assert_identity != expected:
                        raise AssertionError("recovery path identity changed")
                    path.unlink()
            runtime = Path(resources.runtime_dir)
            for path in (runtime, runtime.parent):
                try:
                    path.rmdir()
                except OSError:
                    break
        return ResidueReport(True, ())


class EffectThenOrdinaryErrorProvider:
    def __init__(self, marker: Path) -> None:
        self.marker = marker
        self.calls: list[str] = []

    def start(self, _request, _deadline, _qualifier, _cancellation=None):
        self.calls.append("start")
        self.marker.parent.mkdir(mode=0o700, exist_ok=True)
        self.marker.write_text("effect", encoding="ascii")
        os.chmod(self.marker, 0o600)
        raise ProviderError("ordinary-start-error-after-effect")

    def recover(self, _request, _resources, _deadline):
        self.calls.append("recover")
        raise ProviderResidueError("injected effect remains")


class FakeScopeBackend:
    """Deterministic semantic-fault seam; production never selects this."""

    def __init__(self, fail_at: str | None = None) -> None:
        self.fail_at = fail_at
        self.calls: list[tuple[str, str | None]] = []
        self.freeze_timeouts: list[float] = []
        self.thaw_timeouts: list[float] = []
        self.counter = 0
        self.scope_socket_inodes: dict[str, frozenset[int]] = {}
        self.tcp_connection_inodes: dict[tuple[str, int, str, int], int] = {}

    def plan(self) -> ScopeIdentity:
        self.counter += 1
        self.calls.append(("plan", None))
        return ScopeIdentity(
            backend="cgroup-v2-v1",
            parent_path="/sys/fs/cgroup/fake-parent",
            parent_device=1,
            parent_inode=2,
            scope_path=f"/sys/fs/cgroup/fake-parent/grok-ms-{self.counter:024x}",
            scope_device=None,
            scope_inode=None,
        )

    def create(self, planned: ScopeIdentity) -> ScopeHandle:
        self.calls.append(("create", None))
        if self.fail_at == "create-before":
            raise ScopeError("injected failure after PREPARED")
        created = dataclasses.replace(
            planned, scope_device=1, scope_inode=100 + self.counter
        )
        if self.fail_at == "create-after":
            raise ScopeError("injected failure after mkdir")
        return ScopeHandle(created, os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC))

    def attach(self, _handle: ScopeHandle, _child: ProcessIdentity) -> None:
        self.calls.append(("attach", None))
        if self.fail_at == "attach-before":
            raise ScopeError("injected failure after inode record")
        if self.fail_at == "attach-after":
            raise ScopeError("injected failure after PID move")

    def freeze(self, handle: ScopeHandle, timeout_seconds: float) -> None:
        self.calls.append(("freeze", handle.identity.scope_path))
        self.freeze_timeouts.append(timeout_seconds)
        freeze_number = sum(name == "freeze" for name, _value in self.calls)
        if self.fail_at in {"freeze", f"freeze-{freeze_number}"}:
            raise ScopeError("injected freeze failure")
        if self.fail_at == f"freeze-uncertain-{freeze_number}":
            raise ScopeResidueError("injected uncertain freeze rollback")

    def thaw(self, handle: ScopeHandle, timeout_seconds: float) -> None:
        self.calls.append(("thaw", handle.identity.scope_path))
        self.thaw_timeouts.append(timeout_seconds)
        if self.fail_at == "thaw":
            raise ScopeError("injected thaw failure")

    def frozen_socket_inodes(
        self, handle: ScopeHandle, deadline_monotonic_ns: int
    ) -> frozenset[int]:
        self.calls.append(("socket-inodes", handle.identity.scope_path))
        if deadline_monotonic_ns <= time.monotonic_ns():
            raise ScopeError("injected ownership deadline")
        return self.scope_socket_inodes.get(
            handle.identity.scope_path, frozenset()
        )

    def tcp_connection_inode(
        self,
        client_host: str,
        client_port: int,
        frontend_host: str,
        frontend_port: int,
        deadline_monotonic_ns: int,
    ) -> int | None:
        self.calls.append(("tcp-inode", None))
        if deadline_monotonic_ns <= time.monotonic_ns():
            raise ScopeError("injected ownership deadline")
        return self.tcp_connection_inodes.get(
            (client_host, client_port, frontend_host, frontend_port)
        )

    def reconcile(
        self,
        _scope: ScopeIdentity,
        phase: str,
        _child: ProcessIdentity,
        pidfd: int | None,
        _timeout_seconds: float,
        *,
        handle: ScopeHandle | None = None,
    ) -> None:
        self.calls.append(("reconcile", phase))
        if self.fail_at == "reconcile":
            raise ScopeError("injected scope residue")
        if pidfd is not None:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                select.select([pidfd], [], [], 2)
            except (AttributeError, OSError):
                pass

    def force_kill(
        self,
        scope: ScopeIdentity,
        *,
        handle: ScopeHandle | None = None,
    ) -> None:
        del scope, handle
        self.calls.append(("force-kill", None))


class QualificationFrontendStub:
    """Exact qualification seam for supervisor protocol tests."""

    def __init__(self, generation: int = 1) -> None:
        self.generation: int | None = generation
        self.accepting = True
        self.response_hold = False
        self.accept_cursor = 0
        self.quiesce_epoch = 0
        self.streams: list[dict[str, object]] = []
        self.qualification_gate_closed = False

    def gauges(self) -> FrontendGauges:
        client_bytes = sum(
            int(item["client_to_backend_bytes"]) for item in self.streams
        )
        server_bytes = sum(
            int(item["backend_to_client_bytes"]) for item in self.streams
        )
        return FrontendGauges(
            listener_alive=True,
            accepting=self.accepting,
            closing=False,
            committed_generation=self.generation,
            active_streams=len(self.streams),
            peak_active_streams=len(self.streams),
            buffered_bytes=0,
            peak_buffered_bytes=0,
            stream_limit=16,
            backlog_limit=16,
            per_stream_buffer_limit=4_096,
            total_buffer_limit=65_536,
            accepted_streams=self.accept_cursor,
            backend_connected_streams=len(self.streams),
            client_to_backend_bytes=client_bytes,
            backend_to_client_bytes=server_bytes,
            completed_streams=0,
            revoked_streams=0,
            rejected_uncommitted=0,
            rejected_overload=0,
            backend_connect_failures=0,
        )

    def qualification_state(self) -> dict[str, object]:
        return {
            "response_hold": self.response_hold,
            "accept_cursor": self.accept_cursor,
            "quiesce_epoch": self.quiesce_epoch,
            "streams": [dict(item) for item in self.streams],
        }

    def qualification_peers(self) -> dict[int, tuple[str, int, str, int]]:
        return {
            int(item["stream_id"]): (
                "127.0.0.1",
                30_000 + int(item["stream_id"]),
                "127.0.0.1",
                1_080,
            )
            for item in self.streams
        }

    def qualification_arm(self) -> SimpleNamespace:
        if self.generation is None or not self.accepting or self.streams:
            raise AssertionError("qualification stub was not empty at arm")
        self.response_hold = True
        return SimpleNamespace(generation=self.generation)

    def qualification_disarm(self) -> None:
        self.response_hold = False

    def qualification_reopen(
        self, generation: int, _timeout: float = 1.0
    ) -> None:
        if self.generation != generation:
            raise AssertionError("qualification stub generation changed")
        self.qualification_gate_closed = False
        self.accepting = True

    def set_ready_streams(self, generation: int, count: int = 2) -> None:
        self.streams = []
        for index in range(count):
            self.accept_cursor += 1
            self.streams.append(
                {
                    "stream_id": self.accept_cursor,
                    "generation": generation,
                    "socks_state": "complete",
                    "client_to_backend_bytes": 64 + index,
                    "backend_to_client_bytes": 12,
                    "application_client_to_backend_bytes": 32 + index,
                    "application_backend_to_client_bytes": 0,
                }
            )

    def qualification_revoke(
        self, expected_stream_ids: set[int], _timeout: float
    ) -> tuple[FrontendQualificationStream, ...]:
        if {int(item["stream_id"]) for item in self.streams} != expected_stream_ids:
            raise AssertionError("qualification stub stream IDs changed")
        result = tuple(
            FrontendQualificationStream(**item) for item in self.streams
        )
        self.streams = []
        self.accepting = False
        self.generation = None
        return result

    def qualification_quiesce(
        self, generation: int, _timeout: float
    ) -> dict[str, int]:
        self.streams = []
        self.quiesce_epoch += 1
        self.generation = generation
        self.accepting = False
        self.qualification_gate_closed = True
        return {
            "accept_cursor": self.accept_cursor,
            "quiesce_epoch": self.quiesce_epoch,
            "generation": generation,
        }

    def revoke(self, _timeout: float) -> bool:
        self.streams = []
        self.accepting = False
        self.generation = None
        return True

    def close(self, _timeout: float) -> None:
        self.revoke(_timeout)

    def commit_generation(self, committed, *, revoke_timeout: float) -> None:
        del revoke_timeout
        self.generation = committed.generation
        self.accepting = True


def register_packet(wanted: RouteContract, request_id: str | None = None) -> dict:
    return {
        "type": "register",
        "schema_version": 1,
        "protocol_version": 1,
        "request_id": request_id or str(uuid.uuid4()),
        "lease_nonce": "b" * 32,
        "wrapper": wrapper_record(),
        "contract": wanted.to_dict(),
    }


def request(connection: SeqPacketConnection, payload: dict, fds=()) -> dict:
    connection.send(payload, fds)
    return connection.recv().payload


def wait_for_decimal_file(path: Path, timeout: float = 5.0) -> int:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            value = path.read_text(encoding="ascii")
        except FileNotFoundError:
            value = ""
        if value.isdecimal():
            return int(value)
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for decimal marker: {path.name}")


class RunningSupervisor:
    def __init__(
        self,
        wanted: RouteContract,
        provider: ScriptedProvider,
        *,
        start_watchdog: bool = False,
        health_check=None,
        process_scopes=None,
        qualifier=evidence,
    ) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "control"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.supervisor = Supervisor(
            self.root,
            ROOT,
            wanted.digest(),
            expected_control_cap=wanted.limits.max_control_connections,
            release_id=wanted.release_id,
            providers={"*": provider},
            qualifier=qualifier,
            health_check=health_check,
            start_watchdog=start_watchdog,
            watchdog_interval=0.02,
            process_scopes=process_scopes,
        )
        self.supervisor.bootstrap()
        self.thread = threading.Thread(
            target=self.supervisor.serve_forever,
            name="test-supervisor",
            daemon=True,
        )
        self.thread.start()

    def connect(self) -> SeqPacketConnection:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        sock.settimeout(3)
        sock.connect(str(self.root / "supervisor.sock"))
        return SeqPacketConnection(sock)

    def finish(self) -> None:
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            self.supervisor._force_shutdown("test-cleanup")
            self.supervisor._stop.set()
            self.thread.join(timeout=5)
        self.supervisor.finalize()
        self.temporary.cleanup()


@unittest.skipUnless(
    hasattr(socket, "SOCK_SEQPACKET")
    and hasattr(socket, "SO_PEERCRED")
    and hasattr(os, "pidfd_open"),
    "Linux packet credentials and pidfds are required",
)
class SupervisorProtocolTests(unittest.TestCase):
    def test_provider_canary_fd_is_exact_and_binds_the_first_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "control"
            control.mkdir(mode=0o700)
            release_control = root / "release-control"
            release_control.mkdir(mode=0o700)
            authorization = release_control / "canary-auth.lock"
            authorization.write_bytes(b"")
            authorization.chmod(0o600)
            wanted = contract(ladder=("vpn",))
            nonce = "b" * 64

            def publish(path: Path, value: dict[str, object]) -> None:
                path.unlink(missing_ok=True)
                path.write_text(
                    json.dumps(value, sort_keys=True, separators=(",", ":"))
                    + "\n",
                    encoding="ascii",
                )
                path.chmod(0o444)

            publish(
                release_control / "rollback-deny.json",
                {
                    "schema_version": 1,
                    "operation": "canary",
                    "from_release": wanted.release_id,
                    "to_release": wanted.release_id,
                },
            )
            canary_record = {
                "schema_version": 4,
                "release_id": wanted.release_id,
                "host_id": Supervisor._host_id(),
                "canary_kind": "rung",
                "rung": "vpn",
                "route_profile": "auto-no-direct",
                "contract_sha256": wanted.digest(),
                "grok_release_id": wanted.grok_release_id,
                "model_id": wanted.model_id,
                "canary_nonce": nonce,
                "created_unix_ns": time.time_ns(),
            }
            publish(release_control / "rung-canary.json", canary_record)
            descriptor = os.open(
                authorization,
                os.O_RDONLY | os.O_CLOEXEC,
            )
            environment = {
                "GROK_TESTING": "1",
                "GROK_TEST_ROOT_RELEASE_CONTROL": str(release_control),
            }
            try:
                with mock.patch.dict(os.environ, environment, clear=False):
                    publish(
                        release_control / "rung-canary.json",
                        {
                            **canary_record,
                            "rung": "home:bad/name",
                            "route_profile": "home:bad/name",
                        },
                    )
                    with self.assertRaisesRegex(
                        supervisor_module.AdmissionError,
                        "record is invalid",
                    ):
                        Supervisor(
                            control,
                            ROOT,
                            wanted.digest(),
                            release_id=wanted.release_id,
                            providers={"vpn": ScriptedProvider(())},
                            qualifier=evidence,
                            start_watchdog=False,
                            provider_canary_fd=descriptor,
                        )
                    os.fstat(descriptor)

                    publish(
                        release_control / "rung-canary.json",
                        canary_record,
                    )
                    with (
                        mock.patch.object(
                            supervisor_module,
                            "LegacyShellProvider",
                            side_effect=RuntimeError("injected constructor failure"),
                        ),
                        self.assertRaisesRegex(
                            RuntimeError,
                            "injected constructor failure",
                        ),
                    ):
                        Supervisor(
                            control,
                            ROOT,
                            wanted.digest(),
                            release_id=wanted.release_id,
                            providers={"vpn": ScriptedProvider(())},
                            qualifier=evidence,
                            start_watchdog=False,
                            provider_canary_fd=descriptor,
                        )
                    matching = 0
                    expected_identity = os.fstat(descriptor)
                    for entry in Path("/proc/self/fd").iterdir():
                        try:
                            identity = os.stat(entry)
                        except FileNotFoundError:
                            continue
                        if (
                            identity.st_dev,
                            identity.st_ino,
                        ) == (
                            expected_identity.st_dev,
                            expected_identity.st_ino,
                        ):
                            matching += 1
                    self.assertEqual(matching, 1)

                    instance = Supervisor(
                        control,
                        ROOT,
                        wanted.digest(),
                        release_id=wanted.release_id,
                        providers={"vpn": ScriptedProvider(())},
                        qualifier=evidence,
                        start_watchdog=False,
                        provider_canary_fd=descriptor,
                    )
                    owned = instance._provider_canary_fd
                    self.assertIsNotNone(owned)
                    assert owned is not None
                    self.assertNotEqual(owned, descriptor)
                    os.fstat(descriptor)
                    os.fstat(owned)
                    instance._validate_provider_canary_contract(wanted)
                    with self.assertRaisesRegex(
                        supervisor_module.AdmissionError,
                        "first contract",
                    ):
                        instance._validate_provider_canary_contract(
                            dataclasses.replace(wanted, model_id="wrong-model")
                        )
                    with mock.patch.object(
                        instance.runtime,
                        "initialize",
                        side_effect=RuntimeError("injected bootstrap failure"),
                    ), self.assertRaisesRegex(
                        RuntimeError,
                        "injected bootstrap failure",
                    ):
                        instance.bootstrap()
                    with self.assertRaises(OSError):
                        os.fstat(owned)
                    self.assertIsNone(instance._provider_canary_record)
                    self.assertIsNone(
                        instance._legacy_provider._provider_canary_fd
                    )
                    with self.assertRaisesRegex(
                        supervisor_module.SupervisorError,
                        "bootstrap is terminal",
                    ):
                        instance.bootstrap()
                    instance._close_provider_canary()
                    os.fstat(descriptor)
            finally:
                os.close(descriptor)

    def test_diagnostic_text_escapes_control_characters(self) -> None:
        value = supervisor_module._diagnostic_text("line\n\x1b[31msecret\t", 512)
        self.assertEqual(value, r"line\n\u001b[31msecret\t")
        self.assertNotIn("\x1b", value)

    def test_production_register_rejects_wrong_grok_descriptor_before_provider_effects(self) -> None:
        wanted = dataclasses.replace(
            contract(),
            grok_release_id="sha256:" + "0" * 64,
        )
        provider = ScriptedProvider(())
        running = RunningSupervisor(wanted, provider, qualifier=None)
        connection = running.connect()
        try:
            with VerifiedGrokExecutable.open(Path("/bin/true")) as executable:
                response = request(
                    connection,
                    register_packet(wanted),
                    fds=(executable.descriptor,),
                )
            self.assertFalse(response["ok"])
            self.assertIn("does not match the contract", response["error"])
            self.assertEqual(provider.calls, ())
        finally:
            connection.close()
            running.finish()

    def test_default_qualifier_executes_open_grok_inode_after_path_retarget_without_fd_leak(self) -> None:
        first_source = """#!/usr/bin/python3
import os
expected = (int(os.environ["EXPECTED_GROK_DEV"]), int(os.environ["EXPECTED_GROK_INO"]))
for name in os.listdir("/proc/self/fd"):
    try:
        info = os.fstat(int(name))
    except (OSError, ValueError):
        continue
    if (info.st_dev, info.st_ino) == expected:
        raise SystemExit(77)
print("  - grok-4.5")
"""
        second_source = """#!/usr/bin/python3
raise SystemExit(88)
"""
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "control"
            root.mkdir(mode=0o700)
            first = base / "first-grok"
            second = base / "second-grok"
            selected = base / "selected-grok"
            first.write_text(first_source, encoding="ascii")
            second.write_text(second_source, encoding="ascii")
            os.chmod(first, 0o700)
            os.chmod(second, 0o700)
            selected.symlink_to(first)
            executable = VerifiedGrokExecutable.open(selected)
            selected.unlink()
            selected.symlink_to(second)
            wanted = dataclasses.replace(
                contract(),
                grok_release_id=executable.release_id,
            )
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                qualifier=None,
                start_watchdog=False,
            )
            supervisor.contract = wanted
            supervisor.contract_digest = wanted.digest()
            supervisor._grok_executable = executable
            supervisor.runtime.initialize()
            supervisor.recovery = RecoveryStore(supervisor.runtime)
            info = os.fstat(executable.descriptor)
            request_value = ProviderRequest(
                owner_epoch="a" * 32,
                transition_id="b" * 32,
                generation=1,
                rung="direct",
                model_id=wanted.model_id,
                private_endpoint=Endpoint("127.0.0.1", wanted.private_ports[0]),
                contract=wanted,
            )
            try:
                with mock.patch.dict(
                    os.environ,
                    {"GROK_HOME": str(base / "empty-grok-home")},
                    clear=False,
                ):
                    output = supervisor._models_through_proxy(
                        request_value,
                        {
                            "PATH": os.environ.get("PATH", ""),
                            "EXPECTED_GROK_DEV": str(info.st_dev),
                            "EXPECTED_GROK_INO": str(info.st_ino),
                        },
                        TransitionDeadline.after_ms(2_000),
                    )
                self.assertIn("  - grok-4.5", output)
            finally:
                supervisor._grok_executable = None
                executable.close()

    def test_default_qualifier_uses_hostname_trace_endpoint(self) -> None:
        wanted = contract()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            instance = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                qualifier=None,
                start_watchdog=False,
            )
            instance.contract = wanted
            request_value = ProviderRequest(
                owner_epoch="a" * 32,
                transition_id="b" * 32,
                generation=1,
                rung="direct",
                model_id=wanted.model_id,
                private_endpoint=Endpoint("127.0.0.1", wanted.private_ports[0]),
                contract=wanted,
            )
            with mock.patch.object(
                instance,
                "_run_probe",
                return_value="ip=203.0.113.20\nloc=JP\n",
            ) as probe, mock.patch.object(
                instance,
                "_models_through_proxy",
                return_value="  - grok-4.5\n",
            ):
                result = instance._default_qualifier(
                    request_value.private_endpoint,
                    request_value,
                    TransitionDeadline.after_ms(1_000),
                    None,
                )
            self.assertEqual(result.exit_identity, "203.0.113.20")
            self.assertEqual(
                probe.call_args.args[0][-1],
                "https://www.cloudflare.com/cdn-cgi/trace",
            )

    def test_probe_cancellation_kills_blocking_descendant_and_clears_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "control"
            root.mkdir(mode=0o700)
            wanted = contract()
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                qualifier=evidence,
                start_watchdog=False,
            )
            supervisor.contract = wanted
            supervisor.runtime.initialize()
            supervisor.recovery = RecoveryStore(supervisor.runtime)
            marker = base / "descendant.pid"
            source = (
                "import pathlib,subprocess,time\n"
                f"p=subprocess.Popen(['/bin/sleep','60'],start_new_session=True)\n"
                f"pathlib.Path({str(marker)!r}).write_text(str(p.pid),encoding='ascii')\n"
                "while True: time.sleep(1)\n"
            )
            cancellation = threading.Event()
            errors: list[BaseException] = []

            def run() -> None:
                try:
                    supervisor._run_probe(
                        ["/usr/bin/python3", "-c", source],
                        {"PATH": "/usr/bin:/bin"},
                        TransitionDeadline.after_ms(10_000),
                        "blocking descendant",
                        cancellation=cancellation,
                    )
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            descendant_pid = wait_for_decimal_file(marker)
            records = supervisor.recovery.list_probes()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].phase, "ATTACHED")
            direct = records[0].child
            descendant = ProcessIdentity(
                descendant_pid,
                read_pid_start_ticks(descendant_pid),
                read_boot_id(),
            )
            descendant_pidfd = os.pidfd_open(descendant.pid, 0)
            self.addCleanup(os.close, descendant_pidfd)
            cancellation.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ProviderCancelled)
            end = time.monotonic() + 2
            while time.monotonic() < end and process_matches(direct):
                time.sleep(0.01)
            self.assertFalse(process_matches(direct))
            readable, _, _ = select.select([descendant_pidfd], [], [], 2)
            self.assertEqual(readable, [descendant_pidfd])
            self.assertFalse(Path(records[0].scope.scope_path).exists())
            self.assertEqual(supervisor.recovery.list_probes(), ())

    def test_probe_put_persist_then_raise_is_reconciled_and_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            wanted = contract()
            backend = FakeScopeBackend()
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                qualifier=evidence,
                start_watchdog=False,
                process_scopes=backend,
            )
            supervisor.bootstrap()
            supervisor.contract = wanted
            supervisor._cleanup_proved = True

            def persist_then_raise(path, payload):
                self.assertTrue(_atomic_create_json(path, payload))
                raise OSError("injected post-persist failure")

            try:
                with mock.patch.object(
                    supervisor_module,
                    "_atomic_create_json",
                    side_effect=persist_then_raise,
                ):
                    with self.assertRaisesRegex(
                        ProviderError,
                        "post-persist failure",
                    ):
                        supervisor._run_probe(
                            ["/bin/sleep", "60"],
                            {"PATH": "/usr/bin:/bin"},
                            TransitionDeadline.after_ms(2_000),
                            "post-persist",
                        )
                self.assertIn(("reconcile", "PREPARED"), backend.calls)
                assert supervisor.recovery is not None
                self.assertEqual(supervisor.recovery.list_probes(), ())
            finally:
                supervisor.finalize()
            self.assertIsNone(FenceStore(supervisor.runtime).load())

    def test_probe_conflicting_persisted_record_is_never_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            wanted = contract()
            backend = FakeScopeBackend()
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                qualifier=evidence,
                start_watchdog=False,
                process_scopes=backend,
            )
            supervisor.bootstrap()
            supervisor.contract = wanted
            supervisor._cleanup_proved = True
            assert supervisor.recovery is not None
            original_put = supervisor.recovery.put_probe

            def persist_conflict(record):
                original_put(dataclasses.replace(record, owner_epoch="f" * 32))
                raise OSError("injected conflicting persistence")

            try:
                with mock.patch.object(
                    supervisor.recovery,
                    "put_probe",
                    side_effect=persist_conflict,
                ):
                    with self.assertRaisesRegex(
                        ScopeError,
                        "conflicts with its cleanup authority",
                    ):
                        supervisor._run_probe(
                            ["/bin/sleep", "60"],
                            {"PATH": "/usr/bin:/bin"},
                            TransitionDeadline.after_ms(2_000),
                            "conflicting-persist",
                        )
                retained = supervisor.recovery.list_probes()
                self.assertEqual(len(retained), 1)
                self.assertEqual(retained[0].owner_epoch, "f" * 32)
                self.assertTrue(supervisor._preserve_fence_on_abort)
            finally:
                supervisor.finalize()
            self.assertIsNotNone(FenceStore(supervisor.runtime).load())

    def test_finalize_during_slow_active_probe_never_clears_fence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            wanted = contract()
            backend = FakeScopeBackend()
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                qualifier=evidence,
                start_watchdog=False,
                process_scopes=backend,
            )
            supervisor.bootstrap()
            supervisor.contract = wanted
            supervisor._cleanup_proved = True
            errors: list[BaseException] = []

            def run() -> None:
                try:
                    supervisor._run_probe(
                        ["/bin/sleep", "60"],
                        {"PATH": "/usr/bin:/bin"},
                        TransitionDeadline.after_ms(10_000),
                        "slow-finalize",
                        cancellation=supervisor._stop,
                    )
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            end = time.monotonic() + 3
            while time.monotonic() < end:
                with supervisor._state_lock:
                    active = bool(supervisor._active_probes)
                if active and ("attach", None) in backend.calls:
                    break
                time.sleep(0.01)
            self.assertTrue(active)
            self.assertIn(("attach", None), backend.calls)
            supervisor.finalize()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ProviderCancelled)
            assert supervisor.recovery is not None
            self.assertEqual(supervisor.recovery.list_probes(), ())
            self.assertFalse(supervisor._cleanup_proved)
            self.assertIsNotNone(FenceStore(supervisor.runtime).load())

    def test_immediate_probe_reconcile_failure_preserves_record_and_fence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            wanted = contract()
            backend = FakeScopeBackend("reconcile")
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                qualifier=evidence,
                start_watchdog=False,
                process_scopes=backend,
            )
            supervisor.bootstrap()
            supervisor.contract = wanted
            supervisor._cleanup_proved = True
            try:
                with self.assertRaisesRegex(ScopeError, "injected scope residue"):
                    supervisor._run_probe(
                        ["/bin/true"],
                        {"PATH": "/usr/bin:/bin"},
                        TransitionDeadline.after_ms(2_000),
                        "immediate-reconcile-failure",
                    )
                assert supervisor.recovery is not None
                retained = supervisor.recovery.list_probes()
                self.assertEqual(len(retained), 1)
                self.assertEqual(retained[0].phase, "ATTACHED")
                self.assertTrue(supervisor._preserve_fence_on_abort)
            finally:
                supervisor.finalize()
            self.assertIsNotNone(FenceStore(supervisor.runtime).load())

    def test_simultaneous_fast_and_slow_output_floods_are_bounded_and_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            wanted = contract()
            backend = FakeScopeBackend()
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                qualifier=evidence,
                start_watchdog=False,
                process_scopes=backend,
            )
            supervisor.contract = wanted
            supervisor.runtime.initialize()
            supervisor.recovery = RecoveryStore(supervisor.runtime)
            gate = threading.Barrier(3)
            errors: list[BaseException] = []

            def source(delay: float) -> str:
                return (
                    "import os,threading,time\n"
                    "chunk=b'x'*16384\n"
                    f"delay={delay!r}\n"
                    "def pump(fd):\n"
                    "  for _ in range(16):\n"
                    "    os.write(fd,chunk)\n"
                    "    time.sleep(delay)\n"
                    "threads=[threading.Thread(target=pump,args=(fd,)) for fd in (1,2)]\n"
                    "[thread.start() for thread in threads]\n"
                    "[thread.join() for thread in threads]\n"
                )

            def run(delay: float) -> None:
                gate.wait()
                try:
                    supervisor._run_probe(
                        ["/usr/bin/python3", "-c", source(delay)],
                        {"PATH": "/usr/bin:/bin"},
                        TransitionDeadline.after_ms(5_000),
                        f"flood-{delay}",
                    )
                except BaseException as exc:
                    errors.append(exc)

            threads = [
                threading.Thread(target=run, args=(delay,), daemon=True)
                for delay in (0.0, 0.01)
            ]
            for thread in threads:
                thread.start()
            with mock.patch.object(supervisor_module, "_MAX_PROBE_OUTPUT", 65_536):
                gate.wait()
                for thread in threads:
                    thread.join(timeout=5)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(len(errors), 2)
            self.assertTrue(all(isinstance(error, ProviderError) for error in errors))
            self.assertTrue(
                all("output exceeded its bound" in str(error) for error in errors)
            )
            self.assertEqual(
                [call for call in backend.calls if call == ("reconcile", "ATTACHED")],
                [("reconcile", "ATTACHED"), ("reconcile", "ATTACHED")],
            )
            self.assertEqual(supervisor.recovery.list_probes(), ())
            with supervisor._state_lock:
                self.assertEqual(supervisor._active_probes, set())

    def test_accept_loop_reserves_capacity_before_spawning_handlers(self) -> None:
        wanted = contract(max_leases=32, max_control_connections=34)
        provider = ScriptedProvider(())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                expected_control_cap=wanted.limits.max_control_connections,
                release_id=wanted.release_id,
                providers={"*": provider},
                qualifier=evidence,
                start_watchdog=False,
            )
            supervisor.bootstrap()
            gate = threading.Event()
            original = supervisor._connection_loop

            def delayed(sock):
                gate.wait(3)
                original(sock)

            supervisor._connection_loop = delayed
            thread = threading.Thread(target=supervisor.serve_forever, daemon=True)
            thread.start()
            clients: list[socket.socket] = []
            try:
                for _ in range(wanted.limits.max_control_connections + 8):
                    connect_deadline = time.monotonic() + 3
                    while True:
                        client = socket.socket(
                            socket.AF_UNIX, socket.SOCK_SEQPACKET
                        )
                        client.settimeout(2)
                        try:
                            client.connect(str(root / "supervisor.sock"))
                        except BlockingIOError:
                            client.close()
                            if time.monotonic() >= connect_deadline:
                                raise
                            time.sleep(0.01)
                            continue
                        clients.append(client)
                        break
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    with supervisor._state_lock:
                        slots = supervisor._connection_slots
                    if slots == wanted.limits.max_control_connections:
                        break
                    time.sleep(0.01)
                with supervisor._state_lock:
                    self.assertEqual(
                        supervisor._connection_slots,
                        wanted.limits.max_control_connections,
                    )
                    pending = [
                        item
                        for item in supervisor._threads
                        if item.name == "grok-supervisor-control"
                    ]
                    self.assertEqual(
                        len(pending), wanted.limits.max_control_connections
                    )
                rejected = 0
                inspected: set[int] = set()
                reject_deadline = time.monotonic() + 3
                while rejected < 8 and time.monotonic() < reject_deadline:
                    candidates = [
                        client for client in clients if client.fileno() not in inspected
                    ]
                    readable, _, _ = select.select(candidates, [], [], 0.05)
                    for client in readable:
                        inspected.add(client.fileno())
                        try:
                            payload = SeqPacketConnection(client).recv().payload
                        except Exception:
                            continue
                        if payload.get("error") == "control connection capacity exceeded":
                            rejected += 1
                self.assertEqual(rejected, 8)
            finally:
                gate.set()
                for client in clients:
                    client.close()
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    with supervisor._state_lock:
                        if supervisor._connection_slots == 0:
                            break
                    time.sleep(0.01)
                supervisor._cleanup_proved = True
                supervisor._stop.set()
                thread.join(timeout=5)
                supervisor.finalize()

    def test_blocked_first_transition_reserves_status_and_observes_register_eof(self) -> None:
        wanted = contract(max_leases=32, max_control_connections=34)
        wanted = dataclasses.replace(
            wanted,
            timeout_policy=dataclasses.replace(
                wanted.timeout_policy, transition_ms=10_000
            ),
        )
        entered = threading.Event()

        def blocked_qualifier(endpoint, request_value, deadline, cancellation):
            entered.set()
            while cancellation is None or not cancellation.wait(0.01):
                deadline.check("blocked qualification")
            raise ProviderError("qualification cancelled after register EOF")

        provider = ScriptedProvider((ScriptedStep("start"),))
        running = RunningSupervisor(
            wanted,
            provider,
            qualifier=blocked_qualifier,
        )
        clients: list[SeqPacketConnection] = []
        try:
            for _ in range(32):
                client = running.connect()
                clients.append(client)
                client.send(register_packet(wanted))
            self.assertTrue(entered.wait(2), "provider transition did not start")
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if running.supervisor.status_snapshot()["live_interest"] == 32:
                    break
                time.sleep(0.01)
            self.assertEqual(
                running.supervisor.status_snapshot()["live_interest"], 32
            )

            status = running.connect()
            try:
                started = time.monotonic()
                response = request(
                    status,
                    {
                        "type": "status",
                        "schema_version": 1,
                        "protocol_version": 1,
                        "request_id": str(uuid.uuid4()),
                    },
                )
                self.assertTrue(response["ok"])
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                status.close()

            for client in clients:
                client.close()
            clients.clear()
            running.thread.join(timeout=5)
            with running.supervisor._state_lock:
                thread_state = [
                    (item.name, item.is_alive())
                    for item in running.supervisor._threads
                ]
            self.assertFalse(
                running.thread.is_alive(),
                (running.supervisor.status_snapshot(), thread_state),
            )
            self.assertEqual(provider.calls[0], ("start", "direct", 1))
            self.assertEqual(running.supervisor.status_snapshot()["live_interest"], 0)
        finally:
            for client in clients:
                client.close()
            running.finish()

    def test_post_publication_fault_revokes_frontend_and_uses_fresh_stop_budget(self) -> None:
        wanted = contract()
        provider = ScriptedProvider(
            (ScriptedStep("start"), ScriptedStep("stop"))
        )
        running = RunningSupervisor(wanted, provider)
        client = running.connect()
        original_record = running.supervisor._record_locked

        def fail_after_publication(event, *, result, **fields):
            if event == "transition" and result == "committed":
                raise OSError("injected diagnostic fault after publication")
            return original_record(event, result=result, **fields)

        try:
            with mock.patch.object(
                running.supervisor,
                "_record_locked",
                side_effect=fail_after_publication,
            ):
                response = request(client, register_packet(wanted))
            self.assertFalse(response["ok"])
            self.assertIn("injected diagnostic fault", response["error"])
            self.assertIsNone(running.supervisor.active_result)
            self.assertIsNone(running.supervisor.active_adapter)
            self.assertIsNotNone(running.supervisor.frontend)
            gauges = running.supervisor.frontend.gauges()
            self.assertFalse(gauges.accepting)
            self.assertEqual(gauges.active_streams, 0)
            self.assertEqual(
                provider.calls,
                (("start", "direct", 1), ("stop", "direct", 1)),
            )
        finally:
            client.close()
            running.finish()

    def test_child_ack_replay_and_last_release_prove_empty(self) -> None:
        wanted = contract()
        provider = ScriptedProvider((ScriptedStep("start"), ScriptedStep("stop")))
        running = RunningSupervisor(wanted, provider)
        client = running.connect()
        child = None
        try:
            packet = register_packet(wanted)
            registered = request(client, packet)
            replayed = request(client, packet)
            self.assertTrue(registered["ok"])
            self.assertEqual(replayed, registered)
            self.assertEqual(provider.calls, (("start", "direct", 1),))

            child = subprocess.Popen(["/bin/sleep", "60"])
            child_identity = {
                "pid": child.pid,
                "pid_start_ticks": read_pid_start_ticks(child.pid),
                "boot_id": read_boot_id(),
            }
            attach = {
                "type": "attach-child",
                "schema_version": 1,
                "protocol_version": 1,
                "owner_epoch": registered["owner_epoch"],
                "lease_id": registered["lease_id"],
                "request_id": str(uuid.uuid4()),
                "child": child_identity,
            }
            first_pidfd = os.pidfd_open(child.pid)
            try:
                attached = request(client, attach, (first_pidfd,))
            finally:
                os.close(first_pidfd)
            second_pidfd = os.pidfd_open(child.pid)
            try:
                attach_replay = request(client, attach, (second_pidfd,))
            finally:
                os.close(second_pidfd)
            self.assertTrue(attached["ok"])
            self.assertEqual(attach_replay, attached)

            child.terminate()
            child_status = child.wait(timeout=3)
            child = None
            released = request(
                client,
                {
                    "type": "release",
                    "schema_version": 1,
                    "protocol_version": 1,
                    "owner_epoch": registered["owner_epoch"],
                    "lease_id": registered["lease_id"],
                    "request_id": str(uuid.uuid4()),
                    "child_status": 128 + (-child_status),
                },
            )
            self.assertTrue(released["ok"])
            self.assertTrue(released["shutdown"])
        finally:
            client.close()
            if child is not None:
                child.kill()
                child.wait()
            running.finish()
        self.assertEqual(
            provider.calls,
            (("start", "direct", 1), ("stop", "direct", 1)),
        )
        self.assertFalse((running.root / "recovery.fence").exists())
        self.assertFalse((running.root / "supervisor.ready").exists())

    def test_child_scope_durable_crash_boundaries_reconcile_before_ack(self) -> None:
        cases = (
            ("create-before", "PREPARED"),
            ("create-after", "PREPARED"),
            ("attach-before", "SCOPE_CREATED"),
            ("attach-after", "SCOPE_CREATED"),
            ("after-attached-record", "ATTACHED"),
        )
        for fault, expected_phase in cases:
            with self.subTest(fault=fault):
                wanted = contract()
                provider = ScriptedProvider(
                    (ScriptedStep("start"), ScriptedStep("stop"))
                )
                backend = FakeScopeBackend(
                    None if fault == "after-attached-record" else fault
                )
                running = RunningSupervisor(
                    wanted,
                    provider,
                    process_scopes=backend,
                )
                client = running.connect()
                child = subprocess.Popen(["/bin/sleep", "60"])
                try:
                    registered = request(client, register_packet(wanted))
                    if fault == "after-attached-record":
                        assert running.supervisor.recovery is not None
                        original = running.supervisor.recovery.replace_child

                        def replace_and_drain(record):
                            original(record)
                            if record.phase == "ATTACHED":
                                with running.supervisor._state_lock:
                                    running.supervisor.phase = "DRAINING"

                        running.supervisor.recovery.replace_child = replace_and_drain
                    pidfd = os.pidfd_open(child.pid)
                    try:
                        response = request(
                            client,
                            {
                                "type": "attach-child",
                                "schema_version": 1,
                                "protocol_version": 1,
                                "owner_epoch": registered["owner_epoch"],
                                "lease_id": registered["lease_id"],
                                "request_id": str(uuid.uuid4()),
                                "child": {
                                    "pid": child.pid,
                                    "pid_start_ticks": read_pid_start_ticks(child.pid),
                                    "boot_id": read_boot_id(),
                                },
                            },
                            (pidfd,),
                        )
                    finally:
                        os.close(pidfd)
                    self.assertFalse(response["ok"], response)
                    self.assertIn(("reconcile", expected_phase), backend.calls)
                    child.wait(timeout=3)
                    assert running.supervisor.recovery is not None
                    self.assertIsNone(
                        running.supervisor.recovery.load_child(registered["lease_id"])
                    )
                finally:
                    client.close()
                    if child.poll() is None:
                        child.kill()
                        child.wait()
                    running.finish()

    def test_acknowledged_scope_cleanup_uncertainty_keeps_record_and_fence(self) -> None:
        wanted = contract()
        provider = ScriptedProvider((ScriptedStep("start"), ScriptedStep("stop")))
        backend = FakeScopeBackend("reconcile")
        running = RunningSupervisor(wanted, provider, process_scopes=backend)
        client = running.connect()
        child = subprocess.Popen(["/bin/sleep", "60"])
        registered = request(client, register_packet(wanted))
        try:
            pidfd = os.pidfd_open(child.pid)
            try:
                attached = request(
                    client,
                    {
                        "type": "attach-child",
                        "schema_version": 1,
                        "protocol_version": 1,
                        "owner_epoch": registered["owner_epoch"],
                        "lease_id": registered["lease_id"],
                        "request_id": str(uuid.uuid4()),
                        "child": {
                            "pid": child.pid,
                            "pid_start_ticks": read_pid_start_ticks(child.pid),
                            "boot_id": read_boot_id(),
                        },
                    },
                    (pidfd,),
                )
            finally:
                os.close(pidfd)
            self.assertTrue(attached["ok"], attached)
            client.close()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if ("reconcile", "ATTACHED") in backend.calls:
                    break
                time.sleep(0.01)
            assert running.supervisor.recovery is not None
            retained = running.supervisor.recovery.load_child(registered["lease_id"])
            self.assertIsNotNone(retained)
            self.assertEqual(retained.phase, "ATTACHED")
            self.assertIsNotNone(FenceStore(running.supervisor.runtime).load())
            self.assertFalse(running.supervisor._cleanup_proved)
        finally:
            client.close()
            if child.poll() is None:
                child.kill()
                child.wait()
            running.finish()

    def test_ordinary_start_error_after_effect_remains_durably_fenced(self) -> None:
        wanted = contract()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            marker = root / "p" / "unrecorded-effect"
            provider = EffectThenOrdinaryErrorProvider(marker)
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                expected_control_cap=wanted.limits.max_control_connections,
                release_id=wanted.release_id,
                providers={"*": provider},
                qualifier=evidence,
                start_watchdog=False,
            )
            supervisor.bootstrap()
            thread = threading.Thread(target=supervisor.serve_forever, daemon=True)
            thread.start()
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            sock.settimeout(3)
            sock.connect(str(root / "supervisor.sock"))
            client = SeqPacketConnection(sock)
            try:
                response = request(client, register_packet(wanted))
                self.assertFalse(response["ok"])
                self.assertIn("could not prove empty", response["error"])
            finally:
                client.close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(provider.calls, ["start", "recover"])
            self.assertTrue(marker.exists())
            self.assertTrue((root / "recovery.fence").exists())
            records = RecoveryStore(SecureRuntime(root)).list_providers()
            self.assertEqual(len(records), 1)
            self.assertIn(records[0].phase, {"PREPARED", "FAILED"})
            supervisor.finalize()

    def test_seeded_32_client_attach_release_eof_schedule_returns_resources(self) -> None:
        wanted = contract(
            max_leases=32,
            max_control_connections=34,
        )
        provider = ScriptedProvider((ScriptedStep("start"), ScriptedStep("stop")))
        running = RunningSupervisor(wanted, provider)
        clients: list[SeqPacketConnection] = []
        children: dict[int, subprocess.Popen[bytes]] = {}
        registrations: list[dict] = []
        try:
            first = running.connect()
            clients.append(first)
            registrations.append(request(first, register_packet(wanted)))
            self.assertEqual(provider.calls, (("start", "direct", 1),))

            unequal_client = running.connect()
            unequal = dataclasses.replace(wanted, model_id="grok-unequal")
            try:
                rejected = request(unequal_client, register_packet(unequal))
                self.assertFalse(rejected["ok"])
                self.assertIn("contract mismatch", rejected["error"])
                self.assertEqual(provider.calls, (("start", "direct", 1),))
            finally:
                unequal_client.close()

            for _ in range(31):
                connection = running.connect()
                clients.append(connection)
                registered = request(connection, register_packet(wanted))
                self.assertTrue(registered["ok"])
                registrations.append(registered)
            self.assertEqual(len({item["leader_path"] for item in registrations}), 32)
            self.assertEqual(provider.calls, (("start", "direct", 1),))

            rng = random.Random(0x47524F4B)
            attached_indices = set(rng.sample(range(32), 20))
            for index in sorted(attached_indices):
                child = subprocess.Popen(["/bin/sleep", "60"])
                children[index] = child
                pidfd = os.pidfd_open(child.pid)
                try:
                    response = request(
                        clients[index],
                        {
                            "type": "attach-child",
                            "schema_version": 1,
                            "protocol_version": 1,
                            "owner_epoch": registrations[index]["owner_epoch"],
                            "lease_id": registrations[index]["lease_id"],
                            "request_id": str(uuid.uuid4()),
                            "child": {
                                "pid": child.pid,
                                "pid_start_ticks": read_pid_start_ticks(child.pid),
                                "boot_id": read_boot_id(),
                            },
                        },
                        (pidfd,),
                    )
                finally:
                    os.close(pidfd)
                self.assertTrue(response["ok"])

            order = list(range(32))
            rng.shuffle(order)
            release_indices = set(order[:16])
            self.assertTrue(release_indices & attached_indices)
            self.assertTrue((set(range(32)) - release_indices) & attached_indices)
            for index in sorted(release_indices):
                status_value = 0
                child = children.get(index)
                if child is not None:
                    child.terminate()
                    status_value = 128 + (-child.wait(timeout=3))
                released = request(
                    clients[index],
                    {
                        "type": "release",
                        "schema_version": 1,
                        "protocol_version": 1,
                        "owner_epoch": registrations[index]["owner_epoch"],
                        "lease_id": registrations[index]["lease_id"],
                        "request_id": str(uuid.uuid4()),
                        "child_status": status_value,
                    },
                )
                self.assertTrue(released["ok"])
                clients[index].close()

            for index in sorted(set(range(32)) - release_indices):
                clients[index].close()
            for index, child in children.items():
                if index not in release_indices:
                    self.assertLess(child.wait(timeout=5), 0)
            running.thread.join(timeout=8)
            self.assertFalse(running.thread.is_alive())
            self.assertEqual(
                provider.calls,
                (("start", "direct", 1), ("stop", "direct", 1)),
            )
            self.assertFalse((running.root / "recovery.fence").exists())
            self.assertEqual(tuple((running.root / "leaders").iterdir()), ())
            recovery = RecoveryStore(SecureRuntime(running.root))
            self.assertEqual(recovery.list_children(), ())
            self.assertEqual(recovery.list_providers(), ())
            with running.supervisor._state_lock:
                self.assertEqual(running.supervisor._connection_slots, 0)
                self.assertEqual(running.supervisor._connections, {})
        finally:
            for connection in clients:
                connection.close()
            for child in children.values():
                if child.poll() is None:
                    child.kill()
                    child.wait()
            running.finish()
        self.assertFalse((running.root / "supervisor.sock").exists())

    def test_contract_field_difference_and_capacity_reject_before_provider_mutation(self) -> None:
        wanted = contract(max_leases=1)
        provider = ScriptedProvider((ScriptedStep("start"), ScriptedStep("stop")))
        running = RunningSupervisor(wanted, provider)
        first = running.connect()
        second = running.connect()
        try:
            accepted = request(first, register_packet(wanted))
            self.assertTrue(accepted["ok"])

            changed = dataclasses.replace(wanted, model_id="grok-other")
            mismatch = request(second, register_packet(changed))
            self.assertFalse(mismatch["ok"])
            self.assertIn("contract mismatch: model_id", mismatch["error"])
            self.assertEqual(provider.calls, (("start", "direct", 1),))

            capacity = request(second, register_packet(wanted))
            self.assertFalse(capacity["ok"])
            self.assertEqual(capacity["error"], "lease capacity exceeded")
            self.assertEqual(provider.calls, (("start", "direct", 1),))
        finally:
            second.close()
            first.close()
            running.finish()

    def test_two_leases_have_unique_leaders_status_and_linearized_last_interest(self) -> None:
        wanted = contract(max_leases=2)
        provider = ScriptedProvider((ScriptedStep("start"), ScriptedStep("stop")))
        running = RunningSupervisor(wanted, provider)
        first = running.connect()
        second = running.connect()
        status_client = running.connect()
        try:
            one = request(first, register_packet(wanted))
            two = request(second, register_packet(wanted))
            self.assertNotEqual(one["leader_path"], two["leader_path"])
            self.assertLess(len(os.fsencode(one["leader_path"])), 100)
            status = request(
                status_client,
                {
                    "type": "status",
                    "schema_version": 1,
                    "protocol_version": 1,
                    "request_id": str(uuid.uuid4()),
                },
            )["status"]
            self.assertEqual(status["live_interest"], 2)
            self.assertEqual(status["provisional_leases"], 2)
            self.assertEqual(status["active_rung"], "direct")
            ip = request(
                status_client,
                {
                    "type": "ip",
                    "schema_version": 1,
                    "protocol_version": 1,
                    "request_id": str(uuid.uuid4()),
                },
            )
            self.assertEqual(ip["egress_ip"], "203.0.113.20")

            first.close()
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if running.supervisor.status_snapshot()["live_interest"] == 1:
                    break
                time.sleep(0.01)
            self.assertEqual(running.supervisor.phase, "READY")
            self.assertEqual(provider.calls, (("start", "direct", 1),))

            second.close()
            running.thread.join(timeout=5)
            self.assertFalse(running.thread.is_alive())
            self.assertEqual(running.supervisor.phase, "DRAINING")
        finally:
            status_client.close()
            first.close()
            second.close()
            running.finish()

    def test_control_eof_terminates_the_exact_attached_child(self) -> None:
        wanted = contract()
        provider = ScriptedProvider((ScriptedStep("start"), ScriptedStep("stop")))
        running = RunningSupervisor(wanted, provider)
        client = running.connect()
        child = subprocess.Popen(["/bin/sleep", "60"])
        try:
            registered = request(client, register_packet(wanted))
            pidfd = os.pidfd_open(child.pid)
            try:
                attached = request(
                    client,
                    {
                        "type": "attach-child",
                        "schema_version": 1,
                        "protocol_version": 1,
                        "owner_epoch": registered["owner_epoch"],
                        "lease_id": registered["lease_id"],
                        "request_id": str(uuid.uuid4()),
                        "child": {
                            "pid": child.pid,
                            "pid_start_ticks": read_pid_start_ticks(child.pid),
                            "boot_id": read_boot_id(),
                        },
                    },
                    (pidfd,),
                )
            finally:
                os.close(pidfd)
            self.assertTrue(attached["ok"])
            client.close()
            self.assertLess(child.wait(timeout=5), 0)
            running.thread.join(timeout=5)
            self.assertFalse(running.thread.is_alive())
        finally:
            client.close()
            if child.poll() is None:
                child.kill()
                child.wait()
            running.finish()

    def test_failed_rung_is_cleaned_before_downward_candidate_commits(self) -> None:
        wanted = contract(ladder=("direct", "vpn"))
        provider = ScriptedProvider(
            (
                ScriptedStep("start", error="direct-rejected"),
                ScriptedStep("start"),
                ScriptedStep("stop"),
            )
        )
        running = RunningSupervisor(wanted, provider)
        client = running.connect()
        try:
            registered = request(client, register_packet(wanted))
            self.assertTrue(registered["ok"])
            self.assertEqual(running.supervisor.status_snapshot()["active_rung"], "vpn")
            self.assertEqual(
                provider.calls,
                (("start", "direct", 1), ("start", "vpn", 2)),
            )
        finally:
            client.close()
            running.finish()

    def test_watchdog_repairs_same_rung_once_then_demotes_strictly_downward(self) -> None:
        wanted = contract(ladder=("direct", "vpn"))
        provider = ScriptedProvider(
            (
                ScriptedStep("start"),
                ScriptedStep("stop"),
                ScriptedStep("start"),
                ScriptedStep("stop"),
                ScriptedStep("start"),
                ScriptedStep("stop"),
            )
        )
        checks: list[str] = []

        def health(result) -> bool:
            checks.append(result.request.rung)
            return result.request.rung == "vpn"

        running = RunningSupervisor(
            wanted,
            provider,
            start_watchdog=True,
            health_check=health,
        )
        client = running.connect()
        try:
            registered = request(client, register_packet(wanted))
            self.assertTrue(registered["ok"])
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if running.supervisor.status_snapshot()["active_rung"] == "vpn":
                    break
                time.sleep(0.01)
            self.assertEqual(running.supervisor.status_snapshot()["active_rung"], "vpn")
            self.assertEqual(
                provider.calls[:5],
                (
                    ("start", "direct", 1),
                    ("stop", "direct", 1),
                    ("start", "direct", 2),
                    ("stop", "direct", 2),
                    ("start", "vpn", 3),
                ),
            )
            self.assertIn("direct", checks)
            self.assertNotIn(("start", "direct", 3), provider.calls)
            self.assertEqual(
                running.supervisor.status_snapshot()["watchdog"]["same_rung_repaired"],
                ["direct"],
            )
            watchdogs = [
                item
                for item in threading.enumerate()
                if item.name == "grok-supervisor-watchdog" and item.is_alive()
            ]
            self.assertEqual(len(watchdogs), 1)
        finally:
            client.close()
            running.finish()
        self.assertEqual(provider.calls[-1], ("stop", "vpn", 3))

    def test_watchdog_ladder_exhaustion_terminates_epoch(self) -> None:
        wanted = contract(ladder=("direct",))
        provider = ScriptedProvider(
            (
                ScriptedStep("start"),
                ScriptedStep("stop"),
                ScriptedStep("start"),
                ScriptedStep("stop"),
            )
        )
        running = RunningSupervisor(
            wanted,
            provider,
            start_watchdog=True,
            health_check=lambda _result: False,
        )
        client = running.connect()
        try:
            self.assertTrue(request(client, register_packet(wanted))["ok"])
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                snapshot = running.supervisor.status_snapshot()
                if (
                    running.supervisor._stop.is_set()
                    and snapshot["live_interest"] == 0
                    and snapshot["active_rung"] is None
                ):
                    break
                time.sleep(0.01)
            snapshot = running.supervisor.status_snapshot()
            self.assertTrue(running.supervisor._stop.is_set())
            self.assertEqual(snapshot["live_interest"], 0)
            self.assertIsNone(snapshot["active_rung"])
            self.assertEqual(
                provider.calls,
                (
                    ("start", "direct", 1),
                    ("stop", "direct", 1),
                    ("start", "direct", 2),
                    ("stop", "direct", 2),
                ),
            )
        finally:
            client.close()
            running.finish()

    def test_authenticated_qualification_fault_repairs_once_and_replays(self) -> None:
        wanted = dataclasses.replace(
            contract(ladder=("direct",), model_id="xai/grok-4.5"),
            route_mode=RouteMode.DIRECT,
        )
        provider = ScriptedProvider(
            (
                ScriptedStep("start"),
                ScriptedStep("stop"),
                ScriptedStep("start"),
                ScriptedStep("stop"),
            )
        )
        running = RunningSupervisor(wanted, provider)
        lease = running.connect()
        root_control = Path(running.temporary.name) / "release-control"
        root_control.mkdir(mode=0o700)
        auth = root_control / "canary-auth.lock"
        auth.write_bytes(b"")
        os.chmod(auth, 0o600)
        nonce = "d" * 64
        record = {
            "schema_version": 4,
            "release_id": wanted.release_id,
            "host_id": running.supervisor._host_id(),
            "canary_kind": "rung",
            "rung": "direct",
            "route_profile": "direct",
            "contract_sha256": wanted.digest(),
            "grok_release_id": wanted.grok_release_id,
            "model_id": wanted.model_id,
            "canary_nonce": nonce,
            "created_unix_ns": time.time_ns(),
        }
        canary = root_control / "rung-canary.json"
        canary.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        os.chmod(canary, 0o444)
        fault = running.connect()
        descriptor = os.open(auth, os.O_RDONLY | os.O_CLOEXEC)
        environment = {
            "GROK_TESTING": "1",
            "GROK_TEST_ROOT_RELEASE_CONTROL": str(root_control),
        }
        try:
            self.assertTrue(request(lease, register_packet(wanted))["ok"])
            packet = {
                "type": "qualification-provider-fault",
                "schema_version": 1,
                "protocol_version": 1,
                "request_id": str(uuid.uuid4()),
                "owner_epoch": running.supervisor.owner_epoch,
                "canary_nonce": nonce,
                "pause_id": "f" * 32,
                "expected_generation": 1,
            }
            failed = running.supervisor.active_result
            self.assertIsNotNone(failed)
            real_frontend = running.supervisor.frontend
            qualification_frontend = QualificationFrontendStub()
            qualification_frontend.response_hold = True
            qualification_frontend.set_ready_streams(1)
            packet["expected_old_streams_sha256"] = hashlib.sha256(
                supervisor_module.canonical_json_bytes(
                    qualification_frontend.streams
                )
            ).hexdigest()
            running.supervisor.frontend = qualification_frontend
            guard = SimpleNamespace(
                qualification_deadline_ns=time.monotonic_ns() + 30_000_000_000,
                qualification_fault_in_progress=False,
            )

            def repaired(*_args, **_kwargs):
                qualification_frontend.generation = 2
                qualification_frontend.accepting = True
                return {
                    "duration_ms": 7,
                    "generation_after": 2,
                    "repaired": True,
                }

            try:
                with mock.patch.dict(
                    os.environ, environment, clear=False
                ), mock.patch.object(
                    running.supervisor,
                    "_qualification_authorization",
                    return_value=(record, wanted, failed),
                ), mock.patch.object(
                    running.supervisor,
                    "_qualification_fault_guard",
                    return_value=guard,
                ), mock.patch.object(
                    running.supervisor,
                    "_repair_active",
                    side_effect=repaired,
                ) as repair:
                    first = request(fault, packet, (descriptor,))
                    self.assertTrue(first["ok"], first)
                    self.assertTrue(first["repair_succeeded"])
                    self.assertFalse(first["replayed"])
                    self.assertEqual(first["generation_before"], 1)
                    self.assertEqual(first["generation_after"], 2)
                    self.assertRegex(first["old_streams_sha256"], r"^[0-9a-f]{64}$")

                    replay = running.connect()
                    try:
                        packet["request_id"] = str(uuid.uuid4())
                        second = request(replay, packet, (descriptor,))
                        self.assertTrue(second["ok"])
                        self.assertTrue(second["replayed"])
                        self.assertEqual(second["generation_after"], 2)
                        self.assertEqual(
                            second["old_streams_sha256"],
                            first["old_streams_sha256"],
                        )
                    finally:
                        replay.close()
                    repair.assert_called_once()
            finally:
                running.supervisor.frontend = real_frontend
        finally:
            os.close(descriptor)
            fault.close()
            lease.close()
            running.finish()

    def test_qualification_pause_binds_exact_pair_fences_admission_and_eof_thaws(self) -> None:
        wanted = dataclasses.replace(
            contract(
                ladder=("direct",),
                max_leases=8,
                max_control_connections=10,
            ),
            route_mode=RouteMode.DIRECT,
        )
        backend = FakeScopeBackend()
        provider = ScriptedProvider((ScriptedStep("start"),))
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = Supervisor(
                Path(temporary),
                ROOT,
                wanted.digest(),
                expected_control_cap=wanted.limits.max_control_connections,
                release_id=wanted.release_id,
                providers={"*": provider},
                qualifier=evidence,
                start_watchdog=False,
                process_scopes=backend,
            )
            request_value = ProviderRequest(
                supervisor.owner_epoch,
                "transition-1",
                1,
                "direct",
                wanted.model_id,
                Endpoint("127.0.0.1", wanted.private_ports[0]),
                wanted,
            )
            active = provider.start(
                request_value,
                TransitionDeadline.after_ms(2_000),
                evidence,
            )
            frontend = QualificationFrontendStub()
            supervisor.contract = wanted
            supervisor.contract_digest = wanted.digest()
            supervisor.phase = "READY"
            supervisor.generation = 1
            supervisor.active_result = active
            supervisor.frontend = frontend

            processes = [
                subprocess.Popen(["/bin/sleep", "60"])
                for _index in range(4)
            ]
            wrappers = tuple(
                ProcessIdentity(
                    process.pid,
                    read_pid_start_ticks(process.pid),
                    read_boot_id(),
                )
                for process in processes[:2]
            )
            children = tuple(
                ProcessIdentity(
                    process.pid,
                    read_pid_start_ticks(process.pid),
                    read_boot_id(),
                )
                for process in processes[2:]
            )
            handles: list[ScopeHandle] = []
            pidfds: list[int] = []
            parent_map = {
                wrappers[0].pid: os.getpid(),
                wrappers[1].pid: os.getpid(),
                children[0].pid: wrappers[0].pid,
                children[1].pid: wrappers[1].pid,
            }
            server_socket, peer_socket = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET
            )
            context = supervisor_module._Connection(
                "qualification-connection",
                os.getpid(),
                os.getuid(),
                server_socket,
            )
            supervisor._connections[context.connection_id] = context
            descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            try:
                for index, (wrapper, child) in enumerate(zip(wrappers, children)):
                    handle = backend.create(backend.plan())
                    handles.append(handle)
                    pidfd = os.pidfd_open(child.pid, 0)
                    pidfds.append(pidfd)
                    supervisor._leases[f"lease-{index}"] = supervisor_module._Lease(
                        lease_id=f"lease-{index}",
                        lease_nonce=f"nonce-{index}",
                        register_request_id=f"register-{index}",
                        connection_id=f"lease-connection-{index}",
                        wrapper=wrapper,
                        contract_digest=wanted.digest(),
                        leader_path=Path(temporary) / f"leader-{index}.sock",
                        state="LIVE",
                        child=child,
                        child_pidfd=pidfd,
                        child_scope=handle.identity,
                        child_scope_handle=handle,
                    )
                packet = {
                    "type": "qualification-pause",
                    "schema_version": 1,
                    "protocol_version": 1,
                    "request_id": str(uuid.uuid4()),
                    "owner_epoch": supervisor.owner_epoch,
                    "canary_nonce": "d" * 64,
                    "deadline_monotonic_ns": time.monotonic_ns()
                    + 60_000_000_000,
                    "wrappers": [
                        supervisor_module._identity_to_dict(wrapper)
                        for wrapper in wrappers
                    ],
                }
                with mock.patch.object(
                    supervisor,
                    "_qualification_authorization",
                    return_value=({}, wanted, active),
                ), mock.patch.object(
                    supervisor_module,
                    "_process_parent",
                    side_effect=lambda pid: parent_map[pid],
                ):
                    paused = supervisor._qualification_pause(
                        context, packet, [descriptor]
                    )
                    self.assertTrue(paused["ok"])
                    self.assertEqual(
                        paused["deadline_monotonic_ns"],
                        packet["deadline_monotonic_ns"],
                    )
                    self.assertEqual(len(paused["bindings"]), 2)
                    qualification = supervisor.status_snapshot()["resources"][
                        "qualification"
                    ]
                    self.assertEqual(
                        {
                            name: qualification[name]
                            for name in (
                                "active", "pause_id", "lease_count",
                                "frozen_scopes", "fault_in_progress",
                            )
                        },
                        {
                            "active": True,
                            "pause_id": paused["pause_id"],
                            "lease_count": 2,
                            "frozen_scopes": 2,
                            "fault_in_progress": False,
                        },
                    )
                    self.assertEqual(
                        qualification["frontend"],
                        {
                            "response_hold": True,
                            "accept_cursor": 0,
                            "quiesce_epoch": 0,
                            "streams": [],
                        },
                    )
                    competing = supervisor_module._Connection(
                        "competing", os.getpid(), os.getuid(), peer_socket
                    )
                    with self.assertRaisesRegex(
                        supervisor_module.AdmissionError,
                        "closed lease admission",
                    ):
                        supervisor._register(
                            competing,
                            register_packet(wanted),
                            [],
                        )
                    valid_fault = supervisor_module._Connection(
                        "fault", os.getpid(), os.getuid(), peer_socket
                    )
                    frontend.set_ready_streams(1)
                    peers = frontend.qualification_peers()
                    for index, handle in enumerate(handles):
                        stream_id = index + 1
                        inode = 700 + index
                        backend.tcp_connection_inodes[peers[stream_id]] = inode
                        backend.scope_socket_inodes[
                            handle.identity.scope_path
                        ] = frozenset({inode})
                    state = supervisor._qualification_stream_state(frontend)
                    bindings, socket_inodes = (
                        supervisor._qualification_stream_bindings(context, state)
                    )
                    self.assertEqual(
                        {
                            stream_id: lease_id
                            for stream_id, (lease_id, _inode) in bindings.items()
                        },
                        {1: "lease-0", 2: "lease-1"},
                    )
                    self.assertEqual(set(socket_inodes), {"lease-0", "lease-1"})
                    backend.scope_socket_inodes[
                        handles[1].identity.scope_path
                    ] = frozenset({700, 701})
                    with self.assertRaisesRegex(
                        supervisor_module.AdmissionError,
                        "not owned by one exact lease scope",
                    ):
                        supervisor._qualification_stream_bindings(context, state)
                    backend.scope_socket_inodes[
                        handles[1].identity.scope_path
                    ] = frozenset({701})
                    self.assertIs(
                        supervisor._qualification_fault_guard(
                            valid_fault,
                            packet["canary_nonce"],
                            paused["pause_id"],
                            1,
                            active_streams=2,
                            begin=True,
                        ),
                        context,
                    )
                    self.assertEqual(
                        context.qualification_forbidden_socket_inodes,
                        {
                            "lease-0": frozenset({700}),
                            "lease-1": frozenset({701}),
                        },
                    )
                    wrong_peer = supervisor_module._Connection(
                        "wrong-peer", os.getpid() + 1, os.getuid(), peer_socket
                    )
                    with self.assertRaisesRegex(
                        supervisor_module.AdmissionError,
                        "lacks its exact frozen pair guard",
                    ):
                        supervisor._qualification_fault_guard(
                            wrong_peer,
                            packet["canary_nonce"],
                            paused["pause_id"],
                            1,
                            active_streams=2,
                        )
                    context.qualification_fault_in_progress = False
                    empty_quiesce = supervisor._qualification_quiesce(
                        context,
                        {
                            "type": "qualification-quiesce",
                            "schema_version": 1,
                            "protocol_version": 1,
                            "request_id": str(uuid.uuid4()),
                            "owner_epoch": supervisor.owner_epoch,
                            "canary_nonce": packet["canary_nonce"],
                            "pause_id": paused["pause_id"],
                            "expected_generation": 1,
                            "wrapper": None,
                            "stream_ids": [],
                        },
                        [],
                    )
                    self.assertEqual(empty_quiesce["qualification"]["streams"], [])
                    self.assertEqual(empty_quiesce["quiesce_epoch"], 1)

                    frontend.set_ready_streams(1, count=1)
                    fresh_id = int(frontend.streams[0]["stream_id"])
                    fresh_endpoint = frontend.qualification_peers()[fresh_id]
                    backend.tcp_connection_inodes[fresh_endpoint] = 800
                    backend.scope_socket_inodes[
                        handles[0].identity.scope_path
                    ] = frozenset({700, 800})
                    fresh_quiesce = supervisor._qualification_quiesce(
                        context,
                        {
                            "type": "qualification-quiesce",
                            "schema_version": 1,
                            "protocol_version": 1,
                            "request_id": str(uuid.uuid4()),
                            "owner_epoch": supervisor.owner_epoch,
                            "canary_nonce": packet["canary_nonce"],
                            "pause_id": paused["pause_id"],
                            "expected_generation": 1,
                            "wrapper": supervisor_module._identity_to_dict(
                                wrappers[0]
                            ),
                            "stream_ids": [fresh_id],
                        },
                        [],
                    )
                    self.assertEqual(fresh_quiesce["quiesce_epoch"], 2)

                    frontend.set_ready_streams(1, count=1)
                    reused_id = int(frontend.streams[0]["stream_id"])
                    reused_endpoint = frontend.qualification_peers()[reused_id]
                    backend.tcp_connection_inodes[reused_endpoint] = 700
                    with self.assertRaisesRegex(
                        supervisor_module.AdmissionError,
                        "reused a pre-fault socket",
                    ):
                        supervisor._qualification_quiesce(
                            context,
                            {
                                "type": "qualification-quiesce",
                                "schema_version": 1,
                                "protocol_version": 1,
                                "request_id": str(uuid.uuid4()),
                                "owner_epoch": supervisor.owner_epoch,
                                "canary_nonce": packet["canary_nonce"],
                                "pause_id": paused["pause_id"],
                                "expected_generation": 1,
                                "wrapper": supervisor_module._identity_to_dict(
                                    wrappers[0]
                                ),
                                "stream_ids": [reused_id],
                            },
                            [],
                        )
                    frontend.streams = []

                    def expire_during_disarm() -> None:
                        frontend.response_hold = False
                        context.qualification_deadline_ns = (
                            time.monotonic_ns() - 1
                        )

                    with mock.patch.object(
                        frontend,
                        "qualification_disarm",
                        side_effect=expire_during_disarm,
                    ), self.assertRaisesRegex(
                        ScopeResidueError,
                        "expired while disarming",
                    ):
                        supervisor._qualification_disarm(
                            context,
                            {
                                "type": "qualification-disarm",
                                "schema_version": 1,
                                "protocol_version": 1,
                                "request_id": str(uuid.uuid4()),
                                "owner_epoch": supervisor.owner_epoch,
                                "canary_nonce": packet["canary_nonce"],
                                "pause_id": paused["pause_id"],
                                "expected_generation": 1,
                            },
                            [],
                        )
                    context.qualification_deadline_ns = (
                        time.monotonic_ns() + 30_000_000_000
                    )
                    supervisor._connection_lost(context)
                self.assertIsNone(supervisor._qualification_connection_id)
                self.assertEqual(supervisor.phase, "DRAINING")
                self.assertTrue(supervisor._stop.is_set())
                self.assertFalse(frontend.response_hold)
                self.assertEqual(
                    [name for name, _value in backend.calls].count("freeze"), 2
                )
                self.assertEqual(
                    [name for name, _value in backend.calls].count("thaw"), 2
                )
                self.assertEqual(len(supervisor._leases), 0)
            finally:
                os.close(descriptor)
                server_socket.close()
                peer_socket.close()
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                for process in processes:
                    process.wait(timeout=3)
                for pidfd in pidfds:
                    try:
                        os.close(pidfd)
                    except OSError:
                        pass
                for handle in handles:
                    try:
                        handle.close()
                    except OSError:
                        pass

    def test_qualification_release_deadline_and_uncertainty_are_terminal(self) -> None:
        wanted = contract(ladder=("direct",))

        def exercise(*, remaining_seconds: float, uncertain: bool):
            backend = FakeScopeBackend()
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "control"
                root.mkdir(mode=0o700)
                supervisor = Supervisor(
                    root,
                    ROOT,
                    wanted.digest(),
                    release_id=wanted.release_id,
                    providers={"*": ScriptedProvider(())},
                    qualifier=evidence,
                    start_watchdog=False,
                    process_scopes=backend,
                )
                supervisor.contract = wanted
                supervisor.phase = "READY"
                supervisor.generation = 1
                handle = backend.create(backend.plan())
                server, peer = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                context = supervisor_module._Connection(
                    "qualification-release", os.getpid(), os.getuid(), server
                )
                context.qualification_pause_id = "a" * 32
                context.qualification_nonce = "b" * 64
                context.qualification_lease_ids = ("lease-0",)
                context.qualification_frozen.add("lease-0")
                context.qualification_freeze_uncertain = uncertain
                context.qualification_deadline_ns = (
                    time.monotonic_ns()
                    + int(remaining_seconds * 1_000_000_000)
                )
                supervisor._qualification_connection_id = context.connection_id
                supervisor._connections[context.connection_id] = context
                supervisor._leases["lease-0"] = supervisor_module._Lease(
                    lease_id="lease-0",
                    lease_nonce="nonce-0",
                    register_request_id="register-0",
                    connection_id="lease-connection-0",
                    wrapper=current_process_identity(),
                    contract_digest=wanted.digest(),
                    leader_path=root / "leader-0.sock",
                    state="LIVE",
                    child_scope=handle.identity,
                    child_scope_handle=handle,
                )
                try:
                    with mock.patch.object(
                        supervisor, "_set_fence_phase"
                    ), mock.patch.object(
                        supervisor, "_force_shutdown"
                    ) as forced:
                        if uncertain:
                            with self.assertRaisesRegex(
                                ScopeError, "qualification thaw was uncertain"
                            ):
                                supervisor._release_qualification_pause(
                                    context, reason="test"
                                )
                            forced.assert_called_once_with(
                                "qualification-thaw-uncertain"
                            )
                        else:
                            supervisor._release_qualification_pause(
                                context, reason="test"
                            )
                            forced.assert_called_once_with(
                                "qualification-guard-released"
                            )
                    self.assertEqual(supervisor.phase, "DRAINING")
                    self.assertTrue(supervisor._stop.is_set())
                    self.assertIsNone(supervisor._qualification_connection_id)
                    self.assertEqual(len(backend.thaw_timeouts), 1)
                    self.assertAlmostEqual(
                        backend.thaw_timeouts[0],
                        wanted.timeout_policy.stop_ms / 1_000,
                    )
                finally:
                    server.close()
                    peer.close()
                    handle.close()

        exercise(remaining_seconds=0.5, uncertain=False)
        exercise(remaining_seconds=0.5, uncertain=True)

        backend = FakeScopeBackend()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                providers={"*": ScriptedProvider(())},
                qualifier=evidence,
                start_watchdog=False,
                process_scopes=backend,
            )
            supervisor.contract = wanted
            supervisor.phase = "READY"
            server, peer = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET
            )
            context = supervisor_module._Connection(
                "qualification-expired", os.getpid(), os.getuid(), server
            )
            context.qualification_pause_id = "a" * 32
            context.qualification_deadline_ns = time.monotonic_ns() - 1
            supervisor._qualification_connection_id = context.connection_id
            supervisor._connections[context.connection_id] = context
            try:
                with mock.patch.object(
                    supervisor, "_set_fence_phase"
                ), mock.patch.object(
                    supervisor, "_force_shutdown"
                ) as forced:
                    self.assertTrue(
                        supervisor._qualification_pause_expired(context)
                    )
                forced.assert_called_once_with("qualification-guard-released")
                self.assertEqual(supervisor.phase, "DRAINING")
                self.assertTrue(supervisor._stop.is_set())
            finally:
                server.close()
                peer.close()

    def test_partial_and_uncertain_qualification_freeze_fail_closed(self) -> None:
        wanted = dataclasses.replace(
            contract(
                ladder=("direct",),
                max_leases=8,
                max_control_connections=10,
            ),
            route_mode=RouteMode.DIRECT,
        )

        def exercise(fail_at: str, expected_error: str, force_reason: str) -> None:
            backend = FakeScopeBackend(fail_at=fail_at)
            provider = ScriptedProvider((ScriptedStep("start"),))
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "control"
                root.mkdir(mode=0o700)
                supervisor = Supervisor(
                    root,
                    ROOT,
                    wanted.digest(),
                    expected_control_cap=wanted.limits.max_control_connections,
                    release_id=wanted.release_id,
                    providers={"*": provider},
                    qualifier=evidence,
                    start_watchdog=False,
                    process_scopes=backend,
                )
                request_value = ProviderRequest(
                    supervisor.owner_epoch,
                    "transition-1",
                    1,
                    "direct",
                    wanted.model_id,
                    Endpoint("127.0.0.1", wanted.private_ports[0]),
                    wanted,
                )
                active = provider.start(
                    request_value,
                    TransitionDeadline.after_ms(2_000),
                    evidence,
                )
                supervisor.contract = wanted
                supervisor.contract_digest = wanted.digest()
                supervisor.phase = "READY"
                supervisor.generation = 1
                supervisor.active_result = active
                supervisor.frontend = QualificationFrontendStub()
                wrappers = (
                    ProcessIdentity(101, 1001, read_boot_id()),
                    ProcessIdentity(102, 1002, read_boot_id()),
                )
                children = (
                    ProcessIdentity(201, 2001, read_boot_id()),
                    ProcessIdentity(202, 2002, read_boot_id()),
                )
                handles: list[ScopeHandle] = []
                descriptors: list[int] = []
                for index, (wrapper, child) in enumerate(zip(wrappers, children)):
                    handle = backend.create(backend.plan())
                    handles.append(handle)
                    pidfd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                    descriptors.append(pidfd)
                    supervisor._leases[f"lease-{index}"] = supervisor_module._Lease(
                        lease_id=f"lease-{index}",
                        lease_nonce=f"nonce-{index}",
                        register_request_id=f"register-{index}",
                        connection_id=f"lease-connection-{index}",
                        wrapper=wrapper,
                        contract_digest=wanted.digest(),
                        leader_path=root / f"leader-{index}.sock",
                        state="LIVE",
                        child=child,
                        child_pidfd=pidfd,
                        child_scope=handle.identity,
                        child_scope_handle=handle,
                    )
                server, peer = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                context = supervisor_module._Connection(
                    "partial-freeze", 100, os.getuid(), server
                )
                supervisor._connections[context.connection_id] = context
                auth_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                packet = {
                    "type": "qualification-pause",
                    "schema_version": 1,
                    "protocol_version": 1,
                    "request_id": str(uuid.uuid4()),
                    "owner_epoch": supervisor.owner_epoch,
                    "canary_nonce": "d" * 64,
                    "deadline_monotonic_ns": time.monotonic_ns()
                    + 60_000_000_000,
                    "wrappers": [
                        supervisor_module._identity_to_dict(item)
                        for item in wrappers
                    ],
                }
                parent_map = {
                    wrappers[0].pid: 100,
                    wrappers[1].pid: 100,
                    children[0].pid: wrappers[0].pid,
                    children[1].pid: wrappers[1].pid,
                }
                try:
                    with mock.patch.object(
                        supervisor,
                        "_qualification_authorization",
                        return_value=({}, wanted, active),
                    ), mock.patch.object(
                        supervisor_module,
                        "process_matches",
                        return_value=True,
                    ), mock.patch.object(
                        supervisor_module,
                        "_pidfd_matches",
                        return_value=True,
                    ), mock.patch.object(
                        supervisor_module,
                        "_process_parent",
                        side_effect=lambda pid: parent_map[pid],
                    ), mock.patch.object(
                        supervisor, "_set_fence_phase"
                    ), mock.patch.object(
                        supervisor, "_force_shutdown"
                    ) as forced, self.assertRaisesRegex(
                        ScopeError, expected_error
                    ):
                        supervisor._qualification_pause(
                            context, packet, [auth_fd]
                        )
                    forced.assert_called_once_with(force_reason)
                    self.assertEqual(supervisor.phase, "DRAINING")
                    self.assertTrue(supervisor._stop.is_set())
                    self.assertIsNone(supervisor._qualification_connection_id)
                    self.assertEqual(
                        [name for name, _value in backend.calls].count("freeze"),
                        2,
                    )
                    self.assertEqual(
                        [name for name, _value in backend.calls].count("thaw"),
                        1,
                    )
                finally:
                    os.close(auth_fd)
                    server.close()
                    peer.close()
                    for descriptor in descriptors:
                        os.close(descriptor)
                    for handle in handles:
                        handle.close()

        exercise(
            "freeze-2",
            "injected freeze failure",
            "qualification-guard-released",
        )
        exercise(
            "freeze-uncertain-2",
            "qualification pause failed and thaw was uncertain",
            "qualification-thaw-uncertain",
        )

    def test_guarded_lease_cleanup_failure_forces_terminal_drain(self) -> None:
        wanted = contract(ladder=("direct",))
        backend = FakeScopeBackend(fail_at="reconcile")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                providers={"*": ScriptedProvider(())},
                qualifier=evidence,
                start_watchdog=False,
                process_scopes=backend,
            )
            supervisor.contract = wanted
            supervisor.phase = "READY"
            handle = backend.create(backend.plan())
            server, peer = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET
            )
            context = supervisor_module._Connection(
                "qualification-cleanup", os.getpid(), os.getuid(), server
            )
            context.qualification_pause_id = "a" * 32
            context.qualification_nonce = "b" * 64
            context.qualification_lease_ids = ("lease-0",)
            context.qualification_frozen.add("lease-0")
            context.qualification_deadline_ns = (
                time.monotonic_ns() + 30_000_000_000
            )
            supervisor._qualification_connection_id = context.connection_id
            supervisor._connections[context.connection_id] = context
            supervisor._leases["lease-0"] = supervisor_module._Lease(
                lease_id="lease-0",
                lease_nonce="nonce-0",
                register_request_id="register-0",
                connection_id="lease-connection-0",
                wrapper=current_process_identity(),
                contract_digest=wanted.digest(),
                leader_path=root / "leader-0.sock",
                state="LIVE",
                child=current_process_identity(),
                child_scope=handle.identity,
                child_scope_handle=handle,
            )
            try:
                with mock.patch.object(
                    supervisor, "_child_has_exited", return_value=True
                ):
                    supervisor._drop_lease("lease-0", terminate=True)
                self.assertTrue(context.qualification_cleanup_uncertain)
                with mock.patch.object(
                    supervisor, "_set_fence_phase"
                ), mock.patch.object(
                    supervisor, "_force_shutdown"
                ) as forced, self.assertRaisesRegex(
                    ScopeError, "qualification thaw was uncertain"
                ):
                    supervisor._release_qualification_pause(
                        context, reason="guarded-lease-cleanup"
                    )
                forced.assert_called_once_with("qualification-thaw-uncertain")
                self.assertEqual(supervisor.phase, "DRAINING")
            finally:
                server.close()
                peer.close()

    def test_force_shutdown_continues_after_fence_write_failure(self) -> None:
        wanted = contract(ladder=("direct",))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                providers={"*": ScriptedProvider(())},
                qualifier=evidence,
                start_watchdog=False,
            )
            supervisor.contract = wanted
            supervisor.phase = "READY"
            supervisor._leases["lease-0"] = supervisor_module._Lease(
                lease_id="lease-0",
                lease_nonce="nonce-0",
                register_request_id="register-0",
                connection_id="lease-connection-0",
                wrapper=current_process_identity(),
                contract_digest=wanted.digest(),
                leader_path=root / "leader-0.sock",
            )
            with mock.patch.object(
                supervisor,
                "_set_fence_phase",
                side_effect=RuntimeSecurityError("injected fence failure"),
            ), mock.patch.object(
                supervisor, "_drop_lease", return_value=True
            ) as dropped, mock.patch.object(
                supervisor, "_drain_epoch"
            ) as drained:
                supervisor._force_shutdown("test-fence-failure")
            dropped.assert_called_once_with("lease-0", terminate=True)
            drained.assert_called_once_with()
            self.assertTrue(supervisor._stop.is_set())
            self.assertEqual(supervisor.phase, "DRAINING")
            self.assertTrue(supervisor._preserve_fence_on_abort)
            self.assertIn("injected fence failure", supervisor._cleanup_error)

    def test_last_lease_eof_stops_after_fence_linearization_failure(self) -> None:
        wanted = contract(ladder=("direct",))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            root.mkdir(mode=0o700)
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                providers={"*": ScriptedProvider(())},
                qualifier=evidence,
                start_watchdog=False,
            )
            supervisor.contract = wanted
            supervisor.phase = "READY"
            server, peer = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET
            )
            context = supervisor_module._Connection(
                "lease-connection-0", os.getpid(), os.getuid(), server
            )
            context.leases.add("lease-0")
            supervisor._connections[context.connection_id] = context
            supervisor._leases["lease-0"] = supervisor_module._Lease(
                lease_id="lease-0",
                lease_nonce="nonce-0",
                register_request_id="register-0",
                connection_id=context.connection_id,
                wrapper=current_process_identity(),
                contract_digest=wanted.digest(),
                leader_path=root / "leader-0.sock",
            )
            try:
                with mock.patch.object(
                    supervisor,
                    "_set_fence_phase",
                    side_effect=RuntimeSecurityError("injected EOF fence failure"),
                ), mock.patch.object(supervisor, "_drain_epoch") as drained:
                    supervisor._connection_lost(context)
                drained.assert_called_once_with()
                self.assertTrue(supervisor._stop.is_set())
                self.assertEqual(supervisor.phase, "DRAINING")
                self.assertFalse(supervisor._leases)
                self.assertTrue(supervisor._preserve_fence_on_abort)
                self.assertTrue(
                    any(
                        "injected EOF fence failure" in item
                        for item in supervisor._lease_cleanup_errors
                    )
                )
            finally:
                server.close()
                peer.close()

    def test_repair_of_inactive_generation_is_closed_and_qualification_fails(self) -> None:
        wanted = dataclasses.replace(
            contract(ladder=("direct",)), route_mode=RouteMode.DIRECT
        )
        provider = ScriptedProvider((ScriptedStep("start"), ScriptedStep("stop")))
        running = RunningSupervisor(wanted, provider)
        lease = running.connect()
        try:
            self.assertTrue(request(lease, register_packet(wanted))["ok"])
            failed = running.supervisor.active_result
            self.assertIsNotNone(failed)
            with running.supervisor._state_lock:
                running.supervisor.phase = "DRAINING"
            outcome = running.supervisor._repair_active(failed)
            self.assertEqual(outcome["generation_after"], failed.request.generation)
            self.assertFalse(outcome["repaired"])
            with self.assertRaisesRegex(
                ProviderError, "qualification same-rung repair failed"
            ):
                running.supervisor._repair_active(
                    failed,
                    reason="qualification-fault",
                    require_same_rung=True,
                )
        finally:
            lease.close()
            running.finish()

    def test_failed_qualification_fault_is_consumed_fail_closed(self) -> None:
        wanted = dataclasses.replace(
            contract(ladder=("direct",)), route_mode=RouteMode.DIRECT
        )
        provider = ScriptedProvider(
            (
                ScriptedStep("start"),
                ScriptedStep("stop"),
                ScriptedStep("start", error="repair-rejected"),
            )
        )
        running = RunningSupervisor(wanted, provider)
        lease = running.connect()
        root_control = Path(running.temporary.name) / "release-control-failed"
        root_control.mkdir(mode=0o700)
        auth = root_control / "canary-auth.lock"
        auth.write_bytes(b"")
        os.chmod(auth, 0o600)
        nonce = "e" * 64
        record = {
            "schema_version": 4,
            "release_id": wanted.release_id,
            "host_id": running.supervisor._host_id(),
            "canary_kind": "rung",
            "rung": "direct",
            "route_profile": "direct",
            "contract_sha256": wanted.digest(),
            "grok_release_id": wanted.grok_release_id,
            "model_id": wanted.model_id,
            "canary_nonce": nonce,
            "created_unix_ns": time.time_ns(),
        }
        canary = root_control / "rung-canary.json"
        canary.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        os.chmod(canary, 0o444)
        descriptor = os.open(auth, os.O_RDONLY | os.O_CLOEXEC)
        packet = {
            "type": "qualification-provider-fault",
            "schema_version": 1,
            "protocol_version": 1,
            "request_id": str(uuid.uuid4()),
            "owner_epoch": running.supervisor.owner_epoch,
            "canary_nonce": nonce,
            "pause_id": "f" * 32,
            "expected_generation": 1,
        }
        environment = {
            "GROK_TESTING": "1",
            "GROK_TEST_ROOT_RELEASE_CONTROL": str(root_control),
        }
        fault_server, fault_peer = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )
        fault_context = supervisor_module._Connection(
            "failed-fault", os.getpid(), os.getuid(), fault_server
        )
        try:
            self.assertTrue(request(lease, register_packet(wanted))["ok"])
            failed = running.supervisor.active_result
            self.assertIsNotNone(failed)
            real_frontend = running.supervisor.frontend
            qualification_frontend = QualificationFrontendStub()
            qualification_frontend.response_hold = True
            qualification_frontend.set_ready_streams(1)
            packet["expected_old_streams_sha256"] = hashlib.sha256(
                supervisor_module.canonical_json_bytes(
                    qualification_frontend.streams
                )
            ).hexdigest()
            running.supervisor.frontend = qualification_frontend
            guard = SimpleNamespace(
                qualification_deadline_ns=time.monotonic_ns() + 30_000_000_000,
                qualification_fault_in_progress=False,
            )
            with mock.patch.dict(
                os.environ, environment, clear=False
            ), mock.patch.object(
                running.supervisor,
                "_qualification_authorization",
                return_value=(record, wanted, failed),
            ), mock.patch.object(
                running.supervisor,
                "_qualification_fault_guard",
                return_value=guard,
            ), mock.patch.object(
                running.supervisor,
                "_repair_active",
                side_effect=ProviderError("qualification same-rung repair failed"),
            ):
                with self.assertRaisesRegex(
                    ProviderError, "qualification same-rung repair failed"
                ):
                    running.supervisor._qualification_provider_fault(
                        fault_context, packet, [descriptor]
                    )
                marker = running.supervisor.control_root / (
                    "qualification-fault-" + nonce + ".json"
                )
                self.assertEqual(json.loads(marker.read_text())["phase"], "PREPARED")
                with self.assertRaisesRegex(
                    supervisor_module.AdmissionError,
                    "already consumed",
                ):
                    running.supervisor._qualification_provider_fault(
                        fault_context, packet, [descriptor]
                    )
                self.assertIn(nonce, running.supervisor._qualification_fault_nonces)
                self.assertEqual(provider.calls, (("start", "direct", 1),))
            running.supervisor.frontend = real_frontend
        finally:
            fault_server.close()
            fault_peer.close()
            os.close(descriptor)
            lease.close()
            running.finish()

    def test_default_health_probe_detects_exit_identity_drift(self) -> None:
        wanted = contract()
        provider = ScriptedProvider((ScriptedStep("start"), ScriptedStep("stop")))
        running = RunningSupervisor(wanted, provider)
        client = running.connect()
        try:
            self.assertTrue(request(client, register_packet(wanted))["ok"])
            active = running.supervisor.active_result
            self.assertIsNotNone(active)
            with mock.patch("grok_ms.supervisor.process_matches", return_value=True):
                with mock.patch.object(
                    running.supervisor,
                    "_run_probe",
                    return_value="ip=203.0.113.20\nloc=JP\n",
                ) as probe:
                    self.assertTrue(running.supervisor._default_health_check(active))
                    self.assertEqual(
                        probe.call_args.args[0][-1],
                        "https://www.cloudflare.com/cdn-cgi/trace",
                    )
                with mock.patch.object(
                    running.supervisor,
                    "_run_probe",
                    return_value="ip=203.0.113.21\nloc=JP\n",
                ):
                    self.assertFalse(running.supervisor._default_health_check(active))
        finally:
            client.close()
            running.finish()

    def test_teardown_failure_exits_but_preserves_recovery_fence(self) -> None:
        wanted = contract()
        provider = ScriptedProvider(
            (ScriptedStep("start"), ScriptedStep("stop", error="stop-failed"))
        )
        running = RunningSupervisor(wanted, provider)
        client = running.connect()
        try:
            self.assertTrue(request(client, register_packet(wanted))["ok"])
            client.close()
            running.thread.join(timeout=5)
            self.assertFalse(running.thread.is_alive())
            self.assertFalse(running.supervisor._cleanup_proved)
            self.assertTrue((running.root / "recovery.fence").exists())
        finally:
            client.close()
            # TemporaryDirectory cleanup is safe for the isolated test residue;
            # production finalization deliberately leaves the durable fence.
            running.finish()

    def test_unexpected_leader_residue_still_stops_provider_and_keeps_fence(self) -> None:
        wanted = contract()
        provider = ScriptedProvider((ScriptedStep("start"), ScriptedStep("stop")))
        running = RunningSupervisor(wanted, provider)
        client = running.connect()
        try:
            registered = request(client, register_packet(wanted))
            Path(registered["leader_path"]).write_text("unexpected", encoding="ascii")
            client.close()
            running.thread.join(timeout=5)
            self.assertFalse(running.thread.is_alive())
            self.assertEqual(
                provider.calls,
                (("start", "direct", 1), ("stop", "direct", 1)),
            )
            self.assertFalse(running.supervisor._cleanup_proved)
            self.assertTrue((running.root / "recovery.fence").exists())
        finally:
            client.close()
            running.finish()


class SupervisorRecoveryTests(unittest.TestCase):
    def test_expired_handoff_deadline_rejects_before_process_creation(self) -> None:
        expired = TransitionDeadline(1)
        with mock.patch.object(supervisor_module.subprocess, "Popen") as popen:
            with self.assertRaises(ProviderTimeout):
                supervisor_module._run_compatibility_handoff(
                    Path("/nonexistent/control"),
                    ROOT,
                    "expired-handoff-owner",
                    "a" * 64,
                    recovery_deadline=expired,
                )
        popen.assert_not_called()

    def test_compatibility_handoff_contains_double_forked_setsid_descendant(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, runtime = self.make_root(temporary)
            release = base / "release"
            package = release / "grok_ms"
            package.mkdir(parents=True)
            guard = package / "parent_guard.py"
            guard.write_bytes((ROOT / "grok_ms/parent_guard.py").read_bytes())
            guard.chmod(0o755)
            script = release / "egress.sh"
            script.write_text(
                r'''#!/bin/bash
set -euo pipefail
[[ "${1:-}" == compatibility-handoff ]]
marker="$(dirname "$0")/handoff-descendant.pid"
(
  (
    setsid /bin/bash -c 'trap "" TERM HUP; printf "%s\n" "$$" > "$1"; while :; do sleep 60; done' _ "$marker" </dev/null >/dev/null 2>&1 &
  ) &
)
for _ in $(seq 1 200); do [[ -s "$marker" ]] && exit 0; sleep 0.01; done
exit 91
''',
                encoding="utf-8",
            )
            script.chmod(0o755)
            owner = "handoff-test-owner"
            release_id = "a" * 64
            current = current_process_identity()
            FenceStore(runtime).publish(
                FenceRecord(
                    schema_version=1,
                    release_id=release_id,
                    owner_epoch=owner,
                    pid=current.pid,
                    pid_start_ticks=current.start_ticks,
                    boot_id=current.boot_id,
                    phase="BOOTSTRAPPING",
                )
            )
            store = DetachedScopeStore(root)
            errors: list[BaseException] = []

            class RecordingScopeBackend(LinuxCgroupV2Scope):
                def __init__(self) -> None:
                    super().__init__()
                    self.forced: list[str] = []

                def force_kill(self, scope, *, handle=None) -> None:
                    self.forced.append(scope.scope_path)
                    super().force_kill(scope, handle=handle)

            backend = RecordingScopeBackend()

            def run() -> None:
                try:
                    supervisor_module._run_compatibility_handoff(
                        root,
                        release,
                        owner,
                        release_id,
                        timeout_seconds=5.0,
                        cleanup_timeout_seconds=5.0,
                        process_scopes=backend,
                        detached_scopes=store,
                    )
                except BaseException as exc:
                    errors.append(exc)

            worker = threading.Thread(target=run)
            worker.start()
            descendant_pidfd = -1
            scope_path: Path | None = None
            try:
                marker = release / "handoff-descendant.pid"
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    record = store.load("compatibility-handoff")
                    if record is not None and record.phase == "ATTACHED":
                        scope_path = Path(record.scope.scope_path)
                    if marker.exists() and scope_path is not None:
                        break
                    if not worker.is_alive():
                        break
                    time.sleep(0.005)
                self.assertTrue(marker.exists())
                self.assertIsNotNone(scope_path)
                descendant_pid = int(marker.read_text(encoding="ascii"))
                descendant_pidfd = os.pidfd_open(descendant_pid, 0)
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                readable, _, _ = select.select([descendant_pidfd], [], [], 0)
                self.assertEqual(readable, [descendant_pidfd])
                assert scope_path is not None
                self.assertFalse(scope_path.exists())
                self.assertEqual(store.list_records(), ())
                self.assertEqual(backend.forced, [str(scope_path)])
            finally:
                worker.join(timeout=1)
                if descendant_pidfd >= 0:
                    os.close(descendant_pidfd)

    def test_provider_recovery_record_rejects_frozen_release_mismatch(self) -> None:
        wanted = contract()
        request_value = ProviderRequest(
            owner_epoch="dead-epoch",
            transition_id="transition-1",
            generation=1,
            rung="direct",
            model_id=wanted.model_id,
            private_endpoint=Endpoint("127.0.0.1", wanted.private_ports[0]),
            contract=dataclasses.replace(
                wanted,
                release_id="different-frozen-release",
            ),
        )
        with self.assertRaisesRegex(ValueError, "request release differs"):
            ProviderRecoveryRecord(
                schema_version=1,
                record_version=1,
                release_id=wanted.release_id,
                owner_epoch=request_value.owner_epoch,
                effect_id="dead-epoch-g1-start",
                phase="PREPARED",
                request=request_value,
                resources=None,
            )

    def test_offline_recovery_rejects_frozen_release_mismatch_before_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            fence = self.recovery_fence(runtime)
            request_value = self.recovery_request(fence)
            effect_id = f"{fence.owner_epoch}-g1-start"
            record = ProviderRecoveryRecord(
                schema_version=1,
                record_version=1,
                release_id=fence.release_id,
                owner_epoch=fence.owner_epoch,
                effect_id=effect_id,
                phase="PREPARED",
                request=request_value,
                resources=None,
            ).to_dict()
            record["request"]["contract"]["release_id"] = "different-frozen-release"
            store = RecoveryStore(runtime)
            self.assertTrue(
                _atomic_create_json(store.provider_path(effect_id), record)
            )
            adapter = ScriptedProvider(())
            with self.assertRaisesRegex(
                RuntimeSecurityError, "request release differs"
            ):
                recover_offline(
                    root,
                    ROOT,
                    providers={"direct": adapter},
                    recover_compatibility=False,
                )
            self.assertEqual(adapter.calls, ())
            self.assertTrue((root / "recovery.fence").exists())

    def test_strict_direct_recovery_flags_reject_compatibility_enablement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control"
            with self.assertRaisesRegex(
                ValueError, "cannot enable compatibility handoff"
            ):
                recover_offline(
                    root,
                    ROOT,
                    recover_compatibility=True,
                    forbid_compatibility_handoff=True,
                )
            with self.assertRaisesRegex(
                ValueError, "forbid_compatibility_handoff must be a boolean"
            ):
                recover_offline(
                    root,
                    ROOT,
                    recover_compatibility=False,
                    forbid_compatibility_handoff=1,  # type: ignore[arg-type]
                )

    def test_strict_direct_recovering_retry_never_runs_compatibility_handoff(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            fence = FenceRecord(
                schema_version=1,
                release_id=_release_id(ROOT),
                owner_epoch="strict-recovering-epoch",
                pid=2**31 - 1,
                pid_start_ticks=1,
                boot_id=read_boot_id(),
                phase="RECOVERING",
            )
            FenceStore(runtime).publish(fence)
            with mock.patch.object(
                supervisor_module, "_run_compatibility_handoff"
            ) as handoff:
                outcome = recover_offline(
                    root,
                    ROOT,
                    recover_compatibility=False,
                    forbid_compatibility_handoff=True,
                )
            handoff.assert_not_called()
            self.assertTrue(outcome.recovered)
            self.assertEqual(outcome.owner_epoch, fence.owner_epoch)
            self.assertIsNone(FenceStore(runtime).load())

    def test_strict_direct_recovery_fails_closed_on_disallowed_records(self) -> None:
        for residue_kind in (
            "compatibility-handoff",
            "non-direct-provider",
            "non-direct-provider-scope",
        ):
            with self.subTest(residue_kind=residue_kind):
                with tempfile.TemporaryDirectory() as temporary:
                    root, runtime = self.make_root(temporary)
                    fence = self.recovery_fence(runtime)
                    IntentStore(runtime)
                    recovery = RecoveryStore(runtime)
                    detached = DetachedScopeStore(root)
                    expected_error: str
                    if residue_kind == "compatibility-handoff":
                        scope = FakeScopeBackend().plan()
                        detached.put(
                            supervisor_module.DetachedScopeRecord(
                                schema_version=1,
                                record_version=1,
                                release_id=fence.release_id,
                                kind="compatibility-handoff",
                                phase="PREPARED",
                                owner_epoch=fence.owner_epoch,
                                child=dead_identity(),
                                scope=scope,
                            )
                        )
                        expected_error = "compatibility handoff scope"
                    elif residue_kind == "non-direct-provider":
                        request_value = self.recovery_request(fence, rung="vpn")
                        self.put_recovery(
                            runtime,
                            fence,
                            request_value,
                            "PREPARED",
                            None,
                        )
                        expected_error = "non-direct provider record"
                    else:
                        request_value = self.recovery_request(fence, rung="vpn")
                        recovery.provider_scope_store.put(
                            request_value,
                            ProviderScopeRecord(
                                schema_version=1,
                                record_version=1,
                                release_id=fence.release_id,
                                verb="provider-up",
                                phase="PREPARED",
                                request=request_value,
                                child=dead_identity(),
                                scope=FakeScopeBackend().plan(),
                            ),
                        )
                        expected_error = "non-direct provider scope"
                    self.prepare_scoped_recovery_locks(root)
                    before = tuple(
                        item
                        for item in self.recovery_tree_snapshot(root)
                        if item[0] not in {"bootstrap.lock", "compatibility.lock"}
                    )
                    with self.assertRaisesRegex(RecoveryRequired, expected_error):
                        recover_offline(
                            root,
                            ROOT,
                            recover_compatibility=False,
                            forbid_compatibility_handoff=True,
                        )
                    after = tuple(
                        item
                        for item in self.recovery_tree_snapshot(root)
                        if item[0] not in {"bootstrap.lock", "compatibility.lock"}
                    )
                    self.assertEqual(after, before)
                    self.assertEqual(FenceStore(runtime).load(), fence)

    def make_root(self, temporary: str) -> tuple[Path, SecureRuntime]:
        root = Path(temporary) / "control"
        runtime = SecureRuntime(root)
        runtime.initialize()
        return root, runtime

    @staticmethod
    def prepare_scoped_recovery_locks(root: Path) -> None:
        for name in ("bootstrap.lock", "compatibility.lock"):
            path = root / name
            path.write_bytes(b"")
            os.chmod(path, 0o600)

    @staticmethod
    def recovery_tree_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
        records: list[tuple[object, ...]] = []
        for path in sorted((root, *root.rglob("*")), key=lambda item: str(item)):
            info = path.lstat()
            records.append(
                (
                    str(path.relative_to(root)),
                    info.st_mode,
                    info.st_uid,
                    info.st_gid,
                    info.st_dev,
                    info.st_ino,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                    path.read_bytes() if path.is_file() else None,
                )
            )
        return tuple(records)

    def stale_fence(self, runtime: SecureRuntime) -> FenceRecord:
        record = FenceRecord(
            schema_version=1,
            release_id="old-release",
            owner_epoch="old-epoch",
            pid=2**31 - 1,
            pid_start_ticks=1,
            boot_id=read_boot_id(),
            phase="BOOTSTRAPPING",
        )
        FenceStore(runtime).publish(record)
        return record

    def recovery_fence(self, runtime: SecureRuntime, owner: str = "dead-epoch") -> FenceRecord:
        record = FenceRecord(
            schema_version=1,
            release_id=_release_id(ROOT),
            owner_epoch=owner,
            pid=2**31 - 1,
            pid_start_ticks=1,
            boot_id=read_boot_id(),
            phase="DRAINING",
        )
        FenceStore(runtime).publish(record)
        return record

    def recovery_request(
        self,
        fence: FenceRecord,
        *,
        rung: str = "direct",
        generation: int = 1,
    ) -> ProviderRequest:
        wanted = dataclasses.replace(
            contract(ladder=(rung,)),
            release_id=fence.release_id,
        )
        return ProviderRequest(
            owner_epoch=fence.owner_epoch,
            transition_id=f"transition-{generation}",
            generation=generation,
            rung=rung,
            model_id=wanted.model_id,
            private_endpoint=wanted.private_ports
            and Endpoint("127.0.0.1", wanted.private_ports[0]),
            contract=wanted,
        )

    def put_recovery(
        self,
        runtime: SecureRuntime,
        fence: FenceRecord,
        request_value: ProviderRequest,
        phase: str,
        resources: ProviderResourceGraph | None,
    ) -> str:
        effect_id = f"{fence.owner_epoch}-g{request_value.generation}-start"
        RecoveryStore(runtime).put_provider(
            ProviderRecoveryRecord(
                schema_version=1,
                record_version=1,
                release_id=fence.release_id,
                owner_epoch=fence.owner_epoch,
                effect_id=effect_id,
                phase=phase,
                request=request_value,
                resources=resources,
            )
        )
        IntentStore(runtime).put(
            EffectIntent(
                schema_version=1,
                owner_epoch=fence.owner_epoch,
                generation=request_value.generation,
                effect_id=effect_id,
                operation="provider-start",
                parameters_digest=hashlib.sha256(
                    canonical_json_bytes(request_value.to_dict())
                ).hexdigest(),
                phase=phase if phase in {"PREPARED", "APPLIED", "FAILED"} else "CLEANED",
            )
        )
        return effect_id

    def exact_graph(
        self,
        root: Path,
        request_value: ProviderRequest,
        *,
        privileged: tuple[PrivilegedResourceIdentity, ...] = (),
    ) -> ProviderResourceGraph:
        provider_root = root / "p"
        runtime = recovery_workspace(root, request_value)
        for directory in (provider_root, runtime):
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        inventory = runtime / "inventory.json"
        inventory.write_text("recovery\n", encoding="ascii")
        os.chmod(inventory, 0o600)
        info = inventory.lstat()
        process = dead_identity()
        return ProviderResourceGraph(
            owner_epoch=request_value.owner_epoch,
            transition_id=request_value.transition_id,
            generation=request_value.generation,
            rung=request_value.rung,
            runtime_dir=str(runtime),
            processes=(process,),
            listeners=(
                ListenerIdentity(request_value.private_endpoint, 99_001, process),
            ),
            paths=(
                PathIdentity(
                    path=str(inventory),
                    kind="inventory",
                    device=info.st_dev,
                    inode=info.st_ino,
                    uid=info.st_uid,
                    mode=info.st_mode & 0o7777,
                ),
            ),
            privileged=privileged,
        )

    def test_dead_effect_free_bootstrap_is_recovered_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            self.stale_fence(runtime)
            wanted = contract()
            provider = ScriptedProvider(())
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                expected_control_cap=wanted.limits.max_control_connections,
                release_id=wanted.release_id,
                providers={"*": provider},
                qualifier=evidence,
                start_watchdog=False,
            )
            supervisor.bootstrap()
            try:
                current = FenceStore(runtime).load()
                self.assertIsNotNone(current)
                self.assertEqual(current.owner_epoch, supervisor.owner_epoch)
            finally:
                supervisor._cleanup_proved = True
                supervisor.finalize()

    def test_warm_handoff_runs_after_fence_and_before_ready_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            wanted = contract()
            observed: list[str] = []

            def handoff(control_root, _release, owner, release_id, **_kwargs):
                self.assertEqual(control_root, root)
                fence = FenceStore(runtime).load()
                self.assertIsNotNone(fence)
                self.assertEqual(fence.owner_epoch, owner)
                self.assertEqual(fence.release_id, release_id)
                self.assertFalse((root / "supervisor.ready").exists())
                observed.append(owner)

            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                providers={"*": ScriptedProvider(())},
                qualifier=evidence,
                start_watchdog=False,
                warm_legacy_handoff=True,
            )
            with mock.patch(
                "grok_ms.supervisor._run_compatibility_handoff",
                side_effect=handoff,
            ):
                supervisor.bootstrap()
            try:
                self.assertEqual(observed, [supervisor.owner_epoch])
                self.assertTrue((root / "supervisor.ready").exists())
            finally:
                supervisor._cleanup_proved = True
                supervisor.finalize()

    def test_owned_before_ready_sigkill_recovers_exact_supervisor_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            release_id = _release_id(ROOT)
            wanted = dataclasses.replace(contract(), release_id=release_id)
            backend = LinuxCgroupV2Scope()
            store = DetachedScopeStore(root)
            planned = backend.plan()
            start_read, start_write = os.pipe2(os.O_CLOEXEC)
            checkpoint_read, checkpoint_write = os.pipe2(os.O_CLOEXEC)
            child = os.fork()
            if child == 0:
                os.close(start_write)
                os.close(checkpoint_read)
                if os.read(start_read, 1) != b"1":
                    os._exit(90)
                os.close(start_read)
                supervisor = Supervisor(
                    root,
                    ROOT,
                    wanted.digest(),
                    release_id=release_id,
                    providers={"*": ScriptedProvider(())},
                    qualifier=evidence,
                    start_watchdog=False,
                    scoped_bootstrap=True,
                    process_scopes=LinuxCgroupV2Scope(),
                )

                def pause_before_listener(*_args, **_kwargs):
                    os.write(checkpoint_write, b"1")
                    while True:
                        signal.pause()

                try:
                    with mock.patch.object(
                        supervisor_module,
                        "bind_seqpacket_listener",
                        side_effect=pause_before_listener,
                    ):
                        supervisor.bootstrap()
                except BaseException:
                    os._exit(91)
                os._exit(92)
            os.close(start_read)
            os.close(checkpoint_write)
            identity = ProcessIdentity(
                child,
                read_pid_start_ticks(child),
                read_boot_id(),
            )
            prepared = supervisor_module.DetachedScopeRecord(
                schema_version=1,
                record_version=1,
                release_id=release_id,
                kind="supervisor-epoch",
                phase="PREPARED",
                owner_epoch=None,
                child=identity,
                scope=planned,
            )
            store.put(prepared)
            handle = backend.create(planned)
            created = prepared.with_phase(
                "SCOPE_CREATED", scope=handle.identity
            )
            store.replace(prepared, created)
            backend.attach(handle, identity)
            attached = created.with_phase("ATTACHED")
            store.replace(created, attached)
            handle.close()
            try:
                self.assertEqual(os.write(start_write, b"1"), 1)
                os.close(start_write)
                start_write = -1
                readable, _, _ = select.select(
                    [checkpoint_read], [], [], 8
                )
                self.assertEqual(readable, [checkpoint_read])
                self.assertEqual(os.read(checkpoint_read, 1), b"1")
                owned = store.load("supervisor-epoch")
                self.assertIsNotNone(owned)
                assert owned is not None
                self.assertEqual(owned.phase, "OWNED")
                self.assertIsNotNone(owned.owner_epoch)
                fence = FenceStore(runtime).load()
                self.assertIsNotNone(fence)
                assert fence is not None
                self.assertEqual(fence.owner_epoch, owned.owner_epoch)
                self.assertFalse((root / "supervisor.ready").exists())
                self.assertFalse((root / "supervisor.sock").exists())

                os.kill(child, signal.SIGKILL)
                waited, status = os.waitpid(child, 0)
                self.assertEqual(waited, child)
                self.assertTrue(os.WIFSIGNALED(status))
                self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                outcome = recover_offline(
                    root,
                    ROOT,
                    process_scopes=backend,
                    recover_compatibility=False,
                )
                self.assertTrue(outcome.recovered)
                self.assertIsNone(store.load("supervisor-epoch"))
                self.assertIsNone(FenceStore(runtime).load())
                self.assertFalse(Path(attached.scope.scope_path).exists())
                self.assertFalse((root / "supervisor.ready").exists())
            finally:
                if start_write >= 0:
                    os.close(start_write)
                os.close(checkpoint_read)
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child, os.WNOHANG)
                except ChildProcessError:
                    pass
                remaining = store.load("supervisor-epoch")
                if remaining is not None:
                    try:
                        backend.reconcile(
                            remaining.scope,
                            "ATTACHED"
                            if remaining.phase == "OWNED"
                            else remaining.phase,
                            remaining.child,
                            None,
                            5.0,
                        )
                        store.delete(remaining)
                    except Exception:
                        pass

    def test_failed_warm_handoff_keeps_fence_and_never_publishes_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            wanted = contract()
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                providers={"*": ScriptedProvider(())},
                qualifier=evidence,
                start_watchdog=False,
                warm_legacy_handoff=True,
            )
            with mock.patch(
                "grok_ms.supervisor._run_compatibility_handoff",
                side_effect=RecoveryRequired("legacy listener remains"),
            ):
                with self.assertRaisesRegex(RecoveryRequired, "legacy listener"):
                    supervisor.bootstrap()
            self.assertIsNotNone(FenceStore(runtime).load())
            self.assertFalse((root / "supervisor.ready").exists())

    def test_dead_epoch_with_prepared_effect_remains_fenced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            stale = self.stale_fence(runtime)
            digest = "d" * 64
            IntentStore(runtime).put(
                EffectIntent(
                    schema_version=1,
                    owner_epoch=stale.owner_epoch,
                    generation=1,
                    effect_id="g1-start",
                    operation="provider-start",
                    parameters_digest=digest,
                    phase="PREPARED",
                )
            )
            wanted = contract()
            supervisor = Supervisor(
                root,
                ROOT,
                wanted.digest(),
                release_id=wanted.release_id,
                providers={"*": ScriptedProvider(())},
                qualifier=evidence,
                start_watchdog=False,
            )
            with self.assertRaisesRegex(RecoveryRequired, "uncertain provider or intent"):
                supervisor.bootstrap()
            self.assertEqual(FenceStore(runtime).load(), stale)

    def test_offline_recovery_replays_graph_child_qualifier_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            fence = self.recovery_fence(runtime)
            request_value = self.recovery_request(fence)
            graph = self.exact_graph(root, request_value)
            effect_id = self.put_recovery(
                runtime, fence, request_value, "APPLIED", graph
            )
            leaders = root / "leaders"
            leaders.mkdir(mode=0o700)
            os.chmod(leaders, 0o700)
            child = subprocess.Popen(["sleep", "60"])
            child_identity = ProcessIdentity(
                child.pid,
                read_pid_start_ticks(child.pid),
                read_boot_id(),
            )
            process_scopes = LinuxCgroupV2Scope()
            child_scope = process_scopes.create(process_scopes.plan())
            process_scopes.attach(child_scope, child_identity)
            child_scope.close()
            RecoveryStore(runtime).put_child(
                ChildRecoveryRecord(
                    schema_version=1,
                    record_version=2,
                    release_id=fence.release_id,
                    owner_epoch=fence.owner_epoch,
                    lease_id="a" * 32,
                    phase="ATTACHED",
                    child=child_identity,
                    leader_path=str(leaders / "l-123456789abc.sock"),
                    scope=child_scope.identity,
                )
            )
            qualifier = root / "qualify" / "models-crash"
            qualifier.mkdir(parents=True, mode=0o700)
            os.chmod(qualifier.parent, 0o700)
            os.chmod(qualifier, 0o700)
            auth = qualifier / "auth.json"
            auth.write_text("{}", encoding="ascii")
            os.chmod(auth, 0o600)
            adapter = ExactRecoveryProvider(root)
            outcome = recover_offline(
                root,
                ROOT,
                providers={"direct": adapter},
                recover_compatibility=False,
            )
            child.wait(timeout=3)
            self.assertTrue(outcome.recovered)
            self.assertEqual((outcome.provider_records, outcome.child_records), (1, 1))
            self.assertEqual(adapter.calls, [("direct", 1, True)])
            self.assertFalse((root / "recovery.fence").exists())
            self.assertIsNone(IntentStore(runtime).load(effect_id))
            self.assertFalse((root / "qualify").exists())
            second = recover_offline(
                root,
                ROOT,
                providers={"direct": adapter},
                recover_compatibility=False,
            )
            self.assertFalse(second.recovered)
            self.assertEqual(adapter.calls, [("direct", 1, True)])

    def test_offline_recovery_deletes_orphan_cleaned_intent_before_clearing_fence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            fence = self.recovery_fence(runtime)
            intent = EffectIntent(
                schema_version=1,
                owner_epoch=fence.owner_epoch,
                generation=1,
                effect_id=f"{fence.owner_epoch}-g1-start",
                operation="provider-start",
                parameters_digest="d" * 64,
                phase="CLEANED",
            )
            intents = IntentStore(runtime)
            intents.put(intent)

            outcome = recover_offline(
                root,
                ROOT,
                recover_compatibility=False,
            )

            self.assertTrue(outcome.recovered)
            self.assertIsNone(intents.load(intent.effect_id))
            self.assertIsNone(FenceStore(runtime).load())

    def test_real_sigkill_at_cleaned_intent_persistence_boundaries(self) -> None:
        boundaries = (
            ("intent-cleaned", "CLEANED", "APPLIED", 1),
            ("provider-cleaned", "CLEANED", "CLEANED", 1),
            ("intent-deleted", None, "CLEANED", 1),
            ("provider-deleted", None, None, 0),
        )
        for boundary, expected_intent, expected_record, expected_replays in boundaries:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                root, runtime = self.make_root(temporary)
                release_id = _release_id(ROOT)
                owner = f"intent-crash-{boundary}"
                wanted = dataclasses.replace(
                    contract(ladder=("direct",)), release_id=release_id
                )
                request_value = ProviderRequest(
                    owner_epoch=owner,
                    transition_id="intent-crash-transition",
                    generation=1,
                    rung="direct",
                    model_id=wanted.model_id,
                    private_endpoint=Endpoint(
                        "127.0.0.1", wanted.private_ports[0]
                    ),
                    contract=wanted,
                )
                process_identity = dead_identity()
                graph = ProviderResourceGraph(
                    owner_epoch=owner,
                    transition_id=request_value.transition_id,
                    generation=1,
                    rung="direct",
                    runtime_dir=f"/tmp/grok-intent-{boundary}",
                    processes=(process_identity,),
                    listeners=(
                        ListenerIdentity(
                            request_value.private_endpoint,
                            99_001,
                            process_identity,
                        ),
                    ),
                    paths=(),
                )
                effect_id = f"{owner}-g1-start"
                read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                child = os.fork()
                if child == 0:
                    os.close(read_fd)
                    identity = current_process_identity()
                    FenceStore(runtime).publish(
                        FenceRecord(
                            schema_version=1,
                            release_id=release_id,
                            owner_epoch=owner,
                            pid=identity.pid,
                            pid_start_ticks=identity.start_ticks,
                            boot_id=identity.boot_id,
                            phase="DRAINING",
                        )
                    )
                    intents = IntentStore(runtime)
                    store = RecoveryStore(runtime)
                    intents.put(
                        EffectIntent(
                            schema_version=1,
                            owner_epoch=owner,
                            generation=1,
                            effect_id=effect_id,
                            operation="provider-start",
                            parameters_digest=hashlib.sha256(
                                canonical_json_bytes(request_value.to_dict())
                            ).hexdigest(),
                            phase="APPLIED",
                        )
                    )
                    store.put_provider(
                        ProviderRecoveryRecord(
                            schema_version=1,
                            record_version=1,
                            release_id=release_id,
                            owner_epoch=owner,
                            effect_id=effect_id,
                            phase="APPLIED",
                            request=request_value,
                            resources=graph,
                        )
                    )

                    class ChildAdapter:
                        def stop(self, *_args) -> None:
                            return None

                        def prove_empty(self, _result) -> ResidueReport:
                            return ResidueReport(True, ())

                    adapter = ChildAdapter()
                    supervisor = Supervisor(
                        root,
                        ROOT,
                        wanted.digest(),
                        release_id=release_id,
                        providers={"*": adapter},
                        qualifier=evidence,
                        start_watchdog=False,
                    )
                    supervisor.intents = intents
                    supervisor.recovery = store

                    def checkpoint() -> None:
                        os.write(write_fd, b"1")
                        while True:
                            signal.pause()

                    original_advance = IntentStore.advance
                    original_replace = RecoveryStore.replace_provider
                    original_intent_delete = IntentStore.delete
                    original_provider_delete = RecoveryStore.delete_provider

                    def advance(instance, effect, old, new):
                        result = original_advance(instance, effect, old, new)
                        if boundary == "intent-cleaned" and new == "CLEANED":
                            checkpoint()
                        return result

                    def replace_provider(instance, record):
                        result = original_replace(instance, record)
                        if boundary == "provider-cleaned" and record.phase == "CLEANED":
                            checkpoint()
                        return result

                    def delete_intent(instance, effect):
                        result = original_intent_delete(instance, effect)
                        if boundary == "intent-deleted":
                            checkpoint()
                        return result

                    def delete_provider(instance, effect):
                        result = original_provider_delete(instance, effect)
                        if boundary == "provider-deleted":
                            checkpoint()
                        return result

                    try:
                        with (
                            mock.patch.object(IntentStore, "advance", advance),
                            mock.patch.object(
                                RecoveryStore, "replace_provider", replace_provider
                            ),
                            mock.patch.object(IntentStore, "delete", delete_intent),
                            mock.patch.object(
                                RecoveryStore, "delete_provider", delete_provider
                            ),
                        ):
                            supervisor._stop_result(
                                adapter,
                                SimpleNamespace(
                                    request=request_value, resources=graph
                                ),
                                TransitionDeadline.after_ms(5_000),
                                effect_id,
                            )
                    except BaseException:
                        os._exit(91)
                    os._exit(92)
                os.close(write_fd)
                try:
                    readable, _, _ = select.select([read_fd], [], [], 8)
                    self.assertEqual(readable, [read_fd])
                    self.assertEqual(os.read(read_fd, 1), b"1")
                    os.kill(child, signal.SIGKILL)
                    waited, status = os.waitpid(child, 0)
                    self.assertEqual(waited, child)
                    self.assertTrue(os.WIFSIGNALED(status))
                    self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                finally:
                    os.close(read_fd)
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(child, os.WNOHANG)
                    except ChildProcessError:
                        pass

                intent = IntentStore(runtime).load(effect_id)
                record = RecoveryStore(runtime).load_provider(effect_id)
                self.assertEqual(
                    None if intent is None else intent.phase, expected_intent
                )
                self.assertEqual(
                    None if record is None else record.phase, expected_record
                )
                self.assertIsNotNone(FenceStore(runtime).load())

                class RecoveryAdapter:
                    def __init__(self) -> None:
                        self.calls = 0

                    def recover(self, *_args) -> ResidueReport:
                        self.calls += 1
                        return ResidueReport(True, ())

                adapter = RecoveryAdapter()
                first = recover_offline(
                    root,
                    ROOT,
                    providers={"direct": adapter},
                    recover_compatibility=False,
                )
                self.assertTrue(first.recovered)
                self.assertEqual(adapter.calls, expected_replays)
                self.assertIsNone(IntentStore(runtime).load(effect_id))
                self.assertIsNone(RecoveryStore(runtime).load_provider(effect_id))
                self.assertIsNone(FenceStore(runtime).load())
                second = recover_offline(
                    root,
                    ROOT,
                    providers={"direct": adapter},
                    recover_compatibility=False,
                )
                self.assertFalse(second.recovered)
                self.assertEqual(adapter.calls, expected_replays)

    def test_offline_recovery_kills_probe_descendant_and_removes_exact_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            fence = self.recovery_fence(runtime)
            marker = Path(temporary) / "probe-descendant.pid"
            source = (
                "import pathlib,subprocess,time\n"
                "p=subprocess.Popen(['/bin/sleep','60'],start_new_session=True)\n"
                f"pathlib.Path({str(marker)!r}).write_text(str(p.pid),encoding='ascii')\n"
                "while True: time.sleep(1)\n"
            )
            parent = current_process_identity()
            barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
            process = subprocess.Popen(
                [
                    "/usr/bin/python3",
                    "-I",
                    str(ROOT / "grok_ms" / "parent_guard.py"),
                    "--parent-pid",
                    str(parent.pid),
                    "--parent-start-ticks",
                    str(parent.start_ticks),
                    "--parent-boot-id",
                    parent.boot_id,
                    "--barrier-fd",
                    str(barrier_read),
                    "--",
                    "/usr/bin/python3",
                    "-c",
                    source,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(barrier_read,),
                start_new_session=True,
            )
            os.close(barrier_read)
            direct = ProcessIdentity(
                process.pid,
                read_pid_start_ticks(process.pid),
                read_boot_id(),
            )
            scopes = LinuxCgroupV2Scope()
            planned = scopes.plan()
            record = ProbeRecoveryRecord(
                schema_version=1,
                record_version=1,
                release_id=fence.release_id,
                owner_epoch=fence.owner_epoch,
                probe_id="c" * 32,
                phase="PREPARED",
                child=direct,
                scope=planned,
            )
            store = RecoveryStore(runtime)
            store.put_probe(record)
            handle = scopes.create(planned)
            record = dataclasses.replace(
                record,
                phase="SCOPE_CREATED",
                scope=handle.identity,
            )
            store.replace_probe(record)
            scopes.attach(handle, direct)
            record = dataclasses.replace(record, phase="ATTACHED")
            store.replace_probe(record)
            handle.close()
            self.assertEqual(os.write(barrier_write, b"\x01"), 1)
            os.close(barrier_write)
            descendant_pid = wait_for_decimal_file(marker)
            descendant = ProcessIdentity(
                descendant_pid,
                read_pid_start_ticks(descendant_pid),
                read_boot_id(),
            )
            descendant_pidfd = os.pidfd_open(descendant.pid, 0)
            self.addCleanup(os.close, descendant_pidfd)

            outcome = recover_offline(
                root,
                ROOT,
                recover_compatibility=False,
            )
            process.wait(timeout=3)
            self.assertTrue(outcome.recovered)
            self.assertEqual(outcome.probe_records, 1)
            self.assertFalse(process_matches(direct))
            readable, _, _ = select.select([descendant_pidfd], [], [], 2)
            self.assertEqual(readable, [descendant_pidfd])
            self.assertFalse(Path(record.scope.scope_path).exists())
            self.assertEqual(store.list_probes(), ())
            self.assertFalse((root / "recovery.fence").exists())

    def test_offline_recovery_discards_strict_probe_stages_at_each_write_boundary(self) -> None:
        for crash_at, persisted_phase, recovered_phase in (
            ("put", None, None),
            ("SCOPE_CREATED", "PREPARED", "PREPARED"),
            ("ATTACHED", "SCOPE_CREATED", "SCOPE_CREATED"),
        ):
            with self.subTest(crash_at=crash_at):
                with tempfile.TemporaryDirectory() as temporary:
                    root, runtime = self.make_root(temporary)
                    fence = self.recovery_fence(runtime)
                    backend = FakeScopeBackend()
                    planned = backend.plan()
                    created = dataclasses.replace(
                        planned,
                        scope_device=1,
                        scope_inode=101,
                    )
                    child = dead_identity()
                    probe_id = "d" * 32
                    prepared = ProbeRecoveryRecord(
                        schema_version=1,
                        record_version=1,
                        release_id=fence.release_id,
                        owner_epoch=fence.owner_epoch,
                        probe_id=probe_id,
                        phase="PREPARED",
                        child=child,
                        scope=planned,
                    )
                    scope_created = dataclasses.replace(
                        prepared,
                        phase="SCOPE_CREATED",
                        scope=created,
                    )
                    attached = dataclasses.replace(scope_created, phase="ATTACHED")
                    store = RecoveryStore(runtime)
                    if persisted_phase == "PREPARED":
                        store.put_probe(prepared)
                        staged_payload = scope_created.to_dict()
                    elif persisted_phase == "SCOPE_CREATED":
                        store.put_probe(scope_created)
                        staged_payload = attached.to_dict()
                    else:
                        staged_payload = prepared.to_dict()
                    staged = store.probes / f".{probe_id}.json.{'e' * 24}.tmp"
                    staged.write_bytes(canonical_json_bytes(staged_payload) + b"\n")
                    os.chmod(staged, 0o600)

                    outcome = recover_offline(
                        root,
                        ROOT,
                        process_scopes=backend,
                        recover_compatibility=False,
                    )
                    self.assertTrue(outcome.recovered)
                    self.assertEqual(
                        outcome.probe_records,
                        0 if persisted_phase is None else 1,
                    )
                    if recovered_phase is None:
                        self.assertFalse(
                            any(call[0] == "reconcile" for call in backend.calls)
                        )
                    else:
                        self.assertIn(("reconcile", recovered_phase), backend.calls)
                    self.assertFalse(staged.exists())
                    self.assertEqual(store.list_probes(), ())
                    self.assertFalse((root / "recovery.fence").exists())

    def test_offline_recovery_accepts_exact_post_link_probe_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            fence = self.recovery_fence(runtime)
            backend = FakeScopeBackend()
            probe_id = "f" * 32
            record = ProbeRecoveryRecord(
                schema_version=1,
                record_version=1,
                release_id=fence.release_id,
                owner_epoch=fence.owner_epoch,
                probe_id=probe_id,
                phase="PREPARED",
                child=dead_identity(),
                scope=backend.plan(),
            )
            store = RecoveryStore(runtime)
            store.put_probe(record)
            final = store.probe_path(probe_id)
            staged = store.probes / f".{probe_id}.json.{'a' * 24}.tmp"
            os.link(final, staged)
            self.assertEqual(final.stat().st_nlink, 2)

            outcome = recover_offline(
                root,
                ROOT,
                process_scopes=backend,
                recover_compatibility=False,
            )
            self.assertTrue(outcome.recovered)
            self.assertIn(("reconcile", "PREPARED"), backend.calls)
            self.assertFalse(staged.exists())
            self.assertFalse(final.exists())
            self.assertFalse((root / "recovery.fence").exists())

    def test_offline_recovery_converges_readiness_publish_crash_states(self) -> None:
        for crash_state in ("staged", "linked", "partial-legacy-final"):
            with self.subTest(crash_state=crash_state):
                with tempfile.TemporaryDirectory() as temporary:
                    root, runtime = self.make_root(temporary)
                    fence = self.recovery_fence(runtime)
                    ready = root / "supervisor.ready"
                    staged = root / f".supervisor.ready.{'b' * 24}.tmp"
                    payload = {
                        "schema_version": 1,
                        "protocol_version": 1,
                        "release_id": fence.release_id,
                        "owner_epoch": fence.owner_epoch,
                        "pid": fence.pid,
                        "pid_start_ticks": fence.pid_start_ticks,
                        "boot_id": fence.boot_id,
                        "socket": str(root / "supervisor.sock"),
                    }
                    if crash_state == "partial-legacy-final":
                        ready.write_bytes(b"{")
                        os.chmod(ready, 0o600)
                    else:
                        staged.write_bytes(canonical_json_bytes(payload) + b"\n")
                        os.chmod(staged, 0o600)
                        if crash_state == "linked":
                            os.link(staged, ready)
                            self.assertEqual(staged.stat().st_nlink, 2)

                    outcome = recover_offline(
                        root,
                        ROOT,
                        recover_compatibility=False,
                    )
                    self.assertTrue(outcome.recovered)
                    self.assertFalse(staged.exists())
                    self.assertFalse(ready.exists())
                    self.assertFalse((root / "recovery.fence").exists())

    def test_offline_recovery_rejects_hostile_probe_stage_without_removing_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            fence = self.recovery_fence(runtime)
            store = RecoveryStore(runtime)
            staged = store.probes / f".{'e' * 32}.json.{'f' * 24}.tmp"
            staged.write_text("{}\n", encoding="ascii")
            os.chmod(staged, 0o644)

            with self.assertRaisesRegex(RuntimeSecurityError, "unsafe staged"):
                recover_offline(
                    root,
                    ROOT,
                    recover_compatibility=False,
                )
            self.assertTrue(staged.exists())
            self.assertEqual(FenceStore(runtime).load(), fence)

    def test_prepared_crash_before_spawn_removes_only_empty_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            fence = self.recovery_fence(runtime)
            request_value = self.recovery_request(fence)
            self.put_recovery(runtime, fence, request_value, "PREPARED", None)
            workspace = recovery_workspace(root, request_value)
            workspace.mkdir(parents=True, mode=0o700)
            for directory in (
                root / "p",
                workspace,
            ):
                os.chmod(directory, 0o700)
            outcome = recover_offline(root, ROOT, recover_compatibility=False)
            self.assertTrue(outcome.recovered)
            self.assertFalse(workspace.exists())
            self.assertFalse((root / "recovery.fence").exists())

    def test_prepared_unknown_effect_and_unsafe_qualifier_stay_fenced(self) -> None:
        for unsafe_qualifier in (False, True):
            with self.subTest(unsafe_qualifier=unsafe_qualifier):
                with tempfile.TemporaryDirectory() as temporary:
                    root, runtime = self.make_root(temporary)
                    fence = self.recovery_fence(runtime)
                    if unsafe_qualifier:
                        models = root / "qualify" / "models-unsafe"
                        models.mkdir(parents=True, mode=0o700)
                        os.chmod(models.parent, 0o700)
                        os.chmod(models, 0o700)
                        (models / "auth.json").symlink_to("/etc/passwd")
                    else:
                        request_value = self.recovery_request(fence)
                        self.put_recovery(
                            runtime, fence, request_value, "PREPARED", None
                        )
                        workspace = recovery_workspace(root, request_value)
                        workspace.mkdir(parents=True, mode=0o700)
                        for directory in (
                            root / "p",
                            workspace,
                        ):
                            os.chmod(directory, 0o700)
                        unknown = workspace / "unknown.state"
                        unknown.write_text("effect", encoding="ascii")
                        os.chmod(unknown, 0o600)
                    with self.assertRaises(
                        (ProviderResidueError, RuntimeError)
                    ):
                        recover_offline(
                            root, ROOT, recover_compatibility=False
                        )
                    retained = FenceStore(runtime).load()
                    self.assertIsNotNone(retained)
                    self.assertEqual(retained.owner_epoch, fence.owner_epoch)
                    self.assertEqual(retained.phase, "RECOVERING")

    def test_zombie_fence_owner_does_not_block_offline_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            child, owner = barriered_zombie()
            try:
                self.assertTrue(process_matches(owner))
                self.assertFalse(process_can_still_execute(owner))
                FenceStore(runtime).publish(
                    FenceRecord(
                        schema_version=1,
                        release_id=_release_id(ROOT),
                        owner_epoch="zombie-offline-owner",
                        pid=owner.pid,
                        pid_start_ticks=owner.start_ticks,
                        boot_id=owner.boot_id,
                        phase="DRAINING",
                    )
                )
                outcome = recover_offline(
                    root,
                    ROOT,
                    recover_compatibility=False,
                )
                self.assertTrue(outcome.recovered)
                self.assertEqual(outcome.owner_epoch, "zombie-offline-owner")
                self.assertIsNone(FenceStore(runtime).load())
            finally:
                os.waitpid(child, 0)

    def test_unknown_owner_state_never_grants_recovery_authority(self) -> None:
        owner = current_process_identity()
        with mock.patch(
            "grok_ms.runtime._read_pid_state_and_start_ticks",
            side_effect=PermissionError("injected proc denial"),
        ):
            self.assertTrue(process_can_still_execute(owner))

    def test_zombie_fence_owner_does_not_block_effect_free_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            child, owner = barriered_zombie()
            supervisor: Supervisor | None = None
            try:
                FenceStore(runtime).publish(
                    FenceRecord(
                        schema_version=1,
                        release_id="stale-release",
                        owner_epoch="zombie-bootstrap-owner",
                        pid=owner.pid,
                        pid_start_ticks=owner.start_ticks,
                        boot_id=owner.boot_id,
                        phase="BOOTSTRAPPING",
                    )
                )
                wanted = contract()
                supervisor = Supervisor(
                    root,
                    ROOT,
                    wanted.digest(),
                    expected_control_cap=wanted.limits.max_control_connections,
                    release_id=wanted.release_id,
                    providers={"*": ScriptedProvider(())},
                    qualifier=evidence,
                    start_watchdog=False,
                )
                supervisor.bootstrap()
                current = FenceStore(runtime).load()
                self.assertIsNotNone(current)
                self.assertEqual(current.owner_epoch, supervisor.owner_epoch)
            finally:
                if supervisor is not None and supervisor._bootstrapped:
                    supervisor._cleanup_proved = True
                    supervisor.finalize()
                os.waitpid(child, 0)

    def test_offline_recovery_uses_one_deadline_across_probe_records(self) -> None:
        class BudgetScopeBackend(FakeScopeBackend):
            def __init__(self) -> None:
                super().__init__()
                self.reconcile_timeouts: list[float] = []

            def reconcile(
                self,
                scope,
                phase,
                child,
                pidfd,
                timeout_seconds,
                *,
                handle=None,
            ) -> None:
                del scope, child, pidfd, handle
                self.calls.append(("reconcile", phase))
                self.reconcile_timeouts.append(timeout_seconds)
                time.sleep(min(0.11, timeout_seconds))

        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            fence = self.recovery_fence(runtime)
            store = RecoveryStore(runtime)
            backend = BudgetScopeBackend()
            child = dead_identity()
            for number in range(3):
                store.put_probe(
                    ProbeRecoveryRecord(
                        schema_version=1,
                        record_version=1,
                        release_id=fence.release_id,
                        owner_epoch=fence.owner_epoch,
                        probe_id=f"{number + 1:032x}",
                        phase="PREPARED",
                        child=child,
                        scope=backend.plan(),
                    )
                )
            started = time.monotonic()
            with self.assertRaises(ProviderTimeout):
                recover_offline(
                    root,
                    ROOT,
                    process_scopes=backend,
                    stop_ms=250,
                    recover_compatibility=False,
                )
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.40)
            self.assertGreaterEqual(len(backend.reconcile_timeouts), 2)
            self.assertLess(
                backend.reconcile_timeouts[-1],
                backend.reconcile_timeouts[0],
            )
            retained = FenceStore(runtime).load()
            self.assertIsNotNone(retained)
            self.assertEqual(retained.phase, "RECOVERING")

    def test_live_fence_refuses_offline_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            owner = current_process_identity()
            FenceStore(runtime).publish(
                FenceRecord(
                    schema_version=1,
                    release_id=_release_id(ROOT),
                    owner_epoch="live-epoch",
                    pid=owner.pid,
                    pid_start_ticks=owner.start_ticks,
                    boot_id=owner.boot_id,
                    phase="READY",
                )
            )
            from grok_ms.runtime import FenceBusyError

            with self.assertRaises(FenceBusyError):
                recover_offline(root, ROOT, recover_compatibility=False)

    def test_exact_live_fence_refuses_before_store_creation_or_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            owner = current_process_identity()
            fence = FenceRecord(
                schema_version=1,
                release_id=_release_id(ROOT),
                owner_epoch="exact-live-epoch",
                pid=owner.pid,
                pid_start_ticks=owner.start_ticks,
                boot_id=owner.boot_id,
                phase="READY",
            )
            FenceStore(runtime).publish(fence)
            self.prepare_scoped_recovery_locks(root)
            expected = (fence.release_id, fence.owner_epoch, owner)
            before = self.recovery_tree_snapshot(root)
            from grok_ms.runtime import FenceBusyError

            with (
                mock.patch.object(supervisor_module, "IntentStore") as intents,
                mock.patch.object(supervisor_module, "RecoveryStore") as recovery,
                mock.patch.object(
                    supervisor_module, "DetachedScopeStore"
                ) as detached_scopes,
            ):
                with self.assertRaisesRegex(FenceBusyError, "still alive"):
                    recover_offline(
                        root,
                        ROOT,
                        recover_compatibility=False,
                        expected_fence=expected,
                    )
                intents.assert_not_called()
                recovery.assert_not_called()
                detached_scopes.assert_not_called()

            self.assertEqual(self.recovery_tree_snapshot(root), before)
            self.assertEqual(FenceStore(runtime).load(), fence)

    def test_offline_recovery_exact_expectation_cannot_reconcile_replacement_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            replacement = self.recovery_fence(runtime, owner="replacement-epoch")
            self.prepare_scoped_recovery_locks(root)
            expected = (
                replacement.release_id,
                "original-epoch",
                ProcessIdentity(
                    replacement.pid,
                    replacement.pid_start_ticks,
                    replacement.boot_id,
                ),
            )
            before = self.recovery_tree_snapshot(root)
            from grok_ms.runtime import FenceBusyError

            with self.assertRaisesRegex(FenceBusyError, "differs from the exact"):
                recover_offline(
                    root,
                    ROOT,
                    recover_compatibility=False,
                    expected_fence=expected,
                )
            self.assertEqual(self.recovery_tree_snapshot(root), before)
            self.assertEqual(FenceStore(runtime).load(), replacement)

    def test_offline_recovery_expected_absence_rejects_any_epoch_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            replacement = self.recovery_fence(runtime, owner="replacement-epoch")
            self.prepare_scoped_recovery_locks(root)
            before = self.recovery_tree_snapshot(root)
            from grok_ms.runtime import FenceBusyError

            with self.assertRaisesRegex(FenceBusyError, "expected no fence"):
                recover_offline(
                    root,
                    ROOT,
                    recover_compatibility=False,
                    require_fence_absent=True,
                )
            self.assertEqual(self.recovery_tree_snapshot(root), before)
            self.assertEqual(FenceStore(runtime).load(), replacement)

    def test_offline_recovery_expected_absence_accepts_empty_qualifier_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            IntentStore(runtime)
            RecoveryStore(runtime)
            DetachedScopeStore(root)
            self.prepare_scoped_recovery_locks(root)
            qualifier = root / "qualify"
            qualifier.mkdir(mode=0o700)
            before = qualifier.lstat()

            outcome = recover_offline(
                root,
                ROOT,
                recover_compatibility=False,
                require_fence_absent=True,
            )

            after = qualifier.lstat()
            self.assertFalse(outcome.recovered)
            self.assertEqual(
                (after.st_dev, after.st_ino),
                (before.st_dev, before.st_ino),
            )
            self.assertEqual(tuple(qualifier.iterdir()), ())

    def test_offline_recovery_unscoped_accepts_empty_qualifier_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _runtime = self.make_root(temporary)
            qualifier = root / "qualify"
            qualifier.mkdir(mode=0o700)
            before = qualifier.lstat()

            outcome = recover_offline(
                root,
                ROOT,
                recover_compatibility=False,
                forbid_compatibility_handoff=True,
            )

            after = qualifier.lstat()
            self.assertFalse(outcome.recovered)
            self.assertEqual(
                (after.st_dev, after.st_ino),
                (before.st_dev, before.st_ino),
            )
            self.assertEqual(tuple(qualifier.iterdir()), ())

    def test_offline_recovery_does_not_repair_unsafe_empty_qualifier_root(self) -> None:
        for kind in ("mode", "symlink", "file"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root, _runtime = self.make_root(temporary)
                qualifier = root / "qualify"
                if kind == "mode":
                    qualifier.mkdir(mode=0o700)
                    qualifier.chmod(0o755)
                elif kind == "symlink":
                    target = root / "qualify-target"
                    target.mkdir(mode=0o700)
                    qualifier.symlink_to(target)
                else:
                    qualifier.write_bytes(b"")
                    qualifier.chmod(0o600)
                before = qualifier.lstat()

                with self.assertRaises(RuntimeSecurityError):
                    recover_offline(
                        root,
                        ROOT,
                        recover_compatibility=False,
                        forbid_compatibility_handoff=True,
                    )

                after = qualifier.lstat()
                self.assertEqual(
                    (after.st_mode, after.st_dev, after.st_ino),
                    (before.st_mode, before.st_dev, before.st_ino),
                )

    def test_offline_recovery_expected_absence_rejects_qualifier_children(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            IntentStore(runtime)
            RecoveryStore(runtime)
            DetachedScopeStore(root)
            self.prepare_scoped_recovery_locks(root)
            qualifier = root / "qualify"
            residue = qualifier / "models-residue"
            residue.mkdir(parents=True, mode=0o700)
            qualifier.chmod(0o700)

            with self.assertRaisesRegex(RecoveryRequired, "qualification residue remains"):
                recover_offline(
                    root,
                    ROOT,
                    recover_compatibility=False,
                    require_fence_absent=True,
                )

            self.assertTrue(residue.is_dir())

    def test_offline_recovery_exact_expectation_reconciles_only_its_dead_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            owned = self.recovery_fence(runtime, owner="owned-dead-epoch")
            IntentStore(runtime)
            RecoveryStore(runtime)
            self.prepare_scoped_recovery_locks(root)
            expected = (
                owned.release_id,
                owned.owner_epoch,
                ProcessIdentity(
                    owned.pid,
                    owned.pid_start_ticks,
                    owned.boot_id,
                ),
            )
            first = recover_offline(
                root,
                ROOT,
                recover_compatibility=False,
                expected_fence=expected,
            )
            self.assertTrue(first.recovered)
            self.assertEqual(first.owner_epoch, owned.owner_epoch)
            self.assertIsNone(FenceStore(runtime).load())
            second = recover_offline(
                root,
                ROOT,
                recover_compatibility=False,
                require_fence_absent=True,
            )
            self.assertFalse(second.recovered)
            self.assertIsNone(second.owner_epoch)

    def test_vpn_recovery_delegates_root_ledger_with_frozen_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime = self.make_root(temporary)
            fence = self.recovery_fence(runtime)
            request_value = self.recovery_request(fence, rung="vpn")
            privileged = tuple(
                PrivilegedResourceIdentity(kind, name, request_value.transition_id)
                for kind, name in (
                    ("namespace", "grokvpn"),
                    ("tun", "tun-grok"),
                    ("vpn_daemon", "openvpn"),
                )
            )
            graph = self.exact_graph(
                root, request_value, privileged=privileged
            )
            self.put_recovery(runtime, fence, request_value, "APPLIED", graph)
            root_ledger = root / "root-ledger-sentinel"
            root_ledger.write_text("owned", encoding="ascii")
            adapter = ExactRecoveryProvider(root, marker=root_ledger)
            outcome = recover_offline(
                root,
                ROOT,
                providers={"vpn": adapter},
                recover_compatibility=False,
            )
            self.assertTrue(outcome.recovered)
            self.assertFalse(root_ledger.exists())
            self.assertEqual(adapter.calls, [("vpn", 1, True)])

    def test_two_clean_epochs_reuse_runtime_without_intent_id_collision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _runtime = self.make_root(temporary)
            wanted = contract()
            epochs: list[str] = []
            for _ in range(2):
                provider = ScriptedProvider(
                    (ScriptedStep("start"), ScriptedStep("stop"))
                )
                supervisor = Supervisor(
                    root,
                    ROOT,
                    wanted.digest(),
                    expected_control_cap=wanted.limits.max_control_connections,
                    release_id=wanted.release_id,
                    providers={"*": provider},
                    qualifier=evidence,
                    start_watchdog=False,
                )
                supervisor.bootstrap()
                epochs.append(supervisor.owner_epoch)
                thread = threading.Thread(target=supervisor.serve_forever, daemon=True)
                thread.start()
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                sock.settimeout(3)
                sock.connect(str(root / "supervisor.sock"))
                client = SeqPacketConnection(sock)
                self.assertTrue(request(client, register_packet(wanted))["ok"])
                client.close()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                self.assertFalse((root / "recovery.fence").exists())
                self.assertEqual(
                    provider.calls,
                    (("start", "direct", 1), ("stop", "direct", 1)),
                )
            self.assertNotEqual(epochs[0], epochs[1])
            intents = tuple((root / "intents").glob("*.json"))
            self.assertEqual(intents, ())


if __name__ == "__main__":
    unittest.main(verbosity=2)
