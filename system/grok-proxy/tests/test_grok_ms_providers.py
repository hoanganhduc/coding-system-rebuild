#!/usr/bin/env python3
"""Loopback-only tests for generation-scoped multi-session providers."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from grok_ms.contract import (
    Endpoint,
    HomeEndpoint,
    ResourceLimits,
    RouteContract,
    RouteMode,
    StabilityPolicy,
    TimeoutPolicy,
    VpnPolicy,
)
from grok_ms.providers import (
    DirectProvider,
    LegacyShellProvider,
    ListenerIdentity,
    PrivilegedResourceIdentity,
    ProviderCancelled,
    ProviderError,
    ProviderProtocolError,
    ProviderRequest,
    ProviderResidueError,
    ProviderResourceGraph,
    ProviderScopeStore,
    ProviderScopeRecord,
    ProviderTimeout,
    QualificationEvidence,
    ScriptedProvider,
    ScriptedStep,
    TransitionDeadline,
    _create_workspace,
    _terminate_exact_processes,
    prove_empty_resources,
)
from grok_ms.process_scope import LinuxCgroupV2Scope
from grok_ms.runtime import (
    FenceRecord,
    FenceStore,
    ProcessIdentity,
    SecureRuntime,
    current_process_identity,
    process_matches,
    read_pid_start_ticks,
)
from grok_ms.config import _release_id
from grok_ms.supervisor import ProviderRecoveryRecord, RecoveryStore, recover_offline


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000_000_000

    def __call__(self) -> int:
        return self.now

    def advance_ms(self, milliseconds: int) -> None:
        self.now += milliseconds * 1_000_000


class StableProcessTerminationTests(unittest.TestCase):
    def test_provider_teardown_accepts_exact_exited_unreaped_process(self) -> None:
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        if child == 0:
            os.close(ready_write)
            os.read(ready_read, 1)
            os.close(ready_read)
            os._exit(0)

        os.close(ready_read)
        pidfd = -1
        try:
            identity = ProcessIdentity(
                pid=child,
                start_ticks=read_pid_start_ticks(child),
                boot_id=current_process_identity().boot_id,
            )
            pidfd = os.pidfd_open(child, 0)
            os.write(ready_write, b"1")
            os.close(ready_write)
            ready_write = -1
            readable, _, _ = select.select([pidfd], [], [], 2)
            self.assertEqual(readable, [pidfd])
            self.assertTrue(process_matches(identity))
            started = time.monotonic()
            exited = _terminate_exact_processes(
                (identity,), TransitionDeadline.after_ms(200)
            )
            self.assertEqual(exited, frozenset({identity}))
            self.assertLess(time.monotonic() - started, 0.1)
            with tempfile.TemporaryDirectory() as temporary:
                resources = ProviderResourceGraph(
                    owner_epoch="epoch-zombie-proof",
                    transition_id="transition-zombie-proof",
                    generation=1,
                    rung="direct",
                    runtime_dir=str(Path(temporary) / "absent-runtime"),
                    processes=(identity,),
                    listeners=(
                        ListenerIdentity(
                            Endpoint("127.0.0.1", unused_port()),
                            1,
                            identity,
                        ),
                    ),
                    paths=(),
                )
                self.assertTrue(prove_empty_resources(resources).clean)
        finally:
            if ready_write >= 0:
                os.close(ready_write)
            if pidfd >= 0:
                os.close(pidfd)
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass

    def test_provider_teardown_signals_only_through_pidfd(self) -> None:
        child = subprocess.Popen(
            ["/bin/sleep", "60"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            identity = ProcessIdentity(
                pid=child.pid,
                start_ticks=read_pid_start_ticks(child.pid),
                boot_id=current_process_identity().boot_id,
            )
            with mock.patch(
                "grok_ms.providers.os.kill",
                side_effect=AssertionError("numeric PID signalling is forbidden"),
            ):
                _terminate_exact_processes(
                    (identity,),
                    TransitionDeadline.after_ms(2_000),
                    {child.pid: child},
                )
            self.assertIsNotNone(child.returncode)
            self.assertFalse(process_matches(identity))
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)


def request(port: int, *, rung: str = "direct", generation: int = 1) -> ProviderRequest:
    home_endpoints = (
        (HomeEndpoint("arch", "100.64.0.10", "alice", 2200),)
        if rung == "home:arch"
        else ()
    )
    phone_id = "n-stable-iphone" if rung == "iphone" else None
    contract = RouteContract(
        schema_version=1,
        protocol_version=1,
        release_id="test-release-1",
        model_id="grok-4.5",
        route_mode=RouteMode.AUTO,
        forced_host=None,
        home_endpoints=home_endpoints,
        phone_node_id=phone_id,
        allow_direct=rung == "direct",
        ladder=(rung,),
        routing_config_digest="a" * 64,
        probe_policy_version="probe-test-v1",
        timeout_policy=TimeoutPolicy(1_000, 2_000, 300_000, 1_000),
        stability_policy=StabilityPolicy("same-exit-test-v1", 3, 250, True),
        vpn_policy=VpnPolicy(
            "grokvpn", 4, "vpn-rank-test-v1", ("VN", "JP"), ("CN", "DE")
        ),
        helper_release_ids=(("broker", "test-release-1"),),
        grok_release_id="grok-test-1",
        public_endpoint=Endpoint("127.0.0.1", 1080),
        private_ports=(port, port + 1),
        limits=ResourceLimits(8, 16, 32, 65_536, 4_096, 131_072),
    )
    return ProviderRequest(
        owner_epoch="epoch-test-1",
        transition_id=f"transition-{generation}",
        generation=generation,
        rung=rung,
        model_id="grok-4.5",
        private_endpoint=Endpoint("127.0.0.1", port),
        contract=contract,
    )


def workspace_tag(wanted: ProviderRequest) -> str:
    material = (
        wanted.owner_epoch.encode("ascii")
        + b"\0"
        + str(wanted.generation).encode("ascii")
        + b"\0"
        + str(wanted.private_endpoint.port).encode("ascii")
    )
    return hashlib.sha256(material).hexdigest()[:24]


def evidence(
    endpoint: Endpoint,
    requested: ProviderRequest,
    deadline: TransitionDeadline | None = None,
    cancellation: threading.Event | None = None,
) -> QualificationEvidence:
    del deadline, cancellation
    return QualificationEvidence(
        endpoint=endpoint,
        model_id=requested.model_id,
        exit_identity="127.0.0.1",
        country_code=None,
        dns_path_verified=True,
        byte_path_verified=True,
        stability_samples=("127.0.0.1",),
    )


def unused_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(65_536)
            if not data:
                return
            self.request.sendall(data)


class _EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def socks_round_trip(proxy: Endpoint, target_port: int, payload: bytes) -> bytes:
    with socket.create_connection((proxy.host, proxy.port), timeout=2) as client:
        client.sendall(b"\x05\x01\x00")
        if client.recv(2) != b"\x05\x00":
            raise AssertionError("SOCKS method negotiation failed")
        # A domain-name CONNECT proves resolution occurs behind the SOCKS
        # boundary rather than in this test client.
        host = b"localhost"
        client.sendall(
            b"\x05\x01\x00\x03"
            + bytes((len(host),))
            + host
            + struct.pack("!H", target_port)
        )
        reply = client.recv(4)
        if len(reply) != 4 or reply[1] != 0:
            raise AssertionError(f"SOCKS CONNECT failed: {reply!r}")
        atyp = reply[3]
        if atyp == 1:
            client.recv(4)
        elif atyp == 4:
            client.recv(16)
        elif atyp == 3:
            client.recv(client.recv(1)[0])
        else:
            raise AssertionError(f"bad SOCKS reply address type: {atyp}")
        client.recv(2)
        client.sendall(payload)
        received = b""
        while len(received) < len(payload):
            chunk = client.recv(len(payload) - len(received))
            if not chunk:
                break
            received += chunk
        return received


class FrozenProviderInputTests(unittest.TestCase):
    def test_request_round_trip_persists_full_contract_and_rejects_deltas(self) -> None:
        wanted = request(11880, rung="home:arch", generation=7)
        self.assertEqual(ProviderRequest.from_dict(wanted.to_dict()), wanted)

        unknown = wanted.to_dict()
        unknown["extra"] = True
        with self.assertRaisesRegex(ValueError, "missing or unexpected"):
            ProviderRequest.from_dict(unknown)
        with self.assertRaisesRegex(ValueError, "differs from the frozen contract"):
            dataclasses.replace(wanted, model_id="grok-other")
        with self.assertRaisesRegex(ValueError, "frozen private ports"):
            dataclasses.replace(
                wanted, private_endpoint=Endpoint("127.0.0.1", 11899)
            )
        with self.assertRaisesRegex(ValueError, "contract ladder"):
            dataclasses.replace(wanted, rung="vpn")
        option_shaped = dataclasses.replace(
            wanted.contract,
            home_endpoints=(
                dataclasses.replace(wanted.contract.home_endpoints[0], host="-oProxyCommand"),
            ),
        )
        with self.assertRaisesRegex(ValueError, "option-shaped"):
            dataclasses.replace(wanted, contract=option_shaped)

    def test_shell_environment_contains_only_frozen_route_values(self) -> None:
        workspace = SimpleNamespace(
            path=Path("/tmp/grok-provider-test"),
            inventory=Path("/tmp/grok-provider-test/inventory.json"),
        )
        home = request(11880, rung="home:arch")
        home_env = LegacyShellProvider._environment(home, workspace)
        self.assertEqual(
            {
                name: home_env[name]
                for name in (
                    "GROK_PROVIDER_HOME_LABEL",
                    "GROK_PROVIDER_HOME_HOST",
                    "GROK_PROVIDER_HOME_USER",
                    "GROK_PROVIDER_HOME_PORT",
                )
            },
            {
                "GROK_PROVIDER_HOME_LABEL": "arch",
                "GROK_PROVIDER_HOME_HOST": "100.64.0.10",
                "GROK_PROVIDER_HOME_USER": "alice",
                "GROK_PROVIDER_HOME_PORT": "2200",
            },
        )
        self.assertEqual(
            home_env["GROK_PROVIDER_CONTRACT_DIGEST"], home.contract.digest()
        )
        self.assertEqual(home_env["GROK_ACTIVE_RELEASE_ID"], "test-release-1")
        self.assertNotIn("GROK_PROVIDER_IPHONE_NODE_ID", home_env)
        self.assertNotIn("VPNGATE_COUNTRIES", home_env)

        iphone = request(11882, rung="iphone")
        iphone_env = LegacyShellProvider._environment(iphone, workspace)
        self.assertEqual(
            iphone_env["GROK_PROVIDER_IPHONE_NODE_ID"], "n-stable-iphone"
        )
        self.assertNotIn("GROK_PROVIDER_HOME_HOST", iphone_env)

        vpn = request(11884, rung="vpn")
        deadline = TransitionDeadline.after_ms(10_000)
        vpn_env = LegacyShellProvider._environment(vpn, workspace, deadline)
        self.assertEqual(
            vpn_env["GROK_PROVIDER_DEADLINE_NS"], str(deadline.expires_ns)
        )
        self.assertEqual(
            {
                "namespace": vpn_env["GROK_PROVIDER_VPN_NAMESPACE"],
                "max_tries": vpn_env["GROK_PROVIDER_VPN_MAX_TRIES"],
                "ranking": vpn_env["GROK_PROVIDER_VPN_RANKING_VERSION"],
                "countries": vpn_env["GROK_PROVIDER_VPN_COUNTRIES"],
                "blocked": vpn_env["GROK_PROVIDER_VPN_BLOCKED_COUNTRIES"],
                "samples": vpn_env["GROK_VPN_STABILITY_CHECKS"],
                "interval_ms": vpn_env["GROK_STABILITY_INTERVAL_MS"],
            },
            {
                "namespace": "grokvpn",
                "max_tries": "4",
                "ranking": "vpn-rank-test-v1",
                "countries": "VN JP",
                "blocked": "CN DE",
                "samples": "3",
                "interval_ms": "250",
            },
        )
        self.assertEqual(vpn_env["GROK_VPN_NETNS"], "grokvpn")
        self.assertEqual(vpn_env["GROK_VPN_MAX_TRIES"], "4")
        self.assertEqual(vpn_env["VPNGATE_COUNTRIES"], "VN JP")
        self.assertEqual(vpn_env["GROK_BLOCKED_CC"], "CN DE")


class DeadlineAndScriptedProviderTests(unittest.TestCase):
    def test_script_is_deterministic_and_resources_are_immutable(self) -> None:
        clock = _Clock()
        adapter = ScriptedProvider(
            (ScriptedStep("start", 25), ScriptedStep("stop", 10)),
            advance_ms=clock.advance_ms,
        )
        wanted = request(11880)
        deadline = TransitionDeadline.after_ms(100, clock_ns=clock)
        result = adapter.start(wanted, deadline, evidence)

        self.assertEqual(adapter.calls, (("start", "direct", 1),))
        self.assertFalse(adapter.prove_empty(result).clean)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.resources.generation = 2  # type: ignore[misc]

        adapter.stop(result, deadline)
        self.assertEqual(
            adapter.calls,
            (("start", "direct", 1), ("stop", "direct", 1)),
        )
        self.assertTrue(adapter.prove_empty(result).clean)

    def test_one_cumulative_deadline_covers_start_and_qualification(self) -> None:
        clock = _Clock()
        adapter = ScriptedProvider(
            (ScriptedStep("start", 60),), advance_ms=clock.advance_ms
        )

        def slow_qualifier(endpoint, wanted, deadline, cancellation):
            del deadline, cancellation
            clock.advance_ms(41)
            return evidence(endpoint, wanted)

        with self.assertRaisesRegex(ProviderTimeout, "qualification"):
            adapter.start(
                request(11881),
                TransitionDeadline.after_ms(100, clock_ns=clock),
                slow_qualifier,
            )

    def test_cancellation_is_observed_before_scripted_effect_completes(self) -> None:
        event = threading.Event()
        event.set()
        adapter = ScriptedProvider((ScriptedStep("start"),))
        with self.assertRaises(ProviderCancelled):
            adapter.start(
                request(11882), TransitionDeadline.after_ms(100), evidence, event
            )

    def test_only_fixed_vpn_privileged_names_are_accepted(self) -> None:
        adapter = ScriptedProvider((ScriptedStep("start"),))
        result = adapter.start(
            request(11883, rung="vpn"), TransitionDeadline.after_ms(100), evidence
        )
        self.assertEqual(
            {(item.kind, item.name) for item in result.resources.privileged},
            {
                ("namespace", "grokvpn"),
                ("tun", "tun-grok"),
                ("vpn_daemon", "openvpn"),
            },
        )
        with self.assertRaises(ValueError):
            PrivilegedResourceIdentity("namespace", "attacker", "broker-1")

    def test_qualification_rejects_an_exit_identity_change(self) -> None:
        with self.assertRaisesRegex(ValueError, "exit identity changed"):
            QualificationEvidence(
                endpoint=Endpoint("127.0.0.1", 11884),
                model_id="grok-4.5",
                exit_identity="203.0.113.1",
                country_code="JP",
                dns_path_verified=True,
                byte_path_verified=True,
                stability_samples=("203.0.113.1", "203.0.113.2"),
            )


class DirectProviderTests(unittest.TestCase):
    @staticmethod
    def _forking_release(root: Path) -> Path:
        release = root / "release"
        package = release / "grok_ms"
        package.mkdir(parents=True)
        shutil.copy2(ROOT / "grok_ms" / "parent_guard.py", package)
        script = release / "socks-netns.py"
        script.write_text(_FORKING_DIRECT, encoding="utf-8")
        script.chmod(0o755)
        return release

    def test_parent_death_closes_pre_graph_backend_and_recovery_removes_pidfile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            runtime = root / "runtime"
            wanted = request(unused_port(), generation=9)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(wanted.to_dict()), encoding="utf-8")
            marker = root / "qualifier.ready"
            helper = r'''
import json, sys, time
from pathlib import Path
from grok_ms.providers import DirectProvider, ProviderRequest, TransitionDeadline

wanted = ProviderRequest.from_dict(json.loads(Path(sys.argv[1]).read_text()))
adapter = DirectProvider(Path(sys.argv[2]), Path(sys.argv[3]))
def qualifier(endpoint, request, deadline, cancellation):
    del endpoint, request, deadline, cancellation
    Path(sys.argv[4]).write_text("ready")
    time.sleep(60)
    raise AssertionError("unreachable")
adapter.start(wanted, TransitionDeadline.after_ms(120_000), qualifier)
'''
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    helper,
                    str(request_path),
                    str(runtime),
                    str(ROOT),
                    str(marker),
                ],
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "PYTHONPATH": str(ROOT),
                },
            )
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not marker.exists():
                    if process.poll() is not None:
                        self.fail(f"provider helper exited early: {process.returncode}")
                    time.sleep(0.02)
                self.assertTrue(marker.exists())
                with socket.socket() as probe:
                    probe.settimeout(0.2)
                    self.assertEqual(
                        probe.connect_ex(
                            (wanted.private_endpoint.host, wanted.private_endpoint.port)
                        ),
                        0,
                    )
                process.kill()
                process.wait(timeout=3)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with socket.socket() as probe:
                        probe.settimeout(0.2)
                        closed = (
                            probe.connect_ex(
                                (
                                    wanted.private_endpoint.host,
                                    wanted.private_endpoint.port,
                                )
                            )
                            != 0
                        )
                    if closed:
                        break
                    time.sleep(0.02)
                self.assertTrue(closed)
                recovered = DirectProvider(runtime, ROOT).recover(
                    wanted,
                    None,
                    TransitionDeadline.after_ms(5_000),
                )
                self.assertTrue(recovered.clean)
                self.assertFalse(runtime.joinpath("p").exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_direct_scope_recovery_covers_every_durable_phase(self) -> None:
        for phase in ("PREPARED", "SCOPE_CREATED", "ATTACHED"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                os.chmod(root, 0o700)
                runtime = root / "runtime"
                wanted = request(unused_port(), generation=14)
                _create_workspace(runtime, wanted)
                store = ProviderScopeStore(runtime)
                backend = LinuxCgroupV2Scope()
                adapter = DirectProvider(
                    runtime,
                    ROOT,
                    process_scopes=backend,
                    scope_store=store,
                )
                planned = backend.plan()
                parent = current_process_identity()
                barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
                process = subprocess.Popen(
                    [
                        sys.executable,
                        str(ROOT / "grok_ms/parent_guard.py"),
                        "--parent-pid",
                        str(parent.pid),
                        "--parent-start-ticks",
                        str(parent.start_ticks),
                        "--parent-boot-id",
                        parent.boot_id,
                        "--barrier-fd",
                        str(barrier_read),
                        "--",
                        "/bin/sleep",
                        "60",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    pass_fds=(barrier_read,),
                    start_new_session=True,
                )
                os.close(barrier_read)
                child = ProcessIdentity(
                    process.pid,
                    read_pid_start_ticks(process.pid),
                    parent.boot_id,
                )
                record = ProviderScopeRecord(
                    schema_version=1,
                    record_version=1,
                    release_id=wanted.contract.release_id,
                    verb="direct-up",
                    phase="PREPARED",
                    request=wanted,
                    child=child,
                    scope=planned,
                )
                store.put(wanted, record)
                handle = None
                try:
                    if phase != "PREPARED":
                        handle = backend.create(planned)
                        record = dataclasses.replace(
                            record,
                            phase="SCOPE_CREATED",
                            scope=handle.identity,
                        )
                        store.replace(wanted, record)
                    if phase == "ATTACHED":
                        assert handle is not None
                        backend.attach(handle, child)
                        record = dataclasses.replace(record, phase="ATTACHED")
                        store.replace(wanted, record)
                    if handle is not None:
                        handle.close()
                        handle = None
                    os.close(barrier_write)
                    barrier_write = -1
                    report = adapter.recover(
                        wanted,
                        None,
                        TransitionDeadline.after_ms(5_000),
                    )
                    process.wait(timeout=3)
                    self.assertTrue(report.clean)
                    self.assertFalse(Path(record.scope.scope_path).exists())
                    self.assertEqual(store.list_records(), ())
                    self.assertFalse(runtime.joinpath("p").exists())
                finally:
                    if handle is not None:
                        handle.close()
                    if barrier_write >= 0:
                        os.close(barrier_write)
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=3)

    def test_real_host_namespace_socks_backend_qualifies_and_stops_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            runtime = root / "runtime"
            adapter = DirectProvider(runtime, ROOT)
            wanted = request(unused_port())
            echo = _EchoServer(("127.0.0.1", 0), _EchoHandler)
            thread = threading.Thread(target=echo.serve_forever, daemon=True)
            thread.start()
            result = None

            def qualify(endpoint, requested, deadline, cancellation):
                del cancellation
                deadline.check("loopback SOCKS qualification")
                payload = b"private-direct-byte-path" * 256
                self.assertEqual(
                    socks_round_trip(endpoint, echo.server_address[1], payload),
                    payload,
                )
                return evidence(endpoint, requested)

            try:
                result = adapter.start(
                    wanted, TransitionDeadline.after_ms(5_000), qualify
                )
                self.assertEqual(result.resources.listeners[0].endpoint, wanted.private_endpoint)
                self.assertTrue(process_matches(result.resources.processes[0]))
                self.assertEqual(len(result.resources.paths), 1)
                self.assertEqual(result.resources.paths[0].kind, "pid")
                self.assertEqual(
                    Path(result.resources.runtime_dir),
                    runtime / "p" / workspace_tag(wanted),
                )
                retained = ProviderScopeStore(runtime).load(wanted, "provider")
                self.assertIsNotNone(retained)
                assert retained is not None
                self.assertEqual((retained.verb, retained.phase), ("direct-up", "ATTACHED"))
                scope_path = Path(retained.scope.scope_path)
                self.assertTrue(scope_path.exists())

                adapter.stop(result, TransitionDeadline.after_ms(5_000))
                self.assertTrue(adapter.prove_empty(result).clean)
                self.assertFalse(scope_path.exists())
                self.assertEqual(ProviderScopeStore(runtime).list_records(), ())
                result = None
            finally:
                if result is not None:
                    try:
                        adapter.stop(result, TransitionDeadline.after_ms(5_000))
                    except Exception:
                        pass
                echo.shutdown()
                echo.server_close()
                thread.join(timeout=2)

    def test_workspace_tag_collision_fails_closed_without_disturbing_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            runtime = root / "runtime"
            adapter = DirectProvider(runtime, ROOT)
            wanted = request(unused_port(), generation=12)
            result = adapter.start(
                wanted, TransitionDeadline.after_ms(5_000), evidence
            )
            try:
                with self.assertRaisesRegex(
                    ProviderResidueError, "generation runtime already exists"
                ):
                    adapter.start(
                        wanted, TransitionDeadline.after_ms(5_000), evidence
                    )
                self.assertTrue(process_matches(result.resources.processes[0]))
                with socket.socket() as probe:
                    probe.settimeout(0.2)
                    self.assertEqual(
                        probe.connect_ex(
                            (
                                wanted.private_endpoint.host,
                                wanted.private_endpoint.port,
                            )
                        ),
                        0,
                    )
            finally:
                adapter.stop(result, TransitionDeadline.after_ms(5_000))
            self.assertFalse(runtime.joinpath("p").exists())

    def test_direct_scope_kills_double_forked_setsid_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._forking_release(root)
            runtime = root / "runtime"
            adapter = DirectProvider(runtime, release)
            wanted = request(unused_port(), generation=13)
            result = adapter.start(
                wanted,
                TransitionDeadline.after_ms(5_000),
                evidence,
            )
            descendant_pidfd = -1
            try:
                marker = release / "descendant.pid"
                descendant_pid = int(marker.read_text(encoding="ascii"))
                descendant = ProcessIdentity(
                    descendant_pid,
                    read_pid_start_ticks(descendant_pid),
                    current_process_identity().boot_id,
                )
                descendant_pidfd = os.pidfd_open(descendant.pid, 0)
                retained = ProviderScopeStore(runtime).load(wanted, "provider")
                self.assertIsNotNone(retained)
                assert retained is not None
                scope_path = Path(retained.scope.scope_path)
                relative = scope_path.relative_to("/sys/fs/cgroup")
                membership = Path(
                    f"/proc/{descendant.pid}/cgroup"
                ).read_text(encoding="ascii").strip()
                self.assertEqual(membership, f"0::/{relative}")

                adapter.stop(result, TransitionDeadline.after_ms(5_000))
                readable, _, _ = select.select([descendant_pidfd], [], [], 0)
                self.assertEqual(readable, [descendant_pidfd])
                self.assertFalse(scope_path.exists())
                self.assertEqual(ProviderScopeStore(runtime).list_records(), ())
                self.assertFalse(runtime.joinpath("p").exists())
                result = None
            finally:
                if descendant_pidfd >= 0:
                    os.close(descendant_pidfd)
                if result is not None:
                    try:
                        adapter.stop(result, TransitionDeadline.after_ms(5_000))
                    except Exception:
                        pass

    def test_qualification_failure_synchronously_removes_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            runtime = root / "runtime"
            adapter = DirectProvider(runtime, ROOT)
            wanted = request(unused_port(), generation=2)

            def reject(endpoint, requested, deadline, cancellation):
                del endpoint, requested, deadline, cancellation
                raise ProviderErrorForTest("qualification-rejected")

            with self.assertRaises(ProviderErrorForTest):
                adapter.start(
                    wanted, TransitionDeadline.after_ms(5_000), reject
                )
            with socket.socket() as probe:
                probe.settimeout(0.2)
                self.assertNotEqual(
                    probe.connect_ex(
                        (wanted.private_endpoint.host, wanted.private_endpoint.port)
                    ),
                    0,
                )
            self.assertFalse(runtime.joinpath("p").exists())

    def test_cancellation_after_listener_readiness_synchronously_removes_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            runtime = root / "runtime"
            adapter = DirectProvider(runtime, ROOT)
            wanted = request(unused_port(), generation=5)
            cancellation = threading.Event()

            def cancel_during_qualification(endpoint, requested, deadline, event):
                del deadline
                self.assertEqual(endpoint, requested.private_endpoint)
                self.assertIs(event, cancellation)
                cancellation.set()
                return evidence(endpoint, requested)

            with self.assertRaises(ProviderCancelled):
                adapter.start(
                    wanted,
                    TransitionDeadline.after_ms(5_000),
                    cancel_during_qualification,
                    cancellation,
                )
            with socket.socket() as probe:
                probe.settimeout(0.2)
                self.assertNotEqual(
                    probe.connect_ex(
                        (wanted.private_endpoint.host, wanted.private_endpoint.port)
                    ),
                    0,
                )
            self.assertFalse(runtime.joinpath("p").exists())


class ProviderErrorForTest(RuntimeError):
    pass


_FORKING_DIRECT = r'''#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import signal
import socket
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--listen", required=True)
parser.add_argument("--pidfile", required=True)
args = parser.parse_args()
host, raw_port = args.listen.rsplit(":", 1)

first = os.fork()
if first == 0:
    os.setsid()
    second = os.fork()
    if second == 0:
        Path(__file__).with_name("descendant.pid").write_text(
            str(os.getpid()), encoding="ascii"
        )
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        while True:
            signal.pause()
    os._exit(0)
os.waitpid(first, 0)

listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((host, int(raw_port)))
listener.listen(16)
Path(args.pidfile).write_text(str(os.getpid()), encoding="ascii")
os.chmod(args.pidfile, 0o600)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True:
    client, _ = listener.accept()
    client.close()
'''


_FAKE_LISTENER = r'''#!/usr/bin/env python3
import os
import signal
import socket
import sys

port = int(sys.argv[1])
pidfile = sys.argv[2]
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", port))
listener.listen(16)
with open(pidfile, "w", encoding="ascii") as handle:
    handle.write(str(os.getpid()))
os.chmod(pidfile, 0o600)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True:
    client, _ = listener.accept()
    with client:
        data = client.recv(4096)
        if data:
            client.sendall(data)
'''


_FAKE_EGRESS = r'''#!/bin/bash
set -uo pipefail
[[ "${GROK_PROVIDER_MODE:-}" == 1 ]] || exit 80
[[ -z "${LEAK_ME+x}" ]] || exit 81
[[ "$GROK_EGRESS_RUNTIME_DIR" == /* ]] || exit 82
[[ "$GROK_PROVIDER_INVENTORY" == "$GROK_EGRESS_RUNTIME_DIR/inventory.json" ]] || exit 83
verb="${1:-}"
rung="${2:-}"
pidfile="$GROK_EGRESS_RUNTIME_DIR/legacy.pid"
write_inventory(){
    pid="$1"
    privileged='[]'
    if [[ "$rung" == vpn ]]; then
      privileged='[{"kind":"namespace","name":"grokvpn","broker_instance":"broker-test"},{"kind":"tun","name":"tun-grok","broker_instance":"broker-test"},{"kind":"vpn_daemon","name":"openvpn","broker_instance":"broker-test"}]'
    fi
    actual_rung="$rung"
    [[ ! -e "$(dirname "$0")/malformed" ]] || actual_rung=wrong
    tmp="$GROK_PROVIDER_INVENTORY.tmp"
    ( umask 077
      printf '{"schema_version":1,"owner_epoch":"%s","transition_id":"%s","generation":%s,"rung":"%s","pids":[%s],"paths":[{"path":"%s","kind":"pid"}],"privileged":%s}\n' \
        "$GROK_PROVIDER_OWNER_EPOCH" "$GROK_PROVIDER_TRANSITION_ID" \
        "$GROK_PROVIDER_GENERATION" "$actual_rung" "$pid" "$pidfile" \
        "$privileged" > "$tmp"
    )
    mv "$tmp" "$GROK_PROVIDER_INVENTORY"
}
case "$verb" in
  provider-up)
    if [[ -e "$(dirname "$0")/pre-artifact" ]]; then
      (
        trap "" TERM HUP
        printf '%s\n' "$BASHPID" > "$(dirname "$0")/escape.pid"
        : > "$(dirname "$0")/escape.ready"
        sleep 1
        : > "$(dirname "$0")/late-effect"
        sleep 60
      ) &
      sleep 60
    fi
    /usr/bin/python3 "$(dirname "$0")/listener.py" "$GROK_PROXY_PORT" "$pidfile" \
      </dev/null >/dev/null 2>&1 &
    pid=$!
    for _ in $(seq 1 100); do [[ -s "$pidfile" ]] && break; sleep 0.01; done
    [[ -s "$pidfile" ]] || exit 84
    if [[ -e "$(dirname "$0")/hold-up" ]]; then
      : > "$(dirname "$0")/up.ready"
      sleep 60
    fi
    write_inventory "$pid"
    ;;
  provider-next)
    [[ "$rung" == vpn ]] || exit 88
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null || exit 89
    counter="$(dirname "$0")/next.count"
    count="$(cat "$counter" 2>/dev/null || printf 0)"
    printf '%s\n' "$((count + 1))" > "$counter"
    write_inventory "$pid"
    ;;
  provider-stop)
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.01; done
      kill -KILL "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile" "$GROK_PROVIDER_INVENTORY"
    ;;
  provider-recover)
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.01; done
      kill -KILL "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile" "$GROK_PROVIDER_INVENTORY"
    rmdir "$GROK_EGRESS_RUNTIME_DIR" 2>/dev/null || true
    ;;
  provider-prove-empty)
    [[ ! -e "$pidfile" && ! -e "$GROK_PROVIDER_INVENTORY" ]] || exit 85
    ! ss -H -lnt "sport = :$GROK_PROXY_PORT" 2>/dev/null | grep -q . || exit 86
    ;;
  *) exit 87 ;;
esac
'''


class LegacyShellProviderTests(unittest.TestCase):
    def _release(self, root: Path) -> Path:
        release = root / "release"
        release.mkdir(mode=0o700)
        (release / "grok_ms").mkdir(mode=0o700)
        (release / "grok_ms" / "parent_guard.py").write_bytes(
            (ROOT / "grok_ms" / "parent_guard.py").read_bytes()
        )
        (release / "listener.py").write_text(_FAKE_LISTENER, encoding="utf-8")
        (release / "egress.sh").write_text(_FAKE_EGRESS, encoding="utf-8")
        for name in ("grok-remote", "socks-netns.py", "vpngate-connect.sh"):
            (release / name).write_bytes((ROOT / name).read_bytes())
        os.chmod(release / "listener.py", 0o700)
        os.chmod(release / "egress.sh", 0o700)
        return release

    def test_recovery_propagates_one_deadline_to_every_legacy_cleanup_step(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            observed: list[TransitionDeadline | None] = []

            class TrackingLegacyProvider(LegacyShellProvider):
                def _reconcile_scope_role(
                    self,
                    request_value,
                    role,
                    *,
                    record=None,
                    handle=None,
                    pidfd=None,
                    deadline=None,
                ):
                    del request_value, role, record, handle, pidfd
                    observed.append(deadline)

                def _command(
                    self,
                    verb,
                    request_value,
                    workspace,
                    deadline,
                    cancellation,
                    *,
                    retain_scope_on_success=False,
                ):
                    del (
                        verb,
                        request_value,
                        workspace,
                        cancellation,
                        retain_scope_on_success,
                    )
                    observed.append(deadline)
                    return 0

                def _scope_residue(self, request_value):
                    del request_value
                    return ()

            wanted = request(
                unused_port(),
                rung="home:arch",
                generation=31,
            )
            shared = TransitionDeadline.after_ms(1_000)
            report = TrackingLegacyProvider(root / "runtime", release).recover(
                wanted,
                None,
                shared,
            )
            self.assertTrue(report.clean)
            self.assertEqual(len(observed), 4)
            self.assertTrue(all(item is shared for item in observed))

    def test_provider_canary_fd_crosses_only_the_guarded_provider_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            authorization = root / "canary-auth.lock"
            authorization.write_bytes(b"")
            descriptor = os.open(authorization, os.O_RDONLY | os.O_CLOEXEC)
            try:
                runtime = root / "runtime"
                wanted = request(
                    unused_port(), rung="home:arch", generation=19
                )
                workspace = _create_workspace(runtime, wanted)
                adapter = LegacyShellProvider(
                    runtime,
                    release,
                    provider_canary_fd=descriptor,
                )
                with mock.patch.object(
                    subprocess,
                    "Popen",
                    side_effect=OSError("injected provider spawn failure"),
                ) as spawn:
                    result = adapter._command(
                        "provider-up",
                        wanted,
                        workspace,
                        TransitionDeadline.after_ms(5_000),
                        None,
                    )
                self.assertEqual(result, 29)
                passed = spawn.call_args.kwargs["pass_fds"]
                self.assertEqual(len(passed), 2)
                self.assertNotEqual(passed[0], descriptor)
                self.assertEqual(passed[1], descriptor)
                self.assertEqual(
                    spawn.call_args.kwargs["env"]["GROK_RELEASE_CANARY_FD"],
                    str(descriptor),
                )
                self.assertEqual(
                    spawn.call_args.kwargs["env"][
                        "GROK_RELEASE_CANARY_RELEASE_ID"
                    ],
                    wanted.contract.release_id,
                )
                os.fstat(descriptor)
                self.assertFalse(os.get_inheritable(descriptor))
            finally:
                os.close(descriptor)

    def test_command_closes_guard_process_and_spawn_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            (release / "egress.sh").write_text(
                '''#!/usr/bin/env bash
status="$(cat "$(dirname "$0")/status")"
if [[ "$status" == signal ]]; then
  kill -TERM $$
  sleep 1
fi
exit "$status"
''',
                encoding="utf-8",
            )
            runtime = root / "runtime"
            adapter = LegacyShellProvider(runtime, release)
            wanted = request(unused_port(), rung="home:arch", generation=12)
            workspace = _create_workspace(runtime, wanted)
            vpn_wanted = request(unused_port(), rung="vpn", generation=13)
            vpn_workspace = _create_workspace(runtime, vpn_wanted)

            for status in (0, *range(20, 29)):
                (release / "status").write_text(str(status), encoding="ascii")
                self.assertEqual(
                    adapter._command(
                        "provider-up",
                        wanted,
                        workspace,
                        TransitionDeadline.after_ms(5_000),
                        None,
                    ),
                    status,
                )

            for status in range(30, 35):
                (release / "status").write_text(str(status), encoding="ascii")
                self.assertEqual(
                    adapter._command(
                        "provider-up",
                        wanted,
                        workspace,
                        TransitionDeadline.after_ms(5_000),
                        None,
                    ),
                    29,
                )

            for status in (0, *range(20, 29), *range(31, 35)):
                (release / "status").write_text(str(status), encoding="ascii")
                self.assertEqual(
                    adapter._command(
                        "provider-up",
                        vpn_wanted,
                        vpn_workspace,
                        TransitionDeadline.after_ms(5_000),
                        None,
                    ),
                    status,
                )

            for status in (30, 35, 125, 255):
                (release / "status").write_text(str(status), encoding="ascii")
                self.assertEqual(
                    adapter._command(
                        "provider-up",
                        vpn_wanted,
                        vpn_workspace,
                        TransitionDeadline.after_ms(5_000),
                        None,
                    ),
                    29,
                )

            for status in (1, 2, 19, 29, 35, 125, 126, 255, "signal"):
                (release / "status").write_text(str(status), encoding="ascii")
                self.assertEqual(
                    adapter._command(
                        "provider-up",
                        wanted,
                        workspace,
                        TransitionDeadline.after_ms(5_000),
                        None,
                    ),
                    29,
                )

            for status in (*range(20, 29), *range(30, 35)):
                (release / "status").write_text(str(status), encoding="ascii")
                self.assertEqual(
                    adapter._command(
                        "provider-stop",
                        vpn_wanted,
                        vpn_workspace,
                        TransitionDeadline.after_ms(5_000),
                        None,
                    ),
                    29,
                )
            with mock.patch(
                "grok_ms.providers.subprocess.Popen", side_effect=OSError("spawn")
            ):
                self.assertEqual(
                    adapter._command(
                        "provider-up",
                        wanted,
                        workspace,
                        TransitionDeadline.after_ms(5_000),
                        None,
                    ),
                    29,
                )

    def test_command_discards_provider_output_and_cleanup_uncertainty_dominates_stage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            stdout_marker = "PROVIDER_STDOUT_MUST_NOT_ESCAPE"
            stderr_marker = "PROVIDER_STDERR_MUST_NOT_ESCAPE"
            (release / "egress.sh").write_text(
                f'''#!/usr/bin/env bash
printf '%s\\n' {stdout_marker!r}
printf '%s\\n' {stderr_marker!r} >&2
exit 31
''',
                encoding="utf-8",
            )
            runtime = root / "runtime"
            adapter = LegacyShellProvider(runtime, release)
            wanted = request(unused_port(), rung="vpn", generation=14)
            workspace = _create_workspace(runtime, wanted)

            with mock.patch(
                "grok_ms.providers.subprocess.Popen", wraps=subprocess.Popen
            ) as spawn:
                self.assertEqual(
                    adapter._command(
                        "provider-up",
                        wanted,
                        workspace,
                        TransitionDeadline.after_ms(5_000),
                        None,
                    ),
                    31,
                )
            self.assertTrue(spawn.call_args_list)
            for call in spawn.call_args_list:
                self.assertEqual(call.kwargs.get("stdout"), subprocess.DEVNULL)
                self.assertEqual(call.kwargs.get("stderr"), subprocess.DEVNULL)

            original_reconcile = adapter._reconcile_scope_role

            def reconcile_then_fail(*args, **kwargs):
                original_reconcile(*args, **kwargs)
                raise ProviderError("fixture cleanup uncertainty")

            with mock.patch.object(
                adapter,
                "_reconcile_scope_role",
                side_effect=reconcile_then_fail,
            ), self.assertRaisesRegex(
                ProviderResidueError,
                "provider-up command scope cleanup is uncertain",
            ):
                adapter._command(
                    "provider-up",
                    wanted,
                    workspace,
                    TransitionDeadline.after_ms(5_000),
                    None,
                )
            self.assertEqual(adapter._scope_residue(wanted), ())

    def test_command_normalizes_actual_egress_predispatch_failure(self) -> None:
        class MissingDeadlineProvider(LegacyShellProvider):
            @staticmethod
            def _environment(request, workspace, deadline=None):
                environment = LegacyShellProvider._environment(
                    request, workspace, deadline
                )
                environment.pop("GROK_PROVIDER_DEADLINE_NS")
                return environment

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = root / "release"
            release.mkdir(mode=0o700)
            (release / "grok_ms").mkdir(mode=0o700)
            (release / "grok_ms" / "parent_guard.py").write_bytes(
                (ROOT / "grok_ms" / "parent_guard.py").read_bytes()
            )
            (release / "egress.sh").write_bytes((ROOT / "egress.sh").read_bytes())
            runtime = root / "runtime"
            adapter = MissingDeadlineProvider(runtime, release)
            wanted = request(unused_port(), rung="home:arch", generation=13)
            workspace = _create_workspace(runtime, wanted)

            self.assertEqual(
                adapter._command(
                    "provider-up",
                    wanted,
                    workspace,
                    TransitionDeadline.after_ms(5_000),
                    None,
                ),
                29,
            )

    def test_parent_death_mid_up_is_recovered_before_inventory_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            (release / "hold-up").touch()
            runtime = root / "runtime"
            wanted = request(unused_port(), rung="home:arch", generation=11)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(wanted.to_dict()), encoding="utf-8")
            helper = r'''
import json, sys
from pathlib import Path
from grok_ms.providers import LegacyShellProvider, ProviderRequest, TransitionDeadline

wanted = ProviderRequest.from_dict(json.loads(Path(sys.argv[1]).read_text()))
adapter = LegacyShellProvider(Path(sys.argv[2]), Path(sys.argv[3]))
adapter.start(wanted, TransitionDeadline.after_ms(120_000), lambda *args: None)
'''
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    helper,
                    str(request_path),
                    str(runtime),
                    str(release),
                ],
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "PYTHONPATH": str(ROOT),
                },
            )
            try:
                ready = release / "up.ready"
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not ready.exists():
                    if process.poll() is not None:
                        self.fail(f"legacy helper exited early: {process.returncode}")
                    time.sleep(0.02)
                self.assertTrue(ready.exists())
                process.kill()
                process.wait(timeout=3)
                report = LegacyShellProvider(runtime, release).recover(
                    wanted,
                    None,
                    TransitionDeadline.after_ms(5_000),
                )
                self.assertTrue(report.clean)
                with socket.socket() as probe:
                    probe.settimeout(0.2)
                    self.assertNotEqual(
                        probe.connect_ex(
                            (wanted.private_endpoint.host, wanted.private_endpoint.port)
                        ),
                        0,
                    )
                self.assertFalse(runtime.joinpath("p").exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_parent_death_before_first_provider_artifact_cannot_escape_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            (release / "pre-artifact").touch()
            runtime = root / "runtime"
            release_id = _release_id(release)
            wanted = request(unused_port(), rung="home:arch", generation=14)
            wanted = dataclasses.replace(
                wanted,
                contract=dataclasses.replace(
                    wanted.contract,
                    release_id=release_id,
                ),
            )
            secure_runtime = SecureRuntime(runtime)
            secure_runtime.initialize()
            fence = FenceRecord(
                schema_version=1,
                release_id=release_id,
                owner_epoch=wanted.owner_epoch,
                pid=2**31 - 1,
                pid_start_ticks=1,
                boot_id=current_process_identity().boot_id,
                phase="DRAINING",
            )
            FenceStore(secure_runtime).publish(fence)
            effect_id = f"{wanted.owner_epoch}-g{wanted.generation}-start"
            RecoveryStore(secure_runtime).put_provider(
                ProviderRecoveryRecord(
                    schema_version=1,
                    record_version=1,
                    release_id=release_id,
                    owner_epoch=wanted.owner_epoch,
                    effect_id=effect_id,
                    phase="PREPARED",
                    request=wanted,
                    resources=None,
                )
            )
            request_path = root / "request.json"
            request_path.write_text(json.dumps(wanted.to_dict()), encoding="utf-8")
            helper = r'''
import json, sys
from pathlib import Path
from grok_ms.providers import LegacyShellProvider, ProviderRequest, TransitionDeadline

wanted = ProviderRequest.from_dict(json.loads(Path(sys.argv[1]).read_text()))
adapter = LegacyShellProvider(Path(sys.argv[2]), Path(sys.argv[3]))
adapter.start(wanted, TransitionDeadline.after_ms(120_000), lambda *args: None)
'''
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    helper,
                    str(request_path),
                    str(runtime),
                    str(release),
                ],
                env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(ROOT)},
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            escaped: ProcessIdentity | None = None
            try:
                ready = release / "escape.ready"
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not ready.exists():
                    if process.poll() is not None:
                        self.fail(f"legacy helper exited early: {process.returncode}")
                    time.sleep(0.02)
                self.assertTrue(ready.exists())
                escaped_pid = int((release / "escape.pid").read_text(encoding="ascii"))
                escaped = ProcessIdentity(
                    escaped_pid,
                    read_pid_start_ticks(escaped_pid),
                    current_process_identity().boot_id,
                )
                process.kill()
                process.wait(timeout=3)

                outcome = recover_offline(
                    runtime,
                    release,
                    recover_compatibility=False,
                )
                self.assertTrue(outcome.recovered)
                self.assertEqual(outcome.provider_records, 1)
                time.sleep(1.2)
                self.assertFalse(release.joinpath("late-effect").exists())
                self.assertFalse(process_matches(escaped))
                self.assertFalse(runtime.joinpath("p").exists())
                self.assertEqual(
                    RecoveryStore(secure_runtime).list_provider_scopes(), ()
                )
                self.assertFalse(runtime.joinpath("recovery.fence").exists())
                self.assertFalse(
                    recover_offline(
                        runtime,
                        release,
                        recover_compatibility=False,
                    ).recovered
                )
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                if escaped is not None and process_matches(escaped):
                    try:
                        _terminate_exact_processes(
                            (escaped,), TransitionDeadline.after_ms(2_000)
                        )
                    except ProviderError:
                        pass

    def test_cancellation_before_first_provider_artifact_reconciles_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            (release / "pre-artifact").touch()
            runtime = root / "runtime"
            wanted = request(unused_port(), rung="home:arch", generation=15)
            adapter = LegacyShellProvider(runtime, release)
            cancellation = threading.Event()
            errors: list[BaseException] = []

            def run() -> None:
                try:
                    adapter.start(
                        wanted,
                        TransitionDeadline.after_ms(30_000),
                        lambda *args: None,
                        cancellation,
                    )
                except BaseException as exc:
                    errors.append(exc)

            worker = threading.Thread(target=run)
            worker.start()
            escaped: ProcessIdentity | None = None
            scope_path: Path | None = None
            try:
                ready = release / "escape.ready"
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not ready.exists():
                    if not worker.is_alive():
                        self.fail("legacy provider worker exited before escape fixture")
                    time.sleep(0.02)
                self.assertTrue(ready.exists())
                escaped_pid = int((release / "escape.pid").read_text(encoding="ascii"))
                escaped = ProcessIdentity(
                    escaped_pid,
                    read_pid_start_ticks(escaped_pid),
                    current_process_identity().boot_id,
                )
                stored = ProviderScopeStore(runtime).load(wanted, "command")
                self.assertIsNotNone(stored)
                assert stored is not None
                scope_path = Path(stored.scope.scope_path)
                self.assertTrue(scope_path.exists())

                cancellation.set()
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], ProviderCancelled)
                time.sleep(1.2)
                self.assertFalse(release.joinpath("late-effect").exists())
                self.assertFalse(process_matches(escaped))
                self.assertFalse(scope_path.exists())
                self.assertEqual(ProviderScopeStore(runtime).list_records(), ())
                self.assertFalse(runtime.joinpath("p").exists())
            finally:
                cancellation.set()
                worker.join(timeout=3)
                if escaped is not None and process_matches(escaped):
                    try:
                        _terminate_exact_processes(
                            (escaped,), TransitionDeadline.after_ms(2_000)
                        )
                    except ProviderError:
                        pass

    def test_command_scope_recovery_covers_every_durable_phase(self) -> None:
        for phase in ("PREPARED", "SCOPE_CREATED", "ATTACHED"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                os.chmod(root, 0o700)
                release = self._release(root)
                runtime = root / "runtime"
                wanted = request(unused_port(), rung="home:arch", generation=16)
                _create_workspace(runtime, wanted)
                adapter = LegacyShellProvider(runtime, release)
                store = ProviderScopeStore(runtime)
                backend = LinuxCgroupV2Scope()
                planned = backend.plan()
                parent = current_process_identity()
                barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
                process = subprocess.Popen(
                    [
                        sys.executable,
                        str(release / "grok_ms/parent_guard.py"),
                        "--parent-pid",
                        str(parent.pid),
                        "--parent-start-ticks",
                        str(parent.start_ticks),
                        "--parent-boot-id",
                        parent.boot_id,
                        "--barrier-fd",
                        str(barrier_read),
                        "--",
                        "/bin/sleep",
                        "60",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    pass_fds=(barrier_read,),
                    start_new_session=True,
                )
                os.close(barrier_read)
                child = ProcessIdentity(
                    process.pid,
                    read_pid_start_ticks(process.pid),
                    parent.boot_id,
                )
                record = ProviderScopeRecord(
                    schema_version=1,
                    record_version=1,
                    release_id=wanted.contract.release_id,
                    verb="provider-up",
                    phase="PREPARED",
                    request=wanted,
                    child=child,
                    scope=planned,
                )
                store.put(wanted, record)
                handle = None
                try:
                    if phase != "PREPARED":
                        handle = backend.create(planned)
                        record = dataclasses.replace(
                            record,
                            phase="SCOPE_CREATED",
                            scope=handle.identity,
                        )
                        store.replace(wanted, record)
                    if phase == "ATTACHED":
                        assert handle is not None
                        backend.attach(handle, child)
                        record = dataclasses.replace(record, phase="ATTACHED")
                        store.replace(wanted, record)
                    if handle is not None:
                        handle.close()
                        handle = None
                    os.close(barrier_write)
                    barrier_write = -1
                    report = adapter.recover(
                        wanted,
                        None,
                        TransitionDeadline.after_ms(5_000),
                    )
                    process.wait(timeout=3)
                    self.assertTrue(report.clean)
                    self.assertFalse(process_matches(child))
                    self.assertFalse(Path(record.scope.scope_path).exists())
                    self.assertEqual(store.list_records(), ())
                    self.assertFalse(runtime.joinpath("p").exists())
                finally:
                    if handle is not None:
                        handle.close()
                    if barrier_write >= 0:
                        os.close(barrier_write)
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=3)

    def test_provider_scope_persist_then_promotion_error_cleans_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            runtime = root / "runtime"
            wanted = request(unused_port(), rung="home:arch", generation=17)
            store = ProviderScopeStore(runtime)
            adapter = LegacyShellProvider(
                runtime,
                release,
                scope_store=store,
            )
            original_promote = store.promote
            promoted_scope: list[Path] = []

            def persist_then_raise(
                request_value: ProviderRequest,
                record: ProviderScopeRecord,
            ) -> None:
                original_promote(request_value, record)
                promoted_scope.append(Path(record.scope.scope_path))
                raise OSError("injected post-promotion failure")

            with mock.patch.object(store, "promote", side_effect=persist_then_raise):
                with self.assertRaisesRegex(
                    ProviderResidueError, "cannot promote provider command scope"
                ):
                    adapter.start(
                        wanted,
                        TransitionDeadline.after_ms(5_000),
                        evidence,
                    )
            self.assertEqual(len(promoted_scope), 1)
            self.assertFalse(promoted_scope[0].exists())
            self.assertEqual(store.list_records(), ())
            self.assertFalse(runtime.joinpath("p").exists())
            with socket.socket() as probe:
                probe.settimeout(0.2)
                self.assertNotEqual(
                    probe.connect_ex(
                        (wanted.private_endpoint.host, wanted.private_endpoint.port)
                    ),
                    0,
                )

    def test_offline_recovery_from_promoted_provider_scope_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            release_id = _release_id(release)
            runtime = root / "runtime"
            wanted = request(unused_port(), rung="home:arch", generation=18)
            wanted = dataclasses.replace(
                wanted,
                contract=dataclasses.replace(
                    wanted.contract,
                    release_id=release_id,
                ),
            )
            adapter = LegacyShellProvider(runtime, release)
            result = adapter.start(
                wanted,
                TransitionDeadline.after_ms(5_000),
                evidence,
            )
            secure_runtime = SecureRuntime(runtime)
            store = RecoveryStore(secure_runtime)
            retained = store.provider_scope_store.load(wanted, "provider")
            self.assertIsNotNone(retained)
            assert retained is not None
            scope_path = Path(retained.scope.scope_path)
            self.assertTrue(scope_path.exists())
            fence = FenceRecord(
                schema_version=1,
                release_id=release_id,
                owner_epoch=wanted.owner_epoch,
                pid=2**31 - 1,
                pid_start_ticks=1,
                boot_id=current_process_identity().boot_id,
                phase="DRAINING",
            )
            FenceStore(secure_runtime).publish(fence)
            effect_id = f"{wanted.owner_epoch}-g{wanted.generation}-start"
            store.put_provider(
                ProviderRecoveryRecord(
                    schema_version=1,
                    record_version=1,
                    release_id=release_id,
                    owner_epoch=wanted.owner_epoch,
                    effect_id=effect_id,
                    phase="APPLIED",
                    request=wanted,
                    resources=result.resources,
                )
            )
            outcome = recover_offline(
                runtime,
                release,
                recover_compatibility=False,
            )
            self.assertTrue(outcome.recovered)
            self.assertEqual(outcome.provider_records, 1)
            self.assertFalse(scope_path.exists())
            self.assertEqual(store.list_provider_scopes(), ())
            self.assertFalse(runtime.joinpath("p").exists())
            self.assertFalse(runtime.joinpath("recovery.fence").exists())
            self.assertFalse(
                recover_offline(
                    runtime,
                    release,
                    recover_compatibility=False,
                ).recovered
            )

    def test_strict_shell_adapter_uses_isolated_env_inventory_and_empty_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            runtime = root / "runtime"
            adapter = LegacyShellProvider(runtime, release)
            wanted = request(unused_port(), rung="home:arch", generation=3)
            seen: list[Endpoint] = []

            def qualify(endpoint, requested, deadline, cancellation):
                del deadline, cancellation
                seen.append(endpoint)
                with socket.create_connection((endpoint.host, endpoint.port), timeout=1) as client:
                    client.sendall(b"private-home")
                    self.assertEqual(client.recv(64), b"private-home")
                return evidence(endpoint, requested)

            old = os.environ.get("LEAK_ME")
            os.environ["LEAK_ME"] = "must-not-reach-provider"
            result = None
            try:
                result = adapter.start(
                    wanted, TransitionDeadline.after_ms(5_000), qualify
                )
                self.assertEqual(seen, [wanted.private_endpoint])
                self.assertEqual(result.resources.rung, "home:arch")
                self.assertEqual(result.resources.listeners[0].owner.pid, result.resources.processes[0].pid)
                self.assertEqual({path.kind for path in result.resources.paths}, {"inventory", "pid"})
                store = ProviderScopeStore(runtime)
                self.assertIsNone(store.load(wanted, "command"))
                retained = store.load(wanted, "provider")
                self.assertIsNotNone(retained)
                assert retained is not None
                self.assertEqual((retained.verb, retained.phase), ("provider-up", "ATTACHED"))
                scope_path = Path(retained.scope.scope_path)
                self.assertTrue(scope_path.exists())
                relative = scope_path.relative_to("/sys/fs/cgroup")
                for identity in result.resources.processes:
                    membership = Path(
                        f"/proc/{identity.pid}/cgroup"
                    ).read_text(encoding="ascii").strip()
                    self.assertEqual(membership, f"0::/{relative}")
                adapter.stop(result, TransitionDeadline.after_ms(5_000))
                self.assertTrue(adapter.prove_empty(result).clean)
                self.assertFalse(scope_path.exists())
                self.assertEqual(store.list_records(), ())
                result = None
            finally:
                if old is None:
                    os.environ.pop("LEAK_ME", None)
                else:
                    os.environ["LEAK_ME"] = old
                if result is not None:
                    try:
                        adapter.stop(result, TransitionDeadline.after_ms(5_000))
                    except Exception:
                        pass

    def test_mismatched_inventory_is_rejected_and_candidate_is_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            (release / "malformed").touch()
            runtime = root / "runtime"
            adapter = LegacyShellProvider(runtime, release)
            wanted = request(unused_port(), rung="iphone", generation=4)

            with self.assertRaisesRegex(ProviderProtocolError, "rung mismatch"):
                adapter.start(
                    wanted, TransitionDeadline.after_ms(5_000), evidence
                )
            with socket.socket() as probe:
                probe.settimeout(0.2)
                self.assertNotEqual(
                    probe.connect_ex(
                        (wanted.private_endpoint.host, wanted.private_endpoint.port)
                    ),
                    0,
                )
            self.assertFalse(runtime.joinpath("p").exists())

    def test_vpn_inventory_requires_and_records_fixed_broker_resource_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            adapter = LegacyShellProvider(root / "runtime", release)
            wanted = request(unused_port(), rung="vpn", generation=6)
            result = adapter.start(
                wanted, TransitionDeadline.after_ms(5_000), evidence
            )
            try:
                self.assertEqual(
                    {(item.kind, item.name) for item in result.resources.privileged},
                    {
                        ("namespace", "grokvpn"),
                        ("tun", "tun-grok"),
                        ("vpn_daemon", "openvpn"),
                    },
                )
                self.assertFalse(adapter.prove_empty(result).clean)
                adapter.stop(result, TransitionDeadline.after_ms(5_000))
                self.assertTrue(adapter.prove_empty(result).clean)
                result = None
            finally:
                if result is not None:
                    try:
                        adapter.stop(result, TransitionDeadline.after_ms(5_000))
                    except Exception:
                        pass

    def test_vpn_qualification_advances_candidates_and_keeps_exact_relay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            adapter = LegacyShellProvider(root / "runtime", release)
            wanted = request(unused_port(), rung="vpn", generation=7)
            calls = 0

            def qualify(endpoint, requested, deadline, cancellation):
                nonlocal calls
                del deadline, cancellation
                calls += 1
                if calls < 3:
                    raise ProviderError(f"candidate {calls} rejected")
                return evidence(endpoint, requested)

            result = adapter.start(
                wanted, TransitionDeadline.after_ms(5_000), qualify
            )
            try:
                self.assertEqual(calls, 3)
                self.assertEqual((release / "next.count").read_text().strip(), "2")
                self.assertTrue(process_matches(result.resources.processes[0]))
                adapter.stop(result, TransitionDeadline.after_ms(5_000))
                self.assertTrue(adapter.prove_empty(result).clean)
                result = None
            finally:
                if result is not None:
                    adapter.stop(result, TransitionDeadline.after_ms(5_000))

    def test_vpn_qualification_exhaustion_fully_cleans_last_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            runtime = root / "runtime"
            adapter = LegacyShellProvider(runtime, release)
            wanted = request(unused_port(), rung="vpn", generation=8)
            calls = 0

            def reject(endpoint, requested, deadline, cancellation):
                nonlocal calls
                del endpoint, requested, deadline, cancellation
                calls += 1
                raise ProviderError(f"candidate {calls} rejected")

            with self.assertRaisesRegex(ProviderError, "candidate 4 rejected"):
                adapter.start(wanted, TransitionDeadline.after_ms(5_000), reject)
            self.assertEqual(calls, 4)
            self.assertEqual((release / "next.count").read_text().strip(), "3")
            self.assertFalse(runtime.joinpath("p").exists())
            with socket.socket() as probe:
                probe.settimeout(0.2)
                self.assertNotEqual(
                    probe.connect_ex(
                        (wanted.private_endpoint.host, wanted.private_endpoint.port)
                    ),
                    0,
                )

    def test_vpn_qualification_cancellation_never_advances_and_cleans(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            release = self._release(root)
            runtime = root / "runtime"
            adapter = LegacyShellProvider(runtime, release)
            wanted = request(unused_port(), rung="vpn", generation=9)
            cancellation = threading.Event()

            def cancel(endpoint, requested, deadline, observed):
                del endpoint, requested, deadline
                self.assertIs(observed, cancellation)
                cancellation.set()
                raise ProviderError("candidate rejected during cancellation")

            with self.assertRaises(ProviderCancelled):
                adapter.start(
                    wanted,
                    TransitionDeadline.after_ms(5_000),
                    cancel,
                    cancellation,
                )
            self.assertFalse((release / "next.count").exists())
            self.assertFalse(runtime.joinpath("p").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
