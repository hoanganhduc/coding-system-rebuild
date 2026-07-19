#!/usr/bin/env python3
"""Deterministic tests for the multi-session contract, IPC, and runtime core."""

from __future__ import annotations

import copy
import dataclasses
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import grok_ms.contract as contract_module
from grok_ms.contract import (
    CONTRACT_SCHEMA_VERSION,
    ContractValidationError,
    Endpoint,
    HomeEndpoint,
    IosEndpoint,
    PROTOCOL_VERSION,
    RUNG_QUALIFICATION_SCHEMA_VERSION,
    ResourceLimits,
    RungQualificationContract,
    RouteContract,
    RouteMode,
    StabilityPolicy,
    TimeoutPolicy,
    VpnPolicy,
    qualification_route_profile_matches,
    reconstruct_original_contract,
)
from grok_ms.ipc import (
    ProtocolError,
    SeqPacketConnection,
    bind_seqpacket_listener,
)
from grok_ms.runtime import (
    EffectIntent,
    FenceBusyError,
    FenceRecord,
    FenceStore,
    IntentConflictError,
    IntentStore,
    ProcessIdentity,
    RuntimeSecurityError,
    SecureRuntime,
    current_process_identity,
    pidfd_for_identity,
    process_matches,
)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def base_contract() -> RouteContract:
    return RouteContract(
        schema_version=CONTRACT_SCHEMA_VERSION,
        protocol_version=PROTOCOL_VERSION,
        release_id="test-release-1",
        model_id="grok-4.5",
        route_mode=RouteMode.AUTO,
        forced_host=None,
        home_endpoints=(
            HomeEndpoint("arch", "100.64.0.10", "alice", 22),
            HomeEndpoint("win", "100.64.0.11", "bob", 2200),
        ),
        ios_endpoints=(
            IosEndpoint("iphone-xr", "n-test-phone"),
            IosEndpoint("ipad-pro", "n-test-ipad"),
        ),
        forced_ios_key=None,
        allow_direct=True,
        ladder=(
            "home:arch",
            "home:win",
            "ios:iphone-xr",
            "ios:ipad-pro",
            "vpn",
        ),
        routing_config_digest="a" * 64,
        probe_policy_version="probe-v1",
        timeout_policy=TimeoutPolicy(
            connect_ms=8_000,
            probe_ms=90_000,
            transition_ms=900_000,
            stop_ms=10_000,
        ),
        stability_policy=StabilityPolicy(
            version="same-exit-v1",
            sample_count=3,
            sample_interval_ms=1_000,
            require_same_exit=True,
        ),
        vpn_policy=VpnPolicy(
            namespace="grokvpn",
            max_tries=6,
            ranking_version="vpn-rank-v1",
            countries=("VN", "JP"),
            blocked_countries=("CN", "DE"),
        ),
        helper_release_ids=(
            ("relay", "relay-release-1"),
            ("socks", "socks-release-1"),
            ("vpn-broker", "broker-release-1"),
        ),
        grok_release_id="grok-0.2.93",
        public_endpoint=Endpoint(host="127.0.0.1", port=1080),
        private_ports=(11880, 11881, 11882, 11883),
        limits=ResourceLimits(
            max_leases=32,
            max_control_connections=64,
            max_frontend_streams=256,
            max_packet_bytes=65_536,
            per_stream_buffer_bytes=262_144,
            total_buffer_bytes=67_108_864,
        ),
    )


class ContractTests(unittest.TestCase):
    def test_rung_qualification_projection_matches_for_forced_and_auto(self) -> None:
        automatic = base_contract()
        forced_home = dataclasses.replace(
            automatic,
            route_mode=RouteMode.HOME,
            forced_host="arch",
            ladder=("home:arch",),
            routing_config_digest="b" * 64,
        )
        forced_ios = dataclasses.replace(
            automatic,
            route_mode=RouteMode.IOS,
            forced_ios_key="iphone-xr",
            ios_endpoints=(automatic.ios_endpoints[0],),
            ladder=("ios:iphone-xr",),
            routing_config_digest="c" * 64,
        )
        forced_vpn = dataclasses.replace(
            automatic,
            route_mode=RouteMode.VPN,
            ladder=("vpn",),
            routing_config_digest="d" * 64,
        )
        forced_direct = dataclasses.replace(
            automatic,
            route_mode=RouteMode.DIRECT,
            ios_endpoints=(),
            ladder=("direct",),
            routing_config_digest="e" * 64,
        )

        pairs = (
            (automatic, forced_home, "home:arch"),
            (automatic, forced_ios, "ios:iphone-xr"),
            (automatic, forced_vpn, "vpn"),
            (automatic, forced_direct, "direct"),
        )
        for left, right, rung in pairs:
            with self.subTest(rung=rung):
                self.assertNotEqual(left.digest(), right.digest())
                self.assertEqual(
                    left.rung_qualification_contract(rung),
                    right.rung_qualification_contract(rung),
                )
                self.assertEqual(
                    left.rung_qualification_digest(rung),
                    right.rung_qualification_digest(rung),
                )

    def test_rung_qualification_projection_normalizes_only_route_selection(self) -> None:
        contract = base_contract()
        baseline = contract.rung_qualification_digest("home:arch")
        unrelated = dataclasses.replace(
            contract,
            home_endpoints=(
                contract.home_endpoints[0],
                dataclasses.replace(
                    contract.home_endpoints[1], host="100.64.0.99"
                ),
            ),
            ios_endpoints=(
                dataclasses.replace(
                    contract.ios_endpoints[0], stable_node_id="n-other-phone"
                ),
                contract.ios_endpoints[1],
            ),
            routing_config_digest="e" * 64,
        )
        selected_endpoint_changed = dataclasses.replace(
            contract,
            home_endpoints=(
                dataclasses.replace(
                    contract.home_endpoints[0], host="100.64.0.12"
                ),
                contract.home_endpoints[1],
            ),
        )

        self.assertEqual(
            unrelated.rung_qualification_digest("home:arch"), baseline
        )
        self.assertNotEqual(
            selected_endpoint_changed.rung_qualification_digest("home:arch"),
            baseline,
        )

    def test_rung_qualification_projection_binds_common_behavior_fields(self) -> None:
        contract = base_contract()
        baseline = contract.rung_qualification_digest("home:arch")
        variants = (
            dataclasses.replace(contract, release_id="test-release-2"),
            dataclasses.replace(contract, model_id="grok-4.5-fast"),
            dataclasses.replace(contract, probe_policy_version="probe-v2"),
            dataclasses.replace(
                contract,
                timeout_policy=dataclasses.replace(
                    contract.timeout_policy, probe_ms=91_000
                ),
            ),
            dataclasses.replace(
                contract,
                stability_policy=dataclasses.replace(
                    contract.stability_policy, sample_count=4
                ),
            ),
            dataclasses.replace(
                contract,
                vpn_policy=dataclasses.replace(
                    contract.vpn_policy, blocked_countries=("CN", "FR")
                ),
            ),
            dataclasses.replace(
                contract,
                helper_release_ids=(
                    ("relay", "relay-release-2"),
                    ("socks", "socks-release-1"),
                    ("vpn-broker", "broker-release-1"),
                ),
            ),
            dataclasses.replace(contract, grok_release_id="grok-0.2.94"),
            dataclasses.replace(
                contract, public_endpoint=Endpoint("127.0.0.1", 1081)
            ),
            dataclasses.replace(
                contract, private_ports=(11880, 11881, 11882, 11884)
            ),
            dataclasses.replace(
                contract,
                limits=dataclasses.replace(contract.limits, max_leases=33),
            ),
        )

        for variant in variants:
            with self.subTest(difference=contract.semantic_differences(variant)):
                self.assertNotEqual(
                    variant.rung_qualification_digest("home:arch"), baseline
                )

    def test_rung_qualification_contract_is_closed_and_round_trips(self) -> None:
        projection = base_contract().rung_qualification_contract("ios:iphone-xr")
        self.assertEqual(
            projection.schema_version, RUNG_QUALIFICATION_SCHEMA_VERSION
        )
        self.assertEqual(
            RungQualificationContract.from_dict(projection.to_dict()), projection
        )
        self.assertEqual(
            RungQualificationContract.from_dict(projection.to_dict()).digest(),
            projection.digest(),
        )

        unexpected = projection.to_dict()
        unexpected["unexpected"] = True
        with self.assertRaises(ContractValidationError):
            RungQualificationContract.from_dict(unexpected)
        malformed = projection.to_dict()
        malformed["private_ports"][0] = True
        with self.assertRaises(ContractValidationError):
            RungQualificationContract.from_dict(malformed)
        with self.assertRaisesRegex(ContractValidationError, "authorized rung"):
            base_contract().rung_qualification_contract("home:missing")

    def test_rung_qualification_field_classification_is_exhaustive(self) -> None:
        partitions = (
            contract_module._RUNG_QUALIFICATION_INCLUDED_ROUTE_FIELDS,
            contract_module._RUNG_QUALIFICATION_SELECTED_ENDPOINT_FIELDS,
            contract_module._RUNG_QUALIFICATION_NORMALIZED_ROUTE_FIELDS,
        )
        actual = {field.name for field in dataclasses.fields(RouteContract)}
        self.assertEqual(set().union(*partitions), actual)
        for field_name in actual:
            self.assertEqual(
                sum(field_name in partition for partition in partitions), 1
            )

    def test_filtered_auto_ladder_preserves_frozen_order_and_reconstructs(self) -> None:
        original = dataclasses.replace(
            base_contract(),
            ladder=(
                "home:arch",
                "home:win",
                "ios:iphone-xr",
                "ios:ipad-pro",
                "vpn",
                "direct",
            ),
        )
        filtered = dataclasses.replace(
            original,
            ladder=("home:win", "vpn", "direct"),
        )
        self.assertEqual(reconstruct_original_contract(filtered), original)
        self.assertTrue(
            qualification_route_profile_matches(filtered, "auto", "vpn")
        )
        self.assertFalse(
            qualification_route_profile_matches(filtered, "auto-no-direct", "vpn")
        )
        with self.assertRaisesRegex(
            ContractValidationError, "preserve frozen home endpoint order"
        ):
            dataclasses.replace(
                original,
                ladder=("home:win", "home:arch"),
            )
        with self.assertRaisesRegex(
            ContractValidationError, "preserve original route order"
        ):
            reconstruct_original_contract(
                dataclasses.replace(original, ladder=("direct", "vpn"))
            )

    def test_filtered_ios_family_keeps_frozen_endpoints_and_reconstructs(self) -> None:
        original = dataclasses.replace(
            base_contract(),
            route_mode=RouteMode.IOS,
            forced_host=None,
            home_endpoints=(),
            forced_ios_key=None,
            allow_direct=True,
            ladder=("ios:iphone-xr", "ios:ipad-pro"),
        )
        filtered = dataclasses.replace(original, ladder=("ios:ipad-pro",))
        self.assertEqual(filtered.ios_endpoints, original.ios_endpoints)
        self.assertEqual(reconstruct_original_contract(filtered), original)
        self.assertTrue(
            qualification_route_profile_matches(filtered, "iphone", "ios:ipad-pro")
        )
        with self.assertRaisesRegex(
            ContractValidationError,
            "only frozen iOS devices",
        ):
            dataclasses.replace(filtered, ladder=("direct",))

    def test_home_label_character_set_excludes_model_namespace_separator(self) -> None:
        with self.assertRaisesRegex(ContractValidationError, "unsupported characters"):
            HomeEndpoint("lab/phone", "100.64.0.10", "alice", 22)
        self.assertEqual(
            dataclasses.replace(base_contract(), model_id="xai/grok-4.5").model_id,
            "xai/grok-4.5",
        )

    def test_canonical_round_trip_is_order_independent(self) -> None:
        contract = base_contract()
        mapping = contract.to_dict()
        reordered = dict(reversed(tuple(mapping.items())))

        decoded = RouteContract.from_dict(reordered)

        self.assertEqual(decoded, contract)
        self.assertEqual(decoded.canonical_bytes(), contract.canonical_bytes())
        self.assertEqual(decoded.digest(), contract.digest())
        self.assertEqual(contract.canonical_bytes(), contract.canonical_bytes())

    def test_semantic_one_field_deltas_change_digest(self) -> None:
        contract = base_contract()
        variants = (
            ("model_id", dataclasses.replace(contract, model_id="grok-4.5-fast")),
            ("allow_direct", dataclasses.replace(contract, allow_direct=False)),
            (
                "public_endpoint.port",
                dataclasses.replace(
                    contract,
                    public_endpoint=dataclasses.replace(contract.public_endpoint, port=1081),
                ),
            ),
            (
                "home_endpoints",
                dataclasses.replace(
                    contract,
                    home_endpoints=(
                        dataclasses.replace(
                            contract.home_endpoints[0], host="100.64.0.11"
                        ),
                        contract.home_endpoints[1],
                    ),
                ),
            ),
            (
                "ios_endpoints",
                dataclasses.replace(
                    contract,
                    ios_endpoints=(
                        IosEndpoint("iphone-xr", "n-other-phone"),
                        contract.ios_endpoints[1],
                    ),
                ),
            ),
            (
                "timeout_policy.probe_ms",
                dataclasses.replace(
                    contract,
                    timeout_policy=dataclasses.replace(contract.timeout_policy, probe_ms=91_000),
                ),
            ),
            (
                "stability_policy.sample_count",
                dataclasses.replace(
                    contract,
                    stability_policy=dataclasses.replace(
                        contract.stability_policy, sample_count=4
                    ),
                ),
            ),
            (
                "vpn_policy.max_tries",
                dataclasses.replace(
                    contract,
                    vpn_policy=dataclasses.replace(contract.vpn_policy, max_tries=7),
                ),
            ),
            (
                "limits.max_leases",
                dataclasses.replace(
                    contract,
                    limits=dataclasses.replace(contract.limits, max_leases=33),
                ),
            ),
        )

        for expected_path, variant in variants:
            with self.subTest(expected_path=expected_path):
                self.assertNotEqual(contract.digest(), variant.digest())
                self.assertEqual(
                    contract.semantic_differences(variant), (expected_path,)
                )

    def test_strict_typed_decode_rejects_unknown_and_bool_as_int(self) -> None:
        mapping = base_contract().to_dict()
        mapping["unexpected"] = "field"
        with self.assertRaises(ContractValidationError):
            RouteContract.from_dict(mapping)

    def test_vpn_attempt_bound_matches_broker_deadline_contract(self) -> None:
        mapping = base_contract().to_dict()
        mapping["vpn_policy"]["max_tries"] = 8
        self.assertEqual(RouteContract.from_dict(mapping).vpn_policy.max_tries, 8)

        mapping["vpn_policy"]["max_tries"] = 9
        with self.assertRaises(ContractValidationError):
            RouteContract.from_dict(mapping)

        with self.assertRaisesRegex(
            ContractValidationError, "timeout_policy.transition_ms"
        ):
            dataclasses.replace(
                base_contract(),
                timeout_policy=dataclasses.replace(
                    base_contract().timeout_policy, transition_ms=300_000
                ),
            )

        mapping = base_contract().to_dict()
        mapping["public_endpoint"]["port"] = True
        with self.assertRaises(ContractValidationError):
            RouteContract.from_dict(mapping)

    def test_unpinned_model_and_invalid_route_combinations_fail(self) -> None:
        with self.assertRaises(ContractValidationError):
            dataclasses.replace(base_contract(), model_id="")
        with self.assertRaises(ContractValidationError):
            dataclasses.replace(
                base_contract(), route_mode=RouteMode.HOME, forced_host=None
            )
        with self.assertRaises(ContractValidationError):
            dataclasses.replace(
                base_contract(), route_mode=RouteMode.DIRECT, allow_direct=False
            )
        with self.assertRaisesRegex(ContractValidationError, "frozen home endpoint"):
            dataclasses.replace(
                base_contract(),
                route_mode=RouteMode.HOME,
                forced_host="unknown",
                ladder=("home:unknown",),
            )
        with self.assertRaisesRegex(ContractValidationError, "iOS endpoint"):
            dataclasses.replace(base_contract(), ios_endpoints=())
        exact_ios = dataclasses.replace(
            base_contract(),
            route_mode=RouteMode.IOS,
            forced_ios_key="iphone-xr",
            ios_endpoints=(base_contract().ios_endpoints[0],),
            ladder=("ios:iphone-xr",),
        )
        with self.assertRaisesRegex(ContractValidationError, "only its selected"):
            dataclasses.replace(
                exact_ios,
                ios_endpoints=base_contract().ios_endpoints,
            )
        with self.assertRaisesRegex(ContractValidationError, "exactly its frozen"):
            dataclasses.replace(
                exact_ios,
                ladder=("ios:iphone-xr", "vpn"),
            )
        with self.assertRaisesRegex(ContractValidationError, "preserve frozen"):
            dataclasses.replace(
                base_contract(),
                home_endpoints=tuple(reversed(base_contract().home_endpoints)),
            )


@unittest.skipUnless(
    hasattr(socket, "SOCK_SEQPACKET") and hasattr(socket, "SO_PEERCRED"),
    "Linux SOCK_SEQPACKET peer credentials are unavailable",
)
class SeqPacketTests(unittest.TestCase):
    def test_real_listener_round_trip_peer_credentials_and_fd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            socket_path = root / "control.sock"
            listener = bind_seqpacket_listener(socket_path)
            client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            client_socket.connect(str(socket_path))
            server_socket, _ = listener.accept()
            listener.close()
            client = SeqPacketConnection(client_socket, max_packet_bytes=4096)
            server = SeqPacketConnection(server_socket, max_packet_bytes=4096)
            sent_fd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
            received_fd = -1
            try:
                self.assertEqual(mode(socket_path), 0o600)
                peer = server.peer_credentials()
                self.assertEqual((peer.pid, peer.uid, peer.gid), (os.getpid(), os.getuid(), os.getgid()))

                client.send({"message_type": "ATTACH_SCOPE", "request_id": "r-1"}, (sent_fd,))
                message = server.recv()
                self.assertEqual(message.payload["message_type"], "ATTACH_SCOPE")
                self.assertEqual(len(message.fds), 1)
                received_fd = message.fds[0]
                self.assertTrue(os.get_inheritable(received_fd) is False)

                server.send({"message_type": "ACK", "request_id": "r-1"})
                self.assertEqual(client.recv().payload["message_type"], "ACK")
            finally:
                if received_fd >= 0:
                    os.close(received_fd)
                os.close(sent_fd)
                client.close()
                server.close()

    def test_truncated_packet_is_rejected(self) -> None:
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            sender.send(b"x" * 2048)
            connection = SeqPacketConnection(receiver, max_packet_bytes=128)
            with self.assertRaisesRegex(ProtocolError, "truncated"):
                connection.recv()
        finally:
            sender.close()
            receiver.close()

    def test_oversize_send_and_duplicate_json_keys_are_rejected(self) -> None:
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            connection = SeqPacketConnection(sender, max_packet_bytes=64)
            with self.assertRaisesRegex(ProtocolError, "too large"):
                connection.send({"payload": "z" * 128})

            receiver.send(b'{"x":1,"x":2}')
            with self.assertRaisesRegex(ProtocolError, "duplicate"):
                connection.recv()
        finally:
            sender.close()
            receiver.close()


class RuntimeTests(unittest.TestCase):
    def test_secure_fence_publish_load_and_clear_are_durable_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "runtime"
            runtime = SecureRuntime(root)
            runtime.initialize()
            identity = current_process_identity()
            record = FenceRecord(
                schema_version=1,
                release_id="test-release-1",
                owner_epoch="epoch-1",
                pid=identity.pid,
                pid_start_ticks=identity.start_ticks,
                boot_id=identity.boot_id,
                phase="BOOTSTRAPPING",
            )
            store = FenceStore(runtime)

            with mock.patch("grok_ms.runtime.os.fsync", wraps=os.fsync) as fsync:
                self.assertTrue(store.publish(record))
                self.assertGreaterEqual(fsync.call_count, 2)

            self.assertEqual(mode(root), 0o700)
            self.assertEqual(mode(store.path), 0o600)
            before = store.path.read_bytes()
            self.assertFalse(store.publish(record))
            self.assertEqual(store.path.read_bytes(), before)
            self.assertEqual(store.load(), record)

            with self.assertRaises(FenceBusyError):
                store.publish(dataclasses.replace(record, owner_epoch="epoch-2"))
            with self.assertRaises(FenceBusyError):
                store.clear("epoch-2")

            self.assertTrue(store.clear("epoch-1"))
            self.assertFalse(store.clear("epoch-1"))

    def test_secure_runtime_rejects_wrong_mode_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "runtime"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o755)
            with self.assertRaises(RuntimeSecurityError):
                SecureRuntime(root).initialize()

            target = Path(tmp) / "target"
            target.mkdir(mode=0o700)
            link = Path(tmp) / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(RuntimeSecurityError):
                SecureRuntime(link).initialize()

    def test_process_identity_matches_pid_start_and_boot(self) -> None:
        identity = current_process_identity()
        self.assertTrue(process_matches(identity))
        self.assertFalse(
            process_matches(dataclasses.replace(identity, start_ticks=identity.start_ticks + 1))
        )
        self.assertFalse(
            process_matches(dataclasses.replace(identity, boot_id="00000000-0000-0000-0000-000000000000"))
        )

        pidfd = pidfd_for_identity(identity)
        try:
            self.assertGreaterEqual(pidfd, 0)
            self.assertFalse(os.get_inheritable(pidfd))
        finally:
            os.close(pidfd)

        self.assertFalse(process_matches(ProcessIdentity(pid=999_999_999, start_ticks=1, boot_id=identity.boot_id)))

    def test_effect_intents_are_idempotent_and_phase_ordered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = SecureRuntime(Path(tmp) / "runtime")
            runtime.initialize()
            store = IntentStore(runtime)
            intent = EffectIntent(
                schema_version=1,
                owner_epoch="epoch-1",
                generation=7,
                effect_id="effect-1",
                operation="START_HOME",
                parameters_digest="b" * 64,
                phase="PREPARED",
            )

            self.assertTrue(store.put(intent))
            path = store.path_for(intent.effect_id)
            self.assertEqual(mode(path), 0o600)
            before = path.read_bytes()
            self.assertFalse(store.put(intent))
            self.assertEqual(path.read_bytes(), before)

            with self.assertRaises(IntentConflictError):
                store.put(dataclasses.replace(intent, operation="START_IPHONE"))

            self.assertTrue(store.advance("effect-1", "PREPARED", "APPLIED"))
            self.assertFalse(store.advance("effect-1", "PREPARED", "APPLIED"))
            self.assertEqual(store.load("effect-1").phase, "APPLIED")
            with self.assertRaises(IntentConflictError):
                store.advance("effect-1", "PREPARED", "CLEANED")


if __name__ == "__main__":
    unittest.main()
