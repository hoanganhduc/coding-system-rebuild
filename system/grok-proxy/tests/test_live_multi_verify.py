#!/usr/bin/env python3
"""Offline unit coverage for the fail-closed live verifier helpers."""

from __future__ import annotations

import json
import inspect
import os
from dataclasses import replace
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from grok_ms import qualification_fake_grok as FIXTURE
from grok_ms import config as CONFIG
from grok_ms import qualification_verifier as VERIFY
from grok_ms import providers as PROVIDERS
from grok_ms import supervisor as SUPERVISOR
from grok_ms.contract import (
    CONTRACT_SCHEMA_VERSION,
    Endpoint,
    HomeEndpoint,
    IosEndpoint,
    PROTOCOL_VERSION,
    ResourceLimits,
    RouteContract,
    RouteMode,
    StabilityPolicy,
    TimeoutPolicy,
    VpnPolicy,
    reconstruct_original_contract,
)
from grok_ms.providers import (
    ListenerIdentity,
    PrivilegedResourceIdentity,
    ProviderRequest,
    ProviderResourceGraph,
)
from grok_ms.managed_profile import (
    ManagedProfile,
    ReadinessPolicy,
    write_content_addressed_profile,
)
from grok_ms.runtime import current_process_identity as runtime_process_identity


class LiveVerifierHelperTests(unittest.TestCase):
    def test_default_country_policy_is_identical_across_all_authorities(self) -> None:
        expected = ("CN", "IR", "KP", "TM", "VE")
        self.assertEqual(tuple(CONFIG._BLOCKED_DEFAULT.split()), expected)
        self.assertEqual(tuple(VERIFY._BLOCKED_DEFAULT.split()), expected)
        for relative in ("egress.sh", "vpngate-connect.sh"):
            source = (ROOT / relative).read_text(encoding="utf-8")
            match = re.search(
                r'^GROK_BLOCKED_CC="\$\{GROK_BLOCKED_CC-([A-Z ]+)\}"$',
                source,
                re.MULTILINE,
            )
            self.assertIsNotNone(match, relative)
            assert match is not None
            self.assertEqual(tuple(match.group(1).split()), expected, relative)

    @staticmethod
    def _open_fds_under(root: Path) -> tuple[int, ...]:
        prefix = f"{root}/"
        matches: list[int] = []
        for name in os.listdir("/proc/self/fd"):
            try:
                target = os.readlink(f"/proc/self/fd/{name}")
            except (FileNotFoundError, OSError, ValueError):
                continue
            if target == str(root) or target.startswith(prefix):
                matches.append(int(name))
        return tuple(sorted(matches))

    @staticmethod
    def _route_contract(rung: str) -> RouteContract:
        if rung == "direct":
            mode = RouteMode.DIRECT
            forced_host = None
            homes: tuple[HomeEndpoint, ...] = ()
            ios_endpoints: tuple[IosEndpoint, ...] = ()
        elif rung == "ios:iphone-xr":
            mode = RouteMode.IOS
            forced_host = None
            homes = ()
            ios_endpoints = (IosEndpoint("iphone-xr", "node-phone-1"),)
        elif rung == "vpn":
            mode = RouteMode.VPN
            forced_host = None
            homes = ()
            ios_endpoints = ()
        else:
            mode = RouteMode.HOME
            forced_host = rung.removeprefix("home:")
            homes = (HomeEndpoint(forced_host, "host.example", "alice", 22),)
            ios_endpoints = ()
        return RouteContract(
            schema_version=CONTRACT_SCHEMA_VERSION,
            protocol_version=PROTOCOL_VERSION,
            release_id="release-test-1",
            model_id="xai/grok-4.5",
            route_mode=mode,
            forced_host=forced_host,
            home_endpoints=homes,
            ios_endpoints=ios_endpoints,
            forced_ios_key="iphone-xr" if mode is RouteMode.IOS else None,
            allow_direct=True,
            ladder=(rung,),
            routing_config_digest="a" * 64,
            probe_policy_version="probe-test-v1",
            timeout_policy=TimeoutPolicy(1_000, 1_000, 200_000, 1_000),
            stability_policy=StabilityPolicy("stable-test-v1", 1, 0, True),
            vpn_policy=VpnPolicy(
                "grokvpn", 1, "rank-test-v1", ("JP",), ("CN",)
            ),
            helper_release_ids=(("broker", "release-test-1"),),
            grok_release_id="grok-test-1",
            public_endpoint=Endpoint("127.0.0.1", 1080),
            private_ports=(11080, 11081),
            limits=ResourceLimits(4, 8, 16, 65_536, 4_096, 65_536),
        )

    def test_provider_authority_graph_is_route_specific(self) -> None:
        identity = runtime_process_identity()
        for rung in ("direct", "home:lab-phone", "ios:iphone-xr", "vpn"):
            with self.subTest(rung=rung):
                contract = self._route_contract(rung)
                request = ProviderRequest(
                    "epoch-1",
                    "transition-1",
                    1,
                    rung,
                    contract.model_id,
                    Endpoint("127.0.0.1", 11080),
                    contract,
                )
                privileged = ()
                if rung == "vpn":
                    privileged = (
                        PrivilegedResourceIdentity(
                            "namespace", "grokvpn", "broker-1"
                        ),
                        PrivilegedResourceIdentity("tun", "tun-grok", "broker-1"),
                        PrivilegedResourceIdentity(
                            "vpn_daemon", "openvpn", "broker-1"
                        ),
                    )
                graph = ProviderResourceGraph(
                    "epoch-1",
                    "transition-1",
                    1,
                    rung,
                    "/tmp/grok-provider-test",
                    (identity,),
                    (ListenerIdentity(request.private_endpoint, 123, identity),),
                    (),
                    privileged,
                )
                record = {
                    "owner_epoch": "epoch-1",
                    "request": request.to_dict(),
                    "resources": graph.to_dict(),
                }
                decoded_request, decoded_graph = VERIFY._provider_authority_graph(
                    record, expected_rung=rung
                )
                self.assertEqual(decoded_request, request)
                self.assertEqual(decoded_graph, graph)
                with self.assertRaisesRegex(
                    VERIFY.VerificationError, "frozen route request"
                ):
                    VERIFY._provider_authority_graph(
                        record,
                        expected_rung=("vpn" if rung != "vpn" else "direct"),
                    )

    def test_recovery_authorities_normalize_provider_process_identities(self) -> None:
        identity = runtime_process_identity()
        contract = self._route_contract("direct")
        request = ProviderRequest(
            "epoch-1",
            "transition-1",
            1,
            "direct",
            contract.model_id,
            Endpoint("127.0.0.1", 11080),
            contract,
        )
        with tempfile.TemporaryDirectory() as directory:
            control = Path(directory) / "control"
            provider_records = control / "recovery/providers"
            provider_scopes = control / "recovery/provider-scopes"
            runtime_dir = control / "p/provider-test"
            provider_records.mkdir(mode=0o700, parents=True)
            provider_scopes.mkdir(mode=0o700, parents=True)
            runtime_dir.mkdir(mode=0o700, parents=True)
            graph = ProviderResourceGraph(
                "epoch-1",
                "transition-1",
                1,
                "direct",
                str(runtime_dir),
                (identity,),
                (ListenerIdentity(request.private_endpoint, 123, identity),),
                (),
            )
            record = {
                "effect_id": "effect-1",
                "kind": "provider-recovery",
                "owner_epoch": "epoch-1",
                "phase": "APPLIED",
                "record_version": 1,
                "release_id": "release-test-1",
                "request": request.to_dict(),
                "resources": graph.to_dict(),
                "schema_version": 1,
            }
            record_path = provider_records / "effect-1.json"
            record_path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            os.chmod(record_path, 0o600)
            scope_record = {
                "child": {
                    "boot_id": identity.boot_id,
                    "pid": identity.pid,
                    "pid_start_ticks": identity.start_ticks,
                },
                "phase": "ATTACHED",
                "record_version": VERIFY.PROVIDER_SCOPE_RECORD_VERSION,
                "release_id": contract.release_id,
                "request": request.to_dict(),
                "schema_version": 1,
                "scope": {"fixture": True},
                "verb": "direct-up",
            }
            scope_path = provider_scopes / (
                f"{VERIFY._provider_scope_tag(request)}.provider.json"
            )
            scope_path.write_text(
                json.dumps(scope_record, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="ascii",
            )
            os.chmod(scope_path, 0o600)
            retained = {
                "scope_path": "/sys/fs/cgroup/grok-ms-" + "d" * 24,
                "scope_device": 1,
                "scope_inode": 2,
                "populated": True,
                "processes": [identity.pid],
            }

            def inspect() -> dict[str, object]:
                with mock.patch.object(
                    VERIFY, "_retained_scope_evidence", return_value=retained
                ):
                    return VERIFY.recovery_authorities(
                        control, expected_rung="direct"
                    )

            authorities = inspect()

            unsupported = dict(record)
            unsupported["record_version"] = 999
            record_path.write_text(
                json.dumps(unsupported, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "provider record is not exactly applied"
            ):
                inspect()
            record_path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            mismatched_release = json.loads(json.dumps(record))
            mismatched_release["request"]["contract"][
                "release_id"
            ] = "different-frozen-release"
            record_path.write_text(
                json.dumps(
                    mismatched_release, sort_keys=True, separators=(",", ":")
                )
                + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "release differs"
            ):
                inspect()
            record_path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            mismatched_path = provider_records / "different-effect.json"
            record_path.rename(mismatched_path)
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "provider record is not exactly applied"
            ):
                inspect()

        normalized = authorities["provider_identities"]
        self.assertEqual(len(normalized), 1)
        self.assertIs(type(normalized[0]), VERIFY.ProcessIdentity)
        self.assertEqual(normalized[0].pid, identity.pid)
        self.assertEqual(normalized[0].pid_start_ticks, identity.start_ticks)
        self.assertEqual(normalized[0].boot_id, identity.boot_id)
        self.assertEqual(
            authorities["provider_listeners"][0]["owner"],
            normalized[0].to_dict(),
        )
        self.assertEqual(
            authorities["providers"][0]["processes"][0]["identity"],
            normalized[0].to_dict(),
        )

    def test_recovery_authorities_bind_one_retained_legacy_provider_scope(self) -> None:
        identity = runtime_process_identity()
        contract = self._route_contract("home:lab")
        request = ProviderRequest(
            "epoch-1",
            "transition-1",
            1,
            "home:lab",
            contract.model_id,
            Endpoint("127.0.0.1", 11080),
            contract,
        )
        with tempfile.TemporaryDirectory() as directory:
            control = Path(directory) / "control"
            providers = control / "recovery/providers"
            scopes = control / "recovery/provider-scopes"
            runtime_dir = control / "p/provider-test"
            providers.mkdir(mode=0o700, parents=True)
            scopes.mkdir(mode=0o700, parents=True)
            runtime_dir.mkdir(mode=0o700, parents=True)
            graph = ProviderResourceGraph(
                "epoch-1",
                "transition-1",
                1,
                "home:lab",
                str(runtime_dir),
                (identity,),
                (ListenerIdentity(request.private_endpoint, 123, identity),),
                (),
            )
            provider_record = {
                "effect_id": "effect-1",
                "kind": "provider-recovery",
                "owner_epoch": "epoch-1",
                "phase": "APPLIED",
                "record_version": 1,
                "release_id": contract.release_id,
                "request": request.to_dict(),
                "resources": graph.to_dict(),
                "schema_version": 1,
            }
            provider_path = providers / "effect-1.json"
            provider_path.write_text(
                json.dumps(provider_record, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="ascii",
            )
            os.chmod(provider_path, 0o600)
            command = {
                "boot_id": identity.boot_id,
                "pid": 2**31 - 1,
                "pid_start_ticks": 1,
            }
            scope_record = {
                "child": command,
                "phase": "ATTACHED",
                "record_version": VERIFY.PROVIDER_SCOPE_RECORD_VERSION,
                "release_id": contract.release_id,
                "request": request.to_dict(),
                "schema_version": 1,
                "scope": {"fixture": True},
                "verb": "provider-up",
            }
            scope_path = scopes / f"{VERIFY._provider_scope_tag(request)}.provider.json"
            scope_path.write_text(
                json.dumps(scope_record, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="ascii",
            )
            os.chmod(scope_path, 0o600)
            retained = {
                "scope_path": "/sys/fs/cgroup/grok-ms-" + "a" * 24,
                "scope_device": 1,
                "scope_inode": 2,
                "populated": True,
                "processes": [identity.pid],
            }
            with mock.patch.object(
                VERIFY, "_retained_scope_evidence", return_value=retained
            ):
                authorities = VERIFY.recovery_authorities(
                    control, expected_rung="home:lab"
                )
            self.assertEqual(len(authorities["provider_scopes"]), 1)
            self.assertEqual(
                authorities["provider_scopes"][0]["scope"], retained
            )

            mismatched_request = ProviderRequest(
                request.owner_epoch,
                request.transition_id,
                request.generation,
                request.rung,
                request.model_id,
                Endpoint("127.0.0.1", 11081),
                request.contract,
            )
            scope_record["request"] = mismatched_request.to_dict()
            mismatched_scope_path = scopes / (
                f"{VERIFY._provider_scope_tag(mismatched_request)}.provider.json"
            )
            scope_path.rename(mismatched_scope_path)
            mismatched_scope_path.write_text(
                json.dumps(scope_record, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="ascii",
            )
            with mock.patch.object(
                VERIFY, "_retained_scope_evidence", return_value=retained
            ), self.assertRaisesRegex(
                VERIFY.VerificationError, "differs from the applied provider request"
            ):
                VERIFY.recovery_authorities(control, expected_rung="home:lab")

            scope_record["verb"] = "provider-stop"
            mismatched_scope_path.write_text(
                json.dumps(scope_record, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "verb"
            ):
                VERIFY.recovery_authorities(control, expected_rung="home:lab")

    def test_recovery_record_versions_match_the_writer_contract(self) -> None:
        self.assertEqual(
            VERIFY.PROVIDER_RECOVERY_RECORD_VERSION,
            SUPERVISOR._RECOVERY_RECORD_VERSION,
        )
        self.assertEqual(
            VERIFY.CHILD_RECOVERY_RECORD_VERSION,
            SUPERVISOR._CHILD_RECOVERY_RECORD_VERSION,
        )
        self.assertEqual(
            VERIFY.PROBE_RECOVERY_RECORD_VERSION,
            SUPERVISOR._PROBE_RECOVERY_RECORD_VERSION,
        )
        self.assertEqual(
            VERIFY.PROVIDER_SCOPE_RECORD_VERSION,
            PROVIDERS._PROVIDER_SCOPE_RECORD_VERSION,
        )

    def test_probe_recovery_requires_the_writer_nonce_grammar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            control = Path(directory) / "control"
            probes = control / "recovery/probes"
            probes.mkdir(mode=0o700, parents=True)
            probe_id = "probe-id-not-lower-hex"
            record = {
                "child": {
                    "boot_id": "11111111-2222-3333-4444-555555555555",
                    "pid": 42,
                    "pid_start_ticks": 123,
                },
                "kind": "probe-recovery",
                "owner_epoch": "epoch-1",
                "phase": "ATTACHED",
                "probe_id": probe_id,
                "record_version": VERIFY.PROBE_RECOVERY_RECORD_VERSION,
                "release_id": "release-test-1",
                "schema_version": 1,
                "scope": {},
            }
            path = probes / f"{probe_id}.json"
            path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "probe record is not exactly attached"
            ):
                VERIFY.recovery_authorities(control, expected_rung="direct")

    def test_process_and_listener_inventory_recheck_exact_identity(self) -> None:
        identity = VERIFY.ProcessIdentity(
            42, 123, "11111111-2222-3333-4444-555555555555"
        )
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            process = proc / "42"
            (process / "fd").mkdir(parents=True)
            (process / "status").write_text(
                "Threads:\t1\nVmRSS:\t4 kB\nVmSize:\t8 kB\n",
                encoding="ascii",
            )
            (process / "cgroup").write_text("0::/fixture\n", encoding="ascii")
            with mock.patch.object(
                VERIFY, "process_matches", side_effect=(True, False)
            ):
                with self.assertRaisesRegex(
                    VERIFY.VerificationError, "changed during metrics inventory"
                ):
                    VERIFY.process_metrics(identity, proc)
            with mock.patch.object(
                VERIFY, "process_matches", side_effect=(True, False)
            ), mock.patch.object(VERIFY, "_tcp_listener_rows", return_value=()):
                with self.assertRaisesRegex(
                    VERIFY.VerificationError, "changed during inventory"
                ):
                    VERIFY.listener_inventory((1080,), (identity,), proc)

    def test_real_process_inventory_requires_a_live_pidfd_anchor(self) -> None:
        identity = VERIFY.current_process_identity(os.getpid())
        with mock.patch.object(
            VERIFY.signal,
            "pidfd_send_signal",
            side_effect=ProcessLookupError,
        ):
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "exited during metrics inventory"
            ):
                VERIFY.process_metrics(identity)

    def test_listener_inventory_rechecks_the_attributed_socket_inode(self) -> None:
        identity = VERIFY.ProcessIdentity(
            42, 123, "11111111-2222-3333-4444-555555555555"
        )
        row = {
            "family": 4,
            "host": "127.0.0.1",
            "port": 1080,
            "inode": 777,
        }
        with mock.patch.object(
            VERIFY, "process_matches", return_value=True
        ), mock.patch.object(
            VERIFY, "_process_socket_inodes", side_effect=({777}, set())
        ), mock.patch.object(
            VERIFY, "_tcp_listener_rows", return_value=(row,)
        ):
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "socket ownership changed"
            ):
                VERIFY.listener_inventory(
                    (1080,), (identity,), Path("/fixture-proc")
                )

    def test_scoped_inventory_is_exhaustive_and_clean_gate_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            control = Path(directory) / "control"
            control.mkdir(mode=0o700)
            for _label, parts in VERIFY._INVENTORY_TARGETS:
                target = control.joinpath(*parts)
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(target, 0o700)

            clean = VERIFY.user_inventory(control)
            VERIFY.assert_user_inventory_clean(clean)

            residue = control / "providers" / "unexpected.json"
            residue.write_text("{}\n", encoding="ascii")
            os.chmod(residue, 0o600)
            dirty = VERIFY.user_inventory(control)
            self.assertEqual(
                dirty["targets"]["providers"]["entries"][0]["path"],
                "unexpected.json",
            )
            with self.assertRaisesRegex(VERIFY.VerificationError, "providers"):
                VERIFY.assert_user_inventory_clean(dirty)

    def test_process_identity_is_exact_and_pidfd_signal_is_not_needed_to_read(self) -> None:
        identity = VERIFY.current_process_identity(os.getpid())
        self.assertTrue(VERIFY.process_matches(identity))
        changed = VERIFY.ProcessIdentity(
            identity.pid, identity.pid_start_ticks + 1, identity.boot_id
        )
        self.assertFalse(VERIFY.process_matches(changed))
        metrics = VERIFY.aggregate_process_metrics((identity, identity))
        self.assertEqual(metrics["process_count"], 1)
        self.assertGreater(metrics["fd_count"], 0)

    def test_pidfd_exit_readiness_does_not_depend_on_zombie_reaping(self) -> None:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        process: subprocess.Popen[bytes] | None = None
        pidfd = -1
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os,sys; os.read(int(sys.argv[1]), 1)",
                    str(read_fd),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(read_fd,),
            )
            identity = VERIFY.current_process_identity(process.pid)
            pidfd = VERIFY.open_exact_pidfd(identity)
            with self.assertRaisesRegex(VERIFY.VerificationError, "did not exit"):
                VERIFY.wait_exact_pidfd_exit(identity, pidfd, 0)
            os.close(read_fd)
            read_fd = -1
            os.write(write_fd, b"x")
            os.close(write_fd)
            write_fd = -1
            VERIFY.wait_exact_pidfd_exit(identity, pidfd, 2)
            self.assertTrue(VERIFY.process_matches(identity))
            process.wait(timeout=2)
            self.assertFalse(VERIFY.process_matches(identity))
        finally:
            for descriptor in (read_fd, write_fd, pidfd):
                if descriptor >= 0:
                    os.close(descriptor)
            if process is not None and process.returncode is None:
                process.kill()
                process.wait(timeout=2)

    def test_real_pair_pause_orders_refresh_fault_resume_and_completion(self) -> None:
        source = inspect.getsource(VERIFY.run_real_pair)
        pause_source = inspect.getsource(VERIFY.QualificationPause.open)
        positions = [
            source.index("_spawn_models_wrapper"),
            source.index("QualificationPause.open"),
            source.index("release_qualification_child"),
            source.index("prove_exclusive_epoch_authority"),
            source.index("_request_provider_fault"),
            source.index("pause.quiesce"),
            source.index("pause.disarm"),
            source.index("_bounded_collect_pair"),
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("pause_exact_processes", source)
        self.assertNotIn("SIGSTOP", source)
        self.assertNotIn("hold_ms", pause_source)
        self.assertEqual(source.count('leader_policy="disabled-empty"'), 2)
        self.assertIn(
            "leader_policy=authority.leader_policy",
            inspect.getsource(VERIFY.cleanup),
        )
        self.assertIn(
            '"deadline_monotonic_ns": overall_deadline_monotonic_ns',
            pause_source,
        )
        self.assertIn("!= overall_deadline_monotonic_ns", pause_source)
        self.assertLess(
            source.index("preflight_cache.stop"),
            source.index("pair_cache.start"),
        )
        for checkpoint in (
            "real-pair-pause",
            "real-pair-model-refresh",
            "real-pair-old-generation",
            "real-pair-provider-fault",
            "real-pair-repair",
            "real-pair-reconnect",
            "real-pair-resume",
            "real-pair-completion",
        ):
            self.assertIn(checkpoint, VERIFY.QUALIFICATION_FAILURE_CODES["real-pair"])
            self.assertIn(f'stage.set("{checkpoint}")', source)

    def test_real_pair_binds_provider_nonce_only_for_provider_backed_rungs(self) -> None:
        direct = VERIFY.QualificationContext(
            release_id="a" * 64,
            nonce="b" * 64,
            canary_kind="rung",
            rung="direct",
            route_profile="direct",
            contract_sha256="c" * 64,
            grok_release_id="grok-release",
            model_id="grok-model",
            auth_fd=-1,
        )
        self.assertIsNone(VERIFY._provider_canary_nonce(direct))
        self.assertEqual(
            VERIFY._provider_canary_nonce(
                replace(direct, rung="vpn", route_profile="vpn")
            ),
            direct.nonce,
        )
        self.assertIn(
            "provider_canary_nonce=_provider_canary_nonce(context)",
            inspect.getsource(VERIFY.run_real_pair),
        )

    def test_captured_process_record_does_not_reopen_a_retired_identity(self) -> None:
        identity = VERIFY.ProcessIdentity(
            100, 1000, "11111111-2222-3333-4444-555555555555"
        )
        aggregate = self._process_aggregate(1)
        with mock.patch.object(
            VERIFY,
            "process_metrics",
            side_effect=AssertionError("retired identity must not be re-read"),
        ):
            record = VERIFY._aggregate_process_record(aggregate, identity)
        self.assertEqual(record, aggregate["processes"][0])

        duplicate = dict(aggregate)
        duplicate["processes"] = [
            aggregate["processes"][0],
            dict(aggregate["processes"][0]),
        ]
        with self.assertRaisesRegex(VERIFY.VerificationError, "one matching identity"):
            VERIFY._aggregate_process_record(duplicate, identity)

        decoy = VERIFY.ProcessIdentity(
            101, 1001, "11111111-2222-3333-4444-555555555555"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "one matching identity"):
            VERIFY._aggregate_process_record(aggregate, decoy)

        post_absence_source = inspect.getsource(VERIFY.run_load).split(
            "assert_process_identities_absent(", 1
        )[1]
        self.assertNotIn("process_metrics(", post_absence_source)
        self.assertIn(
            "_aggregate_process_record(peak_processes, supervisor)",
            post_absence_source,
        )

    def test_fault_recovery_waits_for_wrapper_before_inherited_pipe_eof(self) -> None:
        gate_read, gate_write = os.pipe()
        process: subprocess.Popen[bytes] | None = None
        drained = False
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os,sys\n"
                        "gate=int(sys.argv[1])\n"
                        "child=os.fork()\n"
                        "if child == 0:\n"
                        " os.read(gate,1)\n"
                        " os.close(gate)\n"
                        " os._exit(0)\n"
                        "os.close(gate)\n"
                        "os._exit(7)\n"
                    ),
                    str(gate_read),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=(gate_read,),
            )
            os.close(gate_read)
            gate_read = -1
            self.assertEqual(process.wait(timeout=2), 7)
            with self.assertRaises(subprocess.TimeoutExpired):
                process.communicate(timeout=0.01)
            os.write(gate_write, b"1")
            os.close(gate_write)
            gate_write = -1
            process.communicate(timeout=2)
            drained = True
        finally:
            for descriptor in (gate_read, gate_write):
                if descriptor >= 0:
                    os.close(descriptor)
            if process is not None and not drained:
                try:
                    process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=2)
                    raise

        post_loss_source = inspect.getsource(VERIFY.run_fault).split(
            'stage.set("fault-recovery-supervisor-loss")', 1
        )[1]
        before_recovery = post_loss_source.split(
            'stage.set("fault-recovery-recovery")', 1
        )[0]
        self.assertIn("wrapper.process.wait(", before_recovery)
        self.assertIn('"fault wrapper exit"', before_recovery)
        self.assertNotIn("wrapper.process.communicate(", before_recovery)
        after_recovery_validation = post_loss_source.split(
            "_validate_recovery_pair", 1
        )[1]
        self.assertIn(
            "wait_exact_pidfd_exit(",
            after_recovery_validation,
        )
        self.assertIn(
            '"fault exact exit proof"',
            after_recovery_validation,
        )
        self.assertIn(
            "wrapper.process.communicate(",
            after_recovery_validation,
        )
        self.assertIn(
            '"fault output collection"',
            after_recovery_validation,
        )

    def test_cgroup_scope_requires_exact_inode_and_membership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            proc = base / "proc"
            cgroup = base / "cgroup"
            parent = cgroup / "owner"
            scope = parent / ("grok-ms-" + "a" * 24)
            (proc / "42").mkdir(parents=True)
            (proc / "sys/kernel/random").mkdir(parents=True)
            scope.mkdir(parents=True)
            boot = "11111111-2222-3333-4444-555555555555"
            (proc / "sys/kernel/random/boot_id").write_text(boot + "\n", encoding="ascii")
            fields = ["S", "1", *("0" for _ in range(17)), "123"]
            (proc / "42/stat").write_text(
                "42 (fixture) " + " ".join(fields) + "\n", encoding="ascii"
            )
            relative = scope.relative_to(cgroup)
            (proc / "42/cgroup").write_text(f"0::/{relative}\n", encoding="ascii")
            (scope / "cgroup.events").write_text("populated 1\nfrozen 0\n", encoding="ascii")
            parent_info = parent.lstat()
            scope_info = scope.lstat()
            identity = VERIFY.ProcessIdentity(42, 123, boot)
            record = {
                "backend": "cgroup-v2-v1",
                "parent_path": str(parent),
                "parent_device": parent_info.st_dev,
                "parent_inode": parent_info.st_ino,
                "scope_path": str(scope),
                "scope_device": scope_info.st_dev,
                "scope_inode": scope_info.st_ino,
            }
            evidence = VERIFY._scope_evidence(
                record, identity, proc_root=proc, cgroup_mount=cgroup
            )
            self.assertTrue(evidence["populated"])
            record["scope_inode"] += 1
            with self.assertRaisesRegex(VERIFY.VerificationError, "identity changed"):
                VERIFY._scope_evidence(
                    record, identity, proc_root=proc, cgroup_mount=cgroup
                )

    def test_resource_cgroup_authority_is_exact_fresh_runner_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            proc = base / "proc"
            cgroup = base / "cgroup"
            parent = cgroup / "owner"
            runner = parent / ("grok-installer-" + "a" * 24)
            (proc / "self").mkdir(parents=True)
            runner.mkdir(parents=True)
            relative = runner.relative_to(cgroup)
            (proc / "self/cgroup").write_text(
                f"0::/{relative}\n", encoding="ascii"
            )
            info = runner.lstat()
            authority = {
                "GROK_QUALIFICATION_RESOURCE_CGROUP_PATH": str(runner),
                "GROK_QUALIFICATION_RESOURCE_CGROUP_DEVICE": str(info.st_dev),
                "GROK_QUALIFICATION_RESOURCE_CGROUP_INODE": str(info.st_ino),
            }
            with mock.patch.dict(os.environ, authority, clear=False):
                self.assertEqual(
                    VERIFY.resource_cgroup_path(proc, cgroup), runner
                )
            parent_info = parent.lstat()
            parent_authority = {
                "GROK_QUALIFICATION_RESOURCE_CGROUP_PATH": str(parent),
                "GROK_QUALIFICATION_RESOURCE_CGROUP_DEVICE": str(parent_info.st_dev),
                "GROK_QUALIFICATION_RESOURCE_CGROUP_INODE": str(parent_info.st_ino),
            }
            with (
                mock.patch.dict(os.environ, parent_authority, clear=False),
                self.assertRaisesRegex(
                    VERIFY.VerificationBlocked, "changed identity"
                ),
            ):
                VERIFY.resource_cgroup_path(proc, cgroup)
            changed = dict(authority)
            changed["GROK_QUALIFICATION_RESOURCE_CGROUP_INODE"] = str(
                info.st_ino + 1
            )
            with mock.patch.dict(os.environ, changed, clear=False), self.assertRaisesRegex(
                VERIFY.VerificationBlocked, "changed identity"
            ):
                VERIFY.resource_cgroup_path(proc, cgroup)

    def test_host_limits_bind_exact_cgroup_identity_and_control_schema(self) -> None:
        limits = VERIFY.host_limits()
        self.assertTrue(VERIFY._host_limits_valid(limits))

        changed_identity = json.loads(json.dumps(limits))
        changed_identity["cgroup_limits"]["cgroup_inode"] += 1
        self.assertFalse(VERIFY._host_limits_valid(changed_identity))

        missing_control = json.loads(json.dumps(limits))
        missing_control["cgroup_limits"]["values"].pop("pids.max")
        self.assertFalse(VERIFY._host_limits_valid(missing_control))

    def test_reserved_cgroup_inventory_rejects_orphans_and_matches_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            proc = base / "proc"
            cgroup = base / "cgroup"
            parent = cgroup / "owner"
            (proc / "self").mkdir(parents=True)
            parent.mkdir(parents=True)
            (proc / "self/cgroup").write_text("0::/owner\n", encoding="ascii")

            def make_scope(container: Path, nonce: str, pid: int) -> Path:
                scope = container / f"grok-ms-{nonce}"
                scope.mkdir()
                (scope / "cgroup.events").write_text(
                    "populated 1\nfrozen 0\n", encoding="ascii"
                )
                (scope / "cgroup.procs").write_text(f"{pid}\n", encoding="ascii")
                return scope

            epoch_scope = make_scope(parent, "e" * 24, 7)
            scope = make_scope(epoch_scope, "a" * 24, 42)
            epoch_info = epoch_scope.lstat()
            info = scope.lstat()
            authority = {
                "children": [
                    {
                        "scope": {
                            "scope_path": str(scope),
                            "scope_device": info.st_dev,
                            "scope_inode": info.st_ino,
                        },
                        "process": {"identity": {"pid": 42}},
                    }
                ],
                "probes": [],
                "provider_scopes": [],
                "detached_scopes": [
                    {
                        "kind": "supervisor-epoch",
                        "phase": "OWNED",
                        "scope": {
                            "parent_path": str(parent),
                            "scope_path": str(epoch_scope),
                            "scope_device": epoch_info.st_dev,
                            "scope_inode": epoch_info.st_ino,
                        },
                        "process": {"identity": {"pid": 7}},
                    }
                ],
            }
            inventory = VERIFY.cgroup_scope_inventory(proc, cgroup)
            VERIFY.assert_cgroup_scopes_match(inventory, authority)
            with self.assertRaisesRegex(VERIFY.VerificationError, "remain"):
                VERIFY.assert_cgroup_scopes_clean(inventory)

            (scope / "cgroup.procs").write_text("42\n99\n", encoding="ascii")
            leaked = VERIFY.cgroup_scope_inventory(proc, cgroup)
            with self.assertRaisesRegex(VERIFY.VerificationError, "process set differs"):
                VERIFY.assert_cgroup_scopes_match(leaked, authority)
            VERIFY.assert_cgroup_scopes_match(
                leaked, authority, allowed_descendant_pids=(99,)
            )
            (scope / "cgroup.procs").write_text("42\n", encoding="ascii")

            make_scope(epoch_scope, "b" * 24, 43)
            orphaned = VERIFY.cgroup_scope_inventory(proc, cgroup)
            with self.assertRaisesRegex(VERIFY.VerificationError, "differs"):
                VERIFY.assert_cgroup_scopes_match(orphaned, authority)

            invalid = epoch_scope / "grok-ms-not-an-exact-scope"
            invalid.mkdir()
            with self.assertRaisesRegex(VERIFY.VerificationError, "invalid reserved"):
                VERIFY.cgroup_scope_inventory(proc, cgroup)

    def test_tcp_listener_parser_is_bounded_and_filters_listen_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "net").mkdir()
            header = "sl local_address rem_address st tx rx tr tm retr uid timeout inode\n"
            listen = "0: 0100007F:0438 00000000:0000 0A 0:0 0:0 0 0 0 12345\n"
            wildcard = "1: 00000000:0439 00000000:0000 0A 0:0 0:0 0 0 0 12346\n"
            connected = "2: 0100007F:043A 0100007F:1234 01 0:0 0:0 0 0 0 54321\n"
            (proc / "net/tcp").write_text(
                header + listen + wildcard + connected, encoding="ascii"
            )
            listen6 = (
                "0: 00000000000000000000000001000000:043A "
                "00000000000000000000000000000000:0000 "
                "0A 0:0 0:0 0 0 0 12347\n"
            )
            (proc / "net/tcp6").write_text(header + listen6, encoding="ascii")
            self.assertEqual(
                VERIFY._tcp_listener_rows(proc),
                (
                    {
                        "family": 4,
                        "host": "127.0.0.1",
                        "port": 1080,
                        "inode": 12345,
                    },
                    {
                        "family": 4,
                        "host": "0.0.0.0",
                        "port": 1081,
                        "inode": 12346,
                    },
                    {
                        "family": 6,
                        "host": "::1",
                        "port": 1082,
                        "inode": 12347,
                    },
                ),
            )
            owner = {
                "boot_id": "11111111-2222-3333-4444-555555555555",
                "pid": 42,
                "pid_start_ticks": 123,
            }
            wildcard_row = {
                **VERIFY._tcp_listener_rows(proc)[1],
                "owners": [owner],
            }
            self.assertFalse(
                VERIFY._listener_row_is_exact(
                    wildcard_row,
                    host="127.0.0.1",
                    port=1081,
                    owners=(owner,),
                )
            )

    def test_port_restart_probe_accepts_time_wait_but_rejects_a_listener(self) -> None:
        first_probe = mock.Mock()
        second_probe = mock.Mock()
        second_probe.listen.side_effect = OSError("injected listen collision")
        with mock.patch.object(
            VERIFY.socket,
            "socket",
            side_effect=(first_probe, second_probe),
        ):
            self.assertFalse(VERIFY.ports_are_bindable((1080, 11080)))
        for probe, port in ((first_probe, 1080), (second_probe, 11080)):
            probe.setsockopt.assert_called_once_with(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
            )
            probe.bind.assert_called_once_with(("127.0.0.1", port))
            probe.listen.assert_called_once_with(1)
            probe.close.assert_called_once_with()

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        port = int(listener.getsockname()[1])
        listener.listen(1)
        self.assertFalse(VERIFY.ports_are_bindable((port,)))

        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        server, _address = listener.accept()
        try:
            server.shutdown(socket.SHUT_WR)
            self.assertEqual(client.recv(1), b"")
        finally:
            client.close()
            server.close()
            listener.close()

        bare = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with self.assertRaises(OSError):
                bare.bind(("127.0.0.1", port))
        finally:
            bare.close()
        self.assertTrue(VERIFY.ports_are_bindable((port,)))

    def test_contract_gauges_require_exact_held_client_count(self) -> None:
        count = 2
        frontend = {
            "listener_alive": True,
            "accepting": True,
            "closing": False,
            "committed_generation": 1,
            "active_streams": count,
            "peak_active_streams": count,
            "buffered_bytes": 0,
            "peak_buffered_bytes": 1024,
            "stream_limit": 64,
            "backlog_limit": 16,
            "per_stream_buffer_limit": 4096,
            "total_buffer_limit": 8192,
            "accepted_streams": count,
            "backend_connected_streams": count,
            "client_to_backend_bytes": count * VERIFY.PAYLOAD_BYTES,
            "backend_to_client_bytes": count * VERIFY.PAYLOAD_BYTES,
            "completed_streams": 0,
            "revoked_streams": 0,
            "rejected_uncommitted": 0,
            "rejected_overload": 0,
            "backend_connect_failures": 0,
        }
        snapshot = {
            "generation": 1,
            "live_leases": count,
            "provisional_leases": 0,
            "live_interest": count,
            "phase": "READY",
            "active_rung": "direct",
            "transition": None,
            "cleanup_error": None,
            "resources": {
                "frontend": frontend,
                "leases": count,
                "max_leases": count,
                "control_connections": count + 1,
                "reserved_control_slots": count + 1,
                "max_control_connections": count + 2,
                "provider_processes": 1,
            },
        }
        self.assertEqual(VERIFY._validate_frontend(snapshot, count), frontend)
        frontend["active_streams"] = 1
        with self.assertRaisesRegex(VERIFY.VerificationError, "gauges disagree"):
            VERIFY._validate_frontend(snapshot, count)

    def test_recovery_pair_requires_a_second_exact_noop(self) -> None:
        first = {
            "recovered": True,
            "owner_epoch": "epoch",
            "provider_records": 1,
            "child_records": 1,
            "probe_records": 0,
        }
        second = {
            "recovered": False,
            "owner_epoch": None,
            "provider_records": 0,
            "child_records": 0,
            "probe_records": 0,
        }
        VERIFY._validate_recovery_pair(first, second, "epoch")
        second["child_records"] = 1
        with self.assertRaisesRegex(VERIFY.VerificationError, "idempotent"):
            VERIFY._validate_recovery_pair(first, second, "epoch")

    def test_broker_status_command_is_fixed_and_never_mutating(self) -> None:
        provenance = {"release_id": "a" * 64}
        snapshot = {
            "release_id": "a" * 64,
            "owner_epoch": "epoch-1",
            "generation": 3,
            "contract_digest": "b" * 64,
        }
        command = VERIFY.broker_status_command(provenance, {}, snapshot)
        self.assertEqual(command[:3], ["/usr/bin/sudo", "-n", "/usr/local/libexec/grok-proxy/vpn-broker"])
        self.assertEqual(command[command.index("--operation") + 1], "status")
        self.assertEqual(command[command.index("--caller-pid") + 1], str(os.getpid()))
        self.assertGreater(
            int(command[command.index("--deadline-monotonic-ns") + 1]),
            time.monotonic_ns(),
        )
        self.assertNotIn("down", command)
        self.assertNotIn("recover", command)
        clean = {
            "active": False,
            "namespace_alive": False,
            "tun_alive": False,
            "host_tun_alive": False,
            "vpn_alive": False,
            "relay_alive": False,
            "relay_pid": None,
            "root_artifact_residue": False,
            "ledger": None,
        }
        VERIFY.assert_root_inventory_clean(clean)
        clean["host_tun_alive"] = True
        with self.assertRaisesRegex(VERIFY.VerificationError, "host_tun_alive"):
            VERIFY.assert_root_inventory_clean(clean)

    def test_environment_drops_hostile_ambient_routing_selectors(self) -> None:
        hostile = {
            "GROK_BIN": "/tmp/evil-grok",
            "GROK_TESTING": "1",
            "GROK_TEST_VPN_BROKER": "/tmp/evil-broker",
            "GROK_VPN_MAX_TRIES": "8",
            "GROK_BLOCKED_CC": "DE",
            "VPNGATE_COUNTRIES": "ZZ",
            "TAILSCALE_SOCKET": "/tmp/evil-tailscale",
            "ALL_PROXY": "socks5h://evil.invalid:9",
            "HTTPS_PROXY": "http://evil.invalid:9",
            "BASH_ENV": "/tmp/evil-env",
            "GROK_QUALIFICATION_DIRECT_RECOVERY": "1",
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            selected = VERIFY.environment(2)
            real_selected = VERIFY._real_environment()
        self.assertEqual(selected["GROK_BIN"], str(VERIFY.FAKE_GROK))
        self.assertEqual(selected["GROK_BLOCKED_CC"], "")
        self.assertEqual(selected["GROK_VPN_STABILITY_CHECKS"], "1")
        self.assertEqual(selected["PATH"], "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        for name in (
            "GROK_TESTING",
            "GROK_TEST_VPN_BROKER",
            "GROK_VPN_MAX_TRIES",
            "VPNGATE_COUNTRIES",
            "TAILSCALE_SOCKET",
            "ALL_PROXY",
            "HTTPS_PROXY",
            "BASH_ENV",
            "GROK_QUALIFICATION_DIRECT_RECOVERY",
        ):
            self.assertNotIn(name, selected)
        self.assertNotIn("GROK_BLOCKED_CC", real_selected)

    def test_direct_recovery_marker_is_injected_only_for_authenticated_direct_recovery(
        self,
    ) -> None:
        marker = "GROK_QUALIFICATION_DIRECT_RECOVERY"
        with mock.patch.object(VERIFY, "_canary_environment", return_value={}):
            base = VERIFY.environment(2)
            real_base = VERIFY._real_environment()
        self.assertNotIn(marker, base)
        self.assertNotIn(marker, real_base)

        completed = subprocess.CompletedProcess(
            ["grok-remote", "status"],
            0,
            '{"active":false}\n',
            "",
        )
        with mock.patch.object(VERIFY, "invoke", return_value=completed) as invoke:
            self.assertEqual(
                VERIFY.status(Path("/installed/grok-remote"), base),
                {"active": False},
            )
        self.assertNotIn(marker, invoke.call_args.args[1])

        cases = (
            (
                "release-direct",
                {
                    "GROK_RELEASE_CANARY_KIND": "release",
                    "GROK_RELEASE_CANARY_RUNG": "direct",
                    "GROK_RELEASE_CANARY_ROUTE_PROFILE": "direct",
                },
                True,
            ),
            (
                "rung-direct-auto",
                {
                    "GROK_RELEASE_CANARY_KIND": "rung",
                    "GROK_RELEASE_CANARY_RUNG": "direct",
                    "GROK_RELEASE_CANARY_ROUTE_PROFILE": "auto",
                    "GROK_RELEASE_CANARY_CONTRACT": "c" * 64,
                    "GROK_RELEASE_CANARY_PROFILE_SHA256": "d" * 64,
                },
                True,
            ),
            (
                "rung-forced-direct",
                {
                    "GROK_RELEASE_CANARY_KIND": "rung",
                    "GROK_RELEASE_CANARY_RUNG": "direct",
                    "GROK_RELEASE_CANARY_ROUTE_PROFILE": "direct",
                    "GROK_RELEASE_CANARY_CONTRACT": "c" * 64,
                },
                True,
            ),
            (
                "release-vpn",
                {
                    "GROK_RELEASE_CANARY_KIND": "release",
                    "GROK_RELEASE_CANARY_RUNG": "vpn",
                    "GROK_RELEASE_CANARY_ROUTE_PROFILE": "vpn",
                },
                False,
            ),
            (
                "rung-direct-missing-contract",
                {
                    "GROK_RELEASE_CANARY_KIND": "rung",
                    "GROK_RELEASE_CANARY_RUNG": "direct",
                    "GROK_RELEASE_CANARY_ROUTE_PROFILE": "auto",
                },
                False,
            ),
            (
                "rung-direct-forbidden-profile",
                {
                    "GROK_RELEASE_CANARY_KIND": "rung",
                    "GROK_RELEASE_CANARY_RUNG": "direct",
                    "GROK_RELEASE_CANARY_ROUTE_PROFILE": "auto-no-direct",
                    "GROK_RELEASE_CANARY_CONTRACT": "c" * 64,
                },
                False,
            ),
        )
        for label, bindings, expected in cases:
            hostile = dict(bindings)
            hostile[marker] = "ambient-spoof"
            recovered = VERIFY.recovery_environment(hostile, None)
            with self.subTest(label=label):
                if expected:
                    self.assertEqual(recovered.get(marker), "1")
                else:
                    self.assertNotIn(marker, recovered)
                self.assertEqual(recovered["GROK_RECOVERY_EXPECT_ABSENT"], "1")

    def test_fixed_release_call_sites_use_the_fake_environment(self) -> None:
        marker = RuntimeError("fixed fake release environment selected")
        context = VERIFY.QualificationContext(
            "a" * 64,
            "b" * 64,
            "release",
            "direct",
            "direct",
            None,
            "fixture-grok-release",
            "grok-4.5",
            3,
        )
        calls = (
            (32, lambda: VERIFY.run_load(Path("/unused"), 32, {}, "c" * 64)),
            (
                32,
                lambda: VERIFY.run_fault(
                    Path("/unused"), Path("/unused-marker"), {}, "c" * 64
                ),
            ),
            (32, lambda: VERIFY._release_contract(context)),
        )
        for count, call in calls:
            with self.subTest(call=call), mock.patch.object(
                VERIFY, "environment", side_effect=marker
            ) as selected:
                with self.assertRaisesRegex(
                    RuntimeError, "fixed fake release environment selected"
                ):
                    call()
                selected.assert_called_once_with(count)

    def test_release_and_real_contracts_keep_country_policy_separate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            iphone = root / "iphone"
            release.mkdir()
            iphone.mkdir()
            (release / "hosts.conf").write_text("", encoding="utf-8")
            manifest = release / "release.json"
            manifest.write_text(
                json.dumps({"release_id": "a" * 64}, sort_keys=True) + "\n",
                encoding="ascii",
            )
            os.chmod(manifest, 0o444)

            with mock.patch.object(VERIFY, "_canary_environment", return_value={}):
                release_env = VERIFY.environment(32)
            release_env.update(
                {
                    "GROK_TESTING": "1",
                    "GROK_TEST_IPHONE_STATE_DIR": str(iphone),
                }
            )
            classification = VERIFY.classify(("--direct", "-m", "grok-4.5"))

            def build(selected: dict[str, str]):
                return VERIFY.build_contract(
                    classification,
                    "grok-4.5",
                    release_dir=release,
                    grok_bin=VERIFY.FAKE_GROK,
                    env=selected,
                    grok_release_id="fixture-grok-release",
                )

            first = build(release_env)
            second = build(release_env)
            self.assertEqual(first.vpn_policy.blocked_countries, ())
            self.assertEqual(first.digest(), second.digest())

            default_policy_env = dict(release_env)
            del default_policy_env["GROK_BLOCKED_CC"]
            default_policy = build(default_policy_env)
            self.assertNotIn("DE", default_policy.vpn_policy.blocked_countries)
            self.assertEqual(
                default_policy.vpn_policy.blocked_countries,
                ("CN", "IR", "KP", "TM", "VE"),
            )
            self.assertNotEqual(first.digest(), default_policy.digest())

            with mock.patch.object(VERIFY, "_canary_environment", return_value={}):
                real_env = VERIFY._real_environment()
            real_env.update(
                {
                    "GROK_TESTING": "1",
                    "GROK_TEST_IPHONE_STATE_DIR": str(iphone),
                }
            )
            real = build(real_env)
            self.assertNotIn("DE", real.vpn_policy.blocked_countries)
            self.assertEqual(
                real.vpn_policy.blocked_countries,
                ("CN", "IR", "KP", "TM", "VE"),
            )

            command = VERIFY.broker_status_command(
                {"release_id": "a" * 64},
                release_env,
                None,
                broker=Path("/bin/true"),
                sudo=Path("/bin/true"),
            )
            blocked = command.index("--vpn-blocked-countries")
            self.assertEqual(command[blocked + 1], "")

    def test_shipped_fake_and_verifier_are_release_bound(self) -> None:
        self.assertEqual(VERIFY.FAKE_GROK, ROOT / "grok_ms/qualification_fake_grok.py")
        self.assertEqual(Path(VERIFY.__file__).resolve().parent, ROOT / "grok_ms")
        self.assertTrue(VERIFY.FAKE_GROK.is_file())
        self.assertTrue(os.access(VERIFY.FAKE_GROK, os.X_OK))

    def test_main_qualifies_through_installed_gate_not_release_payload(self) -> None:
        release_id = "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            user_root = home / ".local/lib/grok-proxy"
            release_root = user_root / "releases" / release_id
            control = home / ".local/state/grok-proxy/release-control"
            gate = home / ".local/bin/grok-remote"
            release_root.mkdir(parents=True)
            control.mkdir(parents=True)
            gate.parent.mkdir(parents=True)

            manifest = release_root / "release.json"
            manifest.write_bytes(b'{"fixture":"manifest"}\n')
            os.chmod(manifest, 0o444)
            gate.write_bytes(b"#!/bin/sh\nexit 0\n")
            os.chmod(gate, 0o555)
            self.assertNotEqual(
                VERIFY._sha256_file(gate),
                VERIFY._sha256_file(ROOT / "grok-remote"),
            )
            current = user_root / "current"
            current.symlink_to(f"releases/{release_id}")
            selected = {
                "schema_version": 2,
                "release_schema_version": 1,
                "handshake_protocol": "fixture",
                "release_id": release_id,
                "user_release_id": release_id,
                "root_release_id": release_id,
                "selection_phase": "READY",
                "evidence_sha256": "b" * 64,
                "target_uid": os.getuid(),
                "target_gid": os.getgid(),
                "user_root": str(user_root),
                "user_manifest_sha256": VERIFY._sha256_file(manifest),
                "root_manifest_sha256": "c" * 64,
                "entrypoint_sha256": VERIFY._sha256_file(gate),
                "broker_gate_sha256": "d" * 64,
                "operation": "install",
            }
            selection_path = control / "selected-release.json"
            selection_path.write_text(json.dumps(selected), encoding="ascii")
            os.chmod(selection_path, 0o444)

            original_lstat = Path.lstat
            root_owned = {current, manifest, gate}

            def installed_lstat(path: Path) -> os.stat_result:
                info = original_lstat(path)
                if path not in root_owned:
                    return info
                fields = list(info)
                fields[4] = 0
                fields[5] = 0
                return os.stat_result(fields)

            context = VERIFY.QualificationContext(
                release_id,
                "e" * 64,
                "release",
                "direct",
                "direct",
                None,
                "grok-fixture",
                "grok-4.5",
                3,
            )
            sampler = mock.Mock()
            sampler.stop.return_value = {"samples": []}
            workload = mock.Mock(
                return_value={
                    "resources": {
                        "baseline": {"cgroup": "fixture"},
                        "gate": {},
                    }
                }
            )
            parser = mock.Mock()
            parser.parse_args.return_value = SimpleNamespace(mode="load32")
            with (
                mock.patch.object(Path, "lstat", autospec=True, side_effect=installed_lstat),
                mock.patch.object(VERIFY.Path, "cwd", return_value=VERIFY.ROOT),
                mock.patch.object(
                    VERIFY.pwd,
                    "getpwuid",
                    return_value=SimpleNamespace(pw_dir=str(home)),
                ),
                mock.patch.object(VERIFY, "parser", return_value=parser),
                mock.patch.object(
                    VERIFY.QualificationContext,
                    "from_environment",
                    return_value=context,
                ),
                mock.patch.object(
                    VERIFY,
                    "_qualification_deadlines_ns",
                    return_value=(
                        time.monotonic_ns() + 5_000_000_000,
                        time.monotonic_ns() + 125_000_000_000,
                    ),
                ),
                mock.patch.object(VERIFY.os, "umask"),
                mock.patch.object(VERIFY, "_release_contract", return_value="f" * 64),
                mock.patch.object(VERIFY, "ResourceSampler", return_value=sampler),
                mock.patch.object(VERIFY, "run_load", workload),
                mock.patch.object(
                    VERIFY,
                    "_compact_load",
                    return_value=VERIFY._default_observations("load32"),
                ),
                mock.patch.object(VERIFY, "assert_resource_sampler"),
                mock.patch.object(
                    VERIFY.os, "write", return_value=1
                ) as write_output,
            ):
                self.assertEqual(VERIFY.main(), 0)
            self.assertEqual(workload.call_args.args[0], gate)
            qualification_record = json.loads(
                write_output.call_args.args[1]
            )
            self.assertEqual(qualification_record["schema_version"], 5)
            self.assertIsNone(qualification_record["profile_sha256"])

            os.chmod(selection_path, 0o644)
            selected["entrypoint_sha256"] = VERIFY._sha256_file(
                ROOT / "grok-remote"
            )
            selection_path.write_text(json.dumps(selected), encoding="ascii")
            os.chmod(selection_path, 0o444)
            with (
                mock.patch.object(
                    Path,
                    "lstat",
                    autospec=True,
                    side_effect=installed_lstat,
                ),
                mock.patch.object(
                    VERIFY.pwd,
                    "getpwuid",
                    return_value=SimpleNamespace(pw_dir=str(home)),
                ),
                self.assertRaisesRegex(
                    VERIFY.VerificationBlocked,
                    "provenance digests disagree",
                ),
            ):
                VERIFY.release_provenance(gate)

    def test_qualification_context_accepts_namespaced_model_only(self) -> None:
        with tempfile.TemporaryFile() as capability:
            selected = {
                "GROK_RELEASE_CANARY_MODE": "1",
                "GROK_RELEASE_CANARY_FD": str(capability.fileno()),
                "GROK_RELEASE_CANARY_RELEASE_ID": "a" * 64,
                "GROK_RELEASE_RUNG_CANARY": "1",
                "GROK_RELEASE_CANARY_RUNG": "home:lab-phone",
                "GROK_RELEASE_CANARY_ROUTE_PROFILE": "home:lab-phone",
                "GROK_RELEASE_CANARY_CONTRACT": "b" * 64,
                "GROK_RELEASE_CANARY_GROK_RELEASE": "grok-cli@1.2.3",
                "GROK_RELEASE_CANARY_NONCE": "c" * 64,
                "GROK_RELEASE_CANARY_KIND": "rung",
                "GROK_RELEASE_CANARY_MODEL": "xai/grok-4.5",
                "GROK_RELEASE_CANARY_PROFILE_SHA256": "d" * 64,
            }
            with mock.patch.dict(os.environ, selected, clear=True):
                context = VERIFY.QualificationContext.from_environment()
            self.assertEqual(context.model_id, "xai/grok-4.5")
            self.assertEqual(context.rung, "home:lab-phone")
            self.assertEqual(context.route_profile, "home:lab-phone")
            self.assertEqual(context.profile_sha256, "d" * 64)

            invalid = dict(selected)
            invalid["GROK_RELEASE_CANARY_GROK_RELEASE"] = "vendor/grok-cli"
            with mock.patch.dict(os.environ, invalid, clear=True):
                with self.assertRaisesRegex(
                    VERIFY.VerificationBlocked, "authorization values"
                ):
                    VERIFY.QualificationContext.from_environment()

            invalid_profile = dict(selected)
            invalid_profile["GROK_RELEASE_CANARY_PROFILE_SHA256"] = "not-a-digest"
            with mock.patch.dict(os.environ, invalid_profile, clear=True):
                with self.assertRaisesRegex(
                    VERIFY.VerificationBlocked, "authorization values"
                ):
                    VERIFY.QualificationContext.from_environment()

    def test_route_profiles_reconstruct_original_invocations_exactly(self) -> None:
        self.assertEqual(VERIFY._real_route_arguments("direct"), ["--direct"])
        self.assertEqual(VERIFY._real_route_arguments("iphone"), ["--iphone"])
        self.assertEqual(VERIFY._real_route_arguments("vpn"), ["--vpn"])
        self.assertEqual(
            VERIFY._real_route_arguments("home:lab-phone"),
            ["--host", "lab-phone"],
        )
        self.assertEqual(VERIFY._real_route_arguments("auto"), [])
        self.assertEqual(
            VERIFY._real_route_arguments("auto-no-direct"), ["--no-direct"]
        )
        with self.assertRaisesRegex(VERIFY.VerificationBlocked, "route profile"):
            VERIFY._real_route_arguments("home:lab/phone")
        self.assertTrue(
            VERIFY._models_output_contains(
                b"  - xai/grok-4.5\n", "xai/grok-4.5"
            )
        )
        self.assertFalse(
            VERIFY._models_output_contains(
                b"available: xai/grok-4.5-fast\n", "xai/grok-4.5"
            )
        )
        self.assertFalse(
            VERIFY._models_output_contains(
                b"diagnostic mentions xai/grok-4.5 but lists nothing\n",
                "xai/grok-4.5",
            )
        )

    def test_real_iphone_contract_narrows_runtime_to_qualified_device(self) -> None:
        first = IosEndpoint("iphone-xr", "node-phone-1")
        second = IosEndpoint("ipad-pro", "node-tablet-2")
        original = self._route_contract("ios:iphone-xr")
        original = RouteContract.from_dict(
            {
                **original.to_dict(),
                "forced_ios_key": None,
                "ios_endpoints": [first.to_dict(), second.to_dict()],
                "ladder": ["ios:iphone-xr", "ios:ipad-pro"],
            }
        )
        context = VERIFY.QualificationContext(
            release_id=original.release_id,
            nonce="a" * 64,
            canary_kind="rung",
            rung="ios:ipad-pro",
            route_profile="iphone",
            contract_sha256=original.digest(),
            grok_release_id=original.grok_release_id,
            model_id=original.model_id,
            auth_fd=-1,
        )
        with mock.patch.object(VERIFY, "build_contract", return_value=original):
            reproduced, runtime = VERIFY._real_contracts(context, {})
        self.assertEqual(reproduced, original)
        self.assertEqual(runtime.ladder, ("ios:ipad-pro",))
        self.assertEqual(runtime.ios_endpoints, (first, second))
        self.assertEqual(reconstruct_original_contract(runtime), original)

    def test_profile_bound_real_contract_uses_frozen_nondefault_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile_root = home / ".local/state/grok-proxy/profiles"
            profile_root.mkdir(parents=True, mode=0o700)
            profile_root.chmod(0o700)
            grok = home / "grok-profile-v1"
            grok.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            grok.chmod(0o700)
            grok_identity = VERIFY.grok_release_id(grok)
            contract = replace(
                self._route_contract("direct"),
                release_id="a" * 64,
                grok_release_id=grok_identity,
                public_endpoint=Endpoint("127.0.0.1", 19080),
                private_ports=(19081, 19082),
                timeout_policy=TimeoutPolicy(12_345, 23_456, 234_567, 34_567),
                limits=ResourceLimits(
                    7, 13, 29, 32_768, 131_072, 9_437_184
                ),
            )
            profile = ManagedProfile.create(
                contract,
                grok,
                ReadinessPolicy(1, ()),
            )
            write_content_addressed_profile(
                profile_root,
                profile,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            context = VERIFY.QualificationContext(
                release_id=contract.release_id,
                nonce="b" * 64,
                canary_kind="rung",
                rung="direct",
                route_profile="direct",
                contract_sha256=contract.digest(),
                grok_release_id=contract.grok_release_id,
                model_id=contract.model_id,
                auth_fd=-1,
                profile_sha256=profile.digest(),
            )
            account = SimpleNamespace(
                pw_dir=str(home),
                pw_name="qualification-user",
            )
            hostile_ambient = {
                "GROK_PROXY_PORT": "1080",
                "GROK_PRIVATE_PORTS": "11080 11081",
                "GROK_MAX_LEASES": "1",
                "GROK_CONNECT_TIMEOUT_MS": "1",
                "VPNGATE_COUNTRIES": "ZZ",
            }
            with (
                mock.patch.object(VERIFY.pwd, "getpwuid", return_value=account),
                mock.patch.object(
                    VERIFY,
                    "build_contract",
                    side_effect=AssertionError(
                        "profile qualification consulted ambient configuration"
                    ),
                ),
            ):
                reproduced, runtime = VERIFY._real_contracts(
                    context, hostile_ambient
                )
            self.assertEqual(reproduced, contract)
            self.assertEqual(runtime.ladder, ("direct",))
            self.assertEqual(runtime.public_endpoint.port, 19080)
            self.assertEqual(runtime.limits.max_leases, 7)
            self.assertEqual(runtime.timeout_policy.connect_ms, 12_345)

            mismatched = replace(context, contract_sha256="c" * 64)
            with (
                mock.patch.object(VERIFY.pwd, "getpwuid", return_value=account),
                self.assertRaisesRegex(
                    VERIFY.VerificationBlocked,
                    "profile-bound qualification identity is mismatched",
                ),
            ):
                VERIFY._real_contracts(mismatched, hostile_ambient)

            grok.write_text("#!/bin/sh\nexit 9\n", encoding="ascii")
            grok.chmod(0o700)
            with (
                mock.patch.object(VERIFY.pwd, "getpwuid", return_value=account),
                self.assertRaisesRegex(
                    VERIFY.VerificationBlocked,
                    "profile-bound qualification profile is invalid",
                ),
            ):
                VERIFY._real_contracts(context, hostile_ambient)

    def test_fixed_observation_schemas_are_exact(self) -> None:
        self.assertEqual(VERIFY.EVIDENCE_SCHEMA_VERSION, 5)
        self.assertEqual(
            set(VERIFY._default_observations("load32")),
            {
                "clients_requested", "clients_completed", "active_rung",
                "shared_owner_epoch", "shared_generation", "shared_contract",
                "unique_leaders", "overload_rejected", "byte_path_verified",
                "host_limits_captured", "resource_gate_passed", "cleanup_proved",
                "host_limits_sha256", "resource_contract", "resource_observed",
                "ready_duration_ms", "detail_sha256",
            },
        )
        self.assertEqual(
            set(VERIFY._default_observations("fault-recovery")),
            {
                "active_rung", "supervisor_loss_exact", "wrapper_failed_closed",
                "descendant_contained", "first_recovery_applied",
                "second_recovery_noop", "recovery_duration_ms",
                "resource_gate_passed", "cleanup_proved", "detail_sha256",
                "host_limits_sha256", "resource_contract", "resource_observed",
            },
        )
        self.assertEqual(
            set(VERIFY._default_observations("real-pair")),
            {
                "sessions_requested", "sessions_completed", "active_rung",
                "rung_qualification_sha256",
                "model_id", "shared_owner_epoch", "shared_generation",
                "shared_contract", "independent_grok_units",
                "shared_leader_disabled", "leader_socket_count",
                "unique_session_ids",
                "outputs_valid", "exit_codes_zero", "cache_before_valid",
                "cache_during_valid", "cache_after_valid", "cache_identity_safe",
                "provider_fault_authenticated", "single_repair_observed",
                "clients_survived_repair", "reconnect_duration_ms",
                "transport_duration_ms", "cleanup_proved", "detail_sha256",
                "blocked_reason",
            },
        )

    def test_cache_sampling_and_output_collection_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "models.json"
            cache.write_text('{"models":[]}', encoding="ascii")
            os.chmod(cache, 0o600)
            snapshot = VERIFY._cache_snapshot(cache)
            self.assertEqual(snapshot["state"], "regular")
            self.assertEqual(snapshot["mtime_ns"], cache.stat().st_mtime_ns)
            before = cache.stat()
            changed = SimpleNamespace(
                st_dev=before.st_dev,
                st_ino=before.st_ino,
                st_mode=before.st_mode,
                st_uid=before.st_uid,
                st_size=before.st_size,
                st_mtime_ns=before.st_mtime_ns + 1,
            )
            with (
                mock.patch.object(VERIFY.os, "fstat", side_effect=(before, changed)),
                self.assertRaisesRegex(
                    VERIFY.VerificationError, "changed during one snapshot"
                ),
            ):
                VERIFY._cache_snapshot(cache)
            os.chmod(cache, 0o664)
            with self.assertRaisesRegex(VERIFY.VerificationError, "unsafe identity"):
                VERIFY._cache_snapshot(cache)
            os.chmod(cache, 0o600)
            cache.write_text('{"models":', encoding="ascii")
            with self.assertRaisesRegex(VERIFY.VerificationError, "complete JSON"):
                VERIFY._cache_snapshot(cache)

        absent = {"state": "absent"}
        regular = {
            "state": "regular",
            "device": 1,
            "inode": 2,
            "size": 3,
            "mtime_ns": 4,
            "sha256": "a" * 64,
        }
        changed = {**regular, "mtime_ns": 5, "sha256": "b" * 64}
        self.assertFalse(
            VERIFY._cache_refresh_valid(absent, (absent, absent), absent)
        )
        self.assertTrue(
            VERIFY._cache_refresh_valid(absent, (absent, regular), regular)
        )
        self.assertFalse(
            VERIFY._cache_refresh_valid(regular, (regular, regular), regular)
        )
        self.assertTrue(
            VERIFY._cache_refresh_valid(regular, (regular, changed), changed)
        )
        self.assertTrue(
            VERIFY._cache_window_valid(
                absent,
                (absent, regular),
                regular,
                allow_initial_absent=True,
            )
        )
        self.assertFalse(
            VERIFY._cache_window_valid(
                regular,
                (regular, absent, regular),
                regular,
                allow_initial_absent=False,
            )
        )
        self.assertFalse(
            VERIFY._cache_window_valid(
                absent,
                (regular, absent, regular),
                regular,
                allow_initial_absent=True,
            )
        )
        self.assertTrue(
            VERIFY._cache_window_valid(
                regular,
                (regular, changed),
                changed,
                allow_initial_absent=False,
            )
        )

        class StopAfter:
            def __init__(self, count: int) -> None:
                self.count = count

            def is_set(self) -> bool:
                return False

            def wait(self, _timeout: float) -> bool:
                self.count -= 1
                return self.count == 0

        late_samples = [regular] * 4_096 + [absent, regular]
        with mock.patch.object(
            VERIFY,
            "_cache_snapshot",
            side_effect=[regular, *late_samples],
        ):
            sampler = VERIFY.CacheSampler(Path("unused"))
            sampler._stop = StopAfter(len(late_samples))
            sampler._run()
        self.assertIsInstance(sampler.error, VERIFY.VerificationError)

    def test_wait_status_clips_nested_work_and_sleep_to_one_deadline(self) -> None:
        now = [10.0]
        nested_timeouts: list[float] = []
        sleeps: list[float] = []

        def fake_status(
            _entrypoint: Path,
            _env: object,
            *,
            timeout: float,
        ) -> None:
            nested_timeouts.append(timeout)
            now[0] += timeout
            return None

        def fake_sleep(duration: float) -> None:
            sleeps.append(duration)
            now[0] += duration

        with (
            mock.patch.object(VERIFY.time, "monotonic", side_effect=lambda: now[0]),
            mock.patch.object(VERIFY, "status", side_effect=fake_status),
            mock.patch.object(VERIFY.time, "sleep", side_effect=fake_sleep),
            self.assertRaisesRegex(VERIFY.VerificationError, "timed out"),
        ):
            VERIFY.wait_status(Path("unused"), {}, lambda _value: False, 0.01)
        self.assertEqual(len(nested_timeouts), 1)
        self.assertLessEqual(nested_timeouts[0], 0.01)
        self.assertLessEqual(sum(sleeps), max(0.0, 0.01 - nested_timeouts[0]))
        self.assertLessEqual(now[0], 10.01)

    def test_wait_status_retries_after_one_timed_out_probe(self) -> None:
        completed = subprocess.CompletedProcess(
            ["grok-remote", "status"],
            0,
            '{"active":true}\n',
            "",
        )
        with mock.patch.object(
            VERIFY,
            "invoke",
            side_effect=(
                subprocess.TimeoutExpired(["grok-remote", "status"], 5),
                completed,
            ),
        ) as invoke, mock.patch.object(VERIFY.time, "sleep"):
            result = VERIFY.wait_status(
                Path("/installed/grok-remote"),
                {},
                lambda value: value.get("active") is True,
                10,
            )
        self.assertEqual(result, {"active": True})
        self.assertEqual(invoke.call_count, 2)

    def test_bounded_text_timeout_kills_and_reaps_direct_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "pid"
            script = (
                "import os,pathlib,time; "
                "pathlib.Path(os.environ['PID_PATH']).write_text(str(os.getpid())); "
                "time.sleep(30)"
            )
            env = dict(os.environ)
            env["PID_PATH"] = str(pid_path)
            with self.assertRaises(subprocess.TimeoutExpired):
                VERIFY._bounded_text_command(
                    [sys.executable, "-c", script],
                    env=env,
                    timeout=0.2,
                )
            pid = int(pid_path.read_text(encoding="ascii"))
            try:
                waited = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                waited = None
            if waited is not None:
                if waited == (0, 0):
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                self.fail("bounded helper returned without reaping its child")

        now = time.monotonic_ns()
        work_deadline = now + 5_000_000_000
        cleanup_deadline = (
            work_deadline
            + VERIFY.QUALIFICATION_CLEANUP_RESERVE_SECONDS
            * 1_000_000_000
        )
        self.assertEqual(
            VERIFY._qualification_deadlines_ns(
                {
                    "GROK_QUALIFICATION_DEADLINE_MONOTONIC_NS": str(
                        work_deadline
                    ),
                    "GROK_QUALIFICATION_CLEANUP_DEADLINE_MONOTONIC_NS": str(
                        cleanup_deadline
                    ),
                }
            ),
            (work_deadline, cleanup_deadline),
        )
        with self.assertRaisesRegex(VERIFY.VerificationBlocked, "deadline"):
            VERIFY._qualification_deadline_ns({})
        with self.assertRaisesRegex(VERIFY.VerificationBlocked, "deadline"):
            VERIFY._qualification_deadline_ns(
                {
                    "GROK_QUALIFICATION_DEADLINE_MONOTONIC_NS": str(
                        time.monotonic_ns() + 901_000_000_000
                    )
                }
            )
        with self.assertRaisesRegex(VERIFY.VerificationBlocked, "deadline"):
            VERIFY._qualification_deadlines_ns(
                {
                    "GROK_QUALIFICATION_DEADLINE_MONOTONIC_NS": str(
                        time.monotonic_ns() + 5_000_000_000
                    ),
                    "GROK_QUALIFICATION_CLEANUP_DEADLINE_MONOTONIC_NS": str(
                        time.monotonic_ns() + 124_000_000_000
                    ),
                }
            )

        process = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 65)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "fixed bound"):
            VERIFY._bounded_collect(process, timeout=5, maximum=64)
        self.assertIsNotNone(process.poll())

        sleeper = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        started = time.monotonic()
        with self.assertRaisesRegex(VERIFY.VerificationError, "deadline"):
            VERIFY._bounded_collect(
                sleeper,
                timeout=10,
                deadline_monotonic_ns=time.monotonic_ns() + 50_000_000,
                termination_deadline_monotonic_ns=(
                    time.monotonic_ns() + 500_000_000
                ),
            )
        self.assertLess(time.monotonic() - started, 1)
        self.assertIsNotNone(sleeper.poll())

        with self.assertRaisesRegex(
            VERIFY.VerificationError, "output exceeded"
        ):
            VERIFY._bounded_text_command(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('x' * 65)",
                ],
                env={"PATH": os.environ.get("PATH", "")},
                timeout=5,
                maximum=64,
            )

    def test_runtime_inventory_has_shared_entry_and_deadline_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            for name in ("a", "b", "c"):
                (root / name).write_text(name, encoding="ascii")
            with mock.patch.object(
                VERIFY, "MAX_RUNTIME_INVENTORY_ENTRIES", 2
            ):
                with self.assertRaisesRegex(
                    VERIFY.VerificationError, "entry bound"
                ):
                    VERIFY._inventory_tree(root)
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "deadline"
            ):
                VERIFY._inventory_tree(
                    root,
                    deadline_monotonic_ns=time.monotonic_ns() - 1,
                )
            nested = root / "nested"
            nested.mkdir()
            os.chmod(nested, 0o700)
            current = nested
            for _index in range(80):
                current = current / "d"
                current.mkdir()
            recursion_limit = sys.getrecursionlimit()
            try:
                sys.setrecursionlimit(50)
                inventory = VERIFY._inventory_tree(nested)
            finally:
                sys.setrecursionlimit(recursion_limit)
            self.assertEqual(len(inventory["entries"]), 80)

    def test_fixture_markers_are_exclusive_bounded_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            marker = root / "marker.json"
            FIXTURE._publish_exclusive_json(marker, {"pid": 1})
            self.assertEqual(json.loads(marker.read_text(encoding="ascii")), {"pid": 1})
            with self.assertRaises(FileExistsError):
                FIXTURE._publish_exclusive_json(marker, {"pid": 2})
            FIXTURE._wait_for_release(marker, 0.1)

    def test_fixture_marker_name_is_absent_until_json_is_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            marker = root / "marker.json"
            write_started = threading.Event()
            allow_write = threading.Event()
            failures: list[BaseException] = []
            real_write = os.write

            def held_write(descriptor: int, data: bytes | memoryview) -> int:
                write_started.set()
                if not allow_write.wait(3):
                    raise RuntimeError("fixture marker write was not released")
                return real_write(descriptor, data)

            def publish() -> None:
                try:
                    FIXTURE._publish_exclusive_json(marker, {"pid": 1})
                except BaseException as exc:
                    failures.append(exc)

            with mock.patch.object(FIXTURE.os, "write", side_effect=held_write):
                writer = threading.Thread(target=publish)
                writer.start()
                self.assertTrue(write_started.wait(2))
                try:
                    self.assertFalse(marker.exists())
                finally:
                    allow_write.set()
                    writer.join(timeout=3)
            self.assertFalse(writer.is_alive())
            if failures:
                raise failures[0]
            self.assertEqual(
                json.loads(marker.read_text(encoding="ascii")),
                {"pid": 1},
            )

    def test_fixture_marker_token_failure_closes_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            marker = root / "marker.json"
            with mock.patch.object(
                FIXTURE.secrets,
                "token_hex",
                side_effect=RuntimeError("token-fault"),
            ):
                with self.assertRaisesRegex(RuntimeError, "token-fault"):
                    FIXTURE._publish_exclusive_json(marker, {"pid": 1})
            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(self._open_fds_under(root), ())

    def test_fixture_marker_prelink_failures_leave_no_residue(self) -> None:
        for failure in ("write", "file-fsync", "link"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                os.chmod(root, 0o700)
                marker = root / "marker.json"
                real_fsync = os.fsync

                def fail_regular_file_fsync(descriptor: int) -> None:
                    if stat.S_ISREG(os.fstat(descriptor).st_mode):
                        raise OSError("file-fsync-fault")
                    real_fsync(descriptor)

                if failure == "write":
                    patcher = mock.patch.object(
                        FIXTURE.os,
                        "write",
                        side_effect=OSError("write-fault"),
                    )
                elif failure == "file-fsync":
                    patcher = mock.patch.object(
                        FIXTURE.os,
                        "fsync",
                        side_effect=fail_regular_file_fsync,
                    )
                else:
                    patcher = mock.patch.object(
                        FIXTURE.os,
                        "link",
                        side_effect=OSError("link-fault"),
                    )
                with patcher, self.assertRaisesRegex(OSError, f"{failure}-fault"):
                    FIXTURE._publish_exclusive_json(marker, {"pid": 1})
                self.assertFalse(marker.exists())
                self.assertEqual(list(root.iterdir()), [])
                self.assertEqual(self._open_fds_under(root), ())

    def test_fixture_marker_never_retries_an_ambiguous_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            marker = root / "marker.json"
            real_close = os.close
            sentinel = -1
            injected = False

            def close_then_reuse(descriptor: int) -> None:
                nonlocal injected, sentinel
                if not injected and stat.S_ISREG(os.fstat(descriptor).st_mode):
                    injected = True
                    real_close(descriptor)
                    sentinel = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                    self.assertEqual(sentinel, descriptor)
                    raise OSError("ambiguous-close-fault")
                real_close(descriptor)

            try:
                with (
                    mock.patch.object(
                        FIXTURE.os,
                        "close",
                        side_effect=close_then_reuse,
                    ),
                    self.assertRaisesRegex(OSError, "ambiguous-close-fault"),
                ):
                    FIXTURE._publish_exclusive_json(marker, {"pid": 1})
                self.assertGreaterEqual(sentinel, 0)
                os.fstat(sentinel)
                self.assertFalse(marker.exists())
                self.assertEqual(list(root.iterdir()), [])
                self.assertEqual(self._open_fds_under(root), ())
            finally:
                if sentinel >= 0:
                    real_close(sentinel)

    def test_fixture_marker_collision_preserves_existing_final(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            marker = root / "marker.json"
            FIXTURE._publish_exclusive_json(marker, {"pid": 1})
            before = marker.stat()
            before_bytes = marker.read_bytes()
            with self.assertRaises(FileExistsError):
                FIXTURE._publish_exclusive_json(marker, {"pid": 2})
            after = marker.stat()
            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
            self.assertEqual(marker.read_bytes(), before_bytes)
            self.assertEqual([path.name for path in root.iterdir()], [marker.name])
            self.assertEqual(self._open_fds_under(root), ())

    def test_fixture_marker_postlink_failures_keep_complete_final(self) -> None:
        for failure in ("unlink", "directory-fsync"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                os.chmod(root, 0o700)
                marker = root / "marker.json"
                real_unlink = os.unlink
                real_fsync = os.fsync
                unlink_calls = 0

                def fail_first_unlink(
                    name: str,
                    *,
                    dir_fd: int | None = None,
                ) -> None:
                    nonlocal unlink_calls
                    unlink_calls += 1
                    if unlink_calls == 1:
                        raise OSError("unlink-fault")
                    real_unlink(name, dir_fd=dir_fd)

                def fail_directory_fsync(descriptor: int) -> None:
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                        raise OSError("directory-fsync-fault")
                    real_fsync(descriptor)

                patcher = (
                    mock.patch.object(
                        FIXTURE.os,
                        "unlink",
                        side_effect=fail_first_unlink,
                    )
                    if failure == "unlink"
                    else mock.patch.object(
                        FIXTURE.os,
                        "fsync",
                        side_effect=fail_directory_fsync,
                    )
                )
                with patcher, self.assertRaisesRegex(OSError, f"{failure}-fault"):
                    FIXTURE._publish_exclusive_json(marker, {"pid": 1})
                self.assertEqual(json.loads(marker.read_text(encoding="ascii")), {"pid": 1})
                self.assertEqual([path.name for path in root.iterdir()], [marker.name])
                self.assertEqual(self._open_fds_under(root), ())

    def test_fixture_marker_persistent_unlink_failure_still_closes_fds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            marker = root / "marker.json"
            unlink_calls = 0

            def fail_unlink(
                _name: str,
                *,
                dir_fd: int | None = None,
            ) -> None:
                del dir_fd
                nonlocal unlink_calls
                unlink_calls += 1
                raise OSError(
                    "primary-unlink-fault"
                    if unlink_calls == 1
                    else "cleanup-unlink-fault"
                )

            with (
                mock.patch.object(FIXTURE.os, "unlink", side_effect=fail_unlink),
                self.assertRaisesRegex(OSError, "cleanup-unlink-fault") as raised,
            ):
                FIXTURE._publish_exclusive_json(marker, {"pid": 1})
            self.assertIsNotNone(raised.exception.__cause__)
            self.assertIn("primary-unlink-fault", str(raised.exception.__cause__))
            self.assertEqual(json.loads(marker.read_text(encoding="ascii")), {"pid": 1})
            staged = [path for path in root.iterdir() if path != marker]
            self.assertEqual(len(staged), 1)
            self.assertEqual(marker.stat().st_ino, staged[0].stat().st_ino)
            self.assertEqual(marker.stat().st_nlink, 2)
            self.assertEqual(self._open_fds_under(root), ())
            staged[0].unlink()

    def test_fixture_marker_cleanup_failure_overrides_and_chains_primary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            marker = root / "marker.json"
            real_fsync = os.fsync

            def fail_directory_fsync(descriptor: int) -> None:
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    raise OSError("cleanup-fsync-fault")
                real_fsync(descriptor)

            with (
                mock.patch.object(
                    FIXTURE.os,
                    "write",
                    side_effect=OSError("write-fault"),
                ),
                mock.patch.object(
                    FIXTURE.os,
                    "fsync",
                    side_effect=fail_directory_fsync,
                ),
                self.assertRaisesRegex(OSError, "cleanup-fsync-fault") as raised,
            ):
                FIXTURE._publish_exclusive_json(marker, {"pid": 1})
            self.assertIsNotNone(raised.exception.__cause__)
            self.assertIn("write-fault", str(raised.exception.__cause__))
            self.assertFalse(marker.exists())
            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(self._open_fds_under(root), ())

    def test_fixture_holds_verified_socks_path_until_common_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            ready = root / "ready.json"
            release = root / "release"
            payload = bytes(range(251)) * 8
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = int(listener.getsockname()[1])
            server_error: list[BaseException] = []
            stayed_open = threading.Event()

            def read_exact(connection: socket.socket, size: int) -> bytes:
                result = bytearray()
                while len(result) < size:
                    chunk = connection.recv(size - len(result))
                    if not chunk:
                        raise RuntimeError("fixture test connection closed early")
                    result.extend(chunk)
                return bytes(result)

            def serve() -> None:
                try:
                    connection, _peer = listener.accept()
                    with connection:
                        self.assertEqual(read_exact(connection, 3), b"\x05\x01\x00")
                        connection.sendall(b"\x05\x00")
                        header = read_exact(connection, 5)
                        self.assertEqual(header[:4], b"\x05\x01\x00\x03")
                        read_exact(connection, header[4] + 2)
                        connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
                        self.assertEqual(read_exact(connection, len(payload)), payload)
                        connection.sendall(payload)
                        deadline = time.monotonic() + 2
                        while time.monotonic() < deadline and not ready.exists():
                            time.sleep(0.01)
                        self.assertTrue(ready.exists())
                        connection.settimeout(0.1)
                        with self.assertRaises(socket.timeout):
                            connection.recv(1)
                        stayed_open.set()
                        FIXTURE._publish_exclusive_json(release, {"release": True})
                except BaseException as exc:
                    server_error.append(exc)

            server = threading.Thread(target=serve)
            server.start()
            prior = os.environ.get("ALL_PROXY")
            os.environ["ALL_PROXY"] = f"socks5h://127.0.0.1:{port}"
            try:
                FIXTURE._socks_echo(
                    "example.test:443",
                    payload,
                    slow_read_ms=5,
                    ready_file=ready,
                    release_file=release,
                    barrier_timeout=3,
                )
            finally:
                if prior is None:
                    os.environ.pop("ALL_PROXY", None)
                else:
                    os.environ["ALL_PROXY"] = prior
                listener.close()
            server.join(timeout=3)
            self.assertFalse(server.is_alive())
            if server_error:
                raise server_error[0]
            self.assertTrue(stayed_open.is_set())

    def test_cleanup_failures_are_surfaced_alongside_primary_failure(self) -> None:
        def cleanup_failure() -> None:
            raise RuntimeError("cleanup-proof")

        with self.assertRaisesRegex(
            VERIFY.QualificationStageError, "cleanup-proof"
        ) as caught:
            VERIFY._finalize_run(
                ValueError("primary-proof"),
                (cleanup_failure,),
                cleanup_error_code="load32-cleanup",
            )
        self.assertEqual(caught.exception.error_code, "load32-cleanup")

    def test_cleanup_without_captured_authority_never_mutates_global_state(self) -> None:
        checkpoint = {"clean": True}
        with mock.patch.object(VERIFY, "wait_clean", return_value=checkpoint), mock.patch.object(
            VERIFY, "exact_signal"
        ) as exact_signal, mock.patch.object(VERIFY, "invoke") as invoke:
            result = VERIFY.cleanup(Path("/entrypoint"), {}, (), {}, None)
        self.assertEqual(result, checkpoint)
        exact_signal.assert_not_called()
        invoke.assert_not_called()

    def test_cleanup_status_timeout_still_stops_owned_wrappers(self) -> None:
        identity = VERIFY.ProcessIdentity(
            100, 10, "11111111-2222-3333-4444-555555555555"
        )
        epoch = VERIFY.CleanupAuthority("a" * 64, "epoch-a", identity)
        authority = VERIFY.ExclusiveCleanupAuthority(
            epoch, 1, "b" * 64, (identity,)
        )
        with mock.patch.object(
            VERIFY, "cleanup_fence", return_value=(epoch, "READY")
        ), mock.patch.object(
            VERIFY, "process_matches", return_value=True
        ), mock.patch.object(
            VERIFY,
            "invoke",
            side_effect=subprocess.TimeoutExpired(["status"], 1),
        ), mock.patch.object(
            VERIFY, "_stop_wrappers_bounded", return_value=[]
        ) as stop_wrappers, mock.patch.object(
            VERIFY, "exact_signal"
        ) as exact_signal, mock.patch.object(
            VERIFY, "prove_exclusive_epoch_authority"
        ) as prove_authority:
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "authority refused"
            ):
                VERIFY.cleanup(
                    Path("/entrypoint"),
                    {},
                    (),
                    {},
                    authority,
                    deadline_monotonic_ns=time.monotonic_ns()
                    + 5_000_000_000,
                )
        stop_wrappers.assert_called_once()
        exact_signal.assert_not_called()
        prove_authority.assert_not_called()

    def test_status_normalizes_timeout_as_unavailable_sample(self) -> None:
        with mock.patch.object(
            VERIFY,
            "invoke",
            side_effect=subprocess.TimeoutExpired(["status"], 2.5),
        ) as invoke:
            self.assertIsNone(
                VERIFY.status(Path("/entrypoint"), {}, timeout=2.5)
            )
        invoke.assert_called_once_with(
            Path("/entrypoint"), {}, "status", timeout=2.5
        )

    def test_status_normalizes_malformed_json_before_cleanup(self) -> None:
        response = mock.Mock(returncode=0, stdout="{malformed", stderr="")
        with mock.patch.object(VERIFY, "invoke", return_value=response):
            self.assertIsNone(VERIFY.status(Path("/entrypoint"), {}))
        decoding_error = UnicodeDecodeError(
            "utf-8", b"\xff", 0, 1, "fixture invalid text"
        )
        with mock.patch.object(
            VERIFY, "invoke", side_effect=decoding_error
        ):
            self.assertIsNone(VERIFY.status(Path("/entrypoint"), {}))

    def test_cleanup_proof_clips_nested_broker_to_one_deadline(self) -> None:
        clock = SimpleNamespace(now=0.0)
        captured_timeouts: list[float] = []
        clean_root = {
            "active": False,
            "namespace_alive": False,
            "tun_alive": False,
            "host_tun_alive": False,
            "vpn_alive": False,
            "relay_alive": False,
            "relay_pid": None,
            "root_artifact_residue": False,
            "ledger": None,
        }

        def user_inventory(_control, **_kwargs):
            clock.now = 9.75
            return {}

        def broker_inventory(_provenance, _env, _snapshot, *, timeout):
            captured_timeouts.append(timeout)
            return clean_root

        with mock.patch.object(
            VERIFY.time, "monotonic", side_effect=lambda: clock.now
        ), mock.patch.object(
            VERIFY.time,
            "monotonic_ns",
            side_effect=lambda: int(clock.now * 1_000_000_000),
        ), mock.patch.object(
            VERIFY, "account_control", return_value=Path("/control")
        ), mock.patch.object(
            VERIFY, "user_inventory", side_effect=user_inventory
        ), mock.patch.object(
            VERIFY, "listener_inventory", return_value={}
        ), mock.patch.object(
            VERIFY, "cgroup_scope_inventory", return_value={}
        ), mock.patch.object(
            VERIFY, "assert_user_inventory_clean"
        ), mock.patch.object(
            VERIFY, "assert_ports_clean"
        ), mock.patch.object(
            VERIFY, "assert_cgroup_scopes_clean"
        ), mock.patch.object(
            VERIFY, "broker_inventory", side_effect=broker_inventory
        ), mock.patch.object(
            VERIFY, "cgroup_resource_snapshot", return_value={}
        ), mock.patch.object(
            VERIFY, "aggregate_process_metrics", return_value={}
        ):
            VERIFY.wait_clean(
                {},
                {},
                timeout=10,
                deadline_monotonic_ns=10_000_000_000,
            )
        self.assertEqual(len(captured_timeouts), 1)
        self.assertGreater(captured_timeouts[0], 0)
        self.assertLessEqual(captured_timeouts[0], 0.25)

    def test_cleanup_authority_requires_exact_ready_and_fence_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            control = Path(directory)
            identity = VERIFY.current_process_identity(os.getpid())
            release_id = "a" * 64
            owner_epoch = "epoch-a"
            ready = {
                "schema_version": 1,
                "protocol_version": PROTOCOL_VERSION,
                "release_id": release_id,
                "owner_epoch": owner_epoch,
                **identity.to_dict(),
                "socket": str(control / "supervisor.sock"),
            }
            fence = {
                "schema_version": 1,
                "release_id": release_id,
                "owner_epoch": owner_epoch,
                **identity.to_dict(),
                "phase": "READY",
            }

            def publish(path: Path, value: dict[str, object]) -> None:
                path.write_text(json.dumps(value), encoding="ascii")

            publish(control / "supervisor.ready", ready)
            publish(control / "recovery.fence", fence)
            snapshot = {
                "release_id": release_id,
                "owner_epoch": owner_epoch,
                "phase": "READY",
            }
            authority = VERIFY.capture_cleanup_authority(
                control, snapshot, {"release_id": release_id}
            )
            self.assertEqual(authority.supervisor, identity)

            publish(control / "supervisor.ready", {**ready, "protocol_version": 1})
            with self.assertRaisesRegex(VERIFY.VerificationError, "disagree"):
                VERIFY.capture_cleanup_authority(
                    control, snapshot, {"release_id": release_id}
                )
            publish(control / "supervisor.ready", ready)
            publish(control / "recovery.fence", {**fence, "schema_version": 2})
            with self.assertRaisesRegex(VERIFY.VerificationError, "non-exact"):
                VERIFY.capture_cleanup_authority(
                    control, snapshot, {"release_id": release_id}
                )

    def test_cleanup_refuses_replacement_epoch_without_signalling_or_recovery(self) -> None:
        identity_a = VERIFY.ProcessIdentity(
            100, 10, "11111111-2222-3333-4444-555555555555"
        )
        identity_b = VERIFY.current_process_identity(os.getpid())
        epoch_a = VERIFY.CleanupAuthority("a" * 64, "epoch-a", identity_a)
        authority_a = VERIFY.ExclusiveCleanupAuthority(
            epoch_a, 1, "b" * 64, (identity_a,)
        )
        authority_b = VERIFY.CleanupAuthority("a" * 64, "epoch-b", identity_b)
        with mock.patch.object(
            VERIFY, "cleanup_fence", return_value=(authority_b, "READY")
        ), mock.patch.object(VERIFY, "exact_signal") as exact_signal, mock.patch.object(
            VERIFY, "invoke"
        ) as invoke:
            with self.assertRaisesRegex(VERIFY.VerificationError, "replacement epoch"):
                VERIFY.cleanup(Path("/entrypoint"), {}, (), {}, authority_a)
        exact_signal.assert_not_called()
        invoke.assert_not_called()
        self.assertTrue(VERIFY.process_matches(identity_b), "replacement epoch did not survive")

    def test_cleanup_recovery_is_bound_to_captured_exact_epoch(self) -> None:
        identity = VERIFY.ProcessIdentity(
            100, 10, "11111111-2222-3333-4444-555555555555"
        )
        epoch = VERIFY.CleanupAuthority("a" * 64, "epoch-a", identity)
        authority = VERIFY.ExclusiveCleanupAuthority(
            epoch, 1, "b" * 64, (identity,)
        )
        response = mock.Mock(
            returncode=0,
            stdout=json.dumps(
                {
                    "recovered": True,
                    "owner_epoch": "epoch-a",
                    "provider_records": 1,
                    "child_records": 1,
                    "probe_records": 0,
                }
            ),
            stderr="",
        )
        checkpoint = {"clean": True}
        with mock.patch.object(
            VERIFY,
            "cleanup_fence",
            side_effect=((epoch, "DRAINING"), (epoch, "DRAINING"), (epoch, "DRAINING")),
        ), mock.patch.object(VERIFY, "process_matches", return_value=False), mock.patch.object(
            VERIFY, "invoke", return_value=response
        ) as invoke, mock.patch.object(VERIFY, "wait_clean", return_value=checkpoint):
            self.assertEqual(
                VERIFY.cleanup(Path("/entrypoint"), {}, (), {}, authority), checkpoint
            )
        recovery_env = invoke.call_args.args[1]
        self.assertEqual(recovery_env["GROK_RECOVERY_EXPECT_OWNER_EPOCH"], "epoch-a")
        self.assertEqual(recovery_env["GROK_RECOVERY_EXPECT_PID"], "100")

    def test_exclusive_epoch_rejects_a_same_epoch_foreign_child(self) -> None:
        owned = VERIFY.current_process_identity(os.getpid())
        foreign = VERIFY.ProcessIdentity(
            owned.pid + 1, owned.pid_start_ticks + 1, owned.boot_id
        )
        epoch = VERIFY.CleanupAuthority("a" * 64, "epoch-a", owned)
        snapshot = {
            "release_id": "a" * 64,
            "owner_epoch": "epoch-a",
            "phase": "READY",
            "active_rung": "direct",
            "transition": None,
            "cleanup_error": None,
            "live_leases": 1,
            "provisional_leases": 0,
            "live_interest": 1,
            "generation": 1,
            "contract_digest": "b" * 64,
            "resources": {
                "leases": 1,
                "max_leases": 1,
                "provider_processes": 1,
            },
        }
        authorities = {
            "children": [
                {
                    "release_id": "a" * 64,
                    "owner_epoch": "epoch-a",
                    "leader_path": "/control/leaders/foreign.sock",
                    "process": {"identity": foreign.to_dict()},
                }
            ],
            "probes": [],
            "providers": [
                {
                    "release_id": "a" * 64,
                    "owner_epoch": "epoch-a",
                    "generation": 1,
                }
            ],
            "provider_scopes": [
                {
                    "release_id": "a" * 64,
                    "owner_epoch": "epoch-a",
                }
            ],
            "detached_scopes": [
                {
                    "release_id": "a" * 64,
                    "owner_epoch": "epoch-a",
                    "kind": "supervisor-epoch",
                    "phase": "OWNED",
                    "process": {"identity": owned.to_dict()},
                }
            ],
            "provider_identities": [owned],
        }
        with self.assertRaisesRegex(
            VERIFY.VerificationError, "capacity-filled verifier epoch"
        ):
            VERIFY.prove_exclusive_epoch_authority(
                Path("/control"),
                snapshot,
                epoch,
                authorities,
                (owned,),
                expected_contract_digest="c" * 64,
            )
        with self.assertRaisesRegex(VERIFY.VerificationError, "not owned"):
            VERIFY.prove_exclusive_epoch_authority(
                Path("/control"),
                snapshot,
                epoch,
                authorities,
                (owned,),
                expected_contract_digest="b" * 64,
            )

    def test_exclusive_epoch_leader_policies_are_exact_and_preserved(self) -> None:
        boot_id = "11111111-2222-3333-4444-555555555555"
        supervisor = VERIFY.ProcessIdentity(100, 10, boot_id)
        children = (
            VERIFY.ProcessIdentity(101, 11, boot_id),
            VERIFY.ProcessIdentity(102, 12, boot_id),
        )
        provider = VERIFY.ProcessIdentity(103, 13, boot_id)
        epoch = VERIFY.CleanupAuthority("a" * 64, "epoch-a", supervisor)
        snapshot = {
            "release_id": "a" * 64,
            "owner_epoch": "epoch-a",
            "phase": "READY",
            "active_rung": "direct",
            "transition": None,
            "cleanup_error": None,
            "live_leases": 2,
            "provisional_leases": 0,
            "live_interest": 2,
            "generation": 1,
            "contract_digest": "b" * 64,
            "resources": {
                "leases": 2,
                "max_leases": 2,
                "provider_processes": 1,
            },
        }
        authorities = {
            "children": [
                {
                    "release_id": "a" * 64,
                    "owner_epoch": "epoch-a",
                    "leader_path": f"/control/leaders/child-{index}.sock",
                    "process": {"identity": child.to_dict()},
                }
                for index, child in enumerate(children)
            ],
            "probes": [],
            "providers": [
                {
                    "release_id": "a" * 64,
                    "owner_epoch": "epoch-a",
                    "generation": 1,
                }
            ],
            "provider_scopes": [
                {"release_id": "a" * 64, "owner_epoch": "epoch-a"}
            ],
            "detached_scopes": [
                {
                    "release_id": "a" * 64,
                    "owner_epoch": "epoch-a",
                    "kind": "supervisor-epoch",
                    "phase": "OWNED",
                    "process": {"identity": supervisor.to_dict()},
                }
            ],
            "provider_identities": [provider],
        }
        socket_inventory = {
            "targets": {
                "leaders": {
                    "entries": [
                        {"kind": "socket", "path": f"child-{index}.sock"}
                        for index in range(2)
                    ]
                }
            }
        }
        empty_inventory = {"targets": {"leaders": {"entries": []}}}
        with mock.patch.object(
            VERIFY, "cleanup_fence", return_value=(epoch, "READY")
        ), mock.patch.object(
            VERIFY, "process_matches", return_value=True
        ), mock.patch.object(
            VERIFY, "user_inventory"
        ) as user_inventory:
            user_inventory.return_value = socket_inventory
            exact = VERIFY.prove_exclusive_epoch_authority(
                Path("/control"),
                snapshot,
                epoch,
                authorities,
                children,
                expected_contract_digest="b" * 64,
            )
            self.assertEqual(exact.leader_policy, "exact-sockets")

            user_inventory.return_value = empty_inventory
            disabled = VERIFY.prove_exclusive_epoch_authority(
                Path("/control"),
                snapshot,
                epoch,
                authorities,
                children,
                expected_contract_digest="b" * 64,
                leader_policy="disabled-empty",
            )
            self.assertEqual(disabled.leader_policy, "disabled-empty")
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "leader sockets are not exact"
            ):
                VERIFY.prove_exclusive_epoch_authority(
                    Path("/control"),
                    snapshot,
                    epoch,
                    authorities,
                    children,
                    expected_contract_digest="b" * 64,
                )

            user_inventory.return_value = socket_inventory
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "empty disabled leader directory"
            ):
                VERIFY.prove_exclusive_epoch_authority(
                    Path("/control"),
                    snapshot,
                    epoch,
                    authorities,
                    children,
                    expected_contract_digest="b" * 64,
                    leader_policy="disabled-empty",
                )

            duplicate_paths = {
                **authorities,
                "children": [
                    {**item, "leader_path": "/control/leaders/same.sock"}
                    for item in authorities["children"]
                ],
            }
            user_inventory.return_value = empty_inventory
            with self.assertRaisesRegex(
                VERIFY.VerificationError, "durable leader paths are not unique"
            ):
                VERIFY.prove_exclusive_epoch_authority(
                    Path("/control"),
                    snapshot,
                    epoch,
                    duplicate_paths,
                    children,
                    expected_contract_digest="b" * 64,
                    leader_policy="disabled-empty",
                )

    def test_child_execution_unit_evidence_is_distinct_and_stable(self) -> None:
        boot_id = "11111111-2222-3333-4444-555555555555"
        children = (
            VERIFY.ProcessIdentity(101, 11, boot_id),
            VERIFY.ProcessIdentity(102, 12, boot_id),
        )

        def record(child: VERIFY.ProcessIdentity, index: int) -> dict[str, object]:
            return {
                "process": {"identity": child.to_dict()},
                "scope": {
                    "scope_path": f"/sys/fs/cgroup/grok-ms-{index:024x}",
                    "scope_device": 3,
                    "scope_inode": 1000 + index,
                },
            }

        initial = {"children": [record(children[0], 1), record(children[1], 2)]}
        reordered = {"children": list(reversed(initial["children"]))}
        initial_evidence = VERIFY._child_execution_unit_evidence(
            initial, children
        )
        self.assertEqual(
            VERIFY._child_execution_unit_evidence(reordered, children),
            initial_evidence,
        )
        self.assertEqual(len(initial_evidence), 2)

        swapped = {
            "children": [record(children[0], 2), record(children[1], 1)]
        }
        self.assertNotEqual(
            VERIFY._child_execution_unit_evidence(swapped, children),
            initial_evidence,
        )
        duplicate_scope = {
            "children": [record(children[0], 1), record(children[1], 1)]
        }
        with self.assertRaisesRegex(
            VERIFY.VerificationError, "duplicate or invalid identity"
        ):
            VERIFY._child_execution_unit_evidence(duplicate_scope, children)

    @staticmethod
    def _resource_snapshot(
        *,
        inode: int = 7,
        memory: int = 1000,
        pids: int = 10,
        memory_peak: int | None = None,
        pids_peak: int | None = None,
        memory_event: int = 0,
        pids_event: int = 0,
    ) -> dict[str, object]:
        return {
            "cgroup_path": "/scope",
            "cgroup_device": 3,
            "cgroup_inode": inode,
            "values": {
                "memory.current": str(memory),
                "memory.peak": str(memory if memory_peak is None else memory_peak),
                "memory.max": "max",
                "memory.events": {
                    "low": 0,
                    "high": 0,
                    "max": 0,
                    "oom": memory_event,
                    "oom_kill": 0,
                },
                "pids.current": str(pids),
                "pids.peak": str(pids if pids_peak is None else pids_peak),
                "pids.max": "1000",
                "pids.events": {"max": pids_event},
            },
        }

    @staticmethod
    def _process_aggregate(count: int, *, fds: int = 10) -> dict[str, object]:
        base_fds, extra_fds = divmod(fds, count) if count else (0, 0)
        records = [
            {
                "identity": {
                    "pid": 100 + index,
                    "pid_start_ticks": 1000 + index,
                    "boot_id": "11111111-2222-3333-4444-555555555555",
                },
                "fd_count": base_fds + (1 if index < extra_fds else 0),
                "threads": 1,
                "vmrss_kib": 100,
                "vmsize_kib": 200,
                "cgroup": "0::/scope",
            }
            for index in range(count)
        ]
        return {
            "processes": records,
            "process_count": count,
            "fd_count": fds if count else 0,
            "threads": count,
            "vmrss_kib": count * 100,
            "vmsize_kib": count * 200,
        }

    def test_resource_gate_rejects_zero_samples_changed_cgroup_and_oversize(self) -> None:
        baseline = self._resource_snapshot()
        peak = self._resource_snapshot(memory=2000, pids=15)
        post = self._resource_snapshot(
            memory=1100, pids=10, memory_peak=2000, pids_peak=15
        )
        aggregate = self._process_aggregate(6)
        gate = VERIFY.assert_resource_gate(
            mode="load",
            count=2,
            baseline=baseline,
            peak=peak,
            post=post,
            peak_processes=aggregate,
            post_processes=self._process_aggregate(0, fds=0),
        )
        compact_contract, compact_observed = VERIFY._compact_resource_evidence(gate)
        self.assertEqual(set(compact_contract), VERIFY._RESOURCE_CONTRACT_KEYS)
        self.assertEqual(set(compact_observed), VERIFY._RESOURCE_OBSERVED_KEYS)
        self.assertEqual(compact_observed["memory_event_delta_total"], 0)
        self.assertEqual(compact_observed["pids_event_delta_total"], 0)
        self.assertEqual(compact_observed["post_owned_processes"], 0)
        self.assertEqual(compact_observed["cgroup_memory_highwater_delta_bytes"], 1000)
        with self.assertRaisesRegex(VERIFY.VerificationError, "zero samples"):
            VERIFY.assert_resource_sampler(
                {
                    "samples": 0,
                    "cgroup_identity": ["/scope", 3, 7],
                    "observed_maxima": {},
                },
                expected_cgroup=baseline,
                contract_gate=gate,
            )
        changed = self._resource_snapshot(inode=8, memory=2000, pids=15)
        with self.assertRaisesRegex(VERIFY.VerificationError, "identity changed"):
            VERIFY.assert_resource_gate(
                mode="load",
                count=2,
                baseline=baseline,
                peak=changed,
                post=post,
                peak_processes=aggregate,
                post_processes=self._process_aggregate(0, fds=0),
            )

        oversized = self._process_aggregate(6, fds=10_000)
        with self.assertRaisesRegex(VERIFY.VerificationError, "fd_count exceeds"):
            VERIFY.assert_resource_gate(
                mode="load",
                count=2,
                baseline=baseline,
                peak=peak,
                post=post,
                peak_processes=oversized,
                post_processes=self._process_aggregate(0, fds=0),
            )
        extreme_peak = self._resource_snapshot(
            memory=2000,
            pids=15,
            memory_peak=2**50,
            pids_peak=100_000,
        )
        extreme_post = self._resource_snapshot(
            memory=1100,
            pids=10,
            memory_peak=2**50,
            pids_peak=100_000,
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "high-water"):
            VERIFY.assert_resource_gate(
                mode="load",
                count=2,
                baseline=baseline,
                peak=extreme_peak,
                post=extreme_post,
                peak_processes=aggregate,
                post_processes=self._process_aggregate(0, fds=0),
            )
        event_peak = self._resource_snapshot(
            memory=2000,
            pids=15,
            memory_peak=2000,
            pids_peak=15,
            memory_event=1,
        )
        event_post = self._resource_snapshot(
            memory=1100,
            pids=10,
            memory_peak=2000,
            pids_peak=15,
            memory_event=1,
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "resource event"):
            VERIFY.assert_resource_gate(
                mode="load",
                count=2,
                baseline=baseline,
                peak=event_peak,
                post=event_post,
                peak_processes=aggregate,
                post_processes=self._process_aggregate(0, fds=0),
            )

    def test_load32_cgroup_task_contract_covers_live_peak_and_rejects_overflow(self) -> None:
        contract = VERIFY._resource_contract(32, mode="load")
        self.assertEqual(contract["max_cgroup_pids_delta"], 240)
        baseline = self._resource_snapshot(pids=100, pids_peak=100)
        peak = self._resource_snapshot(pids=302, pids_peak=302)
        post = self._resource_snapshot(pids=100, pids_peak=302)
        gate = VERIFY.assert_resource_gate(
            mode="load",
            count=32,
            baseline=baseline,
            peak=peak,
            post=post,
            peak_processes=self._process_aggregate(66),
            post_processes=self._process_aggregate(0, fds=0),
        )
        VERIFY.assert_resource_sampler(
            {
                "samples": 2,
                "cgroup_identity": ["/scope", 3, 7],
                "observed_maxima": {
                    "memory.current": 1000,
                    "memory.peak": 1000,
                    "pids.current": 302,
                    "pids.peak": 302,
                },
            },
            expected_cgroup=baseline,
            contract_gate=gate,
        )

        overflow = self._resource_snapshot(pids=341, pids_peak=341)
        overflow_post = self._resource_snapshot(pids=100, pids_peak=341)
        with self.assertRaises(VERIFY.QualificationStageError) as caught:
            VERIFY.assert_resource_gate(
                mode="load",
                count=32,
                baseline=baseline,
                peak=overflow,
                post=overflow_post,
                peak_processes=self._process_aggregate(66),
                post_processes=self._process_aggregate(0, fds=0),
            )
        self.assertEqual(
            caught.exception.error_code,
            "load32-resource-cgroup-pids-peak",
        )

        highwater = self._resource_snapshot(pids=302, pids_peak=341)
        with self.assertRaises(VERIFY.QualificationStageError) as caught:
            VERIFY.assert_resource_gate(
                mode="load",
                count=32,
                baseline=baseline,
                peak=highwater,
                post=overflow_post,
                peak_processes=self._process_aggregate(66),
                post_processes=self._process_aggregate(0, fds=0),
            )
        self.assertEqual(
            caught.exception.error_code,
            "load32-resource-cgroup-pids-highwater",
        )

        with self.assertRaisesRegex(VERIFY.VerificationError, "sampled PID peak"):
            VERIFY.assert_resource_sampler(
                {
                    "samples": 2,
                    "cgroup_identity": ["/scope", 3, 7],
                    "observed_maxima": {
                        "memory.current": 1000,
                        "memory.peak": 1000,
                        "pids.current": 341,
                        "pids.peak": 341,
                    },
                },
                expected_cgroup=baseline,
                contract_gate=gate,
            )

    def test_exact_process_nonreturn_is_a_failed_gate(self) -> None:
        identity = VERIFY.ProcessIdentity(
            123, 456, "11111111-2222-3333-4444-555555555555"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "did not return"):
            VERIFY.assert_process_identities_absent(
                (identity,),
                timeout=0,
                matcher=lambda _identity: True,
                sleeper=lambda _seconds: None,
            )

    def test_wrapper_cleanup_deadlines_are_shared_across_all_wrappers(self) -> None:
        clock = SimpleNamespace(now=0.0)

        class FakeProcess:
            def __init__(self) -> None:
                self.returncode: int | None = None
                self.killed = False
                self.waits: list[tuple[bool, float]] = []

            def wait(self, timeout: float):
                self.waits.append((self.killed, timeout))
                if self.killed:
                    self.returncode = -signal.SIGKILL
                    return self.returncode
                clock.now += timeout
                raise subprocess.TimeoutExpired(["fixture"], timeout)

        class FakeWrapper:
            def __init__(self, index: int) -> None:
                self.process = FakeProcess()
                self.identity = VERIFY.ProcessIdentity(
                    10_000 + index,
                    20_000 + index,
                    "11111111-2222-3333-4444-555555555555",
                )
                self.pidfd = 30_000 + index
                self.closed = False

            def close_pidfd(self) -> None:
                self.closed = True

        wrappers = [FakeWrapper(index) for index in range(32)]
        by_identity = {wrapper.identity: wrapper for wrapper in wrappers}

        def exact_signal(identity, signum, _pidfd):
            if signum == signal.SIGKILL:
                by_identity[identity].process.killed = True

        with mock.patch.object(
            VERIFY.time, "monotonic", side_effect=lambda: clock.now
        ), mock.patch.object(VERIFY, "exact_signal", side_effect=exact_signal):
            errors = VERIFY._stop_wrappers_bounded(wrappers)
        self.assertEqual(errors, [])
        term_waits = [
            timeout
            for wrapper in wrappers
            for killed, timeout in wrapper.process.waits
            if not killed
        ]
        self.assertLessEqual(sum(term_waits), VERIFY.CLEANUP_WRAPPER_TERM_SECONDS)
        self.assertTrue(all(wrapper.closed for wrapper in wrappers))
        self.assertTrue(all(wrapper.process.returncode == -signal.SIGKILL for wrapper in wrappers))

    def test_failure_stage_codes_are_closed_and_cleanup_overrides_primary(self) -> None:
        stage = VERIFY.QualificationStage("load32")
        stage.set("load32-overload")
        self.assertEqual(stage.error_code, "load32-overload")
        with self.assertRaisesRegex(ValueError, "codebook"):
            VERIFY.QualificationStage("unknown")
        with self.assertRaisesRegex(ValueError, "not in the mode codebook"):
            stage.set("fault-recovery-recovery")

        def cleanup_failure() -> None:
            raise VERIFY.VerificationError("dynamic cleanup detail")

        with self.assertRaises(VERIFY.QualificationStageError) as caught:
            VERIFY._finalize_run(
                VERIFY.VerificationError("dynamic primary detail"),
                (cleanup_failure,),
                cleanup_error_code="load32-cleanup",
            )
        self.assertEqual(caught.exception.error_code, "load32-cleanup")
        self.assertNotIn("dynamic", caught.exception.error_code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
