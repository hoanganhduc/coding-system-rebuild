#!/usr/bin/env python3
"""Focused tests for strict managed-profile storage and readiness."""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from grok_ms.contract import (  # noqa: E402
    CONTRACT_SCHEMA_VERSION,
    PROTOCOL_VERSION,
    Endpoint,
    HomeEndpoint,
    ResourceLimits,
    RouteContract,
    RouteMode,
    StabilityPolicy,
    TimeoutPolicy,
    VpnPolicy,
)
from grok_ms.grok_exec import grok_release_id  # noqa: E402
from grok_ms.managed_profile import (  # noqa: E402
    ACTIVATION_FILE_MODE,
    PROFILE_FILE_MODE,
    PROFILE_STATUS_SCHEMA,
    ActivationCommitUncertain,
    ActivationRecord,
    ManagedProfile,
    ManagedProfileError,
    ProfileStatus,
    ReadinessPolicy,
    blocked_status,
    load_active_profile,
    load_activation_record,
    load_managed_profile,
    unconfigured_status,
    write_activation_record,
    write_content_addressed_profile,
)


def file_mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def make_grok(root: Path, name: str = "grok-0.2.103-linux-aarch64") -> Path:
    path = root / name
    path.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="ascii")
    path.chmod(0o700)
    return path


def make_contract(grok: Path) -> RouteContract:
    return RouteContract(
        schema_version=CONTRACT_SCHEMA_VERSION,
        protocol_version=PROTOCOL_VERSION,
        release_id="a" * 64,
        model_id="grok-4.5",
        route_mode=RouteMode.AUTO,
        forced_host=None,
        home_endpoints=(HomeEndpoint("lab", "100.64.0.10", "alice", 22),),
        ios_endpoints=(),
        forced_ios_key=None,
        allow_direct=True,
        ladder=("home:lab", "direct"),
        routing_config_digest="b" * 64,
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
            countries=("VN",),
            blocked_countries=("CN",),
        ),
        helper_release_ids=(("relay", "relay-v1"),),
        grok_release_id=grok_release_id(grok),
        public_endpoint=Endpoint("127.0.0.1", 1080),
        private_ports=(11880, 11881),
        limits=ResourceLimits(
            max_leases=32,
            max_control_connections=64,
            max_frontend_streams=256,
            max_packet_bytes=65_536,
            per_stream_buffer_bytes=262_144,
            total_buffer_bytes=67_108_864,
        ),
    )


def make_profile(root: Path) -> tuple[ManagedProfile, Path]:
    grok = make_grok(root)
    profile = ManagedProfile.create(
        make_contract(grok),
        grok,
        ReadinessPolicy(1, ("direct",)),
    )
    return profile, grok


class ManagedProfileRecordTests(unittest.TestCase):
    def test_create_freezes_resolved_versioned_binary_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile, grok = make_profile(root)
            selector = root / "grok"
            selector.symlink_to(grok.name)
            selected = ManagedProfile.create(
                profile.contract,
                selector,
                profile.readiness_policy,
            )

            self.assertEqual(selected.grok_path, grok)
            self.assertEqual(selected.grok_release_id, grok_release_id(grok))
            self.assertEqual(selected.contract_sha256, selected.contract.digest())
            self.assertEqual(ManagedProfile.from_dict(selected.to_dict()), selected)
            self.assertEqual(len(selected.digest()), 64)
            self.assertEqual(selected.filename(), f"{selected.digest()}.json")
            self.assertTrue(selected.canonical_bytes().endswith(b"\n"))

    def test_create_rejects_unversioned_or_mismatched_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            grok = make_grok(root)
            contract = make_contract(grok)
            other = make_grok(root, "grok-0.2.104-linux-aarch64")
            other.write_text("#!/usr/bin/env sh\nexit 9\n", encoding="ascii")
            with self.assertRaisesRegex(ManagedProfileError, "do not match"):
                ManagedProfile.create(
                    contract, other, ReadinessPolicy(1, ("direct",))
                )

            unversioned = make_grok(root, "grok")
            unversioned_contract = dataclasses.replace(
                contract, grok_release_id=grok_release_id(unversioned)
            )
            with self.assertRaisesRegex(ManagedProfileError, "versioned"):
                ManagedProfile.create(
                    unversioned_contract,
                    unversioned,
                    ReadinessPolicy(1, ("direct",)),
                )

    def test_exact_profile_shape_and_bindings_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile, _grok = make_profile(Path(directory))
            for field, value in (
                ("extra", True),
                ("schema_version", True),
                ("profile_name", "other"),
                ("contract_sha256", "0" * 64),
                ("grok_release_id", "sha256:" + "0" * 64),
            ):
                record = profile.to_dict()
                record[field] = value
                with self.subTest(field=field), self.assertRaises(ManagedProfileError):
                    ManagedProfile.from_dict(record)

            with self.assertRaisesRegex(ManagedProfileError, "exceeds"):
                dataclasses.replace(
                    profile,
                    readiness_policy=ReadinessPolicy(3, ()),
                )
            with self.assertRaisesRegex(ManagedProfileError, "outside"):
                dataclasses.replace(
                    profile,
                    readiness_policy=ReadinessPolicy(1, ("vpn",)),
                )
            with self.assertRaisesRegex(ManagedProfileError, "preserve"):
                dataclasses.replace(
                    profile,
                    readiness_policy=ReadinessPolicy(
                        1, ("direct", "home:lab")
                    ),
                )
            with self.assertRaisesRegex(ManagedProfileError, "duplicates"):
                ReadinessPolicy(1, ("direct", "direct"))

    def test_activation_has_only_public_exact_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile, _grok = make_profile(Path(directory))
            activation = ActivationRecord.from_profile(
                profile, activated_unix_ns=1_234_567
            )
            self.assertEqual(
                set(activation.to_dict()),
                {
                    "schema_version",
                    "profile_name",
                    "profile_sha256",
                    "release_id",
                    "contract_sha256",
                    "grok_release_id",
                    "model_id",
                    "activated_unix_ns",
                },
            )
            self.assertNotIn("contract", activation.to_dict())
            self.assertNotIn("grok_path", activation.to_dict())
            self.assertEqual(
                ActivationRecord.from_dict(activation.to_dict()), activation
            )
            extra = activation.to_dict()
            extra["eligible_rungs"] = []
            with self.assertRaises(ManagedProfileError):
                ActivationRecord.from_dict(extra)
            wrong_schema = activation.to_dict()
            wrong_schema["schema_version"] = True
            with self.assertRaises(ManagedProfileError):
                ActivationRecord.from_dict(wrong_schema)
            changed = dataclasses.replace(activation, model_id="grok-4.5-fast")
            with self.assertRaisesRegex(ManagedProfileError, "model_id"):
                changed.validate_profile(profile)


class ManagedProfileReadinessTests(unittest.TestCase):
    def test_ready_degraded_and_blocked_statuses_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile, _grok = make_profile(Path(directory))
            ready = profile.readiness(("direct", "home:lab"))
            degraded = profile.readiness(("direct",))
            required_blocked = profile.readiness(("home:lab",))
            minimum_profile = dataclasses.replace(
                profile, readiness_policy=ReadinessPolicy(2, ())
            )
            minimum_blocked = minimum_profile.readiness(("direct",))

            self.assertEqual((ready.status, ready.reason_code), ("ready", "ready"))
            self.assertEqual(ready.eligible_rungs, ("home:lab", "direct"))
            self.assertEqual(ready.missing_rungs, ())
            self.assertEqual(
                (degraded.status, degraded.reason_code),
                ("degraded", "ready_with_missing_optional_rungs"),
            )
            self.assertEqual(degraded.missing_rungs, ("home:lab",))
            self.assertEqual(
                (required_blocked.status, required_blocked.reason_code),
                ("blocked", "required_rungs_missing"),
            )
            self.assertEqual(
                (minimum_blocked.status, minimum_blocked.reason_code),
                ("blocked", "minimum_eligible_rungs_not_met"),
            )
            for status in (ready, degraded, required_blocked, minimum_blocked):
                self.assertEqual(
                    ProfileStatus.from_dict(status.to_dict()), status
                )
                self.assertEqual(status.schema_version, PROFILE_STATUS_SCHEMA)
                self.assertNotIn("contract", status.to_dict())
                self.assertNotIn("grok_path", status.to_dict())

    def test_readiness_rejects_open_duplicate_or_untyped_rung_sets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile, _grok = make_profile(Path(directory))
            for eligible in (
                ("vpn",),
                ("direct", "direct"),
                "direct",
                (True,),
            ):
                with self.subTest(eligible=eligible), self.assertRaises(
                    ManagedProfileError
                ):
                    profile.readiness(eligible)

    def test_unconfigured_and_untrusted_blocked_statuses_are_redacted(self) -> None:
        unconfigured = unconfigured_status()
        blocked = blocked_status("active_profile_invalid")
        for status in (unconfigured, blocked):
            self.assertIsNone(status.profile_name)
            self.assertIsNone(status.profile_sha256)
            self.assertEqual(status.eligible_rungs, ())
            self.assertEqual(ProfileStatus.from_dict(status.to_dict()), status)

        with self.assertRaisesRegex(ManagedProfileError, "identity"):
            ProfileStatus(
                PROFILE_STATUS_SCHEMA,
                "ready",
                None,
                None,
                None,
                None,
                None,
                (),
                (),
                "ready",
            )

        ready_value = {
            **blocked.to_dict(),
            "reason_code": "arbitrary_future_reason",
        }
        with self.assertRaisesRegex(ManagedProfileError, "reason_code"):
            ProfileStatus.from_dict(ready_value)

        inconsistent = blocked.to_dict()
        inconsistent["reason_code"] = "required_rungs_missing"
        with self.assertRaisesRegex(ManagedProfileError, "reason_code"):
            ProfileStatus.from_dict(inconsistent)


class ManagedProfileStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.profile_root = self.root / "profiles"
        self.activation_root = self.root / "release-control"
        self.profile_root.mkdir(mode=0o700)
        self.activation_root.mkdir(mode=0o755)
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.profile, self.grok = make_profile(self.root)
        self.activation = ActivationRecord.from_profile(
            self.profile, activated_unix_ns=1_234_567
        )
        self.activation_path = self.activation_root / "active-profile.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def publish(self) -> Path:
        profile_path = write_content_addressed_profile(
            self.profile_root,
            self.profile,
            owner_uid=self.uid,
            owner_gid=self.gid,
        )
        write_activation_record(
            self.activation_path,
            self.activation,
            owner_uid=self.uid,
            owner_gid=self.gid,
        )
        return profile_path

    def load(self):
        return load_active_profile(
            self.profile_root,
            self.activation_path,
            profile_uid=self.uid,
            profile_gid=self.gid,
            activation_uid=self.uid,
            activation_gid=self.gid,
        )

    def test_atomic_publication_is_canonical_idempotent_and_fully_bound(self) -> None:
        path = self.publish()
        self.assertEqual(file_mode(path), PROFILE_FILE_MODE)
        self.assertEqual(file_mode(self.activation_path), ACTIVATION_FILE_MODE)
        self.assertEqual(path.read_bytes(), self.profile.canonical_bytes())
        self.assertEqual(
            self.activation_path.read_bytes(), self.activation.canonical_bytes()
        )
        self.assertEqual(
            write_content_addressed_profile(
                self.profile_root,
                self.profile,
                owner_uid=self.uid,
                owner_gid=self.gid,
            ),
            path,
        )
        active = self.load()
        self.assertEqual(active.profile, self.profile)
        self.assertEqual(active.activation, self.activation)
        self.assertEqual(
            load_managed_profile(
                path, expected_uid=self.uid, expected_gid=self.gid
            ),
            self.profile,
        )
        self.assertEqual(
            load_activation_record(
                self.activation_path,
                expected_uid=self.uid,
                expected_gid=self.gid,
            ),
            self.activation,
        )

    def test_profile_read_rejects_noncanonical_mode_owner_name_and_symlink(self) -> None:
        path = self.publish()
        path.write_bytes(b" " + self.profile.canonical_bytes())
        with self.assertRaisesRegex(ManagedProfileError, "canonical"):
            load_managed_profile(path, expected_uid=self.uid, expected_gid=self.gid)

        path.write_bytes(self.profile.canonical_bytes())
        path.chmod(0o644)
        with self.assertRaisesRegex(ManagedProfileError, "owner/type/mode"):
            load_managed_profile(path, expected_uid=self.uid, expected_gid=self.gid)
        path.chmod(0o600)
        with self.assertRaisesRegex(ManagedProfileError, "owner/type/mode"):
            load_managed_profile(
                path, expected_uid=self.uid + 1, expected_gid=self.gid
            )

        wrong_name = self.profile_root / ("0" * 64 + ".json")
        wrong_name.write_bytes(self.profile.canonical_bytes())
        wrong_name.chmod(0o600)
        with self.assertRaisesRegex(ManagedProfileError, "filename"):
            load_managed_profile(
                wrong_name, expected_uid=self.uid, expected_gid=self.gid
            )

        target = self.profile_root / "target.json"
        target.write_bytes(self.profile.canonical_bytes())
        target.chmod(0o600)
        path.unlink()
        path.symlink_to(target.name)
        with self.assertRaises(ManagedProfileError):
            load_managed_profile(path, expected_uid=self.uid, expected_gid=self.gid)

    def test_active_load_rejects_every_binding_and_changed_binary(self) -> None:
        self.publish()
        for field, value in (
            ("profile_sha256", "0" * 64),
            ("release_id", "other-release"),
            ("contract_sha256", "0" * 64),
            ("grok_release_id", "sha256:" + "0" * 64),
            ("model_id", "grok-4.5-fast"),
        ):
            changed = dataclasses.replace(self.activation, **{field: value})
            write_activation_record(
                self.activation_path,
                changed,
                owner_uid=self.uid,
                owner_gid=self.gid,
            )
            with self.subTest(field=field), self.assertRaises(ManagedProfileError):
                self.load()
        write_activation_record(
            self.activation_path,
            self.activation,
            owner_uid=self.uid,
            owner_gid=self.gid,
        )
        self.grok.write_text("#!/usr/bin/env sh\nexit 8\n", encoding="ascii")
        with self.assertRaisesRegex(ManagedProfileError, "identity mismatch"):
            self.load()

    def test_activation_read_rejects_noncanonical_and_writer_refuses_symlink(self) -> None:
        self.publish()
        self.activation_path.chmod(0o600)
        self.activation_path.write_bytes(b" " + self.activation.canonical_bytes())
        self.activation_path.chmod(0o444)
        with self.assertRaisesRegex(ManagedProfileError, "not canonical"):
            load_activation_record(
                self.activation_path,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

        target = self.activation_root / "target.json"
        target.write_bytes(self.activation.canonical_bytes())
        target.chmod(0o444)
        self.activation_path.unlink()
        self.activation_path.symlink_to(target.name)
        with self.assertRaises(ManagedProfileError):
            write_activation_record(
                self.activation_path,
                self.activation,
                owner_uid=self.uid,
                owner_gid=self.gid,
            )

    def test_activation_writer_distinguishes_postrename_fsync_uncertainty(self) -> None:
        self.publish()
        replacement = dataclasses.replace(
            self.activation,
            activated_unix_ns=self.activation.activated_unix_ns + 1,
        )
        real_fsync = os.fsync

        def fail_directory_fsync(descriptor: int) -> None:
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("synthetic directory fsync failure")
            real_fsync(descriptor)

        with (
            mock.patch(
                "grok_ms.managed_profile.os.fsync",
                side_effect=fail_directory_fsync,
            ),
            self.assertRaises(ActivationCommitUncertain),
        ):
            write_activation_record(
                self.activation_path,
                replacement,
                owner_uid=self.uid,
                owner_gid=self.gid,
            )
        self.assertEqual(
            load_activation_record(
                self.activation_path,
                expected_uid=self.uid,
                expected_gid=self.gid,
            ),
            replacement,
        )

    def test_activation_writer_preserves_commit_state_on_close_failure(self) -> None:
        self.publish()
        replacement = dataclasses.replace(
            self.activation,
            activated_unix_ns=self.activation.activated_unix_ns + 1,
        )
        real_close = os.close

        def close_then_fail_for_directory(descriptor: int) -> None:
            is_directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
            real_close(descriptor)
            if is_directory:
                raise OSError("synthetic directory descriptor close failure")

        with (
            mock.patch(
                "grok_ms.managed_profile.os.close",
                side_effect=close_then_fail_for_directory,
            ),
            self.assertRaises(ActivationCommitUncertain),
        ):
            write_activation_record(
                self.activation_path,
                replacement,
                owner_uid=self.uid,
                owner_gid=self.gid,
            )
        self.assertEqual(
            load_activation_record(
                self.activation_path,
                expected_uid=self.uid,
                expected_gid=self.gid,
            ),
            replacement,
        )

    def test_stage_failures_leave_no_hidden_profile_or_activation_residue(self) -> None:
        with mock.patch(
            "grok_ms.managed_profile.os.fchmod",
            side_effect=OSError("synthetic stage mode failure"),
        ):
            with self.assertRaises(ManagedProfileError):
                write_content_addressed_profile(
                    self.profile_root,
                    self.profile,
                    owner_uid=self.uid,
                    owner_gid=self.gid,
                )
        self.assertEqual(list(self.profile_root.iterdir()), [])

        with mock.patch(
            "grok_ms.managed_profile.os.fchmod",
            side_effect=OSError("synthetic stage mode failure"),
        ):
            with self.assertRaises(ManagedProfileError):
                write_activation_record(
                    self.activation_path,
                    self.activation,
                    owner_uid=self.uid,
                    owner_gid=self.gid,
                )
        self.assertEqual(list(self.activation_root.iterdir()), [])

    def test_profile_directory_close_failure_is_normalized_after_link(self) -> None:
        real_close = os.close

        def close_then_fail_for_directory(descriptor: int) -> None:
            is_directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
            real_close(descriptor)
            if is_directory:
                raise OSError("synthetic profile directory close failure")

        with (
            mock.patch(
                "grok_ms.managed_profile.os.close",
                side_effect=close_then_fail_for_directory,
            ),
            self.assertRaisesRegex(
                ManagedProfileError,
                "clean managed-profile publication state",
            ),
        ):
            write_content_addressed_profile(
                self.profile_root,
                self.profile,
                owner_uid=self.uid,
                owner_gid=self.gid,
            )
        self.assertTrue((self.profile_root / self.profile.filename()).is_file())
        self.assertEqual(
            [path.name for path in self.profile_root.iterdir() if path.name.startswith(".")],
            [],
        )

    def test_parent_directory_mode_and_release_binding_fail_closed(self) -> None:
        self.publish()
        self.profile_root.chmod(0o755)
        with self.assertRaisesRegex(ManagedProfileError, "storage directory"):
            self.load()
        self.profile_root.chmod(0o700)
        with self.assertRaisesRegex(ManagedProfileError, "selected release"):
            load_active_profile(
                self.profile_root,
                self.activation_path,
                profile_uid=self.uid,
                profile_gid=self.gid,
                activation_uid=self.uid,
                activation_gid=self.gid,
                expected_release_id="c" * 64,
            )


if __name__ == "__main__":
    unittest.main()
