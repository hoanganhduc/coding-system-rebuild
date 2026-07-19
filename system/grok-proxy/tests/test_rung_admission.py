#!/usr/bin/env python3
"""Regression tests for terminal per-rung runtime admission."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Callable
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from grok_ms.rung_admission import (
    RUNG_EVIDENCE_SCHEMA_VERSION,
    RungAdmissionError,
    eligible_selected_rungs,
)


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        + b"\n"
    )


class RungAdmissionTests(unittest.TestCase):
    release_id = "a" * 64
    host_id = "b" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.control = Path(self.temporary.name) / "release-control"
        self.evidence_root = self.control / "rung-evidence"
        self.release_root = self.evidence_root / self.release_id
        self.release_root.mkdir(parents=True, mode=0o755)
        self.control.chmod(0o755)
        self.evidence_root.chmod(0o755)
        self.release_root.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def evidence(
        self,
        *,
        rung: str,
        qualification: str,
        grok_release: str,
        route_profile: str = "auto",
        profile_sha256: str | None = None,
    ) -> dict[str, object]:
        release_qualification = "c" * 64
        real_pair = "d" * 64
        result = hashlib.sha256(
            canonical(
                {
                    "real_pair_result_sha256": real_pair,
                    "release_qualification_sha256": release_qualification,
                }
            )
        ).hexdigest()
        return {
            "schema_version": RUNG_EVIDENCE_SCHEMA_VERSION,
            "release_id": self.release_id,
            "host_id": self.host_id,
            "rung": rung,
            "route_profile": route_profile,
            "contract_sha256": "e" * 64,
            "rung_qualification_sha256": qualification,
            "grok_release_id": grok_release,
            "model_id": "grok-4.5",
            "qualification_profile_sha256": profile_sha256,
            "measured_unix_ns": 1,
            "canary_nonce": "f" * 64,
            "release_qualification_sha256": release_qualification,
            "real_pair_result_sha256": real_pair,
            "measurements": {
                "duration_ms": 1,
                "fault_load_canary_verified": True,
                "host_limits_verified": True,
                "post_repair_reconnect_cache_execution_units_verified": True,
                "result_sha256": result,
                "shared_route": True,
                "teardown_clean": True,
                "transport_timing_verified": True,
                "two_sessions": True,
            },
            "overall_pass": True,
        }

    def publish(
        self,
        *,
        rung: str,
        qualification: str,
        grok_release: str,
        mutate: Callable[[dict[str, object]], None] | None = None,
    ) -> dict[str, str]:
        evidence = self.evidence(
            rung=rung,
            qualification=qualification,
            grok_release=grok_release,
        )
        if mutate is not None:
            mutate(evidence)
        raw = canonical(evidence)
        digest = hashlib.sha256(raw).hexdigest()
        path = self.release_root / f"{digest}.json"
        path.write_bytes(raw)
        path.chmod(0o444)
        return {
            "contract_sha256": qualification,
            "evidence_sha256": digest,
            "grok_release_id": grok_release,
            "rung": rung,
        }

    def admitted(self, records: list[dict[str, str]]) -> tuple[dict[str, str], ...]:
        return eligible_selected_rungs(
            records,
            control_root=self.control,
            release_id=self.release_id,
            host_id=self.host_id,
            root_uid=os.getuid(),
            root_gid=os.getgid(),
        )

    def test_invalid_sibling_removes_only_that_rung(self) -> None:
        direct = self.publish(
            rung="direct",
            qualification="1" * 64,
            grok_release="sha256:" + "2" * 64,
        )
        vpn = self.publish(
            rung="vpn",
            qualification="3" * 64,
            grok_release="sha256:" + "2" * 64,
        )
        (self.release_root / f"{vpn['evidence_sha256']}.json").unlink()
        self.assertEqual(self.admitted([direct, vpn]), (direct,))

    def test_missing_or_unsafe_evidence_yields_empty_survivors(self) -> None:
        record = self.publish(
            rung="direct",
            qualification="1" * 64,
            grok_release="sha256:" + "2" * 64,
        )
        path = self.release_root / f"{record['evidence_sha256']}.json"
        path.chmod(0o600)
        self.assertEqual(self.admitted([record]), ())
        path.unlink()
        self.assertEqual(self.admitted([record]), ())

    def test_closed_terminal_bindings_are_independently_revocable(self) -> None:
        mutations = {
            "wrong host": lambda value: value.__setitem__("host_id", "0" * 64),
            "old schema": lambda value: value.__setitem__("schema_version", 8),
            "failed": lambda value: value.__setitem__("overall_pass", False),
            "wrong result": lambda value: value["measurements"].__setitem__(
                "result_sha256", "0" * 64
            ),
        }
        for index, (label, mutate) in enumerate(mutations.items(), start=1):
            with self.subTest(label=label):
                record = self.publish(
                    rung="direct",
                    qualification=f"{index:x}" * 64,
                    grok_release="sha256:" + f"{index + 4:x}" * 64,
                    mutate=mutate,
                )
                self.assertEqual(self.admitted([record]), ())

    def test_malformed_duplicate_and_noncanonical_selection_fail_globally(self) -> None:
        direct = self.publish(
            rung="direct",
            qualification="1" * 64,
            grok_release="sha256:" + "2" * 64,
        )
        vpn = self.publish(
            rung="vpn",
            qualification="3" * 64,
            grok_release="sha256:" + "2" * 64,
        )
        malformed = dict(direct)
        malformed["extra"] = "forbidden"
        for records in ([malformed], [direct, direct], [vpn, direct]):
            with self.subTest(records=records), self.assertRaises(
                RungAdmissionError
            ):
                self.admitted(records)


if __name__ == "__main__":
    unittest.main()
