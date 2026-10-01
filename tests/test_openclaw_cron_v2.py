#!/usr/bin/env python3
"""Fixture-only tests for OpenClaw logical cron v2 export/import."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "bin/openclaw-cron-v2.py"
CANARY_SNAPSHOT = ROOT / "system/schedules/openclaw-cron.v2.json"


def load_helper_module():
    spec = importlib.util.spec_from_file_location("openclaw_cron_v2", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command_job(
    key: str | None = "coding-system.restore.canary",
    *,
    name: str = "Scheduler canary",
) -> dict[str, object]:
    job: dict[str, object] = {
        "name": name,
        "enabled": True,
        "schedule": {"kind": "cron", "expr": "*/15 * * * *", "tz": "Etc/UTC", "staggerMs": 0},
        "sessionTarget": "isolated",
        "wakeMode": "now",
        "payload": {
            "kind": "command",
            "argv": ["python3", "/opt/scheduler-canary.py", "record", "--scheduler", "openclaw"],
            "timeoutSeconds": 30,
        },
        "delivery": {"mode": "none"},
    }
    if key is not None:
        job["declarationKey"] = key
    return job


class OpenClawCronV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_helper_module()

    def make_fake_openclaw(self, root: Path, jobs: list[dict[str, object]]) -> tuple[Path, Path, Path]:
        state = root / "openclaw-state.json"
        log = root / "openclaw.log"
        materialized = []
        for index, raw in enumerate(jobs, start=1):
            job = dict(raw)
            job.setdefault("id", f"fixture-{index}")
            job.setdefault("createdAtMs", index)
            job.setdefault("updatedAtMs", index)
            job.setdefault("state", {})
            materialized.append(job)
        state.write_text(json.dumps({"next": len(materialized) + 1, "jobs": materialized}), encoding="utf-8")
        executable = root / "fake-openclaw"
        executable.write_text(
            """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

state_path = Path(os.environ["FAKE_OPENCLAW_STATE"])
log_path = Path(os.environ["FAKE_OPENCLAW_LOG"])
args = sys.argv[1:]
with log_path.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\\n")
state = json.loads(state_path.read_text(encoding="utf-8"))
jobs = state["jobs"]

def save():
    state_path.write_text(json.dumps(state), encoding="utf-8")

if args == ["cron", "list", "--all", "--json"]:
    print(json.dumps({"jobs": jobs}))
elif len(args) == 3 and args[:2] == ["cron", "get"]:
    match = next(job for job in jobs if job["id"] == args[2])
    print(json.dumps(match))
elif args[:3] == ["gateway", "call", "cron.add"]:
    params = json.loads(args[args.index("--params") + 1])
    match = next((job for job in jobs if job.get("declarationKey") == params.get("declarationKey")), None)
    if match is None:
        match = dict(params)
        match["id"] = f"fixture-{state['next']}"
        state["next"] += 1
        match["createdAtMs"] = state["next"]
        match["updatedAtMs"] = state["next"]
        match["state"] = {}
        jobs.append(match)
        created = True
    else:
        for field in ("schedule", "trigger", "payload", "delivery", "displayName", "enabled"):
            if field in params:
                match[field] = params[field]
            else:
                match.pop(field, None)
        created = False
    save()
    print(json.dumps({"created": created, "job": match}))
elif len(args) == 4 and args[:2] == ["cron", "rm"] and args[3] == "--json":
    before = len(jobs)
    state["jobs"] = [job for job in jobs if job["id"] != args[2]]
    save()
    print(json.dumps({"ok": True, "removed": len(state["jobs"]) != before}))
else:
    print(f"unsupported fake OpenClaw command: {args}", file=sys.stderr)
    raise SystemExit(64)
""",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        return executable, state, log

    def run_helper(
        self,
        executable: Path,
        state: Path,
        log: Path,
        *arguments: str,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["FAKE_OPENCLAW_STATE"] = str(state)
        environment["FAKE_OPENCLAW_LOG"] = str(log)
        return subprocess.run(
            ["python3", str(HELPER), "--openclaw-bin", str(executable), *arguments],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
        )

    def write_snapshot(self, path: Path, jobs: list[dict[str, object]]) -> None:
        path.write_text(
            json.dumps(
                {
                    "schema": "coding-system.openclaw-cron/v2",
                    "managedDeclarationPrefix": "coding-system.restore.",
                    "jobs": sorted(jobs, key=lambda job: str(job["declarationKey"])),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_export_is_logical_private_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable, state, log = self.make_fake_openclaw(root, [command_job(None)])
            output = root / "snapshot.json"

            first = self.run_helper(executable, state, log, "export", "--output", str(output))
            snapshot = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(first.returncode, 0, first.stdout)
            self.assertEqual(snapshot["schema"], "coding-system.openclaw-cron/v2")
            self.assertTrue(snapshot["jobs"][0]["declarationKey"].startswith("coding-system.restore."))
            self.assertNotIn("id", snapshot["jobs"][0])
            self.assertNotIn("state", snapshot["jobs"][0])
            self.assertNotIn("createdAtMs", snapshot["jobs"][0])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

            os.utime(output, (1, 1))
            second = self.run_helper(executable, state, log, "export", "--output", str(output))
            self.assertEqual(second.returncode, 0, second.stdout)
            self.assertIn("current", second.stdout)
            self.assertEqual(output.stat().st_mtime_ns, 1_000_000_000)

    def test_export_normalizes_target_home_for_portability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "target-home"
            job = command_job()
            job["payload"] = {
                "kind": "command",
                "argv": ["python3", f"{home}/bin/canary.py"],
            }
            executable, state, log = self.make_fake_openclaw(root, [job])
            output = root / "portable.json"

            result = self.run_helper(
                executable,
                state,
                log,
                "--home",
                str(home),
                "export",
                "--output",
                str(output),
            )

            self.assertEqual(result.returncode, 0, result.stdout)
            serialized = output.read_text(encoding="utf-8")
            self.assertIn("{{ HOME }}/bin/canary.py", serialized)
            self.assertNotIn(str(home), serialized)

    def test_import_converges_keys_deduplicates_legacy_and_prunes_only_managed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            desired = command_job()
            unkeyed = command_job(None)
            stale = command_job("coding-system.restore.stale", name="Stale managed")
            unrelated = command_job("outside.owner.keep", name="Unrelated declaration")
            executable, state, log = self.make_fake_openclaw(
                root, [unkeyed, stale, unrelated]
            )
            snapshot = root / "snapshot.json"
            self.write_snapshot(snapshot, [desired])

            first = self.run_helper(executable, state, log, "import", "--input", str(snapshot))
            after_first = json.loads(state.read_text(encoding="utf-8"))["jobs"]
            self.assertEqual(first.returncode, 0, first.stdout)
            self.assertEqual(
                [job["declarationKey"] for job in after_first if "declarationKey" in job],
                ["outside.owner.keep", "coding-system.restore.canary"],
            )
            self.assertFalse(any("declarationKey" not in job for job in after_first))

            log_before = log.read_text(encoding="utf-8")
            second = self.run_helper(executable, state, log, "import", "--input", str(snapshot))
            new_calls = log.read_text(encoding="utf-8")[len(log_before) :]
            self.assertEqual(second.returncode, 0, second.stdout)
            self.assertNotIn('"gateway"', new_calls)
            self.assertNotIn('"rm"', new_calls)

    def test_dry_run_is_read_only_and_verify_reports_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable, state, log = self.make_fake_openclaw(root, [])
            snapshot = root / "snapshot.json"
            self.write_snapshot(snapshot, [command_job()])
            original = state.read_bytes()

            dry = self.run_helper(
                executable, state, log, "import", "--input", str(snapshot), "--dry-run"
            )
            verify = self.run_helper(executable, state, log, "verify", "--input", str(snapshot))

            self.assertEqual(dry.returncode, 0, dry.stdout)
            self.assertEqual(verify.returncode, 1, verify.stdout)
            self.assertEqual(state.read_bytes(), original)
            calls = log.read_text(encoding="utf-8")
            self.assertNotIn('"gateway"', calls)
            self.assertNotIn('"rm"', calls)

    def test_non_declarative_field_drift_recreates_without_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = command_job(name="Old display name")
            desired = command_job(name="New display name")
            executable, state, log = self.make_fake_openclaw(root, [current])
            snapshot = root / "snapshot.json"
            self.write_snapshot(snapshot, [desired])

            result = self.run_helper(
                executable, state, log, "import", "--input", str(snapshot)
            )
            jobs = json.loads(state.read_text(encoding="utf-8"))["jobs"]

            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]["name"], "New display name")
            calls = log.read_text(encoding="utf-8")
            self.assertIn('"rm"', calls)
            self.assertIn('"cron.add"', calls)

    def test_legacy_migrated_adapter_never_needs_live_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = root / "jobs.json.migrated"
            raw = command_job(None)
            raw["id"] = "runtime-id"
            raw["createdAtMs"] = 123
            raw["state"] = {"lastRunStatus": "ok"}
            legacy.write_text(json.dumps({"version": 1, "jobs": [raw]}), encoding="utf-8")
            output = root / "v2.json"

            result = subprocess.run(
                [
                    "python3",
                    str(HELPER),
                    "--openclaw-bin",
                    str(root / "does-not-exist"),
                    "adapt-legacy",
                    "--input",
                    str(legacy),
                    "--output",
                    str(output),
                ],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            snapshot = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(len(snapshot["jobs"]), 2)
            migrated = next(job for job in snapshot["jobs"] if job["name"] == raw["name"])
            self.assertNotIn("id", migrated)
            self.assertNotIn("state", migrated)
            self.assertIn(
                "coding-system.restore.scheduler-canary",
                {job["declarationKey"] for job in snapshot["jobs"]},
            )
            self.assertEqual(json.loads(legacy.read_text(encoding="utf-8"))["version"], 1)

    def test_duplicate_explicit_declaration_keys_fail_closed(self) -> None:
        first = command_job("coding-system.restore.duplicate", name="First")
        second = command_job("coding-system.restore.duplicate", name="Second")
        with self.assertRaisesRegex(self.module.CronContractError, "ambiguous"):
            self.module.make_snapshot([first, second])

    def test_exact_duplicate_unkeyed_legacy_jobs_collapse_to_one_declaration(self) -> None:
        snapshot = self.module.make_snapshot([command_job(None), command_job(None)])
        self.assertEqual(len(snapshot["jobs"]), 1)

    def test_snapshot_writer_refuses_symlink_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "victim"
            victim.write_text("unchanged\n", encoding="utf-8")
            destination = root / "snapshot.json"
            destination.symlink_to(victim)
            snapshot = self.module.make_snapshot([command_job()])

            with self.assertRaisesRegex(self.module.CronContractError, "non-regular"):
                self.module.write_snapshot(destination, snapshot)
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged\n")

    def test_checked_in_canary_is_fixed_portable_and_provider_free(self) -> None:
        snapshot = self.module.load_snapshot(CANARY_SNAPSHOT)
        self.assertEqual(snapshot["jobs"], [self.module.canary_declaration()])
        job = snapshot["jobs"][0]
        self.assertEqual(job["declarationKey"], "coding-system.restore.scheduler-canary")
        self.assertEqual(job["payload"]["kind"], "command")
        self.assertIn(
            "{{ HOME }}/.local/share/coding-system/repository/bin/scheduler-canary.py",
            job["payload"]["argv"],
        )
        self.assertNotIn("model", job["payload"])

    def test_import_materializes_portable_home_before_cli_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "restored-home"
            executable, state, log = self.make_fake_openclaw(root, [])

            result = self.run_helper(
                executable,
                state,
                log,
                "--home",
                str(home),
                "import",
                "--input",
                str(CANARY_SNAPSHOT),
            )
            jobs = json.loads(state.read_text(encoding="utf-8"))["jobs"]

            self.assertEqual(result.returncode, 0, result.stdout)
            argv = jobs[0]["payload"]["argv"]
            self.assertIn(f"{home}/.local/share/coding-system/repository/bin/scheduler-canary.py", argv)
            self.assertFalse(any("{{ HOME }}" in value for value in argv))

    def test_helper_has_no_database_access_path(self) -> None:
        source = HELPER.read_text(encoding="utf-8").lower()
        self.assertNotIn("import sqlite", source)
        self.assertNotIn(".db", source)
        self.assertIn('["cron", "list", "--all", "--json"]', source)
        self.assertIn('"cron.add"', source)


if __name__ == "__main__":
    unittest.main()
