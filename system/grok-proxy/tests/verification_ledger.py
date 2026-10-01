#!/usr/bin/env python3
"""Run Grok regression cases and maintain an exact JSON-lines result ledger."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import traceback
import unittest


SCHEMA_VERSION = 1
PREFLIGHT_CASES = (
    ("grok.preflight.isolation", "isolation-preflight"),
)
SHELL_CASES = (
    ("grok.shell.p0-baseline", "test_p0_baseline.sh"),
    ("grok.shell.vpngate-input", "test_vpngate_input.sh"),
    ("grok.shell.listener-ownership", "test_listener_ownership.sh"),
    ("grok.shell.ladder", "test_ladder.sh"),
    ("grok.shell.session-lock", "test_session_lock.sh"),
    ("grok.shell.proxy-env", "test_proxy_env.sh"),
    ("grok.shell.diagnostic-safety", "test_diagnostic_safety.sh"),
    ("grok.shell.multi-gate", "test_multi_gate.sh"),
)
PYTHON_SCRIPT_CASES = (
    ("grok.python.socks-relay", "test_socks_relay.py"),
)
UNITTEST_CASES = (
    ("grok.python.ms-core", "test_grok_ms_core.py"),
    ("grok.python.ms-config", "test_grok_ms_config.py"),
    ("grok.python.ios-registry", "test_ios_registry.py"),
    ("grok.python.ms-client", "test_grok_ms_client.py"),
    ("grok.python.managed-profile", "test_managed_profile.py"),
    ("grok.python.rung-admission", "test_rung_admission.py"),
    ("grok.python.ci-delegated-install", "test_ci_delegated_install.py"),
    ("grok.python.bootstrap", "test_bootstrap.py"),
    ("grok.python.bootstrap-publisher", "test_bootstrap_publisher.py"),
    ("grok.python.process-scope", "test_grok_ms_process_scope.py"),
    ("grok.python.ms-frontend", "test_grok_ms_frontend.py"),
    ("grok.python.ms-providers", "test_grok_ms_providers.py"),
    ("grok.python.ms-supervisor", "test_grok_ms_supervisor.py"),
    ("grok.python.live-multi-verify", "test_live_multi_verify.py"),
    ("grok.python.multi-feature-e2e", "test_multi_feature_e2e.py"),
    ("grok.python.vpn-broker", "test_vpn_broker.py"),
    ("grok.python.release-installer", "test_release_installer.py"),
    ("grok.python.install-pipeline", "test_install_pipeline.py"),
    ("grok.python.source-backup-pipeline", "test_source_backup_pipeline.py"),
)

ROOT_CGROUP_SKIP_REASON = "requires explicit root cgroup integration authorization"
ISOLATION_BUS_SKIP_REASON = (
    "requires a second systemd user service; the isolated payload has no live user bus"
)
FORCED_ISOLATION_SKIPS = {
    (
        "grok.python.process-scope",
        "LinuxCgroupV2ScopeTests.test_different_user_service_scope_can_kill_recorded_child_cgroup",
    ): ISOLATION_BUS_SKIP_REASON,
}
ALLOWED_SKIPS = {
    **FORCED_ISOLATION_SKIPS,
    (
        "grok.python.release-installer",
        "ReleaseInstallerTests.test_root_runner_scope_kills_nested_double_forked_setsid_descendant",
    ): ROOT_CGROUP_SKIP_REASON,
    (
        "grok.python.release-installer",
        "ReleaseInstallerTests.test_root_runner_resource_counters_isolate_and_include_nested_tasks",
    ): ROOT_CGROUP_SKIP_REASON,
    (
        "grok.python.release-installer",
        "ReleaseInstallerTests.test_root_runner_test_harness_cleans_failure_immediately_after_create",
    ): ROOT_CGROUP_SKIP_REASON,
    (
        "grok.python.release-installer",
        "ReleaseInstallerTests.test_root_runner_recovers_every_journal_crash_phase",
    ): ROOT_CGROUP_SKIP_REASON,
    (
        "grok.python.release-installer",
        "ReleaseInstallerTests.test_root_runner_recovers_recovery_side_crash_phases",
    ): ROOT_CGROUP_SKIP_REASON,
    (
        "grok.python.release-installer",
        "ReleaseInstallerTests.test_real_target_uid_executes_but_cannot_tamper_with_installed_user_modules",
    ): "passwordless sudo is unavailable for the distinct-UID check",
}

EXPECTED_CASES = tuple(case_id for case_id, _ in (
    *PREFLIGHT_CASES,
    *SHELL_CASES,
    *PYTHON_SCRIPT_CASES,
    *UNITTEST_CASES,
))
UNITTEST_CASE_IDS = frozenset(case_id for case_id, _ in UNITTEST_CASES)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _append_records(ledger: Path, records: list[dict[str, object]]) -> None:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(ledger, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
        ):
            raise RuntimeError("result ledger is not one caller-owned regular file")
        for record in records:
            payload = (_canonical(record) + "\n").encode("ascii")
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise RuntimeError("short write to result ledger")
                view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _record_case(
    ledger: Path,
    case_id: str,
    kind: str,
    status_value: str,
    **extra: object,
) -> None:
    if case_id not in EXPECTED_CASES:
        raise ValueError(f"unknown case ID: {case_id}")
    record: dict[str, object] = {
        "case_id": case_id,
        "kind": kind,
        "record_type": "case",
        "schema_version": SCHEMA_VERSION,
        "status": status_value,
    }
    record.update(extra)
    _append_records(ledger, [record])


def _normalized_test_id(test: unittest.case.TestCase, module_name: str) -> str:
    raw = test.id()
    prefix = module_name + "."
    return raw[len(prefix):] if raw.startswith(prefix) else raw


class _ExactResult(unittest.TextTestResult):
    """Text result that also retains one exact terminal record per test."""

    def __init__(self, *args: object, module_name: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.module_name = module_name
        self.terminal: dict[str, dict[str, object]] = {}

    def _terminal(
        self,
        test: unittest.case.TestCase,
        status_value: str,
        **extra: object,
    ) -> None:
        test_id = _normalized_test_id(test, self.module_name)
        value: dict[str, object] = {"status": status_value}
        value.update(extra)
        self.terminal[test_id] = value

    def addSuccess(self, test: unittest.case.TestCase) -> None:  # noqa: N802
        super().addSuccess(test)
        self._terminal(test, "passed")

    def addFailure(self, test: unittest.case.TestCase, err: object) -> None:  # noqa: N802
        super().addFailure(test, err)
        self._terminal(test, "failed")

    def addError(self, test: unittest.case.TestCase, err: object) -> None:  # noqa: N802
        super().addError(test, err)
        self._terminal(test, "error")

    def addSkip(self, test: unittest.case.TestCase, reason: str) -> None:  # noqa: N802
        super().addSkip(test, reason)
        self._terminal(test, "skipped", skip_reason=reason)

    def addExpectedFailure(  # noqa: N802
        self, test: unittest.case.TestCase, err: object
    ) -> None:
        super().addExpectedFailure(test, err)
        self._terminal(test, "expected-failure")

    def addUnexpectedSuccess(self, test: unittest.case.TestCase) -> None:  # noqa: N802
        super().addUnexpectedSuccess(test)
        self._terminal(test, "unexpected-success")

    def addSubTest(  # noqa: N802
        self,
        test: unittest.case.TestCase,
        subtest: unittest.case._SubTest,
        err: object,
    ) -> None:
        super().addSubTest(test, subtest, err)
        if err is not None:
            parent_id = _normalized_test_id(test, self.module_name)
            self.terminal[parent_id] = {"status": "failed-subtest"}


class _ExactRunner(unittest.TextTestRunner):
    resultclass = _ExactResult

    def __init__(self, *args: object, module_name: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._module_name = module_name

    def _makeResult(self) -> _ExactResult:  # noqa: N802
        return self.resultclass(
            self.stream,
            self.descriptions,
            self.verbosity,
            module_name=self._module_name,
        )


def _run_unittest(case_id: str, ledger: Path, path: Path) -> int:
    expected = dict(UNITTEST_CASES).get(case_id)
    if expected is None or path.name != expected:
        raise ValueError("case ID and unittest file do not match the fixed inventory")
    module_name = "_grok_verify_" + case_id.replace("-", "_").replace(".", "_")
    test_dir = str(path.parent)
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot create an import specification")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        sys.path.insert(0, test_dir)
        try:
            spec.loader.exec_module(module)
        finally:
            if sys.path and sys.path[0] == test_dir:
                del sys.path[0]
    except BaseException as exc:
        traceback.print_exc()
        _record_case(
            ledger,
            case_id,
            "unittest",
            "failed",
            errors=1,
            exception_type=type(exc).__name__,
            failures=0,
            skipped=0,
            tests_run=0,
        )
        return 1

    for (skip_case, test_id), reason in FORCED_ISOLATION_SKIPS.items():
        if skip_case != case_id:
            continue
        class_name, method_name = test_id.split(".", 1)
        test_class = getattr(module, class_name)
        method = getattr(test_class, method_name)
        setattr(test_class, method_name, unittest.skip(reason)(method))

    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    runner = _ExactRunner(verbosity=2, module_name=module_name, stream=sys.stdout)
    result = runner.run(suite)
    assert isinstance(result, _ExactResult)

    allowed_for_case = {
        test_id: reason
        for (allowed_case, test_id), reason in ALLOWED_SKIPS.items()
        if allowed_case == case_id
    }
    observed_skips: dict[str, str] = {}
    unauthorized_skips: list[str] = []
    test_records: list[dict[str, object]] = []
    for test_id, terminal in sorted(result.terminal.items()):
        status_value = str(terminal["status"])
        record: dict[str, object] = {
            "case_id": case_id,
            "record_type": "test",
            "schema_version": SCHEMA_VERSION,
            "status": status_value,
            "test_id": test_id,
        }
        if status_value == "skipped":
            reason = str(terminal["skip_reason"])
            observed_skips[test_id] = reason
            allowed = allowed_for_case.get(test_id) == reason
            record["allowed_skip"] = allowed
            record["skip_reason"] = reason
            if not allowed:
                unauthorized_skips.append(test_id)
        test_records.append(record)

    missing_required_skips = sorted(set(allowed_for_case) - set(observed_skips))
    terminal_failures = sorted(
        test_id
        for test_id, terminal in result.terminal.items()
        if terminal["status"] not in {"passed", "skipped"}
    )
    complete_records = len(result.terminal) == result.testsRun
    passed = (
        result.testsRun > 0
        and result.wasSuccessful()
        and not unauthorized_skips
        and not missing_required_skips
        and not terminal_failures
        and complete_records
    )
    _append_records(ledger, test_records)
    _record_case(
        ledger,
        case_id,
        "unittest",
        "passed" if passed else "failed",
        errors=len(result.errors),
        expected_failures=len(result.expectedFailures),
        failures=len(result.failures),
        missing_required_skips=missing_required_skips,
        skipped=len(result.skipped),
        tests_run=result.testsRun,
        unauthorized_skips=unauthorized_skips,
        unexpected_successes=len(result.unexpectedSuccesses),
    )
    if not passed:
        if unauthorized_skips:
            print(
                "ERROR: undeclared unittest skips: " + ", ".join(unauthorized_skips),
                file=sys.stderr,
            )
        if missing_required_skips:
            print(
                "ERROR: declared isolation skips did not occur: "
                + ", ".join(missing_required_skips),
                file=sys.stderr,
            )
        if not complete_records:
            print("ERROR: unittest result ledger is incomplete", file=sys.stderr)
    return 0 if passed else 1


def _read_ledger_payload(
    path: Path, *, allow_missing: bool = False
) -> tuple[bytes, list[dict[str, object]]]:
    try:
        path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError as exc:
        if allow_missing:
            return b"", []
        raise RuntimeError("result ledger is unavailable") from exc
    except OSError as exc:
        raise RuntimeError("result ledger is unavailable") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_uid, info.st_gid) != (os.geteuid(), os.getegid())
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > 16 * 1024 * 1024
        ):
            raise RuntimeError("result ledger has an unsafe identity, mode, or size")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > 16 * 1024 * 1024:
                raise RuntimeError("result ledger exceeds its size bound")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if raw and not raw.endswith(b"\n"):
        raise RuntimeError("result ledger is not newline terminated")
    records: list[dict[str, object]] = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        if len(line) > 2 * 1024 * 1024:
            raise RuntimeError(f"oversized ledger record at line {line_number}")
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"invalid ledger JSON at line {line_number}") from exc
        if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
            raise RuntimeError(f"invalid ledger record at line {line_number}")
        records.append(value)
    return raw, records


def _read_ledger(path: Path) -> list[dict[str, object]]:
    return _read_ledger_payload(path)[1]


def _validate_partial_records(records: list[dict[str, object]]) -> None:
    case_records = [record for record in records if record.get("record_type") == "case"]
    test_records = [record for record in records if record.get("record_type") == "test"]
    if len(case_records) + len(test_records) != len(records):
        raise RuntimeError("partial ledger contains an unknown record type")
    observed_case_order = [record.get("case_id") for record in case_records]
    if observed_case_order != list(EXPECTED_CASES[: len(observed_case_order)]):
        raise RuntimeError("partial ledger is not a prefix of the fixed case inventory")
    if any(record.get("status") not in {"passed", "failed"} for record in case_records):
        raise RuntimeError("partial ledger contains an invalid case status")
    seen_tests: set[tuple[str, str]] = set()
    terminal_statuses = {
        "passed",
        "skipped",
        "failed",
        "error",
        "expected-failure",
        "unexpected-success",
        "failed-subtest",
    }
    for record in test_records:
        case_id = record.get("case_id")
        test_id = record.get("test_id")
        if case_id not in UNITTEST_CASE_IDS or not isinstance(test_id, str) or not test_id:
            raise RuntimeError("partial ledger contains an invalid unittest identity")
        case_index = EXPECTED_CASES.index(str(case_id))
        if case_index > len(case_records):
            raise RuntimeError("partial ledger contains a test beyond its case prefix")
        identity = (str(case_id), test_id)
        if identity in seen_tests:
            raise RuntimeError("partial ledger contains a duplicate unittest identity")
        seen_tests.add(identity)
        status_value = record.get("status")
        if status_value not in terminal_statuses:
            raise RuntimeError("partial ledger contains an invalid unittest status")
        if status_value == "skipped":
            reason = record.get("skip_reason")
            if (
                record.get("allowed_skip") is not True
                or not isinstance(reason, str)
                or ALLOWED_SKIPS.get(identity) != reason
            ):
                raise RuntimeError("partial ledger contains an unauthorized skip")


def _validate_output_directory(path: Path) -> None:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise RuntimeError("result output directory is not one canonical absolute path")
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or (info.st_uid, info.st_gid) != (os.geteuid(), os.getegid())
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_nlink != 2
        or any(path.iterdir())
    ):
        raise RuntimeError("result output directory has an unsafe identity, mode, or contents")


def _write_published_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("short write while publishing result artifact")
            view = view[written:]
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_uid, info.st_gid) != (os.geteuid(), os.getegid())
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise RuntimeError("published result artifact has an unsafe identity or mode")
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish(ledger: Path, output: Path, outcome: str, returncode: int) -> int:
    if (outcome == "passed") != (returncode == 0):
        raise RuntimeError("result outcome and runner return code are incoherent")
    _validate_output_directory(output)
    raw, records = _read_ledger_payload(
        ledger, allow_missing=outcome == "failed"
    )
    if outcome == "passed":
        _verify(ledger)
    else:
        _validate_partial_records(records)
    case_records = [record for record in records if record.get("record_type") == "case"]
    test_records = [record for record in records if record.get("record_type") == "test"]
    allowed_skips = sum(record.get("status") == "skipped" for record in test_records)
    final_name = "passed" if outcome == "passed" else "failed"
    ledger_name = (
        "grok-test-results.jsonl"
        if outcome == "passed"
        else "grok-test-results.partial.jsonl"
    )
    summary_name = (
        "grok-test-summary.json"
        if outcome == "passed"
        else "grok-test-summary.partial.json"
    )
    final = output / final_name
    ledger_path = final / ledger_name
    summary_path = final / summary_name
    digest = hashlib.sha256(raw).hexdigest()
    summary = {
        "allowed_skips": allowed_skips,
        "case_records": len(case_records),
        "complete": outcome == "passed",
        "expected_cases": len(EXPECTED_CASES),
        "ledger_bytes": len(raw),
        "ledger_path": str(ledger_path),
        "ledger_records": len(records),
        "ledger_sha256": digest,
        "run_returncode": returncode,
        "schema_version": SCHEMA_VERSION,
        "status": outcome,
        "test_records": len(test_records),
    }
    staging = Path(tempfile.mkdtemp(prefix=".pending-", dir=output))
    try:
        staging_info = staging.lstat()
        if (
            not stat.S_ISDIR(staging_info.st_mode)
            or (staging_info.st_uid, staging_info.st_gid)
            != (os.geteuid(), os.getegid())
            or stat.S_IMODE(staging_info.st_mode) != 0o700
            or staging_info.st_nlink != 2
        ):
            raise RuntimeError("result staging directory has an unsafe identity or mode")
        _write_published_file(staging / ledger_name, raw)
        _write_published_file(
            staging / summary_name, (_canonical(summary) + "\n").encode("ascii")
        )
        _fsync_directory(staging)
        os.rename(staging, final)
        _fsync_directory(output)
        output_info = output.lstat()
        final_info = final.lstat()
        if (
            output_info.st_nlink != 3
            or final_info.st_nlink != 2
            or stat.S_IMODE(final_info.st_mode) != 0o700
            or (final_info.st_uid, final_info.st_gid)
            != (os.geteuid(), os.getegid())
            or {entry.name for entry in final.iterdir()} != {ledger_name, summary_name}
        ):
            raise RuntimeError("atomically published result directory is not exact")
    except BaseException:
        for name in (ledger_name, summary_name):
            try:
                (staging / name).unlink()
            except FileNotFoundError:
                pass
        try:
            staging.rmdir()
        except FileNotFoundError:
            pass
        raise
    print(_canonical({
        "case_id": "grok.ledger.publish",
        "ledger_path": str(ledger_path),
        "ledger_sha256": digest,
        "schema_version": SCHEMA_VERSION,
        "status": outcome,
        "summary_path": str(summary_path),
    }))
    return 0


def _verify(ledger: Path) -> int:
    records = _read_ledger(ledger)
    case_records = [record for record in records if record.get("record_type") == "case"]
    test_records = [record for record in records if record.get("record_type") == "test"]
    if len(case_records) + len(test_records) != len(records):
        raise RuntimeError("ledger contains an unknown record type")
    observed_case_order = [str(record.get("case_id")) for record in case_records]
    if observed_case_order != list(EXPECTED_CASES):
        raise RuntimeError("ledger case inventory or order differs from the fixed inventory")
    if any(record.get("status") != "passed" for record in case_records):
        raise RuntimeError("one or more fixed regression cases failed")

    seen_tests: set[tuple[str, str]] = set()
    observed_skips: dict[tuple[str, str], str] = {}
    counts: dict[str, int] = {case_id: 0 for case_id in UNITTEST_CASE_IDS}
    for record in test_records:
        case_id = record.get("case_id")
        test_id = record.get("test_id")
        if case_id not in UNITTEST_CASE_IDS or not isinstance(test_id, str) or not test_id:
            raise RuntimeError("ledger contains an invalid unittest identity")
        identity = (str(case_id), test_id)
        if identity in seen_tests:
            raise RuntimeError("ledger contains a duplicate unittest identity")
        seen_tests.add(identity)
        counts[str(case_id)] += 1
        status_value = record.get("status")
        if status_value == "skipped":
            reason = record.get("skip_reason")
            if record.get("allowed_skip") is not True or not isinstance(reason, str):
                raise RuntimeError("ledger contains an unauthorized skip")
            observed_skips[identity] = reason
        elif status_value != "passed":
            raise RuntimeError("ledger contains a non-passing unittest result")

    for record in case_records:
        case_id = str(record["case_id"])
        if case_id in UNITTEST_CASE_IDS:
            tests_run = record.get("tests_run")
            if type(tests_run) is not int or tests_run <= 0 or counts[case_id] != tests_run:
                raise RuntimeError("unittest aggregate and exact result counts differ")
    if observed_skips != ALLOWED_SKIPS:
        raise RuntimeError("observed skip ledger differs from the exact allowed-skip policy")

    print(_canonical({
        "allowed_skips": len(observed_skips),
        "case_id": "grok.ledger.verify",
        "cases": len(case_records),
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "tests": len(test_records),
    }))
    return 0


def _selftest() -> int:
    case_ids = [
        case_id
        for case_id, _ in (
            *PREFLIGHT_CASES,
            *SHELL_CASES,
            *PYTHON_SCRIPT_CASES,
            *UNITTEST_CASES,
        )
    ]
    if len(case_ids) != len(set(case_ids)) or tuple(case_ids) != EXPECTED_CASES:
        raise RuntimeError("case inventory is not unique and stable")
    base = Path(__file__).resolve().parent
    expected_python_files = {
        filename for _case_id, filename in (*PYTHON_SCRIPT_CASES, *UNITTEST_CASES)
    }
    actual_python_files = {path.name for path in base.glob("test_*.py")}
    expected_shell_files = {filename for _case_id, filename in SHELL_CASES}
    actual_shell_files = {path.name for path in base.glob("test_*.sh")}
    if actual_python_files != expected_python_files:
        raise RuntimeError("Python test files differ from the fixed case inventory")
    if actual_shell_files != expected_shell_files:
        raise RuntimeError("shell test files differ from the fixed case inventory")
    for _case_id, filename in (*SHELL_CASES, *PYTHON_SCRIPT_CASES, *UNITTEST_CASES):
        if not (base / filename).is_file():
            raise RuntimeError(f"fixed case file is missing: {filename}")
    unittest_files = dict(UNITTEST_CASES)
    parsed_methods: dict[str, set[str]] = {}
    for case_id, filename in UNITTEST_CASES:
        tree = ast.parse((base / filename).read_text(encoding="utf-8"), filename)
        parsed_methods[case_id] = {
            f"{node.name}.{child.name}"
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name.startswith("test_")
        }
    for (case_id, test_id), reason in ALLOWED_SKIPS.items():
        if case_id not in UNITTEST_CASE_IDS or test_id.count(".") != 1 or not reason:
            raise RuntimeError("allowed-skip policy is malformed")
        if case_id not in unittest_files or test_id not in parsed_methods[case_id]:
            raise RuntimeError("allowed-skip test ID is absent from the fixed source")
    print("verification-ledger: selftest passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument(
        "--kind", choices=("shell", "python-script", "unittest"), required=True
    )

    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("--ledger", type=Path, required=True)
    record_parser.add_argument("--case-id", required=True)
    record_parser.add_argument(
        "--kind", choices=("preflight", "shell", "python-script"), required=True
    )
    record_parser.add_argument("--status", choices=("passed", "failed"), required=True)
    record_parser.add_argument("--returncode", type=int)

    run_parser = subparsers.add_parser("run-unittest")
    run_parser.add_argument("--ledger", type=Path, required=True)
    run_parser.add_argument("--case-id", required=True)
    run_parser.add_argument("--path", type=Path, required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--ledger", type=Path, required=True)

    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument("--ledger", type=Path, required=True)
    publish_parser.add_argument("--output-dir", type=Path, required=True)
    publish_parser.add_argument("--outcome", choices=("passed", "failed"), required=True)
    publish_parser.add_argument("--returncode", type=int, required=True)

    subparsers.add_parser("selftest")
    args = parser.parse_args()

    if args.command == "list":
        inventory = {
            "shell": SHELL_CASES,
            "python-script": PYTHON_SCRIPT_CASES,
            "unittest": UNITTEST_CASES,
        }[args.kind]
        for case_id, filename in inventory:
            print(f"{case_id}\t{filename}")
        return 0
    if args.command == "record":
        extra: dict[str, object] = {}
        if args.returncode is not None:
            extra["returncode"] = args.returncode
        _record_case(args.ledger, args.case_id, args.kind, args.status, **extra)
        return 0
    if args.command == "run-unittest":
        return _run_unittest(args.case_id, args.ledger, args.path.resolve())
    if args.command == "verify":
        return _verify(args.ledger)
    if args.command == "publish":
        return _publish(
            args.ledger,
            args.output_dir,
            args.outcome,
            args.returncode,
        )
    return _selftest()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"verification-ledger: {exc}", file=sys.stderr)
        raise SystemExit(2)
