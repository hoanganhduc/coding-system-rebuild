#!/usr/bin/env python3
"""Deterministic safety tests for the grok-proxy release installer."""

from __future__ import annotations

from contextlib import redirect_stdout
import fcntl
import errno
import hashlib
import io
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import pwd
import select
import signal
import shutil
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
from grok_ms import qualification_verifier, release_admission
from grok_ms.contract import (
    CONTRACT_SCHEMA_VERSION,
    PROTOCOL_VERSION,
    Endpoint,
    ResourceLimits,
    RouteContract,
    RouteMode,
    StabilityPolicy,
    TimeoutPolicy,
    VpnPolicy,
)
from grok_ms.grok_exec import grok_release_id
from grok_ms.managed_profile import (
    ActivationCommitUncertain,
    ActivationRecord,
    ManagedProfile,
    ReadinessPolicy,
    load_activation_record,
    write_content_addressed_profile,
)

MODULE_PATH = ROOT / "install-release.py"
SPEC = importlib.util.spec_from_file_location("grok_release_installer", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
release_installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_installer)

BROKER_LOADER = SourceFileLoader(
    "grok_release_installer_broker", str(ROOT / "vpn-broker")
)
BROKER_SPEC = importlib.util.spec_from_loader(BROKER_LOADER.name, BROKER_LOADER)
assert BROKER_SPEC is not None and BROKER_SPEC.loader is not None
broker_module = importlib.util.module_from_spec(BROKER_SPEC)
sys.modules[BROKER_LOADER.name] = broker_module
BROKER_SPEC.loader.exec_module(broker_module)


RUNTIME_FILES = (
    "install-release.py",
    "grok-remote",
    "egress.sh",
    "vpn-broker",
    "vpngate-connect.sh",
    "socks-netns.py",
    "sanitize.awk",
    "grok_ms/__init__.py",
    "grok_ms/managed_profile.py",
    "grok_ms/release_admission.py",
    "grok_ms/rung_admission.py",
    "grok_ms/core.py",
    "grok_ms/supervisor.py",
    "grok_ms/nested/worker.py",
    "grok_ms/qualification_fake_grok.py",
    "grok_ms/qualification_verifier.py",
)
ROOT_FILES = {
    "broker": "vpn-broker",
    "vpngate": "vpngate-connect.sh",
    "relay": "socks-netns.py",
    "sanitizer": "sanitize.awk",
}
EXECUTABLES = {
    "grok-remote",
    "egress.sh",
    "vpn-broker",
    "vpngate-connect.sh",
    "socks-netns.py",
    "grok_ms/qualification_fake_grok.py",
}
CANARY_FIXTURE = (
    'if [ "${GROK_RELEASE_CANARY_MODE:-0}" = 1 ]; then\n'
    '  printf "fixture-canary:%s\\n" "$1"\n'
    "  exit 0\n"
    "fi\n"
)


def write_source(
    source: Path, version: str, *, bootstrap_migration: bool = True
) -> None:
    source.mkdir(parents=True, exist_ok=True)
    for name in RUNTIME_FILES:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if name == "install-release.py":
            shutil.copyfile(MODULE_PATH, path)
            path.chmod(0o644)
            continue
        if name == "grok-remote":
            text = (
                "#!/bin/bash\n"
                'SELF="$(/usr/bin/readlink -f "${BASH_SOURCE[0]}")"\n'
                'DIR="$(cd "$(/usr/bin/dirname "$SELF")" && pwd -P)"\n'
                "RELEASE_CANARY=0\n"
                '[[ "${GROK_RELEASE_CANARY_MODE:-0}" == 1 ]] && RELEASE_CANARY=1\n'
                + release_installer.GROK_SELF_ADMISSION_BLOCK.decode("ascii")
                # The fixture runs only behind the generated gate, which is
                # the admission boundary under test.  Do not make it depend
                # on a live host's production install lock as a second gate.
                + "RELEASE_ADMITTED=1\n"
                + release_installer.GROK_ORDINARY_ADMISSION_BLOCK.decode("ascii")
                + CANARY_FIXTURE
                + f"printf 'grok-remote:{version}:%s\\n' \"$*\"\n"
            )
        elif name == "egress.sh":
            text = (
                "#!/bin/bash\n"
                'EG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
                + release_installer.EGRESS_ADMISSION_BLOCK.decode("ascii")
                + f"printf 'egress.sh:{version}:%s\\n' \"$*\"\n"
            )
        elif name == "vpn-broker":
            bootstrap = (
                'if [ "${1:-}" = --release-bootstrap-migrate ]; then\n'
                '  printf \'{"active":false,"migrated":false,"ok":true,'
                '"post_root_artifact_residue":false,'
                '"pre_root_artifact_residue":false,"release_id":"%s"}\\n\' '
                '"${GROK_RELEASE_INVENTORY_RELEASE_ID}"\n'
                "  exit 0\n"
                "fi\n"
                if bootstrap_migration
                else ""
            )
            text = (
                "#!/bin/sh\n"
                'if [ "${1:-}" = --release-root-inventory ]; then\n'
                '  printf \'{"active":false,"host_tun_alive":false,"ledger":null,'
                '"namespace_alive":false,"ok":true,"relay_alive":false,'
                '"release_id":"%s","root_artifact_residue":false,'
                '"root_files":{"broker":"vpn-broker","relay":"socks-netns.py",'
                '"sanitizer":"sanitize.awk","vpngate":"vpngate-connect.sh"},'
                '"tun_alive":false,"vpn_alive":false}\\n\' '
                '"${GROK_RELEASE_INVENTORY_RELEASE_ID}"\n'
                "  exit 0\n"
                "fi\n"
                + bootstrap
                + f"printf 'vpn-broker:{version}:%s:evil=%s\\n' "
                + '"$*" "${EVIL-unset}"\n'
            )
        elif name == "grok_ms/qualification_fake_grok.py":
            text = "#!/usr/bin/python3\nraise SystemExit(0)\n"
        elif name == "grok_ms/qualification_verifier.py":
            text = "# fixture qualification verifier\n"
        elif name == "grok_ms/release_admission.py":
            text = (
                "# fcntl.flock(lock_fd, fcntl.LOCK_SH)\n"
                "# rollback-deny.json\n"
                "# selected-release.json\n"
            )
        elif name == "grok_ms/__init__.py":
            text = f"# fixture package {version}\n"
        elif name == "grok_ms/supervisor.py":
            text = f'''# fixture supervisor {version}
import argparse
from pathlib import Path
import signal
import time

parser = argparse.ArgumentParser()
parser.add_argument("--release-dir", required=True)
parser.add_argument("--control-root", required=True, type=Path)
parser.add_argument("--expected-contract", required=True)
parser.add_argument("--expected-control-cap", required=True)
parser.add_argument("--warm-legacy-handoff", action="store_true")
parser.add_argument("--scoped-bootstrap", action="store_true")
args = parser.parse_args()
marker = args.control_root / "fake-supervisor-ready"
marker.write_text("ready", encoding="ascii")

def stop(_signum, _frame):
    time.sleep(0.25)
    for name in ("recovery.fence", "supervisor.sock", "supervisor.ready", marker.name):
        try:
            (args.control_root / name).unlink()
        except FileNotFoundError:
            pass
    raise SystemExit(0)

signal.signal(signal.SIGTERM, stop)
while True:
    signal.pause()
'''
        else:
            text = f"{name}:{version}\n"
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755 if name in EXECUTABLES else 0o644)


def write_default_source(source: Path, version: str) -> None:
    write_source(source, version)
    # The direct-test manifest has exactly the same declared production names.
    # Add excluded material to prove default discovery is closed.
    (source / "untrusted-extra.py").write_text("do not ship\n", encoding="utf-8")
    (source / "tests").mkdir(exist_ok=True)
    (source / "tests/private.py").write_text("do not ship\n", encoding="utf-8")
    cache = source / "grok_ms/__pycache__"
    cache.mkdir(exist_ok=True)
    (cache / "core.cpython-312.pyc").write_bytes(b"cache")
    (source / "grok_ms/.private.py").write_text("do not ship\n", encoding="utf-8")
    package_tests = source / "grok_ms/tests"
    package_tests.mkdir(exist_ok=True)
    (package_tests / "test_private.py").write_text("do not ship\n", encoding="utf-8")


def write_canary_sensitive_source(
    source: Path,
    version: str,
    *,
    fail_command: str | None = None,
    fail_marker: Path | None = None,
    flood_command: str | None = None,
) -> None:
    write_source(source, version)
    conditions: list[str] = []
    if fail_command is not None:
        conditions.append(f'[[ "$1" == {fail_command!r} ]]')
    if fail_marker is not None:
        conditions.append(f'[[ -e {str(fail_marker)!r} ]]')
    failure = " || ".join(conditions) or "false"
    flood = (
        f'if [[ "$1" == {flood_command!r} ]]; then '
        "exec /usr/bin/python3 -c 'import sys; sys.stdout.write(\"X\" * 300000)'; fi\n"
        if flood_command is not None
        else ""
    )
    target = source / "grok-remote"
    target.write_text(
        "#!/bin/bash\n"
        'if [[ "${GROK_RELEASE_CANARY_MODE:-0}" == 1 ]]; then\n'
        + flood
        + f"  if {failure}; then exit 42; fi\n"
        + '  printf "fixture-canary:%s\\n" "$1"\n'
        + "  exit 0\n"
        + "fi\n"
        + f"printf 'grok-remote:{version}:%s\\n' \"$*\"\n",
        encoding="ascii",
    )
    target.chmod(0o755)


def make_installer(
    base: Path,
    *,
    proc_authority: object | None = None,
) -> tuple[object, object, Path]:
    source = base / "source"
    write_source(source, "v1")
    home = base / "home"
    layout = release_installer.Layout(
        source_dir=source,
        user_root=home / ".local/lib/grok-proxy",
        root_root=base / "root/usr/local/libexec/grok-proxy",
        root_state_root=base / "root/var/lib/grok-proxy/release-control",
        state_root=home / ".local/state/grok-proxy/release-control",
        entrypoint=home / ".local/bin/grok-remote",
        test_install=True,
    )
    installer = release_installer.ReleaseInstaller(
        layout,
        runtime_files=RUNTIME_FILES,
        root_files=ROOT_FILES,
        proc_authority=proc_authority,
    )
    return installer, layout, source


def write_proc_fixture(prefix: Path) -> tuple[Path, str, int]:
    """Project the bounded proc records used by prefix-trust tests."""

    root = prefix / "proc-fixture"
    pid = os.getpid()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="ascii"
    ).strip()
    for directory in (
        root / "sys/kernel/random",
        root / "self/net",
        root / str(pid),
    ):
        directory.mkdir(parents=True, mode=0o755, exist_ok=True)
    (root / "sys/kernel/random/boot_id").write_text(
        boot_id + "\n", encoding="ascii"
    )
    (root / "self/cgroup").write_text("0::/\n", encoding="ascii")
    socket_header = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
        "retrnsmt   uid  timeout inode\n"
    )
    for name in ("tcp", "tcp6"):
        (root / "self/net" / name).write_text(socket_header, encoding="ascii")
    process = root / str(pid)
    for name in ("stat", "status", "cmdline"):
        (process / name).write_bytes((Path("/proc") / str(pid) / name).read_bytes())
    for name in ("cwd", "exe"):
        (process / name).symlink_to(os.readlink(f"/proc/{pid}/{name}"))
    return root, boot_id, pid


def cgroup_proc_authority(root: Path, membership: str) -> object:
    fixture = root / "proc-fixture"
    (fixture / "self").mkdir(parents=True, mode=0o755)
    (fixture / "self/cgroup").write_text(membership, encoding="ascii")
    descriptor = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return release_installer.ProcAuthority.from_fd(
            descriptor, display=fixture, fixture=True
        )
    finally:
        os.close(descriptor)


def make_activation_profile(
    base: Path,
    release_id: str,
) -> tuple[ManagedProfile, Path]:
    grok = base / "grok-0.2.103-linux-aarch64"
    grok.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="ascii")
    grok.chmod(0o700)
    contract = RouteContract(
        schema_version=CONTRACT_SCHEMA_VERSION,
        protocol_version=PROTOCOL_VERSION,
        release_id=release_id,
        model_id="vendor/model-1",
        route_mode=RouteMode.AUTO,
        forced_host=None,
        home_endpoints=(),
        ios_endpoints=(),
        forced_ios_key=None,
        allow_direct=True,
        ladder=("direct",),
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
    return (
        ManagedProfile.create(
            contract,
            grok,
            ReadinessPolicy(1, ("direct",)),
        ),
        grok,
    )


def write_attested_rung_evidence(
    path: Path,
    installer: object,
    release_id: str,
    *,
    rung: str,
    contract_sha256: str,
    grok_release_id: str,
) -> dict[str, object]:
    canary = installer._read_rung_canary()
    transcript_sha256s = installer._rung_transcript_digests(
        release_id=release_id,
        nonce=str(canary["canary_nonce"]),
        rung=rung,
        contract_sha256=contract_sha256,
        grok_release_id=grok_release_id,
        require_success=True,
    )
    result_sha256 = hashlib.sha256(
        release_installer._canonical_json(
            {
                "canary_nonce": canary["canary_nonce"],
                "transcript_sha256s": transcript_sha256s,
            }
        )
        + b"\n"
    ).hexdigest()
    value = {
        "schema_version": release_installer.RUNG_EVIDENCE_SCHEMA_VERSION,
        "release_id": release_id,
        "host_id": installer._host_id(),
        "rung": rung,
        "route_profile": canary["route_profile"],
        "contract_sha256": contract_sha256,
        "rung_qualification_sha256": "b" * 64,
        "grok_release_id": grok_release_id,
        "canary_nonce": canary["canary_nonce"],
        "transcript_sha256s": transcript_sha256s,
        "measured_unix_ns": time.time_ns(),
        "measurements": {
            "duration_ms": 1234,
            "fault_load_canary_verified": True,
            "host_limits_verified": True,
            "result_sha256": result_sha256,
            "post_repair_reconnect_cache_execution_units_verified": True,
            "shared_route": True,
            "teardown_clean": True,
            "transport_timing_verified": True,
            "two_sessions": True,
        },
        "overall_pass": True,
    }
    path.write_bytes(release_installer._canonical_json(value) + b"\n")
    path.chmod(0o400)
    return value


def fixed_qualification_smoke(
    installer: object,
    step: str,
    *,
    status: str = "passed",
    rung_qualification_sha256: str = "b" * 64,
) -> object:
    canary = installer._read_rung_canary()
    resource_contract = release_installer._qualification_resource_contract(step)
    expected_processes = resource_contract["expected_owned_processes"]
    observed_cgroup_pids = 202 if step == "load32" else expected_processes
    resource_evidence = {
        "host_limits_sha256": "f" * 64,
        "resource_contract": resource_contract,
        "resource_observed": {
            "peak_owned_processes": expected_processes,
            "peak_owned_fds": expected_processes * 3,
            "peak_owned_threads": expected_processes,
            "peak_owned_vmrss_kib": expected_processes * 1024,
            "peak_owned_vmsize_kib": expected_processes * 4096,
            "cgroup_pids_delta": observed_cgroup_pids,
            "cgroup_memory_delta_bytes": expected_processes * 1024 * 1024,
            "cgroup_pids_highwater_delta": observed_cgroup_pids,
            "cgroup_memory_highwater_delta_bytes": expected_processes * 1024 * 1024,
            "memory_event_delta_total": 0,
            "pids_event_delta_total": 0,
            "post_owned_processes": 0,
            "post_owned_fds": 0,
            "post_owned_threads": 0,
            "post_owned_vmrss_kib": 0,
            "post_owned_vmsize_kib": 0,
            "post_pids_delta": 0,
            "post_memory_delta_bytes": 0,
        },
    } if step in release_installer.QUALIFICATION_STEPS else {}
    common = {
        "schema_version": release_installer.QUALIFICATION_RESULT_SCHEMA_VERSION,
        "kind": "grok-multi-session-qualification",
        "step": step,
        "release_id": canary["release_id"],
        "canary_nonce": canary["canary_nonce"],
        "canary_kind": canary["canary_kind"],
        "rung": canary["rung"],
        "route_profile": canary["route_profile"],
        "contract_sha256": canary["contract_sha256"] or "c" * 64,
        "grok_release_id": canary["grok_release_id"],
        "model_id": canary["model_id"],
        "profile_sha256": canary.get("profile_sha256"),
        "status": status,
        "started_unix_ns": time.time_ns(),
        "completed_unix_ns": time.time_ns() + 1,
        "duration_ms": 10,
        "error_code": (
            None
            if status == "passed"
            else (
                f"{step}-blocked"
                if status == "blocked"
                else f"{step}-internal"
            )
        ),
        "error_sha256": None if status == "passed" else "e" * 64,
    }
    if step == "load32":
        observations = {
            **resource_evidence,
            "clients_requested": 32,
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
            "ready_duration_ms": 5,
            "detail_sha256": "d" * 64,
        }
    elif step == "fault-recovery":
        observations = {
            **resource_evidence,
            "active_rung": "direct",
            "supervisor_loss_exact": True,
            "wrapper_failed_closed": True,
            "descendant_contained": True,
            "first_recovery_applied": True,
            "second_recovery_noop": True,
            "recovery_duration_ms": 5,
            "resource_gate_passed": True,
            "cleanup_proved": True,
            "detail_sha256": "d" * 64,
        }
    else:
        observations = {
            "sessions_requested": 2,
            "sessions_completed": 2,
            "active_rung": canary["rung"],
            "rung_qualification_sha256": rung_qualification_sha256,
            "model_id": canary["model_id"],
            "shared_owner_epoch": True,
            "shared_generation": True,
            "shared_contract": True,
            "independent_grok_units": 2,
            "shared_leader_disabled": True,
            "leader_socket_count": 0,
            "unique_session_ids": 2,
            "outputs_valid": True,
            "exit_codes_zero": True,
            "cache_before_valid": True,
            "cache_during_valid": True,
            "cache_after_valid": True,
            "cache_identity_safe": True,
            "provider_fault_authenticated": True,
            "single_repair_observed": True,
            "clients_survived_repair": True,
            "reconnect_duration_ms": 5,
            "transport_duration_ms": 9,
            "cleanup_proved": True,
            "detail_sha256": "d" * 64,
            "blocked_reason": None,
        }
    value = {**common, "observations": observations}
    raw = release_installer._canonical_json(value) + b"\n"
    return release_installer.SmokeResult(
        {"passed": 0, "failed": 2, "blocked": 3}[status],
        raw,
        b"",
        10,
    )


def invoke(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(path), *args],
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )


def process_is_running(pid: int) -> bool:
    """Return whether a PID still represents a running, non-zombie process."""

    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (FileNotFoundError, ProcessLookupError):
        return False
    close = raw.rfind(")")
    if close < 0:
        raise AssertionError("fixture process stat is malformed")
    fields = raw[close + 1 :].split()
    if not fields:
        raise AssertionError("fixture process stat has no state")
    return fields[0] != "Z"


def wait_process_stopped(pid: int, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while process_is_running(pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    return not process_is_running(pid)


def tree_snapshot(root: Path) -> dict[str, tuple[int, bytes, str]]:
    result: dict[str, tuple[int, bytes, str]] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISREG(info.st_mode):
            data, kind = path.read_bytes(), "file"
        elif stat.S_ISLNK(info.st_mode):
            data, kind = os.readlink(path).encode(), "link"
        else:
            data, kind = b"", "dir"
        result[rel] = (mode, data, kind)
    return result


def start_fake_fenced_supervisor(layout: object, release_id: str) -> subprocess.Popen[bytes]:
    layout.multi_control.mkdir(parents=True, mode=0o700, exist_ok=True)
    layout.multi_control.chmod(0o700)
    release_dir = layout.user_releases / release_id
    process = subprocess.Popen(
        [
            "/usr/bin/python3", "-E", "-s", "-m", "grok_ms.supervisor",
            "--release-dir", str(release_dir),
            "--control-root", str(layout.multi_control),
            "--expected-contract", "a" * 64,
            "--expected-control-cap", "3",
            "--scoped-bootstrap",
            "--warm-legacy-handoff",
        ],
        cwd=release_dir,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    marker = layout.multi_control / "fake-supervisor-ready"
    deadline = time.monotonic() + 5
    while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    if not marker.exists():
        process.kill()
        process.wait(timeout=5)
        raise AssertionError("fixture supervisor did not start")
    fence = {
        "schema_version": release_installer.CONTROL_SCHEMA_VERSION,
        "release_id": release_id,
        "owner_epoch": "fixture-owner-epoch",
        "pid": process.pid,
        "pid_start_ticks": release_installer.ReleaseInstaller._proc_start_ticks(process.pid),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
        "phase": "READY",
    }
    layout.recovery_fence.write_text(
        json.dumps(fence, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    layout.recovery_fence.chmod(0o600)
    (layout.multi_control / "supervisor.sock").write_bytes(b"fixture")
    return process


def complete_release_qualification(installer: object, release_id: str) -> None:
    installer.begin_release_qualification(release_id=release_id)
    with mock.patch.object(
        installer,
        "_run_qualification_verifier",
        side_effect=lambda **kw: fixed_qualification_smoke(
            installer, str(kw["step"])
        ),
    ):
        installer.qualification_exec("load32")
        installer.qualification_exec("fault-recovery")


def prepare_activatable_profile(
    base: Path,
    installer: object,
    layout: object,
    release_id: str,
) -> tuple[ManagedProfile, Path]:
    profile, grok = make_activation_profile(base, release_id)
    write_content_addressed_profile(
        layout.profile_root,
        profile,
        owner_uid=layout.target_uid,
        owner_gid=layout.target_gid,
    )
    complete_release_qualification(installer, release_id)
    installer.begin_rung_canary(
        release_id=release_id,
        rung="direct",
        profile_sha256=profile.digest(),
    )
    projection = profile.contract.rung_qualification_digest("direct")
    with mock.patch.object(
        installer,
        "_run_qualification_verifier",
        side_effect=lambda **kw: fixed_qualification_smoke(
            installer,
            str(kw["step"]),
            rung_qualification_sha256=projection,
        ),
    ):
        installer.qualification_exec("real-pair")
    installer.promote_rung()
    return profile, grok


def prepare_promotable_rung(
    installer: object,
    release_id: str,
    *,
    route_profile: str = "direct",
) -> dict[str, object]:
    complete_release_qualification(installer, release_id)
    installer.begin_rung_canary(
        release_id=release_id,
        rung="direct",
        route_profile=route_profile,
        contract_sha256="a" * 64,
        grok_release_id="grok-build-v1",
        model_id="vendor/model-1",
    )
    canary = installer._read_rung_canary()
    with mock.patch.object(
        installer,
        "_run_qualification_verifier",
        side_effect=lambda **kw: fixed_qualification_smoke(
            installer, str(kw["step"])
        ),
    ):
        installer.qualification_exec("real-pair")
    return canary


class ReleaseInstallerTests(unittest.TestCase):
    def test_process_is_running_treats_procfs_esrch_as_stopped(self) -> None:
        error = ProcessLookupError(errno.ESRCH, "No such process")
        with mock.patch.object(Path, "read_text", side_effect=error):
            self.assertFalse(process_is_running(12345))

    def test_invocation_lane_rejects_commands_and_explicit_options_before_discovery(
        self,
    ) -> None:
        installed = (
            Path("/usr/local/libexec/grok-proxy/releases")
            / ("a" * 64)
            / "install-release.py"
        )
        cases = (
            (installed, ["install"], "installed"),
            (
                installed,
                ["status", "--source", str(installed.parent)],
                "explicit",
            ),
            (
                Path("/usr/local/libexec/grok-proxy/current/install-release.py"),
                ["status"],
                "lexically concrete release path",
            ),
            (
                Path("/usr/local/libexec/grok-proxy/releases")
                / ("a" * 64)
                / ".."
                / ("a" * 64)
                / "install-release.py",
                ["status"],
                "lexically concrete release path",
            ),
            (
                MODULE_PATH,
                ["begin-release-qualification", "--release-id", "a" * 64, "--apply"],
                "native bootstrap authority",
            ),
            (MODULE_PATH, ["install", "--apply"], "native bootstrap authority"),
            (
                Path.home()
                / ".local/lib/grok-proxy/releases"
                / ("a" * 64)
                / "install-release.py",
                ["rollback", "--release-id", "a" * 64, "--apply"],
                "native bootstrap authority",
            ),
            (MODULE_PATH, ["plan", "--release-id", "a" * 64], "authority"),
        )
        for executable, argv, message in cases:
            with (
                self.subTest(executable=executable, argv=argv),
                mock.patch.object(release_installer, "__file__", str(executable)),
                mock.patch.object(
                    release_installer,
                    "_default_runtime_files",
                    side_effect=AssertionError("source discovery ran"),
                ),
                self.assertRaisesRegex(release_installer.ReleaseError, message),
            ):
                release_installer.main(list(argv))

    def test_rejected_editable_script_does_not_import_mutable_siblings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            editable = Path(td) / "editable"
            package = editable / "grok_ms"
            package.mkdir(parents=True)
            shutil.copy2(MODULE_PATH, editable / "install-release.py")
            (package / "__init__.py").write_text("", encoding="ascii")
            marker = editable / "mutable-sibling-imported"
            payload = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('imported', encoding='ascii')\n"
                "raise RuntimeError('mutable sibling imported')\n"
            )
            (package / "managed_profile.py").write_text(payload, encoding="ascii")
            (package / "rung_admission.py").write_text(payload, encoding="ascii")
            environment = os.environ.copy()
            environment.pop(release_installer._BOOTSTRAP_AUTHORITY_FD_ENV, None)

            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    os.fspath(editable / "install-release.py"),
                    "install",
                    "--apply",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
                timeout=10,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn(b"native bootstrap authority", completed.stderr)
            self.assertFalse(marker.exists())

    def test_bootstrap_lane_consumes_root_owned_sealed_native_authority(self) -> None:
        if not hasattr(os, "memfd_create"):
            self.skipTest("memfd_create is required")
        memfd_flags = getattr(os, "MFD_ALLOW_SEALING", 0)
        try:
            descriptor = os.memfd_create(
                "grok-dispatcher", memfd_flags | 0x0008
            )
            extra_exec_seal = True
        except OSError as exc:
            if exc.errno != errno.EINVAL:
                raise
            descriptor = os.memfd_create("grok-dispatcher", memfd_flags)
            extra_exec_seal = False
        os.write(descriptor, b"signed dispatcher fixture")
        os.fchmod(descriptor, 0o600)
        expected_seals = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, expected_seals)
        if extra_exec_seal:
            self.assertEqual(
                fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & 0x0020,
                0x0020,
            )
        actual = os.fstat(descriptor)
        fields = list(actual)
        fields[4] = 0
        root_owned = os.stat_result(fields)
        real_fstat = os.fstat

        def root_fstat(candidate: int) -> os.stat_result:
            if candidate == descriptor:
                return root_owned
            return real_fstat(candidate)

        with (
            mock.patch.dict(
                os.environ,
                {release_installer._BOOTSTRAP_AUTHORITY_FD_ENV: str(descriptor)},
            ),
            mock.patch.object(release_installer.os, "geteuid", return_value=0),
            mock.patch.object(release_installer.os, "fstat", side_effect=root_fstat),
        ):
            release_installer._consume_bootstrap_authority()
            self.assertNotIn(
                release_installer._BOOTSTRAP_AUTHORITY_FD_ENV,
                os.environ,
            )
        with self.assertRaises(OSError):
            real_fstat(descriptor)

    def test_bootstrap_lane_rejects_oversized_descriptor_without_syscall(self) -> None:
        with (
            mock.patch.dict(
                os.environ,
                {release_installer._BOOTSTRAP_AUTHORITY_FD_ENV: "9999999999"},
            ),
            mock.patch.object(
                release_installer.os,
                "fstat",
                side_effect=AssertionError("oversized descriptor reached fstat"),
            ),
            self.assertRaisesRegex(
                release_installer.ReleaseError,
                "native bootstrap authority",
            ),
        ):
            release_installer._consume_bootstrap_authority()

    def test_authenticated_bootstrap_rejects_caller_source_before_discovery(self) -> None:
        extracted = Path("/run/.grok-bootstrap-fixture/install-release.py")
        with (
            mock.patch.object(release_installer, "__file__", str(extracted)),
            mock.patch.object(release_installer, "_consume_bootstrap_authority"),
            mock.patch.object(
                release_installer,
                "_default_runtime_files",
                side_effect=AssertionError("caller source discovery ran"),
            ),
            self.assertRaisesRegex(release_installer.ReleaseError, "explicit"),
        ):
            release_installer.main(
                ["install", "--source", "/tmp/caller-controlled", "--apply"]
            )

    def test_authenticated_bootstrap_cannot_downgrade_to_prefix_lane(self) -> None:
        extracted = Path("/run/.grok-bootstrap-fixture/install-release.py")
        authority = release_installer._BOOTSTRAP_AUTHORITY_FD_ENV
        with (
            mock.patch.object(release_installer, "__file__", str(extracted)),
            mock.patch.dict(os.environ, {authority: "17"}),
            mock.patch.object(
                release_installer, "_consume_bootstrap_authority"
            ) as consume,
            mock.patch.object(
                release_installer,
                "_default_runtime_files",
                side_effect=AssertionError("caller source discovery ran"),
            ),
            self.assertRaisesRegex(release_installer.ReleaseError, "explicit"),
        ):
            release_installer.main(
                [
                    "install",
                    "--prefix",
                    "/tmp/caller-prefix",
                    "--source",
                    "/tmp/caller-source",
                    "--apply",
                ]
            )
        consume.assert_called_once_with()

    def test_installed_status_uses_shared_existing_locks_without_repair(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fixture, _boot_id, _pid = write_proc_fixture(base / "fixture-prefix")
            descriptor = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            authority = release_installer.ProcAuthority.from_fd(
                descriptor, display=fixture, fixture=True
            )
            os.close(descriptor)
            installer, layout, _source = make_installer(
                base / "install", proc_authority=authority
            )
            release_id = installer.install().release_id
            flock_operations: list[int] = []
            real_flock = release_installer.fcntl.flock

            def tracked_flock(descriptor: int, operation: int) -> object:
                flock_operations.append(operation)
                return real_flock(descriptor, operation)

            with (
                mock.patch.object(
                    installer,
                    "_prepare_roots",
                    side_effect=AssertionError("status repaired roots"),
                ),
                mock.patch.object(
                    installer,
                    "_ensure_selection_lock",
                    side_effect=AssertionError("status repaired the selection lock"),
                ),
                mock.patch.object(release_installer.fcntl, "flock", tracked_flock),
            ):
                status = installer.status(installed=True)
            self.assertEqual(status["active_release_id"], release_id)
            self.assertIn(fcntl.LOCK_SH, flock_operations)

            layout.operation_lock.chmod(0o644)
            with self.assertRaisesRegex(release_installer.ReleaseError, "operation lock"):
                installer.status(installed=True)
            self.assertEqual(stat.S_IMODE(layout.operation_lock.stat().st_mode), 0o644)

    def test_production_mutation_requires_package_provisioned_operation_lock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            layout.test_install = False
            with self.assertRaisesRegex(
                release_installer.ReleaseError, "package-provisioned operation lock"
            ):
                with installer._locked():
                    self.fail("missing production operation lock was accepted")
            self.assertFalse(layout.operation_lock.exists())

    def test_mutation_operation_lock_is_exact_preserved_and_rebound_checked(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            with installer._locked():
                pass
            original = layout.operation_lock.stat()
            with installer._locked():
                pass
            repeated = layout.operation_lock.stat()
            self.assertEqual(
                (repeated.st_dev, repeated.st_ino),
                (original.st_dev, original.st_ino),
            )

            layout.operation_lock.chmod(0o644)
            with self.assertRaisesRegex(release_installer.ReleaseError, "unsafe"):
                with installer._locked():
                    self.fail("wrong-mode operation lock was accepted")
            self.assertEqual(stat.S_IMODE(layout.operation_lock.stat().st_mode), 0o644)
            layout.operation_lock.chmod(0o600)
            layout.operation_lock.write_bytes(b"x")
            with self.assertRaisesRegex(release_installer.ReleaseError, "unsafe"):
                with installer._locked():
                    self.fail("nonempty operation lock was accepted")
            self.assertEqual(layout.operation_lock.read_bytes(), b"x")
            layout.operation_lock.write_bytes(b"")
            alias = layout.operation_lock.with_name("operation-lock-alias")
            os.link(layout.operation_lock, alias)
            with self.assertRaisesRegex(release_installer.ReleaseError, "unsafe"):
                with installer._locked():
                    self.fail("multiply-linked operation lock was accepted")

        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            with installer._locked():
                pass
            real_flock = release_installer.fcntl.flock
            replaced = False

            def replace_after_lock(descriptor: int, operation: int) -> object:
                nonlocal replaced
                result = real_flock(descriptor, operation)
                if operation == fcntl.LOCK_EX and not replaced:
                    replaced = True
                    layout.operation_lock.unlink()
                    layout.operation_lock.write_bytes(b"")
                    layout.operation_lock.chmod(0o600)
                return result

            with (
                mock.patch.object(
                    release_installer.fcntl, "flock", replace_after_lock
                ),
                self.assertRaisesRegex(
                    release_installer.ReleaseError, "changed while held"
                ),
            ):
                with installer._locked():
                    self.fail("rebound operation lock was accepted")

    def test_installed_status_dispatch_is_bound_to_concrete_root_release(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fixture, _boot_id, _pid = write_proc_fixture(base / "fixture-prefix")
            descriptor = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            authority = release_installer.ProcAuthority.from_fd(
                descriptor, display=fixture, fixture=True
            )
            os.close(descriptor)
            installer, layout, _source = make_installer(
                base / "install", proc_authority=authority
            )
            release_id = installer.install().release_id
            installed_path = (
                Path("/usr/local/libexec/grok-proxy/releases")
                / release_id
                / release_installer.INSTALLER_RUNTIME
            )
            self.assertTrue(
                (layout.root_releases / release_id / release_installer.INSTALLER_RUNTIME).is_file()
            )
            output = io.StringIO()
            with (
                mock.patch.object(release_installer, "__file__", str(installed_path)),
                mock.patch.object(
                    release_installer.Layout, "defaults", return_value=layout
                ),
                mock.patch.object(
                    release_installer, "_default_runtime_files", return_value=RUNTIME_FILES
                ),
                mock.patch.object(
                    release_installer, "_default_root_files", return_value=ROOT_FILES
                ),
                mock.patch.object(
                    release_installer, "ReleaseInstaller", return_value=installer
                ),
                mock.patch.object(
                    release_installer.ProcAuthority,
                    "production",
                    return_value=authority,
                ),
                redirect_stdout(output),
            ):
                returncode = release_installer.main(["status"])
            self.assertEqual(returncode, 0)
            self.assertEqual(json.loads(output.getvalue())["active_release_id"], release_id)

    def test_installed_mutation_rechecks_concrete_release_under_operation_lock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fixture, _boot_id, _pid = write_proc_fixture(base / "fixture-prefix")
            descriptor = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            authority = release_installer.ProcAuthority.from_fd(
                descriptor, display=fixture, fixture=True
            )
            os.close(descriptor)
            installer, layout, source = make_installer(
                base / "install", proc_authority=authority
            )
            old_release = installer.install().release_id
            installed = release_installer.ReleaseInstaller(
                layout,
                runtime_files=RUNTIME_FILES,
                root_files=ROOT_FILES,
                proc_authority=authority,
                installed_release_id=old_release,
            )

            write_source(source, "v2")
            new_release = installer.install().release_id
            self.assertNotEqual(new_release, old_release)
            with self.assertRaisesRegex(
                release_installer.ReleaseError,
                "not the concrete root-selected release",
            ):
                installed.revalidate_boot()

    def test_proc_authority_inventory_has_no_ambient_proc_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fixture, boot_id, pid = write_proc_fixture(base / "prefix")
            descriptor = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            authority = release_installer.ProcAuthority.from_fd(
                descriptor,
                display=fixture,
                fixture=True,
            )
            os.close(descriptor)
            scoped, _layout, _source = make_installer(
                base / "install", proc_authority=authority
            )
            real_open = release_installer.os.open
            real_read_text = Path.read_text

            def guarded_open(path: object, *args: object, **kwargs: object) -> int:
                if path == "/proc":
                    raise AssertionError("ambient proc root reopened")
                return real_open(path, *args, **kwargs)

            def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
                if str(path).startswith("/proc/"):
                    raise AssertionError(f"ambient proc leaf read: {path}")
                return real_read_text(path, *args, **kwargs)

            with (
                mock.patch.object(release_installer.os, "open", guarded_open),
                mock.patch.object(Path, "read_text", guarded_read_text),
            ):
                self.assertEqual(scoped._boot_id(), boot_id)
                start_ticks = scoped._proc_start_ticks(pid)
                self.assertGreater(start_ticks, 0)
                self.assertEqual(scoped._legacy_openvpn_process_inventory(), [])
                self.assertEqual(scoped._release_bound_process_inventory(), [])
                self.assertEqual(scoped._fixed_listener_inventory(), [])
                self.assertTrue(
                    scoped._runner_owner_can_execute(
                        {
                            "owner_pid": pid,
                            "owner_start_ticks": start_ticks,
                            "owner_boot_id": boot_id,
                        }
                    )
                )

    def test_prefix_proc_authority_is_fixed_inherited_and_not_a_public_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source = base / "source"
            prefix = base / "prefix"
            fixture, _boot_id, _pid = write_proc_fixture(prefix)
            write_default_source(source, "v1")
            descriptor = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            environment = {
                **os.environ,
                release_installer._PREFIX_PROC_FD_ENV: str(descriptor),
            }
            command = [
                sys.executable,
                str(MODULE_PATH),
                "plan",
                "--source",
                str(source),
                "--prefix",
                str(prefix),
                "--home",
                "/home/caller",
            ]
            try:
                accepted = subprocess.run(
                    command,
                    env=environment,
                    pass_fds=(descriptor,),
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                self.assertIn(
                    release_installer.INSTALLER_RUNTIME,
                    json.loads(accepted.stdout)["runtime_files"],
                )

                production = subprocess.run(
                    [sys.executable, str(MODULE_PATH), "plan", "--source", str(source)],
                    env=environment,
                    pass_fds=(descriptor,),
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(production.returncode, 2, production.stderr)
                self.assertIn("prefix-test only", production.stderr)

                public_path = subprocess.run(
                    [*command, "--test-proc-root", str(fixture)],
                    env=environment,
                    pass_fds=(descriptor,),
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(public_path.returncode, 2, public_path.stderr)
                self.assertIn("unrecognized arguments", public_path.stderr)
            finally:
                os.close(descriptor)

    def test_helper_only_legacy_restore_authority_is_durable_and_one_shot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fixture, _boot_id, _pid = write_proc_fixture(base / "fixture-prefix")
            descriptor = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            authority = release_installer.ProcAuthority.from_fd(
                descriptor, display=fixture, fixture=True
            )
            os.close(descriptor)
            installer, layout, source = make_installer(
                base / "install", proc_authority=authority
            )
            legacy_files = tuple(
                path
                for path in RUNTIME_FILES
                if path
                not in {
                    release_installer.DIRECT_ADMISSION_RUNTIME,
                    release_installer.INSTALLER_RUNTIME,
                }
            )
            legacy_installer = release_installer.ReleaseInstaller(
                layout,
                runtime_files=legacy_files,
                root_files=ROOT_FILES,
                proc_authority=authority,
            )
            with mock.patch.object(
                legacy_installer,
                "validate_target_release_pair",
                side_effect=legacy_installer.validate_release_pair,
            ):
                legacy_release = legacy_installer.install().release_id
            write_source(source, "v2")
            target_release = installer.plan_release().release_id

            with self.assertRaises(release_installer.InjectedFault):
                installer.install(fault_at=release_installer.AFTER_ROOT_PUBLISH)
            authority = json.loads(
                layout.legacy_migration_authority.read_text(encoding="ascii")
            )
            self.assertEqual(authority["state"], "AVAILABLE")
            self.assertEqual(authority["legacy_release_id"], legacy_release)
            self.assertEqual(authority["target_release_id"], target_release)
            self.assertRegex(authority["attempt_id"], r"^[0-9a-f]{32}$")
            self.assertRegex(authority["legacy_pair_sha256"], r"^[0-9a-f]{64}$")

            restored = installer.abort_restore(legacy_release)
            self.assertEqual(restored.release_id, legacy_release)
            consumed = json.loads(
                layout.legacy_migration_authority.read_text(encoding="ascii")
            )
            self.assertEqual(consumed["state"], "CONSUMED")
            self.assertEqual(consumed["ready_release_id"], legacy_release)
            with self.assertRaisesRegex(release_installer.ReleaseError, "one-shot"):
                installer.install()

    def test_ready_legacy_migration_consumption_recovers_without_replay(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fixture, _boot_id, _pid = write_proc_fixture(base / "fixture-prefix")
            descriptor = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            authority = release_installer.ProcAuthority.from_fd(
                descriptor, display=fixture, fixture=True
            )
            os.close(descriptor)
            installer, layout, source = make_installer(
                base / "install", proc_authority=authority
            )
            legacy_files = tuple(
                path
                for path in RUNTIME_FILES
                if path
                not in {
                    release_installer.DIRECT_ADMISSION_RUNTIME,
                    release_installer.INSTALLER_RUNTIME,
                }
            )
            legacy_installer = release_installer.ReleaseInstaller(
                layout,
                runtime_files=legacy_files,
                root_files=ROOT_FILES,
                proc_authority=authority,
            )
            with mock.patch.object(
                legacy_installer,
                "validate_target_release_pair",
                side_effect=legacy_installer.validate_release_pair,
            ):
                legacy_release = legacy_installer.install().release_id
            write_source(source, "v2")
            target_release = installer.plan_release().release_id

            with self.assertRaises(release_installer.InjectedFault):
                installer.install(fault_at=release_installer.BEFORE_DENY_CLEAR)
            authority = json.loads(
                layout.legacy_migration_authority.read_text(encoding="ascii")
            )
            self.assertEqual(authority["state"], "CONSUMED")
            self.assertEqual(authority["ready_release_id"], target_release)
            self.assertTrue(layout.rollback_deny.exists())

            # Model the adjacent crash window after READY publication but
            # before the atomic AVAILABLE -> CONSUMED replacement.
            available = dict(authority)
            available["state"] = "AVAILABLE"
            available["ready_release_id"] = None
            available["consumed_unix_ns"] = None
            release_installer._atomic_json(
                layout.legacy_migration_authority,
                available,
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )

            resumed = installer.resume()
            self.assertEqual(resumed.release_id, target_release)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertEqual(
                json.loads(
                    layout.legacy_migration_authority.read_text(encoding="ascii")
                )["state"],
                "CONSUMED",
            )

            # A crash after consumption but before deny removal converges by
            # clearing only that exact re-published terminal deny.
            with installer._locked():
                installer._publish_deny(
                    "install", legacy_release, target_release
                )
            resumed_consumed = installer.resume()
            self.assertEqual(resumed_consumed.release_id, target_release)
            self.assertFalse(layout.rollback_deny.exists())

    def test_provider_public_recovery_requires_exact_dead_fence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            user_root = home / ".local/lib/grok-proxy"
            user_root.mkdir(parents=True)
            control = home / ".local/state/grok-proxy/control"
            control.mkdir(parents=True, mode=0o700)
            control.chmod(0o700)
            release_id = "a" * 64
            owner_epoch = "owner-epoch"
            environment = {
                "GROK_PROVIDER_MODE": "1",
                "GROK_PROVIDER_OWNER_EPOCH": owner_epoch,
                "GROK_ACTIVE_RELEASE_ID": release_id,
            }
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()

            def publish(
                pid: int,
                start_ticks: int,
                owner: str = owner_epoch,
                *,
                selected_boot: str = boot_id,
                phase: str = "RECOVERING",
                selected_release: str = release_id,
            ) -> None:
                fence = {
                    "schema_version": 1,
                    "release_id": selected_release,
                    "owner_epoch": owner,
                    "pid": pid,
                    "pid_start_ticks": start_ticks,
                    "boot_id": selected_boot,
                    "phase": phase,
                }
                path = control / "recovery.fence"
                path.write_text(
                    json.dumps(fence, sort_keys=True, separators=(",", ":"))
                    + "\n",
                    encoding="ascii",
                )
                path.chmod(0o600)

            publish(
                os.getpid(),
                release_installer.ReleaseInstaller._proc_start_ticks(
                    os.getpid()
                ),
            )
            with self.assertRaisesRegex(
                release_admission.AdmissionError, "still live"
            ):
                release_admission._dead_provider_recovery_fence(
                    user_root,
                    os.getuid(),
                    os.getgid(),
                    release_id,
                    environment,
                )
            publish(
                os.getpid(),
                release_installer.ReleaseInstaller._proc_start_ticks(
                    os.getpid()
                )
                + 1,
            )
            release_admission._dead_provider_recovery_fence(
                user_root,
                os.getuid(),
                os.getgid(),
                release_id,
                environment,
            )
            other_boot = "00000000-0000-0000-0000-000000000001"
            if other_boot == boot_id:
                other_boot = "00000000-0000-0000-0000-000000000002"
            publish(
                os.getpid(),
                release_installer.ReleaseInstaller._proc_start_ticks(
                    os.getpid()
                ),
                selected_boot=other_boot,
            )
            release_admission._dead_provider_recovery_fence(
                user_root,
                os.getuid(),
                os.getgid(),
                release_id,
                environment,
            )
            publish(2**31 - 1, 1)
            release_admission._dead_provider_recovery_fence(
                user_root,
                os.getuid(),
                os.getgid(),
                release_id,
                environment,
            )
            publish(2**31 - 1, 1, owner="foreign-epoch")
            with self.assertRaisesRegex(
                release_admission.AdmissionError, "not exact"
            ):
                release_admission._dead_provider_recovery_fence(
                    user_root,
                    os.getuid(),
                    os.getgid(),
                    release_id,
                    environment,
                )
            for invalid in (
                {**environment, "GROK_PROVIDER_OWNER_EPOCH": ""},
                {**environment, "GROK_ACTIVE_RELEASE_ID": "b" * 64},
            ):
                with self.subTest(environment=invalid), self.assertRaisesRegex(
                    release_admission.AdmissionError,
                    "identity is incomplete",
                ):
                    release_admission._dead_provider_recovery_fence(
                        user_root,
                        os.getuid(),
                        os.getgid(),
                        release_id,
                        invalid,
                    )
            publish(2**31 - 1, 1, phase="UNKNOWN")
            with self.assertRaisesRegex(
                release_admission.AdmissionError,
                "fence is not exact",
            ):
                release_admission._dead_provider_recovery_fence(
                    user_root,
                    os.getuid(),
                    os.getgid(),
                    release_id,
                    environment,
                )
            publish(2**31 - 1, 1, selected_release="b" * 64)
            with self.assertRaisesRegex(
                release_admission.AdmissionError,
                "fence is not exact",
            ):
                release_admission._dead_provider_recovery_fence(
                    user_root,
                    os.getuid(),
                    os.getgid(),
                    release_id,
                    environment,
                )
            fence_path = control / "recovery.fence"
            fence_path.unlink()
            unsafe_target = control / "unsafe-fence-target"
            unsafe_target.write_text("{}\n", encoding="ascii")
            unsafe_target.chmod(0o600)
            fence_path.symlink_to(unsafe_target)
            with self.assertRaisesRegex(
                release_admission.AdmissionError,
                "unsafe release file",
            ):
                release_admission._dead_provider_recovery_fence(
                    user_root,
                    os.getuid(),
                    os.getgid(),
                    release_id,
                    environment,
                )
            with self.assertRaisesRegex(
                release_admission.AdmissionError,
                "requires public recovery",
            ):
                release_admission.validate(
                    Path("/nonexistent-release"),
                    Path("/nonexistent-release/egress.sh"),
                    0,
                    {},
                    provider_recovery=True,
                )

    def _runner_record_value(
        self,
        *,
        nonce: str,
        phase: str,
        record_version: int,
        parent: Path,
        scope: Path,
        runner_kind: str = "qualification",
    ) -> dict[str, object]:
        parent_info = parent.stat()
        scope_info = scope.stat() if scope.exists() else None
        return {
            "schema_version": release_installer.SCHEMA_VERSION,
            "record_version": record_version,
            "run_id": nonce,
            "runner_kind": runner_kind,
            "release_id": "a" * 64,
            "phase": phase,
            "owner_pid": os.getpid(),
            "owner_start_ticks": (
                release_installer.ReleaseInstaller._proc_start_ticks(
                    os.getpid()
                )
            ),
            "owner_boot_id": Path(
                "/proc/sys/kernel/random/boot_id"
            ).read_text(encoding="ascii").strip(),
            "parent_path": str(parent),
            "parent_device": parent_info.st_dev,
            "parent_inode": parent_info.st_ino,
            "scope_path": str(scope),
            "scope_device": (
                None if phase == "PREPARED" else (
                    scope_info.st_dev if scope_info is not None else 1
                )
            ),
            "scope_inode": (
                None if phase == "PREPARED" else (
                    scope_info.st_ino if scope_info is not None else 1
                )
            ),
            "target_uid": os.geteuid(),
            "target_gid": os.getegid(),
        }

    def _regular_runner_fixture(
        self,
        base: Path,
        *,
        phase: str,
        record_version: int,
    ) -> tuple[
        object,
        Path,
        Path,
        Path,
    ]:
        control = base / "control"
        control.mkdir(mode=0o755)
        journal_root = control / "runner-scopes"
        journal_root.mkdir(mode=0o700)
        parent = base / "cgroup-parent"
        parent.mkdir(mode=0o700)
        nonce = "a" * 24
        scope = parent / f"grok-installer-{nonce}"
        scope.mkdir(mode=0o700)
        nested = scope / ("grok-ms-" + "b" * 24)
        nested.mkdir(mode=0o700)
        record = self._runner_record_value(
            nonce=nonce,
            phase=phase,
            record_version=record_version,
            parent=parent,
            scope=scope,
        )
        record_path = journal_root / f"{nonce}.json"
        record_path.write_bytes(
            release_installer._canonical_json(record) + b"\n"
        )
        record_path.chmod(0o600)
        descriptor = os.open(
            scope,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        runner = release_installer._RunnerCgroup(
            record_path=record_path,
            record=record,
            descriptor=descriptor,
            root_uid=os.geteuid(),
            root_gid=os.getegid(),
        )
        return runner, scope, nested, record_path

    def test_runner_parent_requires_target_delegation_and_folds_effective_limits(
        self,
    ) -> None:
        def write_node(
            node: Path,
            *,
            subtree: str,
            pids: str,
            memory_max: str,
            memory_high: str,
            swap_max: str,
            cpu_max: str,
            procs: str = "",
        ) -> None:
            node.mkdir()
            values = {
                "cgroup.type": "domain\n",
                "cgroup.subtree_control": subtree + "\n",
                "cgroup.procs": procs,
                "cgroup.max.depth": "max\n",
                "cgroup.max.descendants": "max\n",
                "pids.max": pids + "\n",
                "memory.max": memory_max + "\n",
                "memory.high": memory_high + "\n",
                "memory.swap.max": swap_max + "\n",
                "cpu.max": cpu_max + "\n",
            }
            for name, value in values.items():
                (node / name).write_text(value, encoding="ascii")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mount = root / "cgroup"
            mount.mkdir()
            delegated = mount / "delegated.service"
            write_node(
                delegated,
                subtree="cpu memory pids",
                pids="100",
                memory_max="200000",
                memory_high="max",
                swap_max="60000",
                cpu_max="20000 100000",
            )
            os.setxattr(delegated, "user.delegate", b"1")
            (delegated / "cgroup.max.depth").write_text("5\n", encoding="ascii")
            current = delegated / "session.scope"
            write_node(
                current,
                subtree="",
                pids="10",
                memory_max="100000",
                memory_high="80000",
                swap_max="50000",
                cpu_max="5000 10000",
                procs=f"{os.getpid()}\n",
            )
            for node, values in (
                (
                    delegated,
                    {
                        "cpu.idle": "0",
                        "cpu.max.burst": "2000",
                        "cpu.uclamp.max": "70.00",
                        "cpu.uclamp.min": "20.00",
                        "cpu.weight": "100",
                        "memory.swap.high": "55000",
                        "memory.zswap.max": "max",
                    },
                ),
                (
                    current,
                    {
                        "cpu.idle": "0",
                        "cpu.max.burst": "1000",
                        "cpu.uclamp.max": "80.00",
                        "cpu.uclamp.min": "10.00",
                        "cpu.weight": "123",
                        "memory.swap.high": "40000",
                        "memory.zswap.max": "30000",
                    },
                ),
            ):
                for name, value in values.items():
                    (node / name).write_text(value + "\n", encoding="ascii")
            proc_authority = cgroup_proc_authority(
                root,
                "0::/delegated.service/session.scope\n",
            )
            placement = release_installer._runner_cgroup_parent(
                os.getuid(),
                os.getgid(),
                proc_authority=proc_authority,
                mount=mount,
            )
            self.assertEqual(placement.parent, delegated)
            self.assertEqual(placement.source, current)
            self.assertEqual(
                dict(placement.effective_limits),
                {
                    "cgroup.max.depth": "4",
                    "cgroup.max.descendants": "1024",
                    "cpu.idle": "0",
                    "cpu.max": "5000 25000",
                    "cpu.max.burst": "1000",
                    "cpu.uclamp.max": "70.00",
                    "cpu.uclamp.min": "20.00",
                    "cpu.weight": "123",
                    "memory.high": "80000",
                    "memory.max": "100000",
                    "memory.swap.high": "40000",
                    "memory.swap.max": "50000",
                    "memory.zswap.max": "30000",
                    "pids.max": "10",
                },
            )
            os.removexattr(delegated, "user.delegate")
            with self.assertRaisesRegex(
                release_installer.ReleaseError,
                "no target-owned delegated cgroup-v2 parent",
            ):
                release_installer._runner_cgroup_parent(
                    os.getuid(),
                    os.getgid(),
                    proc_authority=proc_authority,
                    mount=mount,
                )
            os.setxattr(delegated, "user.delegate", b"1")
            with self.assertRaisesRegex(
                release_installer.ReleaseError,
                "no target-owned delegated cgroup-v2 parent",
            ):
                release_installer._runner_cgroup_parent(
                    os.getuid() + 1,
                    os.getgid() + 1,
                    proc_authority=proc_authority,
                    mount=mount,
                )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mount = root / "cgroup"
            mount.mkdir()
            user_slice = mount / f"user-{os.getuid()}.slice"
            write_node(
                user_slice,
                subtree="cpu memory pids",
                pids="100",
                memory_max="200000",
                memory_high="max",
                swap_max="60000",
                cpu_max="max 100000",
            )
            current = user_slice / "session-2.scope"
            write_node(
                current,
                subtree="",
                pids="10",
                memory_max="100000",
                memory_high="80000",
                swap_max="50000",
                cpu_max="max 100000",
                procs=f"{os.getpid()}\n",
            )
            user_service = user_slice / f"user@{os.getuid()}.service"
            write_node(
                user_service,
                subtree="cpu memory pids",
                pids="max",
                memory_max="max",
                memory_high="max",
                swap_max="max",
                cpu_max="max 100000",
            )
            os.setxattr(user_service, "user.delegate", b"1")
            proc_authority = cgroup_proc_authority(
                root,
                f"0::/user-{os.getuid()}.slice/session-2.scope\n",
            )
            placement = release_installer._runner_cgroup_parent(
                os.getuid(),
                os.getgid(),
                proc_authority=proc_authority,
                mount=mount,
            )
            self.assertEqual(placement.source, current)
            self.assertEqual(placement.parent, user_service)
            self.assertEqual(
                placement.source_cpu_affinity,
                tuple(sorted(os.sched_getaffinity(0))),
            )

    def _strict_root_runner_teardown(
        self,
        *,
        runner: release_installer._RunnerCgroup | None,
        process: subprocess.Popen[bytes] | None,
        leader_pidfd: int,
        other_pidfds: tuple[int, ...],
        scope_path: Path | None,
        record_path: Path | None,
        journal_root: Path,
    ) -> None:
        """Contain a root-test runner and surface every teardown failure."""

        failures: list[BaseException] = []

        def fresh_deadline() -> int:
            return time.monotonic_ns() + 15_000_000_000

        def attempt_cleanup() -> None:
            assert runner is not None
            cleanup_deadline = fresh_deadline()
            runner.journal_deadline_monotonic_ns = cleanup_deadline
            try:
                runner.cleanup(cleanup_deadline)
            except BaseException as exc:
                failures.append(exc)

        session_reaped = process is None or process.returncode is not None

        def attempt_reap_or_kill() -> None:
            nonlocal session_reaped
            assert process is not None
            if session_reaped:
                return
            deadline = fresh_deadline()
            try:
                if runner is not None and runner.scope_removed:
                    release_installer._reap_after_cgroup_cleanup(
                        process,
                        leader_pidfd,
                        deadline_monotonic_ns=deadline,
                    )
                elif process.poll() is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                session_reaped = process.returncode is not None
            except BaseException as exc:
                failures.append(exc)

        if runner is not None and not runner.scope_removed:
            attempt_cleanup()

        if process is not None and not session_reaped:
            attempt_reap_or_kill()

        # A failed first cleanup can become removable after the leader exits.
        # Retain the first error while making one bounded attempt to avoid test
        # residue on the real host.
        if runner is not None and not runner.scope_removed:
            attempt_cleanup()

        # Cleanup may have succeeded only on the second attempt, or the first
        # reap may have timed out.  Never discard durable recovery authority
        # until a fresh attempt confirms that the Popen leader was reaped.
        if process is not None and not session_reaped:
            attempt_reap_or_kill()

        if (
            runner is not None
            and runner.scope_removed
            and session_reaped
            and not runner.cleaned
        ):
            runner.journal_deadline_monotonic_ns = fresh_deadline()
            try:
                runner.finalize_record()
            except BaseException as exc:
                failures.append(exc)
        elif runner is not None and runner.scope_removed and not session_reaped:
            failures.append(
                AssertionError(
                    "root runner leader was not reaped; journal retained"
                )
            )

        if runner is not None:
            try:
                runner.close()
            except BaseException as exc:
                failures.append(exc)
        for descriptor in (leader_pidfd, *other_pidfds):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except BaseException as exc:
                    failures.append(exc)

        try:
            if scope_path is not None:
                self.assertFalse(scope_path.exists())
            if record_path is not None:
                self.assertFalse(record_path.exists())
            self.assertEqual(tuple(journal_root.iterdir()), ())
        except BaseException as exc:
            failures.append(exc)

        if failures:
            if len(failures) == 1:
                raise failures[0]
            raise BaseExceptionGroup("root runner teardown failed", failures)

    def test_runner_journal_recovers_atomic_create_and_legacy_partial_states(
        self,
    ) -> None:
        for crash_state in ("staged", "linked"):
            with self.subTest(crash_state=crash_state), tempfile.TemporaryDirectory() as td:
                installer, layout, _source = make_installer(Path(td))
                layout.test_install = True
                layout.test_runner_scopes = True
                installer._prepare_roots()
                nonce = "c" * 24
                final = layout.runner_scope_root / f"{nonce}.json"
                staged = (
                    layout.runner_scope_root
                    / f".{nonce}.json.tmp-{'d' * 32}"
                )
                # This fixture exercises only recovery of the journal's
                # atomic-create stages.  A PREPARED record with no scope is
                # discarded before cgroup delegation is consulted, so bind it
                # to the fixed cgroup-v2 mount instead of coupling the test to
                # the caller's live delegated service hierarchy.
                parent = Path("/sys/fs/cgroup")
                parent_info = parent.lstat()
                record = {
                    "schema_version": release_installer.SCHEMA_VERSION,
                    "record_version": release_installer.RUNNER_SCOPE_RECORD_VERSION,
                    "run_id": nonce,
                    "runner_kind": "qualification",
                    "release_id": "a" * 64,
                    "phase": "PREPARED",
                    "owner_pid": 2**31 - 1,
                    "owner_start_ticks": 1,
                    "owner_boot_id": installer._boot_id(),
                    "parent_path": str(parent),
                    "parent_device": parent_info.st_dev,
                    "parent_inode": parent_info.st_ino,
                    "scope_path": str(parent / f"grok-installer-{nonce}"),
                    "scope_device": None,
                    "scope_inode": None,
                    "target_uid": layout.target_uid,
                    "target_gid": layout.target_gid,
                }
                staged.write_bytes(
                    release_installer._canonical_json(record) + b"\n"
                )
                staged.chmod(0o600)
                if crash_state == "linked":
                    os.link(staged, final)
                    self.assertEqual(staged.stat().st_nlink, 2)

                installer._recover_runner_scopes(
                    time.monotonic_ns() + 5_000_000_000
                )
                self.assertFalse(staged.exists())
                self.assertFalse(final.exists())
                self.assertEqual(tuple(layout.runner_scope_root.iterdir()), ())

        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            layout.test_install = True
            layout.test_runner_scopes = True
            installer._prepare_roots()
            final = layout.runner_scope_root / f"{'c' * 24}.json"
            final.write_bytes(b"{")
            final.chmod(0o600)
            with self.assertRaisesRegex(
                release_installer.ReleaseError,
                "invalid JSON",
            ):
                installer._recover_runner_scopes(
                    time.monotonic_ns() + 5_000_000_000
                )
            self.assertEqual(final.read_bytes(), b"{")

    def test_runner_journal_lock_prevents_live_stage_discard(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            layout.test_install = True
            layout.test_runner_scopes = True
            installer._prepare_roots()
            staged = (
                layout.runner_scope_root
                / f".{'e' * 24}.json.tmp-{'f' * 32}"
            )
            staged.write_text("{}\n", encoding="ascii")
            staged.chmod(0o600)
            with release_installer._runner_journal_locked(
                layout.runner_scope_lock,
                layout.root_uid,
                layout.root_gid,
                time.monotonic_ns() + 1_000_000_000,
            ):
                with self.assertRaisesRegex(
                    release_installer.SessionContainmentError,
                    "journal lock deadline",
                ):
                    installer._recover_runner_scopes(
                        time.monotonic_ns() + 30_000_000
                    )
                self.assertTrue(staged.exists())
            installer._recover_runner_scopes(
                time.monotonic_ns() + 5_000_000_000
            )
            self.assertFalse(staged.exists())

    def test_runner_cleanup_publishes_exact_ordered_phase_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            runner, scope, nested, record_path = self._regular_runner_fixture(
                Path(td),
                phase="RUNNING",
                record_version=1,
            )
            events: list[str] = []
            kill_count = [0]
            empty_count = [0]
            revoked = [False]
            original_atomic_json = release_installer._atomic_json

            def write_control(
                _descriptor: int, name: str, value: bytes
            ) -> None:
                self.assertEqual((name, value), ("cgroup.kill", b"1\n"))
                kill_count[0] += 1
                events.append(f"kill-{kill_count[0]}")

            def read_control(
                _descriptor: int, name: str, _maximum: int
            ) -> bytes:
                self.assertEqual(name, "cgroup.events")
                empty_count[0] += 1
                events.append(f"empty-{empty_count[0]}")
                return b"populated 0\n"

            def publish(path: Path, value: object, **kwargs: object) -> None:
                assert isinstance(value, dict)
                phase = value.get("phase")
                if phase == "RECOVERED":
                    self.assertTrue(scope.is_dir())
                    self.assertTrue(nested.is_dir())
                    events.append("RECOVERED")
                elif phase == "CONTAINED":
                    self.assertTrue(scope.is_dir())
                    self.assertFalse(nested.exists())
                    events.append("CONTAINED")
                original_atomic_json(path, value, **kwargs)

            def recover() -> bool:
                current = json.loads(record_path.read_text(encoding="ascii"))
                self.assertEqual(current["record_version"], 1)
                self.assertEqual(current["phase"], "RUNNING")
                self.assertTrue(scope.is_dir())
                self.assertTrue(nested.is_dir())
                events.append("callback")
                return True

            def revoke(*_args: object, **_kwargs: object) -> None:
                if not revoked[0]:
                    revoked[0] = True
                    events.append("revoke")

            def remove_nested(_deadline_monotonic_ns: int) -> None:
                current = json.loads(record_path.read_text(encoding="ascii"))
                self.assertEqual(
                    (current["record_version"], current["phase"]),
                    (release_installer.RUNNER_SCOPE_RECORD_VERSION, "RECOVERED"),
                )
                self.assertTrue(nested.is_dir())
                events.append("nested-remove")
                nested.rmdir()

            try:
                with (
                    mock.patch.object(
                        release_installer,
                        "_runner_cgroup_write_at",
                        side_effect=write_control,
                    ),
                    mock.patch.object(
                        release_installer,
                        "_runner_cgroup_read_at",
                        side_effect=read_control,
                    ),
                    mock.patch.object(
                        release_installer,
                        "_atomic_json",
                        side_effect=publish,
                    ),
                    mock.patch.object(
                        release_installer.os,
                        "chown",
                        side_effect=revoke,
                    ),
                    mock.patch.object(
                        runner,
                        "_remove_nested",
                        side_effect=remove_nested,
                    ),
                ):
                    runner.cleanup(
                        time.monotonic_ns() + 5_000_000_000,
                        after_kill=recover,
                        journal_locked=True,
                    )
                self.assertEqual(
                    events,
                    [
                        "kill-1",
                        "empty-1",
                        "callback",
                        "RECOVERED",
                        "revoke",
                        "kill-2",
                        "empty-2",
                        "nested-remove",
                        "CONTAINED",
                    ],
                )
                self.assertTrue(runner.runtime_recovery_applied)
                self.assertTrue(runner.scope_removed)
                self.assertEqual(runner.descriptor, -1)
                self.assertFalse(scope.exists())
                terminal = json.loads(record_path.read_text(encoding="ascii"))
                self.assertEqual(
                    (terminal["record_version"], terminal["phase"]),
                    (release_installer.RUNNER_SCOPE_RECORD_VERSION, "CONTAINED"),
                )
                runner.finalize_record(journal_locked=True)
                self.assertFalse(record_path.exists())
            finally:
                runner.close()

    def test_runner_cleanup_callback_failure_preserves_running_scope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            runner, scope, nested, record_path = self._regular_runner_fixture(
                Path(td),
                phase="RUNNING",
                record_version=release_installer.RUNNER_SCOPE_RECORD_VERSION,
            )
            before = record_path.read_bytes()

            def fail_recovery() -> bool:
                self.assertTrue(scope.is_dir())
                self.assertTrue(nested.is_dir())
                raise RuntimeError("fixture recovery failure")

            try:
                with (
                    mock.patch.object(
                        release_installer,
                        "_runner_cgroup_write_at",
                    ) as write_control,
                    mock.patch.object(
                        release_installer,
                        "_runner_cgroup_read_at",
                        return_value=b"populated 0\n",
                    ) as read_control,
                    mock.patch.object(
                        release_installer,
                        "_atomic_json",
                        wraps=release_installer._atomic_json,
                    ) as atomic_json,
                    mock.patch.object(
                        release_installer.os,
                        "chown",
                    ) as chown,
                    mock.patch.object(runner, "_remove_nested") as remove_nested,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "fixture recovery failure",
                    ):
                        runner.cleanup(
                            time.monotonic_ns() + 5_000_000_000,
                            after_kill=fail_recovery,
                            journal_locked=True,
                        )
                self.assertEqual(write_control.call_count, 1)
                self.assertEqual(read_control.call_count, 1)
                atomic_json.assert_not_called()
                chown.assert_not_called()
                remove_nested.assert_not_called()
                self.assertEqual(record_path.read_bytes(), before)
                self.assertEqual(runner.record["phase"], "RUNNING")
                self.assertFalse(runner.runtime_recovery_applied)
                self.assertFalse(runner.scope_removed)
                self.assertTrue(scope.is_dir())
                self.assertTrue(nested.is_dir())
                os.fstat(runner.descriptor)
            finally:
                runner.close()

    def test_runner_recovered_retry_skips_runtime_callback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            runner, scope, nested, record_path = self._regular_runner_fixture(
                base,
                phase="RUNNING",
                record_version=release_installer.RUNNER_SCOPE_RECORD_VERSION,
            )
            installer, _layout, _source = make_installer(base / "installer")
            deadline = time.monotonic_ns() + 5_000_000_000
            try:
                with (
                    mock.patch.object(
                        installer,
                        "_recover_qualification_runner_runtime",
                        return_value=True,
                    ) as recover,
                    mock.patch.object(
                        release_installer,
                        "_runner_cgroup_write_at",
                    ),
                    mock.patch.object(
                        release_installer,
                        "_runner_cgroup_read_at",
                        return_value=b"populated 0\n",
                    ),
                ):
                    callback = installer._runner_after_kill(
                        runner,
                        runner.record,
                        deadline,
                    )
                    self.assertIsNotNone(callback)
                    with (
                        mock.patch.object(
                            release_installer.os,
                            "chown",
                            side_effect=PermissionError(
                                "fixture revocation interruption"
                            ),
                        ),
                        self.assertRaisesRegex(
                            PermissionError,
                            "fixture revocation interruption",
                        ),
                    ):
                        runner.cleanup(
                            deadline,
                            after_kill=callback,
                            journal_locked=True,
                        )
                    recovered = json.loads(
                        record_path.read_text(encoding="ascii")
                    )
                    self.assertEqual(recovered["phase"], "RECOVERED")
                    self.assertEqual(runner.record["phase"], "RECOVERED")
                    self.assertTrue(scope.is_dir())
                    self.assertTrue(nested.is_dir())
                    self.assertEqual(recover.call_count, 1)

                    retry_callback = installer._runner_after_kill(
                        runner,
                        runner.record,
                        deadline,
                    )
                    self.assertIsNone(retry_callback)

                    def remove_nested(_deadline_monotonic_ns: int) -> None:
                        nested.rmdir()

                    with (
                        mock.patch.object(
                            release_installer.os,
                            "chown",
                        ),
                        mock.patch.object(
                            runner,
                            "_remove_nested",
                            side_effect=remove_nested,
                        ),
                    ):
                        runner.cleanup(
                            deadline,
                            after_kill=retry_callback,
                            journal_locked=True,
                        )
                    self.assertEqual(recover.call_count, 1)
                self.assertFalse(scope.exists())
                self.assertEqual(runner.record["phase"], "CONTAINED")
                runner.finalize_record(journal_locked=True)
                self.assertFalse(record_path.exists())
            finally:
                runner.close()

    def test_runner_missing_scope_phase_matrix_is_fail_closed(self) -> None:
        cases = (
            (1, "PREPARED", True),
            (release_installer.RUNNER_SCOPE_RECORD_VERSION, "PREPARED", True),
            (1, "DELEGATED", False),
            (
                release_installer.RUNNER_SCOPE_RECORD_VERSION,
                "DELEGATED",
                False,
            ),
            (1, "RUNNING", False),
            (
                release_installer.RUNNER_SCOPE_RECORD_VERSION,
                "RUNNING",
                False,
            ),
            (
                release_installer.RUNNER_SCOPE_RECORD_VERSION,
                "RECOVERED",
                False,
            ),
            (
                release_installer.RUNNER_SCOPE_RECORD_VERSION,
                "CONTAINED",
                True,
            ),
        )
        for index, (record_version, phase, should_delete) in enumerate(cases):
            with self.subTest(
                record_version=record_version,
                phase=phase,
            ), tempfile.TemporaryDirectory() as td:
                installer, layout, _source = make_installer(Path(td))
                installer._prepare_roots()
                nonce = format(index + 1, "x") * 24
                parent = Path("/sys/fs/cgroup")
                scope = parent / f"grok-installer-{nonce}"
                self.assertFalse(scope.exists())
                record = self._runner_record_value(
                    nonce=nonce,
                    phase=phase,
                    record_version=record_version,
                    parent=parent,
                    scope=scope,
                )
                record_path = layout.runner_scope_root / f"{nonce}.json"
                raw = release_installer._canonical_json(record) + b"\n"
                record_path.write_bytes(raw)
                record_path.chmod(0o600)
                before = record_path.stat()
                with mock.patch.object(
                    installer,
                    "_runner_owner_can_execute",
                    return_value=False,
                ):
                    if should_delete:
                        installer._recover_runner_scopes_locked(
                            time.monotonic_ns() + 5_000_000_000
                        )
                    else:
                        with self.assertRaisesRegex(
                            release_installer.SessionContainmentError,
                            "disappeared before containment proof",
                        ):
                            installer._recover_runner_scopes_locked(
                                time.monotonic_ns() + 5_000_000_000
                            )
                if should_delete:
                    self.assertFalse(record_path.exists())
                    self.assertEqual(tuple(layout.runner_scope_root.iterdir()), ())
                else:
                    after = record_path.stat()
                    self.assertEqual(record_path.read_bytes(), raw)
                    self.assertEqual(
                        (after.st_dev, after.st_ino, after.st_size),
                        (before.st_dev, before.st_ino, before.st_size),
                    )

    def test_runner_record_versions_preserve_v1_and_v2_phase_grammar(self) -> None:
        self.assertEqual(release_installer.RUNNER_SCOPE_RECORD_VERSION, 2)
        accepted = (
            (1, "PREPARED", "qualification"),
            (1, "CREATED_ROOT", "qualification"),
            (1, "DELEGATED", "qualification"),
            (1, "RUNNING", "qualification"),
            (1, "RUNNING", "manual-canary"),
            (2, "PREPARED", "qualification"),
            (2, "CREATED_ROOT", "qualification"),
            (2, "DELEGATING", "qualification"),
            (2, "DELEGATED", "qualification"),
            (2, "RUNNING", "qualification"),
            (2, "RECOVERED", "qualification"),
            (2, "CONTAINED", "qualification"),
            (2, "RECOVERED", "manual-canary"),
            (2, "CONTAINED", "manual-canary"),
        )
        rejected = (
            (1, "DELEGATING", "qualification"),
            (1, "RECOVERED", "qualification"),
            (1, "CONTAINED", "qualification"),
            (0, "RUNNING", "qualification"),
            (3, "RUNNING", "qualification"),
        )
        for expected, cases in ((True, accepted), (False, rejected)):
            for index, (record_version, phase, runner_kind) in enumerate(cases):
                with self.subTest(
                    accepted=expected,
                    record_version=record_version,
                    phase=phase,
                    runner_kind=runner_kind,
                ), tempfile.TemporaryDirectory() as td:
                    installer, layout, _source = make_installer(Path(td))
                    installer._prepare_roots()
                    nonce = hashlib.sha256(
                        f"{expected}:{index}:{record_version}:{phase}:{runner_kind}".encode(
                            "ascii"
                        )
                    ).hexdigest()[:24]
                    parent = Path("/sys/fs/cgroup")
                    scope = parent / f"grok-installer-{nonce}"
                    record = self._runner_record_value(
                        nonce=nonce,
                        phase=phase,
                        record_version=record_version,
                        parent=parent,
                        scope=scope,
                        runner_kind=runner_kind,
                    )
                    record_path = layout.runner_scope_root / f"{nonce}.json"
                    record_path.write_bytes(
                        release_installer._canonical_json(record) + b"\n"
                    )
                    record_path.chmod(0o600)
                    if expected:
                        self.assertEqual(
                            installer._read_runner_scope_record(record_path),
                            record,
                        )
                    else:
                        with self.assertRaisesRegex(
                            release_installer.ReleaseError,
                            "scope authority is invalid",
                        ):
                            installer._read_runner_scope_record(record_path)

    def test_runner_nested_cleanup_makes_progress_when_breadth_exceeds_budget(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "grok-installer-test"
            root.mkdir()
            for name in ("a", "b", "c", "d"):
                (root / name).mkdir()
            with os.scandir(root) as entries:
                selected = [entry.name for entry in entries if entry.is_dir()][:3]
            (root / min(selected) / "x").mkdir()
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            runner = release_installer._RunnerCgroup(
                record_path=Path(td) / "record.json",
                record={"scope_device": root.stat().st_dev},
                descriptor=descriptor,
                root_uid=os.getuid(),
                root_gid=os.getgid(),
            )
            try:
                before = sum(1 for item in root.rglob("*") if item.is_dir())
                with mock.patch.object(
                    release_installer,
                    "MAX_SWITCH_INVENTORY_ENTRIES",
                    3,
                ):
                    with self.assertRaisesRegex(
                        release_installer.SessionContainmentError,
                        "limit exceeded",
                    ):
                        runner._remove_nested(time.monotonic_ns() + 5_000_000_000)
                after = sum(1 for item in root.rglob("*") if item.is_dir())
                self.assertLess(after, before)
            finally:
                runner.close()

    @unittest.skipUnless(
        os.geteuid() == 0
        and os.environ.get("GROK_RUN_ROOT_CGROUP_TEST") == "1",
        "requires explicit root cgroup integration authorization",
    )
    def test_root_runner_scope_kills_nested_double_forked_setsid_descendant(
        self,
    ) -> None:
        account = pwd.getpwnam(os.environ.get("SUDO_USER", "ubuntu"))
        script = r'''
import fcntl
import os
from pathlib import Path
import time

marker = Path(os.environ["RUNNER_MARKER"])
lock_path = Path(os.environ["RUNNER_LOCK"])
line = Path("/proc/self/cgroup").read_text(encoding="ascii").strip()
assert line.startswith("0::/")
outer = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
nested = outer / ("grok-ms-" + "b" * 24)
nested.mkdir(mode=0o700)
(nested / "cgroup.procs").write_text(str(os.getpid()) + "\n", encoding="ascii")
cursor = nested
for depth in range(2, 33):
    cursor = cursor / f"d{depth}"
    cursor.mkdir(mode=0o700)
try:
    (cursor / "d33").mkdir(mode=0o700)
except OSError:
    pass
else:
    raise AssertionError("runner cgroup depth bound was not enforced")
child = os.fork()
if child == 0:
    os.setsid()
    grandchild = os.fork()
    if grandchild == 0:
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        marker.write_text(str(os.getpid()), encoding="ascii")
        while True:
            time.sleep(1)
    os._exit(0)
deadline = time.monotonic() + 5
while not marker.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
os._exit(0)
'''
        with tempfile.TemporaryDirectory() as td:
            os.chmod(td, 0o755)
            installer, layout, _source = make_installer(Path(td))
            layout.test_install = True
            layout.test_runner_scopes = True
            layout.target_uid = account.pw_uid
            layout.target_gid = account.pw_gid
            installer._prepare_roots()
            work = Path(td) / "runner-work"
            work.mkdir(mode=0o700)
            os.chown(work, account.pw_uid, account.pw_gid)
            marker = work / "descendant.pid"
            lock_path = work / "descendant.lock"
            deadline = time.monotonic_ns() + 10_000_000_000
            runner: release_installer._RunnerCgroup | None = None
            scope_path: Path | None = None
            record_path: Path | None = None
            process: subprocess.Popen[bytes] | None = None
            leader_pidfd = -1
            descendant_pidfd = -1
            try:
                runner = installer._create_runner_scope(
                    account.pw_uid,
                    account.pw_gid,
                    deadline,
                    runner_kind="qualification",
                    release_id="a" * 64,
                )
                scope_path = Path(str(runner.record["scope_path"]))
                record_path = runner.record_path
                self.assertEqual(
                    (scope_path / "cgroup.max.depth")
                    .read_text(encoding="ascii")
                    .strip(),
                    "32",
                )
                self.assertEqual(
                    (scope_path / "cgroup.max.descendants")
                    .read_text(encoding="ascii")
                    .strip(),
                    "1024",
                )
                for control in ("cgroup.max.depth", "cgroup.max.descendants"):
                    self.assertEqual((scope_path / control).stat().st_uid, 0)
                environment = {
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "RUNNER_MARKER": str(marker),
                    "RUNNER_LOCK": str(lock_path),
                }
                process = subprocess.Popen(
                    ["/usr/bin/python3", "-c", script],
                    close_fds=True,
                    pass_fds=(runner.descriptor,),
                    start_new_session=True,
                    env=environment,
                    preexec_fn=runner.preexec(
                        installer._drop_identity(account.pw_uid, account.pw_gid)
                    ),
                )
                runner.mark_running()
                leader_pidfd = os.pidfd_open(process.pid, 0)
                until = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < until:
                    time.sleep(0.01)
                self.assertTrue(marker.is_file())
                descendant = int(marker.read_text(encoding="ascii"))
                descendant_pidfd = os.pidfd_open(descendant, 0)
                self.assertFalse(
                    release_installer._pidfd_exit_ready(descendant_pidfd, 0)
                )
                runner.cleanup(deadline)
                self.assertTrue(
                    release_installer._pidfd_exit_ready(descendant_pidfd, 2)
                )
                release_installer._reap_after_cgroup_cleanup(
                    process,
                    leader_pidfd,
                    deadline_monotonic_ns=deadline,
                )
                runner.finalize_record()
                self.assertFalse(scope_path.exists())
                self.assertFalse(runner.record_path.exists())
                lock_fd = os.open(lock_path, os.O_RDWR)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(lock_fd)
            finally:
                self._strict_root_runner_teardown(
                    runner=runner,
                    process=process,
                    leader_pidfd=leader_pidfd,
                    other_pidfds=(descendant_pidfd,),
                    scope_path=scope_path,
                    record_path=record_path,
                    journal_root=layout.runner_scope_root,
                )

    @unittest.skipUnless(
        os.geteuid() == 0
        and os.environ.get("GROK_RUN_ROOT_CGROUP_TEST") == "1",
        "requires explicit root cgroup integration authorization",
    )
    def test_root_runner_resource_counters_isolate_and_include_nested_tasks(self) -> None:
        account = pwd.getpwnam(os.environ.get("SUDO_USER", "ubuntu"))
        script = r'''
import os
from pathlib import Path
import threading
import time

from grok_ms.qualification_verifier import resource_cgroup_path

runner = Path(os.environ["RUNNER_SCOPE"])
authority = Path(os.environ["RESOURCE_AUTHORITY"])
assert resource_cgroup_path() == authority
expected_affinity = {
    int(item) for item in os.environ["EXPECTED_CPU_AFFINITY"].split(",")
}
actual_affinity = set(os.sched_getaffinity(0))
assert actual_affinity and actual_affinity <= expected_affinity
nested = runner / ("grok-ms-" + "9" * 24)
nested.mkdir(mode=0o700)
child = os.fork()
if child == 0:
    (nested / "cgroup.procs").write_text(str(os.getpid()) + "\n", encoding="ascii")
    hold = threading.Event()
    threads = [threading.Thread(target=hold.wait) for _ in range(4)]
    for thread in threads:
        thread.start()
    allocation = bytearray(16 * 1024 * 1024)
    for offset in range(0, len(allocation), 4096):
        allocation[offset] = 1
    Path(os.environ["RESOURCE_MARKER"]).write_text(str(os.getpid()), encoding="ascii")
    while True:
        time.sleep(1)
while True:
    time.sleep(1)
'''
        with tempfile.TemporaryDirectory() as td:
            os.chmod(td, 0o755)
            installer, layout, _source = make_installer(Path(td))
            layout.test_install = True
            layout.test_runner_scopes = True
            layout.target_uid = account.pw_uid
            layout.target_gid = account.pw_gid
            installer._prepare_roots()
            work = Path(td) / "resource-work"
            work.mkdir(mode=0o700)
            os.chown(work, account.pw_uid, account.pw_gid)
            marker = work / "held.pid"
            deadline = time.monotonic_ns() + 15_000_000_000
            runner: release_installer._RunnerCgroup | None = None
            scope: Path | None = None
            record_path: Path | None = None
            process: subprocess.Popen[bytes] | None = None
            leader_pidfd = -1
            held_pidfd = -1
            try:
                placement = release_installer._runner_cgroup_parent(
                    layout.target_uid,
                    layout.target_gid,
                )
                runner = installer._create_runner_scope(
                    account.pw_uid,
                    account.pw_gid,
                    deadline,
                    runner_kind="qualification",
                    release_id="a" * 64,
                )
                scope = Path(str(runner.record["scope_path"]))
                record_path = runner.record_path
                for control, expected in placement.effective_limits.items():
                    self.assertEqual(
                        (scope / control).read_text(encoding="ascii").strip(),
                        expected,
                    )
                authority = scope
                baseline_pids = int(
                    (authority / "pids.current").read_text().strip()
                )
                baseline_memory = int(
                    (authority / "memory.current").read_text().strip()
                )
                self.assertGreater(
                    int((placement.parent / "pids.current").read_text().strip()),
                    baseline_pids,
                )
                self.assertGreater(
                    int((placement.parent / "memory.current").read_text().strip()),
                    baseline_memory,
                )
                environment = {
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "RUNNER_SCOPE": str(scope),
                    "RESOURCE_AUTHORITY": str(authority),
                    "RESOURCE_MARKER": str(marker),
                    "EXPECTED_CPU_AFFINITY": ",".join(
                        str(item) for item in placement.source_cpu_affinity
                    ),
                    "GROK_QUALIFICATION_RESOURCE_CGROUP_PATH": str(authority),
                    "GROK_QUALIFICATION_RESOURCE_CGROUP_DEVICE": str(
                        runner.record["scope_device"]
                    ),
                    "GROK_QUALIFICATION_RESOURCE_CGROUP_INODE": str(
                        runner.record["scope_inode"]
                    ),
                }
                process = subprocess.Popen(
                    ["/usr/bin/python3", "-c", script],
                    close_fds=True,
                    pass_fds=(runner.descriptor,),
                    start_new_session=True,
                    cwd=ROOT,
                    env=environment,
                    preexec_fn=runner.preexec(
                        installer._drop_identity(account.pw_uid, account.pw_gid)
                    ),
                )
                runner.mark_running()
                leader_pidfd = os.pidfd_open(process.pid, 0)
                until = time.monotonic() + 8
                while not marker.exists() and time.monotonic() < until:
                    time.sleep(0.01)
                self.assertTrue(marker.is_file())
                held_pid = int(marker.read_text(encoding="ascii"))
                held_pidfd = os.pidfd_open(held_pid, 0)
                nested = scope / ("grok-ms-" + "9" * 24)
                held_cgroup = Path(f"/proc/{held_pid}/cgroup").read_text().strip()
                self.assertTrue(held_cgroup.endswith("/" + str(nested).removeprefix("/sys/fs/cgroup/")))
                runner_pids = int((authority / "pids.current").read_text().strip())
                runner_memory = int((authority / "memory.current").read_text().strip())
                self.assertGreaterEqual(runner_pids - baseline_pids, 6)
                self.assertGreaterEqual(runner_memory - baseline_memory, 8 * 1024 * 1024)
                self.assertGreaterEqual(
                    int((authority / "pids.peak").read_text().strip()), runner_pids
                )
                self.assertGreaterEqual(
                    int((authority / "memory.peak").read_text().strip()), runner_memory
                )
                runner.cleanup(deadline)
                self.assertTrue(
                    release_installer._pidfd_exit_ready(held_pidfd, 2)
                )
                release_installer._reap_after_cgroup_cleanup(
                    process,
                    leader_pidfd,
                    deadline_monotonic_ns=deadline,
                )
                runner.finalize_record()
                self.assertFalse(scope.exists())
                self.assertFalse(runner.record_path.exists())
            finally:
                self._strict_root_runner_teardown(
                    runner=runner,
                    process=process,
                    leader_pidfd=leader_pidfd,
                    other_pidfds=(held_pidfd,),
                    scope_path=scope,
                    record_path=record_path,
                    journal_root=layout.runner_scope_root,
                )

    @unittest.skipUnless(
        os.geteuid() == 0
        and os.environ.get("GROK_RUN_ROOT_CGROUP_TEST") == "1",
        "requires explicit root cgroup integration authorization",
    )
    def test_root_runner_test_harness_cleans_failure_immediately_after_create(
        self,
    ) -> None:
        account = pwd.getpwnam(os.environ.get("SUDO_USER", "ubuntu"))
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            layout.test_install = True
            layout.test_runner_scopes = True
            layout.target_uid = account.pw_uid
            layout.target_gid = account.pw_gid
            installer._prepare_roots()
            runner: release_installer._RunnerCgroup | None = None
            scope_path: Path | None = None
            record_path: Path | None = None
            with self.assertRaisesRegex(
                RuntimeError,
                "injected failure after runner creation",
            ):
                try:
                    runner = installer._create_runner_scope(
                        account.pw_uid,
                        account.pw_gid,
                        time.monotonic_ns() + 15_000_000_000,
                        runner_kind="qualification",
                        release_id="a" * 64,
                    )
                    scope_path = Path(str(runner.record["scope_path"]))
                    record_path = runner.record_path
                    raise RuntimeError("injected failure after runner creation")
                finally:
                    self._strict_root_runner_teardown(
                        runner=runner,
                        process=None,
                        leader_pidfd=-1,
                        other_pidfds=(),
                        scope_path=scope_path,
                        record_path=record_path,
                        journal_root=layout.runner_scope_root,
                    )
            self.assertIsNotNone(scope_path)
            self.assertIsNotNone(record_path)
            self.assertFalse(scope_path.exists())
            self.assertFalse(record_path.exists())
            self.assertEqual(tuple(layout.runner_scope_root.iterdir()), ())

    @unittest.skipUnless(
        os.geteuid() == 0
        and os.environ.get("GROK_RUN_ROOT_CGROUP_TEST") == "1",
        "requires explicit root cgroup integration authorization",
    )
    def test_root_runner_recovers_every_journal_crash_phase(self) -> None:
        account = pwd.getpwnam(os.environ.get("SUDO_USER", "ubuntu"))
        payload = r'''
import os
from pathlib import Path
import time

child = os.fork()
if child == 0:
    os.setsid()
    grandchild = os.fork()
    if grandchild == 0:
        Path(os.environ["RUNNER_DESCENDANT"]).write_text(
            str(os.getpid()), encoding="ascii"
        )
        while True:
            time.sleep(1)
    os._exit(0)
while True:
    time.sleep(1)
'''
        for phase in (
            "PREPARED",
            "CREATED_ROOT",
            "DELEGATING",
            "DELEGATED",
            "RUNNING",
        ):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as td:
                os.chmod(td, 0o755)
                installer, layout, _source = make_installer(Path(td))
                layout.test_install = True
                layout.test_runner_scopes = True
                layout.target_uid = account.pw_uid
                layout.target_gid = account.pw_gid
                installer._prepare_roots()
                work = Path(td) / "crash-work"
                work.mkdir(mode=0o700)
                os.chown(work, account.pw_uid, account.pw_gid)
                descendant_path = work / "descendant.pid"
                checkpoint_read, checkpoint_write = os.pipe2(os.O_CLOEXEC)
                child = os.fork()
                if child == 0:
                    os.close(checkpoint_read)

                    def checkpoint() -> None:
                        os.write(checkpoint_write, b"1")
                        while True:
                            signal.pause()

                    original_create = release_installer._exclusive_runner_record
                    original_atomic = release_installer._atomic_json

                    def create_record(path, value, **kwargs):
                        result = original_create(path, value, **kwargs)
                        if phase == "PREPARED":
                            checkpoint()
                        return result

                    def replace_record(path, value, **kwargs):
                        result = original_atomic(path, value, **kwargs)
                        if (
                            isinstance(value, dict)
                            and value.get("phase") == phase
                            and path.parent == layout.runner_scope_root
                        ):
                            checkpoint()
                        return result

                    try:
                        with (
                            mock.patch.object(
                                release_installer,
                                "_exclusive_runner_record",
                                create_record,
                            ),
                            mock.patch.object(
                                release_installer,
                                "_atomic_json",
                                replace_record,
                            ),
                        ):
                            runner = installer._create_runner_scope(
                                account.pw_uid,
                                account.pw_gid,
                                time.monotonic_ns() + 30_000_000_000,
                                runner_kind="gate-smoke",
                                release_id=None,
                            )
                            if phase == "RUNNING":
                                process = subprocess.Popen(
                                    ["/usr/bin/python3", "-c", payload],
                                    close_fds=True,
                                    pass_fds=(runner.descriptor,),
                                    start_new_session=True,
                                    env={
                                        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                        "LANG": "C.UTF-8",
                                        "LC_ALL": "C.UTF-8",
                                        "RUNNER_DESCENDANT": str(descendant_path),
                                    },
                                    preexec_fn=runner.preexec(
                                        installer._drop_identity(
                                            account.pw_uid, account.pw_gid
                                        )
                                    ),
                                )
                                until = time.monotonic() + 8
                                while (
                                    not descendant_path.exists()
                                    and process.poll() is None
                                    and time.monotonic() < until
                                ):
                                    time.sleep(0.01)
                                if not descendant_path.exists():
                                    os._exit(93)
                                runner.mark_running()
                    except BaseException:
                        os._exit(91)
                    os._exit(92)
                os.close(checkpoint_write)
                record_path: Path | None = None
                scope_path: Path | None = None
                descendant_pidfd = -1
                child_reaped = False
                try:
                    readable, _, _ = select.select(
                        [checkpoint_read], [], [], 12
                    )
                    self.assertEqual(readable, [checkpoint_read])
                    self.assertEqual(os.read(checkpoint_read, 1), b"1")
                    records = tuple(layout.runner_scope_root.glob("*.json"))
                    self.assertEqual(len(records), 1)
                    record_path = records[0]
                    record = installer._read_runner_scope_record(record_path)
                    self.assertEqual(
                        record["record_version"],
                        release_installer.RUNNER_SCOPE_RECORD_VERSION,
                    )
                    self.assertEqual(record["phase"], phase)
                    scope_path = Path(str(record["scope_path"]))
                    self.assertEqual(scope_path.exists(), phase != "PREPARED")
                    if phase == "RUNNING":
                        descendant = int(
                            descendant_path.read_text(encoding="ascii")
                        )
                        descendant_pidfd = os.pidfd_open(descendant, 0)
                        self.assertFalse(
                            release_installer._pidfd_exit_ready(
                                descendant_pidfd, 0
                            )
                        )

                    os.kill(child, signal.SIGKILL)
                    waited, status = os.waitpid(child, 0)
                    child_reaped = True
                    self.assertEqual(waited, child)
                    self.assertTrue(os.WIFSIGNALED(status))
                    self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                    with mock.patch.object(
                        release_installer,
                        "_runner_cgroup_parent",
                        side_effect=AssertionError(
                            "valid journal recovery must not derive the current placement"
                        ),
                    ):
                        installer._recover_runner_scopes(
                            time.monotonic_ns() + 15_000_000_000
                        )
                    self.assertEqual(
                        tuple(layout.runner_scope_root.iterdir()), ()
                    )
                    self.assertFalse(record_path.exists())
                    self.assertFalse(scope_path.exists())
                    if descendant_pidfd >= 0:
                        self.assertTrue(
                            release_installer._pidfd_exit_ready(
                                descendant_pidfd, 2
                            )
                        )
                finally:
                    os.close(checkpoint_read)
                    if not child_reaped:
                        try:
                            os.kill(child, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            os.waitpid(child, 0)
                        except ChildProcessError:
                            pass
                    try:
                        installer._recover_runner_scopes(
                            time.monotonic_ns() + 15_000_000_000
                        )
                        self.assertEqual(
                            tuple(layout.runner_scope_root.iterdir()), ()
                        )
                        if record_path is not None:
                            self.assertFalse(record_path.exists())
                        if scope_path is not None:
                            self.assertFalse(scope_path.exists())
                    finally:
                        if descendant_pidfd >= 0:
                            os.close(descendant_pidfd)

    @unittest.skipUnless(
        os.geteuid() == 0
        and os.environ.get("GROK_RUN_ROOT_CGROUP_TEST") == "1",
        "requires explicit root cgroup integration authorization",
    )
    def test_root_runner_recovers_recovery_side_crash_phases(self) -> None:
        account = pwd.getpwnam(os.environ.get("SUDO_USER", "ubuntu"))
        for crash_point in ("RECOVERED", "CONTAINED", "AFTER_RMDIR"):
            with self.subTest(crash_point=crash_point), tempfile.TemporaryDirectory() as td:
                os.chmod(td, 0o755)
                installer, layout, _source = make_installer(Path(td))
                layout.test_install = True
                layout.test_runner_scopes = True
                layout.target_uid = account.pw_uid
                layout.target_gid = account.pw_gid
                installer._prepare_roots()

                creator = os.fork()
                if creator == 0:
                    try:
                        installer._create_runner_scope(
                            account.pw_uid,
                            account.pw_gid,
                            time.monotonic_ns() + 30_000_000_000,
                            runner_kind="gate-smoke",
                            release_id=None,
                        )
                    except BaseException:
                        os._exit(91)
                    os._exit(0)
                waited, status = os.waitpid(creator, 0)
                self.assertEqual(waited, creator)
                self.assertTrue(os.WIFEXITED(status))
                self.assertEqual(os.WEXITSTATUS(status), 0)

                records = tuple(layout.runner_scope_root.glob("*.json"))
                self.assertEqual(len(records), 1)
                record_path = records[0]
                record = installer._read_runner_scope_record(record_path)
                self.assertEqual(
                    record["record_version"],
                    release_installer.RUNNER_SCOPE_RECORD_VERSION,
                )
                self.assertEqual(record["phase"], "DELEGATED")
                scope_path = Path(str(record["scope_path"]))
                self.assertTrue(scope_path.exists())

                checkpoint_read, checkpoint_write = os.pipe2(os.O_CLOEXEC)
                recovery = os.fork()
                recovery_reaped = False
                if recovery == 0:
                    os.close(checkpoint_read)

                    def checkpoint() -> None:
                        os.write(checkpoint_write, b"1")
                        while True:
                            signal.pause()

                    original_atomic = release_installer._atomic_json
                    original_finalize = (
                        release_installer._RunnerCgroup.finalize_record
                    )

                    def replace_record(path, value, **kwargs):
                        result = original_atomic(path, value, **kwargs)
                        if (
                            crash_point in {"RECOVERED", "CONTAINED"}
                            and isinstance(value, dict)
                            and value.get("phase") == crash_point
                            and path.parent == layout.runner_scope_root
                        ):
                            checkpoint()
                        return result

                    def finalize_record(runner, *, journal_locked=False):
                        if crash_point == "AFTER_RMDIR":
                            checkpoint()
                        return original_finalize(
                            runner,
                            journal_locked=journal_locked,
                        )

                    try:
                        with (
                            mock.patch.object(
                                release_installer,
                                "_atomic_json",
                                replace_record,
                            ),
                            mock.patch.object(
                                release_installer._RunnerCgroup,
                                "finalize_record",
                                finalize_record,
                            ),
                        ):
                            installer._recover_runner_scopes(
                                time.monotonic_ns() + 30_000_000_000
                            )
                    except BaseException:
                        os._exit(91)
                    os._exit(92)

                os.close(checkpoint_write)
                try:
                    readable, _, _ = select.select(
                        [checkpoint_read], [], [], 12
                    )
                    self.assertEqual(readable, [checkpoint_read])
                    self.assertEqual(os.read(checkpoint_read, 1), b"1")
                    checkpoint_record = installer._read_runner_scope_record(
                        record_path
                    )
                    expected_phase = (
                        "CONTAINED"
                        if crash_point == "AFTER_RMDIR"
                        else crash_point
                    )
                    self.assertEqual(
                        checkpoint_record["record_version"],
                        release_installer.RUNNER_SCOPE_RECORD_VERSION,
                    )
                    self.assertEqual(
                        checkpoint_record["phase"], expected_phase
                    )
                    self.assertEqual(
                        scope_path.exists(), crash_point != "AFTER_RMDIR"
                    )

                    os.kill(recovery, signal.SIGKILL)
                    waited, status = os.waitpid(recovery, 0)
                    recovery_reaped = True
                    self.assertEqual(waited, recovery)
                    self.assertTrue(os.WIFSIGNALED(status))
                    self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)

                    installer._recover_runner_scopes(
                        time.monotonic_ns() + 15_000_000_000
                    )
                    self.assertFalse(scope_path.exists())
                    self.assertFalse(record_path.exists())
                    self.assertEqual(
                        tuple(layout.runner_scope_root.iterdir()), ()
                    )
                finally:
                    os.close(checkpoint_read)
                    if not recovery_reaped:
                        try:
                            os.kill(recovery, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            os.waitpid(recovery, 0)
                        except ChildProcessError:
                            pass
                    installer._recover_runner_scopes(
                        time.monotonic_ns() + 15_000_000_000
                    )
                    self.assertFalse(scope_path.exists())
                    self.assertFalse(record_path.exists())
                    self.assertEqual(
                        tuple(layout.runner_scope_root.iterdir()), ()
                    )

    def test_qualification_verifier_receives_one_reserved_absolute_deadline(self) -> None:
        self.assertEqual(
            release_installer.QUALIFICATION_WORK_TIMEOUT_SECONDS
            + release_installer.QUALIFICATION_CLEANUP_RESERVE_SECONDS
            + release_installer.QUALIFICATION_TERMINAL_RESERVE_SECONDS
            + release_installer.QUALIFICATION_CONTAINMENT_RESERVE_SECONDS,
            release_installer.RUNG_CANARY_TIMEOUT_SECONDS,
        )
        self.assertGreaterEqual(
            release_installer.QUALIFICATION_CLEANUP_RESERVE_SECONDS,
            120,
        )
        verifier_source = '''import json
import os
print(json.dumps([
    os.environ["GROK_QUALIFICATION_DEADLINE_MONOTONIC_NS"],
    os.environ["GROK_QUALIFICATION_CLEANUP_DEADLINE_MONOTONIC_NS"],
]), flush=True)
'''
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            (source / "grok_ms/qualification_verifier.py").write_text(
                verifier_source,
                encoding="ascii",
            )
            release_id = installer.install().release_id
            auth_fd = os.open(layout.canary_auth, os.O_RDONLY)
            environment = {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": str(layout.user_root.parents[2]),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            }
            before = time.monotonic_ns()
            try:
                result = installer._run_qualification_verifier(
                    release_id=release_id,
                    step="load32",
                    auth_fd=auth_fd,
                    environment=environment,
                )
            finally:
                os.close(auth_fd)
            after = time.monotonic_ns()
            self.assertEqual(result.returncode, 0)
            work_raw, cleanup_raw = json.loads(result.stdout)
            deadline = int(work_raw)
            cleanup_deadline = int(cleanup_raw)
            expected_ns = (
                release_installer.QUALIFICATION_WORK_TIMEOUT_SECONDS
                * 1_000_000_000
            )
            self.assertGreaterEqual(deadline, before + expected_ns)
            self.assertLessEqual(deadline, after + expected_ns)
            self.assertEqual(
                cleanup_deadline - deadline,
                release_installer.QUALIFICATION_CLEANUP_RESERVE_SECONDS
                * 1_000_000_000,
            )
            cleanup_expected_ns = (
                release_installer.QUALIFICATION_WORK_TIMEOUT_SECONDS
                + release_installer.QUALIFICATION_CLEANUP_RESERVE_SECONDS
            ) * 1_000_000_000
            self.assertGreaterEqual(
                cleanup_deadline, before + cleanup_expected_ns
            )
            self.assertLessEqual(
                cleanup_deadline, after + cleanup_expected_ns
            )
            self.assertNotIn(
                "GROK_QUALIFICATION_DEADLINE_MONOTONIC_NS", environment
            )
            self.assertNotIn(
                "GROK_QUALIFICATION_CLEANUP_DEADLINE_MONOTONIC_NS",
                environment,
            )

    def test_real_pair_uses_parent_death_without_resource_runner(self) -> None:
        verifier_source = '''import json
import os
print(json.dumps({
    "resource_authority": "GROK_QUALIFICATION_RESOURCE_CGROUP_PATH" in os.environ,
}), flush=True)
'''
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            (source / "grok_ms/qualification_verifier.py").write_text(
                verifier_source,
                encoding="ascii",
            )
            release_id = installer.install().release_id
            auth_fd = os.open(layout.canary_auth, os.O_RDONLY)
            environment = {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": str(layout.user_root.parents[2]),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            }
            try:
                with (
                    mock.patch.object(
                        installer, "_runner_scopes_required", return_value=True
                    ),
                    mock.patch.object(
                        installer, "_create_runner_scope"
                    ) as create,
                    mock.patch.object(
                        installer,
                        "_parent_death_preexec",
                        wraps=installer._parent_death_preexec,
                    ) as parent_death,
                ):
                    result = installer._run_qualification_verifier(
                        release_id=release_id,
                        step="real-pair",
                        auth_fd=auth_fd,
                        environment=environment,
                    )
            finally:
                os.close(auth_fd)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(
                json.loads(result.stdout),
                {"resource_authority": False},
            )
            create.assert_not_called()
            parent_death.assert_called_once()

    def test_qualification_runner_after_kill_selects_exact_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, _layout, _source = make_installer(Path(td))
            runner = mock.Mock()
            deadline = time.monotonic_ns() + 1_000_000_000
            record = {
                "runner_kind": "qualification",
                "release_id": "a" * 64,
                "phase": "RUNNING",
            }
            with mock.patch.object(
                installer,
                "_recover_qualification_runner_runtime",
                return_value=False,
            ) as recover:
                callback = installer._runner_after_kill(
                    runner,
                    record,
                    deadline,
                )
                self.assertIsNotNone(callback)
                assert callback is not None
                self.assertFalse(callback())
            recover.assert_called_once_with(
                runner,
                "a" * 64,
                deadline,
                strict_direct=True,
            )
            with mock.patch.object(
                installer,
                "_recover_qualification_runner_runtime",
                return_value=True,
            ) as legacy_recover:
                legacy = installer._runner_after_kill(
                    runner,
                    {
                        "runner_kind": "manual-canary",
                        "release_id": "a" * 64,
                        "phase": "DELEGATED",
                    },
                    deadline,
                )
                self.assertIsNotNone(legacy)
                assert legacy is not None
                self.assertTrue(legacy())
            legacy_recover.assert_called_once_with(
                runner,
                "a" * 64,
                deadline,
                strict_direct=False,
            )
            self.assertIsNone(
                installer._runner_after_kill(
                    runner,
                    {"runner_kind": "gate-smoke", "release_id": None},
                    deadline,
                )
            )
            self.assertIsNone(
                installer._runner_after_kill(
                    runner,
                    {
                        "runner_kind": "qualification",
                        "release_id": "a" * 64,
                        "phase": "RECOVERED",
                    },
                    deadline,
                )
            )

    def test_empty_session_group_is_killed_before_leader_reap(self) -> None:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        process: subprocess.Popen[bytes] | None = None
        pidfd = -1
        real_killpg = os.killpg
        observations: list[tuple[int | None, bool]] = []
        try:
            process = subprocess.Popen(
                [
                    "/usr/bin/python3",
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
                start_new_session=True,
            )
            pidfd = os.pidfd_open(process.pid, 0)
            os.close(read_fd)
            read_fd = -1
            os.write(write_fd, b"x")
            os.close(write_fd)
            write_fd = -1

            def observe_killpg(pgid: int, signum: int) -> None:
                assert process is not None
                observations.append(
                    (process.returncode, Path(f"/proc/{process.pid}").exists())
                )
                real_killpg(pgid, signum)

            with mock.patch.object(
                release_installer.os,
                "killpg",
                side_effect=observe_killpg,
            ):
                returncode = release_installer._kill_session_group_before_reap(
                    process,
                    pidfd,
                    graceful_seconds=2,
                )
            self.assertEqual(returncode, 0)
            self.assertEqual(observations, [(None, True)])
            self.assertEqual(process.returncode, 0)
        finally:
            for descriptor in (read_fd, write_fd, pidfd):
                if descriptor >= 0:
                    os.close(descriptor)
            if process is not None and process.returncode is None:
                try:
                    real_killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)

    def test_group_kill_failure_quarantines_leader_before_reap(self) -> None:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        process: subprocess.Popen[bytes] | None = None
        pidfd = -1
        real_killpg = os.killpg
        baseline = len(release_installer._QUARANTINED_SESSIONS)
        try:
            process = subprocess.Popen(
                [
                    "/usr/bin/python3",
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
                start_new_session=True,
            )
            pidfd = os.pidfd_open(process.pid, 0)
            os.close(read_fd)
            read_fd = -1
            os.write(write_fd, b"x")
            os.close(write_fd)
            write_fd = -1
            with mock.patch.object(
                release_installer.os,
                "killpg",
                side_effect=PermissionError("fixture group refusal"),
            ):
                with self.assertRaises(
                    release_installer.SessionContainmentError
                ):
                    release_installer._kill_session_group_before_reap(
                        process,
                        pidfd,
                        graceful_seconds=2,
                    )
            self.assertIsNone(process.returncode)
            self.assertTrue(Path(f"/proc/{process.pid}").exists())
            self.assertTrue(
                release_installer._session_is_quarantined(process)
            )
            self.assertEqual(
                len(release_installer._QUARANTINED_SESSIONS),
                baseline + 1,
            )
        finally:
            for item in release_installer._QUARANTINED_SESSIONS[baseline:]:
                try:
                    real_killpg(item.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if item.process.returncode is None:
                    item.process.wait(timeout=2)
                if item.leader_pidfd >= 0:
                    os.close(item.leader_pidfd)
            del release_installer._QUARANTINED_SESSIONS[baseline:]
            for descriptor in (read_fd, write_fd, pidfd):
                if descriptor >= 0:
                    os.close(descriptor)
            if process is not None and process.returncode is None:
                try:
                    real_killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)

    def test_unanchored_group_kill_failure_quarantines_before_reap(self) -> None:
        process: subprocess.Popen[bytes] | None = None
        real_killpg = os.killpg
        baseline = len(release_installer._QUARANTINED_SESSIONS)
        try:
            process = subprocess.Popen(
                ["/usr/bin/python3", "-I", "-c", "import time; time.sleep(30)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
            with mock.patch.object(
                release_installer.os,
                "killpg",
                side_effect=PermissionError("fixture group refusal"),
            ):
                with self.assertRaises(
                    release_installer.SessionContainmentError
                ):
                    release_installer._kill_session_group_without_pidfd_before_reap(
                        process
                    )
            self.assertIsNone(process.returncode)
            self.assertTrue(
                release_installer._session_is_quarantined(process)
            )
        finally:
            for item in release_installer._QUARANTINED_SESSIONS[baseline:]:
                try:
                    real_killpg(item.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if item.process.returncode is None:
                    item.process.wait(timeout=2)
                if item.leader_pidfd >= 0:
                    os.close(item.leader_pidfd)
            del release_installer._QUARANTINED_SESSIONS[baseline:]
            if process is not None and process.returncode is None:
                try:
                    real_killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)

    def test_runner_cleanup_kills_same_group_descendants_after_leader_exits_first(self) -> None:
        verifier_source = '''from pathlib import Path
import os
import time

marker = Path(os.environ["GROK_TEST_DESCENDANT_PID_FILE"])
pid = os.fork()
if pid == 0:
    marker.write_text(str(os.getpid()), encoding="ascii")
    null_fd = os.open("/dev/null", os.O_RDWR)
    os.dup2(null_fd, 1)
    os.dup2(null_fd, 2)
    os.close(null_fd)
    time.sleep(30)
    os._exit(0)
deadline = time.monotonic() + 2
while not marker.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
raise SystemExit(0)
'''
        gate_source = '''#!/usr/bin/python3
from pathlib import Path
import os
import sys
import time

marker = Path(sys.argv[1])
pid = os.fork()
if pid == 0:
    marker.write_text(str(os.getpid()), encoding="ascii")
    null_fd = os.open("/dev/null", os.O_RDWR)
    os.dup2(null_fd, 1)
    os.dup2(null_fd, 2)
    os.close(null_fd)
    time.sleep(30)
    os._exit(0)
deadline = time.monotonic() + 2
while not marker.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
os._exit(0)
'''
        for runner in ("gate-smoke", "qualification-verifier"):
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as td:
                installer, layout, source = make_installer(Path(td))
                if runner == "qualification-verifier":
                    (source / "grok_ms/qualification_verifier.py").write_text(
                        verifier_source,
                        encoding="ascii",
                    )
                release_id = installer.install().release_id
                marker = Path(td) / f"{runner}-descendant.pid"
                descendant_pid = -1
                try:
                    if runner == "gate-smoke":
                        gate = Path(td) / "leader-first-gate"
                        gate.write_text(gate_source, encoding="ascii")
                        gate.chmod(0o755)
                        result = installer._run_gate_smoke(
                            gate,
                            (str(marker),),
                            uid=layout.target_uid,
                            gid=layout.target_gid,
                            timeout=2,
                            output_limit=1024,
                        )
                    else:
                        auth_fd = os.open(layout.canary_auth, os.O_RDONLY)
                        try:
                            environment = {
                                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                "HOME": str(layout.user_root.parents[2]),
                                "LANG": "C.UTF-8",
                                "LC_ALL": "C.UTF-8",
                                "GROK_TEST_DESCENDANT_PID_FILE": str(marker),
                            }
                            result = installer._run_qualification_verifier(
                                release_id=release_id,
                                step="load32",
                                auth_fd=auth_fd,
                                environment=environment,
                            )
                        finally:
                            os.close(auth_fd)
                    self.assertEqual(result.returncode, 0)
                    self.assertTrue(marker.is_file())
                    descendant_pid = int(marker.read_text(encoding="ascii"))
                    self.assertTrue(
                        wait_process_stopped(descendant_pid),
                        f"{runner} left its descendant running",
                    )
                finally:
                    if descendant_pid > 0 and process_is_running(descendant_pid):
                        os.kill(descendant_pid, signal.SIGKILL)
                        wait_process_stopped(descendant_pid)

    def test_gate_smoke_timeout_has_one_fixed_containment_margin(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            installer.install()
            gate = Path(td) / "sleeping-gate"
            gate.write_text(
                "#!/usr/bin/python3\nimport time\ntime.sleep(30)\n",
                encoding="ascii",
            )
            gate.chmod(0o755)
            started = time.monotonic()
            result = installer._run_gate_smoke(
                gate,
                (),
                uid=layout.target_uid,
                gid=layout.target_gid,
                timeout=0.05,
                output_limit=1024,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(result.returncode, 124)
            self.assertLessEqual(
                elapsed,
                0.05
                + release_installer.GATE_SMOKE_CONTAINMENT_SECONDS
                + 1,
            )

    def test_gate_smoke_honors_a_shorter_caller_work_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            installer.install()
            gate = Path(td) / "caller-deadline-gate"
            gate.write_text(
                "#!/usr/bin/python3\nimport time\ntime.sleep(30)\n",
                encoding="ascii",
            )
            gate.chmod(0o755)
            started = time.monotonic()
            result = installer._run_gate_smoke(
                gate,
                (),
                uid=layout.target_uid,
                gid=layout.target_gid,
                timeout=15,
                output_limit=1024,
                work_deadline_monotonic_ns=time.monotonic_ns() + 50_000_000,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(result.returncode, 124)
            self.assertLessEqual(
                elapsed,
                0.05
                + release_installer.GATE_SMOKE_CONTAINMENT_SECONDS
                + 1,
            )

    def test_no_supervisor_drain_propagates_one_absolute_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, _layout, _source = make_installer(Path(td))
            installer.switch_timeout = 0.25
            seen: list[tuple[str, int]] = []

            def no_supervisor(*, deadline_monotonic_ns: int):
                seen.append(("supervisor", deadline_monotonic_ns))
                return None

            def empty_inventory(
                *,
                allow_root_artifact_residue: bool,
                deadline_monotonic_ns: int,
                broker_inventory: bool = True,
            ) -> dict[str, object]:
                del allow_root_artifact_residue, broker_inventory
                seen.append(("inventory", deadline_monotonic_ns))
                return {}

            before = time.monotonic_ns()
            with mock.patch.object(
                installer,
                "_live_supervisor_pidfd",
                side_effect=no_supervisor,
            ), mock.patch.object(
                installer,
                "_assert_switch_quiescent",
                side_effect=empty_inventory,
            ):
                installer._drain_active()
            after = time.monotonic_ns()
            self.assertEqual([name for name, _value in seen], ["supervisor", "inventory"])
            self.assertEqual(seen[0][1], seen[1][1])
            self.assertGreaterEqual(seen[0][1], before + 200_000_000)
            self.assertLessEqual(seen[0][1], after + 250_000_000)

    def test_switch_inventory_budget_exhaustion_keeps_old_selection_fenced(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            old_id = installer.install().release_id
            write_source(source, "v2")
            before = (installer.active_release_id(), installer.root_active_release_id())
            with mock.patch.object(
                release_installer,
                "MAX_SWITCH_QUIESCENCE_INVENTORY_ENTRIES",
                2,
            ):
                with self.assertRaisesRegex(
                    release_installer.ReleaseError,
                    "switch inventory entry limit exceeded",
                ):
                    installer.install()
            self.assertEqual(
                (installer.active_release_id(), installer.root_active_release_id()),
                before,
            )
            self.assertEqual(before, (old_id, old_id))
            self.assertTrue(layout.rollback_deny.exists())
            resumed = installer.install()
            self.assertNotEqual(resumed.release_id, old_id)
            self.assertFalse(layout.rollback_deny.exists())

    def test_switch_inventory_budget_covers_live_shaped_aggregate(self) -> None:
        observed_clean_pass = (
            ("legacy process inventory", 1_273),
            ("release process inventory", 1_273),
            ("TCP listener inventory", 54),
            ("cgroup-v2 inventory", 8_545),
        )
        observed_total = sum(count for _operation, count in observed_clean_pass)
        budget = release_installer._SwitchInventoryBudget(
            time.monotonic_ns() + 5_000_000_000
        )
        for operation, count in observed_clean_pass:
            for _entry in range(count):
                budget.consume_entry(operation)
        self.assertGreaterEqual(budget.entries_remaining, observed_total)

        exhausted = release_installer._SwitchInventoryBudget(
            time.monotonic_ns() + 5_000_000_000
        )
        for _entry in range(
            release_installer.MAX_SWITCH_QUIESCENCE_INVENTORY_ENTRIES
        ):
            exhausted.consume_entry("bounded inventory")
        with self.assertRaisesRegex(
            release_installer.ReleaseError,
            "switch inventory entry limit exceeded",
        ):
            exhausted.consume_entry("bounded inventory")

    def test_switch_inventory_leaf_scanners_reject_expired_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, _layout, _source = make_installer(Path(td))
            methods = (
                installer._legacy_openvpn_process_inventory,
                installer._release_bound_process_inventory,
                installer._fixed_listener_inventory,
                installer._fixed_cgroup_inventory,
            )
            for method in methods:
                with self.subTest(method=method.__name__):
                    budget = release_installer._SwitchInventoryBudget(
                        time.monotonic_ns() - 1
                    )
                    with self.assertRaisesRegex(
                        release_installer.ReleaseError,
                        "timed out during switch",
                    ):
                        method(budget)

    def test_release_pair_is_deterministic_immutable_and_executable_through_gates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fixture, _boot_id, _pid = write_proc_fixture(base / "fixture-prefix")
            descriptor = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            authority = release_installer.ProcAuthority.from_fd(
                descriptor, display=fixture, fixture=True
            )
            os.close(descriptor)
            installer, layout, _source = make_installer(
                base / "install", proc_authority=authority
            )
            plan = installer.plan_release()
            self.assertEqual(plan.release_id, installer.plan_release().release_id)

            result = installer.install()
            self.assertTrue(result.changed)
            self.assertEqual(result.release_id, plan.release_id)
            installer.validate_release_pair(result.release_id)

            user_release = layout.user_releases / result.release_id
            root_release = layout.root_releases / result.release_id
            root_manifest = json.loads((root_release / "release.json").read_text())
            self.assertEqual(
                {entry["path"] for entry in root_manifest["files"]},
                set(RUNTIME_FILES),
            )
            self.assertEqual(
                {
                    entry["role"]
                    for entry in root_manifest["files"]
                    if "role" in entry
                },
                set(ROOT_FILES),
            )
            self.assertEqual(
                stat.S_IMODE(
                    (root_release / release_installer.INSTALLER_RUNTIME).stat().st_mode
                ),
                0o444,
            )
            for path in (user_release, root_release, user_release / "grok_ms"):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((root_release / "vpn-broker").stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((root_release / "sanitize.awk").stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE((user_release / "release.json").stat().st_mode), 0o444)

            self.assertEqual(os.readlink(layout.current), f"releases/{result.release_id}")
            self.assertEqual(os.readlink(layout.root_current), f"releases/{result.release_id}")
            self.assertFalse(layout.entrypoint.is_symlink())
            self.assertFalse(layout.broker_entrypoint.is_symlink())
            self.assertEqual(stat.S_IMODE(layout.entrypoint.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(layout.broker_entrypoint.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(layout.root_selected.stat().st_mode), 0o444)
            self.assertEqual(layout.root_selected.stat().st_uid, layout.root_uid)
            self.assertFalse(layout.rollback_deny.exists())

            user = invoke(layout.entrypoint, "--flag", "value")
            broker = invoke(layout.broker_entrypoint, "status")
            self.assertEqual(user.returncode, 0, user.stderr)
            self.assertEqual(user.stdout, "grok-remote:v1:--flag value\n")
            self.assertEqual(broker.returncode, 0, broker.stderr)
            self.assertEqual(broker.stdout, "vpn-broker:v1:status:evil=unset\n")
            status = installer.status()
            self.assertTrue(status["active_release_valid"])
            self.assertEqual(status["active_release_id"], result.release_id)
            self.assertTrue(status["release_access_policy_valid"])
            self.assertTrue(status["rollback_eligibility_complete"])
            self.assertEqual(status["rollback_eligible_releases"], [result.release_id])
            self.assertEqual(status["archived_user_releases"], [])
            self.assertEqual(status["exposed_user_releases"], [result.release_id])
            self.assertEqual(
                status["user_release_modes"],
                {result.release_id: "0555"},
            )

    def test_only_selected_release_pair_is_exposed_and_rollback_switches_access(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            first = installer.install().release_id
            write_source(source, "v2")
            second = installer.install().release_id
            self.assertNotEqual(first, second)

            self.assertEqual(
                stat.S_IMODE((layout.user_releases / first).stat().st_mode),
                release_installer.ARCHIVED_RELEASE_MODE,
            )
            self.assertEqual(
                stat.S_IMODE((layout.user_releases / second).stat().st_mode),
                release_installer.ACTIVE_RELEASE_MODE,
            )
            for release_id in (first, second):
                self.assertEqual(
                    stat.S_IMODE(
                        (layout.root_releases / release_id).stat().st_mode
                    ),
                    release_installer.ACTIVE_RELEASE_MODE,
                )
            status = installer.status()
            self.assertEqual(status["archived_user_releases"], [first])
            self.assertEqual(status["exposed_user_releases"], [second])
            self.assertEqual(
                status["rollback_eligible_releases"],
                sorted((first, second)),
            )
            installer.validate_release_pair(first)
            installer.validate_target_release_pair(first)

            installer.rollback(first)
            self.assertEqual(
                stat.S_IMODE((layout.user_releases / first).stat().st_mode),
                release_installer.ACTIVE_RELEASE_MODE,
            )
            self.assertEqual(
                stat.S_IMODE((layout.user_releases / second).stat().st_mode),
                release_installer.ARCHIVED_RELEASE_MODE,
            )
            self.assertTrue(installer._selection_is_exact(first))

            installer.rollback(second)
            self.assertEqual(
                stat.S_IMODE((layout.user_releases / first).stat().st_mode),
                release_installer.ARCHIVED_RELEASE_MODE,
            )
            self.assertEqual(
                stat.S_IMODE((layout.user_releases / second).stat().st_mode),
                release_installer.ACTIVE_RELEASE_MODE,
            )

    def test_release_without_self_admission_cannot_be_selected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            current = installer.install().release_id
            legacy_files = tuple(
                path for path in RUNTIME_FILES
                if path != release_installer.DIRECT_ADMISSION_RUNTIME
            )
            legacy_installer = release_installer.ReleaseInstaller(
                layout,
                runtime_files=legacy_files,
                root_files=ROOT_FILES,
            )
            write_source(source, "legacy")
            legacy_plan = legacy_installer.plan_release()
            with legacy_installer._locked():
                for kind in ("root", "user"):
                    stage, final = legacy_installer._stage_release(
                        legacy_plan, kind
                    )
                    legacy_installer._publish_stage(stage, final)
                legacy_installer._converge_release_access(current)

            for operation in (
                lambda: installer.preview_rollback(legacy_plan.release_id),
                lambda: installer.rollback(legacy_plan.release_id),
            ):
                with self.assertRaisesRegex(
                    release_installer.ReleaseError,
                    "predates mandatory direct self-admission",
                ):
                    operation()
            self.assertEqual(installer.active_release_id(), current)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertEqual(
                stat.S_IMODE(
                    (layout.user_releases / legacy_plan.release_id).stat().st_mode
                ),
                release_installer.ARCHIVED_RELEASE_MODE,
            )
            self.assertEqual(
                stat.S_IMODE(
                    (layout.root_releases / legacy_plan.release_id).stat().st_mode
                ),
                release_installer.ACTIVE_RELEASE_MODE,
            )
            legacy_user = layout.user_releases / legacy_plan.release_id
            legacy_user.chmod(release_installer.ACTIVE_RELEASE_MODE)
            with installer._locked():
                installer._publish_deny("install", current, current)
                deny = installer._deny_record()
                assert deny is not None
                installer._converge_deny_release_access(deny)
                installer._clear_deny()
            self.assertEqual(
                stat.S_IMODE(legacy_user.stat().st_mode),
                release_installer.ARCHIVED_RELEASE_MODE,
            )

    def test_dormant_self_admission_module_cannot_match_production_contract(self) -> None:
        contents = {
            relative: (ROOT / relative).read_bytes()
            for relative in release_installer.DIRECT_ADMISSION_PRODUCTION_SHA256
        }
        self.assertTrue(
            release_installer._production_direct_admission_is_exact(contents)
        )
        bypass = dict(contents)
        bypass["grok-remote"] = bypass["grok-remote"].replace(
            release_installer.GROK_ORDINARY_ADMISSION_BLOCK,
            b"require_installed_release(){\n  return 0\n}\n",
        )
        self.assertNotEqual(bypass["grok-remote"], contents["grok-remote"])
        self.assertFalse(
            release_installer._production_direct_admission_is_exact(bypass)
        )

    def test_production_admission_rejects_reviewed_component_hybrids(self) -> None:
        paths = ("grok-remote", "egress.sh", "grok_ms/release_admission.py")
        first = {paths[0]: b"grok-a", paths[1]: b"egress-a", paths[2]: b"gate-a"}
        second = {paths[0]: b"grok-b", paths[1]: b"egress-b", paths[2]: b"gate-b"}
        bundles = frozenset(
            {
                tuple(hashlib.sha256(first[path]).hexdigest() for path in paths),
                tuple(hashlib.sha256(second[path]).hexdigest() for path in paths),
            }
        )
        hybrid = dict(first)
        hybrid[paths[1]] = second[paths[1]]
        with (
            mock.patch.object(
                release_installer,
                "DIRECT_ADMISSION_PRODUCTION_PATHS",
                paths,
            ),
            mock.patch.object(
                release_installer,
                "DIRECT_ADMISSION_PRODUCTION_BUNDLES",
                bundles,
            ),
        ):
            self.assertTrue(
                release_installer._production_direct_admission_is_exact(first)
            )
            self.assertTrue(
                release_installer._production_direct_admission_is_exact(second)
            )
            self.assertFalse(
                release_installer._production_direct_admission_is_exact(hybrid)
            )

    def test_status_detects_access_drift_and_idempotent_install_repairs_it(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            first = installer.install().release_id
            write_source(source, "v2")
            second = installer.install().release_id

            inactive = layout.user_releases / first
            inactive.chmod(release_installer.ACTIVE_RELEASE_MODE)
            self.assertFalse(installer.status()["active_release_valid"])
            repaired = installer.install()
            self.assertFalse(repaired.changed)
            self.assertEqual(repaired.release_id, second)
            self.assertEqual(
                stat.S_IMODE(inactive.stat().st_mode),
                release_installer.ARCHIVED_RELEASE_MODE,
            )
            self.assertTrue(installer.status()["active_release_valid"])

            active = layout.user_releases / second
            active.chmod(release_installer.ARCHIVED_RELEASE_MODE)
            self.assertFalse(installer.status()["active_release_valid"])
            repaired = installer.install()
            self.assertFalse(repaired.changed)
            self.assertEqual(
                stat.S_IMODE(active.stat().st_mode),
                release_installer.ACTIVE_RELEASE_MODE,
            )
            self.assertTrue(installer.status()["active_release_valid"])

    def test_idempotent_quarantine_failure_is_deny_fenced_until_retry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            first = installer.install().release_id
            write_source(source, "v2")
            second = installer.install().release_id
            inactive = layout.user_releases / first
            inactive.chmod(release_installer.ACTIVE_RELEASE_MODE)
            failed = False
            original = release_installer.os.fchmod

            def fail_inactive_archive(descriptor: int, mode: int) -> None:
                nonlocal failed
                opened = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                if (
                    not failed
                    and opened == inactive
                    and mode == release_installer.ARCHIVED_RELEASE_MODE
                ):
                    failed = True
                    raise OSError(errno.EIO, "injected quarantine failure")
                original(descriptor, mode)

            with mock.patch.object(
                release_installer.os,
                "fchmod",
                side_effect=fail_inactive_archive,
            ), self.assertRaisesRegex(
                release_installer.ReleaseError,
                "durably converge release access",
            ):
                installer.install()

            self.assertTrue(failed)
            self.assertTrue(layout.rollback_deny.exists())
            self.assertEqual(installer.active_release_id(), second)
            self.assertEqual(invoke(layout.entrypoint).returncode, 78)

            repaired = installer.install()
            self.assertFalse(repaired.changed)
            self.assertEqual(repaired.release_id, second)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertEqual(
                stat.S_IMODE(inactive.stat().st_mode),
                release_installer.ARCHIVED_RELEASE_MODE,
            )
            self.assertTrue(installer.status()["active_release_valid"])

    def test_access_convergence_faults_keep_deny_and_retry_cleanly(self) -> None:
        for fault_kind in ("fchmod", "fsync"):
            with self.subTest(fault_kind=fault_kind), tempfile.TemporaryDirectory() as td:
                installer, layout, source = make_installer(Path(td))
                first = installer.install().release_id
                write_source(source, "v2")
                second = installer.install().release_id
                target = layout.user_releases / first
                failed = False

                if fault_kind == "fchmod":
                    original = release_installer.os.fchmod

                    def fail_once(descriptor: int, mode: int) -> None:
                        nonlocal failed
                        if (
                            not failed
                            and mode == release_installer.ACTIVE_RELEASE_MODE
                            and stat.S_IMODE(os.fstat(descriptor).st_mode)
                            == release_installer.ARCHIVED_RELEASE_MODE
                        ):
                            failed = True
                            raise OSError(errno.EIO, "injected fchmod failure")
                        original(descriptor, mode)

                    patcher = mock.patch.object(
                        release_installer.os,
                        "fchmod",
                        side_effect=fail_once,
                    )
                else:
                    original = release_installer.os.fsync

                    def fail_once(descriptor: int) -> None:
                        nonlocal failed
                        try:
                            opened = Path(
                                os.readlink(f"/proc/self/fd/{descriptor}")
                            )
                        except OSError:
                            opened = Path("/")
                        if not failed and opened == target:
                            failed = True
                            raise OSError(errno.EIO, "injected fsync failure")
                        original(descriptor)

                    patcher = mock.patch.object(
                        release_installer.os,
                        "fsync",
                        side_effect=fail_once,
                    )

                with patcher, self.assertRaisesRegex(
                    release_installer.ReleaseError,
                    "durably converge release access",
                ):
                    installer.rollback(first)
                self.assertTrue(failed)
                self.assertTrue(layout.rollback_deny.exists())
                self.assertEqual(installer.active_release_id(), second)

                resumed = installer.rollback(first)
                self.assertEqual(resumed.release_id, first)
                self.assertFalse(layout.rollback_deny.exists())
                self.assertTrue(installer._selection_is_exact(first))

    def test_broker_inventory_failure_reports_hashes_not_hostile_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, _layout, _source = make_installer(Path(td))
            installer.install()
            stdout_data = (
                b"stdout-secret\x1b]8;;https://example.invalid\x07link"
                b"\x1b]8;;\x07\r\b"
            )
            stderr_data = b"stderr-secret\x1b[31mred\x1b[0m\x07\r\b"
            result = release_installer.SmokeResult(
                47, stdout_data, stderr_data, 1
            )
            with mock.patch.object(
                installer, "_run_gate_smoke", return_value=result
            ):
                with self.assertRaises(release_installer.ReleaseError) as raised:
                    installer._broker_inventory()

            message = str(raised.exception)
            self.assertIn("failed with exit 47", message)
            self.assertIn(f"stdout_bytes={len(stdout_data)}", message)
            self.assertIn(
                f"stdout_sha256={hashlib.sha256(stdout_data).hexdigest()}", message
            )
            self.assertIn(f"stderr_bytes={len(stderr_data)}", message)
            self.assertIn(
                f"stderr_sha256={hashlib.sha256(stderr_data).hexdigest()}", message
            )
            for secret in ("stdout-secret", "stderr-secret", "example.invalid"):
                self.assertNotIn(secret, message)
            for control in ("\x1b", "\x07", "\r", "\b"):
                self.assertNotIn(control, message)

    def test_runtime_discovery_is_recursive_but_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source"
            write_default_source(source, "v1")
            discovered = release_installer._default_runtime_files(source)
            self.assertEqual(set(discovered), set(RUNTIME_FILES))
            self.assertNotIn("untrusted-extra.py", discovered)
            self.assertFalse(any("__pycache__" in path for path in discovered))
            self.assertFalse(any(path.startswith("tests/") for path in discovered))

            target = source / "outside.py"
            target.write_text("outside\n", encoding="utf-8")
            link = source / "grok_ms/linked.py"
            link.symlink_to(target)
            with self.assertRaisesRegex(release_installer.ReleaseError, "symlink"):
                release_installer._default_runtime_files(source)

    def test_apply_prerequisite_requires_safe_fixed_openvpn(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            fixture = base / "openvpn"
            fixture.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            fixture.chmod(0o700)
            layout.test_install = True
            layout.openvpn_binary = fixture
            installer.validate_apply_prerequisites()

            fixture.chmod(0o722)
            with self.assertRaisesRegex(release_installer.ReleaseError, "unsafe"):
                installer.validate_apply_prerequisites()
            fixture.chmod(0o700)
            link = base / "openvpn-link"
            link.symlink_to(fixture)
            layout.openvpn_binary = link
            with self.assertRaisesRegex(release_installer.ReleaseError, "unsafe"):
                installer.validate_apply_prerequisites()

            layout.test_install = False
            layout.openvpn_binary = fixture
            with self.assertRaisesRegex(release_installer.ReleaseError, "fixed"):
                installer.validate_apply_prerequisites()

    def test_deny_and_every_mixed_or_corrupt_selection_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            old_id = installer.install().release_id
            with installer._locked():
                installer._publish_deny("install", old_id, old_id)
            for gate in (layout.entrypoint, layout.broker_entrypoint):
                denied = invoke(gate)
                self.assertEqual(denied.returncode, 78)
                self.assertIn("durable install/rollback deny", denied.stderr)
            cleanup = invoke(layout.broker_entrypoint, "--operation", "status")
            self.assertEqual(cleanup.returncode, 0, cleanup.stderr)
            self.assertIn("vpn-broker:v1:--operation status", cleanup.stdout)
            mutating = invoke(layout.broker_entrypoint, "--operation", "up")
            self.assertEqual(mutating.returncode, 78)
            duplicate = invoke(
                layout.broker_entrypoint,
                "--operation",
                "status",
                "--operation",
                "down",
            )
            self.assertEqual(duplicate.returncode, 78)
            self.assertFalse(installer.status()["active_release_valid"])
            with installer._locked():
                installer._clear_deny()

            write_source(source, "v2")
            new_id = installer.install().release_id
            layout.root_current.unlink()
            layout.root_current.symlink_to(f"releases/{old_id}")
            mixed = invoke(layout.entrypoint)
            self.assertEqual(mixed.returncode, 78)
            self.assertIn("mixed selector", mixed.stderr)
            self.assertFalse(installer.status()["active_release_valid"])

            layout.root_current.unlink()
            layout.root_current.symlink_to(f"releases/{new_id}")
            layout.root_selected.chmod(0o644)
            corrupt = invoke(layout.entrypoint)
            self.assertEqual(corrupt.returncode, 78)
            self.assertIn("unsafe owner/mode", corrupt.stderr)

    def test_generated_broker_gate_admits_only_exact_vpn_rung_canary_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            contract = "c" * 64
            installer.begin_rung_canary(
                release_id=release_id,
                rung="vpn",
                route_profile="vpn",
                contract_sha256=contract,
                grok_release_id="sha256:" + "d" * 64,
                model_id="grok-4.5",
            )

            def broker(*arguments: str) -> subprocess.CompletedProcess[str]:
                return invoke(
                    layout.broker_entrypoint,
                    "--operation",
                    arguments[0],
                    "--mode",
                    arguments[1],
                    "--release-id",
                    release_id,
                    "--contract-digest",
                    arguments[2],
                    *arguments[3:],
                )

            for operation in ("up", "next"):
                admitted = broker(operation, "supervisor", contract)
                self.assertEqual(admitted.returncode, 0, admitted.stderr)
                self.assertIn(f"--operation {operation}", admitted.stdout)

            rejected = (
                broker("up", "compatibility", contract),
                broker("reset", "supervisor", contract),
                broker("up", "supervisor", "f" * 64),
                broker("up", "supervisor", contract, "--oper", "reset"),
                broker(
                    "up",
                    "supervisor",
                    contract,
                    "--owner-epoch",
                    "first",
                    "--owner-epoch",
                    "second",
                ),
                broker(
                    "up",
                    "supervisor",
                    contract,
                    "--contract-digest",
                    contract,
                ),
            )
            for result in rejected:
                self.assertEqual(result.returncode, 78)
                self.assertIn("durable install/rollback deny", result.stderr)

            terminal = layout.canary_terminal
            terminal.write_text("{}\n", encoding="ascii")
            terminal.chmod(0o444)
            terminal_rejected = broker("up", "supervisor", contract)
            self.assertEqual(terminal_rejected.returncode, 78)
            terminal.unlink()

            record = json.loads(layout.rung_canary.read_text(encoding="ascii"))
            layout.rung_canary.chmod(0o600)
            record["rung"] = "direct"
            layout.rung_canary.write_text(json.dumps(record), encoding="ascii")
            layout.rung_canary.chmod(0o444)
            rung_rejected = broker("up", "supervisor", contract)
            self.assertEqual(rung_rejected.returncode, 78)

    def test_public_recover_is_admitted_under_deny_and_unblocks_resume(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            prefix = base / "prefix"
            home = Path("/home/caller")
            openvpn = base / "openvpn"
            openvpn.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            openvpn.chmod(0o700)
            layout = release_installer.Layout.defaults(
                ROOT,
                prefix=prefix,
                home=home,
                test_openvpn_binary=openvpn,
            )
            runtime_files = release_installer._default_runtime_files(ROOT)
            installer = release_installer.ReleaseInstaller(
                layout,
                runtime_files=runtime_files,
                root_files=release_installer._default_root_files(runtime_files),
            )
            installer.validate_apply_prerequisites()
            release_id = installer.install().release_id
            # Recovery must remain reachable under durable deny even when the
            # promotion record is the reason normal admission became invalid.
            layout.evidence_path(release_id).unlink()

            control = prefix / "home/caller/.local/state/grok-proxy/control"
            control.mkdir(parents=True, mode=0o700)
            control.chmod(0o700)
            fence = {
                "schema_version": release_installer.CONTROL_SCHEMA_VERSION,
                "release_id": release_id,
                "owner_epoch": "dead-fixture-owner",
                "pid": 2_147_483_000,
                "pid_start_ticks": 1,
                "boot_id": Path("/proc/sys/kernel/random/boot_id")
                .read_text(encoding="ascii")
                .strip(),
                "phase": "READY",
            }
            layout.recovery_fence.write_text(
                json.dumps(fence, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            layout.recovery_fence.chmod(0o600)
            with installer._locked():
                installer._publish_deny("install", release_id, release_id)

            environment = dict(os.environ)
            environment.update(
                {
                    "GROK_TESTING": "1",
                    "GROK_TEST_SKIP_WARM_HANDOFF": "1",
                    "HOME": str(prefix / "home/caller"),
                    "XDG_STATE_HOME": str(prefix / "home/caller/.local/state"),
                }
            )
            ordinary = subprocess.run(
                [str(layout.entrypoint), "--direct", "-m", "grok-build", "prompt"],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
                env=environment,
            )
            maintenance = subprocess.run(
                [str(layout.entrypoint), "stop"],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
                env=environment,
            )
            wrong_arity = subprocess.run(
                [str(layout.entrypoint), "recover", "extra"],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
                env=environment,
            )
            nonliteral_recovery = subprocess.run(
                [str(layout.entrypoint), "recover"],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
                env={**environment, "GROK_MULTI_SESSION": "true"},
            )
            fence_after_nonliteral_recovery = layout.recovery_fence.exists()
            recovered = subprocess.run(
                [str(layout.entrypoint), "recover"],
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
                env=environment,
            )
            self.assertEqual(ordinary.returncode, 78, ordinary.stderr)
            self.assertEqual(maintenance.returncode, 78, maintenance.stderr)
            self.assertEqual(wrong_arity.returncode, 78, wrong_arity.stderr)
            self.assertEqual(
                nonliteral_recovery.returncode,
                78,
                nonliteral_recovery.stderr,
            )
            self.assertTrue(fence_after_nonliteral_recovery)
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertTrue(json.loads(recovered.stdout)["recovered"])
            self.assertFalse(layout.recovery_fence.exists())
            self.assertTrue(layout.rollback_deny.exists())

            layout.recovery_fence.write_text(
                json.dumps(fence, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            layout.recovery_fence.chmod(0o600)
            marker_zero = subprocess.run(
                [str(layout.entrypoint), "recover"],
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
                env={**environment, "GROK_MULTI_SESSION": "0"},
            )
            self.assertEqual(marker_zero.returncode, 0, marker_zero.stderr)
            self.assertFalse(layout.recovery_fence.exists())

            resumed = installer.install()
            self.assertEqual(resumed.release_id, release_id)
            self.assertFalse(layout.rollback_deny.exists())

    def test_exact_standalone_handoff_self_admits_under_deny(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            prefix = base / "prefix"
            home = Path("/home/caller")
            openvpn = base / "openvpn"
            openvpn.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            openvpn.chmod(0o700)
            layout = release_installer.Layout.defaults(
                ROOT,
                prefix=prefix,
                home=home,
                test_openvpn_binary=openvpn,
            )
            runtime_files = release_installer._default_runtime_files(ROOT)
            installer = release_installer.ReleaseInstaller(
                layout,
                runtime_files=runtime_files,
                root_files=release_installer._default_root_files(runtime_files),
            )
            installer.validate_apply_prerequisites()
            release_id = installer.install().release_id
            egress = layout.user_releases / release_id / "egress.sh"
            with installer._locked():
                installer._publish_deny("canary", release_id, release_id)
            environment = dict(os.environ)
            environment.update(
                {
                    "GROK_TESTING": "1",
                    "GROK_TEST_ROOT_RELEASE_CONTROL": str(layout.root_control),
                    "GROK_HANDOFF_MODE": "1",
                }
            )
            try:
                ordinary = subprocess.run(
                    [str(egress), "status"],
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                    env=environment,
                )
                handoff = subprocess.run(
                    [str(egress), "compatibility-handoff"],
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                    env=environment,
                )
            finally:
                with installer._locked():
                    installer._clear_deny()

            self.assertEqual(ordinary.returncode, 78, ordinary.stderr)
            self.assertIn("durable install/rollback deny", ordinary.stderr)
            self.assertNotEqual(handoff.returncode, 78, handoff.stderr)
            self.assertIn("invalid compatibility-handoff owner", handoff.stderr)

    def test_fixed_promotion_evidence_is_closed_and_required_by_gates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            evidence_path = layout.evidence_path(release_id)
            evidence = json.loads(evidence_path.read_text())
            self.assertEqual(stat.S_IMODE(evidence_path.stat().st_mode), 0o444)
            self.assertEqual(evidence_path.stat().st_uid, layout.root_uid)
            self.assertEqual(
                tuple(item["id"] for item in evidence["criteria"]),
                release_installer.EVIDENCE_CRITERIA,
            )
            self.assertTrue(evidence["overall_pass"])
            self.assertNotIn("boot_id", evidence)
            self.assertNotIn("qualified_rungs", evidence)
            selected = json.loads(layout.selected.read_text())
            self.assertEqual(selected["selection_phase"], "READY")
            self.assertEqual(selected["qualified_rungs"], [])
            boot_inventory = json.loads(
                layout.boot_inventory_path(release_id).read_text()
            )
            self.assertEqual(boot_inventory["release_id"], release_id)
            self.assertEqual(boot_inventory["boot_id"], installer._boot_id())
            self.assertEqual(
                selected["evidence_sha256"],
                hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            )

            evidence_path.unlink()
            denied = invoke(layout.entrypoint)
            self.assertEqual(denied.returncode, 78, denied.stderr)
            self.assertIn("evidence", denied.stderr)
            self.assertFalse(installer.status()["active_release_valid"])
            resumed = installer.install()
            self.assertEqual(resumed.release_id, release_id)
            self.assertTrue(evidence_path.is_file())
            self.assertTrue(installer.status()["active_release_valid"])

    def test_canary_authorization_fd_cannot_be_forged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            release_id = installer.install().release_id
            with installer._locked():
                installer._publish_deny("install", release_id, release_id)
            forged = base / "forged-auth"
            forged.write_bytes(b"")
            forged.chmod(0o600)
            descriptor = os.open(forged, os.O_RDONLY)
            try:
                environment = dict(os.environ)
                environment["GROK_RELEASE_CANARY_FD"] = str(descriptor)
                result = subprocess.run(
                    [str(layout.entrypoint), "--help"],
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                    env=environment,
                    pass_fds=(descriptor,),
                )
            finally:
                os.close(descriptor)
            self.assertEqual(result.returncode, 78, result.stderr)
            self.assertIn("incomplete release/rung canary authorization", result.stderr)
            with installer._locked():
                installer._clear_deny()

    def test_generated_user_gate_rejects_canary_bypasses_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            dispatched = base / "canary-dispatched"
            wrapper = source / "grok-remote"
            wrapper.write_text(
                wrapper.read_text(encoding="utf-8").replace(
                    '  printf "fixture-canary:%s\\n" "$1"\n',
                    f"  : > '{dispatched}'\n"
                    '  printf "fixture-canary:%s\\n" "$1"\n',
                ),
                encoding="utf-8",
            )
            release_id = installer.install().release_id
            dispatched.unlink(missing_ok=True)
            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256="a" * 64,
                grok_release_id="grok-build-v1",
                model_id="grok-model",
            )

            for argv in (
                ("--help",),
                ("inspect",),
                ("stop",),
                ("stop", "extra"),
                ("iphone-setup",),
                ("--direct", "leader"),
            ):
                with self.subTest(rejected=argv):
                    result = installer.canary_exec(argv)
                    self.assertEqual(result.returncode, 78)
                    self.assertFalse(dispatched.exists())

            for argv in (("status",), ("recover",), ("-m", "grok-model", "prompt")):
                with self.subTest(allowed=argv):
                    dispatched.unlink(missing_ok=True)
                    result = installer.canary_exec(argv)
                    self.assertEqual(result.returncode, 0)
                    self.assertTrue(dispatched.exists())
            installer.abort_restore(release_id)

    def test_manual_canary_keeps_parent_death_containment_when_runner_scopes_required(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, _layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256="a" * 64,
                grok_release_id="grok-build-v1",
                model_id="grok-model",
            )
            with (
                mock.patch.object(
                    installer, "_runner_scopes_required", return_value=True
                ),
                mock.patch.object(installer, "_create_runner_scope") as create,
                mock.patch.object(
                    installer,
                    "_parent_death_preexec",
                    wraps=installer._parent_death_preexec,
                ) as parent_death,
            ):
                result = installer.canary_exec(("status",))

            self.assertEqual(result.returncode, 0)
            create.assert_not_called()
            parent_death.assert_called_once()
            installer.abort_restore(release_id)

    def test_generated_user_gate_rejects_every_partial_canary_before_bash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            dispatched = base / "partial-canary-dispatched"
            wrapper = source / "grok-remote"
            wrapper.write_text(
                "#!/bin/sh\n"
                f": > '{dispatched}'\n"
                "printf 'fixture-dispatched\\n'\n",
                encoding="ascii",
            )
            wrapper.chmod(0o755)
            installer.install()
            dispatched.unlink(missing_ok=True)
            descriptor = os.open(layout.canary_auth, os.O_RDONLY | os.O_CLOEXEC)
            try:
                values = {
                    "GROK_RELEASE_CANARY_MODE": "1",
                    "GROK_RELEASE_CANARY_FD": str(descriptor),
                    "GROK_RELEASE_CANARY_RELEASE_ID": "a" * 64,
                    "GROK_RELEASE_RUNG_CANARY": "1",
                    "GROK_RELEASE_CANARY_RUNG": "direct",
                    "GROK_RELEASE_CANARY_ROUTE_PROFILE": "direct",
                    "GROK_RELEASE_CANARY_CONTRACT": "b" * 64,
                    "GROK_RELEASE_CANARY_GROK_RELEASE": "grok-build-v1",
                    "GROK_RELEASE_CANARY_KIND": "rung",
                    "GROK_RELEASE_CANARY_MODEL": "grok-model",
                    "GROK_RELEASE_CANARY_NONCE": "c" * 64,
                    "GROK_RELEASE_CANARY_PROFILE_SHA256": "d" * 64,
                }
                self.assertEqual(
                    tuple(values), release_installer.CANARY_ENV_BINDINGS
                )
                base_environment = {
                    name: value
                    for name, value in os.environ.items()
                    if name not in release_installer.CANARY_ENV_BINDINGS
                }
                contexts = [
                    {name: values[name]}
                    for name in release_installer.CANARY_ENV_BINDINGS
                ]
                contexts.append(
                    {
                        "GROK_RELEASE_CANARY_FD": str(descriptor),
                        "GROK_RELEASE_CANARY_ROUTE_PROFILE": "direct",
                    }
                )
                for context in contexts:
                    with self.subTest(bindings=tuple(context)):
                        dispatched.unlink(missing_ok=True)
                        result = subprocess.run(
                            [str(layout.entrypoint), "prompt"],
                            env={**base_environment, **context},
                            pass_fds=(descriptor,),
                            text=True,
                            capture_output=True,
                            timeout=5,
                            check=False,
                        )
                        self.assertEqual(result.returncode, 78, result.stderr)
                        self.assertIn(
                            "release/rung canary authorization", result.stderr
                        )
                        self.assertFalse(dispatched.exists())
            finally:
                os.close(descriptor)

    def test_route_profile_v6_is_exact_and_cli_requires_it(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            release_id = installer.install().release_id
            common = {
                "release_id": release_id,
                "rung": "direct",
                "contract_sha256": "a" * 64,
                "grok_release_id": "grok-build-v1",
                "model_id": "vendor/model-1",
            }
            for profile in ("vpn", "auto-no-direct", "home:lab/phone"):
                with self.subTest(profile=profile), self.assertRaisesRegex(
                    release_installer.ReleaseError, "route profile"
                ):
                    installer.begin_rung_canary(
                        **common,
                        route_profile=profile,
                    )
            self.assertFalse(layout.rollback_deny.exists())

            installer.begin_rung_canary(**common, route_profile="auto")
            record = installer._read_rung_canary()
            self.assertEqual(record["schema_version"], 6)
            self.assertEqual(record["route_profile"], "auto")
            self.assertIsNone(record["profile_sha256"])
            descriptor = os.open(layout.canary_auth, os.O_RDONLY)
            try:
                environment = installer._canary_environment(descriptor, record)
            finally:
                os.close(descriptor)
            self.assertEqual(environment["GROK_RELEASE_CANARY_ROUTE_PROFILE"], "auto")
            self.assertEqual(installer.canary_exec(("route-profile",)).returncode, 0)

            original = layout.rung_canary.read_bytes()
            tampered = dict(record)
            tampered["route_profile"] = "vpn"
            release_installer._atomic_json(
                layout.rung_canary,
                tampered,
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )
            with self.assertRaisesRegex(release_installer.ReleaseError, "invalid"):
                installer._read_rung_canary()
            release_installer._atomic_write(
                layout.rung_canary,
                original,
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )
            installer.abort_restore(release_id)

            with self.assertRaisesRegex(release_installer.ReleaseError, "--route-profile"):
                release_installer.main(
                    [
                        "begin-rung-canary", "--apply", "--source", str(source),
                        "--prefix", str(base / "prefix"), "--release-id", release_id,
                        "--rung", "direct", "--contract-sha256", "a" * 64,
                        "--grok-release-id", "grok-build-v1", "--model-id",
                        "vendor/model-1",
                    ]
                )

    def test_begin_rung_canary_cli_accepts_profile_digest_as_authority(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            profile_sha256 = "d" * 64
            begin = mock.Mock(
                return_value=release_installer.InstallResult(
                    "a" * 64,
                    True,
                    "begin-rung-canary",
                )
            )
            installer.begin_rung_canary = begin
            installer._read_rung_canary = mock.Mock(
                return_value={"canary_nonce": "e" * 64}
            )
            output = io.StringIO()
            with (
                mock.patch.object(
                    release_installer.Layout,
                    "defaults",
                    return_value=layout,
                ),
                mock.patch.object(
                    release_installer,
                    "ReleaseInstaller",
                    return_value=installer,
                ),
                mock.patch.object(
                    release_installer,
                    "_default_runtime_files",
                    return_value=RUNTIME_FILES,
                ),
                mock.patch.object(
                    release_installer,
                    "_default_root_files",
                    return_value=ROOT_FILES,
                ),
                mock.patch.object(
                    release_installer,
                    "_prefix_proc_authority",
                    return_value=installer.proc_authority,
                ),
                redirect_stdout(output),
            ):
                returncode = release_installer.main(
                    [
                        "begin-rung-canary",
                        "--apply",
                        "--source",
                        str(source),
                        "--prefix",
                        str(base / "prefix"),
                        "--release-id",
                        "a" * 64,
                        "--rung",
                        "direct",
                        "--profile-sha256",
                        profile_sha256,
                    ]
                )
            self.assertEqual(returncode, 0)
            self.assertEqual(
                json.loads(output.getvalue())["canary_nonce"],
                "e" * 64,
            )
            begin.assert_called_once_with(
                release_id="a" * 64,
                rung="direct",
                route_profile=None,
                contract_sha256=None,
                grok_release_id=None,
                model_id=None,
                profile_sha256=profile_sha256,
            )

    def test_release_recovery_cli_reports_profile_transition(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            expected = {
                "status": "blocked",
                "release_id": "a" * 64,
                "reason_code": "release_profile_history_invalid",
            }
            installer.profile_transition = expected
            for command in ("resume", "abort"):
                operation = mock.Mock(
                    return_value=release_installer.InstallResult(
                        "a" * 64,
                        True,
                        command,
                    )
                )
                if command == "resume":
                    installer.resume = operation
                else:
                    installer.abort_restore = operation
                output = io.StringIO()
                with (
                    self.subTest(command=command),
                    mock.patch.object(
                        release_installer.Layout,
                        "defaults",
                        return_value=layout,
                    ),
                    mock.patch.object(
                        release_installer,
                        "ReleaseInstaller",
                        return_value=installer,
                    ),
                    mock.patch.object(
                        release_installer,
                        "_default_runtime_files",
                        return_value=RUNTIME_FILES,
                    ),
                    mock.patch.object(
                        release_installer,
                        "_default_root_files",
                        return_value=ROOT_FILES,
                    ),
                    mock.patch.object(
                        release_installer,
                        "_prefix_proc_authority",
                        return_value=installer.proc_authority,
                    ),
                    redirect_stdout(output),
                ):
                    arguments = [
                        command,
                        "--apply",
                        "--source",
                        str(source),
                        "--prefix",
                        str(base / "prefix"),
                    ]
                    returncode = release_installer.main(arguments)
                self.assertEqual(returncode, 0)
                self.assertEqual(
                    json.loads(output.getvalue())["profile_transition"],
                    expected,
                )
                if command == "resume":
                    operation.assert_called_once_with(canary_only=False)
                else:
                    operation.assert_called_once_with(
                        None, fault_at=None, canary_only=False
                    )

    def test_qualification_resource_evidence_is_closed_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, _layout, _source = make_installer(Path(td))
            self.assertEqual(
                release_installer._qualification_resource_contract("load32")[
                    "max_cgroup_pids_delta"
                ],
                240,
            )
            self.assertEqual(
                release_installer._qualification_resource_contract(
                    "fault-recovery"
                )["max_cgroup_pids_delta"],
                54,
            )
            release_id = installer.install().release_id
            installer.begin_release_qualification(release_id=release_id)
            canary = installer._read_rung_canary()
            result = json.loads(fixed_qualification_smoke(installer, "load32").stdout)
            installer._validate_qualification_result_value(
                result,
                step="load32",
                canary=canary,
            )

            extra = json.loads(json.dumps(result))
            extra["observations"]["resource_contract"]["unexpected"] = 1
            with self.assertRaisesRegex(release_installer.ReleaseError, "mismatched"):
                installer._validate_qualification_result_value(
                    extra,
                    step="load32",
                    canary=canary,
                )

            event = json.loads(json.dumps(result))
            event["observations"]["resource_observed"][
                "memory_event_delta_total"
            ] = 1
            with self.assertRaisesRegex(release_installer.ReleaseError, "fixed step"):
                installer._validate_qualification_result_value(
                    event,
                    step="load32",
                    canary=canary,
                )

            overflow = json.loads(json.dumps(result))
            overflow["observations"]["resource_observed"][
                "cgroup_pids_delta"
            ] = 241
            with self.assertRaisesRegex(release_installer.ReleaseError, "fixed step"):
                installer._validate_qualification_result_value(
                    overflow,
                    step="load32",
                    canary=canary,
                )

            highwater = json.loads(json.dumps(result))
            highwater["observations"]["resource_observed"][
                "cgroup_pids_highwater_delta"
            ] = 241
            with self.assertRaisesRegex(release_installer.ReleaseError, "fixed step"):
                installer._validate_qualification_result_value(
                    highwater,
                    step="load32",
                    canary=canary,
                )
            installer.abort_restore(release_id)

    def test_verifier_and_installer_share_exact_qualification_codebooks(self) -> None:
        self.assertEqual(
            release_installer.QUALIFICATION_FAILURE_CODES,
            qualification_verifier.QUALIFICATION_FAILURE_CODES,
        )
        self.assertEqual(
            release_installer.QUALIFICATION_BLOCKED_CODES,
            qualification_verifier.QUALIFICATION_BLOCKED_CODES,
        )
        self.assertEqual(
            release_installer.QUALIFICATION_RESULT_SCHEMA_VERSION,
            qualification_verifier.EVIDENCE_SCHEMA_VERSION,
        )
        with tempfile.TemporaryDirectory() as td:
            installer, _layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            gate = installer._gate_source(release_id, "user").decode("utf-8")
            self.assertIn(
                "QUALIFICATION_RESULT_SCHEMA=5\n",
                gate,
            )
            self.assertIn(
                'value.get("schema_version") != QUALIFICATION_RESULT_SCHEMA',
                gate,
            )
            start = gate.index("def resource_proves(")
            end = gate.index("\ndef fixed_qualification(", start)
            namespace: dict[str, object] = {
                "RID": release_installer.RELEASE_ID_RE,
                "ZERO_DIGEST": release_installer.ZERO_DIGEST,
            }
            exec(
                compile(gate[start:end], "<generated-resource-gate>", "exec"),
                namespace,
            )
            installer.begin_release_qualification(release_id=release_id)
            observations = json.loads(
                fixed_qualification_smoke(installer, "load32").stdout
            )["observations"]
            resource_proves = namespace["resource_proves"]
            self.assertTrue(resource_proves("load32", observations))
            overflow = json.loads(json.dumps(observations))
            overflow["resource_observed"]["cgroup_pids_delta"] = 241
            self.assertFalse(resource_proves("load32", overflow))
            installer.abort_restore(release_id)

    def test_real_pair_execution_unit_observations_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, _layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            installer.begin_release_qualification(release_id=release_id)
            canary = installer._read_rung_canary()
            result = json.loads(
                fixed_qualification_smoke(installer, "real-pair").stdout
            )
            installer._validate_qualification_result_value(
                result,
                step="real-pair",
                canary=canary,
            )

            for field, value in (
                ("independent_grok_units", 1),
                ("shared_leader_disabled", False),
                ("leader_socket_count", 1),
            ):
                invalid = json.loads(json.dumps(result))
                invalid["observations"][field] = value
                with self.assertRaisesRegex(
                    release_installer.ReleaseError, "fixed step"
                ):
                    installer._validate_qualification_result_value(
                        invalid,
                        step="real-pair",
                        canary=canary,
                    )

            legacy = json.loads(json.dumps(result))
            legacy["schema_version"] = 2
            legacy["observations"]["unique_leaders"] = legacy[
                "observations"
            ].pop("independent_grok_units")
            legacy["observations"].pop("shared_leader_disabled")
            legacy["observations"].pop("leader_socket_count")
            with self.assertRaisesRegex(
                release_installer.ReleaseError, "mismatched"
            ):
                installer._validate_qualification_result_value(
                    legacy,
                    step="real-pair",
                    canary=canary,
                )
            installer.abort_restore(release_id)

    def test_qualification_error_codes_are_status_and_step_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, _layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            installer.begin_release_qualification(release_id=release_id)
            canary = installer._read_rung_canary()
            failed = json.loads(
                fixed_qualification_smoke(
                    installer, "load32", status="failed"
                ).stdout
            )
            installer._validate_qualification_result_value(
                failed,
                step="load32",
                canary=canary,
                require_pass=False,
            )
            unknown = json.loads(json.dumps(failed))
            unknown["error_code"] = "load32-provider-supplied-detail"
            with self.assertRaisesRegex(release_installer.ReleaseError, "mismatched"):
                installer._validate_qualification_result_value(
                    unknown,
                    step="load32",
                    canary=canary,
                    require_pass=False,
                )
            wrong_status = json.loads(json.dumps(failed))
            wrong_status["status"] = "blocked"
            with self.assertRaisesRegex(release_installer.ReleaseError, "mismatched"):
                installer._validate_qualification_result_value(
                    wrong_status,
                    step="load32",
                    canary=canary,
                    require_pass=False,
                )
            with mock.patch.object(
                installer,
                "_run_qualification_verifier",
                side_effect=lambda **kw: fixed_qualification_smoke(
                    installer, str(kw["step"]), status="failed"
                ),
            ):
                outcome = installer.qualification_exec("load32")
            self.assertEqual(outcome.returncode, 2)
            self.assertEqual(outcome.error_code, "load32-internal")
            self.assertEqual(outcome.error_sha256, "e" * 64)
            self.assertFalse(
                _layout.qualification_result_path(
                    release_id, "load32"
                ).exists()
            )
            self.assertFalse(
                _layout.qualification_state_path(release_id).exists()
            )
            self.assertTrue(_layout.rollback_deny.exists())
            self.assertTrue(_layout.rung_canary.exists())
            installer.abort_restore(release_id)

    def test_qualification_diagnostic_rechecks_fence_before_returning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            installer.begin_release_qualification(release_id=release_id)

            def mutate_fence(**kwargs: object) -> object:
                result = fixed_qualification_smoke(
                    installer, str(kwargs["step"]), status="failed"
                )
                layout.rollback_deny.unlink()
                return result

            with (
                mock.patch.object(
                    installer,
                    "_run_qualification_verifier",
                    side_effect=mutate_fence,
                ),
                self.assertRaisesRegex(
                    release_installer.ReleaseError,
                    "fence changed",
                ),
            ):
                installer.qualification_exec("load32")
            self.assertFalse(
                layout.qualification_result_path(release_id, "load32").exists()
            )
            self.assertFalse(
                layout.qualification_state_path(release_id).exists()
            )
            self.assertFalse(layout.canary_terminal.exists())
            self.assertTrue(
                (
                    layout.qualification_release_dir(release_id)
                    / "pending-qualification-load32.json"
                ).exists()
            )

    def test_qualification_terminal_post_unlink_fault_converges(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            installer.begin_release_qualification(release_id=release_id)
            with mock.patch.object(
                installer,
                "_run_qualification_verifier",
                side_effect=lambda **kw: fixed_qualification_smoke(
                    installer, str(kw["step"])
                ),
            ):
                installer.qualification_exec("load32")
                with self.assertRaises(release_installer.InjectedFault):
                    installer.qualification_exec(
                        "fault-recovery",
                        fault_at=release_installer.AFTER_CANARY_UNLINK,
                    )
            self.assertTrue(layout.rollback_deny.exists())
            self.assertTrue(layout.canary_terminal.exists())
            self.assertFalse(layout.rung_canary.exists())
            self.assertEqual(invoke(layout.entrypoint).returncode, 78)
            recovered = installer.qualification_exec("fault-recovery")
            self.assertEqual(recovered.status, "passed")
            self.assertFalse(layout.rollback_deny.exists())
            self.assertFalse(layout.canary_terminal.exists())

    def test_abort_terminal_post_unlink_fault_converges(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256="a" * 64,
                grok_release_id="grok-build-v1",
                model_id="vendor/model-1",
            )
            with self.assertRaises(release_installer.InjectedFault):
                installer.abort_restore(
                    release_id,
                    fault_at=release_installer.AFTER_CANARY_UNLINK,
                )
            self.assertTrue(layout.rollback_deny.exists())
            self.assertTrue(layout.canary_terminal.exists())
            self.assertFalse(layout.rung_canary.exists())
            self.assertEqual(invoke(layout.entrypoint).returncode, 78)
            installer.abort_restore(release_id)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertFalse(layout.canary_terminal.exists())

    def test_promotion_terminal_post_unlink_fault_converges(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            prepare_promotable_rung(installer, release_id)
            with self.assertRaises(release_installer.InjectedFault):
                installer.promote_rung(
                    fault_at=release_installer.AFTER_CANARY_UNLINK
                )
            selected = json.loads(layout.selected.read_text())
            self.assertEqual(len(selected["qualified_rungs"]), 1)
            self.assertTrue(layout.rollback_deny.exists())
            self.assertTrue(layout.canary_terminal.exists())
            self.assertFalse(layout.rung_canary.exists())
            self.assertEqual(invoke(layout.entrypoint).returncode, 78)
            converged = installer.abort_restore(release_id)
            self.assertEqual(converged.operation, "rung-promoted")
            self.assertFalse(layout.rollback_deny.exists())
            self.assertFalse(layout.canary_terminal.exists())
            self.assertEqual(invoke(layout.entrypoint).returncode, 0)

    def test_abort_restores_precanary_selection_after_promotion_commit_gap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            prepare_promotable_rung(installer, release_id)
            with (
                mock.patch.object(
                    installer,
                    "_prepare_canary_terminal",
                    side_effect=release_installer.ReleaseError(
                        "simulated crash before promotion commit terminal"
                    ),
                ),
                self.assertRaisesRegex(
                    release_installer.ReleaseError,
                    "before promotion commit terminal",
                ),
            ):
                installer.promote_rung()
            selected = json.loads(layout.selected.read_text(encoding="ascii"))
            self.assertEqual(len(selected["qualified_rungs"]), 1)
            self.assertTrue(layout.rollback_deny.exists())
            self.assertTrue(layout.rung_canary.exists())
            self.assertFalse(layout.canary_terminal.exists())

            aborted = installer.abort_restore(release_id)
            self.assertEqual(aborted.operation, "abort")
            restored = json.loads(layout.selected.read_text(encoding="ascii"))
            self.assertEqual(restored["qualified_rungs"], [])
            self.assertEqual(
                installer._read_qualified_rung_catalog(release_id),
                [],
            )
            self.assertFalse(layout.rollback_deny.exists())
            self.assertFalse(layout.rung_canary.exists())

    def test_terminal_post_deny_clear_fault_converges_before_new_operations(self) -> None:
        def crash_after_deny_clear(installer: object, release_id: str) -> None:
            prepare_promotable_rung(installer, release_id)
            with self.assertRaises(release_installer.InjectedFault):
                installer.promote_rung(
                    fault_at=release_installer.AFTER_DENY_CLEAR
                )

        with self.subTest(operation="install"), tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            old_id = installer.install().release_id
            crash_after_deny_clear(installer, old_id)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertTrue(layout.canary_terminal.exists())
            self.assertEqual(invoke(layout.entrypoint).returncode, 0)

            write_source(source, "v2")
            new_id = installer.install().release_id
            self.assertNotEqual(new_id, old_id)
            self.assertFalse(layout.canary_terminal.exists())
            self.assertTrue(installer._selection_is_exact(new_id))
            self.assertIn("grok-remote:v2", invoke(layout.entrypoint).stdout)

        with self.subTest(operation="rollback"), tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            old_id = installer.install().release_id
            write_source(source, "v2")
            new_id = installer.install().release_id
            crash_after_deny_clear(installer, new_id)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertTrue(layout.canary_terminal.exists())

            restored = installer.rollback(old_id)
            self.assertEqual(restored.release_id, old_id)
            self.assertFalse(layout.canary_terminal.exists())
            self.assertTrue(installer._selection_is_exact(old_id))
            self.assertIn("grok-remote:v1", invoke(layout.entrypoint).stdout)

        with self.subTest(operation="revalidate"), tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            crash_after_deny_clear(installer, release_id)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertTrue(layout.canary_terminal.exists())

            revalidated = installer.revalidate_boot()
            self.assertEqual(revalidated.release_id, release_id)
            self.assertFalse(layout.canary_terminal.exists())
            self.assertTrue(installer._selection_is_exact(release_id))

    def test_terminal_tamper_and_stale_intent_remain_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256="a" * 64,
                grok_release_id="grok-build-v1",
                model_id="vendor/model-1",
            )
            with self.assertRaises(release_installer.InjectedFault):
                installer.abort_restore(
                    release_id,
                    fault_at=release_installer.AFTER_CANARY_UNLINK,
                )
            original = layout.canary_terminal.read_bytes()
            terminal = json.loads(original)
            terminal["user_selection_sha256"] = "f" * 64
            release_installer._atomic_json(
                layout.canary_terminal,
                terminal,
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )
            with self.assertRaisesRegex(release_installer.ReleaseError, "digest changed"):
                installer.abort_restore(release_id)
            self.assertTrue(layout.rollback_deny.exists())
            release_installer._atomic_write(
                layout.canary_terminal,
                original,
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )

            old_run = layout.rung_transcript_dir(release_id, "b" * 64)
            release_installer._ensure_dir(
                old_run, 0o755, layout.root_uid, layout.root_gid
            )
            pending = old_run / f"pending-{'c' * 32}.json"
            release_installer._atomic_json(
                pending,
                {"stale": True},
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )
            with self.assertRaisesRegex(release_installer.ReleaseError, "stale"):
                installer.abort_restore(release_id)
            self.assertTrue(layout.rollback_deny.exists())
            pending.unlink()
            installer.abort_restore(release_id)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertFalse(layout.canary_terminal.exists())

    def test_exact_provider_recovery_self_admits_only_for_a_dead_fence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            prefix = base / "prefix"
            home = Path("/home/caller")
            openvpn = base / "openvpn"
            openvpn.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            openvpn.chmod(0o700)
            layout = release_installer.Layout.defaults(
                ROOT,
                prefix=prefix,
                home=home,
                test_openvpn_binary=openvpn,
            )
            runtime_files = release_installer._default_runtime_files(ROOT)
            installer = release_installer.ReleaseInstaller(
                layout,
                runtime_files=runtime_files,
                root_files=release_installer._default_root_files(runtime_files),
            )
            installer.validate_apply_prerequisites()
            release_id = installer.install().release_id
            egress = layout.user_releases / release_id / "egress.sh"
            control = prefix / "home/caller/.local/state/grok-proxy/control"
            control.mkdir(parents=True, mode=0o700, exist_ok=True)
            control.chmod(0o700)
            owner = "dead-provider-owner"
            generation = 7
            port = 11882
            workspace_tag = hashlib.sha256(
                owner.encode("ascii")
                + b"\0"
                + str(generation).encode("ascii")
                + b"\0"
                + str(port).encode("ascii")
            ).hexdigest()[:24]
            runtime = control / "p" / workspace_tag
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()

            def publish_fence(pid: int, start_ticks: int) -> None:
                layout.recovery_fence.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "release_id": release_id,
                            "owner_epoch": owner,
                            "pid": pid,
                            "pid_start_ticks": start_ticks,
                            "boot_id": boot_id,
                            "phase": "RECOVERING",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                    encoding="ascii",
                )
                layout.recovery_fence.chmod(0o600)

            publish_fence(2_147_483_000, 1)
            with installer._locked():
                installer._publish_deny("canary", release_id, release_id)
            environment = {
                **os.environ,
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": str(prefix / "home/caller"),
                "GROK_TESTING": "1",
                "GROK_TEST_ROOT_RELEASE_CONTROL": str(layout.root_control),
                "GROK_TEST_CONTROL_DIR": str(control),
                "GROK_PROVIDER_MODE": "1",
                "GROK_PROVIDER_OWNER_EPOCH": owner,
                "GROK_INTERLOCK_OWNER_EPOCH": owner,
                "GROK_PROVIDER_TRANSITION_ID": "provider-recovery-transition",
                "GROK_PROVIDER_GENERATION": str(generation),
                "GROK_EGRESS_RUNTIME_DIR": str(runtime),
                "GROK_PROVIDER_INVENTORY": str(runtime / "inventory.json"),
                "GROK_PROXY_PORT": str(port),
                "GROK_REQUIRE_MODEL": "grok-4.5",
                "GROK_PROVIDER_CONTRACT_DIGEST": "b" * 64,
                "GROK_ACTIVE_RELEASE_ID": release_id,
                "GROK_PROVIDER_DEADLINE_NS": str(
                    time.monotonic_ns() + 10_000_000_000
                ),
                "GROK_PROVIDER_HOME_LABEL": "windows",
                "GROK_PROVIDER_HOME_HOST": "100.64.0.20",
                "GROK_PROVIDER_HOME_USER": "alice",
                "GROK_PROVIDER_HOME_PORT": "22",
            }
            ordinary = subprocess.run(
                [str(egress), "provider-up", "home:windows"],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
                env=environment,
            )
            recovered = subprocess.run(
                [str(egress), "provider-prove-empty", "home:windows"],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
                env=environment,
            )
            self.assertEqual(ordinary.returncode, 78, ordinary.stderr)
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertTrue(layout.rollback_deny.exists())
            self.assertTrue(layout.recovery_fence.exists())
            self.assertFalse(runtime.exists())

            publish_fence(
                os.getpid(),
                release_installer.ReleaseInstaller._proc_start_ticks(
                    os.getpid()
                ),
            )
            live_owner = subprocess.run(
                [str(egress), "provider-prove-empty", "home:windows"],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
                env=environment,
            )
            self.assertEqual(live_owner.returncode, 78, live_owner.stderr)
            self.assertTrue(layout.rollback_deny.exists())

    def test_sigkill_in_terminal_window_converges(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            prepare_promotable_rung(installer, release_id)
            read_fd, write_fd = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                original_clear = installer._clear_deny

                def pause_before_clear() -> None:
                    os.write(write_fd, b"1")
                    while True:
                        signal.pause()
                    original_clear()

                installer._clear_deny = pause_before_clear
                try:
                    installer.promote_rung()
                finally:
                    os._exit(91)
            os.close(write_fd)
            try:
                ready, _write, _error = select.select([read_fd], [], [], 10)
                self.assertTrue(ready, "child did not reach terminal crash window")
                self.assertEqual(os.read(read_fd, 1), b"1")
                self.assertTrue(layout.rollback_deny.exists())
                self.assertTrue(layout.canary_terminal.exists())
                self.assertFalse(layout.rung_canary.exists())
                os.kill(pid, signal.SIGKILL)
                waited, status = os.waitpid(pid, 0)
                self.assertEqual(waited, pid)
                self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL)
                pid = -1
                installer.promote_rung()
                self.assertFalse(layout.rollback_deny.exists())
                self.assertFalse(layout.canary_terminal.exists())
                self.assertEqual(invoke(layout.entrypoint).returncode, 0)
            finally:
                os.close(read_fd)
                if pid > 0:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)

    def test_activate_profile_requires_projected_evidence_and_live_pinned_grok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            release_id = installer.install().release_id
            profile, grok = make_activation_profile(base, release_id)
            profile_path = write_content_addressed_profile(
                layout.profile_root,
                profile,
                owner_uid=layout.target_uid,
                owner_gid=layout.target_gid,
            )
            self.assertEqual(profile_path.name, profile.filename())

            with self.assertRaisesRegex(
                release_installer.ReleaseError,
                "readiness policy is not satisfied; missing=direct",
            ):
                installer.activate_profile(profile.digest())
            self.assertFalse(layout.active_profile.exists())

            complete_release_qualification(installer, release_id)
            with self.assertRaisesRegex(
                release_installer.ReleaseError,
                "profile-bound rung canary route_profile is mismatched",
            ):
                installer.begin_rung_canary(
                    release_id=release_id,
                    rung="direct",
                    route_profile="direct",
                    profile_sha256=profile.digest(),
                )
            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                profile_sha256=profile.digest(),
            )
            canary = installer._read_rung_canary()
            self.assertEqual(canary["route_profile"], "auto")
            self.assertEqual(canary["contract_sha256"], profile.contract.digest())
            self.assertEqual(canary["profile_sha256"], profile.digest())
            held_profile = profile_path.with_suffix(".json.held")
            profile_path.rename(held_profile)
            with self.assertRaisesRegex(
                release_installer.ReleaseError,
                "qualification binding is invalid",
            ):
                installer.qualification_exec("real-pair")
            held_profile.rename(profile_path)
            projection = profile.contract.rung_qualification_digest("direct")
            with mock.patch.object(
                installer,
                "_run_qualification_verifier",
                side_effect=lambda **kw: fixed_qualification_smoke(
                    installer,
                    str(kw["step"]),
                    rung_qualification_sha256=projection,
                ),
            ):
                self.assertEqual(
                    installer.qualification_exec("real-pair").status,
                    "passed",
                )
            installer.promote_rung()
            selected = json.loads(layout.selected.read_text(encoding="ascii"))
            evidence_path = layout.rung_evidence_path(
                release_id,
                selected["qualified_rungs"][0]["evidence_sha256"],
            )
            evidence = json.loads(evidence_path.read_text(encoding="ascii"))
            self.assertEqual(
                evidence["qualification_profile_sha256"],
                profile.digest(),
            )
            # The terminal evidence is the live authorization. Qualification
            # transcripts remain audit artifacts after atomic promotion.
            layout.rung_qualification_path(
                release_id,
                str(canary["canary_nonce"]),
            ).unlink()
            self.assertEqual(
                [item["rung"] for item in installer.status()["qualified_rungs"]],
                ["direct"],
            )

            # The active pointer is the commit point.  If its per-release
            # rollback archive cannot be written afterward, activation remains
            # a reported success with an explicit degraded-history result.
            with mock.patch.object(
                installer,
                "_write_profile_activation_history",
                side_effect=OSError(
                    "synthetic activation history failure"
                ),
            ):
                activated = installer.activate_profile(profile.digest())
            self.assertEqual(
                (activated.release_id, activated.operation, activated.changed),
                (release_id, "activate-profile", True),
            )
            self.assertEqual(
                installer.profile_transition,
                {
                    "status": "activated-history-degraded",
                    "release_id": release_id,
                    "reason_code": "release_profile_history_write_failed",
                },
            )
            activation = load_activation_record(
                layout.active_profile,
                expected_uid=layout.root_uid,
                expected_gid=layout.root_gid,
            )
            activation.validate_profile(profile)
            expected_activation = ActivationRecord.from_profile(
                profile,
                activated_unix_ns=activation.activated_unix_ns,
            )
            self.assertEqual(activation, expected_activation)
            self.assertFalse(
                layout.profile_activation_history_path(release_id).exists()
            )

            catalog = installer._read_qualified_rung_catalog(release_id)
            self.assertEqual([item["rung"] for item in catalog], ["direct"])
            write_source(source, "v2")
            next_release = installer.install().release_id
            self.assertNotEqual(next_release, release_id)
            archived_activation = load_activation_record(
                layout.profile_activation_history_path(release_id),
                expected_uid=layout.root_uid,
                expected_gid=layout.root_gid,
            )
            self.assertEqual(archived_activation, activation)
            self.assertEqual(installer.status()["qualified_rungs"], [])
            next_profile, _next_grok = make_activation_profile(
                base,
                next_release,
            )
            write_content_addressed_profile(
                layout.profile_root,
                next_profile,
                owner_uid=layout.target_uid,
                owner_gid=layout.target_gid,
            )
            complete_release_qualification(installer, next_release)
            installer.begin_rung_canary(
                release_id=next_release,
                rung="direct",
                profile_sha256=next_profile.digest(),
            )
            with mock.patch.object(
                installer,
                "_run_qualification_verifier",
                side_effect=lambda **kw: fixed_qualification_smoke(
                    installer,
                    str(kw["step"]),
                    rung_qualification_sha256=(
                        next_profile.contract.rung_qualification_digest("direct")
                    ),
                ),
            ):
                installer.qualification_exec("real-pair")
            installer.promote_rung()
            installer.activate_profile(next_profile.digest())
            self.assertEqual(
                load_activation_record(
                    layout.active_profile,
                    expected_uid=layout.root_uid,
                    expected_gid=layout.root_gid,
                ).release_id,
                next_release,
            )
            real_writer = release_installer.write_activation_record

            def restore_then_report_uncertain(path: Path, *args, **kwargs) -> None:
                real_writer(path, *args, **kwargs)
                if path == layout.active_profile:
                    raise ActivationCommitUncertain(
                        "synthetic rollback pointer durability uncertainty"
                    )

            with mock.patch.object(
                release_installer,
                "write_activation_record",
                side_effect=restore_then_report_uncertain,
            ):
                rolled_back = installer.rollback(release_id)
            self.assertEqual(rolled_back.release_id, release_id)
            self.assertEqual(
                [item["rung"] for item in installer.status()["qualified_rungs"]],
                ["direct"],
            )
            restored_activation = load_activation_record(
                layout.active_profile,
                expected_uid=layout.root_uid,
                expected_gid=layout.root_gid,
            )
            self.assertEqual(restored_activation, activation)
            restored_activation.validate_profile(profile)
            self.assertEqual(
                installer.profile_transition,
                {
                    "status": "restored-durability-uncertain",
                    "release_id": release_id,
                    "reason_code": "active_profile_directory_fsync_failed",
                },
            )

            published = layout.active_profile.read_bytes()
            grok.write_text("#!/usr/bin/env sh\nexit 9\n", encoding="ascii")
            with self.assertRaisesRegex(
                release_installer.ReleaseError,
                "identity mismatch",
            ):
                installer.activate_profile(profile.digest())
            self.assertEqual(layout.active_profile.read_bytes(), published)

    def test_activation_reports_postrename_durability_uncertainty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, _source = make_installer(base)
            release_id = installer.install().release_id
            profile, _grok = prepare_activatable_profile(
                base,
                installer,
                layout,
                release_id,
            )
            real_writer = release_installer.write_activation_record

            def commit_then_report_uncertain(path: Path, *args, **kwargs) -> None:
                real_writer(path, *args, **kwargs)
                if path == layout.active_profile:
                    raise ActivationCommitUncertain(
                        "synthetic post-rename directory fsync uncertainty"
                    )

            with mock.patch.object(
                release_installer,
                "write_activation_record",
                side_effect=commit_then_report_uncertain,
            ):
                activated = installer.activate_profile(profile.digest())
            self.assertEqual(activated.operation, "activate-profile")
            self.assertEqual(
                installer.profile_transition,
                {
                    "status": "activated-durability-uncertain",
                    "release_id": release_id,
                    "reason_code": "active_profile_directory_fsync_failed",
                },
            )
            load_activation_record(
                layout.active_profile,
                expected_uid=layout.root_uid,
                expected_gid=layout.root_gid,
            ).validate_profile(profile)

    def test_rollback_rebuilds_missing_history_from_exact_dormant_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            release_id = installer.install().release_id
            profile, _grok = prepare_activatable_profile(
                base,
                installer,
                layout,
                release_id,
            )
            installer.activate_profile(profile.digest())
            history = layout.profile_activation_history_path(release_id)
            self.assertTrue(history.exists())

            write_source(source, "v2")
            next_release = installer.install().release_id
            self.assertNotEqual(next_release, release_id)
            self.assertEqual(
                load_activation_record(
                    layout.active_profile,
                    expected_uid=layout.root_uid,
                    expected_gid=layout.root_gid,
                ).release_id,
                release_id,
            )
            history.unlink()

            installer.rollback(release_id)
            self.assertEqual(
                installer.profile_transition,
                {
                    "status": "restored",
                    "release_id": release_id,
                    "reason_code": None,
                },
            )
            restored = load_activation_record(
                layout.active_profile,
                expected_uid=layout.root_uid,
                expected_gid=layout.root_gid,
            )
            restored.validate_profile(profile)
            self.assertEqual(
                load_activation_record(
                    history,
                    expected_uid=layout.root_uid,
                    expected_gid=layout.root_gid,
                ),
                restored,
            )
            with mock.patch.object(
                installer,
                "_write_profile_activation_history",
                side_effect=OSError("synthetic restored history failure"),
            ):
                installer._restore_profile_activation(release_id)
            self.assertEqual(
                installer.profile_transition,
                {
                    "status": "restored-history-degraded",
                    "release_id": release_id,
                    "reason_code": "release_profile_history_write_failed",
                },
            )

    def test_rung_promotion_is_exact_and_unqualified_rungs_remain_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, _source = make_installer(base)
            release_id = installer.install().release_id
            contract = "a" * 64
            grok_release = "grok-build-v1"
            model_id = "vendor/model-1"

            # Free-form executions remain auditable manual transcripts but can
            # neither stand in for release qualification nor promote a rung.
            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256=contract,
                grok_release_id=grok_release,
                model_id=model_id,
            )
            canary_record = installer._read_rung_canary()
            executed = installer.canary_exec(("-m", "model", "prompt"))
            self.assertEqual(executed.returncode, 0)
            legacy = base / "legacy-all-true.json"
            write_attested_rung_evidence(
                legacy,
                installer,
                release_id,
                rung="direct",
                contract_sha256=contract,
                grok_release_id=grok_release,
            )
            with self.assertRaisesRegex(release_installer.ReleaseError, "external rung evidence"):
                installer.promote_rung(legacy)
            with self.assertRaisesRegex(release_installer.ReleaseError, "qualification"):
                installer.qualification_exec("real-pair")
            installer.abort_restore(release_id)

            begun = installer.begin_release_qualification(release_id=release_id)
            self.assertTrue(begun.changed)
            with self.assertRaisesRegex(release_installer.ReleaseError, "manual"):
                installer.canary_exec(("not-qualifying",))
            with self.assertRaises((release_installer.ReleaseError, FileNotFoundError)):
                installer.qualification_exec("fault-recovery")
            with mock.patch.object(
                installer,
                "_run_qualification_verifier",
                side_effect=lambda **kw: fixed_qualification_smoke(
                    installer, str(kw["step"])
                ),
            ):
                self.assertEqual(installer.qualification_exec("load32").status, "passed")
                with self.assertRaisesRegex(release_installer.ReleaseError, "replay"):
                    installer.qualification_exec("load32")
                self.assertEqual(
                    installer.qualification_exec("fault-recovery").status, "passed"
                )
            self.assertFalse(layout.rollback_deny.exists())
            self.assertTrue(layout.qualification_state_path(release_id).is_file())

            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256=contract,
                grok_release_id=grok_release,
                model_id=model_id,
            )
            current = installer._read_rung_canary()
            installer.canary_exec(("manual-only",))
            with self.assertRaises((release_installer.ReleaseError, FileNotFoundError)):
                installer.promote_rung()
            with mock.patch.object(
                installer,
                "_run_qualification_verifier",
                side_effect=lambda **kw: fixed_qualification_smoke(
                    installer, str(kw["step"])
                ),
            ):
                self.assertEqual(installer.qualification_exec("real-pair").status, "passed")
            promoted = installer.promote_rung()
            self.assertTrue(promoted.changed)
            self.assertFalse(layout.rollback_deny.exists())
            selected = json.loads(layout.selected.read_text())
            self.assertEqual(len(selected["qualified_rungs"]), 1)
            record = selected["qualified_rungs"][0]
            self.assertEqual(record["rung"], "direct")
            self.assertEqual(record["contract_sha256"], "b" * 64)
            self.assertTrue(
                layout.rung_evidence_path(
                    release_id, record["evidence_sha256"]
                ).is_file()
            )

            evidence = json.loads(
                layout.rung_evidence_path(release_id, record["evidence_sha256"]).read_text()
            )
            self.assertEqual(
                evidence["schema_version"],
                release_installer.RUNG_EVIDENCE_SCHEMA_VERSION,
            )
            self.assertEqual(evidence["schema_version"], 9)
            self.assertEqual(evidence["contract_sha256"], contract)
            self.assertEqual(evidence["rung_qualification_sha256"], "b" * 64)
            self.assertEqual(evidence["model_id"], model_id)
            self.assertIsNone(evidence["qualification_profile_sha256"])
            self.assertNotIn("transcript_sha256s", evidence)
            self.assertIn(
                "post_repair_reconnect_cache_execution_units_verified",
                evidence["measurements"],
            )
            self.assertNotIn(
                "post_repair_reconnect_cache_leader_verified",
                evidence["measurements"],
            )
            legacy_evidence = json.loads(json.dumps(evidence))
            legacy_evidence["schema_version"] = 7
            legacy_evidence["measurements"][
                "post_repair_reconnect_cache_leader_verified"
            ] = (
                legacy_evidence["measurements"].pop(
                    "post_repair_reconnect_cache_execution_units_verified"
                )
            )
            with self.assertRaisesRegex(
                release_installer.ReleaseError,
                "rung evidence does not bind a complete passing measurement",
            ):
                installer._validate_rung_evidence_value(
                    release_id,
                    legacy_evidence,
                )
            admitted_selection = invoke(layout.entrypoint)
            self.assertEqual(
                admitted_selection.returncode, 0, admitted_selection.stderr
            )

            real_pair = layout.rung_qualification_path(
                release_id, str(current["canary_nonce"])
            )
            real_pair_bytes = real_pair.read_bytes()
            real_pair.unlink()
            admitted_without_audit_transcript = invoke(layout.entrypoint)
            self.assertEqual(
                admitted_without_audit_transcript.returncode,
                0,
                admitted_without_audit_transcript.stderr,
            )
            release_installer._exclusive_write(
                real_pair,
                real_pair_bytes,
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )

            # Promotion already proved these audit artifacts. Runtime uses the
            # content-addressed terminal attestation as its live authority.
            invalid_real = json.loads(real_pair_bytes)
            invalid_real["observations"]["sessions_completed"] = 1
            invalid_real_raw = release_installer._canonical_json(invalid_real) + b"\n"
            release_installer._atomic_write(
                real_pair,
                invalid_real_raw,
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )
            admitted_with_changed_audit_transcript = invoke(layout.entrypoint)
            self.assertEqual(
                admitted_with_changed_audit_transcript.returncode,
                0,
                admitted_with_changed_audit_transcript.stderr,
            )

            terminal_evidence = layout.rung_evidence_path(
                release_id,
                record["evidence_sha256"],
            )
            held_terminal_evidence = terminal_evidence.with_suffix(".json.held")
            terminal_evidence.rename(held_terminal_evidence)
            try:
                self.assertTrue(installer._selection_is_exact(release_id))
                self.assertEqual(installer.status()["qualified_rungs"], [])
                requalification = installer.begin_rung_canary(
                    release_id=release_id,
                    rung="direct",
                    route_profile="direct",
                    contract_sha256=contract,
                    grok_release_id=grok_release,
                    model_id=model_id,
                )
                self.assertTrue(requalification.changed)
                installer.abort_restore(release_id)
            finally:
                held_terminal_evidence.rename(terminal_evidence)

    def test_rung_canary_nonce_replay_and_crash_pending_execution_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, _source = make_installer(base)
            release_id = installer.install().release_id
            contract = "a" * 64
            grok_release = "grok-build-v1"
            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256=contract,
                grok_release_id=grok_release,
                model_id="vendor/model-1",
            )
            first_nonce = installer._read_rung_canary()["canary_nonce"]
            installer.canary_exec(("first",))
            stale = base / "stale-evidence.json"
            write_attested_rung_evidence(
                stale,
                installer,
                release_id,
                rung="direct",
                contract_sha256=contract,
                grok_release_id=grok_release,
            )
            installer.abort_restore(release_id)

    def test_fixed_qualification_crash_duplicate_and_wrong_step_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            installer.begin_release_qualification(release_id=release_id)
            pending = (
                layout.qualification_release_dir(release_id)
                / "pending-qualification-load32.json"
            )
            release_installer._atomic_json(
                pending,
                {"crash": True},
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )
            with self.assertRaisesRegex(release_installer.ReleaseError, "crash-pending"):
                installer.qualification_exec("load32")
            installer.abort_restore(release_id)
            self.assertFalse(pending.exists())

            installer.begin_release_qualification(release_id=release_id)
            with mock.patch.object(
                installer,
                "_run_qualification_verifier",
                side_effect=lambda **kw: fixed_qualification_smoke(
                    installer, str(kw["step"])
                ),
            ):
                installer.qualification_exec("load32")
                installer.qualification_exec("fault-recovery")
            state, _digest = installer._validate_release_qualification(release_id)
            self.assertTrue(state["overall_pass"])
            actual_gate_digests = {
                "entrypoint_sha256": hashlib.sha256(
                    layout.entrypoint.read_bytes()
                ).hexdigest(),
                "broker_gate_sha256": hashlib.sha256(
                    layout.broker_entrypoint.read_bytes()
                ).hexdigest(),
            }
            self.assertEqual(
                {name: state[name] for name in actual_gate_digests},
                actual_gate_digests,
            )
            for field in actual_gate_digests:
                with self.subTest(stale_gate=field):
                    changed = dict(actual_gate_digests)
                    changed[field] = "0" * 64
                    with mock.patch.object(
                        installer,
                        "_selected_gate_digests",
                        return_value=changed,
                    ), self.assertRaisesRegex(
                        release_installer.ReleaseError, "failed or mismatched"
                    ):
                        installer.begin_release_qualification(
                            release_id=release_id
                        )

            duplicate = layout.qualification_release_dir(release_id) / "load32-copy.json"
            duplicate.write_bytes(
                layout.qualification_result_path(release_id, "load32").read_bytes()
            )
            duplicate.chmod(0o444)
            with self.assertRaisesRegex(release_installer.ReleaseError, "contains residue"):
                installer._validate_release_qualification(release_id)
            duplicate.unlink()

            fault_path = layout.qualification_result_path(release_id, "fault-recovery")
            fault_bytes = fault_path.read_bytes()
            release_installer._atomic_write(
                fault_path,
                layout.qualification_result_path(release_id, "load32").read_bytes(),
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )
            with self.assertRaisesRegex(
                release_installer.ReleaseError, "failed or mismatched"
            ):
                installer._validate_release_qualification(release_id)
            release_installer._atomic_write(
                fault_path,
                fault_bytes,
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )
            installer._validate_release_qualification(release_id)

            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256="a" * 64,
                grok_release_id="grok-build-v1",
                model_id="vendor/model-1",
            )
            nonce = str(installer._read_rung_canary()["canary_nonce"])
            real_pending = (
                layout.rung_transcript_dir(release_id, nonce)
                / "pending-qualification-real-pair.json"
            )
            release_installer._atomic_json(
                real_pending,
                {"crash": True},
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )
            with self.assertRaisesRegex(
                release_installer.ReleaseError, "crash-pending"
            ):
                installer.qualification_exec("real-pair")
            installer.abort_restore(release_id)
            self.assertFalse(real_pending.exists())

    def test_stale_fixed_qualification_cannot_authorize_regenerated_gates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            installer.begin_release_qualification(release_id=release_id)
            with mock.patch.object(
                installer,
                "_run_qualification_verifier",
                side_effect=lambda **kw: fixed_qualification_smoke(
                    installer, str(kw["step"])
                ),
            ):
                installer.qualification_exec("load32")
                installer.qualification_exec("fault-recovery")
            stale_state, _digest = installer._validate_release_qualification(
                release_id
            )
            selected = json.loads(layout.selected.read_text(encoding="ascii"))
            original_gate_source = installer._gate_source

            def changed_gate_source(*args, **kwargs):
                return original_gate_source(*args, **kwargs) + (
                    b"\n# test gate-generator drift\n"
                )

            with mock.patch.object(
                installer, "_gate_source", side_effect=changed_gate_source
            ):
                installer._publish_selection(
                    release_id,
                    str(selected["operation"]),
                    evidence_sha256=str(selected["evidence_sha256"]),
                    selection_phase="READY",
                    fault_at=None,
                    selector_faults=False,
                )
                self.assertTrue(installer._selection_is_exact(release_id))
                current_gate_digests = installer._selected_gate_digests(
                    release_id
                )
                self.assertNotEqual(
                    current_gate_digests["entrypoint_sha256"],
                    stale_state["entrypoint_sha256"],
                )
                self.assertNotEqual(
                    current_gate_digests["broker_gate_sha256"],
                    stale_state["broker_gate_sha256"],
                )
                with self.assertRaisesRegex(
                    release_installer.ReleaseError, "failed or mismatched"
                ):
                    installer.begin_release_qualification(
                        release_id=release_id
                    )
                self.assertFalse(layout.rollback_deny.exists())

                installer.begin_rung_canary(
                    release_id=release_id,
                    rung="direct",
                    route_profile="direct",
                    contract_sha256="a" * 64,
                    grok_release_id="grok-build-v1",
                    model_id="vendor/model-1",
                )
                with mock.patch.object(
                    installer, "_run_qualification_verifier"
                ) as verifier, self.assertRaisesRegex(
                    release_installer.ReleaseError, "failed or mismatched"
                ):
                    installer.qualification_exec("real-pair")
                verifier.assert_not_called()
                self.assertFalse(
                    layout.rung_qualification_path(
                        release_id,
                        str(installer._read_rung_canary()["canary_nonce"]),
                    ).exists()
                )
                installer.abort_restore(release_id)
                self.assertFalse(layout.rollback_deny.exists())
                self.assertFalse(layout.rung_canary.exists())

    def test_qualification_verifier_and_fake_are_release_identity_bound(self) -> None:
        for relative in (
            "grok_ms/qualification_verifier.py",
            "grok_ms/qualification_fake_grok.py",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as td:
                installer, _layout, source = make_installer(Path(td))
                before = installer.plan_release().release_id
                target = source / relative
                target.write_bytes(target.read_bytes() + b"# identity change\n")
                after = installer.plan_release().release_id
                self.assertNotEqual(before, after)

    def test_manual_canary_nonce_replay_and_crash_pending_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, _source = make_installer(base)
            release_id = installer.install().release_id
            contract = "a" * 64
            grok_release = "grok-build-v1"
            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256=contract,
                grok_release_id=grok_release,
                model_id="vendor/model-1",
            )
            first_nonce = installer._read_rung_canary()["canary_nonce"]
            installer.canary_exec(("first",))
            stale = base / "stale-evidence.json"
            write_attested_rung_evidence(
                stale,
                installer,
                release_id,
                rung="direct",
                contract_sha256=contract,
                grok_release_id=grok_release,
            )
            installer.abort_restore(release_id)
            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256=contract,
                grok_release_id=grok_release,
                model_id="vendor/model-1",
            )
            second_nonce = installer._read_rung_canary()["canary_nonce"]
            self.assertNotEqual(first_nonce, second_nonce)
            installer.canary_exec(("second",))
            with self.assertRaisesRegex(release_installer.ReleaseError, "external rung evidence"):
                installer.promote_rung(stale)
            installer.abort_restore(release_id)

            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256=contract,
                grok_release_id=grok_release,
                model_id="vendor/model-1",
            )
            with mock.patch.object(
                release_installer.subprocess,
                "Popen",
                side_effect=OSError("injected pre-exec failure"),
            ):
                with self.assertRaisesRegex(release_installer.ReleaseError, "cannot execute"):
                    installer.canary_exec(("crash",))
            with self.assertRaisesRegex(release_installer.ReleaseError, "crash-pending"):
                installer.canary_exec(("retry",))
            current = installer._read_rung_canary()
            pending_root = layout.rung_transcript_dir(
                release_id, str(current["canary_nonce"])
            )
            pending_records = list(pending_root.glob("pending-*.json"))
            self.assertEqual(len(pending_records), 1)
            pending = pending_records[0]
            installer.abort_restore(release_id)
            self.assertFalse(pending.exists())

            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256=contract,
                grok_release_id=grok_release,
                model_id="vendor/model-1",
            )
            partial_record = layout.rung_transcript_dir(
                release_id,
                str(installer._read_rung_canary()["canary_nonce"]),
            ) / f"pending-{'1' * 32}.json"
            partial_fd = os.open(
                partial_record,
                os.O_RDWR | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                fcntl.flock(partial_fd, fcntl.LOCK_EX)
                with self.assertRaisesRegex(
                    release_installer.ReleaseError,
                    "active rung canary execution",
                ):
                    installer.abort_restore(release_id)
            finally:
                fcntl.flock(partial_fd, fcntl.LOCK_UN)
                os.close(partial_fd)
            installer.abort_restore(release_id)
            self.assertFalse(partial_record.exists())

            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256=contract,
                grok_release_id=grok_release,
                model_id="vendor/model-1",
            )
            failed_process = subprocess.Popen(
                ["/bin/sh", "-c", "exit 42"],
                start_new_session=True,
            )
            with mock.patch.object(
                release_installer.subprocess,
                "Popen",
                return_value=failed_process,
            ):
                failed = installer.canary_exec(("failed",))
            self.assertEqual(failed.returncode, 42)
            with self.assertRaisesRegex(release_installer.ReleaseError, "all-success"):
                write_attested_rung_evidence(
                    base / "failed-evidence.json",
                    installer,
                    release_id,
                    rung="direct",
                    contract_sha256=contract,
                    grok_release_id=grok_release,
                )
            installer.abort_restore(release_id)

    def test_manual_canary_child_dies_with_installer_parent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            marker = base / "canary-wrapper.pid"
            target = source / "grok-remote"
            target.write_text(
                "#!/bin/sh\n"
                'if [ "${GROK_RELEASE_CANARY_MODE:-0}" = 1 ]; then\n'
                f'  if [ "${{1:-}}" = {json.dumps(str(marker))} ]; then\n'
                '    printf "%s\\n" "$$" > "$1"\n'
                "    exec /bin/sleep 60\n"
                "  fi\n"
                "  exit 0\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            target.chmod(0o755)
            release_id = installer.install().release_id
            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256="a" * 64,
                grok_release_id="grok-build-v1",
                model_id="vendor/model-1",
            )
            worker = os.fork()
            if worker == 0:
                try:
                    installer.canary_exec((str(marker),))
                finally:
                    os._exit(0)

            wrapper = 0
            wrapper_pidfd = -1
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.is_file())
                wrapper = int(marker.read_text(encoding="ascii"))
                wrapper_pidfd = os.pidfd_open(wrapper, 0)
                os.kill(worker, signal.SIGKILL)
                os.waitpid(worker, 0)
                worker = 0
                self.assertTrue(
                    release_installer._pidfd_exit_ready(wrapper_pidfd, 3),
                    "manual canary wrapper survived its installer parent",
                )
            finally:
                if worker > 0:
                    try:
                        os.kill(worker, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(worker, 0)
                    except ChildProcessError:
                        pass
                if wrapper > 0 and (
                    wrapper_pidfd < 0
                    or not release_installer._pidfd_exit_ready(wrapper_pidfd, 0)
                ):
                    try:
                        os.killpg(wrapper, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if wrapper_pidfd >= 0:
                    os.close(wrapper_pidfd)
                installer.abort_restore(release_id)
                self.assertFalse(layout.rollback_deny.exists())

    def test_boot_inventory_is_separate_and_feature_on_requires_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            path = layout.boot_inventory_path(release_id)
            inventory = json.loads(path.read_text())
            inventory["boot_id"] = "0" * 8 + "-0000-0000-0000-" + "0" * 12
            release_installer._atomic_json(
                path,
                inventory,
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )
            compatibility = subprocess.run(
                [str(layout.entrypoint)],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
                env={**os.environ, "GROK_MULTI_SESSION": "0"},
            )
            self.assertEqual(
                compatibility.returncode,
                0,
                compatibility.stderr,
            )
            feature_on = subprocess.run(
                [str(layout.entrypoint)],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
                env={**os.environ, "GROK_MULTI_SESSION": "1"},
            )
            self.assertEqual(feature_on.returncode, 78, feature_on.stderr)
            self.assertIn("current-boot", feature_on.stderr)
            installer.revalidate_boot()
            admitted = subprocess.run(
                [str(layout.entrypoint)],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
                env={**os.environ, "GROK_MULTI_SESSION": "1"},
            )
            self.assertEqual(admitted.returncode, 0, admitted.stderr)

    def test_abort_restores_from_deny_ledger_without_target_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            old_release = installer.install().release_id
            write_source(source, "v2")
            with self.assertRaises(release_installer.InjectedFault):
                installer.install(fault_at=release_installer.AFTER_ROOT_PUBLISH)
            write_source(source, "unrelated-v3")
            restored = installer.abort_restore(old_release)
            self.assertEqual(restored.release_id, old_release)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertIn("grok-remote:v1:", invoke(layout.entrypoint).stdout)

    def test_resume_uses_published_target_from_deny_ledger_without_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            old_release = installer.install().release_id
            write_source(source, "v2")
            target_release = installer.plan_release().release_id
            with self.assertRaises(release_installer.InjectedFault):
                installer.install(fault_at=release_installer.AFTER_EVIDENCE)
            write_source(source, "unrelated-v3")
            resumed = installer.resume()
            self.assertEqual(resumed.release_id, target_release)
            self.assertNotEqual(resumed.release_id, old_release)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertIn("grok-remote:v2:", invoke(layout.entrypoint).stdout)

    def test_first_install_resume_converges_old_broker_when_legacy_root_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            write_source(source, "legacy-v1", bootstrap_migration=False)
            target_release = installer.plan_release().release_id

            with self.assertRaises(release_installer.InjectedFault):
                installer.install(
                    fault_at=release_installer.AFTER_CANARY_SELECTION
                )

            deny = json.loads(layout.rollback_deny.read_text(encoding="ascii"))
            self.assertEqual(
                deny,
                {
                    "schema_version": 1,
                    "operation": "install",
                    "from_release": None,
                    "to_release": target_release,
                },
            )
            selected = json.loads(layout.selected.read_text(encoding="ascii"))
            self.assertEqual(selected["selection_phase"], "CANARY")
            self.assertEqual(selected["release_id"], target_release)
            immutable_broker = layout.root_releases / target_release / "vpn-broker"
            self.assertNotIn(
                b"--release-bootstrap-migrate",
                immutable_broker.read_bytes(),
            )
            self.assertFalse(
                installer._broker_inventory()["root_artifact_residue"]
            )
            fenced_status = installer.status()
            self.assertEqual(
                fenced_status["active_user_release_id"], target_release
            )
            self.assertEqual(
                fenced_status["active_root_release_id"], target_release
            )
            self.assertFalse(fenced_status["active_release_valid"])
            self.assertFalse(fenced_status["boot_inventory_valid"])
            self.assertTrue(fenced_status["rollback_denied"])
            self.assertTrue(fenced_status["deny_valid"])
            stale_evidence = {
                "schema_version": 2,
                "release_id": target_release,
                "overall_pass": False,
            }
            release_installer._atomic_json(
                layout.evidence_path(target_release),
                stale_evidence,
                mode=0o444,
                uid=layout.root_uid,
                gid=layout.root_gid,
                parent_mode=0o755,
            )

            resumed = installer.resume()

            self.assertEqual(
                resumed,
                release_installer.InstallResult(target_release, True, "resume"),
            )
            self.assertFalse(layout.rollback_deny.exists())
            final = json.loads(layout.selected.read_text(encoding="ascii"))
            root_final = json.loads(
                layout.root_selected.read_text(encoding="ascii")
            )
            self.assertEqual(final["selection_phase"], "READY")
            self.assertEqual(root_final["selection_phase"], "READY")
            self.assertEqual(final["release_id"], target_release)
            self.assertEqual(root_final["release_id"], target_release)
            evidence = json.loads(
                layout.evidence_path(target_release).read_text(encoding="ascii")
            )
            self.assertEqual(evidence["schema_version"], 3)
            self.assertTrue(evidence["overall_pass"])
            self.assertEqual(
                [item["id"] for item in evidence["criteria"]],
                list(release_installer.EVIDENCE_CRITERIA),
            )
            migration = {
                "ok": True,
                "active": False,
                "migrated": False,
                "pre_root_artifact_residue": False,
                "post_root_artifact_residue": False,
                "release_id": target_release,
            }
            self.assertEqual(
                evidence["criteria"][2]["result_sha256"],
                hashlib.sha256(
                    release_installer._canonical_json(migration)
                ).hexdigest(),
            )
            evidence_digest = hashlib.sha256(
                layout.evidence_path(target_release).read_bytes()
            ).hexdigest()
            self.assertNotEqual(evidence_digest, release_installer.ZERO_DIGEST)
            self.assertEqual(final["evidence_sha256"], evidence_digest)
            self.assertEqual(root_final["evidence_sha256"], evidence_digest)
            status = installer.status()
            self.assertTrue(status["active_release_valid"])
            self.assertEqual(status["active_release_id"], target_release)
            self.assertEqual(status["active_user_release_id"], target_release)
            self.assertEqual(status["active_root_release_id"], target_release)
            self.assertTrue(status["boot_inventory_valid"])
            self.assertFalse(status["rollback_denied"])
            self.assertFalse(status["deny_valid"])

    def test_promotion_system_errors_restore_previous_release(self) -> None:
        failures = (
            OSError("fixture promotion I/O failure"),
            subprocess.SubprocessError("fixture promotion subprocess failure"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as td:
                base = Path(td)
                installer, layout, source = make_installer(base)
                old_release = installer.install().release_id
                write_source(source, "v2")
                original = installer._produce_evidence
                calls = 0

                def fail_target(
                    release_id: str,
                    operation: str,
                    legacy_migration: object,
                ):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        raise failure
                    return original(release_id, operation, legacy_migration)

                with mock.patch.object(
                    installer,
                    "_produce_evidence",
                    side_effect=fail_target,
                ):
                    with self.assertRaisesRegex(
                        release_installer.ReleaseError,
                        "previous release was restored",
                    ):
                        installer.install()
                self.assertFalse(layout.rollback_deny.exists())
                self.assertEqual(installer.active_release_id(), old_release)

    def test_failed_or_flooding_target_canary_restores_previous_release(self) -> None:
        for failure in ("exit", "flood"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as td:
                installer, layout, source = make_installer(Path(td))
                old_id = installer.install().release_id
                if failure == "exit":
                    write_canary_sensitive_source(
                        source,
                        "v2",
                        fail_command="--release-compatibility-smoke",
                    )
                else:
                    write_canary_sensitive_source(
                        source,
                        "v2",
                        flood_command="--release-compatibility-smoke",
                    )
                failed_id = installer.plan_release().release_id
                with self.assertRaisesRegex(
                    release_installer.ReleaseError,
                    "previous release was restored",
                ):
                    installer.install()
                self.assertEqual(installer.active_release_id(), old_id)
                self.assertEqual(installer.root_active_release_id(), old_id)
                self.assertFalse(layout.rollback_deny.exists())
                self.assertTrue(installer._selection_is_exact(old_id))
                failed_evidence = json.loads(
                    layout.evidence_path(failed_id).read_text()
                )
                self.assertFalse(failed_evidence["overall_pass"])
                self.assertFalse(
                    next(
                        item
                        for item in failed_evidence["criteria"]
                        if item["id"] == "compatibility-matrix"
                    )["passed"]
                )

    def test_rollback_smoke_failure_keeps_deny_if_restore_also_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source = base / "source"
            marker = base / "fail-canaries"
            write_canary_sensitive_source(source, "v1", fail_marker=marker)
            home = base / "home"
            layout = release_installer.Layout(
                source_dir=source,
                user_root=home / ".local/lib/grok-proxy",
                root_root=base / "root/usr/local/libexec/grok-proxy",
                root_state_root=base / "root/var/lib/grok-proxy/release-control",
                state_root=home / ".local/state/grok-proxy/release-control",
                entrypoint=home / ".local/bin/grok-remote",
                test_install=True,
            )
            installer = release_installer.ReleaseInstaller(
                layout,
                runtime_files=RUNTIME_FILES,
                root_files=ROOT_FILES,
            )
            old_id = installer.install().release_id
            write_canary_sensitive_source(source, "v2", fail_marker=marker)
            new_id = installer.install().release_id
            marker.write_bytes(b"fail\n")
            with self.assertRaisesRegex(
                release_installer.ReleaseError,
                "rollback smoke could not be proved",
            ):
                installer.rollback(old_id)
            self.assertTrue(layout.rollback_deny.exists())
            self.assertEqual(installer.active_release_id(), new_id)
            self.assertEqual(installer.root_active_release_id(), new_id)
            self.assertEqual(invoke(layout.entrypoint).returncode, 78)

            marker.unlink()
            resumed = installer.rollback(old_id)
            self.assertEqual(resumed.release_id, old_id)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertTrue(installer._selection_is_exact(old_id))

    def test_rollback_gates_bind_the_target_release_root_helper_map(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fixture, _boot_id, _pid = write_proc_fixture(base / "fixture-prefix")
            descriptor = os.open(
                fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            authority = release_installer.ProcAuthority.from_fd(
                descriptor, display=fixture, fixture=True
            )
            os.close(descriptor)
            self.addCleanup(authority.close)
            installer_a, layout, source = make_installer(
                base / "install", proc_authority=authority
            )
            alternate = source / "vpn-broker.py"
            alternate_map = {**ROOT_FILES, "broker": "vpn-broker.py"}
            alternate.write_text(
                "#!/bin/sh\n"
                'if [ "${1:-}" = --release-root-inventory ]; then\n'
                '  printf \'{"active":false,"host_tun_alive":false,"ledger":null,'
                '"namespace_alive":false,"ok":true,"relay_alive":false,'
                '"release_id":"%s","root_artifact_residue":false,'
                '"root_files":{"broker":"vpn-broker.py","relay":"socks-netns.py",'
                '"sanitizer":"sanitize.awk","vpngate":"vpngate-connect.sh"},'
                '"tun_alive":false,"vpn_alive":false}\\n\' '
                '"${GROK_RELEASE_INVENTORY_RELEASE_ID}"\n'
                "  exit 0\n"
                "fi\n"
                'if [ "${1:-}" = --release-bootstrap-migrate ]; then\n'
                '  printf \'{"active":false,"migrated":false,"ok":true,'
                '"post_root_artifact_residue":false,'
                '"pre_root_artifact_residue":false,"release_id":"%s"}\\n\' '
                '"${GROK_RELEASE_INVENTORY_RELEASE_ID}"\n'
                "  exit 0\n"
                "fi\n"
                "printf 'vpn-broker-alt:v1:%s\\n' \"$*\"\n",
                encoding="ascii",
            )
            alternate.chmod(0o755)
            runtime_files = tuple(sorted((*RUNTIME_FILES, "vpn-broker.py")))
            installer_a = release_installer.ReleaseInstaller(
                layout,
                runtime_files=runtime_files,
                root_files=ROOT_FILES,
                proc_authority=authority,
            )
            release_a = installer_a.install().release_id

            installer_b = release_installer.ReleaseInstaller(
                layout,
                runtime_files=runtime_files,
                root_files=alternate_map,
                proc_authority=authority,
            )
            release_b = installer_b.install().release_id
            self.assertNotEqual(release_a, release_b)
            installer_b.rollback(release_a)

            self.assertTrue(installer_b._selection_is_exact(release_a))
            self.assertIn("grok-remote:v1:", invoke(layout.entrypoint).stdout)
            broker = invoke(layout.broker_entrypoint, "status")
            self.assertEqual(broker.returncode, 0, broker.stderr)
            self.assertIn("vpn-broker:v1:status", broker.stdout)
            root_manifest = json.loads(
                (layout.root_releases / release_a / "release.json").read_text()
            )
            self.assertEqual(
                {
                    entry["role"]: entry["path"]
                    for entry in root_manifest["files"]
                    if "role" in entry
                },
                ROOT_FILES,
            )

            user = json.loads(layout.selected.read_text())
            root = json.loads(layout.root_selected.read_text())
            user["root_files"] = alternate_map
            root["root_files"] = alternate_map
            user_raw = release_installer._canonical_json(user) + b"\n"
            root["user_selection_sha256"] = hashlib.sha256(user_raw).hexdigest()
            layout.selected.chmod(0o644)
            layout.selected.write_bytes(user_raw)
            layout.selected.chmod(0o444)
            layout.root_selected.chmod(0o644)
            layout.root_selected.write_bytes(
                release_installer._canonical_json(root) + b"\n"
            )
            layout.root_selected.chmod(0o444)
            self.assertFalse(installer_b._selection_is_exact(release_a))
            self.assertEqual(invoke(layout.entrypoint).returncode, 78)

    def test_install_interruptions_cover_every_selector_and_resume(self) -> None:
        root_switched = set(release_installer.SELECTION_FAULT_STAGES)
        user_switched = set(release_installer.SELECTION_FAULT_STAGES)
        user_switched.remove(release_installer.AFTER_ROOT_SELECTOR)
        for stage in release_installer.INSTALL_FAULT_STAGES:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as td:
                installer, layout, source = make_installer(Path(td))
                old_id = installer.install().release_id
                write_source(source, "v2")
                new_id = installer.plan_release().release_id

                with self.assertRaises(release_installer.InjectedFault):
                    installer.install(fault_at=stage)

                expected_root = new_id if stage in root_switched else old_id
                expected_user = new_id if stage in user_switched else old_id
                self.assertEqual(installer.root_active_release_id(), expected_root)
                self.assertEqual(installer.active_release_id(), expected_user)
                installer.validate_release_pair(old_id)
                if expected_root == new_id or expected_user == new_id:
                    installer.validate_release_pair(new_id)

                admission = invoke(layout.entrypoint)
                recovery = invoke(layout.entrypoint, "recover")
                mixed_recovery_stages = {
                    release_installer.AFTER_ROOT_SELECTOR,
                    release_installer.AFTER_CURRENT_SELECTOR,
                    release_installer.AFTER_BROKER_SELECTOR,
                    release_installer.AFTER_ENTRYPOINT_SELECTOR,
                    release_installer.AFTER_USER_SELECTION_METADATA,
                }
                self.assertEqual(
                    recovery.returncode,
                    78 if stage in mixed_recovery_stages else 0,
                    recovery.stderr,
                )
                if stage == release_installer.AFTER_DENY_CLEAR:
                    self.assertEqual(admission.returncode, 0, admission.stderr)
                    self.assertIn("grok-remote:v2", admission.stdout)
                    self.assertFalse(layout.rollback_deny.exists())
                else:
                    self.assertEqual(admission.returncode, 78)
                    self.assertTrue(os.path.lexists(layout.rollback_deny))
                    self.assertFalse(installer.status()["active_release_valid"])

                resumed = installer.install()
                self.assertEqual(resumed.release_id, new_id)
                self.assertEqual(installer.active_release_id(), new_id)
                self.assertEqual(installer.root_active_release_id(), new_id)
                installer.validate_release_pair(new_id)
                installer.validate_release_pair(old_id)
                self.assertFalse(layout.rollback_deny.exists())
                self.assertEqual(invoke(layout.entrypoint).returncode, 0)

    def test_real_sigkill_at_selector_publication_boundaries_resumes(self) -> None:
        for stage, mixed in (
            (release_installer.AFTER_ROOT_SELECTOR, True),
            (release_installer.AFTER_CURRENT_SELECTOR, False),
        ):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as td:
                installer, layout, source = make_installer(Path(td))
                old_id = installer.install().release_id
                write_source(source, "v2")
                new_id = installer.plan_release().release_id
                read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                child = os.fork()
                if child == 0:
                    os.close(read_fd)

                    def checkpoint(fault_at: str | None, current: str) -> None:
                        if fault_at == stage and current == stage:
                            os.write(write_fd, b"1")
                            while True:
                                signal.pause()
                        release_installer.ReleaseInstaller._fault(
                            fault_at, current
                        )

                    installer._fault = checkpoint
                    try:
                        installer.install(fault_at=stage)
                    except BaseException:
                        os._exit(91)
                    os._exit(92)
                os.close(write_fd)
                try:
                    readable, _, _ = select.select([read_fd], [], [], 15)
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

                self.assertEqual(installer.root_active_release_id(), new_id)
                self.assertEqual(
                    installer.active_release_id(), old_id if mixed else new_id
                )
                deny = installer._deny_record()
                self.assertIsNotNone(deny)
                assert deny is not None
                self.assertEqual(deny["from_release"], old_id)
                self.assertEqual(deny["to_release"], new_id)
                self.assertEqual(invoke(layout.entrypoint).returncode, 78)
                self.assertEqual(
                    invoke(layout.broker_entrypoint, "status").returncode, 78
                )
                recovery = invoke(layout.entrypoint, "recover")
                self.assertEqual(recovery.returncode, 78, recovery.stderr)
                installer.validate_release_pair(old_id)
                installer.validate_release_pair(new_id)

                resumed = installer.install()
                self.assertEqual(resumed.release_id, new_id)
                self.assertEqual(installer.active_release_id(), new_id)
                self.assertEqual(installer.root_active_release_id(), new_id)
                self.assertFalse(layout.rollback_deny.exists())
                self.assertEqual(invoke(layout.entrypoint).returncode, 0)
                second = installer.install()
                self.assertFalse(second.changed)

    def test_rollback_interruptions_cover_every_selector_and_preserve_releases(self) -> None:
        root_switched = set(release_installer.SELECTION_FAULT_STAGES)
        user_switched = set(release_installer.SELECTION_FAULT_STAGES)
        user_switched.remove(release_installer.AFTER_ROOT_SELECTOR)
        for stage in release_installer.ROLLBACK_FAULT_STAGES:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as td:
                installer, layout, source = make_installer(Path(td))
                old_id = installer.install().release_id
                write_source(source, "v2")
                new_id = installer.install().release_id

                with self.assertRaises(release_installer.InjectedFault):
                    installer.rollback(old_id, fault_at=stage)

                expected_root = old_id if stage in root_switched else new_id
                expected_user = old_id if stage in user_switched else new_id
                self.assertEqual(installer.root_active_release_id(), expected_root)
                self.assertEqual(installer.active_release_id(), expected_user)
                admission = invoke(layout.entrypoint)
                recovery = invoke(layout.entrypoint, "recover")
                mixed_recovery_stages = {
                    release_installer.AFTER_ROOT_SELECTOR,
                    release_installer.AFTER_CURRENT_SELECTOR,
                    release_installer.AFTER_BROKER_SELECTOR,
                    release_installer.AFTER_ENTRYPOINT_SELECTOR,
                    release_installer.AFTER_USER_SELECTION_METADATA,
                }
                self.assertEqual(
                    recovery.returncode,
                    78 if stage in mixed_recovery_stages else 0,
                    recovery.stderr,
                )
                if stage == release_installer.AFTER_DENY_CLEAR:
                    self.assertEqual(admission.returncode, 0, admission.stderr)
                    self.assertIn("grok-remote:v1", admission.stdout)
                else:
                    self.assertEqual(admission.returncode, 78)
                    self.assertTrue(os.path.lexists(layout.rollback_deny))

                result = installer.rollback(old_id)
                self.assertEqual(result.release_id, old_id)
                self.assertFalse(layout.rollback_deny.exists())
                self.assertIn("grok-remote:v1", invoke(layout.entrypoint).stdout)
                for release_id in (old_id, new_id):
                    installer.validate_release_pair(release_id)
                    self.assertTrue((layout.user_releases / release_id).is_dir())
                    self.assertTrue((layout.root_releases / release_id).is_dir())

    def test_same_release_is_idempotent_and_shared_lock_serializes_launch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            first = installer.install()
            selector_inodes = (
                layout.current.lstat().st_ino,
                layout.root_current.lstat().st_ino,
                layout.entrypoint.lstat().st_ino,
                layout.broker_entrypoint.lstat().st_ino,
            )
            second = installer.install()
            self.assertFalse(second.changed)
            self.assertEqual(second.release_id, first.release_id)
            self.assertEqual(
                selector_inodes,
                (
                    layout.current.lstat().st_ino,
                    layout.root_current.lstat().st_ino,
                    layout.entrypoint.lstat().st_ino,
                    layout.broker_entrypoint.lstat().st_ino,
                ),
            )
            with mock.patch.object(
                installer,
                "_legacy_openvpn_process_inventory",
                return_value=[321],
            ), self.assertRaisesRegex(
                release_installer.ReleaseError,
                "legacy OpenVPN process",
            ):
                installer.install()

            with installer._selection_locked():
                process = subprocess.Popen(
                    [str(layout.entrypoint)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                time.sleep(0.1)
                self.assertIsNone(process.poll(), "entrypoint bypassed exclusive release lock")
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertIn("grok-remote:v1", stdout)

    def test_rung_canary_fence_waits_for_every_admitted_shared_lock(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            admitted_fd = os.open(
                layout.install_lock,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            fcntl.flock(admitted_fd, fcntl.LOCK_SH)
            outcome: dict[str, object] = {}

            def begin() -> None:
                try:
                    outcome["result"] = installer.begin_rung_canary(
                        release_id=release_id,
                        rung="vpn",
                        route_profile="vpn",
                        contract_sha256="a" * 64,
                        grok_release_id="sha256:" + "b" * 64,
                        model_id="grok-4.5",
                    )
                except BaseException as exc:
                    outcome["error"] = exc

            worker = threading.Thread(target=begin, daemon=True)
            try:
                worker.start()
                time.sleep(0.1)
                self.assertTrue(worker.is_alive())
                self.assertFalse(layout.rollback_deny.exists())
            finally:
                fcntl.flock(admitted_fd, fcntl.LOCK_UN)
                os.close(admitted_fd)
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertNotIn("error", outcome)
            self.assertTrue(layout.rollback_deny.exists())
            self.assertTrue(layout.rung_canary.exists())
            installer.abort_restore(release_id)

    def test_admitted_target_holds_shared_release_lock_across_exec(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            target = source / "grok-remote"
            target.write_text(
                "#!/bin/sh\n"
                + CANARY_FIXTURE
                +
                "exec /usr/bin/python3 -c 'import pathlib,sys,time; "
                "pathlib.Path(sys.argv[1]).write_text(\"ready\"); time.sleep(30)' \"$1\"\n",
                encoding="utf-8",
            )
            target.chmod(0o755)
            installer.install()
            marker = Path(td) / "target-ready"
            process = subprocess.Popen(
                [str(layout.entrypoint), str(marker)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            lock_fd = os.open(layout.install_lock, os.O_RDONLY)
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists(), "selected target did not reach exec")
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                process.terminate()
                _stdout, stderr = process.communicate(timeout=5)
                self.assertNotEqual(process.returncode, 0, stderr)
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                os.close(lock_fd)

    def test_deny_drains_exact_supervisor_while_launch_storm_sees_only_coherent_releases(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            old_id = installer.install().release_id
            supervisor = start_fake_fenced_supervisor(layout, old_id)
            write_source(source, "v2")

            stop = threading.Event()
            observations: list[tuple[int, str, str]] = []
            observation_lock = threading.Lock()

            def launch_storm() -> None:
                while not stop.is_set():
                    result = invoke(layout.entrypoint)
                    with observation_lock:
                        observations.append((result.returncode, result.stdout, result.stderr))
                    time.sleep(0.005)

            worker = threading.Thread(target=launch_storm, daemon=True)
            worker.start()
            deadline = time.monotonic() + 3
            while not observations and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(observations, "launch storm did not admit the old release")
            try:
                changed = installer.install()
                time.sleep(0.1)
            finally:
                stop.set()
                worker.join(timeout=5)
                if supervisor.poll() is None:
                    supervisor.kill()
                try:
                    supervisor.wait(timeout=5)
                except ChildProcessError:
                    pass

            self.assertNotEqual(changed.release_id, old_id)
            self.assertFalse(layout.recovery_fence.exists())
            self.assertFalse((layout.multi_control / "supervisor.sock").exists())
            self.assertFalse(layout.rollback_deny.exists())
            self.assertFalse(worker.is_alive())
            self.assertTrue(
                any(returncode == 78 for returncode, _stdout, _stderr in observations),
                "continuous launches never observed the durable deny",
            )
            for returncode, stdout, stderr in observations:
                self.assertIn(returncode, {0, 78}, (returncode, stdout, stderr))
                if returncode == 0:
                    self.assertTrue(
                        stdout.startswith("grok-remote:v1:")
                        or stdout.startswith("grok-remote:v2:"),
                        stdout,
                    )
                else:
                    self.assertIn("release selection unavailable", stderr)
            final = invoke(layout.entrypoint)
            self.assertEqual(final.returncode, 0, final.stderr)
            self.assertIn("grok-remote:v2:", final.stdout)

    def test_bounded_old_lane_drain_failure_keeps_deny_until_resume(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            target = source / "grok-remote"
            target.write_text(
                "#!/bin/sh\n"
                + CANARY_FIXTURE
                +
                "exec /usr/bin/python3 -c 'import pathlib,sys,time; "
                "pathlib.Path(sys.argv[1]).write_text(\"ready\"); time.sleep(30)' \"$1\"\n",
                encoding="ascii",
            )
            target.chmod(0o755)
            old_id = installer.install().release_id
            marker = Path(td) / "old-lane-ready"
            old_lane = subprocess.Popen(
                [str(layout.entrypoint), str(marker)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 5
            while not marker.exists() and old_lane.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            write_source(source, "v2")
            installer.switch_timeout = 0.2
            try:
                with self.assertRaisesRegex(release_installer.ReleaseError, "timed out"):
                    installer.install()
                self.assertTrue(layout.rollback_deny.exists())
                self.assertEqual(installer.active_release_id(), old_id)
                self.assertEqual(invoke(layout.entrypoint).returncode, 78)
            finally:
                old_lane.terminate()
                old_lane.wait(timeout=5)

            installer.switch_timeout = 5
            new = installer.install()
            self.assertNotEqual(new.release_id, old_id)
            self.assertFalse(layout.rollback_deny.exists())
            self.assertIn("grok-remote:v2:", invoke(layout.entrypoint).stdout)

    def test_real_sigkill_after_deny_resumes_install_and_then_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source = base / "source"
            prefix = base / "prefix"
            openvpn = base / "openvpn"
            openvpn.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            openvpn.chmod(0o700)
            fixture, _boot_id, _pid = write_proc_fixture(prefix)
            proc_fd = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            self.addCleanup(os.close, proc_fd)
            proc_environment = {
                **os.environ,
                release_installer._PREFIX_PROC_FD_ENV: str(proc_fd),
            }
            write_default_source(source, "v1")
            common = [
                sys.executable,
                str(MODULE_PATH),
                "--source",
                str(source),
                "--prefix",
                str(prefix),
                "--home",
                "/home/caller",
                "--test-openvpn-binary",
                str(openvpn),
            ]
            first = subprocess.run(
                [common[0], common[1], "install", *common[2:], "--apply"],
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
                env=proc_environment,
                pass_fds=(proc_fd,),
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            old_id = json.loads(first.stdout)["release_id"]

            write_default_source(source, "v2")
            bulk = source / "grok_ms/bulk"
            bulk.mkdir()
            for index in range(256):
                (bulk / f"fixture_{index:04d}.py").write_text(
                    f"VALUE = {index}\n", encoding="ascii"
                )
            interrupted = subprocess.Popen(
                [common[0], common[1], "install", *common[2:], "--apply"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=proc_environment,
                pass_fds=(proc_fd,),
            )
            deny = prefix / "var/lib/grok-proxy/release-control/rollback-deny.json"
            deadline = time.monotonic() + 10
            while not deny.exists() and interrupted.poll() is None and time.monotonic() < deadline:
                time.sleep(0.002)
            self.assertTrue(deny.exists(), "installer never published deny before staging")
            self.assertIsNone(interrupted.poll(), "installer completed before SIGKILL checkpoint")
            interrupted.kill()
            interrupted.communicate(timeout=5)
            self.assertEqual(interrupted.returncode, -signal.SIGKILL)

            gate = prefix / "home/caller/.local/bin/grok-remote"
            self.assertEqual(invoke(gate).returncode, 78)
            resumed = subprocess.run(
                [common[0], common[1], "install", *common[2:], "--apply"],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env=proc_environment,
                pass_fds=(proc_fd,),
            )
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            new_id = json.loads(resumed.stdout)["release_id"]
            self.assertNotEqual(new_id, old_id)
            self.assertFalse(deny.exists())
            self.assertIn("grok-remote:v2:", invoke(gate).stdout)

            rolled_back = subprocess.run(
                [
                    common[0], common[1], "rollback", *common[2:],
                    "--release-id", old_id, "--apply",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env=proc_environment,
                pass_fds=(proc_fd,),
            )
            self.assertEqual(rolled_back.returncode, 0, rolled_back.stderr)
            self.assertFalse(deny.exists())
            self.assertIn("grok-remote:v1:", invoke(gate).stdout)

    def test_validation_rejects_mutable_files_links_and_wrong_expected_owner(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            target = layout.user_releases / release_id / "grok_ms/core.py"
            target.chmod(0o644)
            with self.assertRaisesRegex(release_installer.ReleaseError, "mode"):
                installer.validate_release_pair(release_id)

        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            package = layout.user_releases / release_id / "grok_ms"
            package.chmod(0o755)
            target = package / "core.py"
            target.unlink()
            target.symlink_to("/etc/passwd")
            package.chmod(0o555)
            with self.assertRaises(release_installer.ReleaseError):
                installer.validate_release_pair(release_id)

        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            wrong = release_installer.Layout(
                source_dir=layout.source_dir,
                user_root=layout.user_root,
                root_root=layout.root_root,
                root_state_root=layout.root_control,
                state_root=layout.state_root,
                entrypoint=layout.entrypoint,
                target_uid=layout.target_uid,
                target_gid=layout.target_gid,
                root_uid=layout.root_uid + 1,
                root_gid=layout.root_gid,
            )
            verifier = release_installer.ReleaseInstaller(
                wrong, runtime_files=RUNTIME_FILES, root_files=ROOT_FILES
            )
            with self.assertRaisesRegex(release_installer.ReleaseError, "owner"):
                verifier._validate_release(wrong.user_releases / release_id, release_id, "user")

    def test_real_target_uid_executes_but_cannot_tamper_with_installed_user_modules(self) -> None:
        marker = "GROK_INSTALLER_ROOT_OWNERSHIP_INNER"
        if os.geteuid() != 0:
            sudo = shutil.which("sudo")
            if sudo is None:
                self.skipTest("sudo is unavailable for the distinct-UID ownership check")
            probe = subprocess.run(
                [sudo, "-n", "/usr/bin/true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if probe.returncode != 0:
                self.skipTest("passwordless sudo is unavailable for the distinct-UID check")
            environment = dict(os.environ)
            environment[marker] = "1"
            inner = subprocess.run(
                [
                    sudo,
                    "-n",
                    "/usr/bin/env",
                    f"{marker}=1",
                    "/usr/bin/python3",
                    str(Path(__file__).resolve()),
                    f"{self.__class__.__name__}.{self._testMethodName}",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env=environment,
            )
            self.assertEqual(inner.returncode, 0, inner.stdout + inner.stderr)
            return

        if os.environ.get(marker) != "1":
            self.skipTest("distinct-UID inner check is invoked through passwordless sudo")
        target_uid = int(os.environ["SUDO_UID"])
        target_gid = int(os.environ["SUDO_GID"])
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            base.chmod(0o755)
            source = base / "source"
            write_source(source, "v1")
            home = base / "home"
            layout = release_installer.Layout(
                source_dir=source,
                user_root=home / ".local/lib/grok-proxy",
                root_root=base / "root/usr/local/libexec/grok-proxy",
                root_state_root=base / "root/var/lib/grok-proxy/release-control",
                state_root=home / ".local/state/grok-proxy/release-control",
                entrypoint=home / ".local/bin/grok-remote",
                target_uid=target_uid,
                target_gid=target_gid,
                root_uid=0,
                root_gid=0,
                test_install=True,
            )
            installer = release_installer.ReleaseInstaller(
                layout,
                runtime_files=RUNTIME_FILES,
                root_files=ROOT_FILES,
            )
            release_id = installer.install().release_id
            module = layout.user_releases / release_id / "grok_ms/core.py"
            for path in (
                layout.user_root,
                layout.user_releases,
                layout.user_releases / release_id,
                module,
                layout.entrypoint,
            ):
                self.assertEqual(path.lstat().st_uid, 0, path)
                self.assertEqual(path.lstat().st_gid, 0, path)

            child = os.fork()
            if child == 0:
                try:
                    os.setgroups([])
                    os.setgid(target_gid)
                    os.setuid(target_uid)
                    os.chmod(module, 0o644)
                except PermissionError:
                    os._exit(0)
                except BaseException:
                    os._exit(2)
                os._exit(1)
            _pid, child_status = os.waitpid(child, 0)
            self.assertTrue(os.WIFEXITED(child_status))
            self.assertEqual(os.WEXITSTATUS(child_status), 0)

            def drop_to_target() -> None:
                os.setgroups([])
                os.setgid(target_gid)
                os.setuid(target_uid)

            execution = subprocess.run(
                [str(layout.entrypoint), "--ownership-check"],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
                preexec_fn=drop_to_target,
            )
            self.assertEqual(execution.returncode, 0, execution.stderr)
            self.assertIn("grok-remote:v1:--ownership-check", execution.stdout)

            profile, grok = make_activation_profile(base, release_id)
            os.chown(grok, target_uid, target_gid)
            write_content_addressed_profile(
                layout.profile_root,
                profile,
                owner_uid=target_uid,
                owner_gid=target_gid,
            )
            complete_release_qualification(installer, release_id)
            installer.begin_rung_canary(
                release_id=release_id,
                rung="direct",
                route_profile="direct",
                contract_sha256=profile.contract.digest(),
                grok_release_id=profile.grok_release_id,
                model_id=profile.contract.model_id,
            )
            projection = profile.contract.rung_qualification_digest("direct")
            with mock.patch.object(
                installer,
                "_run_qualification_verifier",
                side_effect=lambda **kw: fixed_qualification_smoke(
                    installer,
                    str(kw["step"]),
                    rung_qualification_sha256=projection,
                ),
            ):
                installer.qualification_exec("real-pair")
            installer.promote_rung()
            activated = installer.activate_profile(profile.digest())
            self.assertEqual(activated.operation, "activate-profile")
            self.assertEqual(grok.stat().st_uid, target_uid)
            load_activation_record(
                layout.active_profile,
                expected_uid=0,
                expected_gid=0,
            ).validate_profile(profile)

            write_source(source, "v2")
            replacement = installer.install().release_id
            self.assertNotEqual(release_id, replacement)
            self.assertEqual(
                stat.S_IMODE((layout.user_releases / release_id).stat().st_mode),
                release_installer.ARCHIVED_RELEASE_MODE,
            )
            self.assertEqual(
                stat.S_IMODE((layout.user_releases / replacement).stat().st_mode),
                release_installer.ACTIVE_RELEASE_MODE,
            )
            for root_release in (release_id, replacement):
                self.assertEqual(
                    stat.S_IMODE(
                        (layout.root_releases / root_release).stat().st_mode
                    ),
                    release_installer.ACTIVE_RELEASE_MODE,
                )

            child = os.fork()
            if child == 0:
                try:
                    os.setgroups([])
                    os.setgid(target_gid)
                    os.setuid(target_uid)
                    os.execv(
                        str(layout.user_releases / release_id / "grok-remote"),
                        ["grok-remote", "--retained-release-check"],
                    )
                except PermissionError:
                    os._exit(0)
                except BaseException:
                    os._exit(2)
                os._exit(1)
            _pid, child_status = os.waitpid(child, 0)
            self.assertTrue(os.WIFEXITED(child_status))
            self.assertEqual(os.WEXITSTATUS(child_status), 0)

            execution = subprocess.run(
                [str(layout.entrypoint), "--replacement-check"],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
                preexec_fn=drop_to_target,
            )
            self.assertEqual(execution.returncode, 0, execution.stderr)
            self.assertIn("grok-remote:v2:--replacement-check", execution.stdout)

    def test_legacy_selector_is_atomically_replaced_by_fail_closed_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            layout.entrypoint.parent.mkdir(parents=True, mode=0o755)
            legacy = Path(td) / "legacy-grok"
            legacy.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            legacy.chmod(0o755)
            layout.entrypoint.symlink_to(legacy)
            layout.root_root.mkdir(parents=True, mode=0o755)
            layout.broker_entrypoint.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            layout.broker_entrypoint.chmod(0o755)

            installer.install()
            self.assertFalse(layout.entrypoint.is_symlink())
            self.assertFalse(layout.broker_entrypoint.is_symlink())
            self.assertEqual(invoke(layout.entrypoint).returncode, 0)
            self.assertEqual(invoke(layout.broker_entrypoint).returncode, 0)

    def test_cli_dry_run_apply_status_and_rollback_are_prefix_safe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source = base / "source"
            prefix = base / "prefix"
            openvpn = base / "openvpn"
            openvpn.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            openvpn.chmod(0o700)
            fixture, _boot_id, _pid = write_proc_fixture(prefix)
            proc_fd = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            self.addCleanup(os.close, proc_fd)
            proc_environment = {
                **os.environ,
                release_installer._PREFIX_PROC_FD_ENV: str(proc_fd),
            }
            write_default_source(source, "v1")
            common = [
                sys.executable,
                str(MODULE_PATH),
                "--source",
                str(source),
                "--prefix",
                str(prefix),
                "--home",
                "/home/caller",
                "--test-openvpn-binary",
                str(openvpn),
            ]

            dry = subprocess.run(
                [common[0], common[1], "install", *common[2:], "--dry-run"],
                text=True,
                capture_output=True,
                check=False,
                env=proc_environment,
                pass_fds=(proc_fd,),
            )
            self.assertEqual(dry.returncode, 0, dry.stderr)
            dry_record = json.loads(dry.stdout)
            self.assertFalse(dry_record["applied"])
            self.assertFalse(
                (prefix / "var/lib/grok-proxy").exists(),
                "dry run mutated release state",
            )

            first_installers = [
                subprocess.Popen(
                    [common[0], common[1], "install", *common[2:], "--apply"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=proc_environment,
                    pass_fds=(proc_fd,),
                )
                for _ in range(2)
            ]
            first_records = []
            for process in first_installers:
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                first_records.append(json.loads(stdout))
            self.assertEqual(len({record["release_id"] for record in first_records}), 1)
            self.assertEqual(sum(bool(record["changed"]) for record in first_records), 1)
            old_id = first_records[0]["release_id"]
            entrypoint = prefix / "home/caller/.local/bin/grok-remote"
            self.assertIn("grok-remote:v1", invoke(entrypoint).stdout)

            write_default_source(source, "v2")
            concurrent = [
                subprocess.Popen(
                    [common[0], common[1], "install", *common[2:], "--apply"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=proc_environment,
                    pass_fds=(proc_fd,),
                )
                for _ in range(2)
            ]
            records = []
            for process in concurrent:
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                records.append(json.loads(stdout))
            self.assertEqual(len({record["release_id"] for record in records}), 1)
            self.assertEqual(sum(bool(record["changed"]) for record in records), 1)
            new_id = records[0]["release_id"]
            self.assertNotEqual(old_id, new_id)

            rollback_dry = subprocess.run(
                [
                    common[0], common[1], "rollback", *common[2:],
                    "--release-id", old_id, "--dry-run",
                ],
                text=True,
                capture_output=True,
                check=False,
                env=proc_environment,
                pass_fds=(proc_fd,),
            )
            self.assertEqual(rollback_dry.returncode, 0, rollback_dry.stderr)
            self.assertIn("grok-remote:v2", invoke(entrypoint).stdout)
            rollback = subprocess.run(
                [
                    common[0], common[1], "rollback", *common[2:],
                    "--release-id", old_id, "--apply",
                ],
                text=True,
                capture_output=True,
                check=False,
                env=proc_environment,
                pass_fds=(proc_fd,),
            )
            self.assertEqual(rollback.returncode, 0, rollback.stderr)
            self.assertIn("grok-remote:v1", invoke(entrypoint).stdout)

            status = subprocess.run(
                [
                    common[0], common[1], "status",
                    *common[2:-2],
                ],
                text=True,
                capture_output=True,
                check=False,
                env=proc_environment,
                pass_fds=(proc_fd,),
            )
            self.assertEqual(status.returncode, 0, status.stderr)
            status_record = json.loads(status.stdout)
            self.assertTrue(status_record["active_release_valid"])
            self.assertEqual(status_record["active_release_id"], old_id)

    def test_sudo_defaults_target_calling_users_real_home(self) -> None:
        account = SimpleNamespace(pw_gid=4243, pw_dir="/home/calling-user")
        with (
            mock.patch.object(release_installer.os, "geteuid", return_value=0),
            mock.patch.object(release_installer.os, "getegid", return_value=0),
            mock.patch.object(release_installer.pwd, "getpwuid", return_value=account),
            mock.patch.dict(os.environ, {"SUDO_UID": "4242"}),
        ):
            layout = release_installer.Layout.defaults(Path("/source"))
            self.assertEqual(layout.target_uid, 4242)
            self.assertEqual(layout.target_gid, 4243)
            self.assertEqual(layout.user_root, Path("/home/calling-user/.local/lib/grok-proxy"))
            self.assertEqual(layout.entrypoint, Path("/home/calling-user/.local/bin/grok-remote"))
            self.assertEqual(layout.root_uid, 0)
            with self.assertRaisesRegex(release_installer.ReleaseError, "passwd home"):
                release_installer.Layout.defaults(Path("/source"), home=Path("/root"))
        with self.assertRaisesRegex(release_installer.ReleaseError, "must not be /"):
            release_installer.Layout.defaults(Path("/source"), prefix=Path("/"))
        with self.assertRaisesRegex(release_installer.ReleaseError, "must be absolute"):
            release_installer.Layout.defaults(Path("/source"), prefix=Path("relative"))

    def test_prefix_home_is_canonical_and_contained_before_apply(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            prefix = base / "prefix"
            source = base / "source"
            openvpn = base / "openvpn"
            write_default_source(source, "v1")
            openvpn.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            openvpn.chmod(0o700)
            escaped = base / "escape"
            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "install",
                    "--source",
                    str(source),
                    "--prefix",
                    str(prefix),
                    "--home",
                    "/../escape",
                    "--test-openvpn-binary",
                    str(openvpn),
                    "--apply",
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(prefix.exists(), "rejected layout produced prefix effects")
            self.assertFalse(escaped.exists(), "prefix-mode home escaped its prefix")

            with self.assertRaisesRegex(release_installer.ReleaseError, "canonical"):
                release_installer.Layout.defaults(
                    source,
                    prefix=prefix,
                    home=Path("/home/caller/../escape"),
                )

            real_prefix = base / "real-prefix"
            real_prefix.mkdir()
            linked_prefix = base / "linked-prefix"
            linked_prefix.symlink_to(real_prefix, target_is_directory=True)
            with self.assertRaisesRegex(release_installer.ReleaseError, "canonical"):
                release_installer.Layout.defaults(
                    source,
                    prefix=linked_prefix,
                    home=Path("/home/caller"),
                )

    def test_ensure_dir_rename_symlink_race_cannot_redirect_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            parent = base / "parent"
            parent.mkdir()
            target = parent / "managed"
            displaced = parent / "displaced"
            sentinel = base / "sentinel"
            sentinel.mkdir(mode=0o755)
            sentinel.chmod(0o755)
            before = sentinel.stat()
            real_mkdir = os.mkdir
            fired = False

            def racing_mkdir(name, mode=0o777, *, dir_fd=None):
                nonlocal fired
                result = real_mkdir(name, mode, dir_fd=dir_fd)
                if name == target.name and not fired:
                    fired = True
                    target.rename(displaced)
                    target.symlink_to(sentinel, target_is_directory=True)
                return result

            with mock.patch.object(
                release_installer.os, "mkdir", side_effect=racing_mkdir
            ), self.assertRaisesRegex(
                release_installer.ReleaseError,
                "cannot open created directory safely",
            ):
                release_installer._ensure_dir(
                    target, 0o700, os.geteuid(), os.getegid()
                )

            after = sentinel.stat()
            self.assertTrue(fired)
            self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
            self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
            self.assertTrue(displaced.is_dir())

    def test_atomic_and_exclusive_parent_swap_stay_on_retained_directory(self) -> None:
        for writer in ("atomic", "exclusive"):
            with self.subTest(writer=writer), tempfile.TemporaryDirectory() as td:
                base = Path(td)
                parent = base / "parent"
                moved = base / "moved"
                replacement = base / "replacement"
                parent.mkdir(mode=0o700)
                replacement.mkdir(mode=0o700)
                parent.chmod(0o700)
                replacement.chmod(0o700)
                destination = parent / "record"
                if writer == "atomic":
                    sentinel = replacement / "record"
                    sentinel.write_bytes(b"sentinel\n")
                    sentinel.chmod(0o600)
                    before = sentinel.read_bytes()
                real_open = os.open
                fired = False

                def racing_open(path, flags, mode=0o777, *, dir_fd=None):
                    nonlocal fired
                    name = os.fspath(path)
                    trigger = (
                        writer == "atomic" and name.startswith(".record.tmp-")
                    ) or (
                        writer == "exclusive"
                        and name == "record"
                        and bool(flags & os.O_EXCL)
                    )
                    if trigger and not fired:
                        fired = True
                        parent.rename(moved)
                        parent.symlink_to(replacement, target_is_directory=True)
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                with mock.patch.object(
                    release_installer.os, "open", side_effect=racing_open
                ), self.assertRaisesRegex(
                    release_installer.ReleaseError,
                    "directory path changed during operation",
                ):
                    if writer == "atomic":
                        release_installer._atomic_write(
                            destination,
                            b"new-data\n",
                            mode=0o600,
                            uid=os.geteuid(),
                            gid=os.getegid(),
                            parent_mode=0o700,
                        )
                    else:
                        release_installer._exclusive_write(
                            destination,
                            b"new-data\n",
                            mode=0o600,
                            uid=os.geteuid(),
                            gid=os.getegid(),
                            parent_mode=0o700,
                        )

                self.assertTrue(fired)
                if writer == "atomic":
                    self.assertEqual(sentinel.read_bytes(), before)
                    self.assertEqual((moved / "record").read_bytes(), b"new-data\n")
                else:
                    self.assertFalse((replacement / "record").exists())
                    self.assertFalse((moved / "record").exists())

    def test_atomic_write_failure_does_not_unlink_replaced_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / "parent"
            parent.mkdir(mode=0o700)
            parent.chmod(0o700)
            held = parent / "held-original"
            attacker_bytes = b"attacker-owned-replacement\n"

            def fail_after_replacement(_fd, _data, _destination):
                temporaries = list(parent.glob(".record.tmp-*"))
                self.assertEqual(len(temporaries), 1)
                temporary = temporaries[0]
                temporary.rename(held)
                temporary.write_bytes(attacker_bytes)
                raise RuntimeError("injected write failure")

            with mock.patch.object(
                release_installer,
                "_write_all",
                side_effect=fail_after_replacement,
            ), self.assertRaisesRegex(RuntimeError, "injected write failure"):
                release_installer._atomic_write(
                    parent / "record",
                    b"new-data\n",
                    mode=0o600,
                    uid=os.geteuid(),
                    gid=os.getegid(),
                    parent_mode=0o700,
                )

            replacements = list(parent.glob(".record.tmp-*"))
            self.assertEqual(len(replacements), 1)
            self.assertEqual(replacements[0].read_bytes(), attacker_bytes)
            self.assertTrue(held.is_file())

    def test_user_release_staging_parent_swap_cannot_escape_retained_tree(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, _source = make_installer(base)
            installer._prepare_roots()
            plan = installer.plan_release()
            moved = base / "moved-user-root"
            replacement = base / "replacement-user-root"
            replacement_releases = replacement / "releases"
            replacement_releases.mkdir(parents=True, mode=0o755)
            replacement_releases.chmod(0o755)
            sentinel = base / "profile.d"
            sentinel.mkdir(mode=0o755)
            sentinel.chmod(0o755)
            sentinel_mode = stat.S_IMODE(sentinel.stat().st_mode)
            real_mkdir = os.mkdir
            fired = False

            def racing_mkdir(name, mode=0o777, *, dir_fd=None):
                nonlocal fired
                result = real_mkdir(name, mode, dir_fd=dir_fd)
                if (
                    isinstance(name, str)
                    and name.startswith(f".stage-{plan.release_id}-")
                    and not fired
                ):
                    fired = True
                    layout.user_root.rename(moved)
                    layout.user_root.symlink_to(
                        replacement, target_is_directory=True
                    )
                    (replacement_releases / name).symlink_to(
                        sentinel, target_is_directory=True
                    )
                return result

            with mock.patch.object(
                release_installer.os, "mkdir", side_effect=racing_mkdir
            ), self.assertRaisesRegex(
                release_installer.ReleaseError,
                "directory path changed during operation",
            ):
                installer._stage_release(plan, "user")

            self.assertTrue(fired)
            self.assertEqual(list(sentinel.iterdir()), [])
            self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), sentinel_mode)
            self.assertEqual(
                list((moved / "releases").glob(f".stage-{plan.release_id}-*")),
                [],
            )

    def test_user_release_publish_rejects_parent_swap_without_redirecting(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, _source = make_installer(base)
            installer._prepare_roots()
            plan = installer.plan_release()
            stage, final = installer._stage_release(plan, "user")
            self.assertIsNotNone(stage)
            assert stage is not None
            moved = base / "moved-user-root"
            replacement = base / "replacement-user-root"
            (replacement / "releases").mkdir(parents=True, mode=0o755)
            (replacement / "releases").chmod(0o755)
            layout.user_root.rename(moved)
            layout.user_root.symlink_to(replacement, target_is_directory=True)

            with self.assertRaisesRegex(
                release_installer.ReleaseError,
                "cannot open directory component safely",
            ):
                installer._publish_stage(stage, final)

            self.assertFalse((replacement / "releases" / plan.release_id).exists())
            self.assertTrue((moved / "releases" / stage.name).is_dir())

    def test_private_config_and_state_are_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, _layout, source = make_installer(base)
            private = base / "home/grok-proxy"
            iphone = base / "home/.local/state/grok-proxy/iphone"
            private.mkdir(parents=True)
            iphone.mkdir(parents=True)
            (private / "hosts.conf").write_bytes(b"private-host-data\n")
            (private / "id_grokproxy").write_bytes(b"private-key-data\n")
            (private / "id_grokproxy").chmod(0o600)
            (iphone / "tailscaled.state").write_bytes(b"private-sidecar-state\n")
            (iphone / "tailscaled.state").chmod(0o600)
            before = tree_snapshot(base / "home")

            old_id = installer.install().release_id
            write_source(source, "v2")
            installer.install()
            installer.rollback(old_id)

            after = tree_snapshot(base / "home")
            for rel in (
                "grok-proxy/hosts.conf",
                "grok-proxy/id_grokproxy",
                ".local/state/grok-proxy/iphone/tailscaled.state",
            ):
                self.assertEqual(after[rel], before[rel])

    def test_root_selection_binds_user_record_and_gate_digests(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, _source = make_installer(Path(td))
            release_id = installer.install().release_id
            root = json.loads(layout.root_selected.read_text())
            user_raw = layout.selected.read_bytes()
            self.assertEqual(root["release_id"], release_id)
            self.assertEqual(root["user_selection_sha256"], hashlib.sha256(user_raw).hexdigest())
            self.assertEqual(root["entrypoint_sha256"], hashlib.sha256(layout.entrypoint.read_bytes()).hexdigest())
            self.assertEqual(root["broker_gate_sha256"], hashlib.sha256(layout.broker_entrypoint.read_bytes()).hexdigest())
            self.assertEqual(root["target_uid"], layout.target_uid)
            self.assertEqual(root["target_gid"], layout.target_gid)
            self.assertEqual(root["root_control"], str(layout.root_control))
            self.assertTrue(layout.broker_state.is_dir())
            self.assertEqual(stat.S_IMODE(layout.broker_state.stat().st_mode), 0o700)
            self.assertTrue(layout.broker_lock.is_file())
            self.assertEqual(stat.S_IMODE(layout.broker_lock.stat().st_mode), 0o600)

    def test_installed_control_and_manifest_are_consumable_by_real_broker(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, _source = make_installer(base)
            release_id = installer.install().release_id
            broker = broker_module.Broker(
                broker_module.Layout(
                    releases=layout.root_releases,
                    selection=layout.root_selected,
                    deny=layout.rollback_deny,
                    state=layout.broker_state,
                ),
                expected_root_uid=layout.root_uid,
            )
            with broker.locked(create=False):
                pass
            broker._selection(release_id, "status")
            self.assertEqual(
                broker._helper(release_id),
                layout.root_releases / release_id / "vpngate-connect.sh",
            )

    def test_switch_refuses_broker_ledger_fence_and_live_epoch_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            installer, layout, source = make_installer(Path(td))
            old_id = installer.install().release_id
            write_source(source, "v2")

            layout.broker_state.mkdir(parents=True, mode=0o700, exist_ok=True)
            layout.broker_state.chmod(0o700)
            ledger = {
                "schema_version": 2,
                "phase": "FAILED",
                "release_id": old_id,
            }
            layout.broker_ledger.write_text(json.dumps(ledger), encoding="utf-8")
            layout.broker_ledger.chmod(0o600)
            before = (os.readlink(layout.current), os.readlink(layout.root_current))
            with self.assertRaisesRegex(release_installer.ReleaseError, "broker ledger"):
                installer.install()
            self.assertEqual(
                (os.readlink(layout.current), os.readlink(layout.root_current)),
                before,
            )
            self.assertTrue(layout.rollback_deny.exists())
            ledger["phase"] = "ACTIVE"
            layout.broker_ledger.write_text(json.dumps(ledger), encoding="utf-8")
            layout.broker_ledger.chmod(0o600)
            with self.assertRaisesRegex(release_installer.ReleaseError, "phase=ACTIVE"):
                installer.install()
            with self.assertRaisesRegex(release_installer.ReleaseError, "different interrupted"):
                installer.rollback(old_id)
            layout.broker_ledger.unlink()

            layout.multi_control.mkdir(parents=True, mode=0o700)
            layout.multi_control.chmod(0o700)
            layout.recovery_fence.write_text("{}\n", encoding="ascii")
            layout.recovery_fence.chmod(0o600)
            with self.assertRaisesRegex(release_installer.ReleaseError, "recovery fence"):
                installer.install()
            self.assertTrue(layout.recovery_fence.exists(), "installer altered the recovery fence")
            self.assertTrue(layout.rollback_deny.exists())
            layout.recovery_fence.unlink()

            layout.provider_root.mkdir(mode=0o700)
            (layout.provider_root / "0123456789abcdef01234567").mkdir(mode=0o700)
            with self.assertRaisesRegex(release_installer.ReleaseError, "provider workspace"):
                installer.install()
            self.assertTrue(layout.rollback_deny.exists())
            (layout.provider_root / "0123456789abcdef01234567").rmdir()
            layout.provider_root.rmdir()

            new_id = installer.install().release_id
            self.assertNotEqual(new_id, old_id)
            layout.broker_ledger.write_text(
                json.dumps({**ledger, "phase": "FAILED", "release_id": new_id}), encoding="utf-8"
            )
            layout.broker_ledger.chmod(0o600)
            with self.assertRaisesRegex(release_installer.ReleaseError, "phase=FAILED"):
                installer.rollback(old_id)
            self.assertEqual(installer.active_release_id(), new_id)
            self.assertTrue(layout.rollback_deny.exists())
            layout.broker_ledger.unlink()
            self.assertEqual(installer.rollback(old_id).release_id, old_id)

    def test_switch_quiescence_includes_intents_and_leaders(self) -> None:
        cases = (
            "valid-intent",
            "malformed-intent",
            "provider-scope-record",
            "leader-directory",
            "leader-socket",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                installer, layout, source = make_installer(Path(td))
                old_id = installer.install().release_id
                write_source(source, "v2")
                layout.multi_control.mkdir(parents=True, mode=0o700)
                layout.multi_control.chmod(0o700)
                opened_socket: socket.socket | None = None
                if case.endswith("intent"):
                    residue_root = layout.multi_control / "intents"
                    residue_root.mkdir(mode=0o700)
                    residue = residue_root / "effect.json"
                    if case == "valid-intent":
                        residue.write_text(
                            json.dumps(
                                {
                                    "schema_version": 1,
                                    "owner_epoch": "dead-owner",
                                    "generation": 1,
                                    "effect_id": "effect",
                                    "operation": "provider-start",
                                    "parameters_digest": "a" * 64,
                                    "phase": "PREPARED",
                                }
                            ),
                            encoding="ascii",
                        )
                    else:
                        residue.write_bytes(b"not-json\n")
                    residue.chmod(0o600)
                    expected = "effect intent"
                elif case == "provider-scope-record":
                    residue_root = layout.multi_control / "recovery/provider-scopes"
                    residue_root.mkdir(mode=0o700, parents=True)
                    residue = residue_root / "fixture.provider.json"
                    residue.write_bytes(b"{}\n")
                    residue.chmod(0o600)
                    expected = "recovery record"
                else:
                    residue_root = layout.multi_control / "leaders"
                    residue_root.mkdir(mode=0o700)
                    residue = residue_root / "l-fixture.sock"
                    if case == "leader-directory":
                        residue.mkdir(mode=0o700)
                    else:
                        opened_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        opened_socket.bind(str(residue))
                    expected = "leader"
                before = (installer.active_release_id(), installer.root_active_release_id())
                try:
                    with self.assertRaisesRegex(release_installer.ReleaseError, expected):
                        installer.install()
                    self.assertEqual(
                        (installer.active_release_id(), installer.root_active_release_id()),
                        before,
                    )
                    self.assertTrue(layout.rollback_deny.exists())
                finally:
                    if opened_socket is not None:
                        opened_socket.close()
                    if residue.exists() or residue.is_symlink():
                        residue.rmdir() if residue.is_dir() else residue.unlink()
                    residue_root.rmdir()
                    if case == "provider-scope-record":
                        residue_root.parent.rmdir()

                new_id = installer.install().release_id
                self.assertNotEqual(new_id, old_id)
                residue_root.mkdir(
                    mode=0o700,
                    parents=case == "provider-scope-record",
                )
                residue = residue_root / "residue"
                residue.write_bytes(b"residue\n")
                residue.chmod(0o600)
                before = (installer.active_release_id(), installer.root_active_release_id())
                with self.assertRaisesRegex(release_installer.ReleaseError, expected):
                    installer.rollback(old_id)
                self.assertEqual(
                    (installer.active_release_id(), installer.root_active_release_id()),
                    before,
                )
                self.assertTrue(layout.rollback_deny.exists())
                residue.unlink()
                residue_root.rmdir()
                if case == "provider-scope-record":
                    residue_root.parent.rmdir()
                self.assertEqual(installer.rollback(old_id).release_id, old_id)

    def test_switch_quiescence_blocks_process_listener_and_cgroup_residue(self) -> None:
        cases = ("release-process", "fixed-listener", "grok-cgroup")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                installer, layout, source = make_installer(Path(td))
                old_id = installer.install().release_id
                write_source(source, "v2")
                sleeper: subprocess.Popen[bytes] | None = None
                listener: socket.socket | None = None
                patcher = None
                expected = ""
                try:
                    if case == "release-process":
                        sleeper = subprocess.Popen(
                            ["/bin/sleep", "30"],
                            cwd=layout.user_releases / old_id,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        expected = "release-bound processes"
                    elif case == "fixed-listener":
                        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        listener.bind(("127.0.0.1", 11081))
                        listener.listen(1)
                        expected = "fixed Grok listener"
                    else:
                        patcher = mock.patch.object(
                            installer,
                            "_fixed_cgroup_inventory",
                            return_value=["/sys/fs/cgroup/grok-ms-0123456789abcdef01234567"],
                        )
                        patcher.start()
                        expected = "cgroup-v2 residue"
                    with self.assertRaisesRegex(release_installer.ReleaseError, expected):
                        installer.install()
                    self.assertEqual(installer.active_release_id(), old_id)
                    self.assertTrue(layout.rollback_deny.exists())
                finally:
                    if patcher is not None:
                        patcher.stop()
                    if listener is not None:
                        listener.close()
                    if sleeper is not None:
                        sleeper.terminate()
                        sleeper.wait(timeout=5)

                resumed = installer.install()
                self.assertNotEqual(resumed.release_id, old_id)
                self.assertFalse(layout.rollback_deny.exists())

    def test_root_gate_ignores_pythonpath_and_sanitizes_broker_environment(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, _source = make_installer(base)
            installer.install()
            injection = base / "injection"
            injection.mkdir()
            (injection / "json.py").write_text("raise SystemExit(91)\n", encoding="utf-8")
            environment = dict(os.environ)
            environment.update({"PYTHONPATH": str(injection), "EVIL": "secret"})
            result = subprocess.run(
                [str(layout.broker_entrypoint), "status"],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "vpn-broker:v1:status:evil=unset\n")

    def test_user_gate_uses_fixed_bash_and_bounds_test_and_startup_environment(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            installer, layout, source = make_installer(base)
            target = source / "grok-remote"
            target.write_text(
                """#!/bin/bash
if [[ "${GROK_RELEASE_CANARY_MODE:-0}" == 1 ]]; then
  printf 'fixture-canary:%s\n' "$1"
  exit 0
fi
/usr/bin/python3 - <<'PY'
import os
names = (
    "PATH",
    "GROK_TESTING",
    "GROK_TEST_ROOT_RELEASE_CONTROL",
    "GROK_TEST_CURL_BIN",
    "GROK_TEST_IPHONE_STATE_DIR",
    "GROK_TEST_SKIP_WARM_HANDOFF",
    "GROK_TEST_FAULT",
    "GROK_TEST_CONTROL_DIR",
    "GROK_TEST_VPN_BROKER",
    "GROK_BOOTSTRAP_PUBLISHER_TEST_MODE",
    "GROK_BOOTSTRAP_PACKAGE_ACTIVATOR_TEST_MODE",
    "GROK_LAUNCHER_TEST_CLOSE_RANGE_SYSCALL",
    "GROK_RUN_ROOT_CGROUP_TEST",
    "GROK_INSTALLER_INTERNAL_PROC_FD",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
)
print("|".join(os.environ.get(name, "unset") for name in names))
PY
""",
                encoding="ascii",
            )
            os.chmod(target, 0o755)
            installer.install()

            fake_bin = base / "fake-bin"
            fake_bin.mkdir()
            fake_bash = fake_bin / "bash"
            fake_bash.write_text("#!/bin/sh\nexit 92\n", encoding="ascii")
            os.chmod(fake_bash, 0o755)
            for name in ("python3", "flock", "chmod"):
                fake = fake_bin / name
                fake.write_text("#!/bin/sh\nexit 93\n", encoding="ascii")
                os.chmod(fake, 0o755)
            startup = base / "startup.sh"
            marker = base / "startup-ran"
            startup.write_text(
                f"#!/bin/sh\n/usr/bin/touch {marker}\n",
                encoding="ascii",
            )
            environment = dict(os.environ)
            environment.update(
                {
                    "PATH": str(fake_bin),
                    "GROK_TESTING": "0",
                    "GROK_TEST_ROOT_RELEASE_CONTROL": "/tmp/untrusted-control",
                    "GROK_TEST_CURL_BIN": "/fixture/fake-curl",
                    "GROK_TEST_IPHONE_STATE_DIR": "/fixture/iphone-state",
                    "GROK_TEST_SKIP_WARM_HANDOFF": "1",
                    "GROK_TEST_FAULT": "injected",
                    "GROK_TEST_CONTROL_DIR": "/tmp/untrusted-state",
                    "GROK_TEST_VPN_BROKER": "/bin/false",
                    "GROK_BOOTSTRAP_PUBLISHER_TEST_MODE": "1",
                    "GROK_BOOTSTRAP_PACKAGE_ACTIVATOR_TEST_MODE": "1",
                    "GROK_LAUNCHER_TEST_CLOSE_RANGE_SYSCALL": "999",
                    "GROK_RUN_ROOT_CGROUP_TEST": "1",
                    "GROK_INSTALLER_INTERNAL_PROC_FD": "99",
                    "BASH_ENV": str(startup),
                    "ENV": str(startup),
                    "SHELLOPTS": "xtrace",
                    "BASHOPTS": "sourcepath",
                }
            )
            result = subprocess.run(
                [str(layout.entrypoint)],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout,
                "|".join(
                    (
                        "/usr/sbin:/usr/bin:/sbin:/bin",
                        "1",
                        str(layout.root_control),
                        "/fixture/fake-curl",
                        "/fixture/iphone-state",
                        "1",
                        "unset",
                        "unset",
                        "unset",
                        "unset",
                        "unset",
                        "unset",
                        "unset",
                        "unset",
                        "unset",
                        "unset",
                        "unset",
                        "unset\n",
                    )
                ),
            )
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
