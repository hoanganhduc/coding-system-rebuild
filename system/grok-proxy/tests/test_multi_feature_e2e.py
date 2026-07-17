#!/usr/bin/env python3
"""Public feature-on regression through an installed release and real sockets."""

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install-release.py"
FAKE_GROK = ROOT / "tests/fixtures/fake-grok-load.py"
FAKE_CURL = ROOT / "tests/fixtures/fake-curl-trace.py"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from grok_ms.config import build_contract, classify  # noqa: E402
from grok_ms.grok_exec import grok_release_id  # noqa: E402
from test_release_installer import (  # noqa: E402
    fixed_qualification_smoke,
    release_installer,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _delegated_cgroup_available() -> bool:
    try:
        relative = next(
            line.split("::", 1)[1].strip()
            for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
            if line.startswith("0::")
        )
        parent = Path("/sys/fs/cgroup") / relative.lstrip("/")
        candidate = parent / f"grok-ms-e2e-check-{uuid.uuid4().hex}"
        candidate.mkdir(mode=0o700)
        candidate.rmdir()
        return True
    except (OSError, StopIteration, ValueError):
        return False


def _installer_base(
    prefix: Path,
    logical_home: Path,
    source: Path = ROOT,
) -> list[str]:
    return [
        "/usr/bin/python3",
        str(INSTALLER),
        "--source",
        str(source),
        "--prefix",
        str(prefix),
        "--home",
        str(logical_home),
        "--test-openvpn-binary",
        str(FAKE_CURL),
    ]


def _installed_release_installer(prefix: Path, logical_home: Path) -> object:
    layout = release_installer.Layout.defaults(
        ROOT,
        prefix=prefix,
        home=logical_home,
        test_openvpn_binary=FAKE_CURL,
    )
    runtime_files = release_installer._default_runtime_files(ROOT)
    return release_installer.ReleaseInstaller(
        layout,
        runtime_files=runtime_files,
        root_files=release_installer._default_root_files(runtime_files),
    )


def _canary_command(
    installer_base: list[str],
    argv: list[str],
) -> list[str]:
    command = [*installer_base[:2], "canary-exec", *installer_base[2:], "--apply"]
    command.extend(f"--canary-arg={argument}" for argument in argv)
    return command


def _json_objects(output: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


class _EchoServer:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.port = int(self.listener.getsockname()[1])
        self.accepted = 0
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _peer = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted += 1
            worker = threading.Thread(
                target=self._echo, args=(connection,), daemon=True
            )
            self._workers.append(worker)
            worker.start()

    @staticmethod
    def _echo(connection: socket.socket) -> None:
        with connection:
            while True:
                data = connection.recv(64 * 1024)
                if not data:
                    return
                connection.sendall(data)

    def close(self) -> None:
        self._stop.set()
        self.listener.close()
        self._thread.join(timeout=2)
        for worker in self._workers:
            worker.join(timeout=2)


class InstalledFeatureOnTests(unittest.TestCase):
    def setUp(self) -> None:
        if not _delegated_cgroup_available():
            self.skipTest("a writable delegated cgroup-v2 parent is required")

    def test_two_public_wrappers_share_one_generation_and_clean_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            prefix = base / "prefix"
            logical_home = Path("/home/grok-e2e")
            installer_base = _installer_base(prefix, logical_home)
            legacy = prefix / "var/lib/grok-vpngate"
            legacy.mkdir(parents=True, mode=0o700)
            # Model the production /var/lib trust boundary even on developer
            # hosts whose default umask creates group-writable prefix parents.
            legacy.parent.chmod(0o755)
            for name, mode, content in (
                ("list.csv", 0o644, b"csv\n"),
                ("parsed.tsv", 0o644, b"tsv\n"),
                ("vpngate.ovpn", 0o644, b"client\n"),
                ("up.sh", 0o755, b"#!/bin/sh\n"),
                ("openvpn.log", 0o600, b""),
            ):
                path = legacy / name
                path.write_bytes(content)
                path.chmod(mode)
            interrupted = subprocess.run(
                [
                    *installer_base[:2],
                    "install",
                    *installer_base[2:],
                    "--apply",
                    "--fault-at",
                    "after-canary-selection",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(interrupted.returncode, 2)
            self.assertTrue(legacy.exists())
            install = subprocess.run(
                [*installer_base[:2], "resume", *installer_base[2:], "--apply"],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(install.returncode, 0, install.stderr)
            self.assertFalse(legacy.exists())
            release_id = json.loads(install.stdout)["release_id"]
            installed_home = prefix / logical_home.relative_to("/")
            entrypoint = installed_home / ".local/bin/grok-remote"
            user_state = installed_home / ".local/state"
            root_control = prefix / "var/lib/grok-proxy/release-control"
            control = user_state / "grok-proxy/control"
            release_dir = (
                installed_home
                / ".local/lib/grok-proxy/releases"
                / release_id
            )
            installed_release = _installed_release_installer(prefix, logical_home)

            ports: list[int] = []
            while len(ports) < 3:
                candidate = _free_port()
                if candidate not in ports:
                    ports.append(candidate)
            public_port, private_a, private_b = ports
            environment = {
                **os.environ,
                "GROK_MULTI_SESSION": "1",
                "GROK_TESTING": "1",
                "GROK_TEST_ROOT_RELEASE_CONTROL": str(root_control),
                "GROK_TEST_CURL_BIN": str(FAKE_CURL),
                "GROK_TEST_SKIP_WARM_HANDOFF": "1",
                "GROK_BIN": str(FAKE_GROK),
                "GROK_HOME": str(base / "grok-home"),
                "HOME": str(installed_home),
                "XDG_STATE_HOME": str(user_state),
                "GROK_PROXY_PORT": str(public_port),
                "GROK_PRIVATE_PORTS": f"{private_a} {private_b}",
                "GROK_MAX_LEASES": "4",
                "GROK_MAX_CONTROL_CONNECTIONS": "6",
                "GROK_MAX_FRONTEND_STREAMS": "8",
                "GROK_VPN_STABILITY_CHECKS": "1",
                "GROK_STABILITY_INTERVAL_MS": "0",
                "GROK_CONNECT_TIMEOUT_MS": "3000",
                "GROK_PROBE_TIMEOUT_MS": "5000",
                "GROK_TRANSITION_TIMEOUT_MS": "15000",
                "GROK_STOP_TIMEOUT_MS": "5000",
                "GROK_WATCHDOG_INTERVAL_MS": "60000",
            }
            (base / "grok-home").mkdir(mode=0o700)
            echo = _EchoServer()
            echo.start()
            crash_canaries: list[subprocess.Popen[str]] = []
            canary_wrappers: list[subprocess.Popen[str]] = []
            wrappers: list[subprocess.Popen[str]] = []
            try:
                canary_arguments = [
                    "--direct",
                    "-m",
                    "grok-4.5",
                    "--fake-connect",
                    f"127.0.0.1:{echo.port}",
                    "--fake-payload",
                    "grok-e2e-canary",
                    "--fake-hold",
                    "8",
                ]
                grok_identity = grok_release_id(FAKE_GROK)
                contract = build_contract(
                    classify(canary_arguments),
                    "grok-4.5",
                    release_dir=release_dir,
                    grok_bin=FAKE_GROK,
                    env=environment,
                    grok_release_id=grok_identity,
                )
                contract_digest = contract.digest()

                release_canary = installed_release.begin_release_qualification(
                    release_id=release_id
                )
                self.assertTrue(release_canary.changed)
                with mock.patch.object(
                    installed_release,
                    "_run_qualification_verifier",
                    side_effect=lambda **kw: fixed_qualification_smoke(
                        installed_release, str(kw["step"])
                    ),
                ):
                    self.assertEqual(
                        installed_release.qualification_exec("load32").status,
                        "passed",
                    )
                    self.assertEqual(
                        installed_release.qualification_exec(
                            "fault-recovery"
                        ).status,
                        "passed",
                    )

                begun = subprocess.run(
                    [
                        *installer_base[:2],
                        "begin-rung-canary",
                        *installer_base[2:],
                        "--release-id",
                        release_id,
                        "--rung",
                        "direct",
                        "--route-profile",
                        "direct",
                        "--contract-sha256",
                        contract_digest,
                        "--grok-release-id",
                        grok_identity,
                        "--model-id",
                        "grok-4.5",
                        "--apply",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                    env=environment,
                )
                self.assertEqual(begun.returncode, 0, begun.stderr)
                begun_records = _json_objects(begun.stdout)
                self.assertTrue(begun_records, begun.stdout)
                canary_nonce = begun_records[-1].get("canary_nonce")
                self.assertIsInstance(canary_nonce, str)
                assert isinstance(canary_nonce, str)

                # Kill one installer parent while two canaries share the same
                # supervisor. The killed lane deliberately creates a
                # double-forked setsid descendant; its wrapper and whole lease
                # must die without disturbing the other lane.
                descendant_record = base / "canary-a-descendant.json"
                crash_arguments: list[list[str]] = []
                for index in range(2):
                    arguments = list(canary_arguments)
                    arguments[arguments.index("8")] = "30"
                    arguments[arguments.index("grok-e2e-canary")] = (
                        f"grok-e2e-crash-{index}"
                    )
                    if index == 0:
                        arguments.extend(
                            ["--fake-descendant-file", str(descendant_record)]
                        )
                    crash_arguments.append(arguments)
                    crash_canaries.append(
                        subprocess.Popen(
                            _canary_command(installer_base, arguments),
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=environment,
                        )
                    )

                crash_snapshot: dict[str, object] | None = None
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    status = subprocess.run(
                        _canary_command(installer_base, ["status"]),
                        text=True,
                        capture_output=True,
                        timeout=5,
                        env=environment,
                        check=False,
                    )
                    for candidate in _json_objects(status.stdout):
                        if candidate.get("live_leases") == 2:
                            crash_snapshot = candidate
                            break
                    if crash_snapshot is not None and descendant_record.exists():
                        break
                    if any(process.poll() is not None for process in crash_canaries):
                        self.fail(
                            "crash canary exited before shared READY: "
                            f"{[process.communicate() for process in crash_canaries]!r}"
                        )
                    time.sleep(0.05)
                self.assertIsNotNone(crash_snapshot)
                self.assertTrue(descendant_record.exists())
                assert crash_snapshot is not None
                crash_owner = crash_snapshot.get("owner_epoch")
                self.assertIsInstance(crash_owner, str)
                descendant_value = json.loads(
                    descendant_record.read_text(encoding="ascii")
                )
                descendant_pid = int(descendant_value["pid"])
                descendant_pidfd = os.pidfd_open(descendant_pid, 0)
                wrapper_pidfd = -1
                try:
                    wrapper_children = Path(
                        f"/proc/{crash_canaries[0].pid}/task/"
                        f"{crash_canaries[0].pid}/children"
                    ).read_text(encoding="ascii").split()
                    self.assertEqual(len(wrapper_children), 1)
                    wrapper_pidfd = os.pidfd_open(int(wrapper_children[0]), 0)

                    os.kill(crash_canaries[0].pid, signal.SIGKILL)
                    crash_canaries[0].wait(timeout=5)
                    self.assertEqual(crash_canaries[0].returncode, -signal.SIGKILL)
                    for descriptor in (wrapper_pidfd, descendant_pidfd):
                        readable, _, _ = select.select([descriptor], [], [], 10)
                        self.assertEqual(readable, [descriptor])

                    survivor_snapshot: dict[str, object] | None = None
                    last_survivor_status: tuple[int, str, str] | None = None
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        auth_fd = os.open(
                            installed_release.layout.canary_auth,
                            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                        )
                        try:
                            status_environment = {
                                **environment,
                                **installed_release._canary_environment(
                                    auth_fd,
                                    installed_release._read_rung_canary(),
                                ),
                            }
                            status = subprocess.run(
                                [str(entrypoint), "status"],
                                text=True,
                                capture_output=True,
                                timeout=5,
                                env=status_environment,
                                pass_fds=(auth_fd,),
                                check=False,
                            )
                        finally:
                            os.close(auth_fd)
                        last_survivor_status = (
                            status.returncode,
                            status.stdout,
                            status.stderr,
                        )
                        for candidate in _json_objects(status.stdout):
                            if candidate.get("live_leases") == 1:
                                survivor_snapshot = candidate
                                break
                        if survivor_snapshot is not None:
                            break
                        time.sleep(0.05)
                    self.assertIsNotNone(
                        survivor_snapshot,
                        "surviving canary did not remain attached: "
                        f"poll={crash_canaries[1].poll()!r}; "
                        f"status={last_survivor_status!r}",
                    )
                    assert survivor_snapshot is not None
                    self.assertEqual(survivor_snapshot.get("owner_epoch"), crash_owner)
                    self.assertEqual(survivor_snapshot.get("phase"), "READY")
                    self.assertIsNone(crash_canaries[1].poll())
                finally:
                    for descriptor in (wrapper_pidfd, descendant_pidfd):
                        if descriptor >= 0:
                            os.close(descriptor)

                os.kill(crash_canaries[1].pid, signal.SIGKILL)
                crash_canaries[1].wait(timeout=5)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if not (control / "supervisor.sock").exists() and not (
                        control / "recovery.fence"
                    ).exists():
                        break
                    time.sleep(0.05)
                self.assertFalse((control / "supervisor.sock").exists())
                self.assertFalse((control / "recovery.fence").exists())

                aborted = subprocess.run(
                    [*installer_base[:2], "abort", *installer_base[2:], "--apply"],
                    text=True,
                    capture_output=True,
                    timeout=30,
                    env=environment,
                    check=False,
                )
                self.assertEqual(aborted.returncode, 0, aborted.stderr)
                begun = subprocess.run(
                    [
                        *installer_base[:2],
                        "begin-rung-canary",
                        *installer_base[2:],
                        "--release-id",
                        release_id,
                        "--rung",
                        "direct",
                        "--route-profile",
                        "direct",
                        "--contract-sha256",
                        contract_digest,
                        "--grok-release-id",
                        grok_identity,
                        "--model-id",
                        "grok-4.5",
                        "--apply",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                    env=environment,
                )
                self.assertEqual(begun.returncode, 0, begun.stderr)

                for index in range(2):
                    arguments = list(canary_arguments)
                    arguments[arguments.index("grok-e2e-canary")] = (
                        f"grok-e2e-canary-{index}"
                    )
                    canary_wrappers.append(
                        subprocess.Popen(
                            _canary_command(installer_base, arguments),
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=environment,
                        )
                    )

                canary_snapshot: dict[str, object] | None = None
                last_canary_status: tuple[int, str, str] | None = None
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    status = subprocess.run(
                        _canary_command(installer_base, ["status"]),
                        text=True,
                        capture_output=True,
                        timeout=5,
                        env=environment,
                        check=False,
                    )
                    last_canary_status = (
                        status.returncode,
                        status.stdout,
                        status.stderr,
                    )
                    for candidate in _json_objects(status.stdout):
                        if candidate.get("live_leases") == 2:
                            canary_snapshot = candidate
                            break
                    if canary_snapshot is not None:
                        break
                    if all(process.poll() is not None for process in canary_wrappers):
                        early = [process.communicate() for process in canary_wrappers]
                        self.fail(
                            "authorized canary wrappers exited before READY: "
                            f"outputs={early!r}; status={last_canary_status!r}"
                        )
                    time.sleep(0.05)
                self.assertIsNotNone(
                    canary_snapshot,
                    f"last authorized status={last_canary_status!r}",
                )
                assert canary_snapshot is not None
                self.assertEqual(canary_snapshot["phase"], "READY")
                self.assertEqual(canary_snapshot["active_rung"], "direct")
                canary_resources = canary_snapshot["resources"]
                assert isinstance(canary_resources, dict)
                self.assertEqual(canary_resources["provider_processes"], 1)
                self.assertEqual(canary_resources["leases"], 2)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    canary_leaders = tuple(
                        (control / "leaders").glob("*.sock")
                    )
                    canary_children = tuple(
                        (control / "recovery/children").glob("*.json")
                    )
                    if len(canary_leaders) == 2 and len(canary_children) == 2:
                        break
                    time.sleep(0.05)
                self.assertEqual(len(canary_leaders), 2)
                self.assertEqual(len(canary_children), 2)

                canary_outputs = [
                    process.communicate(timeout=20) for process in canary_wrappers
                ]
                for process, (_stdout, stderr) in zip(
                    canary_wrappers, canary_outputs, strict=True
                ):
                    self.assertEqual(process.returncode, 0, stderr)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if not (control / "supervisor.sock").exists() and not (
                        control / "recovery.fence"
                    ).exists():
                        break
                    time.sleep(0.05)
                self.assertFalse((control / "supervisor.sock").exists())
                self.assertFalse((control / "recovery.fence").exists())
                canary_accepts = echo.accepted
                self.assertGreaterEqual(canary_accepts, 2)

                with mock.patch.object(
                    installed_release,
                    "_run_qualification_verifier",
                    side_effect=lambda **kw: fixed_qualification_smoke(
                        installed_release, str(kw["step"])
                    ),
                ):
                    self.assertEqual(
                        installed_release.qualification_exec("real-pair").status,
                        "passed",
                    )
                promoted = subprocess.run(
                    [
                        *installer_base[:2],
                        "promote-rung",
                        *installer_base[2:],
                        "--apply",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                    env=environment,
                )
                self.assertEqual(promoted.returncode, 0, promoted.stderr)
                selected = json.loads(
                    (root_control / "selected-release.json").read_text(
                        encoding="ascii"
                    )
                )
                self.assertEqual(
                    [record["rung"] for record in selected["qualified_rungs"]],
                    ["direct"],
                )

                for index in range(2):
                    wrappers.append(
                        subprocess.Popen(
                            [
                                str(entrypoint),
                                "--direct",
                                "-m",
                                "grok-4.5",
                                "--fake-connect",
                                f"127.0.0.1:{echo.port}",
                                "--fake-payload",
                                f"grok-e2e-{index}",
                                "--fake-hold",
                                "8",
                            ],
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=environment,
                        )
                    )

                snapshot: dict[str, object] | None = None
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    status = subprocess.run(
                        [str(entrypoint), "status"],
                        text=True,
                        capture_output=True,
                        timeout=5,
                        env=environment,
                        check=False,
                    )
                    if status.returncode == 0 and status.stdout.strip().startswith("{"):
                        candidate = json.loads(status.stdout)
                        if candidate.get("live_leases") == 2:
                            snapshot = candidate
                            break
                    time.sleep(0.05)
                self.assertIsNotNone(snapshot)
                assert snapshot is not None
                self.assertEqual(snapshot["release_id"], release_id)
                self.assertEqual(snapshot["phase"], "READY")
                self.assertEqual(snapshot["active_rung"], "direct")
                resources = snapshot["resources"]
                assert isinstance(resources, dict)
                self.assertEqual(resources["provider_processes"], 1)
                self.assertEqual(resources["leases"], 2)
                self.assertIsNotNone(resources["frontend"])

                leaders = control / "leaders"
                child_records = control / "recovery/children"
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    leader_entries = tuple(leaders.glob("*.sock")) if leaders.exists() else ()
                    child_entries = tuple(child_records.glob("*.json")) if child_records.exists() else ()
                    if len(leader_entries) == 2 and len(child_entries) == 2 and echo.accepted >= 2:
                        break
                    time.sleep(0.05)
                self.assertEqual(len(leader_entries), 2)
                self.assertEqual(len({entry.name for entry in leader_entries}), 2)
                self.assertEqual(len(child_entries), 2)
                self.assertGreaterEqual(echo.accepted, canary_accepts + 2)

                outputs = [process.communicate(timeout=20) for process in wrappers]
                for process, (stdout, stderr) in zip(wrappers, outputs, strict=True):
                    self.assertEqual(process.returncode, 0, stderr)
                    self.assertIn("FAKE_GROK_OK", stdout)
                reported_leaders = {
                    line.split("leader=", 1)[1].strip()
                    for stdout, _stderr in outputs
                    for line in stdout.splitlines()
                    if "leader=" in line
                }
                self.assertEqual(len(reported_leaders), 2)

                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if not (control / "supervisor.sock").exists() and not (
                        control / "recovery.fence"
                    ).exists():
                        break
                    time.sleep(0.05)
                self.assertFalse((control / "supervisor.sock").exists())
                self.assertFalse((control / "supervisor.ready").exists())
                self.assertFalse((control / "recovery.fence").exists())
                for relative in (
                    "p",
                    "leaders",
                    "qualify",
                    "recovery/providers",
                    "recovery/children",
                    "recovery/probes",
                    "recovery/provider-scopes",
                ):
                    path = control / relative
                    if path.exists():
                        self.assertEqual(tuple(path.iterdir()), (), relative)
                for port in ports:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                        probe.bind(("127.0.0.1", port))
            finally:
                echo.close()
                for process in crash_canaries:
                    if process.poll() is None:
                        process.terminate()
                for process in crash_canaries:
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                    for stream in (process.stdout, process.stderr):
                        if stream is not None:
                            stream.close()
                for process in canary_wrappers:
                    if process.poll() is None:
                        process.terminate()
                for process in canary_wrappers:
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                for process in wrappers:
                    if process.poll() is None:
                        process.terminate()
                for process in wrappers:
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                ready = control / "supervisor.ready"
                if ready.exists():
                    try:
                        record = json.loads(ready.read_text(encoding="ascii"))
                        pid = int(record["pid"])
                        expected = int(record["pid_start_ticks"])
                        actual = int(
                            Path(f"/proc/{pid}/stat")
                            .read_text()
                            .rsplit(") ", 1)[1]
                            .split()[19]
                        )
                        if actual == expected:
                            os.kill(pid, signal.SIGKILL)
                    except (KeyError, OSError, ValueError, json.JSONDecodeError):
                        pass
                if entrypoint.exists():
                    subprocess.run(
                        [str(entrypoint), "recover"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                        env=environment,
                        check=False,
                    )

    def test_upgrade_resume_migrates_only_with_passing_prior_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            for relative in release_installer._default_runtime_files(ROOT):
                source_path = ROOT / relative
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, target)

            prefix = base / "prefix"
            logical_home = Path("/home/grok-upgrade-e2e")
            installer_base = _installer_base(prefix, logical_home, source)
            first = subprocess.run(
                [*installer_base[:2], "install", *installer_base[2:], "--apply"],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            first_release = json.loads(first.stdout)["release_id"]

            legacy = prefix / "var/lib/grok-vpngate"
            legacy.mkdir(parents=True, mode=0o700)
            legacy.parent.chmod(0o755)
            for name, mode, content in (
                ("list.csv", 0o644, b"csv\n"),
                ("parsed.tsv", 0o644, b"tsv\n"),
                ("vpngate.ovpn", 0o644, b"client\n"),
                ("up.sh", 0o755, b"#!/bin/sh\n"),
                ("openvpn.log", 0o600, b""),
            ):
                path = legacy / name
                path.write_bytes(content)
                path.chmod(mode)
            same_release = subprocess.run(
                [*installer_base[:2], "install", *installer_base[2:], "--apply"],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(same_release.returncode, 2)
            self.assertTrue(legacy.exists())
            shutil.rmtree(legacy)

            changed = source / "grok_ms/__init__.py"
            changed.write_text(
                changed.read_text(encoding="utf-8") + "\n# upgrade-e2e\n",
                encoding="utf-8",
            )
            interrupted = subprocess.run(
                [
                    *installer_base[:2],
                    "install",
                    *installer_base[2:],
                    "--apply",
                    "--fault-at",
                    "after-canary-selection",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(interrupted.returncode, 2)

            legacy.mkdir(parents=True, mode=0o700)
            legacy.parent.chmod(0o755)
            for name, mode, content in (
                ("list.csv", 0o644, b"csv\n"),
                ("parsed.tsv", 0o644, b"tsv\n"),
                ("vpngate.ovpn", 0o644, b"client\n"),
                ("up.sh", 0o755, b"#!/bin/sh\n"),
                ("openvpn.log", 0o600, b""),
            ):
                path = legacy / name
                path.write_bytes(content)
                path.chmod(mode)

            resumed = subprocess.run(
                [*installer_base[:2], "resume", *installer_base[2:], "--apply"],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            second_release = json.loads(resumed.stdout)["release_id"]
            self.assertNotEqual(second_release, first_release)
            self.assertFalse(legacy.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
