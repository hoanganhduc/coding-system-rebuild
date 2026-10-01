#!/usr/bin/env python3
"""Real-host and fail-closed tests for exact Grok lease process scopes."""

from __future__ import annotations

import ctypes
import ast
from dataclasses import replace
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37

from grok_ms.process_scope import (  # noqa: E402
    LinuxCgroupV2Scope,
    ScopeError,
    ScopeIdentity,
    ScopeResidueError,
)
import grok_ms.process_scope as process_scope_module  # noqa: E402
from grok_ms.runtime import (  # noqa: E402
    ProcessIdentity,
    current_process_identity,
    process_matches,
    read_boot_id,
    read_pid_start_ticks,
)


def identity(pid: int) -> ProcessIdentity:
    return ProcessIdentity(pid, read_pid_start_ticks(pid), read_boot_id())


def wait_reap_all(timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reaped = False
        try:
            while True:
                pid, _status = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
                reaped = True
        except ChildProcessError:
            return True
        if not reaped:
            time.sleep(0.01)
    return False


@unittest.skipUnless(
    hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
    "Linux pidfds are required",
)
class LinuxCgroupV2ScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        if libc.prctl(
            PR_GET_CHILD_SUBREAPER,
            ctypes.byref(previous),
            0,
            0,
            0,
        ) != 0:
            raise OSError(ctypes.get_errno(), "PR_GET_CHILD_SUBREAPER failed")
        cls._previous_child_subreaper = previous.value
        # Let the test runner reap a double-forked descendant after cgroup.kill.
        if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            if not wait_reap_all():
                raise AssertionError("child subreaper still owns live test residue")
        finally:
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(
                PR_SET_CHILD_SUBREAPER,
                cls._previous_child_subreaper,
                0,
                0,
                0,
            ) != 0:
                raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")

    def test_exact_scope_freeze_and_thaw_are_kernel_acknowledged(self) -> None:
        backend = LinuxCgroupV2Scope()
        handle = backend.create(backend.plan())
        child = os.fork()
        pidfd: int | None = None
        try:
            if child == 0:
                os.execl("/bin/sleep", "sleep", "60")
            direct = identity(child)
            pidfd = os.pidfd_open(child, 0)
            backend.attach(handle, direct)

            backend.freeze(handle, 2.0)
            self.assertEqual(backend._events(handle.descriptor).get("frozen"), "1")
            self.assertTrue(process_matches(direct))

            backend.thaw(handle, 2.0)
            self.assertEqual(backend._events(handle.descriptor).get("frozen"), "0")
            self.assertTrue(process_matches(direct))
        finally:
            if child > 0:
                try:
                    backend.reconcile(
                        handle.identity,
                        "ATTACHED",
                        direct,
                        pidfd,
                        3.0,
                        handle=handle,
                    )
                except (NameError, OSError, ScopeError):
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if pidfd is not None:
                os.close(pidfd)
            handle.close()
            wait_reap_all()

    def test_nested_cleanup_makes_progress_when_breadth_exceeds_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "parent"
            scope_path = parent / "grok-ms-111111111111111111111111"
            scope_path.mkdir(parents=True)
            for name in ("a", "b", "c", "d"):
                (scope_path / name).mkdir()
            with os.scandir(scope_path) as entries:
                selected = [entry.name for entry in entries if entry.is_dir()][:3]
            (scope_path / min(selected) / "x").mkdir()
            parent_info = parent.stat()
            scope_info = scope_path.stat()
            scope = ScopeIdentity(
                backend="cgroup-v2-v1",
                parent_path=str(parent),
                parent_device=parent_info.st_dev,
                parent_inode=parent_info.st_ino,
                scope_path=str(scope_path),
                scope_device=scope_info.st_dev,
                scope_inode=scope_info.st_ino,
            )
            descriptor = os.open(
                scope_path,
                getattr(os, "O_PATH", os.O_RDONLY)
                | os.O_DIRECTORY
                | os.O_CLOEXEC,
            )
            try:
                before = sum(
                    1 for item in scope_path.rglob("*") if item.is_dir()
                )
                backend = LinuxCgroupV2Scope()
                with mock.patch.object(
                    process_scope_module,
                    "_LEASE_CGROUP_CLEANUP_MAX_DESCENDANTS",
                    3,
                ):
                    with self.assertRaisesRegex(ScopeResidueError, "limit exceeded"):
                        backend._remove_nested(
                            descriptor,
                            scope,
                            time.monotonic() + 5.0,
                        )
                after = sum(
                    1 for item in scope_path.rglob("*") if item.is_dir()
                )
                self.assertLess(after, before)
            finally:
                os.close(descriptor)

    def test_frozen_scope_owns_exact_loopback_tcp_client_inode(self) -> None:
        backend = LinuxCgroupV2Scope()
        handle = backend.create(backend.plan())
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener_address = listener.getsockname()
        release_read, release_write = os.pipe2(os.O_CLOEXEC)
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        pidfd: int | None = None
        accepted: socket.socket | None = None
        direct: ProcessIdentity | None = None
        try:
            if child == 0:
                os.close(release_write)
                os.close(ready_read)
                listener.close()
                if os.read(release_read, 1) != b"1":
                    os._exit(125)
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect(listener_address)
                os.write(ready_write, b"1")
                while True:
                    time.sleep(60)

            os.close(release_read)
            release_read = -1
            os.close(ready_write)
            ready_write = -1
            direct = identity(child)
            pidfd = os.pidfd_open(child, 0)
            backend.attach(handle, direct)
            os.write(release_write, b"1")
            os.close(release_write)
            release_write = -1
            listener.settimeout(2)
            accepted, _address = listener.accept()
            readable, _, _ = select.select([ready_read], [], [], 2)
            self.assertTrue(readable)
            self.assertEqual(os.read(ready_read, 1), b"1")
            client_host, client_port = accepted.getpeername()
            frontend_host, frontend_port = accepted.getsockname()

            backend.freeze(handle, 2.0)
            deadline = time.monotonic_ns() + 2_000_000_000
            inode = backend.tcp_connection_inode(
                str(client_host),
                int(client_port),
                str(frontend_host),
                int(frontend_port),
                deadline,
            )
            self.assertIsNotNone(inode)
            self.assertIn(
                inode,
                backend.frozen_socket_inodes(handle, deadline),
            )
            self.assertTrue(
                backend.owns_tcp_connection(
                    handle,
                    str(client_host),
                    int(client_port),
                    str(frontend_host),
                    int(frontend_port),
                    deadline,
                )
            )
            self.assertFalse(
                backend.owns_tcp_connection(
                    handle,
                    str(frontend_host),
                    int(frontend_port),
                    str(client_host),
                    int(client_port),
                    deadline,
                )
            )
        finally:
            if direct is not None:
                try:
                    backend.reconcile(
                        handle.identity,
                        "ATTACHED",
                        direct,
                        pidfd,
                        3.0,
                        handle=handle,
                    )
                except (OSError, ScopeError):
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if accepted is not None:
                accepted.close()
            listener.close()
            for descriptor in (
                release_read,
                release_write,
                ready_read,
                ready_write,
                pidfd,
            ):
                if descriptor is not None and descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            handle.close()
            wait_reap_all()

    def test_tcp_inode_lookup_rejects_ambiguity_and_expired_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc_root = Path(temporary)
            (proc_root / "net").mkdir()
            local = "0100007F:7530"
            remote = "0100007F:0438"
            (proc_root / "net/tcp").write_text(
                "sl local_address rem_address st tx rx tr tm retr uid timeout inode\n"
                f"0: {local} {remote} 01 0 0 0 0 0 901\n"
                f"1: {local} {remote} 01 0 0 0 0 0 902\n",
                encoding="ascii",
            )
            backend = LinuxCgroupV2Scope(proc_root=proc_root)
            with self.assertRaisesRegex(ScopeError, "ambiguous"):
                backend.tcp_connection_inode(
                    "127.0.0.1",
                    30_000,
                    "127.0.0.1",
                    1_080,
                    time.monotonic_ns() + 1_000_000_000,
                )
            with self.assertRaisesRegex(ScopeError, "deadline"):
                backend.tcp_connection_inode(
                    "127.0.0.1",
                    30_000,
                    "127.0.0.1",
                    1_080,
                    time.monotonic_ns() - 1,
                )

    def test_reconcile_kills_and_removes_a_still_frozen_scope(self) -> None:
        backend = LinuxCgroupV2Scope()
        handle = backend.create(backend.plan())
        child = os.fork()
        pidfd: int | None = None
        direct: ProcessIdentity | None = None
        try:
            if child == 0:
                os.execl("/bin/sleep", "sleep", "60")
            direct = identity(child)
            pidfd = os.pidfd_open(child, 0)
            backend.attach(handle, direct)
            backend.freeze(handle, 2.0)
            backend.reconcile(
                handle.identity,
                "ATTACHED",
                direct,
                pidfd,
                3.0,
                handle=handle,
            )
            os.waitpid(child, 0)
            self.assertFalse(Path(handle.identity.scope_path).exists())
            self.assertFalse(process_matches(direct))
        finally:
            if direct is not None and process_matches(direct):
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if pidfd is not None:
                os.close(pidfd)
            handle.close()
            wait_reap_all()

    def test_reconcile_removes_empty_nested_cgroup_hierarchy(self) -> None:
        backend = LinuxCgroupV2Scope()
        handle = backend.create(backend.plan())
        scope_path = Path(handle.identity.scope_path)
        self.assertEqual(
            (scope_path / "cgroup.max.depth").read_text(encoding="ascii").strip(),
            "8",
        )
        self.assertEqual(
            (scope_path / "cgroup.max.descendants")
            .read_text(encoding="ascii")
            .strip(),
            "256",
        )
        first = scope_path / "nested-a"
        second = first / "nested-b"
        first.mkdir(mode=0o700)
        second.mkdir(mode=0o700)
        child = os.fork()
        pidfd: int | None = None
        direct: ProcessIdentity | None = None
        try:
            if child == 0:
                os.execl("/bin/sleep", "sleep", "60")
            direct = identity(child)
            pidfd = os.pidfd_open(child, 0)
            backend.attach(handle, direct)

            backend.reconcile(
                handle.identity,
                "ATTACHED",
                direct,
                pidfd,
                3.0,
                handle=handle,
            )

            self.assertFalse(Path(handle.identity.scope_path).exists())
        finally:
            for path in (second, first):
                try:
                    path.rmdir()
                except FileNotFoundError:
                    pass
            if direct is not None and Path(handle.identity.scope_path).exists():
                try:
                    backend.reconcile(
                        handle.identity,
                        "ATTACHED",
                        direct,
                        pidfd,
                        3.0,
                        handle=handle,
                    )
                except (OSError, ScopeError):
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if pidfd is not None:
                os.close(pidfd)
            handle.close()
            wait_reap_all()

    def test_release_current_force_kills_term_ignoring_setsid_descendant_early(
        self,
    ) -> None:
        report_read, report_write = os.pipe2(os.O_CLOEXEC)
        worker = os.fork()
        if worker == 0:
            os.close(report_read)
            backend = LinuxCgroupV2Scope()
            handle = None
            stubborn = 0
            outcome: tuple[object, ...]
            try:
                handle = backend.create(backend.plan())
                owner = current_process_identity()
                backend.attach(handle, owner)
                ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
                stubborn = os.fork()
                if stubborn == 0:
                    os.close(ready_read)
                    os.setsid()
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    os.write(ready_write, b"1")
                    os.close(ready_write)
                    while True:
                        signal.pause()
                os.close(ready_write)
                if os.read(ready_read, 1) != b"1":
                    raise RuntimeError("stubborn descendant readiness failed")
                os.close(ready_read)
                os.kill(stubborn, signal.SIGTERM)
                started = time.monotonic()
                backend.release_current(handle.identity, 2.0)
                elapsed = time.monotonic() - started
                os.waitpid(stubborn, 0)
                stubborn = 0
                outcome = (
                    "ok",
                    elapsed,
                    Path(handle.identity.scope_path).exists(),
                )
            except BaseException as exc:
                outcome = ("error", type(exc).__name__, str(exc)[:300])
            finally:
                if stubborn > 0:
                    try:
                        os.kill(stubborn, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(stubborn, 0)
                    except ChildProcessError:
                        pass
                if handle is not None:
                    handle.close()
                os.write(report_write, repr(outcome).encode("ascii") + b"\n")
                os.close(report_write)
                os._exit(0 if outcome[0] == "ok" else 1)

        os.close(report_write)
        data = b""
        deadline = time.monotonic() + 6
        while b"\n" not in data and time.monotonic() < deadline:
            readable, _, _ = select.select([report_read], [], [], 0.1)
            if readable:
                data += os.read(report_read, 4_096)
        os.close(report_read)
        if b"\n" not in data:
            try:
                os.kill(worker, signal.SIGKILL)
            except ProcessLookupError:
                pass
        _pid, status = os.waitpid(worker, 0)
        self.assertTrue(data, "release_current worker produced no result")
        outcome = ast.literal_eval(data.decode("ascii").strip())
        self.assertEqual(status, 0, outcome)
        self.assertEqual(outcome[0], "ok", outcome)
        self.assertLess(outcome[1], 1.5)
        self.assertFalse(outcome[2])

    def test_barriered_child_setsid_fork_exec_inherits_and_scope_kills_all(self) -> None:
        backend = LinuxCgroupV2Scope()
        planned = backend.plan()
        handle = backend.create(planned)
        barrier_r, barrier_w = os.pipe2(os.O_CLOEXEC)
        report_r, report_w = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        grandchild: int | None = None
        pidfd: int | None = None
        try:
            if child == 0:
                os.close(barrier_w)
                os.close(report_r)
                if os.read(barrier_r, 1) != b"1":
                    os._exit(125)
                os.close(barrier_r)
                before = (
                    os.getppid(),
                    os.getsid(0),
                    os.getpgrp(),
                    Path("/proc/self/cgroup").read_text(encoding="ascii").strip(),
                )
                os.setsid()
                spawned = os.fork()
                if spawned == 0:
                    os.close(report_w)
                    os.execl("/bin/sleep", "sleep", "60")
                after = Path(f"/proc/{spawned}/cgroup").read_text(
                    encoding="ascii"
                ).strip()
                payload = repr((before, spawned, after)).encode("ascii") + b"\n"
                os.write(report_w, payload)
                os.close(report_w)
                os.execl("/bin/sleep", "sleep", "60")

            os.close(barrier_r)
            os.close(report_w)
            direct = identity(child)
            self.assertEqual(
                int(Path(f"/proc/{child}/stat").read_text().split(") ", 1)[1].split()[1]),
                os.getpid(),
            )
            backend.attach(handle, direct)
            os.write(barrier_w, b"1")
            os.close(barrier_w)
            barrier_w = -1
            data = b""
            deadline = time.monotonic() + 3
            while b"\n" not in data and time.monotonic() < deadline:
                readable, _, _ = select.select([report_r], [], [], 0.2)
                if readable:
                    data += os.read(report_r, 4_096)
            before, grandchild, descendant_cgroup = ast.literal_eval(
                data.decode("ascii").strip()
            )
            expected = "0::/" + str(
                Path(handle.identity.scope_path).relative_to("/sys/fs/cgroup")
            )
            self.assertEqual(before[0], os.getpid())
            self.assertEqual(before[3], expected)
            self.assertEqual(descendant_cgroup, expected)
            self.assertNotEqual(before[1], os.getsid(grandchild))
            pidfd = os.pidfd_open(child)
            backend.reconcile(
                handle.identity,
                "ATTACHED",
                direct,
                pidfd,
                2.0,
                handle=handle,
            )
            wait_reap_all()
            self.assertFalse(Path(f"/proc/{child}").exists())
            self.assertFalse(Path(f"/proc/{grandchild}").exists())
            self.assertFalse(Path(handle.identity.scope_path).exists())
        finally:
            for pid in (child, grandchild):
                if pid:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            try:
                if Path(handle.identity.scope_path).exists():
                    backend.reconcile(
                        handle.identity,
                        "ATTACHED",
                        direct,
                        pidfd,
                        1.0,
                        handle=handle,
                    )
            except (ScopeError, UnboundLocalError):
                pass
            for descriptor in (barrier_r, barrier_w, report_r, report_w, pidfd):
                if descriptor is not None and descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            handle.close()
            wait_reap_all()

    def test_different_user_service_scope_can_kill_recorded_child_cgroup(self) -> None:
        backend = LinuxCgroupV2Scope()
        handle = backend.create(backend.plan())
        child = subprocess.Popen(["/bin/sleep", "60"])
        pidfd: int | None = None
        direct = identity(child.pid)
        try:
            backend.attach(handle, direct)
            pidfd = os.pidfd_open(child.pid)
            helper = (
                "import pathlib,sys; "
                "print(pathlib.Path('/proc/self/cgroup').read_text().strip(), flush=True); "
                "pathlib.Path(sys.argv[1], 'cgroup.kill').write_text('1\\n')"
            )
            unit = f"grok-scope-cross-test-{os.getpid()}.service"
            result = subprocess.run(
                [
                    "systemd-run",
                    "--user",
                    "--wait",
                    "--collect",
                    "--pipe",
                    "--service-type=exec",
                    "--unit",
                    unit,
                    sys.executable,
                    "-c",
                    helper,
                    handle.identity.scope_path,
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("/app.slice/", result.stdout)
            self.assertNotIn(Path(handle.identity.scope_path).name, result.stdout)
            child.wait(timeout=3)
            backend.reconcile(
                handle.identity,
                "ATTACHED",
                direct,
                pidfd,
                1.0,
                handle=handle,
            )
            self.assertFalse(Path(handle.identity.scope_path).exists())
        finally:
            if pidfd is not None:
                os.close(pidfd)
            if child.poll() is None:
                child.kill()
                child.wait()
            handle.close()

    def test_missing_prepared_scope_kills_blocked_direct_but_attached_mismatch_fences(self) -> None:
        backend = LinuxCgroupV2Scope()
        for phase, error in (("PREPARED", False), ("ATTACHED", True)):
            with self.subTest(phase=phase):
                planned = backend.plan()
                scope = (
                    planned
                    if phase == "PREPARED"
                    else replace(planned, scope_device=planned.parent_device, scope_inode=1)
                )
                child = subprocess.Popen(["/bin/sleep", "60"])
                direct = identity(child.pid)
                pidfd = os.pidfd_open(child.pid)
                try:
                    if error:
                        with self.assertRaisesRegex(
                            ScopeResidueError, "absent while its direct child was live"
                        ):
                            backend.reconcile(scope, phase, direct, pidfd, 1.0)
                    else:
                        backend.reconcile(scope, phase, direct, pidfd, 1.0)
                    child.wait(timeout=3)
                finally:
                    os.close(pidfd)
                    if child.poll() is None:
                        child.kill()
                        child.wait()

    def test_created_empty_scope_still_proves_unmoved_blocked_child_dead(self) -> None:
        backend = LinuxCgroupV2Scope()
        handle = backend.create(backend.plan())
        child = subprocess.Popen(["/bin/sleep", "60"])
        direct = identity(child.pid)
        pidfd = os.pidfd_open(child.pid)
        try:
            backend.reconcile(
                handle.identity,
                "SCOPE_CREATED",
                direct,
                pidfd,
                1.0,
                handle=handle,
            )
            child.wait(timeout=2)
            self.assertFalse(Path(handle.identity.scope_path).exists())
        finally:
            os.close(pidfd)
            if child.poll() is None:
                child.kill()
                child.wait()
            handle.close()

    def test_wrong_inode_and_missing_cgroup2_never_fall_back(self) -> None:
        backend = LinuxCgroupV2Scope()
        handle = backend.create(backend.plan())
        wrong = replace(handle.identity, scope_inode=handle.identity.scope_inode + 1)
        dead = subprocess.Popen(["/bin/sleep", "60"])
        direct = identity(dead.pid)
        dead.terminate()
        dead.wait(timeout=2)
        try:
            with self.assertRaisesRegex(ScopeError, "inode identity changed"):
                backend.reconcile(wrong, "ATTACHED", direct, None, 1.0)
            backend.reconcile(handle.identity, "ATTACHED", direct, None, 1.0, handle=handle)
        finally:
            handle.close()

        with tempfile.TemporaryDirectory() as temporary:
            unavailable = LinuxCgroupV2Scope(mount_root=Path(temporary))
            with self.assertRaisesRegex(ScopeError, "not the writable cgroup-v2 mount"):
                unavailable.plan()

    def test_rmdir_rechecks_name_against_held_inode_and_recovery_rejects_foreign_parent(self) -> None:
        backend = LinuxCgroupV2Scope()
        handle = backend.create(backend.plan())
        original = Path(handle.identity.scope_path)
        try:
            # cgroupfs permits removing an empty cgroup while an O_PATH handle
            # remains open.  Recreate the same random name to model recovery's
            # path-reuse race while retaining the exact old inode in `handle`.
            original.rmdir()
            original.mkdir()
            with self.assertRaisesRegex(
                ScopeResidueError, "no longer identifies the held exact scope"
            ):
                backend._remove(handle.identity)
        finally:
            try:
                original.rmdir()
            except FileNotFoundError:
                pass
            handle.close()

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "parent"
            parent.mkdir()
            scope_path = parent / "grok-ms-111111111111111111111111"
            scope_path.mkdir()
            parent_info = parent.stat()
            scope_info = scope_path.stat()
            forged = ScopeIdentity(
                backend="cgroup-v2-v1",
                parent_path=str(parent),
                parent_device=parent_info.st_dev,
                parent_inode=parent_info.st_ino,
                scope_path=str(scope_path),
                scope_device=scope_info.st_dev,
                scope_inode=scope_info.st_ino,
            )
            dead = subprocess.Popen(["/bin/sleep", "60"])
            dead_identity = identity(dead.pid)
            dead.terminate()
            dead.wait(timeout=2)
            with self.assertRaisesRegex(ScopeError, "outside the cgroup-v2 mount"):
                backend.reconcile(forged, "ATTACHED", dead_identity, None, 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
