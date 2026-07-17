#!/usr/bin/env python3
"""Run one test command without orphaning descendants to a non-reaping PID 1."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


PR_SET_CHILD_SUBREAPER = 36
CHILDREN = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")


def _adopted_children() -> tuple[int, ...]:
    try:
        raw = CHILDREN.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return ()
    if not raw:
        return ()
    values = tuple(int(item) for item in raw.split())
    if any(item < 1 for item in values) or len(values) != len(set(values)):
        raise RuntimeError("subreaper child inventory is invalid")
    return values


def _reap_exited() -> None:
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def _reap_adopted_while_running(
    command_pid: int,
    stop: threading.Event,
    errors: list[BaseException],
) -> None:
    """Continuously reap exited adoptees without consuming the command child."""

    try:
        while not stop.is_set():
            for pid in _adopted_children():
                if pid == command_pid:
                    continue
                try:
                    os.waitpid(pid, os.WNOHANG)
                except (ChildProcessError, ProcessLookupError):
                    pass
            stop.wait(0.01)
    except BaseException as exc:
        errors.append(exc)
        stop.set()


def _drain_adopted() -> bool:
    """Return whether live residue had to be killed."""

    killed_residue = False
    grace_deadline = time.monotonic() + 2
    while time.monotonic() < grace_deadline:
        _reap_exited()
        if not _adopted_children():
            return killed_residue
        time.sleep(0.02)

    killed_residue = True
    for pid in _adopted_children():
        try:
            pidfd = os.pidfd_open(pid, 0)
        except ProcessLookupError:
            continue
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            os.close(pidfd)
    kill_deadline = time.monotonic() + 2
    while time.monotonic() < kill_deadline:
        _reap_exited()
        if not _adopted_children():
            return killed_residue
        time.sleep(0.02)
    raise RuntimeError("subreaper could not drain adopted test descendants")


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("usage: subreaper_run.py COMMAND [ARG ...]")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    process = subprocess.Popen(sys.argv[1:], start_new_session=True)
    stop_reaper = threading.Event()
    reaper_errors: list[BaseException] = []
    reaper = threading.Thread(
        target=_reap_adopted_while_running,
        args=(process.pid, stop_reaper, reaper_errors),
        name="test-adoptee-reaper",
        daemon=True,
    )
    reaper.start()
    try:
        returncode = process.wait()
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        stop_reaper.set()
        reaper.join(timeout=1)
        _drain_adopted()
        raise
    stop_reaper.set()
    reaper.join(timeout=1)
    if reaper.is_alive():
        raise RuntimeError("subreaper background reaper did not stop")
    if reaper_errors:
        raise RuntimeError("subreaper background reaper failed") from reaper_errors[0]
    killed_residue = _drain_adopted()
    if killed_residue:
        print(
            "subreaper_run: killed live descendant residue after tests",
            file=sys.stderr,
        )
        return 1
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
