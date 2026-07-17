#!/usr/bin/env python3
"""Exec one provider child with a Linux parent-death fail-closed barrier."""

from __future__ import annotations

import argparse
import ctypes
import os
from pathlib import Path
import signal


def clear_parent_death_signal() -> None:
    """Transfer lifetime ownership away from the launcher after durable ACK."""

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, 0, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _start_ticks(pid: int) -> int:
    record = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
    closing = record.rfind(")")
    fields = record[closing + 2 :].split() if closing >= 0 else []
    if len(fields) <= 19 or not fields[19].isdecimal():
        raise ValueError("invalid parent process identity")
    return int(fields[19])


def _boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent-pid", required=True, type=int)
    parser.add_argument("--parent-start-ticks", required=True, type=int)
    parser.add_argument("--parent-boot-id", required=True)
    parser.add_argument("--barrier-fd", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        return 2

    libc = ctypes.CDLL(None, use_errno=True)
    # PR_SET_PDEATHSIG.  SIGKILL survives exec and prevents a direct backend
    # from outliving the supervisor in the intent-before-graph crash window.
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        return 125
    try:
        if (
            os.getppid() != args.parent_pid
            or _boot_id() != args.parent_boot_id
            or _start_ticks(args.parent_pid) != args.parent_start_ticks
        ):
            return 125
    except (OSError, ValueError):
        return 125
    if args.barrier_fd is not None:
        try:
            released = os.read(args.barrier_fd, 1)
        except OSError:
            return 125
        finally:
            try:
                os.close(args.barrier_fd)
            except OSError:
                pass
        if released != b"\x01":
            return 125
    os.execv(command[0], command)
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
