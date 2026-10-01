#!/usr/bin/python3
"""Immutable Grok-shaped executable for installed qualification gates."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import sys
import time
from urllib.parse import urlsplit


MODEL = "grok-4.5"
_MAX_PAYLOAD_BYTES = 262_144
_MAX_BARRIER_SECONDS = 120.0


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise RuntimeError("SOCKS connection closed early")
        data.extend(chunk)
    return bytes(data)


def _process_start_ticks(pid: int) -> int:
    record = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = record[record.rfind(")") + 2 :].split()
    if len(fields) <= 19 or not fields[19].isdecimal():
        raise RuntimeError("cannot read the exact process start identity")
    return int(fields[19])


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="ascii"
    ).strip()
    if len(value) != 36:
        raise RuntimeError("cannot read the Linux boot identity")
    return value


def _publish_exclusive_json(path: Path, value: dict[str, object]) -> None:
    if not path.is_absolute():
        raise RuntimeError("fixture marker paths must be absolute")
    data = (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(path.parent, directory_flags)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    temporary = ""
    descriptor = -1
    temporary_present = False
    primary_error: BaseException | None = None
    primary_traceback = None
    cleanup_error: BaseException | None = None

    def remember_cleanup_error(error: BaseException) -> None:
        nonlocal cleanup_error
        if cleanup_error is None:
            cleanup_error = error
        else:
            cleanup_error.add_note(
                f"additional marker cleanup failure: {type(error).__name__}: {error}"
            )

    try:
        try:
            temporary = f".{path.name}.{secrets.token_hex(12)}.tmp"
            descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
            temporary_present = True
            os.fchmod(descriptor, 0o600)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short marker write")
                view = view[written:]
            os.fsync(descriptor)
            closing_descriptor = descriptor
            descriptor = -1
            os.close(closing_descriptor)
            os.link(
                temporary,
                path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            os.unlink(temporary, dir_fd=directory)
            temporary_present = False
            os.fsync(directory)
        except BaseException as error:
            primary_error = error
            primary_traceback = error.__traceback__
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as error:
                remember_cleanup_error(error)
        if temporary_present:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                temporary_present = False
            except BaseException as error:
                remember_cleanup_error(error)
            else:
                temporary_present = False
                try:
                    os.fsync(directory)
                except BaseException as error:
                    remember_cleanup_error(error)
        try:
            os.close(directory)
        except BaseException as error:
            remember_cleanup_error(error)

    if cleanup_error is not None:
        if primary_error is not None:
            raise cleanup_error from primary_error.with_traceback(primary_traceback)
        raise cleanup_error
    if primary_error is not None:
        raise primary_error.with_traceback(primary_traceback)


def _wait_for_release(path: Path, timeout: float) -> None:
    if not path.is_absolute():
        raise RuntimeError("fixture release path must be absolute")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            info = path.lstat()
        except FileNotFoundError:
            time.sleep(0.01)
            continue
        if path.is_symlink() or not path.is_file() or info.st_uid != os.getuid():
            raise RuntimeError("fixture release marker has an unsafe identity")
        return
    raise RuntimeError("fixture data-path barrier timed out")


def _socks_echo(
    target: str,
    payload: bytes,
    *,
    slow_read_ms: int = 0,
    ready_file: Path | None = None,
    release_file: Path | None = None,
    barrier_timeout: float = 30.0,
) -> None:
    proxy = os.environ.get("ALL_PROXY", "")
    parsed = urlsplit(proxy)
    if parsed.scheme != "socks5h" or parsed.hostname is None or parsed.port is None:
        raise RuntimeError("ALL_PROXY is not the committed socks5h endpoint")
    target_host, separator, target_port_text = target.rpartition(":")
    if not separator or not target_host or not target_port_text.isdecimal():
        raise RuntimeError("--fake-connect must be HOST:PORT")
    target_port = int(target_port_text)
    encoded_host = target_host.encode("ascii")
    if len(encoded_host) > 255 or not 1 <= target_port <= 65535:
        raise RuntimeError("invalid echo target")

    with socket.create_connection((parsed.hostname, parsed.port), timeout=10) as connection:
        connection.settimeout(10)
        connection.sendall(b"\x05\x01\x00")
        if _read_exact(connection, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS authentication negotiation failed")
        request = b"\x05\x01\x00\x03" + bytes((len(encoded_host),))
        request += encoded_host + struct.pack("!H", target_port)
        connection.sendall(request)
        header = _read_exact(connection, 4)
        if header[:2] != b"\x05\x00":
            raise RuntimeError(f"SOCKS connect failed with status {header[1]:#x}")
        address_type = header[3]
        if address_type == 1:
            _read_exact(connection, 4)
        elif address_type == 3:
            _read_exact(connection, _read_exact(connection, 1)[0])
        elif address_type == 4:
            _read_exact(connection, 16)
        else:
            raise RuntimeError("SOCKS reply used an unknown address type")
        _read_exact(connection, 2)
        connection.sendall(payload)
        if slow_read_ms:
            time.sleep(slow_read_ms / 1_000)
        if _read_exact(connection, len(payload)) != payload:
            raise RuntimeError("committed frontend changed the echo payload")

        # Keep every verified byte path concurrently open until the verifier
        # publishes one common release marker.  This makes active-stream and
        # bounded-buffer gauges evidence rather than a post-hoc connection
        # count.  Both marker writes are exclusive and durable.
        if ready_file is not None:
            if release_file is None:
                raise RuntimeError("fixture ready marker requires a release marker")
            _publish_exclusive_json(
                ready_file,
                {
                    "boot_id": _boot_id(),
                    "payload_bytes": len(payload),
                    "pid": os.getpid(),
                    "pid_start_ticks": _process_start_ticks(os.getpid()),
                },
            )
            _wait_for_release(release_file, barrier_timeout)


def _spawn_descendant(marker: Path) -> None:
    first = os.fork()
    if first != 0:
        os.waitpid(first, 0)
        return
    os.setsid()
    second = os.fork()
    if second != 0:
        os._exit(0)
    _publish_exclusive_json(
        marker,
        {
            "boot_id": _boot_id(),
            "pid": os.getpid(),
            "pid_start_ticks": _process_start_ticks(os.getpid()),
        },
    )
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    while True:
        time.sleep(60)


def _arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--leader-socket")
    parser.add_argument("--fake-hold", type=float, default=5.0)
    parser.add_argument("--fake-connect")
    parser.add_argument("--fake-payload", default="grok-ms-live-byte-path")
    parser.add_argument("--fake-payload-bytes", type=int)
    parser.add_argument("--fake-slow-read-ms", type=int, default=0)
    parser.add_argument("--fake-ready-file", type=Path)
    parser.add_argument("--fake-release-file", type=Path)
    parser.add_argument("--fake-barrier-timeout", type=float, default=30.0)
    parser.add_argument("--fake-descendant-file", type=Path)
    parser.add_argument("--fake-identity-file", type=Path)
    parsed, _unknown = parser.parse_known_args(argv)
    return parsed


def main() -> int:
    if "models" in sys.argv[1:]:
        print(f"  - {MODEL}")
        return 0
    if any(item in {"inspect", "--version", "version"} for item in sys.argv[1:]):
        print("fake-grok-load 1")
        return 0

    args = _arguments(sys.argv[1:])
    if not args.leader_socket:
        raise RuntimeError("missing --leader-socket")
    if args.fake_payload_bytes is not None and not 1 <= args.fake_payload_bytes <= _MAX_PAYLOAD_BYTES:
        raise RuntimeError(
            f"--fake-payload-bytes must be in [1, {_MAX_PAYLOAD_BYTES}]"
        )
    if not 0 <= args.fake_slow_read_ms <= 10_000:
        raise RuntimeError("--fake-slow-read-ms must be in [0, 10000]")
    if not 0.1 <= args.fake_barrier_timeout <= _MAX_BARRIER_SECONDS:
        raise RuntimeError(
            f"--fake-barrier-timeout must be in [0.1, {_MAX_BARRIER_SECONDS:g}]"
        )
    if (args.fake_ready_file is None) != (args.fake_release_file is None):
        raise RuntimeError("fixture data-path barrier requires ready and release paths")
    payload = (
        args.fake_payload.encode("utf-8")
        if args.fake_payload_bytes is None
        else bytes((index % 251 for index in range(args.fake_payload_bytes)))
    )
    if not payload or len(payload) > _MAX_PAYLOAD_BYTES:
        raise RuntimeError(f"fixture payload must be in [1, {_MAX_PAYLOAD_BYTES}] bytes")
    leader_path = Path(args.leader_socket)
    leader_path.parent.mkdir(parents=True, exist_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(leader_path))
        listener.listen(1)
        if args.fake_identity_file is not None:
            _publish_exclusive_json(
                args.fake_identity_file,
                {
                    "boot_id": _boot_id(),
                    "leader_path": str(leader_path),
                    "pid": os.getpid(),
                    "pid_start_ticks": _process_start_ticks(os.getpid()),
                },
            )
        if args.fake_connect:
            _socks_echo(
                args.fake_connect,
                payload,
                slow_read_ms=args.fake_slow_read_ms,
                ready_file=args.fake_ready_file,
                release_file=args.fake_release_file,
                barrier_timeout=args.fake_barrier_timeout,
            )
        if args.fake_descendant_file is not None:
            _spawn_descendant(args.fake_descendant_file)
        print(
            f"FAKE_GROK_OK pid={os.getpid()} leader={leader_path}",
            flush=True,
        )
        deadline = time.monotonic() + max(0.0, args.fake_hold)
        while time.monotonic() < deadline:
            time.sleep(min(0.1, deadline - time.monotonic()))
        return 0
    finally:
        listener.close()
        try:
            leader_path.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"fake-grok-load: {exc}", file=sys.stderr)
        raise SystemExit(2)
