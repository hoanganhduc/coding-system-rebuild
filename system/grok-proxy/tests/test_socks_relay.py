#!/usr/bin/env python3
"""Deterministic regressions for bounded, byte-preserving duplex relay I/O."""

from __future__ import annotations

import importlib.util
import os
import pwd
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("socks_netns", ROOT / "socks-netns.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

sys.path.insert(0, str(ROOT))
from grok_ms.contract import Endpoint
from grok_ms.providers import (
    ProviderProtocolError,
    _identity_for_pid,
    _listener_identity,
)


def close_all(*sockets: socket.socket) -> None:
    for item in sockets:
        try:
            item.close()
        except OSError:
            pass


def recv_until_eof(sock: socket.socket, timeout: float = 4.0) -> bytes:
    sock.settimeout(timeout)
    result = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return bytes(result)
        result.extend(chunk)


def test_backpressure() -> None:
    client_peer, client_proxy = socket.socketpair()
    upstream_proxy, upstream_peer = socket.socketpair()
    payload = bytes(range(256)) * 8192
    for item in (client_proxy, upstream_proxy):
        item.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)

    pump = threading.Thread(target=MODULE.pump, args=(client_proxy, upstream_proxy), daemon=True)
    sender = threading.Thread(
        target=lambda: (client_peer.sendall(payload), client_peer.shutdown(socket.SHUT_WR)),
        daemon=True,
    )
    pump.start()
    sender.start()
    # Force the relay's destination buffer to fill before the reader drains it.
    time.sleep(0.15)
    received = recv_until_eof(upstream_peer)
    # Complete the reverse half-close too.  A correct duplex relay must remain
    # alive after only the request side reaches EOF because a delayed response
    # may still arrive on the other direction.
    upstream_peer.shutdown(socket.SHUT_WR)
    sender.join(2)
    pump.join(2)
    close_all(client_peer, client_proxy, upstream_proxy, upstream_peer)
    assert not sender.is_alive(), "sender did not finish"
    assert not pump.is_alive(), "relay did not terminate after both half-closes"
    assert received == payload, f"relay truncated {len(payload)} bytes to {len(received)}"


def test_half_close() -> None:
    client_peer, client_proxy = socket.socketpair()
    upstream_proxy, upstream_peer = socket.socketpair()
    request = b"request-complete"
    response = b"delayed-response-after-client-fin"
    pump = threading.Thread(target=MODULE.pump, args=(client_proxy, upstream_proxy), daemon=True)
    pump.start()

    client_peer.sendall(request)
    client_peer.shutdown(socket.SHUT_WR)
    assert recv_until_eof(upstream_peer) == request
    upstream_peer.sendall(response)
    upstream_peer.shutdown(socket.SHUT_WR)
    assert recv_until_eof(client_peer) == response

    pump.join(2)
    close_all(client_peer, client_proxy, upstream_proxy, upstream_peer)
    assert not pump.is_alive(), "relay did not finish after duplex FIN"


def test_broker_owned_pid_descriptor_and_symlink_rejection() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        pidfile = root / "backend.pid"
        fd = os.open(pidfile, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        MODULE.write_pidfile(str(pidfile), fd)
        assert pidfile.read_text(encoding="ascii") == f"{os.getpid()}\n"
        try:
            os.fstat(fd)
        except OSError:
            pass
        else:
            raise AssertionError("inherited broker pid descriptor was not closed")

        target = root / "target.pid"
        target.write_text("do-not-overwrite\n", encoding="ascii")
        link = root / "linked.pid"
        link.symlink_to(target)
        try:
            MODULE.write_pidfile(str(link))
        except OSError:
            pass
        else:
            raise AssertionError("pidfile path followed a symbolic link")
        assert target.read_text(encoding="ascii") == "do-not-overwrite\n"


def test_same_uid_listener_is_attributed_after_dumpability_reset() -> None:
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            listener = MODULE.bind_listener("127.0.0.1", 0)
            port = listener.getsockname()[1]
            libc = MODULE.ctypes.CDLL(None, use_errno=True)
            if libc.prctl(MODULE.PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
                os._exit(2)
            os.write(write_fd, f"{port}\n".encode("ascii"))
            os.close(write_fd)
            MODULE.serve(listener, pwd.getpwuid(os.getuid()).pw_name, "")
        except BaseException:
            os._exit(3)
        os._exit(0)

    os.close(write_fd)
    try:
        raw = b""
        while not raw.endswith(b"\n"):
            chunk = os.read(read_fd, 64)
            if not chunk:
                break
            raw += chunk
        assert raw.endswith(b"\n"), "relay child did not publish its port"
        endpoint = Endpoint("127.0.0.1", int(raw))
        identity = _identity_for_pid(child)
        deadline = time.monotonic() + 5
        last_error = "listener did not become inspectable"
        while time.monotonic() < deadline:
            try:
                listener = _listener_identity(endpoint, (identity,))
                assert listener.owner == identity
                break
            except ProviderProtocolError as exc:
                last_error = str(exc)
                time.sleep(0.02)
        else:
            raise AssertionError(last_error)
    finally:
        os.close(read_fd)
        try:
            os.kill(child, 9)
        except ProcessLookupError:
            pass
        os.waitpid(child, 0)


def test_pid_descriptor_closes_before_inspection_and_failure_prevents_listen() -> None:
    class Listener:
        listened = False

        def listen(self, _backlog):
            self.listened = True

    with tempfile.TemporaryDirectory() as temporary:
        pidfile = Path(temporary) / "relay.pid"
        pid_fd = os.open(pidfile, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        listener = Listener()

        def fail_after_close(_username):
            try:
                os.fstat(pid_fd)
            except OSError:
                pass
            else:
                raise AssertionError("broker pid descriptor remained open")
            raise RuntimeError("injected prctl failure")

        with (
            mock.patch.object(MODULE, "drop_privileges"),
            mock.patch.object(
                MODULE,
                "enable_same_uid_fd_inspection",
                side_effect=fail_after_close,
            ),
        ):
            try:
                MODULE.serve(
                    listener,
                    pwd.getpwuid(os.getuid()).pw_name,
                    str(pidfile),
                    pid_fd,
                )
            except RuntimeError as exc:
                assert str(exc) == "injected prctl failure"
            else:
                raise AssertionError("dumpability failure did not fail closed")
        assert not listener.listened, "relay listened before inspection was enabled"


if __name__ == "__main__":
    test_backpressure()
    test_half_close()
    test_broker_owned_pid_descriptor_and_symlink_rejection()
    test_same_uid_listener_is_attributed_after_dumpability_reset()
    test_pid_descriptor_closes_before_inspection_and_failure_prevents_listen()
    print("PASS: SOCKS relay preserves bytes, backpressure, and half-closes")
