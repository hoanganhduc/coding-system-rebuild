#!/usr/bin/env python3
"""Deterministic loopback tests for the committed-generation frontend."""

from __future__ import annotations

from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from typing import Callable
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from grok_ms.frontend import (
    CommittedFrontend,
    CommittedGeneration,
    GenerationRevoked,
    _FrontendStream,
    _Socks5Transcript,
)


SOCKS_GREETING = b"\x05\x01\x00"
SOCKS_METHOD = b"\x05\x00"
SOCKS_REQUEST = b"\x05\x01\x00\x03\x0bexample.com\x01\xbb"
SOCKS_REPLY = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x04\x38"


def wait_until(predicate: Callable[[], bool], timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition did not become true before its deadline")


def recv_to_eof(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = sock.recv(65_536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def recv_exactly(sock: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise AssertionError("socket closed before the expected response arrived")
        result.extend(chunk)
    return bytes(result)


class LoopbackBackend:
    """Small bounded test backend whose handler runs once per connection."""

    def __init__(self, handler: Callable[[socket.socket], None]) -> None:
        self.handler = handler
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.address = self.listener.getsockname()
        self.stop_event = threading.Event()
        self.accept_thread = threading.Thread(target=self._accept, daemon=True)
        self.lock = threading.Lock()
        self.connections: list[socket.socket] = []
        self.workers: list[threading.Thread] = []
        self.errors: list[BaseException] = []
        self.accepted = 0
        self.received = bytearray()

    def __enter__(self) -> LoopbackBackend:
        self.accept_thread.start()
        return self

    def __exit__(self, _kind, _value, _traceback) -> None:
        self.stop()

    def _accept(self) -> None:
        while not self.stop_event.is_set():
            try:
                connection, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            connection.settimeout(10)
            with self.lock:
                self.accepted += 1
                self.connections.append(connection)
            worker = threading.Thread(
                target=self._handle, args=(connection,), daemon=True
            )
            with self.lock:
                self.workers.append(worker)
            worker.start()

    def _handle(self, connection: socket.socket) -> None:
        try:
            self.handler(connection)
        except (ConnectionError, OSError) as exc:
            if not self.stop_event.is_set():
                with self.lock:
                    self.errors.append(exc)
        except BaseException as exc:
            with self.lock:
                self.errors.append(exc)
        finally:
            try:
                connection.close()
            except OSError:
                pass

    def record(self, data: bytes) -> None:
        with self.lock:
            self.received.extend(data)

    def received_bytes(self) -> bytes:
        with self.lock:
            return bytes(self.received)

    def connection_count(self) -> int:
        with self.lock:
            return self.accepted

    def assert_clean(self) -> None:
        with self.lock:
            if self.errors:
                raise AssertionError(f"backend worker errors: {self.errors!r}")

    def stop(self) -> None:
        self.stop_event.set()
        try:
            self.listener.close()
        except OSError:
            pass
        with self.lock:
            connections = tuple(self.connections)
            workers = tuple(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.accept_thread.join(1)
        for worker in workers:
            worker.join(1)


def generation(number: int, backend: LoopbackBackend, label: str) -> CommittedGeneration:
    return CommittedGeneration(
        generation=number,
        backend_id=f"backend-{label}",
        backend_host=str(backend.address[0]),
        backend_port=int(backend.address[1]),
        contract_digest=(f"{number:x}" * 64)[:64],
    )


def connect(frontend: CommittedFrontend) -> socket.socket:
    client = socket.create_connection(frontend.address, timeout=3)
    client.settimeout(10)
    return client


class ThrottledSocket:
    """Selector-compatible socket seam with deterministic partial I/O/EAGAIN."""

    def __init__(self, sock: socket.socket, *, max_io: int) -> None:
        self.sock = sock
        self.max_io = max_io
        self.send_calls = 0
        self.recv_calls = 0
        self.short_writes = 0
        self.write_eagain = 0
        self.read_eagain = 0

    def fileno(self) -> int:
        return self.sock.fileno()

    def set_inheritable(self, inheritable: bool) -> None:
        self.sock.set_inheritable(inheritable)

    def setblocking(self, blocking: bool) -> None:
        self.sock.setblocking(blocking)

    def setsockopt(self, *args) -> None:
        self.sock.setsockopt(*args)

    def shutdown(self, how: int) -> None:
        self.sock.shutdown(how)

    def close(self) -> None:
        self.sock.close()

    def recv(self, length: int) -> bytes:
        self.recv_calls += 1
        if self.recv_calls % 5 == 1:
            self.read_eagain += 1
            raise BlockingIOError()
        return self.sock.recv(min(length, self.max_io))

    def send(self, data) -> int:
        self.send_calls += 1
        if self.send_calls % 4 == 1:
            self.write_eagain += 1
            raise BlockingIOError()
        limited = memoryview(data)[: self.max_io]
        sent = self.sock.send(limited)
        if sent < len(data):
            self.short_writes += 1
        return sent


class CommittedFrontendTests(unittest.TestCase):
    def test_revocation_before_backend_ownership_closes_new_socket(self) -> None:
        frontend = CommittedFrontend("127.0.0.1", 0)
        client, peer = socket.socketpair()
        record = CommittedGeneration(
            generation=1,
            backend_id="revoked-before-attach",
            backend_host="127.0.0.1",
            backend_port=1,
            contract_digest="a" * 64,
        )
        stream = _FrontendStream(client, record)
        stream.revoke()
        upstream = mock.Mock()
        try:
            with mock.patch("grok_ms.frontend.socket.socket", return_value=upstream):
                with self.assertRaises(GenerationRevoked):
                    frontend._connect_backend(stream)
            upstream.close.assert_called_once_with()
        finally:
            stream.close()
            peer.close()

    def test_socks5_transcript_tracks_fragmented_control_and_application_bytes(self) -> None:
        transcript = _Socks5Transcript()

        for byte in SOCKS_GREETING:
            transcript.observe(from_client=True, data=bytes((byte,)))
        self.assertEqual(transcript.state, "server-method")
        for byte in SOCKS_METHOD:
            transcript.observe(from_client=False, data=bytes((byte,)))
        self.assertEqual(transcript.state, "client-request")
        for byte in SOCKS_REQUEST:
            transcript.observe(from_client=True, data=bytes((byte,)))
        self.assertEqual(transcript.state, "server-reply")
        for byte in SOCKS_REPLY:
            transcript.observe(from_client=False, data=bytes((byte,)))
        self.assertEqual(transcript.state, "complete")

        client_payload = b"fragmented-client-application"
        server_payload = b"fragmented-server-application"
        transcript.observe(from_client=True, data=client_payload[:7])
        transcript.observe(from_client=True, data=client_payload[7:])
        transcript.observe(from_client=False, data=server_payload[:11])
        transcript.observe(from_client=False, data=server_payload[11:])

        self.assertEqual(
            transcript.client_to_backend_bytes,
            len(SOCKS_GREETING) + len(SOCKS_REQUEST) + len(client_payload),
        )
        self.assertEqual(
            transcript.backend_to_client_bytes,
            len(SOCKS_METHOD) + len(SOCKS_REPLY) + len(server_payload),
        )
        self.assertEqual(
            transcript.application_client_to_backend_bytes, len(client_payload)
        )
        self.assertEqual(
            transcript.application_backend_to_client_bytes, len(server_payload)
        )

    def test_socks5_response_prefix_separates_coalesced_reply_from_tunnel_data(self) -> None:
        transcript = _Socks5Transcript()
        transcript.observe(from_client=True, data=SOCKS_GREETING)
        transcript.observe(from_client=False, data=SOCKS_METHOD)
        transcript.observe(from_client=True, data=SOCKS_REQUEST)

        response = b"coalesced-tunnel-response"
        first_fragment = bytearray(SOCKS_REPLY[:1])
        self.assertEqual(transcript.server_control_write_limit(first_fragment), 1)
        transcript.observe(from_client=False, data=bytes(first_fragment))

        coalesced = bytearray(SOCKS_REPLY[1:] + response)
        control_length = transcript.server_control_write_limit(coalesced)
        self.assertEqual(control_length, len(SOCKS_REPLY) - 1)
        transcript.observe(from_client=False, data=bytes(coalesced[:control_length]))
        del coalesced[:control_length]

        self.assertEqual(transcript.state, "complete")
        self.assertEqual(
            transcript.backend_to_client_bytes,
            len(SOCKS_METHOD) + len(SOCKS_REPLY),
        )
        self.assertEqual(transcript.application_backend_to_client_bytes, 0)
        self.assertEqual(transcript.server_control_write_limit(coalesced), 0)

        transcript.observe(from_client=False, data=bytes(coalesced))
        self.assertEqual(
            transcript.application_backend_to_client_bytes, len(response)
        )

    def test_qualification_hold_passes_socks_control_and_releases_tunnel_response(self) -> None:
        application_request = b"client-application-request"
        application_response = b"backend-application-response"
        response_sent = threading.Event()

        def socks_backend(connection: socket.socket) -> None:
            self.assertEqual(
                recv_exactly(connection, len(SOCKS_GREETING)), SOCKS_GREETING
            )
            connection.sendall(SOCKS_METHOD)
            self.assertEqual(
                recv_exactly(connection, len(SOCKS_REQUEST)), SOCKS_REQUEST
            )
            connection.sendall(SOCKS_REPLY)
            self.assertEqual(
                recv_exactly(connection, len(application_request)),
                application_request,
            )
            connection.sendall(application_response)
            response_sent.set()
            connection.shutdown(socket.SHUT_WR)

        with LoopbackBackend(socks_backend) as backend:
            with CommittedFrontend("127.0.0.1", 0) as frontend:
                frontend.commit_generation(generation(1, backend, "qualification-hold"))
                armed = frontend.qualification_arm()
                self.assertEqual(armed.generation, 1)
                client = connect(frontend)
                try:
                    client.sendall(SOCKS_GREETING[:1])
                    client.sendall(SOCKS_GREETING[1:])
                    self.assertEqual(recv_exactly(client, len(SOCKS_METHOD)), SOCKS_METHOD)
                    for fragment in (
                        SOCKS_REQUEST[:4],
                        SOCKS_REQUEST[4:9],
                        SOCKS_REQUEST[9:],
                    ):
                        client.sendall(fragment)
                    self.assertEqual(recv_exactly(client, len(SOCKS_REPLY)), SOCKS_REPLY)
                    client.sendall(application_request)
                    self.assertTrue(response_sent.wait(3))

                    def held_receipt_ready() -> bool:
                        streams = frontend.qualification_streams()
                        return (
                            len(streams) == 1
                            and streams[0].socks_state == "complete"
                            and streams[0].application_client_to_backend_bytes
                            == len(application_request)
                            and streams[0].application_backend_to_client_bytes == 0
                            and frontend.gauges().buffered_bytes
                            >= len(application_response)
                        )

                    wait_until(held_receipt_ready)
                    client.settimeout(0.15)
                    with self.assertRaises(socket.timeout):
                        client.recv(1)

                    state = frontend.qualification_state()
                    self.assertTrue(state["response_hold"])
                    self.assertEqual(len(state["streams"]), 1)
                    frontend.qualification_disarm()
                    client.settimeout(3)
                    self.assertEqual(
                        recv_exactly(client, len(application_response)),
                        application_response,
                    )
                    self.assertEqual(recv_to_eof(client), b"")
                finally:
                    client.close()
                wait_until(lambda: frontend.gauges().active_streams == 0)
                self.assertFalse(frontend.qualification_state()["response_hold"])
        backend.assert_clean()

    def test_qualification_revoke_returns_exact_held_transcript(self) -> None:
        application_request = b"request-before-fault"
        application_response = b"response-must-not-cross-fault"
        response_sent = threading.Event()

        def socks_backend(connection: socket.socket) -> None:
            self.assertEqual(
                recv_exactly(connection, len(SOCKS_GREETING)), SOCKS_GREETING
            )
            connection.sendall(SOCKS_METHOD)
            self.assertEqual(
                recv_exactly(connection, len(SOCKS_REQUEST)), SOCKS_REQUEST
            )
            connection.sendall(SOCKS_REPLY)
            self.assertEqual(
                recv_exactly(connection, len(application_request)),
                application_request,
            )
            connection.sendall(application_response)
            response_sent.set()
            connection.recv(1)

        with LoopbackBackend(socks_backend) as backend:
            with CommittedFrontend("127.0.0.1", 0) as frontend:
                frontend.commit_generation(generation(1, backend, "qualification-revoke"))
                frontend.qualification_arm()
                client = connect(frontend)
                try:
                    client.sendall(SOCKS_GREETING)
                    self.assertEqual(recv_exactly(client, len(SOCKS_METHOD)), SOCKS_METHOD)
                    client.sendall(SOCKS_REQUEST)
                    self.assertEqual(recv_exactly(client, len(SOCKS_REPLY)), SOCKS_REPLY)
                    client.sendall(application_request)
                    self.assertTrue(response_sent.wait(3))

                    wait_until(
                        lambda: len(frontend.qualification_streams()) == 1
                        and frontend.qualification_streams()[0].socks_state
                        == "complete"
                        and frontend.qualification_streams()[0].application_client_to_backend_bytes
                        == len(application_request)
                        and frontend.gauges().buffered_bytes
                        >= len(application_response)
                    )
                    stream_id = frontend.qualification_streams()[0].stream_id
                    final = frontend.qualification_revoke({stream_id}, timeout=3)
                    self.assertEqual(len(final), 1)
                    self.assertEqual(final[0].stream_id, stream_id)
                    self.assertEqual(final[0].generation, 1)
                    self.assertEqual(final[0].socks_state, "complete")
                    self.assertEqual(
                        final[0].application_client_to_backend_bytes,
                        len(application_request),
                    )
                    self.assertEqual(final[0].application_backend_to_client_bytes, 0)
                    self.assertEqual(frontend.gauges().active_streams, 0)
                    self.assertFalse(frontend.gauges().accepting)
                    self.assertIsNone(frontend.gauges().committed_generation)
                finally:
                    client.close()
                    frontend.qualification_disarm()
        backend.assert_clean()

    def test_qualification_quiesce_rejects_closed_gate_backlog_before_reopen(self) -> None:
        def hold(connection: socket.socket) -> None:
            while connection.recv(4_096):
                pass

        with LoopbackBackend(hold) as backend:
            with CommittedFrontend("127.0.0.1", 0, backlog=16) as frontend:
                frontend.commit_generation(generation(1, backend, "qualification-quiesce"))
                frontend.qualification_arm()
                original = connect(frontend)
                wait_until(lambda: frontend.gauges().active_streams == 1)

                result: dict[str, int] = {}
                errors: list[BaseException] = []

                def quiesce() -> None:
                    try:
                        result.update(frontend.qualification_quiesce(1, timeout=3))
                    except BaseException as exc:
                        errors.append(exc)

                worker = threading.Thread(target=quiesce)
                worker.start()
                wait_until(lambda: not frontend.gauges().accepting)
                queued = [connect(frontend) for _ in range(6)]
                worker.join(5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                self.assertGreaterEqual(frontend.gauges().rejected_uncommitted, 6)
                for queued_client in queued:
                    self.assertEqual(recv_to_eof(queued_client), b"")
                    queued_client.close()
                original.close()

                self.assertEqual(result["generation"], 1)
                self.assertEqual(result["quiesce_epoch"], 1)
                self.assertEqual(result["accept_cursor"], 1)
                state = frontend.qualification_state()
                self.assertTrue(state["response_hold"])
                self.assertEqual(state["streams"], [])
                self.assertEqual(state["quiesce_epoch"], 1)
                self.assertFalse(frontend.gauges().accepting)
                self.assertEqual(frontend.gauges().committed_generation, 1)

                accepted_while_closed = threading.Event()
                release_classification = threading.Event()

                class DelayedListener:
                    def __init__(self, listener: socket.socket) -> None:
                        self.listener = listener

                    def accept(self):
                        accepted = self.listener.accept()
                        accepted_while_closed.set()
                        release_classification.wait(3)
                        return accepted

                    def close(self) -> None:
                        self.listener.close()

                with frontend._state_lock:
                    real_listener = frontend._listener
                    self.assertIsNotNone(real_listener)
                    frontend._listener = DelayedListener(real_listener)  # type: ignore[assignment]
                time.sleep(0.25)
                delayed = connect(frontend)
                self.assertTrue(accepted_while_closed.wait(3))
                reopen_errors: list[BaseException] = []

                def reopen() -> None:
                    try:
                        frontend.qualification_reopen(1, timeout=3)
                    except BaseException as exc:
                        reopen_errors.append(exc)

                reopen_worker = threading.Thread(target=reopen)
                reopen_worker.start()
                wait_until(lambda: reopen_worker.is_alive())
                self.assertFalse(frontend.gauges().accepting)
                release_classification.set()
                reopen_worker.join(5)
                self.assertFalse(reopen_worker.is_alive())
                self.assertEqual(reopen_errors, [])
                self.assertEqual(recv_to_eof(delayed), b"")
                delayed.close()
                self.assertEqual(frontend.gauges().active_streams, 0)

                self.assertTrue(frontend.gauges().accepting)
                after = connect(frontend)
                wait_until(lambda: len(frontend.qualification_streams()) == 1)
                self.assertGreater(
                    frontend.qualification_streams()[0].stream_id,
                    result["accept_cursor"],
                )
                stream_id = frontend.qualification_streams()[0].stream_id
                frontend.qualification_revoke({stream_id}, timeout=3)
                after.close()
                frontend.qualification_disarm()
        backend.assert_clean()

    def test_qualification_reopen_requires_idle_ack_from_exact_epoch(self) -> None:
        def hold(connection: socket.socket) -> None:
            while connection.recv(4_096):
                pass

        with LoopbackBackend(hold) as backend:
            with CommittedFrontend("127.0.0.1", 0, backlog=16) as frontend:
                frontend.commit_generation(generation(1, backend, "idle-epoch"))
                frontend.qualification_arm()
                frontend.qualification_quiesce(1, timeout=3)

                timeout_caught = threading.Event()
                release_timeout = threading.Event()
                next_accept_entered = threading.Event()
                release_next_accept = threading.Event()

                class CrossingTimeoutListener:
                    def __init__(self, listener: socket.socket) -> None:
                        self.listener = listener
                        self.calls = 0

                    def accept(self):
                        self.calls += 1
                        if self.calls == 1:
                            try:
                                return self.listener.accept()
                            except socket.timeout:
                                timeout_caught.set()
                                release_timeout.wait(3)
                                raise
                        if self.calls == 2:
                            next_accept_entered.set()
                            release_next_accept.wait(3)
                        return self.listener.accept()

                    def close(self) -> None:
                        self.listener.close()

                with frontend._state_lock:
                    real_listener = frontend._listener
                    self.assertIsNotNone(real_listener)
                    frontend._listener = CrossingTimeoutListener(  # type: ignore[assignment]
                        real_listener
                    )
                    closed_epoch = frontend._admission_epoch

                queued: list[socket.socket] = []
                reopen_errors: list[BaseException] = []
                reopen_done = threading.Event()

                def reopen() -> None:
                    try:
                        frontend.qualification_reopen(1, timeout=3)
                    except BaseException as exc:
                        reopen_errors.append(exc)
                    finally:
                        reopen_done.set()

                reopen_worker: threading.Thread | None = None
                try:
                    self.assertTrue(timeout_caught.wait(3))
                    reopen_worker = threading.Thread(target=reopen)
                    reopen_worker.start()

                    def drain_epoch_started() -> bool:
                        with frontend._state_lock:
                            return frontend._admission_epoch > closed_epoch

                    wait_until(drain_epoch_started)
                    queued = [connect(frontend) for _ in range(3)]
                    release_timeout.set()
                    self.assertTrue(next_accept_entered.wait(3))
                    self.assertFalse(reopen_done.wait(0.25))
                    self.assertFalse(frontend.gauges().accepting)

                    release_next_accept.set()
                    reopen_worker.join(5)
                    self.assertFalse(reopen_worker.is_alive())
                    self.assertEqual(reopen_errors, [])
                    for client in queued:
                        self.assertEqual(recv_to_eof(client), b"")
                    self.assertGreaterEqual(
                        frontend.gauges().rejected_uncommitted, len(queued)
                    )
                    self.assertEqual(frontend.gauges().active_streams, 0)
                    self.assertTrue(frontend.gauges().accepting)

                    after = connect(frontend)
                    try:
                        wait_until(lambda: len(frontend.qualification_streams()) == 1)
                        stream_id = frontend.qualification_streams()[0].stream_id
                        frontend.qualification_revoke({stream_id}, timeout=3)
                    finally:
                        after.close()
                    frontend.qualification_disarm()
                finally:
                    release_timeout.set()
                    release_next_accept.set()
                    if reopen_worker is not None:
                        reopen_worker.join(5)
                    for client in queued:
                        client.close()
        backend.assert_clean()

    def test_seeded_32_client_data_plane_returns_all_resources(self) -> None:
        count = 32
        start = threading.Barrier(count)

        def echo_after_all_connected(connection: socket.socket) -> None:
            start.wait(timeout=10)
            payload = recv_to_eof(connection)
            connection.sendall(payload)

        with LoopbackBackend(echo_after_all_connected) as backend:
            frontend = CommittedFrontend(
                "127.0.0.1",
                0,
                backlog=64,
                max_streams=count,
                per_stream_buffer_bytes=4_096,
                total_buffer_bytes=count * 4_096,
            )
            frontend.start()
            failures: list[str] = []

            def round_trip(index: int) -> None:
                payload = (f"client-{index:02d}:".encode("ascii") * 257)[:4_096]
                try:
                    peer = connect(frontend)
                    peer.sendall(payload)
                    peer.shutdown(socket.SHUT_WR)
                    received = recv_to_eof(peer)
                    peer.close()
                    if received != payload:
                        failures.append(f"client {index} byte mismatch")
                except BaseException as exc:
                    failures.append(f"client {index}: {exc}")

            try:
                frontend.commit_generation(generation(1, backend, "load32"))
                clients = [
                    threading.Thread(target=round_trip, args=(index,))
                    for index in range(count)
                ]
                for thread in clients:
                    thread.start()
                for thread in clients:
                    thread.join(15)
                self.assertFalse(any(thread.is_alive() for thread in clients))
                self.assertEqual(failures, [])
                wait_until(lambda: frontend.gauges().active_streams == 0)
            finally:
                frontend.close(timeout=5)

            gauges = frontend.gauges()
            self.assertEqual(gauges.accepted_streams, count)
            self.assertEqual(gauges.completed_streams, count)
            self.assertEqual(gauges.rejected_overload, 0)
            self.assertEqual(gauges.peak_active_streams, count)
            self.assertEqual(gauges.buffered_bytes, 0)
            self.assertFalse(gauges.listener_alive)
        backend.assert_clean()

    def test_deterministic_partial_writes_eagain_and_duplex_backpressure(self) -> None:
        frontend = CommittedFrontend(
            "127.0.0.1",
            0,
            max_streams=1,
            per_stream_buffer_bytes=4_096,
            total_buffer_bytes=4_096,
            io_chunk_bytes=1_024,
        )
        client_relay_raw, client_peer = socket.socketpair()
        upstream_relay_raw, upstream_peer = socket.socketpair()
        client_relay = ThrottledSocket(client_relay_raw, max_io=37)
        upstream_relay = ThrottledSocket(upstream_relay_raw, max_io=43)
        record = CommittedGeneration(
            generation=1,
            backend_id="semantic-fault-seam",
            backend_host="127.0.0.1",
            backend_port=1,
            contract_digest="a" * 64,
        )
        stream = _FrontendStream(client_relay, record)
        stream.attach_upstream(upstream_relay)
        relay_errors: list[BaseException] = []

        def relay() -> None:
            try:
                frontend._relay(stream, upstream_relay)
            except BaseException as exc:
                relay_errors.append(exc)

        client_payload = bytes(range(251)) * 521
        upstream_payload = bytes(reversed(range(239))) * 547
        received: dict[str, bytes] = {}
        endpoint_errors: list[BaseException] = []

        def send_half(sock: socket.socket, payload: bytes) -> None:
            try:
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
            except BaseException as exc:
                endpoint_errors.append(exc)

        def receive(sock: socket.socket, key: str) -> None:
            try:
                received[key] = recv_to_eof(sock)
            except BaseException as exc:
                endpoint_errors.append(exc)

        for peer in (client_peer, upstream_peer):
            peer.settimeout(10)
        relay_thread = threading.Thread(target=relay)
        workers = (
            threading.Thread(target=send_half, args=(client_peer, client_payload)),
            threading.Thread(
                target=send_half, args=(upstream_peer, upstream_payload)
            ),
            threading.Thread(target=receive, args=(client_peer, "client")),
            threading.Thread(target=receive, args=(upstream_peer, "upstream")),
        )
        try:
            relay_thread.start()
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(10)
            relay_thread.join(10)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertFalse(relay_thread.is_alive())
            self.assertEqual(endpoint_errors, [])
            self.assertEqual(relay_errors, [])
            self.assertEqual(received["upstream"], client_payload)
            self.assertEqual(received["client"], upstream_payload)
            self.assertGreater(client_relay.short_writes, 0)
            self.assertGreater(upstream_relay.short_writes, 0)
            self.assertGreater(client_relay.write_eagain, 0)
            self.assertGreater(upstream_relay.write_eagain, 0)
            self.assertGreater(client_relay.read_eagain, 0)
            self.assertGreater(upstream_relay.read_eagain, 0)
            gauges = frontend.gauges()
            self.assertGreater(gauges.peak_buffered_bytes, 0)
            self.assertLessEqual(gauges.peak_buffered_bytes, 4_096)
            self.assertEqual(gauges.buffered_bytes, 0)
        finally:
            stream.revoke()
            stream.close()
            for peer in (client_peer, upstream_peer):
                try:
                    peer.close()
                except OSError:
                    pass

    def test_unpublished_candidate_receives_no_client_bytes(self) -> None:
        def record_handler(connection: socket.socket) -> None:
            while data := connection.recv(4_096):
                candidate.record(data)

        with LoopbackBackend(record_handler) as candidate:
            with CommittedFrontend("127.0.0.1", 0, max_streams=2) as frontend:
                # Merely constructing a qualified-looking record has no
                # publication side effect.
                _unpublished = generation(1, candidate, "candidate")
                client = connect(frontend)
                try:
                    try:
                        client.sendall(b"must-not-reach-candidate")
                    except OSError:
                        pass
                    wait_until(
                        lambda: frontend.gauges().rejected_uncommitted == 1
                    )
                finally:
                    client.close()
                time.sleep(0.05)
                self.assertEqual(candidate.connection_count(), 0)
                self.assertEqual(candidate.received_bytes(), b"")
                gauges = frontend.gauges()
                self.assertFalse(gauges.accepting)
                self.assertIsNone(gauges.committed_generation)

    def test_cutover_revokes_old_stream_before_new_publication(self) -> None:
        def labeled_handler(backend: LoopbackBackend, label: bytes):
            def handle(connection: socket.socket) -> None:
                while data := connection.recv(4_096):
                    backend.record(data)
                    connection.sendall(label + data)

            return handle

        old = LoopbackBackend(lambda _connection: None)
        new = LoopbackBackend(lambda _connection: None)
        rejected = LoopbackBackend(lambda _connection: None)
        old.handler = labeled_handler(old, b"old:")
        new.handler = labeled_handler(new, b"new:")
        rejected.handler = labeled_handler(rejected, b"rejected:")

        with old, new, rejected:
            with CommittedFrontend("127.0.0.1", 0, max_streams=4) as frontend:
                frontend.commit_generation(generation(1, old, "old"))
                old_client = connect(frontend)
                old_client.sendall(b"before")
                self.assertEqual(recv_exactly(old_client, 10), b"old:before")
                wait_until(lambda: old.connection_count() == 1)

                # A rejected/probing generation is never handed to commit and
                # therefore remains isolated from both old and new traffic.
                _rejected_candidate = generation(2, rejected, "rejected")
                frontend.commit_generation(generation(2, new, "new"))
                self.assertEqual(frontend.gauges().committed_generation, 2)
                self.assertEqual(frontend.gauges().active_streams, 0)

                try:
                    old_client.sendall(b"after-revocation")
                except OSError:
                    pass
                old_client.close()
                time.sleep(0.05)
                self.assertEqual(old.received_bytes(), b"before")

                new_client = connect(frontend)
                new_client.sendall(b"after")
                self.assertEqual(recv_exactly(new_client, 9), b"new:after")
                new_client.shutdown(socket.SHUT_WR)
                self.assertEqual(recv_to_eof(new_client), b"")
                new_client.close()
                wait_until(lambda: frontend.gauges().active_streams == 0)
                self.assertEqual(new.received_bytes(), b"after")
                self.assertEqual(rejected.connection_count(), 0)
                self.assertGreaterEqual(frontend.gauges().revoked_streams, 1)

        old.assert_clean()
        new.assert_clean()
        rejected.assert_clean()

    def test_byte_preservation_slow_reader_and_buffer_bounds(self) -> None:
        def slow_echo(connection: socket.socket) -> None:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8_192)
            while data := connection.recv(4_096):
                backend.record(data)
                time.sleep(0.0002)
                connection.sendall(data)
            connection.shutdown(socket.SHUT_WR)

        payload = bytes(range(256)) * 2_048  # 512 KiB, far above every relay buffer.
        with LoopbackBackend(slow_echo) as backend:
            with CommittedFrontend(
                "127.0.0.1",
                0,
                max_streams=2,
                per_stream_buffer_bytes=16_384,
                total_buffer_bytes=32_768,
                io_chunk_bytes=1_024,
            ) as frontend:
                frontend.commit_generation(generation(1, backend, "slow"))
                client = connect(frontend)
                client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8_192)
                client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8_192)
                sender_errors: list[BaseException] = []

                def send_payload() -> None:
                    try:
                        client.sendall(payload)
                        client.shutdown(socket.SHUT_WR)
                    except BaseException as exc:
                        sender_errors.append(exc)

                sender = threading.Thread(target=send_payload)
                sender.start()
                echoed = bytearray()
                while chunk := client.recv(4_096):
                    echoed.extend(chunk)
                    time.sleep(0.0001)
                sender.join(10)
                self.assertFalse(sender.is_alive())
                self.assertEqual(sender_errors, [])
                client.close()
                wait_until(lambda: frontend.gauges().active_streams == 0)

                self.assertEqual(bytes(echoed), payload)
                self.assertEqual(backend.received_bytes(), payload)
                gauges = frontend.gauges()
                self.assertGreater(gauges.peak_buffered_bytes, 0)
                self.assertLessEqual(
                    gauges.peak_buffered_bytes, gauges.total_buffer_limit
                )
                self.assertEqual(gauges.buffered_bytes, 0)
                self.assertEqual(gauges.active_streams, 0)
            closed = frontend.gauges()
            self.assertFalse(closed.listener_alive)
            self.assertEqual(closed.buffered_bytes, 0)
        backend.assert_clean()

    def test_duplex_half_close_delayed_response_and_graceful_drain(self) -> None:
        response = b"response-after-byte-silent-delay"

        def delayed_response(connection: socket.socket) -> None:
            request = bytearray()
            while data := connection.recv(4_096):
                request.extend(data)
            backend.record(bytes(request))
            time.sleep(0.2)
            connection.sendall(response)
            connection.shutdown(socket.SHUT_WR)

        with LoopbackBackend(delayed_response) as backend:
            with CommittedFrontend("127.0.0.1", 0) as frontend:
                frontend.commit_generation(generation(1, backend, "half-close"))
                client = connect(frontend)
                try:
                    # TCP connect completion precedes the frontend's admission
                    # linearization point; wait until this stream is registered
                    # before asking drain to preserve it.
                    wait_until(lambda: frontend.gauges().active_streams == 1)
                    client.sendall(b"request")
                    client.shutdown(socket.SHUT_WR)

                    # Drain closes admission but deliberately does not revoke this
                    # established duplex stream while the backend is silent.
                    self.assertTrue(frontend.drain(timeout=3))
                    self.assertEqual(recv_to_eof(client), response)
                finally:
                    client.close()
                self.assertEqual(backend.received_bytes(), b"request")
                self.assertFalse(frontend.gauges().accepting)

                rejected_client = connect(frontend)
                wait_until(
                    lambda: frontend.gauges().rejected_uncommitted >= 1
                )
                self.assertEqual(recv_to_eof(rejected_client), b"")
                rejected_client.close()
                self.assertEqual(backend.connection_count(), 1)
        backend.assert_clean()

    def test_overload_is_rejected_and_all_resources_return(self) -> None:
        release = threading.Event()
        accepted = threading.Event()

        def hold(connection: socket.socket) -> None:
            accepted.set()
            release.wait(5)
            try:
                while connection.recv(4_096):
                    pass
            except OSError:
                pass

        with LoopbackBackend(hold) as backend:
            frontend = CommittedFrontend(
                "127.0.0.1",
                0,
                backlog=1,
                max_streams=1,
                per_stream_buffer_bytes=4_096,
                total_buffer_bytes=4_096,
            )
            frontend.start()
            try:
                frontend.commit_generation(generation(1, backend, "hold"))
                first = connect(frontend)
                self.assertTrue(accepted.wait(3))
                wait_until(lambda: frontend.gauges().active_streams == 1)

                second = connect(frontend)
                wait_until(lambda: frontend.gauges().rejected_overload == 1)
                self.assertEqual(recv_to_eof(second), b"")
                second.close()

                gauges = frontend.gauges()
                self.assertEqual(gauges.active_streams, 1)
                self.assertEqual(gauges.peak_active_streams, 1)
                self.assertEqual(gauges.stream_limit, 1)
                self.assertEqual(gauges.backlog_limit, 1)
                release.set()
                first.shutdown(socket.SHUT_WR)
                self.assertEqual(recv_to_eof(first), b"")
                first.close()
                wait_until(lambda: frontend.gauges().active_streams == 0)
            finally:
                release.set()
                frontend.close(timeout=3)

            gauges = frontend.gauges()
            self.assertFalse(gauges.listener_alive)
            self.assertEqual(gauges.active_streams, 0)
            self.assertEqual(gauges.buffered_bytes, 0)
            self.assertEqual(gauges.accepted_streams, gauges.completed_streams)
        backend.assert_clean()

    def test_configuration_rejects_non_loopback_and_unbounded_budget(self) -> None:
        with self.assertRaises(ValueError):
            CommittedFrontend("0.0.0.0", 0)
        with self.assertRaises(ValueError):
            CommittedFrontend(
                "127.0.0.1",
                0,
                max_streams=2,
                per_stream_buffer_bytes=4_096,
                total_buffer_bytes=4_095,
            )
        with self.assertRaises(ValueError):
            CommittedGeneration(
                generation=1,
                backend_id="external",
                backend_host="192.0.2.1",
                backend_port=1_080,
                contract_digest="a" * 64,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
