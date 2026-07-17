"""Bounded committed-generation TCP frontend for multi-session Grok.

The frontend deliberately knows nothing about provider qualification.  A caller
may construct or probe as many private backends as it needs, but client traffic
can reach only the one immutable :class:`CommittedGeneration` installed with
``commit_generation``.  Publication, revocation, and accept admission share one
critical section, so an accepted stream is either registered against the old
generation (and included in its revocation set) or against the new generation.

The listener remains bound while the publication gate is closed.  The accept
thread immediately closes such connections instead of allowing the kernel
backlog to retain pre-commit bytes for a later generation.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import ipaddress
import math
import selectors
import socket
import threading
import time
from typing import Final


DEFAULT_BACKLOG: Final = 128
DEFAULT_MAX_STREAMS: Final = 256
DEFAULT_PER_STREAM_BUFFER_BYTES: Final = 262_144
DEFAULT_CONNECT_TIMEOUT: Final = 15.0
DEFAULT_REVOKE_TIMEOUT: Final = 10.0
DEFAULT_IO_CHUNK_BYTES: Final = 65_536


class FrontendError(RuntimeError):
    """Base class for committed-frontend lifecycle failures."""


class FrontendClosedError(FrontendError):
    """Raised when an operation requires a running frontend."""


class FrontendDrainTimeout(FrontendError):
    """Raised when revoked streams do not return before the cutover deadline."""


class GenerationRevoked(FrontendError):
    """Internal signal that a stream lost its generation before relay start."""


def _numeric_loopback(host: str, *, field: str) -> tuple[str, int]:
    if type(host) is not str:
        raise ValueError(f"{field} must be a numeric loopback address")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"{field} must be a numeric loopback address") from exc
    if not address.is_loopback:
        raise ValueError(f"{field} must be a loopback address")
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    return str(address), family


def _bounded_int(value: int, *, field: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer in [{minimum}, {maximum}]")
    return value


def _timeout(value: float, *, field: str) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        raise ValueError(f"{field} must be a finite non-negative number")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{field} must be a finite non-negative number")
    return result


@dataclass(frozen=True, slots=True)
class CommittedGeneration:
    """Immutable, already-qualified private backend publication record."""

    generation: int
    backend_id: str
    backend_host: str
    backend_port: int
    contract_digest: str

    def __post_init__(self) -> None:
        _bounded_int(
            self.generation, field="generation", minimum=1, maximum=2**63 - 1
        )
        if (
            type(self.backend_id) is not str
            or not self.backend_id
            or len(self.backend_id) > 256
            or "\x00" in self.backend_id
        ):
            raise ValueError("backend_id must be a non-empty bounded string")
        host, _family = _numeric_loopback(self.backend_host, field="backend_host")
        object.__setattr__(self, "backend_host", host)
        _bounded_int(
            self.backend_port, field="backend_port", minimum=1, maximum=65_535
        )
        if (
            type(self.contract_digest) is not str
            or len(self.contract_digest) != 64
            or any(char not in "0123456789abcdef" for char in self.contract_digest)
        ):
            raise ValueError("contract_digest must be a lowercase SHA-256 digest")

    @property
    def endpoint(self) -> tuple[str, int]:
        return self.backend_host, self.backend_port


@dataclass(frozen=True, slots=True)
class FrontendGauges:
    """One bounded, non-authoritative resource/counter snapshot."""

    listener_alive: bool
    accepting: bool
    closing: bool
    committed_generation: int | None
    active_streams: int
    peak_active_streams: int
    buffered_bytes: int
    peak_buffered_bytes: int
    stream_limit: int
    backlog_limit: int
    per_stream_buffer_limit: int
    total_buffer_limit: int
    accepted_streams: int
    backend_connected_streams: int
    client_to_backend_bytes: int
    backend_to_client_bytes: int
    completed_streams: int
    revoked_streams: int
    rejected_uncommitted: int
    rejected_overload: int
    backend_connect_failures: int


@dataclass(frozen=True, slots=True)
class FrontendQualificationStream:
    """Exact active-stream transcript used only by the guarded real canary."""

    stream_id: int
    generation: int
    socks_state: str
    client_to_backend_bytes: int
    backend_to_client_bytes: int
    application_client_to_backend_bytes: int
    application_backend_to_client_bytes: int

    def to_dict(self) -> dict[str, int | str]:
        return {
            "stream_id": self.stream_id,
            "generation": self.generation,
            "socks_state": self.socks_state,
            "client_to_backend_bytes": self.client_to_backend_bytes,
            "backend_to_client_bytes": self.backend_to_client_bytes,
            "application_client_to_backend_bytes": (
                self.application_client_to_backend_bytes
            ),
            "application_backend_to_client_bytes": (
                self.application_backend_to_client_bytes
            ),
        }


class _Socks5Transcript:
    """Observe successful relay writes without changing the byte stream."""

    def __init__(self) -> None:
        self.state = "client-greeting"
        self.pending = bytearray()
        self.client_to_backend_bytes = 0
        self.backend_to_client_bytes = 0
        self.application_client_to_backend_bytes = 0
        self.application_backend_to_client_bytes = 0

    @staticmethod
    def _address_frame_length(data: bytearray) -> int | None:
        if len(data) < 4:
            return None
        address_type = data[3]
        if address_type == 1:
            return 10
        if address_type == 4:
            return 22
        if address_type == 3:
            if len(data) < 5:
                return None
            return 7 + data[4]
        return -1

    def _invalid(self) -> None:
        self.state = "invalid"
        self.pending.clear()

    def observe(self, *, from_client: bool, data: bytes) -> None:
        if not data:
            return
        if from_client:
            self.client_to_backend_bytes += len(data)
        else:
            self.backend_to_client_bytes += len(data)
        if self.state == "complete":
            if from_client:
                self.application_client_to_backend_bytes += len(data)
            else:
                self.application_backend_to_client_bytes += len(data)
            return
        if self.state == "invalid":
            return

        expected_client = self.state in {"client-greeting", "client-request"}
        if from_client is not expected_client:
            self._invalid()
            return
        self.pending.extend(data)
        if self.state == "client-greeting":
            if len(self.pending) < 2:
                return
            length = 2 + self.pending[1]
            if self.pending[0] != 5 or self.pending[1] < 1:
                self._invalid()
                return
            if len(self.pending) < length:
                return
            if len(self.pending) != length:
                self._invalid()
                return
            self.pending.clear()
            self.state = "server-method"
            return
        if self.state == "server-method":
            if len(self.pending) < 2:
                return
            if (
                len(self.pending) != 2
                or self.pending[0] != 5
                or self.pending[1] == 255
            ):
                self._invalid()
                return
            self.pending.clear()
            self.state = "client-request"
            return
        if self.state == "client-request":
            length = self._address_frame_length(self.pending)
            if length is None:
                return
            if (
                length < 0
                or len(self.pending) < length
                or self.pending[0:3] != b"\x05\x01\x00"
            ):
                if length < 0 or len(self.pending) >= max(length, 0):
                    self._invalid()
                return
            if len(self.pending) != length:
                self._invalid()
                return
            self.pending.clear()
            self.state = "server-reply"
            return

        length = self._address_frame_length(self.pending)
        if length is None:
            return
        if (
            length < 0
            or len(self.pending) < length
            or self.pending[0:3] != b"\x05\x00\x00"
        ):
            if length < 0 or len(self.pending) >= max(length, 0):
                self._invalid()
            return
        remainder = bytes(self.pending[length:])
        self.pending.clear()
        self.state = "complete"
        if remainder:
            self.application_backend_to_client_bytes += len(remainder)

    def server_control_write_limit(self, data: bytearray) -> int:
        """Return the prefix that is still SOCKS control, never tunnel data."""

        if not data or self.state in {"complete", "invalid"}:
            return 0
        if self.state == "server-method":
            return min(len(data), max(0, 2 - len(self.pending)))
        if self.state != "server-reply":
            return 0
        combined = self.pending + data
        if len(combined) < 4:
            return len(data)
        length = self._address_frame_length(combined)
        if length is None:
            return min(len(data), max(0, 5 - len(self.pending)))
        if length < 0:
            return 0
        return min(len(data), max(0, length - len(self.pending)))


class _FrontendStream:
    """One accepted socket, registered before any backend connection begins."""

    def __init__(
        self,
        client: socket.socket,
        generation: CommittedGeneration,
        stream_id: int = 0,
        peer_endpoint: tuple[str, int] | None = None,
        frontend_endpoint: tuple[str, int] | None = None,
    ) -> None:
        self.stream_id = stream_id
        self.client = client
        self.generation = generation
        self.peer_endpoint = peer_endpoint
        self.frontend_endpoint = frontend_endpoint
        self.upstream: socket.socket | None = None
        self.io_lock = threading.Lock()
        self.revoked = False
        self.done = threading.Event()
        self.transcript = _Socks5Transcript()
        self.wake_reader, self.wake_writer = socket.socketpair()
        for sock in (self.client, self.wake_reader, self.wake_writer):
            sock.set_inheritable(False)
        self.wake_reader.setblocking(False)
        self.wake_writer.setblocking(False)

    def attach_upstream(self, upstream: socket.socket) -> None:
        with self.io_lock:
            if self.revoked:
                raise GenerationRevoked("generation was revoked during backend connect")
            self.upstream = upstream

    def is_revoked(self) -> bool:
        with self.io_lock:
            return self.revoked

    def observe_write(self, *, from_client: bool, data: bytes) -> None:
        with self.io_lock:
            self.transcript.observe(from_client=from_client, data=data)

    def qualification_snapshot(self) -> FrontendQualificationStream:
        with self.io_lock:
            transcript = self.transcript
            return FrontendQualificationStream(
                stream_id=self.stream_id,
                generation=self.generation.generation,
                socks_state=transcript.state,
                client_to_backend_bytes=transcript.client_to_backend_bytes,
                backend_to_client_bytes=transcript.backend_to_client_bytes,
                application_client_to_backend_bytes=(
                    transcript.application_client_to_backend_bytes
                ),
                application_backend_to_client_bytes=(
                    transcript.application_backend_to_client_bytes
                ),
            )

    def server_control_write_limit(self, data: bytearray) -> int:
        with self.io_lock:
            return self.transcript.server_control_write_limit(data)

    def revoke(self) -> bool:
        """Linearize revocation against every relay read/write operation."""

        with self.io_lock:
            if self.revoked:
                return False
            self.revoked = True
            for sock in (self.client, self.upstream):
                if sock is None:
                    continue
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.wake()
        return True

    def wake(self) -> None:
        try:
            self.wake_writer.send(b"x")
        except (BlockingIOError, OSError):
            pass

    def close(self) -> None:
        with self.io_lock:
            sockets = (
                self.client,
                self.upstream,
                self.wake_reader,
                self.wake_writer,
            )
            for sock in sockets:
                if sock is None:
                    continue
                try:
                    sock.close()
                except OSError:
                    pass


class CommittedFrontend:
    """Loopback TCP relay whose publication gate exposes one generation only."""

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 1080,
        *,
        backlog: int = DEFAULT_BACKLOG,
        max_streams: int = DEFAULT_MAX_STREAMS,
        per_stream_buffer_bytes: int = DEFAULT_PER_STREAM_BUFFER_BYTES,
        total_buffer_bytes: int | None = None,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        io_chunk_bytes: int = DEFAULT_IO_CHUNK_BYTES,
    ) -> None:
        self._listen_host, self._family = _numeric_loopback(
            listen_host, field="listen_host"
        )
        self._listen_port = _bounded_int(
            listen_port, field="listen_port", minimum=0, maximum=65_535
        )
        self._backlog = _bounded_int(
            backlog, field="backlog", minimum=1, maximum=4_096
        )
        self._max_streams = _bounded_int(
            max_streams, field="max_streams", minimum=1, maximum=65_536
        )
        self._per_stream_buffer_bytes = _bounded_int(
            per_stream_buffer_bytes,
            field="per_stream_buffer_bytes",
            minimum=1,
            maximum=2**31 - 1,
        )
        minimum_total = self._max_streams * self._per_stream_buffer_bytes
        if total_buffer_bytes is None:
            total_buffer_bytes = minimum_total
        self._total_buffer_bytes = _bounded_int(
            total_buffer_bytes,
            field="total_buffer_bytes",
            minimum=minimum_total,
            maximum=2**63 - 1,
        )
        self._connect_timeout = _timeout(connect_timeout, field="connect_timeout")
        self._io_chunk_bytes = _bounded_int(
            io_chunk_bytes, field="io_chunk_bytes", minimum=1, maximum=2**20
        )

        self._state_lock = threading.Lock()
        self._accept_condition = threading.Condition(self._state_lock)
        self._gauge_lock = threading.Lock()
        self._qualification_lock = threading.Lock()
        self._transition_lock = threading.Lock()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._bound_address: tuple[str, int] | None = None
        self._started = False
        self._closing = False
        self._closed = False
        self._accepting = False
        self._active_generation: CommittedGeneration | None = None
        self._last_generation = 0
        self._streams: set[_FrontendStream] = set()
        self._next_stream_id = 1
        self._accept_idle_sequence = 0
        self._accept_idle_epoch = 0
        self._admission_epoch = 0
        self._accept_observed_epoch = 0
        self._qualification_accept_barrier = False
        self._qualification_quiesce_epoch = 0
        self._qualification_hold_responses = False

        self._buffered_bytes = 0
        self._peak_buffered_bytes = 0
        self._peak_active_streams = 0
        self._accepted_streams = 0
        self._backend_connected_streams = 0
        self._client_to_backend_bytes = 0
        self._backend_to_client_bytes = 0
        self._completed_streams = 0
        self._revoked_streams = 0
        self._rejected_uncommitted = 0
        self._rejected_overload = 0
        self._backend_connect_failures = 0

    @property
    def address(self) -> tuple[str, int]:
        with self._state_lock:
            if self._bound_address is None:
                raise FrontendClosedError("frontend has not been started")
            return self._bound_address

    def start(self) -> tuple[str, int]:
        """Bind and start rejection-only admission; no backend is published."""

        with self._state_lock:
            if self._started or self._closing or self._closed:
                raise FrontendClosedError("frontend cannot be started in its current state")
            listener = socket.socket(self._family, socket.SOCK_STREAM)
            listener.set_inheritable(False)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                if self._family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((self._listen_host, self._listen_port))
                listener.listen(self._backlog)
                # This timeout is solely a lifecycle wakeup for the accept thread;
                # established relay streams never receive an application idle timeout.
                listener.settimeout(0.2)
            except Exception:
                listener.close()
                raise
            address = listener.getsockname()
            self._listener = listener
            self._bound_address = (str(address[0]), int(address[1]))
            self._started = True
            thread = threading.Thread(
                target=self._accept_loop,
                name="grok-frontend-accept",
                daemon=True,
            )
            self._accept_thread = thread
            thread.start()
            return self._bound_address

    def commit_generation(
        self,
        generation: CommittedGeneration,
        *,
        revoke_timeout: float = DEFAULT_REVOKE_TIMEOUT,
    ) -> None:
        """Revoke the old generation completely, then publish ``generation``.

        A timeout leaves the gate closed and the candidate unpublished.
        """

        if not isinstance(generation, CommittedGeneration):
            raise TypeError("generation must be a CommittedGeneration")
        timeout = _timeout(revoke_timeout, field="revoke_timeout")
        deadline = time.monotonic() + timeout
        with self._transition_lock:
            with self._accept_condition:
                self._require_running_locked()
                if generation.generation <= self._last_generation:
                    raise ValueError("generation numbers must increase monotonically")
                self._accepting = False
                self._active_generation = None
                self._admission_epoch += 1
                old_streams = tuple(self._streams)

            self._revoke_streams(old_streams)
            if not self._wait_streams(
                old_streams, max(0.0, deadline - time.monotonic())
            ):
                raise FrontendDrainTimeout(
                    "old-generation streams did not stop before cutover deadline"
                )

            with self._accept_condition:
                self._require_running_locked()
                # This assignment and gate opening are the publication
                # linearization point observed by the accept loop.
                self._active_generation = generation
                self._last_generation = generation.generation
                self._accepting = True
                self._qualification_accept_barrier = False
                self._admission_epoch += 1
                open_epoch = self._admission_epoch
                self._accept_condition.notify_all()
                while self._accept_observed_epoch != open_epoch:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._accepting = False
                        self._active_generation = None
                        self._admission_epoch += 1
                        self._accept_condition.notify_all()
                        raise FrontendDrainTimeout(
                            "accept loop did not observe publication before deadline"
                        )
                    self._accept_condition.wait(remaining)

    def drain(self, timeout: float = DEFAULT_REVOKE_TIMEOUT) -> bool:
        """Close admission and wait for existing streams without revoking them."""

        timeout = _timeout(timeout, field="timeout")
        with self._transition_lock:
            with self._state_lock:
                if not self._started or self._closed:
                    return True
                self._accepting = False
                self._active_generation = None
                self._admission_epoch += 1
                streams = tuple(self._streams)
            return self._wait_streams(streams, timeout)

    def revoke(self, timeout: float = DEFAULT_REVOKE_TIMEOUT) -> bool:
        """Close admission, revoke every stream, and wait for resource return."""

        timeout = _timeout(timeout, field="timeout")
        with self._transition_lock:
            with self._state_lock:
                if not self._started or self._closed:
                    return True
                self._accepting = False
                self._active_generation = None
                self._admission_epoch += 1
                streams = tuple(self._streams)
            self._revoke_streams(streams)
            return self._wait_streams(streams, timeout)

    def qualification_streams(self) -> tuple[FrontendQualificationStream, ...]:
        """Return exact active SOCKS transcript snapshots for qualification."""

        with self._state_lock:
            streams = tuple(self._streams)
        return tuple(
            sorted(
                (stream.qualification_snapshot() for stream in streams),
                key=lambda item: item.stream_id,
            )
        )

    def qualification_state(self) -> dict[str, object]:
        """Return the guard-local response gate, cursor, and active transcripts."""

        with self._qualification_lock:
            armed = self._qualification_hold_responses
        with self._state_lock:
            cursor = self._next_stream_id - 1
            epoch = self._qualification_quiesce_epoch
            streams = tuple(self._streams)
        return {
            "response_hold": armed,
            "accept_cursor": cursor,
            "quiesce_epoch": epoch,
            "streams": [
                item.to_dict()
                for item in sorted(
                    (stream.qualification_snapshot() for stream in streams),
                    key=lambda value: value.stream_id,
                )
            ],
        }

    def qualification_peers(
        self,
    ) -> dict[int, tuple[str, int, str, int]]:
        """Return immutable TCP endpoint identities for active streams."""

        with self._state_lock:
            streams = tuple(self._streams)
        result: dict[int, tuple[str, int, str, int]] = {}
        for stream in streams:
            peer = stream.peer_endpoint
            frontend = stream.frontend_endpoint
            if peer is None or frontend is None:
                raise FrontendDrainTimeout(
                    "qualification stream lacks its accepted TCP identity"
                )
            result[stream.stream_id] = (
                peer[0], peer[1], frontend[0], frontend[1]
            )
        return result

    def qualification_arm(self) -> CommittedGeneration:
        """Arm response holding before qualification children may execute."""

        with self._transition_lock:
            with self._state_lock:
                self._require_running_locked()
                generation = self._active_generation
                if generation is None or not self._accepting or self._streams:
                    raise FrontendDrainTimeout(
                        "qualification arm requires one committed empty frontend"
                    )
            with self._qualification_lock:
                if self._qualification_hold_responses:
                    raise FrontendDrainTimeout(
                        "qualification response hold is already armed"
                    )
                self._qualification_hold_responses = True
            return generation

    def qualification_disarm(self) -> None:
        """Release held repaired-generation responses after both receipts."""

        with self._qualification_lock:
            self._qualification_hold_responses = False
        with self._state_lock:
            streams = tuple(self._streams)
        for stream in streams:
            stream.wake()

    def qualification_reopen(
        self,
        generation: int,
        timeout: float = DEFAULT_REVOKE_TIMEOUT,
    ) -> None:
        """Open a quiesced qualification gate only at an exact thaw boundary."""

        if type(generation) is not int or generation < 1:
            raise ValueError("qualification generation is invalid")
        deadline = time.monotonic() + _timeout(timeout, field="timeout")
        with self._transition_lock:
            with self._accept_condition:
                self._require_running_locked()
                active = self._active_generation
                if active is None or active.generation != generation:
                    raise FrontendDrainTimeout(
                        "qualification reopen generation is not committed"
                    )
                if self._accepting:
                    if self._qualification_accept_barrier:
                        raise FrontendDrainTimeout(
                            "qualification admission state is inconsistent"
                        )
                    target_epoch = self._admission_epoch
                else:
                    if not self._qualification_accept_barrier or self._streams:
                        raise FrontendDrainTimeout(
                            "qualification reopen requires one quiesced empty gate"
                        )
                    idle_before = self._accept_idle_sequence
                    self._admission_epoch += 1
                    drain_epoch = self._admission_epoch
                    self._accept_condition.notify_all()
                    while (
                        self._accept_observed_epoch != drain_epoch
                        or self._accept_idle_sequence <= idle_before
                        or self._accept_idle_epoch != drain_epoch
                    ):
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise FrontendDrainTimeout(
                                "qualification accept backlog did not drain before reopen"
                            )
                        self._accept_condition.wait(remaining)
                    self._qualification_accept_barrier = False
                    self._accepting = True
                    self._admission_epoch += 1
                    target_epoch = self._admission_epoch
                    self._accept_condition.notify_all()
                while self._accept_observed_epoch != target_epoch:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise FrontendDrainTimeout(
                            "qualification accept loop did not observe reopen"
                        )
                    self._accept_condition.wait(remaining)

    def qualification_quiesce(
        self,
        generation: int,
        timeout: float = DEFAULT_REVOKE_TIMEOUT,
    ) -> dict[str, int]:
        """Revoke streams and keep admission closed until an exact thaw boundary."""

        timeout = _timeout(timeout, field="timeout")
        deadline = time.monotonic() + timeout
        with self._qualification_lock:
            if not self._qualification_hold_responses:
                raise FrontendDrainTimeout(
                    "qualification quiesce requires an armed response hold"
                )
        with self._transition_lock:
            with self._accept_condition:
                self._require_running_locked()
                active = self._active_generation
                if active is None or active.generation != generation:
                    raise FrontendDrainTimeout(
                        "qualification quiesce generation is not committed"
                    )
                self._accepting = False
                self._active_generation = None
                self._qualification_accept_barrier = True
                self._admission_epoch += 1
                closed_epoch = self._admission_epoch
                streams = tuple(self._streams)
                idle_before = self._accept_idle_sequence
            self._revoke_streams(streams)
            if not self._wait_streams(
                streams, max(0.0, deadline - time.monotonic())
            ):
                raise FrontendDrainTimeout(
                    "qualification streams did not stop before quiesce deadline"
                )
            with self._accept_condition:
                while (
                    self._accept_idle_sequence <= idle_before
                    or self._accept_idle_epoch != closed_epoch
                    or self._accept_observed_epoch != closed_epoch
                ):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise FrontendDrainTimeout(
                            "qualification accept backlog did not quiesce"
                        )
                    self._accept_condition.wait(remaining)
                if self._streams:
                    raise FrontendDrainTimeout(
                        "qualification streams reappeared while admission was closed"
                    )
                cursor = self._next_stream_id - 1
                self._qualification_quiesce_epoch += 1
                epoch = self._qualification_quiesce_epoch
                self._active_generation = active
                self._accept_condition.notify_all()
            return {
                "accept_cursor": cursor,
                "quiesce_epoch": epoch,
                "generation": generation,
            }

    def qualification_revoke(
        self,
        expected_stream_ids: set[int],
        timeout: float = DEFAULT_REVOKE_TIMEOUT,
    ) -> tuple[FrontendQualificationStream, ...]:
        """Revoke one exact active stream set and return its final transcripts."""

        timeout = _timeout(timeout, field="timeout")
        if (
            type(expected_stream_ids) is not set
            or not expected_stream_ids
            or any(type(value) is not int or value < 1 for value in expected_stream_ids)
        ):
            raise ValueError("expected qualification stream IDs are invalid")
        with self._transition_lock:
            with self._state_lock:
                self._require_running_locked()
                streams = tuple(self._streams)
                actual = {stream.stream_id for stream in streams}
                if actual != expected_stream_ids:
                    raise FrontendDrainTimeout(
                        "qualification active stream identity changed before revoke"
                    )
                self._accepting = False
                self._active_generation = None
                self._admission_epoch += 1
            self._revoke_streams(streams)
            if not self._wait_streams(streams, timeout):
                raise FrontendDrainTimeout(
                    "qualification streams did not stop before revoke deadline"
                )
            return tuple(
                sorted(
                    (stream.qualification_snapshot() for stream in streams),
                    key=lambda item: item.stream_id,
                )
            )

    def close(self, timeout: float = DEFAULT_REVOKE_TIMEOUT) -> None:
        """Synchronously stop admission and return all frontend-owned resources."""

        timeout = _timeout(timeout, field="timeout")
        deadline = time.monotonic() + timeout
        with self._transition_lock:
            with self._accept_condition:
                if self._closed:
                    return
                self._closing = True
                self._accepting = False
                self._active_generation = None
                self._admission_epoch += 1
                self._qualification_accept_barrier = False
                self._accept_condition.notify_all()
                listener = self._listener
                self._listener = None
                streams = tuple(self._streams)
                accept_thread = self._accept_thread
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    pass
            self._revoke_streams(streams)
            streams_stopped = self._wait_streams(
                streams, max(0.0, deadline - time.monotonic())
            )
            if accept_thread is not None:
                accept_thread.join(max(0.0, deadline - time.monotonic()))
            accept_stopped = accept_thread is None or not accept_thread.is_alive()
            with self._state_lock:
                if streams_stopped and accept_stopped and not self._streams:
                    self._closed = True
            if not streams_stopped or not accept_stopped:
                raise FrontendDrainTimeout(
                    "frontend resources did not stop before close deadline"
                )

    def gauges(self) -> FrontendGauges:
        """Return a bounded snapshot; counters are diagnostics, not authority."""

        with self._state_lock:
            listener_alive = self._listener is not None and not self._closed
            accepting = self._accepting
            closing = self._closing
            generation = (
                None
                if self._active_generation is None
                else self._active_generation.generation
            )
            active_streams = len(self._streams)
        with self._gauge_lock:
            return FrontendGauges(
                listener_alive=listener_alive,
                accepting=accepting,
                closing=closing,
                committed_generation=generation,
                active_streams=active_streams,
                peak_active_streams=self._peak_active_streams,
                buffered_bytes=self._buffered_bytes,
                peak_buffered_bytes=self._peak_buffered_bytes,
                stream_limit=self._max_streams,
                backlog_limit=self._backlog,
                per_stream_buffer_limit=self._per_stream_buffer_bytes,
                total_buffer_limit=self._total_buffer_bytes,
                accepted_streams=self._accepted_streams,
                backend_connected_streams=self._backend_connected_streams,
                client_to_backend_bytes=self._client_to_backend_bytes,
                backend_to_client_bytes=self._backend_to_client_bytes,
                completed_streams=self._completed_streams,
                revoked_streams=self._revoked_streams,
                rejected_uncommitted=self._rejected_uncommitted,
                rejected_overload=self._rejected_overload,
                backend_connect_failures=self._backend_connect_failures,
            )

    def __enter__(self) -> CommittedFrontend:
        self.start()
        return self

    def __exit__(self, _kind, _value, _traceback) -> None:
        self.close()

    def _require_running_locked(self) -> None:
        if not self._started or self._closing or self._closed:
            raise FrontendClosedError("frontend is not running")

    def _accept_loop(self) -> None:
        while True:
            with self._accept_condition:
                listener = self._listener
                closing = self._closing
                accept_epoch = self._admission_epoch
                accept_permitted = self._accepting
                self._accept_observed_epoch = accept_epoch
                self._accept_condition.notify_all()
            if listener is None or closing:
                return
            try:
                client, _address = listener.accept()
            except socket.timeout:
                with self._accept_condition:
                    if not self._accepting:
                        self._accept_idle_sequence += 1
                        self._accept_idle_epoch = accept_epoch
                        self._accept_condition.notify_all()
                continue
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                with self._state_lock:
                    if self._closing or self._listener is None:
                        return
                continue

            client.set_inheritable(False)
            stream: _FrontendStream | None = None
            reject_reason = ""
            with self._state_lock:
                generation = self._active_generation
                if (
                    self._closing
                    or not self._accepting
                    or not accept_permitted
                    or generation is None
                    or accept_epoch != self._admission_epoch
                ):
                    reject_reason = "uncommitted"
                elif len(self._streams) >= self._max_streams:
                    reject_reason = "overload"
                else:
                    try:
                        stream = _FrontendStream(
                            client,
                            generation,
                            self._next_stream_id,
                            (
                                str(client.getpeername()[0]),
                                int(client.getpeername()[1]),
                            ),
                            (
                                str(client.getsockname()[0]),
                                int(client.getsockname()[1]),
                            ),
                        )
                        self._next_stream_id += 1
                    except Exception:
                        reject_reason = "overload"
                    else:
                        self._streams.add(stream)
                        worker = threading.Thread(
                            target=self._stream_worker,
                            args=(stream,),
                            name=f"grok-frontend-g{generation.generation}",
                            daemon=True,
                        )
                        try:
                            worker.start()
                        except Exception:
                            self._streams.remove(stream)
                            stream.close()
                            stream = None
                            reject_reason = "overload"
                        else:
                            with self._gauge_lock:
                                self._accepted_streams += 1
                                self._peak_active_streams = max(
                                    self._peak_active_streams, len(self._streams)
                                )
            if stream is None:
                try:
                    client.close()
                except OSError:
                    pass
                with self._gauge_lock:
                    if reject_reason == "overload":
                        self._rejected_overload += 1
                    else:
                        self._rejected_uncommitted += 1

    def _stream_worker(self, stream: _FrontendStream) -> None:
        try:
            try:
                upstream = self._connect_backend(stream)
            except GenerationRevoked:
                return
            except OSError:
                if not stream.is_revoked():
                    with self._gauge_lock:
                        self._backend_connect_failures += 1
                return
            with self._gauge_lock:
                self._backend_connected_streams += 1
            try:
                self._relay(stream, upstream)
            except (GenerationRevoked, OSError):
                # A reset established stream is a normal relay termination, not
                # evidence that the committed backend failed to accept it.
                pass
        finally:
            stream.close()
            with self._state_lock:
                self._streams.discard(stream)
            with self._gauge_lock:
                self._completed_streams += 1
            stream.done.set()

    def _connect_backend(self, stream: _FrontendStream) -> socket.socket:
        generation = stream.generation
        _host, family = _numeric_loopback(
            generation.backend_host, field="backend_host"
        )
        upstream = socket.socket(family, socket.SOCK_STREAM)
        try:
            upstream.set_inheritable(False)
            upstream.setblocking(False)
            stream.attach_upstream(upstream)
        except BaseException:
            upstream.close()
            raise
        result = upstream.connect_ex(generation.endpoint)
        if result in (0, errno.EISCONN):
            return upstream
        in_progress = {
            errno.EINPROGRESS,
            errno.EWOULDBLOCK,
            errno.EALREADY,
            errno.EINTR,
        }
        if result not in in_progress:
            raise OSError(result, "private backend connect failed")

        selector = selectors.DefaultSelector()
        try:
            selector.register(upstream, selectors.EVENT_WRITE)
            selector.register(stream.wake_reader, selectors.EVENT_READ)
            deadline = time.monotonic() + self._connect_timeout
            while True:
                if stream.is_revoked():
                    raise GenerationRevoked("generation revoked during backend connect")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("private backend connect timed out")
                events = selector.select(remaining)
                if not events:
                    raise TimeoutError("private backend connect timed out")
                for key, _mask in events:
                    if key.fileobj is stream.wake_reader:
                        raise GenerationRevoked(
                            "generation revoked during backend connect"
                        )
                    error = upstream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if error:
                        raise OSError(error, "private backend connect failed")
                    if stream.is_revoked():
                        raise GenerationRevoked(
                            "generation revoked after backend connect"
                        )
                    return upstream
        finally:
            selector.close()

    def _relay(self, stream: _FrontendStream, upstream: socket.socket) -> None:
        client = stream.client
        for sock in (client, upstream):
            sock.setblocking(False)
            self._enable_keepalive(sock)

        selector = selectors.DefaultSelector()
        peers = {client: upstream, upstream: client}
        pending = {client: bytearray(), upstream: bytearray()}
        read_open = {client: True, upstream: True}
        write_closed = {client: False, upstream: False}
        registered: set[socket.socket] = set()
        buffered = 0

        def close_write(sock: socket.socket) -> None:
            if write_closed[sock]:
                return
            with stream.io_lock:
                if stream.revoked:
                    raise GenerationRevoked("generation revoked during half-close")
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                write_closed[sock] = True

        def permitted_write(sock: socket.socket) -> int:
            if not pending[sock]:
                return 0
            if sock is not client:
                return len(pending[sock])
            with self._qualification_lock:
                held = self._qualification_hold_responses
            if not held:
                return len(pending[sock])
            return stream.server_control_write_limit(pending[sock])

        def refresh(sock: socket.socket) -> None:
            peer = peers[sock]
            events = 0
            if read_open[sock] and buffered < self._per_stream_buffer_bytes:
                events |= selectors.EVENT_READ
            if permitted_write(sock) and not write_closed[sock]:
                events |= selectors.EVENT_WRITE
            if events:
                if sock in registered:
                    selector.modify(sock, events)
                else:
                    selector.register(sock, events)
                    registered.add(sock)
            elif sock in registered:
                selector.unregister(sock)
                registered.remove(sock)

        selector.register(stream.wake_reader, selectors.EVENT_READ)
        try:
            while True:
                if stream.is_revoked():
                    raise GenerationRevoked("generation revoked during relay")
                refresh(client)
                refresh(upstream)
                if not read_open[client] and not read_open[upstream] and buffered == 0:
                    return
                for key, mask in selector.select(timeout=None):
                    sock = key.fileobj
                    if sock is stream.wake_reader:
                        try:
                            while stream.wake_reader.recv(256):
                                pass
                        except (BlockingIOError, OSError):
                            pass
                        if stream.is_revoked():
                            raise GenerationRevoked(
                                "generation revoked during relay"
                            )
                        continue
                    peer = peers[sock]
                    if mask & selectors.EVENT_READ:
                        room = self._per_stream_buffer_bytes - buffered
                        if room:
                            with stream.io_lock:
                                if stream.revoked:
                                    raise GenerationRevoked(
                                        "generation revoked before relay read"
                                    )
                                try:
                                    data = sock.recv(min(self._io_chunk_bytes, room))
                                except BlockingIOError:
                                    data = None
                            if data == b"":
                                read_open[sock] = False
                                if not pending[peer]:
                                    close_write(peer)
                            elif data:
                                pending[peer].extend(data)
                                buffered += len(data)
                                self._adjust_buffer(len(data))

                    if mask & selectors.EVENT_WRITE and pending[sock]:
                        write_limit = permitted_write(sock)
                        if write_limit == 0:
                            continue
                        with stream.io_lock:
                            if stream.revoked:
                                raise GenerationRevoked(
                                    "generation revoked before relay write"
                                )
                            try:
                                sent = sock.send(
                                    memoryview(pending[sock])[:write_limit]
                                )
                            except BlockingIOError:
                                sent = 0
                        if sent:
                            with self._gauge_lock:
                                if sock is upstream:
                                    self._client_to_backend_bytes += sent
                                else:
                                    self._backend_to_client_bytes += sent
                            stream.observe_write(
                                from_client=sock is upstream,
                                data=bytes(pending[sock][:sent]),
                            )
                            del pending[sock][:sent]
                            buffered -= sent
                            self._adjust_buffer(-sent)
                        if not pending[sock] and not read_open[peer]:
                            close_write(sock)
        finally:
            selector.close()
            if buffered:
                self._adjust_buffer(-buffered)

    def _adjust_buffer(self, delta: int) -> None:
        with self._gauge_lock:
            new_value = self._buffered_bytes + delta
            if not 0 <= new_value <= self._total_buffer_bytes:
                raise AssertionError("frontend application buffer accounting escaped bounds")
            self._buffered_bytes = new_value
            self._peak_buffered_bytes = max(self._peak_buffered_bytes, new_value)

    def _revoke_streams(self, streams: tuple[_FrontendStream, ...]) -> None:
        revoked = 0
        for stream in streams:
            if stream.revoke():
                revoked += 1
        if revoked:
            with self._gauge_lock:
                self._revoked_streams += revoked

    @staticmethod
    def _wait_streams(
        streams: tuple[_FrontendStream, ...], timeout: float
    ) -> bool:
        deadline = time.monotonic() + timeout
        for stream in streams:
            if not stream.done.wait(max(0.0, deadline - time.monotonic())):
                return False
        return True

    @staticmethod
    def _enable_keepalive(sock: socket.socket) -> None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass


__all__ = [
    "CommittedFrontend",
    "CommittedGeneration",
    "FrontendClosedError",
    "FrontendDrainTimeout",
    "FrontendError",
    "FrontendGauges",
]
