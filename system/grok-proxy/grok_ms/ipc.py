"""Bounded Linux Unix-domain ``SOCK_SEQPACKET`` control transport."""

from __future__ import annotations

import array
from dataclasses import dataclass
import json
import os
from pathlib import Path
import socket
import stat
import struct
from typing import Any, Iterable, Mapping

from .contract import ContractValidationError, canonical_json_bytes


DEFAULT_MAX_PACKET_BYTES = 65_536
DEFAULT_MAX_ANCILLARY_FDS = 1
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 4_096
MAX_JSON_STRING = 16_384


class ProtocolError(ValueError):
    """Raised when an IPC peer violates framing or record constraints."""


class UnsupportedTransportError(RuntimeError):
    """Raised when the required Linux packet transport is not present."""


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class SeqPacketMessage:
    payload: dict[str, Any]
    fds: tuple[int, ...] = ()


def _reject_float(_value: str) -> None:
    raise ProtocolError("floating-point JSON values are forbidden")


def _reject_constant(value: str) -> None:
    raise ProtocolError(f"non-finite JSON value {value!r} is forbidden")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ProtocolError(f"duplicate JSON key {key!r}")
        output[key] = value
    return output


def _validate_json_tree(value: Any) -> None:
    nodes = 0

    def visit(item: Any, depth: int, path: str) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ProtocolError("JSON record has too many values")
        if depth > MAX_JSON_DEPTH:
            raise ProtocolError("JSON record is nested too deeply")
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if not -(2**63) <= item <= 2**63 - 1:
                raise ProtocolError(f"integer at {path} exceeds signed 64-bit range")
            return
        if type(item) is str:
            if len(item) > MAX_JSON_STRING:
                raise ProtocolError(f"string at {path} is too long")
            if any(ord(char) == 0 for char in item):
                raise ProtocolError(f"string at {path} contains NUL")
            return
        if type(item) is list:
            for index, child in enumerate(item):
                visit(child, depth + 1, f"{path}[{index}]")
            return
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or len(key) > 256:
                    raise ProtocolError(f"invalid object key at {path}")
                visit(child, depth + 1, f"{path}.{key}")
            return
        raise ProtocolError(f"unsupported JSON type at {path}: {type(item).__name__}")

    visit(value, 0, "$")


def strict_json_loads(data: bytes, max_packet_bytes: int) -> dict[str, Any]:
    if not data:
        raise ProtocolError("empty control packet")
    if len(data) > max_packet_bytes:
        raise ProtocolError("control packet is too large")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolError("control packet is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except ProtocolError:
        raise
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise ProtocolError(f"invalid JSON control packet: {exc}") from exc
    if type(value) is not dict:
        raise ProtocolError("control packet root must be an object")
    _validate_json_tree(value)
    return value


def encode_packet(payload: Mapping[str, Any], max_packet_bytes: int) -> bytes:
    if not isinstance(payload, Mapping):
        raise ProtocolError("control packet payload must be an object")
    try:
        data = canonical_json_bytes(payload)
    except ContractValidationError as exc:
        raise ProtocolError(str(exc)) from exc
    if len(data) > max_packet_bytes:
        raise ProtocolError(
            f"control packet is too large ({len(data)} > {max_packet_bytes})"
        )
    return data


def _require_secure_parent(path: Path) -> None:
    parent = path.parent
    try:
        info = parent.lstat()
    except FileNotFoundError as exc:
        raise ProtocolError(f"control socket parent does not exist: {parent}") from exc
    if not stat.S_ISDIR(info.st_mode) or parent.is_symlink():
        raise ProtocolError(f"control socket parent is not a real directory: {parent}")
    if info.st_uid != os.getuid():
        raise ProtocolError(f"control socket parent is not owned by uid {os.getuid()}")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise ProtocolError(f"control socket parent mode must be 0700: {parent}")


def bind_seqpacket_listener(
    path: str | os.PathLike[str], *, backlog: int = 32
) -> socket.socket:
    """Bind a mode-0600 packet listener without unlinking an existing object."""

    if not hasattr(socket, "SOCK_SEQPACKET"):
        raise UnsupportedTransportError("socket.SOCK_SEQPACKET is unavailable")
    socket_path = Path(path)
    _require_secure_parent(socket_path)
    if socket_path.exists() or socket_path.is_symlink():
        raise ProtocolError(f"control socket path already exists: {socket_path}")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    try:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600, follow_symlinks=False)
        listener.listen(backlog)
    except Exception:
        listener.close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return listener


class SeqPacketConnection:
    """One-record-per-packet transport with optional stable-handle transfer."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        max_packet_bytes: int = DEFAULT_MAX_PACKET_BYTES,
        max_ancillary_fds: int = DEFAULT_MAX_ANCILLARY_FDS,
    ) -> None:
        if sock.family != socket.AF_UNIX or sock.type & 0xF != socket.SOCK_SEQPACKET:
            raise ValueError("SeqPacketConnection requires an AF_UNIX SOCK_SEQPACKET socket")
        if type(max_packet_bytes) is not int or max_packet_bytes < 1:
            raise ValueError("max_packet_bytes must be a positive integer")
        if type(max_ancillary_fds) is not int or max_ancillary_fds < 0:
            raise ValueError("max_ancillary_fds must be a non-negative integer")
        self.socket = sock
        self.max_packet_bytes = max_packet_bytes
        self.max_ancillary_fds = max_ancillary_fds
        self.socket.set_inheritable(False)

    def peer_credentials(self) -> PeerCredentials:
        if not hasattr(socket, "SO_PEERCRED"):
            raise UnsupportedTransportError("socket.SO_PEERCRED is unavailable")
        raw = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        pid, uid, gid = struct.unpack("3i", raw)
        return PeerCredentials(pid=pid, uid=uid, gid=gid)

    def verify_peer(
        self, *, expected_uid: int, expected_pid: int | None = None
    ) -> PeerCredentials:
        peer = self.peer_credentials()
        if peer.uid != expected_uid:
            raise ProtocolError(
                f"peer uid mismatch: expected {expected_uid}, received {peer.uid}"
            )
        if expected_pid is not None and peer.pid != expected_pid:
            raise ProtocolError(
                f"peer pid mismatch: expected {expected_pid}, received {peer.pid}"
            )
        return peer

    def send(
        self, payload: Mapping[str, Any], fds: Iterable[int] = ()
    ) -> None:
        data = encode_packet(payload, self.max_packet_bytes)
        descriptors = tuple(fds)
        if len(descriptors) > self.max_ancillary_fds:
            raise ProtocolError("too many file descriptors in control packet")
        for descriptor in descriptors:
            if type(descriptor) is not int or descriptor < 0:
                raise ProtocolError("invalid file descriptor in control packet")
        ancillary = []
        if descriptors:
            packed = array.array("i", descriptors)
            ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, packed))
        sent = self.socket.sendmsg([data], ancillary)
        if sent != len(data):
            raise ProtocolError(
                f"short SOCK_SEQPACKET send ({sent} of {len(data)} bytes)"
            )

    def recv(self) -> SeqPacketMessage:
        int_size = array.array("i").itemsize
        # Ask for one extra descriptor so an over-limit packet is detected rather
        # than silently accepted after ancillary truncation.
        ancillary_capacity = socket.CMSG_SPACE(
            (self.max_ancillary_fds + 1) * int_size
        )
        flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
        data, ancillary, message_flags, _address = self.socket.recvmsg(
            self.max_packet_bytes, ancillary_capacity, flags
        )
        received: list[int] = []
        try:
            if message_flags & socket.MSG_TRUNC:
                raise ProtocolError("truncated SOCK_SEQPACKET payload")
            if message_flags & socket.MSG_CTRUNC:
                raise ProtocolError("truncated SOCK_SEQPACKET ancillary data")
            for level, kind, raw in ancillary:
                if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                    raise ProtocolError("unsupported ancillary control record")
                usable = len(raw) - (len(raw) % int_size)
                unpacked = array.array("i")
                unpacked.frombytes(raw[:usable])
                received.extend(unpacked)
            if len(received) > self.max_ancillary_fds:
                raise ProtocolError("too many received file descriptors")
            for descriptor in received:
                os.set_inheritable(descriptor, False)
            payload = strict_json_loads(data, self.max_packet_bytes)
            return SeqPacketMessage(payload=payload, fds=tuple(received))
        except Exception:
            for descriptor in received:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise

    def close(self) -> None:
        self.socket.close()


__all__ = [
    "DEFAULT_MAX_ANCILLARY_FDS",
    "DEFAULT_MAX_PACKET_BYTES",
    "PeerCredentials",
    "ProtocolError",
    "SeqPacketConnection",
    "SeqPacketMessage",
    "UnsupportedTransportError",
    "bind_seqpacket_listener",
    "encode_packet",
    "strict_json_loads",
]
