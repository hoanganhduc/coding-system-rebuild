"""Exact lease process ownership using a delegated Linux cgroup-v2 child.

The pidfd retained by the wrapper and supervisor is an exact handle for the
direct Grok process, but it is deliberately *not* treated as a descendant
scope.  Every admitted child is moved, while still blocked before ``exec``,
into a dedicated cgroup.  Forked, re-execed, double-forked, and ``setsid``
descendants inherit that cgroup and can therefore be reconciled without a
race-prone ``/proc`` tree walk or process-group signalling.

There is no production fallback.  A host which cannot provide the verified
cgroup-v2 operations fails the feature-on attachment before the child barrier
is released.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import time
from typing import Any, Callable, Mapping, Protocol

from .runtime import ProcessIdentity, RuntimeSecurityError, process_matches


_BACKEND = "cgroup-v2-v1"
_SCOPE_NAME_RE = re.compile(r"^grok-ms-[0-9a-f]{24}$")
_PHASES = frozenset({"PREPARED", "SCOPE_CREATED", "ATTACHED"})
_MAX_PROC_RECORD = 16_384
_MAX_EVENT_RECORD = 4_096
_LEASE_CGROUP_MAX_DEPTH = 8
_LEASE_CGROUP_MAX_DESCENDANTS = 256
_LEASE_CGROUP_CLEANUP_MAX_DEPTH = 64
_LEASE_CGROUP_CLEANUP_MAX_DESCENDANTS = 1_024


class ScopeError(RuntimeSecurityError):
    """The host cannot establish the required exact lease process scope."""


class ScopeResidueError(ScopeError):
    """A lease scope could not be proved empty and removed."""


def _require_int(value: Any, name: str, *, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name}: expected an integer >= {minimum}")
    return value


def _require_optional_int(value: Any, name: str) -> int | None:
    if value is None:
        return None
    return _require_int(value, name)


@dataclass(frozen=True, slots=True)
class ScopeIdentity:
    """Durable identity for one planned or created lease cgroup."""

    backend: str
    parent_path: str
    parent_device: int
    parent_inode: int
    scope_path: str
    scope_device: int | None
    scope_inode: int | None

    def __post_init__(self) -> None:
        if self.backend != _BACKEND:
            raise ValueError("scope.backend: unsupported value")
        parent = Path(self.parent_path)
        scope = Path(self.scope_path)
        if (
            type(self.parent_path) is not str
            or not parent.is_absolute()
            or type(self.scope_path) is not str
            or not scope.is_absolute()
            or scope.parent != parent
            or _SCOPE_NAME_RE.fullmatch(scope.name) is None
        ):
            raise ValueError("scope paths do not identify one strict lease child")
        _require_int(self.parent_device, "scope.parent_device")
        _require_int(self.parent_inode, "scope.parent_inode")
        device = _require_optional_int(self.scope_device, "scope.scope_device")
        inode = _require_optional_int(self.scope_inode, "scope.scope_inode")
        if (device is None) != (inode is None):
            raise ValueError("scope device and inode must both be null or both be set")

    @property
    def created(self) -> bool:
        return self.scope_device is not None

    def with_scope_stat(self, info: os.stat_result) -> "ScopeIdentity":
        return replace(self, scope_device=info.st_dev, scope_inode=info.st_ino)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "parent_device": self.parent_device,
            "parent_inode": self.parent_inode,
            "parent_path": self.parent_path,
            "scope_device": self.scope_device,
            "scope_inode": self.scope_inode,
            "scope_path": self.scope_path,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ScopeIdentity":
        fields = {
            "backend",
            "parent_device",
            "parent_inode",
            "parent_path",
            "scope_device",
            "scope_inode",
            "scope_path",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ValueError("scope: missing or unexpected fields")
        return cls(
            backend=value["backend"],
            parent_path=value["parent_path"],
            parent_device=value["parent_device"],
            parent_inode=value["parent_inode"],
            scope_path=value["scope_path"],
            scope_device=value["scope_device"],
            scope_inode=value["scope_inode"],
        )


@dataclass(slots=True)
class ScopeHandle:
    identity: ScopeIdentity
    descriptor: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


class ProcessScopeBackend(Protocol):
    def plan(self) -> ScopeIdentity:
        """Return an effect-free unique scope plan under this process's cgroup."""

    def create(self, planned: ScopeIdentity) -> ScopeHandle:
        """Create and return the exact planned scope."""

    def attach(self, handle: ScopeHandle, child: ProcessIdentity) -> None:
        """Move the still-barriered direct child into the scope and verify it."""

    def freeze(self, handle: ScopeHandle, timeout_seconds: float) -> None:
        """Freeze every process in the exact scope and wait for kernel ACK."""

    def thaw(self, handle: ScopeHandle, timeout_seconds: float) -> None:
        """Thaw every process in the exact scope and wait for kernel ACK."""

    def frozen_socket_inodes(
        self,
        handle: ScopeHandle,
        deadline_monotonic_ns: int,
    ) -> frozenset[int]:
        """Return the exact socket-FD inventory of one frozen scope."""

    def tcp_connection_inode(
        self,
        client_host: str,
        client_port: int,
        frontend_host: str,
        frontend_port: int,
        deadline_monotonic_ns: int,
    ) -> int | None:
        """Resolve one exact established client-to-frontend TCP tuple."""

    def reconcile(
        self,
        scope: ScopeIdentity,
        phase: str,
        child: ProcessIdentity,
        pidfd: int | None,
        timeout_seconds: float,
        *,
        handle: ScopeHandle | None = None,
    ) -> None:
        """Terminate remaining scope processes and prove exact empty removal."""

    def force_kill(
        self,
        scope: ScopeIdentity,
        *,
        handle: ScopeHandle | None = None,
    ) -> None:
        """Immediately kill every process in one exact created scope."""

    def release_current(
        self,
        scope: ScopeIdentity,
        timeout_seconds: float,
    ) -> None:
        """Move the current owner to its parent, then empty and remove its scope."""


def _decode_mount_field(value: str) -> str:
    # mountinfo uses these four octal escapes in path fields.
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _read_bounded(
    path: Path,
    maximum: int,
    *,
    deadline_monotonic_ns: int | None = None,
) -> str:
    if (
        deadline_monotonic_ns is not None
        and (
            type(deadline_monotonic_ns) is not int
            or deadline_monotonic_ns <= time.monotonic_ns()
        )
    ):
        raise ScopeError("qualification ownership inspection deadline expired")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            if (
                deadline_monotonic_ns is not None
                and time.monotonic_ns() >= deadline_monotonic_ns
            ):
                raise ScopeError(
                    "qualification ownership inspection deadline expired"
                )
            chunk = os.read(descriptor, min(16_384, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ScopeError(f"oversized kernel ownership record: {path}")
    finally:
        os.close(descriptor)
    try:
        return b"".join(chunks).decode("ascii")
    except UnicodeDecodeError as exc:
        raise ScopeError(f"non-ASCII kernel ownership record: {path}") from exc


class LinuxCgroupV2Scope:
    """Production cgroup-v2 lease scope; all failures are fail-closed."""

    def __init__(
        self,
        *,
        mount_root: Path = Path("/sys/fs/cgroup"),
        proc_root: Path = Path("/proc"),
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.mount_root = mount_root
        self.proc_root = proc_root
        self._clock = clock
        self._sleep = sleeper

    @staticmethod
    def _directory_flags() -> int:
        return (
            getattr(os, "O_PATH", os.O_RDONLY)
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
        )

    def _verify_cgroup2_mount(self) -> os.stat_result:
        try:
            root_info = self.mount_root.lstat()
        except OSError as exc:
            raise ScopeError(f"cgroup-v2 mount is unavailable: {self.mount_root}") from exc
        if self.mount_root.is_symlink() or not stat.S_ISDIR(root_info.st_mode):
            raise ScopeError("cgroup-v2 mount root is not a real directory")
        found = False
        try:
            text = _read_bounded(self.proc_root / "self/mountinfo", 1_048_576)
        except OSError as exc:
            raise ScopeError("cannot inspect cgroup mount topology") from exc
        for line in text.splitlines():
            fields = line.split()
            try:
                separator = fields.index("-")
            except ValueError:
                continue
            if len(fields) <= separator + 2 or len(fields) < 6:
                continue
            mountpoint = _decode_mount_field(fields[4])
            if mountpoint != str(self.mount_root):
                continue
            found = fields[separator + 1] == "cgroup2" and "rw" in fields[5].split(",")
            break
        if not found:
            raise ScopeError(f"{self.mount_root} is not the writable cgroup-v2 mount")
        return root_info

    def _relative_cgroup(self, pid: int | str = "self") -> str:
        try:
            text = _read_bounded(self.proc_root / str(pid) / "cgroup", _MAX_PROC_RECORD)
        except OSError as exc:
            raise ScopeError(f"cannot inspect process cgroup membership for {pid}") from exc
        lines = text.splitlines()
        if len(lines) != 1 or not lines[0].startswith("0::/"):
            raise ScopeError("process is not in one unified cgroup-v2 hierarchy")
        relative = lines[0][3:]
        parts = Path(relative).parts
        if not relative.startswith("/") or ".." in parts:
            raise ScopeError("process cgroup path is not canonical")
        return relative

    def _parent(self) -> tuple[Path, os.stat_result]:
        root_info = self._verify_cgroup2_mount()
        relative = self._relative_cgroup()
        parent = self.mount_root / relative.lstrip("/")
        try:
            info = parent.lstat()
        except OSError as exc:
            raise ScopeError(f"current cgroup is unavailable: {parent}") from exc
        if (
            parent.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_dev != root_info.st_dev
        ):
            raise ScopeError("current cgroup is not a delegated user-owned cgroup-v2 directory")
        return parent, info

    def plan(self) -> ScopeIdentity:
        parent, info = self._parent()
        # The caller durably records this unpredictable name before mkdir.
        import secrets

        name = f"grok-ms-{secrets.token_hex(12)}"
        return ScopeIdentity(
            backend=_BACKEND,
            parent_path=str(parent),
            parent_device=info.st_dev,
            parent_inode=info.st_ino,
            scope_path=str(parent / name),
            scope_device=None,
            scope_inode=None,
        )

    def _open_parent(self, scope: ScopeIdentity) -> int:
        parent = Path(scope.parent_path)
        root_info = self._verify_cgroup2_mount()
        try:
            relative = parent.relative_to(self.mount_root)
        except ValueError as exc:
            raise ScopeError("lease cgroup parent is outside the cgroup-v2 mount") from exc
        if not relative.parts or ".." in relative.parts:
            raise ScopeError("lease cgroup parent is not beneath the cgroup-v2 mount")
        if scope.parent_device != root_info.st_dev:
            raise ScopeError("recorded lease parent is not on the cgroup-v2 device")
        descriptor = os.open(parent, self._directory_flags())
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or (info.st_dev, info.st_ino)
                != (scope.parent_device, scope.parent_inode)
            ):
                raise ScopeError("lease cgroup parent identity changed")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _verify_scope_files(self, descriptor: int) -> None:
        for name in ("cgroup.events", "cgroup.freeze", "cgroup.kill", "cgroup.procs"):
            flags = os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            flags |= os.O_RDONLY if name == "cgroup.events" else os.O_WRONLY
            child = os.open(name, flags, dir_fd=descriptor)
            try:
                info = os.fstat(child)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                    raise ScopeError(f"unsafe lease cgroup control file: {name}")
            finally:
                os.close(child)

    def create(self, planned: ScopeIdentity) -> ScopeHandle:
        if planned.created:
            raise ScopeError("lease scope plan is already marked created")
        parent_fd = self._open_parent(planned)
        name = Path(planned.scope_path).name
        descriptor = -1
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            descriptor = os.open(name, self._directory_flags(), dir_fd=parent_fd)
            os.set_inheritable(descriptor, False)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_dev != planned.parent_device
            ):
                raise ScopeError("created lease cgroup has an unexpected identity")
            self._verify_scope_files(descriptor)
            for control, maximum in (
                ("cgroup.max.depth", _LEASE_CGROUP_MAX_DEPTH),
                ("cgroup.max.descendants", _LEASE_CGROUP_MAX_DESCENDANTS),
            ):
                self._write_control(
                    descriptor,
                    control,
                    f"{maximum}\n".encode("ascii"),
                )
                try:
                    actual = int(self._read_control(descriptor, control, 64).strip())
                except ValueError as exc:
                    raise ScopeError(f"invalid lease cgroup bound: {control}") from exc
                if actual != maximum:
                    raise ScopeError(f"lease cgroup did not retain its {control} bound")
            return ScopeHandle(planned.with_scope_stat(info), descriptor)
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        finally:
            os.close(parent_fd)

    def _open_existing(self, scope: ScopeIdentity) -> ScopeHandle | None:
        parent_fd = self._open_parent(scope)
        descriptor = -1
        try:
            try:
                descriptor = os.open(
                    Path(scope.scope_path).name,
                    self._directory_flags(),
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                return None
            os.set_inheritable(descriptor, False)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_dev != scope.parent_device
            ):
                raise ScopeError("lease cgroup has an unexpected owner, type, or device")
            if scope.created and (info.st_dev, info.st_ino) != (
                scope.scope_device,
                scope.scope_inode,
            ):
                raise ScopeError("lease cgroup inode identity changed")
            self._verify_scope_files(descriptor)
            identity = scope if scope.created else scope.with_scope_stat(info)
            return ScopeHandle(identity, descriptor)
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        finally:
            os.close(parent_fd)

    def _write_control(self, descriptor: int, name: str, value: bytes) -> None:
        flags = os.O_WRONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        target = os.open(name, flags, dir_fd=descriptor)
        try:
            view = memoryview(value)
            while view:
                written = os.write(target, view)
                if written <= 0:
                    raise ScopeError(f"short write to lease cgroup {name}")
                view = view[written:]
        finally:
            os.close(target)

    def attach(self, handle: ScopeHandle, child: ProcessIdentity) -> None:
        if not handle.identity.created or not process_matches(child):
            raise ScopeError("cannot attach a dead child or an uncreated lease scope")
        self._write_control(handle.descriptor, "cgroup.procs", f"{child.pid}\n".encode("ascii"))
        if not process_matches(child):
            raise ScopeError("child identity changed while entering its lease cgroup")
        expected = "/" + str(
            Path(handle.identity.scope_path).relative_to(self.mount_root)
        )
        if self._relative_cgroup(child.pid) != expected:
            raise ScopeError("child did not enter the exact lease cgroup")

    def _freeze_deadline(
        self, handle: ScopeHandle, timeout_seconds: float
    ) -> float:
        if type(timeout_seconds) not in (int, float) or timeout_seconds <= 0:
            raise ValueError("scope freeze timeout is invalid")
        if handle.descriptor < 0 or not handle.identity.created:
            raise ScopeError("cannot change freeze state without an exact live scope handle")
        return self._clock() + float(timeout_seconds)

    def _wait_frozen(self, handle: ScopeHandle, expected: str, deadline: float) -> None:
        while True:
            actual = self._events(handle.descriptor).get("frozen")
            if actual == expected:
                return
            remaining = deadline - self._clock()
            if remaining <= 0:
                action = "freeze" if expected == "1" else "thaw"
                raise ScopeError(f"lease cgroup did not acknowledge {action}")
            self._sleep(min(0.01, remaining))

    def freeze(self, handle: ScopeHandle, timeout_seconds: float) -> None:
        deadline = self._freeze_deadline(handle, timeout_seconds)
        if self._events(handle.descriptor).get("frozen") != "0":
            raise ScopeError("lease cgroup was already frozen before qualification")
        try:
            self._write_control(handle.descriptor, "cgroup.freeze", b"1\n")
            self._wait_frozen(handle, "1", deadline)
        except BaseException as primary:
            try:
                self._write_control(handle.descriptor, "cgroup.freeze", b"0\n")
                self._wait_frozen(handle, "0", deadline)
            except BaseException as rollback:
                raise ScopeResidueError(
                    "lease cgroup freeze failed and rollback was uncertain"
                ) from rollback
            raise primary

    def thaw(self, handle: ScopeHandle, timeout_seconds: float) -> None:
        deadline = self._freeze_deadline(handle, timeout_seconds)
        if self._events(handle.descriptor).get("frozen") != "1":
            raise ScopeError("lease cgroup was not frozen by the qualification guard")
        self._write_control(handle.descriptor, "cgroup.freeze", b"0\n")
        try:
            self._wait_frozen(handle, "0", deadline)
        except BaseException as exc:
            raise ScopeResidueError("lease cgroup thaw was uncertain") from exc

    def _read_control(
        self,
        descriptor: int,
        name: str,
        maximum: int,
        *,
        deadline_monotonic_ns: int | None = None,
    ) -> str:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        target = os.open(name, flags, dir_fd=descriptor)
        try:
            info = os.fstat(target)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise ScopeError(f"unsafe lease cgroup control file: {name}")
            chunks: list[bytes] = []
            total = 0
            while True:
                if (
                    deadline_monotonic_ns is not None
                    and time.monotonic_ns() >= deadline_monotonic_ns
                ):
                    raise ScopeError(
                        "qualification scope inspection deadline expired"
                    )
                chunk = os.read(target, min(16_384, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    raise ScopeError(f"oversized lease cgroup control file: {name}")
        finally:
            os.close(target)
        try:
            return b"".join(chunks).decode("ascii")
        except UnicodeDecodeError as exc:
            raise ScopeError(
                f"non-ASCII lease cgroup control file: {name}"
            ) from exc

    @staticmethod
    def _proc_tcp_endpoint(host: str, port: int) -> tuple[str, str]:
        if type(host) is not str or type(port) is not int or not 1 <= port <= 65_535:
            raise ScopeError("qualification TCP endpoint is invalid")
        try:
            packed = socket.inet_pton(socket.AF_INET, host)
        except OSError:
            try:
                packed = socket.inet_pton(socket.AF_INET6, host)
            except OSError as exc:
                raise ScopeError(
                    "qualification TCP endpoint is not numeric"
                ) from exc
            encoded = b"".join(
                packed[index : index + 4][::-1]
                for index in range(0, len(packed), 4)
            ).hex().upper()
            table = "tcp6"
        else:
            encoded = packed[::-1].hex().upper()
            table = "tcp"
        return f"{encoded}:{port:04X}", table

    def tcp_connection_inode(
        self,
        client_host: str,
        client_port: int,
        frontend_host: str,
        frontend_port: int,
        deadline_monotonic_ns: int,
    ) -> int | None:
        if (
            type(deadline_monotonic_ns) is not int
            or deadline_monotonic_ns <= time.monotonic_ns()
        ):
            raise ScopeError("qualification TCP ownership deadline expired")
        local, local_table = self._proc_tcp_endpoint(client_host, client_port)
        remote, remote_table = self._proc_tcp_endpoint(
            frontend_host, frontend_port
        )
        if local_table != remote_table:
            raise ScopeError("qualification TCP endpoint families differ")
        try:
            text = _read_bounded(
                self.proc_root / "net" / local_table,
                16_777_216,
                deadline_monotonic_ns=deadline_monotonic_ns,
            )
        except OSError as exc:
            raise ScopeError("cannot inspect qualification TCP ownership") from exc
        matches: set[int] = set()
        for line in text.splitlines()[1:]:
            if time.monotonic_ns() >= deadline_monotonic_ns:
                raise ScopeError("qualification TCP ownership deadline expired")
            fields = line.split()
            if len(fields) < 10:
                raise ScopeError("malformed kernel TCP ownership record")
            if fields[1] != local or fields[2] != remote or fields[3] != "01":
                continue
            if not fields[9].isdecimal() or int(fields[9]) < 1:
                raise ScopeError("kernel TCP ownership inode is invalid")
            matches.add(int(fields[9]))
        if len(matches) > 1:
            raise ScopeError("qualification TCP endpoint identity is ambiguous")
        return next(iter(matches), None)

    def _scope_processes(
        self,
        handle: ScopeHandle,
        deadline_monotonic_ns: int,
    ) -> tuple[int, ...]:
        if (
            type(deadline_monotonic_ns) is not int
            or deadline_monotonic_ns <= time.monotonic_ns()
        ):
            raise ScopeError("qualification scope inspection deadline expired")
        if handle.descriptor < 0 or not handle.identity.created:
            raise ScopeError("qualification scope handle is not exact-live")
        if self._events(handle.descriptor).get("frozen") != "1":
            raise ScopeError("qualification TCP ownership requires a frozen scope")
        text = self._read_control(
            handle.descriptor,
            "cgroup.procs",
            1_048_576,
            deadline_monotonic_ns=deadline_monotonic_ns,
        )
        values = text.split()
        if (
            not values
            or len(values) > 4_096
            or any(not value.isdecimal() or int(value) < 1 for value in values)
        ):
            raise ScopeError("qualification scope process inventory is invalid")
        processes = tuple(int(value) for value in values)
        if len(processes) != len(set(processes)):
            raise ScopeError("qualification scope process inventory is duplicated")
        if time.monotonic_ns() >= deadline_monotonic_ns:
            raise ScopeError("qualification scope inspection deadline expired")
        return processes

    def frozen_socket_inodes(
        self,
        handle: ScopeHandle,
        deadline_monotonic_ns: int,
    ) -> frozenset[int]:
        """Return every socket inode held by one exact frozen lease cgroup."""

        before = self._scope_processes(handle, deadline_monotonic_ns)
        socket_inodes: set[int] = set()
        examined = 0
        for pid in before:
            if time.monotonic_ns() >= deadline_monotonic_ns:
                raise ScopeError("qualification descriptor inspection deadline expired")
            try:
                entries = list((self.proc_root / str(pid) / "fd").iterdir())
            except OSError as exc:
                raise ScopeError(
                    "cannot inspect a frozen qualification process descriptor set"
                ) from exc
            if len(entries) > 65_536:
                raise ScopeError(
                    "qualification process descriptor inventory is oversized"
                )
            for entry in entries:
                examined += 1
                if time.monotonic_ns() >= deadline_monotonic_ns:
                    raise ScopeError(
                        "qualification descriptor inspection deadline expired"
                    )
                if examined > 131_072:
                    raise ScopeError(
                        "qualification scope descriptor inventory is oversized"
                    )
                try:
                    target = os.readlink(entry)
                except OSError as exc:
                    raise ScopeError(
                        "qualification descriptor identity changed while frozen"
                    ) from exc
                match = re.fullmatch(r"socket:\[(\d+)\]", target)
                if match is not None:
                    inode = int(match.group(1))
                    if inode < 1:
                        raise ScopeError(
                            "qualification descriptor socket inode is invalid"
                        )
                    socket_inodes.add(inode)
        after = self._scope_processes(handle, deadline_monotonic_ns)
        if before != after:
            raise ScopeError(
                "qualification scope membership changed while frozen"
            )
        return frozenset(socket_inodes)

    def owns_tcp_connection(
        self,
        handle: ScopeHandle,
        client_host: str,
        client_port: int,
        frontend_host: str,
        frontend_port: int,
        deadline_monotonic_ns: int | None = None,
    ) -> bool:
        """Compatibility helper for one exact frozen-scope TCP ownership check."""

        deadline = (
            time.monotonic_ns() + 5_000_000_000
            if deadline_monotonic_ns is None
            else deadline_monotonic_ns
        )
        inode = self.tcp_connection_inode(
            client_host,
            client_port,
            frontend_host,
            frontend_port,
            deadline,
        )
        return (
            inode is not None
            and inode in self.frozen_socket_inodes(handle, deadline)
        )

    def _events(self, descriptor: int) -> dict[str, str]:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        target = os.open("cgroup.events", flags, dir_fd=descriptor)
        try:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(target, min(1_024, _MAX_EVENT_RECORD + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > _MAX_EVENT_RECORD:
                    raise ScopeError("oversized cgroup.events record")
            data = b"".join(chunks)
        finally:
            os.close(target)
        try:
            lines = data.decode("ascii").splitlines()
            result = dict(line.split(" ", 1) for line in lines)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ScopeError("malformed cgroup.events record") from exc
        if result.get("populated") not in {"0", "1"}:
            raise ScopeError("cgroup.events has no valid populated state")
        return result

    def _wait_empty(self, descriptor: int, deadline: float) -> bool:
        while True:
            if self._events(descriptor)["populated"] == "0":
                return True
            remaining = deadline - self._clock()
            if remaining <= 0:
                return False
            self._sleep(min(0.01, remaining))

    @staticmethod
    def _direct_exited(child: ProcessIdentity, pidfd: int | None) -> bool:
        if pidfd is not None:
            try:
                readable, _, _ = select.select([pidfd], [], [], 0)
                if readable:
                    return True
            except (OSError, ValueError):
                pass
        return not process_matches(child)

    @staticmethod
    def _signal_direct(pidfd: int | None, signum: int) -> None:
        if pidfd is None:
            return
        try:
            signal.pidfd_send_signal(pidfd, signum)
        except (AttributeError, ProcessLookupError, OSError):
            pass

    def _wait_direct_exit(
        self, child: ProcessIdentity, pidfd: int | None, deadline: float
    ) -> bool:
        while not self._direct_exited(child, pidfd):
            remaining = deadline - self._clock()
            if remaining <= 0:
                return False
            self._sleep(min(0.01, remaining))
        return True

    def _remove_nested(
        self,
        descriptor: int,
        scope: ScopeIdentity,
        deadline: float,
    ) -> None:
        seen = [0]

        def remove_from(directory_fd: int, depth: int) -> None:
            if self._clock() >= deadline:
                raise ScopeResidueError("lease cgroup hierarchy cleanup timed out")
            if depth > _LEASE_CGROUP_CLEANUP_MAX_DEPTH:
                raise ScopeResidueError("lease cgroup hierarchy depth exceeded")
            truncated = False
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        raise ScopeResidueError("lease cgroup hierarchy contains a symlink")
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    if seen[0] >= _LEASE_CGROUP_CLEANUP_MAX_DESCENDANTS:
                        truncated = True
                        break
                    seen[0] += 1
                    name = entry.name
                    if self._clock() >= deadline:
                        raise ScopeResidueError(
                            "lease cgroup hierarchy cleanup timed out"
                        )
                    flags = (
                        os.O_RDONLY
                        | os.O_DIRECTORY
                        | os.O_CLOEXEC
                        | getattr(os, "O_NOFOLLOW", 0)
                    )
                    child = os.open(name, flags, dir_fd=directory_fd)
                    try:
                        before = os.fstat(child)
                        if (
                            not stat.S_ISDIR(before.st_mode)
                            or before.st_dev != scope.parent_device
                            or before.st_uid != os.getuid()
                        ):
                            raise ScopeResidueError(
                                "lease cgroup descendant has an unsafe identity"
                            )
                        remove_from(child, depth + 1)
                        after = os.stat(
                            name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                        if (after.st_dev, after.st_ino) != (
                            before.st_dev,
                            before.st_ino,
                        ):
                            raise ScopeResidueError(
                                "lease cgroup descendant changed before removal"
                            )
                    finally:
                        os.close(child)
                    try:
                        os.rmdir(name, dir_fd=directory_fd)
                    except OSError as exc:
                        raise ScopeResidueError(
                            "lease cgroup descendant could not be removed"
                        ) from exc
            if truncated:
                # Preserve the durable record, but make bounded progress so a
                # subsequent recovery can converge on over-broad legacy residue.
                raise ScopeResidueError("lease cgroup hierarchy limit exceeded")

        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
        )
        readable = os.open(".", flags, dir_fd=descriptor)
        try:
            remove_from(readable, 0)
        finally:
            os.close(readable)

    def _remove(
        self,
        scope: ScopeIdentity,
        *,
        descriptor: int | None = None,
        deadline: float | None = None,
    ) -> None:
        if not scope.created:
            raise ScopeResidueError("cannot remove a lease cgroup without an inode identity")
        parent_fd = self._open_parent(scope)
        name = Path(scope.scope_path).name
        owned_descriptor = -1
        try:
            try:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise ScopeResidueError("lease cgroup name disappeared before rmdir") from exc
            if (
                not stat.S_ISDIR(info.st_mode)
                or (info.st_dev, info.st_ino) != (scope.scope_device, scope.scope_inode)
            ):
                raise ScopeResidueError(
                    "lease cgroup name no longer identifies the held exact scope"
                )
            if descriptor is None:
                owned_descriptor = os.open(
                    name,
                    self._directory_flags(),
                    dir_fd=parent_fd,
                )
                descriptor = owned_descriptor
            held = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(held.st_mode)
                or (held.st_dev, held.st_ino) != (scope.scope_device, scope.scope_inode)
                or (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino)
            ):
                raise ScopeResidueError(
                    "lease cgroup name no longer identifies the held exact scope"
                )
            self._remove_nested(
                descriptor,
                scope,
                self._clock() + 5.0 if deadline is None else deadline,
            )
            after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (after.st_dev, after.st_ino) != (held.st_dev, held.st_ino):
                raise ScopeResidueError(
                    "lease cgroup name changed after descendant cleanup"
                )
            os.rmdir(name, dir_fd=parent_fd)
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise ScopeResidueError("lease cgroup remained after rmdir")
        except OSError as exc:
            raise ScopeResidueError(f"cannot remove empty lease cgroup: {exc}") from exc
        finally:
            if owned_descriptor >= 0:
                os.close(owned_descriptor)
            os.close(parent_fd)

    def reconcile(
        self,
        scope: ScopeIdentity,
        phase: str,
        child: ProcessIdentity,
        pidfd: int | None,
        timeout_seconds: float,
        *,
        handle: ScopeHandle | None = None,
    ) -> None:
        if phase not in _PHASES:
            raise ScopeError("unsupported child scope recovery phase")
        if type(timeout_seconds) not in (int, float) or timeout_seconds <= 0:
            raise ValueError("scope cleanup timeout must be positive")
        owned_handle = False
        exact = handle
        if exact is None:
            exact = self._open_existing(scope)
            owned_handle = exact is not None
        try:
            if exact is None:
                was_live = not self._direct_exited(child, pidfd)
                if was_live:
                    self._signal_direct(pidfd, signal.SIGKILL)
                    deadline = self._clock() + float(timeout_seconds)
                    while not self._direct_exited(child, pidfd) and self._clock() < deadline:
                        self._sleep(0.01)
                if not self._direct_exited(child, pidfd):
                    raise ScopeResidueError("direct child remains alive without its lease cgroup")
                if was_live and phase != "PREPARED":
                    raise ScopeResidueError(
                        "created lease cgroup was absent while its direct child was live"
                    )
                return

            if scope.created and exact.identity != scope:
                raise ScopeError("opened lease cgroup differs from its durable identity")
            total_deadline = self._clock() + float(timeout_seconds)
            self._signal_direct(pidfd, signal.SIGTERM)
            grace = min(0.5, float(timeout_seconds) / 2)
            if not self._wait_empty(exact.descriptor, min(total_deadline, self._clock() + grace)):
                self._write_control(exact.descriptor, "cgroup.kill", b"1\n")
                if not self._wait_empty(exact.descriptor, total_deadline):
                    raise ScopeResidueError("lease cgroup remained populated after cgroup.kill")
            # PREPARED/SCOPE_CREATED can legitimately describe an empty scope
            # before the blocked PID was moved.  Proving the cgroup empty is not
            # sufficient in that crash window: also prove the exact direct child
            # exited before deleting its durable record.
            direct_was_live_outside = not self._direct_exited(child, pidfd)
            if direct_was_live_outside:
                self._signal_direct(pidfd, signal.SIGKILL)
                if not self._wait_direct_exit(child, pidfd, total_deadline):
                    raise ScopeResidueError(
                        "direct child remained alive after lease cgroup emptied"
                    )
            self._remove(
                exact.identity,
                descriptor=exact.descriptor,
                deadline=total_deadline,
            )
            if direct_was_live_outside and phase == "ATTACHED":
                raise ScopeResidueError(
                    "attached direct child was live outside its recorded lease cgroup"
                )
        finally:
            if owned_handle and exact is not None:
                exact.close()

    def force_kill(
        self,
        scope: ScopeIdentity,
        *,
        handle: ScopeHandle | None = None,
    ) -> None:
        owned_handle = False
        exact = handle
        if exact is None:
            exact = self._open_existing(scope)
            owned_handle = exact is not None
        try:
            if exact is None:
                if scope.created:
                    raise ScopeResidueError(
                        "exact lease cgroup disappeared before forced containment"
                    )
                return
            if scope.created and exact.identity != scope:
                raise ScopeError("opened lease cgroup differs from its durable identity")
            self._write_control(exact.descriptor, "cgroup.kill", b"1\n")
        finally:
            if owned_handle and exact is not None:
                exact.close()

    def release_current(
        self,
        scope: ScopeIdentity,
        timeout_seconds: float,
    ) -> None:
        if type(timeout_seconds) not in (int, float) or timeout_seconds <= 0:
            raise ValueError("scope cleanup timeout must be positive")
        exact = self._open_existing(scope)
        if exact is None:
            raise ScopeResidueError("current owner scope disappeared before release")
        try:
            expected_scope = "/" + str(
                Path(exact.identity.scope_path).relative_to(self.mount_root)
            )
            if self._relative_cgroup() != expected_scope:
                raise ScopeResidueError("current process is outside its recorded owner scope")
            parent_fd = self._open_parent(exact.identity)
            try:
                self._write_control(
                    parent_fd,
                    "cgroup.procs",
                    f"{os.getpid()}\n".encode("ascii"),
                )
            finally:
                os.close(parent_fd)
            expected_parent = "/" + str(
                Path(exact.identity.parent_path).relative_to(self.mount_root)
            )
            if self._relative_cgroup() != expected_parent:
                raise ScopeResidueError(
                    "current process did not enter its recorded owner-scope parent"
                )
            total_deadline = self._clock() + float(timeout_seconds)
            grace = min(0.5, float(timeout_seconds) / 2)
            grace_deadline = min(total_deadline, self._clock() + grace)
            if not self._wait_empty(exact.descriptor, grace_deadline):
                self._write_control(exact.descriptor, "cgroup.kill", b"1\n")
                if not self._wait_empty(exact.descriptor, total_deadline):
                    raise ScopeResidueError(
                        "owner scope remained populated after cgroup.kill"
                    )
            self._remove(
                exact.identity,
                descriptor=exact.descriptor,
                deadline=total_deadline,
            )
        finally:
            exact.close()


__all__ = [
    "LinuxCgroupV2Scope",
    "ProcessScopeBackend",
    "ScopeError",
    "ScopeHandle",
    "ScopeIdentity",
    "ScopeResidueError",
]
