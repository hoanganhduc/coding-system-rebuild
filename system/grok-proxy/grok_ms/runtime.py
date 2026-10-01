"""Secure durable runtime records and stable Linux process identities."""

from __future__ import annotations

from dataclasses import dataclass, replace
import errno
import os
from pathlib import Path
import re
import secrets
import select
import stat
from typing import Any, Mapping

from .contract import SCHEMA_VERSION, canonical_json_bytes
from .ipc import DEFAULT_MAX_PACKET_BYTES, ProtocolError, strict_json_loads


_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:+@-]{1,256}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_BOOT_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_FENCE_PHASES = {"BOOTSTRAPPING", "RECOVERING", "READY", "DRAINING"}
_INTENT_PHASES = {"PREPARED", "APPLIED", "CLEANED", "FAILED"}
_STAGED_JSON_RE = re.compile(
    r"^\.(?P<target>[A-Za-z0-9._:+@-]{1,300})\."
    r"(?P<nonce>[0-9a-f]{24})\.tmp$"
)


class RuntimeSecurityError(RuntimeError):
    """Raised when a runtime path has an unsafe owner, type, or mode."""


class FenceBusyError(RuntimeError):
    """Raised when a different owner epoch already has a durable fence."""


class IntentConflictError(RuntimeError):
    """Raised when an effect replay disagrees with its durable record."""


def _require_token(value: Any, path: str) -> str:
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        raise ValueError(f"{path}: invalid token")
    return value


def _require_int(value: Any, path: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{path}: expected integer in [{minimum}, {maximum}]")
    return value


def _require_exact_keys(
    value: Any, expected: set[str], path: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise ValueError(f"{path}: expected an object with string keys")
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{path}: keys differ; missing={sorted(expected - actual)!r}, "
            f"unexpected={sorted(actual - expected)!r}"
        )
    return value


def _validate_secure_directory(path: Path, *, mode: int = 0o700) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeSecurityError(f"runtime directory does not exist: {path}") from exc
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise RuntimeSecurityError(f"runtime path is not a real directory: {path}")
    if info.st_uid != os.getuid():
        raise RuntimeSecurityError(
            f"runtime directory {path} is owned by uid {info.st_uid}, expected {os.getuid()}"
        )
    actual_mode = stat.S_IMODE(info.st_mode)
    if actual_mode != mode:
        raise RuntimeSecurityError(
            f"runtime directory {path} mode is {actual_mode:04o}, expected {mode:04o}"
        )


def _create_secure_directory(path: Path, *, mode: int = 0o700) -> None:
    try:
        path.mkdir(mode=mode)
        os.chmod(path, mode, follow_symlinks=False)
    except FileExistsError:
        pass
    _validate_secure_directory(path, mode=mode)


def _open_secure_directory(path: Path) -> int:
    _validate_secure_directory(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise RuntimeSecurityError(f"runtime directory changed during open: {path}")
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeSecurityError(f"runtime directory mode changed during open: {path}")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write to durable runtime record")
        view = view[written:]


def _stage_json(directory_fd: int, filename: str, payload: Any) -> str:
    data = canonical_json_bytes(payload) + b"\n"
    if len(data) > DEFAULT_MAX_PACKET_BYTES:
        raise ValueError("durable runtime record exceeds the bounded record size")
    temporary = f".{filename}.{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, data)
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    os.close(descriptor)
    return temporary


def _discard_staged_json(
    directory: Path,
    *,
    allowed_target: re.Pattern[str],
) -> int:
    """Durably discard strict atomic-write temps under offline exclusion.

    Callers must already hold the writer's exclusion lock and prove that no
    live owner can still be staging a record. Unrecognized entries are left in
    place so the normal strict enumerator rejects them; recognized entries with
    unsafe identity are an explicit recovery failure, never silently removed.
    """

    descriptor = _open_secure_directory(directory)
    removed = 0
    changed = False
    try:
        for name in os.listdir(descriptor):
            match = _STAGED_JSON_RE.fullmatch(name)
            if match is None or allowed_target.fullmatch(match.group("target")) is None:
                continue
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                staged = os.open(name, flags, dir_fd=descriptor)
            except OSError as exc:
                raise RuntimeSecurityError(
                    f"cannot open staged runtime record {directory / name}: {exc}"
                ) from exc
            try:
                info = os.fstat(staged)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink not in {1, 2}
                ):
                    raise RuntimeSecurityError(
                        f"unsafe staged runtime record: {directory / name}"
                    )
                if info.st_nlink == 2:
                    target = match.group("target")
                    try:
                        final = os.open(target, flags, dir_fd=descriptor)
                    except OSError as exc:
                        raise RuntimeSecurityError(
                            f"staged runtime record has no exact final link: "
                            f"{directory / name}"
                        ) from exc
                    try:
                        final_info = os.fstat(final)
                        if (
                            not stat.S_ISREG(final_info.st_mode)
                            or final_info.st_uid != os.getuid()
                            or stat.S_IMODE(final_info.st_mode) != 0o600
                            or final_info.st_nlink != 2
                            or (final_info.st_dev, final_info.st_ino)
                            != (info.st_dev, info.st_ino)
                        ):
                            raise RuntimeSecurityError(
                                "staged runtime record final link changed identity: "
                                f"{directory / name}"
                            )
                    finally:
                        os.close(final)
            finally:
                os.close(staged)
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (current.st_dev, current.st_ino, current.st_nlink) != (
                info.st_dev,
                info.st_ino,
                info.st_nlink,
            ):
                raise RuntimeSecurityError(
                    f"staged runtime record changed before removal: {directory / name}"
                )
            os.unlink(name, dir_fd=descriptor)
            removed += 1
            changed = True
        if changed:
            os.fsync(descriptor)
        return removed
    finally:
        os.close(descriptor)


def _atomic_create_json(path: Path, payload: Any) -> bool:
    directory_fd = _open_secure_directory(path.parent)
    temporary = ""
    try:
        temporary = _stage_json(directory_fd, path.name, payload)
        try:
            os.link(
                temporary,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            return False
        finally:
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
        os.fsync(directory_fd)
        return True
    finally:
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _validate_regular_file(descriptor: int, path: Path) -> None:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeSecurityError(f"runtime record is not a regular file: {path}")
    if info.st_uid != os.getuid():
        raise RuntimeSecurityError(
            f"runtime record {path} is owned by uid {info.st_uid}, expected {os.getuid()}"
        )
    actual_mode = stat.S_IMODE(info.st_mode)
    if actual_mode != 0o600:
        raise RuntimeSecurityError(
            f"runtime record {path} mode is {actual_mode:04o}, expected 0600"
        )


def _read_secure_json(path: Path) -> dict[str, Any] | None:
    directory_fd = _open_secure_directory(path.parent)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        try:
            descriptor = os.open(path.name, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        try:
            _validate_regular_file(descriptor, path)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 16_384)
                if not chunk:
                    break
                total += len(chunk)
                if total > DEFAULT_MAX_PACKET_BYTES:
                    raise RuntimeSecurityError(f"runtime record is too large: {path}")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)
    try:
        return strict_json_loads(b"".join(chunks), DEFAULT_MAX_PACKET_BYTES)
    except ProtocolError as exc:
        raise RuntimeSecurityError(f"invalid runtime record {path}: {exc}") from exc


def _atomic_replace_json(path: Path, payload: Any) -> None:
    directory_fd = _open_secure_directory(path.parent)
    temporary = ""
    try:
        # Refuse to replace a link, device, wrong-owner file, or wrong-mode file.
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path.name, flags, dir_fd=directory_fd)
        try:
            _validate_regular_file(descriptor, path)
        finally:
            os.close(descriptor)
        temporary = _stage_json(directory_fd, path.name, payload)
        os.replace(
            temporary,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary = ""
        os.fsync(directory_fd)
    finally:
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _durable_unlink(path: Path) -> bool:
    directory_fd = _open_secure_directory(path.parent)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        try:
            descriptor = os.open(path.name, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            return False
        try:
            _validate_regular_file(descriptor, path)
        finally:
            os.close(descriptor)
        os.unlink(path.name, dir_fd=directory_fd)
        os.fsync(directory_fd)
        return True
    finally:
        os.close(directory_fd)


class SecureRuntime:
    """Verified per-user stable runtime root."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)

    def initialize(self) -> None:
        if not self.root.is_absolute():
            raise RuntimeSecurityError("runtime root must be an absolute path")
        _create_secure_directory(self.root)

    def verify(self) -> None:
        _validate_secure_directory(self.root)


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    start_ticks: int
    boot_id: str

    def __post_init__(self) -> None:
        _require_int(self.pid, "process.pid", 1, 2**31 - 1)
        _require_int(self.start_ticks, "process.start_ticks", 1, 2**63 - 1)
        if type(self.boot_id) is not str or _BOOT_ID_RE.fullmatch(self.boot_id) is None:
            raise ValueError("process.boot_id: invalid Linux boot ID")


def read_boot_id(
    path: str | os.PathLike[str] = "/proc/sys/kernel/random/boot_id",
) -> str:
    with open(path, "r", encoding="ascii") as handle:
        value = handle.read(128).strip().lower()
    if _BOOT_ID_RE.fullmatch(value) is None:
        raise ValueError("kernel boot_id has an invalid shape")
    return value


def _read_pid_state_and_start_ticks(
    pid: int,
    proc_root: str | os.PathLike[str] = "/proc",
) -> tuple[str, int]:
    _require_int(pid, "pid", 1, 2**31 - 1)
    path = Path(proc_root) / str(pid) / "stat"
    with path.open("r", encoding="ascii", errors="strict") as handle:
        record = handle.read(65_536)
    closing = record.rfind(")")
    if closing < 0 or closing + 2 > len(record):
        raise ValueError(f"malformed process stat record for pid {pid}")
    # Tokens after the command name begin at field 3 (state). starttime is field 22.
    fields = record[closing + 2 :].split()
    if len(fields) <= 19:
        raise ValueError(f"short process stat record for pid {pid}")
    state = fields[0]
    if len(state) != 1 or not state.isascii() or not state.isalpha():
        raise ValueError(f"invalid process state for pid {pid}")
    value = fields[19]
    if not value.isdecimal():
        raise ValueError(f"invalid process start time for pid {pid}")
    return (
        state,
        _require_int(int(value), "process.start_ticks", 1, 2**63 - 1),
    )


def read_pid_start_ticks(pid: int, proc_root: str | os.PathLike[str] = "/proc") -> int:
    return _read_pid_state_and_start_ticks(pid, proc_root)[1]


def current_process_identity() -> ProcessIdentity:
    pid = os.getpid()
    return ProcessIdentity(
        pid=pid,
        start_ticks=read_pid_start_ticks(pid),
        boot_id=read_boot_id(),
    )


def process_matches(identity: ProcessIdentity) -> bool:
    try:
        return (
            read_boot_id() == identity.boot_id
            and read_pid_start_ticks(identity.pid) == identity.start_ticks
        )
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError, ValueError):
        return False


def process_can_still_execute(identity: ProcessIdentity) -> bool:
    """Return whether an exact owner identity can still execute user code.

    ``process_matches`` deliberately remains a pure PID/start-time identity
    predicate: a zombie still has that identity and recovery may need a pidfd
    for it.  Bootstrap ownership gates need the narrower question answered
    here.  The state and start ticks come from one bounded ``/proc`` record;
    when pidfds are available, readability additionally proves that the exact
    process has exited even if its zombie record has not yet been reaped.
    Inspection failures after an identity match are treated conservatively as
    executable rather than granting recovery authority on uncertainty.
    """

    try:
        current_boot_id = read_boot_id()
    except (PermissionError, OSError, ValueError):
        return True
    if current_boot_id != identity.boot_id:
        return False
    try:
        state, start_ticks = _read_pid_state_and_start_ticks(identity.pid)
    except (FileNotFoundError, ProcessLookupError):
        return False
    except (PermissionError, OSError, ValueError):
        return True
    if start_ticks != identity.start_ticks:
        return False
    if state in {"Z", "X", "x"}:
        return False
    if not hasattr(os, "pidfd_open"):
        return True
    try:
        descriptor = os.pidfd_open(identity.pid, 0)
        os.set_inheritable(descriptor, False)
    except (ProcessLookupError, FileNotFoundError):
        return False
    except (PermissionError, OSError):
        return True
    try:
        try:
            current_boot_id = read_boot_id()
        except (PermissionError, OSError, ValueError):
            return True
        if current_boot_id != identity.boot_id:
            return False
        try:
            state, start_ticks = _read_pid_state_and_start_ticks(identity.pid)
        except (FileNotFoundError, ProcessLookupError):
            return False
        except (PermissionError, OSError, ValueError):
            return True
        if start_ticks != identity.start_ticks or state in {"Z", "X", "x"}:
            return False
        try:
            readable, _, _ = select.select([descriptor], [], [], 0)
        except (OSError, ValueError):
            return True
        return not readable
    finally:
        os.close(descriptor)


def pidfd_for_identity(identity: ProcessIdentity) -> int:
    if not hasattr(os, "pidfd_open"):
        raise RuntimeError("os.pidfd_open is unavailable")
    if not process_matches(identity):
        raise ProcessLookupError(identity.pid)
    descriptor = os.pidfd_open(identity.pid, 0)
    os.set_inheritable(descriptor, False)
    if not process_matches(identity):
        os.close(descriptor)
        raise ProcessLookupError(identity.pid)
    return descriptor


@dataclass(frozen=True, slots=True)
class FenceRecord:
    schema_version: int
    release_id: str
    owner_epoch: str
    pid: int
    pid_start_ticks: int
    boot_id: str
    phase: str

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("fence.schema_version: unsupported value")
        _require_token(self.release_id, "fence.release_id")
        _require_token(self.owner_epoch, "fence.owner_epoch")
        ProcessIdentity(self.pid, self.pid_start_ticks, self.boot_id)
        if self.phase not in _FENCE_PHASES:
            raise ValueError(f"fence.phase: unsupported value {self.phase!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "boot_id": self.boot_id,
            "owner_epoch": self.owner_epoch,
            "phase": self.phase,
            "pid": self.pid,
            "pid_start_ticks": self.pid_start_ticks,
            "release_id": self.release_id,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "FenceRecord":
        fields = {
            "schema_version",
            "release_id",
            "owner_epoch",
            "pid",
            "pid_start_ticks",
            "boot_id",
            "phase",
        }
        value = _require_exact_keys(value, fields, "fence")
        return cls(
            schema_version=_require_int(
                value["schema_version"], "fence.schema_version", 1, 2**31 - 1
            ),
            release_id=_require_token(value["release_id"], "fence.release_id"),
            owner_epoch=_require_token(value["owner_epoch"], "fence.owner_epoch"),
            pid=_require_int(value["pid"], "fence.pid", 1, 2**31 - 1),
            pid_start_ticks=_require_int(
                value["pid_start_ticks"], "fence.pid_start_ticks", 1, 2**63 - 1
            ),
            boot_id=value["boot_id"],
            phase=_require_token(value["phase"], "fence.phase"),
        )


class FenceStore:
    def __init__(self, runtime: SecureRuntime) -> None:
        runtime.verify()
        self.runtime = runtime
        self.path = runtime.root / "recovery.fence"

    def load(self) -> FenceRecord | None:
        value = _read_secure_json(self.path)
        if value is None:
            return None
        try:
            return FenceRecord.from_dict(value)
        except ValueError as exc:
            raise RuntimeSecurityError(f"invalid recovery fence: {exc}") from exc

    def publish(self, record: FenceRecord) -> bool:
        if _atomic_create_json(self.path, record.to_dict()):
            return True
        existing = self.load()
        if existing == record:
            return False
        raise FenceBusyError(
            "a different owner or recovery phase already holds the durable fence"
        )

    def clear(self, expected_owner_epoch: str) -> bool:
        _require_token(expected_owner_epoch, "expected_owner_epoch")
        existing = self.load()
        if existing is None:
            return False
        if existing.owner_epoch != expected_owner_epoch:
            raise FenceBusyError(
                f"fence belongs to epoch {existing.owner_epoch!r}, not {expected_owner_epoch!r}"
            )
        return _durable_unlink(self.path)


@dataclass(frozen=True, slots=True)
class EffectIntent:
    schema_version: int
    owner_epoch: str
    generation: int
    effect_id: str
    operation: str
    parameters_digest: str
    phase: str

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("intent.schema_version: unsupported value")
        _require_token(self.owner_epoch, "intent.owner_epoch")
        _require_int(self.generation, "intent.generation", 0, 2**63 - 1)
        _require_token(self.effect_id, "intent.effect_id")
        _require_token(self.operation, "intent.operation")
        if (
            type(self.parameters_digest) is not str
            or _DIGEST_RE.fullmatch(self.parameters_digest) is None
        ):
            raise ValueError("intent.parameters_digest: invalid SHA-256 digest")
        if self.phase not in _INTENT_PHASES:
            raise ValueError(f"intent.phase: unsupported value {self.phase!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "generation": self.generation,
            "operation": self.operation,
            "owner_epoch": self.owner_epoch,
            "parameters_digest": self.parameters_digest,
            "phase": self.phase,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "EffectIntent":
        fields = {
            "schema_version",
            "owner_epoch",
            "generation",
            "effect_id",
            "operation",
            "parameters_digest",
            "phase",
        }
        value = _require_exact_keys(value, fields, "intent")
        return cls(
            schema_version=_require_int(
                value["schema_version"], "intent.schema_version", 1, 2**31 - 1
            ),
            owner_epoch=_require_token(value["owner_epoch"], "intent.owner_epoch"),
            generation=_require_int(
                value["generation"], "intent.generation", 0, 2**63 - 1
            ),
            effect_id=_require_token(value["effect_id"], "intent.effect_id"),
            operation=_require_token(value["operation"], "intent.operation"),
            parameters_digest=value["parameters_digest"],
            phase=_require_token(value["phase"], "intent.phase"),
        )


class IntentStore:
    def __init__(self, runtime: SecureRuntime) -> None:
        runtime.verify()
        self.runtime = runtime
        self.directory = runtime.root / "intents"
        _create_secure_directory(self.directory)

    def path_for(self, effect_id: str) -> Path:
        _require_token(effect_id, "effect_id")
        return self.directory / f"{effect_id}.json"

    def load(self, effect_id: str) -> EffectIntent | None:
        value = _read_secure_json(self.path_for(effect_id))
        if value is None:
            return None
        try:
            record = EffectIntent.from_dict(value)
        except ValueError as exc:
            raise RuntimeSecurityError(f"invalid effect intent: {exc}") from exc
        if record.effect_id != effect_id:
            raise RuntimeSecurityError("effect intent filename and record ID disagree")
        return record

    def put(self, intent: EffectIntent) -> bool:
        path = self.path_for(intent.effect_id)
        if _atomic_create_json(path, intent.to_dict()):
            return True
        existing = self.load(intent.effect_id)
        if existing == intent:
            return False
        raise IntentConflictError(
            f"effect {intent.effect_id!r} replay disagrees with its durable intent"
        )

    def advance(self, effect_id: str, expected_phase: str, new_phase: str) -> bool:
        if expected_phase not in _INTENT_PHASES or new_phase not in _INTENT_PHASES:
            raise ValueError("unsupported intent phase")
        existing = self.load(effect_id)
        if existing is None:
            raise IntentConflictError(f"effect {effect_id!r} has no durable intent")
        if existing.phase == new_phase:
            return False
        if existing.phase != expected_phase:
            raise IntentConflictError(
                f"effect {effect_id!r} is in phase {existing.phase!r}, "
                f"expected {expected_phase!r}"
            )
        _atomic_replace_json(self.path_for(effect_id), replace(existing, phase=new_phase).to_dict())
        return True

    def delete(self, effect_id: str, *, require_phase: str = "CLEANED") -> bool:
        existing = self.load(effect_id)
        if existing is None:
            return False
        if existing.phase != require_phase:
            raise IntentConflictError(
                f"effect {effect_id!r} is in phase {existing.phase!r}, "
                f"expected {require_phase!r} before deletion"
            )
        return _durable_unlink(self.path_for(effect_id))


__all__ = [
    "EffectIntent",
    "FenceBusyError",
    "FenceRecord",
    "FenceStore",
    "IntentConflictError",
    "IntentStore",
    "ProcessIdentity",
    "RuntimeSecurityError",
    "SecureRuntime",
    "current_process_identity",
    "pidfd_for_identity",
    "process_can_still_execute",
    "process_matches",
    "read_boot_id",
    "read_pid_start_ticks",
]
