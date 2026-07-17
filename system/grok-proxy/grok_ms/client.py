"""Feature-on Grok wrapper client and child pre-exec ownership barrier."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass, replace
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
from typing import Any, Mapping, Sequence

from .config import (
    CommandKind,
    ConfigurationError,
    _release_id,
    build_contract,
    classify,
    resolve_model,
)
from .contract import (
    PROTOCOL_VERSION,
    SCHEMA_VERSION,
    RouteContract,
    qualification_route_profile_matches,
)
from .grok_exec import GrokExecutableError, VerifiedGrokExecutable
from .ipc import ProtocolError, SeqPacketConnection
from .detached_scope import DetachedScopeRecord, DetachedScopeStore
from .process_scope import LinuxCgroupV2Scope, ProcessScopeBackend, ScopeHandle
from .runtime import (
    ProcessIdentity,
    current_process_identity,
    pidfd_for_identity,
    process_can_still_execute,
    process_matches,
    read_boot_id,
    read_pid_start_ticks,
)
from .secure_files import SecureFileError, read_secure_json


class ClientError(RuntimeError):
    pass


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_RUNG_RE = re.compile(r"^(?:direct|iphone|vpn|home:[A-Za-z0-9._:+@-]{1,120})$")
_ROUTE_PROFILE_RE = re.compile(
    r"^(?:direct|iphone|vpn|auto|auto-no-direct|home:[A-Za-z0-9._:+@-]{1,120})$"
)
_GROK_RELEASE_RE = re.compile(r"^[A-Za-z0-9._:+@-]{1,128}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9._:+/@-]{1,128}$")
_CANARY_BINDINGS = (
    "GROK_RELEASE_CANARY_MODE",
    "GROK_RELEASE_CANARY_FD",
    "GROK_RELEASE_CANARY_RELEASE_ID",
    "GROK_RELEASE_RUNG_CANARY",
    "GROK_RELEASE_CANARY_RUNG",
    "GROK_RELEASE_CANARY_ROUTE_PROFILE",
    "GROK_RELEASE_CANARY_CONTRACT",
    "GROK_RELEASE_CANARY_GROK_RELEASE",
    "GROK_RELEASE_CANARY_KIND",
    "GROK_RELEASE_CANARY_MODEL",
    "GROK_RELEASE_CANARY_NONCE",
)
_DIRECT_QUALIFICATION_RECOVERY = "GROK_QUALIFICATION_DIRECT_RECOVERY"
_DIRECT_QUALIFICATION_BOOTSTRAP = "GROK_INTERNAL_DIRECT_QUALIFICATION"
_FRONTEND_RELEASE_LOCK_FD = "GROK_FRONTEND_RELEASE_LOCK_FD"
_SUPERVISOR_CHILDREN: list[subprocess.Popen[bytes]] = []


@dataclass(frozen=True, slots=True)
class _ProviderCanary:
    descriptor: int
    nonce: str


def _account_home() -> Path:
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError) as exc:
        raise ClientError(f"cannot resolve current account home: {exc}") from exc
    if not home.is_absolute():
        raise ClientError("current account home is not absolute")
    return home


def _home(env: Mapping[str, str]) -> Path:
    if env.get("GROK_TESTING") == "1":
        home = Path(env.get("HOME", str(_account_home())))
        if not home.is_absolute():
            raise ClientError("test HOME must be absolute")
        return home
    return _account_home()


def _grok_home(env: Mapping[str, str]) -> Path:
    fixed = _home(env) / ".grok"
    if env.get("GROK_TESTING") == "1" and "GROK_HOME" in env:
        selected = Path(env["GROK_HOME"])
        if not selected.is_absolute():
            raise ClientError("test GROK_HOME must be absolute")
        return selected
    return fixed


def _grok_bin(env: Mapping[str, str]) -> Path:
    selected = Path(env.get("GROK_BIN", str(_home(env) / ".local/bin/grok")))
    if not selected.is_absolute():
        raise ClientError("GROK_BIN must be an absolute path")
    return selected


def _remember_explicit_model(
    choice_path: Path,
    model_id: str,
    *,
    canary_active: bool,
) -> None:
    """Durably remember a user choice without letting qualification alter it."""

    if canary_active:
        return
    if choice_path.name != ".model.choice" or _MODEL_RE.fullmatch(model_id) is None:
        raise ClientError("cannot persist an invalid model choice")
    parent = choice_path.parent
    try:
        parent.mkdir(mode=0o700, parents=False, exist_ok=True)
        directory_fd = os.open(
            parent,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ClientError(f"cannot open the private model-choice directory: {exc}") from exc
    temporary = f".{choice_path.name}.tmp-{secrets.token_hex(16)}"
    descriptor = -1
    try:
        info = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & stat.S_IWOTH
        ):
            raise ClientError("private model-choice directory has an unsafe identity")
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        data = f"{model_id}\n".encode("ascii")
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise OSError("short write while persisting model choice")
            written += count
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary,
            choice_path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except ClientError:
        raise
    except OSError as exc:
        raise ClientError(f"cannot persist the private model choice: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(directory_fd)


def _execution_env(env: Mapping[str, str]) -> dict[str, str]:
    selected = dict(env)
    if env.get("GROK_TESTING") != "1":
        home = _account_home()
        selected["HOME"] = str(home)
        selected["GROK_HOME"] = str(home / ".grok")
        selected["XDG_STATE_HOME"] = str(home / ".local/state")
    return selected


def _state_home(env: Mapping[str, str]) -> Path:
    # The root broker derives the user fence from passwd(5).  Production must
    # use the same canonical location or XDG/HOME overrides could split the
    # user and privileged interlocks.  Tests may opt into an isolated seam.
    if env.get("GROK_TESTING") == "1":
        return Path(env.get("XDG_STATE_HOME", str(_home(env) / ".local/state")))
    return _account_home() / ".local/state"


def control_root(env: Mapping[str, str]) -> Path:
    return _state_home(env) / "grok-proxy/control"


def _secure_control_root(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ClientError(f"unsafe multi-session control directory: {path}")
    os.chmod(path, 0o700)


def _read_json(
    path: Path,
    maximum: int = 65_536,
    *,
    expected_mode: int = 0o600,
    expected_uid: int | None = None,
) -> dict[str, Any]:
    try:
        return read_secure_json(
            path,
            expected_uid=os.getuid() if expected_uid is None else expected_uid,
            expected_mode=expected_mode,
            maximum=maximum,
        )
    except (SecureFileError, OSError) as exc:
        raise ClientError(f"cannot read secure metadata {path}: {exc}") from exc


def _root_release_control(env: Mapping[str, str]) -> Path:
    fixed = Path("/var/lib/grok-proxy/release-control")
    if env.get("GROK_TESTING") != "1":
        return fixed
    value = env.get("GROK_TEST_ROOT_RELEASE_CONTROL")
    if value is None:
        return fixed
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ClientError("test root release-control path must be absolute")
    return candidate


def _release_root_uid(env: Mapping[str, str]) -> int:
    return os.getuid() if env.get("GROK_TESTING") == "1" else 0


def _release_gate(release_dir: Path, env: Mapping[str, str]) -> dict[str, Any]:
    """Refuse opt-in while install/rollback is mixed or not atomically selected."""

    user_control = _state_home(env) / "grok-proxy/release-control"
    root_control = _root_release_control(env)
    user_deny = user_control / "rollback-deny.json"
    root_deny = root_control / "rollback-deny.json"
    active_denies = tuple(
        path for path in (user_deny, root_deny) if path.exists() or path.is_symlink()
    )
    rung_canary_requested = env.get("GROK_RELEASE_RUNG_CANARY") == "1"
    if active_denies and not rung_canary_requested:
        raise ClientError(f"release switching is fenced by {active_denies[0]}")
    manifest_path = release_dir / "release.json"
    if not manifest_path.exists():
        raise ClientError("multi-session mode requires an atomically installed release")
    manifest = _read_json(
        manifest_path,
        maximum=1024 * 1024,
        expected_mode=0o444,
        expected_uid=_release_root_uid(env),
    )
    release_id = manifest.get("release_id")
    selected = _read_json(
        user_control / "selected-release.json",
        maximum=1024 * 1024,
        expected_mode=0o444,
    )
    root_selected = _read_json(
        root_control / "selected-release.json",
        maximum=1024 * 1024,
        expected_mode=0o444,
        expected_uid=_release_root_uid(env),
    )
    user_digest = root_selected.pop("user_selection_sha256", None)
    selected_bytes = (
        json.dumps(selected, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    if (
        type(release_id) is not str
        or selected.get("release_id") != release_id
        or selected.get("user_release_id") != release_id
        or selected.get("root_release_id") != release_id
        or selected.get("selection_phase") != "READY"
        or not isinstance(selected.get("qualified_rungs"), list)
        or user_digest != hashlib.sha256(selected_bytes).hexdigest()
        or root_selected != selected
    ):
        raise ClientError("wrapper and selected user/root releases are not coherent")
    if rung_canary_requested:
        if active_denies != (root_deny,):
            raise ClientError("rung canary lacks one exact root deny ledger")
        deny = _read_json(
            root_deny,
            maximum=65_536,
            expected_mode=0o444,
            expected_uid=_release_root_uid(env),
        )
        if (
            set(deny)
            != {"schema_version", "operation", "from_release", "to_release"}
            or deny.get("schema_version") != 1
            or deny.get("operation") != "canary"
            or deny.get("from_release") != release_id
            or deny.get("to_release") != release_id
            or _rung_canary_authorization(str(release_id), env) is None
        ):
            raise ClientError("rung canary deny/authentication is not exact")
    return selected


def _release_lock_fd(env: Mapping[str, str]) -> int:
    """Open and hold the fixed selection lock independently of the user gate."""

    expected_path = _root_release_control(env) / "install.lock"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(expected_path, flags)
        actual = os.fstat(descriptor)
    except OSError as exc:
        raise ClientError(f"cannot open fixed release lock: {exc}") from exc
    if (
        not stat.S_ISREG(actual.st_mode)
        or actual.st_uid != _release_root_uid(env)
        or stat.S_IMODE(actual.st_mode) != 0o644
    ):
        os.close(descriptor)
        raise ClientError("fixed release lock is unsafe")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


def _close_frontend_release_lock(env: dict[str, str]) -> None:
    """Consume the wrapper's admission lock after taking our own shared lock."""

    raw = env.pop(_FRONTEND_RELEASE_LOCK_FD, None)
    if raw is None:
        return
    if not raw.isascii() or not raw.isdecimal() or int(raw) < 3:
        raise ClientError("frontend release lock descriptor is invalid")
    descriptor = int(raw)
    expected_path = _root_release_control(env) / "install.lock"
    try:
        actual = os.fstat(descriptor)
        expected = expected_path.lstat()
    except OSError as exc:
        raise ClientError(f"cannot validate frontend release lock: {exc}") from exc
    if (
        not stat.S_ISREG(actual.st_mode)
        or not stat.S_ISREG(expected.st_mode)
        or expected.st_uid != _release_root_uid(env)
        or stat.S_IMODE(expected.st_mode) != 0o644
        or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise ClientError("frontend release lock is not the fixed selection lock")
    try:
        os.close(descriptor)
    except OSError as exc:
        raise ClientError(f"cannot close frontend release lock: {exc}") from exc


def _host_id() -> str:
    try:
        raw = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    except OSError as exc:
        raise ClientError(f"cannot read host identity: {exc}") from exc
    if re.fullmatch(r"[0-9a-f]{32}", raw) is None:
        raise ClientError("host machine identity is invalid")
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _canary_authorization(
    release_id: str,
    env: Mapping[str, str],
) -> tuple[dict[str, Any], str, str | None, str, str, str, int, str] | None:
    """Authenticate one release/rung canary without weakening its contract."""

    requested = env.get("GROK_RELEASE_RUNG_CANARY")
    if requested != "1":
        if any(name in env for name in _CANARY_BINDINGS):
            raise ClientError("incomplete rung canary authorization")
        return None
    raw_fd = env.get("GROK_RELEASE_CANARY_FD", "")
    if not raw_fd.isascii() or not raw_fd.isdecimal() or int(raw_fd) < 3:
        raise ClientError("rung canary descriptor is invalid")
    descriptor = int(raw_fd)
    root = _root_release_control(env)
    try:
        actual = os.fstat(descriptor)
        expected = (root / "canary-auth.lock").lstat()
    except OSError as exc:
        raise ClientError(f"cannot validate rung canary descriptor: {exc}") from exc
    if (
        not stat.S_ISREG(actual.st_mode)
        or not stat.S_ISREG(expected.st_mode)
        or actual.st_uid != _release_root_uid(env)
        or expected.st_uid != _release_root_uid(env)
        or stat.S_IMODE(actual.st_mode) != 0o600
        or stat.S_IMODE(expected.st_mode) != 0o600
        or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise ClientError("rung canary descriptor is not the fixed authorization")
    record = _read_json(
        root / "rung-canary.json",
        maximum=65_536,
        expected_mode=0o444,
        expected_uid=_release_root_uid(env),
    )
    fields = {
        "schema_version", "release_id", "host_id", "canary_kind", "rung",
        "contract_sha256", "grok_release_id", "model_id", "canary_nonce",
        "created_unix_ns", "route_profile",
    }
    canary_kind = env.get("GROK_RELEASE_CANARY_KIND")
    rung = env.get("GROK_RELEASE_CANARY_RUNG")
    contract_digest = env.get("GROK_RELEASE_CANARY_CONTRACT")
    grok_release = env.get("GROK_RELEASE_CANARY_GROK_RELEASE")
    model_id = env.get("GROK_RELEASE_CANARY_MODEL")
    canary_nonce = env.get("GROK_RELEASE_CANARY_NONCE")
    route_profile = env.get("GROK_RELEASE_CANARY_ROUTE_PROFILE")
    if (
        set(record) != fields
        or record.get("schema_version") != 4
        or record.get("release_id") != release_id
        or record.get("host_id") != _host_id()
        or canary_kind not in {"release", "rung"}
        or record.get("canary_kind") != canary_kind
        or type(rung) is not str
        or _RUNG_RE.fullmatch(rung) is None
        or record.get("rung") != rung
        or (
            canary_kind == "release"
            and (contract_digest is not None or record.get("contract_sha256") is not None)
        )
        or (
            canary_kind == "rung"
            and (
                type(contract_digest) is not str
                or _DIGEST_RE.fullmatch(contract_digest) is None
            )
        )
        or record.get("contract_sha256") != contract_digest
        or type(grok_release) is not str
        or _GROK_RELEASE_RE.fullmatch(grok_release) is None
        or record.get("grok_release_id") != grok_release
        or type(model_id) is not str
        or _MODEL_RE.fullmatch(model_id) is None
        or record.get("model_id") != model_id
        or type(canary_nonce) is not str
        or _DIGEST_RE.fullmatch(canary_nonce) is None
        or record.get("canary_nonce") != canary_nonce
        or type(route_profile) is not str
        or _ROUTE_PROFILE_RE.fullmatch(route_profile) is None
        or record.get("route_profile") != route_profile
        or type(record.get("created_unix_ns")) is not int
        or record.get("created_unix_ns", 0) <= 0
        or env.get("GROK_RELEASE_CANARY_MODE") != "1"
        or env.get("GROK_RELEASE_CANARY_RELEASE_ID") != release_id
    ):
        raise ClientError("release/rung canary authorization record is not exact")
    return (
        record,
        rung,
        contract_digest,
        grok_release,
        model_id,
        canary_kind,
        descriptor,
        route_profile,
    )


# Compatibility name retained for focused callers while the authorization
# record now covers both fixed release qualification and exact rung canaries.
_rung_canary_authorization = _canary_authorization


def _scrub_canary_bindings(env: dict[str, str]) -> None:
    for name in _CANARY_BINDINGS:
        env.pop(name, None)


def _close_canary_authorization(
    authorization: tuple[dict[str, Any], str, str | None, str, str, str, int, str],
    env: dict[str, str],
) -> None:
    descriptor = authorization[6]
    try:
        os.close(descriptor)
    except OSError as exc:
        raise ClientError(f"cannot close release/rung canary descriptor: {exc}") from exc
    finally:
        _scrub_canary_bindings(env)


def _prepare_canary_dispatch(
    classification: Any,
    release_dir: Path,
    env: dict[str, str],
) -> bool:
    """Authenticate every canary marker before command-class dispatch."""

    if _DIRECT_QUALIFICATION_BOOTSTRAP in env:
        raise ClientError(
            "GROK_INTERNAL_DIRECT_QUALIFICATION is reserved for authenticated dispatch"
        )
    direct_recovery = env.get(_DIRECT_QUALIFICATION_RECOVERY)
    if direct_recovery is not None and direct_recovery != "1":
        raise ClientError(
            "GROK_QUALIFICATION_DIRECT_RECOVERY must be the literal value 1"
        )
    if not any(name in env for name in _CANARY_BINDINGS):
        if direct_recovery is not None:
            raise ClientError(
                "direct qualification recovery lacks canary authorization"
            )
        return False
    release_id = _release_id(release_dir, env)
    authorization = _canary_authorization(release_id, env)
    if authorization is None:
        raise ClientError("incomplete rung canary authorization")
    if classification.kind in {
        CommandKind.USAGE,
        CommandKind.BARE,
        CommandKind.MAINTENANCE,
    }:
        _close_canary_authorization(authorization, env)
        raise ClientError("release/rung canary command class is forbidden")
    if classification.kind in {CommandKind.CONTROL, CommandKind.RECOVERY}:
        strict_direct = (
            classification.kind is CommandKind.RECOVERY
            and direct_recovery == "1"
            and authorization[5] == "release"
            and authorization[1] == "direct"
            and authorization[2] is None
            and authorization[7] == "direct"
        )
        if direct_recovery is not None and not strict_direct:
            _close_canary_authorization(authorization, env)
            env.pop(_DIRECT_QUALIFICATION_RECOVERY, None)
            raise ClientError(
                "direct qualification recovery authorization is mismatched"
            )
        try:
            # Re-read the selected release, exact root deny, and complete
            # authorization record immediately before a non-Grok dispatch.
            _release_gate(release_dir, env)
        except Exception:
            try:
                _close_canary_authorization(authorization, env)
            except ClientError:
                pass
            raise
        _close_canary_authorization(authorization, env)
        env.pop(_DIRECT_QUALIFICATION_RECOVERY, None)
        return strict_direct
    if classification.kind is not CommandKind.GATED:
        _close_canary_authorization(authorization, env)
        raise ClientError("unsupported release/rung canary command class")
    env.pop(_DIRECT_QUALIFICATION_RECOVERY, None)
    # Gated Grok admission revalidates, closes, and scrubs the capability in
    # _canary_rung after the exact immutable contract has been constructed.
    return False


def _canary_rung(
    contract: RouteContract,
    env: dict[str, str],
) -> tuple[str | None, _ProviderCanary | None]:
    authorization = _canary_authorization(contract.release_id, env)
    if authorization is None:
        return None, None
    (
        _record,
        rung,
        contract_digest,
        grok_release,
        model_id,
        canary_kind,
        descriptor,
        route_profile,
    ) = authorization
    valid = not (
        grok_release != contract.grok_release_id
        or model_id != contract.model_id
        or rung not in contract.ladder
        or not qualification_route_profile_matches(contract, route_profile, rung)
        or (canary_kind == "release" and (rung != "direct" or contract.ladder != ("direct",)))
        or (canary_kind == "rung" and contract_digest != contract.digest())
    )
    if not valid:
        _close_canary_authorization(authorization, env)
        raise ClientError("release/rung canary is not bound to this Grok/contract/rung")
    if canary_kind == "release":
        _close_canary_authorization(authorization, env)
        # Set only after exact FD-backed canary authentication.  Fixed direct
        # qualification must never enter warm singleton compatibility handoff,
        # because its root runner recovery is intentionally direct-only.
        env[_DIRECT_QUALIFICATION_BOOTSTRAP] = "1"
        return rung, None
    if rung == "direct":
        _close_canary_authorization(authorization, env)
        return rung, None
    try:
        os.set_inheritable(descriptor, False)
    except OSError as exc:
        _close_canary_authorization(authorization, env)
        raise ClientError("cannot contain provider canary descriptor") from exc
    _scrub_canary_bindings(env)
    return rung, _ProviderCanary(descriptor, str(_record["canary_nonce"]))


def _qualified_contract(
    contract: RouteContract,
    selection: Mapping[str, Any],
    env: dict[str, str],
) -> tuple[RouteContract, _ProviderCanary | None]:
    """Constrain the immutable ladder to externally promoted exact rungs."""

    canary_rung, provider_canary = _canary_rung(contract, env)
    if canary_rung is not None:
        eligible = (canary_rung,)
    else:
        records = selection.get("qualified_rungs")
        if not isinstance(records, list):
            raise ClientError("selected qualified rung set is invalid")
        allowed: set[str] = set()
        identities: set[tuple[str, str, str]] = set()
        contract_digest = contract.digest()
        for record in records:
            if not isinstance(record, dict) or set(record) != {
                "contract_sha256", "evidence_sha256", "grok_release_id", "rung"
            }:
                raise ClientError("selected qualified rung record has an unexpected shape")
            rung = record.get("rung")
            recorded_contract = record.get("contract_sha256")
            grok_release = record.get("grok_release_id")
            evidence = record.get("evidence_sha256")
            if (
                type(rung) is not str
                or _RUNG_RE.fullmatch(rung) is None
                or type(recorded_contract) is not str
                or _DIGEST_RE.fullmatch(recorded_contract) is None
                or type(grok_release) is not str
                or _GROK_RELEASE_RE.fullmatch(grok_release) is None
                or type(evidence) is not str
                or _DIGEST_RE.fullmatch(evidence) is None
            ):
                raise ClientError("selected qualified rung identity is invalid")
            identity = (rung, recorded_contract, grok_release)
            if identity in identities:
                raise ClientError("selected qualified rung identity is duplicated")
            identities.add(identity)
            if (
                recorded_contract == contract_digest
                and grok_release == contract.grok_release_id
                and rung in contract.ladder
            ):
                allowed.add(rung)
        eligible = tuple(rung for rung in contract.ladder if rung in allowed)
    if not eligible:
        raise ClientError(
            "no rung is externally promoted for this exact release/Grok/contract"
        )
    return replace(contract, ladder=eligible), provider_canary


def _ready_identity(
    value: dict[str, Any],
    *,
    provider_canary_nonce: str | None = None,
) -> ProcessIdentity:
    expected = {
        "schema_version", "protocol_version", "release_id", "owner_epoch",
        "pid", "pid_start_ticks", "boot_id", "socket",
    }
    if provider_canary_nonce is not None:
        expected.add("provider_canary_nonce")
    if set(value) != expected:
        raise ClientError("supervisor readiness record has an unexpected shape")
    if (
        provider_canary_nonce is not None
        and value.get("provider_canary_nonce") != provider_canary_nonce
    ):
        raise ClientError("supervisor readiness belongs to another provider canary")
    if value["schema_version"] != SCHEMA_VERSION or value["protocol_version"] != PROTOCOL_VERSION:
        raise ClientError("supervisor readiness version mismatch")
    try:
        return ProcessIdentity(value["pid"], value["pid_start_ticks"], value["boot_id"])
    except (TypeError, ValueError) as exc:
        raise ClientError(f"invalid supervisor identity: {exc}") from exc


def _connect(path: Path, timeout: float = 2.0) -> SeqPacketConnection:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    sock.settimeout(timeout)
    try:
        sock.connect(str(path))
    except Exception:
        sock.close()
        raise
    connection = SeqPacketConnection(sock)
    try:
        connection.verify_peer(expected_uid=os.getuid())
    except Exception:
        connection.close()
        raise
    # The timeout bounds only bootstrap/connect.  Registration may legitimately
    # spend the contract transition budget qualifying a route, and leaving the
    # two-second socket timeout installed aborts every real first admission.
    sock.settimeout(None)
    return connection


def _validate_ready(
    value: dict[str, Any],
    *,
    release_id: str,
    socket_path: Path,
    provider_canary_nonce: str | None = None,
) -> ProcessIdentity:
    identity = _ready_identity(
        value,
        provider_canary_nonce=provider_canary_nonce,
    )
    if value["release_id"] != release_id:
        raise ClientError("supervisor readiness release does not match the request")
    if value["socket"] != str(socket_path):
        raise ClientError("supervisor readiness names a different control socket")
    if not process_can_still_execute(identity):
        raise ClientError("supervisor readiness identity is not live")
    return identity


def _open_bounded_log(path: Path, maximum: int = 4 * 1024 * 1024) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ClientError(f"unsafe supervisor log: {path}")
        os.fchmod(descriptor, 0o600)
        if info.st_size > maximum:
            os.ftruncate(descriptor, 0)
            os.write(descriptor, b"[egress] previous supervisor log exceeded its bound and was dropped\n")
            os.fsync(descriptor)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _supervisor_env(env: Mapping[str, str], release_dir: Path) -> dict[str, str]:
    allowed_prefixes = (
        "GROK_", "VPNGATE_", "TAILSCALE_",
    )
    selected = {
        key: value
        for key, value in env.items()
        if key.startswith(allowed_prefixes)
        or key in {"HOME", "LANG", "LC_ALL", "XDG_STATE_HOME"}
    }
    selected["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    selected["GROK_MULTI_SESSION"] = "1"
    selected.pop(_DIRECT_QUALIFICATION_BOOTSTRAP, None)
    selected.pop(_FRONTEND_RELEASE_LOCK_FD, None)
    for name in _CANARY_BINDINGS:
        selected.pop(name, None)
    return selected


def _remaining(deadline: float, operation: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ClientError(f"supervisor bootstrap deadline expired during {operation}")
    return remaining


def _bootstrap_timeout(contract: RouteContract, requested: float) -> float:
    if requested <= 0:
        raise ValueError("requested bootstrap timeout must be positive")
    # Warm singleton cleanup is allowed a bounded 20 seconds in the supervisor;
    # retain contract stop budget plus margin without permitting an unbounded
    # client-side wait.
    return min(
        60.0,
        max(float(requested), contract.timeout_policy.stop_ms / 1_000 + 25.0),
    )


def _supervisor_argv(
    release_dir: Path,
    root: Path,
    contract: RouteContract,
    env: Mapping[str, str] | None = None,
    provider_canary: _ProviderCanary | None = None,
) -> list[str]:
    direct_qualification = (
        None if env is None else env.get(_DIRECT_QUALIFICATION_BOOTSTRAP)
    )
    if direct_qualification not in {None, "1"}:
        raise ClientError("internal direct qualification marker is invalid")
    argv = [
        "/usr/bin/python3",
        "-E",
        "-s",
        "-m",
        "grok_ms.supervisor",
        "--release-dir",
        str(release_dir),
        "--control-root",
        str(root),
        "--expected-contract",
        contract.digest(),
        "--expected-control-cap",
        str(contract.limits.max_control_connections),
        "--scoped-bootstrap",
    ]
    skip_handoff = bool(
        env is not None
        and (
            direct_qualification == "1"
            or (
                env.get("GROK_TESTING") == "1"
                and env.get("GROK_TEST_SKIP_WARM_HANDOFF") == "1"
            )
        )
    )
    if not skip_handoff:
        argv.append("--warm-legacy-handoff")
    if provider_canary is not None:
        if provider_canary.descriptor < 3:
            raise ClientError("provider canary descriptor is unsafe")
        argv.extend(
            ("--provider-canary-fd", str(provider_canary.descriptor))
        )
    return argv


@dataclass(slots=True)
class _SupervisorLaunch:
    process: subprocess.Popen[bytes]
    pidfd: int
    record: DetachedScopeRecord
    handle: ScopeHandle
    backend: ProcessScopeBackend
    store: DetachedScopeStore
    barrier_write: int
    transferred: bool = False

    def release(self) -> None:
        if self.barrier_write < 0:
            raise ClientError("supervisor bootstrap barrier was already released")
        if os.write(self.barrier_write, b"\x01") != 1:
            raise ClientError("short supervisor bootstrap barrier release")
        os.close(self.barrier_write)
        self.barrier_write = -1

    def transfer(self, owner_epoch: str) -> None:
        if self.transferred or self.barrier_write >= 0:
            raise ClientError("supervisor ownership transfer is out of order")
        owned = self.store.load("supervisor-epoch")
        if (
            owned is None
            or owned.phase != "OWNED"
            or owned.owner_epoch != owner_epoch
            or owned.release_id != self.record.release_id
            or owned.child != self.record.child
            or owned.scope != self.record.scope
        ):
            raise ClientError("supervisor did not durably accept scoped ownership")
        self.record = owned
        self.transferred = True
        self.handle.close()
        os.close(self.pidfd)
        self.pidfd = -1
        _SUPERVISOR_CHILDREN.append(self.process)

    def cleanup(self, timeout_seconds: float) -> None:
        if self.transferred:
            return
        if self.barrier_write >= 0:
            os.close(self.barrier_write)
            self.barrier_write = -1
        persisted = self.store.load("supervisor-epoch")
        if persisted is not None:
            if (
                persisted.release_id != self.record.release_id
                or persisted.child != self.record.child
                or persisted.scope != self.record.scope
            ):
                raise ClientError("supervisor scope authority changed during cleanup")
            self.record = persisted
        phase = "ATTACHED" if self.record.phase == "OWNED" else self.record.phase
        self.backend.reconcile(
            self.record.scope,
            phase,
            self.record.child,
            self.pidfd if self.pidfd >= 0 else None,
            timeout_seconds,
            handle=self.handle if self.handle.descriptor >= 0 else None,
        )
        self.handle.close()
        self.store.delete(self.record)
        if self.pidfd >= 0:
            os.close(self.pidfd)
            self.pidfd = -1
        try:
            self.process.wait(timeout=min(1.0, timeout_seconds))
        except subprocess.TimeoutExpired:
            pass


def _reconcile_stale_supervisor_scope(
    store: DetachedScopeStore,
    backend: ProcessScopeBackend,
    timeout_seconds: float,
) -> None:
    record = store.load("supervisor-epoch")
    if record is None:
        return
    if record.phase == "OWNED" and process_can_still_execute(record.child):
        raise ClientError("the scoped supervisor epoch is alive but not attachable")
    pidfd = -1
    if process_matches(record.child):
        try:
            pidfd = pidfd_for_identity(record.child)
        except (OSError, ProcessLookupError, RuntimeError) as exc:
            raise ClientError("cannot acquire the unowned supervisor scope") from exc
    try:
        backend.reconcile(
            record.scope,
            "ATTACHED" if record.phase == "OWNED" else record.phase,
            record.child,
            pidfd if pidfd >= 0 else None,
            timeout_seconds,
        )
        store.delete(record)
    except Exception as exc:
        raise ClientError("cannot reconcile the previous supervisor scope") from exc
    finally:
        if pidfd >= 0:
            os.close(pidfd)


def _spawn_scoped_supervisor(
    release_dir: Path,
    root: Path,
    contract: RouteContract,
    env: Mapping[str, str],
    log_fd: int,
    *,
    backend: ProcessScopeBackend,
    store: DetachedScopeStore,
    cleanup_seconds: float,
    provider_canary: _ProviderCanary | None = None,
) -> _SupervisorLaunch:
    parent = current_process_identity()
    planned = backend.plan()
    barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
    process: subprocess.Popen[bytes] | None = None
    identity: ProcessIdentity | None = None
    pidfd = -1
    handle: ScopeHandle | None = None
    record: DetachedScopeRecord | None = None
    try:
        guard = release_dir / "grok_ms" / "parent_guard.py"
        process = subprocess.Popen(
            [
                sys.executable,
                str(guard),
                "--parent-pid",
                str(parent.pid),
                "--parent-start-ticks",
                str(parent.start_ticks),
                "--parent-boot-id",
                parent.boot_id,
                "--barrier-fd",
                str(barrier_read),
                "--",
                *_supervisor_argv(
                    release_dir,
                    root,
                    contract,
                    env,
                    provider_canary,
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=log_fd,
            stderr=log_fd,
            close_fds=True,
            pass_fds=(
                (barrier_read,)
                if provider_canary is None
                else (barrier_read, provider_canary.descriptor)
            ),
            # Installer canaries contain their wrapper's entire session before
            # reaping it.  The shared supervisor has separate pidfd+cgroup
            # authority and must not be a member of that per-wrapper session.
            start_new_session=True,
            env=_supervisor_env(env, release_dir),
            cwd=release_dir,
        )
        os.close(barrier_read)
        barrier_read = -1
        identity = ProcessIdentity(
            process.pid,
            read_pid_start_ticks(process.pid),
            parent.boot_id,
        )
        pidfd = pidfd_for_identity(identity)
        record = DetachedScopeRecord(
            schema_version=SCHEMA_VERSION,
            record_version=1,
            release_id=contract.release_id,
            kind="supervisor-epoch",
            phase="PREPARED",
            owner_epoch=None,
            child=identity,
            scope=planned,
        )
        store.put(record)
        handle = backend.create(planned)
        created = record.with_phase("SCOPE_CREATED", scope=handle.identity)
        store.replace(record, created)
        record = created
        backend.attach(handle, identity)
        attached = record.with_phase("ATTACHED")
        store.replace(record, attached)
        record = attached
        launch = _SupervisorLaunch(
            process,
            pidfd,
            record,
            handle,
            backend,
            store,
            barrier_write,
        )
        barrier_write = -1
        launch.release()
        return launch
    except BaseException as primary:
        cleanup_error: BaseException | None = None
        if barrier_write >= 0:
            os.close(barrier_write)
            barrier_write = -1
        if record is not None and identity is not None:
            try:
                backend.reconcile(
                    record.scope,
                    record.phase,
                    identity,
                    pidfd if pidfd >= 0 else None,
                    cleanup_seconds,
                    handle=handle,
                )
                if handle is not None:
                    handle.close()
                handle = None
                store.delete(record)
            except BaseException as exc:
                cleanup_error = exc
        elif process is not None:
            try:
                if pidfd >= 0:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=cleanup_seconds)
            except BaseException as exc:
                cleanup_error = exc
        if handle is not None:
            handle.close()
        if pidfd >= 0:
            os.close(pidfd)
        if cleanup_error is not None:
            raise ClientError(
                "failed supervisor bootstrap could not be contained"
            ) from cleanup_error
        raise ClientError("cannot establish scoped supervisor bootstrap") from primary
    finally:
        if barrier_read >= 0:
            os.close(barrier_read)


def _validate_owned_supervisor_scope(
    store: DetachedScopeStore,
    ready: Mapping[str, Any],
    release_id: str,
    *,
    provider_canary_nonce: str | None = None,
) -> DetachedScopeRecord:
    record = store.load("supervisor-epoch")
    identity = _ready_identity(
        dict(ready),
        provider_canary_nonce=provider_canary_nonce,
    )
    if (
        record is None
        or record.phase != "OWNED"
        or record.release_id != release_id
        or record.owner_epoch != ready.get("owner_epoch")
        or record.child != identity
    ):
        raise ClientError("supervisor readiness lacks exact scoped authority")
    return record


def ensure_supervisor(
    release_dir: Path,
    contract: RouteContract,
    env: Mapping[str, str],
    *,
    start_timeout: float = 15.0,
    process_scopes: ProcessScopeBackend | None = None,
    detached_store: DetachedScopeStore | None = None,
    provider_canary: _ProviderCanary | None = None,
) -> SeqPacketConnection:
    start_timeout = _bootstrap_timeout(contract, start_timeout)
    deadline = time.monotonic() + start_timeout
    root = control_root(env)
    _secure_control_root(root)
    backend = process_scopes or LinuxCgroupV2Scope()
    store = detached_store or DetachedScopeStore(root)
    cleanup_seconds = min(
        30.0,
        max(1.0, contract.timeout_policy.stop_ms / 1_000),
    )
    lock_fd = os.open(root / "bootstrap.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    locked = False
    try:
        os.fchmod(lock_fd, 0o600)
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError:
                remaining = _remaining(deadline, "bootstrap lock")
                time.sleep(min(0.05, remaining))
        socket_path = root / "supervisor.sock"
        ready_path = root / "supervisor.ready"
        existing_connection: SeqPacketConnection | None = None
        try:
            existing_connection = _connect(
                socket_path,
                timeout=min(2.0, _remaining(deadline, "existing supervisor connect")),
            )
            ready = _read_json(ready_path)
            _validate_ready(
                ready,
                release_id=contract.release_id,
                socket_path=socket_path,
                provider_canary_nonce=(
                    None if provider_canary is None else provider_canary.nonce
                ),
            )
            _validate_owned_supervisor_scope(
                store,
                ready,
                contract.release_id,
                provider_canary_nonce=(
                    None if provider_canary is None else provider_canary.nonce
                ),
            )
            return existing_connection
        except (FileNotFoundError, ConnectionRefusedError, TimeoutError, OSError, ProtocolError):
            if existing_connection is not None:
                existing_connection.close()
            pass
        except ClientError:
            if existing_connection is not None:
                existing_connection.close()
            raise

        # Never unlink an ownership-looking socket until the recorded process is
        # proved dead.  A live-but-unresponsive epoch is recovery work.
        if ready_path.exists() or ready_path.is_symlink():
            ready = _read_json(ready_path)
            identity = _ready_identity(
                ready,
                provider_canary_nonce=(
                    None if provider_canary is None else provider_canary.nonce
                ),
            )
            if process_can_still_execute(identity):
                raise ClientError("the recorded supervisor is alive but not attachable")
            recorded_socket = ready.get("socket")
            if recorded_socket != str(socket_path):
                raise ClientError("stale readiness record names a different socket")
            ready_path.unlink()
            if socket_path.exists() or socket_path.is_symlink():
                socket_path.unlink()
        elif socket_path.exists() or socket_path.is_symlink():
            raise ClientError("unowned supervisor socket requires gated recovery")

        _reconcile_stale_supervisor_scope(store, backend, cleanup_seconds)
        if store.load("compatibility-handoff") is not None:
            raise ClientError(
                "a compatibility handoff scope requires gated recovery"
            )

        log_path = root / "supervisor.log"
        log_fd = _open_bounded_log(log_path)
        launch: _SupervisorLaunch | None = None
        try:
            launch = _spawn_scoped_supervisor(
                release_dir,
                root,
                contract,
                env,
                log_fd,
                backend=backend,
                store=store,
                cleanup_seconds=cleanup_seconds,
                provider_canary=provider_canary,
            )
        finally:
            os.close(log_fd)
        last_error: Exception | None = None
        assert launch is not None
        try:
            while time.monotonic() < deadline:
                if launch.process.poll() is not None:
                    raise ClientError(
                        f"supervisor exited during bootstrap: {launch.process.returncode}"
                    )
                connection: SeqPacketConnection | None = None
                try:
                    connection = _connect(
                        socket_path,
                        timeout=min(0.5, _remaining(deadline, "supervisor connect")),
                    )
                    ready = _read_json(ready_path)
                    _validate_ready(
                        ready,
                        release_id=contract.release_id,
                        socket_path=socket_path,
                        provider_canary_nonce=(
                            None
                            if provider_canary is None
                            else provider_canary.nonce
                        ),
                    )
                    if _ready_identity(
                        ready,
                        provider_canary_nonce=(
                            None
                            if provider_canary is None
                            else provider_canary.nonce
                        ),
                    ) != launch.record.child:
                        raise ClientError(
                            "supervisor readiness differs from the scoped launch"
                        )
                    owner_epoch = ready.get("owner_epoch")
                    if type(owner_epoch) is not str:
                        raise ClientError("supervisor readiness owner is invalid")
                    launch.transfer(owner_epoch)
                    return connection
                except (
                    FileNotFoundError,
                    ConnectionRefusedError,
                    TimeoutError,
                    OSError,
                    ProtocolError,
                    ClientError,
                ) as exc:
                    if connection is not None:
                        connection.close()
                    last_error = exc
                    remaining = deadline - time.monotonic()
                    if remaining > 0:
                        time.sleep(min(0.05, remaining))
            raise ClientError(f"supervisor did not become ready: {last_error}")
        except BaseException as primary:
            try:
                launch.cleanup(cleanup_seconds)
            except BaseException as cleanup:
                raise ClientError(
                    "supervisor bootstrap failed and scoped cleanup was uncertain"
                ) from cleanup
            raise primary
    finally:
        if locked:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _request(
    connection: SeqPacketConnection,
    payload: dict[str, Any],
    *,
    fds: Sequence[int] = (),
) -> dict[str, Any]:
    connection.send(payload, fds)
    response = connection.recv().payload
    if response.get("ok") is not True:
        raise ClientError(str(response.get("error", "supervisor rejected request")))
    return response


def _pidfd_signal(pidfd: int, signum: int) -> None:
    try:
        signal.pidfd_send_signal(pidfd, signum)
    except (AttributeError, OSError):
        pass


def run_owned_child(
    connection: SeqPacketConnection,
    registration: dict[str, Any],
    grok: VerifiedGrokExecutable,
    grok_argv: Sequence[str],
    model_id: str,
    model_was_explicit: bool,
    env: Mapping[str, str],
) -> int:
    grok.verify()
    lease_id = registration["lease_id"]
    owner_epoch = registration["owner_epoch"]
    leader_path = registration["leader_path"]
    endpoint = registration["public_endpoint"]
    if (
        type(lease_id) is not str
        or type(owner_epoch) is not str
        or type(leader_path) is not str
        or type(endpoint) is not dict
        or endpoint.get("host") != "127.0.0.1"
        or type(endpoint.get("port")) is not int
    ):
        raise ClientError("invalid registration response")
    read_barrier, write_barrier = os.pipe2(os.O_CLOEXEC)
    wrapper_pid = os.getpid()
    child_pid = os.fork()
    if child_pid == 0:
        try:
            os.close(write_barrier)
            # If the wrapper disappears before or after the supervisor ACK,
            # make the directly owned Grok child fail closed even before the
            # supervisor observes control EOF.  Recheck PPID to close the small
            # race between fork and prctl.
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
                os._exit(125)
            if os.getppid() != wrapper_pid:
                os._exit(125)
            allowed = os.read(read_barrier, 1)
            os.close(read_barrier)
            if allowed != b"1":
                os._exit(125)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            signal.signal(signal.SIGQUIT, signal.SIG_DFL)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            child_env = dict(env)
            child_env.pop(_DIRECT_QUALIFICATION_BOOTSTRAP, None)
            for name in (
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy",
            ):
                child_env.pop(name, None)
            proxy = f"socks5h://127.0.0.1:{endpoint['port']}"
            no_proxy = "localhost,127.0.0.1,::1,100.64.0.0/10,.ts.net"
            child_env.update({"ALL_PROXY": proxy, "NO_PROXY": no_proxy, "no_proxy": no_proxy})
            argv = [
                str(grok.path),
                "--no-leader",
                "--leader-socket",
                leader_path,
            ]
            if not model_was_explicit:
                argv.extend(("-m", model_id))
            argv.extend(grok_argv)
            grok.exec(argv, child_env)
        except BaseException:
            os._exit(126)

    os.close(read_barrier)
    try:
        pidfd = os.pidfd_open(child_pid, 0)
    except BaseException:
        os.close(write_barrier)
        try:
            os.kill(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(child_pid, 0)
        raise
    os.set_inheritable(pidfd, False)
    try:
        identity = {
            "pid": child_pid,
            "pid_start_ticks": read_pid_start_ticks(child_pid),
            "boot_id": read_boot_id(),
        }
        _request(
            connection,
            {
                "type": "attach-child",
                "schema_version": SCHEMA_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "owner_epoch": owner_epoch,
                "lease_id": lease_id,
                "request_id": str(uuid.uuid4()),
                "child": identity,
            },
            fds=(pidfd,),
        )
        qualification_hold = env.get("GROK_QUALIFICATION_CHILD_HOLD_FD")
        if qualification_hold is not None:
            if not qualification_hold.isdecimal():
                raise ClientError("qualification child hold descriptor is invalid")
            hold_fd = int(qualification_hold)
            if hold_fd < 3:
                raise ClientError("qualification child hold descriptor is unsafe")
            try:
                hold_info = os.fstat(hold_fd)
                if not stat.S_ISFIFO(hold_info.st_mode):
                    raise ClientError(
                        "qualification child hold descriptor is not a pipe"
                    )
                allowed = os.read(hold_fd, 1)
            finally:
                os.close(hold_fd)
            if allowed != b"1":
                raise ClientError("qualification child hold was not released")
        os.write(write_barrier, b"1")
    except BaseException:
        _pidfd_signal(pidfd, signal.SIGKILL)
        os.close(write_barrier)
        write_barrier = -1
        try:
            os.waitpid(child_pid, 0)
        except ChildProcessError:
            pass
        os.close(pidfd)
        raise
    finally:
        if write_barrier >= 0:
            os.close(write_barrier)

    old_term = signal.getsignal(signal.SIGTERM)
    old_int = signal.getsignal(signal.SIGINT)
    old_quit = signal.getsignal(signal.SIGQUIT)
    signal.signal(signal.SIGTERM, lambda _s, _f: _pidfd_signal(pidfd, signal.SIGTERM))
    signal.signal(signal.SIGINT, lambda _s, _f: None)
    signal.signal(signal.SIGQUIT, lambda _s, _f: None)
    try:
        while True:
            waited, status = os.waitpid(child_pid, os.WNOHANG)
            if waited == child_pid:
                if os.WIFEXITED(status):
                    result = os.WEXITSTATUS(status)
                elif os.WIFSIGNALED(status):
                    result = 128 + os.WTERMSIG(status)
                else:
                    continue
                try:
                    _request(
                        connection,
                        {
                            "type": "release",
                            "schema_version": SCHEMA_VERSION,
                            "protocol_version": PROTOCOL_VERSION,
                            "owner_epoch": owner_epoch,
                            "lease_id": lease_id,
                            "request_id": str(uuid.uuid4()),
                            "child_status": result,
                        },
                    )
                except (ClientError, ProtocolError, OSError):
                    pass
                return result
            readable, _, _ = select.select([connection.socket], [], [], 0.2)
            if readable:
                try:
                    event = connection.recv().payload
                except (ProtocolError, OSError):
                    _pidfd_signal(pidfd, signal.SIGTERM)
                    time.sleep(0.5)
                    _pidfd_signal(pidfd, signal.SIGKILL)
                    os.waitpid(child_pid, 0)
                    raise ClientError("supervisor control EOF terminated the Grok child")
                if event.get("type") == "terminate":
                    _pidfd_signal(pidfd, signal.SIGTERM)
    finally:
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGQUIT, old_quit)
        os.close(pidfd)


def _bare_exec(grok_bin: Path, argv: Sequence[str], env: Mapping[str, str]) -> None:
    with VerifiedGrokExecutable.open(grok_bin) as grok:
        grok.exec([str(grok.path), *argv], env)


def _maintenance(
    classification_argv: Sequence[str], release_dir: Path, env: Mapping[str, str]
) -> None:
    root = control_root(env)
    socket_path = root / "supervisor.sock"
    if socket_path.exists() or socket_path.is_symlink():
        raise ClientError("maintenance is refused while a multi-session epoch owns the egress")
    legacy_env = dict(env)
    legacy_env["GROK_MULTI_SESSION"] = "0"
    wrapper = release_dir / "grok-remote"
    os.execvpe(str(wrapper), [str(wrapper), *classification_argv], legacy_env)


def _control(command: str, env: Mapping[str, str]) -> int:
    root = control_root(env)
    socket_path = root / "supervisor.sock"
    try:
        connection = _connect(socket_path)
    except (FileNotFoundError, ConnectionRefusedError, OSError, ProtocolError):
        residue = _inactive_residue(root)
        if residue is not None:
            print(
                f"[egress] recovery required before multi-session use: {residue}",
                file=sys.stderr,
            )
            return 2
        print("[egress] no multi-session supervisor is active", file=sys.stderr)
        return 0 if command == "status" else 1
    try:
        response = _request(
            connection,
            {
                "type": command,
                "schema_version": SCHEMA_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "request_id": str(uuid.uuid4()),
            },
        )
    finally:
        connection.close()
    if command == "ip":
        print(response.get("egress_ip", ""))
    else:
        print(json.dumps(response.get("status", {}), sort_keys=True))
    return 0


def _inactive_residue(root: Path) -> str | None:
    fence = root / "recovery.fence"
    if fence.exists() or fence.is_symlink():
        try:
            _read_json(fence)
        except ClientError as exc:
            return f"unsafe recovery fence ({exc})"
        return "a durable recovery fence is present"
    for directory, label in (
        (root / "p", "provider workspace"),
        (root / "qualify", "qualification workspace"),
        (root / "intents", "effect intent"),
        (root / "leaders", "leader"),
        (root / "recovery" / "providers", "provider recovery record"),
        (root / "recovery" / "children", "child recovery record"),
        (root / "recovery" / "probes", "probe recovery record"),
        (root / "recovery" / "provider-scopes", "provider command scope record"),
        (root / "recovery" / "detached-scopes", "detached process scope record"),
    ):
        if not directory.exists() and not directory.is_symlink():
            continue
        try:
            info = directory.lstat()
            if (
                directory.is_symlink()
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                return f"unsafe {label} path"
            if any(directory.iterdir()):
                return f"{label} residue is present"
        except OSError as exc:
            return f"cannot inspect {label}: {exc}"
    return None


def _recover(
    release_dir: Path,
    env: Mapping[str, str],
    *,
    strict_direct: bool = False,
) -> int:
    from .providers import ProviderError
    from .runtime import FenceBusyError, FenceRecord, RuntimeSecurityError
    from .supervisor import RecoveryRequired, recover_offline

    try:
        expectation_names = (
            "GROK_RECOVERY_EXPECT_RELEASE_ID",
            "GROK_RECOVERY_EXPECT_OWNER_EPOCH",
            "GROK_RECOVERY_EXPECT_PID",
            "GROK_RECOVERY_EXPECT_PID_START_TICKS",
            "GROK_RECOVERY_EXPECT_BOOT_ID",
        )
        present = tuple(name in env for name in expectation_names)
        require_absent = env.get("GROK_RECOVERY_EXPECT_ABSENT") == "1"
        if "GROK_RECOVERY_EXPECT_ABSENT" in env and not require_absent:
            raise ClientError("GROK_RECOVERY_EXPECT_ABSENT must be the literal value 1")
        if require_absent and any(present):
            raise ClientError("recovery cannot expect an owner and an absent fence")
        if any(present) and not all(present):
            raise ClientError("exact recovery expectation is incomplete")
        expected_fence: tuple[str, str, ProcessIdentity] | None = None
        if all(present):
            pid = env["GROK_RECOVERY_EXPECT_PID"]
            start = env["GROK_RECOVERY_EXPECT_PID_START_TICKS"]
            if not pid.isascii() or not pid.isdecimal() or not start.isascii() or not start.isdecimal():
                raise ClientError("exact recovery expectation has non-numeric process identity")
            record = FenceRecord(
                schema_version=SCHEMA_VERSION,
                release_id=env["GROK_RECOVERY_EXPECT_RELEASE_ID"],
                owner_epoch=env["GROK_RECOVERY_EXPECT_OWNER_EPOCH"],
                pid=int(pid),
                pid_start_ticks=int(start),
                boot_id=env["GROK_RECOVERY_EXPECT_BOOT_ID"],
                phase="READY",
            )
            expected_fence = (
                record.release_id,
                record.owner_epoch,
                ProcessIdentity(record.pid, record.pid_start_ticks, record.boot_id),
            )
        skip_compatibility = (
            env.get("GROK_TESTING") == "1"
            and env.get("GROK_TEST_SKIP_WARM_HANDOFF") == "1"
        )
        outcome = recover_offline(
            control_root(env),
            release_dir,
            recover_compatibility=not skip_compatibility and not strict_direct,
            forbid_compatibility_handoff=strict_direct,
            expected_fence=expected_fence,
            require_fence_absent=require_absent,
        )
    except ValueError as exc:
        raise ClientError(f"invalid exact recovery expectation: {exc}") from exc
    except (FenceBusyError, ProviderError, RecoveryRequired, RuntimeSecurityError, OSError) as exc:
        raise ClientError(f"recovery remains fenced: {exc}") from exc
    print(json.dumps(outcome.to_dict(), sort_keys=True))
    return 0


def run(argv: Sequence[str], release_dir: Path, env: Mapping[str, str]) -> int:
    classification = classify(argv)
    dispatch_env = dict(env)
    strict_direct_recovery = _prepare_canary_dispatch(
        classification,
        release_dir,
        dispatch_env,
    )
    canary_active = any(name in dispatch_env for name in _CANARY_BINDINGS)
    if classification.kind is CommandKind.USAGE:
        legacy_env = dict(dispatch_env)
        legacy_env["GROK_MULTI_SESSION"] = "0"
        os.execvpe(str(release_dir / "grok-remote"), [str(release_dir / "grok-remote"), *argv], legacy_env)
    execution_env = _execution_env(dispatch_env)
    if classification.kind is CommandKind.MAINTENANCE:
        _maintenance(classification.grok_argv, release_dir, execution_env)
    if classification.kind is CommandKind.CONTROL:
        assert classification.control is not None
        return _control(classification.control, execution_env)
    if classification.kind is CommandKind.RECOVERY:
        return _recover(
            release_dir,
            execution_env,
            strict_direct=strict_direct_recovery,
        )
    grok_bin = _grok_bin(execution_env)
    if classification.kind is CommandKind.BARE:
        _bare_exec(grok_bin, classification.grok_argv, execution_env)
    if classification.force_pick:
        raise ClientError("--pick-model is not supported in noninteractive v1 admission; pass -m")

    selection = _release_gate(release_dir, execution_env)
    release_lock_fd = _release_lock_fd(execution_env)
    provider_canary: _ProviderCanary | None = None
    try:
        _close_frontend_release_lock(execution_env)
        grok_home = _grok_home(execution_env)
        private_dir = (
            release_dir
            if (release_dir / ".model.choice").exists()
            else _home(execution_env) / "grok-proxy"
        )
        model_id, explicit = resolve_model(
            classification.grok_argv,
            choice_path=private_dir / ".model.choice",
            config_path=grok_home / "config.toml",
        )
        try:
            grok = VerifiedGrokExecutable.open(grok_bin)
        except (GrokExecutableError, OSError) as exc:
            raise ClientError(f"cannot verify Grok executable: {exc}") from exc
        with grok:
            contract = build_contract(
                classification,
                model_id,
                release_dir=release_dir,
                grok_bin=grok_bin,
                env=execution_env,
                grok_release_id=grok.release_id,
            )
            contract, provider_canary = _qualified_contract(
                contract,
                selection,
                execution_env,
            )
            if explicit:
                _remember_explicit_model(
                    private_dir / ".model.choice",
                    model_id,
                    canary_active=canary_active,
                )
            connection = ensure_supervisor(
                release_dir,
                contract,
                execution_env,
                provider_canary=provider_canary,
            )
            if provider_canary is not None:
                os.close(provider_canary.descriptor)
                provider_canary = None
            request_id = str(uuid.uuid4())
            wrapper = {
                "pid": os.getpid(),
                "pid_start_ticks": read_pid_start_ticks(os.getpid()),
                "boot_id": read_boot_id(),
            }
            try:
                registration = _request(
                    connection,
                    {
                        "type": "register",
                        "schema_version": SCHEMA_VERSION,
                        "protocol_version": PROTOCOL_VERSION,
                        "request_id": request_id,
                        "lease_nonce": secrets.token_hex(16),
                        "wrapper": wrapper,
                        "contract": contract.to_dict(),
                    },
                    fds=(grok.descriptor,),
                )
                # The durable recovery fence and registered lease now own this
                # epoch.  Releasing the gate lock permits a bounded installer
                # to publish deny and terminate the exact supervisor without
                # waiting for the user-facing Grok process to finish first.
                if release_lock_fd is not None:
                    os.close(release_lock_fd)
                    release_lock_fd = None
                    execution_env.pop("GROK_RELEASE_LOCK_FD", None)
                return run_owned_child(
                    connection,
                    registration,
                    grok,
                    classification.grok_argv,
                    model_id,
                    explicit,
                    execution_env,
                )
            finally:
                connection.close()
    finally:
        if provider_canary is not None:
            os.close(provider_canary.descriptor)
        if release_lock_fd is not None:
            os.close(release_lock_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("args", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    forwarded = args.args
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]
    return run(forwarded, args.release_dir.resolve(), os.environ)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        ClientError,
        ConfigurationError,
        GrokExecutableError,
        ProtocolError,
        OSError,
    ) as exc:
        print(f"[egress] multi-session: {exc}", file=sys.stderr)
        raise SystemExit(2)
