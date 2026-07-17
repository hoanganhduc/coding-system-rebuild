"""Self-admission for immutable Grok user releases.

The installed gate is a convenience selector, not an authentication oracle:
it runs as the same UID as its caller.  Each payload therefore proves that it
is the exact READY release while holding the root selection lock itself.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
from typing import Any, Mapping


class AdmissionError(RuntimeError):
    pass


_RID = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9._:+@-]{1,256}$")
_BOOT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_ZERO = "0" * 64
_ROOT_CONTROL = Path("/var/lib/grok-proxy/release-control")
_ROOT_ROOT = Path("/usr/local/libexec/grok-proxy")


def _regular(path: Path, uid: int, gid: int, mode: int) -> os.stat_result:
    value = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(value.st_mode)
        or value.st_uid != uid
        or value.st_gid != gid
        or stat.S_IMODE(value.st_mode) != mode
    ):
        raise AdmissionError(f"unsafe release file: {path}")
    return value


def _directory(path: Path, uid: int, gid: int, mode: int) -> os.stat_result:
    value = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(value.st_mode)
        or value.st_uid != uid
        or value.st_gid != gid
        or stat.S_IMODE(value.st_mode) != mode
    ):
        raise AdmissionError(f"unsafe release directory: {path}")
    return value


def _read(path: Path, uid: int, gid: int, mode: int, maximum: int = 1024 * 1024):
    _regular(path, uid, gid, mode)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        value = os.fstat(descriptor)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != uid
            or value.st_gid != gid
            or stat.S_IMODE(value.st_mode) != mode
        ):
            raise AdmissionError(f"release file changed while opening: {path}")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise AdmissionError(f"oversized release metadata: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _json(path: Path, uid: int, gid: int, mode: int) -> tuple[dict[str, Any], bytes]:
    raw = _read(path, uid, gid, mode)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise AdmissionError(f"invalid release metadata: {path}") from exc
    if not isinstance(value, dict):
        raise AdmissionError(f"release metadata is not an object: {path}")
    canonical = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    if raw != canonical:
        raise AdmissionError(f"release metadata is not canonical: {path}")
    return value, raw


def _selector(path: Path, uid: int, gid: int, release_id: str) -> None:
    value = path.lstat()
    if (
        not stat.S_ISLNK(value.st_mode)
        or value.st_uid != uid
        or value.st_gid != gid
        or os.readlink(path) != f"releases/{release_id}"
    ):
        raise AdmissionError(f"release selector is not coherent: {path}")


def _control(environment: Mapping[str, str]) -> tuple[Path, int, int, bool]:
    testing = environment.get("GROK_TESTING") == "1"
    override = environment.get("GROK_TEST_ROOT_RELEASE_CONTROL")
    if not testing or not override:
        return _ROOT_CONTROL, 0, 0, False
    candidate = Path(override)
    if not candidate.is_absolute():
        raise AdmissionError("test release-control path is not absolute")
    return candidate, os.geteuid(), os.getegid(), True


def _dead_provider_recovery_fence(
    user_root: Path,
    target_uid: int,
    target_gid: int,
    release_id: str,
    environment: Mapping[str, str],
) -> None:
    owner_epoch = environment.get("GROK_PROVIDER_OWNER_EPOCH")
    if (
        environment.get("GROK_PROVIDER_MODE") != "1"
        or type(owner_epoch) is not str
        or _TOKEN.fullmatch(owner_epoch) is None
        or environment.get("GROK_ACTIVE_RELEASE_ID") != release_id
    ):
        raise AdmissionError("provider recovery identity is incomplete")
    account_home = user_root.parents[2]
    control = account_home / ".local/state/grok-proxy/control"
    _directory(control, target_uid, target_gid, 0o700)
    fence, _raw = _json(
        control / "recovery.fence",
        target_uid,
        target_gid,
        0o600,
    )
    expected = {
        "schema_version",
        "release_id",
        "owner_epoch",
        "pid",
        "pid_start_ticks",
        "boot_id",
        "phase",
    }
    pid = fence.get("pid")
    start_ticks = fence.get("pid_start_ticks")
    boot_id = fence.get("boot_id")
    if (
        set(fence) != expected
        or fence.get("schema_version") != 1
        or fence.get("release_id") != release_id
        or fence.get("owner_epoch") != owner_epoch
        or type(pid) is not int
        or not 1 <= pid <= 2**31 - 1
        or type(start_ticks) is not int
        or not 1 <= start_ticks <= 2**63 - 1
        or type(boot_id) is not str
        or _BOOT.fullmatch(boot_id) is None
        or fence.get("phase")
        not in {"BOOTSTRAPPING", "RECOVERING", "READY", "DRAINING"}
    ):
        raise AdmissionError("provider recovery fence is not exact")
    try:
        running_boot = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip().lower()
    except (OSError, UnicodeError) as exc:
        raise AdmissionError("cannot inspect the running boot identity") from exc
    if _BOOT.fullmatch(running_boot) is None:
        raise AdmissionError("running boot identity is invalid")
    if boot_id != running_boot:
        return
    try:
        process_stat = (Path("/proc") / str(pid) / "stat").read_text(
            encoding="ascii"
        )
    except FileNotFoundError:
        return
    except (OSError, UnicodeError) as exc:
        raise AdmissionError("cannot inspect the provider recovery owner") from exc
    closing = process_stat.rfind(")")
    fields = process_stat[closing + 2 :].split() if closing >= 0 else []
    if (
        len(fields) <= 19
        or len(fields[0]) != 1
        or not fields[19].isdecimal()
    ):
        raise AdmissionError("provider recovery owner identity is malformed")
    if int(fields[19]) != start_ticks or fields[0] in {"Z", "X", "x"}:
        return
    raise AdmissionError("provider recovery fence owner is still live")


def _manifest_file(
    manifest: Mapping[str, Any], relative: str, path: Path, uid: int, gid: int
) -> None:
    records = [
        record
        for record in manifest.get("files", [])
        if isinstance(record, dict) and record.get("path") == relative
    ]
    if len(records) != 1:
        raise AdmissionError(f"release manifest does not bind {relative}")
    record = records[0]
    raw = _read(path, uid, gid, 0o555)
    if (
        record.get("mode") != "0555"
        or record.get("size") != len(raw)
        or record.get("sha256") != hashlib.sha256(raw).hexdigest()
    ):
        raise AdmissionError(f"release manifest digest differs for {relative}")


def validate(
    release_dir: Path,
    executable: Path,
    lock_fd: int,
    environment: Mapping[str, str],
    *,
    canary_fd: int | None = None,
    public_recovery: bool = False,
    provider_recovery: bool = False,
) -> str:
    if provider_recovery and not public_recovery:
        raise AdmissionError("provider recovery requires public recovery admission")
    control, root_uid, root_gid, test_install = _control(environment)
    if not test_install and any(
        name == "GROK_TESTING" or name.startswith("GROK_TEST_")
        for name in environment
    ):
        raise AdmissionError("test variables are forbidden in a production release")
    _directory(control, root_uid, root_gid, 0o755)
    lock = control / "install.lock"
    lock_info = _regular(lock, root_uid, root_gid, 0o644)
    actual_lock = os.fstat(lock_fd)
    if (
        not stat.S_ISREG(actual_lock.st_mode)
        or (actual_lock.st_dev, actual_lock.st_ino) != (lock_info.st_dev, lock_info.st_ino)
    ):
        raise AdmissionError("release lock descriptor is not the fixed lock")
    fcntl.flock(lock_fd, fcntl.LOCK_SH)

    release_dir = Path(os.path.abspath(release_dir))
    executable = Path(os.path.abspath(executable))
    release_id = release_dir.name
    if _RID.fullmatch(release_id) is None:
        raise AdmissionError("release directory has no release identity")

    root_selection, _root_raw = _json(
        control / "selected-release.json", root_uid, root_gid, 0o444
    )
    user_root_value = root_selection.get("user_root")
    root_root_value = root_selection.get("root_root")
    if not isinstance(user_root_value, str) or not isinstance(root_root_value, str):
        raise AdmissionError("selection roots are invalid")
    user_root = Path(user_root_value)
    root_root = Path(root_root_value)
    if not test_install:
        account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        if user_root != account_home / ".local/lib/grok-proxy" or root_root != _ROOT_ROOT:
            raise AdmissionError("selection roots are not canonical")
    if root_selection.get("root_control") != str(control):
        raise AdmissionError("selection control root differs")
    if release_dir != user_root / "releases" / release_id:
        raise AdmissionError("release is not at its canonical selected path")

    _directory(user_root, root_uid, root_gid, 0o755)
    _directory(user_root / "releases", root_uid, root_gid, 0o755)
    _directory(release_dir, root_uid, root_gid, 0o555)
    _directory(root_root, root_uid, root_gid, 0o755)
    _directory(root_root / "releases", root_uid, root_gid, 0o755)
    _directory(root_root / "releases" / release_id, root_uid, root_gid, 0o555)

    user_manifest, user_manifest_raw = _json(
        release_dir / "release.json", root_uid, root_gid, 0o444
    )
    root_manifest, root_manifest_raw = _json(
        root_root / "releases" / release_id / "release.json",
        root_uid,
        root_gid,
        0o444,
    )
    if (
        user_manifest.get("schema_version") != 2
        or user_manifest.get("kind") != "user"
        or user_manifest.get("release_id") != release_id
        or root_manifest.get("schema_version") != 2
        or root_manifest.get("kind") != "root"
        or root_manifest.get("release_id") != release_id
    ):
        raise AdmissionError("release manifests are not one coherent pair")
    relative = executable.relative_to(release_dir).as_posix()
    _manifest_file(user_manifest, relative, executable, root_uid, root_gid)

    if canary_fd is not None:
        auth = control / "canary-auth.lock"
        auth_info = _regular(auth, root_uid, root_gid, 0o600)
        actual_auth = os.fstat(canary_fd)
        if (
            not stat.S_ISREG(actual_auth.st_mode)
            or (actual_auth.st_dev, actual_auth.st_ino)
            != (auth_info.st_dev, auth_info.st_ino)
            or environment.get("GROK_RELEASE_CANARY_RELEASE_ID") != release_id
        ):
            raise AdmissionError("release canary authorization is not fixed")
        return release_id

    deny_path = control / "rollback-deny.json"
    deny_present = deny_path.exists() or deny_path.is_symlink()
    if deny_present and public_recovery:
        deny, _deny_raw = _json(deny_path, root_uid, root_gid, 0o444)
        if (
            set(deny) != {"schema_version", "operation", "from_release", "to_release"}
            or deny.get("schema_version") != 1
            or deny.get("operation") not in {"install", "rollback", "canary"}
            or release_id not in {deny.get("from_release"), deny.get("to_release")}
        ):
            raise AdmissionError("public recovery deny ledger is invalid")
        target_uid = root_selection.get("target_uid")
        target_gid = root_selection.get("target_gid")
        if type(target_uid) is not int or type(target_gid) is not int:
            raise AdmissionError("selection target identity is invalid")
        if provider_recovery:
            _dead_provider_recovery_fence(
                user_root,
                target_uid,
                target_gid,
                release_id,
                environment,
            )
        return release_id
    if deny_present:
        raise AdmissionError("durable install/rollback deny is active")

    target_uid = root_selection.get("target_uid")
    target_gid = root_selection.get("target_gid")
    if target_uid != os.getuid() or target_gid != os.getgid():
        raise AdmissionError("selection targets another account")
    account_home = user_root.parents[2]
    user_control = account_home / ".local/state/grok-proxy/release-control"
    _directory(user_control, target_uid, target_gid, 0o700)
    user_selection, user_raw = _json(
        user_control / "selected-release.json", target_uid, target_gid, 0o444
    )
    root_copy = dict(root_selection)
    user_sha = root_copy.pop("user_selection_sha256", None)
    if user_sha != hashlib.sha256(user_raw).hexdigest() or root_copy != user_selection:
        raise AdmissionError("root and user selection records differ")
    if (
        root_copy.get("schema_version") != 1
        or root_copy.get("release_schema_version") != 2
        or root_copy.get("handshake_protocol") != 1
        or root_copy.get("selection_phase") != "READY"
        or root_copy.get("release_id") != release_id
        or root_copy.get("user_release_id") != release_id
        or root_copy.get("root_release_id") != release_id
        or not isinstance(root_copy.get("qualified_rungs"), list)
        or root_copy.get("user_manifest_sha256")
        != hashlib.sha256(user_manifest_raw).hexdigest()
        or root_copy.get("root_manifest_sha256")
        != hashlib.sha256(root_manifest_raw).hexdigest()
    ):
        raise AdmissionError("selected release metadata is not READY and coherent")
    evidence_digest = root_copy.get("evidence_sha256")
    if (
        not isinstance(evidence_digest, str)
        or _RID.fullmatch(evidence_digest) is None
        or evidence_digest == _ZERO
    ):
        raise AdmissionError("selected release lacks final evidence")
    evidence, evidence_raw = _json(
        control / "evidence" / f"{release_id}.json", root_uid, root_gid, 0o444
    )
    if (
        hashlib.sha256(evidence_raw).hexdigest() != evidence_digest
        or evidence.get("schema_version") != 3
        or evidence.get("release_id") != release_id
        or evidence.get("overall_pass") is not True
        or evidence.get("user_manifest_sha256")
        != root_copy.get("user_manifest_sha256")
        or evidence.get("root_manifest_sha256")
        != root_copy.get("root_manifest_sha256")
        or evidence.get("root_files") != root_copy.get("root_files")
    ):
        raise AdmissionError("selected release evidence is invalid")
    _selector(user_root / "current", root_uid, root_gid, release_id)
    _selector(root_root / "current", root_uid, root_gid, release_id)

    if environment.get("GROK_MULTI_SESSION") == "1":
        inventory, _raw = _json(
            control / "boot-inventory" / f"{release_id}.json",
            root_uid,
            root_gid,
            0o444,
        )
        try:
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()
        except OSError as exc:
            raise AdmissionError("cannot read current boot identity") from exc
        if (
            inventory.get("schema_version") != 1
            or inventory.get("release_id") != release_id
            or inventory.get("boot_id") != boot_id
            or not isinstance(inventory.get("checked_unix_ns"), int)
            or inventory.get("checked_unix_ns", 0) <= 0
            or not isinstance(inventory.get("inventory_sha256"), str)
            or _RID.fullmatch(inventory["inventory_sha256"]) is None
        ):
            raise AdmissionError("current-boot root inventory is invalid")

    if (control / "rollback-deny.json").exists() or (
        control / "rollback-deny.json"
    ).is_symlink():
        raise AdmissionError("durable deny appeared during admission")
    return release_id


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--public-recovery", action="store_true")
    parser.add_argument("--provider-recovery", action="store_true")
    parser.add_argument("release_dir")
    parser.add_argument("executable")
    parser.add_argument("lock_fd", type=int)
    parser.add_argument("canary_fd", nargs="?", type=int)
    args = parser.parse_args()
    try:
        validate(
            Path(args.release_dir),
            Path(args.executable),
            args.lock_fd,
            os.environ,
            canary_fd=args.canary_fd,
            public_recovery=args.public_recovery,
            provider_recovery=args.provider_recovery,
        )
    except (AdmissionError, OSError, ValueError) as exc:
        print(f"release admission failed: {exc}", file=os.sys.stderr)
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
