#!/usr/bin/python3
"""Launch the degraded CI install from one exact delegated cgroup boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import stat
import sys
from types import ModuleType


CGROUP_MOUNT = Path("/sys/fs/cgroup")
PROC_CGROUP = Path("/proc/self/cgroup")
EXPECTED_SUBGROUP = "installer"
REQUIRED_CONTROLLERS = frozenset({"cpu", "memory", "pids"})
INSTALLER_PATH = Path("system/grok-proxy/install-release.py")
INSTALL_EXECUTABLE = "/usr/bin/bash"
INSTALL_SCRIPT = Path("bin/install.sh")
FORWARDED_ENVIRONMENT = {
    "SKIP_LATEX": "1",
    "SKIP_DOCKER_IMAGES": "1",
    "AAS_PYTHON": "/bin/false",
    "PYTHONPATH": "/tmp/csr-hostile-aas-pythonpath",
}
READ_LIMIT = 16_384
INSTALLER_SOURCE_LIMIT = 4 * 1024 * 1024


class PreflightError(RuntimeError):
    """A closed, non-sensitive delegated-launch precondition failed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _read_bounded(path: Path, maximum: int = READ_LIMIT) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        information = os.fstat(descriptor)
        if not stat.S_ISREG(information.st_mode):
            raise PreflightError("control-identity")
        value = os.read(descriptor, maximum + 1)
        if len(value) > maximum:
            raise PreflightError("control-oversized")
        return value
    finally:
        os.close(descriptor)


def _read_control(descriptor: int, name: str, maximum: int = 4096) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    child = os.open(name, flags, dir_fd=descriptor)
    try:
        information = os.fstat(child)
        if not stat.S_ISREG(information.st_mode):
            raise PreflightError("control-identity")
        value = os.read(child, maximum + 1)
        if len(value) > maximum:
            raise PreflightError("control-oversized")
        return value
    finally:
        os.close(child)


def _write_controllers(descriptor: int) -> None:
    flags = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    child = os.open("cgroup.subtree_control", flags, dir_fd=descriptor)
    try:
        if not stat.S_ISREG(os.fstat(child).st_mode):
            raise PreflightError("control-identity")
        value = b"+cpu +memory +pids\n"
        if os.write(child, value) != len(value):
            raise PreflightError("controller-enable")
    finally:
        os.close(child)


def _membership(raw: bytes, mount: Path) -> tuple[Path, Path]:
    try:
        text = raw.decode("ascii")
    except UnicodeError as exc:
        raise PreflightError("membership-invalid") from exc
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise PreflightError("membership-invalid")
    relative = lines[0][3:]
    if not relative.startswith("/") or ".." in Path(relative).parts:
        raise PreflightError("membership-invalid")
    source = mount / relative.lstrip("/")
    if source.name != EXPECTED_SUBGROUP or source.parent == mount:
        raise PreflightError("subgroup-unexpected")
    return source, source.parent


def _file_snapshot(information: os.stat_result) -> tuple[int, ...]:
    return (
        information.st_dev,
        information.st_ino,
        information.st_mode,
        information.st_uid,
        information.st_gid,
        information.st_nlink,
        information.st_size,
        information.st_mtime_ns,
        information.st_ctime_ns,
    )


def _read_descriptor(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise PreflightError("installer-source")
    return b"".join(chunks)


def _load_installer(path: Path) -> ModuleType:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        named_before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PreflightError("installer-source") from exc
    try:
        opened_before = os.fstat(descriptor)
        if (
            path.is_symlink()
            or not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_uid != os.geteuid()
            or opened_before.st_nlink != 1
            or _file_snapshot(named_before) != _file_snapshot(opened_before)
        ):
            raise PreflightError("installer-source")
        source = _read_descriptor(descriptor, INSTALLER_SOURCE_LIMIT)
        opened_after = os.fstat(descriptor)
        named_after = path.lstat()
        if (
            _file_snapshot(opened_before) != _file_snapshot(opened_after)
            or _file_snapshot(opened_after) != _file_snapshot(named_after)
        ):
            raise PreflightError("installer-source")
    except OSError as exc:
        raise PreflightError("installer-source") from exc
    finally:
        os.close(descriptor)

    module_name = "grok_ci_release_installer"
    module = ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    module._RUNNER_CGROUP_PROBE_IMPORT = True
    sys.modules[module_name] = module
    original_import_path = list(sys.path)
    try:
        code = compile(source, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
        if _file_snapshot(path.lstat()) != _file_snapshot(named_after):
            raise PreflightError("installer-source")
    except Exception as exc:
        sys.modules.pop(module_name, None)
        if isinstance(exc, PreflightError):
            raise
        raise PreflightError("installer-source") from exc
    finally:
        sys.path[:] = original_import_path
    return module


def _open_install_script(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        named_before = path.lstat()
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        named_after = path.lstat()
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise PreflightError("install-command") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or opened.st_nlink != 1
        or _file_snapshot(named_before) != _file_snapshot(opened)
        or _file_snapshot(opened) != _file_snapshot(named_after)
    ):
        os.close(descriptor)
        raise PreflightError("install-command")
    try:
        os.set_inheritable(descriptor, True)
    except OSError as exc:
        os.close(descriptor)
        raise PreflightError("install-command") from exc
    return descriptor


def _prepare_exact_parent(
    *,
    mount: Path = CGROUP_MOUNT,
    proc_cgroup: Path = PROC_CGROUP,
) -> tuple[Path, Path]:
    uid = os.geteuid()
    gid = os.getegid()
    if uid < 1 or gid < 1:
        raise PreflightError("target-identity")
    raw_membership = _read_bounded(proc_cgroup)
    source, parent = _membership(raw_membership, mount)
    try:
        mount_information = mount.lstat()
        source_information = source.lstat()
        parent_information = parent.lstat()
    except OSError as exc:
        raise PreflightError("cgroup-identity") from exc
    if (
        mount.is_symlink()
        or source.is_symlink()
        or parent.is_symlink()
        or not stat.S_ISDIR(mount_information.st_mode)
        or not stat.S_ISDIR(source_information.st_mode)
        or not stat.S_ISDIR(parent_information.st_mode)
        or source_information.st_dev != mount_information.st_dev
        or parent_information.st_dev != mount_information.st_dev
        or (source_information.st_uid, source_information.st_gid) != (uid, gid)
        or (parent_information.st_uid, parent_information.st_gid) != (uid, gid)
    ):
        raise PreflightError("cgroup-identity")
    try:
        delegated = os.getxattr(parent, "user.delegate", follow_symlinks=False)
    except OSError as exc:
        raise PreflightError("delegation-marker") from exc
    if delegated != b"1":
        raise PreflightError("delegation-marker")

    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(parent, flags)
    try:
        anchored = os.fstat(descriptor)
        if (anchored.st_dev, anchored.st_ino) != (
            parent_information.st_dev,
            parent_information.st_ino,
        ):
            raise PreflightError("cgroup-changed")
        if _read_control(descriptor, "cgroup.procs").strip():
            raise PreflightError("parent-populated")
        if _read_control(descriptor, "cgroup.type", maximum=64).strip() != b"domain":
            raise PreflightError("parent-type")
        available = set(
            _read_control(descriptor, "cgroup.controllers").decode("ascii").split()
        )
        if not REQUIRED_CONTROLLERS <= available:
            raise PreflightError("controllers-unavailable")
        enabled = set(
            _read_control(descriptor, "cgroup.subtree_control")
            .decode("ascii")
            .split()
        )
        if not REQUIRED_CONTROLLERS <= enabled:
            _write_controllers(descriptor)
            enabled = set(
                _read_control(descriptor, "cgroup.subtree_control")
                .decode("ascii")
                .split()
            )
        if not REQUIRED_CONTROLLERS <= enabled:
            raise PreflightError("controller-enable")
        source_descriptor = os.open(
            source,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            source_anchored = os.fstat(source_descriptor)
            if (source_anchored.st_dev, source_anchored.st_ino) != (
                source_information.st_dev,
                source_information.st_ino,
            ):
                raise PreflightError("cgroup-changed")
            for name in (
                "cgroup.max.depth",
                "cgroup.max.descendants",
                "cpu.max",
                "memory.high",
                "memory.max",
                "memory.swap.max",
                "pids.max",
            ):
                _read_control(source_descriptor, name, maximum=128)
        finally:
            os.close(source_descriptor)
    except UnicodeError as exc:
        raise PreflightError("controller-invalid") from exc
    except OSError as exc:
        raise PreflightError("controller-access") from exc
    finally:
        os.close(descriptor)

    if _read_bounded(proc_cgroup) != raw_membership:
        raise PreflightError("membership-changed")
    try:
        final_source = source.lstat()
        final_parent = parent.lstat()
        final_delegate = os.getxattr(parent, "user.delegate", follow_symlinks=False)
    except OSError as exc:
        raise PreflightError("cgroup-changed") from exc
    if (
        (final_source.st_dev, final_source.st_ino)
        != (source_information.st_dev, source_information.st_ino)
        or (final_parent.st_dev, final_parent.st_ino)
        != (parent_information.st_dev, parent_information.st_ino)
        or final_delegate != b"1"
    ):
        raise PreflightError("cgroup-changed")
    return source, parent


def _closed_environment() -> dict[str, str]:
    uid = os.geteuid()
    try:
        account = pwd.getpwuid(uid)
    except KeyError as exc:
        raise PreflightError("target-account") from exc
    if (
        account.pw_gid != os.getegid()
        or not Path(account.pw_dir).is_absolute()
        or not account.pw_name
    ):
        raise PreflightError("target-account")
    forwarded = _forwarded_environment()
    runtime = Path(f"/run/user/{uid}")
    bus = runtime / "bus"
    try:
        runtime_information = runtime.lstat()
        bus_information = bus.lstat()
    except OSError as exc:
        raise PreflightError("user-bus") from exc
    if (
        runtime.is_symlink()
        or bus.is_symlink()
        or not stat.S_ISDIR(runtime_information.st_mode)
        or not stat.S_ISSOCK(bus_information.st_mode)
        or runtime_information.st_uid != uid
        or bus_information.st_uid != uid
    ):
        raise PreflightError("user-bus")
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "SHELL": account.pw_shell or "/bin/bash",
        "XDG_RUNTIME_DIR": str(runtime),
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
        **forwarded,
    }


def _forwarded_environment() -> dict[str, str]:
    for name, expected in FORWARDED_ENVIRONMENT.items():
        if os.environ.get(name) != expected:
            raise PreflightError("environment-contract")
    return dict(FORWARDED_ENVIRONMENT)


def main() -> int:
    install_descriptor = -1
    try:
        source, expected_parent = _prepare_exact_parent()
        source_information = source.lstat()
        parent_information = expected_parent.lstat()
        installer = _load_installer(Path.cwd() / INSTALLER_PATH)
        try:
            placement = installer._runner_cgroup_parent(
                os.geteuid(), os.getegid()
            )
        except Exception as exc:
            raise PreflightError("production-predicate") from exc
        if (
            placement.source != source
            or placement.parent != expected_parent
            or (placement.source_info.st_dev, placement.source_info.st_ino)
            != (source_information.st_dev, source_information.st_ino)
            or (placement.parent_info.st_dev, placement.parent_info.st_ino)
            != (parent_information.st_dev, parent_information.st_ino)
        ):
            raise PreflightError("production-fallback")
        environment = _closed_environment()
        install_script = Path.cwd() / INSTALL_SCRIPT
        install_descriptor = _open_install_script(install_script)
        environment["CSR_INSTALL_REPO_ROOT"] = str(Path.cwd())
    except (OSError, PreflightError) as exc:
        if install_descriptor >= 0:
            os.close(install_descriptor)
        code = exc.code if isinstance(exc, PreflightError) else "operating-system"
        print(f"delegated-install-preflight: {code}", file=sys.stderr)
        return 2

    print(
        "CSR_GATE_JSON "
        + json.dumps(
            {
                "case_id": "install.delegated-cgroup.preflight",
                "exact_parent": True,
                "required_controllers": sorted(REQUIRED_CONTROLLERS),
                "schema_version": 1,
                "status": "passed",
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )
    try:
        os.execve(
            INSTALL_EXECUTABLE,
            (INSTALL_EXECUTABLE, f"/proc/self/fd/{install_descriptor}"),
            environment,
        )
    except OSError:
        os.close(install_descriptor)
        print("delegated-install-preflight: install-exec", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
