#!/usr/bin/env python3
"""Stage the declared Grok installer runtime as a closed zipapp source tree."""

from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

sys.dont_write_bytecode = True

from build_bundle import (  # noqa: E402
    BuildError,
    normalized_mode,
    read_open_file,
    same_snapshot,
)
import dispatcher_main as shim  # noqa: E402


SHIM_SOURCE = "bootstrap/dispatcher_main.py"


class StagingError(RuntimeError):
    """The authoring tree does not match the reviewed runtime declaration."""


def _literal(node: ast.AST, values: dict[str, object]) -> object:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in values:
        return values[node.id]
    if isinstance(node, ast.Tuple):
        return tuple(_literal(item, values) for item in node.elts)
    if isinstance(node, ast.Set):
        return {_literal(item, values) for item in node.elts}
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "frozenset"
        and len(node.args) == 1
        and not node.keywords
    ):
        value = _literal(node.args[0], values)
        if not isinstance(value, set):
            raise StagingError("frozenset declaration is not a literal set")
        return frozenset(value)
    raise StagingError("runtime declaration is not a closed literal")


def declared_contract(installer: bytes) -> dict[str, object]:
    try:
        tree = ast.parse(installer, filename="install-release.py")
    except (SyntaxError, ValueError) as exc:
        raise StagingError("installer declaration cannot be parsed") from exc
    wanted = {
        "INSTALLER_RUNTIME",
        "DIRECT_ADMISSION_RUNTIME",
        "DECLARED_RUNTIME_REQUIRED",
        "DECLARED_BROKER_CANDIDATES",
        "DECLARED_PACKAGE_ROOT",
        "DECLARED_PACKAGE_REQUIRED",
        "EXCLUDED_PACKAGE_PARTS",
    }
    values: dict[str, object] = {}
    for statement in tree.body:
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            name = statement.targets[0].id
            if name in wanted:
                values[name] = _literal(statement.value, values)
    if set(values) != wanted:
        raise StagingError("installer runtime declaration is incomplete")
    return values


def _read_named_file(
    directory_descriptor: int,
    name: str,
    *,
    initial: os.stat_result | None = None,
) -> tuple[int, bytes]:
    try:
        named = (
            os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            if initial is None
            else initial
        )
    except FileNotFoundError as exc:
        raise StagingError(f"declared runtime file is absent: {name}") from exc
    if (
        not stat.S_ISREG(named.st_mode)
        or named.st_nlink != 1
        or named.st_size < 0
    ):
        raise StagingError(f"declared runtime file is linked or special: {name}")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_descriptor,
        )
    except OSError as exc:
        raise StagingError(f"declared runtime file cannot be opened safely: {name}") from exc
    try:
        opened = os.fstat(descriptor)
        if not same_snapshot(named, opened):
            raise StagingError(f"declared runtime file changed during open: {name}")
        data = read_open_file(descriptor, opened)
        current = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if not same_snapshot(opened, current):
            raise StagingError(f"declared runtime file changed during read: {name}")
        return normalized_mode(opened), data
    finally:
        os.close(descriptor)


def _open_relative_directory(root_descriptor: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        for part in parts:
            try:
                named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise StagingError(
                    f"declared runtime directory cannot be opened safely: {part}"
                ) from exc
            opened = os.fstat(child)
            if not stat.S_ISDIR(opened.st_mode) or not same_snapshot(named, opened):
                os.close(child)
                raise StagingError(f"declared runtime directory changed: {part}")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_relative_file(root_descriptor: int, relative: str) -> tuple[int, bytes]:
    if not shim._safe_relative_path(relative):
        raise StagingError(f"unsafe declared runtime path: {relative!r}")
    parts = tuple(relative.split("/"))
    parent = _open_relative_directory(root_descriptor, parts[:-1])
    try:
        return _read_named_file(parent, parts[-1])
    finally:
        os.close(parent)


def _collect_package(
    root_descriptor: int,
    package_root: str,
    excluded: frozenset[str],
) -> dict[str, tuple[int, bytes]]:
    package_descriptor = _open_relative_directory(root_descriptor, (package_root,))
    package_initial = os.fstat(package_descriptor)
    selected: dict[str, tuple[int, bytes]] = {}

    def visit(directory_descriptor: int, prefix: str) -> None:
        before = os.fstat(directory_descriptor)
        with os.scandir(directory_descriptor) as iterator:
            names = sorted(entry.name for entry in iterator)
        for name in names:
            if name in excluded or name.startswith("."):
                continue
            relative = f"{prefix}/{name}"
            if not shim._safe_relative_path(relative):
                raise StagingError(f"unsafe runtime package path: {relative!r}")
            information = os.stat(
                name, dir_fd=directory_descriptor, follow_symlinks=False
            )
            if stat.S_ISDIR(information.st_mode):
                child = _open_relative_directory(directory_descriptor, (name,))
                try:
                    visit(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(information.st_mode):
                if name.endswith(".py"):
                    selected[relative] = _read_named_file(
                        directory_descriptor, name, initial=information
                    )
            else:
                raise StagingError(
                    f"runtime package contains a linked or special object: {relative}"
                )
        after = os.fstat(directory_descriptor)
        if not same_snapshot(before, after):
            raise StagingError(f"runtime package directory changed: {prefix}")

    try:
        visit(package_descriptor, package_root)
        current = os.stat(package_root, dir_fd=root_descriptor, follow_symlinks=False)
        if not same_snapshot(package_initial, current):
            raise StagingError("runtime package root changed during snapshot")
        return selected
    finally:
        os.close(package_descriptor)


def select_runtime(root_descriptor: int) -> list[tuple[str, int, bytes]]:
    installer_mode, installer = _read_relative_file(
        root_descriptor, "install-release.py"
    )
    _shim_mode, shim_data = _read_relative_file(root_descriptor, SHIM_SOURCE)
    contract = declared_contract(installer)

    required = tuple(contract["DECLARED_RUNTIME_REQUIRED"])
    brokers = tuple(contract["DECLARED_BROKER_CANDIDATES"])
    package_root = str(contract["DECLARED_PACKAGE_ROOT"])
    package_required = frozenset(contract["DECLARED_PACKAGE_REQUIRED"])
    excluded = frozenset(contract["EXCLUDED_PACKAGE_PARTS"])
    direct_admission = str(contract["DIRECT_ADMISSION_RUNTIME"])
    if (
        required != shim.REQUIRED_TOP_LEVEL
        or brokers != shim.BROKER_CANDIDATES
        or package_root != shim.PACKAGE_ROOT
        or package_required != shim.MANDATORY_PACKAGE_FILES
        or excluded != shim.EXCLUDED_PACKAGE_PARTS
        or direct_admission not in shim.MANDATORY_PACKAGE_FILES
    ):
        raise StagingError("dispatcher shim and installer declarations differ")

    if (
        not all(isinstance(name, str) and "/" not in name for name in required)
        or not all(isinstance(name, str) and "/" not in name for name in brokers)
        or not shim._safe_relative_path(package_root)
        or "/" in package_root
        or not all(
            isinstance(name, str)
            and shim._safe_relative_path(name)
            and name.startswith(package_root + "/")
            for name in package_required
        )
        or not all(isinstance(name, str) for name in excluded)
    ):
        raise StagingError("installer runtime declarations are not closed paths")

    selected: dict[str, tuple[int, bytes]] = {
        "install-release.py": (installer_mode, installer)
    }
    for name in required:
        if name != "install-release.py":
            selected[name] = _read_relative_file(root_descriptor, name)
    present_brokers: list[tuple[str, os.stat_result]] = []
    for name in brokers:
        try:
            information = os.stat(
                name, dir_fd=root_descriptor, follow_symlinks=False
            )
        except FileNotFoundError:
            continue
        present_brokers.append((name, information))
    if len(present_brokers) != 1:
        raise StagingError("exactly one declared broker must be present")
    broker, broker_information = present_brokers[0]
    selected[broker] = _read_named_file(
        root_descriptor, broker, initial=broker_information
    )

    selected.update(_collect_package(root_descriptor, package_root, excluded))
    if not package_required.issubset(selected):
        raise StagingError("runtime package lacks a mandatory module")

    executable = {"grok-remote", "socks-netns.py", "vpngate-connect.sh", broker}
    wrong_mode = sorted(name for name in executable if selected[name][0] != 0o755)
    if wrong_mode or selected["sanitize.awk"][0] != 0o644:
        raise StagingError("declared runtime executable modes are invalid")

    output = [("__main__.py", 0o644, shim_data)]
    output.extend((path, mode, data) for path, (mode, data) in selected.items())
    output.sort(key=lambda item: item[0])
    return output


def _write_all(file_descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(file_descriptor, data[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise StagingError("short staging write")
        offset += written


def _make_removable(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        try:
            information = path.lstat()
            if not stat.S_ISLNK(information.st_mode):
                path.chmod(0o700 if stat.S_ISDIR(information.st_mode) else 0o600)
        except FileNotFoundError:
            pass
    try:
        root.chmod(0o700)
    except FileNotFoundError:
        pass


def stage_dispatcher(source: Path, output: Path) -> Path:
    try:
        source_info = source.lstat()
        parent_info = output.parent.lstat()
    except OSError as exc:
        raise StagingError("source and output parent must already exist") from exc
    if source.is_symlink() or not stat.S_ISDIR(source_info.st_mode):
        raise StagingError("source root must be a real directory")
    if output.parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode):
        raise StagingError("output parent must be a real directory")
    if output.exists() or output.is_symlink():
        raise StagingError("staging output must not already exist")

    source = source.resolve(strict=True)
    output = output.parent.resolve(strict=True) / output.name
    if source == output or source in output.parents or output in source.parents:
        raise StagingError("source and staging output trees must be disjoint")

    source_descriptor = os.open(
        source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        opened_source = os.fstat(source_descriptor)
        named_source = source.lstat()
        if not same_snapshot(opened_source, named_source):
            raise StagingError("source root changed during open")
        selected = select_runtime(source_descriptor)
    finally:
        os.close(source_descriptor)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    renamed = False
    complete = False
    try:
        directories: set[Path] = set()
        for relative, mode, data in selected:
            destination = temporary / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            directories.update(destination.parents)
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            try:
                _write_all(descriptor, data)
                os.fchmod(descriptor, 0o555 if mode == 0o755 else 0o444)
            finally:
                os.close(descriptor)
        for directory in sorted(
            (path for path in directories if temporary in path.parents),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            directory.chmod(0o555)
        os.rename(temporary, output)
        renamed = True
        output.chmod(0o555)
        complete = True
        return output
    finally:
        cleanup = output if renamed and not complete else temporary
        if cleanup.exists() and not (complete and cleanup == output):
            _make_removable(cleanup)
            shutil.rmtree(cleanup, ignore_errors=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        output = stage_dispatcher(args.source_root, args.output)
    except (BuildError, StagingError, OSError, ValueError) as exc:
        print(f"stage-dispatcher: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
