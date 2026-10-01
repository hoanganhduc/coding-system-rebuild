#!/usr/bin/env python3
"""Validate and inspect the checked-in npm CLI closure.

This helper uses only the Python standard library.  npm remains responsible for
verifying package tarball integrity during ``npm ci``; this helper makes the
repository contract and the resulting direct CLI/package exposure explicit.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PACKAGE_JSON = HERE / "package.json"
PACKAGE_LOCK = HERE / "package-lock.json"
PACKAGE_LIST = ROOT / "system" / "packages" / "npm-globals.txt"
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
BIN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PACKAGE_NAME = re.compile(r"^(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*$")


class ClosureError(RuntimeError):
    """The source closure or installed closure is invalid."""


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ClosureError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ClosureError(f"JSON root must be an object: {path}")
    return value


def package_specs() -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = PACKAGE_LIST.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ClosureError(f"cannot read {PACKAGE_LIST}: {exc}") from exc
    for raw in lines:
        spec = raw.strip()
        if not spec or spec.startswith("#"):
            continue
        separator = spec.rfind("@")
        if separator <= 0:
            raise ClosureError(f"npm package is not exactly versioned: {spec}")
        name, version = spec[:separator], spec[separator + 1 :]
        if not PACKAGE_NAME.fullmatch(name) or not SEMVER.fullmatch(version):
            raise ClosureError(f"npm package is not an exact supported spec: {spec}")
        if name in result:
            raise ClosureError(f"duplicate npm package: {name}")
        result[name] = version
    if not result:
        raise ClosureError("npm package list is empty")
    return result


def checked_relative(value: object, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ClosureError(f"{label} must be a nonempty relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ClosureError(f"{label} escapes its package: {value!r}")
    normalized = PurePosixPath(*[part for part in path.parts if part not in {"", "."}])
    if not normalized.parts:
        raise ClosureError(f"{label} must name a file")
    return normalized


def normalized_bins(value: object, package_name: str) -> dict[str, str]:
    if isinstance(value, str):
        return {package_name.rsplit("/", 1)[-1]: value}
    if not isinstance(value, dict):
        raise ClosureError(f"direct npm package has no bin declaration: {package_name}")
    result: dict[str, str] = {}
    for name, target in value.items():
        if not isinstance(name, str) or not BIN_NAME.fullmatch(name):
            raise ClosureError(f"invalid bin name in {package_name}: {name!r}")
        checked_relative(target, label=f"bin {name}")
        result[name] = str(target)
    if not result:
        raise ClosureError(f"direct npm package has an empty bin declaration: {package_name}")
    return result


def integrity_is_sha512(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha512-"):
        return False
    try:
        digest = base64.b64decode(value.removeprefix("sha512-"), validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(digest) == 64


def validate_resolved(value: object, record: str) -> None:
    if not isinstance(value, str):
        raise ClosureError(f"lock record lacks resolved URL: {record}")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "registry.npmjs.org"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ClosureError(f"lock record is not pinned to credential-free registry.npmjs.org: {record}")


def source_contract() -> tuple[dict[str, object], dict[str, object], dict[str, str]]:
    package = load_json(PACKAGE_JSON)
    lock = load_json(PACKAGE_LOCK)
    requested = package_specs()

    if package.get("private") is not True:
        raise ClosureError("npm closure package must be private")
    dependencies = package.get("dependencies")
    if dependencies != requested:
        raise ClosureError("package.json dependencies do not exactly equal npm-globals.txt")
    if lock.get("lockfileVersion") != 3 or lock.get("requires") is not True:
        raise ClosureError("npm closure requires package-lock v3")
    records = lock.get("packages")
    if not isinstance(records, dict) or not records:
        raise ClosureError("package-lock has no package records")
    root_record = records.get("")
    if not isinstance(root_record, dict) or root_record.get("dependencies") != requested:
        raise ClosureError("package-lock root dependencies do not equal npm-globals.txt")

    for record_name, record in records.items():
        if record_name == "":
            continue
        if not isinstance(record_name, str) or not record_name.startswith("node_modules/"):
            raise ClosureError(f"unexpected package-lock record path: {record_name!r}")
        if not isinstance(record, dict):
            raise ClosureError(f"package-lock record is not an object: {record_name}")
        validate_resolved(record.get("resolved"), record_name)
        if not integrity_is_sha512(record.get("integrity")):
            raise ClosureError(f"package-lock record lacks valid sha512 integrity: {record_name}")
        version = record.get("version")
        if not isinstance(version, str) or not version:
            raise ClosureError(f"package-lock record lacks version: {record_name}")

    declared: dict[str, tuple[str, str]] = {}
    for name, version in requested.items():
        record_name = f"node_modules/{name}"
        record = records.get(record_name)
        if not isinstance(record, dict) or record.get("version") != version:
            raise ClosureError(f"direct package record does not match exact version: {name}@{version}")
        for bin_name, target in normalized_bins(record.get("bin"), name).items():
            if bin_name in declared:
                raise ClosureError(f"direct packages declare colliding bin: {bin_name}")
            declared[bin_name] = (name, target)

    configured = package.get("csrCliBins")
    if not isinstance(configured, dict) or set(configured) != set(declared):
        raise ClosureError("csrCliBins must exactly cover bins declared by direct packages")
    supported_platforms = {"linux/amd64", "linux/arm64"}
    for bin_name, entry in configured.items():
        if not isinstance(entry, dict):
            raise ClosureError(f"csrCliBins entry must be an object: {bin_name}")
        keys = set(entry)
        if keys not in ({"package", "path"}, {"package", "path", "platformExecutables"}):
            raise ClosureError(f"csrCliBins entry has unexpected fields: {bin_name}")
        expected_package, expected_path = declared[bin_name]
        configured_path = checked_relative(entry.get("path"), label=f"csrCliBins {bin_name}")
        locked_path = checked_relative(expected_path, label=f"locked bin {bin_name}")
        if entry.get("package") != expected_package or configured_path != locked_path:
            raise ClosureError(f"csrCliBins does not match package bin metadata: {bin_name}")
        overrides = entry.get("platformExecutables")
        if overrides is None:
            continue
        if not isinstance(overrides, dict) or set(overrides) != supported_platforms:
            raise ClosureError(f"platform executable map must cover both Ubuntu architectures: {bin_name}")
        for platform_name, override in overrides.items():
            if not isinstance(override, dict) or set(override) != {"package", "path"}:
                raise ClosureError(f"invalid platform executable for {bin_name} on {platform_name}")
            source_package = override.get("package")
            if not isinstance(source_package, str) or not PACKAGE_NAME.fullmatch(source_package):
                raise ClosureError(f"invalid platform package for {bin_name} on {platform_name}")
            checked_relative(override.get("path"), label=f"platform executable {bin_name}")
            if f"node_modules/{source_package}" not in records:
                raise ClosureError(f"platform executable package is absent from lock: {source_package}")

    return package, lock, requested


def relock(npm: str = "npm") -> None:
    """Re-resolve the closure for the versions requested in npm-globals.txt.

    npm resolves the transitive lock from the public registry with an empty
    configuration, never the owner's ~/.npmrc. The new package.json and lock
    replace the old ones only when the closure contract still holds.
    """
    package = load_json(PACKAGE_JSON)
    requested = package_specs()
    package["dependencies"] = requested
    with tempfile.TemporaryDirectory(prefix="npm-closure-relock-") as scratch:
        work = Path(scratch) / "closure"
        work.mkdir()
        (work / "package.json").write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
        shutil.copy2(PACKAGE_LOCK, work / "package-lock.json")
        user_config = Path(scratch) / "user.npmrc"
        global_config = Path(scratch) / "global.npmrc"
        for config in (user_config, global_config):
            config.write_text("", encoding="utf-8")
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": scratch,
            "LANG": "C",
            "npm_config_userconfig": str(user_config),
            "npm_config_globalconfig": str(global_config),
            "npm_config_registry": "https://registry.npmjs.org/",
            "npm_config_cache": str(Path(scratch) / "cache"),
        }
        try:
            completed = subprocess.run(
                [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
                cwd=work,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=1200,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ClosureError("npm could not resolve the closure for npm-globals.txt") from exc
        if completed.returncode != 0:
            raise ClosureError("npm could not resolve the closure for npm-globals.txt")
        lock_bytes = (work / "package-lock.json").read_bytes()
    lock = json.loads(lock_bytes)
    records = lock.get("packages", {})
    declared: dict[str, tuple[str, str]] = {}
    for name in requested:
        record = records.get(f"node_modules/{name}")
        if isinstance(record, dict):
            for bin_name, target in normalized_bins(record.get("bin"), name).items():
                declared[bin_name] = (name, target)
    configured = package.get("csrCliBins") or {}
    order = [name for name in configured if name in declared] + sorted(set(declared) - set(configured))
    bins: dict[str, object] = {}
    for bin_name in order:
        entry = dict(configured.get(bin_name, {}))
        entry["package"], entry["path"] = declared[bin_name]
        bins[bin_name] = entry
    package["csrCliBins"] = bins
    previous = (PACKAGE_JSON.read_bytes(), PACKAGE_LOCK.read_bytes())
    PACKAGE_JSON.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
    PACKAGE_LOCK.write_bytes(lock_bytes)
    try:
        source_contract()
    except ClosureError:
        PACKAGE_JSON.write_bytes(previous[0])
        PACKAGE_LOCK.write_bytes(previous[1])
        raise


def source_digest() -> str:
    digest = hashlib.sha256()
    for path in (PACKAGE_JSON, PACKAGE_LOCK):
        data = path.read_bytes()
        digest.update(path.name.encode("ascii") + b"\x00")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


# bin/lib/openclaw_closure.py names the published directory after this digest and
# only then adds its manifest and completion marker at the root; they are not part
# of the npm tree, so the digest of a published closure leaves them out.
PUBLICATION_FILES = frozenset({".csr-tree-manifest.json", ".csr-tree-complete"})


def tree_digest(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ClosureError(f"closure root is missing, a symlink, or not a directory: {root}")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative in PUBLICATION_FILES:
            continue
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            record = f"D\0{relative}\0".encode()
        elif stat.S_ISREG(metadata.st_mode):
            content = hashlib.sha256(path.read_bytes()).hexdigest()
            executable = "1" if metadata.st_mode & 0o111 else "0"
            record = f"F\0{relative}\0{executable}\0{content}\0".encode()
        elif stat.S_ISLNK(metadata.st_mode):
            record = f"L\0{relative}\0{os.readlink(path)}\0".encode()
        else:
            raise ClosureError(f"closure contains unsupported filesystem object: {relative}")
        digest.update(record)
    return digest.hexdigest()


def checked_installed_path(root: Path, parts: tuple[str, ...], *, label: str) -> Path:
    path = root
    for part in parts:
        path /= part
        if path.is_symlink():
            raise ClosureError(f"{label} traverses a symlink: {path}")
    return path


def installed_package(root: Path, package_name: str) -> tuple[Path, dict[str, object]]:
    package_parts = tuple(PurePosixPath(package_name).parts)
    package_root = checked_installed_path(
        root, ("node_modules", *package_parts), label=f"installed package {package_name}"
    )
    manifest_path = checked_installed_path(
        root,
        ("node_modules", *package_parts, "package.json"),
        label=f"installed package manifest {package_name}",
    )
    if not package_root.is_dir() or not manifest_path.is_file():
        raise ClosureError(f"installed package is missing or invalid: {package_name}")
    return package_root, load_json(manifest_path)


def installed_file(root: Path, package_name: str, relative: object, *, label: str) -> Path:
    relative_path = checked_relative(relative, label=label)
    path = checked_installed_path(
        root,
        ("node_modules", *PurePosixPath(package_name).parts, *relative_path.parts),
        label=label,
    )
    if path.is_symlink() or not path.is_file():
        raise ClosureError(f"installed executable is missing, nonregular, or a symlink: {path}")
    if not os.access(path, os.X_OK):
        raise ClosureError(f"installed executable is not executable: {path}")
    return path


def verify_install(root: Path, arch: str, immutable: bool = False) -> tuple[dict[str, Path], dict[str, Path]]:
    package, lock, requested = source_contract()
    if arch not in {"amd64", "arm64"}:
        raise ClosureError(f"unsupported npm closure architecture: {arch}")
    if root.is_symlink() or not root.is_dir():
        raise ClosureError(f"installed closure root is invalid: {root}")
    for source in (PACKAGE_JSON, PACKAGE_LOCK):
        installed = root / source.name
        if installed.is_symlink() or not installed.is_file() or installed.read_bytes() != source.read_bytes():
            raise ClosureError(f"installed closure metadata differs from repository: {source.name}")

    records = lock["packages"]
    package_paths: dict[str, Path] = {}
    for name, version in requested.items():
        package_root, manifest = installed_package(root, name)
        if manifest.get("name") != name or manifest.get("version") != version:
            raise ClosureError(f"installed direct package version differs: {name}")
        package_paths[name] = package_root

    platform_name = f"linux/{arch}"
    bins: dict[str, Path] = {}
    configured = package["csrCliBins"]
    assert isinstance(configured, dict)
    for bin_name, raw_entry in configured.items():
        assert isinstance(raw_entry, dict)
        executable_package = raw_entry["package"]
        executable_path = raw_entry["path"]
        overrides = raw_entry.get("platformExecutables")
        if isinstance(overrides, dict):
            override = overrides[platform_name]
            assert isinstance(override, dict)
            executable_package = override["package"]
            executable_path = override["path"]
        locked_record = records[f"node_modules/{executable_package}"]
        assert isinstance(locked_record, dict)
        _, installed_manifest = installed_package(root, str(executable_package))
        if installed_manifest.get("version") != locked_record.get("version"):
            raise ClosureError(f"platform executable package version differs: {executable_package}")
        bins[bin_name] = installed_file(
            root,
            str(executable_package),
            executable_path,
            label=f"installed executable {bin_name}",
        )

    if immutable:
        for path in [root, *root.rglob("*")]:
            metadata = path.lstat()
            if not stat.S_ISLNK(metadata.st_mode) and metadata.st_mode & 0o222:
                raise ClosureError(f"installed closure contains writable content: {path.relative_to(root)}")
    return bins, package_paths


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="validate package list, package.json, and full package-lock")
    subparsers.add_parser("source-digest", help="print the source package/lock digest")
    subparsers.add_parser("relock", help="re-resolve package.json and the lock for npm-globals.txt")
    tree = subparsers.add_parser("tree-digest", help="print a deterministic installed-tree digest")
    tree.add_argument("root", type=Path)
    for command in ("verify-install", "emit-bins", "emit-packages"):
        installed = subparsers.add_parser(command)
        installed.add_argument("root", type=Path)
        installed.add_argument("--arch", choices=("amd64", "arm64"), required=True)
        installed.add_argument("--immutable", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "validate":
            _, lock, requested = source_contract()
            print(f"npm closure valid: {len(requested)} direct, {len(lock['packages']) - 1} total packages")
        elif args.command == "source-digest":
            source_contract()
            print(source_digest())
        elif args.command == "tree-digest":
            print(tree_digest(args.root))
        elif args.command == "relock":
            relock()
            _, lock, requested = source_contract()
            print(f"npm closure relocked: {len(requested)} direct, {len(lock['packages']) - 1} total packages")
        else:
            bins, packages = verify_install(args.root, args.arch, args.immutable)
            if args.command == "verify-install":
                print(f"npm closure install valid: {len(packages)} direct packages, {len(bins)} declared bins")
            elif args.command == "emit-bins":
                for name in sorted(bins):
                    print(f"{name}\t{bins[name]}")
            elif args.command == "emit-packages":
                for name in sorted(packages):
                    print(f"{name}\t{packages[name]}")
    except (ClosureError, KeyError, OSError) as exc:
        print(f"npm closure: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
