"""Strict owner-only registry for reusable iOS Tailscale exit nodes."""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import unicodedata
from typing import Any, Iterable


REGISTRY_SCHEMA_VERSION = 1
MAX_DEVICES = 16
MAX_REGISTRY_BYTES = 65_536
_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_NODE_RE = re.compile(r"^[A-Za-z0-9._:+/@-]{1,256}$")


class IosRegistryError(ValueError):
    """The iOS registry is unsafe, malformed, or semantically ambiguous."""


class IosRegistryMissing(IosRegistryError):
    """No canonical registry has been published yet."""


def _fail(message: str) -> IosRegistryError:
    return IosRegistryError(message)


@dataclass(frozen=True, slots=True)
class IosDevice:
    key: str
    stable_node_id: str

    def __post_init__(self) -> None:
        if type(self.key) is not str or _KEY_RE.fullmatch(self.key) is None:
            raise _fail("device key has unsupported characters")
        if (
            type(self.stable_node_id) is not str
            or _NODE_RE.fullmatch(self.stable_node_id) is None
            or self.stable_node_id.startswith("-")
        ):
            raise _fail("stable node ID has unsupported characters")

    def to_dict(self) -> dict[str, str]:
        return {"key": self.key, "stable_node_id": self.stable_node_id}

    @classmethod
    def from_dict(cls, value: Any, path: str = "device") -> "IosDevice":
        if type(value) is not dict or set(value) != {"key", "stable_node_id"}:
            raise _fail(f"{path} has missing or unexpected fields")
        try:
            return cls(key=value["key"], stable_node_id=value["stable_node_id"])
        except IosRegistryError as exc:
            raise _fail(f"{path}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class IosRegistry:
    devices: tuple[IosDevice, ...]

    def __post_init__(self) -> None:
        if type(self.devices) is not tuple:
            raise _fail("devices must be an immutable tuple")
        if len(self.devices) > MAX_DEVICES:
            raise _fail(f"registry supports at most {MAX_DEVICES} devices")
        keys: set[str] = set()
        node_ids: set[str] = set()
        for index, device in enumerate(self.devices):
            if not isinstance(device, IosDevice):
                raise _fail(f"devices[{index}] is not an IosDevice")
            if device.key in keys:
                raise _fail(f"duplicate device key {device.key!r}")
            if device.stable_node_id in node_ids:
                raise _fail(f"duplicate stable node ID {device.stable_node_id!r}")
            keys.add(device.key)
            node_ids.add(device.stable_node_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "devices": [device.to_dict() for device in self.devices],
        }

    @classmethod
    def from_dict(cls, value: Any) -> "IosRegistry":
        if type(value) is not dict or set(value) != {"schema_version", "devices"}:
            raise _fail("registry has missing or unexpected fields")
        if value["schema_version"] != REGISTRY_SCHEMA_VERSION:
            raise _fail("registry schema version is unsupported")
        devices = value["devices"]
        if type(devices) is not list:
            raise _fail("registry devices must be an array")
        return cls(
            tuple(
                IosDevice.from_dict(item, f"devices[{index}]")
                for index, item in enumerate(devices)
            )
        )

    def by_key(self, key: str) -> IosDevice | None:
        return next((device for device in self.devices if device.key == key), None)

    def by_node_id(self, node_id: str) -> IosDevice | None:
        return next(
            (device for device in self.devices if device.stable_node_id == node_id),
            None,
        )

    def remove(self, key: str) -> "IosRegistry":
        if self.by_key(key) is None:
            raise _fail(f"unknown iOS device key {key!r}")
        return IosRegistry(tuple(device for device in self.devices if device.key != key))

    def reorder(self, keys: Iterable[str]) -> "IosRegistry":
        ordered = tuple(keys)
        current = tuple(device.key for device in self.devices)
        if len(ordered) != len(set(ordered)):
            raise _fail("reorder contains a duplicate key")
        if set(ordered) != set(current) or len(ordered) != len(current):
            raise _fail("reorder must be an exact permutation of registered keys")
        mapping = {device.key: device for device in self.devices}
        return IosRegistry(tuple(mapping[key] for key in ordered))


def register_device(registry: IosRegistry, device: IosDevice) -> IosRegistry:
    by_key = registry.by_key(device.key)
    by_id = registry.by_node_id(device.stable_node_id)
    if by_key is not None:
        if by_key == device:
            return registry
        raise _fail(
            f"device key {device.key!r} already maps to another stable node ID"
        )
    if by_id is not None:
        raise _fail(
            f"stable node ID already belongs to device key {by_id.key!r}"
        )
    return IosRegistry((*registry.devices, device))


def derive_device_key(name: str) -> str:
    if type(name) is not str:
        raise _fail("device name must be text")
    normalized = name.strip().rstrip(".")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise _fail("cannot derive a device key from an IP address; pass --label KEY")
    candidate = normalized.split(".", 1)[0]
    ascii_name = (
        unicodedata.normalize("NFKD", candidate)
        .encode("ascii", "ignore")
        .decode("ascii")
        .lower()
    )
    key = re.sub(r"[^a-z0-9._-]+", "-", ascii_name)
    key = re.sub(r"[-_.]{2,}", "-", key).strip("-_.")[:64].rstrip("-_.")
    if _KEY_RE.fullmatch(key) is None:
        raise _fail("cannot derive a valid device key; pass --label KEY")
    return key


def canonical_registry_bytes(registry: IosRegistry) -> bytes:
    if not isinstance(registry, IosRegistry):
        raise TypeError("registry must be an IosRegistry")
    return (
        json.dumps(
            registry.to_dict(),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _open_registry_directory(path: Path, expected_uid: int) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _fail(f"cannot open registry directory {path}: {exc}") from exc
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise _fail(f"unsafe owner/type/mode for registry directory {path}")
    return descriptor


def load_registry(
    path: Path,
    *,
    expected_uid: int | None = None,
    allow_missing: bool = True,
) -> IosRegistry:
    expected = os.getuid() if expected_uid is None else expected_uid
    try:
        directory = _open_registry_directory(path.parent, expected)
    except IosRegistryError:
        if allow_missing and not path.parent.exists():
            return IosRegistry(())
        if not path.parent.exists():
            raise IosRegistryMissing(f"registry is missing: {path}")
        raise
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path.name, flags, dir_fd=directory)
        except FileNotFoundError:
            if allow_missing:
                return IosRegistry(())
            raise IosRegistryMissing(f"registry is missing: {path}")
        except OSError as exc:
            raise _fail(f"cannot open registry {path}: {exc}") from exc
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > MAX_REGISTRY_BYTES
        ):
            raise _fail(f"unsafe owner/type/mode/size for registry {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, MAX_REGISTRY_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_REGISTRY_BYTES:
                raise _fail(f"oversized registry {path}")
        try:
            value = json.loads(b"".join(chunks))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _fail(f"invalid registry JSON: {exc}") from exc
        return IosRegistry.from_dict(value)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def _load_private_text(path: Path, *, expected_uid: int) -> str | None:
    try:
        directory = _open_registry_directory(path.parent, expected_uid)
    except IosRegistryError:
        if not path.parent.exists():
            return None
        raise
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.name, flags, dir_fd=directory)
    except FileNotFoundError:
        os.close(directory)
        return None
    except OSError as exc:
        os.close(directory)
        raise _fail(f"cannot open legacy state {path}: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or not 1 <= info.st_size <= 512
        ):
            raise _fail(f"unsafe legacy state {path}")
        data = os.read(descriptor, 513)
        if len(data) > 512 or os.read(descriptor, 1):
            raise _fail(f"oversized legacy state {path}")
    finally:
        os.close(descriptor)
        os.close(directory)
    try:
        return data.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise _fail(f"legacy state is not ASCII: {path}") from exc


def load_legacy_device(
    node_path: Path,
    ready_path: Path,
    *,
    expected_uid: int | None = None,
) -> IosDevice | None:
    expected = os.getuid() if expected_uid is None else expected_uid
    node = _load_private_text(node_path, expected_uid=expected)
    ready = _load_private_text(ready_path, expected_uid=expected)
    if node is None or ready is None:
        return None
    if node != ready:
        return None
    return IosDevice("iphone", node)


def load_effective_registry(
    path: Path,
    legacy_node_path: Path,
    legacy_ready_path: Path,
    *,
    expected_uid: int | None = None,
) -> IosRegistry:
    expected = os.getuid() if expected_uid is None else expected_uid
    try:
        return load_registry(path, expected_uid=expected, allow_missing=False)
    except IosRegistryMissing:
        legacy = load_legacy_device(
            legacy_node_path,
            legacy_ready_path,
            expected_uid=expected,
        )
        return IosRegistry(()) if legacy is None else IosRegistry((legacy,))


def migrate_legacy_registry(
    path: Path,
    legacy_node_path: Path,
    legacy_ready_path: Path,
    *,
    expected_uid: int | None = None,
) -> IosRegistry:
    """Publish one canonical registry from a valid legacy pair, once."""

    expected = os.getuid() if expected_uid is None else expected_uid
    try:
        return load_registry(path, expected_uid=expected, allow_missing=False)
    except IosRegistryMissing:
        legacy = load_legacy_device(
            legacy_node_path,
            legacy_ready_path,
            expected_uid=expected,
        )
        if legacy is None:
            return IosRegistry(())
        registry = IosRegistry((legacy,))
        write_registry(path, registry, expected_uid=expected)
        return registry


def write_registry(
    path: Path,
    registry: IosRegistry,
    *,
    expected_uid: int | None = None,
) -> None:
    expected = os.getuid() if expected_uid is None else expected_uid
    payload = canonical_registry_bytes(registry)
    if len(payload) > MAX_REGISTRY_BYTES:
        raise _fail("encoded registry is oversized")
    directory = _open_registry_directory(path.parent, expected)
    temporary = f".{path.name}.{secrets.token_hex(12)}.tmp"
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("short registry write")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary,
            path.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        os.fsync(directory)
    except OSError as exc:
        raise _fail(f"cannot publish registry {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def _paths(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    return Path(args.registry), Path(args.legacy_node), Path(args.legacy_ready)


def _cli_registry(args: argparse.Namespace) -> IosRegistry:
    registry, legacy_node, legacy_ready = _paths(args)
    return load_effective_registry(registry, legacy_node, legacy_ready)


def _cli_devices(args: argparse.Namespace) -> int:
    for device in _cli_registry(args).devices:
        print(f"{device.key}\t{device.stable_node_id}")
    return 0


def _cli_migrate(args: argparse.Namespace) -> int:
    registry, legacy_node, legacy_ready = _paths(args)
    migrated = migrate_legacy_registry(registry, legacy_node, legacy_ready)
    for device in migrated.devices:
        print(f"{device.key}\t{device.stable_node_id}")
    return 0


def _cli_node(args: argparse.Namespace) -> int:
    device = _cli_registry(args).by_key(args.key)
    if device is None:
        raise _fail(f"unknown iOS device key {args.key!r}")
    print(device.stable_node_id)
    return 0


def _cli_register(args: argparse.Namespace) -> int:
    path, _legacy_node, _legacy_ready = _paths(args)
    registry = _cli_registry(args)
    existing = registry.by_node_id(args.node_id)
    if existing is not None:
        requested_key = (
            args.label
            if args.label is not None
            else derive_device_key(args.name_hint)
        )
        if requested_key == existing.key:
            device = existing
        elif existing.key == "iphone" and len(registry.devices) == 1:
            if registry.by_key(requested_key) is not None:
                raise _fail(f"device key {requested_key!r} is already registered")
            device = IosDevice(requested_key, args.node_id)
            registry = IosRegistry(
                tuple(
                    device if item == existing else item
                    for item in registry.devices
                )
            )
        elif args.label is None:
            device = existing
        else:
            raise _fail(
                f"stable node ID already belongs to device key {existing.key!r}"
            )
    else:
        key = args.label if args.label is not None else derive_device_key(args.name_hint)
        device = IosDevice(key, args.node_id)
        registry = register_device(registry, device)
    write_registry(path, registry)
    print(device.key)
    return 0


def _cli_remove(args: argparse.Namespace) -> int:
    path, _legacy_node, _legacy_ready = _paths(args)
    write_registry(path, _cli_registry(args).remove(args.key))
    return 0


def _cli_reorder(args: argparse.Namespace) -> int:
    path, _legacy_node, _legacy_ready = _paths(args)
    write_registry(path, _cli_registry(args).reorder(tuple(args.keys)))
    return 0


def _cli_json(args: argparse.Namespace) -> int:
    registry = _cli_registry(args)
    value = registry.to_dict()
    if args.redacted:
        value = {
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "devices": [
                {
                    "key": device.key,
                    "stable_node_id_sha256": hashlib.sha256(
                        device.stable_node_id.encode("ascii")
                    ).hexdigest(),
                }
                for device in registry.devices
            ],
        }
    print(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    common = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    common.add_argument("--registry", required=True)
    common.add_argument("--legacy-node", required=True)
    common.add_argument("--legacy-ready", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    devices = commands.add_parser("devices", parents=[common], allow_abbrev=False)
    devices.set_defaults(handler=_cli_devices)
    migrate = commands.add_parser("migrate", parents=[common], allow_abbrev=False)
    migrate.set_defaults(handler=_cli_migrate)
    node = commands.add_parser("node", parents=[common], allow_abbrev=False)
    node.add_argument("key")
    node.set_defaults(handler=_cli_node)
    register = commands.add_parser("register", parents=[common], allow_abbrev=False)
    register.add_argument("--node-id", required=True)
    register.add_argument("--name-hint", required=True)
    register.add_argument("--label")
    register.set_defaults(handler=_cli_register)
    remove = commands.add_parser("remove", parents=[common], allow_abbrev=False)
    remove.add_argument("key")
    remove.set_defaults(handler=_cli_remove)
    reorder = commands.add_parser("reorder", parents=[common], allow_abbrev=False)
    reorder.add_argument("keys", nargs="+")
    reorder.set_defaults(handler=_cli_reorder)
    json_command = commands.add_parser("json", parents=[common], allow_abbrev=False)
    json_command.add_argument("--redacted", action="store_true")
    json_command.set_defaults(handler=_cli_json)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (IosRegistryError, OSError) as exc:
        print(f"ios_registry: {exc}", file=os.sys.stderr)
        return 2


__all__ = [
    "IosDevice",
    "IosRegistry",
    "IosRegistryError",
    "IosRegistryMissing",
    "MAX_DEVICES",
    "REGISTRY_SCHEMA_VERSION",
    "canonical_registry_bytes",
    "derive_device_key",
    "load_registry",
    "load_effective_registry",
    "load_legacy_device",
    "migrate_legacy_registry",
    "register_device",
    "write_registry",
]


if __name__ == "__main__":
    raise SystemExit(main())
