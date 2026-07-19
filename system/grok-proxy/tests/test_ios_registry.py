#!/usr/bin/env python3
"""Deterministic tests for the private multi-device iOS registry."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from grok_ms.ios_registry import (  # noqa: E402
    IosDevice,
    IosRegistry,
    IosRegistryError,
    derive_device_key,
    load_effective_registry,
    load_registry,
    migrate_legacy_registry,
    register_device,
    write_registry,
)


class IosRegistryTests(unittest.TestCase):
    def test_canonical_round_trip_and_order(self) -> None:
        registry = IosRegistry(
            (
                IosDevice("iphone-xr", "n-phone"),
                IosDevice("ipad-pro", "n-tablet"),
            )
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "iphone"
            root.mkdir(mode=0o700)
            path = root / "devices.json"
            write_registry(path, registry)
            self.assertEqual(load_registry(path), registry)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(
                path.read_bytes(),
                b'{"devices":[{"key":"iphone-xr","stable_node_id":"n-phone"},'
                b'{"key":"ipad-pro","stable_node_id":"n-tablet"}],"schema_version":1}\n',
            )

    def test_registration_is_additive_idempotent_and_never_rebinds(self) -> None:
        initial = IosRegistry((IosDevice("iphone-xr", "n-phone"),))
        same = register_device(initial, IosDevice("iphone-xr", "n-phone"))
        self.assertIs(same, initial)
        appended = register_device(initial, IosDevice("ipad-pro", "n-tablet"))
        self.assertEqual(
            tuple(device.key for device in appended.devices),
            ("iphone-xr", "ipad-pro"),
        )
        with self.assertRaisesRegex(IosRegistryError, "already belongs"):
            register_device(initial, IosDevice("other", "n-phone"))
        with self.assertRaisesRegex(IosRegistryError, "already maps"):
            register_device(initial, IosDevice("iphone-xr", "n-other"))

    def test_remove_and_reorder_require_exact_known_keys(self) -> None:
        registry = IosRegistry(
            (IosDevice("a", "n-a"), IosDevice("b", "n-b"))
        )
        self.assertEqual(
            registry.reorder(("b", "a")).devices,
            (IosDevice("b", "n-b"), IosDevice("a", "n-a")),
        )
        self.assertEqual(registry.remove("a").devices, (IosDevice("b", "n-b"),))
        for keys in (("a",), ("a", "a"), ("a", "missing")):
            with self.assertRaises(IosRegistryError):
                registry.reorder(keys)
        with self.assertRaisesRegex(IosRegistryError, "unknown"):
            registry.remove("missing")

    def test_strict_shape_keys_ids_limit_and_secure_metadata(self) -> None:
        for key in ("", "Upper", "bad/key", "-bad", "a" * 65):
            with self.assertRaises(IosRegistryError, msg=key):
                IosDevice(key, "n-id")
        for node in ("", "has space", "-option", "x" * 257):
            with self.assertRaises(IosRegistryError, msg=node):
                IosDevice("valid", node)
        with self.assertRaisesRegex(IosRegistryError, "at most 16"):
            IosRegistry(tuple(IosDevice(f"d{i}", f"n-{i}") for i in range(17)))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "iphone"
            root.mkdir(mode=0o700)
            path = root / "devices.json"
            path.write_text('{"schema_version":1,"devices":[]}\n', encoding="ascii")
            path.chmod(0o644)
            with self.assertRaises(IosRegistryError):
                load_registry(path)
            path.unlink()
            target = root / "target"
            target.write_text('{"schema_version":1,"devices":[]}\n', encoding="ascii")
            target.chmod(0o600)
            path.symlink_to(target)
            with self.assertRaises(IosRegistryError):
                load_registry(path)

    def test_missing_registry_and_key_derivation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(load_registry(Path(td) / "missing"), IosRegistry(()))
        self.assertEqual(
            derive_device_key("ipad-pro-12-9-gen-5.tail.example.ts.net."),
            "ipad-pro-12-9-gen-5",
        )
        self.assertEqual(derive_device_key("My iPhone!"), "my-iphone")
        with self.assertRaises(IosRegistryError):
            derive_device_key("---")
        with self.assertRaisesRegex(IosRegistryError, "IP address"):
            derive_device_key("100.64.0.99")

    def test_legacy_pair_is_imported_once_without_live_device_access(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "iphone"
            root.mkdir(mode=0o700)
            node = root / "exit-node"
            ready = root / "ready"
            node.write_text("n-legacy-phone\n", encoding="ascii")
            ready.write_text("n-legacy-phone\n", encoding="ascii")
            node.chmod(0o600)
            ready.chmod(0o600)
            path = root / "devices.json"

            effective = load_effective_registry(path, node, ready)
            self.assertEqual(
                effective.devices,
                (IosDevice("iphone", "n-legacy-phone"),),
            )
            self.assertFalse(path.exists())

            command = [
                sys.executable,
                str(ROOT / "grok_ms/ios_registry.py"),
                "devices",
                "--registry",
                str(path),
                "--legacy-node",
                str(node),
                "--legacy-ready",
                str(ready),
            ]
            listed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(listed.returncode, 0, listed.stderr)
            self.assertEqual(listed.stdout, "iphone\tn-legacy-phone\n")
            self.assertFalse(path.exists())

            migrated = migrate_legacy_registry(path, node, ready)
            self.assertEqual(migrated, effective)
            self.assertEqual(load_registry(path), effective)
            node.write_text("n-changed-after-migration\n", encoding="ascii")
            self.assertEqual(migrate_legacy_registry(path, node, ready), effective)

    def test_legacy_import_rejects_an_unsafe_or_linked_parent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            unsafe = base / "unsafe"
            unsafe.mkdir(mode=0o755)
            node = unsafe / "exit-node"
            ready = unsafe / "ready"
            node.write_text("n-phone\n", encoding="ascii")
            ready.write_text("n-phone\n", encoding="ascii")
            node.chmod(0o600)
            ready.chmod(0o600)
            with self.assertRaisesRegex(IosRegistryError, "registry directory"):
                load_effective_registry(unsafe / "devices.json", node, ready)

            unsafe.chmod(0o700)
            linked = base / "linked"
            linked.symlink_to(unsafe, target_is_directory=True)
            with self.assertRaises(IosRegistryError):
                load_effective_registry(
                    linked / "devices.json",
                    linked / "exit-node",
                    linked / "ready",
                )

    def test_setup_registration_upgrades_only_the_single_legacy_key(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "iphone"
            root.mkdir(mode=0o700)
            path = root / "devices.json"
            node = root / "exit-node"
            ready = root / "ready"
            node.write_text("n-phone\n", encoding="ascii")
            ready.write_text("n-phone\n", encoding="ascii")
            node.chmod(0o600)
            ready.chmod(0o600)
            migrate_legacy_registry(path, node, ready)
            command = [
                sys.executable,
                str(ROOT / "grok_ms/ios_registry.py"),
                "register",
                "--node-id",
                "n-phone",
                "--name-hint",
                "iphone-xr.tail.example.ts.net.",
                "--registry",
                str(path),
                "--legacy-node",
                str(node),
                "--legacy-ready",
                str(ready),
            ]
            upgraded = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(upgraded.returncode, 0, upgraded.stderr)
            self.assertEqual(upgraded.stdout.strip(), "iphone-xr")
            self.assertEqual(
                load_registry(path).devices,
                (IosDevice("iphone-xr", "n-phone"),),
            )


if __name__ == "__main__":
    unittest.main()
