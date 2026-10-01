#!/usr/bin/env python3
"""Hostile fixtures for the full-transitive OpenClaw boundary, owned by the user (never root)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "bin/converge-openclaw-executable.py"
SPEC = importlib.util.spec_from_file_location("openclaw_contract", HELPER)
assert SPEC is not None and SPEC.loader is not None
contract_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract_module)
LAUNCHER = ROOT / "bin/openclaw-launcher.py"
LAUNCHER_SPEC = importlib.util.spec_from_file_location("openclaw_launcher", LAUNCHER)
assert LAUNCHER_SPEC is not None and LAUNCHER_SPEC.loader is not None
launcher_module = importlib.util.module_from_spec(LAUNCHER_SPEC)
LAUNCHER_SPEC.loader.exec_module(launcher_module)
CLOSURE_BUILDER = ROOT / "bin/lib/openclaw_closure.py"
CLOSURE_SPEC = importlib.util.spec_from_file_location(
    "openclaw_closure", CLOSURE_BUILDER
)
assert CLOSURE_SPEC is not None and CLOSURE_SPEC.loader is not None
closure_module = importlib.util.module_from_spec(CLOSURE_SPEC)
CLOSURE_SPEC.loader.exec_module(closure_module)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


class OpenClawExecutableContractTests(unittest.TestCase):
    def seal_tree(
        self,
        root: Path,
        *,
        arch: str,
        kind: str,
        files: dict[str, tuple[bytes, int]],
        links: dict[str, str] | None = None,
    ) -> str:
        root.mkdir(parents=True)
        links = links or {}
        for relative, (payload, mode) in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            path.chmod(mode)
        for relative, target in links.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(target)
        entries: list[dict[str, object]] = []
        directories = sorted(
            {
                parent
                for relative in [*files, *links]
                for parent in Path(relative).parents
                if parent != Path(".")
            },
            key=lambda path: path.as_posix(),
        )
        for directory in directories:
            (root / directory).chmod(0o555)
            entries.append(
                {"mode": "0555", "path": directory.as_posix(), "type": "directory"}
            )
        for relative, (payload, mode) in files.items():
            entries.append(
                {
                    "mode": f"{mode:04o}",
                    "path": relative,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                    "type": "file",
                }
            )
        for relative, target in links.items():
            entries.append({"path": relative, "target": target, "type": "symlink"})
        entries.sort(key=lambda entry: str(entry["path"]))
        manifest = {
            "arch": arch,
            "entries": entries,
            "identity": f"fixture-{arch}-{kind}",
            "kind": kind,
            "schema": contract_module.TREE_SCHEMA,
        }
        payload = canonical(manifest)
        digest = hashlib.sha256(payload).hexdigest()
        (root / contract_module.MANIFEST_NAME).write_bytes(payload)
        (root / contract_module.MANIFEST_NAME).chmod(0o444)
        (root / contract_module.MARKER_NAME).write_bytes(
            canonical(
                {
                    "manifest_sha256": digest,
                    "schema": contract_module.TREE_MARKER_SCHEMA,
                }
            )
        )
        (root / contract_module.MARKER_NAME).chmod(0o444)
        root.chmod(0o555)
        return digest

    def fixture(self, root: Path, arch: str = "amd64") -> tuple[Path, Path, Path, Path]:
        coding = root / "coding-system"
        node_root = coding / "node-generations" / f"fixture-{arch}"
        fake_node = (
            b"#!/usr/bin/python3\n"
            b"import json, os, sys\n"
            b"print('synthetic:' + json.dumps({'args': sys.argv[2:], 'entry': sys.argv[1], "
            b"'path': os.environ.get('PATH'), 'home': os.environ.get('HOME'), "
            b"'leaked': [name for name in ('OPENAI_API_KEY','NODE_OPTIONS','CSR_SECRET_CANARY') if name in os.environ]}, sort_keys=True))\n"
        )
        node_manifest = self.seal_tree(
            node_root,
            arch=arch,
            kind="node-runtime",
            files={"bin/node": (fake_node, 0o555)},
        )
        closure_root = coding / "npm-closures" / f"fixture-{arch}"
        entry = b"// synthetic OpenClaw entry\n"
        module = b"export const safe = true;\n"
        closure_manifest = self.seal_tree(
            closure_root,
            arch=arch,
            kind="npm-closure",
            files={
                "node_modules/openclaw/openclaw.mjs": (entry, 0o555),
                "node_modules/openclaw/dist/module.js": (module, 0o444),
                "node_modules/openclaw/dist/empty.js": (b"", 0o444),
                "node_modules/openclaw/package.json": (
                    b'{"name":"openclaw","version":"2026.7.1-2"}\n',
                    0o444,
                ),
            },
            links={"node_modules/openclaw/current.js": "dist/module.js"},
        )
        contract = root / "launcher/contract.json"
        contract.parent.mkdir(parents=True)
        contract.write_bytes(
            canonical(
                {
                    "arch": arch,
                    "closure_manifest_sha256": closure_manifest,
                    "closure_root": os.fspath(closure_root),
                    "entry": "node_modules/openclaw/openclaw.mjs",
                    "entry_sha256": hashlib.sha256(entry).hexdigest(),
                    "node": "bin/node",
                    "node_manifest_sha256": node_manifest,
                    "node_root": os.fspath(node_root),
                    "node_sha256": hashlib.sha256(fake_node).hexdigest(),
                    "package": "openclaw",
                    "schema": contract_module.EXPECTED_SCHEMA,
                    "version": "2026.7.1-2",
                }
            )
        )
        contract.chmod(0o444)
        home = root / "home"
        home.mkdir(mode=0o700)
        return coding, home, contract, closure_root

    def launcher_fixture(
        self, root: Path, arch: str = "amd64"
    ) -> tuple[Path, Path, Path, Path, Path, Path]:
        coding, home, source_contract, closure = self.fixture(root, arch)
        launcher_root = root / "openclaw-launchers"
        generations = launcher_root / "generations"
        selectors = launcher_root / "selectors"
        generations.mkdir(parents=True)
        selectors.mkdir()
        # resolve() requires each of these to be exactly 0755, but mkdir honours
        # the ambient umask, so under the common 0002 they land on 0775 and every
        # resolve() in this file fails.  Set the mode the contract demands.
        for directory in (launcher_root, generations, selectors):
            directory.chmod(0o755)
        helper_payload = HELPER.read_bytes()
        contract_payload = source_contract.read_bytes()
        helper_sha = hashlib.sha256(helper_payload).hexdigest()
        contract_sha = hashlib.sha256(contract_payload).hexdigest()
        marker_payload = canonical(
            {
                "contract_sha256": contract_sha,
                "helper_sha256": helper_sha,
                "schema": "coding-system.openclaw-launcher/v1",
            }
        )
        marker_sha = hashlib.sha256(marker_payload).hexdigest()
        generation_sha = hashlib.sha256(
            helper_payload + contract_payload + marker_payload
        ).hexdigest()
        generation = generations / f"sha256-{generation_sha}"
        generation.mkdir()
        helper = generation / "converge-openclaw-executable.py"
        contract = generation / "contract.json"
        marker = generation / ".csr-launcher-complete"
        for path, payload in (
            (helper, helper_payload),
            (contract, contract_payload),
            (marker, marker_payload),
        ):
            path.write_bytes(payload)
            path.chmod(0o444)
        generation.chmod(0o555)
        selector = selectors / f"{arch}.json"
        selector.write_bytes(
            canonical(
                {
                    "arch": arch,
                    "contract_sha256": contract_sha,
                    "helper_sha256": helper_sha,
                    "launcher_root": os.fspath(generation),
                    "marker_sha256": marker_sha,
                    "schema": launcher_module.SCHEMA,
                }
            )
        )
        selector.chmod(0o444)
        return launcher_root, coding, home, closure, generation, selector

    def converge(self, coding: Path, home: Path, contract: Path) -> dict[str, object]:
        return contract_module.converge(
            home,
            contract,
            apply=False,
            trusted_uid=os.getuid(),
            trusted_gid=os.getgid(),
            trusted_prefix=coding,
        )

    def test_full_transitive_manifests_verify_on_both_architectures(self) -> None:
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temporary:
                coding, home, contract, _closure = self.fixture(Path(temporary), arch)
                report = self.converge(coding, home, contract)
                self.assertEqual(report["arch"], arch)
                self.assertEqual(report["schema"], contract_module.EXPECTED_SCHEMA)
                self.assertEqual(report["status"], "verified")

    def test_exact_exec_uses_sealed_generation_and_closed_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            coding, home, contract, _closure = self.fixture(root)
            runner = (
                "import importlib.util, os, pathlib, sys;"
                "s=importlib.util.spec_from_file_location('m',sys.argv[1]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                "m.converge(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]),apply=False,"
                "exec_arguments=['credential-probe'],trusted_uid=os.getuid(),trusted_gid=os.getgid(),"
                "trusted_prefix=pathlib.Path(sys.argv[4]))"
            )
            observed = subprocess.run(
                ["/usr/bin/python3", "-I", "-B", "-c", runner, os.fspath(HELPER), os.fspath(home), os.fspath(contract), os.fspath(coding)],
                env={
                    **os.environ,
                    "PATH": os.fspath(root / "hostile"),
                    "NODE_OPTIONS": "--require=/evil.js",
                    "OPENAI_API_KEY": "must-not-leak",
                    "CSR_SECRET_CANARY": "must-not-leak",
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(observed.returncode, 0, observed.stderr)
            payload = json.loads(observed.stdout.removeprefix("synthetic:"))
            self.assertEqual(payload["args"], ["credential-probe"])
            self.assertEqual(payload["path"], "/usr/bin:/bin")
            self.assertEqual(payload["home"], os.fspath(home))
            self.assertEqual(payload["leaked"], [])
            self.assertTrue(payload["entry"].endswith("/node_modules/openclaw/openclaw.mjs"))

    def test_entry_transitive_module_marker_symlink_and_extra_mutations_fail(self) -> None:
        for case in ("entry", "transitive", "marker", "symlink", "extra", "node"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                coding, home, contract, closure = self.fixture(root)
                if case == "node":
                    target = coding / "node-generations/fixture-amd64/bin/node"
                    target.chmod(0o755)
                    target.write_text("#!/bin/sh\necho evil\n", encoding="utf-8")
                    target.chmod(0o555)
                elif case in {"entry", "transitive"}:
                    relative = (
                        "node_modules/openclaw/openclaw.mjs"
                        if case == "entry"
                        else "node_modules/openclaw/dist/module.js"
                    )
                    target = closure / relative
                    target.chmod(0o644)
                    target.write_text("evil\n", encoding="utf-8")
                    target.chmod(0o555 if case == "entry" else 0o444)
                elif case == "marker":
                    closure.chmod(0o755)
                    target = closure / contract_module.MARKER_NAME
                    target.chmod(0o644)
                    target.write_text("{}\n", encoding="utf-8")
                    target.chmod(0o444)
                    closure.chmod(0o555)
                elif case == "symlink":
                    parent = closure / "node_modules/openclaw"
                    parent.chmod(0o755)
                    target = parent / "current.js"
                    target.unlink()
                    target.symlink_to("openclaw.mjs")
                    parent.chmod(0o555)
                else:
                    closure.chmod(0o755)
                    (closure / "unexpected").write_text("evil\n", encoding="utf-8")
                    (closure / "unexpected").chmod(0o444)
                    closure.chmod(0o555)
                with self.assertRaises(contract_module.ContractError):
                    self.converge(coding, home, contract)

    def test_launcher_rejects_helper_contract_marker_selector_and_symlink_swaps(self) -> None:
        for case in ("helper", "contract", "marker", "selector", "symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                launcher_root, _coding, _home, _closure, generation, selector = (
                    self.launcher_fixture(Path(temporary))
                )
                helper = generation / "converge-openclaw-executable.py"
                contract = generation / "contract.json"
                marker = generation / ".csr-launcher-complete"
                if case == "symlink":
                    generation.chmod(0o755)
                    helper.unlink()
                    helper.symlink_to(contract.name)
                    generation.chmod(0o555)
                else:
                    target = {
                        "helper": helper,
                        "contract": contract,
                        "marker": marker,
                        "selector": selector,
                    }[case]
                    target.chmod(0o644)
                    target.write_bytes(b"{}\n")
                    target.chmod(0o444)
                with self.assertRaises(launcher_module.LauncherError):
                    launcher_module.resolve(
                        "amd64",
                        root=launcher_root,
                        trusted_uid=os.getuid(),
                        trusted_gid=os.getgid(),
                    )

    def test_launcher_resolves_each_architecture_from_exact_generation(self) -> None:
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temporary:
                launcher_root, _coding, _home, _closure, generation, _selector = (
                    self.launcher_fixture(Path(temporary), arch)
                )
                helper, contract, descriptor = launcher_module.resolve(
                    arch,
                    root=launcher_root,
                    trusted_uid=os.getuid(),
                    trusted_gid=os.getgid(),
                )
                os.close(descriptor)
                self.assertEqual(helper.parent, generation)
                self.assertEqual(contract.parent, generation)

    def test_builder_has_exact_platform_inputs_for_both_architectures(self) -> None:
        observed: dict[str, str] = {}
        for arch in ("amd64", "arm64"):
            _profile, artifacts = closure_module._platform_lock(ROOT, arch)
            observed[arch] = artifacts["node"]["sha256"]
            self.assertIn(f"linux-{'x64' if arch == 'amd64' else 'arm64'}", artifacts["node"]["url"])
            for identifier in closure_module.ARTIFACT_IDS:
                self.assertRegex(artifacts[identifier]["sha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(artifacts[identifier]["version"], "0.9.2")
        self.assertNotEqual(observed["amd64"], observed["arm64"])

    def run_helper(self, home: Path, contract: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                os.fspath(HELPER),
                "--home",
                os.fspath(home),
                "--contract",
                os.fspath(contract),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_production_cli_trusts_only_the_owner_coding_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            owner_home = Path(temporary) / "owner"
            share = owner_home / ".local/share"
            share.mkdir(parents=True)
            owner_home.chmod(0o700)
            _coding, _home, contract, _closure = self.fixture(share)
            accepted = self.run_helper(owner_home, contract)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(json.loads(accepted.stdout)["status"], "verified")
            other_home = Path(temporary) / "other"
            other_home.mkdir(mode=0o700)
            refused = self.run_helper(other_home, contract)
            self.assertEqual(refused.returncode, 2)
            self.assertIn("invalid closure root", refused.stderr)

    def test_launcher_helper_and_builder_refuse_root(self) -> None:
        saved_argv, real_geteuid = sys.argv, os.geteuid
        try:
            os.geteuid = lambda: 0
            sys.argv = ["converge", "--home", "/nonexistent", "--contract", "/nonexistent"]
            self.assertEqual(contract_module.main(), 2)
            sys.argv = ["launcher", "--home", "/nonexistent", "--resolve-json"]
            self.assertEqual(launcher_module.main(), 2)
        finally:
            os.geteuid = real_geteuid
            sys.argv = saved_argv
        saved_owner = closure_module.OWNER_UID
        try:
            closure_module.OWNER_UID = 0
            sys.argv = ["openclaw_closure", "publish-node", "--repository", "/nonexistent", "--arch", "amd64"]
            with self.assertRaisesRegex(closure_module.ClosureError, "never by root"):
                closure_module.main()
        finally:
            closure_module.OWNER_UID = saved_owner
            sys.argv = saved_argv

    def test_install_and_wrapper_use_only_the_owner_launcher(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        wrapper = (ROOT / "system/bin/openclaw").read_text(encoding="utf-8")
        prepare = (ROOT / "bin/prepare.sh").read_text(encoding="utf-8")
        self.assertIn('"$HOME/.local/share/coding-system/openclaw-launchers/loader.py"', install)
        self.assertIn(
            '"$RESTORE_HOME/.local/share/coding-system/openclaw-launchers/loader.py"', wrapper
        )
        self.assertIn("openclaw_closure.py", prepare)
        self.assertNotIn("$REPOSITORY/bin/converge-openclaw-executable.py", wrapper)
        node_and_npm = prepare.split('step "Node.js locked binary distribution"', 1)[1].split(
            'step "pipx tools"', 1
        )[0]
        self.assertNotIn("sudo", node_and_npm)
        for text in (install, wrapper, prepare):
            for retired in ("openclaw-launchers", "node-generations", "npm-closures"):
                self.assertNotIn(f"/usr/local/libexec/coding-system/{retired}", text)

if __name__ == "__main__":
    unittest.main()
