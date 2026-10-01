#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import platform
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
# The compatibility checkout sits beside the repository on the reference host
# and in $HOME on a fresh one (bin/components.sh).
AAS_CHECKOUT = next(
    (path for path in (ROOT.parent / "ai-agents-skills", Path.home() / "ai-agents-skills") if path.is_dir()),
    ROOT.parent / "ai-agents-skills",
)
TEMPLATE = ROOT / "system/bin/copilot"
MATERIALIZER = ROOT / "bin/materialize-secret-projections.py"


class CopilotWrapperTests(unittest.TestCase):
    def render(self, home: Path) -> Path:
        wrapper = home / ".local/bin/copilot"
        wrapper.parent.mkdir(parents=True)
        machine = platform.machine().lower()
        arch = "arm64" if machine in {"aarch64", "arm64"} else "amd64"
        node = home / (
            f".local/share/coding-system/node-generations/sha256-{arch}-" + "e" * 64 + "/bin/node"
        )
        node.parent.mkdir(parents=True)
        # The shared secret loader projects a minimal child environment, so the
        # report lands under HOME — one of the few names it retains — instead of
        # a caller-supplied variable the loader is expected to drop.
        node.write_text(
            "#!/usr/bin/python3\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['HOME'], 'result.json').write_text(json.dumps({\n"
            "  'argv': sys.argv[1:],\n"
            "  'copilot': os.environ.get('COPILOT_GITHUB_TOKEN'),\n"
            "  'gh': os.environ.get('GH_TOKEN'),\n"
            "  'github': os.environ.get('GITHUB_TOKEN'),\n"
            "  'openai': os.environ.get('OPENAI_API_KEY'),\n"
            "  'byok_api': os.environ.get('COPILOT_PROVIDER_API_KEY'),\n"
            "  'byok_bearer': os.environ.get('COPILOT_PROVIDER_BEARER_TOKEN'),\n"
            "  'bash_env': os.environ.get('BASH_ENV'),\n"
            "  'node_options': os.environ.get('NODE_OPTIONS'),\n"
            "  'pointer': os.environ.get('AAS_PROVIDER_SECRETS_FILE'),\n"
            "}))\n",
            encoding="utf-8",
        )
        node.chmod(0o755)
        node_link = home / ".npm-global/bin/node"
        node_link.parent.mkdir(parents=True, exist_ok=True)
        node_link.symlink_to(node)
        cli_loader = (
            home
            / (
                f".local/share/coding-system/npm-closures/sha256-{arch}-"
                + "a" * 64
                + "-"
                + "b" * 64
                + "/node_modules/@github/copilot/npm-loader.js"
            )
        )
        cli_loader.parent.mkdir(parents=True)
        cli_loader.write_text("// test loader\n", encoding="utf-8")
        cli_loader.chmod(0o444)
        compatibility = home / ".npm-global/lib/node_modules/@github/copilot"
        compatibility.parent.mkdir(parents=True)
        compatibility.symlink_to(cli_loader.parent)
        wrapper.write_text(
            TEMPLATE.read_text(encoding="utf-8")
            .replace("{{ HOME }}", str(home))
            .replace("{{ COPILOT_LOADER }}", str(cli_loader)),
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        return wrapper

    def add_secret_loader(self, home: Path) -> None:
        source = AAS_CHECKOUT / "canonical/runtime/runners"
        runtime = home / ".local/share/ai-agents-skills/runtime"
        runners = runtime / "runners"
        runners.mkdir(parents=True)
        shutil.copy2(source / "load_secret_env.py", runtime / "load_secret_env.py")
        (runtime / "load_secret_env.py").chmod(0o644)
        for name in (
            "credential_projection_probe.py",
            "credential_projection_check.py",
        ):
            shutil.copy2(source / name, runners / name)
            (runners / name).chmod(0o644)

    def write_copilot_authority(self, home: Path, payload: str) -> Path:
        authority = home / ".config/ai-agents-skills/providers/copilot.env"
        authority.parent.mkdir(parents=True)
        authority.write_text(payload, encoding="utf-8")
        authority.chmod(0o600)
        return authority

    def test_projects_only_copilot_tokens_without_secret_argv_or_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            wrapper = self.render(home)
            self.add_secret_loader(home)
            authority = self.write_copilot_authority(
                home,
                "GH_TOKEN=restored-copilot-secret\n"
                "COPILOT_PROVIDER_BEARER_TOKEN=restored-byok-secret\n",
            )
            output = home / "result.json"
            env = {
                "HOME": str(home),
                "PATH": "/usr/bin:/bin",
                "COPILOT_GITHUB_TOKEN": "stale-high-precedence-secret",
                "OPENAI_API_KEY": "stale-openai-secret",
                # The broad ARL pointer is a target-selection cue, never the
                # authority opened by the native Copilot launcher.
                "AAS_PROVIDER_SECRETS_FILE": str(
                    home / ".config/ai-agents-skills/providers.env"
                ),
            }

            completed = subprocess.run(
                [str(wrapper), "--no-auto-update", "-p", "offline-fixture"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["gh"], "restored-copilot-secret")
            self.assertIsNone(result["copilot"])
            self.assertIsNone(result["github"])
            self.assertEqual(result["byok_bearer"], "restored-byok-secret")
            self.assertIsNone(result["byok_api"])
            self.assertIsNone(result["openai"])
            self.assertIsNone(result["pointer"])
            argv = " ".join(result["argv"])
            self.assertIn(
                "--secret-env-vars=COPILOT_GITHUB_TOKEN,COPILOT_PROVIDER_API_KEY,"
                "COPILOT_PROVIDER_BEARER_TOKEN,GH_TOKEN,GITHUB_TOKEN",
                result["argv"],
            )
            for secret in (
                "restored-copilot-secret",
                "restored-openai-secret",
                "restored-byok-secret",
                "stale-high-precedence-secret",
                "stale-openai-secret",
            ):
                self.assertNotIn(secret, argv + completed.stdout + completed.stderr)

    def test_version_does_not_require_provider_authority_or_secret_loader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            wrapper = self.render(home)
            output = home / "result.json"
            completed = subprocess.run(
                [str(wrapper), "--version"],
                env={
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin",
                    "GH_TOKEN": "ambient-secret-never-pass",
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertIsNone(result["gh"])
            self.assertEqual(result["argv"][-1], "--version")

    def test_copilot_authority_rejects_broad_provider_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            wrapper = self.render(home)
            self.add_secret_loader(home)
            self.write_copilot_authority(
                home,
                "GH_TOKEN=copilot-fixture\n"
                "OPENAI_API_KEY=must-never-enter-native-copilot\n",
            )
            output = home / "result.json"
            completed = subprocess.run(
                [str(wrapper), "-p", "offline-fixture"],
                env={
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin",
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(output.exists())
            self.assertNotIn(
                "must-never-enter-native-copilot",
                completed.stdout + completed.stderr,
            )

    def test_arbitrary_provider_pointer_is_rejected_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            wrapper = self.render(home)
            self.add_secret_loader(home)
            self.write_copilot_authority(home, "GH_TOKEN=managed-fixture\n")
            hostile = home / "hostile.env"
            hostile.write_text("GH_TOKEN=hostile-fixture\n", encoding="utf-8")
            hostile.chmod(0o600)
            output = home / "result.json"
            completed = subprocess.run(
                [str(wrapper), "-p", "offline-fixture"],
                env={
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin",
                    "AAS_PROVIDER_SECRETS_FILE": str(hostile),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 127)
            self.assertFalse(output.exists())
            self.assertNotIn("hostile-fixture", completed.stdout + completed.stderr)

    def test_no_authority_fails_closed_without_inheriting_caller_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            wrapper = self.render(home)
            output = home / "result.json"
            completed = subprocess.run(
                [str(wrapper), "-p", "offline-fixture"],
                env={
                    "HOME": str(home),
                    "PATH": "/hostile/path",
                    "GH_TOKEN": "caller-copilot-secret",
                    "OPENAI_API_KEY": "ambient-openai-secret",
                    "NODE_OPTIONS": "--require=/must/not/run.js",
                    "NODE_PATH": "/must/not/search",
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 127)
            self.assertFalse(output.exists())
            self.assertNotIn(
                "caller-copilot-secret", completed.stdout + completed.stderr
            )

    def test_metadata_routes_are_auth_free_even_after_global_options(self) -> None:
        for arguments in (
            ["-v"],
            ["--no-color", "--help"],
            ["--no-color", "login"],
            ["completion", "bash"],
        ):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                wrapper = self.render(home)
                output = home / "result.json"
                completed = subprocess.run(
                    [str(wrapper), *arguments],
                    env={
                        "HOME": str(home),
                        "PATH": "/usr/bin:/bin",
                        "GH_TOKEN": "metadata-must-not-see-this",
                        "AAS_PROVIDER_SECRETS_FILE": "/must/not/be/opened",
                    },
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                result = json.loads(output.read_text(encoding="utf-8"))
                self.assertIsNone(result["gh"])
                self.assertIsNone(result["pointer"])

    def test_caller_cannot_weaken_managed_secret_env_list(self) -> None:
        for arguments in (
            ["--secret-env-vars=ONLY_THIS", "-p", "offline"],
            ["--secret-env-vars", "ONLY_THIS", "-p", "offline"],
        ):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                wrapper = self.render(home)
                output = home / "result.json"
                completed = subprocess.run(
                    [str(wrapper), *arguments],
                    env={
                        "HOME": str(home),
                        "PATH": "/usr/bin:/bin",
                        "GH_TOKEN": "must-not-run",
                    },
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertFalse(output.exists())
                self.assertNotIn("must-not-run", completed.stdout + completed.stderr)

    def test_shell_and_node_startup_canaries_do_not_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            wrapper = self.render(home)
            self.add_secret_loader(home)
            self.write_copilot_authority(home, "GH_TOKEN=caller-secret\n")
            output = home / "result.json"
            bash_canary = home / "bash-env.sh"
            bash_marker = home / "bash-env-ran"
            bash_canary.write_text(f"touch '{bash_marker}'\n", encoding="utf-8")
            completed = subprocess.run(
                [str(wrapper), "-p", "offline"],
                env={
                    "HOME": str(home),
                    "PATH": "/hostile/path",
                    "GH_TOKEN": "caller-secret",
                    "BASH_ENV": str(bash_canary),
                    "NODE_OPTIONS": "--require=/must/not/run.js",
                    "NODE_PATH": "/must/not/search",
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(bash_marker.exists())
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertIsNone(result["bash_env"])
            self.assertIsNone(result["node_options"])

    def test_runtime_rejects_a_compatibility_link_to_an_alternate_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            wrapper = self.render(home)
            compatibility = home / ".npm-global/lib/node_modules/@github/copilot"
            compatibility.unlink()
            arch = "arm64" if platform.machine().lower() in {"aarch64", "arm64"} else "amd64"
            alternate = (
                home
                / (
                    f".local/share/coding-system/npm-closures/sha256-{arch}-"
                    + "c" * 64
                    + "-"
                    + "d" * 64
                    + "/node_modules/@github/copilot"
                )
            )
            alternate.mkdir(parents=True)
            (alternate / "npm-loader.js").write_text("// alternate\n", encoding="utf-8")
            compatibility.symlink_to(alternate)
            completed = subprocess.run(
                [str(wrapper), "--version"],
                env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 127)
            self.assertIn("differs from the installed locked closure", completed.stderr)

    def test_runtime_rejects_node_outside_the_locked_generations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            wrapper = self.render(home)
            node_link = home / ".npm-global/bin/node"
            locked_node = node_link.resolve(strict=True)
            arch = "arm64" if platform.machine().lower() in {"aarch64", "arm64"} else "amd64"
            # The retired ~/.npm-global/node-v<version>-<arch> layout, and a
            # generation for the other architecture, are both refused.
            for outside in (
                home / f".npm-global/node-v22.23.2-{arch}/bin/node",
                home / (
                    ".local/share/coding-system/node-generations/sha256-"
                    + ("amd64" if arch == "arm64" else "arm64")
                    + "-" + "e" * 64 + "/bin/node"
                ),
            ):
                outside.parent.mkdir(parents=True)
                shutil.copy2(locked_node, outside)
                node_link.unlink()
                node_link.symlink_to(outside)
                completed = subprocess.run(
                    [str(wrapper), "--version"],
                    env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 127, outside)
                self.assertIn("locked Node runtime is unavailable or unsafe", completed.stderr)

    def test_offline_credential_probe_proves_scoped_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            wrapper = self.render(home)
            self.add_secret_loader(home)
            providers = self.write_copilot_authority(
                home, "GH_TOKEN=restored-copilot-secret\n"
            )
            completed = subprocess.run(
                [str(wrapper), "--csr-credential-probe"],
                env={
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin",
                    "AAS_PROVIDER_SECRETS_FILE": str(providers),
                    "OPENAI_API_KEY": "stale-openai-secret",
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                completed.stdout.strip(), "PASS lane=provider"
            )
            self.assertNotIn("restored-copilot-secret", completed.stdout + completed.stderr)
            self.assertNotIn("restored-openai-secret", completed.stdout + completed.stderr)

    def test_wrapper_allowlist_matches_the_materialized_copilot_contract(self) -> None:
        module = ast.parse(MATERIALIZER.read_text(encoding="utf-8"))
        provider_keys: set[str] | None = None
        copilot_keys: set[str] | None = None
        for statement in module.body:
            if isinstance(statement, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "PROVIDER_ENV_KEYS"
                for target in statement.targets
            ):
                provider_keys = set(ast.literal_eval(statement.value))
            if isinstance(statement, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "COPILOT_ENV_KEYS"
                for target in statement.targets
            ):
                copilot_keys = set(ast.literal_eval(statement.value))
        self.assertIsNotNone(provider_keys)
        self.assertIsNotNone(copilot_keys)
        source = TEMPLATE.read_text(encoding="utf-8")
        block = re.search(r"^ALL_PROVIDER_KEYS='([^']+)'$", source, re.MULTILINE)
        self.assertIsNotNone(block)
        self.assertEqual(
            set(block.group(1).split()),
            provider_keys | copilot_keys,
        )
        copilot_block = re.search(r"^COPILOT_KEYS='([^']+)'$", source, re.MULTILINE)
        self.assertIsNotNone(copilot_block)
        self.assertEqual(set(copilot_block.group(1).split()), copilot_keys)
        self.assertNotIn("source ", source)
        self.assertNotIn("eval ", source)
        self.assertIn("--export-key", source)

    def test_install_publishes_wrapper_only_after_shared_loader(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        phase_six = install.split("# 7 ─ OpenClaw slice", 1)[0]
        self.assertIn('"$wrapper_name" != copilot', phase_six)
        # The loader gate is a pinned digest comparison between the immutable
        # ai-agents-skills checkout and the shared runtime copy.
        self.assertIn(
            'AAS_SHARED_RUNTIME="$HOME/.local/share/ai-agents-skills/runtime"',
            install,
        )
        shared_loader_gate = install.index(
            '"$AAS_IMMUTABLE/canonical/runtime/runners/load_secret_env.py'
            '|$AAS_SHARED_RUNTIME/load_secret_env.py"'
        )
        wrapper_install = install.index(
            'COPILOT_WRAPPER_SOURCE="$REPO/system/bin/copilot"'
        )
        target_gate = install.index(
            'python3 "$REPO/bin/verify-target-state.py"'
        )
        self.assertLess(shared_loader_gate, wrapper_install)
        self.assertLess(wrapper_install, target_gate)


if __name__ == "__main__":
    unittest.main()
