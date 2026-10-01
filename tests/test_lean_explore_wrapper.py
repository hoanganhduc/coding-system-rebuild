#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[1]
TEMPLATE = REPO / "system/bin/lean-explore-mcp-api"


class LeanExploreWrapperTests(unittest.TestCase):
    def render(self, root: Path) -> Path:
        wrapper = root / "lean-explore-mcp-api"
        wrapper.write_text(
            TEMPLATE.read_text(encoding="utf-8").replace("{{ HOME }}", str(root)),
            encoding="utf-8",
        )
        wrapper.chmod(0o700)

        runtime = root / ".codex/runtime/workspace/.venvs/lean-explore"
        runtime_bin = runtime / "bin"
        runtime_bin.mkdir(parents=True)
        (runtime / "pyvenv.cfg").write_text(
            f"home = {Path(sys.executable).parent}\n"
            "include-system-site-packages = false\n"
            f"version = {sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}\n"
            f"executable = {sys.executable}\n",
            encoding="utf-8",
        )
        (runtime_bin / "python").symlink_to(sys.executable)
        site = (
            runtime
            / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages"
        )
        package = site / "lean_explore"
        mcp = package / "mcp"
        mcp.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "api.py").write_text(
            "class ApiClient:\n"
            "    def __init__(self, api_key):\n"
            "        self.api_key = api_key\n",
            encoding="utf-8",
        )
        (mcp / "__init__.py").write_text("", encoding="utf-8")
        (mcp / "tools.py").write_text("", encoding="utf-8")
        (mcp / "app.py").write_text(
            "import json, os, pathlib, sys, time\n"
            "IMPORT_KEY = os.environ.get('LEANEXPLORE_API_KEY')\n"
            "IMPORT_SELECTOR = os.environ.get('AAS_SKILL_SECRETS_FILE')\n"
            "class App:\n"
            "    _lean_explore_backend_service = None\n"
            "    def run(self, transport):\n"
            "        if os.environ.get('TEST_WAIT'):\n"
            "            pathlib.Path(os.environ['TEST_PID']).write_text(str(os.getpid()))\n"
            "            time.sleep(30)\n"
            "            return\n"
            "        pathlib.Path(os.environ['TEST_OUTPUT']).write_text(json.dumps({\n"
            "            'argv': sys.argv[1:],\n"
            "            'key': self._lean_explore_backend_service.api_key,\n"
            "            'env_key': os.environ.get('LEANEXPLORE_API_KEY'),\n"
            "            'env_selector': os.environ.get('AAS_SKILL_SECRETS_FILE'),\n"
            "            'import_key': IMPORT_KEY,\n"
            "            'import_selector': IMPORT_SELECTOR,\n"
            "            'stdin': sys.stdin.readline(),\n"
            "            'transport': transport,\n"
            "        }))\n"
            "mcp_app = App()\n",
            encoding="utf-8",
        )
        distribution = site / "lean_explore-1.2.1.dist-info"
        distribution.mkdir()
        (distribution / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: lean-explore\nVersion: 1.2.1\n",
            encoding="utf-8",
        )
        return wrapper

    @staticmethod
    def base_environment(root: Path, output: Path) -> dict[str, str]:
        environment = {**os.environ, "HOME": str(root), "TEST_OUTPUT": str(output)}
        environment.pop("LEANEXPLORE_API_KEY", None)
        environment.pop("AAS_SKILL_SECRETS_FILE", None)
        environment.pop("LEANEXPLORE_SECRET_FILE", None)
        return environment

    def test_secret_file_key_is_in_memory_only_before_package_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wrapper = self.render(root)
            secret = root / ".config/ai-agents-skills/skill.env"
            secret.parent.mkdir(parents=True)
            secret.write_text(
                "export LEANEXPLORE_API_KEY='fixture-secret'\n", encoding="utf-8"
            )
            secret.chmod(0o600)
            output = root / "result.json"
            subprocess.run(
                [str(wrapper)],
                env=self.base_environment(root, output),
                input="mcp-input-preserved\n",
                check=True,
                capture_output=True,
                text=True,
            )
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["argv"], [])
            self.assertEqual(result["key"], "fixture-secret")
            self.assertIsNone(result["env_key"])
            self.assertIsNone(result["env_selector"])
            self.assertIsNone(result["import_key"])
            self.assertIsNone(result["import_selector"])
            self.assertEqual(result["transport"], "stdio")
            self.assertEqual(result["stdin"], "mcp-input-preserved\n")

    def test_unsafe_secret_permissions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wrapper = self.render(root)
            secret = root / ".config/ai-agents-skills/skill.env"
            secret.parent.mkdir(parents=True)
            secret.write_text("LEANEXPLORE_API_KEY=fixture-secret\n", encoding="utf-8")
            secret.chmod(0o644)
            output = root / "result.json"
            result = subprocess.run(
                [str(wrapper)],
                env=self.base_environment(root, output),
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn("unsafe", result.stderr)

    def test_aas_skill_selector_takes_precedence_and_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wrapper = self.render(root)
            selected = root / "selected.env"
            selected.write_text("LEANEXPLORE_API_KEY=selected-key\n", encoding="utf-8")
            selected.chmod(0o600)
            legacy = root / "legacy.env"
            legacy.write_text("LEANEXPLORE_API_KEY=legacy-key\n", encoding="utf-8")
            legacy.chmod(0o600)
            output = root / "result.json"
            environment = self.base_environment(root, output)
            environment["AAS_SKILL_SECRETS_FILE"] = str(selected)
            environment["LEANEXPLORE_SECRET_FILE"] = str(legacy)
            subprocess.run(
                [str(wrapper)],
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["key"], "selected-key")
            self.assertIsNone(result["env_selector"])
            self.assertIsNone(result["import_selector"])

    def test_inherited_key_is_removed_before_package_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wrapper = self.render(root)
            output = root / "result.json"
            environment = self.base_environment(root, output)
            environment["LEANEXPLORE_API_KEY"] = "inherited-key"
            subprocess.run(
                [str(wrapper)],
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["key"], "inherited-key")
            self.assertIsNone(result["env_key"])
            self.assertIsNone(result["import_key"])

    def test_wrapper_is_exact_version_in_process_and_argv_free(self) -> None:
        source = TEMPLATE.read_text(encoding="utf-8")
        self.assertNotIn(".bashrc", source)
        self.assertIn("AAS_SKILL_SECRETS_FILE", source)
        self.assertNotIn('"--api-key"', source)
        self.assertNotIn("subprocess", source)
        self.assertIn('EXPECTED_LEAN_EXPLORE_VERSION = "1.2.1"', source)
        self.assertIn("os.environ.pop", source)
        self.assertIn("os.memfd_create", source)
        self.assertIn("os.execve", source)
        self.assertNotIn("eval ", source)

    @unittest.skipUnless(Path("/proc/self/cmdline").is_file(), "requires procfs")
    def test_synthetic_process_cmdline_and_environment_never_contain_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wrapper = self.render(root)
            secret = root / ".config/ai-agents-skills/skill.env"
            secret.parent.mkdir(parents=True)
            canary = "synthetic-lean-key-never-in-process-metadata"
            secret.write_text(f"LEANEXPLORE_API_KEY={canary}\n", encoding="utf-8")
            secret.chmod(0o600)
            pid_file = root / "pid"
            environment = self.base_environment(root, root / "unused.json")
            environment.update(
                {
                    "AAS_SKILL_SECRETS_FILE": str(secret),
                    "TEST_PID": str(pid_file),
                    "TEST_WAIT": "1",
                }
            )
            process = subprocess.Popen(
                [str(wrapper)],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(pid_file.exists())
                synthetic_pid = int(pid_file.read_text(encoding="ascii"))
                cmdline = Path(f"/proc/{synthetic_pid}/cmdline").read_bytes()
                environ = Path(f"/proc/{synthetic_pid}/environ").read_bytes()
                self.assertNotIn(canary.encode("ascii"), cmdline)
                self.assertNotIn(canary.encode("ascii"), environ)
                self.assertNotIn(b"LEANEXPLORE_API_KEY=", environ)
                self.assertNotIn(b"AAS_SKILL_SECRETS_FILE=", environ)
                self.assertNotIn(b"--api-key", cmdline)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)

    def test_runtime_version_mismatch_fails_before_package_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wrapper = self.render(root)
            metadata_file = next(
                root.glob(
                    ".codex/runtime/workspace/.venvs/lean-explore/lib/"
                    "python*/site-packages/lean_explore-1.2.1.dist-info/METADATA"
                )
            )
            metadata_file.write_text(
                "Metadata-Version: 2.1\nName: lean-explore\nVersion: 9.9.9\n",
                encoding="utf-8",
            )
            output = root / "result.json"
            environment = self.base_environment(root, output)
            environment["LEANEXPLORE_API_KEY"] = "version-mismatch-canary"
            completed = subprocess.run(
                [str(wrapper)], env=environment, capture_output=True, text=True
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn("version differs", completed.stderr)
            self.assertNotIn("version-mismatch-canary", completed.stderr)


if __name__ == "__main__":
    unittest.main()
