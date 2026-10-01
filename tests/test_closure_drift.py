#!/usr/bin/env python3
"""The closure-drift report follows the component store and the running generation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/check-closure-drift.py"
GIT_ENVIRONMENT = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
SOURCES = {"host_exec.py": "scripts/host_exec.py", "worker.sh": "workspace/worker.sh"}


def git(directory: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(directory), *arguments],
        env=GIT_ENVIRONMENT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def commit_component(path: Path, worker: str) -> str:
    (path / "scripts").mkdir(parents=True, exist_ok=True)
    (path / "workspace").mkdir(exist_ok=True)
    (path / "scripts/service_transaction.py").write_text(
        "HOST_ARTIFACTS: tuple[tuple[str, str, str], ...] = (\n"
        '    ("host_exec.py", "scripts/host_exec.py", "python-isolated"),\n'
        '    ("worker.sh", "workspace/worker.sh", "bash"),\n'
        ")\n",
        encoding="utf-8",
    )
    (path / "scripts/host_exec.py").write_text("print('host')\n", encoding="utf-8")
    (path / "workspace/worker.sh").write_text(worker, encoding="utf-8")
    if not (path / ".git").exists():
        git(path, "init", "-q")
    git(path, "add", "-A")
    git(path, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-q", "-m", "fixture")
    return git(path, "rev-parse", "HEAD")


class ClosureDriftTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, Path, str]:
        home = root / "home"
        store = home / ".local/share/coding-system/components/openclaw-bot"
        store.mkdir(parents=True)
        source = root / "source"
        pinned = commit_component(source, "echo pinned\n")
        component = store / pinned
        shutil.move(source, component)

        repository = root / "repository"
        (repository / "system/openclaw").mkdir(parents=True)
        (repository / "components.lock").write_text(
            f"openclaw-bot=https://example.invalid/openclaw-bot.git@{pinned}\n", encoding="utf-8"
        )
        (repository / "system/openclaw/compatibility.lock.json").write_text(
            json.dumps(
                {
                    "openclaw": {"version": "2026.7.1-2"},
                    "component": {"name": "openclaw-bot", "commit": pinned},
                    "sandbox": {"image": "example.invalid/sandbox@sha256:" + "a" * 64},
                }
            ),
            encoding="utf-8",
        )
        # A dirty development checkout at another commit must not be reported.
        decoy = repository / "external/openclaw-bot"
        commit_component(decoy, "echo development\n")
        (decoy / "workspace/worker.sh").write_text("echo edited\n", encoding="utf-8")
        return home, repository, component, pinned

    def install_generation(self, home: Path, component: Path, generation: str, *, worker_sha256: str | None = None) -> None:
        artifacts = {}
        for destination, source in SOURCES.items():
            digest = hashlib.sha256((component / source).read_bytes()).hexdigest()
            if destination == "worker.sh" and worker_sha256 is not None:
                digest = worker_sha256
            artifacts[destination] = {"sha256": digest, "mode": 320, "interpreter": "bash"}
        directory = home / ".local/libexec/openclaw-bot/generations" / generation
        directory.mkdir(parents=True)
        (directory / "MANIFEST.json").write_text(
            json.dumps(
                {
                    "schema": "openclaw.host-runtime/v1",
                    "generation": generation,
                    "artifacts": artifacts,
                    "externalRuntime": {"version": "2026.7.1-2"},
                }
            ),
            encoding="utf-8",
        )

    def write_unit(self, home: Path, name: str, generation: str) -> None:
        units = home / ".config/systemd/user"
        units.mkdir(parents=True, exist_ok=True)
        (units / name).write_text(
            "[Service]\nExecStart="
            f"{home}/.local/libexec/openclaw-bot/generations/{generation}/host_exec.py\n",
            encoding="utf-8",
        )

    def report(self, root: Path, home: Path, repository: Path) -> dict:
        shims = root / "shims"
        shims.mkdir(exist_ok=True)
        for name in ("docker", "npm"):
            shim = shims / name
            shim.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            shim.chmod(0o755)
        completed = subprocess.run(
            ["python3", str(SCRIPT), "--repository", str(repository), "--home", str(home)],
            env={**os.environ, "PATH": f"{shims}:/usr/bin:/bin"},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_running_generation_built_from_the_pinned_store_copy_is_not_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, repository, component, pinned = self.fixture(root)
            generation = "1" * 64
            self.install_generation(home, component, generation)
            self.write_unit(home, "openclaw-gateway.service", generation)
            self.write_unit(home, "send-queue-worker.service", generation)

            report = self.report(root, home, repository)

            observed = report["observed"]["component"]
            self.assertEqual(observed["source"], str(component))
            self.assertEqual(observed["commit"], pinned)
            self.assertEqual(observed["generations"], [generation])
            self.assertEqual(observed["running_commit"], pinned)
            self.assertEqual(observed["openclaw_version"], "2026.7.1-2")
            self.assertFalse(report["drift"]["component"])
            self.assertFalse(report["drift"]["component_dirty"])
            self.assertFalse(report["drift"]["generation_mixed"])

    def test_generation_not_built_from_the_pinned_copy_is_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, repository, component, _pinned = self.fixture(root)
            generation = "2" * 64
            self.install_generation(home, component, generation, worker_sha256="0" * 64)
            self.write_unit(home, "openclaw-gateway.service", generation)

            report = self.report(root, home, repository)

            self.assertIsNone(report["observed"]["component"]["running_commit"])
            self.assertTrue(report["drift"]["component"])

    def test_units_on_two_generations_are_mixed_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, repository, component, _pinned = self.fixture(root)
            for generation, unit in (("3" * 64, "a.service"), ("4" * 64, "b.service")):
                self.install_generation(home, component, generation)
                self.write_unit(home, unit, generation)

            report = self.report(root, home, repository)

            self.assertEqual(report["observed"]["component"]["generations"], ["3" * 64, "4" * 64])
            self.assertTrue(report["drift"]["generation_mixed"])
            self.assertTrue(report["drift"]["component"])

    def test_host_without_the_component_reports_it_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, repository, component, _pinned = self.fixture(root)
            shutil.rmtree(component)

            report = self.report(root, home, repository)

            self.assertFalse(report["observed"]["component"]["available"])
            self.assertFalse(report["drift"]["component"])
            self.assertFalse(report["drift"]["generation_mixed"])


if __name__ == "__main__":
    unittest.main()
