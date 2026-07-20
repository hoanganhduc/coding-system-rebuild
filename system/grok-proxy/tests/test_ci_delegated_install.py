#!/usr/bin/env python3
"""Tests for the fixed-purpose degraded-install cgroup launcher."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock


HELPER = Path(__file__).with_name("ci_delegated_install.py")
CAPTURE_HELPER = HELPER.parents[3] / "bin" / "lib" / "ci_bounded_tee.py"
SPECIFICATION = importlib.util.spec_from_file_location(
    "ci_delegated_install", HELPER
)
if SPECIFICATION is None or SPECIFICATION.loader is None:
    raise RuntimeError("cannot load delegated install helper")
launcher = importlib.util.module_from_spec(SPECIFICATION)
SPECIFICATION.loader.exec_module(launcher)


class DelegatedInstallLauncherTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path]:
        mount = root / "cgroup"
        parent = mount / "system.slice" / "run-test.service"
        source = parent / launcher.EXPECTED_SUBGROUP
        source.mkdir(parents=True)
        proc_cgroup = root / "self.cgroup"
        proc_cgroup.write_text(
            "0::/system.slice/run-test.service/installer\n", encoding="ascii"
        )
        controls = {
            parent / "cgroup.procs": "",
            parent / "cgroup.type": "domain\n",
            parent / "cgroup.controllers": "cpu memory pids\n",
            parent / "cgroup.subtree_control": "cpu memory pids\n",
        }
        for name in (
            "cgroup.max.depth",
            "cgroup.max.descendants",
            "cpu.max",
            "memory.high",
            "memory.max",
            "memory.swap.max",
            "pids.max",
        ):
            controls[source / name] = "max\n" if name != "cpu.max" else "max 100000\n"
        for path, value in controls.items():
            path.write_text(value, encoding="ascii")
        return mount, proc_cgroup, source

    def test_exact_direct_parent_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            mount, proc_cgroup, source = self._fixture(Path(directory))
            with mock.patch.object(launcher.os, "getxattr", return_value=b"1"):
                actual_source, actual_parent = launcher._prepare_exact_parent(
                    mount=mount,
                    proc_cgroup=proc_cgroup,
                )
        self.assertEqual(actual_source, source)
        self.assertEqual(actual_parent, source.parent)

    def test_nonempty_parent_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            mount, proc_cgroup, source = self._fixture(Path(directory))
            (source.parent / "cgroup.procs").write_text("123\n", encoding="ascii")
            with (
                mock.patch.object(launcher.os, "getxattr", return_value=b"1"),
                self.assertRaisesRegex(launcher.PreflightError, "parent-populated"),
            ):
                launcher._prepare_exact_parent(
                    mount=mount,
                    proc_cgroup=proc_cgroup,
                )

    def test_missing_controller_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            mount, proc_cgroup, source = self._fixture(Path(directory))
            (source.parent / "cgroup.controllers").write_text(
                "cpu memory\n", encoding="ascii"
            )
            with (
                mock.patch.object(launcher.os, "getxattr", return_value=b"1"),
                self.assertRaisesRegex(
                    launcher.PreflightError, "controllers-unavailable"
                ),
            ):
                launcher._prepare_exact_parent(
                    mount=mount,
                    proc_cgroup=proc_cgroup,
                )

    def test_missing_delegate_marker_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            mount, proc_cgroup, _source = self._fixture(Path(directory))
            with (
                mock.patch.object(launcher.os, "getxattr", return_value=b"0"),
                self.assertRaisesRegex(launcher.PreflightError, "delegation-marker"),
            ):
                launcher._prepare_exact_parent(
                    mount=mount,
                    proc_cgroup=proc_cgroup,
                )

    def test_missing_subtree_controllers_are_enabled_and_revalidated(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            mount, proc_cgroup, source = self._fixture(Path(directory))
            control = source.parent / "cgroup.subtree_control"
            control.write_text("", encoding="ascii")

            def enable(_descriptor: int) -> None:
                control.write_text("cpu memory pids\n", encoding="ascii")

            with (
                mock.patch.object(launcher.os, "getxattr", return_value=b"1"),
                mock.patch.object(launcher, "_write_controllers", side_effect=enable),
            ):
                actual_source, actual_parent = launcher._prepare_exact_parent(
                    mount=mount,
                    proc_cgroup=proc_cgroup,
                )
            self.assertEqual(actual_source, source)
            self.assertEqual(actual_parent, source.parent)

    def test_unexpected_subgroup_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            root = Path(directory)
            membership = root / "self.cgroup"
            membership.write_text(
                "0::/system.slice/run-test.service/not-installer\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(launcher.PreflightError, "subgroup-unexpected"):
                launcher._membership(
                    launcher._read_bounded(membership), root / "cgroup"
                )

    def test_forwarded_environment_must_match_exactly(self) -> None:
        values = {**launcher.FORWARDED_ENVIRONMENT, "COMPONENTS_TOKEN": "secret"}
        with mock.patch.dict(launcher.os.environ, values, clear=True):
            self.assertEqual(
                launcher._forwarded_environment(), launcher.FORWARDED_ENVIRONMENT
            )
        values["SKIP_LATEX"] = "0"
        with (
            mock.patch.dict(launcher.os.environ, values, clear=True),
            self.assertRaisesRegex(launcher.PreflightError, "environment-contract"),
        ):
            launcher._forwarded_environment()

    def test_installer_source_replacement_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            root = Path(directory)
            source = root / "installer.py"
            replacement = root / "replacement.py"
            source.write_text("VALUE = 1\n", encoding="ascii")
            replacement.write_text("VALUE = 2\n", encoding="ascii")
            original_read = launcher._read_descriptor

            def replace_after_read(descriptor: int, maximum: int) -> bytes:
                value = original_read(descriptor, maximum)
                replacement.replace(source)
                return value

            with (
                mock.patch.object(
                    launcher, "_read_descriptor", side_effect=replace_after_read
                ),
                self.assertRaisesRegex(launcher.PreflightError, "installer-source"),
            ):
                launcher._load_installer(source)

    def test_real_installer_predicate_loads_from_bound_source(self) -> None:
        module = launcher._load_installer(HELPER.parents[1] / "install-release.py")
        self.assertIs(module._RUNNER_CGROUP_PROBE_IMPORT, True)
        self.assertFalse(hasattr(module, "ManagedProfileError"))
        self.assertTrue(callable(module._runner_cgroup_parent))

    def test_install_script_exec_descriptor_pins_opened_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            root = Path(directory)
            script = root / "install.sh"
            replacement = root / "replacement.sh"
            script.write_bytes(b"original\n")
            replacement.write_bytes(b"replacement\n")
            descriptor = launcher._open_install_script(script)
            try:
                replacement.replace(script)
                self.assertEqual(launcher.os.read(descriptor, 64), b"original\n")
                self.assertTrue(launcher.os.get_inheritable(descriptor))
            finally:
                launcher.os.close(descriptor)

    def test_bash_can_execute_the_inherited_script_descriptor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            script = Path(directory) / "install.sh"
            script.write_bytes(b"#!/usr/bin/bash\nprintf '%s' descriptor-ok\n")
            descriptor = launcher._open_install_script(script)
            try:
                result = subprocess.run(
                    [launcher.INSTALL_EXECUTABLE, f"/proc/self/fd/{descriptor}"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=(descriptor,),
                    timeout=5,
                    check=False,
                    env={"PATH": "/usr/bin:/bin"},
                )
            finally:
                launcher.os.close(descriptor)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"descriptor-ok")

    def test_bounded_capture_rejects_a_one_byte_overflow(self) -> None:
        limit = 4096
        for size, expected_status in (
            (limit - 1, 0),
            (limit, 0),
            (limit + 1, 2),
        ):
            with self.subTest(size=size):
                with tempfile.TemporaryDirectory(
                    prefix="grok-ci-launcher-"
                ) as directory:
                    log = Path(directory) / "install.log"
                    payload = b"x" * size
                    result = subprocess.run(
                        [
                            "/usr/bin/python3",
                            "-I",
                            "-B",
                            str(CAPTURE_HELPER),
                            "--output",
                            log.name,
                            "--limit",
                            str(limit),
                        ],
                        input=payload,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5,
                        check=False,
                        cwd=directory,
                        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                    )
                    admitted = payload[:limit]
                    self.assertEqual(result.returncode, expected_status, result.stderr)
                    self.assertEqual(result.stdout, admitted)
                    self.assertEqual(log.read_bytes(), admitted)
                    if size > limit:
                        self.assertEqual(
                            result.stderr,
                            b"bounded-stream: output limit exceeded\n",
                        )

    def test_bounded_capture_exclusively_creates_and_safely_seeds_log(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            root = Path(directory)
            prefix = root / "bootstrap-preflight.log"
            output = root / "install.log"
            victim = root / "victim"
            prefix.write_bytes(b"prefix\n")
            victim.write_bytes(b"unchanged")
            result = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(CAPTURE_HELPER),
                    "--prefix",
                    prefix.name,
                    "--output",
                    output.name,
                    "--limit",
                    "16",
                ],
                input=b"payload",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
                cwd=directory,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"payload")
            self.assertEqual(output.read_bytes(), b"prefix\npayload")
            output.unlink()
            output.symlink_to(victim)
            rejected = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(CAPTURE_HELPER),
                    "--prefix",
                    prefix.name,
                    "--output",
                    output.name,
                    "--limit",
                    "16",
                ],
                input=b"payload",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
                cwd=directory,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(victim.read_bytes(), b"unchanged")

    def test_install_script_accepts_only_canonical_descriptor_root(self) -> None:
        repository = HELPER.parents[3]
        script = repository / "bin" / "install.sh"
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            link = Path(directory) / "repository-link"
            link.symlink_to(repository, target_is_directory=True)
            cases = (
                (str(repository), 0),
                (f"{repository}/../{repository.name}", 2),
                (str(link), 2),
                ("/", 2),
            )
            for root, expected_status in cases:
                with self.subTest(root=root):
                    descriptor = launcher._open_install_script(script)
                    try:
                        result = subprocess.run(
                            [
                                launcher.INSTALL_EXECUTABLE,
                                f"/proc/self/fd/{descriptor}",
                            ],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            pass_fds=(descriptor,),
                            timeout=5,
                            check=False,
                            env={
                                "CSR_INSTALL_REPO_ROOT": root,
                                "HOME": directory,
                                "LANG": "C",
                                "LC_ALL": "C",
                                "LOGNAME": "tester",
                                "PATH": "/usr/bin:/bin",
                                "PHASE": "2147483647",
                                "SHELL": "/bin/bash",
                                "USER": "tester",
                            },
                        )
                    finally:
                        launcher.os.close(descriptor)
                    self.assertEqual(
                        result.returncode,
                        expected_status,
                        (result.stdout, result.stderr),
                    )
                    if expected_status == 0:
                        self.assertIn(b"install: done", result.stdout)
                    else:
                        self.assertIn(b"descriptor-bound install root", result.stderr)

    def test_production_fallback_is_rejected_before_exec(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            root = Path(directory)
            source = root / "run-test.service" / launcher.EXPECTED_SUBGROUP
            source.mkdir(parents=True)
            script = root / "install.sh"
            script.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            placement = types.SimpleNamespace(
                source=source,
                parent=root / "user@1001.service",
                source_info=source.lstat(),
                parent_info=root.lstat(),
            )
            installer = types.SimpleNamespace(
                _runner_cgroup_parent=lambda _uid, _gid: placement
            )
            with (
                mock.patch.object(
                    launcher, "_prepare_exact_parent", return_value=(source, source.parent)
                ),
                mock.patch.object(launcher, "_load_installer", return_value=installer),
                mock.patch.object(launcher, "INSTALL_SCRIPT", script),
                mock.patch.object(launcher.os, "execve") as execute,
            ):
                result = launcher.main()
            self.assertEqual(result, 2)
            execute.assert_not_called()

    def test_production_inode_mismatch_is_rejected_before_exec(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            root = Path(directory)
            source = root / "run-test.service" / launcher.EXPECTED_SUBGROUP
            source.mkdir(parents=True)
            script = root / "install.sh"
            script.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            placement = types.SimpleNamespace(
                source=source,
                parent=source.parent,
                source_info=root.lstat(),
                parent_info=source.parent.lstat(),
            )
            installer = types.SimpleNamespace(
                _runner_cgroup_parent=lambda _uid, _gid: placement
            )
            with (
                mock.patch.object(
                    launcher, "_prepare_exact_parent", return_value=(source, source.parent)
                ),
                mock.patch.object(launcher, "_load_installer", return_value=installer),
                mock.patch.object(launcher, "INSTALL_SCRIPT", script),
                mock.patch.object(launcher.os, "execve") as execute,
            ):
                result = launcher.main()
            self.assertEqual(result, 2)
            execute.assert_not_called()

    def test_exec_environment_is_closed(self) -> None:
        expected_environment = {"PATH": "/usr/bin:/bin"}
        with tempfile.TemporaryDirectory(prefix="grok-ci-launcher-") as directory:
            root = Path(directory)
            source = root / "run-test.service" / launcher.EXPECTED_SUBGROUP
            source.mkdir(parents=True)
            script = root / "install.sh"
            script.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            placement = types.SimpleNamespace(
                source=source,
                parent=source.parent,
                source_info=source.lstat(),
                parent_info=source.parent.lstat(),
            )
            installer = types.SimpleNamespace(
                _runner_cgroup_parent=lambda _uid, _gid: placement
            )

            class ExecReached(BaseException):
                pass

            def execute(path: str, argv: tuple[str, ...], environment: dict[str, str]) -> None:
                self.assertEqual(path, launcher.INSTALL_EXECUTABLE)
                self.assertEqual(
                    argv, (launcher.INSTALL_EXECUTABLE, "/proc/self/fd/77")
                )
                self.assertEqual(
                    environment,
                    {
                        **expected_environment,
                        "CSR_INSTALL_REPO_ROOT": str(Path.cwd()),
                    },
                )
                self.assertNotIn("COMPONENTS_TOKEN", environment)
                raise ExecReached

            with (
                mock.patch.object(
                    launcher, "_prepare_exact_parent", return_value=(source, source.parent)
                ),
                mock.patch.object(launcher, "_load_installer", return_value=installer),
                mock.patch.object(
                    launcher, "_closed_environment", return_value=expected_environment
                ),
                mock.patch.object(launcher, "INSTALL_SCRIPT", script),
                mock.patch.object(launcher, "_open_install_script", return_value=77),
                mock.patch.object(launcher.os, "execve", side_effect=execute),
                self.assertRaises(ExecReached),
            ):
                launcher.main()


if __name__ == "__main__":
    unittest.main()
