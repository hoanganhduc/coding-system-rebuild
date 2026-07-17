#!/usr/bin/env python3
"""Focused integration tests for render-install's atomic Grok release handoff."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


_TEST_PATH = Path(__file__).resolve()
_REPO_CANDIDATES = (
    _TEST_PATH.parents[3],
    _TEST_PATH.parents[1].parent / "coding-system-rebuild",
)
REPO_ROOT = next(
    (
        candidate
        for candidate in _REPO_CANDIDATES
        if (candidate / "bin/lib/render_install.py").is_file()
    ),
    _REPO_CANDIDATES[0],
)
MODULE_PATH = REPO_ROOT / "bin/lib/render_install.py"
SPEC = importlib.util.spec_from_file_location("grok_render_install", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
render_install = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(render_install)

RELEASE_ID = "a" * 64


def completed(
    command: list[str],
    record: dict[str, object],
    *,
    stdout: object,
    stderr: object,
    **_kwargs: object,
) -> subprocess.CompletedProcess[bytes]:
    del stderr
    stdout.write(json.dumps(record).encode("ascii"))
    stdout.flush()
    return subprocess.CompletedProcess(command, 0)


class InstallPipelineTests(unittest.TestCase):
    def make_fixture(self, base: Path) -> tuple[Path, Path]:
        repo = base / "repo"
        home = base / "home"
        source = repo / "system/grok-proxy"
        cache = source / "grok_ms/__pycache__"
        cache.mkdir(parents=True)
        home.mkdir()
        (source / "grok-remote").write_text("#!/bin/sh\necho release\n", encoding="utf-8")
        (source / "grok-remote").chmod(0o755)
        (source / "install-release.py").write_text("# fixture installer\n", encoding="utf-8")
        (source / "grok_ms/client.py").parent.mkdir(parents=True, exist_ok=True)
        (source / "grok_ms/client.py").write_text("CURRENT = True\n", encoding="utf-8")
        (source / ".planning").mkdir()
        (source / ".planning/never-restore.md").write_text(
            "repository-only\n", encoding="utf-8"
        )
        (cache / "core.cpython-312.pyc").write_bytes(b"generated-cache")
        (repo / "MANIFEST.yaml").write_text(
            """entries:
  - id: grokproxy-scripts
    root: grok-proxy
    match: [grok-remote, install-release.py, grok_ms]
    exclude: [\"**/__pycache__/**\", \"**/*.pyc\"]
    class: public-copy
    dest_dir: system/grok-proxy
""",
            encoding="utf-8",
        )
        return repo, home

    def invoke(self, repo: Path, home: Path, *, render_only: bool) -> int:
        argv = [
            str(MODULE_PATH),
            "--repo",
            str(repo),
            "--home",
            str(home),
        ]
        if render_only:
            argv.append("--render-only")
        with mock.patch.object(sys, "argv", argv):
            return render_install.main()

    def test_render_only_keeps_roundtrip_copy_and_never_invokes_sudo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            with mock.patch.object(render_install.subprocess, "run") as run:
                self.assertEqual(self.invoke(repo, home, render_only=True), 0)
            run.assert_not_called()
            self.assertEqual(
                (home / "grok-proxy/grok-remote").read_text(encoding="utf-8"),
                "#!/bin/sh\necho release\n",
            )
            self.assertTrue((home / "grok-proxy/install-release.py").is_file())
            self.assertFalse((home / "grok-proxy/grok_ms/__pycache__").exists())

    def test_real_render_populates_absent_public_source_preserves_private_tree_and_validates_release(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            private = home / "grok-proxy"
            private.mkdir()
            (private / "hosts.conf").write_bytes(b"private-hosts\n")
            (private / "id_grokproxy").write_bytes(b"private-key\n")
            (private / ".model.choice").write_bytes(b"private-model\n")
            (private / "grok_ms/__pycache__").mkdir(parents=True)
            (private / "grok_ms/__pycache__/client.pyc").write_bytes(b"generated\n")
            install_record = {
                "schema_version": 2,
                "release_id": RELEASE_ID,
                "changed": True,
                "operation": "install",
                "applied": True,
            }
            status_record = {
                "schema_version": 2,
                "active_release_id": RELEASE_ID,
                "active_user_release_id": RELEASE_ID,
                "active_root_release_id": RELEASE_ID,
                "active_release_valid": True,
                "rollback_denied": False,
                "release_access_policy_valid": True,
                "rollback_eligibility_complete": True,
                "rollback_eligible_releases": [RELEASE_ID],
                "exposed_user_releases": [RELEASE_ID],
            }

            def fake_run(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                record = install_record if "install" in command else status_record
                return completed(command, record, **kwargs)

            with mock.patch.object(render_install.subprocess, "run", side_effect=fake_run) as run:
                self.assertEqual(self.invoke(repo, home, render_only=False), 0)

            self.assertEqual((private / "hosts.conf").read_bytes(), b"private-hosts\n")
            self.assertEqual((private / "id_grokproxy").read_bytes(), b"private-key\n")
            self.assertEqual(
                (private / ".model.choice").read_bytes(), b"private-model\n"
            )
            self.assertEqual(
                (private / "grok-remote").read_text(encoding="utf-8"),
                "#!/bin/sh\necho release\n",
            )
            self.assertTrue((private / "grok-remote").stat().st_mode & 0o111)
            self.assertEqual(
                (private / "grok_ms/client.py").read_text(encoding="utf-8"),
                "CURRENT = True\n",
            )
            self.assertEqual(
                (private / "grok_ms/__pycache__/client.pyc").read_bytes(),
                b"generated\n",
            )
            self.assertFalse((private / ".planning").exists())
            self.assertEqual(run.call_count, 2)
            source = str(home / "grok-proxy")
            prefix = [
                "/usr/bin/sudo",
                "-n",
                "--",
                "/usr/bin/python3",
                "-I",
                "-B",
                str(repo / "system/grok-proxy/install-release.py"),
            ]
            self.assertEqual(
                run.call_args_list[0].args[0],
                [*prefix, "install", "--source", source, "--home", str(home), "--apply"],
            )
            self.assertEqual(
                run.call_args_list[1].args[0],
                [*prefix, "status", "--source", source, "--home", str(home)],
            )

    def test_hard_crash_prefix_resumes_without_overwriting_private_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            private = home / "grok-proxy"
            private.mkdir()
            (private / "hosts.conf").write_bytes(b"private-hosts\n")
            manifest = render_install.yaml.safe_load(
                (repo / "MANIFEST.yaml").read_text(encoding="utf-8")
            )
            entry = manifest["entries"][0]
            original = render_install._rename_noreplace
            terminated = False

            def terminate_after_publish(
                source_fd: int,
                source: str,
                destination_fd: int,
                destination: str,
            ) -> None:
                nonlocal terminated
                original(source_fd, source, destination_fd, destination)
                if not terminated:
                    terminated = True
                    raise SystemExit(137)

            with mock.patch.object(
                render_install,
                "_rename_noreplace",
                side_effect=terminate_after_publish,
            ):
                with self.assertRaises(SystemExit):
                    render_install.reconcile_grok_authoring_source(
                        str(repo), str(home), entry
                    )

            self.assertTrue((private / ".grok-source-restore.json").is_file())
            self.assertEqual((private / "hosts.conf").read_bytes(), b"private-hosts\n")
            restored = render_install.reconcile_grok_authoring_source(
                str(repo), str(home), entry
            )
            self.assertGreaterEqual(restored, 1)
            self.assertFalse((private / ".grok-source-restore.json").exists())
            self.assertFalse(
                [path for path in private.glob(".grok-source-restore-*") if path.is_dir()]
            )
            self.assertEqual((private / "hosts.conf").read_bytes(), b"private-hosts\n")
            self.assertTrue((private / "grok_ms/client.py").is_file())

    def test_concurrent_authoring_file_is_never_replaced_or_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            private = home / "grok-proxy"
            private.mkdir()
            manifest = render_install.yaml.safe_load(
                (repo / "MANIFEST.yaml").read_text(encoding="utf-8")
            )
            entry = manifest["entries"][0]
            original = render_install._rename_noreplace
            appeared = False

            def publish_with_race(
                source_fd: int,
                source: str,
                destination_fd: int,
                destination: str,
            ) -> None:
                nonlocal appeared
                if not appeared:
                    appeared = True
                    descriptor = os.open(
                        destination,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=destination_fd,
                    )
                    os.write(descriptor, b"concurrent user work\n")
                    os.close(descriptor)
                original(source_fd, source, destination_fd, destination)

            with mock.patch.object(
                render_install, "_rename_noreplace", side_effect=publish_with_race
            ):
                with self.assertRaises(render_install.GrokSourceRestoreError):
                    render_install.reconcile_grok_authoring_source(
                        str(repo), str(home), entry
                    )

            raced = private / "grok-remote"
            self.assertEqual(raced.read_bytes(), b"concurrent user work\n")
            with self.assertRaises(render_install.GrokSourceRestoreError):
                render_install.reconcile_grok_authoring_source(
                    str(repo), str(home), entry
                )
            self.assertEqual(raced.read_bytes(), b"concurrent user work\n")

    def test_marker_short_write_leaves_no_poisoned_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            entry = render_install.yaml.safe_load(
                (repo / "MANIFEST.yaml").read_text(encoding="utf-8")
            )["entries"][0]
            real_write = render_install.os.write
            first = True

            def short_first_write(descriptor: int, data: object) -> int:
                nonlocal first
                if first:
                    first = False
                    return 0
                return real_write(descriptor, data)

            with mock.patch.object(render_install.os, "write", side_effect=short_first_write):
                with self.assertRaises(render_install.GrokSourceRestoreError):
                    render_install.reconcile_grok_authoring_source(
                        str(repo), str(home), entry
                    )

            private = home / "grok-proxy"
            self.assertFalse((private / ".grok-source-restore.json").exists())
            self.assertFalse(list(private.glob(".grok-source-restore-marker-*")))
            self.assertGreater(
                render_install.reconcile_grok_authoring_source(
                    str(repo), str(home), entry
                ),
                0,
            )

    def test_intermediate_directory_symlink_race_never_writes_external_tree(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            private = home / "grok-proxy"
            private.mkdir()
            (private / "grok_ms/__pycache__").mkdir(parents=True)
            external = Path(td) / "external"
            external.mkdir()
            entry = render_install.yaml.safe_load(
                (repo / "MANIFEST.yaml").read_text(encoding="utf-8")
            )["entries"][0]
            original = render_install._open_restore_directory
            raced = False

            def open_with_race(parent_fd: int, name: str) -> int:
                nonlocal raced
                parent = os.path.realpath(f"/proc/self/fd/{parent_fd}")
                if not raced and parent == str(private) and name == "grok_ms":
                    raced = True
                    os.rename(
                        "grok_ms", "grok_ms.concurrent", src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                    os.symlink(str(external), "grok_ms", dir_fd=parent_fd)
                return original(parent_fd, name)

            with mock.patch.object(
                render_install, "_open_restore_directory", side_effect=open_with_race
            ):
                with self.assertRaises((OSError, render_install.GrokSourceRestoreError)):
                    render_install.reconcile_grok_authoring_source(
                        str(repo), str(home), entry
                    )

            self.assertTrue(raced)
            self.assertEqual(list(external.iterdir()), [])

    def test_divergent_public_source_fails_before_any_source_write_or_release_install(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            private = home / "grok-proxy"
            private.mkdir()
            (private / "hosts.conf").write_bytes(b"private-hosts\n")
            (private / "grok-remote").write_bytes(b"local-authoring-change\n")
            before = {
                path.relative_to(private): path.read_bytes()
                for path in private.rglob("*")
                if path.is_file()
            }

            with (
                mock.patch.object(render_install.subprocess, "run") as run,
                mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
            ):
                self.assertEqual(self.invoke(repo, home, render_only=False), 2)

            run.assert_not_called()
            self.assertIn("authoring source differs", stderr.getvalue())
            self.assertEqual(
                before,
                {
                    path.relative_to(private): path.read_bytes()
                    for path in private.rglob("*")
                    if path.is_file()
                },
            )
            self.assertFalse(any(private.rglob("*.new")))
            self.assertFalse((private / "install-release.py").exists())

    def test_identical_public_source_is_a_noop_before_release_install(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            private = home / "grok-proxy"
            private.mkdir()
            (private / "hosts.conf").write_bytes(b"private-hosts\n")
            for rel in ("grok-remote", "install-release.py", "grok_ms/client.py"):
                source = repo / "system/grok-proxy" / rel
                destination = private / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(source.read_bytes())
                destination.chmod(source.stat().st_mode & 0o777)
            before = {
                path.relative_to(private): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in private.rglob("*")
                if path.is_file()
            }
            install_record = {
                "schema_version": 2,
                "release_id": RELEASE_ID,
                "changed": False,
                "operation": "install",
                "applied": True,
            }
            status_record = {
                "schema_version": 2,
                "active_release_id": RELEASE_ID,
                "active_user_release_id": RELEASE_ID,
                "active_root_release_id": RELEASE_ID,
                "active_release_valid": True,
                "rollback_denied": False,
                "release_access_policy_valid": True,
                "rollback_eligibility_complete": True,
                "rollback_eligible_releases": [RELEASE_ID],
                "exposed_user_releases": [RELEASE_ID],
            }
            records = iter((install_record, status_record))

            def fake_run(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                return completed(command, next(records), **kwargs)

            with mock.patch.object(
                render_install.subprocess, "run", side_effect=fake_run
            ) as run:
                self.assertEqual(self.invoke(repo, home, render_only=False), 0)

            self.assertEqual(run.call_count, 2)
            self.assertEqual(
                before,
                {
                    path.relative_to(private): (path.read_bytes(), path.stat().st_mtime_ns)
                    for path in private.rglob("*")
                    if path.is_file()
                },
            )

    def test_missing_extra_symlink_and_mode_drift_all_fail_before_sudo(self) -> None:
        mutations = ("missing", "extra", "symlink", "mode")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                repo, home = self.make_fixture(Path(td))
                private = home / "grok-proxy"
                private.mkdir()
                for rel in ("grok-remote", "install-release.py", "grok_ms/client.py"):
                    source = repo / "system/grok-proxy" / rel
                    destination = private / rel
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.read_bytes())
                    destination.chmod(source.stat().st_mode & 0o777)
                if mutation == "missing":
                    (private / "grok_ms/client.py").unlink()
                elif mutation == "extra":
                    (private / "grok_ms/extra.py").write_text(
                        "EXTRA = True\n", encoding="utf-8"
                    )
                elif mutation == "symlink":
                    (private / "grok_ms/client.py").unlink()
                    (private / "grok_ms/client.py").symlink_to("/dev/null")
                else:
                    (private / "grok-remote").chmod(0o644)

                with (
                    mock.patch.object(render_install.subprocess, "run") as run,
                    mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
                ):
                    self.assertEqual(self.invoke(repo, home, render_only=False), 2)

                run.assert_not_called()
                self.assertIn("authoring source differs", stderr.getvalue())
                self.assertFalse(any(private.rglob("*.new")))

    def test_apply_or_status_failure_fails_render_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            def failed_run(
                command: list[str], *, stderr: object, **_kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                stderr.write(b"installer refused")
                stderr.flush()
                return subprocess.CompletedProcess(command, 2)

            with (
                mock.patch.object(
                    render_install.subprocess, "run", side_effect=failed_run
                ) as run,
                mock.patch("sys.stderr", new_callable=io.StringIO),
            ):
                self.assertEqual(self.invoke(repo, home, render_only=False), 2)
            self.assertEqual(run.call_count, 1)

        with tempfile.TemporaryDirectory() as td:
            repo, home = self.make_fixture(Path(td))
            install_record = {
                "schema_version": 2,
                "release_id": RELEASE_ID,
                "changed": False,
                "operation": "install",
                "applied": True,
            }
            incoherent = {
                "schema_version": 2,
                "active_release_id": None,
                "active_user_release_id": RELEASE_ID,
                "active_root_release_id": "b" * 64,
                "active_release_valid": False,
                "rollback_denied": True,
            }
            records = iter((install_record, incoherent))

            def fake_run(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                return completed(command, next(records), **kwargs)

            with (
                mock.patch.object(
                    render_install.subprocess, "run", side_effect=fake_run
                ) as run,
                mock.patch("sys.stderr", new_callable=io.StringIO),
            ):
                self.assertEqual(self.invoke(repo, home, render_only=False), 2)
            self.assertEqual(run.call_count, 2)

    def test_release_command_failure_reports_hashes_not_hostile_output(self) -> None:
        stdout_data = b"stdout-secret\x1b]8;;https://example.invalid\x07link\x1b]8;;\x07\r\b"
        stderr_data = b"stderr-secret\x1b[31mred\x1b[0m\x07\r\b"

        def failed_run(
            command: list[str], *, stdout: object, stderr: object, **_kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            stdout.write(stdout_data)
            stderr.write(stderr_data)
            stdout.flush()
            stderr.flush()
            return subprocess.CompletedProcess(command, 23)

        with mock.patch.object(
            render_install.subprocess, "run", side_effect=failed_run
        ):
            with self.assertRaises(render_install.GrokReleaseInstallError) as raised:
                render_install._run_release_command(["fixture"], "fixture release")

        message = str(raised.exception)
        self.assertIn("failed with exit 23", message)
        self.assertIn(f"stdout_bytes={len(stdout_data)}", message)
        self.assertIn(
            f"stdout_sha256={hashlib.sha256(stdout_data).hexdigest()}", message
        )
        self.assertIn(f"stderr_bytes={len(stderr_data)}", message)
        self.assertIn(
            f"stderr_sha256={hashlib.sha256(stderr_data).hexdigest()}", message
        )
        for secret in ("stdout-secret", "stderr-secret", "example.invalid"):
            self.assertNotIn(secret, message)
        for control in ("\x1b", "\x07", "\r", "\b"):
            self.assertNotIn(control, message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
