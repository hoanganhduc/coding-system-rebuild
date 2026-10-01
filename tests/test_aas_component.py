#!/usr/bin/env python3
"""Regression tests for pinned ai-agents-skills materialization."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "bin/lib/aas_component.py"
SPEC = importlib.util.spec_from_file_location("aas_component_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AAS_COMPONENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AAS_COMPONENT)
PIN = "a" * 40


def make_writable(root: Path) -> None:
    if not root.exists():
        return
    for directory, dirnames, _filenames in os.walk(root, topdown=True):
        os.chmod(directory, 0o700)
        for name in dirnames:
            child = Path(directory) / name
            if not child.is_symlink():
                os.chmod(child, 0o700)


class AasComponentTests(unittest.TestCase):
    def fixture(self, base: Path) -> tuple[Path, int, int]:
        uid = os.geteuid()
        gid = os.getegid()
        authority = base / "authority"
        authority.mkdir(mode=0o755)
        root = AAS_COMPONENT.ensure_component_root(
            base=authority,
            parts=("coding-system", "components", "ai-agents-skills"),
            uid=uid,
        )
        return root, uid, gid

    def populate(self, stage: Path, marker: bytes = b"fixture\n") -> None:
        installer = stage / "installer"
        installer.mkdir(mode=0o755)
        bootstrap = installer / "bootstrap.sh"
        bootstrap.write_bytes(b"#!/bin/sh\nexit 0\n")
        bootstrap.chmod(0o755)
        payload = stage / "payload.txt"
        payload.write_bytes(marker)
        payload.chmod(0o644)

    def test_archive_inventory_rejects_links_and_requires_bootstrap(self) -> None:
        valid = (
            b"100755 blob "
            + b"1" * 40
            + b"\tinstaller/bootstrap.sh\0"
            + b"100644 blob "
            + b"2" * 40
            + b"\tpayload.txt\0"
        )
        AAS_COMPONENT.validate_archive_source(valid, PIN)

        linked = b"120000 blob " + b"3" * 40 + b"\tunsafe-link\0"
        with self.assertRaisesRegex(AAS_COMPONENT.ComponentError, "link, submodule"):
            AAS_COMPONENT.validate_archive_source(valid + linked, PIN)
        with self.assertRaisesRegex(AAS_COMPONENT.ComponentError, "bootstrap"):
            AAS_COMPONENT.validate_archive_source(
                b"100644 blob " + b"4" * 40 + b"\tpayload.txt\0",
                PIN,
            )

    def test_phase8_uses_only_immutable_source_and_closed_python(self) -> None:
        source = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        phase = source.split('# 8 ─ skills via ai-agents-skills', 1)[1].split(
            '# 9 ─ python environments', 1
        )[0]
        self.assertNotIn('$AAS_HOME/installer/bootstrap.sh', phase)
        for required in (
            'AAS_HELPER_SOURCE="$REPO/bin/lib/aas_component.py"',
            'AAS_BOUND_HELPER=',
            'os.O_NOFOLLOW | os.O_NONBLOCK',
            "information.st_nlink != 1",
            'AAS_HELPER_ROOT="$HOME/.local/share/coding-system/install-helpers"',
            'AAS_COMPONENT_ROOT="$HOME/.local/share/coding-system/components/ai-agents-skills"',
            '"execution_source":"owner-pinned-object"',
            'AAS_HELPER="$AAS_BOUND_HELPER"',
            'emit-raw-tar',
            'verify-extracted',
            'cd "$AAS_IMMUTABLE"',
            '/usr/bin/env -i "${AAS_CLOSED_ENV[@]}"',
            'AAS_INSTALL_CONFIRM="$AAS_PHRASE"',
            'AAS_PYTHON=/usr/bin/python3',
            'PYTHONNOUSERSITE=1',
            'PYTHONSAFEPATH=1',
            '--profile complete-restore',
            '--artifact-profile workflow-artifacts',
            '--runtime-profile full',
            '--require-all-requested-agents',
            '--require-complete-install',
            '--post-install-smoke verify',
            'AAS_RESTORE_AGENTS',
            'AAS_SHARED_RUNTIME="$HOME/.local/share/ai-agents-skills/runtime"',
            'AAS_RUNTIME_DIGEST_PAIRS=(',
            '$AAS_IMMUTABLE/canonical/runtime/runners/run_skill.sh|$AAS_SHARED_RUNTIME/run_skill.sh',
            '$AAS_IMMUTABLE/canonical/runtime/runners/load_secret_env.py|$AAS_SHARED_RUNTIME/load_secret_env.py',
            'AAS_RUNTIME_EXPECTED_SHA256=',
            'AAS_RUNTIME_OBSERVED_SHA256=',
            'installed shared runtime differs from pinned ai-agents-skills source',
            '[[ -x "$AAS_SHARED_RUNTIME/run_skill.sh" ]]',
            '--agents codex install',
            '--runtime-root "$HOME/.codex/runtime"',
            '[[ -x "$HOME/.codex/runtime/run_skill.sh" ]]',
            '[[ -f "$HOME/.codex/runtime/load_secret_env.py"',
            '"$HOME/.codex/config.toml"',
            '"$HOME/.codex/runtime"',
            'Codex config does not select its private runtime root',
        ):
            self.assertIn(required, phase)
        # ai-agents-skills never uses root.
        self.assertNotIn("sudo", phase)
        self.assertNotIn("/usr/local/libexec", phase)

        shared_install = phase.index('case_id":"install.phase8.aas-install')
        shared_digest_gate = phase.index('AAS_RUNTIME_DIGEST_PAIRS=(', shared_install)
        shared_digest_compare = phase.index(
            '[[ "$AAS_RUNTIME_EXPECTED_SHA256" == "$AAS_RUNTIME_OBSERVED_SHA256" ]]',
            shared_digest_gate,
        )
        codex_install = phase.index('--agents codex install', shared_digest_compare)
        self.assertLess(shared_install, shared_digest_gate)
        self.assertLess(shared_digest_gate, shared_digest_compare)
        self.assertLess(shared_digest_compare, codex_install)

        self.assertNotIn('--skills modal-research-compute', phase)
        phase9 = source.split('# 9 ─ python environments', 1)[1].split(
            '# 10 ─ docker images', 1
        )[0]
        self.assertIn('installed-runtime-smoke --require-complete-coverage', phase9)
        self.assertIn(
            'AAS_IMMUTABLE_PHASE9="$HOME/.local/share/coding-system/components/ai-agents-skills/$AAS_PIN_PHASE9"',
            phase9,
        )
        self.assertNotIn("/usr/local/libexec/coding-system/components", phase9)
        self.assertIn('missing_managed_runtime_count', phase9)
        self.assertIn(
            'AAS_RUNTIME_PYTHON="$HOME/.local/share/coding-system/python-closure/shared/bin/python"',
            phase9,
        )
        for isolated_smoke_contract in (
            'CODEX_SHARED_PROBE="$CODEX_SMOKE_HOME/.local/share/ai-agents-skills/runtime"',
            '[[ ! -e "$CODEX_SHARED_PROBE" && ! -L "$CODEX_SHARED_PROBE" ]]',
            'HOME="$CODEX_SMOKE_HOME"',
            'AAS_RUNTIME_ROOT="$HOME/.codex/runtime"',
            '"$HOME/.codex/runtime/run_skill.sh"',
            'skills/formal-skeleton-helper/run_formal_skeleton.sh',
            'install.phase9.codex-private-runtime-smoke',
        ):
            self.assertIn(isolated_smoke_contract, phase9)

        codex_config = tomllib.loads(
            (ROOT / "agents/codex/config.toml.template")
            .read_text(encoding="utf-8")
            .replace("{{ HOME }}", "/home/fixture")
        )
        self.assertEqual(
            codex_config["shell_environment_policy"]["set"]["AAS_RUNTIME_ROOT"],
            "/home/fixture/.codex/runtime",
        )
        self.assertEqual(
            codex_config["shell_environment_policy"]["set"]["AAS_RUNTIME_PYTHON"],
            "/home/fixture/.local/share/coding-system/python-closure/shared/bin/python",
        )
        self.assertEqual(
            codex_config["shell_environment_policy"]["set"][
                "AAS_COMPUTE_SECRETS_FILE"
            ],
            "/home/fixture/.config/ai-agents-skills/compute.env",
        )

        digest_line = next(
            line.strip()
            for line in phase.splitlines()
            if line.strip().startswith('AAS_HELPER_SHA256="')
        )
        declared_digest = digest_line.split('"', 2)[1]
        actual_digest = hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest()
        self.assertEqual(declared_digest, actual_digest)
        binding_end = phase.index('AAS_HELPER="$AAS_BOUND_HELPER"')
        first_helper_use = phase.index(
            '/usr/bin/python3 -I -B "$AAS_HELPER"'
        )
        self.assertLess(binding_end, first_helper_use)
        self.assertNotIn(
            '/usr/bin/python3 -I -B "$AAS_HELPER_SOURCE"',
            phase,
        )
        verification = (ROOT / "bin/verify.sh").read_text(encoding="utf-8")
        self.assertIn("component materializer authority/hash invalid", verification)
        self.assertIn("component immutable authority invalid", verification)
        self.assertIn("/usr/bin/sha256sum", verification)
        self.assertIn("/usr/bin/stat", verification)
        self.assertIn("/usr/bin/git --no-replace-objects --no-optional-locks", verification)
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", verification)
        self.assertIn(
            'AAS_RUNTIME_PYTHON="$HOME/.local/share/coding-system/python-closure/shared/bin/python"',
            verification,
        )

    def test_raw_transport_does_not_apply_checkout_attributes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()

            def git(*arguments: str) -> None:
                result = subprocess.run(
                    ["/usr/bin/git", "-C", str(repo), *arguments],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())

            git("init", "-q")
            git("config", "user.name", "AAS Component Test")
            git("config", "user.email", "aas-component@example.invalid")
            (repo / ".gitattributes").write_text("*.bat text eol=crlf\n", encoding="ascii")
            (repo / "installer").mkdir()
            bootstrap = repo / "installer/bootstrap.sh"
            bootstrap.write_bytes(b"#!/bin/sh\nexit 0\n")
            bootstrap.chmod(0o755)
            (repo / "make.bat").write_bytes(b"@echo off\necho raw\n")
            git("add", ".")
            git("commit", "-qm", "fixture")
            pin = subprocess.check_output(
                ["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"],
                text=True,
            ).strip()
            output = io.BytesIO()
            AAS_COMPONENT.emit_raw_tar(repo, pin, output)
            output.seek(0)
            with tarfile.open(fileobj=output, mode="r:") as archive:
                stream = archive.extractfile("make.bat")
                assert stream is not None
                self.assertEqual(stream.read(), b"@echo off\necho raw\n")

    def test_extracted_tree_is_bound_to_git_blob_ids_and_modes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root, uid, gid = self.fixture(base)
            try:
                stage = AAS_COMPONENT.create_stage(root, PIN, uid=uid, gid=gid)
                self.populate(stage)

                def record(mode: bytes, path: str, data: bytes) -> bytes:
                    import hashlib

                    digest = hashlib.sha1(
                        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
                    ).hexdigest()
                    return mode + b" blob " + digest.encode("ascii") + b"\t" + path.encode() + b"\0"

                inventory = record(
                    b"100755",
                    "installer/bootstrap.sh",
                    b"#!/bin/sh\nexit 0\n",
                ) + record(b"100644", "payload.txt", b"fixture\n")
                AAS_COMPONENT.verify_extracted_archive(
                    root, inventory, PIN, stage, uid=uid, gid=gid
                )
                (stage / "payload.txt").write_bytes(b"changed\n")
                with self.assertRaisesRegex(
                    AAS_COMPONENT.ComponentError,
                    "blob differs",
                ):
                    AAS_COMPONENT.verify_extracted_archive(
                        root, inventory, PIN, stage, uid=uid, gid=gid
                    )
                AAS_COMPONENT._remove_stage(root, PIN, stage, uid=uid, gid=gid)
            finally:
                make_writable(base)

    def test_publish_is_immutable_idempotent_and_conflict_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root, uid, gid = self.fixture(base)
            try:
                stage = AAS_COMPONENT.create_stage(root, PIN, uid=uid, gid=gid)
                self.populate(stage)
                target = AAS_COMPONENT.publish_stage(
                    root, PIN, stage, uid=uid, gid=gid
                )
                self.assertEqual(
                    AAS_COMPONENT.verify_component(root, PIN, uid=uid, gid=gid),
                    target,
                )
                self.assertEqual(target.stat().st_mode & 0o777, 0o555)
                self.assertEqual(
                    (target / "installer/bootstrap.sh").stat().st_mode & 0o777,
                    0o555,
                )
                self.assertEqual((target / "payload.txt").stat().st_mode & 0o777, 0o444)

                repeat = AAS_COMPONENT.create_stage(root, PIN, uid=uid, gid=gid)
                self.populate(repeat)
                self.assertEqual(
                    AAS_COMPONENT.publish_stage(
                        root, PIN, repeat, uid=uid, gid=gid
                    ),
                    target,
                )
                self.assertFalse(repeat.exists())

                conflict = AAS_COMPONENT.create_stage(root, PIN, uid=uid, gid=gid)
                self.populate(conflict, marker=b"different\n")
                with self.assertRaisesRegex(
                    AAS_COMPONENT.ComponentError,
                    "does not match",
                ):
                    AAS_COMPONENT.publish_stage(
                        root, PIN, conflict, uid=uid, gid=gid
                    )
                self.assertEqual((target / "payload.txt").read_bytes(), b"fixture\n")
                AAS_COMPONENT._remove_stage(
                    root, PIN, conflict, uid=uid, gid=gid
                )
            finally:
                make_writable(base)

    def test_stage_rejects_symlink_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root, uid, gid = self.fixture(base)
            try:
                stage = AAS_COMPONENT.create_stage(root, PIN, uid=uid, gid=gid)
                self.populate(stage)
                (stage / "unsafe").symlink_to("payload.txt")
                with self.assertRaisesRegex(AAS_COMPONENT.ComponentError, "unsafe file"):
                    AAS_COMPONENT.publish_stage(
                        root, PIN, stage, uid=uid, gid=gid
                    )
                AAS_COMPONENT._remove_stage(root, PIN, stage, uid=uid, gid=gid)
            finally:
                make_writable(base)

    def test_helper_refuses_root(self) -> None:
        real_geteuid = AAS_COMPONENT.os.geteuid
        AAS_COMPONENT.os.geteuid = lambda: 0
        try:
            with self.assertRaisesRegex(AAS_COMPONENT.ComponentError, "never by root"):
                AAS_COMPONENT.main(["verify", PIN])
        finally:
            AAS_COMPONENT.os.geteuid = real_geteuid

    def test_owner_directory_rule_rejects_group_writable_and_foreign_trees(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "home"
            base.mkdir(mode=0o755)
            uid = os.geteuid()
            root = AAS_COMPONENT.ensure_component_root(base=base, uid=uid)
            self.assertEqual(
                root,
                base / ".local/share/coding-system/components/ai-agents-skills",
            )
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            root.chmod(0o770)
            with self.assertRaisesRegex(AAS_COMPONENT.ComponentError, "unsafe authority"):
                AAS_COMPONENT.ensure_component_root(base=base, uid=uid)
            root.chmod(0o700)
            with self.assertRaisesRegex(AAS_COMPONENT.ComponentError, "unsafe authority"):
                AAS_COMPONENT.ensure_component_root(base=base, uid=uid + 1)

    def test_verifier_checks_the_owner_tree_without_root(self) -> None:
        verification = (ROOT / "bin/verify.sh").read_text(encoding="utf-8")
        self.assertNotIn("/usr/local/libexec/coding-system/components", verification)
        self.assertNotIn("/usr/local/libexec/coding-system/install-helpers", verification)
        for required in (
            'helper="$HOME/.local/share/coding-system/install-helpers/aas-component-$helper_digest.py"',
            'immutable="$HOME/.local/share/coding-system/components/ai-agents-skills/$pin"',
            '== "$owner_uid:444:1"',
            '== "$owner_uid:555"',
            '== "$owner_uid:555:1"',
            'AAS_IMMUTABLE="$HOME/.local/share/coding-system/components/ai-agents-skills/$AAS_PIN"',
        ):
            self.assertIn(required, verification)

    def test_credential_lanes_launch_from_the_owner_runtime(self) -> None:
        profile = (ROOT / "system/shell/profile.block.sh").read_text(encoding="utf-8")
        block = profile.split("# >>> ai-agents-skills credential lanes >>>", 1)[1].split(
            "# <<< ai-agents-skills credential lanes <<<", 1
        )[0]
        self.assertIn(
            'launcher="$HOME/.local/share/ai-agents-skills/runtime/run_skill.sh"', block
        )
        self.assertNotIn("/usr/local", block)
        workflow = (ROOT / ".github/workflows/rehearsal.yml").read_text(encoding="utf-8")
        self.assertIn('== "owner-pinned-object"', workflow)
        self.assertNotIn("root-owned-pinned-object", workflow)

    def test_no_file_places_ai_agents_skills_under_root(self) -> None:
        forbidden = "/usr/local/libexec/coding-system/" + "components"
        this_test = Path(__file__).resolve()
        listed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, check=True,
        ).stdout.decode("utf-8").split("\0")
        offenders = []
        for name in filter(None, listed):
            path = ROOT / name
            if path.is_symlink() or not path.is_file() or path.resolve() == this_test:
                continue
            relative = path.relative_to(ROOT)
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if forbidden in text:
                offenders.append(relative.as_posix())
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
