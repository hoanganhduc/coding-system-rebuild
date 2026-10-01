#!/usr/bin/env python3
"""Process-death and boundary tests for durable recovery transactions."""

from __future__ import annotations

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
HELPER = ROOT / "bin" / "lib" / "recovery_tool.py"
STATE = Path(".local/state/coding-system/recovery-transactions")
PATH_MODES = {
    ".config/demo/a.json": 0o600,
    ".created/deep/b.json": 0o600,
}

LOAD = r"""
import importlib.util
import pathlib
import sys
spec = importlib.util.spec_from_file_location("recovery_tool_child", sys.argv[1])
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
"""


def load_helper():
    spec = importlib.util.spec_from_file_location("recovery_tool_transaction_test", HELPER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DurableRestoreTransactionTests(unittest.TestCase):
    def make_fixture(self, root: Path) -> tuple[Path, Path]:
        stage = root / "stage"
        destination = root / "home"
        stage.mkdir(mode=0o700)
        stage.chmod(0o700)
        destination.mkdir()
        destination.chmod(0o700)
        first = stage / ".config/demo/a.json"
        first.parent.mkdir(parents=True)
        first.write_bytes(b"synthetic-new-a\n")
        first.chmod(0o600)
        second = stage / ".created/deep/b.json"
        second.parent.mkdir(parents=True)
        second.write_bytes(b"synthetic-new-b\n")
        second.chmod(0o600)
        old = destination / ".config/demo/a.json"
        old.parent.mkdir(parents=True)
        (destination / ".config").chmod(0o700)
        old.parent.chmod(0o700)
        old.write_bytes(b"synthetic-old-a\n")
        old.chmod(0o640)
        return stage, destination

    def crash_apply(self, stage: Path, destination: Path, cutpoint: str) -> int:
        code = LOAD + r"""
module.apply_staged_tree(
    pathlib.Path(sys.argv[2]),
    pathlib.Path(sys.argv[3]),
    {".config/demo/a.json": 0o600, ".created/deep/b.json": 0o600},
    replace=True,
    _test_crash_at=sys.argv[4],
)
"""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                code,
                str(HELPER),
                str(stage),
                str(destination),
                cutpoint,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 97, result.stderr.decode(errors="replace"))
        return result.returncode

    def crash_recovery(self, destination: Path, cutpoint: str) -> int:
        code = LOAD + r"""
module.recover_incomplete_restore(
    pathlib.Path(sys.argv[2]), _test_crash_at=sys.argv[3]
)
"""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                code,
                str(HELPER),
                str(destination),
                cutpoint,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 97, result.stderr.decode(errors="replace"))
        return result.returncode

    def transaction_dirs(self, destination: Path) -> list[Path]:
        state = destination / STATE
        return sorted(path for path in state.iterdir() if path.name != ".lock")

    def assert_original(self, destination: Path) -> None:
        old = destination / ".config/demo/a.json"
        self.assertEqual(old.read_bytes(), b"synthetic-old-a\n")
        self.assertEqual(stat.S_IMODE(old.stat().st_mode), 0o640)
        self.assertFalse((destination / ".created/deep/b.json").exists())
        self.assertFalse((destination / ".created").exists())

    def test_process_death_before_commit_rolls_back_exact_bytes_and_modes(self) -> None:
        helper = load_helper()
        for cutpoint in (
            "after_prepared",
            "after_applying",
            "after_directories",
            "during_target_1",
            "after_target_1",
            "after_targets",
        ):
            with self.subTest(cutpoint=cutpoint), tempfile.TemporaryDirectory() as td:
                stage, destination = self.make_fixture(Path(td))
                self.crash_apply(stage, destination, cutpoint)
                transactions = self.transaction_dirs(destination)
                self.assertEqual(len(transactions), 1)
                transaction = transactions[0]
                self.assertEqual(stat.S_IMODE(transaction.stat().st_mode), 0o700)
                journal_path = transaction / "journal.json"
                self.assertEqual(stat.S_IMODE(journal_path.stat().st_mode), 0o600)
                journal_raw = journal_path.read_bytes()
                self.assertNotIn(b"synthetic-old-a", journal_raw)
                self.assertNotIn(b"synthetic-new-a", journal_raw)
                journal = json.loads(journal_raw)
                self.assertIn(journal["state"], {"prepared", "applying"})
                for backup in (transaction / "backups").iterdir():
                    self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
                    self.assertEqual(backup.stat().st_nlink, 1)
                helper.recover_incomplete_restore(destination)
                self.assert_original(destination)
                self.assertEqual(self.transaction_dirs(destination), [])

    def test_process_death_after_commit_keeps_new_state_and_only_cleans(self) -> None:
        helper = load_helper()
        for cutpoint in ("after_committed", "after_cleanup_published"):
            with self.subTest(cutpoint=cutpoint), tempfile.TemporaryDirectory() as td:
                stage, destination = self.make_fixture(Path(td))
                self.crash_apply(stage, destination, cutpoint)
                transaction = self.transaction_dirs(destination)[0]
                journal = json.loads((transaction / "journal.json").read_bytes())
                self.assertEqual(journal["state"], "committed")
                self.assertEqual(journal["outcome"], "applied")
                helper.recover_incomplete_restore(destination)
                first = destination / ".config/demo/a.json"
                second = destination / ".created/deep/b.json"
                self.assertEqual(first.read_bytes(), b"synthetic-new-a\n")
                self.assertEqual(second.read_bytes(), b"synthetic-new-b\n")
                self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(second.stat().st_mode), 0o600)
                self.assertEqual(self.transaction_dirs(destination), [])

    def test_process_death_during_rollback_is_idempotently_recovered(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            stage, destination = self.make_fixture(Path(td))
            self.crash_apply(stage, destination, "after_targets")
            self.crash_recovery(destination, "rollback_during_target_1")
            helper.recover_incomplete_restore(destination)
            self.assert_original(destination)
            self.assertEqual(self.transaction_dirs(destination), [])

    def test_next_restore_recovers_before_its_own_preflight(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            stage, destination = self.make_fixture(Path(td))
            self.crash_apply(stage, destination, "after_target_1")
            (stage / ".config/demo/a.json").write_bytes(b"second-attempt\n")
            with self.assertRaisesRegex(helper.RecoveryError, "divergent"):
                helper.apply_staged_tree(
                    stage, destination, PATH_MODES, replace=False
                )
            self.assert_original(destination)
            self.assertEqual(self.transaction_dirs(destination), [])

    def test_hardlinked_source_or_destination_is_refused_before_mutation(self) -> None:
        helper = load_helper()
        for boundary in ("source", "destination"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as td:
                stage, destination = self.make_fixture(Path(td))
                if boundary == "source":
                    os.link(
                        stage / ".config/demo/a.json",
                        stage / ".config/demo/a-hardlink.json",
                    )
                else:
                    os.link(
                        destination / ".config/demo/a.json",
                        destination / ".config/demo/a-hardlink.json",
                    )
                with self.assertRaisesRegex(helper.RecoveryError, "unsafe restore regular"):
                    helper.apply_staged_tree(
                        stage, destination, PATH_MODES, replace=True
                    )
                self.assert_original(destination)

    def test_transaction_state_symlink_is_refused(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            stage, destination = self.make_fixture(Path(td))
            outside = Path(td) / "outside"
            outside.mkdir()
            state_parent = destination / ".local/state/coding-system"
            state_parent.mkdir(parents=True)
            (destination / ".local").chmod(0o700)
            (destination / ".local/state").chmod(0o700)
            state_parent.chmod(0o700)
            (state_parent / "recovery-transactions").symlink_to(
                outside, target_is_directory=True
            )
            with self.assertRaisesRegex(helper.RecoveryError, "state|unsafe"):
                helper.apply_staged_tree(stage, destination, PATH_MODES, replace=True)
            self.assert_original(destination)

    def test_shared_writable_destination_is_refused_before_preflight(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            stage, destination = self.make_fixture(Path(td))
            destination.chmod(0o770)
            with self.assertRaisesRegex(helper.RecoveryError, "writable.*principal"):
                helper.apply_staged_tree(stage, destination, PATH_MODES, replace=True)
            self.assert_original(destination)

    def test_authenticated_deletion_commits_in_the_same_transaction(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as td:
            stage, destination = self.make_fixture(Path(td))
            legacy = destination / ".config/demo/legacy.env"
            legacy.write_bytes(b"synthetic-legacy-secret\n")
            legacy.chmod(0o600)
            helper.apply_staged_tree(
                stage,
                destination,
                {".config/demo/legacy.env": None},
                replace=True,
            )
            self.assertFalse(legacy.exists())
            self.assertEqual(self.transaction_dirs(destination), [])

    def test_bounded_replace_paths_do_not_weaken_unrelated_restore_entries(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            stage, destination = self.make_fixture(Path(temporary))
            projection = destination / ".config/demo/projected.json"
            projection.write_text("old projection\n", encoding="utf-8")
            projection.chmod(0o600)
            (stage / ".config/demo/projected.json").write_text(
                "new projection\n", encoding="utf-8"
            )
            (stage / ".config/demo/projected.json").chmod(0o600)
            modes = dict(PATH_MODES)
            modes[".config/demo/projected.json"] = 0o600

            with self.assertRaises(helper.RecoveryError):
                helper.apply_staged_tree(
                    stage,
                    destination,
                    modes,
                    replace=False,
                    replace_paths=frozenset({".config/demo/projected.json"}),
                )

            # Only the explicitly replaceable projection may diverge. Once
            # the unrelated authority is converged, the same plan succeeds.
            (destination / ".config/demo/a.json").write_bytes(
                (stage / ".config/demo/a.json").read_bytes()
            )
            helper.apply_staged_tree(
                stage,
                destination,
                modes,
                replace=False,
                replace_paths=frozenset({".config/demo/projected.json"}),
            )
            self.assertEqual(projection.read_text(encoding="utf-8"), "new projection\n")

    def test_process_death_after_deletion_rolls_back_exact_bytes_and_mode(self) -> None:
        helper = load_helper()
        code = LOAD + r'''
module.apply_staged_tree(
    pathlib.Path(sys.argv[2]),
    pathlib.Path(sys.argv[3]),
    {".config/demo/legacy.env": None},
    replace=True,
    _test_crash_at=sys.argv[4],
)
'''
        for cutpoint in ("during_target_1", "after_target_1", "after_targets"):
            with self.subTest(cutpoint=cutpoint), tempfile.TemporaryDirectory() as td:
                stage, destination = self.make_fixture(Path(td))
                legacy = destination / ".config/demo/legacy.env"
                legacy.write_bytes(b"synthetic-legacy-secret\n")
                legacy.chmod(0o640)
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        code,
                        str(HELPER),
                        str(stage),
                        str(destination),
                        cutpoint,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(
                    result.returncode, 97, result.stderr.decode(errors="replace")
                )
                helper.recover_incomplete_restore(destination)
                self.assertEqual(legacy.read_bytes(), b"synthetic-legacy-secret\n")
                self.assertEqual(stat.S_IMODE(legacy.stat().st_mode), 0o640)
                self.assertEqual(self.transaction_dirs(destination), [])

    def test_combined_projection_migration_crash_rolls_back_every_secret_file(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "home"
            destination.mkdir(mode=0o700)
            legacy = destination / ".claude/secrets.json"
            legacy.parent.mkdir(mode=0o700)
            legacy.write_text(
                '{"GH_TOKEN":"copilot-fixture","KIMI_API_KEY":"arl-fixture"}\n',
                encoding="utf-8",
            )
            legacy.chmod(0o600)
            broad = destination / ".openclaw/workspace/.secrets.json"
            broad.parent.mkdir(parents=True)
            for parent in (destination / ".openclaw", broad.parent):
                parent.chmod(0o700)
            broad.write_text('{"GH_TOKEN":"copilot-fixture"}\n', encoding="utf-8")
            broad.chmod(0o600)
            dotenv = destination / ".secrets.env"
            dotenv.write_text("CLASSROOM50_ORG_ALLOWLIST=fixture\n", encoding="utf-8")
            dotenv.chmod(0o600)
            originals = {
                path.relative_to(destination).as_posix(): (
                    path.read_bytes(),
                    stat.S_IMODE(path.stat().st_mode),
                )
                for path in (legacy, broad, dotenv)
            }

            recovery_stage = root / "recovery-stage"
            recovery_stage.mkdir(mode=0o700)
            staged_dotenv = recovery_stage / ".secrets.env"
            staged_dotenv.write_text(
                "CLASSROOM50_ORG_ALLOWLIST=fixture\n"
                "KAGGLE_API_TOKEN=kaggle-fixture\n",
                encoding="utf-8",
            )
            staged_dotenv.chmod(0o600)
            work = root / "work"
            work.mkdir(mode=0o700)
            stage, modes, replace_paths = helper._prepare_materialized_restore(
                recovery_stage,
                destination,
                {".secrets.env": 0o600},
                work,
            )
            code = LOAD + r'''
import json
module.apply_staged_tree(
    pathlib.Path(sys.argv[2]),
    pathlib.Path(sys.argv[3]),
    json.loads(sys.argv[4]),
    replace=True,
    replace_paths=frozenset(json.loads(sys.argv[5])),
    _test_crash_at="after_targets",
)
'''
            crashed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    code,
                    str(HELPER),
                    str(stage),
                    str(destination),
                    json.dumps(modes, sort_keys=True),
                    json.dumps(sorted(replace_paths)),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(crashed.returncode, 97, crashed.stderr)

            helper.recover_incomplete_restore(destination)

            for relative, (payload, mode) in originals.items():
                restored = destination / relative
                self.assertEqual(restored.read_bytes(), payload)
                self.assertEqual(stat.S_IMODE(restored.stat().st_mode), mode)
            self.assertFalse(
                (destination / ".config/ai-agents-skills/providers/copilot.env").exists()
            )
            self.assertEqual(self.transaction_dirs(destination), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
