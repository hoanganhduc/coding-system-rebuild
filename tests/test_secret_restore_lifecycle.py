from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SecretRestoreLifecycleTests(unittest.TestCase):
    def _write_executable(self, path: Path, body: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)

    def _fixture(self, root: Path) -> tuple[Path, dict[str, str], Path]:
        repository = root / "repository"
        (repository / "bin/lib").mkdir(parents=True)
        (repository / "secrets").mkdir()
        (repository / "secrets/secrets-manifest.yaml").write_text(
            "entries: []\n", encoding="utf-8"
        )
        (repository / "bin/secrets-restore.sh").write_bytes(
            (ROOT / "bin/secrets-restore.sh").read_bytes()
        )
        (repository / "bin/secrets-restore.sh").chmod(0o755)

        self._write_executable(
            repository / "bin/lib/recovery_tool.py",
            "#!/usr/bin/env python3\n"
            "import os\n"
            "from pathlib import Path\n"
            "import sys\n"
            "operation = sys.argv[1]\n"
            "with Path(os.environ['CSR_TEST_LIFECYCLE_LOG']).open('a', encoding='utf-8') as stream:\n"
            "    stream.write(operation + '\\n')\n"
            "stage = os.environ.get('CSR_TEST_FAIL_STAGE')\n"
            "if operation == 'restore' and stage in {'restore', 'recover'}:\n"
            "    raise SystemExit(41)\n"
            "if operation == 'recover-transaction' and stage == 'recover':\n"
            "    raise SystemExit(45)\n",
        )
        self._write_executable(
            repository / "bin/secret-restore-quiescence.sh",
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "action=${1#--}\n"
            "[[ ${2:-} == --state-file && -n ${3:-} ]]\n"
            "state=$3\n"
            "echo \"$action\" >> \"$CSR_TEST_LIFECYCLE_LOG\"\n"
            "if [[ $action == quiesce ]]; then\n"
            "  mkdir -p \"$(dirname \"$state\")\"\n"
            "  chmod 0700 \"$(dirname \"$state\")\"\n"
            "  printf '%s\\n' state > \"$state\"\n"
            "  chmod 0600 \"$state\"\n"
            "elif [[ ${CSR_TEST_FAIL_STAGE:-} == resume ]]; then\n"
            "  exit 42\n"
            "else\n"
            "  rm -f -- \"$state\"\n"
            "fi\n",
        )
        self._write_executable(
            repository / "bin/materialize-openclaw-runtime.sh",
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "echo runtime >> \"$CSR_TEST_LIFECYCLE_LOG\"\n"
            "[[ ${CSR_TEST_FAIL_STAGE:-} != runtime ]] || exit 43\n",
        )
        self._write_executable(
            repository / "bin/verify-skill-credentials.py",
            "#!/usr/bin/env python3\n"
            "import os\n"
            "from pathlib import Path\n"
            "import sys\n"
            "with Path(os.environ['CSR_TEST_LIFECYCLE_LOG']).open('a', encoding='utf-8') as stream:\n"
            "    stream.write('verify\\n')\n"
            "if os.environ.get('CSR_TEST_FAIL_STAGE') == 'verify':\n"
            "    raise SystemExit(44)\n"
            "output = Path(sys.argv[sys.argv.index('--output') + 1])\n"
            "output.parent.mkdir(parents=True, exist_ok=True)\n"
            "output.write_text('{}\\n', encoding='utf-8')\n",
        )

        home = root / "home"
        home.mkdir(mode=0o700)
        (home / ".config/coding-system").mkdir(parents=True)
        (home / ".config/coding-system/skill-credential-source-contract.json").write_text(
            "{}\n", encoding="utf-8"
        )
        recovery_set = root / "recovery-set"
        recovery_set.mkdir()
        first_share = root / "share-01.txt"
        second_share = root / "share-02.txt"
        first_share.write_text("one\n", encoding="utf-8")
        second_share.write_text("two\n", encoding="utf-8")
        log = root / "lifecycle.log"
        environment = {
            **os.environ,
            "HOME": str(home),
            "RECOVERY_SET": str(recovery_set),
            "CSR_ESCROW_SHARE_1_FILE": str(first_share),
            "CSR_ESCROW_SHARE_2_FILE": str(second_share),
            "CSR_TEST_LIFECYCLE_LOG": str(log),
        }
        return repository, environment, log

    def _run(
        self, repository: Path, environment: dict[str, str], *, fail: str = ""
    ) -> subprocess.CompletedProcess[str]:
        selected = dict(environment)
        if fail:
            selected["CSR_TEST_FAIL_STAGE"] = fail
        return subprocess.run(
            ["/usr/bin/bash", str(repository / "bin/secrets-restore.sh")],
            env=selected,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_success_revalidates_before_resuming_and_removes_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, environment, log = self._fixture(root)
            completed = self._run(repository, environment)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                ["validate-set", "quiesce", "restore", "runtime", "verify", "resume"],
            )
            state_root = Path(environment["HOME"]) / ".local/state/coding-system/restore"
            self.assertEqual(list(state_root.glob("service-state-*.state")), [])
            self.assertEqual(len(list(state_root.glob("credential-restore-*.json"))), 1)

    def test_failed_restore_recovers_and_revalidates_before_resuming(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, environment, log = self._fixture(root)
            completed = self._run(repository, environment, fail="restore")

            self.assertEqual(completed.returncode, 41)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                [
                    "validate-set",
                    "quiesce",
                    "restore",
                    "recover-transaction",
                    "runtime",
                    "verify",
                    "resume",
                ],
            )
            state_root = Path(environment["HOME"]) / ".local/state/coding-system/restore"
            self.assertEqual(list(state_root.glob("service-state-*.state")), [])

    def test_unresolved_restore_outcome_keeps_services_stopped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, environment, log = self._fixture(root)
            completed = self._run(repository, environment, fail="recover")

            self.assertEqual(completed.returncode, 41)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                ["validate-set", "quiesce", "restore", "recover-transaction"],
            )
            self.assertIn("services remain stopped", completed.stderr)
            state_root = Path(environment["HOME"]) / ".local/state/coding-system/restore"
            self.assertEqual(len(list(state_root.glob("service-state-*.state"))), 1)

    def test_postcommit_runtime_failure_retains_stopped_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, environment, log = self._fixture(root)
            completed = self._run(repository, environment, fail="runtime")

            self.assertEqual(completed.returncode, 43)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                ["validate-set", "quiesce", "restore", "runtime"],
            )
            self.assertIn("services remain stopped", completed.stderr)
            state_root = Path(environment["HOME"]) / ".local/state/coding-system/restore"
            self.assertEqual(len(list(state_root.glob("service-state-*.state"))), 1)

    def test_postcommit_verifier_failure_does_not_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, environment, log = self._fixture(root)
            completed = self._run(repository, environment, fail="verify")

            self.assertEqual(completed.returncode, 44)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                ["validate-set", "quiesce", "restore", "runtime", "verify"],
            )
            self.assertIn("live revalidation did not complete", completed.stderr)
            state_root = Path(environment["HOME"]) / ".local/state/coding-system/restore"
            self.assertEqual(len(list(state_root.glob("service-state-*.state"))), 1)

    def test_non_live_destination_has_no_service_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, environment, log = self._fixture(root)
            destination = root / "destination"
            destination.mkdir(mode=0o700)
            environment["HOME_OVERRIDE"] = str(destination)
            completed = self._run(repository, environment)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                ["validate-set", "restore", "runtime"],
            )

    def test_resume_validates_and_removes_an_empty_owner_private_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            state_root = home / ".local/state/coding-system/restore"
            state_root.mkdir(parents=True, mode=0o700)
            state = state_root / ("service-state-" + "a" * 32 + ".state")
            state.write_text(
                json.dumps(
                    {
                        "activeUnits": [],
                        "schema": "coding-system.secret-restore-services/v1",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            state.chmod(0o600)

            completed = subprocess.run(
                [
                    "/usr/bin/bash",
                    str(ROOT / "bin/secret-restore-quiescence.sh"),
                    "--resume",
                    "--state-file",
                    str(state),
                ],
                env={**os.environ, "HOME": str(home)},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(state.exists())
            self.assertEqual(stat.S_IMODE(state_root.stat().st_mode), 0o700)

    def test_resume_rejects_a_tampered_service_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            state_root = home / ".local/state/coding-system/restore"
            state_root.mkdir(parents=True, mode=0o700)
            state = state_root / ("service-state-" + "b" * 32 + ".state")
            state.write_text(
                '{"activeUnits":["attacker.service"],'
                '"schema":"coding-system.secret-restore-services/v1"}\n',
                encoding="utf-8",
            )
            state.chmod(0o600)

            completed = subprocess.run(
                [
                    "/usr/bin/bash",
                    str(ROOT / "bin/secret-restore-quiescence.sh"),
                    "--resume",
                    "--state-file",
                    str(state),
                ],
                env={**os.environ, "HOME": str(home)},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertTrue(state.exists())
            self.assertIn("invalid", completed.stderr)

    def test_quiescence_source_persists_state_before_first_stop(self) -> None:
        source = (ROOT / "bin/secret-restore-quiescence.sh").read_text(
            encoding="utf-8"
        )
        scan = source.index("if matches:")
        inspect = source.index("_active_units=()")
        persist = source.index('state_helper prepare "${_active_units[@]}"')
        stop = source.index('systemctl --user stop "$_openclaw_unit"')
        process_gate = source.index("credential_writer_is_running()")
        self.assertLess(scan, inspect)
        self.assertLess(inspect, persist)
        self.assertLess(persist, stop)
        self.assertLess(stop, process_gate)


if __name__ == "__main__":
    unittest.main()
