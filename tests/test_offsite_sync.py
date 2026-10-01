from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


RCLONE_FIXTURE = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import sys

arguments = sys.argv[1:]
with Path(os.environ["CSR_TEST_RCLONE_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(arguments) + "\n")
remote_root = Path(os.environ["CSR_TEST_REMOTE_ROOT"])


def remote_path(value):
    if not value.startswith("dropbox-test:"):
        return None
    return remote_root / value.removeprefix("dropbox-test:").lstrip("/")


def inventory(root):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


command, *rest = arguments
if command == "listremotes":
    print("dropbox-test:")
elif command == "lsd":
    target = remote_path(rest[0])
    raise SystemExit(0 if target is not None and target.is_dir() else 3)
elif command == "lsjson":
    target = remote_path(rest[0])
    raise SystemExit(0 if target is not None and target.exists() else 3)
elif command == "check":
    source = Path(rest[0])
    destination = remote_path(rest[1])
    if destination is None or inventory(source) != inventory(destination):
        raise SystemExit(4)
    if os.environ.get("CSR_TEST_INJECT_AFTER_CHECK") == "1":
        (destination / "injected-after-check.bin").write_bytes(b"injected\n")
elif command == "copy":
    positional = [value for value in rest if not value.startswith("--")]
    if len(positional) != 2:
        raise SystemExit(2)
    source_value, destination_value = positional
    source_remote = remote_path(source_value)
    destination_remote = remote_path(destination_value)
    if source_remote is None and destination_remote is not None:
        source = Path(source_value)
        destination_remote.mkdir(parents=True, exist_ok=True)
        for path in source.rglob("*"):
            if path.is_file():
                target = destination_remote / path.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
    elif source_remote is not None and destination_remote is None:
        destination = Path(destination_value)
        destination.mkdir(parents=True, exist_ok=True)
        for path in source_remote.rglob("*"):
            if path.is_file():
                target = destination / path.relative_to(source_remote)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
        if os.environ.get("CSR_TEST_TAMPER_FETCH") == "1":
            (destination / "recovery-set.json").write_text(
                '{"set_id":"tampered-recovery-set"}\n', encoding="utf-8"
            )
        if os.environ.get("CSR_TEST_TAMPER_OWNER_FETCH") == "1":
            owner = next(destination.glob("openclaw-private-*.tar.gz.gpg"))
            owner.write_bytes(b"tampered owner archive\n")
    else:
        raise SystemExit(2)
else:
    raise SystemExit(2)
'''


RECOVERY_TOOL_FIXTURE = r'''import hashlib
import json
from pathlib import Path


def load_recovery_manifest(directory):
    root = Path(directory)
    value = json.loads((root / "recovery-set.json").read_text(encoding="utf-8"))
    if set(value) != {"set_id", "owner_data"}:
        raise RuntimeError("recovery manifest is malformed")
    owner = value["owner_data"]
    expected = {"recovery-set.json", "recovery-set.json.sig"}
    if owner is not None:
        if not isinstance(owner, dict) or set(owner) != {"file", "sha256", "size"}:
            raise RuntimeError("owner record is malformed")
        member = root / owner["file"]
        payload = member.read_bytes()
        if len(payload) != owner["size"] or hashlib.sha256(payload).hexdigest() != owner["sha256"]:
            raise RuntimeError("owner member differs from signed metadata")
        expected.add(owner["file"])
    actual = {path.name for path in root.iterdir()}
    if actual != expected:
        raise RuntimeError("recovery inventory is not exact")
    return value
'''


class OffsiteSyncTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, dict[str, str], Path, Path]:
        repository = root / "repository"
        (repository / "bin/lib").mkdir(parents=True)
        rclone = root / "trusted-rclone"
        rclone.write_text(RCLONE_FIXTURE, encoding="utf-8")
        rclone.chmod(0o755)
        script = repository / "bin/offsite-sync.sh"
        script.write_text(
            (ROOT / "bin/offsite-sync.sh")
            .read_text(encoding="utf-8")
            .replace("/usr/bin/rclone", os.fspath(rclone)),
            encoding="utf-8",
        )
        script.chmod(0o755)
        (repository / "bin/lib/recovery_tool.py").write_text(
            RECOVERY_TOOL_FIXTURE, encoding="utf-8"
        )
        (repository / "bin/lib/owner_settings.py").write_text(
            (ROOT / "bin/lib/owner_settings.py").read_text(encoding="utf-8"), encoding="utf-8"
        )
        (repository / "bin/lib/secure_temp.py").write_text(
            "import os\n"
            "from pathlib import Path\n"
            "import sys\n"
            "import tempfile\n"
            "if sys.argv[1:2] != ['create'] or sys.argv[2:3] != ['--prefix']:\n"
            "    raise SystemExit(2)\n"
            "path = Path(tempfile.mkdtemp(prefix=sys.argv[3], dir=os.environ['CSR_TEST_TEMP_ROOT']))\n"
            "path.chmod(0o700)\n"
            "print(path)\n",
            encoding="utf-8",
        )
        verifier = repository / "bin/verify-recovery-signature.sh"
        verifier.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "want=$(cat \"$RECOVERY_SET/recovery-set.json.sig\")\n"
            "have=$(/usr/bin/sha256sum \"$RECOVERY_SET/recovery-set.json\" | /usr/bin/cut -d' ' -f1)\n"
            "[[ $want == $have ]]\n",
            encoding="utf-8",
        )
        verifier.chmod(0o755)

        set_id = "csr-20260805t000000z-fixture"
        recovery_set = root / "source" / set_id
        recovery_set.mkdir(parents=True)
        owner_name = "openclaw-private-20260805T010203Z.tar.gz.gpg"
        owner_payload = b"encrypted owner archive fixture\n"
        (recovery_set / owner_name).write_bytes(owner_payload)
        manifest = (
            json.dumps(
                {
                    "set_id": set_id,
                    "owner_data": {
                        "file": owner_name,
                        "sha256": hashlib.sha256(owner_payload).hexdigest(),
                        "size": len(owner_payload),
                    },
                },
                sort_keys=True,
            )
            + "\n"
        ).encode()
        (recovery_set / "recovery-set.json").write_bytes(manifest)
        (recovery_set / "recovery-set.json.sig").write_text(
            hashlib.sha256(manifest).hexdigest() + "\n", encoding="ascii"
        )

        remote = root / "remote"
        (remote / "backups").mkdir(parents=True)
        temp_root = root / "protected-temp"
        temp_root.mkdir(mode=0o700)
        log = root / "rclone.jsonl"
        log.touch(mode=0o600)
        environment = {
            **os.environ,
            "HOME": str(root / "home"),
            "CSR_RCLONE_DEST": "dropbox-test:backups",
            "CSR_TEST_RCLONE_LOG": str(log),
            "CSR_TEST_REMOTE_ROOT": str(remote),
            "CSR_TEST_TEMP_ROOT": str(temp_root),
        }
        Path(environment["HOME"]).mkdir(mode=0o700)
        return script, recovery_set, environment, log, temp_root

    def _run(
        self,
        script: Path,
        recovery_set: Path,
        environment: dict[str, str],
        **extra: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/usr/bin/bash", str(script), str(recovery_set)],
            env={**environment, **extra},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_upload_checks_exact_inventory_then_authenticates_fetched_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, recovery_set, environment, log, temp_root = self._fixture(root)
            completed = self._run(script, recovery_set, environment)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            commands = [json.loads(line) for line in log.read_text().splitlines()]
            check_index = next(i for i, command in enumerate(commands) if command[0] == "check")
            fetch_index = next(
                i
                for i, command in enumerate(commands)
                if command[0] == "copy" and command[1].startswith("dropbox-test:")
            )
            self.assertLess(check_index, fetch_index)
            remote_set = (
                root
                / "remote/backups/recovery-sets"
                / recovery_set.name
            )
            self.assertEqual(
                {path.name: path.read_bytes() for path in remote_set.iterdir()},
                {path.name: path.read_bytes() for path in recovery_set.iterdir()},
            )
            self.assertEqual(list(temp_root.iterdir()), [])
            self.assertIn("readback-checked immutable recovery set", completed.stdout)
            owner = next(remote_set.glob("openclaw-private-*.tar.gz.gpg"))
            self.assertEqual(owner.read_bytes(), b"encrypted owner archive fixture\n")

    def test_missing_destination_setting_fails_before_any_remote_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, recovery_set, environment, log, _temp_root = self._fixture(root)
            environment.pop("CSR_RCLONE_DEST")
            completed = self._run(script, recovery_set, environment)
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("CSR_RCLONE_DEST", completed.stderr)
            self.assertEqual(log.read_text(), "")

    def test_destination_falls_back_to_the_owner_settings_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, recovery_set, environment, log, _temp_root = self._fixture(root)
            destination = environment.pop("CSR_RCLONE_DEST")
            settings = Path(environment["HOME"]) / ".secrets.env"
            settings.write_text(f"CSR_RCLONE_DEST={destination}\n", encoding="utf-8")
            settings.chmod(0o600)
            completed = self._run(script, recovery_set, environment)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("readback-checked immutable recovery set", completed.stdout)

    def _run_owner_offsite(self, home: Path, log: Path) -> subprocess.CompletedProcess[str]:
        fake_bin = home.parent / "fake-bin"
        fake_bin.mkdir(exist_ok=True)
        rclone = fake_bin / "rclone"
        rclone.write_text(f"#!/bin/sh\necho \"$*\" >> {log}\n", encoding="utf-8")
        rclone.chmod(0o755)
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"CSR_OWNER_RCLONE_DEST", "CSR_NO_OFFSITE"}}
        environment["HOME"] = str(home)
        environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
        return subprocess.run(
            ["/usr/bin/bash", str(ROOT / "bin/offsite-owner-sync.sh")],
            env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False,
        )

    def test_owner_offsite_requires_its_destination_setting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            log = Path(temporary) / "rclone.log"
            completed = self._run_owner_offsite(home, log)
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("CSR_OWNER_RCLONE_DEST", completed.stderr)
            self.assertFalse(log.exists())

    def test_owner_offsite_destination_falls_back_to_the_owner_settings_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            settings = home / ".secrets.env"
            settings.write_text("CSR_OWNER_RCLONE_DEST=owner-test:archives\n", encoding="utf-8")
            settings.chmod(0o600)
            log = Path(temporary) / "rclone.log"
            completed = self._run_owner_offsite(home, log)
            # past the destination check: it stops only because no archive exists
            self.assertEqual(completed.returncode, 5, completed.stderr)
            self.assertFalse(log.exists())

    def test_remote_injection_after_check_is_rejected_by_fetched_inventory_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, recovery_set, environment, _log, temp_root = self._fixture(root)
            completed = self._run(
                script,
                recovery_set,
                environment,
                CSR_TEST_INJECT_AFTER_CHECK="1",
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn("readback-checked", completed.stdout)
            self.assertEqual(list(temp_root.iterdir()), [])

    def test_fetched_manifest_tamper_fails_signature_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, recovery_set, environment, _log, temp_root = self._fixture(root)
            completed = self._run(
                script,
                recovery_set,
                environment,
                CSR_TEST_TAMPER_FETCH="1",
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn("readback-checked", completed.stdout)
            self.assertEqual(list(temp_root.iterdir()), [])

    def test_fetched_owner_member_tamper_fails_signed_inventory_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, recovery_set, environment, _log, temp_root = self._fixture(root)
            completed = self._run(
                script,
                recovery_set,
                environment,
                CSR_TEST_TAMPER_OWNER_FETCH="1",
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn("readback-checked", completed.stdout)
            self.assertEqual(list(temp_root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
