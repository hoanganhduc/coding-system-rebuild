#!/usr/bin/env python3
"""Synthetic immutable escrow-distribution tests.

Every rclone and GitHub operation is routed to local mocks.  The suite must
never depend on, inspect, or mutate a live remote or live escrow generation.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/escrow-passphrase.sh"


RCLONE_MOCK = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import sys

arguments = sys.argv[1:]
log = Path(os.environ["MOCK_COMMAND_LOG"])
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(["rclone", *arguments]) + "\n")

root = Path(os.environ["MOCK_REMOTE_ROOT"])

def remote_path(value):
    if value.startswith("dropbox-test:"):
        return root / "dropbox" / value.removeprefix("dropbox-test:").lstrip("/")
    if value.startswith("gdrive-test:"):
        return root / "gdrive" / value.removeprefix("gdrive-test:").lstrip("/")
    return None

if not arguments:
    raise SystemExit(2)
command, *rest = arguments
if command == "lsjson":
    target = remote_path(rest[0]) if rest else None
    if target is None or not target.is_file():
        raise SystemExit(3)
    print(json.dumps({"Name": target.name, "Size": target.stat().st_size}))
    raise SystemExit(0)
if command != "copyto":
    raise SystemExit(2)

immutable = "--immutable" in rest
positional = [value for value in rest if not value.startswith("--")]
if len(positional) != 2:
    raise SystemExit(2)
source, destination = positional
source_remote = remote_path(source)
destination_remote = remote_path(destination)
if source_remote is not None and destination_remote is None:
    if not source_remote.is_file():
        raise SystemExit(4)
    output = Path(destination)
    if output.exists():
        raise SystemExit(5)
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_remote, output)
    output.chmod(0o600)
    raise SystemExit(0)
if source_remote is None and destination_remote is not None:
    if immutable and destination_remote.exists():
        raise SystemExit(6)
    destination_remote.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination_remote)
    destination_remote.chmod(0o600)
    raise SystemExit(0)
raise SystemExit(2)
'''


GH_MOCK = r'''#!/usr/bin/env python3
import base64
import hashlib
import json
import os
from pathlib import Path
import sys

arguments = sys.argv[1:]
log = Path(os.environ["MOCK_COMMAND_LOG"])
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(["gh", *arguments]) + "\n")

if not arguments or arguments[0] != "api":
    raise SystemExit(2)
rest = arguments[1:]
method = "GET"
if "-X" in rest:
    method = rest[rest.index("-X") + 1]
endpoint = next((value for value in rest if value.startswith("repos/")), None)
if endpoint is None:
    raise SystemExit(2)
repository = "test-owner/escrow-store"
if endpoint == "repos/" + repository:
    private = os.environ.get("MOCK_GH_PRIVATE", "true")
    print(repository + "\t" + private)
    raise SystemExit(0)

prefix = "repos/" + repository + "/contents/"
if not endpoint.startswith(prefix):
    raise SystemExit(2)
relative = endpoint.removeprefix(prefix)
if relative.startswith("/") or ".." in relative.split("/"):
    raise SystemExit(2)
target = Path(os.environ["MOCK_REMOTE_ROOT"]) / "github" / relative

if method == "PUT":
    if target.exists():
        raise SystemExit(6)
    if "--input" not in rest:
        raise SystemExit(2)
    payload_path = Path(rest[rest.index("--input") + 1])
    payload = json.loads(payload_path.read_text(encoding="ascii"))
    content = base64.b64decode(payload["content"], validate=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    target.chmod(0o600)
    raise SystemExit(0)

if not target.is_file():
    raise SystemExit(4)
if "--jq" in rest:
    print(hashlib.sha1(target.read_bytes()).hexdigest())
else:
    sys.stdout.buffer.write(target.read_bytes())
'''


class EscrowDistributionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.remote = self.root / "remote"
        self.remote.mkdir(mode=0o700)
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir(mode=0o700)
        (self.fake_bin / "rclone").write_text(RCLONE_MOCK, encoding="utf-8")
        (self.fake_bin / "gh").write_text(GH_MOCK, encoding="utf-8")
        (self.fake_bin / "rclone").chmod(0o700)
        (self.fake_bin / "gh").chmod(0o700)
        # Production pins PATH and must never execute caller-selected tools.
        # Exercise the remote protocol through an explicitly instrumented copy
        # rather than weakening that boundary in the shipped script.
        harness_root = self.root / "harness"
        harness_bin = harness_root / "bin"
        harness_bin.mkdir(parents=True, mode=0o700)
        (harness_bin / "lib").symlink_to(ROOT / "bin/lib", target_is_directory=True)
        harness_text = SCRIPT.read_text(encoding="utf-8").replace(
            "export PATH=/usr/bin:/bin",
            'export PATH="$CSR_ESCROW_TEST_PATH:/usr/bin:/bin"',
            1,
        )
        self.script = harness_bin / SCRIPT.name
        self.script.write_text(harness_text, encoding="utf-8")
        self.script.chmod(0o700)
        self.command_log = self.root / "commands.jsonl"
        self.command_log.touch(mode=0o600)
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "HOME": str(self.home),
                "PATH": str(self.fake_bin) + os.pathsep + self.environment["PATH"],
                "CSR_ESCROW_TEST_PATH": str(self.fake_bin),
                "CSR_RCLONE_DEST": "dropbox-test:backups",
                "CSR_ESCROW_GDRIVE": "gdrive-test:backups",
                "CSR_ESCROW_GH_REPO": "test-owner/escrow-store",
                "CSR_ESCROW_TMPFS_ROOT": "/dev/shm",
                "MOCK_COMMAND_LOG": str(self.command_log),
                "MOCK_REMOTE_ROOT": str(self.remote),
                "MOCK_GH_PRIVATE": "true",
            }
        )

    def run_command(self, *arguments: object, ok: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [str(self.script), *(str(value) for value in arguments)],
            cwd=ROOT,
            env=self.environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        if ok and result.returncode != 0:
            self.fail(
                f"command failed ({result.returncode})\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        if not ok and result.returncode == 0:
            self.fail("command unexpectedly succeeded")
        return result

    def generation_id(self, directory: Path) -> str:
        return json.loads((directory / "escrow-generation.json").read_text())["generation_id"]

    def test_create_publish_readback_fetch_and_retire_are_closed(self) -> None:
        escrow_root = self.home / ".config/coding-system/escrow"
        escrow_root.mkdir(parents=True, mode=0o700)
        os.chmod(self.home / ".config", 0o700)
        os.chmod(self.home / ".config/coding-system", 0o700)
        generation = escrow_root / "generation"
        master = self.root / "master.key"
        published = self.run_command("create-and-publish", generation, master)
        generation_id = self.generation_id(generation)
        prefix = Path("backups/generations") / generation_id

        self.assertEqual(
            sorted(path.name for path in generation.iterdir()),
            ["escrow-generation.json", "share-01.txt"],
        )
        self.assertEqual(stat.S_IMODE((generation / "share-01.txt").stat().st_mode), 0o600)
        current = escrow_root / "current"
        self.assertTrue(current.is_symlink())
        self.assertEqual(os.readlink(current), generation.name)
        manifest = (generation / "escrow-generation.json").read_bytes()
        remote_shares = [
            self.remote / "dropbox" / prefix / "share-02.txt",
            self.remote / "gdrive" / prefix / "share-03.txt",
            self.remote / "github" / "generations" / generation_id / "share-04.txt",
        ]
        remote_manifests = [
            self.remote / "dropbox" / prefix / "escrow-generation.json",
            self.remote / "gdrive" / prefix / "escrow-generation.json",
            self.remote / "github" / "generations" / generation_id / "escrow-generation.json",
        ]
        self.assertTrue(all(path.is_file() for path in remote_shares))
        self.assertTrue(all(path.read_bytes() == manifest for path in remote_manifests))
        secret_payloads = [
            (generation / "share-01.txt").read_text(encoding="ascii").strip(),
            *(share.read_text(encoding="ascii").strip() for share in remote_shares),
            master.read_text(encoding="ascii").strip(),
        ]
        for share in remote_shares:
            self.assertNotIn(share.read_bytes(), manifest)
        for secret_value in secret_payloads:
            self.assertNotIn(secret_value, published.stdout)
            self.assertNotIn(secret_value, published.stderr)
            self.assertNotIn(secret_value, self.command_log.read_text(encoding="utf-8"))

        verified = self.run_command("verify-distributed", generation)
        self.assertIn("all six pairs", verified.stdout)

        inbox = self.root / "inbox" / "escrow" / generation_id
        inbox.mkdir(parents=True, mode=0o700)
        fetched = inbox / "share-03.txt"
        self.run_command(
            "fetch-share", generation / "escrow-generation.json", 3, fetched
        )
        self.assertEqual(fetched.read_bytes(), remote_shares[1].read_bytes())
        self.assertEqual(stat.S_IMODE(fetched.stat().st_mode), 0o600)
        refusal = self.run_command(
            "fetch-share", generation / "escrow-generation.json", 3, fetched, ok=False
        )
        self.assertIn("overwrite", refusal.stderr)

        logged_commands = [json.loads(line) for line in self.command_log.read_text().splitlines()]
        uploads = [entry for entry in logged_commands if entry[:2] == ["rclone", "copyto"]]
        self.assertTrue(any("--immutable" in entry for entry in uploads))

    def test_remote_modes_refuse_without_owner_locations(self) -> None:
        modes = ("publish-generation", "verify-distributed", "create-and-publish", "check", "ensure")
        for mode in modes:
            for name in ("CSR_RCLONE_DEST", "CSR_ESCROW_GDRIVE", "CSR_ESCROW_GH_REPO"):
                with self.subTest(mode=mode, name=name):
                    saved = self.environment.pop(name)
                    try:
                        result = self.run_command(mode, self.root / "absent", ok=False)
                        self.assertEqual(result.returncode, 2)
                        self.assertIn(name, result.stderr)
                        self.assertEqual(self.command_log.read_text(), "")
                    finally:
                        self.environment[name] = saved

    def test_fetch_share_needs_only_the_location_of_that_share(self) -> None:
        escrow_root = self.home / ".config/coding-system/escrow"
        escrow_root.mkdir(parents=True, mode=0o700)
        os.chmod(self.home / ".config", 0o700)
        os.chmod(self.home / ".config/coding-system", 0o700)
        generation = escrow_root / "generation"
        self.run_command("create-and-publish", generation, self.root / "master.key")
        manifest = generation / "escrow-generation.json"
        inbox = self.root / "inbox"
        inbox.mkdir(mode=0o700)
        for name in ("CSR_RCLONE_DEST", "CSR_ESCROW_GDRIVE", "CSR_ESCROW_GH_REPO"):
            self.environment.pop(name)
        self.command_log.write_text("")
        self.run_command("fetch-share", manifest, 1, inbox / "share-01.txt")
        refused = self.run_command("fetch-share", manifest, 3, inbox / "share-03.txt", ok=False)
        self.assertEqual(refused.returncode, 2)
        self.assertIn("CSR_ESCROW_GDRIVE", refused.stderr)
        self.assertEqual(self.command_log.read_text(), "")
        settings = self.home / ".secrets.env"
        settings.write_text("CSR_ESCROW_GDRIVE=gdrive-test:backups\n", encoding="utf-8")
        settings.chmod(0o600)
        self.run_command("fetch-share", manifest, 3, inbox / "share-03.txt")

    def test_unreachable_drive_hint_names_the_configured_remote(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("reconnect gdrive:", source)
        self.assertIn("rclone config reconnect ${GDRIVE_DEST%%:*}:", source)

    def test_existing_remote_object_aborts_before_any_publication(self) -> None:
        generation = self.root / "generation-collision"
        master = self.root / "collision-master.key"
        self.run_command("create-generation", generation, master)
        generation_id = self.generation_id(generation)
        collision = (
            self.remote
            / "dropbox"
            / "backups"
            / "generations"
            / generation_id
            / "share-02.txt"
        )
        collision.parent.mkdir(parents=True)
        collision.write_bytes(b"pre-existing-object\n")
        collision.chmod(0o600)

        result = self.run_command("publish-generation", generation, ok=False)
        self.assertIn("refusing to overwrite", result.stderr)
        self.assertEqual(len(list(generation.glob("share-*.txt"))), 4)
        self.assertFalse((self.remote / "gdrive").exists())
        self.assertFalse((self.remote / "github").exists())

    def test_non_private_or_inexact_github_repository_is_rejected(self) -> None:
        generation = self.root / "generation-public"
        master = self.root / "public-master.key"
        self.run_command("create-generation", generation, master)
        self.environment["MOCK_GH_PRIVATE"] = "false"
        result = self.run_command("publish-generation", generation, ok=False)
        self.assertIn("exact existing repository is private", result.stderr)
        self.assertEqual(len(list(generation.glob("share-*.txt"))), 4)
        self.assertFalse((self.remote / "dropbox").exists())
        self.assertFalse((self.remote / "gdrive").exists())
        self.assertFalse((self.remote / "github").exists())

    def test_readback_tamper_fails_without_retaining_plaintext_temp_files(self) -> None:
        generation = self.root / "generation-tamper"
        master = self.root / "tamper-master.key"
        self.run_command("create-and-publish", generation, master)
        generation_id = self.generation_id(generation)
        share = (
            self.remote
            / "gdrive"
            / "backups"
            / "generations"
            / generation_id
            / "share-03.txt"
        )
        share.write_bytes(b"tampered\n")
        share.chmod(0o600)
        result = self.run_command("verify-distributed", generation, ok=False)
        self.assertNotIn("tampered", result.stdout)
        self.assertNotIn("tampered", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
