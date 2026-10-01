#!/usr/bin/env python3
"""Tests for the private pre-push gate (system/git-hooks/pre-push).

Each test builds a throwaway bare remote and clone, points core.hooksPath at a
copy of the hook, and pushes.  The hook must block commits whose metadata or
newly added lines carry private material, must never print the matched value,
and must leave already-published content and branch deletions alone.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "system" / "git-hooks" / "pre-push"
NOREPLY = "12345+owner@users.noreply.github.com"
CANARY = "canary-private-7Q2xVb"          # stands in for a private denylist entry
TAILNET_NAME = "laptop.tail0a1b2" + ".ts.net"   # synthetic tailnet host name, split so scanners skip it
GMAIL = "someone.private@" + "gmail.com"


class PrePushHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="prepush-test-"))
        self.remote = self.tmp / "remote.git"
        self.work = self.tmp / "work"
        self.hooks = self.tmp / "hooks"
        self.hooks.mkdir()
        shutil.copy2(HOOK, self.hooks / "pre-push")
        (self.hooks / "pre-push").chmod(0o700)
        self.denylist = self.tmp / "denylist.txt"
        self.denylist.write_text("# private test denylist\n" + CANARY + "\n")
        self.pubkey = self.tmp / "signing.pub"
        self.pubkey.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialForTestsOnly0000 test key\n")
        self.git(self.tmp, "init", "-q", "--bare", "-b", "main", str(self.remote))
        self.git(self.tmp, "clone", "-q", str(self.remote), str(self.work))
        self.git(self.work, "config", "user.name", "Owner")
        self.git(self.work, "config", "user.email", NOREPLY)
        self.git(self.work, "config", "core.hooksPath", str(self.hooks))
        self.git(self.work, "checkout", "-q", "-b", "main")
        self.commit({"README.md": "hello\n"}, "initial")
        self.push(verify=False)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def env(self, **extra: str) -> dict[str, str]:
        env = dict(os.environ)
        env.update({"PREPUSH_DENYLIST": str(self.denylist), "PREPUSH_SIGNING_PUBKEY": str(self.pubkey),
                    "GIT_AUTHOR_NAME": "Owner", "GIT_COMMITTER_NAME": "Owner"})
        env.pop("CSR_ALLOW_SIGNING_KEY_CHANGE", None)
        env.update(extra)
        return env

    def git(self, cwd: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(["git", *args], cwd=cwd, env=env or self.env(), text=True,
                              capture_output=True, check=True)

    def commit(self, files: dict[str, str], message: str, **env: str) -> None:
        for name, text in files.items():
            path = self.work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.git(self.work, "add", "-A")
        self.git(self.work, "commit", "-q", "-m", message, env=self.env(**env))

    def push(self, *refspec: str, verify: bool = True, **env: str) -> subprocess.CompletedProcess:
        args = ["push", "-q", "origin", *(refspec or ("main",))]
        if not verify:
            args.insert(1, "--no-verify")
        return subprocess.run(["git", *args], cwd=self.work, env=self.env(**env), text=True, capture_output=True)

    def assertBlocked(self, result: subprocess.CompletedProcess, reason: str) -> None:
        self.assertNotEqual(result.returncode, 0, "push should have been blocked")
        self.assertIn(reason, result.stderr)
        for secret in (CANARY, TAILNET_NAME, GMAIL):
            self.assertNotIn(secret, result.stderr + result.stdout)

    def test_clean_commit_passes(self) -> None:
        self.commit({"docs.md": "plain text\n"}, "add docs")
        result = self.push()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_personal_author_email_is_blocked(self) -> None:
        self.commit({"a.txt": "x\n"}, "change", GIT_AUTHOR_EMAIL=GMAIL)
        self.assertBlocked(self.push(), "author email")

    def test_host_derived_committer_email_is_blocked(self) -> None:
        self.commit({"a.txt": "x\n"}, "change", GIT_COMMITTER_EMAIL="ubuntu@" + TAILNET_NAME)
        self.assertBlocked(self.push(), "committer email")

    def test_claude_session_trailer_is_blocked(self) -> None:
        self.commit({"a.txt": "x\n"}, "change\n\nClaude-Session: https://claude.ai/code/session_X")
        self.assertBlocked(self.push(), "Claude-Session")

    def test_denylist_entry_in_added_line_is_blocked(self) -> None:
        self.commit({"notes.md": "host is " + CANARY + " today\n"}, "notes")
        self.assertBlocked(self.push(), "private denylist entry")

    def test_denylist_entry_in_message_is_blocked(self) -> None:
        self.commit({"a.txt": "x\n"}, "deploy to " + CANARY)
        self.assertBlocked(self.push(), "private denylist entry")

    def test_tailnet_name_is_blocked(self) -> None:
        self.commit({"cfg.txt": "url=https://" + TAILNET_NAME + "/\n"}, "cfg")
        self.assertBlocked(self.push(), "tailnet host name")

    def test_private_key_block_is_blocked(self) -> None:
        self.commit({"k.txt": "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nabc\n"}, "key")
        self.assertBlocked(self.push(), "private key block")

    def test_github_token_is_blocked(self) -> None:
        self.commit({"t.txt": "token=ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4\n"}, "tok")
        self.assertBlocked(self.push(), "github token")

    def test_personal_email_in_content_is_blocked(self) -> None:
        self.commit({"authors.md": "contact " + GMAIL + "\n"}, "authors")
        self.assertBlocked(self.push(), "personal email address")

    def test_exempt_line_passes(self) -> None:
        self.commit({"scanner.sh": "pattern " + CANARY + "  # LEAKSCAN-EXEMPT\n"}, "scanner")
        result = self.push()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_already_published_finding_does_not_block_new_clean_commit(self) -> None:
        self.commit({"old.md": CANARY + "\n"}, "old finding")
        self.push(verify=False)
        self.commit({"new.md": "clean\n"}, "clean follow-up")
        result = self.push()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_history_reachable_only_from_non_branch_refs_is_rechecked(self) -> None:
        self.commit({"old.md": CANARY + "\n"}, "old finding")
        self.git(self.work, "push", "-q", "--no-verify", "origin", "HEAD:refs/pull/1/head")
        self.git(self.work, "update-ref", "-d", "refs/remotes/origin/pull/1/head")
        self.assertBlocked(self.push(), "private denylist entry")

    def test_missing_denylist_blocks(self) -> None:
        self.commit({"a.txt": "x\n"}, "change")
        self.denylist.unlink()
        self.assertBlocked(self.push(), "denylist")

    def test_branch_deletion_passes(self) -> None:
        self.git(self.work, "branch", "topic")
        self.push("topic", verify=False)
        result = self.push(":topic")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_signing_key_pin_must_match_owner_key(self) -> None:
        pub = self.pubkey.read_text()
        import hashlib
        good = hashlib.sha256(pub.encode()).hexdigest()
        self.commit({"system/recovery/recovery-signing-public-key.pub": pub,
                     "restore-ubuntu.sh": f'SIGNING_KEY_SHA256="{good}"\n'}, "pin")
        self.assertEqual(self.push().returncode, 0)
        self.commit({"restore-ubuntu.sh": 'SIGNING_KEY_SHA256="' + "0" * 64 + '"\n'}, "repin")
        self.assertBlocked(self.push(), "SIGNING_KEY_SHA256")
        result = self.push(CSR_ALLOW_SIGNING_KEY_CHANGE="1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_signing_key_file_must_hold_owner_key(self) -> None:
        other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDifferentKeyMaterial000000000000 other\n"
        import hashlib
        pin = hashlib.sha256(other.encode()).hexdigest()
        self.commit({"system/recovery/recovery-signing-public-key.pub": other,
                     "restore-ubuntu.sh": f'SIGNING_KEY_SHA256="{pin}"\n'}, "wrong key")
        self.assertBlocked(self.push(), "signing public key")

    def test_repository_leak_scan_runs_on_pushed_tree(self) -> None:
        self.commit({"bin/leak-scan.sh": "#!/usr/bin/env bash\n[ -f \"${1:-.}/BAD\" ] && exit 2\nexit 0\n"},
                    "scanner")
        self.assertEqual(self.push().returncode, 0)
        self.commit({"BAD": "marker\n"}, "trip scanner")
        self.assertBlocked(self.push(), "bin/leak-scan.sh")


if __name__ == "__main__":
    unittest.main()
