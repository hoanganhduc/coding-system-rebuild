#!/usr/bin/env python3
"""Offline Tailscale authority, file-selector, and readiness regressions."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
APPLY = ROOT / "bin/apply-tailscale-authority.sh"
AUTHKEY = "tskey-auth-abcdefghijklmnopqrstuvwx"


def private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    current = path.parent
    while True:
        current.chmod(0o700)
        if current.name == "home":
            break
        current = current.parent
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


class TailscaleAuthorityTests(unittest.TestCase):
    def _fake_commands(
        self, root: Path, *, state: str, up_status: int
    ) -> tuple[Path, Path, Path]:
        log = root / "tailscale-argv.log"
        tailscale = root / "tailscale"
        tailscale.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            "if [[ ${1:-} == up && ${2:-} == --help ]]; then echo 'auth file: selector'; exit 0; fi\n"
            f"if [[ ${{1:-}} == status ]]; then printf '%s\\n' '{{\"BackendState\":\"{state}\"}}'; exit 0; fi\n"
            f"printf '%s\\n' \"$*\" >> {log!s}\n"
            f"exit {up_status}\n",
            encoding="utf-8",
        )
        tailscale.chmod(0o755)
        sudo = root / "sudo"
        sudo.write_text("#!/usr/bin/env bash\nexec \"$@\"\n", encoding="utf-8")
        sudo.chmod(0o755)
        return tailscale, sudo, log

    def _run(self, home: Path, tailscale: Path, sudo: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", os.fspath(APPLY), "--home", os.fspath(home)],
            env={
                "HOME": os.fspath(home),
                "PATH": os.environ["PATH"],
                "CSR_TAILSCALE_BIN": os.fspath(tailscale),
                "CSR_SUDO_BIN": os.fspath(sudo),
            },
            text=True,
            capture_output=True,
            check=False,
        )

    def test_apply_uses_file_selector_and_reports_authenticated_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            private(home / ".config/coding-system/tailscale-authkey", AUTHKEY + "\n")
            private(home / ".config/coding-system/tailscale-hostname", "openclaw\n")
            tailscale, sudo, log = self._fake_commands(root, state="Running", up_status=0)
            result = self._run(home, tailscale, sudo)
            self.assertEqual(result.returncode, 0, result.stderr)
            argv = log.read_text(encoding="utf-8")
            self.assertIn(
                f"--auth-key=file:{home}/.config/coding-system/tailscale-authkey",
                argv,
            )
            self.assertIn("--hostname openclaw", argv)
            report = json.loads(
                (
                    home / ".local/state/coding-system/restore/tailscale-readiness.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(report["status"], "PASS")
            self.assertTrue(report["daemonAuthenticated"])
            self.assertNotIn(AUTHKEY, result.stdout + result.stderr + json.dumps(report) + argv)

    def test_rejected_key_is_redacted_auth_invalid_reauth_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            private(home / ".config/coding-system/tailscale-authkey", AUTHKEY + "\n")
            private(home / ".config/coding-system/tailscale-hostname", "openclaw\n")
            tailscale, sudo, _log = self._fake_commands(
                root, state="NeedsLogin", up_status=7
            )
            result = self._run(home, tailscale, sudo)
            self.assertEqual(result.returncode, 1)
            report = json.loads(
                (
                    home / ".local/state/coding-system/restore/tailscale-readiness.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(report["status"], "REAUTH_REQUIRED")
            self.assertEqual(report["reason"], "AUTH_INVALID")
            self.assertNotIn(AUTHKEY, result.stdout + result.stderr + json.dumps(report))

    def test_absent_authority_is_not_configured(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            tailscale, sudo, _log = self._fake_commands(
                root, state="NeedsLogin", up_status=0
            )
            result = self._run(home, tailscale, sudo)
            self.assertEqual(result.returncode, 1)
            report = json.loads(
                (
                    home / ".local/state/coding-system/restore/tailscale-readiness.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(report["status"], "NOT_CONFIGURED")

    def test_install_and_setup_never_source_legacy_env_or_put_key_value_in_argv(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        apply = APPLY.read_text(encoding="utf-8")
        setup = (ROOT / "bin/setup-tailscale-key.sh").read_text(encoding="utf-8")
        self.assertNotIn('. "$HOME/.config/coding-system/tailscale.env"', install)
        self.assertNotIn("TS_AUTHKEY", install)
        self.assertNotIn("tailscale.env", setup)
        self.assertIn('--auth-key="file:$AUTHKEY_PATH"', apply)
        self.assertNotIn("$(cat", apply)

    def test_source_tree_apply_requires_an_explicit_home(self) -> None:
        result = subprocess.run(
            ["bash", os.fspath(APPLY)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--home ABSOLUTE_HOME", result.stderr)


if __name__ == "__main__":
    unittest.main()
