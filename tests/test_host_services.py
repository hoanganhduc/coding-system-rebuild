#!/usr/bin/env python3
"""System services restore from public unit templates and the owner's private copies."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DECLARATION = ROOT / "system/host/services.v1.json"
EXPORT = ROOT / "bin/export-system-private.py"
APPLY = ROOT / "bin/apply-host-services.py"


def fake_systemctl(directory: Path, known: set[str]) -> tuple[Path, Path]:
    log = directory / "systemctl.log"
    script = directory / "systemctl"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"known = {sorted(known)!r}\n"
        f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        "if sys.argv[1] == 'cat' and sys.argv[-1] not in known:\n"
        "    sys.exit(1)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script, log


class HostServiceTests(unittest.TestCase):
    def test_declaration_names_templates_and_private_files_completely(self) -> None:
        declaration = json.loads(DECLARATION.read_text(encoding="utf-8"))
        self.assertEqual(declaration["schema"], "coding-system.host-services/v1")
        for unit, template in declaration["units"].items():
            with self.subTest(unit=unit):
                self.assertIn(unit, declaration["enable"])
                text = (ROOT / template).read_text(encoding="utf-8")
                self.assertNotRegex(text, r"/home/[a-z]")
        for item in declaration["private_files"]:
            self.assertTrue(item["path"].startswith("/etc/"))
            self.assertRegex(item["mode"], r"^0[0-7]{3}$")

    def test_export_copies_readable_files_and_reports_the_rest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, home = Path(temporary) / "root", Path(temporary) / "home"
            (root / "etc/caddy").mkdir(parents=True)
            (root / "etc/caddy/Caddyfile").write_text("example.invalid {\n}\n", encoding="utf-8")
            completed = subprocess.run(
                ["python3", str(EXPORT), "--root", str(root), "--home", str(home), "--sudo", "/bin/false"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            copy = home / ".config/coding-system/system-private/etc/caddy/Caddyfile"
            self.assertEqual(copy.read_text(encoding="utf-8"), "example.invalid {\n}\n")
            self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o600)
            self.assertIn("/etc/monit/monitrc", completed.stderr)
            strict = subprocess.run(
                ["python3", str(EXPORT), "--root", str(root), "--home", str(home),
                 "--sudo", "/bin/false", "--strict"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(strict.returncode, 1)

    def test_apply_renders_units_restores_private_files_and_enables_known_services(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, home = base / "root", base / "home"
            private = home / ".config/coding-system/system-private/etc/caddy/Caddyfile"
            private.parent.mkdir(parents=True)
            private.write_text("example.invalid {\n}\n", encoding="utf-8")
            systemctl, log = fake_systemctl(base, {"caddy.service", "tmux-forms.service", "ollama.service"})
            completed = subprocess.run(
                ["python3", str(APPLY), "--repository", str(ROOT), "--root", str(root),
                 "--home", str(home), "--user", "owner", "--group", "owner",
                 "--systemctl", str(systemctl), "--no-chown"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            unit = (root / "etc/systemd/system/tmux-forms.service").read_text(encoding="utf-8")
            self.assertIn(f"WorkingDirectory={home}/forms", unit)
            self.assertIn("User=owner", unit)
            self.assertNotIn("{{", unit)
            restored = root / "etc/caddy/Caddyfile"
            self.assertEqual(restored.read_text(encoding="utf-8"), "example.invalid {\n}\n")
            self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o644)
            calls = log.read_text(encoding="utf-8").splitlines()
            self.assertIn("daemon-reload", calls)
            self.assertIn("enable --now caddy.service", calls)
            self.assertIn("enable --now tmux-forms.service", calls)
            self.assertNotIn("enable --now earlyoom.service", calls)
            self.assertIn("earlyoom.service", completed.stderr)
            # monitrc has no private copy yet: reported, never invented
            self.assertFalse((root / "etc/monit/monitrc").exists())
            self.assertIn("/etc/monit/monitrc", completed.stderr)

    def test_restore_applies_and_backup_exports_the_host_services(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        phase_eleven = install[install.index("# 11 ─ generated state"):install.index("# 12 ─ verification")]
        self.assertIn('bin/apply-host-services.py" --repository "$REPO" --home "$HOME"', phase_eleven)
        self.assertIn("[[ $DEGRADED_MODE -eq 1 ]] \\\n    || sudo /usr/bin/python3 -I -B", phase_eleven)
        refresh = (ROOT / "bin/refresh-state.sh").read_text(encoding="utf-8")
        self.assertIn('bin/export-system-private.py"', refresh)
        secrets = (ROOT / "secrets/secrets-manifest.yaml").read_text(encoding="utf-8")
        self.assertIn(".config/coding-system/system-private/", secrets)


if __name__ == "__main__":
    unittest.main()
