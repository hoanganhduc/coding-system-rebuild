#!/usr/bin/env python3
"""Regression checks for the owner-private OpenCode launcher boundary."""

from __future__ import annotations

import os
from pathlib import Path
import platform
import stat
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "system/bin/opencode"
ARCH = "arm64" if platform.machine().lower() in {"aarch64", "arm64"} else "amd64"
OTHER_ARCH = "amd64" if ARCH == "arm64" else "arm64"
PLATFORM_PACKAGE = {"amd64": "opencode-linux-x64-baseline", "arm64": "opencode-linux-arm64"}


def closure_binary(home: Path, arch: str = ARCH) -> Path:
    """Where the npm closure keeps the locked platform OpenCode binary."""
    return home / (
        f".local/share/coding-system/npm-closures/sha256-{arch}-"
        + "a" * 64 + "-" + "b" * 64
        + f"/node_modules/{PLATFORM_PACKAGE[arch]}/bin/opencode"
    )


class OpenCodeWrapperTests(unittest.TestCase):
    @staticmethod
    def render(home: Path) -> Path:
        wrapper = home / ".local/bin/opencode"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text(
            TEMPLATE.read_text(encoding="utf-8").replace("{{ HOME }}", os.fspath(home)),
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        return wrapper

    @staticmethod
    def link_target(home: Path, target: Path) -> None:
        link = home / ".npm-global/bin/opencode"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)

    @classmethod
    def write_target(cls, home: Path) -> Path:
        target = closure_binary(home)
        target.parent.mkdir(parents=True)
        cls.link_target(home, target)
        target.write_text(
            """#!/usr/bin/bash -p
set -eu
: > "$HOME/opencode-created-state"
printf '%s\n' "$#" "$1" "$PATH"
""",
            encoding="utf-8",
        )
        target.chmod(0o755)
        return target

    def test_launcher_ignores_startup_hooks_uses_exact_target_and_umask_077(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            wrapper = self.render(home)
            self.write_target(home)
            hostile = home / "hostile-bin"
            hostile.mkdir()
            wrong_target = hostile / "opencode"
            wrong_target.write_text(
                "#!/usr/bin/bash\nprintf 'ambient-target-ran\\n'\n",
                encoding="utf-8",
            )
            wrong_target.chmod(0o755)
            startup_marker = home / "startup-hook-ran"
            startup = home / "hostile-bash-env"
            startup.write_text(
                f"#!/usr/bin/bash\n: > {startup_marker}\n",
                encoding="utf-8",
            )
            startup.chmod(0o755)
            environment = {
                "HOME": os.fspath(home / "wrong-home"),
                "PATH": os.fspath(hostile),
                "BASH_ENV": os.fspath(startup),
                "ENV": os.fspath(startup),
                "LANG": "C",
                "LC_ALL": "C",
            }

            result = subprocess.run(
                [os.fspath(wrapper), "argument with spaces"],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            lines = result.stdout.splitlines()
            self.assertEqual(lines[0:2], ["1", "argument with spaces"])
            self.assertEqual(
                lines[2],
                os.pathsep.join(
                    (
                        os.fspath(home / ".npm-global/bin"),
                        os.fspath(home / ".local/bin"),
                        "/usr/local/sbin",
                        "/usr/local/bin",
                        "/usr/sbin",
                        "/usr/bin",
                        "/sbin",
                        "/bin",
                    )
                ),
            )
            created = home / "opencode-created-state"
            self.assertTrue(created.is_file())
            self.assertEqual(stat.S_IMODE(created.stat().st_mode), 0o600)
            self.assertFalse(startup_marker.exists())
            self.assertNotIn("ambient-target-ran", result.stdout + result.stderr)

    def test_launcher_rejects_targets_outside_the_locked_closure(self) -> None:
        # Missing link; a link to an arbitrary file; the opencode-ai placeholder
        # that its postinstall would replace; another architecture's closure.
        for case in ("missing", "outside", "placeholder", "other-arch"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                wrapper = self.render(home)
                victim = home / "victim"
                victim.write_text("must-not-run\n", encoding="utf-8")
                victim.chmod(0o755)
                if case == "outside":
                    self.link_target(home, victim)
                elif case in ("placeholder", "other-arch"):
                    target = (
                        home / ".npm-global/lib/node_modules/opencode-ai/bin/opencode.exe"
                        if case == "placeholder"
                        else closure_binary(home, OTHER_ARCH)
                    )
                    target.parent.mkdir(parents=True)
                    target.write_text(
                        f"#!/bin/sh\necho ran > {victim}\n", encoding="utf-8"
                    )
                    target.chmod(0o755)
                    self.link_target(home, target)

                result = subprocess.run(
                    [os.fspath(wrapper), "--version"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

                self.assertEqual(result.returncode, 127)
                self.assertEqual(victim.read_text(encoding="utf-8"), "must-not-run\n")
                self.assertIn("unavailable or unsafe", result.stderr)

    def test_manifest_and_install_publish_the_managed_wrapper(self) -> None:
        manifest = yaml.safe_load((ROOT / "MANIFEST.yaml").read_text(encoding="utf-8"))
        entry = next(item for item in manifest["entries"] if item["id"] == "localbin-wrappers")
        self.assertIn("opencode", entry["match"])
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        self.assertIn('for f in "$REPO"/system/bin/*', install)
        self.assertNotIn('"$wrapper_name" != opencode', install)


if __name__ == "__main__":
    unittest.main()
