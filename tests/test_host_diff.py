#!/usr/bin/env python3
"""A restored host is compared with the old host's baseline, layer by layer."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_host_diff", ROOT / "bin/verify-host-diff.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

HOME = Path("/home/owner")


def fake_runner(outputs: dict[str, str]):
    def run(command: list[str]) -> str:
        return outputs.get(" ".join(command), "")
    return run


OLD_HOST = {
    "apt-mark showmanual": "caddy\nlinux-oracle\ntor\n",
    "crontab -l": "# comment\n*/2 * * * * /home/owner/bin/reap\nCRON_TZ=Asia/Ho_Chi_Minh\n",
    "systemctl list-unit-files --state=enabled --type=service,timer --no-legend --plain":
        "caddy.service enabled enabled\ntor.service enabled enabled\n",
    "npm ls -g --depth=0 --json": json.dumps({"dependencies": {"pnpm": {"version": "10.0.0"}}}),
    "pipx list --short": "aider-chat 0.86.2\n",
    "docker image ls --format {{.Repository}}:{{.Tag}}": "ghcr.io/example/sandbox:1\n<none>:<none>\n",
}


class HostDiffTests(unittest.TestCase):
    def test_capture_normalizes_each_layer_without_the_home_path(self) -> None:
        layers = MODULE.collect(HOME, fake_runner(OLD_HOST), user_units={})
        self.assertEqual(layers["apt-manual"], ["caddy", "linux-oracle", "tor"])
        self.assertEqual(
            layers["crontab"],
            ["*/2 * * * * {{ HOME }}/bin/reap", "CRON_TZ=Asia/Ho_Chi_Minh"],
        )
        self.assertEqual(layers["systemd-system-enabled"], ["caddy.service", "tor.service"])
        self.assertEqual(layers["npm-globals"], ["pnpm"])
        self.assertEqual(layers["pipx"], ["aider-chat"])
        self.assertEqual(layers["docker-images"], ["ghcr.io/example/sandbox:1"])

    def test_diff_reports_only_unexpected_differences(self) -> None:
        baseline = MODULE.collect(HOME, fake_runner(OLD_HOST), user_units={"a.service": "enabled/active"})
        new_host = dict(OLD_HOST)
        new_host["apt-mark showmanual"] = "caddy\ntor\nlinux-hetzner\n"
        new_host["systemctl list-unit-files --state=enabled --type=service,timer --no-legend --plain"] = (
            "caddy.service enabled enabled\n"
        )
        current = MODULE.collect(HOME, fake_runner(new_host), user_units={"a.service": "enabled/inactive"})
        exceptions = {"apt-manual": {"linux-*": "provider kernel differs between clouds"}}
        report = MODULE.compare(baseline, current, exceptions)
        self.assertEqual(report["apt-manual"]["expected"], ["+linux-hetzner", "-linux-oracle"])
        self.assertEqual(report["apt-manual"]["unexpected"], [])
        self.assertEqual(report["systemd-system-enabled"]["unexpected"], ["-tor.service"])
        self.assertEqual(report["systemd-user-units"]["unexpected"], ["~a.service: enabled/active -> enabled/inactive"])
        self.assertFalse(MODULE.clean(report))
        self.assertTrue(MODULE.clean(MODULE.compare(baseline, baseline, {})))

    def test_capture_and_diff_round_trip_through_private_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            baseline_path = Path(temporary) / "baseline.json"
            layers = MODULE.collect(HOME, fake_runner(OLD_HOST), user_units={})
            MODULE.write_private_json(baseline_path, layers)
            self.assertEqual(baseline_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(baseline_path.read_text(encoding="utf-8")), layers)

    def test_provider_packages_are_expected_and_the_flow_is_wired(self) -> None:
        exceptions = MODULE.merged_exceptions({"pipx": {"kaggle": "owner moved kaggle to the closure"}})
        report = MODULE.compare(
            {"apt-manual": ["linux-oracle", "grub-efi-arm64-signed", "tor"], "pipx": ["kaggle"]},
            {"apt-manual": ["linux-generic", "tor"], "pipx": []},
            exceptions,
        )
        self.assertTrue(MODULE.clean(report), report)
        refresh = (ROOT / "bin/refresh-state.sh").read_text(encoding="utf-8")
        self.assertIn('bin/verify-host-diff.py" capture', refresh)
        verify = (ROOT / "bin/verify.sh").read_text(encoding="utf-8")
        self.assertIn("bin/verify-host-diff.py", verify)
        secrets = (ROOT / "secrets/secrets-manifest.yaml").read_text(encoding="utf-8")
        self.assertIn(".config/coding-system/host-baseline.json", secrets)
        self.assertIn(".config/coding-system/host-diff-exceptions.json", secrets)


if __name__ == "__main__":
    unittest.main()
