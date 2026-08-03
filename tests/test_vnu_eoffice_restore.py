"""Regression tests for rebuilding the OpenClaw VNU eOffice integration."""

from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
BRIDGE_PATH = REPO / "bin" / "lib" / "bridge_vnu_eoffice_secrets.py"


def load_bridge():
    spec = importlib.util.spec_from_file_location("bridge_vnu_eoffice_secrets", BRIDGE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestVnuEofficeRestore(unittest.TestCase):
    def test_bridge_creates_private_workspace_view(self):
        bridge = load_bridge()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            source = home / ".claude" / "secrets.json"
            source.parent.mkdir(parents=True)
            source.write_text(json.dumps({
                "VNU_EOFFICE_USERNAME": "user",
                "VNU_EOFFICE_PASSWORD": "password",
                "UNRELATED": "not copied",
            }), encoding="utf-8")
            target = home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({"STALE": "remove me"}), encoding="utf-8")

            result = bridge.bridge(home)
            self.assertIn("ready", result)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {
                "VNU_EOFFICE_USERNAME": "user",
                "VNU_EOFFICE_PASSWORD": "password",
            })
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)

    def test_bridge_skips_when_vnu_credentials_are_absent(self):
        bridge = load_bridge()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            source = home / ".claude" / "secrets.json"
            source.parent.mkdir(parents=True)
            source.write_text("{}\n", encoding="utf-8")
            self.assertIn("skipped", bridge.bridge(home))
            self.assertFalse((home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json").exists())

    def test_rebuild_contract_uses_workspace_checkout_and_manifest(self):
        lock = (REPO / "components.lock").read_text(encoding="utf-8")
        self.assertRegex(lock, r"(?m)^vnu-eoffice=https://github.com/hoanganhduc/vnu-eoffice\.git@[0-9a-f]{40}$")
        components = (REPO / "bin/components.sh").read_text(encoding="utf-8")
        self.assertIn('$HOME/.openclaw/workspace/vnueoffice_repo', components)
        self.assertIn('VNU_LEGACY="$HOME/vnueoffice"', components)
        manifest = yaml.safe_load((REPO / "secrets/secrets-manifest.yaml").read_text(encoding="utf-8"))
        paths = {entry["path"] for entry in manifest["entries"]}
        self.assertIn(".openclaw/workspace/secrets/vnu-eoffice/secrets.json", paths)


if __name__ == "__main__":
    unittest.main()
