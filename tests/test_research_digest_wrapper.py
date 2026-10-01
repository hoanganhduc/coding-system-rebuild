#!/usr/bin/env python3
"""Regression tests for the host research-digest shortcut."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "system/bin/research-digest"


class ResearchDigestWrapperTests(unittest.TestCase):
    def test_shortcut_delegates_to_secret_aware_managed_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            wrapper = home / "research-digest"
            wrapper.write_text(
                TEMPLATE.read_text(encoding="utf-8").replace("{{ HOME }}", str(home)),
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            target = (
                home
                / ".openclaw/workspace/skills/research-digest-wrapper/run_research_digest.sh"
            )
            target.parent.mkdir(parents=True)
            target.write_text(
                "#!/usr/bin/env bash\n"
                "python3 - \"$@\" <<'PY'\n"
                "import json,sys\n"
                "print(json.dumps(sys.argv[1:]))\n"
                "PY\n",
                encoding="utf-8",
            )
            target.chmod(0o755)
            completed = subprocess.run(
                [str(wrapper), "run", "--tag", "graph-theory"],
                env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                json.loads(completed.stdout), ["run", "--tag", "graph-theory"]
            )

    def test_shortcut_never_bypasses_the_managed_shell_wrapper(self) -> None:
        source = TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("run_research_digest.sh", source)
        self.assertNotIn('"$SCRIPT_DIR/research_digest.py"', source)


if __name__ == "__main__":
    unittest.main()
