#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "bin/verify-lean-explore-mcp.py"


class LeanExploreHandshakeTests(unittest.TestCase):
    def make_server(self, root: Path, *, omit_tool: bool = False) -> Path:
        path = root / "server.py"
        tools = ["search", "search_summary"] if omit_tool else ["search", "search_summary", "get_source_code"]
        path.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env python3
                import json, sys
                for line in sys.stdin:
                    value = json.loads(line)
                    if value.get("method") == "initialize":
                        result = {{"protocolVersion": "2025-06-18", "capabilities": {{}},
                                  "serverInfo": {{"name": "fixture", "version": "1"}}}}
                        print(json.dumps({{"jsonrpc": "2.0", "id": value["id"], "result": result}}), flush=True)
                    elif value.get("method") == "tools/list":
                        tools = [{{"name": item, "inputSchema": {{"type": "object"}}}} for item in {tools!r}]
                        print(json.dumps({{"jsonrpc": "2.0", "id": value["id"], "result": {{"tools": tools}}}}), flush=True)
                """
            ),
            encoding="utf-8",
        )
        path.chmod(0o700)
        return path

    def test_initialize_and_tool_inventory_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server = self.make_server(Path(temporary))
            result = subprocess.run(
                ["python3", str(VERIFIER), "--command", str(server), "--timeout", "5"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "PASS")
            self.assertIn("search_summary", report["tools"])

    def test_incomplete_tool_inventory_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server = self.make_server(Path(temporary), omit_tool=True)
            result = subprocess.run(
                ["python3", str(VERIFIER), "--command", str(server), "--timeout", "5"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("incomplete", result.stderr)


if __name__ == "__main__":
    unittest.main()
