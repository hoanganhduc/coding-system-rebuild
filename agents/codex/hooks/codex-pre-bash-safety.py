#!/usr/bin/env python3
import json
import os
import subprocess
import sys


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    command = payload.get("tool_input", {}).get("command", "").strip()
    if not command:
        return 0

    helper = os.path.expanduser("~/.codex/skills/self_improving_agent/scripts/check_command_safety.sh")
    if not os.path.exists(helper):
        return 0

    result = subprocess.run(
        ["bash", helper],
        input=command,
        text=True,
        capture_output=True,
        check=False,
    )

    if result.returncode != 2:
        return 0

    stderr = (result.stderr or "").strip().splitlines()
    stdout = (result.stdout or "").strip().splitlines()
    reason = (stderr[-1] if stderr else stdout[-1] if stdout else "Command blocked by local safety policy.").strip()

    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
