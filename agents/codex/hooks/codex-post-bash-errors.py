#!/usr/bin/env python3
import json
import os
import subprocess
import sys


def flatten(value):
    if value is None:
        return ""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and stripped[0] in "{[":
            try:
                return flatten(json.loads(value))
            except Exception:
                return value
        return value
    if isinstance(value, dict):
        parts = []
        for key in ("stderr", "stdout", "output", "message", "text", "result"):
            if key in value and value[key]:
                parts.append(flatten(value[key]))
        if not parts:
            parts.append(json.dumps(value, ensure_ascii=False))
        return "\n".join(part for part in parts if part)
    if isinstance(value, list):
        return "\n".join(part for part in (flatten(item) for item in value) if part)
    return str(value)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    tool_output = flatten(payload.get("tool_response"))
    if not tool_output.strip():
        return 0

    helper = os.path.expanduser("~/.codex/skills/self_improving_agent/scripts/detect_common_errors.sh")
    if not os.path.exists(helper):
        return 0

    result = subprocess.run(
        ["bash", helper],
        input=tool_output,
        text=True,
        capture_output=True,
        check=False,
    )

    combined = "\n".join(part for part in [result.stdout, result.stderr] if part)
    if "Potential failure markers detected." not in combined:
        return 0

    message = (
        "Potential failure markers were detected in the last Bash output. "
        "Before moving on, check whether this was an environment, path, dependency, or capability issue, "
        "and consider logging any durable lesson with self_improving_agent."
    )
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": message,
                }
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
