#!/usr/bin/env python3
"""Fail-closed compatibility entrypoint for retired OpenClaw JSON rotation.

OpenClaw 2026.7.1-2 uses per-agent ``openclaw-agent.sqlite`` authentication
stores.  Editing ``auth-profiles.json`` or ``models.json`` can no longer rotate
the effective credential and may falsely report success.  Keep this historical
entrypoint only to reject old automation explicitly until a reviewed
OpenClaw-native rotation transaction is available.
"""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "ERROR: legacy OpenClaw provider-key rotation is disabled for the "
        "DB-first runtime; use an OpenClaw-native auth flow",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
