#!/usr/bin/env python3
"""Entrypoint for the Claude Modal research-compute skill."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    skill_dir = Path(__file__).resolve().parent
    if str(skill_dir) not in sys.path:
        sys.path.insert(0, str(skill_dir))

    from research_compute.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
