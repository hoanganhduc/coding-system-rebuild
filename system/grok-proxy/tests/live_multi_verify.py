#!/usr/bin/env python3
"""Compatibility import/CLI for the shipped immutable verifier."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from grok_ms import qualification_verifier as _implementation

for _name in dir(_implementation):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_implementation, _name)


if __name__ == "__main__":
    raise SystemExit(_implementation.main())
