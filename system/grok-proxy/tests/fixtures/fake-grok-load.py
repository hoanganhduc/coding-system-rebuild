#!/usr/bin/python3
"""Compatibility entrypoint for the shipped qualification fake Grok."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from grok_ms.qualification_fake_grok import (
    _publish_exclusive_json,
    _socks_echo,
    _wait_for_release,
    main,
)


if __name__ == "__main__":
    raise SystemExit(main())
