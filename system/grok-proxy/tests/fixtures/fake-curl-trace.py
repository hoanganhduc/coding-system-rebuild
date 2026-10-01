#!/usr/bin/python3
"""Deterministic Cloudflare-trace-shaped response for feature-on tests."""

from __future__ import annotations

import os
import sys


def main() -> int:
    if "--socks5-hostname" not in sys.argv[1:]:
        print("fake-curl-trace: missing SOCKS endpoint", file=sys.stderr)
        return 2
    if os.environ.get("GROK_TESTING") != "1":
        print("fake-curl-trace: test seam is not active", file=sys.stderr)
        return 2
    sys.stdout.write("ip=203.0.113.17\nloc=JP\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
