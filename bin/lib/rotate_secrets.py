#!/usr/bin/env python3
"""Fail-closed compatibility entrypoint for retired in-place secret rotation.

The old implementation discovered names in migration-era flat files and wrote
those files directly.  Those paths are not proof of the canonical/effective
credential selected by the restored runtime.  OpenClaw provider authentication
is also owned by the native SQLite store.  Until each authority has a reviewed,
atomic, deployed-value verifier, this command must not mutate anything.

Subcommands:
  list       explain why no identifiers are exposed for in-place rotation
  kind ID    report ``unsupported`` and exit nonzero
  apply ID   reject the mutation and exit nonzero

No secret value is read or printed.
"""

from __future__ import annotations

import sys


DISABLED_MESSAGE = (
    "ERROR: in-place secret rotation is disabled because the legacy targets "
    "are not canonical/effective authorities; update the declared canonical "
    "authority with its native workflow, verify the deployed selector "
    "offline, then create a new recovery set"
)


def _usage() -> int:
    print("usage: rotate_secrets.py {list|kind ID|apply ID}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return _usage()

    command = args[0]
    if command == "list":
        if len(args) != 1:
            return _usage()
        print("# In-place secret rotation is disabled")
        print("No rotatable identifiers are exposed by this compatibility command.")
        print("Legacy flat files are not canonical/effective authorities.")
        print("OpenClaw provider authentication requires an OpenClaw-native workflow.")
        print("See docs/SECRETS.md and docs/BACKUP-RESTORE.md.")
        return 0

    if command == "kind":
        if len(args) != 2:
            return _usage()
        print("unsupported")
        return 4

    if command == "apply":
        if len(args) != 2:
            return _usage()
        print(DISABLED_MESSAGE, file=sys.stderr)
        return 2

    return _usage()


if __name__ == "__main__":
    raise SystemExit(main())
