#!/usr/bin/python3
"""Execute an already-open executable descriptor for a short-lived probe."""

from __future__ import annotations

import os
import sys


_PYTHON_FIXTURE_BOOTSTRAP = r'''import os
import sys

descriptor = int(sys.argv[1])
display_path = sys.argv[2]
arguments = sys.argv[3:]
try:
    info = os.fstat(descriptor)
    if not 0 <= info.st_size <= 1024 * 1024:
        raise SystemExit(125)
    chunks = []
    offset = 0
    while offset < info.st_size:
        chunk = os.pread(descriptor, min(65536, info.st_size - offset), offset)
        if not chunk:
            raise SystemExit(125)
        chunks.append(chunk)
        offset += len(chunk)
    script = b"".join(chunks)
finally:
    os.close(descriptor)
sys.argv = [display_path, *arguments]
namespace = {
    "__name__": "__main__",
    "__file__": display_path,
    "__cached__": None,
    "__loader__": None,
    "__package__": None,
    "__spec__": None,
}
exec(compile(script, display_path, "exec"), namespace, namespace)
'''


def _python_fixture(descriptor: int, argv: list[str]) -> None:
    inherited = os.dup(descriptor)
    try:
        os.set_inheritable(inherited, True)
        os.execve(
            "/usr/bin/python3",
            [
                "/usr/bin/python3",
                "-I",
                "-c",
                _PYTHON_FIXTURE_BOOTSTRAP,
                str(inherited),
                argv[0],
                *argv[1:],
            ],
            os.environ,
        )
    finally:
        os.close(inherited)


def _fixture_script(descriptor: int, argv: list[str]) -> None:
    info = os.fstat(descriptor)
    if info.st_size > 1024 * 1024:
        raise SystemExit(125)
    text = os.pread(descriptor, info.st_size, 0).decode("utf-8", errors="strict")
    first = text.splitlines()[0] if text else ""
    if first in {"#!/usr/bin/env python3", "#!/usr/bin/python3"}:
        _python_fixture(descriptor, argv)
        raise SystemExit(125)
    mapping = {
        "#!/usr/bin/env bash": ("/bin/bash", ["/bin/bash", "-c", text, argv[0]]),
        "#!/usr/bin/env sh": ("/bin/sh", ["/bin/sh", "-c", text, argv[0]]),
        "#!/bin/bash": ("/bin/bash", ["/bin/bash", "-c", text, argv[0]]),
        "#!/bin/sh": ("/bin/sh", ["/bin/sh", "-c", text, argv[0]]),
    }
    selected = mapping.get(first)
    if selected is None:
        raise SystemExit(125)
    interpreter, prefix = selected
    os.execve(interpreter, [*prefix, *argv[1:]], os.environ)


def main() -> None:
    if len(sys.argv) < 3 or not sys.argv[1].isdecimal():
        raise SystemExit(125)
    descriptor = int(sys.argv[1])
    argv = [sys.argv[2], *sys.argv[3:]]
    os.set_inheritable(descriptor, False)
    try:
        os.execve(descriptor, argv, os.environ)
    except OSError as exc:
        if exc.errno != 2 or os.pread(descriptor, 2, 0) != b"#!":
            raise
    _fixture_script(descriptor, argv)


if __name__ == "__main__":
    main()
