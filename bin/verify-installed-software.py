#!/usr/bin/env python3
"""Verify the exact Ubuntu package and native CLI state for one platform lock."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Iterable


ARCHITECTURES = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}
MAX_OUTPUT = 64 * 1024


class VerificationError(RuntimeError):
    """The declared or installed software state is invalid."""


def host_architecture(machine: str) -> str:
    try:
        return ARCHITECTURES[machine.lower()]
    except KeyError as exc:
        raise VerificationError(f"unsupported architecture: {machine}") from exc


def load_lock(repository: Path, architecture: str) -> dict[str, object]:
    path = repository / f"system/software/ubuntu-24.04-{architecture}.lock.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read platform lock {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError("platform lock root is not an object")
    host = value.get("host")
    if not isinstance(host, dict) or host.get("architecture") != architecture:
        raise VerificationError("platform lock does not match the selected architecture")
    versions = value.get("cli_versions")
    if not isinstance(versions, dict) or not versions or any(
        not isinstance(name, str) or not isinstance(version, str) or not version
        for name, version in versions.items()
    ):
        raise VerificationError("platform lock cli_versions is invalid")
    return value


# name>=version is a minimum, name@origin a build from that PPA, name=version exact.
APT_ENTRY = re.compile(r"(?P<name>[a-z0-9][a-z0-9+.-]*?)(?P<operator>>=|=|@)(?P<value>\S+)")
VERSION_TOKEN = re.compile(r"(?<![0-9A-Za-z.+-])v?([0-9]+(?:\.[0-9]+)+)")


def apt_specs(path: Path) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise VerificationError(f"cannot read apt lock {path}: {exc}") from exc
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = APT_ENTRY.fullmatch(line)
        if match is None:
            raise VerificationError(f"invalid apt lock entry at line {number}")
        name = match.group("name")
        if name in result:
            raise VerificationError(f"duplicate apt package in lock: {name}")
        result[name] = (match.group("operator"), match.group("value"))
    if not result:
        raise VerificationError("apt lock is empty")
    return result


def apt_satisfied(spec: tuple[str, str], actual: str | None) -> bool:
    operator, value = spec
    if actual is None:
        return False
    if operator == "@":
        return value in actual
    if operator == "=":
        return actual == value
    completed = subprocess.run(
        ["/usr/bin/dpkg", "--compare-versions", actual, "ge", value],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    return completed.returncode == 0


def run_bounded(command: list[str], *, timeout: int = 20) -> tuple[int, str]:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
        )
        output, _ = process.communicate(timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        try:
            process.kill()  # type: ignore[possibly-undefined]
        except (OSError, UnboundLocalError):
            pass
        return 127, f"probe failed: {type(exc).__name__}"
    if len(output) > MAX_OUTPUT:
        return 126, f"probe output exceeded {MAX_OUTPUT} bytes"
    return process.returncode, output.decode("utf-8", errors="replace").strip()


def installed_apt_versions(packages: Iterable[str]) -> dict[str, str | None]:
    names = list(packages)
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\\n", *names],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    found: dict[str, str | None] = {name: None for name in names}
    for raw in result.stdout.splitlines():
        fields = raw.split("\t")
        if len(fields) != 3:
            continue
        package, version, status = fields
        package = package.split(":", 1)[0]
        if package in found and status == "ii ":
            found[package] = version
    return found


def candidate_paths(home: Path, name: str) -> list[Path]:
    fixed = {
        "node": [home / ".npm-global/bin/node"],
        "npm": [home / ".npm-global/bin/npm"],
        "rustup": [home / ".cargo/bin/rustup"],
        "rustc": [home / ".cargo/bin/rustc"],
        "bun": [home / ".bun/bin/bun"],
        "elan": [home / ".elan/bin/elan"],
        "kimi": [home / ".kimi-code/bin/kimi"],
        "grok": [home / ".grok/bin/grok"],
        "agy": [home / ".local/bin/agy"],
        "gh-teacher": [
            home / ".local/share/gh/extensions/gh-teacher/gh-teacher",
        ],
        "modal": [
            home / ".local/share/coding-system/python-closure/modal/bin/modal",
            home / ".local/bin/modal",
        ],
        "aider": [
            home / ".local/share/coding-system/python-closure/aider/bin/aider",
            home / ".local/bin/aider",
        ],
    }
    # The declared install location comes first; a tool the owner installed
    # another way (a system package, pipx) is still found on PATH.
    candidates = list(fixed.get(name, []))
    executable = shutil.which(name)
    if executable and Path(executable) not in candidates:
        candidates.append(Path(executable))
    return candidates


def runnable(path: Path) -> bool:
    """A regular executable, directly or through symlinks such as pipx's."""
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return resolved.is_file() and os.access(resolved, os.X_OK)


def version_command(name: str, executable: Path) -> list[str]:
    if name == "tailscale":
        return [str(executable), "version"]
    return [str(executable), "--version"]


def output_has_exact_version(output: str, version: str) -> bool:
    # Reject a prefix match such as 1.2 matching 1.20 or 1.2.0.  Vendor labels
    # around the value are intentionally allowed because the lock controls the
    # executable and vendors do not share one --version format.
    escaped = re.escape(version)
    plain = rf"(?<![0-9A-Za-z.+-]){escaped}(?![0-9A-Za-z.+-])"
    vendor_v = rf"(?<![0-9A-Za-z.+-])v{escaped}(?![0-9A-Za-z.+-])"
    return re.search(rf"(?:{plain}|{vendor_v})", output) is not None


def output_meets_version(output: str, expected: str) -> bool:
    """An exact version, or with a ">=" prefix a first version at or above it."""
    if not expected.startswith(">="):
        return output_has_exact_version(output, expected)
    match = VERSION_TOKEN.search(output)
    if match is None:
        return False
    observed = tuple(int(part) for part in match.group(1).split("."))
    return observed >= tuple(int(part) for part in expected[2:].split("."))


# A CLI whose installation the operator turned off with its SKIP_* flag set to "1".
SKIPPABLE_CLIS = {
    "gprolog": "SKIP_GPROLOG",
    "grok": "SKIP_GROK",
    "ollama": "SKIP_OLLAMA",
    "veracrypt": "SKIP_VERACRYPT",
}


def skipped_clis(environment: dict[str, str]) -> frozenset[str]:
    return frozenset(name for name, flag in SKIPPABLE_CLIS.items() if environment.get(flag) == "1")


def verify_clis(
    home: Path, versions: dict[str, object], skipped: frozenset[str] = frozenset()
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for name in sorted(versions):
        expected = str(versions[name])
        if name in skipped:
            records.append(
                {"name": name, "expected": expected, "status": "SKIPPED", "reason": f"{SKIPPABLE_CLIS[name]}=1"}
            )
            continue
        candidates = candidate_paths(home, name)
        executable = next((path for path in candidates if runnable(path)), None)
        if executable is None:
            records.append({"name": name, "expected": expected, "status": "FAIL", "reason": "missing executable"})
            continue
        returncode, output = run_bounded(version_command(name, executable))
        # A locked version is the floor: updating a tool never fails verification.
        minimum = expected if expected.startswith(">=") else f">={expected}"
        if not re.fullmatch(r">=[0-9]+(?:\.[0-9]+)+", minimum):
            minimum = expected
        observed = VERSION_TOKEN.search(output)
        if returncode == 0 and output_meets_version(output, minimum):
            records.append(
                {
                    "name": name,
                    "expected": minimum,
                    "observed": observed.group(1) if observed else None,
                    "path": str(executable),
                    "status": "PASS",
                }
            )
        else:
            records.append(
                {
                    "name": name,
                    "expected": expected,
                    "path": str(executable),
                    "status": "FAIL",
                    "reason": f"version probe failed (exit={returncode})",
                }
            )
    return records


def write_report(path: Path, report: dict[str, object]) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise VerificationError("software report parent is unsafe")
    os.chmod(path.parent, 0o700)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise VerificationError("software report destination is unsafe")
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--profile", choices=("source", "full"), default="full")
    parser.add_argument("--architecture", choices=("amd64", "arm64"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        repository = args.repository.resolve()
        architecture = args.architecture or host_architecture(platform.machine())
        lock = load_lock(repository, architecture)
        expected_apt = apt_specs(repository / "system/packages/apt.lock.txt")
        report: dict[str, object] = {
            "schema": "coding-system.installed-software-verification/v1",
            "profile": args.profile,
            "architecture": architecture,
            "status": "PASS",
            "apt": [],
            "clis": [],
        }
        if args.profile == "source":
            report["apt"] = [{"name": name, "expected": "".join(spec), "status": "NOT_RUN"} for name, spec in sorted(expected_apt.items())]
            report["clis"] = [{"name": name, "expected": version, "status": "NOT_RUN"} for name, version in sorted(lock["cli_versions"].items())]  # type: ignore[union-attr]
        else:
            os_release = Path("/etc/os-release").read_text(encoding="utf-8")
            if not re.search(r'^ID=ubuntu$', os_release, re.MULTILINE) or not re.search(
                r'^VERSION_ID="?24\.04"?$', os_release, re.MULTILINE
            ):
                raise VerificationError("installed-software verification requires Ubuntu 24.04")
            if architecture != host_architecture(platform.machine()):
                raise VerificationError("requested lock architecture differs from this host")
            installed = installed_apt_versions(expected_apt)
            apt_records = []
            for name, spec in sorted(expected_apt.items()):
                actual = installed[name]
                apt_records.append(
                    {
                        "name": name,
                        "expected": "".join(spec),
                        "actual": actual,
                        "status": "PASS" if apt_satisfied(spec, actual) else "FAIL",
                    }
                )
            report["apt"] = apt_records
            report["clis"] = verify_clis(
                args.home.expanduser().absolute(),
                lock["cli_versions"],  # type: ignore[arg-type]
                skipped_clis(dict(os.environ)),
            )
            if any(record["status"] == "FAIL" for group in (report["apt"], report["clis"]) for record in group):  # type: ignore[union-attr]
                report["status"] = "FAIL"
        if args.output:
            write_report(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] == "PASS" else 2
    except (VerificationError, OSError) as exc:
        print(f"installed-software: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
