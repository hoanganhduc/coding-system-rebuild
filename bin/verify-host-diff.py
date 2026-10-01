#!/usr/bin/env python3
"""Compare this host with a baseline captured on the host it replaces.

`capture` records each layer of the running host: manually installed apt
packages, user and system services, timer calendars, crontab lines, npm and
pipx tools, Docker images. Only names, versions and states are recorded, with
the home path written as {{ HOME }}. `diff` (the default) records the same
layers again and reports every difference that the owner-approved exceptions do
not explain. The baseline and the exceptions are private files, carried by the
recovery set.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Callable


DEFAULT_BASELINE = Path(".config/coding-system/host-baseline.json")
DEFAULT_EXCEPTIONS = Path(".config/coding-system/host-diff-exceptions.json")
Runner = Callable[[list[str]], str]
# Packages that belong to a cloud image or its boot chain differ between
# providers by design; the owner's private exceptions extend this list.
BUILTIN_EXCEPTIONS = {
    "apt-manual": {
        "linux-*": "provider kernel",
        "grub-*": "bootloader",
        "shim-signed": "bootloader",
        "cloud-init": "cloud image",
        "ubuntu-cloud-minimal": "cloud image",
        "open-iscsi": "cloud storage",
        "unified-monitoring-agent": "cloud agent",
        "zstd": "installed by the restore to unpack the locked Ollama release",
    },
}


def run_command(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def user_unit_states(home: Path, run: Runner) -> dict[str, str]:
    units = home / ".config/systemd/user"
    states: dict[str, str] = {}
    if not units.is_dir():
        return states
    for path in sorted(units.iterdir()):
        if path.suffix in {".service", ".timer"} and path.is_file() and not path.is_symlink():
            enabled = run(["systemctl", "--user", "is-enabled", path.name]).strip() or "unknown"
            active = run(["systemctl", "--user", "is-active", path.name]).strip() or "inactive"
            states[path.name] = f"{enabled}/{active}"
    return states


def collect(home: Path, run: Runner = run_command, user_units: dict[str, str] | None = None) -> dict[str, object]:
    home_prefix = f"{home}/"

    def lines(command: list[str]) -> list[str]:
        return [line.strip() for line in run(command).splitlines() if line.strip()]

    try:
        npm = sorted(json.loads(run(["npm", "ls", "-g", "--depth=0", "--json"]) or "{}").get("dependencies", {}))
    except json.JSONDecodeError:
        npm = []
    return {
        "apt-manual": sorted(lines(["apt-mark", "showmanual"])),
        "crontab": sorted(
            line.replace(home_prefix, "{{ HOME }}/")
            for line in lines(["crontab", "-l"])
            if not line.startswith("#")
        ),
        "systemd-system-enabled": sorted(
            line.split()[0]
            for line in lines(["systemctl", "list-unit-files", "--state=enabled",
                               "--type=service,timer", "--no-legend", "--plain"])
        ),
        "systemd-user-units": user_units if user_units is not None else user_unit_states(home, run),
        "npm-globals": npm,
        "pipx": sorted(line.split()[0] for line in lines(["pipx", "list", "--short"])),
        "docker-images": sorted(
            line for line in lines(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"])
            if "<none>" not in line
        ),
    }


def compare(baseline: dict[str, object], current: dict[str, object], exceptions: dict[str, dict[str, str]]) -> dict[str, dict[str, list[str]]]:
    report: dict[str, dict[str, list[str]]] = {}
    for layer in sorted(set(baseline) | set(current)):
        old, new = baseline.get(layer, []), current.get(layer, [])
        differences: list[tuple[str, str]] = []
        if isinstance(old, dict) or isinstance(new, dict):
            old, new = dict(old or {}), dict(new or {})
            differences += [(f"-{key}", key) for key in sorted(set(old) - set(new))]
            differences += [(f"+{key}", key) for key in sorted(set(new) - set(old))]
            differences += [
                (f"~{key}: {old[key]} -> {new[key]}", key)
                for key in sorted(set(old) & set(new))
                if old[key] != new[key]
            ]
        else:
            differences += [(f"-{item}", item) for item in sorted(set(old) - set(new))]
            differences += [(f"+{item}", item) for item in sorted(set(new) - set(old))]
        patterns = exceptions.get(layer, {})
        expected = [text for text, item in differences if any(fnmatch.fnmatchcase(item, p) for p in patterns)]
        unexpected = [text for text, _item in differences if text not in expected]
        report[layer] = {"expected": sorted(expected), "unexpected": sorted(unexpected)}
    return report


def merged_exceptions(private: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    merged = {layer: dict(patterns) for layer, patterns in BUILTIN_EXCEPTIONS.items()}
    for layer, patterns in private.items():
        merged.setdefault(layer, {}).update(patterns)
    return merged


def clean(report: dict[str, dict[str, list[str]]]) -> bool:
    return not any(layer["unexpected"] for layer in report.values())


def write_private_json(path: Path, value: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", nargs="?", choices=("capture", "diff"), default="diff")
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--exceptions", type=Path)
    arguments = parser.parse_args(argv)
    baseline_path = arguments.baseline or arguments.home / DEFAULT_BASELINE
    current = collect(arguments.home)
    if arguments.command == "capture":
        write_private_json(baseline_path, current)
        print(f"host baseline: captured {len(current)} layers")
        return 0
    if not baseline_path.is_file():
        print(f"host diff: no baseline at {baseline_path}; run `capture` on the reference host", file=sys.stderr)
        return 2
    exceptions_path = arguments.exceptions or arguments.home / DEFAULT_EXCEPTIONS
    private = json.loads(exceptions_path.read_text(encoding="utf-8")) if exceptions_path.is_file() else {}
    exceptions = merged_exceptions(private)
    report = compare(json.loads(baseline_path.read_text(encoding="utf-8")), current, exceptions)
    for layer, result in report.items():
        print(f"{layer}: {len(result['unexpected'])} unexpected, {len(result['expected'])} expected")
        for text in result["unexpected"]:
            print(f"  {text}")
    return 0 if clean(report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
