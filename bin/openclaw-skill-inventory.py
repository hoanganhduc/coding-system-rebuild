#!/usr/bin/env python3
"""Select the pinned non-runtime OpenClaw skill-file restore inventory."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


SCHEMA = "coding-system.openclaw-skill-inventory.v1"
SKILL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
MAX_MANIFEST_BYTES = 16 * 1024 * 1024


class InventoryError(RuntimeError):
    pass


def load_json_manifest(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise InventoryError(f"manifest escapes AAS source root: {relative}") from exc
    descriptor: int | None = None
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > MAX_MANIFEST_BYTES
            or stat.S_IMODE(info.st_mode) & 0o002
        ):
            raise InventoryError(f"unsafe AAS manifest metadata: {relative}")
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != info.st_size
            or stat.S_IMODE(opened.st_mode) & 0o002
        ):
            raise InventoryError(f"AAS manifest changed before read: {relative}")
        payload = bytearray()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise InventoryError(f"AAS manifest was truncated: {relative}")
            payload.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise InventoryError(f"AAS manifest exceeded admitted size: {relative}")
        after = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise InventoryError(f"AAS manifest changed while reading: {relative}")
    except FileNotFoundError as exc:
        raise InventoryError(f"missing AAS manifest: {relative}") from exc
    except OSError as exc:
        raise InventoryError(f"cannot safely read AAS manifest: {relative}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        value = json.loads(bytes(payload).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"invalid JSON AAS manifest: {relative}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise InventoryError(f"unsupported AAS manifest schema: {relative}")
    return value


def build_inventory(aas_root: Path) -> dict[str, Any]:
    root = Path(os.path.abspath(aas_root))
    try:
        root_info = root.lstat()
    except FileNotFoundError as exc:
        raise InventoryError("AAS source root is missing") from exc
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise InventoryError("AAS source root must be a real directory")
    profiles = load_json_manifest(root, "manifest/profiles.yaml")
    skills_manifest = load_json_manifest(root, "manifest/skills.yaml")
    runtime_manifest = load_json_manifest(root, "manifest/runtime.yaml")
    profiles_table = profiles.get("profiles")
    complete = profiles_table.get("complete-restore") if isinstance(profiles_table, dict) else None
    skills_table = skills_manifest.get("skills")
    runtime_table = runtime_manifest.get("skills")
    if (
        not isinstance(complete, dict)
        or complete.get("skills") != ["*"]
        or not isinstance(skills_table, dict)
        or not isinstance(runtime_table, dict)
    ):
        raise InventoryError("AAS complete-restore manifests have an invalid shape")
    runtime_backed = set(runtime_table)
    if any(not isinstance(skill, str) or SKILL_RE.fullmatch(skill) is None for skill in runtime_backed):
        raise InventoryError("AAS runtime manifest contains an invalid skill name")
    selected: list[str] = []
    excluded: list[str] = []
    for skill, spec in skills_table.items():
        if (
            not isinstance(skill, str)
            or SKILL_RE.fullmatch(skill) is None
            or not isinstance(spec, dict)
            or not isinstance(spec.get("supported_agents"), list)
            or any(not isinstance(agent, str) for agent in spec["supported_agents"])
        ):
            raise InventoryError("AAS skills manifest contains an invalid entry")
        if "openclaw" not in spec["supported_agents"]:
            continue
        if skill in runtime_backed:
            excluded.append(skill)
            continue
        source = root / "canonical" / "skills" / skill / "SKILL.md"
        try:
            source_info = source.lstat()
        except FileNotFoundError as exc:
            raise InventoryError(f"canonical OpenClaw skill source is missing: {skill}") from exc
        if (
            not stat.S_ISREG(source_info.st_mode)
            or stat.S_ISLNK(source_info.st_mode)
            or source_info.st_nlink != 1
            or source_info.st_size <= 0
            or stat.S_IMODE(source_info.st_mode) & 0o002
        ):
            raise InventoryError(f"canonical OpenClaw skill source is unsafe: {skill}")
        selected.append(skill)
    selected = sorted(selected)
    if "classroom50" not in selected:
        raise InventoryError("OpenClaw skill-file inventory has no classroom50 canary")
    selected.remove("classroom50")
    selected.insert(0, "classroom50")
    if not selected:
        raise InventoryError("OpenClaw skill-file inventory is empty")
    return {
        "schema": SCHEMA,
        "skills": selected,
        "runtime_backed_excluded": sorted(excluded),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--aas-root", required=True, type=Path)
    parser.add_argument("--format", choices=("lines", "json"), default="lines")
    args = parser.parse_args(argv)
    try:
        inventory = build_inventory(args.aas_root)
    except InventoryError as exc:
        print(f"openclaw-skill-inventory: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(inventory, indent=2, sort_keys=True))
    else:
        print("\n".join(inventory["skills"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
