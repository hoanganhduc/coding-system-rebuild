#!/usr/bin/env python3
"""Pull the architecture-selected OCI closure using digest references only."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

import lockctl


LOCK_PATH = Path(__file__).resolve().with_name("images.lock.json")
REQUIRED_RUNTIME_ROLES = {
    "openclaw-sandbox",
    "sagemath",
    "zotero-translation-server",
}


def selected_images(arch: str) -> list[dict[str, object]]:
    raw = lockctl.load_json(LOCK_PATH)
    if not isinstance(raw, dict) or not isinstance(raw.get("images"), list):
        raise lockctl.LockError("invalid OCI image lock")
    linux_platform = f"linux/{lockctl.canonical_arch(arch)}"
    selected = [
        image
        for image in raw["images"]
        if isinstance(image, dict)
        and isinstance(image.get("platforms"), dict)
        and linux_platform in image["platforms"]
    ]
    role_counts: dict[str, int] = {}
    for image in selected:
        roles = image.get("roles")
        if not isinstance(roles, list):
            raise lockctl.LockError(f"selected image has invalid roles: {image.get('id', '?')}")
        for role in roles:
            if not isinstance(role, str):
                raise lockctl.LockError(f"selected image has invalid roles: {image.get('id', '?')}")
            role_counts[role] = role_counts.get(role, 0) + 1
    missing = sorted(REQUIRED_RUNTIME_ROLES - set(role_counts))
    duplicates = sorted(role for role, count in role_counts.items() if count != 1)
    if missing or duplicates:
        raise lockctl.LockError(
            f"invalid image-role selection for {linux_platform}: "
            f"missing={missing}, non_unique={duplicates}"
        )
    return selected


def docker_prefix() -> list[str]:
    direct = subprocess.run(
        ["docker", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if direct.returncode == 0:
        return ["docker"]
    return ["sudo", "docker"]


def inspect_image(prefix: list[str], reference: str, arch: str) -> None:
    architecture = subprocess.run(
        prefix + ["image", "inspect", "--format", "{{.Architecture}}", reference],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    expected = lockctl.canonical_arch(arch)
    if architecture != expected:
        raise lockctl.LockError(
            f"pulled image architecture mismatch for {reference}: expected {expected}, got {architecture}"
        )
    digests_raw = subprocess.run(
        prefix + ["image", "inspect", "--format", "{{json .RepoDigests}}", reference],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout
    try:
        repo_digests = json.loads(digests_raw)
    except json.JSONDecodeError as exc:
        raise lockctl.LockError(f"Docker returned invalid RepoDigests for {reference}") from exc
    if reference not in repo_digests:
        raise lockctl.LockError(f"Docker did not retain the locked repository digest: {reference}")


def verify_registry_descriptor(
    prefix: list[str], image: dict[str, object], arch: str
) -> None:
    """Bind the selected platform descriptor to the locked index bytes."""
    reference = str(image["reference"])
    try:
        result = subprocess.run(
            prefix + ["buildx", "imagetools", "inspect", reference, "--raw"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
    except subprocess.TimeoutExpired as exc:
        raise lockctl.LockError(
            f"registry descriptor inspection timed out: {reference}"
        ) from exc
    if (
        result.returncode != 0
        or not result.stdout
        or len(result.stdout) > 4 * 1024 * 1024
        or len(result.stderr) > 1024 * 1024
    ):
        raise lockctl.LockError(f"registry descriptor inspection failed: {reference}")
    actual_index = "sha256:" + hashlib.sha256(result.stdout).hexdigest()
    if actual_index != image["index_digest"]:
        raise lockctl.LockError(f"registry index bytes differ from lock: {reference}")
    try:
        descriptor = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise lockctl.LockError(
            f"registry descriptor is not valid JSON: {reference}"
        ) from exc
    expected_platform = f"linux/{lockctl.canonical_arch(arch)}"
    expected_digest = image["platforms"][expected_platform]  # type: ignore[index]
    manifests = descriptor.get("manifests") if isinstance(descriptor, dict) else None
    if manifests is None:
        selected_digest = actual_index
    elif isinstance(manifests, list):
        matches = [
            item.get("digest")
            for item in manifests
            if isinstance(item, dict)
            and isinstance(item.get("platform"), dict)
            and item["platform"].get("os") == "linux"
            and item["platform"].get("architecture") == lockctl.canonical_arch(arch)
        ]
        if len(matches) != 1:
            raise lockctl.LockError(
                f"registry index has {len(matches)} descriptors for {expected_platform}: {reference}"
            )
        selected_digest = matches[0]
    else:
        raise lockctl.LockError(f"registry index manifests field is invalid: {reference}")
    if selected_digest != expected_digest:
        raise lockctl.LockError(
            f"registry platform digest differs from lock for {expected_platform}: {reference}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", default=platform.machine())
    parser.add_argument("--dry-run", action="store_true", help="print pulls without contacting Docker")
    parser.add_argument("--verify-only", action="store_true", help="inspect without pulling")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        arch = lockctl.canonical_arch(args.arch)
        errors = lockctl.validate_profile(arch)
        if errors:
            raise lockctl.LockError("; ".join(errors))
        images = selected_images(arch)
        linux_platform = f"linux/{arch}"
        if args.dry_run:
            for image in images:
                print(f"docker pull --platform {linux_platform} {image['reference']}")
            return 0
        prefix = docker_prefix()
        for image in images:
            reference = str(image["reference"])
            if not args.verify_only:
                subprocess.run(
                    prefix + ["pull", "--platform", linux_platform, reference],
                    check=True,
                )
            verify_registry_descriptor(prefix, image, arch)
            inspect_image(prefix, reference, arch)
            print(f"OCI OK: {image['id']} {reference} ({linux_platform})")
        return 0
    except (lockctl.LockError, OSError, subprocess.CalledProcessError) as exc:
        print(f"pull-locked-images: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
