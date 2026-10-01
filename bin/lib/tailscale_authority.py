#!/usr/bin/env python3
"""Strict data contracts for the portable Tailscale recovery authority."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

from owner_settings import OwnerSettingsError, read_owner_private_bytes


AUTHKEY_RELATIVE = ".config/coding-system/tailscale-authkey"
HOSTNAME_RELATIVE = ".config/coding-system/tailscale-hostname"
LEGACY_RELATIVE = ".config/coding-system/tailscale.env"
AUTHKEY_RE = re.compile(r"tskey-(?:auth-)?[A-Za-z0-9_-]{16,512}")
HOSTNAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


class TailscaleAuthorityError(ValueError):
    """A Tailscale authority or local readiness probe is invalid."""


def parse_authkey(payload: bytes) -> str:
    try:
        value = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TailscaleAuthorityError("Tailscale auth-key authority is invalid") from exc
    if value.endswith("\n"):
        value = value[:-1]
    if "\n" in value or "\r" in value or AUTHKEY_RE.fullmatch(value) is None:
        raise TailscaleAuthorityError("Tailscale auth-key authority is invalid")
    return value


def parse_hostname(payload: bytes) -> str:
    try:
        value = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TailscaleAuthorityError("Tailscale hostname setting is invalid") from exc
    if value.endswith("\n"):
        value = value[:-1]
    if "\n" in value or "\r" in value or HOSTNAME_RE.fullmatch(value) is None:
        raise TailscaleAuthorityError("Tailscale hostname setting is invalid")
    return value


def read_authkey(home: Path) -> str | None:
    try:
        payload = read_owner_private_bytes(home / AUTHKEY_RELATIVE, max_bytes=1024)
    except OwnerSettingsError as exc:
        raise TailscaleAuthorityError("Tailscale auth-key authority is unsafe") from exc
    return None if payload is None else parse_authkey(payload)


def read_hostname(home: Path) -> str | None:
    try:
        payload = read_owner_private_bytes(home / HOSTNAME_RELATIVE, max_bytes=1024)
    except OwnerSettingsError as exc:
        raise TailscaleAuthorityError("Tailscale hostname setting is unsafe") from exc
    return None if payload is None else parse_hostname(payload)


def parse_legacy(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TailscaleAuthorityError("legacy Tailscale authority is invalid") from exc
    values: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            continue
        match = re.fullmatch(r"(?:export[ \t]+)?(TS_AUTHKEY|TS_HOSTNAME)=([^\s'\"`$;]+)", raw)
        if match is None or match.group(1) in values:
            raise TailscaleAuthorityError("legacy Tailscale authority is invalid")
        values[match.group(1)] = match.group(2)
    if "TS_AUTHKEY" in values:
        parse_authkey((values["TS_AUTHKEY"] + "\n").encode("ascii"))
    if "TS_HOSTNAME" in values:
        parse_hostname((values["TS_HOSTNAME"] + "\n").encode("ascii"))
    return values


def local_backend_state(tailscale: str = "tailscale") -> str | None:
    """Return only the non-identity daemon state from a bounded local probe."""

    try:
        completed = subprocess.run(
            [tailscale, "status", "--json"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "NO_COLOR": "1"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode not in (0, 1) or len(completed.stdout) > 4 * 1024 * 1024:
        return None
    try:
        document = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    state = document.get("BackendState") if isinstance(document, dict) else None
    return state if state in {"Running", "NeedsLogin", "NoState", "Stopped"} else None
