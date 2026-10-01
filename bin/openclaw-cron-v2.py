#!/usr/bin/env python3
"""Export and reconcile logical OpenClaw cron declarations through its CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


SCHEMA = "coding-system.openclaw-cron/v2"
DEFAULT_PREFIX = "coding-system.restore."
PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*\.$")
CANARY_KEY = "coding-system.restore.scheduler-canary"
LOGICAL_FIELDS = (
    "declarationKey",
    "displayName",
    "owner",
    "name",
    "description",
    "enabled",
    "deleteAfterRun",
    "agentId",
    "sessionKey",
    "schedule",
    "trigger",
    "sessionTarget",
    "wakeMode",
    "payload",
    "delivery",
    "failureAlert",
)


class CronContractError(ValueError):
    """Invalid snapshot, legacy input, or CLI response."""


def canary_declaration() -> dict[str, Any]:
    return {
        "declarationKey": CANARY_KEY,
        "displayName": "Scheduler canary",
        "name": "coding-system scheduler canary",
        "description": "Provider-free proof that the OpenClaw scheduler executed a command job.",
        "enabled": True,
        "schedule": {
            "kind": "cron",
            "expr": "* * * * *",
            "tz": "Etc/UTC",
            "staggerMs": 0,
        },
        "sessionTarget": "isolated",
        "wakeMode": "now",
        "payload": {
            "kind": "command",
            "argv": [
                "/usr/bin/python3",
                "{{ HOME }}/.local/share/coding-system/repository/bin/scheduler-canary.py",
                "record",
                "--scheduler",
                "openclaw",
                "--state-dir",
                "{{ HOME }}/.local/state/coding-system/scheduler-canaries",
            ],
            "timeoutSeconds": 30,
            "noOutputTimeoutSeconds": 15,
            "outputMaxBytes": 4096,
        },
        "delivery": {"mode": "none"},
    }


def transform_home(value: Any, home: Path, *, materialize: bool) -> Any:
    """Render or normalize the one portable home placeholder recursively."""
    if isinstance(value, str):
        if materialize:
            return value.replace("{{ HOME }}", str(home))
        if value == str(home):
            return "{{ HOME }}"
        return value.replace(f"{home}/", "{{ HOME }}/")
    if isinstance(value, list):
        return [transform_home(item, home, materialize=materialize) for item in value]
    if isinstance(value, dict):
        return {
            key: transform_home(item, home, materialize=materialize)
            for key, item in value.items()
        }
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CronContractError(f"{label} must be an object")
    return value


def _text(value: Any, label: str, *, one_line: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CronContractError(f"{label} must be a non-empty string")
    if one_line and ("\n" in value or "\r" in value):
        raise CronContractError(f"{label} must be a single line")
    return value


def _optional_text(value: Any, label: str) -> None:
    if value is not None and not isinstance(value, str):
        raise CronContractError(f"{label} must be a string")


def _positive_int(value: Any, label: str, *, allow_zero: bool = False) -> None:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CronContractError(f"{label} must be an integer >= {minimum}")


def _nonnegative_number(value: Any, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise CronContractError(f"{label} must be a non-negative number")


def _known_fields(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise CronContractError(f"{label} has unknown fields: {', '.join(sorted(unknown))}")


def validate_schedule(value: Any, label: str) -> None:
    schedule = _object(value, label)
    kind = schedule.get("kind")
    if kind == "at":
        _known_fields(schedule, {"kind", "at"}, label)
        _text(schedule.get("at"), f"{label}.at", one_line=True)
    elif kind == "every":
        _known_fields(schedule, {"kind", "everyMs", "anchorMs"}, label)
        _positive_int(schedule.get("everyMs"), f"{label}.everyMs")
        if "anchorMs" in schedule:
            _positive_int(schedule["anchorMs"], f"{label}.anchorMs", allow_zero=True)
    elif kind == "cron":
        _known_fields(schedule, {"kind", "expr", "tz", "staggerMs"}, label)
        expression = _text(schedule.get("expr"), f"{label}.expr", one_line=True)
        if len(expression.split()) not in {5, 6}:
            raise CronContractError(f"{label}.expr must have five or six fields")
        if "tz" in schedule:
            timezone = _text(schedule["tz"], f"{label}.tz", one_line=True)
            try:
                ZoneInfo(timezone)
            except ZoneInfoNotFoundError as error:
                raise CronContractError(f"{label}.tz is not an installed IANA timezone") from error
        if "staggerMs" in schedule:
            _positive_int(schedule["staggerMs"], f"{label}.staggerMs", allow_zero=True)
    elif kind == "on-exit":
        _known_fields(schedule, {"kind", "command", "cwd"}, label)
        _text(schedule.get("command"), f"{label}.command")
        if "cwd" in schedule:
            _text(schedule["cwd"], f"{label}.cwd")
    else:
        raise CronContractError(f"{label}.kind is unsupported")


def validate_payload(value: Any, label: str) -> None:
    payload = _object(value, label)
    kind = payload.get("kind")
    if kind == "systemEvent":
        _known_fields(payload, {"kind", "text"}, label)
        _text(payload.get("text"), f"{label}.text")
        return
    if kind == "agentTurn":
        allowed = {
            "kind",
            "message",
            "model",
            "fallbacks",
            "thinking",
            "timeoutSeconds",
            "allowUnsafeExternalContent",
            "lightContext",
            "toolsAllow",
            "toolsAllowIsDefault",
        }
        _known_fields(payload, allowed, label)
        _text(payload.get("message"), f"{label}.message")
        for field in ("model", "thinking"):
            if field in payload:
                _optional_text(payload[field], f"{label}.{field}")
        for field in ("fallbacks", "toolsAllow"):
            if field in payload:
                values = payload[field]
                if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                    raise CronContractError(f"{label}.{field} must be a string list")
        if "timeoutSeconds" in payload:
            _nonnegative_number(payload["timeoutSeconds"], f"{label}.timeoutSeconds")
        for field in ("allowUnsafeExternalContent", "lightContext", "toolsAllowIsDefault"):
            if field in payload and not isinstance(payload[field], bool):
                raise CronContractError(f"{label}.{field} must be boolean")
        return
    if kind == "command":
        allowed = {
            "kind",
            "argv",
            "cwd",
            "env",
            "input",
            "timeoutSeconds",
            "noOutputTimeoutSeconds",
            "outputMaxBytes",
        }
        _known_fields(payload, allowed, label)
        argv = payload.get("argv")
        if not isinstance(argv, list) or not argv or not all(
            isinstance(item, str) and bool(item) for item in argv
        ):
            raise CronContractError(f"{label}.argv must be a non-empty string list")
        for field in ("cwd", "input"):
            if field in payload:
                _optional_text(payload[field], f"{label}.{field}")
        if "env" in payload:
            environment = payload["env"]
            if not isinstance(environment, dict) or not all(
                isinstance(key, str) and bool(key) and isinstance(item, str)
                for key, item in environment.items()
            ):
                raise CronContractError(f"{label}.env must be a string map")
        for field in ("timeoutSeconds", "noOutputTimeoutSeconds"):
            if field in payload:
                _nonnegative_number(payload[field], f"{label}.{field}")
        if "outputMaxBytes" in payload:
            _positive_int(payload["outputMaxBytes"], f"{label}.outputMaxBytes")
        return
    raise CronContractError(f"{label}.kind is unsupported")


def validate_delivery(value: Any, label: str) -> None:
    delivery = _object(value, label)
    allowed = {
        "mode",
        "channel",
        "to",
        "threadId",
        "accountId",
        "bestEffort",
        "completionDestination",
        "failureDestination",
    }
    _known_fields(delivery, allowed, label)
    if delivery.get("mode") not in {"none", "announce", "webhook"}:
        raise CronContractError(f"{label}.mode is invalid")
    for field in ("channel", "to", "accountId"):
        if field in delivery:
            _text(delivery[field], f"{label}.{field}")
    if "threadId" in delivery and (
        isinstance(delivery["threadId"], bool)
        or not isinstance(delivery["threadId"], (str, int))
    ):
        raise CronContractError(f"{label}.threadId must be a string or integer")
    if "bestEffort" in delivery and not isinstance(delivery["bestEffort"], bool):
        raise CronContractError(f"{label}.bestEffort must be boolean")
    if "completionDestination" in delivery:
        destination = _object(delivery["completionDestination"], f"{label}.completionDestination")
        _known_fields(destination, {"mode", "to"}, f"{label}.completionDestination")
        if delivery["mode"] != "announce" or destination.get("mode") != "webhook":
            raise CronContractError(f"{label}.completionDestination requires announce/webhook")
        _text(destination.get("to"), f"{label}.completionDestination.to")
    if "failureDestination" in delivery:
        destination = _object(delivery["failureDestination"], f"{label}.failureDestination")
        _known_fields(destination, {"channel", "to", "accountId", "mode"}, f"{label}.failureDestination")
        if "mode" in destination and destination["mode"] not in {"announce", "webhook"}:
            raise CronContractError(f"{label}.failureDestination.mode is invalid")
        for field in ("channel", "to", "accountId"):
            if field in destination:
                _text(destination[field], f"{label}.failureDestination.{field}")
    if delivery["mode"] == "webhook":
        _text(delivery.get("to"), f"{label}.to")
    if delivery["mode"] != "announce" and "completionDestination" in delivery:
        raise CronContractError(f"{label}.completionDestination requires announce mode")


def validate_failure_alert(value: Any, label: str) -> None:
    if value is False:
        return
    alert = _object(value, label)
    _known_fields(
        alert,
        {"after", "channel", "to", "cooldownMs", "includeSkipped", "mode", "accountId"},
        label,
    )
    if "after" in alert:
        _positive_int(alert["after"], f"{label}.after")
    if "cooldownMs" in alert:
        _positive_int(alert["cooldownMs"], f"{label}.cooldownMs", allow_zero=True)
    if "includeSkipped" in alert and not isinstance(alert["includeSkipped"], bool):
        raise CronContractError(f"{label}.includeSkipped must be boolean")
    if "mode" in alert and alert["mode"] not in {"announce", "webhook"}:
        raise CronContractError(f"{label}.mode is invalid")
    for field in ("channel", "to", "accountId"):
        if field in alert:
            _text(alert[field], f"{label}.{field}")


def validate_job(job: dict[str, Any], label: str) -> None:
    _known_fields(job, set(LOGICAL_FIELDS), label)
    key = _text(job.get("declarationKey"), f"{label}.declarationKey", one_line=True)
    if len(key) > 200 or key != key.strip():
        raise CronContractError(f"{label}.declarationKey is invalid")
    _text(job.get("name"), f"{label}.name", one_line=True)
    if not isinstance(job.get("enabled"), bool):
        raise CronContractError(f"{label}.enabled must be boolean")
    for field in ("displayName", "description", "agentId", "sessionKey"):
        if field in job:
            _optional_text(job[field], f"{label}.{field}")
    if "owner" in job:
        owner = _object(job["owner"], f"{label}.owner")
        _known_fields(owner, {"agentId", "sessionKey"}, f"{label}.owner")
        for field in owner:
            _text(owner[field], f"{label}.owner.{field}")
    if "deleteAfterRun" in job and not isinstance(job["deleteAfterRun"], bool):
        raise CronContractError(f"{label}.deleteAfterRun must be boolean")
    if job.get("sessionTarget") not in {"main", "isolated", "current"} and not (
        isinstance(job.get("sessionTarget"), str)
        and job["sessionTarget"].startswith("session:")
        and len(job["sessionTarget"]) > len("session:")
    ):
        raise CronContractError(f"{label}.sessionTarget is invalid")
    if job.get("wakeMode") not in {"now", "next-heartbeat"}:
        raise CronContractError(f"{label}.wakeMode is invalid")
    validate_schedule(job.get("schedule"), f"{label}.schedule")
    validate_payload(job.get("payload"), f"{label}.payload")
    if "delivery" in job:
        validate_delivery(job["delivery"], f"{label}.delivery")
    if "trigger" in job:
        trigger = _object(job["trigger"], f"{label}.trigger")
        _known_fields(trigger, {"script", "once"}, f"{label}.trigger")
        _text(trigger.get("script"), f"{label}.trigger.script")
        if "once" in trigger and not isinstance(trigger["once"], bool):
            raise CronContractError(f"{label}.trigger.once must be boolean")
    if "failureAlert" in job:
        validate_failure_alert(job["failureAlert"], f"{label}.failureAlert")


def logical_job(raw: Any, prefix: str) -> dict[str, Any]:
    source = _object(raw, "OpenClaw cron job")
    job = {
        field: source[field]
        for field in LOGICAL_FIELDS
        if field in source and source[field] is not None
    }
    if "name" not in job:
        raise CronContractError("OpenClaw cron job is missing name")
    if "enabled" not in job:
        job["enabled"] = True
    payload = job.get("payload")
    if "sessionTarget" not in job:
        job["sessionTarget"] = (
            "main" if isinstance(payload, dict) and payload.get("kind") == "systemEvent" else "isolated"
        )
    if "wakeMode" not in job:
        job["wakeMode"] = "now"
    if "declarationKey" not in job or not str(job["declarationKey"]).strip():
        seed = {key: value for key, value in job.items() if key != "declarationKey"}
        digest = hashlib.sha256(canonical_json(seed).encode("utf-8")).hexdigest()[:16]
        slug = re.sub(r"[^a-z0-9]+", "-", str(job["name"]).lower()).strip("-")[:48]
        job["declarationKey"] = f"{prefix}{slug or 'job'}.{digest}"
    validate_job(job, f"job {job.get('name', '<unnamed>')}")
    return job


def make_snapshot(
    raw_jobs: list[Any],
    prefix: str = DEFAULT_PREFIX,
    *,
    home: Path | None = None,
    inject_canary: bool = False,
) -> dict[str, Any]:
    if (
        not isinstance(prefix, str)
        or len(prefix) > 160
        or not PREFIX_RE.fullmatch(prefix)
    ):
        raise CronContractError("managed declaration prefix is invalid")
    jobs_by_key: dict[str, dict[str, Any]] = {}
    explicit_keys: set[str] = set()
    for raw in raw_jobs:
        if home is not None:
            raw = transform_home(raw, home, materialize=False)
        job = logical_job(raw, prefix)
        key = job["declarationKey"]
        previous = jobs_by_key.get(key)
        raw_object = _object(raw, "OpenClaw cron job")
        explicit = isinstance(raw_object.get("declarationKey"), str) and bool(
            raw_object["declarationKey"].strip()
        )
        if previous is not None:
            if explicit or key in explicit_keys or previous != job:
                raise CronContractError(f"ambiguous declaration key: {key}")
            # Exact duplicate legacy jobs without keys collapse to one declaration.
            continue
        jobs_by_key[key] = job
        if explicit:
            explicit_keys.add(key)
    if inject_canary and CANARY_KEY not in jobs_by_key:
        canary = canary_declaration()
        validate_job(canary, "scheduler canary declaration")
        jobs_by_key[CANARY_KEY] = canary
    return {
        "schema": SCHEMA,
        "managedDeclarationPrefix": prefix,
        "jobs": [jobs_by_key[key] for key in sorted(jobs_by_key)],
    }


def load_snapshot(path: Path) -> dict[str, Any]:
    try:
        root = _object(json.loads(path.read_text(encoding="utf-8")), "cron snapshot")
    except (OSError, json.JSONDecodeError) as error:
        raise CronContractError(f"cannot read cron snapshot {path}: {error}") from error
    _known_fields(root, {"schema", "managedDeclarationPrefix", "jobs"}, "cron snapshot")
    if root.get("schema") != SCHEMA:
        raise CronContractError(f"cron snapshot schema must be {SCHEMA}")
    prefix = _text(
        root.get("managedDeclarationPrefix"),
        "cron snapshot managedDeclarationPrefix",
        one_line=True,
    )
    if len(prefix) > 160 or not PREFIX_RE.fullmatch(prefix):
        raise CronContractError("cron snapshot managedDeclarationPrefix is too long")
    jobs = root.get("jobs")
    if not isinstance(jobs, list) or not jobs:
        raise CronContractError("cron snapshot jobs must be a non-empty list")
    seen: set[str] = set()
    for index, raw in enumerate(jobs):
        job = _object(raw, f"cron snapshot jobs[{index}]")
        validate_job(job, f"cron snapshot jobs[{index}]")
        key = job["declarationKey"]
        if key in seen:
            raise CronContractError(f"duplicate declaration key: {key}")
        seen.add(key)
    if jobs != sorted(jobs, key=lambda job: job["declarationKey"]):
        raise CronContractError("cron snapshot jobs must be sorted by declarationKey")
    return root


def materialize_snapshot(snapshot: dict[str, Any], home: Path) -> dict[str, Any]:
    rendered = transform_home(snapshot, home, materialize=True)
    if not isinstance(rendered, dict):
        raise CronContractError("materialized cron snapshot is invalid")
    return rendered


def write_snapshot(path: Path, snapshot: dict[str, Any]) -> bool:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise CronContractError(f"refusing non-regular snapshot destination: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise CronContractError(f"refusing symlink snapshot directory: {path.parent}")
    payload = (json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if path.is_file() and path.read_bytes() == payload:
        os.chmod(path, 0o600)
        return False
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return True


class OpenClawCLI:
    def __init__(
        self,
        executable: str,
        home: Path | None = None,
        *,
        exact_helper: Path | None = None,
        exact_contract: Path | None = None,
    ) -> None:
        if exact_helper is not None or exact_contract is not None:
            if exact_helper is None or exact_contract is None or home is None:
                raise CronContractError(
                    "exact OpenClaw helper, contract, and home must be selected together"
                )
            for path in (exact_helper, exact_contract):
                if (
                    not path.is_absolute()
                    or path.is_symlink()
                    or not path.is_file()
                ):
                    raise CronContractError("exact OpenClaw executable boundary is unsafe")
            self.command = [
                "/usr/bin/python3",
                "-I",
                "-B",
                os.fspath(exact_helper),
                "--home",
                os.fspath(home),
                "--contract",
                os.fspath(exact_contract),
                "--exec",
                "--",
            ]
        else:
            if "/" in executable:
                resolved = executable
            else:
                resolved = shutil.which(executable) or ""
            if not resolved or not os.access(resolved, os.X_OK):
                raise CronContractError(f"OpenClaw executable not found: {executable}")
            self.command = [resolved]
        self.environment = os.environ.copy()
        if home is not None:
            self.environment["HOME"] = str(home)

    def run(self, arguments: list[str]) -> Any:
        result = subprocess.run(
            [*self.command, *arguments],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise CronContractError(
                f"OpenClaw CLI failed ({' '.join(arguments[:3])}, exit {result.returncode}): {detail}"
            )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise CronContractError(
                f"OpenClaw CLI returned non-JSON for {' '.join(arguments[:3])}"
            ) from error

    def list_jobs(self) -> list[dict[str, Any]]:
        value = self.run(["cron", "list", "--all", "--json"])
        jobs = value.get("jobs") if isinstance(value, dict) else value
        if not isinstance(jobs, list) or not all(isinstance(job, dict) for job in jobs):
            raise CronContractError("OpenClaw cron list returned an invalid jobs collection")
        collected = list(jobs)
        pages = 0
        previous_offset = 0
        while isinstance(value, dict) and value.get("hasMore") is True:
            offset = value.get("nextOffset")
            if (
                isinstance(offset, bool)
                or not isinstance(offset, int)
                or offset <= previous_offset
            ):
                raise CronContractError("OpenClaw cron list pagination did not advance")
            value = self.run(
                [
                    "gateway",
                    "call",
                    "cron.list",
                    "--json",
                    "--params",
                    canonical_json({"includeDisabled": True, "limit": 200, "offset": offset}),
                ]
            )
            page_jobs = value.get("jobs") if isinstance(value, dict) else None
            if not isinstance(page_jobs, list) or not all(isinstance(job, dict) for job in page_jobs):
                raise CronContractError("OpenClaw cron list returned an invalid page")
            collected.extend(page_jobs)
            previous_offset = offset
            pages += 1
            if pages > 10000:
                raise CronContractError("OpenClaw cron list pagination exceeded safety limit")
        return collected

    def get_job(self, identifier: str) -> dict[str, Any]:
        value = self.run(["cron", "get", identifier])
        if isinstance(value, dict) and isinstance(value.get("job"), dict):
            value = value["job"]
        return _object(value, f"OpenClaw cron get {identifier}")

    def add_declaration(self, job: dict[str, Any]) -> None:
        self.run(
            [
                "gateway",
                "call",
                "cron.add",
                "--json",
                "--params",
                canonical_json(job),
            ]
        )

    def remove(self, identifier: str) -> None:
        self.run(["cron", "rm", identifier, "--json"])


def get_full_jobs(cli: OpenClawCLI) -> list[dict[str, Any]]:
    listed = cli.list_jobs()
    full: list[dict[str, Any]] = []
    for index, job in enumerate(listed):
        identifier = job.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise CronContractError(f"OpenClaw cron list jobs[{index}] is missing id")
        full.append(cli.get_job(identifier))
    return full


def declared_matches(declared: Any, actual: Any) -> bool:
    """Treat omitted fields as server defaults, but match every declared value."""
    if isinstance(declared, dict):
        return isinstance(actual, dict) and all(
            key in actual and declared_matches(value, actual[key])
            for key, value in declared.items()
        )
    if isinstance(declared, list):
        return isinstance(actual, list) and len(declared) == len(actual) and all(
            declared_matches(left, right) for left, right in zip(declared, actual)
        )
    return declared == actual


def index_live_jobs(raw_jobs: list[dict[str, Any]], prefix: str) -> tuple[dict[str, tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    keyed: dict[str, tuple[str, dict[str, Any]]] = {}
    unkeyed: list[tuple[str, dict[str, Any]]] = []
    for raw in raw_jobs:
        identifier = raw.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise CronContractError("live OpenClaw cron job is missing id")
        logical = logical_job(raw, prefix)
        raw_key = raw.get("declarationKey")
        if isinstance(raw_key, str) and raw_key:
            if raw_key in keyed:
                raise CronContractError(f"live declaration key is ambiguous: {raw_key}")
            keyed[raw_key] = (identifier, logical)
        else:
            unkeyed.append((identifier, logical))
    return keyed, unkeyed


def without_key(job: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in job.items() if key != "declarationKey"}


def plan_reconcile(snapshot: dict[str, Any], raw_live: list[dict[str, Any]], prune: bool) -> dict[str, list[str]]:
    prefix = snapshot["managedDeclarationPrefix"]
    keyed, unkeyed = index_live_jobs(raw_live, prefix)
    desired = {job["declarationKey"]: job for job in snapshot["jobs"]}
    create: list[str] = []
    update: list[str] = []
    current: list[str] = []
    remove: list[str] = []
    for key, job in desired.items():
        existing = keyed.get(key)
        if existing is None:
            create.append(key)
        elif declared_matches(job, existing[1]):
            current.append(key)
        else:
            update.append(key)
    desired_specs = [without_key(job) for job in desired.values()]
    for identifier, job in unkeyed:
        if any(declared_matches(spec, without_key(job)) for spec in desired_specs):
            remove.append(identifier)
    if prune:
        for key, (identifier, _job) in keyed.items():
            if key.startswith(prefix) and key not in desired:
                remove.append(identifier)
    return {
        "create": sorted(create),
        "update": sorted(update),
        "current": sorted(current),
        "remove": sorted(set(remove)),
    }


def reconcile(cli: OpenClawCLI, snapshot: dict[str, Any], prune: bool) -> dict[str, list[str]]:
    initial_jobs = get_full_jobs(cli)
    plan = plan_reconcile(snapshot, initial_jobs, prune)
    desired = {job["declarationKey"]: job for job in snapshot["jobs"]}

    for key in plan["create"]:
        cli.add_declaration(desired[key])
    keyed_initial, _unkeyed_initial = index_live_jobs(
        initial_jobs, snapshot["managedDeclarationPrefix"]
    )
    declarative_fields = {
        "declarationKey",
        "displayName",
        "enabled",
        "schedule",
        "trigger",
        "payload",
        "delivery",
    }
    for key in plan["update"]:
        identifier, existing = keyed_initial[key]
        recreate = any(
            field in desired[key]
            and field not in declarative_fields
            and not declared_matches(desired[key][field], existing.get(field))
            for field in desired[key]
        )
        if recreate:
            cli.remove(identifier)
        cli.add_declaration(desired[key])

    # Native declaration convergence intentionally owns schedule/payload/delivery.
    # Replace only if immutable create-time fields still drift after convergence.
    refreshed = get_full_jobs(cli)
    keyed, _unkeyed = index_live_jobs(refreshed, snapshot["managedDeclarationPrefix"])
    for key, declared in desired.items():
        existing = keyed.get(key)
        if existing is None:
            raise CronContractError(f"OpenClaw did not create declaration: {key}")
        if not declared_matches(declared, existing[1]):
            cli.remove(existing[0])
            cli.add_declaration(declared)

    refreshed = get_full_jobs(cli)
    cleanup_plan = plan_reconcile(snapshot, refreshed, prune)
    for identifier in cleanup_plan["remove"]:
        cli.remove(identifier)

    final_jobs = get_full_jobs(cli)
    final_plan = plan_reconcile(snapshot, final_jobs, prune)
    if final_plan["create"] or final_plan["update"] or final_plan["remove"]:
        raise CronContractError("OpenClaw cron declarations still drift after reconciliation")
    return plan


def legacy_jobs(path: Path) -> list[Any]:
    if not path.name.endswith("jobs.json.migrated"):
        raise CronContractError("legacy adapter input must be named jobs.json.migrated")
    try:
        root = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CronContractError(f"cannot read legacy jobs {path}: {error}") from error
    if isinstance(root, dict):
        jobs = root.get("jobs")
    else:
        jobs = root
    if not isinstance(jobs, list):
        raise CronContractError("legacy jobs.json.migrated must contain a jobs list")
    normalized: list[Any] = []
    for index, raw in enumerate(jobs):
        job = dict(_object(raw, f"legacy jobs[{index}]"))
        schedule = job.get("schedule")
        if isinstance(schedule, dict) and schedule.get("kind") == "cron" and "expr" not in schedule:
            schedule = dict(schedule)
            if isinstance(schedule.get("cron"), str):
                schedule["expr"] = schedule.pop("cron")
            job["schedule"] = schedule
        if isinstance(schedule, dict) and schedule.get("tz") == "":
            schedule = dict(schedule)
            schedule.pop("tz")
            job["schedule"] = schedule
        if "delivery" not in job:
            delivery: dict[str, Any] = {}
            for old, new in (
                ("deliveryMode", "mode"),
                ("channel", "channel"),
                ("to", "to"),
                ("threadId", "threadId"),
                ("accountId", "accountId"),
                ("bestEffortDeliver", "bestEffort"),
            ):
                if old in job:
                    delivery[new] = job[old]
            if delivery:
                delivery.setdefault("mode", "announce")
                job["delivery"] = delivery
        normalized.append(job)
    return normalized


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openclaw-bin", default=os.environ.get("OPENCLAW_BIN", "openclaw"))
    parser.add_argument("--openclaw-helper", type=Path)
    parser.add_argument("--openclaw-contract", type=Path)
    parser.add_argument("--home", type=Path, default=Path.home())
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser("export", help="Export live logical declarations")
    export_parser.add_argument("--output", type=Path, required=True)

    import_parser = subparsers.add_parser("import", help="Reconcile a logical snapshot")
    import_parser.add_argument("--input", type=Path, required=True)
    import_parser.add_argument("--dry-run", action="store_true")
    import_parser.add_argument("--no-prune-managed", action="store_true")

    adapt_parser = subparsers.add_parser(
        "adapt-legacy", help="Convert a legacy jobs.json.migrated file to v2"
    )
    adapt_parser.add_argument("--input", type=Path, required=True)
    adapt_parser.add_argument("--output", type=Path, required=True)

    verify_parser = subparsers.add_parser("verify", help="Compare live jobs with a snapshot")
    verify_parser.add_argument("--input", type=Path, required=True)
    verify_parser.add_argument("--no-prune-managed", action="store_true")

    args = parser.parse_args(argv)
    try:
        home = args.home.expanduser()
        if not home.is_absolute():
            raise CronContractError("--home must be absolute")
        if args.command == "adapt-legacy":
            snapshot = make_snapshot(
                legacy_jobs(args.input), home=home, inject_canary=True
            )
            changed = write_snapshot(args.output, snapshot)
            print(
                f"OpenClaw cron v2: {'wrote' if changed else 'current'}: "
                f"{args.output} ({len(snapshot['jobs'])} jobs)"
            )
            return 0

        cli = OpenClawCLI(
            args.openclaw_bin,
            home,
            exact_helper=args.openclaw_helper,
            exact_contract=args.openclaw_contract,
        )
        if args.command == "export":
            snapshot = make_snapshot(get_full_jobs(cli), home=home)
            changed = write_snapshot(args.output, snapshot)
            print(
                f"OpenClaw cron v2: {'wrote' if changed else 'current'}: "
                f"{args.output} ({len(snapshot['jobs'])} jobs)"
            )
            return 0

        snapshot = materialize_snapshot(load_snapshot(args.input), home)
        prune = not args.no_prune_managed
        if args.command == "verify" or args.dry_run:
            plan = plan_reconcile(snapshot, get_full_jobs(cli), prune)
            drift = bool(plan["create"] or plan["update"] or plan["remove"])
            label = "drift" if drift else "current"
            suffix = " (dry-run; OpenClaw unchanged)" if getattr(args, "dry_run", False) else ""
            print(
                f"OpenClaw cron v2: {label}: create={len(plan['create'])} "
                f"update={len(plan['update'])} remove={len(plan['remove'])}{suffix}"
            )
            return 1 if args.command == "verify" and drift else 0

        plan = reconcile(cli, snapshot, prune)
        print(
            f"OpenClaw cron v2: reconciled: create={len(plan['create'])} "
            f"update={len(plan['update'])} remove={len(plan['remove'])}"
        )
        return 0
    except CronContractError as error:
        print(f"OpenClaw cron v2: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
