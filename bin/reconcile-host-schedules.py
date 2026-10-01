#!/usr/bin/env python3
"""Reconcile declarative host schedules without owning unrelated crontab lines."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


SCHEMA = "coding-system.schedules/v1"
BEGIN = "# >>> coding-system schedules v1 >>>"
END = "# <<< coding-system schedules v1 <<<"
LEGACY_BEGIN = "# >>> coding-system >>>"
LEGACY_END = "# <<< coding-system <<<"
# Lines the owner added by hand are private: they live in the owner's private
# schedule file, which the recovery set carries, and render as their own block.
PRIVATE_BEGIN = "# >>> coding-system private schedules >>>"
PRIVATE_END = "# <<< coding-system private schedules <<<"
DEFAULT_PRIVATE_FILE = Path(".config/coding-system/host-schedules.private.cron")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]+\.timer$")
# Personal schedule values stay out of the repository: a declaration names them
# as ${SETTING} and they are read from these owner settings (~/.secrets.env).
OWNER_VALUE_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
OWNER_SCHEDULE_SETTINGS = frozenset({"CSR_OWNER_TIMEZONE", "CSR_RSS_DIGEST_ONCALENDAR"})
# Scheduled code runs through the repository selector, which the installer points
# at the immutable repository generation it verified; never through the mutable
# checkout.
REPOSITORY_SELECTOR = ".local/share/coding-system/repository"
REPOSITORY_COMMAND_RE = re.compile(
    r"(?P<prefix>\S*/(?:coding-system-rebuild|\.local/share/coding-system/repository)/)"
    r"(?P<relative>[A-Za-z0-9._/-]+)"
)
# A declared systemd schedule is written as this drop-in of its timer: component
# installers rewrite the timer unit itself but leave its drop-in directory alone.
DROPIN_NAME = "90-coding-system-schedule.conf"
TIMER_CALENDAR_RE = re.compile(r"OnCalendar=(.*?) ; next_elapse=")


class ScheduleError(ValueError):
    """Invalid declaration or unsafe live state."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScheduleError(f"{label} must be an object")
    return value


def _one_line(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\n" in value or "\r" in value:
        raise ScheduleError(f"{label} must be a non-empty single line")
    return value


def _owner_setting(name: str) -> str:
    """An owner setting from the environment, else from ~/.secrets.env (install runs
    outside a login shell, where the settings are not exported)."""
    value = os.environ.get(name, "")
    if value:
        return value
    sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
    try:
        from owner_settings import OwnerSettingsError, read_owner_settings
    finally:
        sys.path.pop(0)
    try:
        return read_owner_settings(Path(os.environ.get("HOME", "~")).expanduser() / ".secrets.env").get(name, "")
    except OwnerSettingsError as error:
        raise ScheduleError("the owner settings file is invalid") from error


def _owner_value(value: Any, label: str, expand: bool = True) -> Any:
    """Expand ${SETTING} from the allowlisted owner settings; unset fails closed."""
    if not isinstance(value, str) or not expand:
        return value

    def expand(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in OWNER_SCHEDULE_SETTINGS:
            raise ScheduleError(f"{label} names an unknown owner setting: {name}")
        setting = _owner_setting(name)
        if not setting:
            raise ScheduleError(f"{label} needs the owner setting {name}, which is not set")
        return setting

    return OWNER_VALUE_RE.sub(expand, value)


def _timezone(value: Any, label: str) -> str:
    timezone = _one_line(value, label)
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise ScheduleError(f"{label} is not an installed IANA timezone: {timezone}") from error
    return timezone


def load_declaration(path: Path, owner_values: bool = True) -> dict[str, Any]:
    try:
        root = _object(json.loads(path.read_text(encoding="utf-8")), "schedule declaration")
    except (OSError, json.JSONDecodeError) as error:
        raise ScheduleError(f"cannot read schedule declaration {path}: {error}") from error
    if root.get("schema") != SCHEMA:
        raise ScheduleError(f"schedule declaration schema must be {SCHEMA}")
    if set(root) != {"schema", "jobs"}:
        raise ScheduleError("schedule declaration has unknown top-level fields")
    jobs = root.get("jobs")
    if not isinstance(jobs, list) or not jobs:
        raise ScheduleError("schedule declaration jobs must be a non-empty list")

    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, raw_job in enumerate(jobs):
        job = _object(raw_job, f"jobs[{index}]")
        identifier = _one_line(job.get("id"), f"jobs[{index}].id")
        if not ID_RE.fullmatch(identifier):
            raise ScheduleError(f"invalid stable schedule id: {identifier}")
        if identifier in seen:
            raise ScheduleError(f"duplicate stable schedule id: {identifier}")
        seen.add(identifier)
        backend = job.get("backend")
        if backend not in {"cron", "systemd"}:
            raise ScheduleError(f"{identifier}: backend must be cron or systemd")
        raw_timezone = _owner_value(job.get("timezone"), f"{identifier}.timezone", owner_values)
        timezone = (
            _timezone(raw_timezone, f"{identifier}.timezone")
            if owner_values or not OWNER_VALUE_RE.search(str(raw_timezone))
            else _one_line(raw_timezone, f"{identifier}.timezone")
        )
        policy = job.get("missedRunPolicy")
        if policy not in {"skip", "catch-up-once"}:
            raise ScheduleError(
                f"{identifier}: missedRunPolicy must be skip or catch-up-once"
            )
        schedule = _one_line(
            _owner_value(job.get("schedule"), f"{identifier}.schedule", owner_values),
            f"{identifier}.schedule",
        )
        legacy = job.get("legacyCronLines", [])
        if not isinstance(legacy, list):
            raise ScheduleError(f"{identifier}.legacyCronLines must be a list")
        legacy_lines = [
            _one_line(item, f"{identifier}.legacyCronLines") for item in legacy
        ]

        allowed = {
            "id",
            "backend",
            "schedule",
            "timezone",
            "missedRunPolicy",
            "legacyCronLines",
        }
        normalized_job: dict[str, Any] = {
            "id": identifier,
            "backend": backend,
            "schedule": schedule,
            "timezone": timezone,
            "missedRunPolicy": policy,
            "legacyCronLines": legacy_lines,
        }
        if backend == "cron":
            allowed.add("command")
            command = _one_line(job.get("command"), f"{identifier}.command")
            if len(schedule.split()) != 5:
                raise ScheduleError(f"{identifier}: cron schedule must have five fields")
            if policy != "skip":
                raise ScheduleError(
                    f"{identifier}: classic cron only supports missedRunPolicy=skip"
                )
            normalized_job["command"] = command
        else:
            allowed.add("timerUnit")
            unit = _one_line(job.get("timerUnit"), f"{identifier}.timerUnit")
            if not UNIT_RE.fullmatch(unit) or "/" in unit:
                raise ScheduleError(f"{identifier}: invalid systemd timer unit: {unit}")
            normalized_job["timerUnit"] = unit
        unknown = set(job) - allowed
        if unknown:
            raise ScheduleError(
                f"{identifier}: unknown fields: {', '.join(sorted(unknown))}"
            )
        normalized.append(normalized_job)
    return {"schema": SCHEMA, "jobs": normalized}


def substitute_home(value: str, home: Path) -> str:
    rendered = value.replace("{{ HOME }}", str(home))
    if "{{" in rendered or "}}" in rendered:
        raise ScheduleError("unresolved placeholder in schedule declaration")
    return rendered


def validate_repository_commands(
    declaration: dict[str, Any], home: Path, repository: Path
) -> None:
    """Require every declared repository command to be a real executable.

    The crontab contains the installed-home spelling, while verification may
    run against another fixture home.  Resolve only the bounded relative path
    beneath this authenticated repository; never execute a declaration while
    validating it.
    """
    expected_prefix = f"{home}/{REPOSITORY_SELECTOR}/"
    for job in declaration["jobs"]:
        if job["backend"] != "cron":
            continue
        rendered = substitute_home(job["command"], home)
        if f"{home}/coding-system-rebuild/" in rendered:
            raise ScheduleError(
                f"{job['id']}: runs code from the mutable checkout instead of the repository selector"
            )
        if expected_prefix not in rendered:
            continue
        matches = list(REPOSITORY_COMMAND_RE.finditer(rendered))
        if not matches:
            raise ScheduleError(f"{job['id']}: cannot resolve repository command")
        for match in matches:
            if match.group("prefix") != expected_prefix:
                raise ScheduleError(f"{job['id']}: repository command prefix is unsafe")
            relative = match.group("relative")
            candidate = repository / relative
            try:
                candidate.relative_to(repository)
                info = candidate.lstat()
            except (OSError, ValueError) as error:
                raise ScheduleError(
                    f"{job['id']}: scheduled repository target is unavailable: {relative}"
                ) from error
            if (
                candidate.is_symlink()
                or not candidate.is_file()
                or info.st_nlink != 1
                or not info.st_mode & 0o111
            ):
                raise ScheduleError(
                    f"{job['id']}: scheduled repository target is not a single-link executable: {relative}"
                )


def render_managed_block(declaration: dict[str, Any], home: Path) -> str:
    lines = [BEGIN, "# Generated from system/schedules/host.v1.json; do not edit."]
    for job in declaration["jobs"]:
        if job["backend"] != "cron":
            continue
        identifier = job["id"]
        lines.extend(
            [
                f"# schedule-id: {identifier}; missed-run={job['missedRunPolicy']}",
                f"CRON_TZ={job['timezone']}",
                f"{job['schedule']} {substitute_home(job['command'], home)}",
            ]
        )
    lines.append(END)
    return "\n".join(lines) + "\n"


def render_timer_dropin(job: dict[str, Any]) -> str:
    """The drop-in that replaces every trigger of a declared systemd timer.

    An empty OnCalendar= or monotonic assignment clears what the unit declares,
    so the one declared calendar is the timer's only trigger.
    """
    schedule = job["schedule"]
    if "%" in schedule or "\\" in schedule:
        raise ScheduleError(
            f"{job['id']}: a systemd schedule must not contain % or a backslash"
        )
    persistent = "true" if job["missedRunPolicy"] == "catch-up-once" else "false"
    return (
        "# Generated from system/schedules/host.v1.json "
        f"(schedule-id: {job['id']}); do not edit.\n"
        "[Timer]\n"
        "OnCalendar=\n"
        "OnBootSec=\n"
        "OnUnitActiveSec=\n"
        f"OnCalendar={schedule}\n"
        f"Persistent={persistent}\n"
    )


def timer_dropin_path(home: Path, job: dict[str, Any]) -> Path:
    return home / ".config/systemd/user" / f"{job['timerUnit']}.d" / DROPIN_NAME


def _read_dropin(path: Path) -> str | None:
    if path.parent.is_symlink() or path.is_symlink():
        raise ScheduleError(f"refusing a symlinked timer drop-in: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def _write_dropin(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=".schedule.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _run_tool(command: list[str], label: str) -> str:
    result = subprocess.run(
        command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        raise ScheduleError(f"{label} failed with exit {result.returncode}")
    return result.stdout


def normalized_calendar(analyze: str, job: dict[str, Any]) -> str:
    output = _run_tool([analyze, "calendar", job["schedule"]], f"{job['id']}: systemd-analyze calendar")
    for line in output.splitlines():
        label, _, value = line.strip().partition(":")
        if label == "Normalized form":
            return value.strip()
    raise ScheduleError(f"{job['id']}: systemd-analyze printed no normalized calendar")


def timer_matches(systemctl: str, analyze: str, home: Path, job: dict[str, Any]) -> bool:
    """Whether the loaded timer has exactly the declared calendar and our drop-in."""
    output = _run_tool(
        [systemctl, "--user", "show", "-p", "TimersCalendar", "-p", "TimersMonotonic",
         "-p", "DropInPaths", job["timerUnit"]],
        f"{job['id']}: systemctl show",
    )
    calendars: list[str] = []
    monotonic = ""
    dropins: list[str] = []
    for line in output.splitlines():
        key, _, value = line.partition("=")
        if key == "TimersCalendar":
            calendars.extend(TIMER_CALENDAR_RE.findall(value))
        elif key == "TimersMonotonic":
            monotonic += value.strip()
        elif key == "DropInPaths":
            dropins.extend(value.split())
    return (
        calendars == [normalized_calendar(analyze, job)]
        and not monotonic
        and str(timer_dropin_path(home, job)) in dropins
    )


def reconcile_timers(
    declaration: dict[str, Any], home: Path, *, mode: str, systemctl: str, analyze: str
) -> int:
    jobs = [job for job in declaration["jobs"] if job["backend"] == "systemd"]
    rendered = {job["id"]: render_timer_dropin(job) for job in jobs}
    stale = [
        job for job in jobs if _read_dropin(timer_dropin_path(home, job)) != rendered[job["id"]]
    ]
    if mode == "dry-run":
        print("host timers: drift (dry-run; drop-ins unchanged)" if stale else "host timers: current")
        return 0
    if mode == "verify":
        drifted = {job["id"] for job in stale}
        drifted.update(
            job["id"] for job in jobs if not timer_matches(systemctl, analyze, home, job)
        )
        if drifted:
            print("host timers: drift in " + ", ".join(sorted(drifted)) + " (verification only)")
            return 1
        print("host timers: current")
        return 0
    for job in stale:
        normalized_calendar(analyze, job)
    for job in stale:
        _write_dropin(timer_dropin_path(home, job), rendered[job["id"]])
    if stale:
        _run_tool([systemctl, "--user", "daemon-reload"], "systemctl daemon-reload")
        print("host timers: reconciled")
    else:
        print("host timers: current")
    return 0


def legacy_cron_lines(declaration: dict[str, Any], home: Path) -> set[str]:
    result: set[str] = set()
    for job in declaration["jobs"]:
        if job["backend"] == "cron":
            result.add(f"{job['schedule']} {substitute_home(job['command'], home)}")
        result.update(substitute_home(item, home) for item in job["legacyCronLines"])
    return result


def _cron_parts(line: str) -> tuple[str, str] | None:
    """Return the five-field schedule and command for a classic cron line."""

    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" in stripped.split(maxsplit=1)[0]:
        return None
    parts = stripped.split(maxsplit=5)
    if len(parts) != 6:
        return None
    return " ".join(parts[:5]), parts[5]


def _managed_command_anchors(command: str, home: Path) -> frozenset[str]:
    """Extract only path identities distinctive to repository-owned jobs."""

    escaped_home = re.escape(str(home))
    paths = re.findall(
        rf"{escaped_home}/(?:coding-system-rebuild|\.local/share/coding-system/repository|"
        rf"\.openclaw/workspace-(?:sanitizer|moltbook))/[A-Za-z0-9_.*$/-]+",
        command,
    )
    anchors = set(paths)
    stress_identity = "/usr/bin/stress --cpu 1 --timeout 240"
    if stress_identity in command:
        anchors.add(stress_identity)
    return frozenset(anchors)


def _legacy_claim_contract(
    declaration: dict[str, Any], home: Path
) -> tuple[set[str], dict[str, str], dict[str, str]]:
    """Build exact claims plus bounded identities used to reject near-matches."""

    exact: dict[str, str] = {}
    commands: dict[str, str] = {}
    anchors: dict[str, str] = {}
    for job in declaration["jobs"]:
        lines = [substitute_home(item, home) for item in job["legacyCronLines"]]
        if job["backend"] == "cron":
            lines.append(
                f"{job['schedule']} {substitute_home(job['command'], home)}"
            )
        for line in lines:
            previous = exact.get(line)
            if previous is not None and previous != job["id"]:
                raise ScheduleError(
                    "one legacy cron line is claimed by multiple schedule declarations"
                )
            exact[line] = job["id"]
            parsed = _cron_parts(line)
            if parsed is None:
                raise ScheduleError(f"{job['id']}: legacy cron line is not five-field cron")
            _schedule, command = parsed
            command_owner = commands.get(command)
            if command_owner is not None and command_owner != job["id"]:
                raise ScheduleError(
                    "one legacy cron command is claimed by multiple schedule declarations"
                )
            commands[command] = job["id"]
            for anchor in _managed_command_anchors(command, home):
                anchor_owner = anchors.get(anchor)
                if anchor_owner is not None and anchor_owner != job["id"]:
                    raise ScheduleError(
                        "one managed cron identity is claimed by multiple declarations"
                    )
                anchors[anchor] = job["id"]
    return set(exact), commands, anchors


def _private_lines(private: str, home: Path) -> list[str]:
    return [substitute_home(line, home) for line in private.splitlines() if line.strip()]


def render_private_block(private: str, home: Path) -> str:
    lines = _private_lines(private, home)
    if not lines:
        return ""
    return "\n".join(
        [PRIVATE_BEGIN, "# Restored from the owner's private schedule file; do not edit here.",
         *lines, PRIVATE_END]
    ) + "\n"


def reconcile_text(
    current: str, declaration: dict[str, Any], home: Path, private: str = ""
) -> str:
    """Return the desired crontab while preserving unrelated lines verbatim."""
    managed_pairs = {BEGIN: END, LEGACY_BEGIN: LEGACY_END, PRIVATE_BEGIN: PRIVATE_END}
    claimed_private = set(_private_lines(private, home))
    retained: list[str] = []
    active_end: str | None = None
    found_blocks: dict[str, int] = {BEGIN: 0, LEGACY_BEGIN: 0, PRIVATE_BEGIN: 0}
    legacy, managed_commands, managed_anchors = _legacy_claim_contract(
        declaration, home
    )

    for line in current.splitlines(keepends=True):
        bare = line.rstrip("\r\n")
        marker = bare.strip()
        if active_end is not None:
            if marker == active_end:
                active_end = None
            elif marker in managed_pairs:
                raise ScheduleError("nested coding-system crontab marker block")
            elif marker in {END, LEGACY_END, PRIVATE_END}:
                raise ScheduleError("mismatched coding-system crontab end marker")
            continue
        if marker in managed_pairs:
            active_end = managed_pairs[marker]
            found_blocks[marker] += 1
            if found_blocks[marker] > 1:
                raise ScheduleError("duplicate coding-system crontab marker block")
            continue
        if marker in {END, LEGACY_END, PRIVATE_END}:
            raise ScheduleError("unmatched coding-system crontab end marker")
        if bare in legacy or bare in claimed_private:
            continue
        parsed = _cron_parts(bare)
        if parsed is not None:
            _schedule, command = parsed
            if command in managed_commands:
                raise ScheduleError(
                    "conflicting near-match for a managed cron command outside its block"
                )
            observed_anchors = _managed_command_anchors(command, home)
            if observed_anchors.intersection(managed_anchors):
                raise ScheduleError(
                    "ambiguous managed cron identity outside its block"
                )
        retained.append(line)
    if active_end is not None:
        raise ScheduleError("unterminated coding-system crontab marker block")

    prefix = "".join(retained)
    if prefix and not prefix.endswith("\n"):
        prefix += "\n"
    if prefix and not prefix.endswith("\n\n"):
        prefix += "\n"
    return prefix + render_managed_block(declaration, home) + render_private_block(private, home)


def adopt_unmanaged(current: str, private: str, declaration: dict[str, Any], home: Path) -> str:
    """Add every hand-added crontab line to the private schedule text, home-relative.

    Lines in managed blocks or claimed by a declaration are not adopted, and the
    private text keeps its order; adoption never changes the crontab itself.
    """
    retained = reconcile_text(current, declaration, home, private=private).split(BEGIN, 1)[0]
    lines = [line for line in private.splitlines() if line.strip()]
    home_prefix = f"{home}/"
    for raw in retained.splitlines():
        if not raw.strip():
            continue
        line = raw.replace(home_prefix, "{{ HOME }}/")
        if line not in lines:
            lines.append(line)
    return "".join(f"{line}\n" for line in lines)


def public_block(current: str) -> str:
    """The public managed block of a crontab, for the repository's template."""
    lines: list[str] = []
    inside = False
    for raw in current.splitlines():
        marker = raw.strip()
        if marker == BEGIN:
            inside = True
        if inside:
            lines.append(raw)
        if marker == END:
            inside = False
    return "".join(f"{line}\n" for line in lines)


def read_crontab(command: str) -> str:
    result = subprocess.run(
        [command, "-l"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        return result.stdout
    combined = f"{result.stdout}\n{result.stderr}".lower()
    if result.returncode == 1 and "no crontab" in combined:
        return ""
    raise ScheduleError(
        f"{command} -l failed with exit {result.returncode}: {result.stderr.strip()}"
    )


def install_crontab(command: str, desired: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix="coding-system-crontab.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(desired)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        result = subprocess.run(
            [command, temporary_name],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            raise ScheduleError(
                f"{command} install failed with exit {result.returncode}: "
                f"{result.stderr.strip()}"
            )
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--declaration",
        type=Path,
        default=root / "system/schedules/host.v1.json",
    )
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--crontab-bin", default=os.environ.get("CRONTAB_BIN", "crontab"))
    parser.add_argument(
        "--scope",
        choices=("cron", "systemd"),
        default="cron",
        help="cron reconciles the managed crontab block; systemd writes timer drop-ins",
    )
    parser.add_argument("--systemctl-bin", default="/usr/bin/systemctl")
    parser.add_argument("--systemd-analyze-bin", default="/usr/bin/systemd-analyze")
    parser.add_argument(
        "--private-file",
        type=Path,
        help="the owner's private schedule lines (default ~/" + str(DEFAULT_PRIVATE_FILE) + ")",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument(
        "--verify",
        action="store_true",
        help="Return 1 on drift without changing the crontab",
    )
    mode.add_argument(
        "--adopt-unmanaged",
        action="store_true",
        help="copy hand-added crontab lines into the private schedule file; the crontab is unchanged",
    )
    mode.add_argument(
        "--public-block",
        action="store_true",
        help="print the public managed block of the current crontab",
    )
    args = parser.parse_args(argv)
    try:
        home = args.home.expanduser()
        if not home.is_absolute():
            raise ScheduleError("--home must be absolute")
        private_file = args.private_file or home / DEFAULT_PRIVATE_FILE
        if args.public_block or args.adopt_unmanaged:
            command = args.crontab_bin
            if "/" not in command:
                command = shutil.which(command) or ""
            if not command or not os.access(command, os.X_OK):
                raise ScheduleError(f"crontab executable not found: {args.crontab_bin}")
            current = read_crontab(command)
            if args.public_block:
                sys.stdout.write(public_block(current))
                return 0
            declaration = load_declaration(args.declaration, owner_values=False)
            private = private_file.read_text(encoding="utf-8") if private_file.is_file() else ""
            adopted = adopt_unmanaged(current, private, declaration, home)
            if adopted != private:
                private_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                temporary = private_file.with_name(f".{private_file.name}.{os.getpid()}")
                temporary.write_text(adopted, encoding="utf-8")
                os.chmod(temporary, 0o600)
                os.replace(temporary, private_file)
            print(f"host schedules: {len(adopted.splitlines())} private line(s) kept")
            return 0
        declaration = load_declaration(args.declaration)
        if args.scope == "systemd":
            mode = "verify" if args.verify else "dry-run" if args.dry_run else "apply"
            return reconcile_timers(
                declaration,
                home,
                mode=mode,
                systemctl=args.systemctl_bin,
                analyze=args.systemd_analyze_bin,
            )
        validate_repository_commands(declaration, home, root)
        command = args.crontab_bin
        if "/" not in command:
            command = shutil.which(command) or ""
        if not command or not os.access(command, os.X_OK):
            raise ScheduleError(f"crontab executable not found: {args.crontab_bin}")
        current = read_crontab(command)
        private = private_file.read_text(encoding="utf-8") if private_file.is_file() else ""
        desired = reconcile_text(current, declaration, home, private=private)
        if current == desired:
            print("host schedules: current")
            return 0
        if args.verify:
            print("host schedules: drift (verification only; crontab unchanged)")
            return 1
        if args.dry_run:
            print("host schedules: drift (dry-run; crontab unchanged)")
            return 0
        install_crontab(command, desired)
        print("host schedules: reconciled")
        return 0
    except ScheduleError as error:
        print(f"host schedules: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
