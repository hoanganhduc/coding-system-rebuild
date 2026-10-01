#!/usr/bin/env python3
"""Verify the non-secret Classroom50 restore closure and readiness state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile

LIB = Path(__file__).resolve().parent / "lib"
if os.fspath(LIB) not in sys.path:
    sys.path.insert(0, os.fspath(LIB))
from component_paths import ComponentPathError, resolve_component_path  # noqa: E402
from owner_settings import OwnerSettingsError, read_owner_settings  # noqa: E402


ARCHITECTURES = {
    "aarch64": "arm64",
    "arm64": "arm64",
    "x86_64": "amd64",
    "amd64": "amd64",
}
EXPECTED_COMPONENT_URL = "https://github.com/hoanganhduc/course_management_toolkit.git"
EXPECTED_COMPONENT_COMMIT = "5e402db40db6c4a50d9c9292a5b352e62447ab04"
# gh-teacher is pinned once, in the platform lock, to a foundation50 release;
# backups move that pin to the version installed on the host.
TEACHER_RELEASES = "https://github.com/foundation50/gh-teacher/releases/download/"
STATUS_PRIORITY = {"PASS": 0, "NOT_CONFIGURED": 1, "REAUTH_REQUIRED": 2, "TECHNICAL_FAIL": 3}
# The OpenClaw sandbox embeds the course-management closure from this contract on;
# the locked image may still be older (D14 defers the upgrade).
COURSE_RUNTIME_SANDBOX_CONTRACT = 3
ORG = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
OPENCLAW_MAIN_SELECTOR_VALUES = {
    "AAS_COMPUTE_SECRETS_FILE": "/workspace/.config/ai-agents-skills/compute.env",
    "AAS_PROVIDER_SECRETS_FILE": "/workspace/.config/ai-agents-skills/providers.env",
    "GOOGLE_CLASSROOM_CREDENTIALS": (
        "/workspace/.config/course/google-classroom/credentials.json"
    ),
    "GOOGLE_CLASSROOM_TOKEN": "/workspace/.config/course/google-classroom/token.pickle",
    "CANVAS_CONFIG_PATH": "/workspace/.config/course/canvas/config.json",
    "GETSCIPAPERS_CONFIG_DIR": "/workspace/.config/getscipapers",
    "GETSCIPAPERS_SKILL_CONFIG": (
        "/workspace/data/research/getscipapers_bot/state/config.json"
    ),
    "GH_CONFIG_DIR": "/workspace/.config/gh",
}
OPENCLAW_RETIRED_SELECTOR_KEYS = frozenset(
    {
        "AAS_SECRETS_FILE",
        "OPENCLAW_SECRETS_FILE",
        "AAS_CALIBRE_SECRETS_FILE",
        "AAS_SKILL_SECRETS_FILE",
        "AAS_AXLE_SECRETS_FILE",
        "AAS_LEANEXPLORE_SECRETS_FILE",
        "AAS_RESEARCH_DIGEST_SECRETS_FILE",
        "AAS_SUBMISSION_VENUE_SECRETS_FILE",
        "AAS_ZOTERO_SKILL_SECRETS_FILE",
        "AAS_ZOTERO_SECRETS_FILE",
        "AAS_FILE_DELIVERY_SECRETS_FILE",
        "REMOTE_BRIDGE_SECRETS_FILE",
        "SEND_EMAIL_SECRETS_FILE",
    }
)
OPENCLAW_MANAGED_SELECTOR_KEYS = frozenset(
    (
        *OPENCLAW_MAIN_SELECTOR_VALUES,
        *OPENCLAW_RETIRED_SELECTOR_KEYS,
        "CLASSROOM50_ORG_ALLOWLIST",
    )
)
CLASSROOM50_SKILL_PATHS = {
    "codex": ".codex/skills/classroom50/SKILL.md",
    "claude": ".claude/skills/classroom50/SKILL.md",
    "deepseek": ".deepseek/skills/classroom50/SKILL.md",
    "copilot": ".copilot/skills/classroom50/SKILL.md",
    "opencode": ".config/opencode/skills/classroom50/SKILL.md",
    "antigravity": ".gemini/antigravity-cli/skills/classroom50.md",
    "grok": ".grok/skills/classroom50/SKILL.md",
    "kimi": ".kimi-code/skills/classroom50/SKILL.md",
    "openclaw": ".openclaw/skills/classroom50/SKILL.md",
}
# The pinned ai-agents-skills tree, sealed by the owner (never root), relative to home.
AAS_COMPONENT_ROOT = Path(".local/share/coding-system/components/ai-agents-skills")


class VerificationError(RuntimeError):
    """A Classroom50 technical closure check failed."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_bounded(command: list[str], *, timeout: int = 30) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=timeout,
            env={**os.environ, "NO_COLOR": "1", "TERM": "dumb", "GH_PROMPT_DISABLED": "1"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, type(exc).__name__
    output = result.stdout[:65536]
    return result.returncode, output.strip()


def component_pin(repository: Path) -> tuple[str, str]:
    lock = repository / "components.lock"
    prefix = "course_management_toolkit="
    matches = [line[len(prefix) :] for line in lock.read_text(encoding="utf-8").splitlines() if line.startswith(prefix)]
    if len(matches) != 1 or "@" not in matches[0]:
        raise VerificationError("components.lock must contain exactly one course_management_toolkit pin")
    url, commit = matches[0].rsplit("@", 1)
    if url != EXPECTED_COMPONENT_URL or commit != EXPECTED_COMPONENT_COMMIT:
        raise VerificationError("course_management_toolkit component authority differs from the reviewed pin")
    return url, commit


def aas_pin(repository: Path) -> str:
    prefix = "ai-agents-skills="
    matches = [
        line[len(prefix) :]
        for line in (repository / "components.lock").read_text(encoding="utf-8").splitlines()
        if line.startswith(prefix)
    ]
    if len(matches) != 1 or "@" not in matches[0]:
        raise VerificationError("components.lock must contain one ai-agents-skills pin")
    commit = matches[0].rsplit("@", 1)[1]
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise VerificationError("ai-agents-skills pin is not one full commit ID")
    return commit


def locked_teacher(repository: Path, architecture: str) -> dict[str, str]:
    """The gh-teacher release that the platform lock pins for one architecture."""
    platform_lock = json.loads(
        (repository / f"system/software/ubuntu-24.04-{architecture}.lock.json").read_text(encoding="utf-8")
    )
    artifacts = [item for item in platform_lock.get("artifacts", []) if item.get("id") == "gh-teacher"]
    if len(artifacts) != 1:
        raise VerificationError("platform lock must contain exactly one gh-teacher artifact")
    artifact = artifacts[0]
    version = artifact.get("version")
    if not isinstance(version, str) or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version) is None:
        raise VerificationError("gh-teacher lock version is invalid")
    if artifact.get("url") != f"{TEACHER_RELEASES}v{version}/gh-teacher_linux-{architecture}":
        raise VerificationError("gh-teacher version or release URL differs from the reviewed authority")
    if not isinstance(artifact.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]) is None:
        raise VerificationError("gh-teacher digest is invalid")
    floor = str(platform_lock.get("cli_versions", {}).get("gh-teacher", "")).removeprefix(">=")
    if floor != version:
        raise VerificationError("gh-teacher CLI version and artifact lock disagree")
    return artifact


def validate_declarations(repository: Path, architecture: str) -> list[str]:
    checks: list[str] = []
    component_pin(repository)
    checks.append("component-pin")
    locked_teacher(repository, architecture)
    checks.append("gh-teacher-lock")
    python_lock = json.loads(
        (repository / f"system/python-closure/ubuntu-24.04-{architecture}.lock.json").read_text(encoding="utf-8")
    )
    environment = python_lock.get("environments", {}).get("course-management")
    if not isinstance(environment, dict) or environment.get("installPath") != ".course_venv":
        raise VerificationError("Python closure does not route course-management to ~/.course_venv")
    checks.append("course-python-route")
    manifest_text = (repository / "secrets/secrets-manifest.yaml").read_text(encoding="utf-8")
    if "CLASSROOM50_ORG_ALLOWLIST" not in manifest_text:
        raise VerificationError("Classroom50 organization allowlist authority is undeclared")
    if re.search(
        r"^\s*(?:-\s*)?\{?[^#\n]*path:[^#\n]*CLASSROOM50_SERVICE_TOKEN",
        manifest_text,
        re.MULTILINE,
    ):
        raise VerificationError("CLASSROOM50_SERVICE_TOKEN must not be a global recovery authority")
    for projection_id in (
        "openclaw-github-cli-hosts-projection",
        "openclaw-github-cli-config-projection",
    ):
        if projection_id not in manifest_text:
            raise VerificationError("OpenClaw GitHub CLI projection authority is undeclared")
    checks.append("configuration-authority")
    install_text = (repository / "bin/install.sh").read_text(encoding="utf-8")
    if 'AAS_RESTORE_AGENTS="codex,claude,deepseek,copilot,opencode,antigravity,grok,kimi,chatgpt-local-coder"' not in install_text:
        raise VerificationError("normal AAS restore targets must be the exact nine non-OpenClaw agents")
    gate_commands = (
        "openclaw-target-probe",
        "openclaw-target-dry-run-manifest",
        "openclaw-target-approve-manifest",
        "openclaw-target-apply-manifest",
    )
    if any(command not in install_text for command in gate_commands):
        raise VerificationError("OpenClaw Classroom50 restore does not use the complete v2 target gate")
    if (
        '"$HOME/.openclaw/skills/$OPENCLAW_SKILL/SKILL.md"'
        not in install_text
    ):
        raise VerificationError("OpenClaw Classroom50 skill destination is undeclared")
    checks.append("nine-target-skill-routing")
    closure = json.loads(
        (repository / "system/openclaw/skill-closure.json").read_text(encoding="utf-8")
    )
    if "classroom50" not in closure.get("required_eligible_skills", []):
        raise VerificationError("OpenClaw exact skill closure omits Classroom50")
    checks.extend(validate_sandbox_course_runtime(repository))
    return checks


def sandbox_embeds_course_runtime(repository: Path) -> bool:
    lock = json.loads(
        (repository / "system/openclaw/compatibility.lock.json").read_text(encoding="utf-8")
    )
    contract = lock.get("sandbox", {}).get("contract")
    if not isinstance(contract, int) or isinstance(contract, bool) or contract < 1:
        raise VerificationError("OpenClaw sandbox contract lock is invalid")
    return contract >= COURSE_RUNTIME_SANDBOX_CONTRACT


def validate_sandbox_course_runtime(repository: Path) -> list[str]:
    if not sandbox_embeds_course_runtime(repository):
        return []
    dockerfile = (repository / "system/docker/openclaw-sandbox/Dockerfile").read_text(
        encoding="utf-8"
    )
    sandbox_verify = (repository / "system/docker/openclaw-sandbox/verify.sh").read_text(
        encoding="utf-8"
    )
    course_runtime = "/opt/coding-system/python-closure/course-management"
    if course_runtime not in dockerfile or course_runtime not in sandbox_verify:
        raise VerificationError("OpenClaw sandbox omits the course-management runtime")
    if "course_hoanganhduc.c50_agent --help" not in sandbox_verify:
        raise VerificationError("OpenClaw sandbox omits the Classroom50 adapter smoke")
    return ["openclaw-sandbox-course-runtime"]


def regular_executable(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not path.is_symlink() and os.access(path, os.X_OK)


def private_regular(path: Path) -> bool:
    try:
        information = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(information.st_mode)
        and not path.is_symlink()
        and information.st_uid == os.getuid()
        and information.st_nlink == 1
        and stat.S_IMODE(information.st_mode) == 0o600
    )


def allowlist_from_file(path: Path) -> str | None:
    try:
        return read_owner_settings(path).get("CLASSROOM50_ORG_ALLOWLIST")
    except OwnerSettingsError as exc:
        raise VerificationError(".secrets.env violates the owner-settings contract") from exc


def allowlist_status(home: Path) -> str:
    value = os.environ.get("CLASSROOM50_ORG_ALLOWLIST")
    if value is None:
        value = allowlist_from_file(home / ".secrets.env")
    if value is None or not value.strip():
        return "NOT_CONFIGURED"
    organizations = [item.strip() for item in value.split(",")]
    if not organizations or any(not item or not ORG.fullmatch(item) for item in organizations):
        raise VerificationError("CLASSROOM50_ORG_ALLOWLIST is not a valid comma-separated GitHub organization list")
    if len(organizations) != len(set(item.lower() for item in organizations)):
        raise VerificationError("CLASSROOM50_ORG_ALLOWLIST contains duplicate organizations")
    return "PASS"


def openclaw_main_environment(
    config: object, workspace: Path
) -> tuple[dict[str, object], dict[str, object]]:
    """Validate the main-only selector boundary and return its direct environment."""

    if not isinstance(config, dict):
        raise VerificationError("OpenClaw agent configuration is invalid")
    agents = config.get("agents")
    if not isinstance(agents, dict):
        raise VerificationError("OpenClaw agent configuration is invalid")
    defaults = agents.get("defaults")
    listed = agents.get("list")
    if not isinstance(defaults, dict) or not isinstance(listed, list):
        raise VerificationError("OpenClaw agent configuration is invalid")
    main_candidates = [
        agent
        for agent in listed
        if isinstance(agent, dict) and agent.get("id") == "main"
    ]
    if len(main_candidates) != 1:
        raise VerificationError("OpenClaw must define exactly one main agent")
    main = main_candidates[0]
    if main.get("workspace", defaults.get("workspace")) != str(workspace):
        raise VerificationError(
            "OpenClaw main workspace cannot reach credential projections"
        )

    try:
        default_docker = defaults["sandbox"]["docker"]
        default_environment = default_docker["env"]
    except (KeyError, TypeError) as exc:
        raise VerificationError(
            "OpenClaw default sandbox environment is unavailable"
        ) from exc
    if not isinstance(default_docker, dict) or not isinstance(default_environment, dict):
        raise VerificationError("OpenClaw default sandbox environment is unavailable")
    if OPENCLAW_MANAGED_SELECTOR_KEYS.intersection(default_environment):
        raise VerificationError(
            "OpenClaw default sandbox exposes managed credential selectors"
        )
    if default_environment.get("XDG_DATA_HOME") != "/workspace/.local-data":
        raise VerificationError(
            "OpenClaw sandbox does not select its isolated GitHub data root"
        )

    for agent in listed:
        if not isinstance(agent, dict):
            raise VerificationError("OpenClaw agent configuration is invalid")
        if agent is main:
            continue
        if agent.get("skills") != []:
            raise VerificationError("OpenClaw auxiliary agent advertises skills")
        sandbox = agent.get("sandbox")
        if sandbox is None:
            continue
        if not isinstance(sandbox, dict):
            raise VerificationError("OpenClaw auxiliary sandbox is invalid")
        docker = sandbox.get("docker")
        if docker is None:
            continue
        if not isinstance(docker, dict):
            raise VerificationError("OpenClaw auxiliary sandbox is invalid")
        environment = docker.get("env")
        if environment is None:
            continue
        if not isinstance(environment, dict):
            raise VerificationError("OpenClaw auxiliary sandbox is invalid")
        if OPENCLAW_MANAGED_SELECTOR_KEYS.intersection(environment):
            raise VerificationError(
                "OpenClaw auxiliary sandbox exposes managed credential selectors"
            )

    try:
        main_environment = main["sandbox"]["docker"]["env"]
    except (KeyError, TypeError) as exc:
        raise VerificationError("OpenClaw main sandbox environment is unavailable") from exc
    if not isinstance(main_environment, dict):
        raise VerificationError("OpenClaw main sandbox environment is unavailable")
    if OPENCLAW_RETIRED_SELECTOR_KEYS.intersection(main_environment):
        raise VerificationError(
            "OpenClaw main sandbox exposes a retired credential selector"
        )
    for key, expected in OPENCLAW_MAIN_SELECTOR_VALUES.items():
        if main_environment.get(key) != expected:
            raise VerificationError(
                f"OpenClaw main sandbox does not select its {key} authority"
            )
    return default_docker, main_environment


def verify_openclaw_projections(
    repository: Path, home: Path, architecture: str
) -> tuple[Path, str | None]:
    workspace = home / ".openclaw/workspace"
    try:
        workspace_information = workspace.lstat()
    except OSError as exc:
        raise VerificationError("OpenClaw workspace is unavailable") from exc
    if (
        workspace.is_symlink()
        or not stat.S_ISDIR(workspace_information.st_mode)
        or workspace_information.st_uid != os.getuid()
        or stat.S_IMODE(workspace_information.st_mode) & 0o022
    ):
        raise VerificationError("OpenClaw workspace is unsafe")

    host_teacher = home / ".local/share/gh/extensions/gh-teacher/gh-teacher"
    projected_teacher = workspace / ".local-data/gh/extensions/gh-teacher/gh-teacher"
    expected_digest = locked_teacher(repository, architecture)["sha256"]
    if (
        not regular_executable(host_teacher)
        or not regular_executable(projected_teacher)
        or sha256_file(host_teacher) != expected_digest
        or sha256_file(projected_teacher) != expected_digest
    ):
        raise VerificationError("OpenClaw teacher extension projection differs from its lock")

    for name in ("hosts.yml", "config.yml"):
        authority = home / ".config/gh" / name
        projection = workspace / ".config/gh" / name
        if authority.exists():
            if not private_regular(authority) or not private_regular(projection):
                raise VerificationError("OpenClaw GitHub CLI projection is unsafe")
            if authority.read_bytes() != projection.read_bytes():
                raise VerificationError("OpenClaw GitHub CLI projection differs from its authority")
        elif projection.exists():
            raise VerificationError("stale OpenClaw GitHub CLI projection remains")

    openclaw_config = home / ".openclaw/openclaw.json"
    try:
        config = json.loads(openclaw_config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError("OpenClaw agent configuration is unavailable") from exc
    default_docker, main_environment = openclaw_main_environment(config, workspace)
    if default_docker.get("user") != f"{os.getuid()}:{os.getgid()}":
        raise VerificationError("OpenClaw sandbox user does not own restored bind mounts")
    allowlist = allowlist_from_file(home / ".secrets.env")
    configured = main_environment.get("CLASSROOM50_ORG_ALLOWLIST")
    if allowlist is None:
        if configured is not None:
            raise VerificationError("OpenClaw sandbox retains a stale Classroom50 allowlist")
    elif configured != allowlist:
        raise VerificationError("OpenClaw sandbox Classroom50 allowlist differs from its authority")
    return workspace, allowlist


def verify_openclaw_sandbox(repository: Path, workspace: Path) -> None:
    docker = shutil.which("docker")
    if docker is None:
        raise VerificationError("Docker is unavailable for the OpenClaw Classroom50 smoke")
    lock = json.loads(
        (repository / "system/openclaw/compatibility.lock.json").read_text(encoding="utf-8")
    )
    image = lock.get("sandbox", {}).get("image")
    if not isinstance(image, str) or "@sha256:" not in image:
        raise VerificationError("OpenClaw sandbox image lock is invalid")
    smoke = (
        "/opt/coding-system/python-closure/course-management/bin/python -I -c "
        '"import importlib.metadata as m, course_hoanganhduc; '
        "assert m.version('course-hoanganhduc') == '0.4.0'" + '"\n'
        "/opt/coding-system/python-closure/course-management/bin/python -I "
        "-m course_hoanganhduc.c50_agent --help >/dev/null\n"
        "gh teacher --help >/dev/null\n"
    )
    command = [
        docker,
        "run",
        "--rm",
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--cpus",
        "1",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=64m",
        "--tmpfs",
        "/run:rw,nosuid,nodev,noexec,size=16m",
        "--mount",
        f"type=bind,src={workspace},dst=/workspace,readonly",
        "--env",
        "HOME=/workspace",
        "--env",
        "OPENCLAW_WORKSPACE=/workspace",
        "--env",
        "GH_CONFIG_DIR=/workspace/.config/gh",
        "--env",
        "XDG_DATA_HOME=/workspace/.local-data",
        image,
        "bash",
        "-euc",
        smoke,
    ]
    code, _output = run_bounded(command, timeout=120)
    if code != 0:
        raise VerificationError("OpenClaw Classroom50 sandbox smoke failed")


def _render_openclaw_skill(canonical: str) -> bytes:
    marker = "<!-- Managed by ai-agents-skills. Generated target: openclaw. -->"
    if "Managed by ai-agents-skills" in canonical:
        raise VerificationError("canonical Classroom50 skill unexpectedly contains a managed marker")
    if canonical.startswith("---\n"):
        end = canonical.find("\n---", 4)
        if end != -1:
            insert_at = end + len("\n---")
            return (canonical[:insert_at] + "\n\n" + marker + canonical[insert_at:]).encode()
    return (marker + "\n\n" + canonical).encode()


def _expected_openclaw_skill(repository: Path, home: Path) -> bytes:
    pin = aas_pin(repository)
    source = home / AAS_COMPONENT_ROOT / pin
    if not source.is_dir() or source.is_symlink():
        raise VerificationError("pinned ai-agents-skills source is unavailable")
    canonical = source / "canonical/skills/classroom50/SKILL.md"
    try:
        information = canonical.lstat()
        payload = canonical.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise VerificationError("pinned canonical Classroom50 skill is unavailable") from exc
    if canonical.is_symlink() or not stat.S_ISREG(information.st_mode):
        raise VerificationError("pinned canonical Classroom50 skill is unsafe")
    return _render_openclaw_skill(payload)


def verify_skill_targets(
    home: Path, *, expected_openclaw: bytes | None = None
) -> list[str]:
    missing_or_invalid: list[str] = []
    for agent, relative_path in CLASSROOM50_SKILL_PATHS.items():
        skill_path = home / relative_path
        try:
            payload = skill_path.read_bytes()
            content = payload.decode("utf-8")
        except (OSError, UnicodeError):
            missing_or_invalid.append(agent)
            continue
        if not skill_path.is_file() or not re.search(
            r"(?m)^name:\s*classroom50\s*$", content
        ):
            missing_or_invalid.append(agent)
            continue
        if agent == "openclaw":
            if (
                skill_path.is_symlink()
                or expected_openclaw is None
                or payload != expected_openclaw
            ):
                missing_or_invalid.append(agent)
    if missing_or_invalid:
        raise VerificationError(
            "Classroom50 skill is missing or invalid for: " + ", ".join(missing_or_invalid)
        )
    return list(CLASSROOM50_SKILL_PATHS)


def verify_runtime(repository: Path, home: Path, architecture: str) -> list[str]:
    checks: list[str] = []
    try:
        component = resolve_component_path(
            repository,
            home,
            "course_management_toolkit",
            source_fallback=True,
            require=True,
        )
    except ComponentPathError as exc:
        raise VerificationError(
            "course_management_toolkit checkout is missing or unsafe"
        ) from exc
    if component.is_symlink() or not (component / ".git").is_dir():
        raise VerificationError("course_management_toolkit checkout is missing or unsafe")
    code, output = run_bounded(["git", "-C", str(component), "rev-parse", "HEAD"])
    if code != 0 or output != EXPECTED_COMPONENT_COMMIT:
        raise VerificationError("course_management_toolkit checkout differs from components.lock")
    checks.append("component-checkout")

    teacher = home / ".local/share/gh/extensions/gh-teacher/gh-teacher"
    teacher_lock = locked_teacher(repository, architecture)
    if not regular_executable(teacher) or sha256_file(teacher) != teacher_lock["sha256"]:
        raise VerificationError("installed gh-teacher is missing, unsafe, or digest-mismatched")
    code, output = run_bounded([str(teacher), "--version"])
    if code != 0 or not output.startswith(f"gh-teacher version v{teacher_lock['version']} "):
        raise VerificationError("installed gh-teacher version probe differs from the lock")
    gh = shutil.which("gh")
    if gh is None:
        raise VerificationError("GitHub CLI is missing")
    code, output = run_bounded([gh, "teacher", "--version"])
    if code != 0 or not output.startswith(f"gh-teacher version v{teacher_lock['version']} "):
        raise VerificationError("GitHub CLI does not resolve the locked teacher extension")
    checks.append("gh-teacher-installed")

    course_venv = home / ".course_venv"
    generation_root = home / ".course_venv.generations"
    if not course_venv.is_symlink():
        raise VerificationError("~/.course_venv is not a managed Python closure link")
    try:
        course_venv.resolve(strict=True).relative_to(generation_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise VerificationError("~/.course_venv does not resolve to its managed generation store") from exc
    python = course_venv / "bin/python"
    course = course_venv / "bin/course"
    marker = course_venv / ".coding-system-python-closure.json"
    if not regular_executable(python) or not regular_executable(course) or not marker.is_file() or marker.is_symlink():
        raise VerificationError("managed Classroom50 Python runtime is incomplete or unsafe")
    code, output = run_bounded(
        [str(python), "-I", "-c", "import importlib.metadata as m; print(m.version('course-hoanganhduc'))"]
    )
    if code != 0 or output != "0.4.0":
        raise VerificationError("course-hoanganhduc installed version differs from the lock")
    code, _output = run_bounded([str(course), "--help"])
    if code != 0:
        raise VerificationError("course CLI smoke failed")
    checks.append("course-python-runtime")

    verify_skill_targets(home, expected_openclaw=_expected_openclaw_skill(repository, home))
    checks.append("classroom50-skills-nine-targets")
    workspace, _allowlist = verify_openclaw_projections(repository, home, architecture)
    checks.append("openclaw-classroom50-projections")
    if sandbox_embeds_course_runtime(repository):
        verify_openclaw_sandbox(repository, workspace)
        checks.append("openclaw-classroom50-sandbox")
    return checks


def worst_status(*statuses: str) -> str:
    return max(statuses, key=STATUS_PRIORITY.__getitem__)


def write_report(path: Path, report: dict[str, object]) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise VerificationError("Classroom50 report parent is unsafe")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise VerificationError("Classroom50 report destination is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
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
    architecture = args.architecture or ARCHITECTURES.get(platform.machine().lower())
    if architecture is None:
        print("classroom50: unsupported architecture", file=sys.stderr)
        return 2
    report: dict[str, object] = {
        "schema": "coding-system.classroom50-verification/v1",
        "profile": args.profile,
        "architecture": architecture,
        "technicalStatus": "PASS",
        "status": "PASS",
        "authentication": "REAUTH_REQUIRED",
        "orgAllowlist": "NOT_CONFIGURED",
        "checks": [],
    }
    try:
        report["checks"] = validate_declarations(args.repository.resolve(), architecture)
        if args.profile == "full":
            report["checks"] = report["checks"] + verify_runtime(  # type: ignore[operator]
                args.repository.resolve(), args.home.expanduser().absolute(), architecture
            )
            gh = shutil.which("gh")
            authentication = "REAUTH_REQUIRED"
            if gh is not None and run_bounded([gh, "auth", "status", "--hostname", "github.com"])[0] == 0:
                authentication = "PASS"
            report["authentication"] = authentication
            report["orgAllowlist"] = allowlist_status(args.home.expanduser().absolute())
        report["status"] = worst_status(str(report["authentication"]), str(report["orgAllowlist"]))
    except (VerificationError, OSError, json.JSONDecodeError) as exc:
        report["technicalStatus"] = "TECHNICAL_FAIL"
        report["status"] = "TECHNICAL_FAIL"
        report["error"] = str(exc)
    if args.output:
        try:
            write_report(args.output, report)
        except (VerificationError, OSError) as exc:
            print(f"classroom50: {exc}", file=sys.stderr)
            return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["technicalStatus"] != "PASS":
        return 2
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
