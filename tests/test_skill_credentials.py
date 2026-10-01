#!/usr/bin/env python3
"""Synthetic, no-network tests for skill credential restore closure."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
# The compatibility checkout sits beside the repository on the reference host
# and in $HOME on a fresh one (bin/components.sh).
AAS_CHECKOUT = next(
    (path for path in (ROOT.parent / "ai-agents-skills", Path.home() / "ai-agents-skills") if path.is_dir()),
    ROOT.parent / "ai-agents-skills",
)


def _pinned_openclaw_bot() -> Path:
    """The pinned openclaw-bot checkout: the installed component, else external/.

    bin/components.sh installs it under ~/.local/share/coding-system/components;
    a development layout may provide it as external/openclaw-bot instead.
    """
    spec = importlib.util.spec_from_file_location(
        "component_paths_for_tests", ROOT / "bin/lib/component_paths.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.resolve_component_path(
            ROOT, Path.home(), "openclaw-bot", source_fallback=True
        )
    except module.ComponentPathError:
        return ROOT / "external/openclaw-bot"


OPENCLAW_BOT = _pinned_openclaw_bot()
SCRIPT = ROOT / "bin/verify-skill-credentials.py"
MODULE_SPEC = importlib.util.spec_from_file_location(
    "coding_system_skill_credential_verifier",
    SCRIPT,
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
VERIFIER_MODULE = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = VERIFIER_MODULE
MODULE_SPEC.loader.exec_module(VERIFIER_MODULE)
SECRET_CANARIES = {
    "aas-api-secret-never-report",
    "zulip-api-secret-never-report",
    "smtp-password-secret-never-report",
    "compute-token-secret-never-report",
    "kaggle-token-secret-never-report",
    "skill-token-secret-never-report",
    "provider-token-secret-never-report",
    "copilot-token-secret-never-report",
    "patentsview-token-secret-never-report",
    "modal-token-secret-never-report",
    "google-client-secret-never-report",
    "google-session-secret-never-report",
    "canvas-api-secret-never-report",
    "vnu-password-secret-never-report",
    "vnu-hmac-secret-never-report-0123456789abcdef",
    "getscipapers-secret-never-report",
    "ambient-shell-secret-never-report",
    "file-delivery-target-never-report",
    "forms-github-secret-never-report",
    "forms-runner-secret-never-report",
    "forms-oauth-secret-never-report",
    "forms-jwt-secret-never-report",
}


def write_bytes(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    current = path.parent
    temporary_root = Path(tempfile.gettempdir())
    while current != temporary_root and current != current.parent:
        current.chmod(0o700)
        current = current.parent
    path.write_bytes(payload)
    path.chmod(mode)


def write_text(path: Path, payload: str, mode: int) -> None:
    write_bytes(path, payload.encode("utf-8"), mode)


def write_json(path: Path, value: object, mode: int) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n", mode)


def mirror(source: Path, destinations: tuple[tuple[Path, int], ...]) -> None:
    payload = source.read_bytes()
    for destination, mode in destinations:
        write_bytes(destination, payload, mode)


def copy_contract_repository(destination: Path) -> None:
    """Copy only the source contracts consumed by the verifier into a fixture."""

    source_roots = {
        "repository": ROOT,
        "openclaw": OPENCLAW_BOT,
        "aas": AAS_CHECKOUT,
    }
    destination_roots = {
        "repository": destination,
        "openclaw": destination / "external/openclaw-bot",
        "aas": destination / "ai-agents-skills",
    }
    destination.mkdir(parents=True, exist_ok=True)
    for contracts in VERIFIER_MODULE.SOURCE_CONTRACTS.values():
        for contract in contracts:
            source = source_roots[contract.root] / contract.relative
            target = destination_roots[contract.root] / contract.relative
            if target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def commit_contract_component(root: Path) -> str:
    subprocess.run(
        ["git", "init", "-q"],
        cwd=root,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "add", "--all"],
        cwd=root,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Credential Contract Test",
            "-c",
            "user.email=credential-contract@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        cwd=root,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.strip()


class SkillCredentialVerifierTests(unittest.TestCase):
    maxDiff = None

    def run_verifier(
        self,
        home: Path,
        *extra: str,
        output: bool = True,
        repository: Path | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        if repository is None:
            repository = home / ".credential-contract-repository"
            copy_contract_repository(repository)
        report_path = home / "verification-report.json"
        command = [
            sys.executable,
            "-I",
            "-B",
            str(SCRIPT),
            "--home",
            str(home),
            "--repository",
            str(repository),
        ]
        if output:
            command.extend(("--output", str(report_path)))
        command.extend(extra)
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "HOME": str(home),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
            },
        )
        report = (
            json.loads(report_path.read_text(encoding="utf-8"))
            if output
            else json.loads(completed.stdout)
        )
        combined = completed.stdout + completed.stderr
        serialized = json.dumps(report, sort_keys=True)
        for secret in SECRET_CANARIES:
            self.assertNotIn(secret, combined)
            self.assertNotIn(secret, serialized)
        return completed, report

    def result(self, report: dict[str, object], identifier: str) -> dict[str, object]:
        checks = report["checks"]
        assert isinstance(checks, list)
        return next(item for item in checks if item["id"] == identifier)

    def write_selector_state(self, home: Path) -> None:
        selectors = {
            "AAS_SECRETS_FILE": (
                ".config/ai-agents-skills/secrets.json",
                "/workspace/.config/ai-agents-skills/secrets.json",
            ),
            "AAS_CALIBRE_SECRETS_FILE": (
                ".config/ai-agents-skills/calibre-secrets.json",
                None,
            ),
            "AAS_ZOTERO_SECRETS_FILE": (
                ".config/ai-agents-skills/zotero-secrets.json",
                None,
            ),
            "AAS_FILE_DELIVERY_SECRETS_FILE": (
                ".config/ai-agents-skills/file-delivery-queue.json",
                None,
            ),
            "AAS_COMPUTE_SECRETS_FILE": (
                ".config/ai-agents-skills/compute.env",
                "/workspace/.config/ai-agents-skills/compute.env",
            ),
            "AAS_SKILL_SECRETS_FILE": (
                ".config/ai-agents-skills/skill.env",
                "/workspace/.config/ai-agents-skills/skill.env",
            ),
            "AAS_PROVIDER_SECRETS_FILE": (
                ".config/ai-agents-skills/providers.env",
                "/workspace/.config/ai-agents-skills/providers.env",
            ),
            "REMOTE_BRIDGE_SECRETS_FILE": (
                ".config/remote-bridge/secrets.json",
                None,
            ),
            "SEND_EMAIL_SECRETS_FILE": (
                ".config/send-email/secrets.json",
                None,
            ),
            "GOOGLE_CLASSROOM_CREDENTIALS": (
                ".config/course/google-classroom/credentials.json",
                "/workspace/.config/course/google-classroom/credentials.json",
            ),
            "GOOGLE_CLASSROOM_TOKEN": (
                ".config/course/google-classroom/token.pickle",
                "/workspace/.config/course/google-classroom/token.pickle",
            ),
            "CANVAS_CONFIG_PATH": (
                ".config/course/canvas/config.json",
                "/workspace/.config/course/canvas/config.json",
            ),
            "GETSCIPAPERS_CONFIG_DIR": (
                ".config/getscipapers",
                "/workspace/.config/getscipapers",
            ),
            "GETSCIPAPERS_SKILL_CONFIG": (
                ".openclaw/workspace/data/research/getscipapers_bot/state/config.json",
                "/workspace/data/research/getscipapers_bot/state/config.json",
            ),
            "GH_CONFIG_DIR": (
                ".config/gh",
                "/workspace/.config/gh",
            ),
        }
        selector_values = {
            key: str(home / host_relative)
            for key, (host_relative, _openclaw_value) in selectors.items()
        }
        assignments = ", ".join(
            f'{key} = {json.dumps(value)}' for key, value in selector_values.items()
        )
        write_text(
            home / ".codex/config.toml",
            f"[shell_environment_policy]\nset = {{ {assignments} }}\n",
            0o600,
        )
        write_text(
            home / ".bashrc",
            "\n".join(
                f'export {key}="$HOME/{host_relative}"'
                for key, (host_relative, _openclaw_value) in selectors.items()
            )
            + "\n",
            0o644,
        )
        write_json(
            home / ".openclaw/openclaw.json",
            {
                "agents": {
                    "defaults": {
                        "workspace": str(home / ".openclaw/workspace"),
                        "sandbox": {
                            "docker": {
                                "env": {"XDG_DATA_HOME": "/workspace/.local-data"}
                            }
                        }
                    },
                    "list": [
                        {
                            "id": "main",
                            "sandbox": {
                                "docker": {
                                    "env": {
                                        key: openclaw_value
                                        for key, (
                                            _host_relative,
                                            openclaw_value,
                                        ) in selectors.items()
                                        if openclaw_value is not None and key not in {
                                            "AAS_SECRETS_FILE",
                                            "AAS_SKILL_SECRETS_FILE",
                                        }
                                    }
                                }
                            },
                            "skills": ["main-skill"],
                            "workspace": str(home / ".openclaw/workspace"),
                        },
                        {
                            "id": "review",
                            "skills": [],
                            "workspace": str(home / ".openclaw/workspace-review"),
                        },
                    ],
                }
            },
            0o600,
        )

    def install_projection_probes(self, home: Path) -> None:
        aas_runtime = AAS_CHECKOUT / "canonical/runtime"
        aas_runners = aas_runtime / "runners"
        runtime = home / ".local/share/ai-agents-skills/runtime"
        runners = runtime / "runners"
        runners.mkdir(parents=True, exist_ok=True)
        runners.chmod(0o700)
        shutil.copy2(aas_runners / "load_secret_env.py", runtime / "load_secret_env.py")
        (runtime / "load_secret_env.py").chmod(0o644)
        for name in (
            "credential_projection_probe.py",
            "credential_projection_check.py",
        ):
            shutil.copy2(aas_runners / name, runners / name)
            (runners / name).chmod(0o644)

        installed_skills = runtime / "workspace/skills"
        installed_skills.mkdir(parents=True, exist_ok=True)
        installed_skills.chmod(0o700)
        arl_source = aas_runtime / "skills/autonomous-research-loop-runtime"
        arl_installed = installed_skills / "autonomous-research-loop-runtime"
        arl_installed.mkdir(parents=True, exist_ok=True)
        arl_installed.chmod(0o700)
        for name in VERIFIER_MODULE.ARL_CONSUMER_MODULES:
            shutil.copy2(arl_source / name, arl_installed / name)
            (arl_installed / name).chmod(0o644)
        remote_installed = installed_skills / "remote-bridge/remote_bridge.py"
        remote_installed.parent.mkdir(parents=True, exist_ok=True)
        remote_installed.parent.chmod(0o700)
        shutil.copy2(
            aas_runtime / "skills/remote-bridge/remote_bridge.py",
            remote_installed,
        )
        remote_installed.chmod(0o644)
        kaggle_installed = runtime / "workspace/research_compute/kaggle_backend.py"
        kaggle_installed.parent.mkdir(parents=True, exist_ok=True)
        kaggle_installed.parent.chmod(0o700)
        shutil.copy2(
            aas_runtime / "workspace/research_compute/kaggle_backend.py",
            kaggle_installed,
        )
        kaggle_installed.chmod(0o644)

        machine = platform.machine().lower()
        arch = "arm64" if machine in {"aarch64", "arm64"} else "amd64"
        node = home / (
            f".local/share/coding-system/node-generations/sha256-{arch}-" + "e" * 64 + "/bin/node"
        )
        write_text(node, "#!/bin/sh\nexit 0\n", 0o755)
        node_link = home / ".npm-global/bin/node"
        node_link.parent.mkdir(parents=True, exist_ok=True)
        node_link.symlink_to(node)
        copilot_loader = (
            home
            / (
                f".local/share/coding-system/npm-closures/sha256-{arch}-"
                + "a" * 64
                + "-"
                + "b" * 64
                + "/node_modules/@github/copilot/npm-loader.js"
            )
        )
        write_text(copilot_loader, "// credential probe fixture\n", 0o444)
        compatibility = home / ".npm-global/lib/node_modules/@github/copilot"
        compatibility.parent.mkdir(parents=True, exist_ok=True)
        compatibility.symlink_to(copilot_loader.parent)
        wrapper = home / ".local/bin/copilot"
        rendered = (
            (ROOT / "system/bin/copilot").read_text(encoding="utf-8")
            .replace("{{ HOME }}", str(home))
            .replace("{{ COPILOT_LOADER }}", str(copilot_loader))
        )
        write_text(wrapper, rendered, 0o755)

    def populate_complete(self, home: Path) -> None:
        legacy = {
            "ZOTERO_API_KEY": "aas-api-secret-never-report",
            "WEBDAV_PASSWORD": "webdav-secret-never-report",
            "GDRIVE_CREDENTIALS": "gdrive-secret-never-report",
            "TELEGRAM_BOT_TOKEN": "telegram-secret-never-report",
            "CALIBRE_GDRIVE_FOLDER_ID": "calibre-folder-fixture",
            "ZULIP_ORG_URL": "https://zulip.example.invalid",
            "ZULIP_EMAIL": "bot@example.invalid",
            "ZULIP_API_KEY": "zulip-api-secret-never-report",
            "HCLOUD_TOKEN": "compute-token-secret-never-report",
            "KAGGLE_API_TOKEN": "kaggle-token-secret-never-report",
            "LEANEXPLORE_API_KEY": "skill-token-secret-never-report",
            "OPENAI_API_KEY": "provider-token-secret-never-report",
            "GH_TOKEN": "copilot-token-secret-never-report",
            "VNU_EOFFICE_USERNAME": "vnu-user-fixture",
            "VNU_EOFFICE_PASSWORD": "vnu-password-secret-never-report",
        }
        write_json(home / ".claude/secrets.json", legacy, 0o600)

        aas = {key: legacy[key] for key in (
            "ZOTERO_API_KEY",
            "WEBDAV_PASSWORD",
            "GDRIVE_CREDENTIALS",
            "TELEGRAM_BOT_TOKEN",
            "CALIBRE_GDRIVE_FOLDER_ID",
        )}
        aas_path = home / ".config/ai-agents-skills/secrets.json"
        write_json(aas_path, aas, 0o600)
        mirror(
            aas_path,
            (
                (home / ".codex/runtime/workspace/.secrets.json", 0o600),
                (
                    home
                    / ".local/share/ai-agents-skills/runtime/workspace/.secrets.json",
                    0o600,
                ),
            ),
        )
        write_json(
            home / ".config/ai-agents-skills/file-delivery-queue.json",
            {
                "allowed": {
                    "zulip": ["file-delivery-target-never-report"],
                },
                "hmac_key_hex": "f" * 64,
                "max_job_age_seconds": 120,
                "max_media_bytes": 16 * 1024 * 1024,
                "max_replay_entries": 1_000,
                "replay_ledger_dir": "aas-host-state:file-delivery-replay",
                "replay_retention_seconds": 3_600,
                "version": 1,
            },
            0o600,
        )
        replay_ledger = (
            home / ".local/state/ai-agents-skills/file-delivery-replay"
        )
        replay_ledger.mkdir(parents=True)
        current = replay_ledger
        while current != home:
            current.chmod(0o700)
            current = current.parent
        calibre_secrets = {
            "GDRIVE_CREDENTIALS": legacy["GDRIVE_CREDENTIALS"],
            "CALIBRE_GDRIVE_FOLDER_ID": legacy["CALIBRE_GDRIVE_FOLDER_ID"],
        }
        write_json(
            home / ".config/ai-agents-skills/calibre-secrets.json",
            calibre_secrets,
            0o600,
        )
        write_json(
            home
            / ".openclaw/workspace/.config/ai-agents-skills/calibre-secrets.json",
            calibre_secrets,
            0o600,
        )

        remote_bridge = home / ".config/remote-bridge/secrets.json"
        write_json(
            remote_bridge,
            {
                "allowed_user_ids": [],
                "default_channel": "zulip",
                "notify_channels": ["zulip", "telegram"],
                "telegram": {
                    "bot_token": legacy["TELEGRAM_BOT_TOKEN"],
                },
                "zulip": {
                    "allowed_user_ids": [],
                    "api_key": legacy["ZULIP_API_KEY"],
                    "control_stream": "aas-remote",
                    "email": legacy["ZULIP_EMAIL"],
                    "site": legacy["ZULIP_ORG_URL"],
                    "topic_prefix": "job/",
                },
            },
            0o600,
        )
        email_path = home / ".config/send-email/secrets.json"
        write_json(
            email_path,
            {
                "_README": "bounded operator guidance",
                "smtp": {
                    "from": "sender@example.invalid",
                    "host": "smtp.example.invalid",
                    "password": "smtp-password-secret-never-report",  # LEAKSCAN-EXEMPT: synthetic fixture
                    "port": 587,
                    "security": "starttls",
                    "user": "sender@example.invalid",
                }
            },
            0o600,
        )
        compute = home / ".config/ai-agents-skills/compute.env"
        write_text(
            compute,
            "# managed\n"
            f"HCLOUD_TOKEN={legacy['HCLOUD_TOKEN']}\n"
            f"KAGGLE_API_TOKEN={legacy['KAGGLE_API_TOKEN']}\n",
            0o600,
        )
        mirror(
            compute,
            ((home / ".openclaw/workspace/.config/ai-agents-skills/compute.env", 0o600),),
        )
        write_text(
            home / ".kaggle/access_token", legacy["KAGGLE_API_TOKEN"] + "\n", 0o600
        )

        skill = home / ".config/ai-agents-skills/skill.env"
        write_text(
            skill,
            f"LEANEXPLORE_API_KEY={legacy['LEANEXPLORE_API_KEY']}\n",
            0o600,
        )
        write_text(
            home
            / ".openclaw/workspace/.config/ai-agents-skills/lean-explore.env",
            "# coding-system managed OpenClaw LeanExplore credentials; strict KEY=value format\n"
            f"LEANEXPLORE_API_KEY={legacy['LEANEXPLORE_API_KEY']}\n",
            0o600,
        )
        write_json(
            home / ".config/ai-agents-skills/zotero-secrets.json",
            {
                "GDRIVE_CREDENTIALS": legacy["GDRIVE_CREDENTIALS"],
                "WEBDAV_PASSWORD": legacy["WEBDAV_PASSWORD"],
                "ZOTERO_API_KEY": legacy["ZOTERO_API_KEY"],
            },
            0o600,
        )
        write_json(
            home
            / ".openclaw/workspace/.config/ai-agents-skills/zotero-secrets.json",
            {
                "GDRIVE_CREDENTIALS": legacy["GDRIVE_CREDENTIALS"],
                "WEBDAV_PASSWORD": legacy["WEBDAV_PASSWORD"],
                "ZOTERO_API_KEY": legacy["ZOTERO_API_KEY"],
            },
            0o600,
        )
        openclaw_delivery_policy = {
            "delivery_policy": {
                "allowed_targets": {
                    "googlechat": [],
                    "telegram": [],
                    "whatsapp": [],
                    "zalo": [],
                    "zulip": ["file-delivery-target-never-report"],
                }
            },
            "schema": "openclaw.file-delivery-policy/v1",
        }
        write_json(
            home / ".openclaw/file-delivery-policy.json",
            openclaw_delivery_policy,
            0o600,
        )
        providers = home / ".config/ai-agents-skills/providers.env"
        write_text(
            providers,
            f"OPENAI_API_KEY={legacy['OPENAI_API_KEY']}\n",
            0o600,
        )
        mirror(
            providers,
            ((home / ".openclaw/workspace/.config/ai-agents-skills/providers.env", 0o600),),
        )
        copilot = home / ".config/ai-agents-skills/providers/copilot.env"
        write_text(
            copilot,
            f"GH_TOKEN={legacy['GH_TOKEN']}\n",
            0o600,
        )
        mirror(
            copilot,
            ((
                home
                / ".openclaw/workspace/.config/ai-agents-skills/providers/copilot.env",
                0o600,
            ),),
        )
        self.install_projection_probes(home)
        self.write_selector_state(home)

        modal = home / ".modal.toml"
        write_text(
            modal,
            '[default]\ntoken_id="fixture-id"\n'
            'token_secret="modal-token-secret-never-report"\nactive=true\n',
            0o600,
        )
        mirror(modal, ((home / ".openclaw/workspace/.modal.toml", 0o600),))

        zotero = home / ".config/ai-agents-skills/zotero/config.json"
        write_json(zotero, {"zotero_user_id": "12345"}, 0o644)
        mirror(
            zotero,
            tuple(
                (home / relative, 0o644)
                for relative in (
                    ".openclaw/workspace/skills/zotero/config.json",
                    ".codex/runtime/workspace/skills/zotero/config.json",
                    ".local/share/ai-agents-skills/runtime/workspace/skills/zotero/config.json",
                    ".claude/skills/zotero/config.json",
                )
            ),
        )
        calibre = home / ".config/ai-agents-skills/calibre/config.json"
        write_json(calibre, {"gdrive_folder_id": "calibre-folder-fixture"}, 0o644)
        mirror(
            calibre,
            tuple(
                (home / relative, 0o644)
                for relative in (
                    ".openclaw/workspace/skills/calibre/config.json",
                    ".codex/runtime/workspace/skills/calibre/config.json",
                    ".local/share/ai-agents-skills/runtime/workspace/skills/calibre/config.json",
                    ".claude/skills/calibre/config.json",
                )
            ),
        )

        classroom = home / ".config/course/google-classroom/credentials.json"
        write_json(
            classroom,
            {
                "installed": {
                    "auth_uri": "https://accounts.example.invalid/auth",
                    "client_id": "fixture-client",
                    "client_secret": "google-client-secret-never-report",  # LEAKSCAN-EXEMPT: synthetic fixture
                    "token_uri": "https://accounts.example.invalid/token",
                }
            },
            0o600,
        )
        mirror(
            classroom,
            (
                (
                    home
                    / ".openclaw/workspace/.config/course/google-classroom/credentials.json",
                    0o600,
                ),
            ),
        )
        token = home / ".config/course/google-classroom/token.pickle"
        write_bytes(token, b"google-session-secret-never-report", 0o600)
        mirror(
            token,
            (
                (
                    home
                    / ".openclaw/workspace/.config/course/google-classroom/token.pickle",
                    0o600,
                ),
            ),
        )

        canvas = home / ".config/course/canvas/config.json"
        write_json(
            canvas,
            {
                "CANVAS_LMS_API_KEY": "canvas-api-secret-never-report",
                "CANVAS_LMS_API_URL": "https://canvas.example.invalid",
                "CANVAS_LMS_COURSE_ID": "fixture-course",
            },
            0o600,
        )
        mirror(
            canvas,
            ((home / ".openclaw/workspace/.config/course/canvas/config.json", 0o600),),
        )

        vnu = home / ".config/vnu-eoffice/secrets.json"
        write_json(
            vnu,
            {
                "VNU_EOFFICE_PASSWORD": legacy["VNU_EOFFICE_PASSWORD"],
                "VNU_EOFFICE_USERNAME": legacy["VNU_EOFFICE_USERNAME"],
                "VNU_STATE_HMAC_KEY": "vnu-hmac-secret-never-report-0123456789abcdef",
            },
            0o600,
        )
        mirror(
            vnu,
            ((home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json", 0o600),),
        )

        getscipapers = home / ".config/getscipapers"
        write_json(
            getscipapers / "ablesci/credentials.json",
            {"password": "getscipapers-secret-never-report"},  # LEAKSCAN-EXEMPT: synthetic fixture
            0o600,
        )
        write_json(
            getscipapers / "getpapers/config.json",
            {"email": "fixture@example.invalid"},
            0o600,
        )
        write_json(
            getscipapers / "nexus/proxy_list.json",
            {"proxies": ["proxy.example.invalid"]},
            0o600,
        )
        write_bytes(
            getscipapers / "nexus/telegram_session.session", b"session-fixture", 0o600
        )
        write_bytes(
            getscipapers / "ablesci/ablesci_cache.pkl", b"opaque-cache-fixture", 0o600
        )
        for source in sorted(path for path in getscipapers.rglob("*") if path.is_file()):
            destination = (
                home
                / ".openclaw/workspace/.config/getscipapers"
                / source.relative_to(getscipapers)
            )
            write_bytes(destination, source.read_bytes(), 0o600)

        write_text(
            home / "forms/apps/classroom50-runner/.env",
            "CLASSROOM50_GITHUB_TOKEN=forms-github-secret-never-report\n"
            "CLASSROOM50_RUNNER_SIGNING_SECRET=forms-runner-secret-never-report\n",
            0o600,
        )
        write_text(
            home / "forms/apps/api/.dev.vars",
            "GITHUB_CLIENT_SECRET=forms-oauth-secret-never-report\n"
            "JWT_SECRET=forms-jwt-secret-never-report\n",
            0o600,
        )
        write_text(
            home / "forms/apps/web/.env.local",
            "VITE_API_BASE=https://forms.example.invalid\n",
            0o600,
        )

    def test_absent_optional_authorities_are_nontechnical_and_report_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            first, report = self.run_verifier(home, output=False)
            second, second_report = self.run_verifier(home, output=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout, second.stdout)
            self.assertEqual(report, second_report)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["counts"]["notConfigured"], 22)
            self.assertEqual(report["counts"]["fail"], 0)
            self.assertEqual(report["counts"]["policyConfirmationRequired"], 0)
            self.assertIn("not-configured=22", first.stderr)

    def test_absent_optional_authorities_do_not_require_resolver_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            repository = root / "empty-repository"
            home.mkdir(mode=0o700)
            repository.mkdir(mode=0o700)
            completed, report = self.run_verifier(
                home,
                output=False,
                repository=repository,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["counts"]["notConfigured"], 22)

    def test_forms_local_files_are_source_contracted_and_mode_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            repository = root / "empty-repository"
            home.mkdir(mode=0o700)
            repository.mkdir(mode=0o700)
            runner = home / "forms/apps/classroom50-runner/.env"
            api = home / "forms/apps/api/.dev.vars"
            write_text(
                runner,
                "CLASSROOM50_GITHUB_TOKEN=forms-github-secret-never-report\n",
                0o600,
            )
            write_text(
                api,
                "JWT_SECRET=forms-jwt-secret-never-report\n",
                0o600,
            )

            completed, source = self.run_verifier(home, repository=repository)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            configured = self.result(source, "forms-local")
            self.assertEqual(configured["status"], "PASS")
            self.assertEqual(
                configured["capabilities"],
                ["FORMS_API_LOCAL", "FORMS_CLASSROOM50_RUNNER_LOCAL"],
            )

            api.unlink()
            completed, restored = self.run_verifier(home, repository=repository)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            enforced = VERIFIER_MODULE._enforce_source_capability_contract(
                restored, source
            )
            self.assertEqual(enforced["status"], "TECHNICAL_FAIL")
            self.assertEqual(
                self.result(enforced, "forms-local")["reason"],
                "source-capability-not-restored",
            )

            runner.chmod(0o644)
            completed, unsafe = self.run_verifier(home, repository=repository)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(unsafe, "forms-local")["reason"], "unsafe-file"
            )

    def test_tailscale_authority_distinguishes_authenticated_and_reauth_states(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            write_text(
                home / ".config/coding-system/tailscale-authkey",
                "tskey-auth-abcdefghijklmnopqrstuvwx\n",
                0o600,
            )
            write_text(
                home / ".config/coding-system/tailscale-hostname",
                "openclaw\n",
                0o600,
            )
            with mock.patch.object(
                VERIFIER_MODULE, "tailscale_backend_state", return_value="Running"
            ):
                report = VERIFIER_MODULE.verify(
                    home, repository=ROOT, credit_blocked=frozenset()
                )
            result = self.result(report, "tailscale")
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(
                result["capabilities"],
                ["TAILSCALE_AUTH_KEY", "TAILSCALE_HOSTNAME"],
            )
            substituted = json.loads(json.dumps(report))
            self.result(substituted, "tailscale")["capabilities"] = [
                "TAILSCALE_AUTH_KEY",
                "TAILSCALE_UNEXPECTED_SETTING",
            ]
            enforced = VERIFIER_MODULE._enforce_source_capability_contract(
                substituted, report
            )
            self.assertEqual(enforced["status"], "TECHNICAL_FAIL")
            self.assertEqual(
                self.result(enforced, "tailscale")["reason"],
                "source-capability-not-restored",
            )

            with mock.patch.object(
                VERIFIER_MODULE, "tailscale_backend_state", return_value="NeedsLogin"
            ):
                report = VERIFIER_MODULE.verify(
                    home, repository=ROOT, credit_blocked=frozenset()
                )
            result = self.result(report, "tailscale")
            self.assertEqual(result["status"], "REAUTH_REQUIRED")
            self.assertTrue(result["configured"])
            self.assertEqual(report["counts"]["reauthRequired"], 1)

    def test_tailscale_legacy_env_is_a_redacted_technical_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            write_text(
                home / ".config/coding-system/tailscale.env",
                "TS_AUTHKEY=tskey-auth-secret-never-report-abcdefghijkl\n"
                "TS_HOSTNAME=openclaw\n",
                0o600,
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            result = self.result(report, "tailscale")
            self.assertEqual(result["reason"], "tailscale-legacy-authority-present")
            self.assertNotIn(
                "tskey-auth-secret-never-report-abcdefghijkl",
                completed.stdout + completed.stderr + json.dumps(report),
            )

    def test_configured_authority_fails_when_a_resolver_source_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            repository = root / "contract-repository"
            home.mkdir(mode=0o700)
            self.populate_complete(home)
            copy_contract_repository(repository)
            (repository / "system/bin/lean-explore-mcp-api").unlink()

            completed, report = self.run_verifier(home, repository=repository)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "skill-credentials")["reason"],
                "source-resolver-contract-missing",
            )

    def test_runtime_probe_cannot_be_replaced_by_a_pass_printing_shim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            probe = (
                home
                / ".local/share/ai-agents-skills/runtime/runners/credential_projection_probe.py"
            )
            write_text(
                probe,
                "#!/usr/bin/python3\nprint('PASS lane=skill')\n",
                0o644,
            )

            completed, report = self.run_verifier(home)

            self.assertEqual(completed.returncode, 2)
            for identifier in (
                "compute-credentials",
                "skill-credentials",
                "provider-credentials",
            ):
                self.assertEqual(
                    self.result(report, identifier)["reason"],
                    "credential-projection-probe-divergent",
                )

    def test_zulip_and_kaggle_consumers_are_pinned_and_exercised_offline(self) -> None:
        cases = (
            (
                "remote-bridge",
                (
                    ".local/share/ai-agents-skills/runtime/workspace/skills/"
                    "autonomous-research-loop-runtime/"
                    "autonomous_research_loop_runtime.py"
                ),
            ),
            (
                "kaggle",
                (
                    ".local/share/ai-agents-skills/runtime/workspace/"
                    "research_compute/kaggle_backend.py"
                ),
            ),
        )
        for identifier, relative in cases:
            with self.subTest(identifier=identifier), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                self.populate_complete(home)
                write_text(
                    home / relative,
                    "#!/usr/bin/python3\nprint('PASS consumer=forged')\n",
                    0o644,
                )

                completed, report = self.run_verifier(home)

                self.assertEqual(completed.returncode, 2)
                self.assertEqual(
                    self.result(report, identifier)["reason"],
                    "credential-consumer-probe-divergent",
                )

    def test_legacy_zotero_s2_secret_cannot_remain_in_public_configs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            unsafe = {
                "zotero_user_id": "12345",
                "semantic_scholar_api_key": "legacy-s2-secret-never-report",
            }
            for relative in (
                ".config/ai-agents-skills/zotero/config.json",
                ".openclaw/workspace/skills/zotero/config.json",
                ".codex/runtime/workspace/skills/zotero/config.json",
                ".local/share/ai-agents-skills/runtime/workspace/skills/zotero/config.json",
                ".claude/skills/zotero/config.json",
            ):
                write_json(home / relative, unsafe, 0o644)

            completed, report = self.run_verifier(home)

            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "zotero")["reason"],
                "zotero-config-contains-legacy-secret",
            )

    def test_configured_authorities_fail_on_broken_resolver_contracts(self) -> None:
        cases = (
            (
                "aas-runtime-secrets",
                "ai-agents-skills/canonical/runtime/runners/run_skill.sh",
                "AAS_SECRETS_FILE",
                "AAS_SHARED_FILE",
            ),
            (
                "compute-credentials",
                "ai-agents-skills/canonical/runtime/skills/hetzner-research-compute/run_hetzner_research_compute.sh",
                "--pointer-env AAS_COMPUTE_SECRETS_FILE",
                "--pointer-env BROKEN_COMPUTE_FILE",
            ),
            (
                "provider-credentials",
                "ai-agents-skills/canonical/runtime/skills/autonomous-research-loop-runtime/run_autonomous_research_loop.sh",
                "--pointer-env AAS_PROVIDER_SECRETS_FILE",
                "--pointer-env BROKEN_PROVIDER_FILE",
            ),
            (
                "remote-bridge",
                "ai-agents-skills/canonical/runtime/skills/remote-bridge/dispatch_aas.py",
                '"error_code": "openclaw_control_adapter_retired"',
                '"error_code": "openclaw_control_adapter_retired",\n'
                '                "secrets": REMOTE_BRIDGE_SECRETS_FILE',
            ),
            (
                "openclaw-file-delivery-policy",
                "external/openclaw-bot/scripts/file_delivery.py",
                'parser.add_argument("--channel-state"',
                'parser.add_argument("--state-prefix"',
            ),
            (
                "openclaw-file-delivery-policy",
                "external/openclaw-bot/workspace/scripts/job_queue_worker.sh",
                'DELIVERY_HELPER="$LIBEXEC/file_delivery.py"',
                'DELIVERY_HELPER="$WORKSPACE/skills/zotero/delivery_policy.py"',
            ),
            (
                "skill-credentials",
                "external/openclaw-bot/workspace/skills/research-digest-wrapper/run_research_digest.sh",
                "--profile research-digest",
                "--profile broken-digest",
            ),
            (
                "skill-credentials",
                "external/openclaw-bot/workspace/skills/_load_skill_secrets.py",
                "runpy.run_path",
                "runpy.run_module",
            ),
            (
                "calibre",
                "external/openclaw-bot/workspace/skills/calibre/lib/config.py",
                'os.environ.pop("GDRIVE_CREDENTIALS", None)',
                'os.environ.pop("BROKEN_GDRIVE_CREDENTIALS", None)',
            ),
            (
                "zotero",
                "external/openclaw-bot/workspace/skills/zotero/lib/config.py",
                "for key in SECRETS_KEYS",
                "for key in ()",
            ),
            (
                "zotero",
                "external/openclaw-bot/workspace/skills/zotero/send_telegram.sh",
                'exec /usr/bin/bash -p "$SCRIPT_DIR/send_file.sh" telegram',
                'exec /usr/bin/bash -p "$SCRIPT_DIR/send_file.sh" signal',
            ),
        )
        for identifier, relative, current, replacement in cases:
            with self.subTest(identifier=identifier), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home = root / "home"
                repository = root / "contract-repository"
                home.mkdir(mode=0o700)
                self.populate_complete(home)
                copy_contract_repository(repository)
                source = repository / relative
                text = source.read_text(encoding="utf-8")
                self.assertIn(current, text)
                write_text(source, text.replace(current, replacement), 0o644)

                completed, report = self.run_verifier(home, repository=repository)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(
                    self.result(report, identifier)["reason"],
                    "source-resolver-contract-divergent",
                )

    def test_component_contracts_are_read_from_pins_not_dirty_worktrees(self) -> None:
        cases = (
            (
                "remote-bridge",
                "ai-agents-skills",
                "canonical/runtime/skills/remote-bridge/dispatch_aas.py",
                '"error_code": "openclaw_control_adapter_retired"',
                '"error_code": "openclaw_control_adapter_active"',
            ),
            (
                "skill-credentials",
                "external/openclaw-bot",
                "workspace/skills/research-digest-wrapper/run_research_digest.sh",
                "--profile research-digest",
                "--profile broken-digest",
            ),
        )
        for identifier, component, relative, good, broken in cases:
            with self.subTest(identifier=identifier), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home = root / "home"
                repository = root / "contract-repository"
                home.mkdir(mode=0o700)
                self.populate_complete(home)
                copy_contract_repository(repository)

                broken_source = repository / component / relative
                original = broken_source.read_text(encoding="utf-8")
                self.assertIn(good, original)
                write_text(broken_source, original.replace(good, broken), 0o644)

                aas_pin = commit_contract_component(repository / "ai-agents-skills")
                openclaw_pin = commit_contract_component(
                    repository / "external/openclaw-bot"
                )
                write_text(broken_source, original, 0o644)
                write_text(
                    repository / "components.lock",
                    "openclaw-bot=https://example.invalid/openclaw-bot.git@"
                    f"{openclaw_pin}\n"
                    "ai-agents-skills=https://example.invalid/ai-agents-skills.git@"
                    f"{aas_pin}\n",
                    0o644,
                )

                completed, report = self.run_verifier(home, repository=repository)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(
                    self.result(report, identifier)["reason"],
                    "source-resolver-contract-divergent",
                )

    def test_missing_promisor_blob_never_invokes_a_remote_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            repository = root / "contract-repository"
            home.mkdir(mode=0o700)
            self.populate_complete(home)
            copy_contract_repository(repository)

            aas_repository = repository / "ai-agents-skills"
            aas_pin = commit_contract_component(aas_repository)
            openclaw_pin = commit_contract_component(
                repository / "external/openclaw-bot"
            )
            write_text(
                repository / "components.lock",
                "openclaw-bot=https://example.invalid/openclaw-bot.git@"
                f"{openclaw_pin}\n"
                "ai-agents-skills=https://example.invalid/ai-agents-skills.git@"
                f"{aas_pin}\n",
                0o644,
            )

            helper = root / "promisor-fetch-helper"
            marker = root / "promisor-fetch-was-invoked"
            self.assertNotIn(" ", str(helper))
            write_text(
                helper,
                "#!/usr/bin/python3\n"
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).touch()\n"
                "raise SystemExit(1)\n",
                0o755,
            )
            for key, value in (
                ("core.repositoryFormatVersion", "1"),
                ("extensions.partialClone", "origin"),
                ("remote.origin.url", f"ext::{helper}"),
                ("remote.origin.promisor", "true"),
                ("remote.origin.partialCloneFilter", "blob:none"),
                ("protocol.ext.allow", "always"),
            ):
                subprocess.run(
                    ["git", "config", key, value],
                    cwd=aas_repository,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            required_source = (
                "canonical/runtime/runners/run_skill.sh"
            )
            blob = subprocess.run(
                ["git", "rev-parse", f"{aas_pin}:{required_source}"],
                cwd=aas_repository,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).stdout.strip()
            blob_path = aas_repository / ".git/objects" / blob[:2] / blob[2:]
            self.assertTrue(blob_path.is_file())
            blob_path.unlink()

            control = subprocess.run(
                ["git", "cat-file", "-s", f"{aas_pin}:{required_source}"],
                cwd=aas_repository,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": "/nonexistent",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "GIT_NO_LAZY_FETCH": "0",
                    "GIT_ALLOW_PROTOCOL": "ext",
                    "GIT_TERMINAL_PROMPT": "0",
                },
                timeout=10,
            )
            self.assertNotEqual(control.returncode, 0)
            self.assertTrue(marker.is_file(), "promisor fixture did not try its helper")
            marker.unlink()

            completed, report = self.run_verifier(home, repository=repository)
            self.assertEqual(completed.returncode, 2)
            self.assertFalse(marker.exists())
            self.assertEqual(
                self.result(report, "aas-runtime-secrets")["reason"],
                "source-resolver-contract-missing",
            )

    def test_complete_synthetic_closure_passes_without_revealing_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(report["schema"], "coding-system.skill-credential-verification/v3")
            self.assertEqual(report["schemaVersion"], 3)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["counts"], {
                "creditBlocked": 0,
                "fail": 0,
                "notConfigured": 1,
                "pass": 21,
                "policyConfirmationRequired": 0,
                "reauthRequired": 0,
            })
            self.assertEqual(self.result(report, "zulip")["status"], "PASS")
            self.assertEqual(self.result(report, "telegram")["status"], "PASS")
            self.assertEqual(self.result(report, "kaggle")["status"], "PASS")
            self.assertEqual(self.result(report, "hetzner")["status"], "PASS")
            self.assertEqual(
                self.result(report, "compute-credentials")["capabilities"],
                ["HCLOUD_TOKEN", "KAGGLE_API_TOKEN"],
            )
            self.assertEqual(
                self.result(report, "skill-credentials")["capabilities"],
                ["LEANEXPLORE_API_KEY"],
            )
            self.assertEqual(
                self.result(report, "provider-credentials")["capabilities"],
                ["OPENAI_API_KEY"],
            )
            self.assertEqual(
                self.result(report, "copilot-credentials")["capabilities"],
                ["GH_TOKEN"],
            )
            self.assertEqual(
                self.result(report, "file-delivery-queue")["capabilities"],
                ["FILE_DELIVERY_QUEUE"],
            )
            self.assertEqual(
                self.result(report, "openclaw-file-delivery-policy")["capabilities"],
                ["OPENCLAW_FILE_DELIVERY_POLICY"],
            )
            self.assertEqual(
                self.result(report, "aas-runtime-secrets")["capabilities"],
                [
                    "CALIBRE_GDRIVE_FOLDER_ID",
                    "GDRIVE_CREDENTIALS",
                    "TELEGRAM_BOT_TOKEN",
                    "WEBDAV_PASSWORD",
                    "ZOTERO_API_KEY",
                ],
            )
            self.assertEqual(
                self.result(report, "remote-bridge")["capabilities"],
                ["TELEGRAM", "ZULIP"],
            )
            self.assertEqual(
                self.result(report, "getscipapers")["capabilities"],
                [
                    "GETSCIPAPERS_ABLESCI_ABLESCI_CACHE_PKL",
                    "GETSCIPAPERS_ABLESCI_CREDENTIALS_JSON",
                    "GETSCIPAPERS_GETPAPERS_CONFIG_JSON",
                    "GETSCIPAPERS_NEXUS_PROXY_LIST_JSON",
                    "GETSCIPAPERS_NEXUS_TELEGRAM_SESSION_SESSION",
                ],
            )
            self.assertEqual((home / "verification-report.json").stat().st_mode & 0o777, 0o600)

    def test_file_delivery_queue_authority_and_replay_ledger_are_strict(self) -> None:
        mutations = (
            ("unknown-field", lambda value: value.update({"unexpected": True})),
            (
                "absolute-replay-path",
                lambda value: value.update(
                    {"replay_ledger_dir": "/tmp/file-delivery-replay"}
                ),
            ),
            (
                "duplicate-target",
                lambda value: value["allowed"].update(
                    {"zulip": ["same-target", "same-target"]}
                ),
            ),
            (
                "boolean-age",
                lambda value: value.update({"max_job_age_seconds": True}),
            ),
            (
                "short-retention",
                lambda value: value.update({"replay_retention_seconds": 120}),
            ),
            (
                "small-entry-bound",
                lambda value: value.update({"max_replay_entries": 99}),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                self.populate_complete(home)
                authority = (
                    home / ".config/ai-agents-skills/file-delivery-queue.json"
                )
                value = json.loads(authority.read_text(encoding="utf-8"))
                mutate(value)
                write_json(authority, value, 0o600)

                completed, report = self.run_verifier(home)

                self.assertEqual(completed.returncode, 2)
                self.assertEqual(
                    self.result(report, "file-delivery-queue")["reason"],
                    "file-delivery-authority-invalid",
                )

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            ledger = home / ".local/state/ai-agents-skills/file-delivery-replay"
            write_bytes(ledger / ".ledger.lock", b"", 0o600)
            write_json(
                ledger / ("a" * 64 + ".used"),
                {
                    "job_id": "job-1234567890-" + "b" * 16,
                    "used_at": 1,
                    "version": 1,
                },
                0o600,
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(
                self.result(report, "file-delivery-queue")["status"], "PASS"
            )

            marker = ledger / ("a" * 64 + ".used")
            write_json(marker, {"version": 2, "job_id": "invalid", "used_at": 1}, 0o600)
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "file-delivery-queue")["reason"],
                "file-delivery-replay-ledger-invalid",
            )

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            ledger = home / ".local/state/ai-agents-skills/file-delivery-replay"
            write_json(
                ledger / ("c" * 64 + ".used"),
                {
                    "job_id": "job-1234567890-" + "d" * 16,
                    "used_at": 1,
                    "version": 1,
                },
                0o600,
            )
            ledger.chmod(0o700)
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "file-delivery-queue")["reason"],
                "stale-file-delivery-replay-state",
            )

    def test_file_delivery_source_capability_cannot_be_substituted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            completed, expected = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            actual = json.loads(json.dumps(expected))
            self.result(actual, "file-delivery-queue")["capabilities"] = [
                "FILE_DELIVERY_UNEXPECTED"
            ]

            enforced = VERIFIER_MODULE._enforce_source_capability_contract(
                actual, expected
            )

            self.assertEqual(enforced["status"], "TECHNICAL_FAIL")
            self.assertEqual(
                self.result(enforced, "file-delivery-queue")["reason"],
                "source-capability-not-restored",
            )

    def test_openclaw_file_delivery_policy_is_exact_and_deny_by_default(self) -> None:
        mutations = (
            ("unsupported-schema", lambda value: value.update({"schema": "v0"})),
            ("authority-token", lambda value: value.update({"TELEGRAM_BOT_TOKEN": "x"})),
            (
                "missing-channel",
                lambda value: value["delivery_policy"]["allowed_targets"].pop("zalo"),
            ),
            (
                "unknown-channel",
                lambda value: value["delivery_policy"]["allowed_targets"].update(
                    {"signal": []}
                ),
            ),
            (
                "duplicate-target",
                lambda value: value["delivery_policy"]["allowed_targets"].update(
                    {"zulip": ["same", "same"]}
                ),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                self.populate_complete(home)
                authority = home / ".openclaw/file-delivery-policy.json"
                value = json.loads(authority.read_text(encoding="utf-8"))
                mutate(value)
                write_json(authority, value, 0o600)

                completed, report = self.run_verifier(home)

                self.assertEqual(completed.returncode, 2)
                self.assertEqual(
                    self.result(report, "openclaw-file-delivery-policy")["reason"],
                    "openclaw-file-delivery-policy-invalid",
                )

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(
                self.result(report, "openclaw-file-delivery-policy")["status"],
                "PASS",
            )

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            projection = (
                home / ".openclaw/workspace/.config/file-delivery/secrets.json"
            )
            write_json(
                projection,
                {
                    "delivery_policy": {
                        "allowed_targets": {
                            "googlechat": [],
                            "telegram": [],
                            "whatsapp": [],
                            "zalo": [],
                            "zulip": [],
                        }
                    },
                    "schema": "openclaw.file-delivery-policy/v1",
                },
                0o600,
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "openclaw-file-delivery-policy")["reason"],
                "stale-openclaw-file-delivery-projection",
            )

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            authority = home / ".openclaw/file-delivery-policy.json"
            write_text(
                authority,
                '{"schema":"openclaw.file-delivery-policy/v1",'
                '"schema":"openclaw.file-delivery-policy/v1",'
                '"delivery_policy":{"allowed_targets":{'
                '"telegram":[],"zulip":[],"googlechat":[],'
                '"whatsapp":[],"zalo":[]}}}\n',
                0o600,
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "openclaw-file-delivery-policy")["reason"],
                "duplicate-json-key",
            )

    def test_openclaw_file_delivery_source_capability_cannot_be_substituted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            completed, expected = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            actual = json.loads(json.dumps(expected))
            self.result(actual, "openclaw-file-delivery-policy")["capabilities"] = [
                "OPENCLAW_FILE_DELIVERY_UNEXPECTED"
            ]

            enforced = VERIFIER_MODULE._enforce_source_capability_contract(
                actual, expected
            )

            self.assertEqual(enforced["status"], "TECHNICAL_FAIL")
            self.assertEqual(
                self.result(enforced, "openclaw-file-delivery-policy")["reason"],
                "source-capability-not-restored",
            )

    def test_policy_confirmation_is_explicit_nontechnical_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            completed, report = self.run_verifier(
                home,
                "--policy-confirmation-required",
                "zulip",
                "--credit-blocked",
                "kaggle",
            )

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(
                self.result(report, "zulip")["status"],
                "POLICY_CONFIRMATION_REQUIRED",
            )
            self.assertTrue(self.result(report, "zulip")["configured"])
            self.assertEqual(self.result(report, "kaggle")["status"], "CREDIT_BLOCKED")
            self.assertTrue(self.result(report, "kaggle")["configured"])
            self.assertEqual(report["counts"]["policyConfirmationRequired"], 1)
            self.assertEqual(report["counts"]["creditBlocked"], 1)
            self.assertEqual(report["counts"]["fail"], 0)
            contract = home / "ephemeral-policy-report.json"
            write_json(contract, report, 0o600)
            with self.assertRaises(VERIFIER_MODULE.ClosureIssue):
                VERIFIER_MODULE._load_source_capability_contract(contract)

            # A later restore/readiness pass receives no consent implicitly.
            completed, restored = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(self.result(restored, "zulip")["status"], "PASS")
            self.assertEqual(self.result(restored, "kaggle")["status"], "PASS")
            self.assertEqual(restored["counts"]["policyConfirmationRequired"], 0)

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            completed, report = self.run_verifier(
                home,
                "--policy-confirmation-required",
                "zulip",
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(self.result(report, "zulip")["status"], "NOT_CONFIGURED")
            self.assertEqual(report["counts"]["policyConfirmationRequired"], 0)

    def test_source_contract_preserves_channels_and_compute_backends_individually(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            completed, expected = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            actual = json.loads(json.dumps(expected))
            for identifier in ("zulip", "telegram", "kaggle", "hetzner"):
                self.result(actual, identifier).update(
                    configured=False,
                    items=0,
                    reason="capability-absent",
                    status="NOT_CONFIGURED",
                )

            enforced = VERIFIER_MODULE._enforce_source_capability_contract(
                actual, expected
            )

            self.assertEqual(enforced["status"], "TECHNICAL_FAIL")
            self.assertEqual(
                self.result(enforced, "remote-bridge")["status"], "PASS"
            )
            self.assertEqual(
                self.result(enforced, "compute-credentials")["status"], "PASS"
            )
            for identifier in ("zulip", "telegram", "kaggle", "hetzner"):
                result = self.result(enforced, identifier)
                self.assertEqual(result["status"], "FAIL")
                self.assertEqual(result["reason"], "source-capability-not-restored")
            self.assertEqual(enforced["counts"]["fail"], 4)

    def test_v2_source_capability_contract_remains_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            completed, current = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            legacy = json.loads(json.dumps(current))
            legacy["schema"] = "coding-system.skill-credential-verification/v2"
            legacy["schemaVersion"] = 2
            legacy["checks"] = [
                item
                for item in legacy["checks"]
                if item["id"]
                not in {
                    "zulip",
                    "telegram",
                    "file-delivery-queue",
                    "openclaw-file-delivery-policy",
                    "kaggle",
                    "hetzner",
                    "tailscale",
                    "forms-local",
                }
            ]
            legacy["counts"] = {
                "creditBlocked": 0,
                "fail": 0,
                "notConfigured": 0,
                "pass": 14,
            }
            contract = home / "legacy-source-capabilities.json"
            write_json(contract, legacy, 0o600)

            loaded = VERIFIER_MODULE._load_source_capability_contract(contract)
            self.assertEqual(loaded["schemaVersion"], 2)
            enforced = VERIFIER_MODULE._enforce_source_capability_contract(
                json.loads(json.dumps(current)), loaded
            )
            self.assertEqual(enforced["status"], "PASS")
            self.assertEqual(enforced["counts"]["fail"], 0)

    def test_source_capability_contract_rejects_silent_optional_degradation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            completed, expected = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            actual = json.loads(json.dumps(expected))
            compute = self.result(actual, "compute-credentials")
            compute.update(
                configured=False,
                items=0,
                reason="authority-absent",
                status="NOT_CONFIGURED",
            )

            enforced = VERIFIER_MODULE._enforce_source_capability_contract(
                actual, expected
            )

            self.assertEqual(enforced["status"], "TECHNICAL_FAIL")
            self.assertEqual(
                self.result(enforced, "compute-credentials")["reason"],
                "source-capability-not-restored",
            )
            self.assertEqual(enforced["counts"]["fail"], 1)

    def test_source_capability_contract_rejects_same_count_key_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            completed, expected = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            substitutions = {
                "aas-runtime-secrets": "UNEXPECTED_SHARED_KEY",
                "remote-bridge": "UNEXPECTED_CHANNEL",
                "compute-credentials": "UNEXPECTED_COMPUTE_KEY",
                "skill-credentials": "UNEXPECTED_SKILL_KEY",
                "provider-credentials": "GROK_API_KEY",
                "copilot-credentials": "GITHUB_TOKEN",
                "getscipapers": "GETSCIPAPERS_UNEXPECTED_BACKEND",
            }
            for identifier, replacement in substitutions.items():
                with self.subTest(identifier=identifier):
                    actual = json.loads(json.dumps(expected))
                    result = self.result(actual, identifier)
                    capabilities = list(result["capabilities"])
                    self.assertTrue(capabilities)
                    capabilities[0] = replacement
                    result["capabilities"] = sorted(capabilities)

                    enforced = VERIFIER_MODULE._enforce_source_capability_contract(
                        actual, expected
                    )

                    self.assertEqual(enforced["status"], "TECHNICAL_FAIL")
                    failed = self.result(enforced, identifier)
                    self.assertEqual(
                        failed["reason"], "source-capability-not-restored"
                    )
                    self.assertEqual(failed["items"], 0)
                    self.assertEqual(failed["capabilities"], [])

    def test_source_capability_contract_is_strict_and_owner_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            completed, expected = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            contract = home / "source-capabilities.json"
            write_json(contract, expected, 0o600)
            loaded = VERIFIER_MODULE._load_source_capability_contract(contract)
            self.assertEqual(loaded["status"], "PASS")

            malformed = json.loads(json.dumps(expected))
            malformed["schemaVersion"] = True
            write_json(contract, malformed, 0o600)
            with self.assertRaises(VERIFIER_MODULE.ClosureIssue):
                VERIFIER_MODULE._load_source_capability_contract(contract)

            write_json(contract, expected, 0o644)
            with self.assertRaises(VERIFIER_MODULE.ClosureIssue):
                VERIFIER_MODULE._load_source_capability_contract(contract)

    def test_legacy_configured_source_without_canonical_authority_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            write_json(
                home / ".claude/secrets.json",
                {"ZOTERO_API_KEY": "aas-api-secret-never-report"},
                0o600,
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            result = self.result(report, "aas-runtime-secrets")
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["reason"], "legacy-authority-unmigrated")

    def test_migrated_credentials_cannot_remain_in_ambient_shell_env(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            write_text(
                home / ".secrets.env",
                "ZOTERO_API_KEY=ambient-shell-secret-never-report\n"
                "LEANEXPLORE_API_KEY=ambient-shell-secret-never-report\n",
                0o600,
            )

            completed, report = self.run_verifier(home)

            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "aas-runtime-secrets")["reason"],
                "owner-settings-invalid",
            )
            self.assertEqual(
                self.result(report, "skill-credentials")["reason"],
                "ambient-shell-credential-present",
            )
            self.assertNotIn(
                "ambient-shell-secret-never-report",
                completed.stdout + completed.stderr + json.dumps(report),
            )

    def test_shell_startup_cannot_source_moltbook_or_opengauss_credentials(self) -> None:
        cases = (
            (".bashrc", '. "$HOME/.openclaw/moltbook.env"\n'),
            (".profile", '. "$GAUSS_HOME/.env"\n'),
        )
        for relative, payload in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                write_text(home / relative, payload, 0o600)
                completed, report = self.run_verifier(home)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(
                    self.result(report, "aas-runtime-secrets")["reason"],
                    "ambient-shell-credential-source",
                )

    def test_legacy_shell_reader_preserves_unquoted_hash_as_credential_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            write_text(
                home / ".secrets.env",
                "KAGGLE_API_TOKEN=fixture#hash-never-truncate\n",
                0o600,
            )
            self.assertEqual(
                VERIFIER_MODULE._legacy_shell_values(
                    home, frozenset({"KAGGLE_API_TOKEN"})
                ),
                {"KAGGLE_API_TOKEN": "fixture#hash-never-truncate"},
            )

    def test_divergent_projection_fails_and_both_payloads_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            authority = home / ".config/ai-agents-skills/secrets.json"
            write_json(authority, {"ZOTERO_API_KEY": "aas-api-secret-never-report"}, 0o600)
            write_json(
                home / ".codex/runtime/workspace/.secrets.json",
                {"ZOTERO_API_KEY": "divergent-secret-never-report"},
                0o600,
            )
            write_bytes(
                home / ".local/share/ai-agents-skills/runtime/workspace/.secrets.json",
                authority.read_bytes(),
                0o600,
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "aas-runtime-secrets")["reason"],
                "projection-divergent",
            )
            self.assertNotIn("divergent-secret-never-report", completed.stdout + completed.stderr)
            self.assertNotIn("divergent-secret-never-report", json.dumps(report))

    def test_narrow_openclaw_projections_are_required_and_broad_skill_mirror_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            (
                home
                / ".openclaw/workspace/.config/ai-agents-skills/zotero-secrets.json"
            ).unlink()

            completed, report = self.run_verifier(home)

            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "zotero")["reason"], "projection-missing"
            )

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            write_text(
                home
                / ".openclaw/workspace/.config/ai-agents-skills/skill.env",
                "LEANEXPLORE_API_KEY=stale-broad-canary\n",
                0o600,
            )

            completed, report = self.run_verifier(home)

            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "skill-credentials")["reason"],
                "stale-projection",
            )
            self.assertNotIn("stale-broad-canary", completed.stdout + completed.stderr)

    def test_retired_broad_openclaw_workspace_authority_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            write_json(
                home / ".openclaw/workspace/.secrets.json",
                {"GATEWAY_AUTH_TOKEN": "broad-secret-canary"},
                0o600,
            )

            completed, report = self.run_verifier(home)

            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "aas-runtime-secrets")["reason"],
                "broad-openclaw-workspace-secrets-present",
            )
            self.assertNotIn("broad-secret-canary", completed.stdout + completed.stderr)

    def test_send_email_cannot_be_merged_wholesale_into_shared_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            shared = home / ".config/ai-agents-skills/secrets.json"
            write_json(
                shared,
                {
                    "smtp": {
                        "host": "smtp.example.invalid",
                        "password": "smtp-password-secret-never-report",  # LEAKSCAN-EXEMPT: synthetic fixture
                    }
                },
                0o600,
            )
            mirror(
                shared,
                (
                    (home / ".codex/runtime/workspace/.secrets.json", 0o600),
                    (
                        home
                        / ".local/share/ai-agents-skills/runtime/workspace/.secrets.json",
                        0o600,
                    ),
                ),
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "aas-runtime-secrets")["reason"],
                "shared-authority-contains-unsupported-fields",
            )
            self.assertEqual(
                self.result(report, "send-email")["reason"],
                "send-email-duplicated-in-shared-authority",
            )

    def test_send_email_openclaw_projection_is_retired(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.write_selector_state(home)
            authority = home / ".config/send-email/secrets.json"
            write_json(
                authority,
                {
                    "smtp": {
                        "from": "sender@example.invalid",
                        "host": "smtp.example.invalid",
                        "password": "smtp-password-secret-never-report",  # LEAKSCAN-EXEMPT: synthetic fixture
                        "user": "sender@example.invalid",
                    }
                },
                0o600,
            )
            mirror(
                authority,
                ((home / ".openclaw/workspace/.config/send-email/secrets.json", 0o600),),
            )

            completed, report = self.run_verifier(home)

            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "send-email")["reason"],
                "stale-send-email-openclaw-projection",
            )

    def test_strict_env_rejects_unknown_duplicate_and_selector_drift(self) -> None:
        cases = (
            ("UNKNOWN_KEY=value\n", "invalid-env-entry"),
            ("LEANEXPLORE_API_KEY=one\nLEANEXPLORE_API_KEY=two\n", "invalid-env-entry"),
            ("LEANEXPLORE_API_KEY=value \n", "invalid-env-line"),
            ("LEANEXPLORE_API_KEY=value\tinside\n", "invalid-env-entry"),
            ("LEANEXPLORE_API_KEY=value\x7finside\n", "invalid-env-entry"),
        )
        for payload, reason in cases:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                authority = home / ".config/ai-agents-skills/skill.env"
                write_text(authority, payload, 0o600)
                completed, report = self.run_verifier(home)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(self.result(report, "skill-credentials")["reason"], reason)

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            config = (home / ".codex/config.toml").read_text(encoding="utf-8")
            config = config.replace(
                str(home / ".config/ai-agents-skills/providers.env"),
                str(home / ".config/ai-agents-skills/wrong.env"),
            )
            write_text(home / ".codex/config.toml", config, 0o600)
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "provider-credentials")["reason"],
                "codex-selector-divergent",
            )

    def test_openclaw_selectors_are_main_only_and_stale_main_values_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            path = home / ".openclaw/openclaw.json"
            config = json.loads(path.read_text(encoding="utf-8"))
            main_environment = config["agents"]["list"][0]["sandbox"]["docker"]["env"]
            self.assertTrue(
                {
                    "AAS_SECRETS_FILE",
                    "OPENCLAW_SECRETS_FILE",
                    "AAS_SKILL_SECRETS_FILE",
                    "AAS_AXLE_SECRETS_FILE",
                    "AAS_LEANEXPLORE_SECRETS_FILE",
                    "AAS_RESEARCH_DIGEST_SECRETS_FILE",
                    "AAS_SUBMISSION_VENUE_SECRETS_FILE",
                    "AAS_ZOTERO_SKILL_SECRETS_FILE",
                    "AAS_FILE_DELIVERY_SECRETS_FILE",
                    "REMOTE_BRIDGE_SECRETS_FILE",
                }.isdisjoint(main_environment)
            )
            self.assertEqual(
                main_environment["GETSCIPAPERS_CONFIG_DIR"],
                "/workspace/.config/getscipapers",
            )
            self.assertEqual(
                main_environment["GETSCIPAPERS_SKILL_CONFIG"],
                "/workspace/data/research/getscipapers_bot/state/config.json",
            )
            main_environment["REMOTE_BRIDGE_SECRETS_FILE"] = (
                "/workspace/secrets/remote-bridge/secrets.json"
            )
            write_json(path, config, 0o600)

            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "remote-bridge")["reason"],
                "openclaw-retired-selector-present",
            )

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            path = home / ".openclaw/openclaw.json"
            config = json.loads(path.read_text(encoding="utf-8"))
            config["agents"]["list"][0]["sandbox"]["docker"]["env"][
                "OPENCLAW_SECRETS_FILE"
            ] = "/workspace/.secrets.json"
            write_json(path, config, 0o600)

            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "aas-runtime-secrets")["reason"],
                "openclaw-retired-selector-present",
            )

    def test_remote_bridge_is_host_only_and_rejects_openclaw_projections(self) -> None:
        retired_relatives = (
            ".openclaw/workspace/.config/remote-bridge/secrets.json",
            ".openclaw/workspace/secrets/remote-bridge/secrets.json",
        )
        for relative in retired_relatives:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                self.populate_complete(home)
                authority = home / ".config/remote-bridge/secrets.json"
                for candidate in retired_relatives:
                    self.assertFalse((home / candidate).exists())
                write_bytes(home / relative, authority.read_bytes(), 0o600)

                completed, report = self.run_verifier(home)

                self.assertEqual(completed.returncode, 2)
                self.assertEqual(
                    self.result(report, "remote-bridge")["reason"],
                    "stale-remote-bridge-openclaw-projection",
                )

        leakage_cases = (
            ("defaults", "AAS_PROVIDER_SECRETS_FILE", "provider-credentials"),
            ("defaults", "OPENCLAW_SECRETS_FILE", "aas-runtime-secrets"),
            ("defaults", "AAS_ZOTERO_SKILL_SECRETS_FILE", "zotero"),
            ("defaults", "AAS_ZOTERO_SECRETS_FILE", "zotero"),
            (
                "defaults",
                "AAS_FILE_DELIVERY_SECRETS_FILE",
                "file-delivery-queue",
            ),
            ("auxiliary", "CANVAS_CONFIG_PATH", "canvas"),
            ("auxiliary", "GETSCIPAPERS_CONFIG_DIR", "getscipapers"),
            ("auxiliary", "GETSCIPAPERS_SKILL_CONFIG", "getscipapers"),
        )
        for location, selector, identifier in leakage_cases:
            with self.subTest(location=location, selector=selector), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                self.populate_complete(home)
                path = home / ".openclaw/openclaw.json"
                config = json.loads(path.read_text(encoding="utf-8"))
                if location == "defaults":
                    environment = config["agents"]["defaults"]["sandbox"]["docker"]["env"]
                else:
                    auxiliary = config["agents"]["list"][1]
                    auxiliary["sandbox"] = {"docker": {"env": {}}}
                    environment = auxiliary["sandbox"]["docker"]["env"]
                environment[selector] = "/workspace/stale-selector"
                write_json(path, config, 0o600)

                completed, report = self.run_verifier(home)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(
                    self.result(report, identifier)["reason"],
                    "openclaw-selector-overbroad",
                )

    def test_openclaw_selector_policy_rejects_missing_or_ambiguous_main(self) -> None:
        cases = ([], [{"id": "main"}, {"id": "main"}])
        for listed in cases:
            with self.subTest(count=len(listed)), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                self.populate_complete(home)
                path = home / ".openclaw/openclaw.json"
                config = json.loads(path.read_text(encoding="utf-8"))
                config["agents"]["list"] = listed
                write_json(path, config, 0o600)

                completed, report = self.run_verifier(home)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(
                    self.result(report, "aas-runtime-secrets")["reason"],
                    "openclaw-main-agent-invalid",
                )

    def test_openclaw_auxiliary_agents_cannot_advertise_skills(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.populate_complete(home)
            path = home / ".openclaw/openclaw.json"
            config = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(config["agents"]["list"][0]["skills"], ["main-skill"])
            config["agents"]["list"][1]["skills"] = ["send-email"]
            write_json(path, config, 0o600)

            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "aas-runtime-secrets")["reason"],
                "openclaw-auxiliary-skills-enabled",
            )

    def test_google_client_without_oauth_token_is_not_configured_not_failed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.write_selector_state(home)
            authority = home / ".config/course/google-classroom/credentials.json"
            write_json(
                authority,
                {
                    "installed": {
                        "auth_uri": "https://accounts.example.invalid/auth",
                        "client_id": "fixture-client",
                        "client_secret": "google-client-secret-never-report",  # LEAKSCAN-EXEMPT: synthetic fixture
                        "token_uri": "https://accounts.example.invalid/token",
                    }
                },
                0o600,
            )
            mirror(
                authority,
                (
                    (
                        home
                        / ".openclaw/workspace/.config/course/google-classroom/credentials.json",
                        0o600,
                    ),
                ),
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            classroom = self.result(report, "google-classroom")
            self.assertEqual(classroom["status"], "NOT_CONFIGURED")
            self.assertEqual(classroom["reason"], "oauth-token-not-configured")

    def test_vnu_allows_password_hmac_fallback_but_rejects_weak_dedicated_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            authority = home / ".config/vnu-eoffice/secrets.json"
            write_json(
                authority,
                {
                    "VNU_EOFFICE_USERNAME": "fixture-user",
                    "VNU_EOFFICE_PASSWORD": "vnu-password-secret-never-report",
                },
                0o600,
            )
            mirror(
                authority,
                ((home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json", 0o600),),
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(self.result(report, "vnu-eoffice")["status"], "PASS")
            self.assertEqual(self.result(report, "vnu-eoffice")["items"], 2)

            write_json(
                authority,
                {
                    "VNU_EOFFICE_USERNAME": "fixture-user",
                    "VNU_EOFFICE_PASSWORD": "vnu-password-secret-never-report",
                    "VNU_STATE_HMAC_KEY": "too-short",
                },
                0o600,
            )
            mirror(
                authority,
                ((home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json", 0o600),),
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "vnu-eoffice")["reason"],
                "vnu-hmac-key-weak",
            )

            write_json(
                authority,
                {
                    "VNU_EOFFICE_USERNAME": "fixture-user",
                    "VNU_EOFFICE_PASSWORD": "vnu-password-secret-never-report",
                    "TELEGRAM_BOT_TOKEN": "retired-vnu-delivery-canary",
                },
                0o600,
            )
            mirror(
                authority,
                ((home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json", 0o600),),
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "vnu-eoffice")["reason"],
                "vnu-authority-contains-retired-delivery-fields",
            )

    def write_getscipapers_credential(self, home: Path) -> None:
        """Give a GetSciPapers fixture the one credential that makes it usable."""

        relative = "ablesci/credentials.json"
        payload = {"username": "synthetic", "password": "synthetic-never-reported"}  # LEAKSCAN-EXEMPT: synthetic fixture
        write_json(home / ".config/getscipapers" / relative, payload, 0o600)
        write_json(
            home / ".openclaw/workspace/.config/getscipapers" / relative,
            payload,
            0o600,
        )

    def test_getscipapers_authority_of_only_caches_is_reported_as_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.write_selector_state(home)
            source = home / ".config/getscipapers/nexus/telegram_session.session"
            write_bytes(source, b"opaque-session-not-deserialized", 0o600)
            write_bytes(
                home
                / ".openclaw/workspace/.config/getscipapers/nexus/telegram_session.session",
                source.read_bytes(),
                0o600,
            )

            completed, report = self.run_verifier(home)

            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "getscipapers")["reason"],
                "getscipapers-credentials-absent",
            )

            self.write_getscipapers_credential(home)
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(self.result(report, "getscipapers")["status"], "PASS")

    def test_getscipapers_empty_authority_root_is_not_an_opt_out(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.write_selector_state(home)

            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(
                self.result(report, "getscipapers")["status"], "NOT_CONFIGURED"
            )

            (home / ".config/getscipapers").mkdir(parents=True)
            (home / ".config/getscipapers").chmod(0o700)

            completed, report = self.run_verifier(home)

            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "getscipapers")["reason"],
                "getscipapers-authority-empty",
            )

    def test_getscipapers_declared_sessions_are_opaque_and_unknown_files_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.write_selector_state(home)
            self.write_getscipapers_credential(home)
            source = home / ".config/getscipapers/nexus/telegram_session.session"
            write_bytes(source, b"opaque-session-not-deserialized", 0o600)
            write_bytes(
                home
                / ".openclaw/workspace/.config/getscipapers/nexus/telegram_session.session",
                source.read_bytes(),
                0o600,
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(self.result(report, "getscipapers")["status"], "PASS")

            write_text(home / ".config/getscipapers/nexus/runtime.log", "private-log", 0o600)
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "getscipapers")["reason"],
                "getscipapers-file-undeclared",
            )

    def test_getscipapers_selectors_must_be_canonical_on_main(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.write_selector_state(home)
            self.write_getscipapers_credential(home)
            authority = home / ".config/getscipapers/nexus/telegram_session.session"
            write_bytes(authority, b"opaque-session-not-deserialized", 0o600)
            write_bytes(
                home
                / ".openclaw/workspace/.config/getscipapers/nexus/telegram_session.session",
                authority.read_bytes(),
                0o600,
            )
            config_path = home / ".openclaw/openclaw.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["agents"]["list"][0]["sandbox"]["docker"]["env"][
                "GETSCIPAPERS_SKILL_CONFIG"
            ] = "/workspace/stale-getscipapers-config.json"
            write_json(config_path, config, 0o600)

            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "getscipapers")["reason"],
                "openclaw-selector-divergent",
            )

    def test_legacy_getscipapers_projection_is_a_technical_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            write_json(
                home / ".openclaw/workspace/secrets/getscipapers/ablesci/credentials.json",
                {"password": "getscipapers-secret-never-report"},  # LEAKSCAN-EXEMPT: synthetic fixture
                0o600,
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "getscipapers")["reason"],
                "getscipapers-legacy-projection-remains",
            )

    def test_credit_blocked_is_nontechnical_and_preserves_configured_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            authority = home / ".modal.toml"
            write_text(
                authority,
                '[default]\ntoken_id="fixture"\n'
                'token_secret="modal-token-secret-never-report"\n',
                0o600,
            )
            mirror(authority, ((home / ".openclaw/workspace/.modal.toml", 0o600),))
            completed, report = self.run_verifier(home, "--credit-blocked", "modal")
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            modal = self.result(report, "modal")
            self.assertEqual(modal["status"], "CREDIT_BLOCKED")
            self.assertTrue(modal["configured"])
            self.assertEqual(report["counts"]["creditBlocked"], 1)
            self.assertEqual(report["counts"]["fail"], 0)

    def test_unsafe_mode_and_symlink_are_redacted_technical_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            write_json(
                home / ".config/ai-agents-skills/secrets.json",
                {"ZOTERO_API_KEY": "aas-api-secret-never-report"},
                0o644,
            )
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(self.result(report, "aas-runtime-secrets")["reason"], "unsafe-file")

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            target = home / "private-target"
            write_json(target, {"ZOTERO_API_KEY": "aas-api-secret-never-report"}, 0o600)
            link = home / ".config/ai-agents-skills/secrets.json"
            link.parent.mkdir(parents=True)
            link.symlink_to(target)
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(self.result(report, "aas-runtime-secrets")["reason"], "unsafe-file")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            outside = root / "outside"
            home.mkdir(mode=0o700)
            outside.mkdir(mode=0o700)
            write_json(
                outside / "ai-agents-skills/secrets.json",
                {"ZOTERO_API_KEY": "aas-api-secret-never-report"},
                0o600,
            )
            (home / ".config").symlink_to(outside, target_is_directory=True)
            completed, report = self.run_verifier(home)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                self.result(report, "aas-runtime-secrets")["reason"], "unsafe-file"
            )

    def test_report_output_rejects_symlinked_parent_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            repository = home / ".credential-contract-repository"
            copy_contract_repository(repository)
            outside = home / "outside"
            outside.mkdir(mode=0o700)
            marker = outside / "verification-report.json"
            marker.write_text("unchanged\n", encoding="utf-8")
            (home / "linked-output").symlink_to(outside, target_is_directory=True)

            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(SCRIPT),
                    "--home",
                    str(home),
                    "--repository",
                    str(repository),
                    "--output",
                    str(home / "linked-output/verification-report.json"),
                ],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "HOME": str(home),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": "/usr/bin:/bin",
                },
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("unsafe-report-output", completed.stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"), "unchanged\n")

    def test_report_output_rejects_group_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            repository = home / ".credential-contract-repository"
            copy_contract_repository(repository)
            output_parent = home / "shared-output"
            output_parent.mkdir(mode=0o770)
            output_parent.chmod(0o770)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(SCRIPT),
                    "--home",
                    str(home),
                    "--repository",
                    str(repository),
                    "--output",
                    str(output_parent / "verification-report.json"),
                ],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "HOME": str(home),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": "/usr/bin:/bin",
                },
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("unsafe-report-output", completed.stderr)
            self.assertEqual(list(output_parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
