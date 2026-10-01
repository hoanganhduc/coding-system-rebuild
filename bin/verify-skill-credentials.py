#!/usr/bin/env python3
"""Verify offline skill credential authority, projection, and resolver closure.

The verifier deliberately never authenticates to a provider.  It validates the
portable bytes that a restore owns, the exact derived copies that runtimes
resolve, and the selector paths that connect those copies to the installed
agents.  Optional credentials that have never been configured are reported as
``NOT_CONFIGURED``.  A caller may carry forward an independently established
quota result with ``--credit-blocked`` or an explicit operation-policy gate
with ``--policy-confirmation-required``.  Neither state makes this command
fail, and credential presence never implies that policy consent was granted.

Credential values, digests, account names, service names, and exception text
are never serialized or printed.
"""

from __future__ import annotations

import argparse
import contextvars
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tomllib
from typing import Any, Callable

LIB = Path(__file__).resolve().parent / "lib"
if os.fspath(LIB) not in sys.path:
    sys.path.insert(0, os.fspath(LIB))
from component_paths import ComponentPathError, resolve_component_path  # noqa: E402
from owner_settings import OwnerSettingsError, read_owner_settings  # noqa: E402
from tailscale_authority import (  # noqa: E402
    AUTHKEY_RELATIVE as TAILSCALE_AUTHKEY_RELATIVE,
    HOSTNAME_RELATIVE as TAILSCALE_HOSTNAME_RELATIVE,
    LEGACY_RELATIVE as TAILSCALE_LEGACY_RELATIVE,
    TailscaleAuthorityError,
    local_backend_state as tailscale_backend_state,
    parse_authkey as parse_tailscale_authkey,
    parse_hostname as parse_tailscale_hostname,
)


SCHEMA = "coding-system.skill-credential-verification/v3"
LEGACY_SCHEMA = "coding-system.skill-credential-verification/v2"
SCHEMA_VERSION = 3
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
CHECK_IDS = (
    "aas-runtime-secrets",
    "remote-bridge",
    "zulip",
    "telegram",
    "send-email",
    "file-delivery-queue",
    "openclaw-file-delivery-policy",
    "compute-credentials",
    "kaggle",
    "hetzner",
    "skill-credentials",
    "provider-credentials",
    "copilot-credentials",
    "modal",
    "zotero",
    "calibre",
    "google-classroom",
    "canvas",
    "vnu-eoffice",
    "getscipapers",
    "tailscale",
    "forms-local",
)
LEGACY_CHECK_IDS = tuple(
    identifier
    for identifier in CHECK_IDS
    if identifier
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
)
POLICY_CONFIRMATION_IDS = frozenset({"zulip", "kaggle", "hetzner"})
CONFIGURED_STATUSES = frozenset(
    {"PASS", "CREDIT_BLOCKED", "POLICY_CONFIRMATION_REQUIRED", "REAUTH_REQUIRED"}
)
STATUS_COUNT_KEYS = {
    "CREDIT_BLOCKED": "creditBlocked",
    "FAIL": "fail",
    "NOT_CONFIGURED": "notConfigured",
    "PASS": "pass",
    "POLICY_CONFIRMATION_REQUIRED": "policyConfirmationRequired",
    "REAUTH_REQUIRED": "reauthRequired",
}
COUNT_KEYS = frozenset(STATUS_COUNT_KEYS.values())
LEGACY_COUNT_KEYS = frozenset(
    COUNT_KEYS - {"policyConfirmationRequired", "reauthRequired"}
)
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
        "AAS_SKILL_SECRETS_FILE",
        "AAS_AXLE_SECRETS_FILE",
        "AAS_LEANEXPLORE_SECRETS_FILE",
        "AAS_RESEARCH_DIGEST_SECRETS_FILE",
        "AAS_SUBMISSION_VENUE_SECRETS_FILE",
        "AAS_ZOTERO_SKILL_SECRETS_FILE",
        "AAS_ZOTERO_SECRETS_FILE",
        "AAS_CALIBRE_SECRETS_FILE",
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

AAS_JSON_KEYS = frozenset(
    {
        "ZOTERO_API_KEY",
        "WEBDAV_PASSWORD",
        "GDRIVE_CREDENTIALS",
        "TELEGRAM_BOT_TOKEN",
        "CALIBRE_GDRIVE_FOLDER_ID",
    }
)
COMPUTE_KEYS = frozenset(
    {
        "HCLOUD_TOKEN",
        "HCLOUD_SSH_KEYS",
        "KAGGLE_API_TOKEN",
        "KAGGLE_CONFIG_DIR",
    }
)
SKILL_KEYS = frozenset(
    {
        "AXLE_API_KEY",
        "LEANEXPLORE_API_KEY",
        "OCR_SPACE_API_KEY",
        "OCR_SPACE_KEY",
        "OCRSPACE_API_KEY",
        "OCRSPACE_KEY",
        "OPENCLAW_S2_API_KEY",
        "SEMANTIC_SCHOLAR_API_KEY",
        "UNPAYWALL_EMAIL",
        "ZENODO_TOKEN",
    }
)
PROVIDER_KEYS = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "DEEPSEEK_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GROK_API_KEY",
        "KIMI_API_KEY",
        "MOONSHOT_API_KEY",
        "OPENAI_API_KEY",
        "OPENCODE_API_KEY",
        "XAI_API_KEY",
    }
)
COPILOT_KEYS = frozenset(
    {
        "COPILOT_GITHUB_TOKEN",
        "COPILOT_PROVIDER_API_KEY",
        "COPILOT_PROVIDER_BEARER_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
    }
)
EXACT_CAPABILITY_IDS = frozenset(
    {
        "aas-runtime-secrets",
        "remote-bridge",
        "file-delivery-queue",
        "openclaw-file-delivery-policy",
        "compute-credentials",
        "skill-credentials",
        "provider-credentials",
        "copilot-credentials",
        "getscipapers",
        "tailscale",
        "forms-local",
    }
)
REMOTE_BRIDGE_LEGACY_KEYS = {
    "site": "ZULIP_ORG_URL",
    "email": "ZULIP_EMAIL",
    "api_key": "ZULIP_API_KEY",
}
VNU_REQUIRED_KEYS = (
    "VNU_EOFFICE_USERNAME",
    "VNU_EOFFICE_PASSWORD",
)
VNU_HMAC_KEY = "VNU_STATE_HMAC_KEY"
CANVAS_CONFIG_KEYS = frozenset(
    {
        "CANVAS_LMS_API_URL",
        "CANVAS_LMS_API_KEY",
        "CANVAS_LMS_COURSE_ID",
    }
)
ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
FILE_DELIVERY_AUTHORITY_KEYS = frozenset(
    {
        "version",
        "hmac_key_hex",
        "allowed",
        "max_job_age_seconds",
        "max_media_bytes",
        "replay_ledger_dir",
        "replay_retention_seconds",
        "max_replay_entries",
    }
)
FILE_DELIVERY_REPLAY_TOKEN = "aas-host-state:file-delivery-replay"
FILE_DELIVERY_CHANNEL_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
FILE_DELIVERY_MARKER_RE = re.compile(r"^[0-9a-f]{64}\.used$")
FILE_DELIVERY_JOB_RE = re.compile(r"^job-[0-9]{10}-[0-9a-f]{16}$")
OPENCLAW_FILE_DELIVERY_SCHEMA = "openclaw.file-delivery-policy/v1"
OPENCLAW_FILE_DELIVERY_CHANNELS = frozenset(
    {"telegram", "zulip", "googlechat", "whatsapp", "zalo"}
)
GETSCIPAPERS_FILES = {
    "ablesci/ablesci_cache.pkl": False,
    "ablesci/credentials.json": True,
    "facebook/credentials.json": True,
    "facebook/facebook_session_cache.pkl": False,
    "getpapers/config.json": True,
    "getpapers/proxy.json": True,
    "getpapers/proxy_list.json": True,
    "getpapers/unpywall_cache": False,
    "nexus/credentials.json": True,
    "nexus/proxy.json": True,
    "nexus/proxy_list.json": True,
    "nexus/telegram_session.session": False,
    "scinet/credentials.json": True,
    "scinet/scinet_cache.pkl": False,
    "wosonhj/credentials.json": True,
    "wosonhj/wosonhj_cache.pkl": False,
    "zlib/zlib_config.json": True,
}
SEND_EMAIL_PROFILE_KEYS = frozenset(
    {
        "host",
        "port",
        "user",
        "username",
        "password",
        "pass",
        "from",
        "sender",
        "security",
        "timeout",
        "from_name",
        "reply_to",
        "cc",
        "bcc",
        "signature",
        "signature_html",
        "reply_to_self",
        "bcc_self",
        "pgp_sign",
        "pgp_key",
        "pgp_passphrase",
        "gnupg_home",
    }
)
SEND_EMAIL_TOP_LEVEL = frozenset(
    {"smtp", "accounts", "default_account", "_README"}
)


@dataclass(frozen=True)
class SourceContract:
    """One checked-in credential resolver contract, never credential data."""

    root: str
    relative: str
    fragments: tuple[str, ...]
    normalized_fragments: tuple[str, ...] = ()
    forbidden_fragments: tuple[str, ...] = ()
    normalized_forbidden_fragments: tuple[str, ...] = ()
    identical_to: str | None = None


@dataclass(frozen=True)
class PinnedGitSource:
    """One component source tree addressed by its immutable Git commit."""

    repository: Path
    revision: str


_ACTIVE_AAS_SOURCE: contextvars.ContextVar[Path | PinnedGitSource | None] = (
    contextvars.ContextVar("credential_aas_source", default=None)
)
_ACTIVE_REPOSITORY: contextvars.ContextVar[Path | None] = contextvars.ContextVar(
    "credential_repository", default=None
)

ARL_CONSUMER_MODULES = (
    "anti_false_consensus.py",
    "apply_failover_settings.py",
    "arl_compute_proxy.py",
    "arl_credential_client.py",
    "autonomous_research_loop_runtime.py",
    "compute_policy.py",
    "formal_policy.py",
    "goal_focus.py",
    "goal_priority.py",
    "negative_space.py",
    "notify_v2.py",
    "panel_parent.py",
    "provider_resources.py",
    "state_transaction.py",
    "sync_panel_exclude.py",
)

# Per-module resolver assertions for the ARL consumers. The broker client is the
# only module that holds a credential capability, and it must consume that
# bearer out of the environment at import time so ordinary subprocess
# environment copies cannot inherit it.
ARL_CONSUMER_MODULE_FRAGMENTS: dict[str, tuple[str, ...]] = {
    "arl_credential_client.py": (
        "os.environ.pop(BROKER_SOCKET_ENV",
        "os.environ.pop(BROKER_TOKEN_ENV",
        "def broker_active",
    ),
    "autonomous_research_loop_runtime.py": (
        "detect_configured_notify_channels",
        "auto_notify_channel_from_secrets",
    ),
}
ARL_CONSUMER_MODULE_FORBIDDEN: dict[str, tuple[str, ...]] = {
    "arl_credential_client.py": ("os.environ.get(BROKER_TOKEN_ENV",),
}


STRICT_ENV_LOADER = SourceContract(
    "aas",
    "canonical/runtime/runners/load_secret_env.py",
    ("O_NOFOLLOW", "st_nlink", "allowed_keys", "os.execvpe"),
)
CREDENTIAL_PROJECTION_PROBE_CONTRACT = SourceContract(
    "aas",
    "canonical/runtime/runners/credential_projection_probe.py",
    (
        "credential_projection_check.py",
        "load_pointer_secret_env",
        "--expect-key",
        "PASS lane=",
    ),
)
CREDENTIAL_PROJECTION_CHECK_CONTRACT = SourceContract(
    "aas",
    "canonical/runtime/runners/credential_projection_check.py",
    ("--expect-any-key", "--forbid-key", "pointer-leak", "PASS lane="),
)
OPENCLAW_SKILL_LOADER_RELATIVE = "workspace/skills/_load_skill_secrets.py"
OPENCLAW_SKILL_LOADER_CONTRACT = SourceContract(
    "openclaw",
    OPENCLAW_SKILL_LOADER_RELATIVE,
    (
        "SECRET_PROJECTIONS",
        "AAS_AXLE_SECRETS_FILE",
        "AAS_LEANEXPLORE_SECRETS_FILE",
        "AAS_RESEARCH_DIGEST_SECRETS_FILE",
        "AAS_SUBMISSION_VENUE_SECRETS_FILE",
        "AAS_ZOTERO_SKILL_SECRETS_FILE",
        "home:.config/ai-agents-skills/axiom-axle.env",
        "home:.config/ai-agents-skills/lean-explore.env",
        "home:.config/ai-agents-skills/research-digest.env",
        "home:.config/ai-agents-skills/submission-venue.env",
        "workspace:.config/ai-agents-skills/calibre-secrets.json",
        "workspace:.config/ai-agents-skills/zotero-secrets.json",
        "FORBIDDEN_SHARED_SELECTORS",
        "SAFE_INHERITED_ENV",
        "O_NOFOLLOW",
        "st_nlink",
        "os.environ.clear()",
        "runpy.run_path",
        'parser.add_argument("--profile"',
        "profile.script",
    ),
    forbidden_fragments=(
        "--python-script",
        "os.environ.copy(",
        "os.execve(",
        "os.execvpe(",
    ),
)
SOURCE_CONTRACTS: dict[str, tuple[SourceContract, ...]] = {
    "aas-runtime-secrets": (
        SourceContract(
            "aas",
            "canonical/runtime/runners/run_skill.sh",
            (
                "unset AAS_SECRETS_FILE OPENCLAW_SECRETS_FILE",
                "AAS_CALIBRE_SECRETS_FILE",
                "AAS_ZOTERO_SECRETS_FILE",
                "AAS_FILE_DELIVERY_SECRETS_FILE",
            ),
            forbidden_fragments=("workspace_real/.secrets.json",),
        ),
    ),
    "remote-bridge": (
        SourceContract(
            "repository",
            "bin/materialize-secret-projections.py",
            (
                ".config/remote-bridge/secrets.json",
                ".openclaw/workspace/.config/remote-bridge/secrets.json",
                ".openclaw/workspace/secrets/remote-bridge/secrets.json",
                "_migrate_remote_bridge_legacy",
                "_retire_remote_bridge_openclaw_projection",
                "_remove_projection",
            ),
        ),
        SourceContract(
            "repository",
            "bin/migrate-openclaw-config.py",
            (
                "REMOTE_BRIDGE_SECRETS_FILE",
                "OPENCLAW_RETIRED_SELECTOR_KEYS",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/remote-bridge/dispatch_aas.py",
            (
                '"status": "retired"',
                '"error_code": "openclaw_control_adapter_retired"',
                '"spawned": False',
                '"destination_inspected": False',
            ),
            forbidden_fragments=(
                "REMOTE_BRIDGE_SECRETS_FILE",
                "secrets.json",
                "subprocess",
                "os.environ",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/remote-bridge/remote_bridge.py",
            (
                "REMOTE_BRIDGE_SECRETS_FILE",
                "_secure_read_secrets_file",
                "explicit remote-bridge secrets file",
            ),
        ),
        *(
            SourceContract(
                "aas",
                (
                    "canonical/runtime/skills/"
                    f"autonomous-research-loop-runtime/{name}"
                ),
                ARL_CONSUMER_MODULE_FRAGMENTS.get(name, ()),
                forbidden_fragments=ARL_CONSUMER_MODULE_FORBIDDEN.get(name, ()),
            )
            for name in ARL_CONSUMER_MODULES
        ),
    ),
    "send-email": (
        SourceContract(
            "repository",
            "bin/materialize-secret-projections.py",
            (
                ".config/send-email/secrets.json",
                ".openclaw/workspace/.config/send-email/secrets.json",
                "retired-send-email-openclaw-projection",
            ),
        ),
        SourceContract(
            "repository",
            "bin/migrate-openclaw-config.py",
            (
                "SEND_EMAIL_SECRETS_FILE",
                "OPENCLAW_RETIRED_SELECTOR_KEYS",
            ),
            forbidden_fragments=(
                '"SEND_EMAIL_SECRETS_FILE": "/workspace/.config/send-email/secrets.json"',
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/send-email/send_email.py",
            (
                "SEND_EMAIL_SECRETS_FILE",
                "--secrets-file",
                "_secret_candidates",
                "_read_private_secret_bytes",
                "O_NOFOLLOW",
                "st_nlink",
            ),
            forbidden_fragments=(
                'os.environ.get("AAS_SECRETS_FILE")',
                'os.environ.get("OPENCLAW_SECRETS_FILE")',
                'os.environ.get("AAS_SKILL_SECRETS_FILE")',
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/send-email/run_send_email.sh",
            (
                "run_send_email_host.sh",
                "SEND_EMAIL_SECRETS_FILE=/dev/null",
                "SEND_EMAIL_EXACT_QUEUE=1",
            ),
            forbidden_fragments=(
                'export AAS_SECRETS_FILE=',
                "/workspace/.config/send-email/secrets.json",
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/send-email/run_send_email_host.sh",
            (
                "--host-approval-id",
                'Q="$WS/data/email-queue"',
                '"type": "email"',
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/send-email/send_email.py",
            ("SEND_EMAIL_SECRETS_FILE", "_read_secrets_file", "O_NOFOLLOW", "st_nlink"),
            normalized_fragments=(
                'Path.home() / ".config" / "send-email" / "secrets.json"',
            ),
            forbidden_fragments=("AAS_SECRETS_FILE", "OPENCLAW_SECRETS_FILE"),
        ),
        SourceContract(
            "openclaw",
            "systemd/user/openclaw-email-worker.service",
            (
                "OPENCLAW_QUEUE_KIND=email",
                "BindReadOnlyPaths={{ USER_HOME }}/.config/send-email",
                "BindPaths={{ OPENCLAW_HOME }}/email-approvals",
                "BindPaths={{ OPENCLAW_WORKSPACE }}/data/email-queue",
            ),
        ),
    ),
    "file-delivery-queue": (
        SourceContract(
            "repository",
            "bin/materialize-secret-projections.py",
            (
                ".config/ai-agents-skills/file-delivery-queue.json",
                ".local/state/ai-agents-skills/file-delivery-replay",
                "aas-host-state:file-delivery-replay",
                "FILE_DELIVERY_AUTHORITY_KEYS",
                "_validate_file_delivery_queue_document",
                "_migrate_file_delivery_queue_authority",
                "_ensure_file_delivery_replay_directory",
            ),
        ),
        SourceContract(
            "aas",
            "manifest/target-state.yaml",
            (
                '"file-delivery-queue"',
                '"pointer_env": "AAS_FILE_DELIVERY_SECRETS_FILE"',
                '"exact_value": "aas-host-state:file-delivery-replay"',
                '"restore_policy": "state-continuity"',
                '"backup_required": true',
                '"readiness_when_absent": "NOT_CONFIGURED"',
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/runners/run_skill.sh",
            (
                'delivery_pointer="${AAS_FILE_DELIVERY_SECRETS_FILE:-}"',
                "unset AAS_FILE_DELIVERY_SECRETS_FILE",
                'export AAS_FILE_DELIVERY_SECRETS_FILE="$delivery_pointer"',
                "skills/zotero/send_file.sh",
                "skills/zotero/send_queue_worker.sh",
            ),
            forbidden_fragments=(
                "AAS_FILE_DELIVERY_SECRETS_FILE=/workspace",
                "OPENCLAW_SECRETS_FILE=$delivery_pointer",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/zotero/send_file.sh",
            (
                "#!/bin/bash -p",
                "unset AAS_SECRETS_FILE OPENCLAW_SECRETS_FILE AAS_SKILL_SECRETS_FILE",
                "unset TELEGRAM_BOT_TOKEN ZULIP_API_KEY",
                "export PATH=/usr/bin:/bin",
                'SCRIPT="$SCRIPT_DIR/send_queue.py"',
                "secure_loader=",
                'exec "$PYTHON" -I -c "$secure_loader" "$SCRIPT" submit',
            ),
            forbidden_fragments=(
                "curl ",
                ".config/file-delivery/secrets.json",
                "delivery_policy.py",
                "shutil.which",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/zotero/send_queue.py",
            (
                'AUTHORITY_ENV = "AAS_FILE_DELIVERY_SECRETS_FILE"',
                'REPLAY_LEDGER_TOKEN = "aas-host-state:file-delivery-replay"',
                "AUTHORIZED_EXPORT_RELATIVES",
                "AUTHORITY_KEYS",
                "replay_retention_seconds",
                "max_replay_entries",
                "_locked_replay_ledger",
                "_open_trusted_delivery_cli",
                'Path("/usr/local/bin/openclaw")',
                'Path("/usr/bin/openclaw")',
                "O_NOFOLLOW",
                "pass_fds=(*pass_fds, executable_fd, node_fd)",
            ),
            forbidden_fragments=("shutil.which", "shell=True"),
        ),
    ),
    "openclaw-file-delivery-policy": (
        SourceContract(
            "openclaw",
            "config/file-delivery-policy.json.template",
            (
                '"schema": "openclaw.file-delivery-policy/v1"',
                '"allowed_targets"',
                '"telegram": []',
                '"zulip": []',
                '"googlechat": []',
                '"whatsapp": []',
                '"zalo": []',
            ),
            forbidden_fragments=("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"),
        ),
        SourceContract(
            "openclaw",
            "REBUILD-MANIFEST.json",
            (
                '"file_delivery_policy_authority": "file-delivery-policy.json"',
                '"file_delivery_policy_schema": "openclaw.file-delivery-policy/v1"',
                '"file_delivery_restore_authority": "owner-archive-only"',
                '"file_delivery_generic_secrets_restore": "omitted"',
                '"file-delivery-policy.json"',
            ),
            forbidden_fragments=("file_delivery_materialized_projection",),
        ),
        SourceContract(
            "openclaw",
            "scripts/owner_archive.py",
            (
                'FILE_DELIVERY_POLICY = "file-delivery-policy.json"',
                "ARCHIVE_AUTHORITY_ROOTS",
                "_open_regular_nofollow",
                "recovery-quarantine",
            ),
        ),
        SourceContract(
            "openclaw",
            "scripts/file_delivery.py",
            (
                'POLICY_SCHEMA = "openclaw.file-delivery-policy/v1"',
                "SUPPORTED_CHANNELS",
                "HostSnapshot",
                "load_policy",
                'PROJECTION_SCHEMA = "openclaw.delivery-projection/v1"',
                "_validate_channel_projection",
                'path / "secrets.json"',
                "snapshot_export",
                "_map_media_path",
                'generation / "host_exec.py"',
                '"--generation"',
                'parser.add_argument("--workspace"',
                'parser.add_argument("--policy"',
                'parser.add_argument("--telegram-credential"',
                'parser.add_argument("--channel-state"',
                'parser.add_argument("--job"',
                'parser.add_argument("--result"',
                "O_NOFOLLOW",
            ),
            forbidden_fragments=(
                "workspace/.config/file-delivery/secrets.json",
                "delivery_policy.py",
            ),
        ),
        SourceContract(
            "openclaw",
            "scripts/service_transaction.py",
            (
                "HOST_RUNTIME_SCHEMA",
                "_collect_host_artifacts",
                "_install_host_generation",
                '"MANIFEST.json"',
            ),
            normalized_fragments=(
                '("file_delivery.py", "scripts/file_delivery.py", "python-isolated")',
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/zotero/send_file.sh",
            (
                "#!/usr/bin/bash -p",
                "unset AAS_FILE_DELIVERY_SECRETS_FILE OPENCLAW_BIN REMOTE_BRIDGE_SECRETS_FILE",
                'QUEUE_DIR="$WORKSPACE/data/send-queue/$CHANNEL"',
                '"schema": "openclaw.send-queue-job/v1"',
                '"status": "pending"',
                'printf \'{"status":"queued"',
            ),
            forbidden_fragments=(
                "curl ",
                ".config/file-delivery/secrets.json",
                "delivery_policy.py",
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/scripts/job_queue_worker.sh",
            (
                'DELIVERY_HELPER="$LIBEXEC/file_delivery.py"',
                '/usr/bin/python3 -I -S -B "$DELIVERY_HELPER"',
                '--workspace "$WORKSPACE" --state-prefix "$STATE_PREFIX"',
                '--job "$job_file" --result "$result_file"',
            ),
            forbidden_fragments=(
                ".config/file-delivery/secrets.json",
                "delivery_policy.py",
                "--authorize-only",
            ),
        ),
    ),
    "compute-credentials": (
        STRICT_ENV_LOADER,
        CREDENTIAL_PROJECTION_PROBE_CONTRACT,
        CREDENTIAL_PROJECTION_CHECK_CONTRACT,
        SourceContract(
            "aas",
            "canonical/runtime/skills/modal-research-compute/run_modal_research_compute.sh",
            (
                "load_secret_env.py",
                "AAS_COMPUTE_SECRETS_FILE",
                "--pointer-env AAS_COMPUTE_SECRETS_FILE",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/kaggle-research-compute/run_kaggle_research_compute.sh",
            (
                "load_secret_env.py",
                "AAS_COMPUTE_SECRETS_FILE",
                "--pointer-env AAS_COMPUTE_SECRETS_FILE",
                "KAGGLE_API_TOKEN",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/kaggle-research-compute/run_kaggle_research_compute.ps1",
            (
                "load_secret_env.ps1",
                "AAS_COMPUTE_SECRETS_FILE",
                'Import-AasSecretEnvFile -PointerEnv "AAS_COMPUTE_SECRETS_FILE"',
                "KAGGLE_API_TOKEN",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/hetzner-research-compute/run_hetzner_research_compute.sh",
            (
                "load_secret_env.py",
                "AAS_COMPUTE_SECRETS_FILE",
                "--pointer-env AAS_COMPUTE_SECRETS_FILE",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/hetzner-research-compute/run_hetzner_reaper.sh",
            (
                "load_secret_env.py",
                "AAS_COMPUTE_SECRETS_FILE",
                "--pointer-env AAS_COMPUTE_SECRETS_FILE",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/autonomous-research-loop-runtime/run_autonomous_research_loop.sh",
            (
                "load_secret_env.py",
                "AAS_COMPUTE_SECRETS_FILE",
                "--pointer-env AAS_COMPUTE_SECRETS_FILE",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/autonomous-research-loop-runtime/force-loop/force_loop_cli.py",
            (
                'COMPUTE_SECRETS_ENV = "AAS_COMPUTE_SECRETS_FILE"',
                "_load_managed_secrets",
                "load_pointer_secret_env",
                "O_NOFOLLOW",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/workspace/research_compute/kaggle_backend.py",
            ('TOKEN_ENV = "KAGGLE_API_TOKEN"', "env_token = os.environ.get(TOKEN_ENV)"),
        ),
    ),
    "skill-credentials": (
        STRICT_ENV_LOADER,
        CREDENTIAL_PROJECTION_PROBE_CONTRACT,
        CREDENTIAL_PROJECTION_CHECK_CONTRACT,
        SourceContract(
            "aas",
            "canonical/runtime/runners/run_skill.sh",
            (
                "load_secret_env.py",
                "AAS_SKILL_SECRETS_FILE",
                "select_flat_projection",
                "projection_pointer_env",
                "projection_allow_keys",
                'loader_args=(--pointer-env "$projection_pointer_env"',
                "AXLE_API_KEY",
                "LEANEXPLORE_API_KEY",
                "OPENCLAW_S2_API_KEY",
                "SEMANTIC_SCHOLAR_API_KEY UNPAYWALL_EMAIL",
                "ZENODO_TOKEN",
            ),
        ),
        SourceContract(
            "repository",
            "system/bin/lean-explore-mcp-api",
            (
                "AAS_SKILL_SECRETS_FILE",
                ".config/ai-agents-skills/skill.env",
                "LEANEXPLORE_API_KEY",
                "O_NOFOLLOW",
            ),
        ),
        SourceContract(
            "repository",
            "system/bin/research-digest",
            ("skills/research-digest-wrapper", "run_research_digest.sh", "exec"),
        ),
        OPENCLAW_SKILL_LOADER_CONTRACT,
        SourceContract(
            "openclaw",
            "workspace/skills/axiom-axle-mcp/run_axiom_axle_mcp.sh",
            (
                "#!/usr/bin/bash -p",
                'SECRET_LOADER="$SCRIPT_DIR/../_load_skill_secrets.py"',
                "-I -S -B",
                "--profile axiom-axle-mcp",
            ),
            forbidden_fragments=(
                "AAS_SECRETS_FILE",
                "OPENCLAW_SECRETS_FILE",
                "AAS_SKILL_SECRETS_FILE",
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/lean-explore-cli/run_lean_explore.sh",
            (
                "#!/usr/bin/bash -p",
                'SECRET_LOADER="$SCRIPT_DIR/../_load_skill_secrets.py"',
                "-I -S -B",
                "--profile lean-explore-cli",
            ),
            forbidden_fragments=(
                "AAS_SECRETS_FILE",
                "OPENCLAW_SECRETS_FILE",
                "AAS_SKILL_SECRETS_FILE",
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/lean-explore-mcp/run_lean_explore_mcp.sh",
            (
                "#!/usr/bin/bash -p",
                'SECRET_LOADER="$SCRIPT_DIR/../_load_skill_secrets.py"',
                "-I -S -B",
                "--profile lean-explore-mcp",
            ),
            forbidden_fragments=(
                "AAS_SECRETS_FILE",
                "OPENCLAW_SECRETS_FILE",
                "AAS_SKILL_SECRETS_FILE",
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/research-digest-wrapper/run_research_digest.sh",
            (
                "#!/usr/bin/bash -p",
                'SECRET_LOADER="$SCRIPT_DIR/../_load_skill_secrets.py"',
                "-I -S -B",
                "--profile research-digest",
            ),
            forbidden_fragments=(
                "AAS_SECRETS_FILE",
                "OPENCLAW_SECRETS_FILE",
                "AAS_SKILL_SECRETS_FILE",
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/submission-venue-selector/run_submission_venue_selector.sh",
            (
                "#!/usr/bin/bash -p",
                'secret_loader="$script_dir/../_load_skill_secrets.py"',
                "-I -S -B",
                "--profile submission-venue-selector",
            ),
            forbidden_fragments=(
                "AAS_SECRETS_FILE",
                "OPENCLAW_SECRETS_FILE",
                "AAS_SKILL_SECRETS_FILE",
            ),
        ),
    ),
    "provider-credentials": (
        STRICT_ENV_LOADER,
        CREDENTIAL_PROJECTION_PROBE_CONTRACT,
        CREDENTIAL_PROJECTION_CHECK_CONTRACT,
        SourceContract(
            "aas",
            "canonical/runtime/skills/autonomous-research-loop-runtime/run_autonomous_research_loop.sh",
            (
                "load_secret_env.py",
                "AAS_PROVIDER_SECRETS_FILE",
                "--pointer-env AAS_PROVIDER_SECRETS_FILE",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/autonomous-research-loop-runtime/force-loop/force_loop_cli.py",
            (
                'PROVIDER_SECRETS_ENV = "AAS_PROVIDER_SECRETS_FILE"',
                "PROVIDER_SECRET_KEYS",
                "load_pointer_secret_env",
            ),
        ),
    ),
    "copilot-credentials": (
        STRICT_ENV_LOADER,
        CREDENTIAL_PROJECTION_PROBE_CONTRACT,
        CREDENTIAL_PROJECTION_CHECK_CONTRACT,
        SourceContract(
            "repository",
            "system/bin/copilot",
            (
                ".config/ai-agents-skills/providers/copilot.env",
                "--csr-credential-probe",
                "COPILOT_GITHUB_TOKEN",
                "COPILOT_PROVIDER_API_KEY",
                "COPILOT_PROVIDER_BEARER_TOKEN",
                "GH_TOKEN",
                "GITHUB_TOKEN",
            ),
        ),
    ),
    "zotero": (
        OPENCLAW_SKILL_LOADER_CONTRACT,
        SourceContract(
            "aas",
            "canonical/runtime/skills/zotero/lib/config.py",
            (
                "AAS_ZOTERO_SECRETS_FILE",
                "zotero-secrets.json",
                "SECRETS_KEYS",
                "_load_secret_projection",
                "O_NOFOLLOW",
                "st_nlink",
                "ZOTERO_API_KEY",
            ),
            forbidden_fragments=(
                'os.environ.get("AAS_SECRETS_FILE")',
                'os.environ.get("OPENCLAW_SECRETS_FILE")',
                'os.environ.get("AAS_SKILL_SECRETS_FILE")',
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/zotero/send_file.sh",
            (
                "#!/bin/bash -p",
                "unset AAS_SECRETS_FILE OPENCLAW_SECRETS_FILE AAS_SKILL_SECRETS_FILE",
                'SCRIPT="$SCRIPT_DIR/send_queue.py"',
                "secure_loader=",
                'exec "$PYTHON" -I -c "$secure_loader" "$SCRIPT" submit',
                "--workspace",
                "--request-json-stdin",
                "AAS_FILE_DELIVERY_REQUEST_FD",
                "send_file.sh accepts one bounded JSON request on stdin",
            ),
            forbidden_fragments=(
                "curl ",
                ".config/file-delivery/secrets.json",
                "delivery_policy.py",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/zotero/send_telegram.sh",
            (
                "#!/bin/bash -p",
                "unset AAS_SECRETS_FILE OPENCLAW_SECRETS_FILE AAS_SKILL_SECRETS_FILE",
                'SENDER="$SCRIPT_DIR/send_file.sh"',
                "secure_shell_loader=",
                "send_telegram.sh accepts JSON stdin only",
                'request_fd=os.dup(0)',
                'os.execve("/bin/bash",["/bin/bash","-p","-s","--"],env)',
            ),
            forbidden_fragments=("curl ", ".config/file-delivery/secrets.json"),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/zotero/run_zot.sh",
            (
                "#!/usr/bin/bash -p",
                'SECRET_LOADER="$SKILL_DIR/../_load_skill_secrets.py"',
                "-I -S -B",
                "--profile zotero",
            ),
            forbidden_fragments=(
                "AAS_SECRETS_FILE",
                "OPENCLAW_SECRETS_FILE",
                "AAS_SKILL_SECRETS_FILE",
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/zotero/lib/config.py",
            ("for key in SECRETS_KEYS", "os.environ.get", "ZOTERO_API_KEY"),
            forbidden_fragments=(
                "AAS_SECRETS_FILE",
                "OPENCLAW_SECRETS_FILE",
                "AAS_SKILL_SECRETS_FILE",
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/zotero/send_file.sh",
            (
                "#!/usr/bin/bash -p",
                "unset AAS_FILE_DELIVERY_SECRETS_FILE OPENCLAW_BIN REMOTE_BRIDGE_SECRETS_FILE",
                'QUEUE_DIR="$WORKSPACE/data/send-queue/$CHANNEL"',
                '"schema": "openclaw.send-queue-job/v1"',
                '"status": "pending"',
                "O_NOFOLLOW",
            ),
            forbidden_fragments=(
                "AAS_SECRETS_FILE",
                "OPENCLAW_SECRETS_FILE",
                "AAS_SKILL_SECRETS_FILE",
                "curl ",
                ".config/file-delivery/secrets.json",
                "delivery_policy.py",
            ),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/zotero/send_telegram.sh",
            (
                "#!/usr/bin/bash -p",
                "Compatibility entrypoint",
                'exec /usr/bin/bash -p "$SCRIPT_DIR/send_file.sh" telegram',
            ),
            forbidden_fragments=(
                "AAS_SECRETS_FILE",
                "OPENCLAW_SECRETS_FILE",
                "AAS_SKILL_SECRETS_FILE",
                "curl ",
                ".config/file-delivery/secrets.json",
            ),
        ),
    ),
    "calibre": (
        SourceContract(
            "aas",
            "canonical/runtime/skills/calibre/run_cal.sh",
            (
                "#!/bin/bash -p",
                'calibre_pointer="${AAS_CALIBRE_SECRETS_FILE:-}"',
                "unset AAS_SECRETS_FILE OPENCLAW_SECRETS_FILE AAS_SKILL_SECRETS_FILE",
                'export AAS_CALIBRE_SECRETS_FILE="$calibre_pointer"',
                "unset AAS_FILE_DELIVERY_SECRETS_FILE REMOTE_BRIDGE_SECRETS_FILE SEND_EMAIL_SECRETS_FILE",
                "secure_loader=",
            ),
            forbidden_fragments=(
                "export AAS_SECRETS_FILE=",
                "export OPENCLAW_SECRETS_FILE=",
                "export AAS_SKILL_SECRETS_FILE=",
                "export AAS_FILE_DELIVERY_SECRETS_FILE=",
                "export REMOTE_BRIDGE_SECRETS_FILE=",
                "export SEND_EMAIL_SECRETS_FILE=",
            ),
        ),
        SourceContract(
            "aas",
            "canonical/runtime/skills/calibre/lib/config.py",
            (
                "AAS_CALIBRE_SECRETS_FILE",
                "calibre-secrets.json",
                "GDRIVE_CREDENTIALS",
                "CALIBRE_GDRIVE_FOLDER_ID",
            ),
            forbidden_fragments=("AAS_SECRETS_FILE", "OPENCLAW_SECRETS_FILE"),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/calibre/run_cal.sh",
            (
                "#!/usr/bin/bash -p",
                'SECRET_LOADER="$SKILL_DIR/../_load_skill_secrets.py"',
                "-I -S -B",
                "--profile calibre",
            ),
            forbidden_fragments=("AAS_SECRETS_FILE", "OPENCLAW_SECRETS_FILE"),
        ),
        SourceContract(
            "openclaw",
            "workspace/skills/calibre/lib/config.py",
            (
                "GDRIVE_CREDENTIALS",
                "CALIBRE_GDRIVE_FOLDER_ID",
                'os.environ.pop("GDRIVE_CREDENTIALS", None)',
                'os.environ.pop("CALIBRE_GDRIVE_FOLDER_ID", None)',
            ),
            forbidden_fragments=("AAS_SECRETS_FILE", "OPENCLAW_SECRETS_FILE"),
        ),
    ),
    "tailscale": (
        SourceContract(
            "repository",
            "bin/apply-tailscale-authority.sh",
            (
                '--auth-key="file:$AUTHKEY_PATH"',
                '--hostname "$TAILSCALE_HOSTNAME"',
                "verify-tailscale-readiness.py",
            ),
            forbidden_fragments=("tailscale.env", "TS_AUTHKEY", "|| true"),
        ),
        SourceContract(
            "repository",
            "bin/install.sh",
            ("apply-tailscale-authority.sh", "TAILSCALE_READINESS_RC"),
            forbidden_fragments=(
                '. "$HOME/.config/coding-system/tailscale.env"',
                "sudo tailscale up --authkey",
            ),
        ),
    ),
}


class ClosureIssue(RuntimeError):
    """A redaction-safe technical failure represented by a fixed code."""

    def __init__(self, code: str) -> None:
        if re.fullmatch(r"[a-z0-9-]+", code) is None:
            raise ValueError("closure issue codes must be fixed safe identifiers")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CheckResult:
    identifier: str
    status: str
    configured: bool
    reason: str
    items: int = 0
    capabilities: tuple[str, ...] = ()

    def as_json(self) -> dict[str, object]:
        return {
            "capabilities": list(self.capabilities),
            "configured": self.configured,
            "id": self.identifier,
            "items": self.items,
            "reason": self.reason,
            "status": self.status,
        }


def _result(
    identifier: str,
    status: str,
    reason: str,
    *,
    configured: bool,
    items: int = 0,
    capabilities: tuple[str, ...] = (),
) -> CheckResult:
    return CheckResult(
        identifier,
        status,
        configured,
        reason,
        items,
        capabilities,
    )


def _pass(
    identifier: str,
    *,
    items: int = 1,
    capabilities: tuple[str, ...] = (),
) -> CheckResult:
    return _result(
        identifier,
        "PASS",
        "closed",
        configured=True,
        items=items,
        capabilities=capabilities,
    )


def _not_configured(identifier: str, reason: str = "authority-absent") -> CheckResult:
    return _result(identifier, "NOT_CONFIGURED", reason, configured=False)


def _reauth_required(
    identifier: str, *, reason: str, items: int, capabilities: tuple[str, ...]
) -> CheckResult:
    return _result(
        identifier,
        "REAUTH_REQUIRED",
        reason,
        configured=True,
        items=items,
        capabilities=capabilities,
    )


def _fail(identifier: str, reason: str) -> CheckResult:
    return _result(identifier, "FAIL", reason, configured=False)


def _require_home(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    try:
        info = absolute.lstat()
    except OSError as exc:
        raise ClosureIssue("unsafe-home") from exc
    if (
        absolute.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ClosureIssue("unsafe-home")
    return absolute


def _open_parent_descriptor(
    path: Path, *, create: bool = False
) -> tuple[int, str, tuple[int, int]] | None:
    absolute = path.expanduser().absolute()
    if absolute == Path("/") or absolute.name in {"", ".", ".."}:
        raise ClosureIssue("unsafe-file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open("/", flags)
    try:
        for component in absolute.parts[1:-1]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    os.close(descriptor)
                    return None
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=descriptor)
            information = os.fstat(child)
            sticky_root_directory = (
                information.st_uid == 0
                and bool(information.st_mode & stat.S_ISVTX)
            )
            if (
                not stat.S_ISDIR(information.st_mode)
                or information.st_uid not in {0, os.getuid()}
                or (
                    information.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    and not sticky_root_directory
                )
            ):
                os.close(child)
                raise ClosureIssue("unsafe-file")
            os.close(descriptor)
            descriptor = child
        parent = os.fstat(descriptor)
        return descriptor, absolute.name, (parent.st_dev, parent.st_ino)
    except ClosureIssue:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise ClosureIssue("unsafe-file") from exc


def _confirm_parent_identity(path: Path, expected: tuple[int, int]) -> None:
    reopened = _open_parent_descriptor(path)
    if reopened is None:
        raise ClosureIssue("file-changed")
    descriptor, _leaf, observed = reopened
    os.close(descriptor)
    if observed != expected:
        raise ClosureIssue("file-changed")


def _stable_file_identity(information: os.stat_result) -> tuple[int, ...]:
    return (
        information.st_dev,
        information.st_ino,
        information.st_mode,
        information.st_uid,
        information.st_nlink,
        information.st_size,
        information.st_mtime_ns,
        information.st_ctime_ns,
    )


def _read_regular(
    path: Path,
    *,
    mode: int | frozenset[int],
    allow_empty: bool = False,
    maximum: int = MAX_FILE_BYTES,
) -> bytes | None:
    opened_parent = _open_parent_descriptor(path)
    if opened_parent is None:
        return None
    parent_descriptor, leaf, parent_identity = opened_parent
    try:
        before = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        os.close(parent_descriptor)
        return None
    except OSError as exc:
        os.close(parent_descriptor)
        raise ClosureIssue("unsafe-file") from exc
    accepted_modes = mode if isinstance(mode, frozenset) else frozenset({mode})
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) not in accepted_modes
        or before.st_size > maximum
        or (not allow_empty and before.st_size == 0)
    ):
        os.close(parent_descriptor)
        raise ClosureIssue("unsafe-file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(leaf, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        os.close(parent_descriptor)
        raise ClosureIssue("unsafe-file") from exc
    try:
        opened = os.fstat(descriptor)
        if _stable_file_identity(opened) != _stable_file_identity(before):
            raise ClosureIssue("file-changed")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) > maximum:
            raise ClosureIssue("file-oversized")
        if _stable_file_identity(after) != _stable_file_identity(opened):
            raise ClosureIssue("file-changed")
        if not allow_empty and not payload:
            raise ClosureIssue("empty-file")
        _confirm_parent_identity(path, parent_identity)
        return payload
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def _read_text(
    path: Path, *, mode: int | frozenset[int], allow_empty: bool = False
) -> str | None:
    payload = _read_regular(path, mode=mode, allow_empty=allow_empty)
    if payload is None:
        return None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ClosureIssue("invalid-utf8") from exc


def _component_pin(repository: Path, name: str) -> str | None:
    """Return one full component pin without accepting ambiguous lock entries."""

    try:
        text = (repository / "components.lock").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return None
    prefix = f"{name}="
    matches = [
        line.rsplit("@", 1)[-1]
        for line in text.splitlines()
        if line.startswith(prefix) and "@" in line
    ]
    if len(matches) != 1 or re.fullmatch(r"[0-9a-f]{40}", matches[0]) is None:
        return None
    return matches[0]


def _safe_source_directory(path: Path) -> Path | None:
    absolute = path.expanduser().absolute()
    try:
        info = absolute.lstat()
    except OSError:
        return None
    if absolute.is_symlink() or not stat.S_ISDIR(info.st_mode):
        return None
    return absolute


def _git_object_repository(path: Path) -> Path | None:
    root = _safe_source_directory(path)
    if root is None:
        return None
    try:
        git_info = (root / ".git").lstat()
    except OSError:
        return None
    if (root / ".git").is_symlink() or not stat.S_ISDIR(git_info.st_mode):
        return None
    return root


def _aas_source_candidates(repository: Path) -> list[Path]:
    candidates = [
        repository / "external/ai-agents-skills",
        repository / "ai-agents-skills",
        repository.parent / "ai-agents-skills",
    ]
    try:
        candidates.append(Path(pwd.getpwuid(os.getuid()).pw_dir) / "ai-agents-skills")
    except (KeyError, OSError):
        pass
    return candidates


def _locate_aas_source(repository: Path) -> Path | PinnedGitSource | None:
    """Locate the exact pinned AAS object, or direct source in test fixtures.

    A root-owned materialization named after the pin is not sufficient evidence
    by itself: its sealed filesystem shape does not bind every byte back to the
    Git object.  A normal restore retains the object repository, so configured
    closure requires that exact object whenever components.lock supplies a pin.
    """

    pin = _component_pin(repository, "ai-agents-skills")
    if pin is not None:
        for candidate in _aas_source_candidates(repository):
            object_repository = _git_object_repository(candidate)
            if object_repository is not None:
                return PinnedGitSource(object_repository, pin)
        return None

    seen: set[Path] = set()
    for candidate in _aas_source_candidates(repository):
        absolute = _safe_source_directory(candidate)
        if absolute is None:
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        return absolute
    return None


def _locate_openclaw_source(
    repository: Path, home: Path
) -> Path | PinnedGitSource | None:
    lock = repository / "components.lock"
    if not lock.is_file():
        # Synthetic contract fixtures intentionally carry only the exact
        # source files under external/. A published repository always has a
        # lock; a present but malformed lock must never take this fallback.
        return _safe_source_directory(repository / "external/openclaw-bot")
    pin = _component_pin(repository, "openclaw-bot")
    if pin is None:
        return None
    try:
        root = resolve_component_path(
            repository,
            home,
            "openclaw-bot",
            source_fallback=True,
            require=True,
        )
    except ComponentPathError:
        return None
    object_repository = _git_object_repository(root)
    if object_repository is None:
        return None
    return PinnedGitSource(object_repository, pin)


def _read_pinned_git_source(source: PinnedGitSource, relative: str) -> str:
    git = Path("/usr/bin/git")
    if not git.is_file():
        raise ClosureIssue("source-resolver-contract-missing")
    object_name = f"{source.revision}:{relative}"
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
        "GIT_SSH_COMMAND": "/bin/false",
        "GCM_INTERACTIVE": "never",
        "GIT_ALLOW_PROTOCOL": "",
    }
    command = [
        str(git),
        "--no-replace-objects",
        "--no-optional-locks",
        "-c",
        "credential.helper=",
        "-c",
        "credential.interactive=false",
        "-c",
        "core.askPass=/bin/false",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "protocol.git.allow=never",
        "-c",
        "protocol.http.allow=never",
        "-c",
        "protocol.https.allow=never",
        "-c",
        "protocol.ssh.allow=never",
        "-C",
        str(source.repository),
        "cat-file",
    ]
    try:
        sized = subprocess.run(
            [*command, "-s", object_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ClosureIssue("source-resolver-contract-missing") from exc
    try:
        size = int(sized.stdout.strip())
    except ValueError as exc:
        raise ClosureIssue("source-resolver-contract-missing") from exc
    if sized.returncode != 0:
        raise ClosureIssue("source-resolver-contract-missing")
    if size <= 0 or size > MAX_SOURCE_FILE_BYTES:
        raise ClosureIssue("source-resolver-contract-divergent")
    try:
        loaded = subprocess.run(
            [*command, "blob", object_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ClosureIssue("source-resolver-contract-divergent") from exc
    if loaded.returncode != 0 or len(loaded.stdout) != size:
        raise ClosureIssue("source-resolver-contract-divergent")
    try:
        return loaded.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ClosureIssue("source-resolver-contract-divergent") from exc


def _read_source_contract(
    root: Path | PinnedGitSource | None,
    relative: str,
) -> str:
    """Read one bounded resolver source without following any path links."""

    if root is None:
        raise ClosureIssue("source-resolver-contract-missing")
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise ClosureIssue("source-resolver-contract-divergent")
    if isinstance(root, PinnedGitSource):
        return _read_pinned_git_source(root, relative)

    current = root
    try:
        root_info = current.lstat()
        if current.is_symlink() or not stat.S_ISDIR(root_info.st_mode):
            raise ClosureIssue("source-resolver-contract-divergent")
        for component in pure.parts[:-1]:
            current = current / component
            info = current.lstat()
            if current.is_symlink() or not stat.S_ISDIR(info.st_mode):
                raise ClosureIssue("source-resolver-contract-divergent")
        path = current / pure.parts[-1]
        before = path.lstat()
    except FileNotFoundError as exc:
        raise ClosureIssue("source-resolver-contract-missing") from exc
    except ClosureIssue:
        raise
    except OSError as exc:
        raise ClosureIssue("source-resolver-contract-divergent") from exc

    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_SOURCE_FILE_BYTES
        or before.st_mode & stat.S_IWOTH
    ):
        raise ClosureIssue("source-resolver-contract-divergent")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ClosureIssue("source-resolver-contract-divergent") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
        ):
            raise ClosureIssue("source-resolver-contract-divergent")
        chunks: list[bytes] = []
        remaining = MAX_SOURCE_FILE_BYTES + 1
        while remaining:
            block = os.read(descriptor, min(remaining, 64 * 1024))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) > MAX_SOURCE_FILE_BYTES
            or (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
        ):
            raise ClosureIssue("source-resolver-contract-divergent")
    finally:
        os.close(descriptor)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ClosureIssue("source-resolver-contract-divergent") from exc


def _check_source_contracts(
    repository: Path,
    result: CheckResult,
    *,
    aas_source: Path | PinnedGitSource | None,
    openclaw_source: Path | PinnedGitSource | None,
) -> CheckResult:
    """Gate a configured authority on every versioned resolver it relies on."""

    if result.status != "PASS":
        return result
    contracts = SOURCE_CONTRACTS.get(result.identifier, ())
    roots = {
        "repository": repository,
        "openclaw": openclaw_source,
        "aas": aas_source,
    }
    for contract in contracts:
        source = _read_source_contract(roots[contract.root], contract.relative)
        if contract.identical_to is not None and source != _read_source_contract(
            roots[contract.root], contract.identical_to
        ):
            raise ClosureIssue("source-resolver-contract-divergent")
        if any(fragment not in source for fragment in contract.fragments):
            raise ClosureIssue("source-resolver-contract-divergent")
        if any(fragment in source for fragment in contract.forbidden_fragments):
            raise ClosureIssue("source-resolver-contract-divergent")
        normalized = re.sub(r"\s+", " ", source)
        if any(
            fragment not in normalized
            for fragment in contract.normalized_fragments
        ):
            raise ClosureIssue("source-resolver-contract-divergent")
        if any(
            fragment in normalized
            for fragment in contract.normalized_forbidden_fragments
        ):
            raise ClosureIssue("source-resolver-contract-divergent")
    return result


def _json_object(path: Path, *, mode: int) -> tuple[bytes, dict[str, Any]] | None:
    payload = _read_regular(path, mode=mode)
    if payload is None:
        return None

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ClosureIssue("duplicate-json-key")
            value[key] = item
        return value

    try:
        value = json.loads(payload, object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClosureIssue("invalid-json") from exc
    if not isinstance(value, dict):
        raise ClosureIssue("invalid-json-shape")
    return payload, value


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _check_exact_projections(
    authority: bytes | None,
    projections: tuple[tuple[Path, int], ...],
) -> None:
    observed: list[bytes | None] = []
    for path, mode in projections:
        observed.append(_read_regular(path, mode=mode))
    if authority is None:
        if any(payload is not None for payload in observed):
            raise ClosureIssue("stale-projection")
        return
    if any(payload is None for payload in observed):
        raise ClosureIssue("projection-missing")
    if any(payload != authority for payload in observed):
        raise ClosureIssue("projection-divergent")


def _check_exact_env_subset_projection(
    home: Path,
    *,
    relative: str,
    authority_values: dict[str, str],
    keys: tuple[str, ...],
) -> None:
    expected = {key: authority_values[key] for key in keys if key in authority_values}
    payload = _read_regular(home / relative, mode=0o600)
    if not expected:
        if payload is not None:
            raise ClosureIssue("stale-projection")
        return
    if payload is None:
        raise ClosureIssue("projection-missing")
    if _parse_strict_env(payload, frozenset(keys)) != expected:
        raise ClosureIssue("projection-divergent")


def _check_exact_json_subset_projection(
    home: Path, *, relative: str, expected: dict[str, str]
) -> None:
    loaded = _json_object(home / relative, mode=0o600)
    if not expected:
        if loaded is not None:
            raise ClosureIssue("stale-projection")
        return
    if loaded is None:
        raise ClosureIssue("projection-missing")
    if loaded[1] != expected:
        raise ClosureIssue("projection-divergent")


def _legacy_json_documents(home: Path) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    for relative in (".claude/secrets.json", ".openclaw/secrets.json"):
        loaded = _json_object(home / relative, mode=0o600)
        if loaded is not None:
            documents.append(loaded[1])
    return documents


def _legacy_json_values(home: Path, keys: frozenset[str]) -> dict[str, str]:
    collected: dict[str, list[str]] = {}
    for document in _legacy_json_documents(home):
        for key in keys:
            if key not in document:
                continue
            value = document[key]
            if not _nonempty_string(value):
                raise ClosureIssue("legacy-source-invalid")
            collected.setdefault(key, []).append(value)
    result: dict[str, str] = {}
    for key, values in collected.items():
        if any(value != values[0] for value in values[1:]):
            raise ClosureIssue("legacy-source-conflict")
        result[key] = values[0]
    return result


def _legacy_shell_values(home: Path, keys: frozenset[str]) -> dict[str, str]:
    text = _read_text(home / ".secrets.env", mode=0o600)
    if text is None:
        return {}
    found: dict[str, str] = {}
    for raw in text.splitlines():
        match = re.fullmatch(r"\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*", raw)
        if match is None or match.group(1) not in keys:
            continue
        key = match.group(1)
        if key in found:
            raise ClosureIssue("legacy-source-duplicate")
        try:
            # Match the materializer: '#' inside an assignment word is literal.
            # Trailing comments are rejected as multiple tokens rather than
            # permitting a lossy migration.
            words = shlex.split(match.group(2), comments=False, posix=True)
        except ValueError as exc:
            raise ClosureIssue("legacy-source-invalid") from exc
        if len(words) != 1 or not words[0]:
            raise ClosureIssue("legacy-source-invalid")
        found[key] = words[0]
    return found


def _parse_strict_env(payload: bytes, allowed: frozenset[str]) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ClosureIssue("invalid-utf8") from exc
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if raw != line:
            raise ClosureIssue("invalid-env-line")
        if "=" not in line:
            raise ClosureIssue("invalid-env-line")
        key, value = line.split("=", 1)
        if (
            ENV_KEY.fullmatch(key) is None
            or key not in allowed
            or key in values
            or not value
            or value != value.strip()
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in value
            )
        ):
            raise ClosureIssue("invalid-env-entry")
        values[key] = value
    return values


def _read_openclaw_environment(home: Path) -> dict[str, Any]:
    loaded = _json_object(home / ".openclaw/openclaw.json", mode=0o600)
    if loaded is None:
        raise ClosureIssue("openclaw-selector-missing")
    try:
        agents = loaded[1]["agents"]
        defaults = agents["defaults"]
        listed = agents["list"]
        default_environment = defaults["sandbox"]["docker"]["env"]
    except (KeyError, TypeError) as exc:
        raise ClosureIssue("openclaw-selector-missing") from exc
    if (
        not isinstance(agents, dict)
        or not isinstance(defaults, dict)
        or not isinstance(listed, list)
        or not isinstance(default_environment, dict)
    ):
        raise ClosureIssue("openclaw-selector-invalid")
    main_candidates = [
        agent
        for agent in listed
        if isinstance(agent, dict) and agent.get("id") == "main"
    ]
    if len(main_candidates) != 1:
        raise ClosureIssue("openclaw-main-agent-invalid")
    main = main_candidates[0]
    workspace = main.get("workspace", defaults.get("workspace"))
    if workspace != str(home / ".openclaw/workspace"):
        raise ClosureIssue("openclaw-main-workspace-unreachable")

    if OPENCLAW_MANAGED_SELECTOR_KEYS.intersection(default_environment):
        raise ClosureIssue("openclaw-selector-overbroad")
    if default_environment.get("XDG_DATA_HOME") != "/workspace/.local-data":
        raise ClosureIssue("openclaw-selector-divergent")

    for agent in listed:
        if not isinstance(agent, dict):
            raise ClosureIssue("openclaw-selector-invalid")
        if agent is main:
            continue
        if agent.get("skills") != []:
            raise ClosureIssue("openclaw-auxiliary-skills-enabled")
        sandbox = agent.get("sandbox")
        if sandbox is None:
            continue
        if not isinstance(sandbox, dict):
            raise ClosureIssue("openclaw-selector-invalid")
        docker = sandbox.get("docker")
        if docker is None:
            continue
        if not isinstance(docker, dict):
            raise ClosureIssue("openclaw-selector-invalid")
        environment = docker.get("env")
        if environment is None:
            continue
        if not isinstance(environment, dict):
            raise ClosureIssue("openclaw-selector-invalid")
        if OPENCLAW_MANAGED_SELECTOR_KEYS.intersection(environment):
            raise ClosureIssue("openclaw-selector-overbroad")

    try:
        environment = main["sandbox"]["docker"]["env"]
    except (KeyError, TypeError) as exc:
        raise ClosureIssue("openclaw-selector-missing") from exc
    if not isinstance(environment, dict):
        raise ClosureIssue("openclaw-selector-invalid")
    if OPENCLAW_RETIRED_SELECTOR_KEYS.intersection(environment):
        raise ClosureIssue("openclaw-retired-selector-present")
    if any(
        environment.get(key) != expected
        for key, expected in OPENCLAW_MAIN_SELECTOR_VALUES.items()
    ):
        raise ClosureIssue("openclaw-selector-divergent")
    return environment


def _check_env_selectors(
    home: Path,
    *,
    variable: str,
    host_relative: str,
    openclaw_value: str | None,
    require_runner: bool,
) -> None:
    codex = _read_text(home / ".codex/config.toml", mode=0o600)
    if codex is None:
        raise ClosureIssue("codex-selector-missing")
    try:
        document = tomllib.loads(codex)
        configured = document["shell_environment_policy"]["set"][variable]
    except (tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise ClosureIssue("codex-selector-missing") from exc
    expected_host = str(home / host_relative)
    if configured != expected_host:
        raise ClosureIssue("codex-selector-divergent")

    bashrc = _read_text(
        home / ".bashrc",
        mode=frozenset({0o600, 0o640, 0o644, 0o660, 0o664}),
        allow_empty=True,
    )
    if bashrc is None or variable not in bashrc or host_relative not in bashrc:
        raise ClosureIssue("shell-selector-missing")

    environment = _read_openclaw_environment(home)
    if openclaw_value is None and variable in environment:
        raise ClosureIssue("openclaw-retired-selector-present")
    if openclaw_value is not None and environment.get(variable) != openclaw_value:
        raise ClosureIssue("openclaw-selector-divergent")

    if require_runner:
        for candidate in (
            home / ".codex/runtime/run_skill.sh",
            home / ".local/share/ai-agents-skills/runtime/run_skill.sh",
        ):
            text = _read_text(candidate, mode=0o755, allow_empty=True)
            if text is not None and variable not in text:
                raise ClosureIssue("runtime-selector-missing")


def _check_ambient_shell_credential_policy(home: Path) -> None:
    try:
        read_owner_settings(home / ".secrets.env")
    except OwnerSettingsError as exc:
        raise ClosureIssue("owner-settings-invalid") from exc
    forbidden = (
        ".openclaw/moltbook.env",
        "MOLTBOOK_API_KEY",
        "$GAUSS_HOME/.env",
        "${GAUSS_HOME}/.env",
        ".gauss/.env",
        "OPEN_GAUSS_SKIP_SHELL_AUTOENV",
        "_gauss_shell_autoenv",
    )
    for relative in (".bashrc", ".profile"):
        text = _read_text(
            home / relative,
            mode=frozenset({0o600, 0o640, 0o644, 0o660, 0o664}),
            allow_empty=True,
        )
        if text is not None and any(fragment in text for fragment in forbidden):
            raise ClosureIssue("ambient-shell-credential-source")


def _check_aas_runtime_secrets(home: Path) -> CheckResult:
    identifier = "aas-runtime-secrets"
    _check_ambient_shell_credential_policy(home)
    for retired_workspace_authority in (
        home / ".openclaw/workspace/.secrets.json",
        home / ".openclaw/workspace/.config/ai-agents-skills/secrets.json",
    ):
        try:
            retired_workspace_authority.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ClosureIssue("unsafe-file") from exc
        else:
            raise ClosureIssue("broad-openclaw-workspace-secrets-present")
    if _legacy_shell_values(home, AAS_JSON_KEYS):
        raise ClosureIssue("ambient-shell-credential-present")
    legacy = _legacy_json_values(home, AAS_JSON_KEYS)
    loaded = _json_object(home / ".config/ai-agents-skills/secrets.json", mode=0o600)
    authority = loaded[0] if loaded else None
    value = loaded[1] if loaded else {}
    _check_exact_projections(
        authority,
        (
            (home / ".codex/runtime/workspace/.secrets.json", 0o600),
            (home / ".local/share/ai-agents-skills/runtime/workspace/.secrets.json", 0o600),
        ),
    )
    if loaded is None:
        if legacy:
            raise ClosureIssue("legacy-authority-unmigrated")
        return _not_configured(identifier)
    if set(value) - AAS_JSON_KEYS:
        raise ClosureIssue("shared-authority-contains-unsupported-fields")
    if any(not _nonempty_string(item) for item in value.values()):
        raise ClosureIssue("shared-authority-invalid")
    for key, legacy_value in legacy.items():
        if value.get(key) != legacy_value:
            raise ClosureIssue("legacy-authority-divergent")
    _check_env_selectors(
        home,
        variable="AAS_SECRETS_FILE",
        host_relative=".config/ai-agents-skills/secrets.json",
        openclaw_value=None,
        require_runner=False,
    )
    if not value:
        return _not_configured(identifier, "authority-empty")
    capabilities = tuple(sorted(value))
    return _pass(
        identifier, items=len(capabilities), capabilities=capabilities
    )


def _check_remote_bridge(home: Path) -> CheckResult:
    identifier = "remote-bridge"
    legacy_sets: list[dict[str, str]] = []
    for document in _legacy_json_documents(home):
        present = {
            field: document.get(legacy_key)
            for field, legacy_key in REMOTE_BRIDGE_LEGACY_KEYS.items()
            if _nonempty_string(document.get(legacy_key))
        }
        mentioned = any(legacy_key in document for legacy_key in REMOTE_BRIDGE_LEGACY_KEYS.values())
        if mentioned and len(present) != len(REMOTE_BRIDGE_LEGACY_KEYS):
            raise ClosureIssue("legacy-zulip-incomplete")
        if present:
            legacy_sets.append({key: str(value) for key, value in present.items()})
    if legacy_sets and any(item != legacy_sets[0] for item in legacy_sets[1:]):
        raise ClosureIssue("legacy-source-conflict")

    loaded = _json_object(home / ".config/remote-bridge/secrets.json", mode=0o600)
    for retired in (
        home / ".openclaw/workspace/.config/remote-bridge/secrets.json",
        home / ".openclaw/workspace/secrets/remote-bridge/secrets.json",
    ):
        if _read_regular(retired, mode=0o600) is not None:
            raise ClosureIssue("stale-remote-bridge-openclaw-projection")
    if loaded is None:
        if legacy_sets:
            raise ClosureIssue("legacy-authority-unmigrated")
        return _not_configured(identifier)
    value = loaded[1]
    zulip = value.get("zulip")
    telegram = value.get("telegram")
    complete_zulip = isinstance(zulip, dict) and all(
        _nonempty_string(zulip.get(key)) for key in ("site", "email", "api_key")
    )
    complete_telegram = isinstance(telegram, dict) and _nonempty_string(
        telegram.get("bot_token")
    )
    if not complete_zulip and not complete_telegram:
        raise ClosureIssue("remote-bridge-channel-incomplete")
    if legacy_sets:
        if not complete_zulip or any(zulip.get(key) != expected for key, expected in legacy_sets[0].items()):
            raise ClosureIssue("legacy-authority-divergent")
    channels = value.get("notify_channels")
    if channels is not None and (
        not isinstance(channels, list)
        or len(channels) != len(set(channels))
        or any(channel not in {"zulip", "telegram"} for channel in channels)
        or ("zulip" in channels and not complete_zulip)
        or ("telegram" in channels and not complete_telegram)
    ):
        raise ClosureIssue("remote-bridge-channel-selection-invalid")
    default = value.get("default_channel")
    if default is not None and default not in {"zulip", "telegram"}:
        raise ClosureIssue("remote-bridge-channel-selection-invalid")

    _check_env_selectors(
        home,
        variable="REMOTE_BRIDGE_SECRETS_FILE",
        host_relative=".config/remote-bridge/secrets.json",
        openclaw_value=None,
        require_runner=False,
    )

    if complete_zulip:
        for candidate in (
            home / ".codex/runtime/workspace/skills/zotero/send_file.sh",
            home / ".local/share/ai-agents-skills/runtime/workspace/skills/zotero/send_file.sh",
            home / ".openclaw/workspace/skills/zotero/send_file.sh",
        ):
            script = _read_text(candidate, mode=0o755, allow_empty=True)
            if script is None:
                continue
            dedicated = (
                "REMOTE_BRIDGE_SECRETS_FILE" in script
                or ".config/remote-bridge/secrets.json" in script
                or "remote_bridge" in script
            )
            if "ZULIP_API_KEY" in script and not dedicated:
                raise ClosureIssue("zulip-delivery-resolver-not-dedicated")
        _run_remote_bridge_consumer_probe(home)
    capabilities = tuple(
        sorted(
            capability
            for capability, configured in (
                ("ZULIP", complete_zulip),
                ("TELEGRAM", complete_telegram),
            )
            if configured
        )
    )
    return _pass(
        identifier, items=len(capabilities), capabilities=capabilities
    )


def _check_zulip(home: Path) -> CheckResult:
    """Report Zulip independently from the aggregate Remote Bridge authority."""

    identifier = "zulip"
    loaded = _json_object(home / ".config/remote-bridge/secrets.json", mode=0o600)
    if loaded is None:
        return _not_configured(identifier)
    zulip = loaded[1].get("zulip")
    if zulip is None:
        return _not_configured(identifier, "channel-absent")
    if not isinstance(zulip, dict) or not all(
        _nonempty_string(zulip.get(key)) for key in ("site", "email", "api_key")
    ):
        raise ClosureIssue("zulip-authority-incomplete")
    return _pass(identifier)


def _check_telegram(home: Path) -> CheckResult:
    """Report the Remote Bridge Telegram channel independently."""

    identifier = "telegram"
    loaded = _json_object(home / ".config/remote-bridge/secrets.json", mode=0o600)
    if loaded is None:
        return _not_configured(identifier)
    telegram = loaded[1].get("telegram")
    if telegram is None:
        return _not_configured(identifier, "channel-absent")
    if not isinstance(telegram, dict) or not _nonempty_string(
        telegram.get("bot_token")
    ):
        raise ClosureIssue("telegram-authority-incomplete")
    return _pass(identifier)


def _normalized_send_email_profile(value: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        lowered = str(key).lower()
        if lowered.startswith("smtp_"):
            lowered = lowered[5:]
        normalized[lowered] = item
    return normalized


def _validate_send_email_profile(value: object) -> None:
    if not isinstance(value, dict):
        raise ClosureIssue("send-email-profile-invalid")
    normalized = _normalized_send_email_profile(value)
    if set(normalized) - SEND_EMAIL_PROFILE_KEYS:
        raise ClosureIssue("send-email-profile-invalid")
    required = (
        _nonempty_string(normalized.get("host")),
        _nonempty_string(normalized.get("user") or normalized.get("username")),
        _nonempty_string(normalized.get("password") or normalized.get("pass")),
        _nonempty_string(normalized.get("from") or normalized.get("sender")),
    )
    if not all(required):
        raise ClosureIssue("send-email-profile-incomplete")


def _validate_send_email(value: dict[str, Any]) -> int:
    allowed_top = set(SEND_EMAIL_TOP_LEVEL) | set(SEND_EMAIL_PROFILE_KEYS) | {
        "SMTP_" + key.upper() for key in SEND_EMAIL_PROFILE_KEYS
    }
    if set(value) - allowed_top:
        raise ClosureIssue("send-email-authority-contains-unrelated-fields")
    metadata = value.get("_README")
    if metadata is not None and not _nonempty_string(metadata):
        raise ClosureIssue("send-email-metadata-invalid")
    profiles = 0
    if "smtp" in value:
        _validate_send_email_profile(value["smtp"])
        profiles += 1
    accounts = value.get("accounts")
    if accounts is not None:
        if not isinstance(accounts, dict) or not accounts:
            raise ClosureIssue("send-email-accounts-invalid")
        for account in accounts.values():
            _validate_send_email_profile(account)
            profiles += 1
        default = value.get("default_account")
        if default is not None and (not isinstance(default, str) or default not in accounts):
            raise ClosureIssue("send-email-default-account-invalid")
    direct = {key: item for key, item in value.items() if key not in SEND_EMAIL_TOP_LEVEL}
    if direct:
        _validate_send_email_profile(direct)
        profiles += 1
    if profiles == 0:
        raise ClosureIssue("send-email-authority-incomplete")
    return profiles


def _check_send_email(home: Path) -> CheckResult:
    identifier = "send-email"
    loaded = _json_object(home / ".config/send-email/secrets.json", mode=0o600)
    authority = loaded[0] if loaded else None
    if _read_regular(
        home / ".openclaw/workspace/.config/send-email/secrets.json", mode=0o600
    ) is not None:
        raise ClosureIssue("stale-send-email-openclaw-projection")
    shared = _json_object(home / ".config/ai-agents-skills/secrets.json", mode=0o600)
    if shared is not None and any(
        key in shared[1] or "SMTP_" + key.upper() in shared[1]
        for key in ("smtp", "accounts", "host", "password")
    ):
        raise ClosureIssue("send-email-duplicated-in-shared-authority")
    if loaded is None:
        return _not_configured(identifier)
    _check_env_selectors(
        home,
        variable="SEND_EMAIL_SECRETS_FILE",
        host_relative=".config/send-email/secrets.json",
        openclaw_value=None,
        require_runner=False,
    )
    return _pass(identifier, items=_validate_send_email(loaded[1]))


def _check_file_delivery_replay_ledger(
    home: Path, *, configured: bool, max_entries: int
) -> None:
    ledger = home / ".local/state/ai-agents-skills/file-delivery-replay"
    try:
        ledger_information = ledger.lstat()
    except FileNotFoundError:
        if configured:
            raise ClosureIssue("file-delivery-replay-ledger-missing")
        return
    except OSError as exc:
        raise ClosureIssue("file-delivery-replay-ledger-unsafe") from exc
    if (
        ledger.is_symlink()
        or not stat.S_ISDIR(ledger_information.st_mode)
        or ledger_information.st_uid != os.getuid()
        or stat.S_IMODE(ledger_information.st_mode) != 0o700
    ):
        raise ClosureIssue("file-delivery-replay-ledger-unsafe")

    opened = _open_parent_descriptor(ledger / ".closure-check")
    if opened is None:
        raise ClosureIssue("file-delivery-replay-ledger-unsafe")
    descriptor, _leaf, identity = opened
    try:
        opened_information = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened_information.st_mode)
            or opened_information.st_uid != os.getuid()
            or stat.S_IMODE(opened_information.st_mode) != 0o700
            or (opened_information.st_dev, opened_information.st_ino) != identity
        ):
            raise ClosureIssue("file-delivery-replay-ledger-unsafe")
        try:
            names = sorted(os.listdir(descriptor))
        except OSError as exc:
            raise ClosureIssue("file-delivery-replay-ledger-unsafe") from exc

        if not configured and names:
            raise ClosureIssue("stale-file-delivery-replay-state")

        marker_names: list[str] = []
        for name in names:
            if name == ".ledger.lock":
                lock = _read_regular(
                    ledger / name,
                    mode=0o600,
                    allow_empty=True,
                    maximum=1_024,
                )
                if lock != b"":
                    raise ClosureIssue("file-delivery-replay-ledger-invalid")
                continue
            if FILE_DELIVERY_MARKER_RE.fullmatch(name) is None:
                raise ClosureIssue("file-delivery-replay-ledger-invalid")
            marker_names.append(name)
            payload = _read_regular(
                ledger / name,
                mode=0o600,
                maximum=16_384,
            )
            if payload is None:  # pragma: no cover - listed from this directory
                raise ClosureIssue("file-delivery-replay-ledger-changed")
            try:
                marker = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ClosureIssue("file-delivery-replay-ledger-invalid") from exc
            if (
                not isinstance(marker, dict)
                or set(marker) != {"version", "job_id", "used_at"}
                or type(marker.get("version")) is not int
                or marker["version"] != 1
                or not isinstance(marker.get("job_id"), str)
                or FILE_DELIVERY_JOB_RE.fullmatch(marker["job_id"]) is None
                or type(marker.get("used_at")) is not int
                or not 0 <= marker["used_at"] <= 2**63 - 1
            ):
                raise ClosureIssue("file-delivery-replay-ledger-invalid")
        if len(marker_names) > max_entries:
            raise ClosureIssue("file-delivery-replay-ledger-full")
        try:
            if sorted(os.listdir(descriptor)) != names:
                raise ClosureIssue("file-delivery-replay-ledger-changed")
        except OSError as exc:
            raise ClosureIssue("file-delivery-replay-ledger-changed") from exc
    finally:
        os.close(descriptor)
    _confirm_parent_identity(ledger / ".closure-check", identity)


def _check_file_delivery_queue(home: Path) -> CheckResult:
    identifier = "file-delivery-queue"
    loaded = _json_object(
        home / ".config/ai-agents-skills/file-delivery-queue.json",
        mode=0o600,
    )
    if loaded is None:
        _check_file_delivery_replay_ledger(
            home,
            configured=False,
            max_entries=0,
        )
        return _not_configured(identifier)

    value = loaded[1]
    if (
        set(value) != FILE_DELIVERY_AUTHORITY_KEYS
        or type(value.get("version")) is not int
        or value["version"] != 1
        or not isinstance(value.get("hmac_key_hex"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["hmac_key_hex"]) is None
    ):
        raise ClosureIssue("file-delivery-authority-invalid")
    allowed = value.get("allowed")
    if not isinstance(allowed, dict) or not allowed:
        raise ClosureIssue("file-delivery-authority-invalid")
    for channel, targets in allowed.items():
        if (
            not isinstance(channel, str)
            or FILE_DELIVERY_CHANNEL_RE.fullmatch(channel) is None
            or not isinstance(targets, list)
            or not targets
            or any(
                not isinstance(target, str)
                or not target
                or target != target.strip()
                or len(target.encode("utf-8")) > 1_024
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in target
                )
                for target in targets
            )
            or len(targets) != len(set(targets))
        ):
            raise ClosureIssue("file-delivery-authority-invalid")
    age = value.get("max_job_age_seconds")
    media = value.get("max_media_bytes")
    retention = value.get("replay_retention_seconds")
    max_entries = value.get("max_replay_entries")
    if (
        type(age) is not int
        or not 5 <= age <= 300
        or type(media) is not int
        or not 1 <= media <= 100 * 1024 * 1024
        or value.get("replay_ledger_dir") != FILE_DELIVERY_REPLAY_TOKEN
        or type(retention) is not int
        or not age + 60 <= retention <= 604_800
        or type(max_entries) is not int
        or not 100 <= max_entries <= 100_000
    ):
        raise ClosureIssue("file-delivery-authority-invalid")

    _check_env_selectors(
        home,
        variable="AAS_FILE_DELIVERY_SECRETS_FILE",
        host_relative=".config/ai-agents-skills/file-delivery-queue.json",
        openclaw_value=None,
        require_runner=True,
    )
    _check_file_delivery_replay_ledger(
        home,
        configured=True,
        max_entries=max_entries,
    )
    return _pass(
        identifier,
        items=1,
        capabilities=("FILE_DELIVERY_QUEUE",),
    )


def _validate_openclaw_file_delivery_document(
    value: dict[str, Any], *, allow_token: bool
) -> None:
    expected_top = {"schema", "delivery_policy"}
    if allow_token and "TELEGRAM_BOT_TOKEN" in value:
        expected_top.add("TELEGRAM_BOT_TOKEN")
    if set(value) != expected_top or value.get("schema") != OPENCLAW_FILE_DELIVERY_SCHEMA:
        raise ClosureIssue("openclaw-file-delivery-policy-invalid")
    policy = value.get("delivery_policy")
    if not isinstance(policy, dict) or set(policy) != {"allowed_targets"}:
        raise ClosureIssue("openclaw-file-delivery-policy-invalid")
    allowed = policy.get("allowed_targets")
    if not isinstance(allowed, dict) or set(allowed) != OPENCLAW_FILE_DELIVERY_CHANNELS:
        raise ClosureIssue("openclaw-file-delivery-policy-invalid")
    for targets in allowed.values():
        if (
            not isinstance(targets, list)
            or len(targets) > 1_000
            or any(
                not isinstance(target, str)
                or not target
                or len(target.encode("utf-8")) > 4_096
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in target
                )
                for target in targets
            )
            or len(targets) != len(set(targets))
        ):
            raise ClosureIssue("openclaw-file-delivery-policy-invalid")
    token = value.get("TELEGRAM_BOT_TOKEN")
    if allow_token and token is not None and (
        not isinstance(token, str)
        or not token
        or len(token.encode("utf-8")) > 16_384
        or any(ord(character) < 32 or ord(character) == 127 for character in token)
    ):
        raise ClosureIssue("openclaw-file-delivery-policy-invalid")


def _check_openclaw_file_delivery_policy(home: Path) -> CheckResult:
    identifier = "openclaw-file-delivery-policy"
    loaded = _json_object(home / ".openclaw/file-delivery-policy.json", mode=0o600)
    projection_path = home / ".openclaw/workspace/.config/file-delivery/secrets.json"
    projection = _read_regular(projection_path, mode=0o600)
    if projection is not None:
        raise ClosureIssue("stale-openclaw-file-delivery-projection")
    if loaded is None:
        return _not_configured(identifier)

    authority = loaded[1]
    _validate_openclaw_file_delivery_document(authority, allow_token=False)

    environment = _read_openclaw_environment(home)
    if "AAS_FILE_DELIVERY_SECRETS_FILE" in environment:
        raise ClosureIssue("openclaw-retired-selector-present")
    return _pass(
        identifier,
        items=1,
        capabilities=("OPENCLAW_FILE_DELIVERY_POLICY",),
    )


def _check_strict_env_authority(
    home: Path,
    *,
    identifier: str,
    filename: str,
    selector: str,
    keys: frozenset[str],
    openclaw_value: str | None,
    require_runner: bool,
    check_selectors: bool = True,
    mirror_to_openclaw: bool = True,
) -> tuple[CheckResult, dict[str, str], bytes | None]:
    path = home / ".config/ai-agents-skills" / filename
    payload = _read_regular(path, mode=0o600)
    if _legacy_shell_values(home, keys):
        raise ClosureIssue("ambient-shell-credential-present")
    legacy = _legacy_json_values(home, keys)
    projection = home / ".openclaw/workspace/.config/ai-agents-skills" / filename
    _check_exact_projections(
        payload if mirror_to_openclaw else None,
        ((projection, 0o600),),
    )
    if payload is None:
        if legacy:
            raise ClosureIssue("legacy-authority-unmigrated")
        return _not_configured(identifier), {}, None
    values = _parse_strict_env(payload, keys)
    for key, expected in legacy.items():
        if values.get(key) != expected:
            raise ClosureIssue("legacy-authority-divergent")
    if check_selectors:
        _check_env_selectors(
            home,
            variable=selector,
            host_relative=f".config/ai-agents-skills/{filename}",
            openclaw_value=openclaw_value,
            require_runner=require_runner,
        )
    if not values:
        return _not_configured(identifier, "authority-empty"), values, payload
    return (
        _pass(
            identifier,
            items=len(values),
            capabilities=tuple(sorted(values)),
        ),
        values,
        payload,
    )


def _run_lane_projection_probe(
    home: Path,
    *,
    lane: str,
    authority: Path,
    capabilities: tuple[str, ...],
    provider_profile: str | None = None,
) -> None:
    """Execute the installed provider-free strict-loader probe for every key."""

    runtime = home / ".local/share/ai-agents-skills/runtime"
    probe = runtime / "runners/credential_projection_probe.py"
    checker = runtime / "runners/credential_projection_check.py"
    loader = runtime / "load_secret_env.py"
    accepted_modes = frozenset({0o444, 0o544, 0o644, 0o744, 0o755})
    aas_source = _ACTIVE_AAS_SOURCE.get()
    source_relatives = {
        probe: "canonical/runtime/runners/credential_projection_probe.py",
        checker: "canonical/runtime/runners/credential_projection_check.py",
        loader: "canonical/runtime/runners/load_secret_env.py",
    }
    for path, relative in source_relatives.items():
        payload = _read_regular(path, mode=accepted_modes)
        if payload is None:
            raise ClosureIssue("credential-projection-probe-missing")
        source = _read_source_contract(aas_source, relative).encode("utf-8")
        if payload != source:
            raise ClosureIssue("credential-projection-probe-divergent")
    if lane not in {"skill", "compute", "provider"}:
        raise ClosureIssue("credential-projection-probe-invalid")
    pointer = {
        "skill": "AAS_SKILL_SECRETS_FILE",
        "compute": "AAS_COMPUTE_SECRETS_FILE",
        "provider": "AAS_PROVIDER_SECRETS_FILE",
    }[lane]
    for capability in capabilities:
        command = [
            "/usr/bin/python3",
            "-I",
            os.fspath(probe),
            "--lane",
            lane,
        ]
        if provider_profile is not None:
            command.extend(("--provider-profile", provider_profile))
        command.extend(
            (
                "--expect-key",
                capability,
                "--checker",
                os.fspath(checker),
            )
        )
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "HOME": os.fspath(home),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    pointer: os.fspath(authority),
                },
                timeout=20,
                check=False,
                text=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ClosureIssue("credential-projection-probe-failed") from exc
        if (
            completed.returncode != 0
            or completed.stdout != f"PASS lane={lane}\n"
            or completed.stderr
        ):
            raise ClosureIssue("credential-projection-probe-failed")


def _attest_installed_aas_module(
    home: Path, *, installed_relative: str, source_relative: str
) -> Path:
    """Bind one installed offline consumer module to the pinned AAS bytes."""

    installed = home / installed_relative
    payload = _read_regular(
        installed, mode=frozenset({0o444, 0o544, 0o644, 0o744, 0o755})
    )
    if payload is None:
        raise ClosureIssue("credential-consumer-probe-missing")
    source = _read_source_contract(
        _ACTIVE_AAS_SOURCE.get(), source_relative
    ).encode("utf-8")
    if payload != source:
        raise ClosureIssue("credential-consumer-probe-divergent")
    return installed


def _run_remote_bridge_consumer_probe(home: Path) -> None:
    """Exercise ARL's real, offline Zulip selection through Remote Bridge."""

    installed_root = (
        home
        / ".local/share/ai-agents-skills/runtime/workspace/skills"
        / "autonomous-research-loop-runtime"
    )
    source_root = "canonical/runtime/skills/autonomous-research-loop-runtime"
    for name in ARL_CONSUMER_MODULES:
        _attest_installed_aas_module(
            home,
            installed_relative=os.fspath(
                installed_root.relative_to(home) / name
            ),
            source_relative=f"{source_root}/{name}",
        )
    _attest_installed_aas_module(
        home,
        installed_relative=(
            ".local/share/ai-agents-skills/runtime/workspace/skills/"
            "remote-bridge/remote_bridge.py"
        ),
        source_relative=(
            "canonical/runtime/skills/remote-bridge/remote_bridge.py"
        ),
    )
    probe = r"""
import importlib.util
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root))
target = root / "autonomous_research_loop_runtime.py"
spec = importlib.util.spec_from_file_location("csr_arl_consumer_probe", target)
if spec is None or spec.loader is None:
    raise SystemExit(3)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
channels = module.detect_configured_notify_channels()
selected = module.auto_notify_channel_from_secrets()
if not channels or channels[0] != "zulip" or selected != "zulip":
    raise SystemExit(4)
print("PASS consumer=zulip")
"""
    try:
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                "-c",
                probe,
                os.fspath(installed_root),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "HOME": os.fspath(home),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
                "REMOTE_BRIDGE_SECRETS_FILE": os.fspath(
                    home / ".config/remote-bridge/secrets.json"
                ),
            },
            timeout=20,
            check=False,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClosureIssue("credential-consumer-probe-failed") from exc
    if (
        completed.returncode != 0
        or completed.stdout != "PASS consumer=zulip\n"
        or completed.stderr
    ):
        raise ClosureIssue("credential-consumer-probe-failed")


def _run_kaggle_consumer_probe(home: Path, token: str) -> None:
    """Exercise the installed broker's offline token_present consumer path.

    The broker reads only the KAGGLE_API_TOKEN projection that managed launchers
    place in its environment, so the probe projects the token the same way.
    """

    module = _attest_installed_aas_module(
        home,
        installed_relative=(
            ".local/share/ai-agents-skills/runtime/workspace/"
            "research_compute/kaggle_backend.py"
        ),
        source_relative=(
            "canonical/runtime/workspace/research_compute/kaggle_backend.py"
        ),
    )
    probe = r"""
import importlib.util
import pathlib
import sys

target = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("csr_kaggle_consumer_probe", target)
if spec is None or spec.loader is None:
    raise SystemExit(3)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
if not module.token_present():
    raise SystemExit(4)
print("PASS consumer=kaggle")
"""
    try:
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                "-c",
                probe,
                os.fspath(module),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "HOME": os.fspath(home),
                "KAGGLE_API_TOKEN": token,
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
            },
            timeout=20,
            check=False,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClosureIssue("credential-consumer-probe-failed") from exc
    if (
        completed.returncode != 0
        or completed.stdout != "PASS consumer=kaggle\n"
        or completed.stderr
    ):
        raise ClosureIssue("credential-consumer-probe-failed")


def _run_copilot_projection_probe(home: Path, authority: Path) -> None:
    launcher = home / ".local/bin/copilot"
    payload = _read_regular(launcher, mode=0o755)
    if payload is None:
        raise ClosureIssue("credential-projection-probe-missing")
    repository = _ACTIVE_REPOSITORY.get()
    if repository is None:
        raise ClosureIssue("credential-projection-probe-missing")
    template = _read_source_contract(repository, "system/bin/copilot")
    compatibility_loader = (
        home
        / ".npm-global/lib/node_modules/@github/copilot/npm-loader.js"
    )
    try:
        installed_loader = compatibility_loader.resolve(strict=True)
    except OSError as exc:
        raise ClosureIssue("credential-projection-probe-missing") from exc
    expected = (
        template.replace("{{ HOME }}", os.fspath(home))
        .replace("{{ COPILOT_LOADER }}", os.fspath(installed_loader))
        .encode("utf-8")
    )
    if payload != expected:
        raise ClosureIssue("credential-projection-probe-divergent")
    try:
        completed = subprocess.run(
            [os.fspath(launcher), "--csr-credential-probe"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "HOME": os.fspath(home),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "AAS_PROVIDER_SECRETS_FILE": os.fspath(authority),
            },
            timeout=20,
            check=False,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClosureIssue("credential-projection-probe-failed") from exc
    if (
        completed.returncode != 0
        or completed.stdout != "PASS lane=provider\n"
        or completed.stderr
    ):
        raise ClosureIssue("credential-projection-probe-failed")


def _check_compute(home: Path) -> CheckResult:
    result, values, _payload = _check_strict_env_authority(
        home,
        identifier="compute-credentials",
        filename="compute.env",
        selector="AAS_COMPUTE_SECRETS_FILE",
        keys=COMPUTE_KEYS,
        openclaw_value="/workspace/.config/ai-agents-skills/compute.env",
        require_runner=False,
    )
    token = values.get("KAGGLE_API_TOKEN")
    token_path = home / ".kaggle/access_token"
    observed = _read_regular(token_path, mode=0o600)
    if token is None:
        if observed is not None:
            raise ClosureIssue("stale-kaggle-projection")
    elif observed != (token + "\n").encode("utf-8"):
        raise ClosureIssue("kaggle-projection-divergent")
    if values:
        _run_lane_projection_probe(
            home,
            lane="compute",
            authority=home / ".config/ai-agents-skills/compute.env",
            capabilities=tuple(sorted(values)),
        )
    return result


def _check_kaggle(home: Path) -> CheckResult:
    """Report Kaggle independently from the aggregate compute authority."""

    identifier = "kaggle"
    payload = _read_regular(
        home / ".config/ai-agents-skills/compute.env", mode=0o600
    )
    if payload is None:
        return _not_configured(identifier)
    values = _parse_strict_env(payload, COMPUTE_KEYS)
    token = values.get("KAGGLE_API_TOKEN")
    if token is None:
        return _not_configured(identifier, "capability-absent")
    observed = _read_regular(home / ".kaggle/access_token", mode=0o600)
    if observed != (token + "\n").encode("utf-8"):
        raise ClosureIssue("kaggle-projection-divergent")
    _run_kaggle_consumer_probe(home, token)
    return _pass(identifier)


def _check_hetzner(home: Path) -> CheckResult:
    """Report Hetzner independently from the aggregate compute authority."""

    identifier = "hetzner"
    payload = _read_regular(
        home / ".config/ai-agents-skills/compute.env", mode=0o600
    )
    if payload is None:
        return _not_configured(identifier)
    values = _parse_strict_env(payload, COMPUTE_KEYS)
    if "HCLOUD_TOKEN" not in values:
        return _not_configured(identifier, "capability-absent")
    return _pass(identifier)


def _check_skill_env(home: Path) -> CheckResult:
    result, values, _payload = _check_strict_env_authority(
        home,
        identifier="skill-credentials",
        filename="skill.env",
        selector="AAS_SKILL_SECRETS_FILE",
        keys=SKILL_KEYS,
        openclaw_value=None,
        require_runner=True,
        mirror_to_openclaw=False,
    )
    for relative, keys in (
        (
            ".openclaw/workspace/.config/ai-agents-skills/axiom-axle.env",
            ("AXLE_API_KEY",),
        ),
        (
            ".openclaw/workspace/.config/ai-agents-skills/lean-explore.env",
            ("LEANEXPLORE_API_KEY",),
        ),
        (
            ".openclaw/workspace/.config/ai-agents-skills/research-digest.env",
            ("OPENCLAW_S2_API_KEY",),
        ),
        (
            ".openclaw/workspace/.config/ai-agents-skills/submission-venue.env",
            ("SEMANTIC_SCHOLAR_API_KEY", "UNPAYWALL_EMAIL"),
        ),
    ):
        _check_exact_env_subset_projection(
            home,
            relative=relative,
            authority_values=values,
            keys=keys,
        )
    if values:
        _run_lane_projection_probe(
            home,
            lane="skill",
            authority=home / ".config/ai-agents-skills/skill.env",
            capabilities=tuple(sorted(values)),
        )
    return result


def _check_provider_env(home: Path) -> CheckResult:
    result, values, _payload = _check_strict_env_authority(
        home,
        identifier="provider-credentials",
        filename="providers.env",
        selector="AAS_PROVIDER_SECRETS_FILE",
        keys=PROVIDER_KEYS,
        openclaw_value="/workspace/.config/ai-agents-skills/providers.env",
        require_runner=True,
    )
    if values:
        _run_lane_projection_probe(
            home,
            lane="provider",
            authority=home / ".config/ai-agents-skills/providers.env",
            capabilities=tuple(sorted(values)),
            provider_profile="arl",
        )
    return result


def _check_copilot_env(home: Path) -> CheckResult:
    result, values, _payload = _check_strict_env_authority(
        home,
        identifier="copilot-credentials",
        filename="providers/copilot.env",
        selector="AAS_PROVIDER_SECRETS_FILE",
        keys=COPILOT_KEYS,
        openclaw_value=(
            "/workspace/.config/ai-agents-skills/providers/copilot.env"
        ),
        require_runner=False,
        check_selectors=False,
    )
    if values:
        _run_copilot_projection_probe(
            home,
            home / ".config/ai-agents-skills/providers/copilot.env",
        )
    return result


def _check_modal(home: Path) -> CheckResult:
    identifier = "modal"
    payload = _read_regular(home / ".modal.toml", mode=0o600)
    _check_exact_projections(
        payload,
        ((home / ".openclaw/workspace/.modal.toml", 0o600),),
    )
    if payload is None:
        return _not_configured(identifier)
    try:
        document = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ClosureIssue("modal-authority-invalid") from exc
    profiles = [
        profile
        for profile in document.values()
        if isinstance(profile, dict)
        and _nonempty_string(profile.get("token_id"))
        and _nonempty_string(profile.get("token_secret"))
    ]
    if not profiles:
        raise ClosureIssue("modal-authority-incomplete")
    return _pass(identifier, items=len(profiles))


def _read_shared_aas_value(home: Path, key: str) -> str | None:
    loaded = _json_object(home / ".config/ai-agents-skills/secrets.json", mode=0o600)
    if loaded is None:
        return None
    if set(loaded[1]) - AAS_JSON_KEYS:
        raise ClosureIssue("shared-authority-contains-unsupported-fields")
    value = loaded[1].get(key)
    if value is None:
        return None
    if not _nonempty_string(value):
        raise ClosureIssue("shared-authority-invalid")
    return value


def _check_neutral_config(
    home: Path,
    *,
    identifier: str,
    filename: str,
    projection_paths: tuple[str, ...],
) -> tuple[dict[str, Any] | None, bytes | None]:
    loaded = _json_object(
        home / f".config/ai-agents-skills/{identifier}/config.json", mode=0o644
    )
    payload = loaded[0] if loaded else None
    _check_exact_projections(
        payload,
        tuple((home / path, 0o644) for path in projection_paths),
    )
    return (loaded[1] if loaded else None), payload


def _check_zotero(home: Path) -> CheckResult:
    identifier = "zotero"
    config, _payload = _check_neutral_config(
        home,
        identifier=identifier,
        filename="config.json",
        projection_paths=(
            ".openclaw/workspace/skills/zotero/config.json",
            ".codex/runtime/workspace/skills/zotero/config.json",
            ".local/share/ai-agents-skills/runtime/workspace/skills/zotero/config.json",
            ".claude/skills/zotero/config.json",
        ),
    )
    zotero_secrets = {
        key: value
        for key in ("ZOTERO_API_KEY", "WEBDAV_PASSWORD", "GDRIVE_CREDENTIALS")
        if (value := _read_shared_aas_value(home, key)) is not None
    }
    skill_payload = _read_regular(
        home / ".config/ai-agents-skills/skill.env", mode=0o600
    )
    skill_values = (
        _parse_strict_env(skill_payload, SKILL_KEYS)
        if skill_payload is not None
        else {}
    )
    semantic_scholar = skill_values.get("SEMANTIC_SCHOLAR_API_KEY")
    if semantic_scholar is not None:
        zotero_secrets["SEMANTIC_SCHOLAR_API_KEY"] = semantic_scholar
    for relative in (
        ".config/ai-agents-skills/zotero-secrets.json",
        ".openclaw/workspace/.config/ai-agents-skills/zotero-secrets.json",
    ):
        _check_exact_json_subset_projection(
            home,
            relative=relative,
            expected=zotero_secrets,
        )
    api_key = zotero_secrets.get("ZOTERO_API_KEY")
    if config is not None and "semantic_scholar_api_key" in config:
        raise ClosureIssue("zotero-config-contains-legacy-secret")
    if config is None and api_key is None:
        return _not_configured(identifier)
    _check_env_selectors(
        home,
        variable="AAS_ZOTERO_SECRETS_FILE",
        host_relative=".config/ai-agents-skills/zotero-secrets.json",
        openclaw_value=None,
        require_runner=True,
    )
    _read_openclaw_environment(home)
    if config is None or api_key is None:
        raise ClosureIssue("zotero-authority-incomplete")
    user_id = config.get("zotero_user_id")
    if isinstance(user_id, bool) or not (
        (isinstance(user_id, int) and user_id > 0) or _nonempty_string(user_id)
    ):
        raise ClosureIssue("zotero-config-incomplete")
    return _pass(identifier, items=2)


def _check_calibre(home: Path) -> CheckResult:
    identifier = "calibre"
    config, _payload = _check_neutral_config(
        home,
        identifier=identifier,
        filename="config.json",
        projection_paths=(
            ".openclaw/workspace/skills/calibre/config.json",
            ".codex/runtime/workspace/skills/calibre/config.json",
            ".local/share/ai-agents-skills/runtime/workspace/skills/calibre/config.json",
            ".claude/skills/calibre/config.json",
        ),
    )
    credentials = _read_shared_aas_value(home, "GDRIVE_CREDENTIALS")
    shared_folder = _read_shared_aas_value(home, "CALIBRE_GDRIVE_FOLDER_ID")
    calibre_secrets = {
        key: value
        for key, value in (
            ("GDRIVE_CREDENTIALS", credentials),
            ("CALIBRE_GDRIVE_FOLDER_ID", shared_folder),
        )
        if value is not None
    }
    for relative in (
        ".config/ai-agents-skills/calibre-secrets.json",
        ".openclaw/workspace/.config/ai-agents-skills/calibre-secrets.json",
    ):
        _check_exact_json_subset_projection(
            home,
            relative=relative,
            expected=calibre_secrets,
        )
    configured_folder = config.get("gdrive_folder_id") if config else None
    if config is None and credentials is None and shared_folder is None:
        return _not_configured(identifier)
    _check_env_selectors(
        home,
        variable="AAS_CALIBRE_SECRETS_FILE",
        host_relative=".config/ai-agents-skills/calibre-secrets.json",
        openclaw_value=None,
        require_runner=True,
    )
    if config is None or credentials is None:
        raise ClosureIssue("calibre-authority-incomplete")
    if shared_folder is not None and _nonempty_string(configured_folder) and shared_folder != configured_folder:
        raise ClosureIssue("calibre-folder-authority-conflict")
    folder = configured_folder or shared_folder
    if not _nonempty_string(folder):
        raise ClosureIssue("calibre-config-incomplete")
    return _pass(identifier, items=2)


def _validate_google_client(value: dict[str, Any]) -> None:
    client = value.get("installed") or value.get("web")
    if not isinstance(client, dict) or not all(
        _nonempty_string(client.get(key))
        for key in ("client_id", "client_secret", "auth_uri", "token_uri")
    ):
        raise ClosureIssue("google-classroom-client-invalid")


def _check_google_classroom(home: Path) -> CheckResult:
    identifier = "google-classroom"
    credential = _json_object(
        home / ".config/course/google-classroom/credentials.json", mode=0o600
    )
    token = _read_regular(
        home / ".config/course/google-classroom/token.pickle", mode=0o600
    )
    _check_exact_projections(
        credential[0] if credential else None,
        (
            (
                home
                / ".openclaw/workspace/.config/course/google-classroom/credentials.json",
                0o600,
            ),
        ),
    )
    _check_exact_projections(
        token,
        (
            (
                home / ".openclaw/workspace/.config/course/google-classroom/token.pickle",
                0o600,
            ),
        ),
    )
    if credential is None and token is None:
        return _not_configured(identifier)
    if credential is None:
        raise ClosureIssue("google-classroom-client-missing")
    _validate_google_client(credential[1])
    _check_env_selectors(
        home,
        variable="GOOGLE_CLASSROOM_CREDENTIALS",
        host_relative=".config/course/google-classroom/credentials.json",
        openclaw_value="/workspace/.config/course/google-classroom/credentials.json",
        require_runner=False,
    )
    _check_env_selectors(
        home,
        variable="GOOGLE_CLASSROOM_TOKEN",
        host_relative=".config/course/google-classroom/token.pickle",
        openclaw_value="/workspace/.config/course/google-classroom/token.pickle",
        require_runner=False,
    )
    for skill in (
        home / ".codex/skills/course-google-classroom/SKILL.md",
        home / ".local/share/ai-agents-skills/runtime/workspace/skills/course-google-classroom/SKILL.md",
    ):
        text = _read_text(skill, mode=0o644, allow_empty=True)
        if text is not None and (
            "GOOGLE_CLASSROOM_CREDENTIALS" not in text
            or "GOOGLE_CLASSROOM_TOKEN" not in text
            or ".config/course/google-classroom" not in text
        ):
            raise ClosureIssue("google-classroom-selector-missing")
    if token is None:
        return _not_configured(identifier, "oauth-token-not-configured")
    return _pass(identifier, items=2)


def _legacy_canvas_values(home: Path) -> dict[str, str]:
    root = home / ".config/course"
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ClosureIssue("legacy-canvas-root-unsafe") from exc
    if root.is_symlink() or not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid():
        raise ClosureIssue("legacy-canvas-root-unsafe")
    observed: list[dict[str, str]] = []
    authority = root / "canvas/config.json"
    for path in sorted(root.glob("*/config.json")):
        if path == authority:
            continue
        try:
            parent_info = path.parent.lstat()
        except OSError as exc:
            raise ClosureIssue("legacy-canvas-root-unsafe") from exc
        if (
            path.parent.is_symlink()
            or not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.getuid()
        ):
            raise ClosureIssue("legacy-canvas-root-unsafe")
        payload = _read_regular(
            path,
            mode=frozenset({0o600, 0o640, 0o644}),
        )
        if payload is None:
            continue
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ClosureIssue("legacy-canvas-json-invalid") from exc
        if not isinstance(value, dict):
            raise ClosureIssue("legacy-canvas-json-invalid")
        mentioned = any(key in value for key in CANVAS_CONFIG_KEYS)
        if not mentioned:
            continue
        if stat.S_IMODE(path.lstat().st_mode) != 0o600:
            raise ClosureIssue("legacy-canvas-config-not-private")
        selected = {
            key: value[key].strip()
            for key in CANVAS_CONFIG_KEYS
            if _nonempty_string(value.get(key))
        }
        if not all(key in selected for key in ("CANVAS_LMS_API_URL", "CANVAS_LMS_API_KEY")):
            raise ClosureIssue("legacy-canvas-config-incomplete")
        observed.append(selected)
    if observed and any(item != observed[0] for item in observed[1:]):
        raise ClosureIssue("legacy-canvas-config-conflict")
    return observed[0] if observed else {}


def _check_canvas(home: Path) -> CheckResult:
    identifier = "canvas"
    legacy = _legacy_canvas_values(home)
    loaded = _json_object(home / ".config/course/canvas/config.json", mode=0o600)
    authority = loaded[0] if loaded else None
    _check_exact_projections(
        authority,
        ((home / ".openclaw/workspace/.config/course/canvas/config.json", 0o600),),
    )
    if loaded is None:
        if legacy:
            raise ClosureIssue("legacy-authority-unmigrated")
        return _not_configured(identifier)
    value = loaded[1]
    if set(value) - CANVAS_CONFIG_KEYS:
        raise ClosureIssue("canvas-authority-contains-unsupported-fields")
    if any(
        not _nonempty_string(value.get(key))
        for key in ("CANVAS_LMS_API_URL", "CANVAS_LMS_API_KEY")
    ):
        raise ClosureIssue("canvas-authority-incomplete")
    course_id = value.get("CANVAS_LMS_COURSE_ID")
    if course_id is not None and not _nonempty_string(course_id):
        raise ClosureIssue("canvas-course-id-invalid")
    for key, expected in legacy.items():
        if value.get(key) != expected:
            raise ClosureIssue("legacy-authority-divergent")
    _check_env_selectors(
        home,
        variable="CANVAS_CONFIG_PATH",
        host_relative=".config/course/canvas/config.json",
        openclaw_value="/workspace/.config/course/canvas/config.json",
        require_runner=False,
    )
    for skill in (
        home / ".codex/skills/course-canvas/SKILL.md",
        home / ".local/share/ai-agents-skills/runtime/workspace/skills/course-canvas/SKILL.md",
    ):
        text = _read_text(skill, mode=0o644, allow_empty=True)
        if text is not None and (
            "CANVAS_CONFIG_PATH" not in text or ".config/course/canvas" not in text
        ):
            raise ClosureIssue("canvas-selector-missing")
    return _pass(identifier, items=len(value))


def _check_vnu(home: Path) -> CheckResult:
    identifier = "vnu-eoffice"
    legacy = _legacy_json_values(
        home, frozenset((*VNU_REQUIRED_KEYS, VNU_HMAC_KEY))
    )
    loaded = _json_object(home / ".config/vnu-eoffice/secrets.json", mode=0o600)
    authority = loaded[0] if loaded else None
    _check_exact_projections(
        authority,
        ((home / ".openclaw/workspace/secrets/vnu-eoffice/secrets.json", 0o600),),
    )
    if loaded is None:
        if legacy:
            raise ClosureIssue("legacy-authority-unmigrated")
        return _not_configured(identifier)
    value = loaded[1]
    if set(value) - {*VNU_REQUIRED_KEYS, VNU_HMAC_KEY}:
        raise ClosureIssue("vnu-authority-contains-retired-delivery-fields")
    if any(not _nonempty_string(value.get(key)) for key in VNU_REQUIRED_KEYS):
        raise ClosureIssue("vnu-authority-incomplete")
    hmac_key = value.get(VNU_HMAC_KEY)
    if hmac_key is not None and (
        not _nonempty_string(hmac_key) or len(hmac_key) < 32
    ):
        raise ClosureIssue("vnu-hmac-key-weak")
    for key, expected in legacy.items():
        if value.get(key) != expected:
            raise ClosureIssue("legacy-authority-divergent")
    for wrapper in (
        home / ".openclaw/workspace/skills/vnu-eoffice/run_vnu_eoffice.sh",
        home / ".openclaw/skills/vnu-eoffice/run_vnu_eoffice.sh",
    ):
        text = _read_text(wrapper, mode=0o755, allow_empty=True)
        if text is not None and (
            "VNU_SECRETS_FILE" not in text
            or "secrets/vnu-eoffice/secrets.json" not in text
        ):
            raise ClosureIssue("vnu-selector-missing")
    return _pass(identifier, items=len(VNU_REQUIRED_KEYS) + int(hmac_key is not None))


def _getscipapers_path_allowed(relative: str) -> bool:
    return relative in GETSCIPAPERS_FILES


def _require_private_getscipapers_ancestors(root: Path, path: Path) -> None:
    current = path.parent
    while current != root.parent:
        try:
            information = current.lstat()
        except OSError as exc:
            raise ClosureIssue("getscipapers-entry-unsafe") from exc
        if (
            current.is_symlink()
            or not stat.S_ISDIR(information.st_mode)
            or information.st_uid != os.getuid()
            or information.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ClosureIssue("getscipapers-entry-unsafe")
        if current == root:
            return
        current = current.parent
    raise ClosureIssue("getscipapers-entry-unsafe")


def _scan_getscipapers(root: Path) -> dict[str, bytes]:
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ClosureIssue("getscipapers-root-unsafe") from exc
    if root.is_symlink() or not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid():
        raise ClosureIssue("getscipapers-root-unsafe")
    found: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        try:
            information = path.lstat()
        except OSError as exc:
            raise ClosureIssue("getscipapers-entry-unsafe") from exc
        if path.is_symlink():
            raise ClosureIssue("getscipapers-entry-unsafe")
        if stat.S_ISDIR(information.st_mode):
            # Empty cache/log directories are outside the credential allowlist
            # and may retain package-default modes.  A declared credential file,
            # however, must have a private ancestor chain; check that below.
            if information.st_uid != os.getuid():
                raise ClosureIssue("getscipapers-entry-unsafe")
            continue
        if not stat.S_ISREG(information.st_mode):
            raise ClosureIssue("getscipapers-entry-unsafe")
        relative = path.relative_to(root).as_posix()
        if not _getscipapers_path_allowed(relative):
            raise ClosureIssue("getscipapers-file-undeclared")
        _require_private_getscipapers_ancestors(root, path)
        payload = _read_regular(path, mode=0o600)
        assert payload is not None
        if GETSCIPAPERS_FILES[relative]:
            try:
                decoded = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ClosureIssue("getscipapers-json-invalid") from exc
            if not isinstance(decoded, dict) or not decoded:
                raise ClosureIssue("getscipapers-json-incomplete")
        found[relative] = payload
    return found


def _check_getscipapers(home: Path) -> CheckResult:
    identifier = "getscipapers"
    authority = _scan_getscipapers(home / ".config/getscipapers")
    projection = _scan_getscipapers(
        home / ".openclaw/workspace/.config/getscipapers"
    )
    legacy_projection = _scan_getscipapers(
        home / ".openclaw/workspace/secrets/getscipapers"
    )
    if legacy_projection:
        raise ClosureIssue("getscipapers-legacy-projection-remains")
    if not authority:
        if projection:
            raise ClosureIssue("stale-projection")
        # No tooling creates this root, so its presence means the skill was
        # configured here at least once.  An empty root is therefore a lost
        # credential tree, not an unconfigured one, and must not be reported
        # as a deliberate opt-out.
        if (home / ".config/getscipapers").is_dir():
            raise ClosureIssue("getscipapers-authority-empty")
        return _not_configured(identifier)
    # Set and byte agreement below prove the projection matches the authority;
    # neither proves the authority can authenticate.  A tree holding only opaque
    # caches is perfectly consistent and completely unusable, so require at
    # least one credential-bearing file before reporting closure.
    if not any(GETSCIPAPERS_FILES[relative] for relative in authority):
        raise ClosureIssue("getscipapers-credentials-absent")
    if set(authority) != set(projection):
        raise ClosureIssue("getscipapers-projection-set-divergent")
    if any(projection[name] != payload for name, payload in authority.items()):
        raise ClosureIssue("projection-divergent")
    _read_openclaw_environment(home)
    capabilities = tuple(
        sorted(
            "GETSCIPAPERS_"
            + re.sub(r"[^A-Z0-9]+", "_", relative.upper()).strip("_")
            for relative in authority
        )
    )
    if len(capabilities) != len(set(capabilities)):
        raise ClosureIssue("getscipapers-capability-collision")
    return _pass(
        identifier, items=len(capabilities), capabilities=capabilities
    )


def _check_tailscale(home: Path) -> CheckResult:
    identifier = "tailscale"
    try:
        (home / TAILSCALE_LEGACY_RELATIVE).lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ClosureIssue("tailscale-legacy-authority-unsafe") from exc
    else:
        raise ClosureIssue("tailscale-legacy-authority-present")
    authkey_payload = _read_regular(
        home / TAILSCALE_AUTHKEY_RELATIVE, mode=0o600
    )
    hostname_payload = _read_regular(
        home / TAILSCALE_HOSTNAME_RELATIVE, mode=0o600
    )
    if authkey_payload is None and hostname_payload is None:
        return _not_configured(identifier)
    if authkey_payload is None or hostname_payload is None:
        raise ClosureIssue("tailscale-authority-incomplete")
    try:
        parse_tailscale_authkey(authkey_payload)
        parse_tailscale_hostname(hostname_payload)
    except TailscaleAuthorityError as exc:
        raise ClosureIssue("tailscale-authority-invalid") from exc
    capabilities = ("TAILSCALE_AUTH_KEY", "TAILSCALE_HOSTNAME")
    state = tailscale_backend_state()
    if state == "Running":
        return _pass(identifier, items=2, capabilities=capabilities)
    if state in {"NeedsLogin", "NoState", "Stopped"}:
        return _reauth_required(
            identifier,
            reason="daemon-reauth-required",
            items=2,
            capabilities=capabilities,
        )
    raise ClosureIssue("tailscale-local-status-unavailable")


def _check_forms_local(home: Path) -> CheckResult:
    """Bind exact Git-ignored Forms files without parsing or reporting values."""

    identifier = "forms-local"
    files = (
        (
            "forms/apps/classroom50-runner/.env",
            "FORMS_CLASSROOM50_RUNNER_LOCAL",
        ),
        ("forms/apps/api/.dev.vars", "FORMS_API_LOCAL"),
        ("forms/apps/web/.env.local", "FORMS_WEB_LOCAL"),
    )
    configured = tuple(
        capability
        for relative, capability in files
        if _read_regular(home / relative, mode=0o600) is not None
    )
    if not configured:
        return _not_configured(identifier)
    return _pass(
        identifier,
        items=len(configured),
        capabilities=tuple(sorted(configured)),
    )


CHECKS: tuple[tuple[str, Callable[[Path], CheckResult]], ...] = (
    ("aas-runtime-secrets", _check_aas_runtime_secrets),
    ("remote-bridge", _check_remote_bridge),
    ("zulip", _check_zulip),
    ("telegram", _check_telegram),
    ("send-email", _check_send_email),
    ("file-delivery-queue", _check_file_delivery_queue),
    ("openclaw-file-delivery-policy", _check_openclaw_file_delivery_policy),
    ("compute-credentials", _check_compute),
    ("kaggle", _check_kaggle),
    ("hetzner", _check_hetzner),
    ("skill-credentials", _check_skill_env),
    ("provider-credentials", _check_provider_env),
    ("copilot-credentials", _check_copilot_env),
    ("modal", _check_modal),
    ("zotero", _check_zotero),
    ("calibre", _check_calibre),
    ("google-classroom", _check_google_classroom),
    ("canvas", _check_canvas),
    ("vnu-eoffice", _check_vnu),
    ("getscipapers", _check_getscipapers),
    ("tailscale", _check_tailscale),
    ("forms-local", _check_forms_local),
)


def _load_source_capability_contract(path: Path) -> dict[str, object]:
    payload = _read_regular(path, mode=0o600)
    if payload is None:
        raise ClosureIssue("source-capability-contract-missing")
    try:
        report = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClosureIssue("source-capability-contract-invalid") from exc
    expected_top = {"checks", "counts", "schema", "schemaVersion", "status"}
    if not isinstance(report, dict) or set(report) != expected_top:
        raise ClosureIssue("source-capability-contract-invalid")
    schema_pair = (report.get("schema"), report.get("schemaVersion"))
    if type(report.get("schemaVersion")) is not int or report.get("status") != "PASS":
        raise ClosureIssue("source-capability-contract-invalid")
    if schema_pair == (SCHEMA, SCHEMA_VERSION):
        expected_identifiers = frozenset(CHECK_IDS)
        expected_count_keys = COUNT_KEYS
        # Policy confirmation is ephemeral operation evidence.  A recovery set
        # must never turn it into portable consent or a restore obligation.
        allowed_statuses = frozenset(
            {"CREDIT_BLOCKED", "NOT_CONFIGURED", "PASS", "REAUTH_REQUIRED"}
        )
    elif schema_pair == (LEGACY_SCHEMA, 2):
        # Recovery sets created before the independent channel, compute-backend,
        # and Tailscale rows remain consumable. They cannot prove capabilities
        # their schema never recorded; every new v3 generation records those
        # rows explicitly.
        expected_identifiers = frozenset(LEGACY_CHECK_IDS)
        expected_count_keys = LEGACY_COUNT_KEYS
        allowed_statuses = frozenset({"CREDIT_BLOCKED", "NOT_CONFIGURED", "PASS"})
    else:
        raise ClosureIssue("source-capability-contract-invalid")
    checks = report.get("checks")
    counts = report.get("counts")
    if not isinstance(checks, list) or not isinstance(counts, dict):
        raise ClosureIssue("source-capability-contract-invalid")
    if set(counts) != expected_count_keys or any(
        type(value) is not int or value < 0 for value in counts.values()
    ):
        raise ClosureIssue("source-capability-contract-invalid")
    identifiers: set[str] = set()
    computed = {key: 0 for key in expected_count_keys}
    for item in checks:
        if not isinstance(item, dict) or set(item) != {
            "capabilities",
            "configured",
            "id",
            "items",
            "reason",
            "status",
        }:
            raise ClosureIssue("source-capability-contract-invalid")
        identifier = item.get("id")
        status_value = item.get("status")
        configured = item.get("configured")
        item_count = item.get("items")
        capabilities = item.get("capabilities")
        reason = item.get("reason")
        if (
            identifier not in expected_identifiers
            or identifier in identifiers
            or status_value not in allowed_statuses
            or type(configured) is not bool
            or type(item_count) is not int
            or item_count < 0
            or not isinstance(capabilities, list)
            or any(
                not isinstance(capability, str)
                or ENV_KEY.fullmatch(capability) is None
                for capability in capabilities
            )
            or capabilities != sorted(set(capabilities))
            or not isinstance(reason, str)
            or re.fullmatch(r"[a-z0-9-]+", reason) is None
            or configured != (status_value in CONFIGURED_STATUSES)
            or (configured and item_count < 1)
            or (not configured and item_count != 0)
            or (
                identifier in EXACT_CAPABILITY_IDS
                and len(capabilities) != item_count
            )
            or (
                identifier not in EXACT_CAPABILITY_IDS
                and capabilities
            )
        ):
            raise ClosureIssue("source-capability-contract-invalid")
        identifiers.add(identifier)
        computed[STATUS_COUNT_KEYS[status_value]] += 1
    if identifiers != expected_identifiers or computed != counts or counts["fail"] != 0:
        raise ClosureIssue("source-capability-contract-invalid")
    return report


def _enforce_source_capability_contract(
    report: dict[str, object], expected: dict[str, object]
) -> dict[str, object]:
    expected_checks = {
        item["id"]: item for item in expected["checks"] if isinstance(item, dict)
    }
    checks = report["checks"]
    assert isinstance(checks, list)
    for item in checks:
        assert isinstance(item, dict)
        source = expected_checks.get(item["id"])
        if source is None:
            # A v2 source contract predates the separate channel,
            # compute-backend, and Tailscale rows.
            continue
        if not source["configured"]:
            continue
        if (
            item["status"] not in CONFIGURED_STATUSES
            or not item["configured"]
            or (
                item["id"] in EXACT_CAPABILITY_IDS
                and item["capabilities"] != source["capabilities"]
            )
            or (
                item["id"] not in EXACT_CAPABILITY_IDS
                and item["items"] < source["items"]
            )
        ):
            item.update(
                capabilities=[],
                configured=False,
                items=0,
                reason="source-capability-not-restored",
                status="FAIL",
            )
    counts = {
        count_key: sum(item["status"] == status for item in checks)
        for status, count_key in STATUS_COUNT_KEYS.items()
    }
    report["counts"] = counts
    report["status"] = "TECHNICAL_FAIL" if counts["fail"] else "PASS"
    return report


def verify(
    home: Path,
    *,
    repository: Path,
    credit_blocked: frozenset[str],
    policy_confirmation_required: frozenset[str] = frozenset(),
    source_capability_contract: dict[str, object] | None = None,
) -> dict[str, object]:
    if credit_blocked.intersection(policy_confirmation_required):
        raise ClosureIssue("status-evidence-conflict")
    try:
        safe_home = _require_home(home)
    except ClosureIssue as issue:
        results = [_fail(identifier, issue.code) for identifier in CHECK_IDS]
    else:
        aas_source = _locate_aas_source(repository)
        openclaw_source = _locate_openclaw_source(repository, safe_home)
        results = []
        aas_token = _ACTIVE_AAS_SOURCE.set(aas_source)
        repository_token = _ACTIVE_REPOSITORY.set(repository)
        try:
            for identifier, operation in CHECKS:
                try:
                    result = operation(safe_home)
                    result = _check_source_contracts(
                        repository,
                        result,
                        aas_source=aas_source,
                        openclaw_source=openclaw_source,
                    )
                except ClosureIssue as issue:
                    result = _fail(identifier, issue.code)
                except Exception:
                    # Never serialize exception text: parsers can include secret data in
                    # their messages, and an unexpected failure is technical regardless.
                    result = _fail(identifier, "unexpected-verifier-error")
                if identifier in credit_blocked and result.status == "PASS":
                    result = _result(
                        identifier,
                        "CREDIT_BLOCKED",
                        "quota-blocked-reported",
                        configured=True,
                        items=result.items,
                        capabilities=result.capabilities,
                    )
                elif (
                    identifier in policy_confirmation_required
                    and result.status == "PASS"
                ):
                    result = _result(
                        identifier,
                        "POLICY_CONFIRMATION_REQUIRED",
                        "policy-confirmation-required-reported",
                        configured=True,
                        items=result.items,
                        capabilities=result.capabilities,
                    )
                results.append(result)
        finally:
            _ACTIVE_REPOSITORY.reset(repository_token)
            _ACTIVE_AAS_SOURCE.reset(aas_token)

    counts = {
        count_key: sum(item.status == status for item in results)
        for status, count_key in STATUS_COUNT_KEYS.items()
    }
    report: dict[str, object] = {
        "checks": [item.as_json() for item in results],
        "counts": counts,
        "schema": SCHEMA,
        "schemaVersion": SCHEMA_VERSION,
        "status": "TECHNICAL_FAIL" if counts["fail"] else "PASS",
    }
    if source_capability_contract is not None:
        report = _enforce_source_capability_contract(
            report, source_capability_contract
        )
    return report


def _write_report(path: Path, report: dict[str, object]) -> None:
    target = path.expanduser().absolute()
    opened_parent = _open_parent_descriptor(target, create=True)
    if opened_parent is None:  # pragma: no cover - create=True cannot return None
        raise ClosureIssue("unsafe-report-output")
    parent_descriptor, leaf, parent_identity = opened_parent
    temporary = ""
    try:
        try:
            existing = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != os.getuid()
            or existing.st_nlink != 1
        ):
            raise ClosureIssue("unsafe-report-output")
        payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = -1
        for _attempt in range(32):
            temporary = f".credential-report-{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    temporary, flags, 0o600, dir_fd=parent_descriptor
                )
                break
            except FileExistsError:
                continue
        if descriptor < 0:
            raise ClosureIssue("unsafe-report-output")
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ClosureIssue("unsafe-report-output")
                view = view[written:]
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _confirm_parent_identity(target, parent_identity)
        os.replace(
            temporary,
            leaf,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary = ""
        os.fsync(parent_descriptor)
        _confirm_parent_identity(target, parent_identity)
    finally:
        if temporary:
            try:
                os.unlink(temporary, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--expect-source-capabilities",
        type=Path,
        help="require every credential capability configured at backup time",
    )
    parser.add_argument(
        "--credit-blocked",
        action="append",
        default=[],
        choices=CHECK_IDS,
        metavar="CHECK",
        help="carry forward an independently established provider quota status",
    )
    parser.add_argument(
        "--policy-confirmation-required",
        action="append",
        default=[],
        choices=sorted(POLICY_CONFIRMATION_IDS),
        metavar="CHECK",
        help=(
            "record an explicitly observed operation-policy confirmation gate; "
            "credential presence never sets this status"
        ),
    )
    args = parser.parse_args(argv)
    repository = args.repository.expanduser().absolute()
    if not repository.is_dir():
        parser.error("--repository must name a directory")
    try:
        source_contract = (
            _load_source_capability_contract(args.expect_source_capabilities)
            if args.expect_source_capabilities is not None
            else None
        )
        report = verify(
            args.home,
            repository=repository,
            credit_blocked=frozenset(args.credit_blocked),
            policy_confirmation_required=frozenset(
                args.policy_confirmation_required
            ),
            source_capability_contract=source_contract,
        )
    except ClosureIssue as issue:
        print(f"skill credential closure: {issue.code}", file=sys.stderr)
        return 2
    if args.output is not None:
        try:
            _write_report(args.output, report)
        except (ClosureIssue, OSError):
            print("skill credential closure: unsafe-report-output", file=sys.stderr)
            return 2
    else:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    counts = report["counts"]
    assert isinstance(counts, dict)
    print(
        "skill credential closure: "
        f"{report['status']}; pass={counts['pass']}, fail={counts['fail']}, "
        f"not-configured={counts['notConfigured']}, "
        f"credit-blocked={counts['creditBlocked']}, "
        f"reauth-required={counts['reauthRequired']}, "
        "policy-confirmation-required="
        f"{counts['policyConfirmationRequired']}",
        file=sys.stderr if args.output is None else sys.stdout,
    )
    return 2 if report["status"] == "TECHNICAL_FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
