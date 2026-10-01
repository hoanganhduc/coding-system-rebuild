"""Shared fail-closed contract for restore verification evidence."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import subprocess
import time


EVIDENCE_SCHEMA = "coding-system.verification-evidence/v1"
GATE_CONTRACT = "coding-system.verify-gates/v1"
MAX_EVIDENCE_AGE_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 5
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_GATE_COUNT = 4096
MAX_LABEL_LENGTH = 512
RUN_ID = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VALID_GATE_STATUSES = frozenset({"PASS", "FAIL", "NOT_CONFIGURED"})
SIDECAR_SCHEMAS = {
    "classroom50": "coding-system.classroom50-verification/v1",
    "target": "coding-system.target-verification.v2",
}
SIDECAR_STATUSES = {
    "classroom50": frozenset({"PASS", "REAUTH_REQUIRED", "NOT_CONFIGURED"}),
    "target": frozenset(
        {
            "PASS",
            "AUTH_INVALID",
            "REAUTH_REQUIRED",
            "CREDIT_BLOCKED",
            "NOT_CONFIGURED",
            "NOT_APPLICABLE",
        }
    ),
}


class EvidenceContractError(ValueError):
    """Verification evidence does not satisfy the restore contract."""


def _requirement(
    identifier: str, pattern: str, *statuses: str
) -> tuple[str, re.Pattern[str], frozenset[str]]:
    return identifier, re.compile(pattern), frozenset(statuses)


COMMON_REQUIREMENTS = (
    _requirement(
        "platform-lock",
        r"^Ubuntu 24\.04/(?:amd64|arm64) lock is internally consistent$",
        "PASS",
    ),
    _requirement(
        "npm-closure",
        r"^npm direct/transitive package closure is exact and immutable$",
        "PASS",
    ),
    _requirement(
        "classroom50",
        r"^Classroom50 (?:component/software/runtime/config state \([A-Z_]+\)|technical closure; nontechnical status=[A-Z_]+)$",
        "PASS",
    ),
)


PROFILE_REQUIREMENTS = {
    "full": COMMON_REQUIREMENTS
    + (
        _requirement(
            "software-closure",
            r"^exact apt package and native CLI closure$",
            "PASS",
        ),
        _requirement(
            "python-closure",
            r"^Python OCI provenance \+ exact eight-environment inventories$",
            "PASS",
        ),
        _requirement(
            "scheduler-closure",
            r"^host/systemd/OpenClaw schedules \+ execution canaries$",
            "PASS",
        ),
        _requirement(
            "mcp-closure",
            r"^every enabled configured MCP completed initialize \+ tools/list$",
            "PASS",
        ),
        _requirement(
            "openclaw-completion",
            r"^OpenClaw Bash completion is current and syntactically valid$",
            "PASS",
        ),
        _requirement("secret-authorities", r"^required secrets present$", "PASS"),
        _requirement(
            "skill-credential-closure",
            r"^skill credential authority/projection/resolver closure$",
            "PASS",
        ),
        _requirement(
            "skill-runtime-images",
            r"^locked OCI platform descriptors \+ SageMath \+ Translation Server$",
            "PASS",
        ),
        _requirement(
            "aas-component-authority",
            r"^component object present: ~/ai-agents-skills@[0-9a-f]{12}$",
            "PASS",
        ),
        _requirement(
            "aas-managed-state",
            r"^all requested non-OpenClaw ai-agents-skills targets match managed state$",
            "PASS",
        ),
        _requirement(
            "aas-runtime-smoke",
            r"^installed ai-agents-skills runtime smoke has complete declared coverage$",
            "PASS",
        ),
        _requirement(
            "openclaw-runtime",
            r"^OpenClaw effective runtime closure \(full\)$",
            "PASS",
        ),
        _requirement(
            "agent-target-state",
            r"^agent target (?:state \([A-Z_]+\)|software/config technical state; nontechnical status=[A-Z_]+)$",
            "PASS",
        ),
    ),
    "ci": COMMON_REQUIREMENTS
    + (
        _requirement(
            "software-closure",
            r"^apt/native CLI declarations are structurally verifiable \(ci\)$",
            "PASS",
        ),
        _requirement(
            "python-closure",
            r"^Python closure declarations are structurally valid \(ci\)$",
            "PASS",
        ),
        _requirement(
            "scheduler-closure",
            r"^scheduler declarations \(ci; live state not asserted\)$",
            "PASS",
        ),
        _requirement(
            "mcp-closure",
            r"^MCP declarations are closed or explicitly inert \(ci\)$",
            "PASS",
        ),
        _requirement(
            "openclaw-completion",
            r"^OpenClaw Bash completion \(degraded\)$",
            "NOT_CONFIGURED",
        ),
        _requirement(
            "secret-authorities",
            r"^required secrets \(degraded\)$",
            "NOT_CONFIGURED",
        ),
        _requirement(
            "skill-credential-closure",
            r"^skill credential authority/projection/resolver closure \(degraded\)$",
            "NOT_CONFIGURED",
        ),
        _requirement(
            "skill-runtime-images",
            r"^zotero doctor / digest / sage / LeanExplore MCP \(degraded\)$",
            "NOT_CONFIGURED",
        ),
        _requirement(
            "aas-component-authority",
            r"^component object (?:present: ~/ai-agents-skills@[0-9a-f]{12}|absent: ~/ai-agents-skills \(ci\))$",
            "PASS",
            "NOT_CONFIGURED",
        ),
        _requirement(
            "aas-managed-runtime",
            r"^installed ai-agents-skills state/runtime smoke \(ci\)$",
            "NOT_CONFIGURED",
        ),
        _requirement(
            "openclaw-runtime",
            r"^OpenClaw effective runtime closure \(ci\)$",
            "PASS",
        ),
        _requirement(
            "agent-target-state",
            r"^(?:agent target (?:state \([A-Z_]+\)|software/config technical state; nontechnical status=[A-Z_]+)|target-state manifest unavailable in CI)$",
            "PASS",
            "NOT_CONFIGURED",
        ),
    ),
}


def expected_gate_ids(profile: str) -> list[str]:
    try:
        requirements = PROFILE_REQUIREMENTS[profile]
    except KeyError as exc:
        raise EvidenceContractError(f"unsupported verification profile: {profile}") from exc
    return sorted(identifier for identifier, _pattern, _statuses in requirements)


def validate_run_id(value: object) -> str:
    if not isinstance(value, str) or RUN_ID.fullmatch(value) is None:
        raise EvidenceContractError("restore run ID must be 64 lowercase hexadecimal characters")
    return value


def validate_commit(value: object) -> str:
    if not isinstance(value, str) or COMMIT.fullmatch(value) is None:
        raise EvidenceContractError("repository commit is invalid")
    return value


def closed_repository_commit(repository: Path) -> str:
    """Read HEAD without ambient Git configuration, PATH, or repository redirects."""
    try:
        completed = subprocess.run(
            [
                "/usr/bin/git",
                "--no-optional-locks",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.commitGraph=false",
                "-c",
                "core.multiPackIndex=false",
                "-c",
                "core.alternateRefsCommand=",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.file.allow=never",
                "-c",
                "credential.helper=",
                "-c",
                "core.sshCommand=/bin/false",
                "-C",
                os.fspath(repository),
                "rev-parse",
                "HEAD",
            ],
            env={
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "HOME": "/",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "XDG_CONFIG_HOME": "/dev/null",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceContractError("repository commit could not be read safely") from exc
    if completed.returncode != 0:
        raise EvidenceContractError("repository commit could not be read safely")
    return validate_commit(completed.stdout.strip())


def _requirement_observation(
    gates: list[dict[str, str]], profile: str, identifier: str
) -> dict[str, str]:
    try:
        requirements = PROFILE_REQUIREMENTS[profile]
    except KeyError as exc:
        raise EvidenceContractError(f"unsupported verification profile: {profile}") from exc
    matching_requirements = [
        (pattern, statuses)
        for requirement_id, pattern, statuses in requirements
        if requirement_id == identifier
    ]
    if len(matching_requirements) != 1:
        raise EvidenceContractError(f"unknown verification requirement: {identifier}")
    pattern, allowed_statuses = matching_requirements[0]
    matches = [
        item
        for item in gates
        if pattern.fullmatch(item["label"]) and item["status"] in allowed_statuses
    ]
    if len(matches) != 1:
        raise EvidenceContractError(
            f"verification gate contract requires exactly one {identifier} observation"
        )
    return matches[0]


def _status_from_gate(identifier: str, label: str) -> str:
    if identifier == "classroom50":
        patterns = (
            r"^Classroom50 component/software/runtime/config state \(([A-Z_]+)\)$",
            r"^Classroom50 technical closure; nontechnical status=([A-Z_]+)$",
        )
    elif identifier == "agent-target-state":
        patterns = (
            r"^agent target state \(([A-Z_]+)\)$",
            r"^agent target software/config technical state; nontechnical status=([A-Z_]+)$",
        )
    else:
        raise EvidenceContractError(f"unsupported sidecar gate: {identifier}")
    for pattern in patterns:
        match = re.fullmatch(pattern, label)
        if match:
            return match.group(1)
    raise EvidenceContractError(f"{identifier} gate does not carry a sidecar status")


def validate_sidecar_bindings(
    sidecars: object,
    *,
    gates: list[dict[str, str]],
    profile: str,
    repository_commit: str,
    restore_run_id: str,
    run_started_at_unix: int,
    observed_at_unix: int,
) -> None:
    """Validate content-addressed report sidecars bound to one verification run."""
    if not isinstance(sidecars, dict) or set(sidecars) != set(SIDECAR_SCHEMAS):
        raise EvidenceContractError("verification sidecar inventory is incomplete")
    identity = {
        "repositoryCommit": validate_commit(repository_commit),
        "restoreRunId": validate_run_id(restore_run_id),
        "capturedAtUnix": observed_at_unix,
    }
    gate_ids = {"classroom50": "classroom50", "target": "agent-target-state"}
    for name in sorted(SIDECAR_SCHEMAS):
        binding = sidecars.get(name)
        if not isinstance(binding, dict):
            raise EvidenceContractError(f"{name} sidecar binding is invalid")
        gate = _requirement_observation(gates, profile, gate_ids[name])
        if name == "target" and gate["label"] == "target-state manifest unavailable in CI":
            expected = {
                "present": False,
                **identity,
                "status": "NOT_CONFIGURED",
                "technicalStatus": "PASS",
                "gateLabel": gate["label"],
            }
            if binding != expected or gate["status"] != "NOT_CONFIGURED":
                raise EvidenceContractError("absent target sidecar disagrees with its gate")
            continue
        expected_fields = {
            "present",
            "schema",
            "sha256",
            "sizeBytes",
            "ownerUid",
            "mode",
            "mtimeNs",
            "capturedAtUnix",
            "repositoryCommit",
            "restoreRunId",
            "status",
            "technicalStatus",
            "gateLabel",
        }
        if set(binding) != expected_fields or binding.get("present") is not True:
            raise EvidenceContractError(f"{name} sidecar binding fields are invalid")
        if any(binding.get(key) != value for key, value in identity.items()):
            raise EvidenceContractError(f"{name} sidecar is not bound to this verification run")
        if (
            binding.get("schema") != SIDECAR_SCHEMAS[name]
            or not isinstance(binding.get("sha256"), str)
            or SHA256.fullmatch(binding["sha256"]) is None
            or not isinstance(binding.get("sizeBytes"), int)
            or isinstance(binding.get("sizeBytes"), bool)
            or not 0 < binding["sizeBytes"] <= MAX_EVIDENCE_BYTES
            or not isinstance(binding.get("ownerUid"), int)
            or isinstance(binding.get("ownerUid"), bool)
            or binding["ownerUid"] < 0
            or binding.get("mode") != "0600"
            or not isinstance(binding.get("mtimeNs"), int)
            or isinstance(binding.get("mtimeNs"), bool)
        ):
            raise EvidenceContractError(f"{name} sidecar metadata is invalid")
        if not run_started_at_unix * 1_000_000_000 <= binding["mtimeNs"]:
            raise EvidenceContractError(f"{name} sidecar predates this verification run")
        if binding["mtimeNs"] > (observed_at_unix + MAX_CLOCK_SKEW_SECONDS) * 1_000_000_000:
            raise EvidenceContractError(f"{name} sidecar timestamp is in the future")
        if binding.get("technicalStatus") != "PASS" or gate["status"] != "PASS":
            raise EvidenceContractError(f"{name} sidecar does not prove technical success")
        if binding.get("gateLabel") != gate["label"]:
            raise EvidenceContractError(f"{name} sidecar is bound to the wrong gate")
        expected_status = _status_from_gate(gate_ids[name], gate["label"])
        if (
            binding.get("status") != expected_status
            or expected_status not in SIDECAR_STATUSES[name]
        ):
            raise EvidenceContractError(f"{name} sidecar status disagrees with its gate")


def validate_gate_data(
    gates: object,
    counts: object,
    status: object,
    profile: str,
) -> list[str]:
    if not isinstance(gates, list) or not gates or len(gates) > MAX_GATE_COUNT:
        raise EvidenceContractError("gate list is empty, oversized, or invalid")
    labels: set[str] = set()
    computed = {"pass": 0, "fail": 0, "notConfigured": 0}
    normalized: list[dict[str, str]] = []
    count_key = {"PASS": "pass", "FAIL": "fail", "NOT_CONFIGURED": "notConfigured"}
    for item in gates:
        if not isinstance(item, dict) or set(item) != {"label", "status"}:
            raise EvidenceContractError("gate entries must contain only label and status")
        label = item.get("label")
        gate_status = item.get("status")
        if (
            not isinstance(label, str)
            or not label
            or len(label) > MAX_LABEL_LENGTH
            or any(ord(character) < 32 or ord(character) == 127 for character in label)
        ):
            raise EvidenceContractError("gate label is empty, oversized, or contains control characters")
        if label in labels:
            raise EvidenceContractError(f"duplicate gate label: {label}")
        if gate_status not in VALID_GATE_STATUSES:
            raise EvidenceContractError(f"invalid gate status for {label}")
        labels.add(label)
        computed[count_key[gate_status]] += 1
        normalized.append({"label": label, "status": gate_status})

    if (
        not isinstance(counts, dict)
        or set(counts) != set(computed)
        or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts.values())
        or counts != computed
    ):
        raise EvidenceContractError("gate counts do not match the gate inventory")
    expected_status = "PASS" if computed["fail"] == 0 else "TECHNICAL_FAIL"
    if status != expected_status:
        raise EvidenceContractError("overall verification status disagrees with gate counts")

    inventory: list[str] = []
    if expected_status == "PASS":
        try:
            requirements = PROFILE_REQUIREMENTS[profile]
        except KeyError as exc:
            raise EvidenceContractError(f"unsupported verification profile: {profile}") from exc
        for identifier, pattern, allowed_statuses in requirements:
            matches = [
                item
                for item in normalized
                if pattern.fullmatch(item["label"])
                and item["status"] in allowed_statuses
            ]
            if len(matches) != 1:
                raise EvidenceContractError(
                    f"verification gate contract requires exactly one {identifier} observation"
                )
            inventory.append(identifier)
    return sorted(inventory)


def validate_evidence(
    evidence: object,
    *,
    repository_commit: str,
    profile: str,
    architecture: str,
    restore_run_id: str,
    now_unix: float | None = None,
) -> int:
    if not isinstance(evidence, dict):
        raise EvidenceContractError("verification evidence root must be an object")
    expected_fields = {
        "schema",
        "gateContract",
        "observedAt",
        "observedAtUnix",
        "repositoryCommit",
        "profile",
        "architecture",
        "restoreRunId",
        "runStartedAtUnix",
        "status",
        "counts",
        "gates",
        "gateInventory",
        "sidecars",
    }
    if set(evidence) != expected_fields:
        raise EvidenceContractError("verification evidence fields do not match v1")
    expected_identity = {
        "schema": EVIDENCE_SCHEMA,
        "gateContract": GATE_CONTRACT,
        "repositoryCommit": validate_commit(repository_commit),
        "profile": profile,
        "architecture": architecture,
        "restoreRunId": validate_run_id(restore_run_id),
        "status": "PASS",
    }
    if any(evidence.get(key) != value for key, value in expected_identity.items()):
        raise EvidenceContractError("verification evidence identity does not bind this restore run")

    inventory = validate_gate_data(
        evidence.get("gates"),
        evidence.get("counts"),
        evidence.get("status"),
        profile,
    )
    if evidence.get("gateInventory") != inventory or inventory != expected_gate_ids(profile):
        raise EvidenceContractError("verification evidence gate inventory is incomplete or inconsistent")

    run_started_at_unix = evidence.get("runStartedAtUnix")
    observed_unix = evidence.get("observedAtUnix")
    observed_at = evidence.get("observedAt")
    if not isinstance(observed_unix, int) or isinstance(observed_unix, bool):
        raise EvidenceContractError("verification evidence timestamp is invalid")
    if (
        not isinstance(run_started_at_unix, int)
        or isinstance(run_started_at_unix, bool)
        or run_started_at_unix < 0
        or run_started_at_unix > observed_unix
    ):
        raise EvidenceContractError("verification run boundary is invalid")
    if not isinstance(observed_at, str):
        raise EvidenceContractError("verification evidence timestamp text is invalid")
    try:
        parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceContractError("verification evidence timestamp text is invalid") from exc
    if parsed.tzinfo is None or abs(parsed.timestamp() - observed_unix) > 1:
        raise EvidenceContractError("verification evidence timestamps disagree")
    now = time.time() if now_unix is None else now_unix
    age = int(now) - observed_unix
    if age < -MAX_CLOCK_SKEW_SECONDS:
        raise EvidenceContractError("verification evidence timestamp is in the future")
    if age > MAX_EVIDENCE_AGE_SECONDS:
        raise EvidenceContractError("verification evidence is stale")
    validate_sidecar_bindings(
        evidence.get("sidecars"),
        gates=evidence["gates"],
        profile=profile,
        repository_commit=repository_commit,
        restore_run_id=restore_run_id,
        run_started_at_unix=run_started_at_unix,
        observed_at_unix=observed_unix,
    )
    return max(age, 0)


def utc_timestamp(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
